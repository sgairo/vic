// Copyright 2016 VMware, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"archive/zip"
	"compress/gzip"
	"crypto/tls"
	"html/template"
	"net"
	"net/http"
	"path/filepath"

	"golang.org/x/net/context"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/tlsconfig"
	gorillacontext "github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"

	"crypto/x509"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/vic/lib/vicadmin"
	"github.com/vmware/vic/pkg/trace"
	"github.com/vmware/vic/pkg/vsphere/session"
	"net/url"
	"sync"
	"time"
)

type server struct {
	l    net.Listener
	addr string
	mux  *http.ServeMux
	uss  *UserSessionStore
}

type format int

const (
	formatTGZ format = iota
	formatZip
)

const sessionExpiration = time.Hour * 24
const sessionCookieKey = "sessiondata"

// UserSession holds a user's session metadata
type UserSession struct {
	username string
	created  time.Time
	config   *session.Config
}

// UserSessionStore holds and manages user sessions
type UserSessionStore struct {
	*sync.Mutex
	sessions map[string]*UserSession
	ticker   *time.Ticker
}

func (u *UserSessionStore) Add(username string, config *session.Config) *UserSession {
	u.Lock()
	defer u.Unlock()
	u.sessions[username] = &UserSession{
		username: username,
		created:  time.Now(),
		config:   config,
	}
	return u.sessions[username]
}

func (u *UserSessionStore) Delete(username string) {
	u.Lock()
	defer u.Unlock()
	delete(u.sessions, username)
}

func (u *UserSessionStore) Get(username string) *UserSession {
	return u.sessions[username]
}

// GetSession logs into vSphere and returns a session object. Caller responsible for error handling/logout
func (u *UserSessionStore) GetSession(username string) (vSphereSession *session.Session, err error) {
	return vSphereSessionGet(u.Get(username).config)
}

// reaper takes abandoned sessions to a farm upstate so they don't build up forever
func (u *UserSessionStore) reaper() {
	select {
	case <-u.ticker.C:
		for username, session := range u.sessions {
			if time.Since(session.created) > sessionExpiration {
				u.Delete(username)
			}
		}
	}
}

// NewUserSessionStore creates & initializes a UserSessionStore and starts a session reaper in the background
func NewUserSessionStore() *UserSessionStore {
	u := &UserSessionStore{
		sessions: make(map[string]*UserSession),
		ticker:   time.NewTicker(time.Minute),
	}
	go u.reaper()
	return u
}

var store = sessions.NewCookieStore([]byte(securecookie.GenerateRandomKey(64)))

func (s *server) listen() error {
	defer trace.End(trace.Begin(""))

	var err error
	s.uss = NewUserSessionStore()

	certificate, err := vchConfig.HostCertificate.Certificate()
	if err != nil {
		log.Errorf("Could not load certificate from config - running without TLS: %s", err)

		s.l, err = net.Listen("tcp", s.addr)
		return err
	}

	// FIXME: assignment copies lock value to tlsConfig: crypto/tls.Config contains sync.Once contains sync.Mutex
	tlsconfig := func(c *tls.Config) *tls.Config {
		// if there are CAs, then TLS is enabled
		if len(vchConfig.CertificateAuthorities) != 0 {
			if c.ClientCAs == nil {
				c.ClientCAs = x509.NewCertPool()
			}
			if !c.ClientCAs.AppendCertsFromPEM(vchConfig.CertificateAuthorities) {
				log.Errorf("Unable to load CAs from config; client auth via certificate will not function")
			}
			c.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			log.Warnf("No certificate authorities found for certificate-based authentication. This may be intentional, however, authentication is disabled")
		}

		return &tls.Config{
			Certificates:             c.Certificates,
			NameToCertificate:        c.NameToCertificate,
			GetCertificate:           c.GetCertificate,
			RootCAs:                  c.RootCAs,
			NextProtos:               c.NextProtos,
			ServerName:               c.ServerName,
			ClientAuth:               c.ClientAuth,
			ClientCAs:                c.ClientCAs,
			InsecureSkipVerify:       c.InsecureSkipVerify,
			CipherSuites:             c.CipherSuites,
			PreferServerCipherSuites: c.PreferServerCipherSuites,
			SessionTicketsDisabled:   c.SessionTicketsDisabled,
			SessionTicketKey:         c.SessionTicketKey,
			ClientSessionCache:       c.ClientSessionCache,
			MinVersion:               tls.VersionTLS12,
			MaxVersion:               c.MaxVersion,
			CurvePreferences:         c.CurvePreferences,
		}
	}(&tlsconfig.ServerDefault)

	tlsconfig.Certificates = []tls.Certificate{*certificate}

	innerListener, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Fatal(err)
		return err
	}

	s.l = tls.NewListener(innerListener, tlsconfig)
	return nil
}

func (s *server) listenPort() int {
	return s.l.Addr().(*net.TCPAddr).Port
}

// Enforces authentication on route `link` and runs `handler` on successful auth
func (s *server) AuthenticatedHandle(link string, h http.Handler) {
	s.Authenticated(link, h.ServeHTTP)
}

func (s *server) Handle(link string, h http.Handler) {
	s.mux.Handle(link, gorillacontext.ClearHandler(h))
}

// Enforces authentication on route `link` and runs `handler` on successful auth
func (s *server) Authenticated(link string, handler func(http.ResponseWriter, *http.Request)) {
	defer trace.End(trace.Begin(""))

	authHandler := func(w http.ResponseWriter, r *http.Request) {
		websession, _ := store.Get(r, sessionCookieKey)

		if len(r.TLS.PeerCertificates) > 0 { // the user is authenticated by certificate at connection time
			usersess := s.uss.Add("root", &rootConfig.Config)
			websession, _ := store.Get(r, sessionCookieKey)
			timeNow, _ := usersess.created.MarshalText()
			websession.Values["created"] = string(timeNow)
			websession.Values["username"] = "root"
			websession.Save(r, w)
			handler(w, r)
			return
		}

		c := websession.Values["created"]
		if c == nil { // no cookie, so redirect to login
			http.Redirect(w, r, "/authentication", 302)
			return
		}

		// parse the cookie creation time
		created, _ := time.Parse(time.RFC3339, c.(string))

		if time.Since(created) > sessionExpiration { // cookie exists but is expired
			http.Redirect(w, r, "/authentication?expired", 302)
			return
		}

		// if the date on the cookie was valid, then the user is authenticated
		handler(w, r)
	}
	s.mux.Handle(link, gorillacontext.ClearHandler(http.HandlerFunc(authHandler)))
}

// renders the page for login and handles authorization requests
func (s *server) loginPage(res http.ResponseWriter, req *http.Request) {
	defer trace.End(trace.Begin(""))
	ctx := context.Background()
	if req.Method == "POST" {
		// take the form data and use it to try to authenticate with vsphere

		// create a userconfig
		userconfig := session.Config{
			Insecure:       false,
			Thumbprint:     rootConfig.Thumbprint,
			Keepalive:      rootConfig.Keepalive,
			ClusterPath:    rootConfig.ClusterPath,
			DatacenterPath: rootConfig.DatacenterPath,
			DatastorePath:  rootConfig.DatastorePath,
			HostPath:       rootConfig.Config.HostPath,
			PoolPath:       rootConfig.PoolPath,
		}
		user := url.UserPassword(req.FormValue("username"), req.FormValue("password"))
		serviceURL, err := soap.ParseURL(rootConfig.Service)
		if err != nil {
			log.Errorf("vSphere service URL was not a valid format; parsing returned error: %s", err)
		}
		serviceURL.User = user
		userconfig.Service = serviceURL.String()

		// check login
		usersession, err := vSphereSessionGet(&userconfig)
		if err != nil {
			// something went wrong or we could not authenticate
			http.Redirect(res, req, "/authentication?unauthorized", 302)
		}

		// successful login above; user is authenticated
		// log out
		usersession.Client.Logout(context.Background())

		// save user config locally
		usersess := s.uss.Add(req.FormValue("username"), &userconfig)

		// create a token to save as an encrypted & signed cookie
		websession, _ := store.Get(req, sessionCookieKey)
		timeNow, _ := usersess.created.MarshalText()
		websession.Values["created"] = string(timeNow)
		websession.Values["username"] = req.FormValue("username")
		websession.Save(req, res)

		// redirect to dashboard
		http.Redirect(res, req, "/", 302)
	}

	// Render login page (shows up on non-POST requests):
	sess, err := client(&rootConfig)
	v := vicadmin.NewValidator(ctx, &vchConfig, sess)
	tmpl, err := template.ParseFiles("auth.html")
	err = tmpl.ExecuteTemplate(res, "auth.html", v)
	if err != nil {
		log.Errorf("Error parsing template: %s", err)
	}
}

func (s *server) serve() error {
	defer trace.End(trace.Begin(""))

	s.mux = http.NewServeMux()

	// s.mux.HandleFunc bypasses authentication
	s.mux.HandleFunc("/authentication", s.loginPage)

	// tar of appliance system logs
	s.Authenticated("/logs.tar.gz", s.tarDefaultLogs)
	s.Authenticated("/logs.zip", s.zipDefaultLogs)

	// tar of appliance system logs + container logs
	s.Authenticated("/container-logs.tar.gz", s.tarContainerLogs)
	s.Authenticated("/container-logs.zip", s.zipContainerLogs)

	// these assets bypass authentication & are world-readable
	s.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css/"))))
	s.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images/"))))
	s.Handle("/fonts/", http.StripPrefix("/fonts/", http.FileServer(http.Dir("fonts/"))))

	for _, path := range logFiles() {
		name := filepath.Base(path)
		p := path

		// get single log file (no tail)
		s.Authenticated("/logs/"+name, func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, p)
		})

		// get single log file (with tail)
		s.Authenticated("/logs/tail/"+name, func(w http.ResponseWriter, r *http.Request) {
			s.tailFiles(w, r, []string{p})
		})
	}

	s.Authenticated("/", s.index)
	server := &http.Server{
		Handler: s.mux,
	}

	defaultReaders = configureReaders()

	return server.Serve(s.l)
}

func (s *server) stop() error {
	defer trace.End(trace.Begin(""))

	if s.l != nil {
		err := s.l.Close()
		s.l = nil
		return err
	}

	return nil
}

func getSessionCookie(req *http.Request) *sessions.Session {
	cookieSessionData, _ := store.Get(req, sessionCookieKey)
	return cookieSessionData
}

func (s *server) bundleContainerLogs(res http.ResponseWriter, req *http.Request, f format) {
	defer trace.End(trace.Begin(""))

	readers := defaultReaders
	c, err := s.getSessionFromRequest(req)

	// Note: we don't want to Logout() until tarEntries() completes below
	defer c.Client.Logout(context.Background())

	logs, err := findDatastoreLogs(c)
	if err != nil {
		log.Warningf("error searching datastore: %s", err)
	} else {
		for key, rdr := range logs {
			readers[key] = rdr
		}
	}

	logs, err = findDiagnosticLogs(c)
	if err != nil {
		log.Warningf("error collecting diagnostic logs: %s", err)
	} else {
		for key, rdr := range logs {
			readers[key] = rdr
		}
	}

	s.bundleLogs(res, req, readers, f)
}

func (s *server) tarDefaultLogs(res http.ResponseWriter, req *http.Request) {
	defer trace.End(trace.Begin(""))

	s.bundleLogs(res, req, defaultReaders, formatTGZ)
}
func (s *server) zipDefaultLogs(res http.ResponseWriter, req *http.Request) {
	defer trace.End(trace.Begin(""))

	s.bundleLogs(res, req, defaultReaders, formatZip)
}

func (s *server) bundleLogs(res http.ResponseWriter, req *http.Request, readers map[string]entryReader, f format) {
	defer trace.End(trace.Begin(""))

	var err error
	if f == formatTGZ {
		res.Header().Set("Content-Type", "application/x-gzip")
		z := gzip.NewWriter(res)
		defer z.Close()
		err = tarEntries(readers, z)
	} else if f == formatZip {
		res.Header().Set("Content-Type", "application/zip")
		z := zip.NewWriter(res)
		defer z.Close()
		err = zipEntries(readers, z)
	}

	if err != nil {
		log.Errorf("Error bundling logs: %s", err)
	}
}

func (s *server) tarContainerLogs(res http.ResponseWriter, req *http.Request) {
	s.bundleContainerLogs(res, req, formatTGZ)
}

func (s *server) zipContainerLogs(res http.ResponseWriter, req *http.Request) {
	s.bundleContainerLogs(res, req, formatZip)
}

func (s *server) tailFiles(res http.ResponseWriter, req *http.Request, names []string) {
	defer trace.End(trace.Begin(""))

	cc := res.(http.CloseNotifier).CloseNotify()

	fw := &flushWriter{
		f: res.(http.Flusher),
		w: res,
	}

	done := make(chan bool)
	for _, file := range names {
		go tailFile(fw, file, &done)
	}

	<-cc
	for range names {
		done <- true
	}
}

func (s *server) index(res http.ResponseWriter, req *http.Request) {
	defer trace.End(trace.Begin(""))
	ctx := context.Background()
	sess, err := s.getSessionFromRequest(req)
	v := vicadmin.NewValidator(ctx, &vchConfig, sess)

	tmpl, err := template.ParseFiles("dashboard.html")
	err = tmpl.ExecuteTemplate(res, "dashboard.html", v)
	if err != nil {
		log.Errorf("Error parsing template: %s", err)
	}
}
