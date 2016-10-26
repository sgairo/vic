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
	"github.com/vmware/vic/pkg/vsphere/session"
	"sync"
	"time"
)

// UserSession holds a user's session metadata
type UserSession struct {
	username string
	created  time.Time
	config   *session.Config
}

// UserSessionStore holds and manages user sessions
type UserSessionStore struct {
	mutex    sync.RWMutex
	sessions map[string]*UserSession
	ticker   *time.Ticker
}

type UserSessionStorer interface {
	Add(username string, config *session.Config) *UserSession
	Delete(username string)
	GetRealSession(username string) (vSphereSession *session.Session, err error)
	GetUserSession(username string) *UserSession
}

func (u *UserSessionStore) Add(username string, config *session.Config) *UserSession {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	u.sessions[username] = &UserSession{
		username: username,
		created:  time.Now(),
		config:   config,
	}
	return u.sessions[username]
}

func (u *UserSessionStore) Delete(username string) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	delete(u.sessions, username)
}

// Grabs the UserSession metadta object and doesn't establish a connection to vSphere
func (u *UserSessionStore) Get(username string) *UserSession {
	u.mutex.RLock()
	defer u.mutex.RUnlock()
	return u.sessions[username]
}

// Get logs into vSphere and returns a vSphere session object. Caller responsible for error handling/logout
func (u *UserSessionStore) VSphere(username string) (vSphereSession *session.Session, err error) {
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
		mutex:    sync.RWMutex{},
	}
	go u.reaper()
	return u
}
