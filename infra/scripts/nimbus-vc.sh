#!/bin/bash
set -euo pipefail
IFS=$'\n\t'
# see http://redsymbol.net/articles/unofficial-bash-strict-mode/

# setup & globals
user="$1"
esx_version=3620759
#vcva_version=964349
vcva_version=3634791
nimbus="nimbus-gateway.eng.vmware.com"
worker_deploy_log=""
worker_vm_ip=""
nimbus_esxes_list_file="/tmp/nimbus-esx-instances-$(date -u --iso-8601=seconds)"

log () {
    # our messages are displayed in 'reverse video' to distinguish them
    # from the output produced by the various commands run
    # which we also do not wish to squelch
    echo -en "\x1b[7m$@\x1b[0m\n"
    tput sgr0
}

check_dependencies() {
    [ $(which govc) ] &&\
        log "all dependencies present" ||\
            log "govc needs to be installed. govc is a part of govmomi: https://github.com/vmware/govmomi"
}

worker() {
    ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -C "$user"@"$worker_vm_ip" "$@"
}

deploy_esx_server() {
    worker nimbus-esxdeploy "ESX-$(((1+RANDOM % 10000)))" \
           --disk=48000000 --ssd=24000000 --memory=8192 --nics 2 "$esx_version"\
        | tee /dev/tty \
        | grep "IPv4 is" \
        | sed 's/ /\n/g' \
        | grep -m1 -e "10\..*" \
        | cut -d, -f1
}

deploy_esx_servers () {
    for i in 0 1 2; do
        run_deploy() {
            esx=$(deploy_esx_server)
            unset GOVC_PASSWORD
            unset GOVC_USERNAME
            export GOVC_URL="root@$esx"
            export GOVC_INSECURE=1
            govc host.account.update -id root -password e2eFunctionalTest
            log ESX $((($i+1))) deployed at "$esx"
            echo "$esx" >> "$nimbus_esxes_list_file"
        }
        run_deploy &
    done
    wait
}

getESXes() {
    # thanks, StackOverflow!
    esxes=() # Create array
    while IFS= read -r line # Read a line
    do
        esxes+=("$line") # Append line to the array
    done < "$1"
}

deploy_vc() {

    name="VC-$((1 + RANDOM % 10000))"
    vc=$(worker nimbus-vcvadeploy --vcvaBuild "$vcva_version" "$name" \
             | tee /dev/tty \
             | grep "Cloudvm is running on IP" \
             | sed 's/ /\n/g' \
             | grep -m1 -e "10\..*")
    log vCenter is now available at "$vc"
    export GOVC_URL="$vc"
    export "GOVC_INSECURE=1"
    export GOVC_USERNAME="Administrator@vsphere.local"
    export GOVC_PASSWORD="Admin!23"

    log "GOVC_URL=\"$GOVC_URL\""
    log "GOVC_INSECURE=$GOVC_INSECURE"
    log "GOVC_USERNAME=\"$GOVC_USERNAME\""
    log "GOVC_PASSWORD=\"$GOVC_PASSWORD\""

    log "Adding hosts to VC"
    govc datacenter.create ha-datacenter

    getESXes "$nimbus_esxes_list_file"
    for esx in "${esxes[@]}"; do
        log Adding "$esx" to datacenter
        govc host.add -hostname="$esx" -username=root -dc=ha-datacenter -password=e2eFunctionalTest -noverify=true
    done

    log "Creating a distributed switch"
    govc dvs.create -dc=ha-datacenter test-ds
    log "Create three new distributed switch port groups for management and vm network traffic"
    govc dvs.portgroup.add -nports 12 -dc=ha-datacenter -dvs=test-ds management
    govc dvs.portgroup.add -nports 12 -dc=ha-datacenter -dvs=test-ds vm-network
    govc dvs.portgroup.add -nports 12 -dc=ha-datacenter -dvs=test-ds bridge
    log "Add the ESXi hosts to the port groups"
    for esx in "${esxes[@]}"; do
        log Adding "$esx" to port group
        govc dvs.add -dvs=test-ds -pnic=vmnic1 "$esx"
    done

    esx=${esxes[0]}
    export TEST_URL_ARRAY=$vc
    export TEST_USERNAME="Administrator@vsphere.local"
    export TEST_PASSWORD="Admin!23"
    export BRIDGE_NETWORK=bridge
    export EXTERNAL_NETWORK=vm-network
    export TEST_RESOURCE=/ha-datacenter/host/"$esx"/Resources
    export TEST_TIMEOUT=30m

    log "TEST_URL_ARRAY=$TEST_URL_ARRAY"
    log "TEST_USERNAME=$TEST_USERNAME"
    log "TEST_PASSWORD=$TEST_PASSWORD"
    log "BRIDGE_NETWORK=$BRIDGE_NETWORK"
    log "EXTERNAL_NETWORK=$EXTERNAL_NETWORK"
    log "TEST_RESOURCE=$TEST_RESOURCE"
    log "TEST_TIMEOUT=$TEST_TIMEOUT"

}

deploy_worker() { # finds the worker if it exists already
    if [[ $(ssh -C "$user"@"$nimbus" "nimbus-ctl list *worker* 2>&1 | grep \"No VM found\"") ]]; then
        worker_deploy_log="/tmp/nimbus-worker-deploy-$esx_version-$(date -u --iso-8601=seconds)"
        log "Worker not found; Deploying worker VM... Log can be found at $worker_deploy_log"
        ssh -C "$user"@"$nimbus" \
            "/mts/git/bin/nimbus-genericdeploy --type worker-template $user-worker" \
            &> "$worker_deploy_log"
    else
        worker_deploy_log=$(ls -1 -tr /tmp/nimbus-worker-deploy* | tail -n1)
        log "Worker appears to already be deployed."
        log "Kill this script and delete $worker_deploy_log if Nimbus has reaped your worker"
    fi
    vmline=$(grep "You can kill the VM with" "$worker_deploy_log")
    nimbus_env="NIMBUS=$(echo $vmline | sed 's/ /\n/g' | grep NIMBUS | cut -d= -f2)"
    worker_vm_ip=$(ssh -C "$user"@"$nimbus" "$nimbus_env nimbus-ctl ip $user-worker &2>1" | grep -m 1 $user | awk '{print $3}')
    log "Worker available at IP $worker_vm_ip"
}

main() {
    check_dependencies
    deploy_worker &&\
        deploy_esx_servers &&\
        deploy_vc
    log "Success!"
}

main
