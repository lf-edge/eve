#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
K3S_VERSION=v1.28.5+k3s1

#
# Handle any migrations needed due to updated cluster-init.sh
#   This is expected to be bumped any time:
#       - a migration is needed (new path for something)
#       - a version bump of: K3s, multus, kubevirt, cdi, longhorn
#
KUBE_VERSION=1
APPLIED_KUBE_VERSION_PATH="/var/lib/applied-kube-version"
update_Version_Set() {
    version=$1
    echo "$version" > "$APPLIED_KUBE_VERSION_PATH"
}

update_Version_Get() {
    if [ ! -f "$APPLIED_KUBE_VERSION_PATH" ]; then
        # First Boot
        echo "0"
    fi
    cat "$APPLIED_KUBE_VERSION_PATH"
}

#
# update_Failed()
# Mark failure if Status == COMP_STATUS_FAILED and DestinationKubeUpdateVersion == KUBE_VERSION
# This allows:
#   - update retry control for a given version
#   - recovery update if the eve os version is updated to another release (with a different cluster-init.sh)
#
UPDATE_STATUS_PATH=/persist/status/zedkube/KubeClusterUpdateStatus/global.json
update_Failed() {
    if [ -f $UPDATE_STATUS_PATH ]; then
        if [ "$(jq --arg gen $KUBE_VERSION '.Status==4 and .DestinationKubeUpdateVersion==$gen' < $UPDATE_STATUS_PATH)" = "true" ]; then
            return 0
        fi
    fi
    return 1
}

trigger_k3s_selfextraction() {
    # Run some k3s cli command so that binaries are self-extracted
    /usr/bin/k3s check-config >> "$INSTALL_LOG" 2>&1
}

# shellcheck source=pkg/kube/descheduler-utils.sh
. /usr/bin/descheduler-utils.sh

EdgeNodeInfoPath="/persist/status/zedagent/EdgeNodeInfo/global.json"
COMP_UPDATE_PATH="/usr/bin/update-component"

link_multus_into_k3s() {
    ln -s /var/lib/cni/bin/multus /var/lib/rancher/k3s/data/current/bin/multus
}

update_k3s() {
    logmsg "Installing K3S version $K3S_VERSION"
    mkdir -p /var/lib/k3s/bin
    /usr/bin/curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${K3S_VERSION} INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_SKIP_START=true INSTALL_K3S_BIN_DIR=/var/lib/k3s/bin sh -
    sleep 5
    logmsg "Initializing K3S version $K3S_VERSION"
    ln -s /var/lib/k3s/bin/* /usr/bin
    trigger_k3s_selfextraction
    link_multus_into_k3s
    touch /var/lib/k3s_installed_unpacked
}

# k3s_get_version: return version in form "vW.X.Y+k3sZ"
k3s_get_version() {
    if [ ! -f /var/lib/k3s/bin/k3s ]; then
        echo "v0.0.0+k3s0"
        return
    fi
    /var/lib/k3s/bin/k3s --version | awk '$1=="k3s" {print $3}' | tr -d '\n'
}

# Run on every boot before k3s starts
Update_CheckNodeComponents() {
    applied_version=$(update_Version_Get)
    if [ "$KUBE_VERSION" = "$applied_version" ]; then
        return
    fi

    if update_Failed; then
        return
    fi
    logmsg "update_HandleNode: version:$KUBE_VERSION appliedversion:$applied_version continuing"

    # Handle version specific node migrations here

    # Handle node specific updates, just k3s for now
    if [ "$(k3s_get_version)" != "$K3S_VERSION" ]; then
        publishUpdateStatus "k3s" "download"
        update_k3s
        current_k3s_version=$(k3s_get_version)
        if [ "$current_k3s_version" != "$K3S_VERSION" ]; then
            logmsg "k3s version mismatch after install:$current_k3s_version"
            publishUpdateStatus "k3s" "failed" "version mismatch after install:$current_k3s_version"
        else
            logmsg "k3s installed and unpacked or copied"
            publishUpdateStatus "k3s" "completed"
        fi
    fi
}

# Run on every boot after k3s is started
Update_CheckClusterComponents() {
    wait_for_item "update_cluster_pre"

    applied_version=$(update_Version_Get)
    if [ "$KUBE_VERSION" = "$applied_version" ]; then
        return
    fi

    if update_Failed; then
        return
    fi

    if ! update_isClusterReady; then
        return
    fi
    logmsg "update_HandleCluster: version:$KUBE_VERSION appliedversion:$applied_version continuing"

    # Handle cluster wide component updates
    for comp in multus kubevirt cdi longhorn; do
        while ! update_Component_CheckReady "$comp"; do
            logmsg "Component: $comp not ready on existing version"
            sleep 60
        done
        logmsg "Component: $comp ready on existing version"
        if update_Component_IsRunningExpectedVersion "$comp"; then
            logmsg "Component:$comp running expected version, continuing"
            publishUpdateStatus "$comp" "completed"
            continue
        fi
        if ! update_Component "$comp"; then
            logmsg "Not continuing with further updates after component:${comp} update failed"
            break
        fi
    done

    update_Version_Set "$KUBE_VERSION"
    wait_for_item "update_cluster_post"
}

# Update_RunDeschedulerOnBoot will run the descheduler to evict pods from the edge node
# on boot. This is to allow rebalancing apps via re-scheduling them with an aim to meet
# affinity as specified in the pod config.
Update_RunDeschedulerOnBoot() {
    # Currently only run once per boot
    if [ -f /tmp/descheduler-ran-onboot ]; then
        return
    fi

    if [ ! -f $EdgeNodeInfoPath ]; then
        return
    fi
    # is api ready
    if ! update_isClusterReady; then
        return
    fi
    # Don't run unless it has been installed
    if ! descheduler_install; then
        return
    fi
    # node ready and allowing scheduling
    node=$(jq -r '.DeviceName' < $EdgeNodeInfoPath | tr -d '\n' | tr '[:upper:]' '[:lower:]')
    node_count_ready=$(kubectl get "node/${node}" | grep -v SchedulingDisabled | grep -cw Ready )
    if [ "$node_count_ready" -ne 1 ]; then
        return
    fi
    # Ensure all infrastructure pods are online on node
    lhStatus=$(kubectl -n longhorn-system get daemonsets -o json | jq '.items[].status | .numberReady==.desiredNumberScheduled' | tr -d '\n')
    if [ "$lhStatus" != "truetruetrue" ]; then
        return
    fi
    kvStatus=$(kubectl -n kubevirt get daemonsets -o json | jq '.items[].status | .numberReady==.desiredNumberScheduled' | tr -d '\n')
    if [ "$kvStatus" != "true" ]; then
        return
    fi
    # Job lives persistently in cluster, cleanup after old runs
    if kubectl -n kube-system get job/descheduler-job; then
        kubectl -n kube-system delete job/descheduler-job
    fi
    kubectl apply -f /etc/descheduler-job.yaml
    touch /tmp/descheduler-ran-onboot
}

update_isClusterReady() {
    if ! kubectl cluster-info; then
        return 1
    fi

    if ! update_Helper_APIResponding; then
        return 1
    fi
    return 0
}


#
# Handle kube component updates
#
COMP_UPDATE_PATH="/usr/bin/update-component"

update_Helper_APIResponding() {
    if $COMP_UPDATE_PATH --check-api-ready; then
        return 0
    fi
    return 1
}
update_Component_CheckReady() {
    comp=$1
    if $COMP_UPDATE_PATH --versions-file /etc/expected_versions.yaml --component "$comp" --check-comp-ready; then
        return 0
    fi
    return 1
}
update_Component_Uptime() {
    comp=$1
    $COMP_UPDATE_PATH --versions-file /etc/expected_versions.yaml --component "$comp" --get-uptime
}
update_Component_IsRunningExpectedVersion() {
    comp=$1
    if $COMP_UPDATE_PATH --versions-file /etc/expected_versions.yaml --component "$comp" --compare; then
        return 0
    fi
    return 1
}

update_Component() {
    comp=$1
    # Run go app to check and apply updates and block until new version is ready
    publishUpdateStatus "$comp" "in_progress"
    if $COMP_UPDATE_PATH --versions-file /etc/expected_versions.yaml --component "$comp" --upgrade; then
        publishUpdateStatus "$comp" "completed"
        return 0
    fi
    upgrade_log_path="/persist/kubelog/upgrade-component.log"
    logmsg "update_Component comp:${comp} error starting update, see $upgrade_log_path"
    publishUpdateStatus "$comp" "failed" "error in $upgrade_log_path"
    return 1
}

publishUpdateStatus() {
    component=$1
    status=$2
    errorstr=""
    if [ ! -x "$3" ]; then
        errorstr=$3
    fi

    # If gen==0, then we are in the initial boot not updating, just installing first versions at most-likely first
    #   boot of the device.  Don't publish as this will trigger zedagent to claim baseos_updating.
    cur_version=$(update_Version_Get)
    if [ "$cur_version" = "0" ]; then
        return
    fi

    node=$(jq -r '.DeviceName' < /persist/status/zedagent/EdgeNodeInfo/global.json | tr -d '\n')
    logmsg "publishUpdateStatus() $node $component $status"

    pillarRootfs=/hostfs/containers/services/pillar/rootfs
    LD_LIBRARY_PATH=${pillarRootfs}/usr/lib/ ${pillarRootfs}/opt/zededa/bin/zedkube pubKubeClusterUpdateStatus "$node" "$component" "$status" "$KUBE_VERSION" "$errorstr"
    rc=$?
    if [ $rc -ne 0 ]; then
        logmsg "publishUpdateStatus() $node $component $status in error:$rc"
    fi
}
