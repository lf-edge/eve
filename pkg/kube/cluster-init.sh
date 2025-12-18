#!/bin/sh
#
# Copyright (c) 2023-2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

NODE_IP=""
RESTART_COUNT=0
K3S_LOG_DIR="/persist/kubelog"
INSTALL_LOG="${K3S_LOG_DIR}/k3s-install.log"
CTRD_LOG="${K3S_LOG_DIR}/containerd-user.log"
HOSTNAME=""
VMICONFIG_FILENAME="/run/zedkube/vmiVNC.run"
VNC_RUNNING=false
ClusterPrefixMask=""
config_file="/etc/rancher/k3s/config.yaml"
k3s_config_file="/etc/rancher/k3s/k3s-config.yaml"
clusterStatusPort="12346"
INITIAL_WAIT_TIME=5
MAX_WAIT_TIME=$((10 * 60)) # 10 minutes in seconds, exponential backoff for k3s restart
current_wait_time=$INITIAL_WAIT_TIME
CLUSTER_WAIT_FILE="/run/kube/cluster-change-wait-ongoing"
All_PODS_READY=true
install_kubevirt=1
TRANSITION_PIPE="/tmp/cluster_transition_pipe$$"
TRANSITION_FLAG_FILE="/tmp/cluster_transition_flag"
RebootReasonFile="/persist/reboot-reason"
BootReasonFile="/persist/boot-reason"
BootReasonKubeTransition="BootReasonKubeTransition" # Must match string in types package
KUBE_ROOT_EXT4="/persist/vault/kube"
KUBE_ROOT_ZFS="/dev/zvol/persist/etcd-storage"
KUBE_ROOT_MOUNTPOINT="/var/lib"

# shellcheck source=pkg/kube/pubsub.sh
. /usr/bin/pubsub.sh
# shellcheck source=pkg/kube/descheduler-utils.sh
. /usr/bin/descheduler-utils.sh
# shellcheck source=pkg/kube/longhorn-utils.sh
. /usr/bin/longhorn-utils.sh
# Source the utility script, Dockerfile copies the script to /usr/bin
# shellcheck source=/dev/null
. /usr/bin/cluster-utils.sh
# shellcheck source=pkg/kube/cluster-update.sh
. /usr/bin/cluster-update.sh
# shellcheck source=pkg/kube/registration-utils.sh
. /usr/bin/registration-utils.sh
# shellcheck source=pkg/kube/utils.sh
. /usr/bin/utils.sh
# shellcheck source=pkg/kube/kubevirt-utils.sh
. /usr/bin/kubevirt-utils.sh
# shellcheck source=pkg/kube/tie-breaker-utils.sh
. /usr/bin/tie-breaker-utils.sh

# get cluster IP address from the cluster status file
get_cluster_node_ip() {
    if [ -z "$1" ]; then
        enc_data=$(cat "$enc_status_file")
        clusternodeip=$(echo "$enc_data" | jq -r '.ClusterIPPrefix.IP')
        echo "$clusternodeip"
    else
        echo "$1"
    fi
}

# Function to get the cluster prefix length from the cluster status file
get_cluster_prefix_len() {
    enc_data=$(cat "$enc_status_file")
    mask=$(echo "$enc_data" | jq -r '.ClusterIPPrefix.Mask')
    decoded_mask=$(echo "$mask" | base64 -d | od -An -t u1)
    prefixlen=0

    for byte in $decoded_mask; do
        case $byte in
            255) prefixlen=$((prefixlen + 8)) ;;
            254) prefixlen=$((prefixlen + 7)) ;;
            252) prefixlen=$((prefixlen + 6)) ;;
            248) prefixlen=$((prefixlen + 5)) ;;
            240) prefixlen=$((prefixlen + 4)) ;;
            224) prefixlen=$((prefixlen + 3)) ;;
            192) prefixlen=$((prefixlen + 2)) ;;
            128) prefixlen=$((prefixlen + 1)) ;;
            0) break ;;
            *) logmsg "get_cluster_prefix_len, Unexpected byte value: $byte"; exit 1 ;;
        esac
    done

    echo "/$prefixlen"
}

# Set the node IP to multus differently for single node and cluster mode
assign_multus_nodeip() {
  if [ -f /var/lib/edge-node-cluster-mode ]; then
    NODE_IP=$(get_cluster_node_ip "$1")
    ClusterPrefixMask=$(get_cluster_prefix_len)
    ip_prefix=$(ipcalc -n "$NODE_IP$ClusterPrefixMask" | cut -d "=" -f2)
    ip_prefix="$ip_prefix$ClusterPrefixMask"
    logmsg "Cluster Node IP prefix to multus: $ip_prefix with node-ip $NODE_IP"
  else
    while [ -z "$NODE_IP" ]; do
      # Find the default route interface
      default_interface="$(ip route show default | head -n 1 | awk '/default/ {print $5}')"

      # Get the first IP address of the default route interface as the node IP
      NODE_IP="$(ip addr show dev "$default_interface" | awk '/inet / {print $2}' | head -n 1 | cut -d "/" -f1)"

      [ -z "$NODE_IP" ] && sleep 1
    done

    ip_prefix="$NODE_IP/32"
    logmsg "Single Node IP prefix to multus: $ip_prefix with node-ip $NODE_IP"
  fi

  logmsg "Assign node-ip for multus with $ip_prefix"
  # fill in the outbound external Interface IP prefix in multus config
  awk -v new_ip="$ip_prefix" '{gsub("IPAddressReplaceMe", new_ip)}1' /etc/multus-daemonset.yaml > /etc/multus-daemonset-new.yaml
}

# Check for link request from k3s upgrade and create a multus link
check_for_multus_link_request() {
        if [ -f /var/lib/request-retouch-multus ]; then
                rm -f /var/lib/request-retouch-multus
                link_multus_into_k3s
        fi
}

apply_multus_cni() {
        # remove get_default_intf_IP_prefix
        #get_default_intf_IP_prefix
        if ! kubectl get namespace eve-kube-app > /dev/null 2>&1; then
                kubectl create namespace eve-kube-app
        fi
        logmsg "Apply multus-daemonset-new.yaml"
        if ! kubectl apply -f /etc/multus-daemonset-new.yaml > /dev/null 2>&1; then
                logmsg "Apply Multus, has failed, jump out now"
                return 1
        fi
        logmsg "Done applying Multus"
        link_multus_into_k3s
        # need to only do this once
        touch /var/lib/multus_initialized
        return 0
}

copy_cni_plugin_files() {
        mkdir -p /var/lib/cni/bin
        mkdir -p /opt/cni/bin
        cp /usr/libexec/cni/* /var/lib/cni/bin
        cp /usr/libexec/cni/* /opt/cni/bin
        cp /usr/bin/eve-bridge /var/lib/cni/bin
        cp /usr/bin/eve-bridge /opt/cni/bin
        logmsg "CNI plugins are installed"
}

wait_for_vault() {
        logmsg "Starting wait for Vault"
        pillarRootfs=/hostfs/containers/services/pillar/rootfs
        while ! LD_LIBRARY_PATH=${pillarRootfs}/usr/lib/ ${pillarRootfs}/opt/zededa/bin/vaultmgr waitUnsealed;
        do
                sleep 1
        done
        logmsg "Vault ready"
}

mount_kube_root() {
        persistType=$(cat /run/eve.persist_type)
        if [ "$persistType" = "zfs" ]; then
                logmsg "Using ZFS persistent storage"
                # This is formatted in vaultmgr
                logmsg "Wait for persist/etcd-storage zvol"
                while [ ! -b $KUBE_ROOT_ZFS ];
                do
                        sleep 1
                done
                mount "$KUBE_ROOT_ZFS" "$KUBE_ROOT_MOUNTPOINT"  ## This is where we persist the cluster components (etcd)
                logmsg "persist/etcd-storage available"
        elif [ "$persistType" = "ext4" ]; then
                logmsg "Using EXT4 persistent storage"
                mkdir -p "$KUBE_ROOT_EXT4"
                mount --bind "$KUBE_ROOT_EXT4" "$KUBE_ROOT_MOUNTPOINT"
        else
                logmsg "Unsupported persist type: $persistType"
        fi
}

#Prereqs
setup_prereqs () {
        modprobe tun
        modprobe vhost_net
        modprobe fuse
        modprobe iscsi_tcp
        #Needed for iscsi tools
        mkdir -p /run/lock
        rm -rf /var/log
        ln -s "$K3S_LOG_DIR" /var/log
        /usr/sbin/iscsid start
        mount --make-rshared /
        setup_cgroup
        #Check network and default routes are up
        wait_for_default_route
        check_network_connection
        wait_for_device_name
        chmod o+rw /dev/null
        wait_for_vault
        mount_kube_root
}

config_cluster_roles() {
        # remove the previous k3s-debuguser*.pem files
        # in the case of single node to cluster transition, we may not reboot,
        # and there could be more than one certs files
        rm -f /tmp/k3s-debuguser*.pem

        # generate user debugging-user certificates
        # 10 year expiration for now
        if ! /usr/bin/cert-gen -l 315360000 --ca-cert /var/lib/rancher/k3s/server/tls/client-ca.crt \
                --ca-key /var/lib/rancher/k3s/server/tls/client-ca.key \
                -o k3s-debuguser --output-dir /tmp --cert-cn debugging-user --cert-o rbac; then
                logmsg "Failed to generate debuguser cert"
                return 1
        fi
        user_key_path=$(ls -c /tmp/k3s-debuguser*.key.pem)
        user_crt_path=$(ls -c /tmp/k3s-debuguser*.cert.pem)
        user_key_base64=$(base64 -w0 < "$user_key_path")
        user_crt_base64=$(base64 -w0 < "$user_crt_path")

        # generate kubeConfigure user for debugging-user
        user_yaml_path=/var/lib/rancher/k3s/user.yaml
        cp /etc/rancher/k3s/k3s.yaml "$user_yaml_path"
        sed -i "s|client-certificate-data:.*|client-certificate-data: $user_crt_base64|g" "$user_yaml_path"
        sed -i "s|client-key-data:.*|client-key-data: $user_key_base64|g" "$user_yaml_path"
        cp "$user_yaml_path" /run/.kube/k3s/user.yaml

        # apply kubernetes and kubevirt roles and binding to debugging-user
        kubectl apply -f /etc/debuguser-role-binding.yaml
        touch /var/lib/debuguser-initialized
}

check_start_k3s() {
  # If cluster is in transition, wait until transition is complete
  if [ -f "$TRANSITION_FLAG_FILE" ]; then
    logmsg "Cluster transition in progress, waiting before starting k3s"

    # This will block until something is written to the pipe
    read -r _ < "$TRANSITION_PIPE"

    # Clean up the pipe
    rm -f "$TRANSITION_PIPE"
    logmsg "Cluster transition completed, proceeding with k3s check"
  fi

  # the cluster change code is in another task loop, so if the cluster wait is nogoing
  # don't go to start k3s in this time. wait also
  if [ -f "$CLUSTER_WAIT_FILE" ]; then
        logmsg "Cluster wait ongoing, wait for it before starting k3s"
        while [ -f "$CLUSTER_WAIT_FILE" ]; do
                sleep 5
        done
  fi

  pgrep -f "$K3S_SERVER_CMD" > /dev/null 2>&1
  if [ $? -eq 1 ]; then
        # do exponential backoff for k3s restart, but not more than MAX_WAIT_TIME
        RESTART_COUNT=$((RESTART_COUNT+1))
        logmsg "k3s server not running, restart wait time $current_wait_time, restart count: $RESTART_COUNT"
        sleep $current_wait_time
        current_wait_time=$((current_wait_time * 2))
        if [ $current_wait_time -gt $MAX_WAIT_TIME ]; then
                current_wait_time=$MAX_WAIT_TIME
        fi

        ## Must be after reboot, or from k3s restart
        save_crash_log
        ln -s /var/lib/k3s/bin/* /usr/bin
        if [ ! -d /var/lib/cni/bin ] || [ ! -d /opt/cni/bin ]; then
                copy_cni_plugin_files
        fi
        # for now, always copy to get the latest

        # start the k3s server now
        nohup /usr/bin/k3s server --config "$k3s_config_file" &

        k3s_pid=$!
        # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
        ionice -c2 -n0 -p $k3s_pid
        # Default location where clients will look for config
        # There is a very small window where this file is not available
        # while k3s is starting up
        counter=0
        while [ ! -f /etc/rancher/k3s/k3s.yaml ]; do
                sleep 5
                counter=$((counter+1))
                # to prevent infinite looping, k3s could have crashed immediately
                if [ $counter -eq 120 ]; then
                        break
                fi
        done
        mkdir -p /run/.kube/k3s
        cp /etc/rancher/k3s/k3s.yaml /run/.kube/k3s/k3s.yaml
        return 1
  else
        # k3s is running, reset the wait time to initial value
        current_wait_time=$INITIAL_WAIT_TIME
  fi
  return 0
}

external_boot_image_import() {
        if [ "$install_kubevirt" = "0" ]; then
                return 0
        fi

        # NOTE: https://kubevirt.io/user-guide/virtual_machines/boot_from_external_source/
        # Install external-boot-image image to our eve user containerd registry.
        # This image contains just kernel and initrd to bootstrap a container image as a VM.
        # This is very similar to what we do on kvm based eve to start container as a VM.

        boot_img_path="/etc/external-boot-image.tar"

        # Is containerd up?
        if ! /var/lib/k3s/bin/k3s ctr -a /run/containerd-user/containerd.sock info > /dev/null 2>&1; then
                logmsg "k3s-containerd not yet running for image import"
                return 1
        fi

        eve_external_boot_img_name="docker.io/lfedge/eve-external-boot-image"
        eve_external_boot_img_tag=$(cat /run/eve-release)
        eve_external_boot_img="${eve_external_boot_img_name}:${eve_external_boot_img_tag}"
        if /var/lib/k3s/bin/k3s crictl --runtime-endpoint=unix:///run/containerd-user/containerd.sock inspecti "$eve_external_boot_img"; then
                # Already imported
                return 0
        fi

        import_name_tag=$(tar -xOf "$boot_img_path" manifest.json | jq -r '.[0].RepoTags[0]')
        import_name=$(echo "$import_name_tag" | cut -d ':' -f 1)
        if [ "$import_name" != "$eve_external_boot_img_name" ]; then
                logmsg "external-boot-image.tar is corrupt"
                return 1
        fi

        if ! /var/lib/k3s/bin/k3s ctr -a /run/containerd-user/containerd.sock image import "$boot_img_path"; then
                logmsg "import $boot_img_path failed"
                return 1
        fi

        if ! /var/lib/k3s/bin/k3s ctr -a /run/containerd-user/containerd.sock image tag "$import_name_tag" "$eve_external_boot_img"; then
                logmsg "re-tag external-boot-image failed"
                return 1
        fi
        logmsg "Successfully installed external-boot-image $import_name_tag as $eve_external_boot_img"
        return 0
}

check_start_containerd() {
        # Needed to get the pods to start
        if [ ! -L /usr/bin/runc ]; then
                ln -s /var/lib/rancher/k3s/data/current/bin/runc /usr/bin/runc
        fi
        if [ ! -L /usr/bin/containerd-shim-runc-v2 ]; then
                ln -s /var/lib/rancher/k3s/data/current/bin/containerd-shim-runc-v2 /usr/bin/containerd-shim-runc-v2
        fi

        pgrep -f "/var/lib/rancher/k3s/data/current/bin/containerd" > /dev/null 2>&1
        if [ $? -eq 1 ]; then
                mkdir -p /run/containerd-user
                nohup /var/lib/rancher/k3s/data/current/bin/containerd --config /etc/containerd/config-k3s.toml >> $CTRD_LOG 2>&1 &
                containerd_pid=$!
                logmsg "Started k3s-containerd at pid:$containerd_pid"
        fi
}

# apply the node-uuid label to the node
apply_node_uuid_label () {
        if [ "$All_PODS_READY" = true ]; then
                logmsg "set node label with uuid $DEVUUID"
        else
                logmsg "Not all pods are ready, Continue to wait while applying node labels"
        fi
        kubectl label node "$HOSTNAME" node-uuid="$DEVUUID" --overwrite
}

node_uuid_label_set() {
        val=$(kubectl get "node/${HOSTNAME}" -o jsonpath='{.metadata.labels.node-uuid}')
        if [ "$val" != "$DEVUUID" ]; then
                return 1
        fi
        return 0
}

# reapply the node labels
reapply_node_labels() {
        apply_node_uuid_label
        apply_longhorn_disk_config "$HOSTNAME"
        # Check if the node with both labels exists, don't assume above apply worked
        node_count=$(kubectl get nodes -l node-uuid="$DEVUUID",node.longhorn.io/create-default-disk=config -o json | jq '.items | length')

        if [ "$node_count" -gt 0 ]; then
                logmsg "Node labels re-applied successfully"
                touch /var/lib/node-labels-initialized
        else
                logmsg "Failed to re-apply node labels, on $HOSTNAME, uuid $DEVUUID"
        fi
}

# Return success if all pods are Running/Succeeded and Ready
# Used in install time to control api server load
# Return unix style 0 for success.  (Not 0 for false)
are_all_pods_ready() {
        pod_json=$(kubectl get pods -A -o json)
        not_running=$(echo "$pod_json" | jq '.items[] | select(.status.phase!="Running" and .status.phase!="Succeeded")' | jq -s length)
        if [ "$not_running" -ne 0 ]; then
                return 1
        fi

        not_ready=$(echo "$pod_json" | jq '.items[] | select(.status.phase=="Running") | .status.conditions[] | select(.type=="ContainersReady" and .status!="True" and .reason!="PodCompleted")' | jq -s length)
        if [ "$not_ready" -ne 0 ]; then
                return 1
        fi

        return 0
}

# Reboot the system with a recorded reason
# Usage: reboot_with_reason "reason string"
# The "BootReasonKubeTransition" will be written to /persist/boot-reason and
# the reason will be written to /persist/reboot-reason before rebooting
reboot_with_reason() {
    local reason="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    if [ -z "$reason" ]; then
        reason="kube cluster conversion reboot"
    fi

    logmsg "Rebooting system: $reason"
    if [ ! -f "$BootReasonFile" ]; then
        echo "$BootReasonKubeTransition" > "$BootReasonFile"
    fi
    echo " [$timestamp]: $BootReasonKubeTransition, $reason" >> "$RebootReasonFile"

    # Sync to ensure the file is written to disk
    sync
    sleep 1  # Give sync a moment to complete
    # Perform the reboot
    reboot
}

# run virtctl vnc
check_and_run_vnc() {
  pid=$(pgrep -f "/usr/bin/virtctl vnc" )
  # if remote-console config file exist, and either has not started, or need to restart
  if [ -f "$VMICONFIG_FILENAME" ] && { [ "$VNC_RUNNING" = false ] || [ -z "$pid" ]; }; then
    vmiName=""
    vmiPort=""

    # Read the file and extract values
    while IFS= read -r line; do
        case "$line" in
            *"VMINAME:"*)
                vmiName="${line#*VMINAME:}"   # Extract the part after "VMINAME:"
                vmiName="${vmiName%%[[:space:]]*}"  # Remove leading/trailing whitespace
                ;;
            *"VNCPORT:"*)
                vmiPort="${line#*VNCPORT:}"   # Extract the part after "VNCPORT:"
                vmiPort="${vmiPort%%[[:space:]]*}"  # Remove leading/trailing whitespace
                ;;
        esac
    done < "$VMICONFIG_FILENAME"

    # Check if the 'vmiName' and 'vmiPort' values are empty, if so, log an error and return
    if [ -z "$vmiName" ] || [ -z "$vmiPort" ]; then
        logmsg "Error: VMINAME or VNCPORT is empty in $VMICONFIG_FILENAME"
        return 1
    fi

    logmsg "virctl vnc on vmiName: $vmiName, port $vmiPort"
    nohup /usr/bin/virtctl vnc "$vmiName" -n eve-kube-app --port "$vmiPort" --proxy-only &
    VNC_RUNNING=true
  else
    if [ ! -f "$VMICONFIG_FILENAME" ]; then
      if [ "$VNC_RUNNING" = true ]; then
        if [ -n "$pid" ]; then
            logmsg "Killing process with PID $pid"
            kill -9 "$pid"
        else
            logmsg "Error: Process not found"
        fi
      fi
      VNC_RUNNING=false
    fi
  fi
}

# get the EdgeNodeClusterStatus
enc_status_file="/run/zedkube/EdgeNodeClusterStatus/global.json"
# If the node is part of a cluster, even if the case of only one node in the cluster
# the clusrter_intf, is_bootstrap, join_serverIP, cluster_token, cluster_node_ip
# cluster_uuid are all obtained from the enc_status_file published by zedkube;
# When the kubernetes node is in 'single node' mode, these variables are empty
cluster_intf=""
is_bootstrap=""
join_serverIP=""
cluster_token=""
cluster_node_ip=""
cluster_uuid=""
convert_to_single_node=false

# get the EdgeNodeClusterStatus from zedkube publication
# Return values:
#   0 - Success: file exists and all validations passed
#   1 - File exists but validation failed (incomplete/invalid data)
#   2 - File does not exist
get_enc_status() {
    # Read the JSON data from the file, return 0 if successful, 1 if not
    if [ ! -f "$enc_status_file" ]; then
      return 2
    fi

    enc_data=$(cat "$enc_status_file")
    cluster_intf=$(echo "$enc_data" | jq -r '.ClusterInterface')
    is_bootstrap=$(echo "$enc_data" | jq -r '.BootstrapNode')
    join_serverIP=$(echo "$enc_data" | jq -r '.JoinServerIP')
    cluster_token=$(echo "$enc_data" | jq -r '.EncryptedClusterToken')
    cluster_node_ip=$(echo "$enc_data" | jq -r '.ClusterIPPrefix.IP')
    cluster_node_ip_is_ready=$(echo "$enc_data" | jq -r '.ClusterIPIsReady')
    cluster_uuid=$(echo "$enc_data" | jq -r '.ClusterID.UUID')
    if [ -n "$cluster_intf" ] && [ -n "$join_serverIP" ] && [ -n "$cluster_token" ] &&\
       [ -n "$cluster_node_ip" ] && [ "$cluster_node_ip_is_ready" = "true" ] &&\
       [ -n "$cluster_uuid" ] && [ "$cluster_uuid" != "null" ] &&\
       { [ "$is_bootstrap" = "true" ] || [ "$is_bootstrap" = "false" ]; }; then
      return 0
    else
      return 1
    fi
}

# When transitioning from single node to cluster mode, need change the controller
# provided token for the cluster

rotate_cluster_token() {
        local token="$1"
        /usr/bin/k3s token rotate --new-token "$token"
        local status=$?
        if [ $status -ne 0 ]; then
                logmsg "Failed to rotate token. Exit status: $status"
        else
                logmsg "Token rotated successfully."
        fi
        return $status
}

change_to_new_token() {
  if [ -n "$cluster_token" ]; then
    logmsg "Rotate cluster token size: ${#cluster_token}"
    rotate_cluster_token "$cluster_token"
    # Set the starttime before entering the while loop
    starttime=$(date +%s)

    while true; do
        if grep -q "server:$cluster_token" /var/lib/rancher/k3s/server/token; then
            logmsg "Token change has taken effect."
            break
        else
           currenttime=$(date +%s)
            elapsed=$((currenttime - starttime))
            if [ $elapsed -ge 60 ]; then
                # Redo the rotate_cluster_token and reset the starttime
                rotate_cluster_token "$cluster_token"
                logmsg "Rotate cluster token again by k3s."
                starttime=$(date +%s)
            fi
            logmsg "Token has not taken effect yet. Sleeping for 5 seconds..."
            sleep 5
        fi
    done
  else
    # save the content of the token file
    current_token=$(cat /var/lib/rancher/k3s/server/token)

    # let k3s generate a new token
    /usr/bin/k3s token rotate
    logmsg "Rotate Token by k3s."

    # loop to check if the token file has changed
    while true; do
      if grep -q "$current_token" /var/lib/rancher/k3s/server/token; then
        logmsg "Token change has not taken effect yet. Sleeping for 2 seconds..."
        sleep 2
      else
        logmsg "Token change has taken effect."
        break
      fi
    done
  fi
}

# monitor function to check if the cluster mode has changed, either from single node to cluster
# or from cluster to single node
#
# Return values:
#   0 - No action needed or transition initiated successfully
#
# Operational Cases:
#
# 1. NOT INITIALIZED: Skip checks until /var/lib/all_components_initialized exists
#
# 2. CLUSTER-TO-SINGLE TRANSITION (enc_status=2, enc_status_file missing):
#    - If not in cluster mode: no action
#    - Otherwise: cleanup registration, mark for single-node conversion, REBOOT
#
# 3. SINGLE-TO-CLUSTER TRANSITION (enc_status=0, no edge-node-cluster-mode flag):
#    - EdgeNodeClusterStatus valid AND node was in single mode
#    - Wait loop until valid enc_status received
#    - Mark node as cluster mode before config changes
#    - If zks registration exists: uninstall cluster components (kubevirt, longhorn) first
#    - Bootstrap node case: rotate k3s token to controller-provided token
#    - Remove old multus config, reassign with cluster node IP
#    - Remove node labels for reapplication
#    - Create transition pipe/flag for k3s restart coordination
#    - Terminate k3s process
#    - Non-bootstrap node join case: remove TLS certs, mark debuguser for reinit
#    - Provision cluster config (bootstrap or join mode)
#    - If enc_status_file disappears during wait for joining cluster: revert back to single-node, REBOOT
#    - Non-bootstrap: create transition tracking file with timestamp, if joining cluster fails repeatedly, may REBOOT
#    - Bootstrap: wait for k3s to start
#    - Signal k3s restart via pipe, cleanup transition flag
#
# 4. ALREADY IN DESIRED MODE: No action taken
#
# 5. POST-CONVERSION REGISTRATION: If base-k3s-mode flag exists, uninstall kubevirt, longhorn, apply registration
#
# REBOOT SCENARIOS:
# - Cluster-to-single: Always reboots after cleanup
# - Single-to-cluster: Only non-bootstrap nodes may reboot if join fails (see check_cluster_transition_done) repeatedly
# - Interrupted transition for non-bootstrap nodes: Reboots to single-node if enc_status_file disappears
check_cluster_config_change() {

    # only check the cluster change when it's fully initialized
    if [ ! -f /var/lib/all_components_initialized ]; then
        return 0
    fi

    get_enc_status
    enc_status=$?

    if [ $enc_status -eq 2 ]; then
      # the EdgeNodeClusterStatus file does not exist
      if [ ! -f /var/lib/edge-node-cluster-mode ]; then
        return 0
      else
        # check to see if the persistent config file exists, if yes, then we need to
        # wait until zedkube to publish the ENC status file
        if [ -f "${ENCC_FILE_PATH}" ]; then
          logmsg "EdgeNodeClusterConfig file found, but the EdgeNodeClusterStatus file is missing, wait..."
          return 0
        fi
        Registration_Cleanup
        rm /var/lib/base-k3s-mode
        touch /var/lib/convert-to-single-node
        # We're transitioning from cluster mode to single node, so reboot is still needed
        reboot_with_reason "Transition from cluster mode to single node"
      fi
    elif [ -n "$cluster_token" ] && [ "$cluster_node_ip_is_ready" = "true" ]; then
      # record we have seen this ENC status file
      if [ ! -f /var/lib/edge-node-cluster-mode ]; then
        logmsg "EdgeNodeClusterStatus file found, but the node does not have edge-node-cluster-mode"
        logmsg "*** check_cluster_config_change, before while loop. cluster_node_ip: $cluster_node_ip" # XXX
        while true; do
          if get_enc_status; then
            # got the enc_status successfully, start single node to cluster transition
            logmsg "got the EdgeNodeClusterStatus successfully"
            # mark it cluster mode before changing the config file
            touch /var/lib/edge-node-cluster-mode

            if Registration_ConfigExists; then
                # Hold on, don't apply yet, complete conversion to base mode first
                if [ ! -f /var/lib/base-k3s-mode ]; then
                        uninstall_components
                fi
            fi

            # rotate the token with the new token
            if [ "$is_bootstrap" = "true" ]; then
                change_to_new_token
            fi

            # remove previous multus config
            remove_multus_cni

            # redo the multus config file in /etc/multus-daemonset-new.yaml
            logmsg "Reapply Multus CNI for clusternodeip: $cluster_node_ip"
            assign_multus_nodeip "$cluster_node_ip"

            # need to reapply node labels later
            rm /var/lib/node-labels-initialized

            mkfifo "$TRANSITION_PIPE"
            touch "$TRANSITION_FLAG_FILE"

            # restart k3s will run only if we are ready after the transition configs set
            terminate_k3s
            # romove the /var/lib/rancher/k3s/server/tls directory files
            if [ "$is_bootstrap" = "false" ]; then
              rm -rf /var/lib/rancher/k3s/server/tls/*
              # redo the debugger user role binding since certs are changed
              rm /var/lib/debuguser-initialized
            fi

            logmsg "provision config file for node to cluster mode"
            provision_cluster_config_file true
            provision_status=$?

            # If in the middle of waiting for bootstrap node to be ready, the node is converted again to single node
            # we need to get out of this loop and go back to single node mode
            if [ $provision_status -eq 1 ]; then
              logmsg "EdgeNodeClusterStatus file disappeared, reset the status and back to single node and reboot"
              rm /var/lib/base-k3s-mode
              touch /var/lib/convert-to-single-node
              reboot_with_reason "EdgeNodeClusterStatus file disappeared during cluster join, revert to single node"
            fi

            if [ "$is_bootstrap" = "false" ]; then
              # we got here because we know the bootstrap node is already running
              # For a non-bootstrap node, create transition file and record timestamp
              # This will be checked by check_cluster_transition_done function
              # We have seen in some cases, the k3s server on this node can not join the cluster
              # due to CA cert issues, and reboot is needed to get out of this state
              # so we do not always reboot here, only if it is needed
              echo "$(date +%s) 0" > /var/lib/transition-to-cluster
              logmsg "Created transition file for non-bootstrap node joining cluster"
            else
              logmsg "bootstrap node, wait for k3s to start"
            fi

            ## Allow the k3s loop to restart k3s
            echo "DONE" > "$TRANSITION_PIPE"  # Signal completion
            rm -f "$TRANSITION_FLAG_FILE"
            logmsg "WARNING: changing the node to cluster mode, k3s can restart"
            break
          else
            # In the case, check get_enc_status fails, and the EdgeNodeClusterStatus file is removed
            # we need to exit the loop and try again
            if [ ! -f "$enc_status_file" ]; then
              logmsg "EdgeNodeClusterStatus file disappeared, exit the loop and try again"
              return 0
            fi
            sleep 10
          fi
        done # end of while true
      else # enc_status exists but not in all valid states
        return 0
      fi
    fi
    logmsg "Check cluster config change done"

    ## A conversion to base-k3s mode should be complete here, now complete registration
    if [ -e /var/lib/base-k3s-mode ]; then
        Registration_CheckApply
    fi
}

# Function to check if the cluster transition is complete
check_cluster_transition_done() {
    # If the transition file does not exist, nothing to do
    if [ ! -f /var/lib/transition-to-cluster ]; then
        return 0
    fi

    logmsg "Checking cluster transition status..."

    # Try to get nodes from the cluster
    if kubectl get nodes >/dev/null 2>&1; then
        # Check if we have at least two nodes in ready state
        ready_nodes=$(kubectl get nodes --no-headers | grep -c " Ready ")
        total_nodes=$(kubectl get nodes --no-headers | wc -l)

        logmsg "Found $ready_nodes ready nodes out of $total_nodes total nodes"

        if [ "$ready_nodes" -ge 2 ]; then
            logmsg "Cluster transition complete: At least 2 nodes are ready"
            rm -f /var/lib/transition-to-cluster
            return 0
        fi
    fi

    # Check if we've been waiting too long (5 minutes)
    # File format is "timestamp reboot_count"
    # Maximum reboot attempts is 3
    file_content=$(cat /var/lib/transition-to-cluster)
    transition_timestamp=$(echo "$file_content" | awk '{print $1}')
    reboot_count=$(echo "$file_content" | awk '{print $2}')

    current_timestamp=$(date +%s)
    elapsed_time=$((current_timestamp - transition_timestamp))

    if [ "$elapsed_time" -ge 300 ]; then # 5 minutes in seconds
        logmsg "Cluster transition timeout: Been waiting for ${elapsed_time} seconds"

        # Increment reboot counter
        reboot_count=$((reboot_count + 1))

        if [ "$reboot_count" -le 3 ]; then
            # Update timestamp and reboot count in the same file
            echo "$(date +%s) $reboot_count" > /var/lib/transition-to-cluster
            logmsg "Rebooting system to retry cluster transition (attempt $reboot_count of 3)..."
            reboot_with_reason "Reboot after retry cluster transition attempt $reboot_count"
        else
            logmsg "Maximum reboot attempts (3) reached. We will not reboot again."
            # We could consider adding some recovery action here
            rm -f /var/lib/transition-to-cluster
        fi
    else
        logmsg "Still waiting for cluster transition: ${elapsed_time} seconds elapsed (timeout: 600 seconds)"
    fi

    return 1
}

monitor_cluster_config_change() {
    rm -f "$TRANSITION_FLAG_FILE"
    while true; do
        check_cluster_config_change
        check_cluster_transition_done
        sleep 15
    done
}

# started when we detect registration addition
# start cleaning up some components
# these are cluster-wide operations, only one nodes initiates it
# Marked via the Registration_Exists fence
uninstall_components() {
        touch /tmp/replicated-storage-uninstall-inprogress

        logmsg "convert-to-basek3s: wait api available"
        while ! kubectl cluster-info; do
                sleep 5
        done
        logmsg "convert-to-basek3s: kubectl cluster-info ready, wait nodes ready"
        while true; do
                # shellcheck disable=SC2281,SC2154,SC2046,SC2016
                $not_ready_nodes=$(kubectl get nodes -o go-template='{{range .items}}{{ $ready := false }}{{range .status.conditions}}{{if and (eq .type "Ready") (eq .status "True")}}{{ $ready = true }}{{end}}{{end}}{{if not $ready}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}')
                if [ "$not_ready_nodes" = "" ]; then
                        break
                fi
                sleep 5
        done
        logmsg "convert-to-basek3s: nodes ready"

        logmsg "convert-to-basek3s: Cleanup Descheduler"
        Descheduler_uninstall

        logmsg "convert-to-basek3s: Cleanup longhorn"
        Longhorn_uninstall
        rm /var/lib/longhorn_initialized

        logmsg "convert-to-basek3s: Cleanup cdi"
        Cdi_uninstall

        logmsg "convert-to-basek3s: Cleanup kubevirt"
        Kubevirt_uninstall
        rm /var/lib/kubevirt_initialized

        logmsg "convert-to-basek3s: Cleanup multus"
        Multus_uninstall
        rm /var/lib/multus_initialized

        logmsg "convert-to-basek3s: complete"
        rm /tmp/replicated-storage-uninstall-inprogress

        touch /var/lib/base-k3s-mode
        touch /var/lib/replicated-storage-uninstall-complete
}

# provision the config.yaml and bootstrap-config.yaml for cluster node, passing $1 as k3s needs initializing
# Return values:
#   0 - Success: configuration completed successfully
#   1 - enc_status_file file disappeared during bootstrap wait
provision_cluster_config_file() {
# prepare the config.yaml and bootstrap-config.yaml on node
bootstrapContent=$(cat <<- EOF
cluster-init: true
token: "${cluster_token}"
tls-san:
  - "${join_serverIP}"
flannel-iface: "${cluster_intf}"
node-ip: "${cluster_node_ip}"
node-name: "${HOSTNAME}"
EOF
      )
serverContent=$(cat <<- EOF
server: "https://${join_serverIP}:6443"
token: "${cluster_token}"
flannel-iface: "${cluster_intf}"
node-ip: "${cluster_node_ip}"
node-name: "${HOSTNAME}"
EOF
      )

    # we have 2 conditions, one is we are the bootstrap node or not, the other is we are
    # the first time configure k3s cluster or not. If both are true, then we need bootstrap config
    # otherwise, we just need normal server config to join the existing cluster
    # check if is_bootstrap is true
    if [ "$is_bootstrap" = "true" ]; then
        #Bootstrap_Node=true
        if [ "$1" = "true" ]; then
                cp "$config_file" "$k3s_config_file"
                echo "$bootstrapContent" >> "$k3s_config_file"
                logmsg "bootstrap config.yaml configured with $join_serverIP and $HOSTNAME"
        else # if we are in restart case, and we are the bootstrap node, wait for some other nodes to join
                # we go here, means we can not find node to join the cluster, we have waited long enough
                # but still put in the server config.yaml for now
                logmsg "join the cluster, use server content config.yaml"
                cp "$config_file" "$k3s_config_file"
                #echo "$bootstrapContent" >> "$k3s_config_file"
                echo "$serverContent" >> "$k3s_config_file"
        fi
    else
      # non-bootstrap node, decide if we need to wait for the join server to be ready
      #Bootstrap_Node=false
      cp "$config_file" "$k3s_config_file"
      echo "$serverContent" >> "$k3s_config_file"
      logmsg "config.yaml configured with Join-ServerIP $join_serverIP and hostname $HOSTNAME"
      if [ "$1" = true ]; then
        logmsg "Check if the Endpoint https://$join_serverIP:6443 is in cluster mode, and wait if not..."
        # Check if the join Server is available by kubernetes, wait here until it is ready
        counter=0
        touch "$CLUSTER_WAIT_FILE"

        # Initialize ping counters before the loop
        ping_success_count=0
        ping_fail_count=0

        while true; do
          counter=$((counter+1))
          if curl --insecure --max-time 2 "https://$join_serverIP:6443" >/dev/null 2>&1; then
            #logmsg "curl to Endpoint https://$join_serverIP:6443 ready, check cluster status"
            # if we are here, check the bootstrap server is single or cluster mode
            # cluster status is reported via http://<join_serverIP>:8080/status API and the result if successful is
            # cluster:<cluster-uuid>, we need to verify the cluster-uuid matches our cluster_uuid in case we are joining
            # a wrong cluster in duplicate cluster IP address
            if ! status=$(curl --max-time 2 -s "http://$join_serverIP:$clusterStatusPort/status"); then
                if [ $((counter % 30)) -eq 1 ]; then
                        logmsg "Attempt $counter: Failed to connect to the server. Waiting for 10 seconds..."
                fi
            elif echo "$status" | grep -q "^cluster:"; then
                # Extract the reported cluster UUID from the status
                reported_uuid=$(echo "$status" | cut -d':' -f2)

                # Validate the cluster UUID matches
                if [ "$reported_uuid" = "$cluster_uuid" ]; then
                    logmsg "Server is in 'cluster' status with matching UUID: $cluster_uuid. Done"
                    rm "$CLUSTER_WAIT_FILE"
                    break
                else
                    if [ $((counter % 30)) -eq 1 ]; then
                        logmsg "WARNING: Cluster UUID mismatch, may have duplicate Cluster IP address! Our UUID: $cluster_uuid, Reported UUID: $reported_uuid"
                        logmsg "Attempt $counter: Cluster UUID does not match. Waiting for 10 seconds..."
                    fi
                fi
            else
                if [ $((counter % 30)) -eq 1 ]; then
                        logmsg "Attempt $counter: Server is not in 'cluster' status (got: $status). Waiting for 10 seconds..."
                fi
            fi
          else
                # if curl failed, we want to see if ping fails on join_serverIP
                if ping -c 1 -W 1 "$join_serverIP" >/dev/null 2>&1; then
                        ping_success_count=$((ping_success_count + 1))
                        ping_result="success"
                else
                        ping_fail_count=$((ping_fail_count + 1))
                        ping_result="fail"
                fi
                if [ $((counter % 30)) -eq 1 ]; then
                        logmsg "Attempt $counter: curl to Endpoint https://$join_serverIP:6443 failed (ping $join_serverIP: $ping_result, success=$ping_success_count, fail=$ping_fail_count). Waiting for 10 seconds..."
                fi
          fi
          if [ ! -f "$enc_status_file" ]; then
                logmsg "EdgeNodeClusterStatus file disappeared, exit the loop query bootstrap status"
                rm "$CLUSTER_WAIT_FILE"
                return 1
          fi
          sleep 10
        done
      else
        logmsg "restart case with k3s already installed, no need to wait"
      fi
    fi
    return 0
}

DATESTR=$(date)
mkdir -p "$K3S_LOG_DIR"
echo "========================== $DATESTR ==========================" >> $INSTALL_LOG

setup_prereqs

wait_for_item "k3s-install"
Update_CheckNodeComponents

if [ -f /var/lib/convert-to-single-node ]; then
        logmsg "remove /var/lib and copy saved single node /var/lib"
        restore_var_lib
        logmsg "wiping unreferenced replicas"
        rm -rf /persist/vault/volumes/replicas/*
        # assign node-ip to multus nodeIP for yaml config file
        assign_multus_nodeip
        # set the variable 'convert_to_single_node' to true, in the case
        # if we immediately convert back to cluster mode, we need to wait for the
        # bootstrap status before moving on to cluster mode
        convert_to_single_node=true

        #
        # During first boot this is only set after the save var-lib process
        # So when converting back to single node its missing, set it again here.
        #
        touch /var/lib/all_components_initialized
fi
# since we can wait for long time, always start the containerd first
wait_for_item "containerd"
check_start_containerd
logmsg "containerd started"

# task running in the background to check if the cluster config has changed
monitor_cluster_config_change &

# if this is the first time to run install, we may wait for the
# cluster config and status
if [ ! -f /var/lib/all_components_initialized ]; then
  logmsg "First time for k3s install"

  # if we are in edge-node cluster mode prepare the config.yaml and bootstrap-config.yaml
  # for single node mode, we basically use the existing config.yaml
  if [ -f /var/lib/edge-node-cluster-mode ]; then
    provision_cluster_config_file true
  else
    logmsg "Single node mode prepare config.yaml for $HOSTNAME"

    # append the hostname to the config.yaml and bootstrap-config.yaml
    cp "$config_file" "$k3s_config_file"
  fi

  # assign node-ip to multus
  assign_multus_nodeip "$cluster_node_ip"
else # a restart case, found all_components_initialized
  # k3s initialized already and installed, get the config.yaml if not in cluster mode
  if [ -f /var/lib/edge-node-cluster-mode ]; then
    logmsg "Cluster config case, restarted k3s node, wait for cluster config"
    while true; do
      if get_enc_status; then
        logmsg "got the EdgeNodeClusterStatus successfully"
        break
      else
        sleep 10
      fi
    done
    # got the cluster config, make the config.ymal now
   logmsg "Cluster config status ok, provision config.yaml and bootstrap-config.yaml"

    # if we just converted to cluster mode, then we need to wait for the bootstrap
    # 'cluster' status before moving on to cluster mode
    provision_cluster_config_file $convert_to_single_node
    convert_to_single_node=false
    logmsg "provision config.yaml done"
  else # single node mode
    logmsg "Single node mode, prepare config.yaml for $HOSTNAME"
    cp "$config_file" "$k3s_config_file"
    # append the hostname to the config.yaml
    if ! grep -q node-name "$k3s_config_file"; then
      echo "node-name: $HOSTNAME" >> "$k3s_config_file"
    fi
  fi
fi

# use part of the /run/eve-release to get the OS-IMAGE string
get_eve_os_release

if ! is_amd64; then
        # no cdi support yet
        install_kubevirt=0
fi

#Forever loop every 15 secs
while true;
do
if [ ! -f /var/lib/all_components_initialized ]; then
        if ! check_start_k3s; then
                sleep 5  # Ensure minimum sleep time before retrying
                continue
        fi

        if ! external_boot_image_import; then
                continue
        fi

        # the k3s just started, may have crashed immediately, we need to continue to retry
        # instead of waiting forever
        start_time=$(date +%s)
        while [ $(($(date +%s) - start_time)) -lt 120 ]; do
            node_count_ready=$(kubectl get "node/${HOSTNAME}" | grep -cw Ready )
            if [ "$node_count_ready" -ne 1 ]; then
                sleep 10
                continue
            else
                break
            fi
        done
        if [ "$node_count_ready" -ne 1 ]; then
            continue
        fi

        # label the node with device uuid
        if ! node_uuid_label_set; then
                apply_node_uuid_label
        fi

        if ! are_all_pods_ready; then
                All_PODS_READY=false
                sleep 10
                continue
        fi
        All_PODS_READY=true

        if [ ! -f /var/lib/multus_initialized ]; then
                if [ ! -f /etc/multus-daemonset-new.yaml ]; then
                        assign_multus_nodeip "$cluster_node_ip"
                fi
                apply_multus_cni
                continue
                if [ ! -f /var/lib/multus_initialized ]; then
                        logmsg "Failed to apply multus cni, wait a while"
                        sleep 10
                        continue
                fi
        fi
        check_for_multus_link_request
        if ! pidof dhcp; then
                # if the dhcp.sock exist, then the daemon can not be restarted
                if [ -f /run/cni/dhcp.sock ]; then
                        rm /run/cni/dhcp.sock
                fi
                # launch CNI dhcp service
                /opt/cni/bin/dhcp daemon &
        fi

        # setup debug user credential, role and binding
        if [ ! -f /var/lib/debuguser-initialized ]; then
                config_cluster_roles
                continue
        fi

        if [ "$install_kubevirt" = "1" ]; then
                if [ ! -f /var/lib/kubevirt_initialized ]; then
                        wait_for_item "kubevirt"
                        Kubevirt_install

                        wait_for_item "cdi"
                        Cdi_install

                        touch /var/lib/kubevirt_initialized
                        continue
                fi
        fi

        #
        # k3s is installed now and manifests dir should exist
        #
        if [ ! -e "${KUBE_MANIFESTS_DIR}/" ]; then
                logmsg "k3s manifests dir (${KUBE_MANIFESTS_DIR}/) does not exist yet"
                continue
        fi

        # Selectively copy the manifest files.
        cp /etc/k3s-manifests/storage-classes.yaml "${KUBE_MANIFESTS_DIR}/"
        if [ -d "/opt/vendor/nvidia" ]; then
              logmsg "NVIDIA platform, copying the manifest files to ${KUBE_MANIFESTS_DIR}"
              cp /etc/k3s-manifests/nvidia-device-plugin-18.0.yml "${KUBE_MANIFESTS_DIR}/"
        fi

        #
        # Longhorn
        #
        wait_for_item "longhorn"
        if [ ! -f /var/lib/longhorn_initialized ]; then
                if ! longhorn_install "$HOSTNAME"; then
                        continue
                fi
                if ! Longhorn_is_ready; then
                        # It can take a moment for the new pods to get to ContainerCreating
                        # Just back off until they are caught by the earlier are_all_pods_ready
                        sleep 30
                        continue
                fi
                logmsg "longhorn ready"
                touch /var/lib/longhorn_initialized
        fi

        #
        # Descheduler
        #
        wait_for_item "descheduler"
        logmsg "Applying Descheduler ${DESCHEDULER_VERSION}"
        if ! descheduler_install; then
                continue
        fi


        if [ -f /var/lib/longhorn_initialized ]; then
                sleep 5
                logmsg "stop the k3s server and wait for copy /var/lib"
                terminate_k3s
                sync
                sleep 5
                save_var_lib
                logmsg "saved the copy of /var/lib, done"
                logmsg "All components initialized"
                touch /var/lib/node-labels-initialized
                touch /var/lib/all_components_initialized
        fi
else
        if ! check_start_k3s; then
                start_time=$(date +%s)
                while [ $(($(date +%s) - start_time)) -lt 120 ]; do
                    node_count_ready=$(kubectl get "node/${HOSTNAME}" | grep -cw Ready )
                    if [ "$node_count_ready" -ne 1 ]; then
                        sleep 10
                        pgrep -f "$K3S_SERVER_CMD" > /dev/null 2>&1
                        if [ $? -eq 1 ]; then
                            break
                        fi
                        continue
                    else
                        break
                    fi
                done
                if [ "$node_count_ready" -ne 1 ]; then
                    logmsg "Node not ready, continue to to check_start_k3s"
                    continue
                fi
        else
                if [ ! -f /var/lib/node-labels-initialized ]; then
                        reapply_node_labels
                fi
                if ! external_boot_image_import; then
                        continue
                fi

                # Initialize CNI after k3s reboot
                if [ ! -d /var/lib/cni/bin ] || [ ! -d /opt/cni/bin ]; then
                        copy_cni_plugin_files
                fi
                if [ ! -f /var/lib/multus_initialized ]; then
                        if [ ! -f /etc/multus-daemonset-new.yaml ]; then
                                assign_multus_nodeip "$cluster_node_ip"
                        fi
                        apply_multus_cni
                fi
                check_for_multus_link_request
                if ! pidof dhcp; then
                        # if the dhcp.sock exist, then the daemon can not be restarted
                        if [ -f /run/cni/dhcp.sock ]; then
                                rm /run/cni/dhcp.sock
                        fi
                        # launch CNI dhcp service
                        /opt/cni/bin/dhcp daemon &
                fi
                # setup debug user credential, role and binding
                if [ ! -f /var/lib/debuguser-initialized ]; then
                        config_cluster_roles
                else
                        if [ ! -e /run/.kube/k3s/user.yaml ]; then
                                cp /var/lib/rancher/k3s/user.yaml /run/.kube/k3s/user.yaml
                        fi
                fi

                if Longhorn_is_ready; then
                        check_overwrite_nsmounter
                        Tie_breaker_configApply

                        #
                        # Handle new manifests after eve baseos update
                        #
                        if [ -e "${KUBE_MANIFESTS_DIR}/" ]; then
                                if ! Registration_Applied; then
                                        # Replicated Storage wants extra storage classes
                                        if [ ! -e "${KUBE_MANIFESTS_DIR}/storage-classes.yaml" ]; then
                                                cp /etc/k3s-manifests/storage-classes.yaml "${KUBE_MANIFESTS_DIR}/storage-classes.yaml"
                                        fi
                                else
                                        # Base Mode does not want extra pre-installed storage classes
                                        cleanup_storageclasses
                                fi
                        fi
                fi
                if [ ! -e /var/lib/longhorn_configured ]; then
                        longhorn_post_install_config
                        touch /var/lib/longhorn_configured
                fi
        fi
fi
        check_log_file_size "k3s.log"
        check_log_file_size "multus.log"
        check_log_file_size "k3s-install.log"
        check_log_file_size "eve-bridge.log"
        check_log_file_size "containerd-user.log"
        check_kubeconfig_yaml_files
        check_and_remove_excessive_k3s_logs
        check_and_run_vnc
        if ! Registration_Applied; then
                # Upgrades declared via EVE baseOS updates
                Update_CheckClusterComponents
                Update_RunDeschedulerOnBoot
        fi
        wait_for_item "wait"
        sleep 15
done
