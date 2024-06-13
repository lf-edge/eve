#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

K3S_VERSION=v1.28.5+k3s1
KUBEVIRT_VERSION=v1.1.0
LONGHORN_VERSION=v1.6.2
CDI_VERSION=v1.54.0
NODE_IP=""
MAX_K3S_RESTARTS=10
RESTART_COUNT=0
K3S_LOG_DIR="/persist/kubelog"
INSTALL_LOG="${K3S_LOG_DIR}/k3s-install.log"
CTRD_LOG="${K3S_LOG_DIR}/containerd-user.log"
LOG_SIZE=$((5*1024*1024))
HOSTNAME=""
VMICONFIG_FILENAME="/run/zedkube/vmiVNC.run"
VNC_RUNNING=false
ClusterPrefixMask="/28"
multus_source_dir="/var/lib/cni/multus/results"
multus_dest_dir="/run/kube/multus"
search_multus_string="-net"
config_file="/etc/rancher/k3s/config.yaml"
k3s_config_file="/etc/rancher/k3s/k3s-config.yaml"
k3s_last_start_time=""


logmsg() {
        local MSG
        local TIME
        MSG="$*"
        TIME=$(date +"%F %T")
        echo "$TIME : $MSG"  >> $INSTALL_LOG
}

setup_cgroup () {
        echo "cgroup /sys/fs/cgroup cgroup defaults 0 0" >> /etc/fstab
}

check_log_file_size() {
        currentSize=$(wc -c <"$K3S_LOG_DIR/$1")
        if [ "$currentSize" -gt "$LOG_SIZE" ]; then
                if [ -f "$K3S_LOG_DIR/$1.2" ]; then
                        cp "$K3S_LOG_DIR/$1.2" "$K3S_LOG_DIR/$1.3"
                fi
                if [ -f "$K3S_LOG_DIR/$1.1" ]; then
                        cp "$K3S_LOG_DIR/$1.1" "$K3S_LOG_DIR/$1.2"
                fi
                cp "$K3S_LOG_DIR/$1" "$K3S_LOG_DIR/$1.1"
                truncate -s 0 "$K3S_LOG_DIR/$1"
                logmsg "k3s logfile $1, size $currentSize rotate"
        fi
}

save_crash_log() {
        if [ "$RESTART_COUNT" = "1" ]; then
                return
        fi
        fileBaseName=$1
        # This pattern will alias with older crashes, but also a simple way to contain log bloat
        crashLogBaseName="${fileBaseName}.restart.${RESTART_COUNT}.gz"
        if [ -e "${K3S_LOG_DIR}/${crashLogBaseName}" ]; then
                rm "${K3S_LOG_DIR}/${crashLogBaseName}"
        fi
        gzip -k -9 "${K3S_LOG_DIR}/${fileBaseName}" -c > "${K3S_LOG_DIR}/${crashLogBaseName}"
}

check_network_connection () {
        while true; do
                ret=$(curl -o /dev/null -w "%{http_code}" -s "https://get.k3s.io")
                if [ "$ret" -eq 200 ]; then
                        logmsg "Network is ready."
                        break;
                else
                        logmsg "Network is not yet ready"
                fi
                sleep 5
        done
}

wait_for_default_route() {
        while read -r iface dest gw flags refcnt use metric mask mtu window irtt; do
                if [ "$dest" = "00000000" ] && [ "$mask" = "00000000" ]; then
                        logmsg "Default route found"
                        return 0
                fi
                logmsg "waiting for default route $iface $dest $gw $flags $refcnt $use $metric $mask $mtu $window $irtt"
                sleep 1
        done < /proc/net/route
        return 1
}

assign_multus_nodeip() {
  if [ -f /var/lib/edge-node-cluster-mode ]; then
    NODE_IP=$1
    ip_prefix=$(ipcalc -n "$NODE_IP$ClusterPrefixMask" | cut -d "=" -f2)
    ip_prefix="$ip_prefix$ClusterPrefixMask"
    logmsg "Cluster Node IP prefix to multus: $ip_prefix with node-ip $NODE_IP"
  else
    while [ -z "$NODE_IP" ]; do
      # Find the default route interface
      default_interface="$(ip route show default | head -n 1 | awk '/default/ {print $5}')"

      # Get the IP address of the default route interface
      NODE_IP="$(ip addr show dev "$default_interface" | awk '/inet / {print $2}' | cut -d "/" -f1)"

      [ -z "$NODE_IP" ] && sleep 1
    done

    ip_prefix="$NODE_IP/32"
    logmsg "Single Node IP prefix to multus: $ip_prefix with node-ip $NODE_IP"
  fi

  logmsg "Assign node-ip for multis with $ip_prefix"
  # fill in the outbound external Interface IP prefix in multus config
  awk -v new_ip="$ip_prefix" '{gsub("IPAddressReplaceMe", new_ip)}1' /etc/multus-daemonset.yaml > /etc/multus-daemonset-new.yaml
}

# kubernetes's name must be lower case and '-' instead of '_'
convert_to_k8s_compatible() {
        echo "$1" | tr '[:upper:]_' '[:lower:]-'
}

wait_for_device_name() {
        logmsg "Waiting for DeviceName from controller..."
        EdgeNodeInfoPath="/persist/status/zedagent/EdgeNodeInfo/global.json"
        while [ ! -f $EdgeNodeInfoPath ]; do
                sleep 5
        done
        dName=$(jq -r '.DeviceName' $EdgeNodeInfoPath)
        if [ -n "$dName" ]; then
                HOSTNAME=$(convert_to_k8s_compatible "$dName")
        fi

        # we should have the uuid since we got the device name
        DEVUUID=$(/bin/hostname)

        if ! grep -q node-name /etc/rancher/k3s/config.yaml; then
                echo "node-name: $HOSTNAME" >> /etc/rancher/k3s/config.yaml
        fi
        logmsg "Hostname: $HOSTNAME"
}

apply_multus_cni() {
        # remove get_default_intf_IP_prefix
        #get_default_intf_IP_prefix
        if ! kubectl get namespace eve-kube-app > /dev/null 2>&1; then
                kubectl create namespace eve-kube-app
        fi
        logmsg "Apply Multus, Node-IP: $NODE_IP"
        if ! kubectl apply -f /etc/multus-daemonset-new.yaml > /dev/null 2>&1; then
                logmsg "Apply Multus, has failed, jump out now"
                return 1
        fi
        logmsg "Done applying Multus"
        ln -s /var/lib/cni/bin/multus /var/lib/rancher/k3s/data/current/bin/multus
        # need to only do this once
        touch /var/lib/multus_initialized
        return 0
}

# save the multus network allocation results to /run/kube/multus
check_and_copy_multus_results() {
  # mondified in last 3 minutes
  time_threshold=3
  if [ ! -d "$multus_dest_dir" ]; then
    mkdir -p "$multus_dest_dir"
  fi

  # remove the already deleted files from the destination directory
  for dest_file in "$multus_dest_dir"/*; do
        base_name=$(basename "$dest_file")
        # Check if the file exists in the multis source directory
        if [ ! -f "$multus_source_dir/$base_name" ]; then
                # If the file does not exist, remove it from the destination directory
                rm -f "$dest_file"
        fi
  done

  # if there is recent change in the multus files, copy them to /run/kube/multus
  find "$multus_source_dir" -type f -name "*$search_multus_string*" -mmin -$time_threshold -exec cp -p {} "$multus_dest_dir" \;
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

mount_etcd_vol() {
        # NOTE: We only support zfs storage in production systems because data is persisted on zvol.
        # This is formatted in vaultmgr
        logmsg "Wait for persist/etcd-storage zvol"
        while [ ! -b /dev/zvol/persist/etcd-storage ];
        do
                sleep 1
        done
        mount /dev/zvol/persist/etcd-storage /var/lib  ## This is where we persist the cluster components (etcd)
        logmsg "persist/etcd-storage available"
}

#Prereqs
setup_prereqs () {
        modprobe tun
        modprobe vhost_net
        modprobe fuse
        modprobe iscsi_tcp
        #Needed for iscsi tools
        mkdir -p /run/lock
        mkdir -p "$K3S_LOG_DIR"
        /usr/sbin/iscsid start
        mount --make-rshared /
        setup_cgroup
        #Check network and default routes are up
        wait_for_default_route
        check_network_connection
        wait_for_device_name
        chmod o+rw /dev/null
        wait_for_vault
        mount_etcd_vol
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

apply_longhorn_disk_config() {
        node=$1
        kubectl label node "$node" node.longhorn.io/create-default-disk='config'
        kubectl annotate node "$node" node.longhorn.io/default-disks-config='[ { "path":"/persist/vault/volumes", "allowScheduling":true }]'
}

check_overwrite_nsmounter() {
        ### REMOVE ME+
        # When https://github.com/longhorn/longhorn/issues/6857 is resolved, remove this 'REMOVE ME' section
        # In addition to pkg/kube/nsmounter and the copy of it in pkg/kube/Dockerfile
        longhornCsiPluginPods=$(kubectl -n longhorn-system get pod -o json | jq -r '.items[] | select(.metadata.labels.app=="longhorn-csi-plugin" and .status.phase=="Running") | .metadata.name')
        for csiPod in $longhornCsiPluginPods; do
                if ! kubectl -n longhorn-system exec "pod/${csiPod}" --container=longhorn-csi-plugin -- ls /usr/local/sbin/nsmounter.updated > /dev/null 2>@1; then
                        if kubectl -n longhorn-system exec -i "pod/${csiPod}" --container=longhorn-csi-plugin -- tee /usr/local/sbin/nsmounter < /usr/bin/nsmounter; then
                                logmsg "Updated nsmounter in longhorn pod ${csiPod}"
                                kubectl -n longhorn-system exec "pod/${csiPod}" --container=longhorn-csi-plugin -- touch /usr/local/sbin/nsmounter.updated
                        fi
                fi
        done
        ### REMOVE ME-
}

# A spot to do persistent configuration of longhorn
# These are applied once per cluster
longhorn_post_install_config() {
        # Wait for longhorn objects to be available before patching them
        lhSettingsAvailable=$(kubectl -n longhorn-system get settings -o json | jq '.items | length>0')
        if [ "$lhSettingsAvailable" != "true" ]; then
                return
        fi
        kubectl  -n longhorn-system patch settings.longhorn.io/upgrade-checker -p '[{"op":"replace","path":"/value","value":"false"}]' --type json
        touch /var/lib/longhorn_configured
}

check_start_k3s() {
  pgrep -f "k3s server" > /dev/null 2>&1
  if [ $? -eq 1 ]; then
      # as long as the current restart count is less than the max restarts
      # if the last k3s start time is 30 minutes ago or longer, reset the restart count
      # this is in the case the device is running for a long time, but the k3s has occasional
      # crashes. We want to prevent repeated restarts in a short period of time.
      current_time=$(date +%s)
      # Check if k3s_last_start_time is set and if the difference is more than 30 minutes
      if [ -n "$k3s_last_start_time" ] && [ $((current_time - k3s_last_start_time)) -gt 1800 ] && [ $RESTART_COUNT -lt $MAX_K3S_RESTARTS ]; then
        logmsg "Resetting k3s restart count to 1, currently the counter is $RESTART_COUNT"
        RESTART_COUNT=1
      fi

      if [ $RESTART_COUNT -lt $MAX_K3S_RESTARTS ]; then
          ## Must be after reboot, or from k3s restart
          RESTART_COUNT=$((RESTART_COUNT+1))
          save_crash_log "k3s.log"
          ln -s /var/lib/k3s/bin/* /usr/bin
          if [ ! -d /var/lib/cni/bin ] || [ ! -d /opt/cni/bin ]; then
            copy_cni_plugin_files
          fi
          logmsg "Starting k3s server, restart count: $RESTART_COUNT"
          # for now, always copy to get the latest

          nohup /usr/bin/k3s server --config "$k3s_config_file" &

          # remember the k3s start time
          k3s_last_start_time=$(date +%s)

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
          ln -s /etc/rancher/k3s/k3s.yaml ~/.kube/config
          mkdir -p /run/.kube/k3s
          cp /etc/rancher/k3s/k3s.yaml /run/.kube/k3s/k3s.yaml
          return 1
      fi
  fi
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
        if [ -f /etc/external-boot-image.tar ]; then
                # NOTE: https://kubevirt.io/user-guide/virtual_machines/boot_from_external_source/
                # Install external-boot-image image to our eve user containerd registry.
                # This image contains just kernel and initrd to bootstrap a container image as a VM.
                # This is very similar to what we do on kvm based eve to start container as a VM.
                logmsg "Trying to install new external-boot-image"
                # This import happens once per reboot
                if ctr -a /run/containerd-user/containerd.sock image import /etc/external-boot-image.tar; then
                        eve_external_boot_img_tag=$(cat /run/eve-release)
                        eve_external_boot_img=docker.io/lfedge/eve-external-boot-image:"$eve_external_boot_img_tag"
                        import_tag=$(tar -xOf /etc/external-boot-image.tar manifest.json | jq -r '.[0].RepoTags[0]')
                        ctr -a /run/containerd-user/containerd.sock image tag "$import_tag" "$eve_external_boot_img"

                        logmsg "Successfully installed external-boot-image $import_tag as $eve_external_boot_img"
                        rm -f /etc/external-boot-image.tar
                fi
        fi
}
trigger_k3s_selfextraction() {
        # Analysis of the k3s source shows nearly any cli command will first self-extract a series of binaries.
        # In our case we're looking for the containerd binary.
        # k3s check-config appears to be the only cli cmd which doesn't:
        # - start a long running process/server
        # - timeout connecting to a socket
        # - manipulate config/certs

        # When run on the shell this does throw some config errors, its unclear if we need this issues fixed:
        # - links: aux/ip6tables should link to iptables-detect.sh (fail)
        # - links: aux/ip6tables-restore should link to iptables-detect.sh (fail)
        # - links: aux/ip6tables-save should link to iptables-detect.sh (fail)
        # - links: aux/iptables should link to iptables-detect.sh (fail)
        # - links: aux/iptables-restore should link to iptables-detect.sh (fail)
        # - links: aux/iptables-save should link to iptables-detect.sh (fail)
        # - apparmor: enabled, but apparmor_parser missing (fail)
        /usr/bin/k3s check-config >> $INSTALL_LOG 2>&1
}

# wait for debugging flag in /persist/k3s/wait_{flagname} if exist
wait_for_item() {
        filename="/persist/k3s/wait_$1"
        processname="k3s server"
        while [ -e "$filename" ]; do
                k3sproc=""
                if pgrep -x "$processname" > /dev/null; then
                        k3sproc="k3s server is running"
                else
                        k3sproc="k3s server is NOT running"
                fi
                logmsg "Found $filename file. $k3sproc, Waiting for 60 seconds..."
                sleep 60
        done
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

        not_ready=$(echo "$pod_json" | jq '.items[] | select(.status.phase=="Running") | .status.conditions[] | select(.type=="ContainersReady" and .status!="True")' | jq -s length)
        if [ "$not_ready" -ne 0 ]; then
                return 1
        fi

        return 0
}

# run virtctl vnc
check_and_run_vnc() {
  pid=$(pgrep -f "/usr/bin/virtctl vnc" )
  # if remote-console config file exist, and either has not started, or need to restart
  if [ -f "$VMICONFIG_FILENAME" ] && { [ "$VNC_RUNNING" = false ] || [ -z "$pid" ]; } then
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
cluster_intf=""
is_bootstrap=""
join_serverIP=""
cluster_token=""
cluster_node_ip=""
# for bootstrap node, after reboot to get neighbor node to join
join_serverPlusOne=""
join_serverPlusTwo=""
FoundENCStatus=false

get_prefix_plus_one_ip() {
        ip=$join_serverIP
        # Split the IP address into two parts
        x=$(echo $ip | cut -d'.' -f1-3)
        y=$(echo $ip | cut -d'.' -f4)

        # Increment last octet y and concatenate it to x
        y=$((y + 1))
        join_serverPlusOne="$x.$y"
        y=$((y + 1))
        join_serverPlusTwo="$x.$y"
}

# get the EdgeNodeClusterStatus from zedkube publication
get_enc_status() {
    # Read the JSON data from the file, return 0 if successful, 1 if not
    if [ ! -f "$enc_status_file" ]; then
      return 1
    fi

    enc_data=$(cat "$enc_status_file")
    cluster_intf=$(echo "$enc_data" | jq -r '.ClusterInterface')
    is_bootstrap=$(echo "$enc_data" | jq -r '.BootstrapNode')
    join_serverIP=$(echo "$enc_data" | jq -r '.JoinServerIP')
    cluster_token=$(echo "$enc_data" | jq -r '.EncryptedClusterToken')
    cluster_node_ip=$(echo "$enc_data" | jq -r '.ClusterIPPrefix.IP')
    if [ -n "$cluster_intf" ] && [ -n "$join_serverIP" ] && [ -n "$cluster_token" ] && [ -n "$cluster_node_ip" ] && ( [ "$is_bootstrap" = "true" ] || [ "$is_bootstrap" = "false" ] ); then
      get_prefix_plus_one_ip
      return 0
    else
      return 1
    fi
}

install_and_unpack_k3s() {
  logmsg "Installing K3S version $K3S_VERSION on $HOSTNAME"
  mkdir -p /var/lib/k3s/bin
  /usr/bin/curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${K3S_VERSION} INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_BIN_DIR=/var/lib/k3s/bin sh -
  sleep 5
  logmsg "Initializing K3S version $K3S_VERSION"
  ln -s /var/lib/k3s/bin/* /usr/bin
  trigger_k3s_selfextraction
  touch /var/lib/k3s_installed_unpacked
}

change_to_new_token() {
  if [ -n "$cluster_token" ]; then
    /usr/bin/k3s token rotate --new-token "$cluster_token"
    while true; do
        if grep -q "server:$cluster_token" /var/lib/rancher/k3s/server/token; then
            logmsg "Token change has taken effect."
            break
        else
            logmsg "Token has not taken effect yet. Sleeping for 2 seconds..."
            sleep 2
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

terminate_k3s() {
  # Find the process ID of 'k3s server'
  pid=$(pgrep -f 'k3s server')

  # If the process exists, kill it
  if [ ! -z "$pid" ]; then
    logmsg "Killing 'k3s server' process with PID: $pid"
    kill "$pid"
  else
    logmsg "'k3s server' process not found"
  fi
}

remove_server_tls_dir() {
  if [ -d /var/lib/rancher/k3s/server/tls ]; then
    rm /var/lib/rancher/k3s/server/tls/request-header-ca.key
    rm /var/lib/rancher/k3s/server/tls/server-ca.key
    rm /var/lib/rancher/k3s/server/tls/etcd/peer-ca.key
    rm /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt
    rm /var/lib/rancher/k3s/server/tls/request-header-ca.crt
    rm /var/lib/rancher/k3s/server/tls/etcd/server-ca.key
    rm /var/lib/rancher/k3s/server/cred/ipsec.psk
    rm /var/lib/rancher/k3s/server/tls/server-ca.crt
    rm /var/lib/rancher/k3s/server/tls/service.key
    rm /var/lib/rancher/k3s/server/tls/client-ca.crt
    rm /var/lib/rancher/k3s/server/tls/client-ca.key
    rm /var/lib/rancher/k3s/server/tls/etcd/peer-ca.crt
  fi
}

remove_multus_cni() {
        kubectl delete -f /etc/multus-daemonset-new.yaml
        rm /etc/multus-daemonset-new.yaml
        rm /var/lib/multus_initialized
}

check_cluster_config_change() {

    if [ ! -f "$enc_status_file" ]; then
      #logmsg "EdgeNodeClusterStatus file not found"
      if [ ! -f /var/lib/edge-node-cluster-mode ]; then
        return 0
      else
        # we only move to single node mode if we have seen the ENC status before
        if [ "$FoundENCStatus" = true ]; then
          logmsg "EdgeNodeClusterStatus file not found, but it was seen before, transition to single node mode"
          # remove the edge-node-cluster-mode file before changing the config file
          rm /var/lib/edge-node-cluster-mode

          cp "$config_file" "$k3s_config_file"
          #echo "cluster-reset: true" >> "$k3s_config_file"
          echo "node-name: $HOSTNAME" >> "$k3s_config_file"
          logmsg "Reset cluster, adding node-name to single-node config.yaml for $HOSTNAME"

          #provision_cluster_config_file false
          # rotate the token without given a specific token
          cluster_token=""
          change_to_new_token
            
          # remove previous multus config
          remove_multus_cni

          terminate_k3s
          # XXX needs to start the k3s server with the config and --cluster-reset flag
          # wait it to exit. then continue with normal loop
          # back to single node mode, but the database will stay in etcd instead of sqlite
          logmsg "WARNING: change the node back to single-node mode, done"
        fi
      fi
    else
      # record we have seen this ENC status file
      FoundENCStatus=true
      if [ ! -f /var/lib/edge-node-cluster-mode ]; then
        logmsg "EdgeNodeClusterStatus file found, but the node does not have edge-node-cluster-mode"
        while true; do
          if get_enc_status; then
            logmsg "got the EdgeNodeClusterStatus successfully"
            # mark it cluster mode before changing the config file
            touch /var/lib/edge-node-cluster-mode

            if [ "$is_bootstrap" = "true" ]; then
              # provision this node to cluster mode with bootastrap config
              provision_cluster_config_file true
            else
              # provision this node to cluster mode with server config, will wait for join-ip to be ready
              provision_cluster_config_file false
              # this does not seem to be needed
              # romove the /var/lib/rancher/k3s/server/tls directory
              #if [ -d /var/lib/rancher/k3s/server/tls ]; then
              #  remove_server_tls_dir
              #fi
            fi
            # rotate the token with the new token
            change_to_new_token

            # remove previous multus config
            remove_multus_cni

            # kill the process and let the loop to restart k3s
            terminate_k3s
            # romove the /var/lib/rancher/k3s/server/tls directory files
            if [ "$is_bootstrap" = "false" ]; then
              rm -rf /var/lib/rancher/k3s/server/tls/*
              # redo the debugger user role binding since certs are changed
              rm /var/lib/debuguser-initialized
            fi
            logmsg "WARNING: changing the node to cluster mode, done"
            break
          else
            sleep 10
          fi
        done
      else
        return 0
      fi
    fi
    logmsg "Check cluster config change done"
}


# provision the config.yaml and bootstrap-config.yaml for cluster node, passing $1 as k3s needs initailizing
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
    # the first time configure k3s cluster or not. If both are true, then we need boostrap config
    # otherwise, we just need normal server config to join the existing cluster
    # check if is_bootstrap is true
    if [ "$is_bootstrap" = "true" ]; then
        #Bootstrap_Node=true
        if [ "$1" = "true" ]; then
                cp "$config_file" "$k3s_config_file"
                echo "$bootstrapContent" >> "$k3s_config_file"
                logmsg "bootstrap config.yaml configured with $join_serverIP and $HOSTNAME"
        else # if we are in restart case, and we are the bootstrap node, wait for some other nodes to join
                start_time=$(date +%s)
                while [ $(($(date +%s) - start_time)) -lt 60 ]; do
                        # Get the last octet of the IP address and increment it
                        # we assum the cluster prefix has continous IP address, we check our ip plus one
                        # for enjoing the cluster
 
                        if curl --insecure --max-time 2 "https://$join_serverPlusOne:6443" >/dev/null 2>&1; then
                                logmsg "curl to Endpoint https://$join_serverPlusOne:6443 ready"
                                cp "$config_file" "$k3s_config_file"
                                echo "$serverContent" >> "$k3s_config_file"
                                return
                        fi
                        if curl --insecure --max-time 2 "https://$join_serverPlusTwo:6443" >/dev/null 2>&1; then
                                logmsg "curl to Endpoint https://$join_serverPlusTwo:6443 ready"
                                cp "$config_file" "$k3s_config_file"
                                echo "$serverContent" >> "$k3s_config_file"
                                return
                        fi
                        # https://$join_serverPlusOne:6443 is not responsive, waiting for 10 seconds
                        logmsg "curl to Endpoint https://$join_serverPlusOne:6443 and https://$join_serverPlusTwo:6443 not ready, waiting for 10 seconds"
                        sleep 10
                done
                # we go here, means we can not find node to join the cluster, we have waited long enough
                # but still put in the server config.yaml for now
                logmsg "Failed to find node to join the cluster, use server content anyway"
                cp "$config_file" "$k3s_config_file"
                #echo "$bootstrapContent" >> "$k3s_config_file"
                echo "$serverContent" >> "$k3s_config_file"
        fi
    else
      # non-bootstrap node, decide if we need to wait for the join server to be ready
      #Bootstrap_Node=false
      cp "$config_file" "$k3s_config_file"
      echo "$serverContent" >> "$k3s_config_file"
      logmsg "config.yaml configured with $join_serverIP and $HOSTNAME"
      if [ "$1" == true]; then
        logmsg "Check if the Endpoint https://$join_serverIP:6443 is responsive, and wait if not..."
        # Check if the join Server is available by kubernetes, wait here until it is ready
        while true; do
          if ! curl --insecure --max-time 2 "https://$join_serverIP:6443" >/dev/null 2>&1; then
            # https://$join_serverIP:6443 is not responsive, waiting for 10 seconds
            sleep 10
          fi
          logmsg "curl to Endpoint https://$join_serverIP:6443 ready"
          break
        done
      else
        logmsg "restart case with k3s already installed, no need to wait"
      fi
    fi
}

DATESTR=$(date)
echo "========================== $DATESTR ==========================" >> $INSTALL_LOG
echo "cluster-init.sh start for $HOSTNAME, uuid $DEVUUID" >> $INSTALL_LOG
logmsg "Using ZFS persistent storage"

setup_prereqs

# unpack k3s package and install into directories
if [ ! -f /var/lib/k3s_installed_unpacked ]; then
    install_and_unpack_k3s
    logmsg "k3s installed and unpacked or copied"
fi
# since we can wait for long time, always start the containerd first
check_start_containerd
logmsg "containerd started"

# if this is the first time to run install, we may wait for the
# cluster config and status
if [ ! -f /var/lib/all_components_initialized ]; then
  logmsg "First time for k3s install, wait for the EdgeNodeClusterStatus"

  start_time_wait=$(date +%s)
  # when it's first time to get into k3s, we give 5 minutes, to see if we will be configured
  # into a cluster mode. If not, then precede to single node mode
  # read in the EdgeNodeClusterStatus
  while true; do
    if get_enc_status; then
        logmsg "got the EdgeNodeClusterStatus successfully"
        # mark it cluster mode before changing the config file
        touch /var/lib/edge-node-cluster-mode
        break
    else
      # if we are not edge-node cluster mode, wait for 5 minutes, then move forward
      if [ ! -f /var/lib/edge-node-cluster-mode ]; then
        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time_wait))

        if [ $elapsed_time -gt 120 ]; then
          logmsg "Failed to get the EdgeNodeClusterStatus, exit now, run in single node"
          break
        fi
      fi
      sleep 10
    fi
  done

  # if we are in edge-node cluster mode prepare the config.yaml and bootstrap-config.yaml
  # for single node mode, we basically use the existing config.yaml
  if [ -f /var/lib/edge-node-cluster-mode ]; then
    provision_cluster_config_file true
  else
    logmsg "Single node mode prepare config.yaml for $HOSTNAME"

    # append the hostname to the config.yaml and bootstrap-config.yaml
    cp "$config_file" "$k3s_config_file"
    echo "node-name: $HOSTNAME" >> "$k3s_config_file"
  fi

  # assing node-ip to multus
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
    provision_cluster_config_file false
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

#Forever loop every 15 secs
while true;
do
if [ ! -f /var/lib/all_components_initialized ]; then
        if ! check_start_k3s; then
                continue
        fi

        # the k3s just started, may have crashed immediately, we need to continue to retry
        # instead of waiting forever
        start_time=$(date +%s)
        while [ $(($(date +%s) - start_time)) -lt 120 ]; do
            node_count_ready=$(kubectl get node | grep -w $HOSTNAME | grep -w Ready | wc -l)
            if [ $node_count_ready -ne 1 ]; then
                sleep 10
                continue
            else
                break
            fi
        done
        if [ $node_count_ready -ne 1 ]; then
            continue
        fi
        node_uuid_len=$(kubectl get nodes -l node-uuid="$DEVUUID" -o json | jq '.items | length')
        if [ "$node_uuid_len" -eq 0 ]; then
          logmsg "set node label with uuid $DEVUUID"
          kubectl label node "$HOSTNAME" node-uuid="$DEVUUID"
        fi

        if ! are_all_pods_ready; then
                continue
        fi

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
        if ! pidof dhcp; then
                # launch CNI dhcp service
                /opt/cni/bin/dhcp daemon &
        fi

        # setup debug user credential, role and binding
        if [ ! -f /var/lib/debuguser-initialized ]; then
                config_cluster_roles
                continue
        fi

        if [ ! -f /var/lib/kubevirt_initialized ]; then
                wait_for_item "kubevirt"
                # This patched version will be removed once the following PR https://github.com/kubevirt/kubevirt/pull/9668 is merged
                logmsg "Installing patched Kubevirt"
                kubectl apply -f /etc/kubevirt-operator.yaml
                kubectl apply -f https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-cr.yaml

                wait_for_item "cdi"
                #CDI (containerzed data importer) is need to convert qcow2/raw formats to Persistent Volumes and Data volumes
                #Since CDI goes with kubevirt we install with that.
                logmsg "Installing CDI version $CDI_VERSION"
                kubectl create -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-operator.yaml
                kubectl create -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-cr.yaml
                #Add kubevirt feature gates
                kubectl apply -f /etc/kubevirt-features.yaml

                touch /var/lib/kubevirt_initialized
                continue
        fi

        if [ ! -f /var/lib/longhorn_initialized ]; then
                wait_for_item "longhorn"
                logmsg "Installing longhorn version ${LONGHORN_VERSION}"
                apply_longhorn_disk_config "$HOSTNAME"
                lhCfgPath=/var/lib/lh-cfg-${LONGHORN_VERSION}.yaml
                if [ ! -e $lhCfgPath ]; then
                        curl -k https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/longhorn.yaml > "$lhCfgPath"
                fi
                if ! grep -q 'create-default-disk-labeled-nodes: true' "$lhCfgPath"; then
                        sed -i '/  default-setting.yaml: |-/a\    create-default-disk-labeled-nodes: true' "$lhCfgPath"
                fi
                kubectl apply -f "$lhCfgPath"
                touch /var/lib/longhorn_initialized
        fi

        if [ -f /var/lib/kubevirt_initialized ] && [ -f /var/lib/longhorn_initialized ]; then
                logmsg "All components initialized"
                touch /var/lib/all_components_initialized
        fi
else
        if ! check_start_k3s; then
                start_time=$(date +%s)
                while [ $(($(date +%s) - start_time)) -lt 120 ]; do
                    node_count_ready=$(kubectl get node | grep -w $HOSTNAME | grep -w Ready | wc -l)
                    if [ $node_count_ready -ne 1 ]; then
                        sleep 10
                        pgrep -f "k3s server" > /dev/null 2>&1
                        if [ $? -eq 1 ]; then
                            break
                        fi
                        continue
                    else
                        break
                    fi
                done
                if [ $node_count_ready -ne 1 ]; then
                    logmsg "Node not ready, continue to to check_start_k3s"
                    continue
                fi
        else
                node_uuid_len=$(kubectl get nodes -l node-uuid="$DEVUUID" -o json | jq '.items | length')
                if [ "$node_uuid_len" -eq 0 ]; then
                        logmsg "set node label with uuid $DEVUUID"
                        kubectl label node "$HOSTNAME" node-uuid="$DEVUUID"
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
                if ! pidof dhcp; then
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

                if [ -e /var/lib/longhorn_initialized ]; then
                        check_overwrite_nsmounter
                fi
                if [ ! -e /var/lib/longhorn_configured ]; then
                        longhorn_post_install_config
                fi
        fi
fi
        check_log_file_size "k3s.log"
        check_log_file_size "multus.log"
        check_log_file_size "k3s-install.log"
        check_log_file_size "eve-bridge.log"
        check_log_file_size "containerd-user.log"
        check_and_copy_multus_results
        check_cluster_config_change
        check_and_run_vnc
        wait_for_item "wait"
        sleep 15
done
