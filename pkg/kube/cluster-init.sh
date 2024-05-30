#!/bin/sh
#
# Copyright (c) 2023-2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

K3S_VERSION=v1.28.5+k3s1
KUBEVIRT_VERSION=v1.1.0
LONGHORN_VERSION=v1.6.2
CDI_VERSION=v1.54.0
NODE_IP=""
MAX_K3S_RESTARTS=10
RESTART_COUNT=0
K3S_LOG_DIR="/persist/newlog/kube"
INSTALL_LOG="${K3S_LOG_DIR}/k3s-install.log"
CTRD_LOG="${K3S_LOG_DIR}/containerd-user.log"
LOG_SIZE=$((5*1024*1024))
HOSTNAME=""
VMICONFIG_FILENAME="/run/zedkube/vmiVNC.run"
VNC_RUNNING=false

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
                logmsg "k3s logfile size $currentSize rotate"
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

# Get IP of the interface with the first default route.
# This will be then used as K3s node IP.
# XXX This is a temporary solution. Eventually, the user will be able to select
#     the cluster network interface via EdgeDevConfig.
get_default_intf_IP_prefix() {
        logmsg "Trying to obtain Node IP..."
        while [ -z "$NODE_IP" ]; do
                # Find the default route interface
                default_interface="$(ip route show default | head -n 1 | awk '/default/ {print $5}')"
                # Get the IP address of the default route interface
                NODE_IP="$(ip addr show dev "$default_interface" | awk '/inet / {print $2}' | cut -d "/" -f1)"
                [ -z "$NODE_IP" ] && sleep 1
        done
        logmsg "Node IP Address: $NODE_IP"
        ip_prefix="$NODE_IP/32"
        # Fill in the outbound external Interface IP prefix in multus config
        awk -v new_ip="$ip_prefix" '{gsub("IPAddressReplaceMe", new_ip)}1' /etc/multus-daemonset.yaml > /tmp/multus-daemonset.yaml
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
        get_default_intf_IP_prefix
        kubectl create namespace eve-kube-app
        logmsg "Apply Multus, Node-IP: $NODE_IP"
        if ! kubectl apply -f /tmp/multus-daemonset.yaml; then
                return 1
        fi
        logmsg "Done applying Multus"
        ln -s /var/lib/cni/bin/multus /var/lib/rancher/k3s/data/current/bin/multus
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
      if [ $RESTART_COUNT -lt $MAX_K3S_RESTARTS ]; then
          ## Must be after reboot, or from k3s restart
          RESTART_COUNT=$((RESTART_COUNT+1))
          save_crash_log "k3s.log"
          ln -s /var/lib/k3s/bin/* /usr/bin
          logmsg "Starting k3s server, restart count: $RESTART_COUNT"
          # for now, always copy to get the latest
          nohup /usr/bin/k3s server --config /etc/rancher/k3s/config.yaml &
          k3s_pid=$!
          # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
          ionice -c2 -n0 -p $k3s_pid
          # Default location where clients will look for config
          # There is a very small window where this file is not available
          # while k3s is starting up
          while [ ! -f /etc/rancher/k3s/k3s.yaml ]; do
            sleep 5
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
                nohup /var/lib/rancher/k3s/data/current/bin/containerd --config /etc/containerd/config-k3s.toml > $CTRD_LOG 2>&1 &
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

setup_prereqs
DATESTR=$(date)
echo "========================== $DATESTR ==========================" >> $INSTALL_LOG
echo "cluster-init.sh start for $HOSTNAME, uuid $DEVUUID" >> $INSTALL_LOG
logmsg "Using ZFS persistent storage"

#Forever loop every 15 secs
while true;
do
if [ ! -f /var/lib/all_components_initialized ]; then
        if [ ! -f /var/lib/k3s_initialized ]; then
                logmsg "Installing K3S version $K3S_VERSION on $HOSTNAME"
                mkdir -p /var/lib/k3s/bin
                /usr/bin/curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${K3S_VERSION} INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_BIN_DIR=/var/lib/k3s/bin sh -
                logmsg "Initializing K3S version $K3S_VERSION"
                ln -s /var/lib/k3s/bin/* /usr/bin
                trigger_k3s_selfextraction
                touch /var/lib/k3s_initialized
        fi

        # Be kind to the API server
        sleep 1

        check_start_containerd
        if ! check_start_k3s; then
                continue
        fi

        this_node_ready=$(kubectl get node "$HOSTNAME" -o json | jq '.status.conditions[] | select(.reason=="KubeletReady") | .status=="True"')
        if [ "$this_node_ready" != "true" ]; then
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

        if [ ! -f /var/lib/cni/bin ]; then
                copy_cni_plugin_files
        fi

        if [ ! -f /var/lib/multus_initialized ]; then
                apply_multus_cni
                continue
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

        if [ -f /var/lib/k3s_initialized ] && [ -f /var/lib/kubevirt_initialized ] && [ -f /var/lib/longhorn_initialized ]; then
                logmsg "All components initialized"
                touch /var/lib/all_components_initialized
        fi
else
        check_start_containerd
        if ! check_start_k3s; then
                while [ "$(kubectl get node "$HOSTNAME" -o json | jq '.status.conditions[] | select(.reason=="KubeletReady") | .status=="True"')" != "true" ];
                do
                        sleep 5;
                done
                # Initialize CNI after k3s reboot
                if [ ! -f /var/lib/cni/bin ]; then
                        copy_cni_plugin_files
                fi
                if [ ! -f /var/lib/multus_initialized ]; then
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
                        cp /var/lib/rancher/k3s/user.yaml /run/.kube/k3s/user.yaml
                fi
        else
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
        check_and_run_vnc
        wait_for_item "wait"
        sleep 15
done
