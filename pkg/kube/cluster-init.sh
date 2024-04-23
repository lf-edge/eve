#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

K3S_VERSION=v1.26.3+k3s1
KUBEVIRT_VERSION=v0.59.0
LONGHORN_VERSION=v1.6.0
CDI_VERSION=v1.56.0
NODE_IP=""

INSTALL_LOG=/var/lib/install.log
CTRD_LOG=/var/lib/containerd.log
LOG_SIZE=$((5*1024*1024))

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

apply_multus_cni() {
        get_default_intf_IP_prefix
        kubectl create namespace eve-kube-app
        logmsg "Apply Multus, Node-IP: $NODE_IP"
        while ! kubectl apply -f /tmp/multus-daemonset.yaml; do
                sleep 1
        done
        logmsg "Done applying Multus"
        ln -s /var/lib/cni/bin/multus /var/lib/rancher/k3s/data/current/bin/multus
        # need to only do this once
        touch /var/lib/multus_initialized
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
        /usr/sbin/iscsid start
        mount --make-rshared /
        setup_cgroup
        #Check network and default routes are up
        wait_for_default_route
        check_network_connection
        wait_for_vault
        mount_etcd_vol
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

check_start_containerd() {
        # Needed to get the pods to start
        if [ ! -L /usr/bin/runc ]; then
                ln -s /var/lib/rancher/k3s/data/current/bin/runc /usr/bin/runc
        fi
        if [ ! -L /usr/bin/containerd-shim-runc-v2 ]; then
                ln -s /var/lib/rancher/k3s/data/current/bin/containerd-shim-runc-v2 /usr/bin/containerd-shim-runc-v2
        fi

        if pgrep -f "containerd --config" >> $INSTALL_LOG 2>&1; then
                logmsg "k3s-containerd is alive"
        else
                logmsg "Starting k3s-containerd"
                mkdir -p /run/containerd-user
                nohup /var/lib/rancher/k3s/data/current/bin/containerd --config /etc/containerd/config-k3s.toml > $CTRD_LOG 2>&1 &
        fi
        if [ -f /etc/external-boot-image.tar ]; then
                # NOTE: https://kubevirt.io/user-guide/virtual_machines/boot_from_external_source/
                # Install external-boot-image image to our eve user containerd registry.
                # This image contains just kernel and initrd to bootstrap a container image as a VM.
                # This is very similar to what we do on kvm based eve to start container as a VM.
                logmsg "Trying to install new external-boot-image"
                # This import happens once per reboot
                ctr -a /run/containerd-user/containerd.sock image import /etc/external-boot-image.tar docker.io/lfedge/eve-external-boot-image:latest
                res=$?
                if [ $res -eq 0 ]; then
                        logmsg "Successfully installed external-boot-image"
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


#Make sure all prereqs are set after /var/lib is mounted to get logging info
setup_prereqs

date >> $INSTALL_LOG

#Forever loop every 15 secs
while true;
do
if [ ! -f /var/lib/all_components_initialized ]; then
        if [ ! -f /var/lib/k3s_initialized ]; then
                #/var/lib is where all kubernetes components get installed.
                logmsg "Installing K3S version $K3S_VERSION"
                mkdir -p /var/lib/k3s/bin
                /usr/bin/curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${K3S_VERSION} INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_BIN_DIR=/var/lib/k3s/bin sh -
                ln -s /var/lib/k3s/bin/* /usr/bin
                logmsg "Initializing K3S version $K3S_VERSION"
                trigger_k3s_selfextraction
                check_start_containerd
                nohup /usr/bin/k3s server --config /etc/rancher/k3s/config.yaml &
                #wait until k3s is ready
                logmsg "Looping until k3s is ready"
                while [ "$(kubectl get node "$(/bin/hostname)" -o json | jq '.status.conditions[] | select(.reason=="KubeletReady") | .status=="True"')" != "true" ];
                do
                        sleep 5;
                done
                # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
                ionice -c2 -n0 -p "$(pgrep -f "k3s server")"
                logmsg "k3s is ready on this node"
                # Default location where clients will look for config
                ln -s /etc/rancher/k3s/k3s.yaml ~/.kube/config
                touch /var/lib/k3s_initialized
        fi

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

        if [ ! -f /var/lib/kubevirt_initialized ]; then
                # This patched version will be removed once the following PR https://github.com/kubevirt/kubevirt/pull/9668 is merged
                logmsg "Installing patched Kubevirt"
                kubectl apply -f /etc/kubevirt-operator.yaml
                kubectl apply -f https://github.com/kubevirt/kubevirt/releases/download/${KUBEVIRT_VERSION}/kubevirt-cr.yaml

                #CDI (containerzed data importer) is need to convert qcow2/raw formats to Persistent Volumes and Data volumes
                #Since CDI goes with kubevirt we install with that.
                logmsg "Installing CDI version $CDI_VERSION"
                kubectl create -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-operator.yaml
                kubectl create -f https://github.com/kubevirt/containerized-data-importer/releases/download/$CDI_VERSION/cdi-cr.yaml
                #Add kubevirt feature gates
                kubectl apply -f /etc/kubevirt-features.yaml

                touch /var/lib/kubevirt_initialized
        fi

        if [ ! -f /var/lib/longhorn_initialized ]; then
                logmsg "Installing longhorn version ${LONGHORN_VERSION}"
                apply_longhorn_disk_config "$(/bin/hostname)"
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
        if pgrep k3s >> $INSTALL_LOG 2>&1; then
                logmsg "k3s is alive "
                if [ -e /var/lib/longhorn_initialized ]; then
                        check_overwrite_nsmounter
                fi
        else
                ## Must be after reboot
                ln -s /var/lib/k3s/bin/* /usr/bin
                logmsg "Starting k3s server after reboot"
                nohup /usr/bin/k3s server --config /etc/rancher/k3s/config.yaml &
                logmsg "Looping until k3s is ready"
                while [ "$(kubectl get node "$(/bin/hostname)" -o json | jq '.status.conditions[] | select(.reason=="KubeletReady") | .status=="True"')" != "true" ];
                do
                        sleep 5;
                done
                # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
                ionice -c2 -n0 -p "$(pgrep -f "k3s server")"
                logmsg "k3s is ready on this node"
                # Default location where clients will look for config
                ln -s /etc/rancher/k3s/k3s.yaml ~/.kube/config

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
        fi
fi
        currentSize=$(wc -c <"$CTRD_LOG")
        if [ "$currentSize" -gt "$LOG_SIZE" ]; then
                cp "$CTRD_LOG" "${CTRD_LOG}.1"
                truncate -s 0 "$CTRD_LOG"
        fi
        sleep 15
done
