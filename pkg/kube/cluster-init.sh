#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

K3S_VERSION=v1.26.3+k3s1
KUBEVIRT_VERSION=v0.59.0
LONGHORN_VERSION=v1.4.2
CDI_VERSION=v1.56.0

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
    #Make yetus happy
    logmsg "waiting for default route $iface $dest $gw $flags $refcnt $use $metric $mask $mtu $window $irtt"
    sleep 1
  done < /proc/net/route

  return 1
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
                touch /var/lib/kubevirt_initialized
        fi

        if [ ! -f /var/lib/longhorn_initialized ]; then
                logmsg "Installing longhorn version ${LONGHORN_VERSION}"
                kubectl apply -f  https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/longhorn.yaml
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
        fi
fi
        currentSize=$(wc -c <"$CTRD_LOG")
        if [ "$currentSize" -gt "$LOG_SIZE" ]; then
                cp "$CTRD_LOG" "${CTRD_LOG}.1"
                truncate -s 0 "$CTRD_LOG"
        fi
        sleep 15
done
