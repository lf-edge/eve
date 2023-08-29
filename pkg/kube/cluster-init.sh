#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

K3S_VERSION=v1.26.3+k3s1
KUBEVIRT_VERSION=v0.59.0
LONGHORN_VERSION=v1.4.2
CDI_VERSION=v1.56.0
Node_IP=""
MAX_K3S_RESTARTS=5
RESTART_COUNT=0
k3slogFile="/var/lib/rancher/k3s/k3s.log"
#loglimitSize=$((50*1024*1024))  # 50MB limit
loglimitSize=$((5*1024*1024)) # XXX testing

INSTALL_LOG=/var/lib/install.log

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
  currentSize=$(wc -c <"$k3slogFile")
  if [ "$currentSize" -gt "$loglimitSize" ]; then
    if [ -f "$k3slogFile.2" ]; then
      cp "$k3slogFile.2" "$k3slogFile.3"
    fi
    if [ -f "$k3slogFile.1" ]; then
      cp "$k3slogFile.1" "$k3slogFile.2"
    fi
    cp "$k3slogFile" "$k3slogFile.1"
    cat /dev/null > "$k3slogFile"
    logmsg "k3s logfile size $currentSize rotate"
  fi
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

get_default_intf_IP_prefix() {
	# Find the default route interface
	default_interface=$(ip route show default | awk '/default/ {print $5}')

	# Get the IP address of the default route interface
	NODE_IP=$(ip addr show dev "$default_interface" | awk '/inet / {print $2}' | cut -d "/" -f1)

	echo "IP Address: $ip_address"
	ip_prefix="$NODE_IP/32"

	# fill in the outbound external Interface IP prefix in multus config
	awk -v new_ip="$ip_prefix" '{gsub("IPAddressReplaceMe", new_ip)}1' /etc/multus-daemonset.yaml > /tmp/multus-daemonset.yaml
}

wait_for_device_uuid() {
  while true; do
    if [ -f /persist/status/uuid ]; then
      sleep 5
    fi
    node_name=$(cat /persist/status/uuid)
    echo "node-name: $node_name" >> /etc/rancher/k3s/config.yaml
    break
  done
}

apply_multus_cni() {
  # apply multus
  sleep 10
  # get default ip intf ip address to be node-ip
  get_default_intf_IP_prefix
  logmsg "Apply Multus, Node-IP: $NODE_IP"
  kubectl apply -f /tmp/multus-daemonset.yaml
  logmsg "done applying multus"
  ln -s /var/lib/cni/bin/multus /var/lib/rancher/k3s/data/current/bin/multus
  # need to only do this once
  kubectl create namespace eve-kube-app
  touch /var/lib/multus_initialized
}

copy_cni_plugin_files() {
  mkdir -p /var/lib/cni/bin
  mkdir -p /opt/cni/bin
  cp /usr/libexec/cni/* /var/lib/cni/bin
  cp /usr/libexec/cni/* /opt/cni/bin
  cp /usr/bin/eve-bridge /var/lib/cni/bin
  cp /usr/bin/eve-bridge /opt/cni/bin
  logmsg "cni-plugins install"
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
        wait_for_device_uuid
}

# NOTE: We only support zfs storage in production systems because data is persisted on zvol.
# If ZFS is not available we still go ahead and provide the service but the data is lost on reboot
# because /var/lib will be on overlayfs. The only reason to allow that is to provide a quick debugging env for developers.
if [ -b /dev/zvol/persist/clustered-storage ]; then
        mount /dev/zvol/persist/clustered-storage /var/lib  ## This is where we persist the cluster components (k3s containers)
        logmsg "Using ZFS persistent storage"
else
        logmsg "WARNING: Using overlayfs non-persistent storage"
fi

#Make sure all prereqs are set after /var/lib is mounted to get logging info
setup_prereqs

date >> $INSTALL_LOG
HOSTNAME=$(/bin/hostname)
logmsg "Starting wait for hostname, currently: $HOSTNAME"
while [[ $HOSTNAME = linuxkit* ]];
do
        sleep 1
        HOSTNAME=$(/bin/hostname)
done
logmsg "Got real hostname, currently: $HOSTNAME"

# Wait for vault to unseal
vaultMgrStatusPath="/run/vaultmgr/VaultStatus/Application Data Store.json"
vaultMgrStatus=0
DataSecAtRestStatus_DATASEC_AT_REST_DISABLED=1
DataSecAtRestStatus_DATASEC_AT_REST_ENABLED=2
while [ $vaultMgrStatus -ne $DataSecAtRestStatus_DATASEC_AT_REST_DISABLED ] && [ $vaultMgrStatus -ne $DataSecAtRestStatus_DATASEC_AT_REST_ENABLED ]; 
do
        logmsg "Waiting for vault, currently: $vaultMgrStatus"
        if [ -e "$vaultMgrStatusPath" ]; then
                vaultMgrStatus=$(cat "$vaultMgrStatusPath" | jq -r .Status)
        fi 
        if [ $vaultMgrStatus -ne $DataSecAtRestStatus_DATASEC_AT_REST_DISABLED ] && [ $vaultMgrStatus -ne $DataSecAtRestStatus_DATASEC_AT_REST_ENABLED ]; then 
                sleep 1
        fi
done

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
                nohup /var/lib/rancher/k3s/data/current/bin/containerd --config /etc/containerd/config-k3s.toml &
        fi   
}
trigger_k3s_selfextraction() {
        # This is extracted when k3s server first starts
        # analysis of the k3s source shows any cli command will first extract the binaries.
        # so we'll just run one, check-config appears to be the only one which doesn't:
        # - start a long running process/server
        # - timeout connecting to a socket
        # - manipulate config/certs

        # When run on the shell this does throw some config errors, its unclear if we need this issues fixed:
        # - links: aux/ip6tables should link to iptables-detect.sh (fail)
        #- links: aux/ip6tables-restore should link to iptables-detect.sh (fail)
        #- links: aux/ip6tables-save should link to iptables-detect.sh (fail)
        #- links: aux/iptables should link to iptables-detect.sh (fail)
        #- links: aux/iptables-restore should link to iptables-detect.sh (fail)
        #- links: aux/iptables-save should link to iptables-detect.sh (fail)
        #- apparmor: enabled, but apparmor_parser missing (fail)
        #      - CONFIG_INET_XFRM_MODE_TRANSPORT: missing
        /usr/bin/k3s check-config >> $INSTALL_LOG 2>&1
}

#Forever loop every 15 secs
while true;
do
if [ ! -f /var/lib/all_components_initialized ]; then
        if [ ! -f /var/lib/k3s_initialized ]; then
                # cni plugin
                copy_cni_plugin_files
                #/var/lib is where all kubernetes components get installed.
                logmsg "Installing K3S version $K3S_VERSION"
                mkdir -p /var/lib/k3s/bin
                /usr/bin/curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${K3S_VERSION} INSTALL_K3S_SKIP_ENABLE=true INSTALL_K3S_BIN_DIR=/var/lib/k3s/bin sh -
                ln -s /var/lib/k3s/bin/* /usr/bin
                sleep 60
                logmsg "Initializing K3S version $K3S_VERSION"
                trigger_k3s_selfextraction
                check_start_containerd
                nohup /usr/bin/k3s server --config /etc/rancher/k3s/config.yaml &
                #wait until k3s is ready
                logmsg "Looping until k3s is ready"
                until kubectl get node | grep "$HOSTNAME" | awk '{print $2}' | grep 'Ready'; do sleep 5; done
                #ln -sf /persist/vault/containerd /var/lib/rancher/k3s/agent/containerd
                # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
                ionice -c2 -n0 -p $(pgrep -f "k3s server")
                logmsg "k3s is ready on this node"
                # Default location where clients will look for config
                ln -s /etc/rancher/k3s/k3s.yaml ~/.kube/config
                cp /etc/rancher/k3s/k3s.yaml /run/.kube/k3s/k3s.yaml
                touch /var/lib/k3s_initialized
        fi

        if [ ! -f /var/lib/multus_initialized ]; then
          logmsg "Installing multus cni"
          apply_multus_cni
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

                #Add feature gates
                kubectl apply -f /etc/kubevirt-features.yaml
                touch /var/lib/kubevirt_initialized
        fi

        if [ ! -f /var/lib/longhorn_initialized ]; then
                logmsg "Installing longhorn version ${LONGHORN_VERSION}"
                #kubectl apply -f  https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/longhorn.yaml
                # Switch back to above once all the longhorn services use the updated go iscsi tools
                kubectl apply -f /etc/longhorn-config.yaml
                touch /var/lib/longhorn_initialized
        fi

        if [ -f /var/lib/k3s_initialized ] && [ -f /var/lib/kubevirt_initialized ] && [ -f /var/lib/longhorn_initialized ]; then
                logmsg "All components initialized"
                touch /var/lib/all_components_initialized
        fi
else
        check_start_containerd
        if pgrep -f "k3s server" >> $INSTALL_LOG 2>&1; then
                logmsg "k3s is alive"
        else
            if [ $RESTART_COUNT -lt $MAX_K3S_RESTARTS ]; then
                ## Must be after reboot, or from k3s restart
                let "RESTART_COUNT++"
                if [ ! -f /var/lib/cni/bin ]; then
                  copy_cni_plugin_files
                fi
                ln -s /var/lib/k3s/bin/* /usr/bin
                logmsg "Starting k3s server, restart count: $RESTART_COUNT"
                # for now, always copy to get the latest
                nohup /usr/bin/k3s server --config /etc/rancher/k3s/config.yaml &
                logmsg "Looping until k3s is ready"
                until kubectl get node | grep "$HOSTNAME" | awk '{print $2}' | grep 'Ready'; do sleep 5; done
                # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
                ionice -c2 -n0 -p $(pgrep -f "k3s server")
                logmsg "k3s is ready on this node"
                # Default location where clients will look for config
                ln -s /etc/rancher/k3s/k3s.yaml ~/.kube/config
                cp /etc/rancher/k3s/k3s.yaml /run/.kube/k3s/k3s.yaml

                # apply multus
                if [ ! -f /var/lib/multus_initialized ]; then
                  apply_multus_cni
                fi
                # launch CNI dhcp service
                /opt/cni/bin/dhcp daemon &
            else
                logmsg "k3s is down and restart count exceeded."
            fi
        fi
fi
        check_log_file_size
        sleep 30
done
