#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

#K3S_VERSION=v1.26.3+k3s1
#K3S_VERSION=v1.29.0+k3s1
K3S_VERSION=v1.28.5+k3s1
KUBEVIRT_VERSION=v1.1.0
LONGHORN_VERSION=v1.5.3
CDI_VERSION=v1.56.0
Node_IP=""
MAX_K3S_RESTARTS=10
RESTART_COUNT=0
K3S_LOG_DIR="/persist/newlog/kube"
loglimitSize=$((5*1024*1024))

# install log in K3S_LOG_DIR k3s-install.log
INSTALL_LOG="${K3S_LOG_DIR}/k3s-install.log"

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
  if [ "$currentSize" -gt "$loglimitSize" ]; then
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
  gzip -k -9 ${K3S_LOG_DIR}/${fileBaseName} -c > "${K3S_LOG_DIR}/${crashLogBaseName}"
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
  echo "Trying to obtain Node IP..."
  while [ -z "$NODE_IP" ]; do
    # Find the default route interface
    default_interface="$(ip route show default | head -n 1 | awk '/default/ {print $5}')"

    # Get the IP address of the default route interface
    NODE_IP="$(ip addr show dev "$default_interface" | awk '/inet / {print $2}' | cut -d "/" -f1)"

    [ -z "$NODE_IP" ] && sleep 1
  done

  echo "Node IP Address: $ip_address"
  ip_prefix="$NODE_IP/32"

  # fill in the outbound external Interface IP prefix in multus config
  awk -v new_ip="$ip_prefix" '{gsub("IPAddressReplaceMe", new_ip)}1' /etc/multus-daemonset.yaml > /tmp/multus-daemonset.yaml
}

# kubernetes's name must be lower case and '-' instead of '_'
convert_to_k8s_compatible() {
  echo "$1" | tr '[:upper:]_' '[:lower:]-'
}

wait_for_device_name() {
  logmsg "Waiting for DeviceName from controller..."
  EdgeNodeInfoPath="/persist/status/zedagent/EdgeNodeInfo/global.json"
  while true; do
    if [ -f $EdgeNodeInfoPath ]; then
      dName=$(jq -r '.DeviceName' $EdgeNodeInfoPath)
      if [ -n "$dName" ]; then
        HOSTNAME=$(convert_to_k8s_compatible "$dName")
        break
      fi
    fi
    sleep 5
  done

  # we should have the uuid since we got the device name
  DEVUUID=$(/bin/hostname)
  # get last 5 bytes of the DEVUUID as suffix to the hostname
  DEVUUID_HASH=$(echo $DEVUUID | tail -c 6)
  HOSTNAME="$HOSTNAME-$DEVUUID_HASH"
  if ! grep -q node-name /etc/rancher/k3s/config.yaml; then
    echo "node-name: $HOSTNAME" >> /etc/rancher/k3s/config.yaml
  fi
}

check_start_k3s() {
  pgrep -f "k3s server" > /dev/null 2>&1
  if [ $? -eq 1 ]; then 
      if [ $RESTART_COUNT -lt $MAX_K3S_RESTARTS ]; then
          ## Must be after reboot, or from k3s restart
          let "RESTART_COUNT++"
          save_crash_log "k3s.log"
          if [ ! -f /var/lib/cni/bin ]; then
            copy_cni_plugin_files
          fi
          ln -s /var/lib/k3s/bin/* /usr/bin
          logmsg "Starting k3s server, restart count: $RESTART_COUNT"
          # for now, always copy to get the latest
          nohup /usr/bin/k3s server --config /etc/rancher/k3s/config.yaml &
          k3s_pid=$!
          # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
          ionice -c2 -n0 -p $k3s_pid
          # Default location where clients will look for config
          while [ ! -f /etc/rancher/k3s/k3s.yaml ]; do
            sleep 5
          done
          ln -s /etc/rancher/k3s/k3s.yaml ~/.kube/config
          cp /etc/rancher/k3s/k3s.yaml /run/.kube/k3s/k3s.yaml
          sleep 10
      fi
  fi
}

apply_multus_cni() {
  # apply multus
  sleep 10
  # get IP of the interface with the first default route, which will be used as node IP
  get_default_intf_IP_prefix
  kubectl create namespace eve-kube-app
  logmsg "Apply Multus, Node-IP: $NODE_IP"
  if ! kubectl apply -f /tmp/multus-daemonset.yaml; then
    # Give up the cpu to the containerd/k3s restart loop
    return 1
  fi
  logmsg "done applying multus"
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
        mkdir -p "$K3S_LOG_DIR"
        /usr/sbin/iscsid start
        mount --make-rshared /
        setup_cgroup
        #Check network and default routes are up
        wait_for_default_route
        check_network_connection

        tmp_name=$(/bin/hostname)
        while [[ $tmp_name = linuxkit* ]];
        do
                sleep 1
                tmp_name=$(/bin/hostname)
        done
        logmsg "Got real hostname, currently: $tmp_name"

        wait_for_device_name
        chmod o+rw /dev/null
}

apply_longhorn_disk_config() {
        node=$1
        kubectl label node $node node.longhorn.io/create-default-disk='config'
        kubectl annotate node $node node.longhorn.io/default-disks-config='[ { "path":"/persist/vault/volumes", "allowScheduling":true }]'
}

config_cluster_roles() {
  apk add openssl
  # generate user debugging-user certificates
  openssl genrsa -out /tmp/user.key 2048
  openssl req -new -key /tmp/user.key -out /tmp/user.csr -subj "/CN=debugging-user/O=rbac"
  openssl x509 -req -in /tmp/user.csr -CA /var/lib/rancher/k3s/server/tls/client-ca.crt \
    -CAkey /var/lib/rancher/k3s/server/tls/client-ca.key -CAcreateserial -out /tmp/user.crt -days 365
  user_key_base64=$(cat /tmp/user.key | base64 -w0)
  user_crt_base64=$(cat /tmp/user.crt | base64 -w0)

  # generate kubeConfigure user for debugging-user
  cp /etc/rancher/k3s/k3s.yaml /var/lib/rancher/k3s/user.yaml
  sed -i "s|client-certificate-data:.*|client-certificate-data: $user_crt_base64|g" /var/lib/rancher/k3s/user.yaml
  sed -i "s|client-key-data:.*|client-key-data: $user_key_base64|g" /var/lib/rancher/k3s/user.yaml
  cp /var/lib/rancher/k3s/user.yaml /run/.kube/k3s/user.yaml

  # apply kubernetes and kubevirt roles and binding to debugging-user
  kubectl apply -f /etc/debuguser-role-binding.yaml
  touch /var/lib/debuguser-initialized
}

check_overwrite_nsmounter() {
  ### REMOVE ME+
  # When https://github.com/longhorn/longhorn/issues/6857 is resolved, remove this 'REMOVE ME' section
  # In addition to pkg/kube/nsmounter and the copy of it in pkg/kube/Dockerfile
  longhornCsiPluginPods=$(kubectl -n longhorn-system get pod -o json | jq -r '.items[] | select(.metadata.labels.app=="longhorn-csi-plugin" and .status.phase=="Running") | .metadata.name')
  for csiPod in $longhornCsiPluginPods; do    
    kubectl -n longhorn-system exec pod/${csiPod} --container=longhorn-csi-plugin -- ls /usr/local/sbin/nsmounter.updated > /dev/null 2>@1
    if [ $? -ne 0 ]; then
      cat /usr/bin/nsmounter | kubectl -n longhorn-system exec -i pod/${csiPod} --container=longhorn-csi-plugin -- tee /usr/local/sbin/nsmounter
      if [ $? -eq 0 ]; then
        logmsg "Updated nsmounter in longhorn pod ${csiPod}"
        kubectl -n longhorn-system exec pod/${csiPod} --container=longhorn-csi-plugin -- touch /usr/local/sbin/nsmounter.updated
      fi
    fi
  done
  ### REMOVE ME-
}

HOSTNAME=""
DEVUUID=""
#Make sure all prereqs are set after /var/lib is mounted to get logging info
setup_prereqs

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

        pgrep -f "/var/lib/rancher/k3s/data/current/bin/containerd" > /dev/null 2>&1
        if [ $? -eq 1 ]; then 
                mkdir -p /run/containerd-user
                nohup /var/lib/rancher/k3s/data/current/bin/containerd --config /etc/containerd/config-k3s.toml &
                containerd_pid=$!
                logmsg "Started k3s-containerd at pid:$containerd_pid"
        fi   
        if [ -f /etc/external-boot-image.tar ]; then
                # NOTE: https://kubevirt.io/user-guide/virtual_machines/boot_from_external_source/
                # Install external-boot-image image to our eve user containerd registry.
                # This image contains just kernel and initrd to bootstrap a container image as a VM.
                # This is very similar to what we do on kvm based eve to start container as a VM.
		logmsg "trying to install new external-boot-image"
		# This import happens once per reboot
		ctr -a /run/containerd-user/containerd.sock image import /etc/external-boot-image.tar docker.io/lfedge/eve-external-boot-image:latest
		if [ $? -eq 0 ]; then
			logmsg "Successfully installed external-boot-image"
			rm -f /etc/external-boot-image.tar
		fi
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

# wait for debugging flag in /persist/k3s/wait_{flagname} if exist
wait_for_item() {
  filename="/persist/k3s/wait_$1"
  processname="k3s server"
  while true; do
    if [ -e "$filename" ]; then
      k3sproc=""
      if pgrep -x "$process_name" > /dev/null; then
        k3sproc="k3s server is running"
      else
        k3sproc="k3s server is NOT running"
      fi
      logmsg "Found $filename file. $k3sproc, Waiting for 60 seconds..."
      sleep 60
    else
      #logmsg "$filename not found. Exiting loop."
      break
    fi
  done
}

check_node_ready_k3s_running() {
  # Function to check if 'k3s server' process is running
  check_k3s_running() {
    pgrep -x "k3s server" > /dev/null
  }

  # Function to check if the Kubernetes node is ready
  check_node_ready() {
    kubectl get node | grep "$HOSTNAME" | awk '{print $2}' | grep 'Ready'
  }

  # Continuously check both conditions
  while true; do
    # Check if 'k3s server' is running
    if ! check_k3s_running; then
      K3S_RUNNING=false
      logmsg "k3s server is not running, exit wait"
      break
    fi

    # Check if the Kubernetes node is ready, apply label with device UUID
    if check_node_ready; then
      logmsg "set node lable with uuid $DEVUUID"
      kubectl label node "$HOSTNAME" node-uuid="$DEVUUID"
      break
    fi

    # Sleep for a while before checking again
    logmsg "wait 10 more sec for node to be ready on $HOSTNAME"
    sleep 10
  done
}

# Return success if all pods in existence are Running/Succeeded and Ready
# Return unix style 0 for success.  (Not 0 for false)
are_all_pods_ready() {
  not_running=$(kubectl get pods -A -o json | jq '.items[] | select(.status.phase!="Running" and .status.phase!="Succeeded")' | jq -s length)
  if [ $not_running -ne 0 ]; then
    return 1
  fi

  not_ready=$(kubectl get pods -A -o json | jq '.items[] | select(.status.phase=="Running") | .status.conditions[] | select(.type=="ContainersReady" and .status!="True")' | jq -s length)
  if [ $not_ready -ne 0 ]; then
    return 1
  fi

  #don't want to sleep here, maybe recursion?
  return 0
}

VMICONFIG_FILENAME="/run/zedkube/vmiVNC.run"
VNC_RUNNING=false
# run virtctl vnc
check_and_run_vnc() {
  pid=$(pgrep -f "/usr/bin/virtctl vnc" )
  # if remote-console config file exist, and either has not started, or need to restart
  if [ -f "$VMICONFIG_FILENAME" ] && { [ "$VNC_RUNNING" = false ] || [ -z "$pid"]; } then
    vmiName=""
    vmiPort=""

    # Read the file and extract values
    while IFS= read -r line; do
        if [[ $line == *"VMINAME:"* ]]; then
            vmiName="${line#*VMINAME:}"   # Extract the part after "VMINAME:"
            vmiName="${vmiName%%[[:space:]]*}"  # Remove leading/trailing whitespace
        elif [[ $line == *"VNCPORT:"* ]]; then
            vmiPort="${line#*VNCPORT:}"   # Extract the part after "VNCPORT:"
            vmiPort="${vmiPort%%[[:space:]]*}"  # Remove leading/trailing whitespace
        fi
    done < "$VMICONFIG_FILENAME"

    # Check if vminame and vncport were found and assign default values if not
    if [ -z "$vmiName" ] || [ -z "$vmiPort" ]; then
        logmsg "Error: VMINAME or VNCPORT is empty in $myVNCFile"
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
# NOTE: We only support zfs storage in production systems because data is persisted on zvol.
etcd_fs_ready=0
while [ $etcd_fs_ready -eq 0 ];
do
        logmsg "Waiting for /dev/zvol/persist/etcd-storage"
        sleep 1
        if [ -b /dev/zvol/persist/etcd-storage ]; then
                # blkid would also work...
                fs=$(lsblk -f -d /dev/zvol/persist/etcd-storage | grep -v FSTYPE | awk '{print $2}')
                if [ "$fs" == "ext4" ]; then
                        etcd_fs_ready=1
                fi
        fi
done
mount /dev/zvol/persist/etcd-storage /var/lib  ## This is where we persist the cluster components (etcd)
## before that, the logs in install.log will not be shown
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
                sleep 5
                logmsg "Initializing K3S version $K3S_VERSION"
                ln -s /var/lib/k3s/bin/* /usr/bin
                trigger_k3s_selfextraction
                touch /var/lib/k3s_initialized
        fi
        
        check_start_containerd
        check_start_k3s

        node_count_ready=$(kubectl get node | grep -w $HOSTNAME | grep -w Ready | wc -l)
        if [ $node_count_ready -ne 1 ]; then
          sleep 10
          continue
        fi
        node_uuid_len=$(kubectl get nodes -l node-uuid=$DEVUUID -o json | jq '.items | length')
        if [ $node_uuid_len -eq 0 ]; then
          logmsg "set node label with uuid $DEVUUID"
          kubectl label node "$HOSTNAME" node-uuid="$DEVUUID"
        fi

        if [ ! -f /var/lib/multus_initialized ]; then
          if are_all_pods_ready; then
            logmsg "Installing multus cni"
            apply_multus_cni
            # launch CNI dhcp service
            /opt/cni/bin/dhcp daemon &
          fi
          sleep 10
          continue
        fi

        # setup debug user credential, role and binding
        if [ ! -f /var/lib/debuguser-initialized ]; then
          if are_all_pods_ready; then
            config_cluster_roles
          fi
          sleep 10
          continue
        fi

        if [ ! -f /var/lib/kubevirt_initialized ]; then
          if are_all_pods_ready; then
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

            #Add feature gates
            kubectl apply -f /etc/kubevirt-features.yaml

            touch /var/lib/kubevirt_initialized
          fi
          sleep 10
          continue
        fi

        if [ ! -f /var/lib/longhorn_initialized ]; then
          if are_all_pods_ready; then
            wait_for_item "longhorn"
            logmsg "Installing longhorn version ${LONGHORN_VERSION}"
            apply_longhorn_disk_config $HOSTNAME
            #kubectl apply -f  https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_VERSION}/deploy/longhorn.yaml
            # Switch back to above once all the longhorn services use the updated go iscsi tools
            kubectl apply -f /etc/longhorn-config.yaml
            touch /var/lib/longhorn_initialized
          fi
          sleep 10
          continue
        fi

        if [ -f /var/lib/k3s_initialized ] && [ -f /var/lib/kubevirt_initialized ] && [ -f /var/lib/longhorn_initialized ]; then
                logmsg "All components initialized"
                touch /var/lib/all_components_initialized
        fi
else
        check_start_containerd
        pgrep -f "k3s server" > /dev/null 2>&1
        if [ $? -eq 1 ]; then 
            if [ $RESTART_COUNT -lt $MAX_K3S_RESTARTS ]; then
                ## Must be after reboot, or from k3s restart
                let "RESTART_COUNT++"
                save_crash_log "k3s.log"
                if [ ! -f /var/lib/cni/bin ]; then
                  copy_cni_plugin_files
                fi
                ln -s /var/lib/k3s/bin/* /usr/bin
                logmsg "Starting k3s server, restart count: $RESTART_COUNT"
                # for now, always copy to get the latest
                nohup /usr/bin/k3s server --config /etc/rancher/k3s/config.yaml &
                k3s_pid=$!
                logmsg "Looping until k3s is ready (restart path), pid:$k3s_pid"
                until kubectl get node | grep "$HOSTNAME" | awk '{print $2}' | grep 'Ready'; do sleep 5; done
                # Give the embedded etcd in k3s priority over io as its fsync latencies are critical
                ionice -c2 -n0 -p $k3s_pid
                logmsg "k3s is ready on this node, pid:$k3s_pid"
                # Default location where clients will look for config
                ln -s /etc/rancher/k3s/k3s.yaml ~/.kube/config
                cp /etc/rancher/k3s/k3s.yaml /run/.kube/k3s/k3s.yaml

                # apply multus
                if [ ! -f /var/lib/multus_initialized ]; then
                  apply_multus_cni
                fi
                # launch CNI dhcp service
                /opt/cni/bin/dhcp daemon &

                # setup debug user credential, role and binding
                if [ ! -f /var/lib/debuguser-initialized ]; then
                  config_cluster_roles
                else
                  cp /var/lib/rancher/k3s/user.yaml /run/.kube/k3s/user.yaml
                fi

            else
                logmsg "k3s is down and restart count exceeded."
            fi
        else
          if [ -e /var/lib/longhorn_initialized ]; then
            check_overwrite_nsmounter
          fi
        fi
fi
        check_log_file_size "k3s.log"
        check_log_file_size "multus.log"
        check_log_file_size "k3s-install.log"
        check_log_file_size "eve-bridge.log"
        check_and_run_vnc
        wait_for_item "wait"
        sleep 30
done
