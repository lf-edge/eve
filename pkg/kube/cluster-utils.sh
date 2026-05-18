#!/bin/sh
#
# Copyright (c) 2024 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# shellcheck source=pkg/kube/lib/config.sh
. /usr/bin/config.sh

LOG_SIZE=$((5*1024*1024))
K3s_LOG_FILE="k3s.log"
LEGACY_SAVE_KUBE_VAR_LIB_DIR="/persist/kube-save-var-lib"
SAVE_KUBE_VAR_LIB_DIR="/persist/vault/kube-save-var-lib"
K3S_SERVER_CMD="k3s server"
# shellcheck disable=SC2034
K3S_STOP_FLAG="/run/kube/k3s-stop"
# shellcheck disable=SC2034
K3S_MANUAL_START_FLAG="/run/kube/k3s-start"
TIE_BREAKER_NODE_LABEL="tie-breaker-node"
TIE_BREAKER_NODE_LABEL_SET_VALUE="true"
TIE_BREAKER_NODE_LABEL_UNSET_VALUE="false"

# Persistent location for the k3s node password.
#
# k3s reads/writes its node identity password at /etc/rancher/node/password
# inside the kube container. That path lives in the container's overlay
# upper directory, which is backed by tmpfs and is cleared on every reboot.
# Without persistence, k3s regenerates a new random password each boot, and
# the server-side k8s secret <hostname>.node-password.k3s no longer matches
# the freshly generated password. The server logs deferred validation
# warnings (NodePasswordValidationFailed), and any code path that requires
# the agent to (re)fetch a kubelet certificate from the server gets
# blocked -- which can leave the node stuck NotReady.
#
# We stash the password at /var/lib/k3s-node-password inside the kube
# container. That path is the bind-mount of /persist/vault/kube/ on the
# host, so the file lives in the TPM-sealed vault and survives reboots
# alongside the other /var/lib/*_initialized markers. As a bonus,
# save_var_lib() already does `cp -a /var/lib/. <snapshot>`, so the
# password rides along in the cluster -> single-node snapshot for free
# (no separate snapshot helper needed).
PERSIST_NODE_PASSWD_FILE="/var/lib/k3s-node-password"
RUNTIME_NODE_PASSWD_FILE="/etc/rancher/node/password"
STALE_NODE_PASSWD_FLAG="/var/lib/k3s-passwd-secret-stale"

logmsg() {
        local MSG
        local TIME
        MSG="$*"
        TIME=$(date +"%F %T")
        echo "$TIME : $MSG"  >> "$INSTALL_LOG"
}

check_network_connection () {
        # Address the case where device is installed and moved to a location with no internet access"
        # If we already installed all the components, no internet access is not an issue.
        if [ -f /var/lib/all_components_initialized ]; then
           logmsg "All components already initialized, ignoring network connection check"
           return
        fi

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

# Check if file exists and delete it. The cpu manager policy can change between releases
# which is set in config-k3s.yaml file. If previous config policy is different than new policy
# k3s will not start. So deleting on every reboot is safe approach and this file gets created again from config.
check_and_clean_cpu_manager_state() {
      local state_file="/var/lib/kubelet/cpu_manager_state"

      if [ ! -f "${state_file}" ]; then
        logmsg "$(date '+%Y-%m-%d %H:%M:%S') ${state_file} not found, nothing to do"
        return
      fi
      logmsg "$(date '+%Y-%m-%d %H:%M:%S')  deleting state file: ${state_file}"
      rm -f "${state_file}"

      return
}

setup_cgroup () {
        echo "cgroup /sys/fs/cgroup cgroup defaults 0 0" >> /etc/fstab
}

check_log_file_size() {
        currentSize=$(wc -c <"$K3S_LOG_DIR/$1")
        if [ "$currentSize" -gt "$LOG_SIZE" ]; then
                if [ -f "$K3S_LOG_DIR/$1.2" ]; then
                        cp -p "$K3S_LOG_DIR/$1.2" "$K3S_LOG_DIR/$1.3"
                fi
                if [ -f "$K3S_LOG_DIR/$1.1" ]; then
                        cp -p "$K3S_LOG_DIR/$1.1" "$K3S_LOG_DIR/$1.2"
                fi
                # keep the original log file's attributes
                cp -p "$K3S_LOG_DIR/$1" "$K3S_LOG_DIR/$1.1"
                # Check if the argument passed is "$K3s_LOG_FILE", sometimes the k3s is
                # not releasing the file descriptor, so truncate the file may not
                # take effect. Signal a HUP signal to that.
                if [ "$1" = "$K3s_LOG_FILE" ]; then
                        k3s_pids=$(pgrep -f "$K3S_SERVER_CMD")
                        if [ -n "$k3s_pids" ]; then
                                for pid in $k3s_pids; do
                                        kill -HUP "$pid"
                                        logmsg "Sent HUP signal to k3s server before truncate k3s.log size"
                                done
                        fi
                fi
                truncate -s 0 "$K3S_LOG_DIR/$1"
                logmsg "k3s logfile $1, size $currentSize rotate"
        fi
}

# search and find the last occurrence of the k3s staring string in the file
# and gzip the content from that line to the end of the file
# do the entire file if the string is not found
gzip_last_restart_part() {
    fileBaseName=$1
    targetFile=$2
    searchString="Starting k3s $K3S_VERSION"

    # Find the line number of the last occurrence of the search string, or 1 if not found
    lastLine=$(grep -n -F "$searchString" "$fileBaseName" | tail -n 1 | cut -d: -f1)
    lastLine=${lastLine:-1}

    # Extract the content from the last occurrence of the search string to the end
    tail -n +"$lastLine" "$fileBaseName" | gzip -k -9 -c > "$targetFile"
}

save_crash_log() {
        if [ "$RESTART_COUNT" = "1" ]; then
                return
        fi

        # add timestamp to the filename for clear identification
        timestamp=$(date +"%Y%m%d-%H%M%S")
        # This pattern will alias with older crashes, but also a simple way to contain log bloat
        crashLogBaseName="${K3s_LOG_FILE}.restart.${timestamp}.${RESTART_COUNT}.gz"

        gzip_last_restart_part "${K3S_LOG_DIR}/${K3s_LOG_FILE}" "${K3S_LOG_DIR}/${crashLogBaseName}"

        # Find and list files matching the pattern
        matching_files=""
        for file in "$K3S_LOG_DIR"/*; do
                if echo "$file" | grep -q "${K3s_LOG_FILE}.restart.*.gz"; then
                        matching_files="$matching_files $file"
                fi
        done
        matching_files=$(echo "$matching_files" | xargs)
        file_count=$(echo "$matching_files" | wc -w)

        logmsg "total $file_count crash logs found in dir $K3S_LOG_DIR, file prefix $K3s_LOG_FILE"
        if [ "$file_count" -gt 10 ]; then
                files_to_delete=$(find "$K3S_LOG_DIR" -type f -name "${K3s_LOG_FILE}.restart.*.gz" -print0 | xargs -0 ls -t | tail -n +11)
                echo "$files_to_delete" | while read -r file; do
                        rm -f "$file"
                done
        fi
}

# k3s can generate log files such as this: k3s-2024-07-30T20-29-31.172.log.gz
# they seem to be generated by raft operation warnings
# this check and remove is to prevent the log files from growing indefinitely
# keep the latest 10 log files and delete the rest
check_and_remove_excessive_k3s_logs() {

    # Directory to search in (current directory in this case)
    search_dir="$K3S_LOG_DIR"

    # Regular expression pattern for date and time in the format YYYY-MM-DDTHH-MM-SS.mmm
    pattern='k3s-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}-[0-9]{2}-[0-9]{2}\.[0-9]{3}\.log\.gz'

    # Find and list files matching the pattern
    matching_files=$(find "$search_dir" -type f -name 'k3s-*.log.gz' | grep -E "$pattern")
    file_count=$(echo "$matching_files" | wc -w)
    if [ "$file_count" -gt 10 ]; then
        files_to_delete=$(echo "$matching_files" | grep ".log.gz" | tail -n +11)
        echo "$files_to_delete" | while read -r file; do
                rm -f "${K3S_LOG_DIR}/${file}"
        done
    fi
}

# kubernetes's name must be lower case and '-' instead of '_'
convert_to_k8s_compatible() {
        echo "$1" | tr '[:upper:]_' '[:lower:]-'
}

# Function to check if a string is a valid UUID
is_valid_uuid() {
    local uuid="$1"
    if echo "$uuid" | grep -qE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'; then
        return 0 # Valid UUID
    else
        return 1 # Invalid UUID
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

# Restore the persisted k3s node password into the location k3s expects,
# before k3s starts. On a brand-new device the persistent file does not
# exist yet and this is a no-op; k3s will then generate a password and
# save_node_password() will persist it.
restore_node_password() {
        if [ ! -f "$PERSIST_NODE_PASSWD_FILE" ]; then
                return 0
        fi
        mkdir -p "$(dirname "$RUNTIME_NODE_PASSWD_FILE")"
        cp -p "$PERSIST_NODE_PASSWD_FILE" "$RUNTIME_NODE_PASSWD_FILE"
        chmod 600 "$RUNTIME_NODE_PASSWD_FILE"
        logmsg "restored node password from $PERSIST_NODE_PASSWD_FILE"
}

# Persist the k3s node password whenever the runtime file disagrees with
# (or is newer than) the persistent copy. Specifically: save when the
# persistent file is missing OR when its contents differ from
# /etc/rancher/node/password. When they already match, this is a no-op
# (so safe to call on every boot from the main loop).
#
# Why "different" matters and not just "missing":
#   - Brownfield first boot under the fix: persistent file is missing,
#     k3s has just generated a fresh password -> save it.
#   - Steady state after restore: contents match -> no-op.
#   - Any case where k3s writes a new password into the runtime file
#     after we restored an older one (cert rotation paths, manual
#     intervention, corrupted persistent copy): the persistent file is
#     refreshed so the next boot stays consistent with what k3s is
#     actually using.
#
# Brownfield remediation: on the first boot under this fix the persistent
# file is absent, meaning k3s generated a fresh password that no longer
# matches the hash stored in the cluster secret <hostname>.node-password.k3s.
# We set STALE_NODE_PASSWD_FLAG so that fix_node_password_secret() can delete
# the stale secret once the API server is ready. The delete is retried every
# main-loop iteration (every 15s) until it succeeds, then the flag is removed.
save_node_password() {
        if [ ! -f "$RUNTIME_NODE_PASSWD_FILE" ]; then
                return 0
        fi
        if [ -f "$PERSIST_NODE_PASSWD_FILE" ] && \
           cmp -s "$RUNTIME_NODE_PASSWD_FILE" "$PERSIST_NODE_PASSWD_FILE"; then
                return 0
        fi
        if [ ! -f "$PERSIST_NODE_PASSWD_FILE" ]; then
                touch "$STALE_NODE_PASSWD_FLAG"
        fi
        cp -p "$RUNTIME_NODE_PASSWD_FILE" "$PERSIST_NODE_PASSWD_FILE"
        chmod 600 "$PERSIST_NODE_PASSWD_FILE"
        logmsg "persisted node password to $PERSIST_NODE_PASSWD_FILE"
}

# Delete the stale cluster secret for brownfield nodes. Called from the main
# loop once k3s is running and the API server is reachable. Retries every loop
# iteration until kubectl succeeds, then removes the flag.
fix_node_password_secret() {
        [ -f "$STALE_NODE_PASSWD_FLAG" ] || return 0
        [ -n "$HOSTNAME" ] || return 0
        if kubectl -n kube-system delete secret "${HOSTNAME}.node-password.k3s" \
           --ignore-not-found >/dev/null 2>&1; then
                logmsg "deleted stale node password secret for brownfield fix"
                rm -f "$STALE_NODE_PASSWD_FLAG"
        fi
}

# save the /var/lib to /persist/kube-save-var-lib
save_var_lib() {
  local dest_dir="${SAVE_KUBE_VAR_LIB_DIR}"
  # Check if destination directory exists, if not create it
  if [ ! -d "$dest_dir" ]; then
    mkdir -p "$dest_dir"
  fi

  # Remove everything in the destination directory
  rm -rf "${dest_dir:?}"/*

  # Copy all contents from /var/lib to destination directory
  cp -a /var/lib/. "$dest_dir"
}

# Function to restore contents from /persist/kube-save-var-lib back to /var/lib
restore_var_lib() {
  local source_dir="${SAVE_KUBE_VAR_LIB_DIR}"
  # Remove everything under /var/lib
  rm -rf /var/lib/*

  # Copy everything from /persist/kube-save-var-lib back to /var/lib
  if [ -d "$source_dir" ]; then
        cp -a "${source_dir}/." /var/lib
  else
        ## the saved files are missing, have do install again
        Update_CheckNodeComponents
  fi
}

# Migrate to secure vault
migrate_var_lib() {
        if [ ! -d "$LEGACY_SAVE_KUBE_VAR_LIB_DIR" ]; then
                return
        fi
        if [ -d "$SAVE_KUBE_VAR_LIB_DIR" ]; then
                return
        fi
        logmsg "migrating $LEGACY_SAVE_KUBE_VAR_LIB_DIR to $SAVE_KUBE_VAR_LIB_DIR"
        if ! cp -a "$LEGACY_SAVE_KUBE_VAR_LIB_DIR" "$SAVE_KUBE_VAR_LIB_DIR"; then
                logmsg "ERROR: failed to migrate $LEGACY_SAVE_KUBE_VAR_LIB_DIR to $SAVE_KUBE_VAR_LIB_DIR"
                rm -rf "$SAVE_KUBE_VAR_LIB_DIR"
                return
        fi
        logmsg "migrated  $LEGACY_SAVE_KUBE_VAR_LIB_DIR to $SAVE_KUBE_VAR_LIB_DIR"
        rm -r "$LEGACY_SAVE_KUBE_VAR_LIB_DIR"
        logmsg "removed $LEGACY_SAVE_KUBE_VAR_LIB_DIR"
}

# when transitioning from single node to cluster mode, the k3s.yaml file may need
# to change with new certificates
check_kubeconfig_yaml_files() {
    file1="/etc/rancher/k3s/k3s.yaml"
    file2="/run/.kube/k3s/k3s.yaml"

    if ! cmp -s "$file1" "$file2"; then
        logmsg "k3s.yaml files are different, copying $file1 to $file2"
        cp "$file1" "$file2"
    fi
}

# get the OS-IMAGE name from the /run/eve-release
get_eve_os_release() {
        # Wait for /run/eve-release to appear
        while [ ! -f /run/eve-release ]; do
                sleep 1
        done

        # Read the original name from /run/eve-release
        eve_image_name=$(cat /run/eve-release)

        logmsg "EVE Release: $eve_image_name, write to /etc/os-release"
        # Write the short name to /etc/os-release
        echo "PRETTY_NAME=\"$eve_image_name\"" > /etc/os-release
}

terminate_k3s() {
  # Simple loop to kill all k3s server processes
  max_attempts=4
  attempt=0

  while [ $attempt -lt $max_attempts ]; do
    # Check for any k3s server processes
    pids=$(pgrep -f "$K3S_SERVER_CMD")

    # If no processes found, we're done
    if [ -z "$pids" ]; then
      if [ $attempt -eq 0 ]; then
        logmsg "No '$K3S_SERVER_CMD' processes found"
      else
        logmsg "k3s server processes successfully terminated after $attempt attempts"
      fi
      return 0
    fi

    for pid in $pids; do
        if [ $attempt -lt 3 ]; then
            # First three attempts: use SIGTERM for graceful shutdown
            logmsg "Attempt $((attempt+1))/$max_attempts: Sending SIGTERM to PID $pid for graceful shutdown"
            kill "$pid" 2>/dev/null
        else
            # Last attempt: use SIGKILL for forced termination
            logmsg "Final attempt $max_attempts/$max_attempts: Sending SIGKILL to PID $pid"
            kill -9 "$pid" 2>/dev/null
        fi
    done

    # Wait a moment for processes to terminate
    sleep 1
    attempt=$((attempt+1))
  done

  # Final check for any remaining processes - just report status
  final_check=$(pgrep -f "$K3S_SERVER_CMD")
  if [ -n "$final_check" ]; then
    logmsg "ERROR: Failed to terminate all k3s server processes after $max_attempts attempts. Still running: $final_check"
    return 1
  else
    logmsg "All k3s server processes successfully terminated"
  fi

  # Remove the flannel VXLAN device so the next k3s start gets a clean state.
  ip link del flannel.1 2>/dev/null || true
  return 0
}

# wait for debugging flag in /persist/k3s/wait_{flagname} if exist
wait_for_item() {
        filename="/persist/k3s/wait_$1"
        while [ -e "$filename" ]; do
                k3sproc=""
                if pgrep -x "$K3S_SERVER_CMD" > /dev/null; then
                        k3sproc="k3s server is running"
                else
                        k3sproc="k3s server is NOT running"
                fi
                logmsg "Found $filename file. $k3sproc, Waiting for 60 seconds..."
                sleep 60
        done
}

wait_for_device_name() {
        logmsg "Waiting for DeviceName from controller..."
        EdgeNodeInfoPath="/run/zedagent/EdgeNodeInfo/global.json"
        while [ ! -f $EdgeNodeInfoPath ]; do
                sleep 5
        done
        dName=$(jq -r '.DeviceName' $EdgeNodeInfoPath)
        if [ -n "$dName" ]; then
                HOSTNAME=$(convert_to_k8s_compatible "$dName")
        fi

        # we should have the uuid since we got the device name
        while true; do
                DEVUUID=$(/bin/hostname)
                if is_valid_uuid "$DEVUUID"; then
                        logmsg "got valid Device UUID: $DEVUUID"
                        break
                else
                        sleep 5
                fi
        done

        if [ ! -f "$K3S_NODENAME_CONFIG_FILE" ]; then
                echo "node-name: $HOSTNAME" > "$K3S_NODENAME_CONFIG_FILE"
        fi
        logmsg "Hostname: $HOSTNAME"
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

Multus_uninstall() {
        logmsg "multus uninstall"
        kubectl delete -f /etc/multus-daemonset-new.yaml
        rm /var/lib/multus_initialized
}

Multus_config() {
    dsList=$(kubectl -n kube-system get daemonset -o json | jq -r .items[].metadata.name)
    for ds in $dsList; do
            logmsg "setting node selector for ds:$ds"
            kubectl patch daemonset "$ds" -n kube-system -p '{"spec":{"template":{"spec":{"nodeSelector":{"tie-breaker-node":"false"}}}}}'
    done
}

node_name_from_uuid() {
        node_uuid=$1
        kubectl get nodes -l node-uuid="${node_uuid}" -o jsonpath='{.items[*].metadata.name}'
}

# We assume that when this is called zedagent has initialized and
# published EdgeNodeInfo (from a checkpoint if disconnected),
self_node_name() {
        EdgeNodeInfoPath="/run/zedagent/EdgeNodeInfo/global.json"
        if [ ! -f $EdgeNodeInfoPath ]; then
                echo ""
                return
        fi
        jq -r '.DeviceName' $EdgeNodeInfoPath
        return
}

# Configure tie breaker attributes for node objects, all nodes should run this locally
Nodes_tie_breaker_config_apply() {
        tie_breaker_node_uuid=$1
        nodes=$(kubectl get nodes -l node-uuid="${tie_breaker_node_uuid}" -o jsonpath='{.items[*].metadata.name}')
        for tbNode in $nodes; do
                logmsg "node $tbNode is tie-breaker"
                kubectl label node "${tbNode}" "${TIE_BREAKER_NODE_LABEL}=${TIE_BREAKER_NODE_LABEL_SET_VALUE}" --overwrite
                kubectl cordon "${tbNode}"
        done

        nodes=$(kubectl get nodes -l node-uuid!="${tie_breaker_node_uuid}" -o jsonpath='{.items[*].metadata.name}')
        for notTbNode in $nodes; do
                logmsg "node $notTbNode is not tie-breaker"
                kubectl label node "${notTbNode}" "${TIE_BREAKER_NODE_LABEL}=${TIE_BREAKER_NODE_LABEL_UNSET_VALUE}" --overwrite
                kubectl uncordon "${notTbNode}"
        done
}
