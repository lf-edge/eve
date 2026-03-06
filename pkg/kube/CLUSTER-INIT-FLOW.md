# cluster-init.sh — Detailed Flow Diagram

Source: `pkg/kube/cluster-init.sh`

---

## Phase 0: Script Startup & Sourced Libraries

```
cluster-init.sh starts
       │
       ├─ Set globals:
       │    RESTART_COUNT=0, current_wait_time=5s
       │    MAX_WAIT_TIME=600s (10 min, exponential backoff cap)
       │    TRANSITION_PIPE, TRANSITION_FLAG_FILE
       │    KUBE_ROOT_EXT4=/persist/vault/kube
       │    KUBE_ROOT_ZFS=/dev/zvol/persist/etcd-storage
       │
       └─ Source libraries:
            config.sh          — k3s config helpers
            pubsub.sh          — EVE pubsub helpers
            kube/config.sh     — cluster config management
            descheduler-utils.sh
            longhorn-utils.sh
            cluster-utils.sh
            cluster-update.sh  — Update_CheckNodeComponents, Update_CheckClusterComponents
            registration-utils.sh
            utils.sh
            kubevirt-utils.sh
            tie-breaker-utils.sh
```

---

## Phase 1: setup_prereqs()

```
setup_prereqs()
       │
       ├─ [ONCE] Record initial k3s version
       │    → ${K3S_LOG_DIR}/initial_k3s_version
       │    (prevents downgrades below install version)
       │
       ├─ Load kernel modules:
       │    modprobe tun, vhost_net, fuse, iscsi_tcp
       │
       ├─ Setup filesystem:
       │    mkdir /run/lock
       │    rm -rf /var/log → symlink to /persist/kubelog
       │    mkdir $K3S_CONFIG_DIR
       │
       ├─ Start iSCSI daemon: /usr/sbin/iscsid start
       │
       ├─ mount --make-rshared /
       │
       ├─ setup_cgroup()
       │
       ├─ ┌─ WAIT LOOP: wait_for_default_route() ─────────────────────┐
       │  │  while no default route: sleep 1                          │
       │  └──────────────────────────────────────────────────────────-┘
       │
       ├─ wait_for_device_name()
       │
       ├─ chmod o+rw /dev/null
       │
       ├─ ┌─ WAIT LOOP: wait_for_vault() ─────────────────────────────┐
       │  │  while vaultmgr waitUnsealed fails: sleep 1               │
       │  │  (blocks until TPM-backed vault is unsealed)              │
       │  └───────────────────────────────────────────────────────────┘
       │
       ├─ mount_kube_root():
       │    ├─ ZFS:  wait for /dev/zvol/persist/etcd-storage ──────────┐
       │    │        while [ ! -b $KUBE_ROOT_ZFS ]: sleep 1            │
       │    │        mount zvol → /var/lib                ─────────────┘
       │    └─ EXT4: mkdir /persist/vault/kube
       │             mount --bind → /var/lib
       │
       └─ ┌─ WAIT LOOP: check_network_connection() ────────────────────┐
          │  (waits until network is reachable)                        │
          └───────────────────────────────────────────────────────────-┘
```

---

## Phase 2: One-time Pre-loop Setup

```
After setup_prereqs():
       │
       ├─ wait_for_item "k3s-install"    (pubsub signal)
       ├─ Update_CheckNodeComponents()   (check if k3s binary needs update)
       ├─ Config_k3s_override_apply()    (apply controller k3s.config.override if any)
       │
       ├─ CONVERSION CHECK: /var/lib/convert-to-single-node exists?
       │    YES ──► restore_var_lib()     (restore saved single-node /var/lib snapshot)
       │            rm -rf /persist/vault/volumes/replicas/*   (wipe replica data)
       │            assign_multus_nodeip()  (reconfigure Multus for single-node IP)
       │            convert_to_single_node=true
       │            touch /var/lib/all_components_initialized
       │
       ├─ wait_for_item "containerd"     (pubsub signal)
       ├─ check_start_containerd()       (start k3s user containerd if not running)
       │
       ├─ monitor_cluster_config_change & ◄── BACKGROUND TASK (see Section 5)
       │
       ├─ FIRST TIME OR RESTART CHECK:
       │
       │  NOT YET INITIALIZED (/var/lib/all_components_initialized missing):
       │  ────────────────────────────────────────────────────────────────
       │    if /var/lib/edge-node-cluster-mode:
       │      provision_cluster_config_file(true)  → generate config.yaml
       │    else:
       │      "Single node mode" — use existing config.yaml
       │    assign_multus_nodeip($cluster_node_ip)
       │
       │  RESTART (all_components_initialized exists):
       │  ─────────────────────────────────────────────
       │    if /var/lib/edge-node-cluster-mode:
       │      ┌─ WAIT LOOP: get_enc_status() ──────────────────────────┐
       │      │  while get_enc_status fails: sleep 10                  │
       │      └───────────────────────────────────────────────────────-┘
       │      provision_cluster_config_file($convert_to_single_node)
       │    else:
       │      Single node: append node-name to K3S_NODENAME_CONFIG_FILE
       │
       ├─ get_eve_os_release()
       │
       └─ if NOT amd64: install_kubevirt=0  (no CDI/KubeVirt on ARM)
```

---

## Phase 3: Main Forever Loop (every 15s)

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
while true; do
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌─────────────────────────────────────────────────────────────────────┐
│ BRANCH A: First-time Install Path                                   │
│ (all_components_initialized does NOT exist)                         │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
           ┌───────────┴──────────────────────────────────────────┐
           │  k3s_installed_unpacked missing?                     │
           │  YES → Update_CheckNodeComponents()  ← retry loop   │
           │        sleep 5; continue                            │
           └───────────┬──────────────────────────────────────────┘
                       │ (k3s binary is ready)
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  check_start_k3s()         (see Section 3a)          │
           │  fails (k3s not yet running)?                        │
           │  → sleep 5; continue                                 │
           └───────────┬───────────────────────────────────────────┘
                       │ (k3s started / already running)
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  external_boot_image_import()                        │
           │  fails? → sleep 5; continue                          │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌──────────────────────────────────────────────────────┐
           │  WAIT SUB-LOOP: node ready? (120s timeout)          │
           │  while (time < 120s):                               │
           │    kubectl get node/$HOSTNAME | grep Ready          │
           │    node_count_ready != 1 → sleep 10; continue      │
           │    node_count_ready == 1 → break                   │
           │  timeout? → continue (restart outer loop)          │
           └───────────┬──────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  node-uuid label set?                                │
           │  NO → apply_node_uuid_label()                       │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  are_all_pods_ready()?                               │
           │  NO → All_PODS_READY=false; sleep 10; continue      │
           └───────────┬───────────────────────────────────────────┘
                       │ all pods ready
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  multus_initialized?                                 │
           │  NO → assign_multus_nodeip()                        │
           │       apply_multus_cni()   → continue               │
           │       if still not init: sleep 10; continue         │
           │  YES → check_for_multus_link_request()              │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  CNI DHCP daemon running?                            │
           │  NO → rm /run/cni/dhcp.sock (if stale)              │
           │       /opt/cni/bin/dhcp daemon &                    │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  debuguser-initialized?                              │
           │  NO → config_cluster_roles(); continue              │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  install_kubevirt == 1 AND !kubevirt_initialized?    │
           │  YES → wait_for_item "kubevirt"                     │
           │        Kubevirt_install()                           │
           │        wait_for_item "cdi"                         │
           │        Cdi_install()                               │
           │        touch kubevirt_initialized; continue        │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  KUBE_MANIFESTS_DIR exists?                          │
           │  NO → logmsg; continue                              │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  Copy manifests:                                     │
           │    storage-classes.yaml → KUBE_MANIFESTS_DIR        │
           │    nvidia manifest (if NVIDIA platform)             │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  wait_for_item "longhorn"                            │
           │  longhorn_initialized?                               │
           │  NO → longhorn_install($HOSTNAME)                   │
           │       fails? → continue                             │
           │       Longhorn_is_ready()?                          │
           │       NO  → sleep 30; continue                      │
           │       YES → touch longhorn_initialized             │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  wait_for_item "descheduler"                         │
           │  descheduler_install()                               │
           │  fails? → continue                                  │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  FINALIZE FIRST-TIME INSTALL:                        │
           │    terminate_k3s()                                  │
           │    sync; sleep 5                                    │
           │    save_var_lib()  ← snapshot /var/lib for rollback │
           │    touch node-labels-initialized                    │
           │    touch all_components_initialized   ← GATE FLAG  │
           └───────────────────────────────────────────────────────┘
                       │
                       │  (next loop iteration now takes Branch B)
                       ▼

┌─────────────────────────────────────────────────────────────────────┐
│ BRANCH B: Steady-State / Restart Path                               │
│ (all_components_initialized EXISTS)                                 │
└──────────────────────┬──────────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  Config_k3s_override_apply()                         │
           │  fails? → terminate_k3s(); (will restart on next    │
           │           check_start_k3s call)                     │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  cluster_type == REPLICATED_STORAGE?                 │
           │  YES → Update_CheckNodeComponents()                  │
           └───────────┬───────────────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────────────────────────────────────┐
           │  check_start_k3s()    (see Section 3a)               │
           │  returns 1 = k3s was just (re)started?               │
           └──────────┬────────────────────────────────────────────┘
                      │
           ┌──────────┴──────────┐
           │                     │
    K3S JUST STARTED        K3S WAS ALREADY
    (returned 1)             RUNNING (returned 0)
           │                     │
           ▼                     ▼
  WAIT SUB-LOOP             ┌──────────────────────────────┐
  node ready? (120s)        │  node-labels-initialized?    │
  (same as Branch A)        │  NO → reapply_node_labels()  │
           │                └──────────────┬───────────────┘
           │ ready                         │
           ▼                               ▼
  node_count_ready         ┌──────────────────────────────┐
  == 1?                    │  external_boot_image_import()│
  NO → continue            │  fails? → continue          │
  YES → fall through       └──────────────┬───────────────┘
                                          │
                                          ▼
                           ┌──────────────────────────────┐
                           │  CNI binaries present?       │
                           │  NO → copy_cni_plugin_files()│
                           └──────────────┬───────────────┘
                                          │
                                          ▼
                           ┌──────────────────────────────┐
                           │  multus_initialized?         │
                           │  NO → assign_multus_nodeip() │
                           │       apply_multus_cni()     │
                           └──────────────┬───────────────┘
                                          │
                                          ▼
                           ┌──────────────────────────────┐
                           │  check_for_multus_link_request│
                           │  DHCP daemon running?        │
                           │  NO → restart dhcp daemon   │
                           └──────────────┬───────────────┘
                                          │
                                          ▼
                           ┌──────────────────────────────┐
                           │  debuguser-initialized?      │
                           │  NO → config_cluster_roles() │
                           │  YES → sync user.yaml to /run│
                           └──────────────┬───────────────┘
                                          │
                                          ▼
                           ┌─────────────────────────────────────┐
                           │  Longhorn_is_ready()?               │
                           │  YES:                               │
                           │    check_overwrite_nsmounter()      │
                           │    Tie_breaker_configApply()        │
                           │                                     │
                           │    cluster_type?                    │
                           │    ├─ UNSPECIFIED:                  │
                           │    │   Registration_Applied?        │
                           │    │   NO  → copy storage-classes   │
                           │    │   YES → cleanup_storageclasses │
                           │    │         longhorn_post_config_clean│
                           │    ├─ REPLICATED_STORAGE:           │
                           │    │   copy storage-classes         │
                           │    │   Update_CheckClusterComponents│
                           │    │   Update_RunDeschedulerOnBoot  │
                           │    └─ K3S_BASE:                     │
                           │        cleanup_storageclasses       │
                           │        longhorn_post_config_clean   │
                           └──────────────┬──────────────────────┘
                                          │
                                          ▼
                           ┌─────────────────────────────────────┐
                           │  cluster_type == REPLICATED_STORAGE?│
                           │  YES:                               │
                           │    longhorn_post_install_config()   │
                           │    Update_CheckClusterComponents()  │
                           │    fails? → continue               │
                           │    Update_RunDeschedulerOnBoot()    │
                           └──────────────┬──────────────────────┘
                                          │
                                          ▼

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  END OF BRANCH A/B — common tail (every loop iteration):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  check_log_file_size "k3s.log"
  check_log_file_size "multus.log"
  check_log_file_size "k3s-install.log"
  check_log_file_size "eve-bridge.log"
  check_log_file_size "containerd-user.log"
  check_kubeconfig_yaml_files()
  check_and_remove_excessive_k3s_logs()
  check_and_run_vnc()        (see Section 3c)
  wait_for_item "wait"       (pubsub throttle)
  sleep 15
  ↑
  └─ loop back to top of while true
```

---

## Section 3a: check_start_k3s() — Sub-Loops

```
check_start_k3s()
       │
       ├─ TRANSITION_FLAG_FILE exists?
       │    YES ──► BLOCKING READ from TRANSITION_PIPE
       │            (blocks until monitor_cluster_config_change writes "DONE")
       │            rm TRANSITION_PIPE
       │
       ├─ CLUSTER_WAIT_FILE exists?
       │    ┌─ WAIT LOOP ──────────────────────────────────────────────┐
       │    │  while /run/kube/cluster-change-wait-ongoing exists:     │
       │    │    sleep 5                                               │
       │    └─────────────────────────────────────────────────────────┘
       │
       ├─ Is k3s server process running? (pgrep -f k3s server)
       │
       ├─ NOT RUNNING:
       │    RESTART_COUNT++
       │    sleep $current_wait_time    ← exponential backoff
       │    current_wait_time *= 2      (caps at MAX_WAIT_TIME=600s)
       │    save_crash_log()
       │    ln -s /var/lib/k3s/bin/* /usr/bin
       │    copy_cni_plugin_files() if needed
       │    nohup /usr/bin/k3s server &   (start k3s in background)
       │    ionice -c2 -n0 -p $k3s_pid   (prioritize etcd I/O)
       │    │
       │    ├─ WAIT SUB-LOOP for kubeconfig (max 600s = 120×5s) ───────┐
       │    │  while /etc/rancher/k3s/k3s.yaml missing:               │
       │    │    sleep 5; counter++                                    │
       │    │    counter==120 → break  (k3s may have crashed)         │
       │    └───────────────────────────────────────────────────────-──┘
       │    cp k3s.yaml → /run/.kube/k3s/k3s.yaml
       │    return 1  (k3s just started, caller must wait for node Ready)
       │
       └─ RUNNING:
            current_wait_time = INITIAL_WAIT_TIME (reset backoff)
            return 0  (k3s was already running)
```

---

## Section 3b: provision_cluster_config_file() — Inner Loop (Non-Bootstrap)

```
provision_cluster_config_file(first_time):
       │
       ├─ if is_bootstrap == true:
       │    first_time? → write bootstrapContent → config.yaml
       │    else       → write serverContent    → config.yaml
       │    return 0
       │
       └─ if is_bootstrap == false:
            write serverContent → config.yaml
            if NOT first_time: return 0 (restart, no need to wait)
            │
            touch CLUSTER_WAIT_FILE  ← blocks check_start_k3s
            ping_success_count=0, ping_fail_count=0
            │
            ┌─ WAIT LOOP: wait for bootstrap server to be in cluster mode ──┐
            │  counter=0                                                    │
            │  while true:                                                  │
            │    counter++                                                  │
            │    curl --insecure https://$join_serverIP:6443               │
            │    ├─ CURL OK (HTTPS reachable):                             │
            │    │   curl http://$join_serverIP:12346/status               │
            │    │   ├─ FAIL:      log every 30 attempts                  │
            │    │   ├─ "cluster:<uuid>" returned:                        │
            │    │   │   UUID matches our cluster_uuid?                   │
            │    │   │   YES → rm CLUSTER_WAIT_FILE; break  ✅            │
            │    │   │   NO  → log UUID mismatch warning (dup IP?)        │
            │    │   └─ other status: log "not in cluster mode"           │
            │    ├─ CURL FAIL (HTTPS not reachable):                      │
            │    │   ping $join_serverIP → track ping_success/fail counts │
            │    │   log every 30 attempts                                │
            │    │                                                        │
            │    ├─ enc_status_file disappeared?                          │
            │    │   → rm CLUSTER_WAIT_FILE; return 1  ← triggers reboot  │
            │    │                                                        │
            │    └─ sleep 10; repeat                                      │
            └──────────────────────────────────────────────────────────-──┘
            return 0
```

---

## Section 3c: check_and_run_vnc()

```
check_and_run_vnc()   (called each main loop iteration)
       │
       ├─ VMICONFIG_FILENAME (/run/zedkube/vmiVNC.run) exists
       │   AND (VNC not running OR process dead)?
       │     Parse file for VMINAME and VNCPORT
       │     nohup /usr/bin/virtctl vnc $vmiName -n eve-kube-app
       │             --port $vmiPort --proxy-only &
       │     VNC_RUNNING=true
       │
       └─ VMICONFIG_FILENAME does NOT exist:
            VNC_RUNNING==true? → kill virtctl vnc process
            VNC_RUNNING=false
```

---

## Section 3d: change_to_new_token() — Inner Loops

```
change_to_new_token()   (called during single→cluster transition, bootstrap only)
       │
       ├─ cluster_token provided by controller?
       │    YES:
       │      rotate_cluster_token($cluster_token)
       │      starttime=$(date +%s)
       │      │
       │      ┌─ WAIT LOOP: confirm token rotated ────────────────────┐
       │      │  while true:                                          │
       │      │    grep "server:$cluster_token" /var/lib/.../token    │
       │      │    found? → break  ✅                                 │
       │      │    elapsed >= 60s? → retry rotate_cluster_token()     │
       │      │                      reset starttime                  │
       │      │    sleep 5; repeat                                    │
       │      └───────────────────────────────────────────────────────┘
       │
       └─ NO cluster_token:
            save current_token
            k3s token rotate   (auto-generate)
            │
            ┌─ WAIT LOOP: confirm old token gone ───────────────────┐
            │  while true:                                          │
            │    grep $current_token /var/lib/.../token             │
            │    still present → sleep 2; repeat                    │
            │    gone → break  ✅                                   │
            └───────────────────────────────────────────────────────┘
```

---

## Section 4: uninstall_components() — Sub-Loops (Base-K3S conversion)

```
uninstall_components()   (called when converting to CLUSTER_TYPE_K3S_BASE)
       │
       ├─ touch /tmp/replicated-storage-uninstall-inprogress
       │
       ├─ ┌─ WAIT LOOP: API server available ─────────────────────────┐
       │  │  while ! kubectl cluster-info: sleep 5                   │
       │  └───────────────────────────────────────────────────────────┘
       │
       ├─ ┌─ WAIT LOOP: all nodes ready ──────────────────────────────┐
       │  │  while not_ready_nodes != "": sleep 5                    │
       │  └───────────────────────────────────────────────────────────┘
       │
       ├─ Descheduler_uninstall()
       ├─ Longhorn_uninstall();  rm longhorn_initialized
       ├─ Cdi_uninstall()
       ├─ Kubevirt_uninstall();  rm kubevirt_initialized
       ├─ Multus_uninstall();    rm multus_initialized
       │
       ├─ rm /tmp/replicated-storage-uninstall-inprogress
       ├─ touch /var/lib/base-k3s-mode
       └─ touch /var/lib/replicated-storage-uninstall-complete
```

---

## Section 5: Background Task — monitor_cluster_config_change()

Runs as a **separate background process** (`&`) started once before the main loop.

```
monitor_cluster_config_change()   [background process]
       │
       rm -f TRANSITION_FLAG_FILE    (cleanup any stale flags)
       │
       ┌─ FOREVER LOOP ────────────────────────────────────────────────┐
       │  while true:                                                  │
       │    check_cluster_config_change()   (see 5a below)            │
       │    check_cluster_transition_done() (see 5b below)            │
       │    sleep 15                                                   │
       └───────────────────────────────────────────────────────────────┘
```

### Section 5a: check_cluster_config_change()

```
check_cluster_config_change()
       │
       ├─ all_components_initialized missing? → return 0  (not ready yet)
       │
       ├─ get_enc_status()  → reads /run/zedkube/EdgeNodeClusterStatus/global.json
       │    returns 0 = valid, 1 = invalid/incomplete, 2 = file missing
       │
       ├─ enc_status == 2  (file MISSING = cluster config removed):
       │    edge-node-cluster-mode flag missing? → return 0  (already single node)
       │    Config_cluster_exists()?
       │      YES → "waiting for zedkube to publish" → return 0
       │    NO:
       │      Registration_Cleanup()
       │      rm /var/lib/base-k3s-mode
       │      touch /var/lib/convert-to-single-node
       │      reboot_with_reason("Transition from cluster to single node")  ← REBOOT
       │
       └─ enc_status == 0 + cluster_node_ip_is_ready == true:
            edge-node-cluster-mode flag missing?  (single → cluster transition)
            │
            ┌─ INNER WAIT LOOP ──────────────────────────────────────────┐
            │  while true:                                               │
            │    get_enc_status() succeeds?                             │
            │    YES:                                                   │
            │      touch /var/lib/edge-node-cluster-mode               │
            │      Config_cluster_type_get()                           │
            │      cluster_type == K3S_BASE AND !base-k3s-mode?        │
            │        → uninstall_components()  (see Section 4)        │
            │      is_bootstrap == true?                               │
            │        → change_to_new_token()  (see Section 3d)        │
            │      remove_multus_cni()                                 │
            │      assign_multus_nodeip($cluster_node_ip)             │
            │      rm /var/lib/node-labels-initialized                │
            │      mkfifo TRANSITION_PIPE                             │
            │      touch TRANSITION_FLAG_FILE                         │
            │      terminate_k3s()                                    │
            │      if !bootstrap: rm -rf k3s TLS certs                │
            │                     rm debuguser-initialized            │
            │      provision_cluster_config_file(true)               │
            │        returns 1? (enc_status_file disappeared)         │
            │          → rm base-k3s-mode                            │
            │            touch convert-to-single-node                │
            │            reboot_with_reason("ENC file disappeared") ← REBOOT│
            │      if !bootstrap:                                     │
            │        echo "$(date) 0" > transition-to-cluster        │
            │      echo "DONE" > TRANSITION_PIPE  ← unblocks check_start_k3s│
            │      rm TRANSITION_FLAG_FILE                           │
            │      break                                             │
            │    NO:                                                 │
            │      enc_status_file missing? → return 0  (try again) │
            │      sleep 10                                          │
            └────────────────────────────────────────────────────────┘
            │
            cluster_type == K3S_BASE AND base-k3s-mode exists?
              → Registration_CheckApply()
            else:
              → Registration_CheckApply()
```

### Section 5b: check_cluster_transition_done()

```
check_cluster_transition_done()   (polls for non-bootstrap join success)
       │
       ├─ /var/lib/transition-to-cluster missing? → return 0  (nothing to do)
       │
       ├─ kubectl get nodes (API reachable?)
       │    YES → count ready nodes
       │           ready_nodes >= 2?
       │             YES → rm transition-to-cluster; return 0  ✅
       │
       ├─ Read timestamp and reboot_count from transition-to-cluster
       │
       └─ elapsed >= 300s (5 min timeout)?
            YES:
              reboot_count++
              reboot_count <= 3?
                YES → update file: "$(date) $reboot_count"
                      reboot_with_reason("Retry cluster join attempt $N")  ← REBOOT
                NO  → rm transition-to-cluster  (give up after 3 reboots)
            NO:
              log "still waiting, Xs elapsed"
              return 1
```

---

## State Flags Reference

| Flag File | Meaning |
|-----------|---------|
| `/var/lib/all_components_initialized` | All K3s/KubeVirt/Longhorn/Multus installed ✅ |
| `/var/lib/k3s_installed_unpacked` | K3s binary is available |
| `/var/lib/edge-node-cluster-mode` | Node is in cluster (not single-node) mode |
| `/var/lib/multus_initialized` | Multus daemonset applied |
| `/var/lib/kubevirt_initialized` | KubeVirt + CDI installed |
| `/var/lib/longhorn_initialized` | Longhorn installed and ready |
| `/var/lib/debuguser-initialized` | Debug user certificates/roles applied |
| `/var/lib/node-labels-initialized` | node-uuid and Longhorn labels applied |
| `/var/lib/base-k3s-mode` | Node is in base K3s mode (no Longhorn/KubeVirt) |
| `/var/lib/convert-to-single-node` | Pending conversion back to single-node (triggers restore on next boot) |
| `/var/lib/transition-to-cluster` | Non-bootstrap join in progress (contains timestamp + reboot_count) |
| `/run/kube/cluster-change-wait-ongoing` | Blocks check_start_k3s during cluster join |
| `/tmp/cluster_transition_flag` | Blocks check_start_k3s until transition pipe signaled |
| `/tmp/cluster_transition_pipe$$` | FIFO pipe to coordinate k3s restart after transition |

---

## Reboot Scenarios Summary

| Trigger | Reason |
|---------|--------|
| `cluster → single` | ENC status file removed while in cluster mode |
| `single → cluster` (non-bootstrap) | ENC status file disappeared during bootstrap wait |
| `non-bootstrap join timeout` | Ready nodes < 2 after 300s (up to 3 retries) |
| `k3s override bad config` | terminate_k3s only (no reboot; restarts via check_start_k3s) |
