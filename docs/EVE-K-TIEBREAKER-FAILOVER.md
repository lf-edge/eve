# EVE-K Cluster Failover Scenarios

Cluster topology assumed unless stated otherwise:
- **Node A** — master + worker (leader)
- **Node B** — master + worker
- **Node C** — tie-breaker (etcd quorum only, no workloads)

---

## Scenario 1: Worker Node Crash

**Trigger:** Node becomes unreachable; kubelet stops posting status (~1 min timeout).

```
BEFORE FAILURE
══════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │ (worker) │     │(tie-brkr)│
  │          │     │          │     │          │
  │ [App-1]  │     │ [App-2]  │     │  (etcd)  │
  │ Running  │     │ Running  │     │          │
  └──────────┘     └──────────┘     └──────────┘
        ↕ etcd quorum ↕                   ↕
        └─────────────────────────────────┘

FAILURE EVENT
═════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │  ████    │     │(tie-brkr)│
  │          │     │  CRASH   │     │          │
  │ [App-1]  │     │ [App-2]  │     │  (etcd)  │
  │ Running  │     │Terminatng│     │          │
  └──────────┘     └──────────┘     └──────────┘

DETECTION  (~60s)
   zedkube (Node A, leader)
   └─ checkAppsFailover() — runs every 10s
      └─ detects: App-2 pod has DeletionTimestamp set
                  Node B Ready=False

FAILOVER SEQUENCE
═════════════════

  t=0s    Node B unreachable
          │
  t=60s   K8s marks Node B: Ready=False
          │
  t=90s   ReplicaSet controller evicts App-2 pod
          │  Pod enters "Terminating" state
          │
  t=120s  zedkube (leader) checks:
          │  pod terminating > 2 min? → YES
          │  └─ DetachOldWorkload() called
          │     ├─ Remove virt-launcher finalizers
          │     ├─ Delete PVC attachments on Node B
          │     └─ Force VMI termination
          │
  t=130s  Longhorn detaches volume from Node B
          │  └─ Replica marked offline
          │     Rebuild scheduled on Node A
          │
  t=135s  K8s scheduler places App-2 on Node A
          │  └─ PVC reattaches
          │     Pod transitions: Pending → Running
          │
  t=140s  zedkube publishes:
          └─ ENClusterAppStatus (App-2, Running, Node A)

AFTER RECOVERY
══════════════
  ┌──────────────────────┐     ┌──────────┐
  │        Node A        │     │  Node C  │
  │      (leader)        │     │(tie-brkr)│
  │                      │     │          │
  │  [App-1]   [App-2]   │     │  (etcd)  │
  │  Running   Running   │     │          │
  └──────────────────────┘     └──────────┘

Key timeouts:
  Node NotReady detection  : ~60s  (Kubernetes default)
  Pod eviction trigger     : ~30s  after NotReady
  getKubePodsError threshold: 2min  → mark app not running
  DetachOldWorkload trigger : 2min  of pod terminating
```

---

## Scenario 2: Leader Node Crash

**Trigger:** Master/leader node crashes; etcd has 2 of 3 members (quorum maintained).

```
BEFORE FAILURE
══════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │◄────┤          │     │(tie-brkr)│
  │  etcd    │     │  etcd    │     │  etcd    │
  │ [App-1]  │     │ [App-2]  │     │          │
  └──────────┘     └──────────┘     └──────────┘
   Lease holder
   "eve-kube-stats-leader"

FAILURE EVENT
═════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │  ████    │     │          │     │(tie-brkr)│
  │  CRASH   │     │  etcd    │     │  etcd    │
  │          │     │ [App-2]  │     │          │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 2/3 members alive → QUORUM MAINTAINED

LEADER RE-ELECTION  (Kubernetes Lease mechanism)
════════════════════════════════════════════════

  Lease: LeaseDuration=300s, RenewDeadline=180s, RetryPeriod=15s

  t=0s    Node A stops renewing Lease
          │
  t=180s  Lease renewal deadline exceeded
          │  Node B zedkube: attempts to acquire Lease
          │  Node C: not eligible (tie-breaker, no scheduling)
          │
  t=195s  Node B acquires Lease
          │  └─ publishes KubeLeaderElectInfo:
          │       IsStatsLeader  = true
          │       LeaderIdentity = "node-b"
          │       InLeaderElection = true
          │
  t=195s  Node B becomes isDecisionNode=true
          └─ App-1 failover triggered (same as Scenario 1)
             App-1 rescheduled on Node B

AFTER RECOVERY
══════════════
  ┌──────────────────────┐     ┌──────────┐
  │        Node B        │     │  Node C  │
  │      (NEW leader)    │     │(tie-brkr)│
  │                      │     │          │
  │  [App-1]   [App-2]   │     │  (etcd)  │
  │  Running   Running   │     │          │
  └──────────────────────┘     └──────────┘

  ┌─────────────────────────────────────────────┐
  │ NOTE: If Node A recovers later:             │
  │  • Rejoins etcd cluster                     │
  │  • Node B retains leadership                │
  │  • App-1 stays on Node B (no failback)      │
  │  • Longhorn rebuilds 3rd replica on Node A  │
  └─────────────────────────────────────────────┘
```

---

## Scenario 3: Network Partition (Split-Brain)

**Trigger:** Network splits into two isolated groups.

```
BEFORE PARTITION
════════════════
  ┌──────────┐         ┌──────────┐         ┌──────────┐
  │  Node A  │◄────────┤  Node B  │◄────────┤  Node C  │
  │ (leader) │         │          │         │(tie-brkr)│
  │  etcd    │         │  etcd    │         │  etcd    │
  │ [App-1]  │         │ [App-2]  │         │          │
  └──────────┘         └──────────┘         └──────────┘

PARTITION EVENT  (Node A isolated)
═══════════════════════════════════
  ┌──────────┐    ╳    ┌──────────┐─────────┌──────────┐
  │  Node A  │◄──✗──►  │  Node B  │         │  Node C  │
  │ (leader) │         │          │         │(tie-brkr)│
  │  etcd    │         │  etcd    │         │  etcd    │
  │ [App-1]  │         │ [App-2]  │         │          │
  └──────────┘         └──────────┘         └──────────┘

  ZONE A (minority: 1/3)    │    ZONE B+C (quorum: 2/3)
  ─────────────────────────────────────────────────────

ZONE B+C (quorum) — NORMAL OPERATION CONTINUES
───────────────────────────────────────────────
  • etcd quorum maintained (Node B + Node C)
  • Kubernetes API writable
  • Node B retains or acquires leadership
  • Node A marked NotReady after ~60s
  • App-1 rescheduled on Node B (as per Scenario 1)

ZONE A (minority) — DEGRADED / READ-ONLY
─────────────────────────────────────────
  • etcd cannot commit writes (no quorum)
  • Kubernetes API becomes read-only
  • Lease cannot be renewed → leader election stalls
    KubeLeaderElectInfo: InLeaderElection=false, ElectionRunning=false
  • App-1 pod continues running (kubelet is local)
  • No new scheduling decisions possible

  ┌─────────────────────────────────────────────────────┐
  │ SPLIT-BRAIN RISK: App-1 now runs on BOTH zones      │
  │                                                     │
  │  Zone A: App-1 (old, still running via local kubelet│
  │  Zone B: App-1 (rescheduled by cluster controller)  │
  │                                                     │
  │  Longhorn volume: replicas split, may diverge       │
  └─────────────────────────────────────────────────────┘

NETWORK HEALS
═════════════
  t=0    Network restored
         │
  t=5s   etcd sync begins (Zone A rejoins B+C quorum)
         │
  t=30s  Zone A Node A receives cluster state from B+C
         │  etcd applies missed entries
         │  Pod on Zone A reconciled: duplicate → terminated
         │
  t=60s  App-1: single instance on Node B (winner)
         Longhorn: replica on Node A re-synced from B+C
         Leader: Node B retains leadership

  ┌──────────────────────────────────────────────┐
  │ WARNING: Persistent volume data written in   │
  │ Zone A during partition may be LOST.         │
  │ Longhorn resolves divergence by quorum state │
  └──────────────────────────────────────────────┘
```

---

## Scenario 4: Tie-Breaker Node Failure

**Trigger:** Node C (tie-breaker, etcd-only) becomes unreachable.

```
BEFORE FAILURE
══════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │(tie-brkr)│
  │  etcd    │     │  etcd    │     │  etcd    │
  │ [App-1]  │     │ [App-2]  │     │  NO apps │
  └──────────┘     └──────────┘     └──────────┘

FAILURE EVENT
═════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │  ████    │
  │  etcd    │     │  etcd    │     │  CRASH   │
  │ [App-1]  │     │ [App-2]  │     │          │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 2/3 members alive (A+B) → QUORUM MAINTAINED

IMPACT ASSESSMENT
═════════════════
  Workloads:   ✅ ZERO IMPACT  (tie-breaker has no pods)
  Scheduling:  ✅ NORMAL       (A+B schedule freely)
  Volumes:     ✅ NORMAL       (2-replica policy: lh-sc-rep2)
                               (only A+B needed for Longhorn)
  etcd:        ✅ QUORUM OK    (A+B = 2/3 majority)
  Leadership:  ✅ UNCHANGED    (Node A keeps Lease)
  API:         ✅ WRITABLE     (quorum intact)

  ┌────────────────────────────────────────────────┐
  │ NOTE: Now in degraded quorum state.            │
  │ If either Node A OR Node B also fails          │
  │ → etcd drops to 1/3 → QUORUM LOST (Scenario 7)│
  └────────────────────────────────────────────────┘

RECOVERY
═════════
  1. Node C recovers or is replaced
  2. Re-run tie-breaker-utils.sh: Tie_breaker_configApply()
  3. Node rejoins etcd cluster
  4. Labels re-applied:
       tie-breaker-node=true
       tie-breaker-config-applied=1
  5. CDI, KubeVirt, Longhorn patched to exclude Node C from scheduling
  6. Longhorn: no replica rebuild needed (C had none)
```

---

## Scenario 5: Longhorn Volume Node Failure

**Trigger:** A node hosting volume replicas crashes; storage degrades.

```
BEFORE FAILURE  (3-replica default)
═════════════════════════════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │(tie-brkr)│
  │          │     │          │     │          │
  │[vol-rep-1│     │[vol-rep-2│     │ (no vols)│
  │  active] │     │  active] │     │          │
  └──────────┘     └──────────┘     └──────────┘
        ↑ App-1 attached to vol (PVC: uuid-pvc-1)
        Longhorn: 2 replicas healthy, RWO, StorageClass: longhorn

FAILURE EVENT  (Node B crashes)
════════════════════════════════
  ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │
  │ (leader) │     │  ████    │
  │          │     │  CRASH   │
  │[vol-rep-1│     │[vol-rep-2│  ← replica OFFLINE
  │  active] │     │  offline]│
  └──────────┘     └──────────┘

STORAGE DEGRADATION SEQUENCE
═════════════════════════════

  t=0    Node B unreachable
         │
  t=60s  Longhorn marks replica-2 offline
         │  Volume state: Degraded (1/2 replicas healthy)
         │  App-1 continues running (still attached to Node A)
         │
  t=65s  volumemgr publishes VolumeMgrStatus: degraded
         │  KubeClusterInfo updated: storage_health=degraded
         │
  t=90s  Longhorn attempts to schedule rebuild:
         │  Needs a node with free capacity
         │  Node A: eligible (has space)
         │  Node C: NOT eligible (tie-breaker, no storage)
         │  └─ Schedules replica rebuild on Node A
         │
  t=120s Rebuild starts: Node A now has 2 replicas
         Volume state: Healthy (2/2 replicas)

  App-1: NEVER interrupted (attached node never failed)

DRAIN-ASSISTED RECOVERY  (if node intentionally removed)
══════════════════════════════════════════════════════════

  zedkube drain.go:
    drainAndDeleteNode():
      1. Check if node has Longhorn replicas
         ├─ YES → wait for rebuild on other nodes
         │        only drain after replicas migrated
         └─ NO  → drain immediately

  Excluded from drain (remain to coordinate):
    • csi-attacher
    • csi-provisioner
    • longhorn-admission-webhook
    • longhorn-driver-deployer

CRITICAL FAILURE  (both replicas lost)
════════════════════════════════════════
  If Node A AND Node B both fail:

  Volume state: FAULTED
  App pod: Stuck (cannot attach PVC)
  Recovery: Manual Longhorn volume repair needed
            OR restore from backup

  ┌──────────────────────────────────────────────┐
  │ 2-replica clusters (tie-breaker config):     │
  │   StorageClass: lh-sc-rep2                   │
  │   Single node failure → immediate FAULT      │
  │   No rebuild possible (only 1 node left)     │
  └──────────────────────────────────────────────┘
```

---

## Scenario 6: Manual Node Drain (Maintenance / OS Update)

**Trigger:** `baseosmgr` (OS update) or `zedagent` (reboot) publishes `NodeDrainRequest`.

```
DRAIN STATE MACHINE
════════════════════

  NodeDrainRequest received
         │
         ▼
  ┌─────────────────┐
  │  Single node?   │──YES──► NodeDrainStatus: NOTSUPPORTED
  └────────┬────────┘         (skip drain, proceed with op)
           │ NO
           ▼
  ┌─────────────────────────────┐
  │  k3s API unreachable >300s? │──YES──► NodeDrainStatus: COMPLETE
  └────────────┬────────────────┘         (skip drain, k3s down anyway)
               │ NO
               ▼
  NodeDrainStatus: STARTING
         │
         ▼
  ┌──────────────────────────────────────────┐
  │  CORDON NODE  (mark Unschedulable=true)  │
  │  Retry up to 10x with 5s delay           │
  └────────┬────────────────────────────────-┘
           │ success                   │ all retries fail
           ▼                           ▼
  NodeDrainStatus: CORDONED    NodeDrainStatus: FAILEDCORDON
           │
           ▼
  ┌──────────────────────────────────────────────────────┐
  │  DRAIN NODE                                          │
  │  kubectl drain --force --grace-period=-1             │
  │    --delete-emptydir-data                            │
  │    --ignore-daemonsets                               │
  │    --pod-selector=<exclude longhorn control plane>   │
  │  Timeout: 24h (KubernetesDrainTimeout)               │
  │  Retry up to 5x with 300s delay                      │
  └────────┬─────────────────────────────────────────────┘
           │ success                   │ all retries fail
           ▼                           ▼
  NodeDrainStatus: COMPLETE   NodeDrainStatus: FAILEDDRAIN
           │
           ▼
  Device operation proceeds
  (reboot / OS update)

TIMELINE EXAMPLE  (OS update on Node A)
══════════════════════════════════════════

  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │(tie-brkr)│
  │ [App-1]  │     │ [App-2]  │     │          │
  └──────────┘     └──────────┘     └──────────┘

  baseosmgr publishes NodeDrainRequest (source: baseosmgr)
  zedkube subscribes → begins drain sequence
         │
  t=0s   Node A CORDONED
         │  New pods: will not schedule here
         │  Existing pods: continue running
         │
  t=10s  App-1 evicted from Node A
         │  └─ rescheduled on Node B
         │     Volumes: Longhorn detaches from A, reattaches on B
         │
  t=60s  Drain complete
         │
  t=65s  NodeDrainStatus: COMPLETE → baseosmgr proceeds
         │
  t=70s  Node A reboots for OS update
         │

  ┌──────────────────────┐     ┌──────────┐
  │        Node B        │     │  Node C  │
  │                      │     │(tie-brkr)│
  │  [App-1]   [App-2]   │     │          │
  │  Running   Running   │     │          │
  └──────────────────────┘     └──────────┘

POST-REBOOT RECOVERY
═════════════════════
  Node A boots:
    nodeOnBootHealthStatusWatcher() uncordons node
    Node A: Schedulable=true
    Longhorn: rebuilds replica on Node A
    App-1: may stay on Node B (no automatic failback)

  ┌───────────────────────────────────────────────┐
  │ PubSub flow:                                  │
  │  baseosmgr/zedagent → NodeDrainRequest        │
  │  zedkube            → NodeDrainStatus         │
  │                        (STARTING→CORDONED     │
  │                         →DRAINRETRYING        │
  │                         →COMPLETE/FAILED)     │
  └───────────────────────────────────────────────┘
```

---

## Scenario 7: etcd Quorum Loss

**Trigger:** 2 of 3 nodes become unavailable simultaneously.

```
BEFORE FAILURE
══════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │(tie-brkr)│
  │  etcd    │     │  etcd    │     │  etcd    │
  │ [App-1]  │     │ [App-2]  │     │          │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 3/3 ✅  Quorum: 2/3 needed

FAILURE EVENT  (Nodes A+B crash)
═════════════════════════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │  ████    │     │  ████    │     │(tie-brkr)│
  │  CRASH   │     │  CRASH   │     │  etcd    │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 1/3 ✗  QUORUM LOST

CLUSTER STATE  (Node C alone)
══════════════════════════════
  Kubernetes API: READ-ONLY (no writes committed)
  Leader election: STALLED
    KubeLeaderElectInfo:
      IsStatsLeader    = false
      InLeaderElection = false
      ElectionRunning  = false
      isDecisionNode() = false

  Existing pods: still running (kubelet is local — but no apps on C)
  New scheduling: BLOCKED
  Volume operations: STALLED
  Controller config: ConfigGetStatus ≠ success/saved

RECOVERY PATHS
══════════════

  PATH A: Recover original node (preferred)
  ─────────────────────────────────────────
  1. Restart Node A or Node B
  2. etcd member rejoins: 2/3 → quorum restored
  3. Kubernetes API becomes writable
  4. Leader election re-runs (Node B or A acquires Lease)
  5. Apps rescheduled on recovered nodes
  6. Normal operation resumes

  PATH B: etcd disaster recovery (last resort)
  ─────────────────────────────────────────────
  1. Remove dead members from etcd:
       etcdctl member remove <id-A>
       etcdctl member remove <id-B>
  2. Bootstrap new nodes with fresh etcd members
  3. Add members back to cluster
  4. ⚠ Application data/state may be lost
  5. Longhorn volumes may need manual repair

  ┌──────────────────────────────────────────────────────┐
  │ IMPORTANT:                                           │
  │  • Tie-breaker alone CANNOT recover quorum           │
  │  • Must have ≥1 real master node healthy             │
  │  • Data written during quorum loss is UNRECOVERABLE  │
  │  • Operator alert: KubeClusterInfo reports degraded  │
  └──────────────────────────────────────────────────────┘
```

---

## Scenario 8: App-Level Failure (Pod CrashLoop)

**Trigger:** Container exits with non-zero status; Kubernetes enters `CrashLoopBackOff`.

```
APP CRASH SEQUENCE
══════════════════

  ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │
  │ (leader) │     │          │
  │ [App-1]  │     │ [App-2]  │
  │ Running  │     │ Running  │
  └──────────┘     └──────────┘

  App-1 container exits (non-zero)
         │
  K8s ReplicaSet controller:
  Restart #1  → immediate
  Restart #2  → 10s backoff
  Restart #3  → 20s backoff
  Restart #4  → 40s backoff
  Restart #5  → 80s backoff   ← CrashLoopBackOff
  ...         → exponential (max ~5 min)

  zedkube checkAppsStatus() detects:
    Pod.Status.Phase ≠ Running
    └─ publishes ENClusterAppStatus:
         StatusRunning = false
         ScheduledOnThisNode = true (still on Node A)

  ┌──────────────────────────────────────────────────────┐
  │ KEY DIFFERENCE FROM NODE FAILURE:                    │
  │  • Pod stays on Node A (node is healthy)             │
  │  • NO volume detachment triggered                    │
  │  • NO rescheduling to another node                   │
  │  • Affinity preserved                                │
  │  • zedkube does NOT call DetachOldWorkload()         │
  │                                                      │
  │  Exception: AffinityType = RequiredDuringScheduling  │
  │    → failover.go lines 55-59 skip failover entirely  │
  └──────────────────────────────────────────────────────┘

RECOVERY OPTIONS
════════════════

  Option A: Operator fixes the app (update image/config)
  ────────────────────────────────────────────────────
  Controller pushes new AppInstanceConfig
    → zedagent → zedmanager → domainmgr
    → kubevirt: update VMI/Pod spec
    → K8s rolling update → new pod

  Option B: Manual restart (reset CrashLoopBackOff)
  ─────────────────────────────────────────────────
  kubectl delete pod <app-pod> -n eve-kube-app
    → ReplicaSet recreates immediately
    → backoff counter reset to 0

  Option C: Wait (if transient issue)
  ────────────────────────────────────
  App may self-heal after backoff window
  Max backoff ≈ 5 minutes between restarts

  ┌──────────────────────────────────────────────────────┐
  │ Node failover vs App failover:                       │
  │                                                      │
  │  Node crash  → workload MIGRATED to another node     │
  │  App crash   → workload RESTARTED on same node       │
  └──────────────────────────────────────────────────────┘
```

---

## Combined: Failover Decision Tree

```
  Failure detected
        │
        ▼
  ┌─────────────────┐
  │  Node healthy?  │
  └────────┬────────┘
           │
     ┌─────┴──────┐
    YES            NO
     │              │
     ▼              ▼
  App-level     ┌──────────────────┐
  failure       │  etcd quorum OK? │
  (Scenario 8)  └────────┬─────────┘
  Restart on         │
  same node    ┌──────┴──────┐
              YES             NO
               │               │
               ▼               ▼
         ┌──────────────┐  Quorum loss
         │  Is it the   │  (Scenario 7)
         │  leader?     │  API read-only
         └──────┬───────┘  Manual recovery
                │
          ┌─────┴─────┐
         YES           NO
          │             │
          ▼             ▼
     Leader fails   Worker fails
     (Scenario 2)   (Scenario 1)
     Re-election    Reschedule
     → then         workloads
     Scenario 1     on healthy
                    node
                        │
                        ▼
               ┌────────────────┐
               │  Tie-breaker?  │
               └───────┬────────┘
                       │
                 ┌─────┴─────┐
                YES           NO
                 │             │
                 ▼             ▼
           Scenario 4     Scenario 5
           (no workload   (volume
           impact)        degraded)
```

---

## Timeout Reference

| Parameter | Value | Configurable | Purpose |
|-----------|-------|-------------|---------|
| Node NotReady detection | ~60s | No (K8s default) | Mark node unavailable |
| Pod eviction after NotReady | ~30s | No (K8s default) | Start pod eviction |
| getKubePodsError threshold | 2 min | No (hardcoded) | Mark app not running |
| DetachOldWorkload trigger | 2 min | No (hardcoded) | Force volume detach |
| Lease LeaseDuration | 300s | No | Leader holds lease |
| Lease RenewDeadline | 180s | No | Renew before expiry |
| Lease RetryPeriod | 15s | No | Election retry interval |
| drainSkipK8sAPINotReachableTimeout | 300s | Yes | Skip drain if API down |
| KubernetesDrainTimeout | 24h | Yes | Max drain wait |
| Drain cordon retries | 10× / 5s | No | Cordon retry policy |
| Drain eviction retries | 5× / 300s | No | Drain retry policy |

---

## Source File Reference

| File | Scenario |
|------|----------|
| `pkg/pillar/cmd/zedkube/failover.go` | 1, 2, 3, 5 |
| `pkg/pillar/cmd/zedkube/leaderelect.go` | 2, 3, 7 |
| `pkg/pillar/cmd/zedkube/drain.go` | 5, 6 |
| `pkg/pillar/cmd/zedkube/handlenodedrain.go` | 6 |
| `pkg/pillar/cmd/zedkube/clusterstatus.go` | 2, 4, 7 |
| `pkg/pillar/cmd/zedkube/applogs.go` | 1, 8 |
| `pkg/pillar/cmd/zedkube/podutils.go` | 1, 8 |
| `pkg/pillar/kubeapi/kubeapi.go` | 1, 5 (DetachOldWorkload) |
| `pkg/kube/tie-breaker-utils.sh` | 4 |
| `pkg/kube/longhorn-utils.sh` | 5 |
