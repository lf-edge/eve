# EVE-K: 3-Node Full Control-Plane Cluster — Failover Scenarios

## Cluster Topology

All 3 nodes run: **etcd + K3s control-plane + worker + Longhorn replica**

```
  ┌───────────────────────────────────────────────────────────────┐
  │              3-Node Full Control-Plane Cluster                │
  │                                                               │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
  │  │    Node A    │  │    Node B    │  │    Node C    │        │
  │  │              │  │              │  │              │        │
  │  │ etcd ●       │  │ etcd ●       │  │ etcd ●       │        │
  │  │ control-pln  │  │ control-pln  │  │ control-pln  │        │
  │  │ worker       │  │ worker       │  │ worker       │        │
  │  │ [vol-rep-1]  │  │ [vol-rep-2]  │  │ [vol-rep-3]  │        │
  │  │ Schedulable  │  │ Schedulable  │  │ Schedulable  │        │
  │  └──────────────┘  └──────────────┘  └──────────────┘        │
  │                                                               │
  │  K3s mode:  ALL nodes run `k3s server` (not `k3s agent`)      │
  │  Longhorn:  3 replicas per volume (default storage class)     │
  │  Quorum:    Any 2 of 3 nodes = cluster operational            │
  │  TieBreakerNodeID: UNSET                                      │
  │  IsWorkerNode: true on ALL nodes                              │
  └───────────────────────────────────────────────────────────────┘
```

### Node roles vs. Tie-Breaker topology

```
  FULL 3-MASTER                   TIE-BREAKER
  ═════════════                   ═══════════════

  Node A: etcd + CP + work        Node A: etcd + CP + work
  Node B: etcd + CP + work        Node B: etcd + CP + work
  Node C: etcd + CP + work        Node C: etcd + CP only
          ↑ ALL schedulable               ↑ cordoned, no workloads
                                          ↑ lh-sc-rep2 (2 replicas)
                                          ↑ TieBreakerNodeID set

  Longhorn replicas: 3 nodes      Longhorn replicas: 2 nodes
  Failover targets:  any 2        Failover targets:  1 remaining
  Safe drain:        YES          Safe drain master: NO (loses quorum)
```

---

## Scenario 1: Single Node Failure (Any Node)

**All 3 permutations behave identically. Node C shown as example.**

```
BEFORE FAILURE
══════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │          │
  │ etcd ●   │     │ etcd ●   │     │ etcd ●   │
  │ [App-1]  │     │ [App-2]  │     │ [App-3]  │
  │ [rep-1]  │     │ [rep-2]  │     │ [rep-3]  │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 3/3 ✅  Quorum: 2/3 needed

FAILURE EVENT  (Node C crashes)
════════════════════════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │  ████    │
  │ etcd ●   │     │ etcd ●   │     │  CRASH   │
  │ [App-1]  │     │ [App-2]  │     │          │
  │ [rep-1]  │     │ [rep-2]  │     │ [rep-3]✗ │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 2/3 ✅  Quorum maintained

FAILOVER SEQUENCE
═════════════════
  t=0    Node C unreachable
         │
  t=60s  K8s marks Node C: Ready=False
         │
  t=90s  ReplicaSet evicts App-3 pod (Terminating)
         │
  t=120s zedkube (leader, Node A):
         │  pod terminating >2min → DetachOldWorkload()
         │  ├─ Remove virt-launcher finalizers
         │  ├─ Delete PVC attachment on Node C
         │  └─ Force VMI termination
         │
  t=125s Longhorn: rep-3 offline
         │  Rebuilds 3rd replica on Node A or B
         │  (Both eligible — no tie-breaker restrictions)
         │
  t=130s K8s scheduler picks Node A or B for App-3
         │  └─ App-3: Pending → Running
         │
  t=140s zedkube publishes ENClusterAppStatus: App-3 Running

AFTER RECOVERY  (Node A absorbs App-3 in this example)
═══════════════════════════════════════════════════════
  ┌──────────────────────┐     ┌──────────┐
  │        Node A        │     │  Node B  │
  │      (leader)        │     │          │
  │ etcd ●               │     │ etcd ●   │
  │ [App-1]   [App-3]    │     │ [App-2]  │
  │ [rep-1]   [rep-3b]   │     │ [rep-2]  │
  └──────────────────────┘     └──────────┘

  ┌───────────────────────────────────────────────────────┐
  │ Any of the 3 permutations:                            │
  │   Node A fails → Apps & replicas move to B or C      │
  │   Node B fails → Apps & replicas move to A or C      │
  │   Node C fails → Apps & replicas move to A or B      │
  │                                                       │
  │ Advantage over tie-breaker:                           │
  │   2 healthy nodes available as failover targets       │
  │   (vs. only 1 in tie-breaker topology)                │
  └───────────────────────────────────────────────────────┘
```

---

## Scenario 2: Leader Node Failure

**Unique to full 3-master: any of 2 remaining nodes may become the new leader.**

```
BEFORE FAILURE
══════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │          │
  │ Lease ●  │     │          │     │          │
  │ [App-1]  │     │ [App-2]  │     │ [App-3]  │
  └──────────┘     └──────────┘     └──────────┘

FAILURE EVENT  (Node A crashes)
════════════════════════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │  ████    │     │          │     │          │
  │  CRASH   │     │ attempts │     │ attempts │
  │          │     │ Lease    │     │ Lease    │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 2/3 ✅  Quorum maintained

LEADER RE-ELECTION  (race between B and C)
══════════════════════════════════════════
  Lease: LeaseDuration=300s, RenewDeadline=180s, RetryPeriod=15s

  t=0    Node A stops renewing
         │
  t=180s RenewDeadline exceeded
         │  Node B and Node C both attempt Lease acquisition
         │  (RetryPeriod=15s, first-writer-wins in etcd)
         │
  t=180s One node wins (e.g. Node B)
         │  KubeLeaderElectInfo:
         │    IsStatsLeader  = true   (Node B)
         │    IsStatsLeader  = false  (Node C)
         │    LeaderIdentity = "node-b"
         │
  t=185s Node B: isDecisionNode=true
         └─ Drives App-1 failover (as Scenario 1)
            App-1 moves to Node B or Node C

  ┌────────────────────────────────────────────────────────┐
  │ Key difference vs. tie-breaker:                        │
  │   Tie-breaker topology: only 1 candidate for leader    │
  │   Full 3-master:        2 candidates race for Lease    │
  │   Both topologies: Lease LeaseDuration=300s (same)     │
  └────────────────────────────────────────────────────────┘
```

---

## Scenario 3: Two Node Failure (Quorum Loss)

**Identical to Scenario 7 in tie-breaker document — any 2-node loss loses quorum.**

```
BEFORE FAILURE
══════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │          │
  │ etcd ●   │     │ etcd ●   │     │ etcd ●   │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 3/3 ✅

FAILURE EVENT  (Nodes A+B crash)
═════════════════════════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │  ████    │     │  ████    │     │          │
  │  CRASH   │     │  CRASH   │     │ etcd ●   │
  └──────────┘     └──────────┘     └──────────┘
  etcd: 1/3 ✗  QUORUM LOST

  Kubernetes API: READ-ONLY
  Leader election: STALLED
  KubeLeaderElectInfo: InLeaderElection=false, ElectionRunning=false
  New scheduling: BLOCKED

  ┌───────────────────────────────────────────────────────┐
  │ FULL 3-MASTER vs. TIE-BREAKER comparison:             │
  │                                                       │
  │ Full 3-master:                                        │
  │   Any single-node loss: cluster survives ✅           │
  │   Any 2-node loss:      quorum lost ✗                 │
  │   Apps on surviving node: continue running            │
  │                                                       │
  │ Tie-breaker:                                          │
  │   Any single-node loss: cluster survives ✅           │
  │   Any 2-node loss:      quorum lost ✗                 │
  │   Apps on surviving non-TB node: continue running     │
  │                                                       │
  │ Quorum threshold is IDENTICAL for both topologies     │
  └───────────────────────────────────────────────────────┘

RECOVERY PATHS
══════════════
  PATH A: Recover either Node A or Node B
    etcd: 2/3 → quorum restored
    K8s API writable again
    Leader election: Node C or recovered node wins
    Apps on lost nodes rescheduled on survivors

  PATH B: etcd disaster recovery (last resort)
    etcdctl member remove <failed-member-ids>
    Bootstrap replacement nodes
    ⚠ State and volume data may be lost
```

---

## Scenario 4: Network Partition (Split-Brain)

**More complex than tie-breaker because all 3 nodes run workloads.**

```
BEFORE PARTITION
════════════════
  ┌──────────┐         ┌──────────┐         ┌──────────┐
  │  Node A  │─────────│  Node B  │─────────│  Node C  │
  │ (leader) │         │          │         │          │
  │ [App-1]  │         │ [App-2]  │         │ [App-3]  │
  └──────────┘         └──────────┘         └──────────┘

PARTITION  (Node A isolated from B+C)
═══════════════════════════════════════
  ┌──────────┐    ╳    ┌──────────┐─────────┌──────────┐
  │  Node A  │◄──✗──►  │  Node B  │         │  Node C  │
  │ (leader) │         │          │         │          │
  │ [App-1]  │         │ [App-2]  │         │ [App-3]  │
  └──────────┘         └──────────┘         └──────────┘
  1/3 minority         2/3 quorum ✅

ZONE A (minority)           ZONE B+C (quorum)
─────────────────           ────────────────────────────────
etcd: read-only             etcd: writable
Lease cannot renew          Node B or C wins new Lease
App-1: still running        Node A: marked NotReady at t=60s
  (local kubelet)           App-1 rescheduled on B or C
No new scheduling           App-2, App-3: continue normally
KubeLeaderElectInfo:
  InLeaderElection=false

SPLIT-BRAIN STATE  (worst case)
════════════════════════════════
  App-1 running in BOTH zones simultaneously:
    Zone A: App-1 (old, local kubelet keeps it alive)
    Zone B: App-1 (new, rescheduled by cluster controller)

  Longhorn volume:
    rep-1 on Node A: still accepting writes (isolated)
    rep-2 on Node B: receiving writes from new App-1
    rep-3 on Node C: receiving writes from new App-1
    ↑ DATA DIVERGENCE between rep-1 and rep-2/rep-3

  ┌─────────────────────────────────────────────────────────┐
  │ Higher risk than tie-breaker split-brain:               │
  │   All 3 nodes have active workloads                     │
  │   All 3 nodes have Longhorn replicas                    │
  │   Split can diverge data on all replicas simultaneously │
  └─────────────────────────────────────────────────────────┘

NETWORK HEALS
═════════════
  etcd sync: Node A receives missed entries from B+C
  Conflicting App-1 pod on A: terminated (B+C state wins)
  Longhorn: rep-1 diverged → rebuild from rep-2/rep-3
  App-1: single instance on B or C
  ⚠ Data written to rep-1 during partition: LOST
```

---

## Scenario 5: Manual Node Drain (Maintenance)

**Key advantage of full 3-master: draining any node is safe (2/3 quorum stays intact).**

```
DRAIN WITH FULL 3-MASTER
═════════════════════════
  ┌──────────┐     ┌──────────┐     ┌──────────┐
  │  Node A  │     │  Node B  │     │  Node C  │
  │ (leader) │     │          │     │          │
  │ [App-1]  │     │ [App-2]  │     │ [App-3]  │
  └──────────┘     └──────────┘     └──────────┘

  baseosmgr publishes NodeDrainRequest for Node C
         │
  t=0s   Node C CORDONED
         │  New pods: will not schedule here
         │
  t=10s  App-3 evicted from Node C
         │  K8s scheduler: Node A or B? (both available!)
         │  └─ Let's say Node B is picked
         │
  t=60s  Longhorn: rep-3 moves from C to A (rebuild)
         │
  t=90s  Drain complete → NodeDrainStatus: COMPLETE
         │
  t=95s  Node C reboots for OS update

  DURING DRAIN:
  ┌──────────┐     ┌──────────────────────┐
  │  Node A  │     │        Node B        │
  │ (leader) │     │                      │
  │ etcd ●   │     │ etcd ●               │
  │ [App-1]  │     │  [App-2]   [App-3]   │
  │ [rep-1]  │     │  [rep-2]   [rep-3]   │
  └──────────┘     └──────────────────────┘
  etcd: 2/3 ✅  QUORUM MAINTAINED ← KEY DIFFERENCE

  ┌─────────────────────────────────────────────────────────┐
  │ CRITICAL DIFFERENCE vs. TIE-BREAKER:                   │
  │                                                         │
  │ Full 3-master drain of any node:                        │
  │   etcd quorum: 2/3 ✅ SAFE                              │
  │   Workload failover: 2 target nodes available           │
  │                                                         │
  │ Tie-breaker drain of master node:                       │
  │   etcd quorum: 1/2 ✗ UNSAFE — would lose quorum        │
  │   (Cannot safely drain a master in tie-breaker setup    │
  │    unless tie-breaker node is the one being drained)    │
  └─────────────────────────────────────────────────────────┘

DRAIN STATE MACHINE  (same as tie-breaker)
══════════════════════════════════════════
  NOTREQUESTED → STARTING → CORDONED
    → DRAINRETRYING (if needed, 5x / 300s)
    → COMPLETE  or  FAILEDDRAIN

  Skip conditions:
    Single-node cluster → NOTSUPPORTED
    k3s API down >300s  → COMPLETE (skip drain)

POST-REBOOT
═══════════
  Node C boots → nodeOnBootHealthStatusWatcher() uncordons
  Node C schedulable again
  App-3 may stay on Node B (no automatic failback)
  Longhorn: rebuilds 3rd replica on Node C
```

---

## Scenario 6: Longhorn Volume Failure (3-Replica Advantage)

**Full 3-master uses 3-replica volumes — survives 1-node storage failure without degradation.**

```
LONGHORN REPLICA DISTRIBUTION
══════════════════════════════
  Full 3-master (StorageClass: longhorn, replicas=3):
    Node A: rep-1
    Node B: rep-2
    Node C: rep-3

  Tie-breaker (StorageClass: lh-sc-rep2, replicas=2):
    Node A: rep-1
    Node B: rep-2
    Node C: NONE (excluded)

FAILURE COMPARISON
══════════════════

  Case: Node B crashes

  FULL 3-MASTER:                     TIE-BREAKER:
  ──────────────                     ────────────
  Node A: rep-1 ✅                   Node A: rep-1 ✅
  Node B: rep-2 ✗ (offline)          Node B: rep-2 ✗ (offline)
  Node C: rep-3 ✅                   Node C: NONE

  Volume state: DEGRADED             Volume state: FAULTED
  (2 of 3 replicas online)           (1 of 2 replicas online)
  App continues running ✅            App pod: STUCK ✗
  Longhorn rebuilds rep-2            Manual repair required
    on available node

  ┌───────────────────────────────────────────────┐
  │ Full 3-master: can survive 1 storage failure  │
  │   Volume degrades but app keeps running       │
  │                                               │
  │ Tie-breaker (2-replica): any storage failure  │
  │   → volume FAULTED → app cannot run           │
  └───────────────────────────────────────────────┘

REBUILD PATH  (Full 3-master, Node B lost)
══════════════════════════════════════════
  rep-2 offline → Longhorn schedules rebuild on Node A or C
         │
  Node A has space → rebuilds rep-2b on Node A
         │
  Volume: 3 replicas again ✅  (A=rep-1, A=rep-2b, C=rep-3)
         │
  If Node B recovers:
    Longhorn may rebalance: move rep-2b back to Node B
```

---

## Scenario 7: Rolling Update (All 3 Nodes, One at a Time)

**Unique to full 3-master: can safely roll updates across all nodes sequentially.**

```
ROLLING UPDATE SEQUENCE
════════════════════════
  Goal: Update OS/EVE on all 3 nodes without downtime

  STEP 1: Drain and update Node C
  ────────────────────────────────
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │  Node A  │   │  Node B  │   │  Node C  │
  │ etcd ●   │   │ etcd ●   │   │  DRAIN   │
  │ [App-1]  │   │ [App-2]  │   │ updating │
  │          │   │ [App-3]  │   │          │
  └──────────┘   └──────────┘   └──────────┘
  etcd: 2/3 ✅ quorum

  STEP 2: Node C updated, rejoin. Drain and update Node B
  ─────────────────────────────────────────────────────────
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │  Node A  │   │  Node B  │   │  Node C  │
  │ etcd ●   │   │  DRAIN   │   │ etcd ●   │
  │ [App-1]  │   │ updating │   │ [App-3]  │
  │ [App-2]  │   │          │   │          │
  └──────────┘   └──────────┘   └──────────┘
  etcd: 2/3 ✅ quorum

  STEP 3: Node B updated, rejoin. Drain and update Node A
  ─────────────────────────────────────────────────────────
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │  Node A  │   │  Node B  │   │  Node C  │
  │  DRAIN   │   │ etcd ●   │   │ etcd ●   │
  │ updating │   │ [App-1]  │   │ [App-3]  │
  │          │   │ [App-2]  │   │          │
  └──────────┘   └──────────┘   └──────────┘
  etcd: 2/3 ✅ quorum  (Node A is non-leader, election ran in Step 1)

  COMPLETE: All nodes updated, zero downtime ✅

  ┌──────────────────────────────────────────────────────────┐
  │ IMPORTANT: Never drain 2 nodes simultaneously            │
  │   1 node draining → etcd: 2/3 ✅ safe                    │
  │   2 nodes draining → etcd: 1/3 ✗ quorum loss            │
  │                                                          │
  │ Always wait for NodeDrainStatus=COMPLETE + node rejoins  │
  │ before draining the next node.                           │
  └──────────────────────────────────────────────────────────┘
```

---

## Scenario 8: App CrashLoop

**Identical to tie-breaker topology — node-level failover is not triggered.**

```
  App-1 CrashLoopBackOff on Node A
         │
  K8s exponential backoff (0→10→20→40→80s…)
         │
  zedkube publishes:
    ENClusterAppStatus: StatusRunning=false, ScheduledOnThisNode=true
         │
  NO migration to Node B or C
  (node is healthy; only node failures trigger migration)
         │
  Recovery: same as tie-breaker Scenario 8
    - Operator updates AppInstanceConfig
    - kubectl delete pod to reset backoff
    - Wait for transient issue to resolve
```

---

## Failover Decision Tree (Full 3-Master)

```
  Failure detected
        │
        ▼
  ┌─────────────────────┐
  │  How many nodes     │
  │  are down?          │
  └──────────┬──────────┘
             │
      ┌──────┴──────┐
      │             │
     1 node        2+ nodes
      │             │
      ▼             ▼
  ┌─────────────┐  Quorum lost → Scenario 3
  │ Which node? │  API read-only, manual recovery
  └──────┬──────┘
         │
   ┌─────┴─────────────────┐
   │                       │
  Leader              Non-leader
  (Scenario 2)         │
  Re-election          ▼
  first, then    ┌──────────────┐
  workload       │ Has workloads│
  failover       │  on node?    │
                 └──────┬───────┘
                        │
                  ┌─────┴─────┐
                 YES           NO
                  │             │
                  ▼             ▼
           Reschedule      No workload
           to Node A       impact
           or Node B       (replica
           (2 choices!)     rebuild
           Scenario 1       only)
```

---

## Comparison: Full 3-Master vs. Tie-Breaker

```
  TOPOLOGY             FULL 3-MASTER          TIE-BREAKER (2+1)
  ─────────────────────────────────────────────────────────────
  Schedulable nodes    3                      2
  etcd members         3                      3
  Longhorn replicas    3 (default)            2 (lh-sc-rep2)
  Failover targets     2 nodes                1 node
  Storage redundancy   Survive 1-node loss    0 tolerance
  Safe drain           Any 1 node             Tie-breaker only
  Rolling update       Yes (1-at-a-time)      No (loses quorum)
  Resource usage       Higher (3×)            Lower (2×)
  Disk per volume      3× replicated          2× replicated
  Network I/O          3-way replication      2-way replication
  Leader candidates    Any of 3 nodes         Any of 3 nodes
  Cordoned nodes       None                   1 (tie-breaker)
  Config complexity    Lower (no TB setup)    Higher (TB scripts)
  Split-brain risk     Same                   Same
  Quorum loss point    2 nodes down           2 nodes down
  ─────────────────────────────────────────────────────────────
  Best for             High availability      Resource-constrained
                       production workloads   edge deployments
```

---

## Key Config Fields (EdgeNodeClusterConfig)

```go
// pkg/pillar/types/clustertypes.go

type EdgeNodeClusterConfig struct {
    ClusterID        uuid.UUID         // Cluster identifier
    ClusterInterface string            // Network interface for cluster
    ClusterIPPrefix  net.IPNet         // Cluster IP
    IsWorkerNode     bool              // This node runs workloads
    BootstrapNode    bool              // First node to initialize cluster
    TieBreakerNodeID UUIDandVersion    // UUID of tie-breaker (UNSET = full 3-master)
    JoinServerIP     net.IP            // Existing node to join
    EncryptedClusterToken string       // Bootstrap token
    ClusterContext   string            // Context name in kubeconfig
}
```

**Full 3-master setup:**
- `IsWorkerNode = true` on all 3 nodes
- `TieBreakerNodeID = uuid.UUID{}` (zero value, unset)
- No tie-breaker scripts run
- No node cordoning
- No `lh-sc-rep2` storage class created

---

## Timeout Reference

| Parameter | Value | Configurable | Notes |
|-----------|-------|-------------|-------|
| Node NotReady detection | ~60s | No | K8s default |
| Pod eviction after NotReady | ~30s | No | K8s default |
| DetachOldWorkload trigger | 2 min | No | Same as tie-breaker |
| Lease LeaseDuration | 300s | No | Same as tie-breaker |
| Lease RenewDeadline | 180s | No | 2 candidates race in 3-master |
| Lease RetryPeriod | 15s | No | Same as tie-breaker |
| drainSkipK8sAPINotReachableTimeout | 300s | Yes | Same as tie-breaker |
| KubernetesDrainTimeout | 24h | Yes | Same as tie-breaker |
| Longhorn rebuild start | ~60-120s | No | After replica offline |

---

## Source File Reference

| File | Relevant Scenarios |
|------|--------------------|
| `pkg/pillar/types/clustertypes.go` | Config structure, TieBreakerNodeID field |
| `pkg/pillar/cmd/zedkube/failover.go` | 1, 2 (identical logic to tie-breaker) |
| `pkg/pillar/cmd/zedkube/leaderelect.go` | 2 (2 candidates race for Lease) |
| `pkg/pillar/cmd/zedkube/drain.go` | 5, 7 (safe drain with 2/3 quorum) |
| `pkg/pillar/cmd/zedkube/clusterstatus.go` | Node role detection via K8s labels |
| `pkg/pillar/cmd/zedkube/applogs.go` | 8 (CrashLoop detection) |
| `pkg/pillar/kubeapi/kubeapi.go` | 1, 6 (DetachOldWorkload, PVC ops) |
| `pkg/kube/tie-breaker-utils.sh` | Absent in full 3-master topology |
| `pkg/kube/cluster-init.sh` | All nodes run `k3s server` mode |
