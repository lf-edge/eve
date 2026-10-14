# CPU Placement and Isolation

EVE can give a workload CPUs of its own: whole physical cores, one vCPU per
core, or individual threads, kept NUMA-local and, on a node booted with
`isolcpus`, on cores the kernel isolates. The controller says what a workload
needs; `domainmgr` chooses the host CPUs, pins a VM's vCPUs when asked to, and
reports the result.

This document describes the KVM hypervisor (eve-kvm). See
[Hypervisor support](#hypervisor-support) for EVE-k.

## Two choices

A placement request makes two independent choices, one field each:

- **The pool** (`cpu_policy`): `HOUSEKEEPING`, the CPUs the kernel keeps for the
  system, shared with EVE and every other workload in that pool; `DEDICATED`,
  CPUs of the workload's own; or `ISOLATED`, CPUs of its own that the kernel
  isolates.
- **Pinning** (`pin_cpu`): whether EVE pins each vCPU of a VM to its own CPU of
  that pool.

Each field means the same whatever the others say. A combination the device
does not serve is refused, with the reason in the app's info; it is never
reinterpreted.

The pool is the workload's isolation level, and pinning is a choice on each of
them. What is served today (VM includes a container in a shim VM; see below):

| Pool | Isolation | Pinned | Not pinned |
|---|---|---|---|
| `HOUSEKEEPING` | none: shared with EVE and every other workload in the pool | refused | VM, native container |
| `DEDICATED` | soft: CPUs of its own, no other workload or EVE service on them; kernel threads and interrupts still run there | VM | native container |
| `ISOLATED` | hard: CPUs the kernel isolates (`isolcpus`), so its scheduler stays off them too | VM | native container |

## Placement modes

In every pinned mode a vCPU is pinned to exactly one host logical CPU (one
hardware thread). The modes differ in what happens to the other thread of each
physical core, and in what the guest is told.

| Mode | Requested with | vCPU mapping | The other thread of the core | Guest topology |
|---|---|---|---|---|
| Whole core, both threads | `DEDICATED` or `ISOLATED`, `pin_cpu`, `full_pcpus_only`, `threads_per_core=2` | two vCPUs on the two siblings of one core | the workload's own | `threads=2` |
| One thread per core | `DEDICATED` or `ISOLATED`, `pin_cpu`, `full_pcpus_only`, `threads_per_core=1` | one vCPU per physical core | parked: held for the workload, given to no other workload | `threads=1` |
| Thread-granular | `DEDICATED`, `pin_cpu`, no `full_pcpus_only` | one vCPU per logical CPU | may belong to another workload or to EVE | flat |
| Housekeeping | `HOUSEKEEPING` | vCPUs float over the housekeeping CPUs | shared with everything there | flat |

One thread per core is "SMT off" for one workload: no other workload runs on its
cores, while the rest of the node keeps SMT. The parked sibling is held but
idle: it is in no cpuset, the workload's own included, so QEMU's non-vCPU
threads share the vCPU CPUs unless `io_placement=HOUSEKEEPING` moves them to
EVE's CPUs. It stays online: kernel threads, timers and interrupts can still
run on it.

A native container (`NOHYPER`) has no vCPUs. With `DEDICATED` or `ISOLATED` it
gets its CPUs as its cpuset, `pin_cpu` stays false, and its threads run where
the kernel or the container itself places them: a real-time container in the
isolated pool sets its own threads' affinity. A container in a shim VM (an OCI
image under any other virtualization mode) runs as a VM, with vCPUs, and is
placed exactly like one.

## Requesting a placement

The placement intent travels in `VmConfig`, next to the existing `vcpus` count.

| Field | Values | When unset |
|---|---|---|
| `cpu_policy` | `HOUSEKEEPING`, `DEDICATED`, `ISOLATED` | housekeeping, or the legacy rule below |
| `pin_cpu` | bool: EVE pins each vCPU of a VM to its own CPU of the pool | false |
| `full_pcpus_only` | bool: whole physical cores, no other workload on their siblings | false |
| `threads_per_core` | `1`, `2`, with `full_pcpus_only` | `2` |
| `numa_policy` | `NONE`, `BEST_EFFORT`, `SINGLE_NUMA_NODE`, with `full_pcpus_only` | `BEST_EFFORT` |
| `io_placement` | `DEDICATED`, `HOUSEKEEPING`: where a VM's non-vCPU QEMU threads run, with `full_pcpus_only` | `DEDICATED` |

`full_pcpus_only`, `threads_per_core`, `numa_policy` and `io_placement` refine a
`DEDICATED` or `ISOLATED` request.

Legacy: a controller that predates `cpu_policy` sends only `pin_cpu`. With
`cpu_policy` unset and no other field set, `pin_cpu=true` means `DEDICATED`: a VM
pinned, a native container on CPUs of its own.

What a request is served as:

| `cpu_policy` | `pin_cpu` | VM or container in a shim VM | Native container (`NOHYPER`) |
|---|---|---|---|
| `HOUSEKEEPING` | false | served | served |
| `HOUSEKEEPING` | true | refused, not implemented | refused: no vCPUs |
| `DEDICATED` | true | served | refused: no vCPUs |
| `DEDICATED` | false | refused, not implemented | served |
| `ISOLATED` | true | served, with `full_pcpus_only` | refused: no vCPUs |
| `ISOLATED` | false | refused, not implemented | served, with `full_pcpus_only` |

A request the device cannot serve as sent is refused rather than run on a
weaker placement:

- A combination the table marks refused, a refining field without `DEDICATED`
  or `ISOLATED`, `threads_per_core`, `numa_policy` or `io_placement` without
  `full_pcpus_only`, `io_placement` on a native container, `ISOLATED` without
  `full_pcpus_only`, and a `threads_per_core` other than 1 or 2 are refused as
  `POLICY_INVALID`.
- Whole core with both threads and an odd vCPU count is refused as `ODD_VCPU`.
- `ISOLATED` on a node that isolates no CPU is refused as
  `ISOLATION_UNAVAILABLE`.
- On a node without two-thread cores (SMT off in firmware, and most ARM64
  parts) `threads_per_core=2`, the default, is refused as
  `TOPOLOGY_UNSUPPORTED`; such a request must set `threads_per_core=1`.
- On a node whose CPU topology could not be read, every `DEDICATED` or
  `ISOLATED` request, legacy `pin_cpu` included, is refused as
  `TOPOLOGY_UNSUPPORTED`.
- `io_placement=HOUSEKEEPING` on a node with no CPU to serve it (see
  [Enforcement on KVM](#enforcement-on-kvm), step 4) is refused as
  `INSUFFICIENT`.

The names are the values of `ZInfoApp.cpu_placement_status` without their
`CPU_PLACEMENT_STATUS_` prefix (see [Failures and repack](#failures-and-repack)).

One preference gives way instead of failing: `BEST_EFFORT` spans NUMA nodes
when no single node has enough free cores.

NUMA is taken as the running kernel reports it; a kernel without NUMA
information is one node. The guest of a workload that spans nodes is still told
it has one socket, so a workload that relies on its guest topology should use
`SINGLE_NUMA_NODE`.

A controller sends these fields only to a device that sets
`ZInfoDevice.optional_capabilities.cpu_placement`, which only an EVE reporting
`API_CAPABILITY_CPU_PLACEMENT_POLICY` sets; it sends a `DEDICATED`,
`ISOLATED` or pinned request only to a node whose inventory reports the CPU
topology, and `ISOLATED` only to one that reports isolated CPUs. An enum value
the device does not know is treated as unspecified, which is safe only because
of the capability gate.

## CPU pools

The node's online CPUs fall into three disjoint pools:

| Pool | CPUs |
|---|---|
| `ISOLATED` | the CPUs the running kernel isolates (`isolcpus`), whether free or held by `ISOLATED` workloads |
| `DEDICATED` | CPUs outside the isolated set held by `DEDICATED` workloads, including parked siblings |
| `HOUSEKEEPING` | everything else: the CPUs reserved for EVE, and the free CPUs housekeeping workloads run on |

The lowest `eve_max_vcpus` CPUs (kernel command line, default 1) are reserved
for EVE's own services. No workload of the dedicated or isolated pool is given
one, and a whole-core request skips every core that contains one, so N reserved
CPUs can cost up to N whole cores. Housekeeping workloads, and emulator threads
under `io_placement=HOUSEKEEPING`, do run there.

## How CPUs are chosen

Placement is planned for the whole set of workloads configured to run, not for
whichever starts first. `zedmanager` publishes that set (`CPUDemandSet`) as soon
as the app configs are resolved, before any volume is ready, and `domainmgr`
computes the plan from an empty node:

1. Requests are ordered by how constrained they are (whole core with both
   threads first, then one thread per core, then thread-granular), then by vCPU
   count, largest first, then by UUID.
2. A whole-core request takes free cores in `(socket, core_id)` order. Under
   `SINGLE_NUMA_NODE` and `BEST_EFFORT` it takes them from the lowest-numbered
   NUMA node with enough free cores. When no node has enough, `BEST_EFFORT`
   spans as few nodes as can hold the workload, taking the nodes with the most
   free cores first (the lower-numbered on a tie), and `SINGLE_NUMA_NODE` is
   refused.
   `NONE` always takes cores across nodes in node order, so it can span nodes
   even when one would do.
3. A thread-granular request takes the lowest-numbered free CPUs.

Placement does not consider core class. On a hybrid part with performance and
efficiency cores, a one-thread-per-core or thread-granular workload may get
efficiency cores, or a mix; whole core with both threads fits only two-thread
cores, which on such parts are the performance cores.

The plan is a function of the topology, the reserved CPUs, the isolated CPUs and
the configured workloads, so the same set of workloads lands on the same CPUs on
every boot and in any start order. It is recomputed rather than stored;
`/run/domainmgr/cpuplan.json` mirrors it for inspection only.

The workloads planned for are those the controller intends to run: the ones
`zedmanager`'s demand set names, which it publishes as soon as an app's config
arrives, and any whose `DomainConfig` asks for activation.

When a workload starts it claims its planned CPUs if they are free. If they are
not, it is placed among the free CPUs other than those the plan sets aside for
workloads not started yet, and if it does not fit it is refused (see
[Failures and repack](#failures-and-repack)). A whole-core placement made this
way is scored by NUMA nodes spanned, then L3 domains spanned: at the planned
score the workload runs normally, at a worse score it runs as
`REPACK_ADVISED`. A thread-granular placement is not scored, so a
thread-granular workload placed off its plan is `PLACED`.

A workload that is configured but not activated is left out of the plan, so its
CPUs go to the workloads that run, as an assigned PCI device returns to the pool
when its workload stops.

## Enforcement on KVM

When a pinned VM starts, `domainmgr` and the KVM backend:

1. Write the workload's cgroup cpuset, its vCPU CPUs without the parked
   siblings (in the OCI spec and directly into the cgroup), before QEMU runs.
2. Launch QEMU paused, with `-smp sockets=1,cores=C,threads=T` from the
   assignment for a whole-core workload and a flat topology otherwise.
3. Read each vCPU's thread id with QMP `query-cpus-fast` and pin each vCPU
   thread to its own host CPU. A vCPU count mismatch fails the launch.
4. For a whole-core workload with `io_placement=HOUSEKEEPING`, pin every other
   QEMU thread to the CPUs reserved for EVE (or, on a node that reserves none,
   to housekeeping CPUs no pinned workload is planned onto) and give
   `virtio-blk` disks an iothread there. The cpuset is widened to include those
   CPUs, so the vCPU threads are confined by their pins. Kernel-isolated CPUs
   are never used for this; a node with no such CPU refuses the workload.
5. Release the guest with QMP `cont`.
6. On x86, wait up to a second for KVM's NX huge-page recovery thread, which
   the first vCPU to run creates in the QEMU process with its own one-CPU
   affinity, and give it the CPUs of the other non-vCPU threads: those of
   step 4, or the vCPU CPUs. This runs after the guest is released,
   so a failure is logged and the guest keeps running.

A native container of the dedicated or isolated pool gets its CPUs as its
cgroup cpuset through containerd; nothing pins its threads.

Housekeeping workloads are confined to the housekeeping set. So are the host's
own processes: `init`, `udevd`, `containerd` and every shim live in a top-level
`housekeeping` cpuset beside `/eve` and `/eve-user-apps`, which `domainmgr`
rewrites on every allocation change before moving any process. The root cpuset
itself cannot be narrowed. Kernel threads are left where they are.

A placement is fixed at launch. Moving a workload to other CPUs means restarting
it.

## Kernel CPU isolation

`cpu_policy=ISOLATED` places a workload on cores the kernel isolates with
`isolcpus`, which keeps the scheduler's load balancing off them. The operator
sets the isolated pool once on the kernel command line, for example in
`/config/grub.cfg`:

```text
set_global dom0_extra_args "$dom0_extra_args isolcpus=12-15,28-31"
```

`domainmgr` reads the effective set from `/sys/devices/system/cpu/isolated` at
startup. Then:

- Isolated cores go only to `ISOLATED` workloads, which take whole cores
  (`full_pcpus_only`) all of whose siblings are isolated.
- Other pinned workloads, whole-core and thread-granular, skip any core with an
  isolated thread. Housekeeping workloads, host processes and emulator threads
  skip the isolated CPUs themselves.
- An `ISOLATED` request on a full isolated pool is refused as `INSUFFICIENT`;
  on a node that isolates nothing, as `ISOLATION_UNAVAILABLE`. EVE does not
  change the kernel command line, and changing the pool takes a reboot.

List both siblings of each isolated core. A range written for an SMT-off boot
isolates one thread of each core once SMT is on: such a core serves no pinned
workload, `ISOLATED` or other, and only housekeeping work runs on its other
thread. Leave the CPUs reserved for EVE out of `isolcpus`: the kernel
does not balance EVE's services onto an isolated CPU. `domainmgr` does not
refuse either mistake, because the workloads that do not use the isolated pool
would go down with it. It reports each one on the `ISOLATED` pool of the node's
pool report, in `warnings`: the issue, `CPU_POOL_ISSUE_RESERVED_CPUS` for CPUs
reserved for EVE or `CPU_POOL_ISSUE_PARTIAL_CORE` for a core isolated on some
of its threads, and a `WARNING` naming the CPUs and what to change. It logs
them too, and an `ISOLATED` request that a half-isolated core leaves short says
so. `nohz_full` is reported but not required.

## Failures and repack

A workload that cannot be placed does not start. Its
`ZInfoApp.cpu_placement_status` says why, and its `AppErr` carries the
description at `ERROR` severity with a `retry_condition` saying what has to
change. It is not retried when CPUs free up. Recovery is an explicit deactivate
and activate, as for an app whose assigned PCI device is unavailable.

| Status | Meaning |
|---|---|
| `INSUFFICIENT` | the plan cannot place the workload, or can only by leaving out a running workload |
| `NEEDS_REPACK` | the free CPUs cannot hold it, but the plan can once the flagged workloads restart |
| `POLICY_INVALID` | a field the request cannot carry, a value out of range, or a combination this EVE does not implement |
| `ODD_VCPU` | whole core with both threads needs an even vCPU count |
| `ISOLATION_UNAVAILABLE` | `ISOLATED` on a node that isolates no CPU |
| `TOPOLOGY_UNSUPPORTED` | the node cannot present the request: an unknown topology, no two-thread cores, or a hypervisor on which EVE cannot choose each vCPU's host CPU |

A workload that runs as planned is `PLACED`. A running workload is
`REPACK_ADVISED`, with a `WARNING` in `AppErr`, and keeps running, for one of
two reasons:

- It runs on a placement worse than its planned one.
- It is placed well, but holds CPUs the plan gives to another workload
  (`RepackFor` names that workload).

A repack is a restart of every workload in `NEEDS_REPACK` or `REPACK_ADVISED`,
all at once, through the per-app restart
counter. The device names the set, following chains of workloads in each
other's way. The restarts may reach the device in any order. A workload whose
planned CPUs are held only by workloads that are stopping or flagged for the
same repack waits for them (`CPUWait`, reported as `WAITING` with a `WARNING`) and
takes them when they are released; one whose planned CPUs are held by a
workload staying where it is is placed or refused at once. A flagged workload
that is never restarted keeps the waiting one waiting until either is stopped.

## Reporting

- **Hardware inventory** (`ZInfoHardware`), collected once at startup:
    - One entry per logical CPU with its socket, core and NUMA node, its L2 and
      L3 cache ids, its core class and its base and maximum frequency. A value
      the device cannot read is unset, never zero: a CPU without `socket_id` and
      `core_id` means the topology could not be read, and the entry then
      carries only its id, model and vendor.
    - Core class is `PERFORMANCE` or `EFFICIENCY` on a hybrid part, `UNIFORM` on
      a homogeneous one, and `UNSPECIFIED` when it cannot be told. It is
      reported only; placement does not use it.
    - The L1 data, L1 instruction, L2 and L3 cache domains with the CPUs sharing
      each.
    - Each PCI device's local CPUs, whose NUMA node is the device's; the list
      spans every node when the platform gives the device no affinity.
    - In `kernel_cpu_isolation`, the CPUs the kernel isolates (`isolcpus`)
      and the `nohz_full` set.
- **CPU pools** (`ZInfoDevice.cpu_pools`): per pool, its CPUs, the free CPUs,
  thread counts and whole-core counts. A free thread on a partly used core
  cannot serve a `full_pcpus_only` request, so `free_whole_cores`, the cores
  all of whose threads are free, is what bounds the next whole-core workload.
  It also counts single-thread cores, which cannot serve a both-threads request.
  Sent when the pools change, and periodically.
- **Per app** (`ZInfoApp`):
    - `cpu_placement_status`: where the workload stands with its CPU request,
      as above; `UNSPECIFIED` for a workload that makes none, or is not active.
    - `AppErr`: the refusals' descriptions and the advisories above.
    - `assigned_cpus`, for a workload with CPUs of its own: the CPUs it runs on
      (`cpu_ids`, in vCPU order for a pinned workload: vCPU i runs only on
      `cpu_ids[i]`), its parked siblings (`parked_cpu_ids`), and the CPUs its
      non-vCPU QEMU threads run on under `io_placement=HOUSEKEEPING`
      (`io_cpu_ids`). Filled from `DomainStatus.CPUAssignment()`; unset
      otherwise.

## Hypervisor support

Every build reports `API_CAPABILITY_CPU_PLACEMENT_POLICY`: it knows the
fields, holds legacy `pin_cpu` to the same rules, and reports outcomes in
`cpu_placement_status`. A node sets `optional_capabilities.cpu_placement` when
it can place CPUs: under KVM, on a CPU topology EVE could read
(`Capabilities.CPUTopologyPinning`). Any other node, EVE-k included, leaves it
unset, so a controller sends it no placement fields.

| Hypervisor | Support |
|---|---|
| KVM | everything in this document |
| EVE-k (KubeVirt) | legacy `pin_cpu` gets KubeVirt's dedicated CPU placement, and KubeVirt chooses the CPUs; whole-core requests are refused as `TOPOLOGY_UNSUPPORTED`, since EVE cannot choose each vCPU's host CPU or present a guest SMT topology there |

## Debugging

| What | Where |
|---|---|
| A domain's CPUs, per-vCPU order, parked siblings, guest topology, emulator CPUs, verdict, `RepackFor`, `CPUWait` | `/run/domainmgr/DomainStatus/<uuid>.json`: `VmConfig.CPUs` (the cpuset, without the parked siblings), `OrderedCPUs`, `ParkedCPUs`, `VMTopology`, `EmulatorCPUs`, `CPUPlacementStatus` (the status's number), `RepackFor`, `CPUWait` |
| The plan, for inspection only (nothing reads it back) | `/run/domainmgr/cpuplan.json` |
| The pools | `/run/domainmgr/CPUPoolStatus/global.json` |
| The demand set | `/run/zedmanager/CPUDemandSet/` |
| cpusets | `/sys/fs/cgroup/cpuset/eve-user-apps/<domain>/cpuset.cpus`, `/sys/fs/cgroup/cpuset/housekeeping/cpuset.cpus` |
| A vCPU's host CPU | `grep Cpus_allowed_list /proc/<qemu pid>/task/<tid>/status`, tids from QMP `query-cpus-fast` |
