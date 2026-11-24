# 2-Node HA

2-Node HA lets an EVE-k cluster of only two devices survive the failure of
either one of them. It builds on the regular EVE-k clustering described in
[EVE-K.md](EVE-K.md) and on the application failover and failback described
in [failover.md](../pkg/pillar/docs/failover.md).

## Motivation

An EVE-k cluster keeps its state in the etcd datastore embedded in k3s, and
etcd only works while a majority of its voting members (a quorum) can reach
each other. With two voting members a majority is both of them, so a
two-device cluster stops as soon as either device fails. The usual answer is
a third device, possibly a [tie breaker](EVE-K.md#tie-breaker-node) that runs
no workloads, but that is still a third piece of hardware to buy, install and
maintain at every site.

2-Node HA removes the third device. The third vote is cast by the
**witness**, a small etcd-only member that runs as an extra container on one
of the two devices. This keeps apps available across the failure of either
device, without any action from the user or the controller. The controller
is only needed afterwards, to restore redundancy: to recover the cluster's
control plane after the loss of the seed, and to replace a device that is
lost for good.

## Limitations

- **One device failure at a time.** The cluster tolerates the loss of one
  device. After a failure it must be brought back to two healthy devices
  (both nodes `Ready`, witness `JOINED`, volume replicas rebuilt) before it
  can survive another one.
- **Each device must be able to run everything alone.** After a failure the
  surviving device runs all apps plus the whole control plane (k3s, etcd,
  KubeVirt, Longhorn) on its own, so each device must be sized for that.
- **No control plane while the seed is down.** The failure of the seed (see
  below) takes the witness down with it, and the cluster loses its quorum.
  Apps placed as required below continue running without interruption, but
  no app can be deployed, changed or moved in the cluster until the seed is
  back or the controller has performed a quorum recovery.
- **Two replicas per volume.** Only two devices can host a Longhorn replica,
  so volumes are created with two replicas instead of the usual three. While
  one device is down, every volume runs on a single replica.
- **Writes on the non-seed are lost if the devices lose their connection.**
  If the two devices lose their connection to each other but keep running,
  the app runs on both (see [The non-seed fails](#the-non-seed-fails)), and
  each copy writes to the volume replica on its own device. Once the
  connection is back, Longhorn keeps the seed's replica and rebuilds the
  non-seed's from it: only the seed and the witness, which hold the quorum,
  can record which replica failed. Whatever the app wrote on the non-seed
  in the meantime is lost, even though it was acknowledged to the app.
  Without the quorum, the non-seed cannot stop its copy through Kubernetes:
  its API server cannot change anything, and kubelet keeps running the pods
  it has. Nor should it stop it by other means, because it cannot tell a
  lost connection from a failed seed, and when the seed fails its copy is
  the one that must keep running. This is a limitation of the current
  solution, not the intended behavior: apps are meant to run on the
  non-seed, so its replicas should be the ones kept. Making them win is
  left for future work.

## How it works

### The witness

The witness is a k3s server that runs only etcd: no apiserver, no scheduler,
no kubelet and no workloads, and it does not appear as a Kubernetes node. It
ships as its own container (`pkg/witness`) in every `HV=k` image, reusing the
`kube-init` and k3s binaries of `pkg/kube`. It is a separate container from
`pkg/kube` so that a restart of k3s on the device hosting it costs one vote,
not two.

The witness is enabled by setting `EdgeNodeCluster.witness.witness_ip` in the
cluster config. That address must fall inside `cluster_ip_prefix` and must
not be used by either device. EVE connects the witness to the cluster
interface with this address, so the witness IP stays the same whichever
device hosts it.

The witness keeps its etcd data in a dedicated `witness-storage` zvol on ZFS
devices installed with `eve_install_k3s_witness` (see
[BOOTING.md](BOOTING.md)), or otherwise in a directory inside the vault.

### Seed and non-seed

The **seed** is the device whose cluster IP is the cluster's
`join_server_ip`. The witness always runs on the seed, and on the other
device, the **non-seed**, it stays idle. The seed role, and with it the
witness, follows `join_server_ip` when the controller changes it.

This gives the cluster three etcd votes: the seed, the witness and the
non-seed.

- **The non-seed fails:** the seed and the witness are two votes out of
  three, so the cluster keeps its quorum and handles the failure on its own.
- **The seed fails:** the witness goes down with it, leaving one vote out of
  three. The cluster loses its quorum, so its control plane stops until
  the seed is back or the controller recovers it, but apps on the non-seed
  continue running without interruption.

### Requirements

- Two EVE-k devices in a cluster of type `CLUSTER_TYPE_REPLICATED_STORAGE`,
  with `EdgeNodeCluster.witness.witness_ip` set.
- On ZFS devices, `eve_install_k3s_witness` given at installation, so that
  the witness gets its own reserved storage (optional, see above).
- Every app that should survive a failure is placed on the **non-seed**:
  `AppInstanceConfig.designated_node_id` is the non-seed device and
  `affinity` is `AFFINITY_TYPE_PREFERRED`, which allows the app to run on the
  other device when the non-seed is unavailable.
- Nothing has to be configured for the apps to return to the non-seed after
  a failure: see [Keeping apps on the non-seed](#keeping-apps-on-the-non-seed).

### Why apps are placed on the non-seed

Placing apps on the non-seed is what keeps them available whichever device
fails:

- **The non-seed fails:** the cluster keeps its quorum, so Kubernetes is
  still able to move the app. It restarts the app on the seed, the only
  surviving device.
- **The seed fails:** the cluster loses its quorum and with it the Kubernetes
  control plane. Nothing can move or restart an app anymore, but an app
  running on the non-seed does not need to move: it keeps running untouched.

An app placed on the seed would survive the failure of the non-seed just as
well, as it would not be affected at all. It is the failure of the seed that
it could not survive: the app would go down with the seed, and with no
control plane left nothing would restart it on the surviving device until
the seed is back or the controller has recovered the cluster.

### Keeping apps on the non-seed

Kubernetes moves an app away from a node that fails, but it never moves it
back on its own. In a cluster of three or more nodes that only costs the
placement the controller asked for: any single failure leaves a quorum that
can restart the app elsewhere. In a 2-node HA cluster, the placement is the
protection: an app left on the seed goes down with the next failure of the
seed, and nothing can restart it until the seed is back or the controller has
recovered the cluster (see
[Why apps are placed on the non-seed](#why-apps-are-placed-on-the-non-seed)).
So the designated node of an app pulls it back whenever it runs on the other
device, without waiting for a reboot: the `periodic` event of
`kubernetes.vmi.deschedule.events` (see
[CONFIG-PROPERTIES.md](CONFIG-PROPERTIES.md)) is always enabled in a 2-node
HA cluster, whatever the setting. This covers a non-seed that
comes back after a failure, whether it rebooted or only lost its connection,
and an app designated to a device after it started, such as a replacement
device or the former seed after a quorum recovery. It applies to VM apps and
native containers alike.

The device acts once it has been ready to receive apps for 3 minutes, and at
most every 3 minutes, so that a device that keeps failing does not pull the
apps back and forth: each move restarts the app. The period is set by
`kubernetes.vmi.deschedule.periodic.settle`, and can be shortened for a
faster return to the non-seed. Apps without a designated
node are left wherever they run. See
[failover.md](../pkg/pillar/docs/failover.md) for how the apps are moved.

## Failure scenarios

The scenarios below assume the cluster was healthy before the failure, with
the app on the non-seed.

### The non-seed fails

**Effect on the app.** Once the non-seed stops reporting to Kubernetes (the
k3s node monitor grace period is 40 seconds), EVE detaches the app's
workload from the unreachable node and Kubernetes restarts the app on the
seed, from its Longhorn replica there. This is a restart: the app is down
from the failure until it is running on the seed. The data written to its
volumes before the failure is preserved.

If the non-seed only lost its connection to the seed, for example in a
network outage, the seed cannot tell this from a failure and starts the app
as well, while the non-seed, without quorum, keeps its own copy running.
Until the connection is back, the app runs on both devices. Then the copy on
the non-seed is stopped, and what it wrote to its volumes in the meantime is
discarded in favor of the seed's copy (see [Limitations](#limitations)).

Once the non-seed is back, whether it rebooted or only regained its
connection, and has been ready for 3 minutes (by default), it pulls the app back (see
[Keeping apps on the non-seed](#keeping-apps-on-the-non-seed)), which
restarts the app once more. Longhorn then rebuilds the replica of each volume
on the returning device.

**Reporting to the controller.**

- The non-seed device goes offline.
- The cluster report (`ZInfoKubeCluster`), now sent by the seed as the only
  device left to act as the elected cluster-info reporter, lists the non-seed
  node as not `Ready`. The witness is still reported `JOINED`
  (`ZInfoKubeCluster.witness`), and the volumes as degraded
  (`ZInfoKubeCluster.storage`).
- The app is reported by the seed once it runs there (see
  [failover.md](../pkg/pillar/docs/failover.md)).

**What the user or controller needs to do.** Nothing to keep the app
running: failover and failback are automatic. If the device is lost for good,
a replacement is added to the cluster through the ordinary join workflow as
the new non-seed (with the lost member listed for removal in
`master_node_uuids`), and the controller makes the replacement the
designated node of the apps. Once it has joined, it pulls the apps onto
itself.

### The seed fails

**Effect on the app.** None. The cluster loses its quorum: the Kubernetes API
on the non-seed stops answering, and no app can be started, stopped or moved.
The app, however, keeps running on the non-seed, without a restart and with
its volumes, and EVE keeps reporting its last known state rather than
treating the unreachable API as an app failure.

**Reporting to the controller.**

- The seed device goes offline.
- The cluster report needs the Kubernetes API, so it may stop arriving, and
  the last one the controller received goes stale. A controller must not
  derive the cluster's health from it alone.
- Every member reports its own connection to the cluster in a
  `ZInfoClusterNode` message, which needs neither the Kubernetes API nor a
  quorum. The non-seed asks its local etcd whether it still reaches a
  majority, and reports `quorum` as `Z_INFO_CLUSTER_NODE_QUORUM_LOST` with
  `node_status` `Z_INFO_CLUSTER_NODE_STATUS_DOWN`, the probe failure in
  `error` and the time quorum was lost in `quorum_change_time`. A quorum is
  only reported lost after three consecutive probes without an etcd leader,
  so a short leader election is not reported.
- The app is still reported running by the non-seed.

**What the user or controller needs to do.** Nothing to keep the app
running. What is needed is to restore the control plane and redundancy.

If the seed is expected back soon (a reboot, a short power outage), waiting
is enough: once it is back, the witness starts with it, the cluster regains
its quorum and recovers on its own. `ZInfoClusterNode` then reports
`Z_INFO_CLUSTER_NODE_QUORUM_ESTABLISHED`.

If the seed is not coming back soon, the controller makes the surviving
device the new seed with a **quorum recovery**:

1. In a single config change:
   - on the surviving device, set `join_server_ip` to that device's own
     cluster IP and increment `quorum_recovery_generation`;
   - remove the cluster config from the failed seed.
2. The surviving device forces its etcd into a single-member cluster and
   becomes the sole bootstrap of the cluster, and the witness starts on it at
   the same `witness_ip`. This does not restart the app. The device reports
   its progress in `ZInfoKubeCluster.nodes[].recovery`
   (`KubeQuorumRecoveryStatus`): the recovery is complete when
   `applied_generation` equals the new generation, with `converging` false
   and no `error`. The witness is then reported `JOINED` again, and the
   cluster report lists one `Ready` node: the cluster is running again, but
   with no redundancy.
3. When the failed seed is back, it finds its cluster config removed,
   converts back to a single-node device and reboots. Its cluster state,
   including its volume replicas, is discarded in the process.
4. The controller adds it back to the cluster through the ordinary join
   workflow, as a plain member with `join_server_ip` pointing at the new
   seed, and in the same config change makes it the designated node of the
   apps. Once it has joined, it pulls the apps onto itself, which restarts
   each app once, and Longhorn rebuilds the volume replicas from the copies
   on the new seed.

The cluster is then healthy again, with the roles of the two devices swapped:
the former non-seed is the seed hosting the witness, and the former seed is
the non-seed running the apps. A replacement device can take the place of the
failed seed in steps 3 and 4.

A recovery only ever applies to the device that becomes the new seed. A
device that was already the seed when it recorded the previous generation
refuses a new one, since it still has its quorum and a reset would discard
its live peer, and it reports the reason in `recovery.error`.

## Reporting summary

| What | Where | Sent by |
| ---- | ----- | ------- |
| Nodes and their readiness | `ZInfoKubeCluster.nodes` | the elected cluster-info reporter, needs the Kubernetes API |
| Witness state (`IDLE`, `JOINING`, `JOINED`, `ERROR`) | `ZInfoKubeCluster.witness` | the elected cluster-info reporter |
| Quorum recovery progress | `ZInfoKubeCluster.nodes[].recovery` | the elected cluster-info reporter |
| A member's own quorum and connection | `ZInfoClusterNode` | every member, works without the Kubernetes API and without quorum |
| App status | `ZInfoApp` | the device the app runs on |
