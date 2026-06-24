# EVE HV=k

## Building

Set `HV=k` during make

```bash
make HV=k ZARCH=amd64 clean pkgs eve
```

## Installation

Installation of `HV=k` eve is installed from an `installer-raw` image in a similar method as
`HV=kvm` eve is, there are a few details:

"eve-k" supports ext4 and zfs vaults.  Default installation uses ext4 on a single disk.
To use a zfs vault specify the config grub parameter `eve_install_zfs_with_raid_level`
with the requested raid level or use multiple persist disk with `eve_persist_disk`
which will use zfs automatically.

## PCIe ACS / IOMMU groups

Unlike the default EVE boot path, EVE-K boots without the `pcie_acs_override`
kernel option. IOMMU groups therefore reflect the platform's actual ACS
topology, and PCI passthrough configurations cannot rely on the override to
split a shared group. See [HYPERVISORS.md](./HYPERVISORS.md#acs-override-on-the-kernel-command-line)
for the full discussion.

## Modes

EVE-API controller config will define a mode
[`EdgeNodeCluster.cluster_type`](https://github.com/lf-edge/eve-api/blob/2d9b92e761a24f5def0dfe2dcfea363e95efcfdf/proto/config/edge_node_cluster.proto#L42)
for EVE-k's k3s instance running in the kube service container.

- CLUSTER_TYPE_K3S_BASE : Only k3s + multus installed. Enables native Kubernetes
  orchestration of user workloads (controller-supplied registration manifest +
  kube-vip load balancer). Being phased out; prefer the opt-in flag below.
- CLUSTER_TYPE_REPLICATED_STORAGE : (k3s + multus) and kubevirt, cdi, longhorn.

`EdgeNodeCluster.enable_native_k8s_orchestration` is an opt-in boolean valid only on a
`CLUSTER_TYPE_REPLICATED_STORAGE` cluster. When set, EVE additionally enables the
native Kubernetes orchestration behaviors of `CLUSTER_TYPE_K3S_BASE` (registration
manifest + kube-vip load balancer) while keeping the full replicated-storage stack
(kubevirt, cdi, longhorn) installed — unlike `CLUSTER_TYPE_K3S_BASE`, those components
are NOT removed.

## k3s Config

Config for k3s uses the standard layout of a base `/etc/rancher/k3s/config.yaml` with
additional layers applied from `/etc/rancher/k3s/config.yaml.d` detailed
in [k3s-configuration-file](https://docs.k3s.io/installation/configuration#configuration-file).

Base config in config.yaml contains all static config applicable to every cluster mode (ENC, BaseK3s).
Additional layers provide dynamic config provided from the controller such as:

- node name in `/etc/rancher/k3s/config.yaml.d/00-nodename.yaml`
- cluster config in `/etc/rancher/k3s/config.yaml.d/01-clusterconfig.yaml`
- user override config in `/etc/rancher/k3s/config.yaml.d/99-k3s-config-user-overrides.yaml`

### User Override Config

To set additional k3s configuration parameters or override default options, the EVE-OS config property
`k3s.config.override` is available which accepts a base64 encoded yaml string which is written to
`/persist/vault/k3s-user-override.yaml` by pillar/zedkube.  The kube container monitors this file contents
and synchronizes it with `/etc/rancher/k3s/config.yaml.d/99-k3s-config-user-overrides.yaml`.  Upon any recognized
changes, kube will terminate k3s processes and restart it to apply the config.

To override previously set config it is required to follow the k3s config merge rules defined in
[k3s-config-value-merging](https://docs.k3s.io/installation/configuration#value-merge-behavior).

## Upgrades

Upgrades of `HV=k` EVE-OS are supported through the existing interfaces.
Upgrade from other `HV=` types is not supported and upgrade from `HV=k` to
other `HV=` types is not supported.

## Tie Breaker Node

### Overview

EVE clustering relies on k3s for app scheduling, deployment, and related infrastructural pods
which consume hardware resources on each node.  Additionally each node in a three node cluster
is an etcd master allowing for a single node to fail while two nodes always remain to keep quorum.
In a cluster where no tie-breaker node is set: all nodes can also schedule to handle I/O for a
replica copy of a cluster volume. The Tie Breaker feature is intended to allow for marking a
node as a 'tie-breaker' which disables all pod and volume workloads on this tie-breaker node
and limits its resource workload to only handling etcd quorum.

### Usage

Use a controller to configure a cluster which has EVE-API
config.EdgeNodeCluster.TieBreakerNodeId set to the uuid of a node in the cluster.

### Node labels

A cluster which contains a tie breaker node will receive a series of kubernetes node labels:

| Label Field | Label Value | Usage |
| ----------- | ----------- | ----- |
| tie-breaker-node | 'true' or 'false' | This label is used by pod, daemonset, and deployment nodeSelectors so that the kubernetes scheduler can appropriately schedule work on non-tie-breaker nodes. |
| tie-breaker-config-applied | '1' | on all nodes after all tie-breaker config has been applied to a cluster.  This is used to gate re-applying tie breaker config, or completing config after a node replacement. |

### Component Configuration

Tie Breaker Config applies config for the following kubernetes components:

1. CDI
2. Kubevirt
3. Longhorn

Each of the above components defines control plane components in kubernetes deployment or daemonset form.  In a cluster containing a tie breaker node all of those objects are patched with a nodeSelector to only schedule workloads onto non tie breaker nodes using the previously mentioned node labels.

### Volume replica scheduling

Volume replicas are blocked from scheduling onto a tie breaker node to decrease network resources and disk space needed on that node.  The changes which are set to enable this are:

1. New kubernetes Storage Class is defined with only 2 replicas, this storage class is named 'lh-sc-rep2'.
2. The Longhorn nodes.longhorn.io object with an identical name to the kubernetes node has the following parameters set: .spec.allowScheduling=false, .spec.evictionRequested=true, and those values are also defined on the disk defined in that object as well.

### Volumemgr changes

Volumemgr queries the kubernetes node objects to determine if a tie breaker node exists.  If found then all volume instances are created using the above mentioned storage class 'lh-sc-rep2' which ensures that all volumes only contain 2 replicas and schedule to only nodes not set as a tie breaker.

## User Volumes - Default PVC Options

The available default storage classes will vary depending on the mode which eve-k is
running as.  All storage classes installed by EVE will place volumes in /persist/vault/volumes/... by default.

- Default single node 'First-Boot' Mode (No EdgeNodeCluster eve-api config): Longhorn and Local-Path
- EdgeNodeCluster with Replicated Storage (CLUSTER_TYPE_REPLICATED_STORAGE): Longhorn and Local-Path
- EdgeNodeCluster with Base Mode (CLUSTER_TYPE_K3S_BASE): Local-Path

## Longhorn Recurring Snapshots and Rebuild Performance

### How snapshots improve rebuild performance

When a Longhorn replica fails and later recovers with its on-disk data intact (e.g. after
a node power cycle), Longhorn can perform a **delta rebuild** — transferring only the blocks
that changed since the last common snapshot rather than copying the entire volume. For a
100 GiB volume with modest write rates, the difference between a delta rebuild and a full
rebuild is typically hours vs. minutes.

The delta rebuild path (`CheckAndReuseFailedReplica`) requires a shared snapshot baseline
between the failed replica and the currently-healthy ones. Without any snapshot, the baseline
falls back to volume creation time, which is equivalent to a full rebuild for any
long-running volume.

EVE-k automatically creates a Longhorn
[`RecurringJob`](https://longhorn.io/docs/1.9.1/snapshots-and-backups/scheduling-backups-and-snapshots/)
that snapshots all enrolled volumes on a configurable interval (default: daily). This caps
the maximum delta rebuild data at approximately one interval's worth of writes regardless
of volume age or size.

### Configuration

The snapshot interval is controlled by the EVE global config property:

| Property | Default | Range | Description |
| -------- | ------- | ----- | ----------- |
| `storage.longhorn.snapshot.cron` | `0 0 * * *` | - | Cron schedule for recurring snapshots. Empty string disables. Standard 5-field cron syntax. |

Changes take effect without a reboot: zedkube applies the update to the Longhorn
`RecurringJob` CRD within one `kubeCfgTimer` cycle.

### Volume enrollment

All EVE storage classes (`lh-sc-rep1`, `lh-sc-rep2`, `lh-sc-rep3`) include
`recurringJobSelector: '[{"name":"default","isGroup":true}]'`, so any PVC provisioned from
an EVE storage class is automatically enrolled in the default snapshot group. No manual
labeling is required for volumes created after cluster initialization.

To enroll an existing PVC that was provisioned before recurring jobs were configured, label
it directly:

```bash
kubectl patch pvc <pvc-name> -n eve-kube-app --type=merge \
  -p '{"metadata":{"labels":{"recurring-job-group.longhorn.io/default":"enabled"}}}'
```

### Custom recurring jobs (development / testing)

For testing or higher-frequency snapshots on specific volumes, create a custom RecurringJob
manually. The following example runs an hourly snapshot, retaining 24:

```yaml
apiVersion: longhorn.io/v1beta2
kind: RecurringJob
metadata:
  name: hourly-dev-snapshots
  namespace: longhorn-system
spec:
  cron: "0 * * * *"
  task: snapshot
  groups:
    - hourly-dev
  retain: 24
  concurrency: 2
```

Apply it:

```bash
kubectl apply -f hourly-dev-snapshot-job.yaml
```

Then enroll a specific PVC by adding the job label directly (bypassing the group):

```bash
kubectl patch pvc <pvc-name> -n eve-kube-app --type=merge \
  -p '{"metadata":{"labels":{"recurring-job.longhorn.io/hourly-dev-snapshots":"enabled"}}}'
```

Or enroll by group label if you want any PVC to pick it up:

```bash
kubectl patch pvc <pvc-name> -n eve-kube-app --type=merge \
  -p '{"metadata":{"labels":{"recurring-job-group.longhorn.io/hourly-dev":"enabled"}}}'
```

Verify snapshot activity:

```bash
# List snapshots for a volume
kubectl -n longhorn-system get snapshots.longhorn.io \
  -l longhornvolume=<volume-name> \
  --sort-by='.metadata.creationTimestamp'

# Check RecurringJob execution history
kubectl -n longhorn-system get recurringjob -o wide
```
