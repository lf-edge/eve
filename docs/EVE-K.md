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
