# Application failover and volume data protection support

## Overview

Edge devices can be clustered together if they are installed with a version of EVE which supports kubevirt virtualization (HV=k).
The volumes created on those devices are synchronously replicated within the cluster for data protection and high availability. The applications deployed on those devices are automatically failed over to surviving nodes by the underlying kubernetes infrastructure. This document covers the process of failover and the underlying data structures.

## Components

### Block Volumes

In a clustered setup block volumes are treated as a cluster wide objects. Controller picks one of the nodes in the cluster as the designated node id for that volume. Controller sends volume config to all the devices in the cluster with designated node id set to uuid of the device which is supposed to be designated node id for that volume.

EVE API has been enhanced to include Designated node id as String.

* [config/storage.proto](https://github.com/lf-edge/eve-api/blob/main/proto/config/storage.proto)

```golang
  message Volume {
  ....
  // To inform the edge-node if the device receiving this Volume is
  // responsible for volume creation, convert PVC, or not
  string designated_node_id = 10;
  }
```

EVE volumetypes has been enhanced to include boolean IsReplicated. A volume is set to IsReplicated=false on a node that is designated node id. On all other nodes in the cluster it will set to true. On single node installs it will always be false.

* [types/volumetypes.go](../types/volumetypes.go)

```golang
  type VolumeConfig struct {
  ....
  // This is a replicated volume
  IsReplicated bool
  // This volume is container image for native container.
  // We will find out from NOHYPER flag in appinstanceconfig
  IsNativeContainer bool
  }

  type VolumeStatus struct {
  ....
  // This is a replicated volume
  IsReplicated bool
  // This volume is container image for native container.
  // We will find out from NOHYPER flag in appinstanceconfig
  IsNativeContainer bool
  }
```

Zedagent microservice parses the config from the device and updates the IsReplicated field in the volumeconfig struct.
Eventually volume manager updates the VolumeStatus in run time.

All block volumes are created as kubernetes Persistent Volumes (PV) and replicated to other nodes in the cluster.

### Network instance

Network instances are cluster wide too, except they do not have a designated node id, in other words they are created on all nodes in a cluster. Controller ensures same network instance configuration is sent to all devices in the cluster. This will ensure NI is ready when an application failover and app starts without any issues.

There are no changes to any existing data structures in EVE or eve-api

### Content tree

Content tree images eve downloads are of two types, qcow2/raw format or container image format.
The qcow2/raw files are converted into PVCs by the volume manager and hence content tree config also has designated node id.
This is very important for the non-container format content tree because the content is replicated to all nodes in the cluster and hence it is not necessary to download content tree to all nodes of the cluster.

The container image format content tree is processed in two different ways depending on the application type.

 1) If the application type is a Container (ie container launched in shim VM), only designated node will download the content tree, rest of the nodes will get the content through replication of PVC.
 2) If the application type is Native container (ie NOHYPER virtualization mode), then the content tree is downloaded to all the nodes in the cluster. That is because since the container image does not contain the kernel or OS components they need to be launched natively on the kubernetes infrastructure, converting them to PVC is useless in such cases.

 eve-api has been enhanced to add designated node id to content tree struct

* [config/storage.proto](https://github.com/lf-edge/eve-api/blob/main/proto/config/storage.proto)

```golang
   message ContentTree {
   ....
   // To inform the edge-node if the device receiving this content tree is
   // responsible for content tree download or not.
   string designated_node_id = 12;
   }
```

EVE contenttreetypes.go has been enhanced to include IsLocal boolean. A content tree is set to IsLocal=true if the content tree is downloaded to that node, else it is set to false. For single node setups IsLocal is always true. For native containers IsLocal is always true.

* [types/contentreetypes.go](../types/contenttreetypes.go)

```golang
  type ContentTreeConfig struct {
  ....
  // Do we download on this node
  IsLocal bool
  }

  type ContentTreeStatus struct {
  ....
  IsLocal bool
  }
```

Zedagent microservice parses the config from the device and updates the IsLocal field in the ContentTreeConfig struct.

If the ContentTree is in qcow2/raw, or container format (not native container), it gets converted to Kubernetes Persistent volume (PV) and gets replicated to all other nodes in the cluster.

### Application instance

Application deployed in a cluster setup will also have designated node id. That node is picked by the controller and how it picks the designated node is beyond scope of EVE. Once the designated node id is picked, controller sends Application instance config to all the devices in the cluster with designated node id set to uuid of the device which is supposed to be designated node id for that application.

The designated device will start the application and publishes AppInstanceStatus. All the nodes in the cluster will publish the AppInstanceStatus since they all receive the config. But only the node that is running the app will have aiStatus.Activated is set to true. That will be used by zedagent to update the info message to the controller.

* [zedagent/handlemetrics.go](../cmd/zedagent/handlemetrics.go)

```golang
  // For Clustered apps on HV=k, 'ClusterAppRunning' designates
  // the app is running on this node either naturally or after some failover event.
  ReportAppInfo.ClusterAppRunning = aiStatus.Activated
```

There is also additional flag in AppInstanceStatus named NoUploadStatsToController. Zedagent looks at that flag and decides to upload stats to controller or not. The reason to have such flag is that app can move between nodes and only one node is supposed to upload stats to controller. Hence that flag will be toggled accordingly.

eve-api has been enhanced to add designated node id and affinity type to AppInstanceConfig

* [config/appinfo.config](https://github.com/lf-edge/eve-api/blob/main/proto/config/appconfig.proto)

```golang
  message AppInstanceConfig {
  ....
  // Designated Node Id is used for cluster nodes to determine placement of
  // the AppInstance when an EdgeNodeCluster config is present.
  // See affinity below to set the desired node affinity.
  // eg. Preferred or Required.
  string designated_node_id = 26;
  ....
  // Affinity is used for cluster nodes to determine
  // preferred or required node scheduling for app instances.
  // Node Id for scheduling is defined in designated_node_id.
  AffinityType affinity = 29;
  }
```

* [info/info.proto](https://github.com/lf-edge/eve-api/blob/main/proto/info/info.proto)

```golang
  message ZInfoApp {
  ....
  // Deployed app is scheduled, or rescheduled and launched on this node,
  // it has the Pod Spec-name of this node, the app can be in any operating state.
  bool cluster_app_running = 20;
  }
```

EVE specific changes to AppInstanceConfig and AppInstanceStatus structs to carry bool IsDesignatedNodeID.
AffinityType is also added to AppInstanceConfig

* [types/zedmanagertypes.go](pkg/pillar/types/zedmanagertypes.go)

```golang
  type AppInstanceConfig struct {
  ....
  // Am I Cluster Designated Node Id for this app
  IsDesignatedNodeID bool

  // Node Affinity for cluster IsDesignatedNodeID
  AffinityType Affinity
  }
  type AppInstanceStatus struct {
  ....
  // Am I Cluster Designated Node Id for this app
  IsDesignatedNodeID bool
  }
```

### Config from controller

The app, network and volume config sent from controller is exactly same for all the devices in the cluster.
The devices (eve code) behaves differently depending on the designated node id set for those objects.
This design is simple and helps scale the number of nodes in the cluster easily.

### Failover scenarios

There are various scenarios that can trigger the application failover. Some of the most common ones are:

1) Node graceful reboot
2) Node graceful shutdown
3) Node abrupt power off
4) A network failure between the cluster nodes
5) A physical disk failure on a node.
6) Resource starving on a node.

### Failover handling

We depend on the kubernetes infrastructure to detect and the trigger the failover of an application.
Kubernetes scheduler makes the decision to move the app to some other existing node in a cluster.
If an application is defined with AppInstanceConfig.AffinityType==RequiredDuringScheduling then
the application cannot failover to another node, failover is disabled for only that application.

Once the application gets Scheduled on a particular node after failover. EVE code does the following;

1) zedkube microservice has a periodic loop to check for apps shceduled on that node.
2) zedkube publishes ENClusterAppStatus which looks something like this
   {
  "AppUUID": "a19baff7-5b6c-4363-9a1c-522b210f5139",
  "IsDNSet": false,
  "ScheduledOnThisNode": true,
  "StatusRunning": true
   }
3) zedmanager microservice subscribes to ENClusterAppStatus.
4) zedmanager then does the following if the app is scheduled on that node:
   a) If AppInstanceStatus does not exist for that app, calls handleCreateAppInstanceStatus()
   b) If AppInstanceStatus exists for that app, calls activateAIStatusUUID()

   If the app is descheduled on that node (was scheduled earlier)
   a) If AppInstanceStatus exists for that app, calls publishAppInstanceStatus() to update the flag NoUploadStatsToController = true. This will ensure zedagent does not publish the appinfo to controller.

The workflow above guarantees that the app is running on only one node in a cluster at a given time and the appinfo is sent to controller from only the node that is running the app at that time.

### Failback handling

When a failed node recovers and rejoins the cluster, Kubernetes does not automatically move applications back to their original designated node. EVE uses the Kubernetes descheduler to trigger failback by evicting apps that are running on a node that does not match their preferred affinity.

**Descheduler trigger**

`Update_RunDeschedulerOnBoot()` in `cluster-update.sh` runs the descheduler once per boot on any booting cluster node — this includes the recovered node returning to service, a surviving node rebooting, or any other node in the cluster. Before running, it verifies all of the following:

- The cluster API is reachable
- This node is `Ready` and not `SchedulingDisabled`
- All Longhorn daemonsets report `numberReady == desiredNumberScheduled`
- All KubeVirt daemonsets report `numberReady == desiredNumberScheduled` (if kubevirt is installed)

Once prerequisites are met, any existing `descheduler-job` is deleted and a fresh Job is applied. The sentinel file `/tmp/descheduler-ran-onboot` ensures it runs at most once per boot.

**Descheduler policy**

The descheduler runs the `RemovePodsViolatingNodeAffinity` plugin scoped to the `eve-kube-app` namespace with `preferredDuringSchedulingIgnoredDuringExecution` affinity type. It evicts any pod in that namespace currently running on a node that does not satisfy its preferred node affinity — i.e., an app that failed over away from its designated node and whose designated node is now back online and ready.

**After eviction**

Once the descheduler evicts the pod, KubeVirt reschedules a new VMI. The surviving nodes detect the new scheduling via `ENClusterAppStatus` and EVE handles the transition using the same failover path described above.

**Scope limitation**

The descheduler only acts on apps with `AffinityType == PreferredDuringScheduling`. Apps configured with `AffinityType == RequiredDuringScheduling` never fail over and therefore never require failback.

## Kubernetes Timeline on VMIRs Failover

The following describes the sequence of Kubernetes and Longhorn object state changes during a VMIRs-managed application failover between EVE cluster nodes.

**Best-case timing summary** (new pod already scheduled on failover node):

```
T+0s:       network lost
T+40s:      node → NotReady/Unknown  (node-monitor-grace-period)
T+55s:      DeletionTimestamp set, virt-launcher pod → Terminating  (tolerateSec=15)
T+55–65s:   checkAppsFailover() fires  (logcollectInterval=10s polling)
T+65s:      DetachOldWorkload begins
```

**1. Node network lost**

The failed node loses network connectivity to the cluster. Its kubelet stops posting status updates to the Kubernetes API server.

**2. Node object → NotReady**

After the node monitor grace period (**40 seconds**, per EVE's k3s config `node-monitor-grace-period=40s` with `node-monitor-period=10s`), the Kubernetes control plane transitions the node's `Ready` condition to `Unknown` with the message `"Kubelet stopped posting node status."`. The `node.kubernetes.io/unreachable:NoExecute` taint is added to the node object.

**3. virt-launcher pod → Terminating**

EVE explicitly sets `tolerationSeconds=15` on all VMI and ReplicaSet pod specs at creation time (see `tolerateSec` in `hypervisor/kubevirt.go`), overriding the Kubernetes default of 300 seconds. After this **15-second** window following step 2, Kubernetes sets a `DeletionTimestamp` on all pods on the unreachable node, transitioning them to `Terminating`. The virt-launcher pod cannot fully terminate because the kubelet on the failed node is offline and cannot acknowledge the deletion. Total time from network loss to `Terminating` is approximately **~55 seconds** (40s detection + 15s toleration).

EVE's zedkube `checkAppsFailover()` polls every **10 seconds** (`logcollectInterval`), so there is up to 10 seconds of additional latency before EVE detects the `Terminating` pod and begins acting on it.

**3b. (Contingency if new virt-launcher pod not scheduled) VMIRs replica reset**

If no new scheduling pod appears within ~2 minutes of the pod entering `Terminating`, EVE's zedkube microservice triggers `DetachUtilVmirsReplicaReset()`. This scales the `VirtualMachineInstanceReplicaSet` (VMIRs) from 1 replica to 0 and back to 1, prompting KubeVirt to schedule a new VMI and virt-launcher pod onto an available node.

**4. New virt-launcher pod → Pending on failover node**

KubeVirt creates a replacement VMI and virt-launcher pod, which is scheduled onto a surviving cluster node. The pod remains in `Pending` state because its PVC is still bound to a `VolumeAttachment` referencing the failed node.

**5. Verify old node unreachable (DetachOldWorkload gate)**

When zedkube detects a new pod scheduled on this node via `ENClusterAppStatus`, it calls `DetachOldWorkload()`. The first check verifies the failed node is genuinely unreachable by inspecting the node's `Ready` condition message for `"Kubelet stopped posting node status."`. Other `NotReady` reasons do not qualify — this prevents split-brain data corruption.

**6. Verify PVC storage redundancy**

For each Longhorn volume attached to the application, EVE checks that at least one healthy replica exists on a node other than the failed node. If any volume lacks an off-node healthy replica, the failover is blocked and does not proceed. This is a hard gate.

**7. Control plane pod cleanup on failed node**

Longhorn and KubeVirt control plane pods stuck in `Terminating` on the failed node are force-deleted, clearing the way for storage and compute cleanup.

**8. virt-launcher and VMI cleanup on failed node**

The stuck virt-launcher pod is force-deleted (grace period 0, Foreground propagation). The VMI on the failed node has its finalizers stripped before force-deletion. This unblocks KubeVirt's reconciliation loop.

**9. Longhorn replica removal on failed node**

Longhorn `Replica` objects associated with the failed node for this application's volumes are deleted, removing the failed node's claim on the volume data and allowing Longhorn to re-establish replica count on surviving nodes.

**10. VolumeAttachment deletion**

EVE polls and force-deletes all `VolumeAttachment` objects referencing the failed node for this application. The loop retries until the VA list is empty. The new virt-launcher pod's PVC bind cannot complete while the old `VolumeAttachment` exists.

**11. Longhorn volume node assignment**

With the old `VolumeAttachment` removed, `longhornVolumeSetNode()` updates the Longhorn volume's `spec.nodeID` to the failover node, directing Longhorn to attach the volume engine there. For volumes migrated from Longhorn < v1.7, `BackupTargetName` may be empty; the Longhorn v1.9.x webhook rejects updates with an empty `BackupTargetName`, so EVE sets it to `"default"` when unset.

**12. New VMI → Running**

Once the new `VolumeAttachment` reports `Attached`, storage is available on the failover node. The virt-launcher pod transitions from `Pending` to `Running` and the VMI reaches `Running` state. EVE's zedkube publishes an updated `ENClusterAppStatus` with `ScheduledOnThisNode=true` and `StatusRunning=true`, causing zedmanager on the failover node to set `AppInstanceStatus.Activated=true` and resume reporting app info to the controller.
