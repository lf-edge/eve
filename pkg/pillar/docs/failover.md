# Application failover and volume data protection support

## Overview

Edge devices can be clustered together if they are installed with version of eve which supports kubevirt virtualization.
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
  // For Clustered apps on HV=kubevirt, 'ClusterAppRunning' designates
  // the app is running on this node either naturally or after some failover event.
  ReportAppInfo.ClusterAppRunning = aiStatus.Activated
```

There is also additional flag in AppInstanceStatus named NoUploadStatsToController. Zedagent looks at that flag and decides to upload stats to controller or not. The reason to have such flag is that app can move between nodes and only one node is supposed to upload stats to controller. Hence that flag will be toggled accordingly.

eve-api has been enhanced to add designated node id to AppInstanceConfig

* [config/appinfo.config](https://github.com/lf-edge/eve-api/blob/main/proto/config/appconfig.proto)

```golang
  message AppInstanceConfig {
  ....
  // This edge-node UUID for the Designate Node for the Application
  string designated_node_id = 26;
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

EVE specific changes to AppInstanceConfig and AppInstanceStatus structs to carry bool IsDesignatedNodeID

* [types/zedmanagertypes.go](pkg/pillar/types/zedmanagertypes.go)

```golang
  type AppInstanceConfig struct {
  ....
  // Am I Cluster Designated Node Id for this app
  IsDesignatedNodeID bool
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

Kubernetes descheduler decides to failback the app when the original failover scenario is resolved.
After that the EVE handling of app failback is same as failover handling as mentioned above.
