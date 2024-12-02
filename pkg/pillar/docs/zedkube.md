# Clustered eve nodes (zedkube)

## Overview

## Components

### App VNC for remote console

For Kubevirt VMs, it does not like in KVM image to have QEMU service the VNC port 5900s ready for connection into the VM's console. In kubevirt image, we need to use 'virtctl' tool and specify the needed KubeConfig YAML file for access to the VMI's console.

zedkube service subscribe to the AppInstanceConfig, and monitor if the user has requested the RemoteConsole access. If there is, the service will write to a file in /run/zedkube/vmiVNC.run with specifying the VMI name, VNC port number. The container 'kube' process is monitoring this file, and launch the 'virtctl vnc' commands with the VMI and port. This will enable the VNC port 590x to be enabled and ready to handle the VNC client request. The user can then use the RemoteConsole to connect through the 'guacd' to the VNC port as the same in the KVM image.

### Cluster Status

The kubevirt EVE image supports either running in kubernetes with single node or with cluster mode (at least 3 nodes). In single-node mode, there is no change to the EVE API from the controller with EVE devices. In the cluster mode, controller will send 'EdgeNodeClusterConfig' to the device, and being published in 'zedagent' and zedkube subscribe to that, then it will publish the 'EdgeNodeClusterStatus'. The container 'kube' will monitor the 'EdgeNodeClusterStatus' for cluster mode changes. zedkube will subscribe also to the deviceNetworkStatus from 'nim' and make sure the cluster prefix is ready for the kubernetes.

### Collect App Container Logs

A timer job is used to search through the AppInstanceConfig subscription list, and if the application is a native container, without a VM shim layer, it searches the pods with the application name, and use the kubernetes pods 'GetLogs' API to acquire the logs since last query. It then makes the log entry with App UUID, container name and timestamp, so the newlogd will pick this up for the app log collection.

### Publish Cluster Application Status

zedkube periodically query all the PODs running on this device and report each of the applications in AppInstanceConfig. The main purpose of this status is for application migration handling. We may have the App which sets the Designated Node ID to itself, and the application may moved onto another node; or we are the node which does not match the App's Designated Node ID, but it appears to be scheduled on this node. The 'zedmanager' listens on this ENClusterAppStatus, and makes the decision for the 'effective' activate flag of the application.

In VMI case, there will always be a POD having the name with prefix 'virt-launcher-', we only use this to determine the migration status of the VMI.

### Cluster Status Server

In the Kubernetes cluster mode with multiple HA servers, when it starts up, it needs to join the cluster by specifying the 'bootstrap' server IP address. Even if the IP address is there, sometimes the 'bootstrap' node is still in single-node mode or it has not been converted into the cluster server yet. This will create problem for the joining server, and will later have conflicts with the status and certificates or tokens. To handle this server joining, zedkube is responsible for reporting it's cluster status through HTTP service. Each of the cluster servers will have a HTTP service on the cluster interface with port number '12346' using URL /status. It will report status of 'cluster' if the node has the property of 'master' and 'etcd'. The new joining server node or agent node will not move forward for starting the kubernetes node unless the http query returns 'cluster' status over the cluster network. The 'ClusterStatus' port for the HTTP is explicitly allowed on EVE firewall.

### App Ethernet Passthrough

When the application uses passthrough on ethernet ports, zedkube creates a special NAD, Network Attachment Definition, for the direct connection, uses the name 'host-eth1' for example. It creates the NAD to the kubernetes cluster, and in the case of native container applications, the domainmgr will use this NAD when setup the application configure to kubernetes.

### Kubernetes Stats Collection

This collection is specific for the kubernetes status and stats. Although EVE has the device info, domain status, etc, but kubernetes has a different sets of 'nodes', 'pods', 'vmis', cluster storage stats, etc. This will be reported by zedkube through 'KubeClusterInfo' publication. It will also have some simple non-EVE App related POD status.

### kubenodeop

kubenodeop handles cordoning, uncordoning, and draining of clustered eve-os nodes.
Any given node could be hosting one or more longhorn volume replicas and thus could be the rebuild source for other node replicas.
A drain operation should be performed before any Node Operation / Node Command which can cause an extended outage of a node such as a reboot, shutdown, reset.
kubenodeop handles NodeDrainRequest objects which zedkube subscribes to, initiates the drain, and publishes NodeDrainStatus objects.

## Kubernetes Node Draining

### kubeapi

1. `kubeapi.GetNodeDrainStatus()` to determine if system supports drain
    - HV!=kubevirt: NOTSUPPORTED
    - HV=kubevirt will return:
        - NOTSUPPORTED if in single node.
        - NOTREQUESTED if in cluster mode
1. `kubeapi.RequestNodeDrain()` to begin a drain

### Drain PubSub setup (node reboot/shutdown)

1. zedagent/handlenodedrain.go:`initNodeDrainPubSub()`
    - subscribes to NodeDrainStatus from zedkube
    - creates publication of NodeDrainRequest
1. nodeagent/handlenodedrain.go:`initNodeDrainPubSub()`
    - subscribe to NodeDrainStatus from zedkube

### Drain Request path (node reboot/shutdown)

1. zedagent/parseconfig.go:`scheduleDeviceOperation()`
    - If `shouldDeferForNodeDrain()` is true
        - Set Reboot or shutdown cmd deferred state in zedagentContext
1. zedagent/handlenodedrain.go:`shouldDeferForNodeDrain()`
    - NodeDrainStatus == (NOTREQUESTED || FAILEDCORDON || FAILEDDRAIN):
        - Drain is requested via `kubeapi.RequestNodeDrain()`
        - return Defer
    - NodeDrainStatus == (UNKNOWN || NOTSUPPORTED || COMPLETE )
        - return !Defer
    - NodeDrainStatus == (REQUESTED || STARTING || CORDONED || DRAINRETRYING ):
        - return Defer

### Drain Status Handler (node reboot/shutdown)

1. zedagent/handlenodedrain.go:`handleNodeDrainStatusImpl()`
    - NodeDrainStatus = FAILEDCORDON or FAILEDDRAIN
        - Unpublish NodeDrainRequest
1. nodeagent/handlenodedrain.go:`handleNodeDrainStatusImplNA()`
    - NodeDrainStatus >= REQUESTED and < COMPLETE
        - republish nodeagentstatus with drainInProgress set
    - NodeDrainStatus == COMPLETE
        - republish nodeagentstatus with drainInProgress cleared
1. zedagent/zedagent.go:`handleNodeAgentStatusImpl()`
    - If there is:
        - a deferred device op
        - nodeagent configctx reports drain complete
    - Then process deferred reboot/shutdown

### Drain PubSub setup (node eveimage-update)

1. baseosmgr/handlenodedrain.go:`initNodeDrainPubSub()`
    - subscribe to NodeDrainStatus from zedkube
    - setup publication to NodeDrainRequest

### Drain Request path (node eveimage-update)

1. baseosmgr/handlebaseos.go:`baseOsHandleStatusUpdateUUID()`
    - If BaseOs download complete (LOADING||LOADED||INSTALLED), not currently Activated, and new config requested it Activated
        - Check `shouldDeferForNodeDrain()`, if defer requested return as Completion will later will complete this BaseOsStatusUpdate.
1. baseosmgr/handlenodedrain.go:`shouldDeferForNodeDrain()`
    - NodeDrainStatus == (NOTREQUESTED || FAILEDCORDON || FAILEDDRAIN):
        - save BaseOsId in baseOsMgrContext.deferredBaseOsID
        - Drain is requested via `kubeapi.RequestNodeDrain()`
        - return Defer
    - NodeDrainStatus == (UNKNOWN || NOTSUPPORTED || COMPLETE )
        - return !Defer
    - NodeDrainStatus == (REQUESTED || STARTING || CORDONED || DRAINRETRYING ):
        - return Defer

### Drain Status Handler (node eve-image update)

1. baseosmgr/handlenodedrain.go:`handleNodeDrainStatusImpl()`
    - NodeDrainStatus == FAILEDCORDON or FAILEDDRAIN:
        - Unpublish NodeDrainRequest
    - NodeDrainStatus == COMPLETE:
        - Complete deferred baseOsMgrContext.deferredBaseOsID to `baseOsHandleStatusUpdateUUID()`

### General DrainRequest Processing

1. zedkube/zedkube.go:Run()
    - sub to NodeDrainRequest from zedagent and baseosmgr
    - new publication of NodeDrainStatus
    - Init NodeDrainStatus to NOTSUPPORTED
1. zedkube/zedkube.go:`handleEdgeNodeClusterConfigImpl()`
    - System switching to cluster membership: NodeDrainStatus -> NOTREQUESTED
1. zedkube/zedkube.go:`handleEdgeNodeClusterConfigDelete()`
    - System switching to single node: NodeDrainStatus -> NOTSUPPORTED
1. zedkube/handlenodedrain.go:`handleNodeDrainRequestImpl()`
    - NodeDrainStatus -> REQUESTED
1. zedkube/kubenodeop.go:`cordonAndDrainNode()`
    - NodeDrainStatus -> STARTING
    - Retry Cordon up to 10 times (in case k8s api states object changed)
        - when retries exhausted: NodeDrainStatus -> FAILEDCORDON
    - NodeDrainStatus -> CORDONED
    - Retry Drain up to 5 times
        - between tries: NodeDrainStatus -> DRAINRETRYING
        - on failure: NodeDrainStatus -> FAILEDDRAIN
    - NodeDrainStatus -> COMPLETE

## Cluster Leader Election

In the cluster mode, each node/device will report its own info and metrics as in KVM image, the cluster also needs to report the kubernetes stats as described above. There is no need for every node to report this. The cluster elects a leader as the cluster reporter. If the node can access the cluster, and it can get the configuration successfully from the controller, then it is eligible for participate in the election.

the election request is to request a 'lease' for the name "eve-kube-stats-leader" in the cluster with name space of 'eve-kube-app' for the node name of this device. If a node is a leader and lose the connection to the cluster, it will time out the 'lease', and next available node will be elected. If the node can not get the configuration from the controller, then it will stop the participation of the election.

If all the nodes in cluster are not connected to the cloud, then there is no need to report the stats anyway.

## Debugging

### PubSub NodeDrainRequest/NodeDrainStatus

/run/zedagent/NodeDrainRequest/global.json
/run/baseosmgr/NodeDrainRequest/global.json
/run/zedkube/NodeDrainStatus/global.json

The current node drain progress is available from the global NodeDrainStatus object found at
`cat /run/zedkube/NodeDrainStatus/global.json | jq .`

NodeDrainStatus can be forced by writing the object (in pillar svc container fs) to: /persist/kube-status/force-NodeDrainStatus-global.json

eg. to force disable drain:
echo '{"Status":1,"RequestedBy":1}' > /persist/kube-status/kubeforce-NodeDrainStatus-global.json

eg. to force deviceop drain complete:
echo '{"Status":9,"RequestedBy":2}' > /persist/kube-status/force-NodeDrainStatus-global.json

eg. to force baseosmgr drain complete:
echo '{"Status":9,"RequestedBy":3}' > /persist/kube-status/force-NodeDrainStatus-global.json

"Cannot evict pod as it would violate the pod's disruption budget":
If NodeDrainStatus can get stuck if attempting to drain a node running a pod where the pod has an
explicit spec.nodeName == "drain node".  Delete the pod to continue.
If workload is a statefulset declaing spec.nodeName and node is already cordoned.  Then deleting the pod is not sufficient
The statefulset must be deleted.

### NodeDrainRequest/NodeDrainStatus log strings

- NodeDrainRequest
- NodeDrainStatus
- cordonNode
- cordonAndDrainNode
- scheduleDeviceOperation
- baseOsHandleStatusUpdateUUID
- nodedrain-step
- kubevirt_node_drain_completion_time_seconds
...
    zgrep 'kubevirt_node_drain_completion_time_seconds' /persist/newlog/keepSentQueue/dev.log.1725511530990.gz | jq -r .content | jq -r .msg | cut -d ':' -f 2
    s34.559219
...
