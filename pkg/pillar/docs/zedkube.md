# Clustered eve nodes (zedkube)

## Overview

## Components

### kubenodeop

kubenodeop handles cordoning, uncordoning, and draining of clustered eve-os nodes.
Any given node could be hosting one or more longhorn volume replicas and thus could be the rebuild source for other node replicas.
A drain operation should be performed before any Node Operation / Node Command which can cause an extended outage of a node such as a reboot, shutdown, reset.
kubenodeop handles NodeDrainRequest objects which zedkube subscribes to, initiates the drain, and publishes NodeDrainStatus objects.

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
