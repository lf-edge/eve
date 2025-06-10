# Clustered eve nodes (aka zedkube)

## Overview

zedkube is a service in pillar/cmd/zedkube. The main purpose of the service is to interact with the kubernetes cluster in the container 'kube' and supply some of the pillar commands to the cluster, and relay some information from the cluster to the pillar. It handles some of the actions for the cluster which do not belong to 'volumemgr' or 'domainmgr' services.

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

## Applications under Kubevirt Mode

### Handle Domain Apps Status in domainmgr

When the application is launched and managed in KubeVirt mode, the Kubernetes cluster is provisioned for this application, being a VMI (Virtual Machine Instance) replicaSet object or a Pod replicaSet object. It uses a declarative approach to manage the desired state of the applications. The configurations are saved in the Kubernetes database for the Kubernetes controller to use to ensure the objects eventually achieve the correct state if possible. Any particular VMI/Pod state of a domain may not be in working condition at the time when EVE domainmgr checks. In the domainmgr code running in KubeVirt mode, if it can not contact the Kubernetes API server to query about the application, or if the application itself has not be started yet in the cluster, the kubervirt.go will return the 'Unknown' status back. It will keep a 'Unknown' status starting timestamp per application. If the 'Unknown' status lasts longer then 5 minutes, the status functions in kubevirt.go will return 'Halting' status back to domainmgr. The timestamp will be cleared once it can get the application status from the kubernetes.

## Kubernetes Node Draining

### Description

As a part of kubevirt-eve we have multiple cluster nodes each hosting app workloads and volume replicas.
zedkube implements defer for eve mgmt config operations which will result in unavailability of storage
replicas until the cluster volume is not running on a single replica.  This defer is implemented
through cordoning, uncordoning, and draining of clustered eve-os nodes.

Any given node could be hosting one or more longhorn volume replicas and thus could be the rebuild source for other node replicas.
A drain operation should be performed before any Node Operation / Node Command which can cause an extended outage of a node such as a reboot, shutdown, reset.
kubenodeop handles NodeDrainRequest objects which zedkube subscribes to, initiates the drain, and publishes NodeDrainStatus objects.

An example:

1. Node 1 outage and recovers.
1. Before volumes complete rebuilding on node 1 there is a node 2 outage and recovery.
1. Volumes begin rebuilding replicas on nodes 1 and 2. Only available rebuild source is on node 3.
1. User initiated request to reboot/shutdown/update eve-os on node 3.
1. That config request is set to defer until replicas are rebuilt on the other nodes.

At a high level the eve-side workflow looks like this:

1. eve config received requesting reboot/shutdown/baseos-image-change to node 1
1. drain requested for node 1
1. zedkube cordons node 1 so that new workloads are blocked from scheduling on that node.
1. zedkube initiates a kubernetes drain of that node removing workloads
1. As a part of drain, PDB (Pod Disruption Budget) at longhorn level determines local replica is the last online one.
1. Drain waits for volume replicas to rebuild across the cluster.
1. Drain completes and NodeDrainStatus message sent to continue original config request.
1. On the next boot event zedkube nodeOnBootHealthStatusWatcher() waits until the local kubernetes node comes online/ready for the first time on each boot event and uncordons it, allowing workloads to be scheduled.

Note: For eve baseos image updates this path waits until a new baseos image is fully available locally (LOADED or INSTALLED) and activated before beginning drain.

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

### Application Tracker or App-Tracker

In the Edge-Node Clustering setup, there are multiple EVE nodes handling the applications in a distributed way to prepare and handle the kubernetes cluster Pods and VMIs. The deployed application is downloaded onto all the nodes in the cluster, same for the cluster Network Instance and Volume Instance. Each node handles a different way to the application depending on the node is the Designated Node for the App, or if the kubernetes scheduling has scheduled the application to another node, etc. It is not easy to debug the distributed system when there is an issue encountered.

The service 'zedkube' offers an App-Tracker http service, by offering the URL on the cluster node prefix IP address with the port number 12346. This prefix IP and port is already being used across the network in cluster to query the node cluster status when the node is being converted from single node into the cluster mode. The App-Tracker is using the same endpoint with a different URL to display the page of application status in the node or in the entire cluster.

With the URL `http://<cluster-intf-ip>:12346/app/<app name or uuid>`
it will return the Application state being published by each relevant microservices in pillar and the cluster status. Given the AppInstanceConfig data, we can gather the volume instances and network instances information, and further explore the volume and network related states. The Json file includes those items:

- EdgeNode Info
- EdgeNode Cluster Status
- Kubernetes lease Information (for Cluster status reporter)
- last 10 lines of /persist/kubelog/k3s-install.log
- App Instance Config Info
- Volume Config Info
- Network Instance Status
- EdgeNode Cluster App Status by zedkube
- App Network Config by zedmanager
- App Network Status by zedrouter
- App Volume Status
- App ContentTree Status
- App Network Config by zedmanager
- App Instance Status by zedmanager
- App Domain Config my zedmanager
- App Domain Status by domainmgr
- App Domain Metrics by domainmgr
- App Disk Metrics by volumemgr

For entire cluster status of the App, with the URL `http://<cluster-intf-ip>:12346/cluster-app/<app name or uuid>`
The first node specified by the 'cluster-intf-ip' will gather the above App status on the node, then it will query the cluster on all the cluster-intf-ip of the other nodes on the cluster. Then it sends out the http query to those endpoints with the 'app name or app uuid' in URL to goather the APP status on those nodes, and merge the json results for the query reply to the user.

To use this, one example can be to use Edgeview with TCP command for the first node. First find out the cluster-intf-ip of the node on the cluster, for instance it is '10.244.244.3', then do:

  edgeview.sh tcp/10.244.244.3:12346

then go to a web browser (or use 'curl'), enter url: `http://localhost:9001/app/<app name or uuid>` for the particular node status of the App, or enter url: `http://localhost:9001/cluster-app/<app name or uuid>` for the cluster status of the App.

If the \<app name or uuid\> is empty in the URL, then the query reply only returns the cluster related status. (the above first 4 items in the list)

## Kubernetes Service and Ingress Networking

### Service and Ingress Overview

zedkube periodically collects information about exposed Kubernetes services and ingresses across all namespaces (except system namespaces like `kube-system`, `kubevirt`, `longhorn-system`, `cdi`, and `eve-kube-app`), and publishes this information through `KubeUserServices` for consumption by other microservices. This enables EVE to implement specific network traffic rules for these services.

For applications that do not use EVE CNI and rely on the default Pod 'eth0' interface for Pod external access, the traffic must be routed through the cni0 interface with source IP addresses in the '10.42.x.0/24' prefix range. This outbound traffic to external endpoints requires proper marking to ensure that return traffic is allowed according to the flow setup established for the Pod. This marking is essential for maintaining proper network connectivity for Pods using the default kubernetes CNI configuration.

### Implementation

The collector for Kubernetes services and ingresses runs on a timer-based interval and performs the following operations:

1. **Service Collection**: The `collectKubeSvcs` function calls `GetAllKubeServices` to gather information about all services across non-system namespaces. For each service:
   - Extracts metadata like name, namespace, protocol, port, node port, and service type
   - For LoadBalancer services, collects the LoadBalancer IP from:
     - The requested IP in the service spec (`LoadBalancerIP`)
     - Any external IPs configured for the service
     - Any `kube-vip.io/loadbalancerIPs` annotations

2. **Ingress Collection**: The `collectKubeSvcs` function also calls `GetAllKubeIngresses` to gather information about all ingresses across non-system namespaces. For each ingress:
   - Extracts metadata like name, namespace, hostname, path, path type, protocol
   - Records the ingress IP address from the LoadBalancer status
   - Maps the ingress to the backend service and port

3. **Publication**: The collected service and ingress information is published as a combined `KubeUserServices` object containing:
   - `UserService` - a slice of `KubeServiceInfo` objects
   - `UserIngress` - a slice of `KubeIngressInfo` objects

### Network Rule Generation

The Network Interface Manager (`nim`) microservice subscribes to the `KubeUserServices` publication from zedkube. When changes are detected, it triggers an update to the network ACL rules in the Linux iptables mangle table through the `addKubeServiceRules` function:

1. **TCP and UDP Service Rules**:
   - For services with LoadBalancer IPs, creates destination-specific rules matching IP+port combinations
   - For NodePort services and LoadBalancer services without specific IPs, creates generic port-only rules
   - Both use connection marking to identify the traffic type (e.g., `in_tcp_svc_port`, `in_udp_svc_port`)

2. **HTTP and HTTPS Ingress Rules**:
   - Creates destination-specific rules for unique ingress IPs on ports 80 (HTTP) and 443 (HTTPS)
   - Creates generic port-only rules for ingresses without specific IPs
   - Uses connection marking to identify the traffic type (e.g., `in_http_ingress`, `in_https_ingress`)

This implementation ensures that external traffic to Kubernetes services and ingresses is properly identified and can be subjected to appropriate traffic control policies.

### Kube-VIP Service Load Balancer

Kube-VIP provides LoadBalancer implementations for services and ingress resources in the K3s cluster, enabling external access to applications. This feature is currently available as a testing tool that must be explicitly deployed by the user.

#### Architecture

Kube-VIP runs as a DaemonSet in the K3s cluster and handles:

1. **IP Address Management**:
   - Allocates IP addresses from a configured CIDR range
   - Maintains a pool of available IPs for services
   - Ensures IPs are unique across the cluster

2. **Service Handling**:
   - Watches for services of type LoadBalancer
   - Allocates and assigns external IPs from the configured pool
   - Creates appropriate ARP announcements to make IPs reachable

3. **Ingress Support**:
   - Works with ingress controllers to provide stable IPs for HTTP/HTTPS ingress
   - Enables host-based and path-based routing to services

#### Manual Deployment For Testing

The Kube-VIP integration with EVE requires manual deployment before support from the controller side:

1. **Deployment Command**:

   ```bash
   /usr/bin/kubevip-apply.sh <interface> <prefix>
   ```

   Where:
   - `<interface>` is the network interface to use (e.g., `eth0`)
   - `<prefix>` is the CIDR range for IP allocation (e.g., `10.20.30.0/24`)

2. **Deployment Process**:
   - The script generates a ConfigMap YAML file with the specified settings
   - Applies the service account and provider-controller deployment from `kubevip-sa.yaml`
   - Deploys the Kube-VIP DaemonSet from `kubevip-ds.yaml`

3. **Configuration**:
   - CIDR range is defined for allocating service IPs
   - Network interface is configured to correspond with the application network
   - Strict CIDR validation ensures IP allocations stay within defined ranges
   - Exclusion ranges prevent conflicts with other network resources

4. **Implementation Details**:
   - The CIDR is split into IP and mask components for precise configuration
   - Sort mechanisms ensure consistent ordering of IngressIP arrays
   - Change detection algorithms monitor service type, protocol, and IP allocation changes

#### Manual Removal/Cleanup

To remove the deployed Kube-VIP components from the cluster, use the provided deletion script:

```bash
/usr/bin/kubevip-delete.sh
```

This script will:

- Remove the Kube-VIP DaemonSet
- Delete the Kube-VIP ConfigMap
- Remove the Kube-VIP service account and provider-controller deployment
- Clean up any allocated LoadBalancer IPs

It's recommended to run this script before attempting to redeploy Kube-VIP with different settings or when transitioning back to standard K3s networking.

#### Troubleshooting

Common issues with the Kube-VIP implementation:

1. **IP Allocation Failures**:
   - Check the kubevip ConfigMap for proper CIDR configuration
   - Ensure the CIDR range doesn't conflict with other network resources
   - Verify that the strict-cidr setting is correctly configured

2. **Connectivity Issues**:
   - Confirm that the network interface is correctly specified
   - Check that ARP announcements are functioning correctly
   - Verify that allocated IPs are within the application network's reachable range

### Example

For a LoadBalancer service exposed at 192.168.86.200:80 and an ingress at 10.244.244.1:443, the system will:

1. Collect these services and ingresses via the collector
2. Create a TCP rule for the LoadBalancer service matching destination 192.168.86.200 port 80
3. Create an HTTPS rule for the ingress matching destination 10.244.244.1 port 443
4. Apply appropriate connection marking to allow for traffic control policies

### Authorized Cluster Endpoint (ACE)

The Authorized Cluster Endpoint (ACE) feature enables secure local cluster access via kubectl on port 6443. This implementation focuses on handling services in the `cattle-system` namespace and provides special port remapping for cluster access.

#### Implementation Details

1. **Service Type Conversion**:
   - Services in the `cattle-system` namespace with port 443 are automatically converted to NodePort services
   - The NodePort is explicitly set to 6443 to maintain consistent access

2. **ACEenabled Flag**:
   - The ACEenabled flag controls the behavior of service conversion
   - When enabled, it triggers the special handling of cattle-system namespace services
   - Affects how the service is processed in the getIntenedFilterFules function

3. **Traffic Rules**:
   - Special iptables rules are created when running in HVTypeKube mode
   - These rules specifically handle traffic to port 6443
   - Ensures proper routing of kubectl commands to the cluster endpoint

4. **Mangle Table Handling**:
   - Services in the cattle-system namespace are excluded from standard mangle table markrules
   - This exclusion prevents interference with the ACE functionality
   - Maintains separation between ACE traffic and regular service traffic

#### Usage

The ACE feature automatically configures the necessary network rules when enabled, allowing:

- Local kubectl access via port 6443
- Secure communication with the cluster control plane with cluster webhook for verification

This implementation ensures that local cluster management tools can reliably connect to the cluster while maintaining security and proper traffic routing.
