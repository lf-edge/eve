# EVE-K App Deployment — Microservice Flow

## Overview Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              CONTROLLER (cloud)                                  │
└───────────────────────────────────┬──────────────────────────────────────────────┘
                                    │ AppInstanceConfig (HTTPS/protobuf)
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  zedagent                                                                        │
│  pkg/pillar/cmd/zedagent/                                                        │
│  Receives controller config, publishes to all downstream agents                  │
└────────┬────────────────────────────────────────────────┬────────────────────────┘
         │ AppInstanceConfig (pubsub)                     │ AppInstanceConfig (pubsub)
         ▼                                                ▼
┌─────────────────────────────┐               ┌──────────────────────────────────┐
│  zedmanager                 │               │  zedkube  (//go:build k only)    │
│  pkg/pillar/cmd/zedmanager/ │               │  pkg/pillar/cmd/zedkube/         │
│  Central orchestrator       │               │  K8s/KubeVirt cluster manager    │
└──┬────────────┬─────────────┘               │                                  │
   │            │            │                │  ┌─────────────────────────────┐ │
   │VolumeRef   │AppNetwork  │Domain          │  │  KubeVirt API               │ │
   │Config      │Config      │Config          │  │  Deploy VMI/Pod ReplicaSet  │ │
   ▼            ▼            ▼                │  └─────────────────────────────┘ │
┌──────────┐ ┌──────────┐ ┌──────────────┐   │                                  │
│volumemgr │ │zedrouter │ │  domainmgr   │   │  Publishes:                      │
│          │ │          │ │              │   │  • ENClusterAppStatus            │
│Creates   │ │Creates   │ │Calls         │   │  • KubeClusterInfo               │
│PVCs via  │ │network   │ │hypervisor    │   │  • NodeDrainStatus               │
│kubeapi   │ │instances │ │.Setup()      │   └──────────────────────────────────┘
│          │ │          │ │              │
│Longhorn  │ │Multus+   │ │  kubevirt.go │            ┌───────────────────────┐
│PVC/PV    │ │eve-bridge│ │  (HV=k path) │◄───────────│  nim                  │
│          │ │NAD setup │ │              │  Device    │  pkg/pillar/cmd/nim/  │
└────┬─────┘ └────┬─────┘ └──────┬───────┘  Network  │  Physical port config │
     │VolumeRef   │AppNetwork    │Domain    Status    │  DeviceNetworkStatus  │
     │Status      │Status        │Status              └───────────────────────┘
     └────────────┴──────────────┘
                  │ (all status flows back to zedmanager → zedagent → controller)
                  ▼
         ┌────────────────┐
         │   zedmanager   │
         │  AppInstance   │
         │  Status        │
         └────────┬───────┘
                  │
                  ▼
             ┌─────────┐       ┌──────────────────────────────────────────────┐
             │ zedagent│──────►│ CONTROLLER (reports app status)              │
             └─────────┘       └──────────────────────────────────────────────┘
```

---

## Storage Path (volumemgr → Longhorn)

```
VolumeRefConfig
      │
      ▼
kubeapi.CreatePVC()                     PVC name: <uuid>-pvc-<generation>
      │                                 Namespace: eve-kube-app
      ▼                                 StorageClass: longhorn (or local-path)
Kubernetes API
      │
      ▼
Longhorn operator
      ├─ Creates PersistentVolume
      └─ Provisions replicated block storage
            │
            └─► kubevirt VMI spec:
                  vmi.Spec.Volumes[].PersistentVolumeClaim.ClaimName = pvcName
```

---

## Networking Path (zedrouter → Multus → eve-bridge)

```
AppNetworkConfig
      │
      ▼
zedrouter
      ├─ Creates network instance + bridge
      └─ Creates Multus NAD "network-instance-attachment"
                (type: eve-bridge, RPC: /run/eve-bridge/rpc.sock)
                        │
                        ▼
            VMI/Pod annotation:
            k8s.v1.cni.cncf.io/networks: "network-instance-attachment"
                        │
                        ▼
            K8s calls eve-bridge CNI
                        │
                 RPC → zedrouter
                        │
                        └─► Attaches veth/tap to pod with MAC from config
```

---

## Hypervisor Path (domainmgr → kubevirt.go → Kubernetes)

```
DomainConfig
      │
      ▼
domainmgr  ──  hypervisor.Setup()
                      │
               ┌──────┴──────┐
               │             │
          NOHYPER           HVM/PV
         (container)         (VM)
               │             │
               ▼             ▼
      CreateReplicaPod  CreateReplicaVMI
      Config()          Config()
               │             │
               └──────┬──────┘
                      │
                 JSON encoded
                 ReplicaSet spec
                      │
                      ▼
                  zedkube
                      │
              kubectl apply (via client-go)
                      │
                      ▼
              ┌───────────────┐
              │  Kubernetes   │
              │  Scheduler    │
              └───────┬───────┘
                      │
             ┌────────┴────────┐
             │                 │
        Pod (container)   VMI (VM via
        appsv1.           KubeVirt
        ReplicaSet)       VMIRS)
             │                 │
             └────────┬────────┘
                      │
              Namespace: eve-kube-app
              Label: App-Domain-Name=<name>
```

---

## State Transitions

```
AppInstanceConfig (Activate=true)
      │
      ▼
zedmanager drives parallel pipelines:
      ├─ VolumeRefConfig → volumemgr → PVC created (Longhorn)
      ├─ AppNetworkConfig → zedrouter → NAD + bridge ready
      └─ DomainConfig → domainmgr → kubevirt ReplicaSet spec written
                                           │
                                           ▼
                                       zedkube applies to Kubernetes
                                           │
                                           ▼
                                  Kubernetes Scheduler
                                     Pending → Running
                                           │
                                           ▼
                                    DomainStatus updated
                                           │
                                           ▼
                               zedmanager → AppInstanceStatus
                                           │
                                           ▼
                               zedagent → Controller (reported)
```

---

## Pubsub Message Table

| From | To | Message | Contains |
|------|----|---------|----------|
| zedagent | zedmanager, zedkube | `AppInstanceConfig` | App spec, volumes, nets, virtualization mode |
| zedmanager | volumemgr | `VolumeRefConfig` | Volume UUID, size, image ref |
| zedmanager | zedrouter | `AppNetworkConfig` | Network instance UUIDs, VIF list |
| zedmanager | domainmgr | `DomainConfig` | vCPUs, RAM, disks (PVC names), VifList, mode |
| volumemgr | zedmanager | `VolumeRefStatus` | PVC name as `ActiveFileLocation` |
| zedrouter | zedmanager | `AppNetworkStatus` | VIF assignments, MACs |
| domainmgr | zedmanager | `DomainStatus` | Running/Pending/Failed, metrics |
| nim | zedrouter, zedkube | `DeviceNetworkStatus` | Physical port assignments |
| zedkube | (reporting) | `ENClusterAppStatus` | Cluster-level app health |

---

## Key Source Files

| Agent | Path | Key Function |
|-------|------|-------------|
| zedagent | `pkg/pillar/cmd/zedagent/zedagent.go` | Controller config reception |
| zedmanager | `pkg/pillar/cmd/zedmanager/zedmanager.go` | Orchestration hub |
| zedmanager | `pkg/pillar/cmd/zedmanager/handledomainmgr.go` | `MaybeAddDomainConfig()` |
| zedmanager | `pkg/pillar/cmd/zedmanager/handlevolumemgr.go` | Publishes VolumeRefConfig |
| volumemgr | `pkg/pillar/cmd/volumemgr/blob.go` | PVC creation for HV=k |
| zedrouter | `pkg/pillar/cmd/zedrouter/zedrouter.go` | Network instance + CNI setup |
| zedrouter | `pkg/pillar/cmd/zedrouter/cni.go` | eve-bridge RPC server |
| domainmgr | `pkg/pillar/cmd/domainmgr/domainmgr.go` | HV=k detection, hypervisor call |
| zedkube | `pkg/pillar/cmd/zedkube/zedkube.go` | KubeVirt API interaction |
| kubevirt hypervisor | `pkg/pillar/hypervisor/kubevirt.go` | `Setup()`, `CreateReplicaVMIConfig()`, `CreateReplicaPodConfig()` |
| kubeapi | `pkg/pillar/kubeapi/vitoapiserver.go` | `CreatePVC()`, PVC management |
| kubeapi | `pkg/pillar/kubeapi/longhorninfo.go` | Longhorn queries |
