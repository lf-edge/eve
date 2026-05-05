# EVE Microservice Classification

EVE's `pillar` package implements a set of microservices that together provide
the complete EVE OS experience. These microservices can be divided into two
categories based on their role: **device management** and **workload management**.

Note: this document covers only the `pillar` microservices (the processes that
run inside the `pillar` container). EVE also runs a set of linuxkit system
services outside of `pillar` — such as `newlogd`, `wwan`, `vtpm`, `watchdog`,
`vector`, `edgeview`, and others — whose classification is outside the scope of
this document.

## Why this distinction matters

Remote manageability is the fundamental promise of EVE: a deployed edge device
should never require physical access. Maintaining that property requires that the
device can always reach its controller, receive configuration updates, roll out
new EVE-OS versions, and maintain its cryptographic identity. A bug in a device
management microservice that prevents controller communication cannot be recovered
remotely and requires a physical truck roll.

Workload management microservices handle running applications on the device —
creating domains, network instances, and volumes for user workloads. If a workload
management service misbehaves, the device remains remotely manageable: the
controller can push a corrected EVE version or a revised workload configuration to
recover the situation without physical access.

This distinction has direct implications for:

- **Testing priority**: Device management microservices warrant more thorough test
  coverage because their failure mode is catastrophic (loss of remote manageability).
  Workload management failures, while serious, are remotely recoverable.
- **Code review rigor**: Changes to device management microservices should be
  reviewed and tested more carefully than workload management changes.
- **EVE image partitioning**: EVE's dual IMGA/IMGB rootfs partitions exist precisely
  to enable safe rollback of device management code. Since workload runtime failures
  are recoverable without physical access, workload runtimes are candidates for
  living outside the A/B partitions — in `/persist` — as explored in the
  [EVE-K](EVE-K.md) design.

## Device Management Microservices

These microservices are essential for keeping the device remotely manageable. They
handle controller communication, EVE-OS updates, device identity, and hardware
security. A sustained failure in any of these may require physical intervention to
recover the device.

| Microservice | Role |
|---|---|
| `nim` | Manages network interfaces; ensures the device can reach the controller |
| `zedagent` | Retrieves device configuration from the controller; distributes it to other services via pubsub |
| `client` | Device registration and initial onboarding with the controller |
| `baseosmgr` | Manages EVE base OS downloads and A/B partition update state machine |
| `downloader` | Downloads content from datastores (EVE updates and app content) |
| `verifier` | Verifies cryptographic integrity of downloaded content |
| `volumemgr` | Manages storage volumes (EVE-OS update volumes and application volumes) |
| `nodeagent` | Manages node state transitions, reboots, and hardware watchdog |
| `tpmmgr` | TPM provisioning, vault management, and device certificate lifecycle |
| `loguploader` | Collects and uploads device and application logs to the controller |

`downloader`, `verifier`, and `volumemgr` are dual-use: they serve both EVE-OS
update content and application content. Their correct operation is therefore
critical for both remote management and workload deployment.

## Workload Management Microservices

These microservices create and operate application workloads — network instances,
application volumes, and application domains. They are not required for the device
to remain remotely manageable.

| Microservice | Role |
|---|---|
| `domainmgr` | Creates and manages application domains (VMs, containers, unikernels) |
| `zedrouter` | Creates and manages network instances for application connectivity |
| `zedmanager` | Orchestrates app instance lifecycle state machines |
| `diag` | Diagnostics: tests controller reachability and reports device health to console; observability only, not in the controller communication path |

The hypervisor layer (KVM, Xen), the container runtime (containerd for user
applications), and optional runtimes such as the Kubernetes distribution used by
EVE-K are also part of workload management. The EVE-K design takes this further by
placing the Kubernetes runtime and its associated storage provider (Longhorn) in
`/persist` rather than in the IMGA/IMGB partitions, decoupling their lifecycle from
EVE core updates entirely.

## Relationship to image partitioning and rollback

EVE's A/B partition scheme is designed around device management. If a new EVE
version contains a bug in a device management microservice, the device falls back
to the previous IMGA/IMGB image, restoring remote manageability. Because workload
management failures do not prevent the controller from reaching the device, there is
no comparable need to include workload runtimes in the A/B partitions.

This is the architectural justification for extracting workload runtimes out of the
EVE rootfs: it enables a richer set of optional runtimes (different hypervisors,
Kubernetes variants, proprietary GPU stacks) without inflating the device management
footprint that must fit in the size-constrained IMGA/IMGB partitions and without
compromising the rollback guarantee that protects remote manageability.

## Testing implications

See [CODE-COVERAGE.md](CODE-COVERAGE.md) for how this classification informs test
coverage priorities. The short summary: any coverage gap in device management code
carries higher operational risk (physical intervention required to recover) than an
equal gap in workload management code, so device management gaps should be addressed
first.
