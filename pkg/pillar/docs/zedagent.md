# zedagent Microservice

`zedagent` is a central microservice responsible for retrieving, parsing and validating
the edge-node configuration and orchestrating communication with the controller, LOC
(Local Operator Console) and LPS (Local Profile Server).

## Responsibilities

- **Device configuration management**
  - Retrieves, parses, and validates edge-node configuration.
  - Periodically fetches device configuration from the cloud controller.
  - If the controller is unreachable and LOC is configured, attempts to fetch
    the configuration from LOC.
  - Publishes device configuration through pubsub to other microservices,
    split into logical parts, e.g.:
    - `DevicePortConfig` – networking configuration
    - `AppInstanceConfig` – application configuration
    - `NetworkInstanceConfig` – network instance configuration
    - `VolumeConfig` – volume configuration
    - etc.
  - Other microservices subscribe to the parts they are responsible for and apply
    configuration changes.

- **Information and metrics publishing**
  - zedagent subscribes to status, info, and metrics messages from other microservices,
    aggregates the relevant data, converts them to the appropriate protobuf messages,
    and publishes them to the controller and, if configured, to the LOC.
  - Runs separate Go routines (tasks) to publish info messages on change:
    - Device info
    - Network instance info
    - Volume info
    - App info
    - etc.
  - Publishes metrics such as resource utilization, packet counters, etc.

- **Certificate management**
  - Runs a Go routine to periodically fetch the latest controller certificate.
  - Also fetches certificates whenever signature verification fails, potentially
    indicating that the local copy of certificates is obsolete.

## Local Profile Server (LPS) Support

`zedagent` contains a component called **LocalCmdAgent**, which manages interaction
with LPS. Key points:

- LPS typically runs as an application on the same edge-node (see [LPS documentation](../../../docs/LPS.md)).
- `LocalCmdAgent` periodically performs a GET request to fetch the current local profile
  override from LPS (which determines the subset of applications to activate).
- `LocalCmdAgent` periodically publishes info messages to LPS:
  - Device info
  - App info
  - Wireless info
  - Location
- LPS may respond with commands to be executed locally:
  - Enable or disable radio silence
  - Reboot app / edge-node
  - Purge app
  - Shutdown applications
  - Device Power-off
  - Collect debug information (`collect-info.sh`)
- `LocalCmdAgent` checks the received LPS token, timestamps (if used in the given LPS endpoint),
  and calls `Apply*` methods on `zedagent`.
- `zedagent` publishes updated configuration via pubsub to the microservices responsible
  for applying the changes.
- Status messages are received back through pubsub, which `LocalCmdAgent` monitors to report
  operation success/failure to LPS.

```text
┌────────────────┐   LPS config (URL, token)    ┌──────────┐  publish info, status  ┌───────┐
│    zedagent    │ ───────────────────────────► │ LocalCmd │ ─────────────────────► │  LPS  │
│ (microservice) │                              │  Agent   │                        │ (App) │
│                │    Apply profile, commands   │          │  get profile, commands │       │
└───────┬────────┘ ◄─────────────────────────── └──────────┘ ◄───────────────────── └───────┘
        │                                            ▲
        │ publish controller config                  │
        │ merged with local config                   │ status reported from microservices
        │                                            │ handling the local commands
        ▼                                            │
┌────────────────┐                                   │
|     pubsub     |───────────────────────────────────┘
└────────────────┘
```

## Startup Sequence

`zedagent` performs a strictly ordered, gate-based initialization before entering its
main event loop. Each gate blocks until a prerequisite is satisfied so that later stages
always have a consistent view of device state.

1. **Hardware inventory** – collected before any config is applied so the reported
   hardware info is not affected by config-driven device changes (e.g., vfio-pci
   assignments).
2. **Global config initialization** – looks for a saved checkpoint in
   `/persist/checkpoint/`.  If absent, tries a bootstrap config, then falls back to
   `/config/GlobalConfig`. The resolved config is immediately published to pubsub so
   all agents start with correct settings.
3. **Publications created** – all pubsub publications are registered before any
   subscription is activated, ensuring downstream agents never race against a missing
   publisher.
4. **Onboarding gate** – subscribes to `OnboardingStatus` from `zedclient` and blocks
   until the device UUID is known. No controller communication happens before this point.
5. **Controller client initialized** – TLS context and device UUID are now available to
   construct authenticated HTTP requests.
6. **Post-onboard subscriptions activated** – all 45+ subscriptions to other
   microservices are set up now that the UUID is known (needed for correct pubsub topic
   naming).
7. **NodeAgentStatus gate** – waits for the first `NodeAgentStatus` from `nodeagent` to
   populate reboot reason, reboot counter, and related fields before the first config
   fetch (some config fetch decisions depend on boot reason).
8. **Cipher module initialized** – sets up the cipher context used for config
   decryption; depends on device state obtained in the previous step.
9. **GlobalConfig gate** – waits for the GlobalConfig to arrive via self-subscription,
   confirming the publish round-tripped through pubsub and that log levels and timers
   are set before any periodic tasks start.
10. **Zboot gate** – waits for `ZbootStatus` from `baseosmgr` before fetching config,
    avoiding config application during an active OTA update where the system may be
    in a transitional state.
11. **DNS gate** – waits for `DeviceNetworkStatus` from `nim` confirming at least one
    working uplink before attempting any outbound HTTP requests.
12. **Goroutines started** – see [Goroutine Architecture](#goroutine-architecture).
13. **Main event loop** – `mainEventLoop()` runs indefinitely, dispatching pubsub events
    to their handlers.

## Goroutine Architecture

After the startup gates complete, `zedagent` runs the following long-lived goroutines
in addition to the main event loop:

| Goroutine | Purpose |
|---|---|
| `configTimerTask` | Periodically fetches device config from controller (and LOC if needed); backs up config after stable period. |
| `deviceInfoTask` | Sends `ZInfoDevice` to controller/LOC when triggered via `triggerDeviceInfo` channel. |
| `objectInfoTask` | Sends per-object info (`ZInfoApp`, `ZInfoNetworkInstance`, `ZInfoVolume`, etc.) to controller when triggered via `triggerObjectInfo` channel. |
| `flowlogTask` | Drains the `flowlogQueue` channel and sends `AppFlowLog` messages to the controller. |
| `hardwareInfoTask` | Sends `ZInfoHardware` (hardware inventory) to controller when triggered via `triggerHwInfo` channel. |
| `metricsAndInfoTimerTask` | Periodically calls `publishMetrics` to send `ZMetricMsg` to controller; also triggers periodic device info republish. |
| `hardwareHealthTimerTask` | Periodically collects SMART data and sends `ZMetricHardwareHealth` to controller. |
| `locationTimerTask` | Periodically sends `ZInfoLocation` to controller and to any configured app. |
| `ntpSourcesTimerTask` | Periodically sends NTP source status to controller. |
| `kubeClusterInfoTask` | (Kubevirt only) Sends `ZInfoKubeCluster` to controller when triggered. |
| `kubeClusterUpdateStatusTask` | (Kubevirt only) Sends cluster update status to controller when triggered. |
| `controllerCertsTask` | Periodically fetches controller certificates; also triggered on signature verification failure. |
| `edgeNodeCertsTask` | Publishes edge-node certificates (device cert, attestation cert, etc.) to the controller. |
| `attestModuleStart` tasks | Run the remote attestation FSM: request nonce → send quote → receive encrypted escrow. |
| `parseSMARTData` | One-shot goroutine that parses SMART data from disk devices at startup. |
| `localCmdAgent.RunTasks` | Handles LPS polling and local command processing. |

### Trigger-channel pattern

Info-publishing goroutines (`deviceInfoTask`, `objectInfoTask`, etc.) are driven by
buffered channels of capacity 1.  The main event loop and other goroutines write to
these channels via helper functions (`triggerPublishDevInfo`,
`triggerPublishAllInfo`, etc.) rather than publishing directly.  Because the channel
capacity is 1, multiple rapid triggers coalesce into a single publish, avoiding
redundant round-trips to the controller during bursty config changes.

## Config Fetch Flow

```text
configTimerTask (periodic ticker)
  └─► getLatestConfig
        ├─► requestConfigByURL (controller)
        │     └─► HTTP GET /api/v2/edgeDevice/config
        │           └─► inhaleDeviceConfig
        │                 ├─► validate UUID / epoch
        │                 └─► parseConfig
        │                       ├─► parseAppInstanceConfig  ──► pubAppInstanceConfig
        │                       ├─► parseNetworkInstanceConfig ► pubNetworkInstanceConfig
        │                       ├─► parseVolumeConfig        ──► pubVolumeConfig
        │                       ├─► parseBaseOS              ──► pubBaseOsConfig
        │                       ├─► parseDatastoreConfig     ──► pubDatastoreConfig
        │                       ├─► parseConfigItems         ──► pubGlobalConfig
        │                       └─► ... (other sub-parsers)
        └─► requestConfigByURL (LOC, if needRequestLocConfig)
```

Key behaviours:

- **Hash comparison** – `computeConfigSha` is used to detect whether the newly
  fetched config differs from the last processed config.  Unchanged configs are
  acknowledged to the controller but not reprocessed.
- **Config backup** – after `MintimeUpdateSuccess` has elapsed since the last config
  change without any error, the config is backed up to
  `/persist/checkpoint/lastconfig.bak`.
- **Retry/backoff** – failed fetches are retried with exponential backoff.  The timer
  interval is randomized ±10 % to prevent thundering-herd from large fleets.
- **Epoch change** – when the controller increments its epoch counter, `zedagent`
  republishes all info messages to the controller, ensuring the controller has a
  fresh snapshot of device state.

## Config Source Hierarchy

`zedagent` processes configuration from four possible sources, in order of precedence:

| Source | Description | Precedence |
|---|---|---|
| **Controller** | Fetched periodically over HTTPS from the cloud controller. | Highest |
| **LOC** (Local Operator Console) | Fetched when controller is unreachable and `LOCConfig` is active; provides a compound config. | Fallback |
| **Bootstrap config** | Signed `BootstrapConfig` protobuf placed in the image at `/config/bootstrap-config.pb`; used on first boot before any controller contact. Controller certificate chain is verified before accepting it. | First-boot |
| **Saved config** | `/persist/checkpoint/lastconfig` – the last successfully applied config; restored across reboots if the controller remains unreachable. | Last resort |

The `GlobalConfig` (config items / tunable parameters) follows a similar but
separate path: the `/config/GlobalConfig` JSON file provides factory defaults, the
controller can override individual items via the `ConfigItems` section of the device
config, and overrides from LPS or LOC are merged on top.

## Deferred Queue Mechanism

All outbound HTTP requests to the controller are queued rather than sent inline, to
decouple the event loop from network latency and to handle connectivity gaps.
`zedagent` maintains three deferred queues:

| Queue | Policy | Used for |
|---|---|---|
| `deferredEventQueue` | Reliable – retried on connectivity restore; has a priority function and a sent-callback. | Info messages, attestation escrow, EdgeNodeCerts – messages that must eventually reach the controller. |
| `deferredPeriodicQueue` | Best-effort – dropped on failure without retry; no callback. | Metrics, hardware health, NTP sources – periodic data where a missed report is acceptable. |
| `deferredLOCPeriodicQueue` | Best-effort (same as above) | Periodic publishes to LOC. |

When connectivity is restored (detected via `DeviceNetworkStatus`), the main event
loop kicks `deferredEventQueue` to flush any pending reliable messages.

## Source File Map

| File | Responsibility |
|---|---|
| `zedagent.go` | `Run()`, `mainEventLoop()`, `initPublications()`, `initPostOnboardSubs()`; handlers for DNS, DPCL, GlobalConfig, AppInstanceStatus, NodeAgentStatus, VaultStatus, etc. |
| `handleconfig.go` | Config timer task, config fetch and parsing orchestration, bootstrap/saved-config loading, config backup, `getconfigContext`. |
| `parseconfig.go` | Protobuf parsing for all config sub-types: apps, networks, volumes, base OS, datastores, config items, device I/O, SCEP, PNAC, bonds, VLANs, disks, patch envelopes, device ops. |
| `reportinfo.go` | `deviceInfoTask`, `objectInfoTask`, `PublishDeviceInfoToZedCloud`, `PublishAppInfoToZedCloud`, and all helper encoders for `ZInfoDevice`. |
| `handlemetrics.go` | `metricsAndInfoTimerTask`, `publishMetrics`, and all metric collection helpers (disk, volume, NI, app, flow, ZFS). |
| `attesttask.go` | Remote attestation FSM: nonce, quote, escrow; `attestContext`; TPM agent and verifier implementations. |
| `handlecertconfig.go` | Controller cert fetching and caching; edge-node cert publishing; cipher context; `cipherContext`. |
| `handlenetworkinstance.go` | NI and app-network status handling; NI info/metrics publish; flow monitor and flow log. |
| `localcommand.go` | `Apply*` methods called by `LocalCmdAgent` to execute LPS/LOC commands via pubsub. |
| `handlentp.go` | NTP source timer task; chrony socket queries; NTP info publish. |
| `handlelocation.go` | Location timer task; GPS/cell location info publish to controller and apps. |
| `hardwareinfo.go` | Hardware info task; triggers `ZInfoHardware` publish. |
| `handlebaseos.go` | Base OS and zboot status handlers; signals config-restarted to baseosmgr. |
| `handlecontent.go` | Content tree config parsing and status handling. |
| `handlevolume.go` | Volume config parsing and status handling. |
| `handlecipherconfig.go` | Cipher context and cipher block parsing from controller config. |
| `parseedgeview.go` | EdgeView JWT parsing and configuration. |
| `parsepatchenvelopes.go` | Patch envelope parsing; cipher-block artifact caching. |
| `parsedisk.go` | Edge-node disk configuration parsing. |
| `parseedgenodeinfo.go` | Edge-node info fields (serial, model, product) from config. |
| `handleedgenodecluster.go` | Kubernetes cluster info and update status tasks (Kubevirt only). |
| `handlenodedrain.go` | Node drain status handling; drain-deferred config application. |
| `handlepatchenvelopes.go` | Patch envelope status handling and info publish. |
| `handleappInstMetadata.go` | App instance metadata (msrv) status handling. |
| `handleblob.go` | Blob status handling for info publish. |
| `watchdog.go` | Hardware watchdog detection helper. |
| `validate.go` | Config UTF-8 validation (used with `-p`/`-V` CLI flags). |
