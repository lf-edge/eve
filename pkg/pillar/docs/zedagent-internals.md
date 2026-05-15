# zedagent Internals

This document covers subsystems of `zedagent` that are architecturally significant
but too detailed for the main [zedagent.md](zedagent.md) overview.  It is intended
for contributors working on the agent itself or writing eden integration tests.

## Pubsub Map

### Publications (zedagent → downstream agents)

| Topic type | pubsub key | Consumer(s) |
|---|---|---|
| `AppInstanceConfig` | app UUID | `zedmanager` |
| `AppNetworkConfig` | app UUID | `zedrouter` |
| `NetworkInstanceConfig` | NI UUID | `zedrouter` |
| `NetworkXObjectConfig` | network UUID | `zedrouter` |
| `BaseOsConfig` | base OS UUID | `baseosmgr` |
| `DatastoreConfig` | datastore UUID | `downloader` |
| `ContentTreeConfig` | content tree UUID | `volumemgr` |
| `VolumeConfig` | volume UUID | `volumemgr` |
| `DevicePortConfig` | `"lps"` (`types.LpsDPCKey`) | `nim` |
| `PhysicalIOAdapterList` | `"global"` | `domainmgr` |
| `GlobalConfig` (ConfigItemValueMap) | `"global"` | all agents (self-subscribe for log levels, timers, etc.) |
| `ZedAgentStatus` | `"zedagent"` (agent name) | `baseosmgr`, `nodeagent`, `LPS/LOC` consumers |
| `ControllerCert` | cert hash | `downloader`, `nim`, other agents doing TLS |
| `CipherContext` | cipher context UUID | `domainmgr`, `zedrouter`, `downloader`, others |
| `SCEPProfile` | profile key | `scepclient` |
| `LOCConfig` | `""` (empty) | `baseosmgr` |
| `CollectInfoCmd` | `time.Now().String()` (dynamic per request) | `diag` |
| `DisksConfig` (EdgeNodeDisks) | `"global"` | `domainmgr` |
| `EdgeNodeInfo` | `"global"` | `baseosmgr` |
| `PatchEnvelopeInfoList` | `"global"` | `msrv` |
| `EdgeNodeClusterConfig` | `"global"` | `zedkube` (Kubevirt only) |
| `AttestNonce` | hex of nonce (dynamic per request) | `tpmmgr` |
| `EncryptedKeyFromController` | vault name (dynamic per vault) | `vaultmgr` |
| `NodeDrainRequest` | `"global"` | `nodeagent` |
| `MetricsMap` | `"global"` | (internal, for metrics deduplication) |

### Subscriptions (zedagent ← upstream agents)

| Topic type | Publisher | Handler(s) |
|---|---|---|
| `OnboardingStatus` | `zedclient` | `handleOnboardStatusCreate/Modify` – unblocks onboarding gate |
| `NodeAgentStatus` | `nodeagent` | `handleNodeAgentStatusImpl` – reboot reason, counters, device/shutdown state |
| `GlobalConfig` | self | `handleGlobalConfigImpl` – applies config items, maintenance mode |
| `ZbootStatus` | `baseosmgr` | `handleZbootRestarted` – unblocks zboot gate; tracks OTA state |
| `BaseOsStatus` | `baseosmgr` | `handleBaseOsStatusImpl` – OTA update progress for device info |
| `AppInstanceStatus` | `zedmanager` | `handleAppInstanceStatusCreate/Modify/Delete` – app info trigger |
| `AppNetworkStatus` | `zedrouter` | `handleAppNetworkStatusCreate/Modify/Delete` – per-app NI binding |
| `NetworkInstanceStatus` | `zedrouter` | `handleNetworkInstanceImpl` – NI info + metrics trigger |
| `NetworkInstanceMetrics` | `zedrouter` | (folded into `handleNetworkInstanceImpl`) |
| `AppFlowMonitor` | `zedrouter` | `handleAppFlowMonitorImpl` – enqueues flow log messages |
| `AppContainerMetrics` | `zedrouter` | `handleAppContainerMetricsImpl` – app container stats |
| `DevicePortConfigList` | `nim` | `handleDPCLImpl` – DPC state for device info |
| `DeviceNetworkStatus` | `nim` | `handleDNSImpl` – unblocks DeviceNetworkStatus gate; kicks deferred queue |
| `NetworkMetrics` | `zedrouter` | (folded into `publishMetrics`) |
| `NimMetrics` | `nim` | (folded into `publishMetrics`) |
| `ZRouterMetrics` | `zedrouter` | (folded into `publishMetrics`) |
| `ClientMetrics` | `zedclient` | (folded into `publishMetrics`) |
| `LoguploaderMetrics` | `loguploader` | (folded into `publishMetrics`) |
| `DownloaderMetrics` | `downloader` | (folded into `publishMetrics`) |
| `DiagMetrics` | `diag` | (folded into `publishMetrics`) |
| `DomainMetric` | `domainmgr` | (folded into `publishMetrics`) |
| `ProcessMetric` | `domainmgr` | (folded into `publishMetrics`) |
| `HostMemory` | `domainmgr` | (folded into `publishMetrics`) |
| `DiskMetric` | `volumemgr` | `handleDiskMetricImpl` – global disk usage for metrics |
| `AppDiskMetric` | `volumemgr` | `handleAppDiskMetricImpl` – per-app disk usage for metrics |
| `VolumeStatus` | `volumemgr` | `handleVolumeStatusImpl` – volume info trigger |
| `ContentTreeStatus` | `volumemgr` | `handleContentTreeStatusImpl` – content tree info trigger |
| `BlobStatus` | `volumemgr` | `handleBlobStatusImpl` – blob info trigger |
| `ZFSPoolStatus` | `zfsmanager` | (folded into device info) |
| `ZFSPoolMetrics` | `zfsmanager` | (folded into `publishMetrics`) |
| `AssignableAdapters` | `domainmgr` | `handleAAImpl` – device IO assignment for device info |
| `Capabilities` | `domainmgr` | (folded into device info) |
| `EdgeNodeCert` | `tpmmgr` | `handleEdgeNodeCertImpl` – triggers edge-node cert publish |
| `VaultStatus` | `vaultmgr` | `handleVaultStatusImpl` – vault/TPM status for device info |
| `AttestQuote` | `tpmmgr` | `handleAttestQuoteImpl` – drives attestation FSM forward |
| `EncryptedKeyFromDevice` | `vaultmgr` | `handleEncryptedKeyFromDeviceImpl` – attestation escrow |
| `WwanStatus` | `wwan` | (folded into device info / metrics) |
| `WwanMetrics` | `wwan` | (folded into `publishMetrics`) |
| `LocationInfo` | `wwan` | `locationTimerTask` – location info publish |
| `NewlogMetrics` | `newlogd` | (folded into `publishMetrics`) |
| `BaseOsMgrStatus` | `baseosmgr` | (folded into device info) |
| `AppInstMetaData` | `msrv` | `handleAppInstMetaDataImpl` – app metadata info |
| `EdgeviewStatus` | `edgeview` | `handleEdgeviewStatusImpl` – EdgeView info trigger |
| `PatchEnvelopeStatus` | `msrv` | `handlePatchEnvelopeStatusImpl` – patch envelope info |
| `PatchEnvelopeUsage` | `msrv` | (folded into app info) |
| `CachedResolvedIPs` | `nim` | (forwarded to config HTTP client) |
| `NodeDrainStatus` | `nodeagent` | `handleNodeDrainStatusImpl` – defers config during drain |
| `ClusterUpdateStatus` | `zedkube` | (Kubevirt only) cluster update info trigger |
| `KubeClusterInfo` | `zedkube` | (Kubevirt only) cluster info trigger |
| `NestedAppRuntimeStorageMetric` | `zedrouter` | (folded into app metrics) |
| `EnrolledCertStatus` | `scepclient` | (folded into device info) |
| `PNACMetricsList` | `nim` | (folded into `publishMetrics`) |
| `BondMetricsList` | `nim` | (folded into `publishMetrics`) |
| `CipherMetrics` (×5) | `downloader`, `domainmgr`, `nim`, `zedrouter`, `wwan` | (folded into `publishMetrics`) |

## Attestation FSM

Remote attestation runs an FSM in `attesttask.go` using the `zattest` package.
The full sequence on a TPM-equipped device is:

```text
zedagent                 tpmmgr              controller              vaultmgr
   │                        │                    │                       │
   │─── pubAttestNonce ────►│                    │                       │
   │    (nonce request)      │                    │                       │
   │                        │──► InternalQuoteRequest                    │
   │◄── AttestQuote ────────│    (TPM quote with PCRs)                   │
   │                        │                    │                       │
   │─── SendAttestQuote ───────────────────────►│                       │
   │    (quote + nonce)      │                    │                       │
   │◄── EncryptedEscrow ────────────────────────│                       │
   │    (sealed key blob)    │                    │                       │
   │─── pubEncryptedKeyFromController ─────────────────────────────────►│
   │    (encrypted key)      │                    │                       │
   │                        │                    │ (vault unlocked)      │
```

Conceptually, the security-relevant flow is end-to-end between the **controller and
the TPM**: the controller mints a fresh nonce, the TPM bakes it into a signed quote
over the device's PCRs, and the controller validates the resulting quote. The
diagram above shows zedagent's internal role as the courier that routes those
payloads — `AttestNonce` and `AttestQuote` over pubsub between `tpmmgr` and
`zedagent`, then `ZAttestReq`/`ZAttestResponse` over the EVE API between `zedagent`
and the controller — and that escrows the resulting vault keys via `vaultmgr`.

All three FSM transitions ride a single EVE-API endpoint,
`POST /api/v2/edgedevice/id/{deviceUUID}/attest`, with a discriminated `ZAttestReq`
body:

| Step | `ReqType` | Request payload | Response payload |
|---|---|---|---|
| Nonce request | `ATTEST_REQ_NONCE` | (empty) | `ZAttestNonceResp{Nonce}` |
| Quote send | `ATTEST_REQ_QUOTE` | `ZAttestQuote{AttestData,Signature,PcrValues[0..15],Versions,TpmBinaryEventLog}` | `ZAttestQuoteResp{Response,IntegrityToken,Keys}` |
| Escrow (non-airgapped) | `Z_ATTEST_REQ_TYPE_STORE_KEYS` | `AttestStorageKeys{IntegrityToken,Keys}` | `AttestStorageKeysResp{Response}` |

Proto types live in `eve-api/go/attest/`. The controller-side semantics — nonce
freshness, PCR policy, escrow handling — are described in the [Measured Boot and
Remote Attestation](https://lf-edge.atlassian.net/wiki/spaces/EVE/pages/14584444/Measured+Boot+and+Remote+Attestation)
Confluence page.

Key points:

- The FSM is initialized by `attestModuleInitialize` before post-onboard subscriptions
  are activated so that `AttestQuote` and `EncryptedKeyFromDevice` events are never
  missed.
- On failure (quote rejected, nonce mismatch, TPM error), the FSM retries with
  exponential backoff via `restartAttestation`.  `attestationTryCount` tracks retries
  and is reported in device info (`ZInfoDevice.attestState`).
- `storeIntegrityToken` / `readIntegrityToken` persist the integrity token across
  reboots in `/persist/status/zedagent/`.
- On non-TPM devices (`SkipEscrow = true`), the escrow step is skipped; attestation
  reaches `ATTEST_STATE_COMPLETE` after a successful quote exchange.
- The integrity token is included in subsequent config requests to prove device health
  to the controller.

## Maintenance Mode

`zedagent` derives a single `maintenanceMode` bool from three independent sources and
consolidates them in `mergeMaintenanceMode`:

| Source | Field | Type | Set when |
|---|---|---|---|
| Controller config API | `apiMaintenanceMode` | `bool` | The device config's dedicated `EdgeDevConfig.MaintenanceMode` protobuf field is set (controller-supplied; `parseconfig.go:110`). |
| GlobalConfig knob | `gcpMaintenanceMode` | `TriState` | The `maintenance.mode` global-config entry is set (`types/global.go:317`); written by controller or LOC (never LPS) via `parseConfigItems` (`parseconfig.go:3197`, `zedagent.go:2704`). |
| Local failure (nodeagent) | `localMaintenanceMode` + `localMaintModeReasons` | `bool` + `[]MaintenanceModeReason` | `nodeagent` publishes `NodeAgentStatus.LocalMaintenanceMode=true` with one or more reasons from `types.MaintenanceModeReason` (`UserRequested`, `VaultLockedUp`, `NoDiskSpace`, `TpmEncFailure`, `TpmQuoteFailure`, `EdgeNodeCertsRefused`); enum at `types/zedagenttypes.go:404`. |

`maintenanceMode = apiMaintenanceMode || (gcpMaintenanceMode == TS_TRUE) || localMaintenanceMode`

When `maintenanceMode` is set:

- `devState` is set to `DS_MAINTENANCE_MODE` and published in `ZedAgentStatus` and
  `ZInfoDevice`.
- The `configTimerTask` still fetches config so that the controller can clear
  maintenance mode remotely.
- New application deployments and base OS updates are deferred until maintenance mode
  is cleared.

## Eden Test Coverage Map

This section maps each major zedagent subsystem to the eden test that exercises it and
notes which functions each test is specifically designed to cover.

### Go unit tests (no EVE required)

None of the zedagent subsystems are cleanly unit-testable without a running EVE
because they all depend on the pubsub event loop.  The exception is pure parsing
logic in `parseconfig.go` (e.g., `parseIpspec`, `computeConfigSha`, `isLocConfigValid`)
which could be extracted and unit-tested; this has not been done yet.

### Eden integration tests

| Test | Location | Primary targets |
|---|---|---|
| `config_items_and_status` | `tests/zedagent/testdata/` | `parseConfigItems`, `handleGlobalConfigImpl`, `publishZedAgentStatus`, `mergeMaintenanceMode` |
| `network_instance_info_metrics` | `tests/zedagent/testdata/` | `handleNetworkInstanceImpl`, `prepareAndPublishNetworkInstanceInfoMsg`, `createNetworkInstanceMetrics`, `handleAppFlowMonitorImpl`, `flowlogTask` |
| `app_metrics_detail` | `tests/zedagent/testdata/` | `handleDiskMetricImpl`, `handleAppDiskMetricImpl`, `createVolumeInstanceMetrics`, `getVolumeResourcesMetrics`, `fillStorageDiskMetrics`, `addUserSwInfo` |
| `device_info_completeness` | `tests/zedagent/testdata/` | `PublishDeviceInfoToZedCloud`, `getDataSecAtRestInfo`, `createConfigItemStatus`, `getCapabilities`, `getEnrolledCertsInfo`, `encodeSystemAdapterInfo` |
| `maintenance_mode` | `tests/zedagent/testdata/` | `mergeMaintenanceMode`, `equalMaintenanceMode`, `handleGlobalConfigImpl` (maintenance path), `publishZedAgentStatus`, `getDeviceState` |
| `attest_flow` | `tests/zedagent/testdata/` | `handleAttestQuoteImpl`, `handleEncryptedKeyFromDeviceImpl`, `publishAttestNonce`, `storeIntegrityToken`, `readIntegrityToken`, `restartAttestation`, `recordAttestationTry` |
| `ctrl_cert_change` | `tests/eclient/testdata/` | `parsePublishControllerCerts`, `handleControllerCertsSha`, `triggerControllerCertEvent`, `verifySigningCertNewest` |

### Subsystems not yet covered

| Subsystem | Functions | Blocker |
|---|---|---|
| Base OS fallback path | `forcefallback.go` (6 fns) | Need OTA update test with deliberate failure |
| SCEP enrollment | `parseSCEPProfiles`, scep HTTP flow | Need SCEP server in test environment |
| PNAC config | `parsePNACConfig` | Need 802.1X-capable test environment |
| ZFS metrics | `fillStorageZVolMetrics`, `fillStorageVDevMetrics` | Need ZFS-capable test instance |
| vcom metrics | protobuf `Reset`/`String` methods | Need vcom test suite with coverage build |
| Device operation commands | `handleDeviceOperationCmd`, `scheduleBackup` | Requires reboot/backup capable test |
| Snapshot config | `parseSnapshotConfig`, `parseSnapshots` | Requires volume snapshot support in test |
