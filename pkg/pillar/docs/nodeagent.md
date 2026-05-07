# Node Agent

## Overview

`nodeagent` is the EVE microservice responsible for the lifecycle of the node
itself — as opposed to the workloads it runs. Its main jobs are:

* drive the **A/B baseos upgrade** process, in cooperation with `baseosmgr` and
  `zedagent`, including the post-upgrade *test* window during which the new
  image must prove itself by reaching the controller before being marked
  `active`,
* **reboot, shut down or power off** the device when asked by the controller
  (via `zedagent`) or when an internal health timer expires,
* watch a small set of **health signals** (controller reachability, vault
  state, TPM sanity, free disk space, certificate refusal, kubernetes node
  drain) and either trigger a reboot or push the device into
  *Maintenance Mode*,
* on every boot, **reconstruct and report the previous reboot** (reason, boot
  reason, stack/dmesg, image, time) and bump the persistent `restartCounter`,
* surface installer logs from the very first boot of a freshly installed image.

`nodeagent` is intentionally small (a single `nodeagentContext` event loop, no
sub-packages); most of its complexity lives in *when* to do something rather
than *how*. The "how" — flipping partition states, reaching the controller —
is delegated to `baseosmgr`/`zboot` and `zedagent`.

## Key Input/Output

**nodeagent consumes** (all via pubsub unless noted):

* global configuration properties
  * `ConfigItemValueMap` from `zedagent`
  * supplies the four health-timer thresholds:
    `timer.reboot.no.network` (`ResetIfCloudGoneTime`),
    `timer.update.fallback.no.network` (`FallbackIfCloudGoneTime`),
    `timer.test.baseimage.update` (`MintimeUpdateSuccess`),
    `timer.vault.ready.cutoff` (`VaultReadyCutOffTime`)
* zedagent status
  * `ZedAgentStatus` from `zedagent`
  * carries the controller-driven `RebootCmd` / `ShutdownCmd` / `PoweroffCmd`
    requests with a `RequestedRebootReason` and `RequestedBootReason`,
  * carries `ConfigGetStatus` (`Success`, `TemporaryFail`, `ReadSaved`,
    `Fail`) which is the heartbeat used to drive every "have we lost the
    controller?" timer,
  * carries `EdgeNodeCertsRefused` to drive the corresponding
    Maintenance Mode reason
* zboot status
  * `ZbootStatus` per partition from `baseosmgr`
  * tells nodeagent when the *other* partition has been flipped to
    `updating` (→ schedule a reboot into the new image) and when the
    *current* partition has been flipped to `active` (→ upgrade fully
    committed)
* domain status
  * `DomainStatus` from `domainmgr`
  * polled while a reboot/shutdown/poweroff is in flight to wait for all
    app domains to be halted
* vault status
  * `VaultStatus` from `vaultmgr` — drives `MaintenanceModeReasonVaultLockedUp`
    and, if an upgrade is in progress and the vault never opens within
    `VaultReadyCutOffTime`, triggers a fallback reboot
    (`BootReasonVaultFailure`)
* TPM sanity status
  * `TpmSanityStatus` from `tpmmgr` — drives
    `MaintenanceModeReasonTpmEncFailure`
* volume manager status
  * `VolumeMgrStatus` from `volumemgr` — its `RemainingSpace` field drives
    `MaintenanceModeReasonNoDiskSpace`
* node drain status (kubevirt builds only)
  * `kubeapi.NodeDrainStatus` from `zedkube`
  * keeps `WaitDrainInProgress` set in `NodeAgentStatus` so that `zedagent`
    holds back the controller-requested reboot/shutdown/poweroff until the
    kube node has finished draining its workloads
* onboarding status
  * `OnboardingStatus` (via `wait.WaitForOnboarded`) — nodeagent blocks on
    this once before joining the main event loop
* on-disk state (read at start)
  * `/persist/reboot-reason`, `/persist/boot-reason`, `/persist/reboot-stack`,
    `/persist/reboot-image` (via `agentlog.Get*`), used to reconstruct the
    previous reboot,
  * `/persist/SMART_details.json` and `/persist/SMART_details_previous.json`
    — SMART power-cycle counters from the storage controller; consulted
    when no reboot reason was recorded, to distinguish a dirty power-off
    (counter incremented) from a kernel panic / watchdog reset
    (counter unchanged),
  * `/run/global/first-boot` — marker dropped by the installer on the very
    first boot; presence sets the boot reason to `BootReasonFirst`,
  * `/persist/installer/installer.log` plus
    `/persist/installer/send-require` — installer output to be replayed
    into the regular log stream,
  * `/persist/status/restartcounter` — monotonic restart counter,
  * `/persist/fault-injection/readfile` — fault-injection knob.

**nodeagent publishes**:

* `NodeAgentStatus` (consumed by `zedagent`, ultimately surfaced to the
  controller)
  * current active partition (`IMGA` or `IMGB`),
  * `UpdateInprogress` plus the `RemainingTestTime` countdown shown to the
    operator during post-upgrade validation,
  * `DeviceReboot` / `DeviceShutdown` / `DevicePoweroff` plus
    `AllDomainsHalted` (the fine-grained progression of the operation),
  * `RebootReason`, `BootReason`, `RebootStack`, `RebootTime`, `RebootImage`
    from the previous boot,
  * `RestartCounter`,
  * `LocalMaintenanceMode` and the multi-reason
    `LocalMaintenanceModeReasons`,
  * `HVTypeKube`, `WaitDrainInProgress`
* `ZbootConfig` — one entry per partition (`IMGA`, `IMGB`); the only
  meaningful field is `TestComplete`, which is flipped to `true` when the
  post-upgrade test window expires successfully and `baseosmgr` should
  commit the new image. This publication is **persistent**: it is read back
  on next boot.
* `RebootReason` / `BootReason` files in `/persist/` — written via
  `agentlog.RebootReason()` just before issuing the actual `zboot.Reset()`
  or `zboot.Poweroff()` so that the *next* boot of nodeagent can pick them
  up.

## Components

Unlike NIM, nodeagent is not split into separately-testable components with
Go interfaces between them. It is a single `nodeagentContext` running one
goroutine for the main event loop. The logical responsibilities, however,
are cleanly partitioned across the source files:

### Lifecycle / pubsub wiring (`nodeagent.go`)

`Run()` initializes the agent, creates the publishers and subscribers,
starts a 10-second `tickerTimer` and a 25-second `stillRunning` watchdog,
blocks for `GlobalConfig` and onboarding to be available, and then enters
the main `select` loop. The same file also contains the handlers for the
non-zboot subscriptions: `globalConfig`, `vaultStatus`, `volumeMgrStatus`,
`tpmStatus`, and the `zedAgentStatus` ingress that translates controller
device-ops into local `handleDeviceCmd()` calls.

### Reboot-reason reconstruction (`nodeagent.go`)

`handleLastRebootReason()` is called once at startup. It reads anything the
*previous* boot left behind (`agentlog.GetRebootReason()`,
`GetBootReason()`, `GetRebootImage()`), and if nothing was recorded it
synthesizes a default using two side-channel signals:

* `/run/global/first-boot` (set by the installer) → `BootReasonFirst`,
* the `PowerCycleCount` delta between current and previous SMART snapshots
  → `BootReasonPowerFail` (count went up: dirty power cycle) versus
  `BootReasonKernel` (count unchanged: kernel panic / watchdog with no
  kdump),
* fallback: `BootReasonUnknown`.

The reboot stack, if any, is logged line-by-line and (if it is bigger than
~1700 bytes) tail-truncated so that the publication fits in pubsub. This
function is also where `restartCounter` gets read, incremented, and
written back.

### Health timers (`handletimers.go`)

`handleDeviceTimers()` fires every 10 seconds and is the heart of the
agent. It only operates on its own monotonic `timeTickCount` (incremented
by the timer interval), never on wall-clock time, so that NTP jumping the
clock by decades on first boot does not trip every timer at once. It runs
four checks in order:

1. **`handleFallbackOnCloudDisconnect`** — only when an upgrade is being
   tested. If the controller has been unreachable for
   `FallbackIfCloudGoneTime`, the new image is presumed bad: schedule a
   reboot with `BootReasonFallback`, `baseosmgr` will then flip the
   partition back.
2. **`handleRebootOnVaultLocked`** — if `vaultmgr` reports the vault as
   `DATASEC_AT_REST_ERROR`, wait at most `VaultReadyCutOffTime`. If an
   upgrade is in progress when the deadline fires, reboot with
   `BootReasonVaultFailure` (the upgrade fails); otherwise enter
   Maintenance Mode with `MaintenanceModeReasonVaultLockedUp`.
3. **`handleResetOnCloudDisconnect`** — independently of any upgrade, if
   the controller has been unreachable for `ResetIfCloudGoneTime`,
   schedule a reboot with `BootReasonDisconnect`. This is the long-tail
   "we have lost the cloud, try a clean restart" timer, intended to
   recover from odd hardware/driver failures (for example a hung Ethernet
   adapter) that a reboot is likely to clear.
4. **`handleUpgradeTestValidation`** — if a post-upgrade test is in flight
   (`testInprogress`) and `MintimeUpdateSuccess` has elapsed, declare the
   image good: clear the test, set `ZbootConfig.TestComplete = true` so
   `baseosmgr` commits the partition.

`updateZedagentCloudConnectStatus()` translates `ConfigGetStatus`
transitions into `lastControllerReachableTime` updates and into
start/restart/clear of the test window.

`handleDeviceCmd()` and `scheduleNodeOperation()` are the entry points for
both controller-driven (`RebootCmd`/`ShutdownCmd`/`PoweroffCmd`) and
internally-driven device operations. They guard against double-trigger,
update `NodeAgentStatus`, and spawn `handleNodeOperation()` in its own
goroutine.

`handleNodeOperation()` waits `minRebootDelay` (30s by default), persists
the reboot reason via `agentlog.RebootReason()`, calls
`waitForAllDomainsHalted()` (poll `DomainStatus` up to
`maxDomainHaltTime`), `syscall.Sync()`, waits another `minRebootDelay`,
flushes coverage data, and finally calls `zboot.Reset()` or
`zboot.Poweroff()`. A 120-second backstop goroutine `os.Exit(0)`s the
process if the zboot call hangs — the underlying `reboot` syscall has
been seen to stall inside the kernel due to kernel bugs, so the backstop
ensures the in-kernel watchdog takes over and restarts the node.

### A/B upgrade orchestration (`handlebaseos.go`, `handlezboot.go`)

`handleZbootStatusImpl()` is the inbound side. When the *current*
partition transitions to `active` while we still thought the upgrade was
in progress, the agent latches the upgrade as fully committed
(`updateInprogress=false`, etc.). It then dispatches:

* `doZbootBaseOsInstallationComplete()` — the *other* partition just
  became `updating` (a new image was written): schedule a reboot with
  `BootReasonUpdate` and a friendly `NORMAL: baseos-update(...) to EVE
  version X reboot` message.
* `doZbootBaseOsTestValidationComplete()` — the *current* partition's
  `TestComplete` flag has been observed back from `baseosmgr` after we
  set it; clear it on the config side and mark `updateComplete=true`.

`handlezboot.go` contains the small lookup helpers (`lookupZbootConfig`,
`lookupZbootStatus`, `getZbootOtherPartition`,
`isZbootOtherPartitionStateUpdating`, `publishZbootConfig*`). All
real partition operations are delegated to the `pillar/zboot` package
which knows about `IMGA`/`IMGB`/`grubenv`.

### Kube node-drain glue (`handlenodedrain.go`)

Kubevirt builds receive a `kubeapi.NodeDrainStatus` from `zedkube`. As
long as a drain initiated by *device-op* (reboot/shutdown/poweroff) is
between `REQUESTED` and `COMPLETE`, nodeagent flips
`WaitDrainInProgress` so that `zedagent` keeps the deferred device op
deferred. On `COMPLETE`, the flag is cleared and the device op is
allowed to proceed.

### Maintenance Mode

Maintenance Mode is a multi-reason flag (`MaintenanceModeMultiReason`)
maintained via two helpers, `addMaintenanceModeReason()` and
`removeMaintenanceModeReason()`. Each contributing handler (vault, TPM,
disk space, certs-refused) calls these and re-publishes
`NodeAgentStatus`. The mode is only fully cleared when *every* reason
has been removed.

## Control-flow

There are four largely independent control paths through nodeagent.

### 1. Boot and onboarding

```text
Run()
  └─ subscribe GlobalConfig
  └─ wait for GCInitialized                   (sets log levels)
  └─ parseSMARTData()
  └─ handleLastRebootReason()                 (publishes nothing yet,
  └─ handleInstallationLog()                   updates ctx fields)
  └─ create publications, ZbootConfig, NodeAgentStatus
  └─ subscribe vault/volume/tpm
  └─ publishZbootConfigAll()                  (one entry per partition)
  └─ ctx.updateInprogress = zboot.IsCurrentPartitionStateInProgress()
  └─ publishNodeAgentStatus()                 (first publication)
  └─ subscribe DomainStatus
  └─ wait.WaitForOnboarded()
  └─ setTestStartTime()                       (no-op unless updateInprogress)
  └─ subscribe ZbootStatus, ZedAgentStatus, NodeDrainStatus
  └─ event loop
```

### 2. Periodic timer tick (every 10s)

```text
tickerTimer fires
  → updateTickerTime()                    (advance ctx.timeTickCount)
  → handleFallbackOnCloudDisconnect()     (only if updateInprogress)
  → handleRebootOnVaultLocked()           (only if vault disabled)
  → handleResetOnCloudDisconnect()        (always)
  → handleUpgradeTestValidation()         (only if testInprogress)
```

### 3. Controller-driven device operation

```text
zedagent publishes ZedAgentStatus{RebootCmd:true, …}
  → handleZedAgentStatusImpl()
    → handleDeviceCmd(op=Reboot)
      → scheduleNodeOperation(reason, bootReason, op)
        → ctx.deviceReboot = true
        → publishNodeAgentStatus()        (zedagent now sees DeviceReboot)
        → go handleNodeOperation(op)
            ├ wait minRebootDelay
            ├ agentlog.RebootReason(...)  (persists reason for next boot)
            ├ waitForAllDomainsHalted()
            ├ ctx.allDomainsHalted = true; publish
            ├ syscall.Sync(); wait minRebootDelay
            ├ flushCoverage
            └ zboot.Reset() / zboot.Poweroff()
```

The very same `scheduleNodeOperation()` is what the four health timers
call when they decide the device must be reset.

### 4. Baseos upgrade

```text
(a) "other partition is updating" — new image just written
zedagent → ZbootStatus(other = updating)
  → handleZbootStatusImpl()
    → doZbootBaseOsInstallationComplete()
      → scheduleNodeOperation(BootReasonUpdate, Reboot)

(b) post-reboot, current partition still inprogress — test window
Run() sets updateInprogress = true
  → setTestStartTime() once GlobalConfig is in
ConfigGetStatus = Success keeps lastControllerReachableTime fresh
After MintimeUpdateSuccess seconds:
  handleUpgradeTestValidation()
    → initiateBaseOsControllerTestComplete()
      → publish ZbootConfig{TestComplete:true} for curPart

(c) baseosmgr acknowledges by flipping curPart to active and clearing
    its TestComplete in ZbootStatus:
  handleZbootStatusImpl():
    if curPart && updateInprogress && state==active:
       updateInprogress = false; testComplete = false; updateComplete = false
    doZbootBaseOsTestValidationComplete():
       republish ZbootConfig with TestComplete=false; updateComplete=true
```

If the test window times out without the controller being reachable,
`handleFallbackOnCloudDisconnect()` instead schedules a fallback
reboot (`BootReasonFallback`). `baseosmgr` then rolls the partition
back on the next boot.

## Debugging

### PubSub

On a running device:

```sh
cat /run/nodeagent/NodeAgentStatus/nodeagent.json | jq
cat /persist/status/nodeagent/ZbootConfig/IMGA.json | jq
cat /persist/status/nodeagent/ZbootConfig/IMGB.json | jq
```

The first shows the agent's view of update/reboot state and the list of
maintenance-mode reasons. The other two show whether nodeagent has
asked `baseosmgr` to commit the new image (`TestComplete`).

Persistent files of interest under `/persist/`:

* `status/restartcounter` — number of restarts of pillar
* `reboot-reason`, `boot-reason`, `reboot-stack`, `reboot-image` —
  written just before reboot; consumed and discarded on next boot
* `SMART_details.json`, `SMART_details_previous.json` — power-cycle
  counter snapshots used by the boot-reason heuristic
* `installer/installer.log`, `installer/send-require` — installer
  output to be replayed into the log stream on first post-install boot

### Logs

Useful `grep` patterns:

```text
"Current partition RebootReason"        – previous boot's reason as read at startup
"found bootReason"                      – previous boot's BootReason
"Default RebootReason"                  – nodeagent had to synthesize one
"Starting upgrade validation for"       – post-upgrade test window opening
"inprogress, waiting for"               – periodic countdown of remaining test time
"Upgrade Validation Test Complete"      – post-upgrade test window expired OK
"Exceeded fallback outage"              – BootReasonFallback path firing
"Exceeded outage for controller"        – BootReasonDisconnect path firing
"Exceeded time for vault to be ready"   – BootReasonVaultFailure path firing
"setting MaintenanceModeReason"         – addMaintenanceModeReason()
"clearing MaintenanceModeReason"        – removeMaintenanceModeReason()
"No reason to be in maintenance mode"   – mode fully cleared
"baseos-update("                        – BootReasonUpdate scheduling
"handleNodeOperation: minRebootDelay"   – the 30s pre-reboot pause
"waitForAllDomainsHalted"               – polling DomainStatus before reboot
"Doing a sync.."                        – just before zboot.Reset/Poweroff
"nodedrain-step:"                       – kube node-drain glue
```

### Forcing transitions for development

* Reboot/shutdown/poweroff via the controller is the normal path; on
  a dev device it can also be exercised by making `zedagent` publish
  `ZedAgentStatus{RebootCmd:true,…}`.
* The fallback / reset timers can be exercised by cutting controller
  reachability (`eden eve link down` in eden) for longer than the
  configured `timer.update.fallback.no.network` /
  `timer.reboot.no.network`.
* The post-upgrade test window can be shortened with
  `timer.test.baseimage.update=30` (used by the
  `update_eve_image` eden test).
* The fault-injection knob `/persist/fault-injection/readfile` causes
  nodeagent to read an arbitrary file at startup. Pointing it at a
  large file is the easiest way to drive pillar into an out-of-memory
  condition, which then triggers the OOM-killer and a watchdog reboot —
  useful for exercising the OOM/watchdog path end-to-end.
