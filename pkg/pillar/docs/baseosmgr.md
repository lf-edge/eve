# Base OS Manager

## Overview

`baseosmgr` is the EVE microservice responsible for the **A/B partition state
machine** that backs every base-os upgrade. It owns the two `IMGA`/`IMGB`
partitions: which one is `active`, which one is `inprogress` / `updating` /
`unused`, and the version strings recorded in each. Its main jobs are:

* take a controller-supplied `BaseOsConfig` (a content tree UUID and a desired
  `BaseOsVersion`) and **install the new image into the *other* partition** —
  but only after `volumemgr` has finished downloading and verifying it,
* on `Activate=true`, **flip the other partition's GRUB state to `updating`**
  so that the next reboot lands on it; the actual reboot is `nodeagent`'s job,
* on `BaseOsConfig` **delete** while an install is still in flight, **cancel
  the pending install worker** and, if the other partition has already been
  flipped to `updating`, **roll it back to `unused`** so a later reboot does
  not pick up the abandoned image,
* on the post-upgrade test pass (signalled by `nodeagent` via
  `ZbootConfig{TestComplete:true}` for the current partition), **commit the
  upgrade** by calling `zboot.MarkCurrentPartitionStateActive`,
* surface, into `BaseOsStatus`, the **reason a previous upgrade failed** —
  copying the previous boot's `RebootReason`/`RebootTime` (received via
  `NodeAgentStatus`) onto the BaseOsStatus that owns the now-`inprogress`
  other partition,
* respect the **kubevirt node-drain** protocol: defer the partition flip until
  `zedkube` reports the node has finished draining,
* implement the **force-fallback** knob: if the controller bumps
  `ForceFallbackCounter`, mark the (currently `unused`) other partition as
  `updating` so `nodeagent` reboots into the prior image,
* implement the **retry-update counter**: if the controller bumps
  `RetryUpdateCounter` while the other partition is in `inprogress` with the
  same version that just failed, kick the partition state back to `updating`
  so the same image is tried again across a reboot,
* maintain a published mirror of the on-disk GRUB state, **`ZbootStatus`**,
  one entry per partition, that other agents (`zedagent`, and `nodeagent`
  once it is running) consume instead of going through the `zboot`
  package directly.

`baseosmgr` itself never reboots the device, never decides *when* to reboot,
and never decides whether the upgrade is "good enough". Those policy
decisions live in `nodeagent`. `baseosmgr` is the *mechanism* underneath:
mostly a wrapper around `pkg/pillar/zboot`, the `volumemgr`/content-tree
flow, and a tiny background `worker` pool that performs the actual `dd` of
the rootfs image into the partition device.

## Key Input/Output

**baseosmgr consumes** (all via pubsub unless noted):

* base os configuration
  * `BaseOsConfig` from `zedagent`, keyed on `ContentTreeUUID`
  * carries `BaseOsVersion`, `Activate`, `RetryUpdateCounter`. Empty
    `ContentTreeUUID` is rejected as a config error.
* content tree status
  * `ContentTreeStatus` from `volumemgr`
  * the download/load progress for the rootfs blob; baseosmgr will not
    even consider installing until `State == LOADED`.
* zboot config (the test-complete signal)
  * `ZbootConfig` from `nodeagent`, one entry per partition (`IMGA`,
    `IMGB`); only `TestComplete` is meaningful. When it flips to `true`
    for the *current* partition while that partition is `inprogress`,
    that is `nodeagent`'s "post-upgrade test passed, commit it" message.
* nodeagent status (last reboot reason)
  * `NodeAgentStatus` from `nodeagent`
  * baseosmgr only consumes `RebootReason` / `RebootTime` / `RebootImage`
    from the *previous* boot — used by `updateBaseOsStatusOnReboot` to
    surface the failure onto whichever `BaseOsStatus` owns the partition
    that we just rolled back from.
* zedagent status (force-fallback knob)
  * `ZedAgentStatus` from `zedagent`
  * baseosmgr only consumes `ForceFallbackCounter`. A bump (relative to
    the persistent file `/persist/checkpoint/forceFallbackCounter`)
    triggers `handleForceFallback` to flip the *unused* other partition
    to `updating`.
* node-drain status (kubevirt builds)
  * `kubeapi.NodeDrainStatus` from `zedkube`
  * gates the partition flip when EVE is running kubevirt; while a drain
    is in progress, baseosmgr stashes the deferred BaseOs uuid on the
    context and re-runs the status update on `COMPLETE`.
* global configuration
  * `ConfigItemValueMap` from `zedagent`; only used to set log level —
    baseosmgr has no behavior knobs of its own here.
* on-disk state (read at start)
  * `/persist/status/current_retry_update_counter` and
    `/persist/status/config_retry_update_counter` — last seen value of
    `RetryUpdateCounter` from a successful update, and from the most
    recent `BaseOsConfig`. Used to detect whether the controller bumped
    the counter relative to a known-good state.
  * `/persist/checkpoint/forceFallbackCounter` — last seen value of
    `ForceFallbackCounter`; baseline against incoming
    `ZedAgentStatus.ForceFallbackCounter`. Read lazily on the first
    `ZedAgentStatus`, not at startup.
* on-disk state (read indirectly via `zboot`)
  * GRUB env (`grubenv`) on the boot disk: partition states (`active`,
    `inprogress`, `unused`, `updating`), short/long version strings.
    baseosmgr publishes a pubsub mirror; most consumers read that mirror
    instead of GRUB (`nodeagent` additionally queries `zboot` directly at
    startup, before baseosmgr has published).
* startup gates (synchronous waits, not subscriptions)
  * `wait.WaitForOnboarded` (UUID known) — happens **before** any
    publication or subscription is set up,
  * `wait.WaitForVault` (vault unlocked) — `volumemgr` downloads EVE-OS
    images into `/persist/vault` and is therefore not operational until
    the vault is open,
  * `containerd.WaitForUserContainerd` (user containerd ready) — needed
    because the rootfs image lands as an OCI ref and the install worker
    has to be able to read blobs out of it.

**baseosmgr publishes**:

* `BaseOsStatus`, keyed on `ContentTreeUUID` (consumed by `zedagent`,
  forwarded to the controller)
  * `BaseOsVersion`, `Activated`, `TooEarly` (failed because previous was
    still in test), `PartitionLabel`/`PartitionState`/`PartitionDevice`,
    `State` (the `volumemgr`-style state from `INITIAL` through `INSTALLED`),
    and an `ErrorAndTime` block for failures.
* `ZbootStatus` per partition (`IMGA`, `IMGB`), keyed on `PartitionLabel`
  (consumed by `nodeagent` and `zedagent`)
  * `PartitionState` (the GRUB state), `CurrentPartition` (`true` for the
    one we booted from), `PartitionDevname` (e.g. `/dev/sda3`),
    `ShortVersion`/`LongVersion` (read out of the partition's
    `/etc/eve-release`), `TestComplete` (mirrors what we observed back
    from the on-disk env after acting on `ZbootConfig`).
* `BaseOSMgrStatus` with key `"global"`
  * just `CurrentRetryUpdateCounter` — the value of `RetryUpdateCounter`
    at the time of the last successful update commit. Consumed by
    `zedagent` so the controller can tell which retry attempt's outcome
    it is looking at.
* `NodeDrainRequest` with key `"global"` (kubevirt builds)
  * published when an upgrade has reached the partition-flip step but a
    drain is still required; consumed by `zedkube`.
* persistent files written under `/persist/`
  * `status/current_retry_update_counter`, `status/config_retry_update_counter`
    via `fileutils.WriteRename`,
  * `checkpoint/forceFallbackCounter` likewise.
* GRUB-env writes (via `zboot`, *not* via pubsub)
  * `SetOtherPartitionStateUpdating` (after a successful install, and on
    force-fallback / retry-update),
  * `SetOtherPartitionStateUnused` (when version inside the freshly-dd'd
    image does not match what we expected),
  * `MarkCurrentPartitionStateActive` (commit, on
    `ZbootConfig{TestComplete:true}` for the current partition).
  * The actual `dd` of the rootfs onto the partition device is
    `zboot.WriteToPartition`, called only from the install worker.

## Components

`baseosmgr` is one event loop in `Run()` plus a single-purpose background
worker pool. The logical responsibilities are partitioned across the source
files as follows.

### Lifecycle / pubsub wiring (`baseosmgr.go`)

`Run()` waits for onboarding, sets up the three publications
(`BaseOsStatus`, `ZbootStatus`, `BaseOSMgrStatus`), reads the persistent
retry counters, calls `updateAndPublishZbootStatusAll` to seed `ZbootStatus`
from `zboot`, then activates all subscriptions. The 25-second `stillRunning`
ticker is the only periodic work — the rest is pure event handling. The
event loop blocks on `subGlobalConfig`, `subBaseOsConfig`, `subZbootConfig`,
`subContentTreeStatus`, `subNodeAgentStatus`, `subZedAgentStatus`,
`subNodeDrainStatus`, `worker.MsgChan()`, and the watchdog ticker.

The same file contains the pubsub dispatch wrappers
(`handleBaseOsConfigCreate/Modify/Delete`, `handleZbootConfigCreate/Modify/Delete`,
`handleNodeAgentStatusCreate/Modify`, `handleGlobalConfigImpl`) and the trivial
publication helpers `initializeSelfPublishHandles`, `publishBaseOSMgrStatus`.

### BaseOs config processing (`handlebaseos.go`)

`baseOsHandleStatusUpdate` → `doBaseOsStatusUpdate` is the heart of the
agent. The decision tree, in order, is:

1. content-tree errors → propagate to `BaseOsStatus.Error`,
2. version already in `current` partition → mark `INSTALLED`/`Activated`,
3. version already in `other` partition (and `Activate=true`) → mark
   `DOWNLOADED`, fall through to overwrite anyway (ContentTree might
   have been re-downloaded),
4. EVE-k vs non-EVE-k personality switch → reject with an error,
5. `doBaseOsInstall`: `validatePartition` (refuse if other = `inprogress`
   with same version — that's the "previous attempt failed" case), then
   `checkBaseOsVolumeStatus` (returns *not done* until ContentTree is
   `LOADED`),
6. if `Activate=false` → `doBaseOsInactivate` (currently a no-op that
   just notes "flip will happen on reboot"),
7. `validateAndAssignPartition`: refuse if current = `inprogress` or
   other = `active` (we're still in the test window of a different
   upgrade); otherwise assign `PartitionLabel = otherPartName`,
8. `doBaseOsActivate`: size check (image vs partition), call
   `installDownloadedObjects` to schedule the `dd` worker, on worker
   completion call `checkInstalledVersion` (read `ShortVersion` back out
   of the freshly written partition); on a match call
   `zboot.SetOtherPartitionStateUpdating`, on a mismatch
   `zboot.SetOtherPartitionStateUnused`.

The `baseOsHandleStatusUpdateUUID` wrapper is what `volumemgr` and the
worker call back into; it adds the `shouldDeferForNodeDrain` check before
re-entering `baseOsHandleStatusUpdate`.

### Partition state mirror (`handlebaseos.go`)

`updateAndPublishZbootStatusAll`, `updateAndPublishZbootStatus`,
`createZbootStatus`, `getZbootStatus`, `publishZbootStatus` form the
pubsub mirror of the GRUB env. `baseOsGetActivationStatus` and
`baseOsSetPartitionInfoInStatus` propagate the published partition state
into individual `BaseOsStatus` entries. `getPartitionState` prefers the
published mirror but falls back to a live `zboot` read.

### Test-complete / commit (`handlebaseos.go`)

`handleZbootTestComplete` is the inbound side of nodeagent's
"test-passed" signal. When `ZbootConfig.TestComplete` flips to `true`
for the current partition (and that partition is in `inprogress`), it
calls `zboot.MarkCurrentPartitionStateActive`, mirrors the new state
into `ZbootStatus`, calls `updateAndPublishBaseOsStatusAll` so every
`BaseOsStatus` picks up the new `PartitionState`, then
`maybeRetryInstall` to kick anything that had been `TooEarly`.

### Reboot-reason surfacing (`handlebaseos.go`)

`updateBaseOsStatusOnReboot` runs on every `NodeAgentStatus` arrival.
If the *other* partition is `inprogress` (i.e. nodeagent rebooted us
back off a failed upgrade) and a `BaseOsStatus` matches that
partition's `ShortVersion`, `handleOtherPartRebootReason` copies the
previous boot's `RebootReason`/`RebootTime` onto the BaseOsStatus, so
the controller learns *why* the upgrade failed — typically `Fallback`
from a missed test window, or a kernel panic stack from the new image.

### Retry-update counter (`handlebaseos.go`)

`handleUpdateRetryCounter` is invoked from
`handleBaseOsConfigCreate/Modify` and from the tail of
`handleZbootTestComplete`. The branches are:

* current partition not `active` → ignore the counter (we're still
  testing something),
* `isImageInErrorState` (other partition is `inprogress` with a
  matching `BaseOsConfig.Activate=true`) and counter changed → save
  counter, re-arm the retry by calling
  `zboot.SetOtherPartitionStateUpdating` so the partition flip
  happens again on next reboot,
* otherwise → just save the counter and republish `BaseOSMgrStatus`.

### Force-fallback (`forcefallback.go`)

`handleForceFallback` is the inbound from `ZedAgentStatus`. On the
first read (file absent) it initializes
`/persist/checkpoint/forceFallbackCounter` and returns. When the
counter changes it checks the very narrow precondition (current is
`active`, other is `unused`, other has a non-empty `ShortVersion`);
only if that holds does it call `zboot.SetOtherPartitionStateUpdating`,
publish the `BaseOsStatus`, and then persist the new counter. If the
precondition is not met it returns without persisting. The precondition
is intentionally strict: this is a
"controller-driven roll-back to the previous image", not a generic
partition reshuffler.

### Content-tree dispatch (`handlevolumemgr.go`)

`handleContentTreeStatusImpl` looks up which `BaseOsStatus` is using
this content tree and calls `baseOsHandleStatusUpdateUUID` for each.
This is what walks the install state machine forward as
`volumemgr` advances the download.

### Install worker (`handledownload.go`, `worker.go`)

`installDownloadedObjects` / `installDownloadedObject` either submit
or pop a result from the worker pool. The worker (`installWorker`)
calls `zboot.WriteToPartition(log, ref, target)` — this is the actual
`dd if=<oci blob> of=/dev/sdX`. The result handler
`processInstallWorkResult` re-enters
`baseOsHandleStatusUpdateUUID`, where the `wres != nil` branch in
`installDownloadedObject` then returns `proceed=true`.

### Node-drain glue (`handlenodedrain.go`)

`shouldDeferForNodeDrain` is called from `baseOsHandleStatusUpdateUUID`
just before activation kicks in — i.e. before the install worker writes
the image and before `zboot.SetOtherPartitionStateUpdating` flips the
other partition state. It either returns `false` (non-kube build, drain
not required, or drain `COMPLETE`) or stashes
`ctx.deferredBaseOsID` and returns `true` (drain needed; will be
retried when `NodeDrainStatus.COMPLETE` arrives).
`handleNodeDrainStatusImpl` is the inbound side that picks the
deferred id back up.

## Control-flow

There are five largely independent control paths through baseosmgr.

### 1. Boot and onboarding

```text
Run()
  └─ wait.WaitForOnboarded()                 (block until we know our UUID)
  └─ initializeSelfPublishHandles            (BaseOsStatus, ZbootStatus, BaseOSMgrStatus)
  └─ readSavedCurrentRetryUpdateCounter
  └─ readSavedConfigRetryUpdateCounter
  └─ publishBaseOSMgrStatus                  (first publication)
  └─ initializeGlobalConfigHandles           (subscriptions activated immediately)
  └─ initializeNodeAgentHandles              (NodeAgentStatus, ZedAgentStatus, ZbootConfig)
  └─ initializeZedagentHandles               (BaseOsConfig)
  └─ initializeVolumemgrHandles              (ContentTreeStatus)
  └─ initializeNodeDrainHandles              (NodeDrainStatus, NodeDrainRequest)
  └─ updateAndPublishZbootStatusAll          (seed ZbootStatus from zboot+grubenv)
  └─ ctx.worker = worker.NewPool(... installWorker ...)
  └─ pubZbootStatus.SignalRestarted()        (lets nodeagent know seeding is done)
  └─ wait for GCInitialized
  └─ wait.WaitForVault()
  └─ containerd.WaitForUserContainerd()
  └─ event loop
```

`pubZbootStatus.SignalRestarted()` marks that baseosmgr has seeded the
`ZbootStatus` mirror for every partition, so subscribers can tell the
initial publication is complete. Note that `nodeagent` does *not* wait
for it to learn whether an update is in progress: at startup — before
baseosmgr is ready — it derives `updateInprogress` by calling
`zboot.IsCurrentPartitionStateInProgress()` directly, and only consumes
the `ZbootStatus` mirror afterwards.

### 2. New BaseOsConfig (controller-driven upgrade)

```text
zedagent → BaseOsConfig{ContentTreeUUID, BaseOsVersion, Activate=true}
  → handleBaseOsConfigCreate
    → validateBaseOsConfig
    → publishBaseOsStatus (empty, with version)
    → baseOsHandleStatusUpdate
      → baseOsGetActivationStatus
      → doBaseOsStatusUpdate
        ├─ same version in current?            → INSTALLED/Activated, return
        ├─ same version in other?              → DOWNLOADED, fall through
        ├─ EVE-k personality mismatch?         → error, return
        ├─ doBaseOsInstall
        │    ├─ validatePartition              (other=inprogress same ver? → fail)
        │    └─ checkBaseOsVolumeStatus        (waits for ContentTreeStatus.LOADED)
        ├─ Activate=false?                     → doBaseOsInactivate, return
        ├─ validateAndAssignPartition          (curr=inprogress|other=active? → TooEarly)
        └─ doBaseOsActivate
             ├─ check partition state ∈ {unused,inprogress,updating}
             ├─ check partition size ≥ image size
             ├─ installDownloadedObjects
             │    └─ AddWorkInstall (worker → zboot.WriteToPartition)
             ├─ wait for worker.MsgChan() result
             ├─ checkInstalledVersion          (read ShortVersion back; mismatch → unused)
             └─ zboot.SetOtherPartitionStateUpdating
    → handleUpdateRetryCounter
```

The corresponding pubsub side-effects out of this path are
`BaseOsStatus` republishes at every step (state, error, partition
fields, `Activated` once the worker finishes) and a `ZbootStatus`
republish when the partition state flips to `updating`.

### 3. Volume / content-tree progress

```text
volumemgr → ContentTreeStatus(state advances DOWNLOADING→VERIFIED→LOADED)
  → handleContentTreeStatusImpl
    → lookupBaseOsStatusesByContentID
    → for each: baseOsHandleStatusUpdateUUID
        ├─ if content LOADED and we're about to flip:
        │    shouldDeferForNodeDrain          (kube → stash deferredBaseOsID, return)
        └─ baseOsHandleStatusUpdate           (re-enter doBaseOsStatusUpdate)
```

This is what walks the install state machine forward. While
`MinState < LOADED`, `checkBaseOsVolumeStatus` returns `done=false`
and the install path no-ops; once `LOADED` arrives — and we're
about to actually switch to it — `baseOsHandleStatusUpdateUUID`
is also where the kubevirt drain gate fires, before
`doBaseOsActivate` runs. The same wrapper is re-entered on
worker completion (`processInstallWorkResult`) and on drain
completion (`handleNodeDrainStatusImpl`).

### 4. Test-complete / commit

```text
nodeagent → ZbootConfig{IMG?: TestComplete=true}
  → handleZbootConfigImpl
    → handleZbootTestComplete
      ├─ Key() must be currentPart, currentPart must be inprogress
      ├─ zboot.MarkCurrentPartitionStateActive
      ├─ publishZbootStatus(curr: TestComplete=true)
      ├─ updateAndPublishZbootStatusAll       (re-read all partition states)
      ├─ updateAndPublishBaseOsStatusAll      (propagate into every BaseOsStatus)
      ├─ maybeRetryInstall                    (kick anything previously TooEarly)
      └─ handleUpdateRetryCounter             (sync currentUpdateRetry → save)
```

If `MarkCurrentPartitionStateActive` itself fails (rare —
disk-write failure on the boot disk), the BaseOsStatus picks up the
error and the partition is left in `inprogress`; on the next boot
nodeagent will hit the fallback path again.

### 5. Reboot-after-failed-update

```text
nodeagent → NodeAgentStatus{RebootReason, RebootImage, RebootTime}
  → handleNodeAgentStatusImpl
    → ctx.rebootReason / rebootTime / rebootImage = ...
    → updateBaseOsStatusOnReboot
      ├─ otherPart in inprogress?
      ├─ matching BaseOsStatus by partLabel + ShortVersion?
      └─ handleOtherPartRebootReason
           ├─ if rebootImage == currentPart → no-op (we booted *this* image, no rollback)
           └─ status.SetError(rebootReason, rebootTime)   // surface the failure
```

Validation that the failure happened on the *other* image (rather
than the current one) is what the `rebootImage == curPart` early
return handles.

### 6. Side channels

* **Force-fallback** (`forcefallback.go`): bumping
  `ZedAgentStatus.ForceFallbackCounter` while curr=active and
  other=unused is the controller's "switch back to the previous
  image" knob. baseosmgr writes the new counter to
  `/persist/checkpoint/forceFallbackCounter` and flips the other
  partition to `updating`; nodeagent then reboots us into it.
* **Retry-update** (`handlebaseos.go`): bumping
  `BaseOsConfig.RetryUpdateCounter` while curr=active and
  other=inprogress with a matching `BaseOsConfig.Activate=true` is
  the controller's "try the failed image again" knob. baseosmgr
  saves the counter to
  `/persist/status/config_retry_update_counter` and flips the
  other partition to `updating`.

## Debugging

### PubSub

On a running device:

```sh
# What the controller asked for
ls /run/zedagent/BaseOsConfig/
cat /run/zedagent/BaseOsConfig/<uuid>.json | jq

# What baseosmgr is doing about it
ls /run/baseosmgr/BaseOsStatus/
cat /run/baseosmgr/BaseOsStatus/<uuid>.json | jq

# The mirror of the GRUB env (consumed by nodeagent + zedagent)
cat /run/baseosmgr/ZbootStatus/IMGA.json | jq
cat /run/baseosmgr/ZbootStatus/IMGB.json | jq

# nodeagent's commit signal back to baseosmgr
cat /run/nodeagent/ZbootConfig/IMGA.json | jq
cat /run/nodeagent/ZbootConfig/IMGB.json | jq

# The retry counter snapshot
cat /run/baseosmgr/BaseOSMgrStatus/global.json | jq
```

A healthy idle device has `IMGx.PartitionState=active` for the current
partition, `IMGy.PartitionState=unused` for the other, and
`BaseOsStatus.Activated=true` for whichever uuid matches the
`active` partition's `ShortVersion`. During an upgrade the other
partition transitions `unused → updating → inprogress → active`.

Persistent files of interest under `/persist/`:

* `status/current_retry_update_counter` — last counter that succeeded
* `status/config_retry_update_counter` — last counter we acknowledged
  from `BaseOsConfig`
* `checkpoint/forceFallbackCounter` — last counter we acknowledged
  from `ZedAgentStatus`

### Logs

Useful `grep` patterns:

```text
"doBaseOsStatusUpdate"                  – top-level state-machine entry, prints the BaseOsConfig
"validatePartition"                     – early reject (other=inprogress same version)
"validateAndAssignPartition"            – partition assignment / TooEarly path
"Image size .* greater than partition"  – size precheck failure
"installWorker to install"              – the actual dd starting
"installWorker DONE install"            – the dd finished
"Mark other partition .* unused"        – version-mismatch rollback after install
"checkInstalledVersion"                 – reading version back out of the partition
"handleZbootTestComplete"               – commit path entry
"Mark the current partition .* active"  – commit succeeded
"Handle ForceFallbackCounter update"    – force-fallback knob bumped
"ForceFallback from .* to"              – force-fallback actually firing
"handleUpdateRetryCounter"              – retry-counter machinery
"UpdateRetry from .* to"                – retry-counter actually firing
"shouldDeferForNodeDrain"               – kubevirt drain gate
"nodedrain-step:"                       – kubevirt drain glue
```

### Forcing transitions for development

* The normal upgrade path is exercised by
  `eden controller edge-node eveimage-update file://<rootfs>.squashfs`,
  which makes `zedagent` publish a `BaseOsConfig{Activate:true}`.
  See `tests/update_eve_image/testdata/update_eve_image_http.txt`.
* To exercise the *post-test commit* path quickly, set
  `timer.test.baseimage.update=30` so nodeagent's test window is 30s
  rather than the default 600s.
* To exercise the *fallback* (rollback) path, see the eden tests
  under `tests/nodeagent/testdata/baseos_fallback_*.txt`: they cut
  controller reachability during the test window so nodeagent
  reboots back to the previous image.
* To exercise the *retry-update* path, install a known-bad image
  (so the test window times out and the partition lands in
  `inprogress`), then bump `RetryUpdateCounter` in `BaseOsConfig`.
* To exercise *force-fallback*, after a successful upgrade so the
  other partition is `unused` with a previous version, bump
  `ForceFallbackCounter` in the controller.
