# Upgrade Converter

The upgrade converter (`upgradeconverter`) is a one-shot migration step
that runs early in every EVE-OS boot. Its job is to bring the on-disk
layout under `/persist` up to date with what the currently running EVE
version expects. Over time EVE has moved directories around, renamed
files, and changed the type/format of some persisted pubsub state. When
a device upgrades from an older release, its `/persist` partition still
holds data in the old layout; the upgrade converter detects the old
layout and migrates it to the new one so the rest of pillar finds its
state where it expects it.

It is not a long-running agent. Each handler runs once per boot, does
its migration (or finds nothing to do), and the process exits. Handlers
are written to be idempotent and safe to run on a device that is already
in the new layout — on a first boot, or on a device that has already
been converted, they simply find nothing to migrate.

## Why there are two phases

EVE encrypts sensitive data at rest under `/persist/vault`
(`types.SealedDirName`), which `vaultmgr` sets up and unlocks using a
key released by the TPM. The vault is not available for most of early
boot: it has to be unlocked before anything can read or write files
under it. This splits the conversions into two groups:

- **pre-vault** — conversions that touch only unencrypted locations
  (e.g. `/persist/status/...` or pubsub state outside the vault). These
  can and must run early, before the vault exists.
- **post-vault** — conversions that read from or write to
  `/persist/vault`. These cannot run until `vaultmgr` has unlocked the
  vault, so they are deferred until after vault setup completes.

The dividing rule is encoded directly in the handler lists in
`upgradeconverter.go`: any handler that interacts with
`types.SealedDirName` belongs in `postVaultconversionHandlers`;
everything else belongs in `preVaultconversionHandlers`.

## How each phase is invoked

The two phases are started from two different places in the boot flow,
and the converter selects which set of handlers to run based on a phase
argument/parameter.

### pre-vault

`pkg/pillar/scripts/onboot.sh` runs the converter synchronously, as a
binary, before the vault-using services come up:

```sh
$BINDIR/upgradeconverter pre-vault
```

`upgradeconverter` is one of the applets dispatched by `zedbox`
(registered as `inlineAlways`), so this invokes `upgradeconverter.Run`,
which parses the `pre-vault` argument and runs `preVaultconversionHandlers`.
Because `onboot.sh` blocks on it, the pre-vault migrations are guaranteed
complete before later boot stages start.

### post-vault

The post-vault phase is **not** run as a separate binary. Instead,
`vaultmgr` invokes it in-process, once it has unlocked the default vault
(or immediately, on non-TPM platforms where there is no key to wait
for). `vaultmgr` calls `upgradeconverter.RunPostVaultHandlers` in a
goroutine and waits for completion on a channel:

```go
log.Notice("Starting upgradeconverter(post-vault)")
go uc.RunPostVaultHandlers(agentName, ps, logger, log,
        ctx.CLIParams().DebugOverride, ctx.ucChan)
```

Running it inside `vaultmgr` (rather than as a child process) lets
`vaultmgr` keep its watchdog alive: it spawns the work as a task and
`select`s on the completion channel, then re-publishes vault status once
the conversion is done. This is why the converter exposes
`RunPostVaultHandlers` as a library entry point in addition to the
binary `Run` path.

> Note: `upgradeconverter.go` also defines a symmetric
> `RunPreVaultHandlers` library helper, but it currently has no caller —
> the pre-vault phase is driven entirely through the `Run` binary path
> from `onboot.sh`.

### Invocation summary

| Phase | Trigger | Entry point | Handler set | Runs when |
|-------|---------|-------------|-------------|-----------|
| pre-vault | `onboot.sh`: `upgradeconverter pre-vault` | `Run` → `runPhase(UCPhasePreVault)` | `preVaultconversionHandlers` | Early boot, before vault setup; blocks boot until done |
| post-vault | `vaultmgr` goroutine | `RunPostVaultHandlers` → `runPhase(UCPhasePostVault)` | `postVaultconversionHandlers` | After the default vault is unlocked (or immediately on non-TPM) |

`-p <dir>` overrides the persist directory (used by tests), and `-n`
(the "noFlag" dry-run) makes the file-moving handlers log what they
*would* do without modifying the filesystem.

## Conversion handlers

Each handler is a `ConversionHandler` (a description plus a function).
`runHandlers` iterates the phase's list, logging each handler and
continuing past a handler that returns an error (errors are logged, not
fatal — one failed migration must not block the rest of boot).

### pre-vault handlers

**Move `UUIDPairToNum` to `AppInterfaceToNum`** (`convertUUIDPairToNum`)
— Migrates `zedrouter`'s persistent number-allocator state. The older
`UUIDPairToNum` keyed an allocated number by `(BaseID, AppID)`; the
newer `types.AppInterfaceToNum` keys by `(NetInstID, AppID, IfIdx)` so
that an app with multiple interfaces on the same network can get
distinct numbers. The handler reads the old persistent publication,
re-publishes each entry as an `AppInterfaceToNum` (with `IfIdx = 0`),
and unpublishes the old entries. Operates on pubsub state, not files.

**Move `/status/zedrouter/AppInstMetaData` to `/status/msrv/AppInstMetaData`**
(`movePersistPubsub`) — When app-instance metadata ownership moved from
`zedrouter` to the metadata server (`msrv`), the persisted pubsub
directory had to move with it. Copies
`/persist/status/zedrouter/AppInstMetaData` to
`/persist/status/msrv/AppInstMetaData` if the source exists and the
destination does not.

### post-vault handlers

**Move volumes to `/persist/vault`** (`convertPersistVolumes`) — The
largest migration. Older EVE stored app volumes in `/persist/img`
(VM/raw/qcow2) and `/persist/runx/pods/prepared` (OCI/container)
under filenames encoding `appInstanceID + sha256 + purgeCounter`. The
volume model later changed to volume-ID-keyed files under
`/persist/vault/volumes` (`volumeID#generationCounter.format`). To map
old names to new ones it parses the checkpointed controller config at
`/persist/checkpoint/lastconfig` (the saved `EdgeDevConfig` protobuf),
building the relationship between app instances, their drives, content
trees, and volume references, and uses the persisted `zedmanager` latch
(`AppAndImageToHash`) to recover the sha for OCI volumes. It then moves
each old volume to its new path. If the checkpoint file is absent
(always the case on a first boot) there is nothing to convert and the
handler returns early.

**Move verified files to `/persist/vault/verifier/verified`**
(`renameVerifiedFiles`) — Moves downloaded-and-verified images from the
old unencrypted `/persist/downloads/<objType>/verified/<UPPERCASE-SHA>/<file>`
layout into the vault at `/persist/vault/verifier/verified/<lowercase-sha>`,
flattening the per-sha subdirectory and lowercasing the sha.

**Move old files to user containerd** (`moveToUserContainerd`) — Moves
`/persist/containerd` to `/persist/vault/containerd` so the
content-store lives inside the encrypted vault.

## Design points that matter for correctness and testing

- **Checkpoint dependency.** `convertPersistVolumes` cannot map old
  volume names to new ones without `/persist/checkpoint/lastconfig`. A
  device that never received a config (true first boot) has no
  checkpoint and the handler is a no-op — this is expected, not an
  error condition for the device, even though it logs an error.

- **Copy-not-rename across the vault boundary.** Files cannot be
  `rename(2)`'d into the fscrypt-encrypted vault, so the file handlers
  copy then delete. `copyRenameDelete` copies to a `.tmp` name, does an
  atomic `rename` to the final name within the vault, then removes the
  source — so a crash mid-migration never leaves a half-written file at
  the destination name. For directories (containers),
  `convertPersistVolumes` uses `CopyDir` + `RemoveAll` and records the
  old snapshot basename via `containerd.SaveSnapshotID`.

- **Downgrade/re-upgrade handling.** `maybeMove` will not overwrite a
  destination file that is *newer* than the source. The reasoning: if a
  device was downgraded to old code (which recreated the old
  directories) and then upgraded again, the file already in the new
  location is the one to trust; a newer mtime on a raw/qcow2 image means
  the app modified it while booted in the downgraded state.

- **Dry-run.** The `-n` flag (`noFlag`) makes the moving handlers log
  the intended operation without touching the filesystem — useful for
  inspecting what a real device would migrate.

- **Idempotency.** Every handler tolerates being run when the new layout
  already exists (destination present → skip, source absent → skip), so
  re-running a phase is safe.

## EVE-OS version history (for removal planning)

A conversion handler exists only to migrate devices coming from a
release that used the *old* layout. Once EVE no longer supports a direct
upgrade from any release older than the one that introduced a given new
layout, that handler is dead weight and can be removed. The table below
records the first stable EVE-OS release that shipped each conversion
(i.e. the release that introduced the corresponding new layout); these
were determined from the introducing commit via `git tag --contains`.

| Handler | Phase | Migration | Introducing commit | First stable release |
|---------|-------|-----------|--------------------|----------------------|
| `convertPersistVolumes` | post-vault | `/persist/img`, `/persist/runx/pods/prepared` → `/persist/vault/volumes` | `7251c9ba5` (2020-06-18) | 5.7.0 |
| `renameVerifiedFiles` | post-vault | `/persist/downloads/*/verified/<SHA>/` → `/persist/vault/verifier/verified/<sha>` | `ed43f40a7` (2020-07-08) | 5.7.1 |
| `convertUUIDPairToNum` | pre-vault | `UUIDPairToNum` → `AppInterfaceToNum` (zedrouter persisted pubsub) | `feaf11dfe` (2022-01-12) | 7.7.0 |
| `moveToUserContainerd` | post-vault | `/persist/containerd` → `/persist/vault/containerd` | `c2428a33c` (2022-02-21) | 7.11.0 |
| `movePersistPubsub` | pre-vault | `/persist/status/zedrouter/AppInstMetaData` → `/persist/status/msrv/AppInstMetaData` | `8a86e93e8` (2024-06-27) | 12.5.0 |

**Removal rule of thumb:** a handler is safe to delete once the oldest
release a device is allowed to upgrade *from* is at least the "first
stable release" listed above — at that point every device already has
the new layout and the handler can only ever be a no-op. The two oldest
conversions (the 5.7.x volume and verified-file moves) are the first
candidates to retire; `movePersistPubsub` (12.5.0) is the youngest and
must be kept the longest. The actual cutoff is a project policy decision
about the minimum supported upgrade-from version.

(`types.PersistConfigDir` = `/persist/config` and
`types.OldGlobalConfig` carry similar "remove once upgradeconverter code
is removed" markers, so retiring conversions should be coordinated with
cleanup of the legacy types they read.)

## Input for building test cases

This section is meant only as input for designing tests; a full test
plan is a separate document. The functionality to exercise, per handler:

- **Pre-condition fixtures.** Each handler is driven by the presence of
  an old-layout artifact under a configurable persist root (the `-p`
  flag and the `ucContext` path fields exist precisely so tests can
  point at a temp directory — see `upgradeconverter_test.go`). A test
  case constructs the old layout, runs the phase, and asserts the new
  layout.

- **`convertPersistVolumes`** is the richest to test: it needs a
  `/persist/checkpoint/lastconfig` protobuf with apps/drives/volumes/
  content-trees that resolve, plus old volume files in `/persist/img`
  and `/persist/runx/pods/prepared`. Cases worth covering: VM vs OCI
  volumes; volumes with and without a purge counter; sha recovered from
  the latch vs from the content tree; missing checkpoint (no-op);
  destination already newer than source (downgrade case — must not
  overwrite); name that fails to parse (ignored).

- **`renameVerifiedFiles`**: uppercase→lowercase sha, flattening the
  per-sha directory, both `appImg` and `baseOs` object types, and the
  "destination already exists → skip" path.

- **`movePersistPubsub`** and **`convertUUIDPairToNum`** are
  state-shape migrations: seed the old location/type, assert the new
  location/type and that the old entries are removed; assert the no-op
  when only the new form is present.

- **Cross-cutting:** idempotency (run twice, second run is a no-op),
  dry-run (`-n` makes no filesystem changes), and graceful handling of a
  handler error not aborting the rest of the phase.
