# Vault Manager

## Overview

`vaultmgr` is the EVE microservice responsible for **data-at-rest
encryption**: it owns the on-disk *vault* at `/persist/vault`, the key
that unlocks it, and the `VaultStatus` publication that gates pillar
startup. Its main jobs are:

* **set up** the vault on first boot and **unlock** it on every
  subsequent boot — using `fscrypt` over ext4 (AES-256-XTS for file
  contents, AES-256-CTS for filenames, policy v2; see
  [`pkg/pillar/rootfs/fscrypt.conf`](../rootfs/fscrypt.conf)) or
  native ZFS encryption (`-o encryption=aes-256-gcm`), depending on
  the persist filesystem,
* **derive the vault key** from the TPM, sealed under PCRs
  (`TpmKeyOnly=true` — the only path used on devices installed at EVE
  ≥ 7.10.0; older modes survive as forward-compat carry-over and are
  documented in [Appendix: legacy key-derivation modes](#appendix-legacy-key-derivation-modes)),
* **publish the device-wrapped vault key**
  (`EncryptedVaultKeyFromDevice`) to the controller via `zedagent` so
  it can be returned after an upgrade has changed the PCRs,
* **accept the rescued key from the controller**
  (`EncryptedVaultKeyFromController`), unwrap it via
  `etpm.EncryptDecryptUsingTpm` (an AES key derived in-TPM from the
  ECDH private key and the device certificate; see [evetpm.md →
  Encrypt / decrypt](../evetpm/evetpm.md#encrypt--decrypt)), re-seal
  it under the *current* PCRs, and unlock the vault — this is the
  path that keeps a device upgradable across PCR changes,
* **wipe and recreate** the vault when the controller has no key for
  it and the installer-dropped sentinel `/persist/status/allow-vault-clean`
  is present,
* **run the post-vault `upgradeconverter`** exactly once after the
  vault opens, then republish each `VaultStatus` with
  `ConversionComplete=true` (which is what every `wait.WaitForVault`
  caller actually blocks on),
* **report data-at-rest health** as `VaultStatus.Status` in the
  `info.DataSecAtRestStatus` enum (`DISABLED` / `ENABLED` / `ERROR`),
  attaching the list of mismatching PCRs when seal/unseal fails so the
  controller can decide whether to re-issue the key.

A *vault* in EVE is a directory (or, on ZFS, a dataset) whose
contents are stored encrypted at rest. Today there is exactly one
vault that matters in steady state — `"Application Data Store"` at
`/persist/vault`, holding app instance volumes, downloader/verifier
caches, containerd state, OVMF NVRAM, and similar — plus a couple of
deprecated vaults retained for upgrade compatibility from EVE
< 5.6.2.

`vaultmgr` itself is a thin orchestrator. The fscrypt and ZFS
mechanics live in [`pkg/pillar/vault`](vault.md); the TPM
primitives (seal/unseal, `EncryptDecryptUsingTpm`, PCR-policy
bookkeeping) live in [`pkg/pillar/evetpm`](../evetpm/evetpm.md).
`vaultmgr` decides *when* to unlock, recreate, or rescue, and which
key-derivation mode applies. The ext4 path drives Google's
[`fscrypt`](https://github.com/google/fscrypt) (shipped at
`/opt/zededa/bin/fscrypt`); the ZFS path uses native dataset
encryption.

## Key Input/Output

**vaultmgr consumes** (via pubsub unless noted):

* global configuration
  * `ConfigItemValueMap` from `zedagent` — only used for log levels;
    `vaultmgr` does not look at any other config item.
* controller-supplied vault key
  * `EncryptedVaultKeyFromController` from `zedagent` (forwarded from
    the controller after attestation), keyed on vault name. Carries:
    * `EncryptedVaultKey` — opaque protobuf `AttestVolumeKeyData`
      whose `EncryptedKey` field is the device's own `EncryptedVaultKeyFromDevice`
      payload returned by the controller verbatim — i.e. an AES-CFB
      blob that only this device can decrypt via
      `etpm.EncryptDecryptUsingTpm` (see [evetpm.md →
      Encrypt / decrypt](../evetpm/evetpm.md#encrypt--decrypt)),
    * `PolicyPcr` — optional PCR selection the controller wants used
      for re-sealing the rescued key. `PolicyPresent=false` means
      "use the default PCR set" (`evetpm.DefaultDiskKeySealingPCRs`).
    * Empty `EncryptedVaultKey` is the controller's signal "I have no
      key for you" — interpreted as a request to recreate the vault
      (only honored when the cleanup sentinel is present).
* on-disk
  * filesystem type — `persist.ReadPersistType()` returns `PersistExt4`,
    `PersistZFS`, or unsupported. Picks the handler at startup.
  * `/persist/vault` (ext4) or the `persist/vault` ZFS dataset — the
    vault itself.
  * `/persist/status/allow-vault-clean` — sentinel dropped by the
    installer / `storage-init`; presence means "if controller has no
    key, wipe & recreate". `vault.DisallowVaultCleanup()` removes it
    once the device is past first boot.
  * `/persist/status/policy-pcr.json` — the controller's last
    advertised PCR selection for the disk-key seal policy. Read by
    `evetpm.GetDiskKeyPolicyPcrOrDefault` when re-sealing.
  * TPM (via `evetpm`) — the sealed disk-key blob (NV indices
    `0x1800000` / `0x1900000`), the TPM ECDH key (`TpmEcdhKeyHdl =
    0x81000005`) used by `EncryptDecryptUsingTpm`, and the PCR bank
    state. The on-TPM data layout is canonically described in
    [evetpm.md → On-TPM Data Layout](../evetpm/evetpm.md#on-tpm-data-layout).
* self
  * `VaultConfig` (persistent self-publication) — only consulted on
    first vault setup (see `checkAndPublishVaultConfig`); see
    [Appendix](#appendix-legacy-key-derivation-modes) for the legacy
    `TpmKeyOnly=false` carry-over.

**vaultmgr publishes**:

* `VaultStatus` (one per known vault — currently just
  `"Application Data Store"`, plus the deprecated
  `"Configuration Data Store"` if it still exists on ext4)
  * `Status` — the `DataSecAtRestStatus` enum,
  * `PCRStatus` — `PCR_ENABLED` if the SHA256 PCR bank is present,
  * `ConversionComplete` — set to `true` only after
    `upgradeconverter`'s post-vault phase has finished. Every
    `wait.WaitForVault` caller blocks until this is true,
  * `MismatchingPCRs` — populated when seal/unseal fails so the
    controller can correlate the failure with a known PCR change,
  * `ErrorAndTime` — error string when status is `ERROR`.
* `EncryptedVaultKeyFromDevice` (consumed by `zedagent`, forwarded to
  the controller)
  * `EncryptedVaultKey` — empty if no TPM; otherwise the protobuf
    `AttestVolumeKeyData` (encrypted-key + sha256 digest), where the
    encrypted-key bytes are `etpm.EncryptDecryptUsingTpm(rawKey,
    encrypt=true)`. The wrap is purely device-side and is symmetric:
    only this device's TPM ECDH key + device cert can produce or
    reverse it.
  * `IsTpmEnabled` — lets the controller know whether to even bother
    storing a copy.
* `VaultConfig` — internal, persistent. Records the key-derivation
  mode for the vault and is sticky once written. See
  [Appendix](#appendix-legacy-key-derivation-modes).

## Components

`vaultmgr` is a single `vaultMgrContext` event loop in
`cmd/vaultmgr/vaultmgr.go`, plus a filesystem-handler abstraction and
a key-derivation helper under `pkg/pillar/vault/`, and TPM glue under
`pkg/pillar/evetpm/`.

### Lifecycle / pubsub wiring (`cmd/vaultmgr/vaultmgr.go`)

`Run()` does the standard agentbase init, blocks on
`wait.WaitForOnboarded()`, subscribes `ConfigItemValueMap` and
`EncryptedVaultKeyFromController`, blocks on `GCInitialized`, and
*then* picks the filesystem handler with `vault.GetHandler(log)`.

`checkAndPublishVaultConfig()` runs next, recording the
key-derivation mode for this vault into the persistent `VaultConfig`
self-publication; see
[Appendix](#appendix-legacy-key-derivation-modes) for the legacy
branch.

Then `handler.SetupDefaultVault()` is called. If it returns an error,
`vaultmgr` publishes the failing `VaultStatus` and waits for the
controller to push back a key. If it succeeds, `defaultVaultUnlocked`
is set and `uc.RunPostVaultHandlers` is fired off in a goroutine; the
event loop publishes a final `VaultStatus` with `ConversionComplete`
when that goroutine signals `ucChan`.

### Single-shot CLI (`runCommand`)

Two subcommands:

* `vaultmgr setupDeprecatedVaults` — invoked from `onboot.sh`, runs
  the ext4 handler's deprecated-vault path (the `/persist/img` and
  `/persist/config` legacy vaults from < 5.6.2). On ZFS this is a
  no-op.
* `vaultmgr waitUnsealed` — exits 0 once `wait.WaitForVault` sees a
  healthy `VaultStatus` for `"Application Data Store"` with
  `ConversionComplete=true`. Other agents that need the vault use
  the `wait` helper directly; `waitUnsealed` is the equivalent for
  shell scripts.

### Controller-rescue path (`handleVaultKeyFromControllerImpl`)

The agent's most consequential branch. On every
`EncryptedVaultKeyFromController` for the default vault:

1. **Skip** if no TPM is enabled (a non-TPM device cannot consume the
   wrapped key).
2. **Unwrap** `EncryptedVaultKey` with `etpm.EncryptDecryptUsingTpm`
   (the same device-bound AES-CFB wrap used outbound; see [evetpm.md
   → Encrypt / decrypt](../evetpm/evetpm.md#encrypt--decrypt)) and
   check the sha256 digest matches the one the controller co-signed.
3. **Validate and persist policy-PCR**. If the controller supplied a
   `PolicyPcr` block, `etpm.ValidatePolicyPcr` checks it; if valid,
   `etpm.SaveDiskKeyPolicyPcr` writes it to
   `/persist/status/policy-pcr.json`. The return flag
   `policyChanged=true` means the next seal must use the new PCR set.
4. **Re-seal** the freshly unwrapped key under
   `etpm.GetDiskKeyPolicyPcrOrDefault(...)` if either the policy
   changed, or the vault has not yet been unlocked locally.
5. **Unlock** via `handler.UnlockDefaultVault()`. This is the case
   where local seal/unseal had failed earlier (typically: PCRs
   changed across a baseos upgrade) and the controller is rescuing us.
6. **Empty-key recovery branch** — if `EncryptedVaultKey` is empty:
   * if the vault is already unlocked, ignore;
   * else if `vault.IsVaultCleanupAllowed()` (i.e.
     `/persist/status/allow-vault-clean` exists), call
     `handler.RemoveDefaultVault()` followed by `SetupDefaultVault()`
     to wipe and recreate. The new key is locally generated and
     sealed.
7. **Re-publish** `EncryptedVaultKeyFromDevice` (so the controller
   sees the new device-wrapped key if there is one) and re-launch
   `uc.RunPostVaultHandlers` so the upgrade-converter runs against
   the freshly opened vault. The main loop's `ucChan` case will then
   re-publish all `VaultStatus` records with `ConversionComplete=true`.

### Filesystem handler abstraction (`pkg/pillar/vault/handler.go`)

```go
type Handler interface {
    RemoveDefaultVault() error
    UnlockDefaultVault() error
    SetupDeprecatedVaults() error
    SetupDefaultVault() error
    GetVaultStatuses() []*types.VaultStatus
    SetHandlerOptions(HandlerOptions)
    GetOperationalInfo() (info.DataSecAtRestStatus, string)
}
```

`GetHandler` dispatches on `persist.ReadPersistType()`:
`PersistExt4 → Ext4Handler`, `PersistZFS → ZFSHandler`, anything else
→ `UnsupportedHandler` (always returns `DATASEC_AT_REST_DISABLED`).
`HandlerOptions{TpmKeyOnlyMode}` is set on the handler from
`vaultmgr.Run()` after the persistent `VaultConfig` decision.

### Ext4 handler (`pkg/pillar/vault/handler_ext4.go`)

Wraps `/opt/zededa/bin/fscrypt`. Key user-visible behaviors:

* **First use** of `/persist`: `fscrypt setup /persist --quiet`.
* **Vault create**: `fscrypt encrypt /persist/vault --source raw_key
  --name TheVaultKeyvault --user root` — the protector key comes
  from a tmpfs file at `/TmpVaultDir2/protector.key`, populated by
  `stageKey()` and `shred --remove`'d on unstage.
* **Vault unlock**: `fscrypt unlock /persist/vault`, then
  `keyctl link @u @s` to expose the policy key in the session
  keyring.
* **Deprecated vaults** `/persist/img` and the historical
  `"Configuration Data Store"` at `/persist/config` are *only*
  unlocked, never created. If they were locked with the cloud-only
  pre-5.6.2 protector, `changeProtector()` migrates them to a
  TPM-derived raw-key protector by staging the old key in
  `/TmpVaultDir1` and the new in `/TmpVaultDir2` and running
  `fscrypt metadata change-passphrase`.
* **Status**: `getVaultStatus` parses `fscrypt status /persist/vault`
  for `Unlocked: Yes`. Failures fall through to a few special-cases
  (no SHA256 PCR bank → `DISABLED`; non-empty unencrypted dir →
  `DISABLED`) before settling on `ERROR` and attaching
  `etpm.FindMismatchingPCRs()`.

### ZFS handler (`pkg/pillar/vault/handler_zfs.go`)

Uses native ZFS encryption. Key paths:

* **Vault create**: `zfs.CreateVaultDataset(persist/vault,
  /run/TmpVaultDir2/protector.key)` →
  `zfs create -o encryption=aes-256-gcm -o keyformat=raw
  -o keylocation=file://… persist/vault`.
* **Vault unlock**: `zfs load-key persist/vault` followed by
  `zfs.MountDataset(persist/vault)`.
* **Kubevirt build** (`base.IsHVTypeKube()`): also creates and
  manages a separate `persist/etcd-storage` zvol via
  `CreateZvolEtcd`, and exposes the vault as an ext4-formatted zvol
  via `CreateZvolVault` + `MountVaultZvol`. The zvol mount uses
  `MS_DIRSYNC|MS_NOATIME` unless the kernel cmdline carries
  `eve_no_dirsync`, which is set when EVE itself runs as a VM (to
  avoid the I/O penalty of nested DIRSYNC).
* **No-TPM ZFS** is supported: a plain unencrypted dataset (or zvol
  on kube) is created instead — `Status` becomes
  `DATASEC_AT_REST_DISABLED`.
* **Status**: `checkOperationalStatus` requires `mounted=yes`,
  `keystatus=available`, `encryption=aes-256-gcm`. Anything else →
  `ERROR` with `MismatchingPCRs` attached when PCR-SHA256 is enabled.

### Key derivation (`pkg/pillar/vault/key.go`)

`stageKey` mounts a tmpfs at the chosen directory, calls
`deriveVaultKey` to produce 32 bytes of key material, writes them to
the on-tmpfs key file for `fscrypt` / `zfs load-key` to consume, and
returns an unstage closure that `shred`s the file and unmounts the
tmpfs. On every device installed at EVE ≥ 7.10.0,
`deriveVaultKey` simply returns `etpm.FetchSealedVaultKey(log)` — a
PCR-policy unseal of the blob in NV indices `0x1800000` / `0x1900000`.
The legacy "merged" and "cloud-only" branches are described in
[Appendix: legacy key-derivation modes](#appendix-legacy-key-derivation-modes).

### TPM glue (uses `pkg/pillar/evetpm`)

`vaultmgr` is the principal consumer of `evetpm`; the full API surface
is documented in [evetpm.md](../evetpm/evetpm.md#public-api-surface).
The entry points `vaultmgr` calls and the role each one plays:

| Function | Role in `vaultmgr` |
|---|---|
| `IsTpmEnabled` | Gates the TPM-rooted code paths. Returns true iff `/config/device.cert.pem` exists and `/config/device.key.pem` does not (i.e. provisioning landed on the TPM path). |
| `FetchSealedVaultKey` / `SealDiskKey` | Unseal and re-seal the 32-byte vault key under a `tpm2.PCRSelection`. `FetchSealedVaultKey` calls `UnsealDiskKeyWithRecovery` internally, which transparently brute-forces a working PCR subset if the saved selection no longer matches. Measurement logs (`/persist/status/tpm_measurement_seal_success`, `…unseal_fail`) are updated for `FindMismatchingPCRs` to diff. |
| `EncryptDecryptUsingTpm(buf, encrypt)` | Device-bound AES-CFB wrap/unwrap of the rescued and published vault key. The AES key is derived in hardware via `ECDHZGen(TpmEcdhKeyHdl=0x81000005, deviceCertPubKey)` → SHA-256 — see [evetpm.md → Encrypt / decrypt](../evetpm/evetpm.md#encrypt--decrypt). |
| `GetDiskKeyPolicyPcrOrDefault` / `ValidatePolicyPcr` / `SaveDiskKeyPolicyPcr` | Read, validate, and persist the controller-supplied PCR selection at `/persist/status/policy-pcr.json`. Used in the rescue path. |
| `CompareLegacyandSealedKey` | Returns `SealedKeyType` (`Unknown` / `Reused` / `New` / `Unprotected`); logged on vault open and surfaced in `VaultStatus.ErrorAndTime` when the result doesn't match the expected state. |
| `WipeOutStaleSealedKeyIfAny`, `FindMismatchingPCRs` | Used in the re-seal and unseal-failure paths respectively. |

## Control-flow

There are five independent control paths through `vaultmgr`.

### 1. First-boot install of the vault

```text
Run()
  └─ wait.WaitForOnboarded()
  └─ subscribe ConfigItemValueMap, EncryptedVaultKeyFromController
  └─ wait for GCInitialized
  └─ initializeSelfPublishHandles()                  (reads VaultConfig)
  └─ tpmEnabled = etpm.IsTpmEnabled()
  └─ checkAndPublishVaultConfig()                    (sets TpmKeyOnly)
  └─ handler.SetHandlerOptions({TpmKeyOnlyMode})
  └─ handler.SetupDefaultVault()                     ext4: fscrypt setup+encrypt
                                                     zfs:  zfs create -o encryption=…
  └─ defaultVaultUnlocked = true
  └─ go uc.RunPostVaultHandlers(...)                 post-vault upgradeconverter
  └─ publishVaultKey(DefaultVaultName)               EncryptedVaultKeyFromDevice
  └─ event loop:
       ucChan close → vaultUCDone=true; getAndPublishAllVaultStatuses()
                                       (now ConversionComplete=true)
```

### 2. Boot when the vault opens locally (steady state)

Same as (1) except `SetupDefaultVault` finds the vault already
encrypted and just unlocks it. The PCR-policy file may already be
present from a previous controller exchange. No re-seal is performed.

### 3. Boot when local seal/unseal fails — controller rescue

```text
Run()
  └─ handler.SetupDefaultVault()                     returns error (PCR mismatch)
  └─ getAndPublishAllVaultStatuses()                 publishes VaultStatus(ERROR,
                                                     MismatchingPCRs=[...])
  └─ defaultVaultUnlocked stays false
  └─ uc.RunPostVaultHandlers is NOT started yet
  └─ event loop: wait for EncryptedVaultKeyFromController

(zedagent attests, controller returns the key)
EncryptedVaultKeyFromController arrives
  → handleVaultKeyFromControllerImpl()
    ├─ etpm.EncryptDecryptUsingTpm(decrypt)          AES-CFB unwrap (TPM-bound)
    ├─ digest sha256 check
    ├─ etpm.ValidatePolicyPcr / SaveDiskKeyPolicyPcr if controller supplied PolicyPcr
    ├─ etpm.SealDiskKey(decryptedKey, pcrSelection)  re-seal under current PCRs
    ├─ handler.UnlockDefaultVault()                  fscrypt unlock / zfs load-key+mount
    ├─ defaultVaultUnlocked = true
    ├─ publishVaultKey(DefaultVaultName)
    ├─ getAndPublishAllVaultStatuses()
    └─ go uc.RunPostVaultHandlers(...)
```

`nodeagent` watches the failing `VaultStatus` and, after
`timer.vault.ready.cutoff` (`VaultReadyCutOffTime`), either reboots
with `BootReasonVaultFailure` (if an upgrade is in progress) or
flips into `MaintenanceModeReasonVaultLockedUp`. The controller-rescue
race against that timer is what makes attestation latency
operationally important.

### 4. Empty-controller-key recovery (vault wipe)

```text
EncryptedVaultKeyFromController arrives with EncryptedVaultKey=[]
  → handleVaultKeyFromControllerImpl()
    if defaultVaultUnlocked: return                   (we're fine)
    if !vault.IsVaultCleanupAllowed(): warn and return
    handler.RemoveDefaultVault()
    handler.SetupDefaultVault()                       fresh key, fresh seal
    defaultVaultUnlocked = true
    publishVaultKey, getAndPublishAllVaultStatuses
    go uc.RunPostVaultHandlers(...)
```

The cleanup sentinel `/persist/status/allow-vault-clean` is dropped
by the installer and storage-init and removed once the device has
successfully past the first vault open
(`vault.DisallowVaultCleanup()`). After that point an empty-key
message from the controller is *not* a wipe instruction.

### 5. Post-vault upgradeconverter

`uc.RunPostVaultHandlers` runs the conversions that need the vault
mounted (volume metadata, snapshot directory layout, etc.) on a
goroutine, then closes `ucChan`. The main loop notices, sets
`vaultUCDone=true`, and re-publishes every `VaultStatus` so that
`ConversionComplete=true` becomes visible. Every other agent that
called `wait.WaitForVault` only proceeds at this point.

## Debugging

### PubSub

```sh
cat /run/vaultmgr/VaultStatus/*.json | jq
cat /run/vaultmgr/EncryptedVaultKeyFromDevice/*.json | jq
cat /persist/status/vaultmgr/VaultConfig/global.json | jq
```

`VaultStatus` for `"Application Data Store"` is the canonical
indicator: `Status==ENABLED` and `ConversionComplete==true` together
mean the device is fully open. `MismatchingPCRs` populated on `ERROR`
is what the controller correlates with a known PCR change.

### Files of interest under /persist/

* `/persist/vault/` — the vault root (or `persist/vault` ZFS dataset)
* `/persist/status/policy-pcr.json` — controller-supplied PCR
  selection used for re-sealing
* `/persist/status/allow-vault-clean` — installer-dropped sentinel
  permitting wipe-on-controller-empty-key
* `/persist/status/tpm_measurement_seal_success`,
  `/persist/status/tpm_measurement_unseal_fail` — copies of the
  kernel TPM event log, used by `FindMismatchingPCRs`

### Useful CLIs (from a pillar shell)

```sh
/opt/zededa/bin/fscrypt status /persist          # ext4: protector + policy
/opt/zededa/bin/fscrypt status /persist/vault    # is it Unlocked: Yes?
zfs get keystatus,encryption,mounted persist/vault   # zfs variant
/opt/zededa/bin/vaultmgr waitUnsealed            # block on healthy VaultStatus
/opt/zededa/bin/tpmmgr printPCRs                 # current PCR values
```

### Logs

`vaultmgr`'s log records ship through pillar's `newlogd` like every
other agent. On a running device, recent (not-yet-uploaded) batches
land under `/persist/newlog/devUpload/` as gzipped JSON; filter on
`source=vaultmgr`:

```sh
zcat /persist/newlog/devUpload/*.gz | jq -c 'select(.source=="vaultmgr")'
```

Once uploaded, the same records are available in the controller's
log store.

### Useful grep patterns

These are literal substrings from log calls in
`pkg/pillar/cmd/vaultmgr/vaultmgr.go`; they have no `printf` directives
and can be fed directly to `grep` (or `jq 'select(.msg | contains(...))'`).

```text
"about to setup the vault and fetch the disk key from TPM" – Run() at first attempt
"vault is setup and unlocked successfully"                 – local open succeeded
"SetupDefaultVault failed"                                 – local open failed; rescue path armed
"Re-sealing disk key, Vault Unlocked:"                     – controller-rescue re-seal
"Sealed key in TPM, unlocking"                             – rescue is unlocking the vault
"unlocked using key type"                                  – CompareLegacyandSealedKey result
"Saved controller provided Policy PCR with id"             – new policy-PCR persisted
"Vault cleanup is not allowed"                             – empty-key message ignored (no sentinel)
"default vault removed"                                    – wipe branch fired
"upgradeconverter(post-vault) Completed"                   – ucChan close, ConversionComplete to flip
```

### Forcing transitions for development

* **Force the rescue path**: bump a PCR that's part of the seal
  policy by changing the boot-time measurement (e.g. swapping in a
  modified rootfs / GRUB config) and reboot. `SetupDefaultVault`
  will fail and `vaultmgr` will publish `ERROR` with
  `MismatchingPCRs` populated, exactly as during a real upgrade.
* **Force the wipe path**: ensure
  `/persist/status/allow-vault-clean` exists, then arrange for the
  controller to publish an empty `EncryptedVaultKeyFromController`
  for `"Application Data Store"`. This is destructive — every
  app-data store under `/persist/vault` is destroyed.

## Further reading

* [`pkg/pillar/docs/vault.md`](vault.md) — the package that
  provides the filesystem-handler abstraction and key-derivation
  helpers `vaultmgr` drives.
* [`pkg/pillar/evetpm/evetpm.md`](../evetpm/evetpm.md) — the TPM
  primitives `vaultmgr` builds on (seal/unseal, `EncryptDecryptUsingTpm`,
  PCR-policy bookkeeping).
* [`pkg/pillar/docs/tpmmgr.md`](tpmmgr.md) — the microservice that
  provisions the keys `vaultmgr` consumes.
* [EVE Security Architecture](../../../docs/SECURITY-ARCHITECTURE.md)
  — device identity, onboarding, attestation, and the broader EVE
  security foundation that `vaultmgr` plugs into.
* [`fscrypt`](https://github.com/google/fscrypt) — Google's
  userspace driver for Linux filesystem-level encryption (Apache 2.0).

## Appendix: legacy key-derivation modes

Every device installed at EVE ≥ 7.10.0 derives the vault key as the
unmodified output of `etpm.FetchSealedVaultKey`. The two legacy
branches in `pkg/pillar/vault/key.go` exist only so the on-disk vault
key does not change shape underneath devices that pre-date that
release and have since been upgraded:

* **`TpmKeyOnly=false` merged mode** — used on devices first installed
  at 5.6.2 ≤ EVE < 7.10.0. `deriveVaultKey` returns
  `mergeKeys(tpmKey, cloudKey)` = first 16 B of the TPM key
  concatenated with the second 16 B of `cloudKey`, where `cloudKey` is
  the hard-coded 32-byte string `"foobarfoobarfoobarfoobarfoobarfo"`
  in `retrieveCloudKey`. The controller side of the merge was never
  wired up, so this is in practice a per-device-static rebrand of the
  TPM key. `TpmKeyOnly` is sticky in `VaultConfig` — once
  `false`, it stays `false`, because the on-disk fscrypt protector
  cannot be re-derived from a different key.
* **`cloudKeyOnlyMode=true`** — only reached from
  `Ext4Handler.changeProtector` while migrating the pre-5.6.2
  deprecated vaults (`/persist/img`, `/persist/config`) to a TPM-derived
  protector. `deriveVaultKey` returns the cloud key alone so the
  legacy protector can be unstaged, then a second `stageKey` call with
  the TPM-derived key sets the new protector.

Neither branch is reachable on a fresh install. They are kept for
forward compatibility only.
