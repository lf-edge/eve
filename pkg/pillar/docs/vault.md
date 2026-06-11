# vault: Filesystem-Handler and Key-Derivation Layer

## Overview

`pkg/pillar/vault` is the Go library that owns the filesystem-side
mechanics for the EVE *vault* — the directory (ext4) or dataset (ZFS)
under `/persist/vault` whose contents are stored encrypted at rest. It
abstracts the two filesystems behind a single `Handler` interface,
derives the 32-byte vault key from the TPM, and stages that key on a
tmpfs file for `fscrypt` or `zfs load-key` to read.

It is not itself a microservice; it has no `Run()`, no pubsub, no
long-lived state of its own. The microservice that drives it is
[`cmd/vaultmgr`](vaultmgr.md); the TPM primitives it consumes
live in [`pkg/pillar/evetpm`](../evetpm/evetpm.md).

EVE targets TPM 2.0. On platforms without a usable TPM (`IsTpmEnabled`
returns false) the package still creates a vault directory/dataset
*unencrypted* and reports
`info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED`, so the device can
still onboard and exchange config — there is no soft-key fallback for
data-at-rest.

## Handler interface

The package exposes one interface and a constructor:

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

type HandlerOptions struct {
    TpmKeyOnlyMode bool
}

func GetHandler(log *base.LogObject) Handler
```

`GetHandler` dispatches on `persist.ReadPersistType()`:

| Persist type | Handler | Encryption | Notes |
|---|---|---|---|
| `PersistExt4` | `Ext4Handler` | `fscrypt` (AES-256-XTS contents, AES-256-CTS filenames, policy v2) | Requires a usable TPM. |
| `PersistZFS` | `ZFSHandler` | ZFS native dataset encryption (`aes-256-gcm`) | Requires a usable TPM for encryption; otherwise creates an unencrypted dataset. |
| anything else | `UnsupportedHandler` | none | `GetOperationalInfo` always returns `DATASEC_AT_REST_DISABLED`. |

`HandlerOptions{TpmKeyOnlyMode}` is set once at startup by `vaultmgr`
based on the persistent `VaultConfig` it owns; the handler hands the
flag down to `stageKey`.

### Ext4Handler (`handler_ext4.go`)

Wraps Google's `fscrypt` userspace tool (`/opt/zededa/bin/fscrypt`,
config at `/etc/fscrypt.conf` — see
[`pkg/pillar/rootfs/fscrypt.conf`](../rootfs/fscrypt.conf)).

| Operation | What it runs |
|---|---|
| First-time setup | `fscrypt setup /persist --quiet` |
| Vault create (`SetupDefaultVault`) | `fscrypt encrypt /persist/vault --source=raw_key --name=TheVaultKey<basename> --user=root`, with the raw key staged on tmpfs at `/TmpVaultDir2/protector.key`. |
| Vault unlock (`UnlockDefaultVault`) | `fscrypt unlock /persist/vault`, then `keyctl link @u @s` to expose the policy key in the session keyring. |
| Deprecated vaults (`SetupDeprecatedVaults`) | Migrates `/persist/img` and `"Configuration Data Store"` at `/persist/config` (pre-5.6.2) to TPM-derived raw-key protectors via `fscrypt metadata change-passphrase`. These vaults are only ever *unlocked*, never created. |
| Status (`getVaultStatus`) | Parses `fscrypt status /persist/vault` for `Unlocked: Yes`; falls through to a few special cases (no SHA256 PCR bank → `DISABLED`; non-empty unencrypted dir → `DISABLED`) before settling on `ERROR` with `etpm.FindMismatchingPCRs()` attached. |

### ZFSHandler (`handler_zfs.go`)

Drives ZFS native encryption via `pkg/pillar/zfs` and `go-libzfs`.

| Operation | What it runs |
|---|---|
| Vault create (`SetupDefaultVault`) | `zfs.CreateVaultDataset(persist/vault, /run/TmpVaultDir2/protector.key)` → `zfs create -o encryption=aes-256-gcm -o keyformat=raw -o keylocation=file://… persist/vault`. |
| Vault unlock (`UnlockDefaultVault`) | `zfs load-key persist/vault` followed by `zfs.MountDataset(persist/vault)`. |
| Status (`checkOperationalStatus`) | Requires `mounted=yes`, `keystatus=available`, `encryption=aes-256-gcm`. Anything else → `ERROR` with `MismatchingPCRs` attached when the SHA256 PCR bank is present. |
| Kubevirt build (`base.IsHVTypeKube()`) | Also creates the `persist/etcd-storage` zvol via `CreateZvolEtcd`, and exposes the vault as an ext4-formatted zvol via `CreateZvolVault` + `MountVaultZvol`. The zvol mount uses `MS_DIRSYNC \| MS_NOATIME` unless the kernel cmdline carries `eve_no_dirsync` (set when EVE itself runs as a VM, to avoid nested DIRSYNC overhead). |
| No-TPM ZFS | A plain unencrypted dataset (or zvol on kube) is created instead; `GetOperationalInfo` reports `DISABLED`. |

The kubevirt-specific helpers `CreateZvolVault`, `CreateZvolEtcd`,
and `MountVaultZvol` are exported but currently only consumed by the
`ZFSHandler` itself.

### UnsupportedHandler (`handler_unsupported.go`)

Stub for persist filesystems other than ext4 and ZFS. All operations
are no-ops; `SetupDefaultVault` just creates an unencrypted `/persist/vault`
directory. `GetOperationalInfo` always reports
`DATASEC_AT_REST_DISABLED`.

## Key derivation (`key.go`)

`stageKey` mounts a tmpfs at the requested directory, calls
`deriveVaultKey` to produce 32 bytes of key material, writes them to
the on-tmpfs key file for `fscrypt` / `zfs load-key` to consume, and
returns an `unstage` closure that `shred --remove`s the file and
unmounts the tmpfs. On every device installed at EVE ≥ 7.10.0,
`deriveVaultKey` simply returns `etpm.FetchSealedVaultKey(log)` — a
PCR-policy unseal of the 32-byte blob in the TPM. The two legacy
branches in `deriveVaultKey` exist only for forward compatibility with
devices first installed at older EVE versions; see
[Appendix: legacy key-derivation modes](#appendix-legacy-key-derivation-modes).

## Vault-cleanup sentinel (`vault.go`)

The installer / `storage-init` drops
`/persist/status/allow-vault-clean` (`allowVaultCleanFile`) on first
provisioning. As long as that file exists, `IsVaultCleanupAllowed`
returns true and `vaultmgr` honors an empty
`EncryptedVaultKeyFromController` as a wipe-and-recreate instruction.
`DisallowVaultCleanup` removes the sentinel (and syncs its parent
directory) once the device has successfully opened its vault at least
once — after that point an empty-key message from the controller is
ignored.

`GetOperationalInfo(log)` is a convenience wrapper that picks the
handler via `GetHandler` and forwards
`GetOperationalInfo()`. `vaultmgr` uses it when publishing
`VaultStatus` for vaults whose handler hasn't been instantiated yet.

## Callers

The dependency arrows all point inward. `vaultmgr` is the principal
consumer; a couple of other agents reach in for narrow read-only uses:

| Caller | What it uses `vault` for |
|---|---|
| `pkg/pillar/cmd/vaultmgr` | `GetHandler`, the `Handler` interface, `HandlerOptions`, `IsVaultCleanupAllowed`. The vault-setup / unlock / rescue / wipe flows all go through here. |
| `pkg/pillar/cmd/volumemgr` | `DisallowVaultCleanup` — called after the first volume-management work, so a subsequent empty `EncryptedVaultKeyFromController` no longer wipes the device. |
| `pkg/pillar/cmd/zedagent` | `GetOperationalInfo` for the device-info report (`info.DataSecAtRest.Status` / `.Info`). |

## Test Hooks

`vault` has no test simulators of its own; tests that exercise the
handlers run against real `fscrypt` / `zfs` binaries in a controlled
container. The TPM primitives the package calls are simulated via
`evetpm.SimTpm*` (see [evetpm.md → Test
Hooks](../evetpm/evetpm.md#test-hooks)).

## Further Reading

* [`pkg/pillar/docs/vaultmgr.md`](vaultmgr.md) — the
  microservice that drives this package.
* [`pkg/pillar/evetpm/evetpm.md`](../evetpm/evetpm.md) — the TPM
  primitives (`FetchSealedVaultKey`, `SealDiskKey`,
  `EncryptDecryptUsingTpm`, PCR-policy bookkeeping) that the
  key-derivation and handler paths build on.
* [`docs/SECURITY-ARCHITECTURE.md`](../../../docs/SECURITY-ARCHITECTURE.md)
  — EVE's top-level security design: device identity, onboarding,
  vault-key sealing, attestation.
* [`fscrypt`](https://github.com/google/fscrypt) — Google's
  userspace driver for Linux filesystem-level encryption (Apache 2.0).

## Appendix: legacy key-derivation modes

Every device installed at EVE ≥ 7.10.0 uses `TpmKeyOnly=true`, so
`deriveVaultKey` returns `etpm.FetchSealedVaultKey(log)` and nothing
else. The two legacy branches survive because the on-disk vault key
shape cannot change underneath a device whose fscrypt or ZFS protector
was set up against the older derivation:

| Caller flags | Branch | Reachable when |
|---|---|---|
| `cloudKeyOnlyMode=true` | returns the hard-coded 32-byte `cloudKey` (`"foobarfoobarfoobarfoobarfoobarfo"` in `retrieveCloudKey`) | Only in `Ext4Handler.changeProtector`, while unstaging the pre-5.6.2 deprecated-vault protector before re-staging with a TPM-derived key. |
| `tpmKeyOnlyMode=false` *and* `cloudKeyOnlyMode=false` | returns `mergeKeys(tpmKey, cloudKey)` = first 16 B of TPM key ‖ second 16 B of `cloudKey` | Only on devices first installed at 5.6.2 ≤ EVE < 7.10.0 that have since been upgraded. `TpmKeyOnly` is sticky in the persistent `VaultConfig` — once `false`, it stays `false`. |
| `useSealedKey=false` | returns the non-sealed TPM key via `etpm.FetchVaultKey` | Only used during the deprecated-vault migration when the sealed path is not yet in place. |

The controller side of the merge was never wired up, so the merged
mode is in practice a per-device-static rebrand of the TPM key.
`mergeKeys` enforces `len(key1) == len(key2) == vaultKeyLen == 32` and
returns `errInvalidKeyLen` otherwise.

None of these branches is reachable on a fresh install.
