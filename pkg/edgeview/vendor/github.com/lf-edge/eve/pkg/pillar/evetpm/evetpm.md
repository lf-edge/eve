# evetpm: Shared TPM 2.0 Primitive Layer

## Overview

`pkg/pillar/evetpm` is the Go library that every pillar component
which touches the TPM goes through. It owns the
on-TPM data layout for EVE (well-known persistent handles, NV
indices, PCR selections, disk-key seal blobs, policy-PCR bookkeeping)
and exposes the primitives — probe, sign, encrypt/decrypt, seal/unseal,
PCR policy — that the microservices above it compose into product
behaviour. It is not itself a microservice; it has no `Run()`, no
pubsub, and no long-lived state of its own beyond what it stores in
the TPM or on disk on behalf of its callers.

The boundary against the microservices is intentionally narrow:

* **`evetpm`** decides *what* the on-TPM layout looks like (which
  handles, which NV indices, which PCRs go into a disk-key policy,
  how the policy digest is computed) and provides the operations
  (`SealDiskKey`, `UnsealDiskKey`, `EncryptDecryptUsingTpm`,
  `TpmSign`, …) that mutate or read it. It opens `/dev/tpmrm0` on
  every call and closes it again; it holds no TPM session across
  calls.
* **`tpmmgr`** drives provisioning and attestation against that
  layout — see [`pkg/pillar/docs/tpmmgr.md`](../docs/tpmmgr.md).
* **`vaultmgr`** drives disk-key seal/unseal on top of
  `SealDiskKey` / `UnsealDiskKey` / `FetchSealedVaultKey`.
* **`zedagent`** and **`controllerconn`** use the encrypt/decrypt
  and signing primitives for cert hashing, the attestation FSM, and
  the device-key-signed authentication to the controller.

EVE targets the TPM 2.0 revision. A TPM 1.0 device or a TPM 2.0 that
fails the runtime check in `IsTpmEnabled` is treated as "no usable
TPM"; callers branch into their soft (on-disk key) paths and the
TPM-rooted operations in this package are skipped.

## On-TPM Data Layout

The package owns the global EVE convention for what lives where on
the TPM. Other pillar code references these constants rather than
hard-coding handle values. The microservice doc
[`pkg/pillar/docs/tpmmgr.md`](../docs/tpmmgr.md#key-inputoutput)
summarises the same table from the operator's perspective; this
section is the canonical statement.

### Persistent key handles

| Constant | Handle | Purpose |
|---|---|---|
| `TpmEKHdl` | `0x81000001` | Endorsement Key (RSA-2048, restricted decrypt). Created from the TCG standard EK template (`DefaultEkTemplate`). |
| `TpmSRKHdl` | `0x81000002` | Storage Root Key (RSA-2048, restricted decrypt). Parent for sealed objects. |
| `TpmAIKHdl` | `0x81000003` | Attestation Key (AK; RSA-2048, restricted signing). Used in the vTPM credential-activation flow. The constant identifier retains the TPM 1.2 "AIK" name; the TPM 2.0 spec calls it AK. |
| `TpmQuoteKeyHdl` | `0x81000004` | PCR Quote signing key (ECC P-256, restricted signing). |
| `TpmEcdhKeyHdl` | `0x81000005` | ECDH key (ECC P-256). Used both for ECDH key derivation in `EncryptDecryptUsingTpm` / `DecryptSecretWithEcdhKey` and by `vaultmgr` for vault-key wrap/unwrap. |
| `TpmDeviceKeyHdl` | `0x817FFFFF` | Long-lived ECDSA device-identity key. The certificate at `/config/device.cert.pem` chains to this. |

### NV indices

| Constant | Handle | Contents |
|---|---|---|
| `TpmDeviceCertHdl` | `0x1500000` | Backup copy of `/config/device.cert.pem`. `tpmmgr` mirrors the device cert into NV at first boot so the cert survives a wipe of `/config`. |
| `TpmPasswdHdl` | `0x1600000` | TPM credentials (a UUID generated on first boot, truncated to `MaxPasswdLength` = 7 bytes by `ReadOwnerCrdl`). Mirrored at `/config/tpm_credential`. **Not** the owner-hierarchy password — every owner-hierarchy operation in `evetpm`/`tpmmgr` passes `EmptyPassword`. The credential is instead bound as the `userAuth` of the **device key** at creation time (`CreatePrimary`'s `inSensitive.userAuth` in `createDeviceKey`), and must subsequently be supplied to authorize that key in `TpmSign` and `ECDHZGen`. `vcomlink` also passes it as the auth value for caller-supplied NV / signing / certify operations. |
| `TpmDiskKeyHdl` | `0x1700000` | Legacy (un-sealed) disk key — random 32-byte raw key written via `writeDiskKey`. Pre-dates PCR-sealed vaults; carried forward for upgrade compatibility (see `FetchSealedVaultKey`). |
| `TpmSealedDiskPubHdl` | `0x1900000` | TPM2B_PUBLIC of the sealed disk-key object. Both the encrypted (`enc_seal.go`) and legacy (`tpm.go`) seal paths write here. |
| `TpmSealedDiskPrivHdl` | `0x1800000` | TPM2B_PRIVATE of the sealed disk-key object. |

The legacy disk key at `TpmDiskKeyHdl` and the sealed pair at
`TpmSealedDiskPubHdl` / `TpmSealedDiskPrivHdl` can coexist on the
same device — see [Disk-key seal / unseal](#disk-key-seal--unseal) for
the migration logic.

### PCR selections

All PCR operations are in the SHA256 bank. The package exposes three
distinct selections, used for different things; conflating them is a
common source of bugs.

| Variable | PCRs | Used for |
|---|---|---|
| `PcrSelection` | `{7}` | "Entropy" PCR selection passed to `CreatePrimary` when generating non-policy keys. The contents don't matter for the resulting key, but PCR 7 is stable across boots. |
| `PcrListForQuote` | `{0..15}` | Selection signed in `tpm2.Quote` for attestation. PCRs 16–23 are deliberately excluded. |
| `DefaultDiskKeySealingPCRs` | `{0,1,2,3,4,6,7,8,9,10,11,12,13,14}` | Default selection sealing the vault key. PCR 5 is excluded (`PCRIndexGPT`, which measures the GPT partition table — volatile across A/B image updates because EVE flips the IMGA/IMGB "active" vs "updating" attribute bits in the GPT header on every base-OS upgrade); PCR 15 is excluded (`PCRIndexOS`, reserved for OS / user use). |

`ValidatePolicyPcr` enforces the constraints on any controller-supplied
selection: PCR 0 (`PCRIndexSRTM`) must be present, PCR 5 must not be
present, no duplicates, all indexes in `[0..15]`, total count ≤ 15
(`PCRIndexMaxCount`).

### Disk-key policy persistence

The PCR selection actually used to seal the on-disk vault key is
persisted at `types.PolicyPcrFile` (`/persist/status/policy-pcr.json`),
serialised as `types.VaultKeyPolicyPCR{PolicyPresent, Indexes, ID}`.
The file is owned by this package — `GetDiskKeyPolicyPcrOrDefault`,
`SaveDiskKeyPolicyPcr`, `RecoverDiskKeyPolicyPcr`, and
`ValidatePolicyPcr` all read or write it under a file lock.

The `ID` field distinguishes how the policy got there:

* `> 0` — controller-supplied (the integer is the controller's policy
  ID).
* `0` (`PolicyPCRRecoveredDefault`) — recovery succeeded with the
  default PCR set.
* `-1` (`PolicyPCRRecovered`) — recovery searched the candidate space
  and found a non-default subset that produces the digest baked into
  the sealed object's `AuthPolicy`.

`RecoverDiskKeyPolicyPcr` is the read-back path used when unseal
fails with the saved selection. It reads the `AuthPolicy` digest out
of the sealed object's public area
(`tpm2.NVReadEx(TpmSealedDiskPubHdl)` →
`tpm2.DecodePublic` → `pubData.AuthPolicy`) and brute-forces all
subsets of `PcrListForQuote.PCRs` against the current PCR values,
computing each candidate digest with `computePolicyPCRAuthDigest`.
With 16 candidate PCRs that is at most 2^16 trials — sub-millisecond
in practice. The recovered selection is persisted back to
`policy-pcr.json` so subsequent unseals can skip the search.

`computePolicyPCRAuthDigest` reproduces the TPM's policy-digest
formula in software:

```text
newPolicyDigest = SHA256(
        oldPolicyDigest         // 32 bytes of zero, since PolicyPCR
                                // is the first and only policy
     || TPM_CC_PolicyPCR        // 0x0000017F, big-endian
     || TPML_PCR_SELECTION      // Count | HashAlg | SizeOfSelect | bitmap
     || SHA256(PCR_i ‖ PCR_j ‖ …)  // digestTPM, PCRs concatenated in
                                   // ascending index order
)
```

The bitmap is 3 bytes wide (sufficient for PCRs 0–23, matching the
`PcrListForQuote` range), MSB-first within each byte.

### Other persistent state on disk

| Path | Written by | Purpose |
|---|---|---|
| `/persist/status/sealingpcrs` (`savedSealingPcrsFile`) | `saveDiskKeySealingPCRs` after a successful seal | gob-encoded `map[int][]byte` of PCR values at seal time. Read by `FindMismatchingPCRs` to diagnose unseal failure. |
| `/persist/status/tpm_measurement_seal_success` (`measurementLogSealSuccess`) | `SealDiskKey` (and `-backup` rotation on re-seal) | Concatenation of `types.TpmMeasurementLogFile` + `types.TpmMeasurefsEventLog` at seal time. |
| `/persist/status/tpm_measurement_unseal_fail` (`measurementLogUnsealFail`) | `UnsealDiskKey` on failure | Same shape, captured at the failing unseal. Diffing this against `…_seal_success` is the operator's tool for "why did unseal fail?" |
| `/persist/status/boot_vars/success`, `…/fail` | `saveBootVariables` from the same call sites | EFI BootOrder + BootXXXX variables copied from `/hostfs/sys/firmware/efi/efivars/`, with the GUID suffix stripped. |

`GetTpmLogFileNames`, `GetTpmLogBackupFileNames`, and
`GetBootVariablesDirNames` are the public accessors `monitor` and
similar tools use to reach the log paths without hard-coding them.

## Public API Surface

### Capability / probe

| Function | What it returns |
|---|---|
| `IsTpmEnabled() bool` | `true` iff `/config/device.cert.pem` exists and `/config/device.key.pem` does not. The presence of the soft key file is the canonical "TPM path failed at provisioning time" marker. Before `tpmmgr createDeviceCert` has run (no cert file yet) it returns `false`, which is correct: a not-yet-provisioned device has no TPM-rooted identity. |
| `PCRBankSHA256Enabled() bool` | Cached probe: reads PCR 0 in the SHA256 bank once and remembers the result in `pcrBank256Status`. False on no-TPM platforms or TPMs without a SHA256 bank. |
| `FetchTpmSwStatus() info.HwSecurityModuleStatus` | `NOTFOUND` / `DISABLED` / `ENABLED` for the controller report. |
| `FetchTpmHwInfo() / FetchTpmHwInfoDescription() (string, error)` | "`<vendor>-<model>, FW Version <v>`" string for the controller report. Returns `ErrNoTPM` on no-TPM platforms (or `""` from `…Description`). Cached after the first call. |
| `GetSpecVersion() (string, error)` | TPM family indicator (e.g. `"2.0"`). |
| `GetTpmProperty(tpm2.TPMProp) (uint32, error)` | Raw `GetCapability` wrapper used by the helpers above. |
| `GetModelName(v1, v2 uint32) string` / `GetFirmwareVersion(v1, v2 uint32) string` | Decode the four-byte ASCII vendor strings and packed firmware-version words returned by the TPM. |
| `GetRandom(uint16) ([]byte, error)` | `tpm2.GetRandom` wrapper. Used as the entropy source for vault-key seed generation (`FetchVaultKey`, `FetchSealedVaultKey`) — TPM RNG is preferred over `/dev/urandom` to match the recommendation in the TPM 2.0 architecture spec. |

### Key + cert primitives

| Function | Purpose |
|---|---|
| `TpmPrivateKey` | `crypto.Signer` whose `Sign` routes through the TPM device key. Used as the private-key argument to `x509.CreateCertificate` so that certs are signed by the in-TPM device key without ever materialising the private value. `Public()` returns either the cached value set by `SetDevicePublicKey` (used during the bootstrap before `device.cert.pem` is on disk) or the public key parsed from the cert file. |
| `SetDevicePublicKey(crypto.PublicKey)` | Seed the cached public key for `TpmPrivateKey.Public()` during the self-signed bootstrap. |
| `TpmSign(digest []byte) (*big.Int, *big.Int, error)` | Low-level: sign a 32-byte SHA-256 digest with the device key (`TpmDeviceKeyHdl`), returning the raw ECDSA `R, S`. `controllerconn/authen.go` calls this for the device-authenticated handshake. `TpmPrivateKey.Sign` wraps it with `asn1.Marshal`. |
| `CreateKey(log, tpmPath, keyHandle, ownerHandle, template, overwrite)` | Generate a primary key under the owner hierarchy and `EvictControl` it into a persistent slot. The `overwrite=false` path is idempotent: an existing key with matching attributes is left in place; only attribute mismatches trigger a recreate. Called by `tpmmgr` for EK / SRK / AK / quote / ECDH and for the device key itself. |
| `ReadOwnerCrdl() (string, error)` | Read `/config/tpm_credential` and truncate to `MaxPasswdLength` (7 bytes). This is the auth value bound to the device key on creation (see `TpmPasswdHdl` row above); device-key operations (`TpmSign`, `ECDHZGen`, and vcomlink's `tpmSign` / `tpmReadNV` / `tpmCertifyKeyWithAik`) must pass it. |
| `GetDevicePrivateKey()` / `GetPrivateKeyFromFile(path)` / `GetPublicKeyFromCert(path)` | PEM helpers in `keys.go` for the soft-key path. `GetDevicePrivateKey` reads `/config/device.key.pem` and returns an `*ecdsa.PrivateKey`; `GetPublicKeyFromCert` parses any X.509 cert PEM. |
| `EccIntToBytes(curve, *big.Int) []byte` | Left-pad an ECC scalar to the curve's byte width. Works around the "missing leading zero" issue in pre-v1.38 TPMs that reject ECPoints whose `XRaw`/`YRaw` are shorter than the curve size. |

`DefaultKeyParams`, `DefaultEkTemplate`, `DefaultSrkTemplate`,
`DefaultAikTemplate`, `DefaultQuoteKeyTemplate`,
`DefaultEcdhKeyTemplate` are the `tpm2.Public` templates used with
`CreateKey`. The EK template is the TCG standard EK template
(verbatim AuthPolicy from
[Credential_Profile_EK_V2.0](https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf));
the others are bespoke to EVE.

### Encrypt / decrypt

`encryptdecypt.go` implements the two operations that funnel almost
every "secret crossing the TPM boundary" path in pillar:

| Function | Used by |
|---|---|
| `EncryptDecryptUsingTpm(in []byte, encrypt bool) ([]byte, error)` | `vaultmgr` for vault-key wrap/unwrap; `tpmmgr testEncryptDecrypt` and the periodic TPM sanity check; `cipher` for `EdgeNodeCert` body roundtrips. Derives an AES-256 key from the ECDH shared secret between the device's own ECDH key (`TpmEcdhKeyHdl`) and the device cert public key, then AES-CFB encrypts or decrypts with an all-zero IV. Same call on both sides → reversible. |
| `DecryptSecretWithEcdhKey(log, X, Y, edgeNodeCert, iv, ciphertext, plaintext)` | `cipher` for controller-to-device secret exchange. The controller has performed the other half of an ECDH against the published `ecdh.cert.pem`; this function reconstructs the shared secret (`tpm2.ECDHZGen(TpmEcdhKeyHdl, …)` if TPM, scalar mult if soft), KDFs it (SHA256 over the X/Y points padded to curve width), and AES-CFB-decrypts. |
| `AESEncrypt` / `AESDecrypt` | The AES-CFB primitive used by both of the above. Also exported for direct use by `cipher`. |
| `Sha256FromECPoint(X, Y, pubKey)` | KDF: pad X and Y to curve width, concatenate, SHA-256. |

The soft-fallback path inside `getDecryptKey` triggers when either
`IsTpmEnabled()` is false or `edgeNodeCert.IsTpm` is false — the
latter handles the case where the device has a TPM in general but
the ECDH cert was created via the soft path. In that case the
private key is read from `EcdhKeyFile` (`/persist/certs/ecdh.key.pem`)
and the scalar multiplication happens in Go rather than in hardware.

### Disk-key seal / unseal

`SealDiskKey` and `UnsealDiskKey` are the public entry points. Both
branch on `tpmSupportsAES128CFB()`:

* If the TPM supports AES-128-CFB as a symmetric cipher (queried via
  `tpm2.TestParms`), the encrypted variants in `enc_seal.go` are used.
  These wrap the seal/unseal in a salted HMAC session
  (`tpm2.Salted(TpmEKHdl, ekPub)`) with `tpm2.AESEncryption(128,
  Encrypt{In,Out})` parameter encryption. The session salt is
  encrypted to the EK public key by the kernel-side
  `transport.TPM`; the plaintext disk key is therefore encrypted on
  the CPU↔TPM bus and protected from a passive bus snooper.
* Otherwise, the legacy variants `sealDiskKeyLegacy` /
  `unsealDiskKeyLegacy` are used. These use the older `legacy/tpm2`
  API with a plain `PolicyPCR` session — correct, but the key value
  is in cleartext on the bus.

Both paths store the sealed object in the same two NV indices
(`TpmSealedDiskPubHdl` / `TpmSealedDiskPrivHdl`) in the same wire
format. The encrypted variant strips the leading 2-byte size prefix
from the v2 `tpm2.Marshal(TPMTPublic)` output before storing, so an
encrypted-path seal can be unsealed by the legacy path on a
subsequent boot (and vice versa) — both paths read the same on-TPM
bytes.

The two reasons `enc_seal.go` uses the newer `tpm2` package while
the rest of the file uses `legacy/tpm2`:

1. Parameter encryption (`AESEncryption(128, Encrypt{In,Out})`) on
   salted HMAC sessions is only available on the v2 API.
2. `TPMLPCRSelection` / `TPMSPCRSelection` carry the
   PC-Client-compatible bitmap helpers (`PCClientCompatible.PCRs(...)`)
   needed to build the policy session correctly for the v2 ABI.

Migrating the rest of the package to v2 is tracked separately — see
[TSS 2.0 Backend](#tss-20-backend) below.

#### Wrapper / high-level entry points

| Function | What it does |
|---|---|
| `FetchVaultKey(log)` | Legacy (un-sealed) path. Reads `TpmDiskKeyHdl` from NV; on miss generates 32 random bytes via `GetRandom` and writes them. Used on TPMs without a usable SHA256 PCR bank. |
| `FetchSealedVaultKey(log)` | Modern path. Branches on `(sealedKeyPresent, legacyKeyPresent)`: fresh install → generate + seal; legacy only → "clone-then-seal" migration so a failed upgrade can still fall back; sealed present → unseal. Falls back to `FetchVaultKey` if the SHA256 PCR bank is absent. |
| `SealDiskKey(log, key, pcrSel)` | Seal + write success-side measurement log + boot variables + sealing-PCR snapshot. |
| `UnsealDiskKey(pcrSel)` | Unseal; on failure also copy the current measurement log and boot variables into the `…_unseal_fail` slots, and call `FindMismatchingPCRs` to enrich the returned error with the list of PCR indexes whose values have changed since seal time. |
| `UnsealDiskKeyWithRecovery(log, pcrSel)` | Try `UnsealDiskKey(pcrSel)`; on failure call `RecoverDiskKeyPolicyPcr` and try again with the recovered selection. Called from inside `FetchSealedVaultKey`. |
| `WipeOutStaleSealedKeyIfAny()` | NV-undefine both seal handles. Used by `vaultmgr` before re-sealing with a new policy. |
| `PolicyPCRSession(rw, pcrSel)` | Build a `tpm2.SessionPolicy` with a single `PolicyPCR` step and return the session handle + computed policy digest. Used by the legacy seal/unseal path. |
| `CompareLegacyandSealedKey(log)` | Returns a `SealedKeyType` (`Unknown` / `Reused` / `New` / `Unprotected`) describing the relationship between the legacy and sealed keys for the controller report. |

`SealedKeyType` is the user-facing label set published in
`EncryptedVaultKeyFromDevice`; its `String()` is what the controller
sees.

### PCR policy bookkeeping

| Function | What it does |
|---|---|
| `GetDiskKeyPolicyPcrOrDefault(path) tpm2.PCRSelection` | Read `policy-pcr.json` under a file lock, validate, return the selection. Fall back to `DefaultDiskKeySealingPCRs` on missing / corrupt / invalid file. |
| `SaveDiskKeyPolicyPcr(sp, path) (changed, err)` | Sort indexes, compare to existing file under lock, write atomically only if different. **Crashes the service via `log.Fatalf` on write failure** — the rationale is to let the boot loop retry rather than continue with a stale policy. |
| `ValidatePolicyPcr(sp) error` | Constraint check (see [PCR selections](#pcr-selections)). |
| `RecoverDiskKeyPolicyPcr() (tpm2.PCRSelection, error)` | Read the sealed object's `AuthPolicy` digest, try the default selection first, then brute-force subsets of `PcrListForQuote.PCRs`. Saves the recovered selection back to `policy-pcr.json` with `ID = PolicyPCRRecoveredDefault` or `PolicyPCRRecovered`. |
| `FindMismatchingPCRs() ([]int, error)` | Read the saved sealing-time PCR map (`sealingpcrs`) and compare against current PCR values; return the indexes that differ. Used to enrich unseal-failure errors with operator-actionable detail (e.g. "PCR 7 changed → secure-boot policy update"). |

## Callers

`evetpm` has no main package; the dependency arrows all point inward.
Major callers in pillar:

| Caller | What it uses `evetpm` for |
|---|---|
| `pkg/pillar/cmd/tpmmgr` | Everything provisioning-related: `CreateKey` against every template, `IsTpmEnabled`, `TpmPrivateKey`, `FetchTpmHwInfoDescription`, `EncryptDecryptUsingTpm` (sanity check), `GetTpmLogFileNames` / `GetBootVariablesDirNames` (debug bundles). See [`pkg/pillar/docs/tpmmgr.md`](../docs/tpmmgr.md). |
| `pkg/pillar/cmd/vaultmgr` | `FetchSealedVaultKey`, `SealDiskKey`, `EncryptDecryptUsingTpm` (wrap/unwrap of the controller-supplied vault key), `CompareLegacyandSealedKey`, `ValidatePolicyPcr` / `SaveDiskKeyPolicyPcr`. The vault key seal/unseal flow is the principal consumer of this package; `UnsealDiskKeyWithRecovery`, `WipeOutStaleSealedKeyIfAny`, and `FindMismatchingPCRs` are reached transitively through `FetchSealedVaultKey` and the `pkg/pillar/vault` handlers. |
| `pkg/pillar/vault/{handler_ext4,handler_zfs,key}.go` | Wrappers that pick `FetchSealedVaultKey` vs. `FetchVaultKey` based on `PCRBankSHA256Enabled()`. |
| `pkg/pillar/cipher/handlecipher.go` | `DecryptSecretWithEcdhKey`, `EncryptDecryptUsingTpm` for the controller-to-device secret exchange (`EdgeNodeCert`-keyed cipher blocks). |
| `pkg/pillar/controllerconn/{authen,tls}.go` | `TpmPrivateKey`, `TpmSign` for the device-key-signed authentication handshake; `IsTpmEnabled` to pick the soft vs. TPM-rooted code path. |
| `pkg/pillar/cmd/zedagent/reportinfo.go` | `FetchTpmSwStatus`, `FetchTpmHwInfoDescription`, `GetSpecVersion`, `CompareLegacyandSealedKey` for the controller info report (`HSMStatus`, `HSMInfo`). |
| `pkg/pillar/cmd/vcomlink` | `TpmEKHdl`, `TpmAIKHdl` and the read primitives — the guest-VM TPM service exposed over vsock proxies a subset of TPM ops back into this package. |
| `pkg/pillar/cmd/msrv` | Credential-activation flow (`ActivateCredentialReq`) goes through the same handles. |
| `pkg/pillar/cmd/monitor/messages.go` | `GetTpmLogFileNames`, `GetTpmLogBackupFileNames`, `GetBootVariablesDirNames` to ship the latest seal/unseal artefacts off the device for diagnostics. |
| `pkg/pillar/hardware/inventory.go` | `FetchTpmHwInfo` for the hardware inventory. |

`nodeagent` is an indirect consumer: it watches `TpmSanityStatus`
published by `tpmmgr`, which `tpmmgr` derives from the result of
`EncryptDecryptUsingTpm` + `tpm2.Quote` here.

## TSS 2.0 Backend

TPM2 commands go through Google's
[`go-tpm`](https://github.com/google/go-tpm) (Apache 2.0). The
package pulls in **both** the `legacy/tpm2` package and the newer
top-level `tpm2` (plus `tpm2/transport`). The split is by file:

| File | API | Why |
|---|---|---|
| `tpm.go`, `encryptdecypt.go` | `legacy/tpm2` | These predate the v2 package upstream. The legacy API is still supported and the migration cost has not justified the rewrite. |
| `enc_seal.go` | `tpm2` + `tpm2/transport` | Salted HMAC sessions with AES-128-CFB parameter encryption are only exposed on the v2 API. The bitmap helpers (`PCClientCompatible.PCRs(...)`) and `TPMLPCRSelection` types also live there. |
| `keys.go` | none (pure Go `crypto/*` / PEM) | Soft-key helpers. |

Most of `tpmmgr` and `evetpm` predate the v2 package and the legacy
API has remained adequate; `enc_seal.go` was written against the v2
package because parameter encryption and `TPMLPCRSelection` are only
exposed there. A full v2 migration is **TBD** — a tracking issue will
be filed separately.

## Test Hooks

`testhelper.go` exposes two helpers (`SimTpmWaitForTpmReadyState`,
`SimTpmAvailable`) for unit tests that run against a `swtpm`
simulator. Several package globals are deliberately `var` rather
than `const` so tests can redirect them:

* `TpmDevicePath` (`/dev/tpmrm0`) — set to the swtpm socket.
* `EcdhKeyFile` (`/persist/certs/ecdh.key.pem`) — set to a tempdir
  path; `SetECDHPrivateKeyFile` is the public setter.
* `savedSealingPcrsFile`, `measurementLogSealSuccess`,
  `measurementLogUnsealFail` — redirected so a test seal/unseal does
  not stomp the on-device persistent state.

These are not part of the runtime API surface — production callers
should treat them as constants.

## Further Reading

* [`pkg/pillar/docs/tpmmgr.md`](../docs/tpmmgr.md) — the microservice
  that drives provisioning and attestation through this package.
* [`docs/SECURITY-ARCHITECTURE.md`](../../../docs/SECURITY-ARCHITECTURE.md)
  — EVE's top-level security design: device identity, onboarding,
  vault-key sealing, attestation.
* [Trusted Computing Group](https://trustedcomputinggroup.org/) —
  TPM 2.0 specifications. The policy-digest formula reproduced in
  `computePolicyPCRAuthDigest` is in Part 1 ("Architecture"), the
  EK template is from the EK Credential Profile.
* [`go-tpm`](https://github.com/google/go-tpm) — both `legacy/tpm2`
  and the top-level `tpm2` packages used here.
