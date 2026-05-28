# TPM Manager

## Overview

`tpmmgr` is the EVE microservice responsible for managing the
[Trusted Platform Module](https://trustedcomputinggroup.org) (TPM)
on EVE systems. The TPM is a
[Trusted Computing Group](https://trustedcomputinggroup.org) standard
for a discrete hardware chip or platform firmware component that
creates crypto keys, seals secrets, measures system components, and
stores those measurements in a tamper-evident way. EVE targets the
**TPM 2.0** revision of the standard; a TPM 1.0 device, or a TPM 2.0
that fails the runtime checks in `etpm.IsTpmEnabled()`, is treated
as "no usable TPM" and `tpmmgr` switches to the soft fallback paths.
`tpmmgr` is the userspace interface between EVE and that hardware (or
firmware).

`tpmmgr` runs in two modes:

* **Single-shot CLI**, invoked from `onboot.sh` / `device-steps.sh`
  during boot to provision the device identity key/cert and the
  EK / SRK / AK / quote / ECDH keys, generate the matching X.509
  certs, and save TPM vendor info. Each subcommand is a one-shot
  process.
* **Long-running service**, started under `zedbox` after onboarding.
  It publishes the device's edge-node certificates to `zedagent`,
  services controller-initiated attestation quotes via
  `AttestNonce` → `AttestQuote`, and runs an hourly `tpmSanityCheck`
  whose `TpmSanityStatus` publication drives `nodeagent`'s
  `MaintenanceModeReasonTpm{Enc,Quote}Failure` paths. The
  `EdgeNodeCert` publication carries the EK's `TPM2B_PUBLIC` as
  metadata so the controller can verify the key chain back to the
  TPM manufacturer.

Without a usable TPM (no TPM at all, TPM 1.x, or a TPM 2.0 that fails
`etpm.IsTpmEnabled()`) the device identity key and ECDH / quote certs
are generated as soft keys on disk so the device can still onboard.
The EK cert is not published, attestation quotes are not produced,
and the sanity check is skipped.

The on-TPM data layout — well-known handles, NV indices for the
device cert and credentials, the sealed disk-key blob, PCR selections
— is owned by the `pkg/pillar/evetpm` package; see
[`pkg/pillar/evetpm/evetpm.md`](../evetpm/evetpm.md) for the canonical
table. `tpmmgr` is the microservice that drives it; `vaultmgr` and
`zedagent` use the same package directly for vault key sealing/unsealing
and for cert hashing.

### Where edge-node certificates live on disk

| Cert / key | Path | TPM-backed? | Survives EVE re-install? |
|---|---|---|---|
| Device cert PEM | `/config/device.cert.pem` | Yes (private key in TPM) | Yes — the cert PEM is also mirrored into TPM NV index `0x1500000`, so a fresh `/config` is restored from NV on first boot |
| Device key PEM | `/config/device.key.pem` | No (soft path only) | Yes if present (only exists on no-TPM platforms) |
| ECDH cert / key | `/persist/certs/ecdh.{cert,key}.pem` | Cert yes; soft key only when TPM path failed | **No** — regenerated on first boot after re-install |
| Quote ("attest") cert / key | `/persist/certs/attest.{cert,key}.pem` | Cert yes; soft key only when TPM path failed | **No** — regenerated on first boot after re-install |
| EK cert | `/persist/certs/ek.cert.pem` | Yes (no soft variant) | **No** — regenerated on first boot after re-install |

The asymmetry matters: re-installing EVE preserves the **device
identity** (because it lives in TPM NVRAM), but the EK / ECDH / quote
certs are regenerated. The controller therefore sees fresh
`EdgeNodeCert` publications after every re-install even though the
device's identity hasn't changed.

## Key Input/Output

**tpmmgr consumes** (via pubsub unless noted):

* global configuration
  * `ConfigItemValueMap` from `zedagent` — only used for log levels.
* attestation requests
  * `AttestNonce` from `zedagent` — published with a fresh nonce
    each time the controller wants a quote; carries `Requester` for
    log traceability and `Nonce` (12–32 bytes).
* TPM device
  * `/dev/tpmrm0` (`etpm.TpmDevicePath`) — the resource-managed TPM
    device file. All TPM2 commands go through this.
  * Persistent handles (EK / SRK / AK / quote / ECDH at
    `0x8100000{1..5}`, device key at `0x817FFFFF`) and NV indices
    (device-cert backup `0x1500000`, credentials `0x1600000`, sealed
    disk-key pair `0x1800000` / `0x1900000`) — see
    [evetpm.md](../evetpm/evetpm.md#on-tpm-data-layout) for the
    canonical table. `tpmmgr` itself touches the device key (for cert
    signing via `etpm.TpmPrivateKey`), the quote key (attestation),
    NV `0x1500000` (device-cert backup), and NV `0x1600000` (the
    credential used as the device-key `userAuth`); the sealed
    disk-key NV pair is owned by `vaultmgr`.
* on-disk
  * `/config/tpm_credential` — TPM credentials cache, mirrored from
    NV index `0x1600000`. Created on first boot; used as the
    device-key `userAuth` — see
    [`TpmPasswdHdl` in evetpm.md](../evetpm/evetpm.md#nv-indices).
  * `/config/device.cert.pem`, `/config/device.key.pem` — device
    identity cert and (for non-TPM platforms) its private key.
  * `/persist/certs/ecdh.cert.pem`, `attest.cert.pem`, `ek.cert.pem`
    — published edge-node certs.
  * `/persist/certs/ecdh.key.pem`, `attest.key.pem` — soft private
    keys, written when the TPM path is unavailable or the per-cert
    TPM path fails and the dispatcher falls back to soft.

**tpmmgr publishes**:

* `EdgeNodeCert` (persistent) — one entry per cert type
  (`CertTypeEcdhXchange`, `CertTypeRestrictSigning`, `CertTypeEk`).
  Carries the cert PEM, a sha256-first-16 hash as `CertID`, an
  `IsTpm` flag indicating whether the corresponding key actually
  lives in the TPM, and (for the EK only) a `MetaDataItems` slice
  containing the EK's `TPM2B_PUBLIC` blob. Consumed by `zedagent`,
  forwarded to the controller.
* `AttestQuote` — one entry per nonce, keyed on the nonce itself.
  Carries the signed quote (ECDSA-SHA256), the signature, and the
  raw PCR values (SHA256 bank) read separately for the controller's
  use. Only produced when a usable TPM is present. The read range
  and the in-quote range are separately defined — see
  [Attestation quote](#attestation-quote-getquote--handleattestnonceimpl).
  Consumed by `zedagent`'s attestation FSM, then unpublished after the
  controller confirms receipt.
* `TpmSanityStatus` — keyed on the TPM device path. `Status` is one
  of `MaintenanceModeReasonNone` (TPM healthy),
  `MaintenanceModeReasonTpmEncFailure` (encrypt/decrypt round-trip
  failed), or `MaintenanceModeReasonTpmQuoteFailure` (`Quote` cmd
  failed). Consumed by `nodeagent` to drive Maintenance Mode.

## Components

`tpmmgr` lives in a single source file (`cmd/tpmmgr/tpmmgr.go`) with
no internal sub-packages. The logical responsibilities are partitioned
across function groups as follows.

### Lifecycle / pubsub wiring (long-running service)

`Run()` blocks on `wait.WaitForOnboarded()`, subscribes
`ConfigItemValueMap` and `AttestNonce`, creates the publications,
and immediately publishes the three edge-node certificates that
must reach the controller for attestation to work:

* `ecdh.cert.pem` as `CertTypeEcdhXchange`
* `attest.cert.pem` as `CertTypeRestrictSigning`
* `ek.cert.pem` as `CertTypeEk` with the EK's `TPM2B_PUBLIC` attached
  via `getEkCertMetaData()`

`IsTpm` is set per-cert: true only if the TPM is enabled and no soft
fallback key file is present (`etpm.EcdhKeyFile` for ECDH,
`quoteKeyFile` for the quote cert). The EK is always TPM-backed and
is not published when there is no usable TPM.

After `GCInitialized`, `Run()` enters its event loop driving an
hourly `tpmSanityCheckTicker`.

### Single-shot CLI (`runCommand`)

Subcommands and the boot script that invokes each:

| Subcommand | Caller | What it does |
|---|---|---|
| `createDeviceCert` | `device-steps.sh` (TPM present, no soft key file) | TPM-rooted device-identity provisioning — see [Key + cert creation](#key--cert-creation-tpm-rooted-vs-soft). |
| `createSoftDeviceCert` | `device-steps.sh` (no TPM, or `createDeviceCert` failed) | Soft device-identity provisioning. |
| `createCerts` | `device-steps.sh` (TPM present) | TPM-rooted ECDH / quote / EK certs; per-cert soft fallback. |
| `createSoftCerts` | `device-steps.sh` (no TPM) | Soft ECDH and quote certs (no EK). |
| `genCredentials` / `readCredentials` | startup | Generate/read the UUID at `/config/tpm_credential` ↔ NV `0x1600000`. Used as the device-key `userAuth` (see [Key Input/Output](#key-inputoutput)). |
| `saveTpmInfo <file>` | `device-steps.sh` | Dump TPM vendor / firmware description (`etpm.FetchTpmHwInfoDescription`) for diagnostic bundles. |
| `printCapability` / `printPCRs` | manual (debugging) | Print vendor info; read all PCRs (SHA256) and a sample quote. |
| `testTpmEcdhSupport` / `testEcdhAES` / `testEncryptDecrypt` | manual / CI (debugging) | Exercise the ECDH, ECDH-AES, and EncryptDecryptUsingTpm round trips (the same primitives `vaultmgr` and the controller cipher path use). |

### Key + cert creation (TPM-rooted vs soft)

For each non-EK cert (device, quote, ECDH), `tpmmgr` has paired
`create*OnTpm` / `create*Soft` implementations. The TPM-rooted variant
signs via `etpm.TpmPrivateKey` (which routes through the device key
at `0x817FFFFF`); the soft variant generates an in-memory ECDSA P-256
key with `ecdsa.GenerateKey` and writes the matching `.key.pem` next
to the cert. The dispatchers `createQuoteCert` / `createEcdhCert`
prefer TPM and fall back to soft on failure. `createDeviceCert` does
not fall back internally — `device-steps.sh` catches the non-zero
exit and invokes `createSoftDeviceCert`.

`createOtherKeys(override bool)` bulk-creates the EK / SRK / AK /
quote / ECDH keys at their well-known handles. `override=true`
(`createDeviceCert`) wipes and recreates from a fresh owner;
`override=false` (`createCerts`) only fills empty slots. The EK has
no soft variant and is therefore not published when there is no
usable TPM.

### Attestation quote (`getQuote` / `handleAttestNonceImpl`)

`getQuote(nonce)` validates nonce length (12–32 bytes), reads every
PCR 0..23 in the SHA256 bank, and signs PCRs 0..15
(`etpm.PcrListForQuote`) via `tpm2.Quote(TpmQuoteKeyHdl, …)`. The raw
0..23 values ride along in `AttestQuote.PCRs` (unsigned), letting the
controller inspect the dynamic-PCR range without re-deriving the
quote; PCRs 16–23 are deliberately excluded from the signed range.
The signed selection itself is fixed — disk-key sealing in `vaultmgr`
is a separate path with its own controller-configurable selection
(see [PCR selections in evetpm.md](../evetpm/evetpm.md#pcr-selections)).

`handleAttestNonceImpl` calls `getQuote` and publishes
`AttestQuote{Nonce, SigType:EcdsaSha256, Signature, Quote, PCRs}`
keyed on the nonce; `handleAttestNonceDelete` unpublishes on delete.

### TPM sanity check

`tpmSanityCheck()` runs every hour from the long-running service.
It exists because some TPM failures only surface when the device
needs an upgrade or the controller needs a quote — i.e. far too
late. The check verifies the two operations whose failure modes are
not caught by ordinary device traffic:

1. `etpm.EncryptDecryptUsingTpm` round-trip — this is what
   `vaultmgr` uses to wrap/unwrap vault keys; failure means a
   PCR-changing upgrade can no longer be rescued by the controller,
   which would maroon the device on the old image.
2. `tpm2.Quote` with a random nonce — this is what attestation uses;
   failure means the controller cannot verify integrity even if
   `tpmmgr` is otherwise running.

The result is published as `TpmSanityStatus` keyed on the TPM device
path. `nodeagent` watches this publication and lifts the corresponding
maintenance reason when the status flips back to
`MaintenanceModeReasonNone`.

The other TPM-failure paths are caught implicitly: vault seal/unseal
failure sets `VaultStatus=ERROR` (which `nodeagent` handles), and
device-key signing is exercised on every onboarding handshake.

### TSS 2.0 backend

TPM2 commands go through Google's
[`go-tpm`](https://github.com/google/go-tpm) (Apache 2.0). EVE pulls in
both the `legacy/tpm2` API (used by `tpmmgr` and most of `evetpm`) and
the newer top-level `tpm2` (used by `pkg/pillar/evetpm/enc_seal.go` for
encrypted disk-key seal/unseal, where parameter encryption is only
exposed on the v2 API). The full file-by-file split and the v1→v2
migration status are documented in
[`pkg/pillar/evetpm/evetpm.md`](../evetpm/evetpm.md#tss-20-backend).

## Control-flow

There are four largely independent paths through `tpmmgr`.

### 1. First-boot provisioning (single-shot CLI)

```text
device-steps.sh: device.cert.pem missing
  if /dev/tpmrm0 present and /config/device.key.pem absent:
    tpmmgr createDeviceCert
      ├─ initializeDirs()
      ├─ genCredentials()                  /config/tpm_credential + NV 0x1600000
      ├─ readDeviceCert()                  re-read previous cert from NV (idempotent)
      └─ on miss:
         ├─ createDeviceKey()              CreatePrimary at owner hierarchy,
         │                                 EvictControl into TpmDeviceKeyHdl
         ├─ createDeviceCertOnTpm()        x509 cert signed via TpmPrivateKey
         ├─ writeDeviceCert()              /config/device.cert.pem + NV 0x1500000
         └─ createOtherKeys(override=true) EK/SRK/AK/quote/ECDH
    on failure:
      tpmmgr createSoftDeviceCert         soft ECDSA, /config/device.{key,cert}.pem
  else:
    tpmmgr createSoftDeviceCert
```

Then, once `/config/server` and `/config/root-certificate.pem` are
present:

```text
device-steps.sh: provision additional certs
  if /dev/tpmrm0 present and /config/device.key.pem absent:
    tpmmgr createCerts
      ├─ createOtherKeys(override=false)   create only what's missing
      ├─ createEcdhCert()                  TPM-rooted, fall back to soft
      ├─ createQuoteCert()                 TPM-rooted, fall back to soft
      └─ createEkCert()                    TPM-rooted, no soft fallback
  else:
    tpmmgr createSoftCerts                 ECDH + quote, soft only
```

### 2. Boot-time long-running service (`Run()`)

```text
Run()
  └─ wait.WaitForOnboarded()
  └─ subscribe ConfigItemValueMap, AttestNonce
  └─ create publications: AttestQuote, EdgeNodeCert (persistent), TpmSanityStatus
  └─ publishEdgeNodeCertToController(ecdh.cert.pem,    CertTypeEcdhXchange,  IsTpm=…)
  └─ publishEdgeNodeCertToController(attest.cert.pem,  CertTypeRestrictSigning, IsTpm=…)
  └─ publishEdgeNodeCertToController(ek.cert.pem,      CertTypeEk, IsTpm=true,
                                     metaData=getEkCertMetaData())   TPM2B_PUBLIC
  └─ wait for GCInitialized
  └─ if /config/tpm_credential missing: readCredentials()             recover from NV
  └─ start tpmSanityCheckTicker (1h)
  └─ event loop:
       AttestNonce arrives → handleAttestNonceImpl
                           → getQuote() → publish AttestQuote
       AttestNonce deleted → handleAttestNonceDelete → unpublish
       tpmSanityCheckTicker fires → periodicTpmSanityCheck
                                  → publish TpmSanityStatus
```

### 3. Attestation quote

```text
zedagent.AttestNonce{Nonce, Requester} arrives
  → handleAttestNonceImpl
    → getQuote(Nonce)
      ├─ validate len(Nonce) ∈ [12,32]
      ├─ for i in 0..23: tpm2.ReadPCR(i, AlgSHA256)
      └─ tpm2.Quote(TpmQuoteKeyHdl, Nonce, PcrListForQuote=[0..15])
    → asn1.Marshal({R,S})
    → publish AttestQuote{Nonce, SigType:EcdsaSha256, Signature, Quote, PCRs}
zedagent picks up AttestQuote and forwards it to controller.
After controller acks: zedagent removes AttestNonce
  → handleAttestNonceDelete → unpublish AttestQuote
```

### 4. Periodic TPM sanity check

```text
tpmSanityCheckTicker fires (every 1h)
  → periodicTpmSanityCheck
    if !etpm.IsTpmEnabled(): return
    → tpmSanityCheck()
      ├─ EncryptDecryptUsingTpm(msg, true)  encrypt
      ├─ EncryptDecryptUsingTpm(enc,  false) decrypt
      ├─ bytes.Equal(msg, decrypted)?
      └─ getQuote(random nonce)
    on failure:
      → publish TpmSanityStatus{Status:TpmEncFailure | TpmQuoteFailure,
                                ErrorAndTime{...}}
    on success:
      → publish TpmSanityStatus{Status:None}
```

`nodeagent` watches `TpmSanityStatus` and adds/removes the matching
maintenance reason. A device whose TPM has degraded — but is still
running — therefore goes into Maintenance Mode within an hour, well
before the next baseos upgrade attempt.

## Debugging

### PubSub

```sh
ls /persist/status/tpmmgr/EdgeNodeCert/    # one file per cert type
cat /run/tpmmgr/AttestQuote/*.json | jq    # only present during attestation
cat /run/tpmmgr/TpmSanityStatus/*.json | jq
```

`EdgeNodeCert` is the canonical "what does this device claim to be?"
output. `TpmSanityStatus.Status==MaintenanceModeReasonNone` and a
recent `ErrorAndTime` cleared is the "TPM healthy" indicator.

### Files of interest

* `/dev/tpmrm0` — resource-managed TPM device
* `/config/device.cert.pem`, `/config/device.key.pem` — identity cert
  (key file only present on no-TPM platforms)
* `/config/tpm_credential` — TPM credentials cache, mirror of NV
  `0x1600000`
* `/persist/certs/{ecdh,attest,ek}.cert.pem` — published certs
* `/persist/certs/{ecdh,attest}.key.pem` — soft private keys, if any
* `/persist/status/tpm_measurement_seal_success`,
  `/persist/status/tpm_measurement_unseal_fail` — written by
  `pkg/pillar/evetpm` (not by `tpmmgr` itself); used by
  `FindMismatchingPCRs` to diagnose why a vault unseal failed

### Useful CLIs (from a pillar shell)

```sh
/opt/zededa/bin/tpmmgr printCapability       # vendor / firmware info
/opt/zededa/bin/tpmmgr printPCRs             # PCR 0..23 SHA256 + sample quote
/opt/zededa/bin/tpmmgr testTpmEcdhSupport    # ECDHKeyGen + ECDHZGen round trip
/opt/zededa/bin/tpmmgr testEncryptDecrypt    # what vaultmgr's wrap/unwrap relies on
/opt/zededa/bin/tpmmgr testEcdhAES           # full ECDH-AES exchange against ecdh.cert.pem
/opt/zededa/bin/tpmmgr saveTpmInfo /tmp/tpm.txt
```

### Logs

`tpmmgr`'s log records ship through `newlogd` like every other
agent. On a running device, recent (not-yet-uploaded) batches land
under `/persist/newlog/devUpload/` as gzipped JSON; filter on
`source=tpmmgr`:

```sh
zcat /persist/newlog/devUpload/*.gz | jq -c 'select(.source=="tpmmgr")'
```

Once uploaded, the same records are available in the controller's
log store.

### Useful grep patterns

These are literal substrings from log calls in
`pkg/pillar/cmd/tpmmgr/tpmmgr.go`; they have no `printf` directives
and can be fed directly to `grep` (or `jq 'select(.msg | contains(...))'`).

```text
"TPM Quote Nonce"                                       – attestation quote requested by zedagent
"Received quote request from"                           – same line, includes the Requester string
"publishing quote for nonce"                            – AttestQuote being published
"Unpublishing quote for nonce"                          – AttestQuote being removed after controller ack
"TPM sanity check failed"                               – periodic 1h check failed (errored detail follows)
"failed to encrypt key using TPM"                       – TpmEncFailure path (wrapped into TpmSanityStatus.ErrorAndTime)
"failed to get quote using TPM"                         – TpmQuoteFailure path (wrapped into TpmSanityStatus.ErrorAndTime)
"readDeviceCert success"                                – first-boot path found cert in NV index 0x1500000
"readDeviceCert failed"                                 – first-boot path actually creating the device key (subsequent log line: "generating new key and cert")
"CreatePrimary failed"                                  – TPM owner-hierarchy refusal; usually means BIOS reset needed
"Error in creating Endorsement Key Certificate"         – EK cert creation failed (no soft fallback; cert simply not published)
"publishEdgeNodeCertToController failed: no cert file"  – cert PEM missing on disk
```

### Forcing transitions for development

* **Trigger the sanity-check failure path**: replace `/dev/tpmrm0`
  with a `swtpm` instance whose state has been damaged (e.g. force
  a key handle to be evicted). The next `tpmSanityCheckTicker` tick
  will publish `TpmSanityStatus{Status:TpmEncFailure}`, and within
  10s `nodeagent` will add `MaintenanceModeReasonTpmEncFailure` to
  `NodeAgentStatus.LocalMaintenanceModeReasons`.
* **Force soft fallback on an already-onboarded device**: drop a
  (dummy) `/config/device.key.pem` file. `etpm.IsTpmEnabled()` is
  defined as `device.cert.pem exists AND device.key.pem does NOT
  exist`, so the soft key file makes it return `false`; subsequent
  `EdgeNodeCert` publications carry `IsTpm=false`. This does not
  retro-actively unwind earlier TPM state — keys at the well-known
  handles remain, and an EK cert that was already published stays in
  `/persist/certs/`. To exercise the no-TPM provisioning paths from
  scratch, omit `/dev/tpmrm0` before the first `device-steps.sh` run
  on a fresh install.
* **Re-issue device cert without re-onboarding**: delete
  `/config/device.cert.pem` and reboot. `device-steps.sh` will
  re-invoke `tpmmgr createDeviceCert`, which finds the previous cert
  in NV `0x1500000` via `readDeviceCert()` and restores it — no
  re-onboarding required.

## Further reading

* [EVE Security Architecture](../../../docs/SECURITY-ARCHITECTURE.md) —
  device identity, onboarding, attestation, and the broader EVE
  security foundation that `tpmmgr` plugs into.
* [Trusted Computing Group](https://trustedcomputinggroup.org) — the
  governing body for TPM specifications.
* [`go-tpm`](https://github.com/google/go-tpm) — the Go library
  `tpmmgr` and `pkg/pillar/evetpm` use to drive the TPM (Apache 2.0).
