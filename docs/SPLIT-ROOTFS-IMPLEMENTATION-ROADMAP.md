# Split Rootfs Implementation Roadmap

## 1. Purpose and Scope

EVE's rootfs is approaching the partition size limit on legacy devices. This document
defines the complete implementation roadmap for splitting the monolithic rootfs into a
Core Image and an Extension Image, including:

- Making the Core Image hypervisor-agnostic (one image for KVM, Xen, and Kubevirt)
- Security design choices for Extension Image integrity and attestation
- How split rootfs affects every installation method (USB, iPXE)
- How split rootfs integrates with the existing A/B update mechanism
- Relative effort estimation for each implementation path

The security analysis is central. Every architectural choice - where the
Extension Image lives on disk, how it is verified, whether it participates in
TPM measurement  and sealing - affects the installation flow, upgrade flow, 
and controller integration. These connections are discussed together, not 
in isolation.

Effort estimates are relative, using the USB boot priority feature as a calibration point.
That work touched EVE API protobuf definitions, pillar type system, zedagent with LPS
integration, KVM hypervisor layer, UEFI firmware patches (EDK2), and documentation —
approximately 2,700 hand-written lines across 42 files in 6 subsystems over 
~9 weeks of concentrated effort. It is assigned **8 story points** and serves as the
reference for all estimates in this document.

Where controller-side changes are needed, the scope is identified but the work belongs to
a separate team. Controller-side effort is outside our control and represents a scheduling
risk: device-side work that depends on controller changes cannot ship until the controller
team delivers. Approaches that require controller-side coordination are flagged throughout
this document. All effort estimates are device-side unless explicitly marked otherwise.

## 2. Current Baseline: How EVE Boot, Measurement, and Sealing Work Today

Understanding the current security model is essential before evaluating what split rootfs
changes. This section describes what `origin/master` does today.

### Boot Chain

EVE uses a two-stage GRUB architecture:

```
Firmware (UEFI/BIOS)
  └─ Loads 1st-stage GRUB from EFI partition [written once at install, never updated]
       └─ gptprio.next selects highest-priority partition (IMGA or IMGB)
       └─ Chainloads 2nd-stage GRUB from inside the selected squashfs
            └─ measurefs $root --pcr 13    [measures entire rootfs into TPM]
            └─ Loads kernel from squashfs
            └─ Passes root=PARTUUID=<squashfs-partition> to kernel
                 └─ Kernel mounts squashfs directly as read-only root
                      └─ Linuxkit init → containerd → pillar agents
```

The 1st-stage GRUB is the only component that cannot be updated after deployment. All boot
logic, TPM measurement, and hardware detection live in the 2nd stage, which ships with
every rootfs update.

### TPM and PCR Registers

EVE supports devices both with and without TPM. On TPM-enabled devices, attestation and
vault sealing use TPM2 PCR values from the SHA256 bank. In current EVE policy, PCR indexes
0–15 are used for quote and sealing decisions. Each PCR is a 256-bit SHA256 register with
two key properties:

- **Extend-only**: `PCR[n]_new = SHA256(PCR[n]_current || measurement)`. You cannot write
  arbitrary values.
- **Reset only on reboot**: Once extended, a PCR value cannot be undone until power cycle.

Current PCR usage in EVE:

| PCR | Extended By | Contains | In Sealing Set? |
|-----|-------------|----------|-----------------|
| 0–4 | UEFI firmware, GRUB | Firmware, bootloader, kernel | Yes (except 5) |
| 5 | UEFI | GPT partition table, boot manager config | **No** (volatile) |
| 6–7 | UEFI | Secure Boot state, boot variables | Yes |
| 8–9 | GRUB | GRUB commands, binary modules | Yes |
| 10–11 | (unused) | All zeros | Yes |
| **12** | **(unused)** | **All zeros** | **Yes** |
| 13 | GRUB (`measurefs`) | Rootfs squashfs hash | Yes |
| 14 | `measure-config` | /config partition file hashes | Yes |
| 15 | (unused) | All zeros | **No** (reserved for OS/user) |

### Sealing: Disk Encryption Key Protection

EVE seals the disk encryption key (for `/persist/vault/`) to specific PCR values. The TPM
only releases the key if current PCR values match the values recorded at seal time.

**Default sealing PCR set** (from `pkg/pillar/evetpm/tpm.go:120-135`):

```
{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14}
```

This is all PCRs from 0 to 14, excluding PCR 5 (volatile GPT state) and PCR 15 (reserved).

**Critical detail**: PCRs 10, 11, and 12 are currently all-zeros because nothing extends
them. Sealing works because zero is a consistent, reproducible value. If any code begins
extending one of these PCRs, the sealed value changes, and vault unsealing fails on next
boot. This is not a bug — it is an intentional property of measured boot. But it means that
adding new PCR measurements requires deliberate policy migration.

The controller can also provide a custom PCR policy (via `VaultKeyPolicyPCR`) that overrides
the default. This is the mechanism for planned PCR policy changes during rollout.

### Attestation: How the Controller Verifies Device State

EVE periodically proves to the controller what software is running:

1. Controller sends a nonce (random challenge).
2. Device asks TPM to sign all 16 PCR values together with the nonce.
3. Device sends the signed quote back to controller.
4. Controller validates: signature from real TPM, nonce is fresh, PCR values match
   expected baseline.

**Attestation quotes include all PCRs 0–15** (`PcrListForQuote` in
`pkg/pillar/evetpm/tpm.go:171`), including currently-unused PCRs like 10, 11, 12. This
means the controller already sees these zero-valued PCRs and has baselines for them.

### PCR Baseline Management

The controller uses "trust on first use with operator approval":

- **First boot**: Device sends PCR values. Operator reviews and accepts as baseline.
- **Normal operation**: PCR values match baseline. Attestation passes automatically.
- **PCR change** (e.g., after EVE update): Controller flags mismatch. Operator reviews
  and accepts new baseline (routine for expected updates).

### Update and Vault Recovery

When EVE is updated, PCR values change (new kernel, new rootfs). The vault key sealed to
old PCR values cannot be unsealed. Recovery uses a two-party key escrow:

1. Encrypted backup of vault key is stored on controller.
2. After update + reboot, device re-attests with new PCR values.
3. Controller checks if new values match a known EVE version profile.
4. If recognized: automatic recovery — controller sends encrypted backup key.
5. Device decrypts backup, re-seals vault key to new PCR values.
6. If not recognized: blocked until operator reviews.

This mechanism already exists and works for PCR 13 changes (rootfs updates). Any new PCR
measurement (for Extension Image) would follow the same recovery path — as long as the
controller is aware of the new PCR behavior.

### What This Means for Split Rootfs

In master today, all services that would move to Extension are inside the monolithic rootfs.
They are covered by PCR 13 measurement (GRUB measures the entire squashfs). After split:

- Core Image stays in IMGA/IMGB, measured into PCR 13 by GRUB. No change.
- Extension Image is a separate artifact. Its security posture depends on design choices
  covered in the rest of this document.

The key question is not "is Extension secure?" but rather "what level of security assurance
does each approach provide, and what does each cost to implement?"

## 3. Problem Statement

### The Immediate Problem

EVE's rootfs is approaching partition size limits:

| Variant | Current Size | Limit | Headroom |
|---------|-------------|-------|----------|
| amd64-kvm-generic | ~277MB | 300MB | 23MB |
| arm64-kvm-nvidia-jp6 | ~446MB | 512MB | 66MB |

Legacy devices (pre-10.10.0) have 300MB partitions; newer installations (including
nvidia JP6) default to 512MB. CVE fixes and new dependencies are consuming the
remaining space. Generic variants on legacy partitions are closest to the limit — some
cannot receive routine security updates without partition resizing.

### Why 300MB?

The limit exists for backward compatibility. EVE 10.10.0 increased the default to 512MB
for new installations, but devices deployed before that release still have the old partition
layout. Resizing requires maintenance windows that operators may not schedule for urgent
CVE patches. The installed base of 300MB devices is a hard constraint.

### The Strategic Problem

EVE currently produces many different builds for different hypervisor and hardware
combinations. A modular approach — one base image with pluggable extensions — would reduce
build matrix complexity and simplify fleet management.

### What Can Move Out of Rootfs

Analysis of the rootfs content shows which packages can move to a separate image.
The POC Extension template (`images/rootfs_ext.yml.in`) defines the package set:
eve-debug, eve-vtpm, eve-wwan, eve-vector, eve-kube (HV=k only), guacd, edgeview,
memory-monitor, node-exporter.

Size estimates below are derived from build experiments on `master` at commit `94c51ee`
(see *Single Image Evaluation* report). The experiments measured effective rootfs size
reduction by removing package subsets and rebuilding. Because container layers are shared,
savings are not a simple sum of individual image sizes — each row was measured as a group.
The experiment's package sets do not match the POC exactly (see notes), so actual savings
need validation with the final Extension build.

| Variant | Measured Savings | Resulting Core | Notes |
|---------|-----------------|----------------|-------|
| amd64-kvm-generic | ~38MB → ~239MB | from ~277MB | Experiment removed eve-wwan, eve-debug, eve-vtpm. POC Extension adds vector, guacd, edgeview, memory-monitor, node-exporter — actual savings will be larger. |
| arm64-kvm-generic | ~35MB → ~218MB | from ~253MB | Same as above. |
| arm64-kvm-nvidia-jp6 | ~166MB → ~280MB | from ~446MB | Experiment removed eve-nvidia in addition to the Extension set. POC does not move eve-nvidia — actual savings will be smaller. |
| amd64-kubevirt-generic | ~112MB → ~268MB | from ~380MB | Experiment removed eve-wwan, eve-kube. POC Extension adds more packages — actual savings will be larger. |

Generic variants on legacy 300MB partitions are the most space-constrained. The measured
~38MB saving is a lower bound — the full POC Extension set moves additional packages and
will save more. The nvidia variant is the most challenging: without moving eve-nvidia,
it may not fit under 300MB (but it uses 512MB partitions, so the constraint is softer).

### Two Problems, One Solution

Split rootfs addresses both problems simultaneously: it keeps Core under the partition
limit, and when combined with a generic (HV-agnostic) Core Image, it reduces the build
matrix to one core artifact per architecture.

## 4. Generic Core Image: One Image for All Hypervisors

### Why This Matters for Split Rootfs

If Core Image remains hypervisor-specific (separate builds for KVM, Xen, Kubevirt), the
split produces N core images times M extension images. Making Core generic means one core
image per architecture, with HV selection at runtime. This simplifies:

- **Build system**: one Core build target instead of per-HV targets
- **Security**: one PCR 13 baseline per architecture, not per HV variant
- **Fleet management**: one update package per architecture
- **Testing**: one boot path to validate

### Key Insight: KVM, Xen, and Kubevirt Share Binaries

Analysis of the pillar codebase shows that the same Go binary can run on all three
hypervisors. Today, the `//go:build k` tag conditionally compiles Kubevirt-specific code —
without this tag, `kubeapi/`, `cmd/zedkube/`, and related files are excluded from the build.
This produces different binaries for different HV types.

**The goal is to eliminate build tags entirely and produce one identical binary.** All
Kubevirt-specific code is compiled unconditionally. HV-specific behavior is gated purely
at runtime by reading `/run/eve-hv-type`. This guarantees that the Core Image is
byte-identical across KVM, Xen, and Kubevirt deployments on the same architecture.

Xen packages (xen.gz, xen-tools) are already included in all rootfs variants regardless
of HV type. Once pillar is also HV-agnostic, the entire Core Image becomes universal.

### Runtime Guard Architecture

With build tags removed, all HV-specific code is always present in the binary. Safety is
ensured by runtime guards:

**Runtime guard** (`pkg/pillar/kubeapi/runtimeguard.go`): Every exported function in the
kubeapi package calls `ensureKubeRuntime()`, which checks `base.IsHVTypeKube()`. If the
HV type is not `k`, the function returns an error immediately. This prevents Kubevirt code
from executing on KVM/Xen devices.

```go
// pkg/pillar/kubeapi/runtimeguard.go
func ensureKubeRuntime(op string) error {
    if base.IsHVTypeKube() {
        return nil
    }
    return fmt.Errorf("%s: kube runtime is not enabled", op)
}
```

Runtime detection reads from `/run/eve-hv-type`, which is written at boot time by GRUB
(from CONFIG partition) or falls back to `/etc/eve-hv-type` (baked into rootfs at build
time).

### CONFIG Partition as HV Selector

The HV type is determined by a chain of overrides:

```
CONFIG partition /eve-hv-type   (set by ZFlash at flash time)
  ↓ overrides
/etc/eve-hv-type                (baked into rootfs at build time)
  ↓ read by
GRUB → writes /run/eve-hv-type
  ↓ read by
storage-init.sh → selects ext4 or ZFS for persist
onboot.sh → propagates to runtime
pillar agents → base.IsHVTypeKube(), hypervisor.BootTimeHypervisor()
extsloader → skips HV-specific services (e.g., kube requires HV=k)
```

This means HV selection happens at flash time (via ZFlash) or install time (via CONFIG
partition content), not at build time. A single installer image supports all HV types.

### Security Implication

With a generic Core Image, PCR 13 produces the same value on all devices running the same
EVE version on the same architecture, regardless of HV type. This simplifies attestation
baseline management: the controller maintains one expected PCR 13 value per
{architecture, version} pair, not per {architecture, version, HV} triple.

### What Needs to Change (from master)

| Area | Change | Scope |
|------|--------|-------|
| `pkg/pillar/kubeapi/` | Add runtime guards to all exported functions | ~50 call sites |
| `pkg/pillar/hypervisor/kubevirt.go` | Add `IsHVTypeKube()` fail-fast checks | ~5 entry points |
| `pkg/pillar/cmd/zedkube/` | Gate startup by HV type | Startup check |
| `pkg/pillar/cmd/zedmanager/` | Conditional subscription to ENClusterAppStatus | 1 subscription |
| `pkg/pillar/cmd/volumemgr/` | Gate PVC disk metrics by HV type | 2 checks |
| All `//go:build k` files | **Remove build tags** — compile unconditionally | ~20 files |
| `pkg/pillar/scripts/device-steps.sh` | Conditional zedkube agent startup | Shell check |
| `pkg/pillar/scripts/onboot.sh` | Propagate CONFIG eve-hv-type to /run | File copy |
| `pkg/storage-init/storage-init.sh` | Select ext4/ZFS based on HV type | Shell check |
| `pkg/grub/rootfs.cfg` | Read eve-hv-type from CONFIG | GRUB variable |
| `images/rootfs_core.yml.in` | Single pillar binary (no HV-specific builds) | Template change |
| `Makefile` | Remove per-HV pillar targets, add split targets | Build cleanup |

Removing build tags requires verifying that all kube-specific code paths are properly
guarded at runtime. Any function that currently relies on "this code is only compiled for k"
must have an explicit runtime check added. This is methodical but must be thorough — a
missed call site could attempt kube operations on a KVM device.

**Effort estimate: 2 story points development** (device-side only; Eden testing in
Section 10). Smaller than USB boot priority's development portion (~3 SP): mostly
mechanical runtime guard insertion (~50 call sites, each following the same pattern),
build tag deletion (~20 files), and GRUB/shell plumbing. POC `runtimeguard.go` already
exists. No API proto changes, no firmware patches, no LPS integration.

## 5. Split Rootfs Architecture

### Overview

The monolithic rootfs is split into two images:

- **Core Image** (~240MB, squashfs): Kernel, init, pillar, containerd, networking, firmware,
  Extension Loader. Lives on IMGA/IMGB partitions. Measured into PCR 13 by GRUB.

- **Extension Image** (erofs + dm-verity): Non-critical services — eve-debug, eve-vtpm,
  eve-wwan, eve-vector, memory-monitor, edgeview, guacd, node-exporter, eve-kube (HV=k
  only). Lives on PERSIST partition. Loaded after boot by Extension Loader.

### Image Format

Core Image stays squashfs — the entire boot chain depends on it (GRUB reads from it,
kernel mounts it directly).

Extension Image uses erofs + dm-verity. erofs is a read-only filesystem designed for fast
mount and page-aligned access. dm-verity provides a Merkle hash tree that validates every
block read from the filesystem. The combination means:

- At build time: erofs image is created, dm-verity hash tree is generated and appended,
  root hash is recorded.
- At runtime: Extension Loader sets up a loop device, calls `veritysetup` with the trusted
  root hash, mounts the verified device read-only.
- Any modification to the underlying file causes dm-verity to return I/O errors on affected
  block reads.

**Why not squashfs for Extension?** squashfs provides one-time verification (check hash at
mount time). dm-verity provides continuous block-level verification. Since Extension lives
on a writable partition (PERSIST), dm-verity matters: an attacker who gains write access to
PERSIST cannot inject modified content without triggering I/O errors. With squashfs alone,
modifications would go undetected until the next reboot's hash check.

### dm-verity Root Hash Trust Chain

The dm-verity root hash is embedded in the Core Image at build time
(`/etc/ext-verity-roothash`). Since the Core squashfs is measured into PCR 13 by GRUB,
the root hash is transitively protected by the TPM-measured boot chain:

```
PCR 13 (GRUB) seals Core squashfs
  └─ Core squashfs contains /etc/ext-verity-roothash
      └─ dm-verity validates every block of Extension erofs
```

This means Core and Extension are cryptographically bound: changing Extension requires
changing Core (new root hash), which changes PCR 13 (new squashfs hash). They are always
the same version.

### Extension Loader (extsloader)

The Extension Loader is a pillar agent inside Core that manages the Extension lifecycle:

1. Wait for PERSIST to be accessible (and vault to be unlocked, if Extension is in vault)
2. Determine active partition (IMGA or IMGB) via `zboot.GetCurrentPartition()`
3. Find Extension Image at the corresponding path
4. Read dm-verity root hash from `/hostfs/etc/ext-verity-roothash`
5. Set up loop device + dm-verity (`veritysetup open`)
6. Mount verified erofs read-only
7. Start services via containerd (filtered by HV type for kube-specific services)
8. Periodically verify running services, restart if needed

### Graceful Degradation

If Extension fails (missing, corrupted, verification failure), the device enters degraded
mode:

- **Running**: nim, zedagent, baseosmgr (controller communication + update capability)
- **Not running**: Extension services, workload VMs and containers
- **Purpose**: Device stays reachable so operator can push update or trigger rollback

Degraded mode is intentionally conservative: no workloads run, reducing the risk surface
when part of the platform is not verified.

### Core vs Extension Service Allocation

**Core Image**: kernel, init, firmware, pillar (nim, zedagent, domainmgr, volumemgr,
baseosmgr, etc.), containerd, networking (wlan, dnsmasq), Extension Loader
(extsloader), watchdog, monitor, apparmor, measure-config.

**Extension Image** (from `images/rootfs_ext.yml.in`): eve-debug, eve-vtpm, eve-wwan,
eve-vector, memory-monitor, node-exporter, edgeview, guacd, eve-kube (HV=k only).

### Build System

Two Linuxkit YAML templates define the split content:

- `images/rootfs_core.yml.in` — Core: full bootable Linuxkit spec (kernel, init, onboot,
  services, files) using the universal pillar binary.
- `images/rootfs_ext.yml.in` — Extension: services-only manifest (no kernel, no init).
  Lists the OCI containers to include in the Extension Image.

**Core Image build** follows the existing pipeline: `linuxkit build -o tar` produces a tar
of the rootfs tree, which is piped into `pkg/mkrootfs-squash` to create a squashfs image.
No changes to the existing flow.

**Extension Image build** requires a new pipeline. LinuxKit can extract the service
containers from `rootfs_ext.yml.in` into a tar, but the conversion to erofs is not part
of the existing EVE build tooling. The build system needs:
- `mkfs.erofs` added to the build tools (either a new `pkg/mkrootfs-erofs` package
  following the pattern of `pkg/mkrootfs-squash`, or a standalone build script)
- `veritysetup` to generate the dm-verity hash tree and root hash
- A build step that embeds the root hash into the Core Image (`/etc/ext-verity-roothash`)
  before creating the Core squashfs

This creates a build ordering dependency: Extension Image must be built first (to produce
the root hash), then Core Image is built with the root hash embedded.

Build: `make split_rootfs` produces both `rootfs-core.img` and `rootfs-ext.img`.

## 6. Security Design Space: Three Key Questions

The split introduces three independent security design choices. Each choice affects
implementation effort, controller integration, and operational behavior. They can be
combined independently, producing different security postures at different costs.

### Question 1: Should Extension Image participate in PCR measurement?

**Option 1A — No PCR measurement**: Extension Loader verifies the image via dm-verity and
reports health to the controller through normal telemetry. No PCR is extended.

- **Local integrity**: Strong. dm-verity prevents loading tampered content. Root hash in
  Core (measured by PCR 13) ensures only the correct Extension is accepted.
- **Remote assurance**: Controller relies on software-reported health telemetry for Extension
  state. If the telemetry path is broken, delayed, or compromised, the controller has no
  independent signal for Extension.
- **Sealing impact**: None. No PCR changes, no policy migration needed.
- **Controller work**: Minimal — controller needs to display Extension health status, but
  no PCR-related changes.

Realistic scenario — telemetry gap:
> Extension fails locally. Health publication path is delayed. Controller sees Core
> attestation is normal (PCR 13 matches). Without PCR evidence for Extension, controller
> confidence depends on fail-closed treatment of unknown status.

**Option 1B — PCR measurement (userspace)**: Extension Loader extends a designated PCR
(e.g., PCR 12) with the Extension Image hash after verification. Attestation quotes
include this PCR, giving the controller a hardware-signed signal for Extension state.

Multi-step measurement creates diagnosable states:

```
Boot starts:           PCR = 0x0000...     (loader hasn't run)
Loader starts:         PCR = extend(0, "extsloader:starting")
Image verified+mounted: PCR = extend(prev, SHA256(extension.img))
Services running:      PCR = extend(prev, "extsloader:services-running")

OR on failure:         PCR = extend(prev, "extsloader:failed:<reason>")
```

Controller can distinguish: loader never ran (PCR = zero) vs. loader ran but Extension
failed vs. Extension loaded successfully.

- **Local integrity**: Same as 1A (dm-verity).
- **Remote assurance**: Stronger. Controller has TPM-signed evidence of Extension state
  independent of software telemetry. Fleet-wide drift detection is more reliable.
- **Sealing impact**: Depends on Question 2 (below).
- **Controller work**: Controller must understand the new PCR, maintain baselines, and
  correlate PCR state with Extension health telemetry.

Trust chain clarification: This measurement happens in userspace, but it is still chained
to the measured boot. Extension Loader runs inside Core, which was measured into PCR 13 by
GRUB. If Core is compromised, PCR measurements from userspace cannot be trusted — but if
Core is compromised, the entire platform is compromised regardless. The practical security
value of userspace PCR measurement is high for detecting Extension-specific failures while
Core remains intact.

**Why not GRUB-stage measurement?** A third option would be to place the Extension Image
on dedicated partitions (EXTA/EXTB) and have GRUB measure it directly, like it does for
Core (PCR 13). This would provide the strongest remote assurance (boot-chain-level
measurement). However, it requires changing the GPT partition table layout, which we want
to avoid: it touches `make-raw`, `storage-init`, the installer, and every existing device
needs a migration path. ZFS devices cannot shrink P3 at all. The cost is disproportionate
to the security benefit over userspace PCR measurement (1B), which already provides
TPM-attested Extension state.

| | 1A: No PCR | 1B: Userspace PCR |
|--|-----------|-------------------|
| Local integrity | dm-verity | dm-verity |
| Remote assurance | Telemetry only | TPM-attested |
| Controller change | Minimal | New PCR baseline |
| Device change | Loader + dm-verity | + PCR extend code |
| Migration risk | None | PCR policy (Q2) |
| **Effort (dev only)** | **3 SP** | **4 SP** |

The 3 SP base (Option 1A) covers the full Extension Loader: dm-verity setup, erofs mount,
service management, and degraded mode. The effort delta between 1A and 1B is moderate:
the PCR extend code itself is small, but it introduces the sealing policy question (Q2)
and requires controller coordination.

### Question 2: Should the Extension PCR be in the sealing set?

This question only applies if PCR measurement is chosen (1B). If no PCR measurement
(1A), this is moot.

**Option 2A — Not in sealing set (attestation only)**: The Extension PCR is used for
attestation (controller can verify), but vault unsealing does not depend on it.

- **Graceful degradation preserved**: If Extension fails, vault still unseals, Core boots
  fully, device is reachable for recovery.
- **Policy migration required**: The default sealing set includes PCRs 0–14 (except 5, 15).
  If we choose a PCR in this range (like 12), we must update the sealing policy to exclude
  it before rollout. This requires the controller to push a new `VaultKeyPolicyPCR` that
  omits the Extension PCR, or a code change to the default.
- **Controller work**: Must push updated sealing policy to all devices before Extension PCR
  starts being extended. This is a one-time fleet-wide policy update.

**Option 2B — In sealing set**: Vault unsealing requires Extension PCR to match.

- **Strongest binding**: A device with wrong Extension cannot access encrypted data.
- **No degradation vs master**: If the vault fails to unseal today (e.g., after an update
  changes PCR 13), the device already enters the same state: nodeagent triggers maintenance
  mode after 5 minutes, baseosmgr/downloader/verifier block on `WaitForVault()`, no
  workloads run, but nim/zedagent/nodeagent stay up for controller communication and
  device reporting. Adding Extension PCR to the sealing set does not change this behavior
  — it just adds one more reason the vault might not unseal (Extension PCR mismatch),
  alongside the existing Core PCR mismatch. The recovery path is the same: controller
  sends backup key, vault re-seals to new PCR values.
- **Update complexity**: Every EVE update changes the Extension PCR. Vault recovery must
  handle this alongside the existing PCR 13 change. The two-party key escrow mechanism
  already handles this pattern, but it doubles the number of changing PCRs per update.

**Recommendation**: Option 2A (attestation only, not in sealing) is simpler to roll out
because it avoids the PCR policy migration coordination. But 2B is viable — it does not
degrade device behavior compared to how master handles vault unsealing failures today.

| | 2A: Not in sealing | 2B: In sealing |
|--|-------------------|----------------|
| Degraded mode | Works (vault unseals) | Same as master vault-failure behavior |
| baseosmgr (updates) | Works | Blocked until vault recovery (same as today) |
| Extension required for boot | No | No (but vault locked without it) |
| Policy migration | One-time PCR exclusion | None (already in set) |
| Update recovery | Same as today | More PCRs changing per update |
| **Effort (dev only)** | **+0.5 SP** (policy migration) | **+0 SP** (no code changes needed) |

### Question 3: Should Extension Image live inside the vault directory?

The vault (`/persist/vault/`) is encrypted by a key sealed to TPM PCRs. It is only
accessible after `vaultmgr` successfully unseals the vault key.

**Option 3A — Outside vault (plaintext on PERSIST)**: Extension Image at
`/persist/ext-imga.img`, `/persist/ext-imgb.img`.

```
Boot ordering:
  storage-init mounts /persist     ← Extension accessible HERE
      ↓
  extsloader verifies + mounts     ← runs immediately
      ↓
  vaultmgr unseals vault           ← happens in parallel
```

- **Pro**: Extension services start earlier (no vault dependency). Simpler implementation.
- **Con**: An offline attacker (physical access, boots from USB) can read and modify the
  Extension file on PERSIST. Modification is caught by dm-verity on next boot (image won't
  load), but the attacker achieves denial of service (forces degraded mode). The attacker
  can also delete the file entirely.
- **Security**: dm-verity catches tampering. Attacker cannot inject malicious code into
  Extension. The worst case is DoS (forced degraded mode).

**Option 3B — Inside vault** (`/persist/vault/ext-imga.img`,
`/persist/vault/ext-imgb.img`):

```
Boot ordering:
  storage-init mounts /persist     ← vault encrypted, Extension NOT accessible
      ↓
  vaultmgr unseals vault           ← must complete first
      ↓
  extsloader verifies + mounts     ← can only run AFTER vault unlock
```

- **Pro**: Offline attacker cannot read Extension contents and cannot perform targeted,
  content-level modification without unlocking the vault key.
- **Con**: Extension services start later (after vault unlock). During updates when PCRs
  change, vault cannot unseal until controller provides backup key. During this window,
  Extension is inaccessible. However, Core services (including controller communication)
  run independently. Also, offline deletion/corruption of the encrypted Extension file is
  still possible and remains a DoS vector.
- **Security**: Adds at-rest confidentiality and raises the bar for offline tampering.
  dm-verity still enforces runtime integrity. This does not fully prevent offline DoS.

**Upgrade path implication**: Vault placement directly affects the system upgrade flow.

With **3A (outside vault)**, the upgrade path is straightforward:
1. baseosmgr downloads new Core + Extension.
2. Writes new Core to inactive IMGA/IMGB partition.
3. Writes new Extension to `/persist/ext-{inactive}.img`.
4. Device reboots. New PCR values → vault sealed to old values → vault recovery needed.
5. But Extension is **outside** vault — accessible immediately regardless of vault state.
6. Extension Loader can verify and mount the new Extension while vault recovery proceeds
   in parallel. Extension services start without waiting for vault.

With **3B (inside vault)**, the upgrade path has an additional dependency:
1. Same download and write (baseosmgr can write to vault because vault is still unlocked
   during the pre-reboot phase — PCR values haven't changed yet).
2. Device reboots. New PCR values → vault cannot unseal.
3. Extension Image is **inside** vault — encrypted, inaccessible.
4. Device runs in degraded mode (Core only) until vault recovery completes.
5. Controller provides backup key → vault unseals → Extension becomes accessible.
6. Extension Loader verifies and mounts. Extension services start.

The degraded-mode window during vault recovery is typically short (seconds to minutes,
depending on controller reachability). Core services handle controller communication, so
recovery proceeds normally. But for deployments with intermittent connectivity, this window
could be longer.

**Trade-off summary**:

| | 3A: Outside vault | 3B: Inside vault |
|--|------------------|------------------|
| Extension start time | Earlier (parallel with vault) | Later (after vault unlock) |
| Extension during update | Available immediately after reboot | **Unavailable until vault recovery** |
| Offline DoS prevention | No (can delete/corrupt file) | No (delete/corrupt still possible) |
| Offline tampering | Caught by dm-verity | Harder (encrypted at rest) + dm-verity at load time |
| Upgrade complexity | Simpler | Vault recovery dependency |
| Implementation complexity | Simpler | Vault unlock ordering |
| **Effort (dev only)** | **baseline** | **+1.5 SP** (vault dependency + upgrade ordering) |

**Recommendation**: Option 3B (inside vault) for production deployments where physical
access is a concern. Option 3A for environments where offline DoS is not a significant
threat and faster Extension availability during updates is preferred. This could also be
a per-deployment configuration rather than a build-time decision — the Extension Loader
can check both locations with vault-path preferred.

### Combined Security Approaches

The three questions produce independent choices that combine into overall security postures.
Three practical combinations:

**Approach A — Speed-first (1A + 3A)**: dm-verity only, no PCR, outside vault.
- Fastest to implement. Strong local integrity. Weakest remote assurance.
- Controller relies on telemetry for Extension state.
- Extension available immediately after update reboot (no vault dependency).
- **Security-specific dev effort: 3 SP.** Controller: 2 SP (×2 = 4 SP effective).
- **Controller dependency**: Low. Health display is additive, not a blocker for device work.

**Approach B — Balanced (1B + 2A + 3B)**: dm-verity + userspace PCR (not in sealing) +
vault placement.
- TPM-attested Extension state. Offline DoS prevention. Graceful degradation preserved.
- Requires PCR policy migration before rollout.
- Extension unavailable during post-update vault recovery window.
- **Security-specific dev effort: 6 SP.** Controller: 5 SP (×2 = 10 SP effective).
- **Controller dependency**: High. PCR policy must be deployed fleet-wide **before**
  PCR-enabled images ship. Device work is blocked on controller delivery for production
  rollout.

**Approach B' — Balanced without vault (1B + 2A + 3A)**: dm-verity + userspace PCR +
outside vault.
- Same TPM-attested Extension state. No offline DoS prevention. Simpler upgrade path.
- Extension available immediately after reboot.
- **Security-specific dev effort: 4.5 SP.** Controller: 5 SP (×2 = 10 SP effective).
- **Controller dependency**: Same as B — high.

These are development-only, security-choice-specific estimates. Full effort including
shared work (Generic Core Image, build system, installer, baseosmgr) and Eden testing
is in Section 10.

## 7. Installation Flows

EVE can be installed via several methods. Each method must deliver the Extension Image to
the device alongside the Core Image. The security approach (from Section 6) affects where
and how the Extension Image is placed.

### Current Installation: Single Rootfs

In master, every installation method writes one `rootfs.img` to the IMGA partition. The
installer (`pkg/installer/install`) receives the rootfs via `/bits/rootfs.img` (bound from
the installer Linuxkit config in `images/installer.yml.in`). `make-raw` creates the GPT
layout, `dd` copies the squashfs directly to the partition.

### Split Installation: Core + Extension

With split rootfs, the installer must deliver two artifacts:
- Core Image → IMGA partition (same as today's rootfs.img)
- Extension Image → PERSIST partition (as a file)

The Core Image write is identical to today. The new step is placing the Extension Image.

### Method 1: USB Installer

The standard installation path. User boots from USB media containing the installer.
The USB media is typically prepared using ZFlash (see Section 9), which writes the
installer `.raw` image to the USB stick. With universal images, ZFlash will also
parametrize the CONFIG partition (e.g., setting the HV type) — this capability exists
as a local prototype but is not yet in production. ZFlash is a preparation tool — the
actual installation runs on the target device.

**Current flow** (`pkg/installer/install`):
```
1. Boot installer from USB
2. Probe for destination disk (eve_install_disk= or auto-detect)
3. Create GPT partition table (make-raw): EFI, IMGA, IMGB, CONFIG, P3
4. Write rootfs.img → IMGA partition (dd)
5. Initialize PERSIST (ext4 or ZFS based on HV type)
6. Write CONFIG partition (certs, server URL)
7. Mark IMGA as bootable (GPT priority)
```

**Split flow additions**:
```
4a. Write Core Image → IMGA partition (dd, same as today)
5a. Initialize PERSIST
5b. [If vault placement (3B)]: vaultmgr creates vault on first boot,
    Extension copied to /persist/vault/ext-imga.img after vault init
    [If plaintext (3A)]: copy Extension to /persist/ext-imga.img during install
```

For vault placement (3B), the installer cannot write directly into the vault because vault
encryption is set up on first boot by `vaultmgr`, not during installation. Two options:

**Option A — First-boot copy**: Installer places Extension at a temporary location
(`/persist/ext-staging.img`). On first boot, after vault is created, Extension Loader moves
it into `/persist/vault/ext-imga.img`.

**Option B — Installer initializes vault**: The installer calls `vaultmgr`-like code to
create vault and seal the key during installation. More complex but Extension is in vault
from the start.

For plaintext placement (3A), the installer simply copies the file during installation.
No first-boot step needed.

**How Extension reaches the installer**: The installer image bundles the Extension Image
at `/bits/rootfs-ext.img` (via `images/installer.yml.in` file binding):

```yaml
# images/installer.yml.in
- path: /rootfs-ext.img
  source: rootfs-ext.img
  optional: true
```

The installer script copies it to PERSIST:
```bash
# pkg/installer/install
if [ -f /bits/rootfs-ext.img ]; then
    cp /bits/rootfs-ext.img /persist/ext-imga.img   # or vault path
fi
```

**Effort impact by approach**:

| | Approach A (no PCR, plaintext) | Approach B/B' (PCR, vault/plain) |
|--|-------------------------------|--------------------------------|
| Installer change | Copy ext to /persist | Same (+ vault staging for 3B) |
| make-raw change | None | None |
| First-boot step | None | Move from staging to vault (3B) |

### Method 2: iPXE / Network Boot

EVE has iPXE-based network installation support (`tools/makenet.sh`,
`pkg/eve/installer/ipxe.efi.cfg`). This path has a history of breakage — it was fixed
multiple times in May–June 2025 and has fragile duplicated logic between `makenet.sh`
and `runme.sh`. It is not as heavily tested as USB installation.

When functional, the network installer runs the same `pkg/installer/install` script as
the USB path. The Extension Image would be bundled inside the installer ISO, so no
additional split-rootfs-specific effort is needed beyond what the USB installer requires.
However, network boot should be verified as working before relying on it for split
rootfs testing.

### Installation Flow Summary

The EVE installer (`pkg/installer/install`) is non-interactive by default — it reads
kernel command-line parameters (`eve_install_disk`, `eve_install_server`, etc.) and
auto-detects everything else. There is no separate "headless" mode; non-interactive is
the normal behavior. An opt-in interactive TUI exists (selected via GRUB menu) but is
not the common path.

All installation paths — USB boot and iPXE/network boot — run the same installer script.
ZFlash prepares the USB media but does not affect the installation flow itself
(see Section 9).

| Method | Extension delivery | Extra work vs current | Security approach impact |
|--------|-------------------|----------------------|------------------------|
| USB installer | Bundled in installer media | Copy to PERSIST (+staging for vault) | Vault: first-boot staging |
| iPXE/network | Bundled in installer ISO | Same as USB (if iPXE is functional) | Same as USB |

**Effort for installation changes: 0.5 SP development** (add Extension copy to installer
script + optional vault staging; Eden testing in Section 10).

## 8. System Upgrade Flow

System upgrades are the most security-sensitive lifecycle event: the running device
downloads and installs new software, reboots into it, and validates it works. The Extension
Image must participate in this flow correctly.

### Current A/B Update Mechanism

```
1. Controller sends BaseOsConfig to zedagent
   └─ Contains: version, ContentTreeUUID, Activate=true
2. baseosmgr receives config
   └─ Requests volumemgr to download + verify image (SHA256)
3. volumemgr downloads to Content Addressable Storage on PERSIST
   └─ Transitions to LOADED state
4. baseosmgr assigns target partition
   └─ If booted from IMGA → target is IMGB (and vice versa)
5. Worker writes image to target partition
   └─ zboot.WriteToPartition() — extracts from CAS to raw device
6. baseosmgr sets GPT priority, marks partition "updating"
7. Device reboots into new partition
8. nodeagent monitors health (testing window)
   └─ Must reach controller within timeout
9. Success: mark new partition "active", old becomes "unused"
   Failure: next reboot falls back to old partition automatically
```

### Split Update: Core + Extension

Core and Extension are always the same version. There are no Extension-only updates. The
update package contains both artifacts. baseosmgr must write both during a single update
transaction.

**Updated flow**:

```
1-3. Same as current (download + verify)
4.   baseosmgr assigns target partition for Core (IMGB if booted from IMGA)
5a.  Worker writes Core Image to target partition (same as today)
5b.  baseosmgr writes Extension Image to PERSIST:
     [Approach 3A]: /persist/ext-{inactive}.img
     [Approach 3B]: /persist/vault/ext-{inactive}.img
     (where {inactive} matches the target Core partition; vault is still accessible
      pre-reboot because PCRs have not changed yet)
6.   Mark partition "updating"
7.   Device reboots
```

**Post-reboot (Approach 3A — outside vault)**:
```
8a.  GRUB measures new Core → PCR 13 changes
8b.  Vault cannot unseal (PCR mismatch) → vault recovery starts
8c.  Extension Loader finds /persist/ext-{active}.img → accessible immediately
8d.  Verifies via dm-verity (root hash from new Core) → mounts → starts services
8e.  [If PCR measurement (1B)]: extends PCR with Extension hash
8f.  nodeagent testing window proceeds normally
8g.  Vault recovery completes in parallel (controller provides backup key)
9.   Test passes → mark active
```

**Post-reboot (Approach 3B — inside vault)**:
```
8a.  GRUB measures new Core → PCR 13 changes
8b.  Vault cannot unseal → vault recovery starts
8c.  Extension Image INACCESSIBLE (inside encrypted vault)
8d.  Device in degraded mode — Core services only
8e.  Controller provides backup key → vault unseals
8f.  Extension Loader finds /persist/vault/ext-{active}.img → verifies → mounts
8g.  [If PCR measurement (1B)]: extends PCR with Extension hash
8h.  nodeagent testing window continues
9.   Test passes → mark active
```

### Rollback Behavior

Rollback is automatic via GRUB's gptprio mechanism. If the new partition fails to boot or
the testing window expires without controller contact:

```
1. GRUB boots the previous partition (the one active before the failed update)
2. Old Core is intact, old PCR 13 restored
3. Old Extension Image for that partition is still at /persist/[vault/]ext-{rollback}.img
4. Extension Loader loads old Extension → old services start
5. Vault unseals normally (old PCR values match sealed policy)
```

Rollback works correctly because:
- baseosmgr only overwrites the Extension file paired with the inactive target partition
- The Extension file paired with the currently active partition is never modified during updates
- A/B naming convention ensures the correct Extension pairs with the correct Core

### Testing Window Considerations

The existing testing window (nodeagent monitors controller reachability) needs Extension
awareness:

- **What to test**: Core services are healthy AND Extension services are healthy (if
  Extension is a required component).
- **Timeout behavior**: If Extension fails to load within the testing window, should the
  update be considered failed?

**Recommendation**: Extension failure during testing window should trigger rollback.
If Extension doesn't load, the new version is not fully functional, and rolling back to
the previous known-good state is the correct action.

### baseosmgr Changes Required

| Change | Description | Approach |
|--------|-------------|----------|
| Extension download | Download Extension alongside Core (same ContentTree) | All |
| Extension write | Write Extension to PERSIST after Core write | All |
| Extension verification | Verify Extension SHA256 before writing | All |
| A/B file management | Manage ext-imga.img / ext-imgb.img naming | All |
| Vault staging | Handle staging → vault move on first boot | B (with 3B) |
| Testing window | Include Extension health in test criteria | All |
| Rollback | Preserve old Extension file (already handled by A/B naming) | All |

### Update Package Format

Current: single rootfs.img (squashfs) in ContentTree.
Split: Core + Extension bundled in the same ContentTree.

Two options for bundling:

**Option A — Single container with both images**: One OCI container containing both
`rootfs.img` (Core) and `extension.img` (Extension). baseosmgr extracts both from the
same download. Simpler controller-side (one ContentTree per update).

**Option B — Separate ContentTrees**: Core and Extension as separate downloadable artifacts.
Allows theoretical independent updates (not planned). More complex controller-side.

**Recommendation**: Option A (single container). Core and Extension are always the same
version. Bundling simplifies controller-side and eliminates version mismatch risk.

### Effort for Upgrade Changes

| Approach | baseosmgr changes | Controller changes | Dev effort | Controller (×2) |
|----------|------------------|-------------------|------------|-----------------|
| A | Extension write + A/B files + testing | Bundle format | 2 SP | 2×2 = 4 SP |
| B'/B | Same + PCR extend + vault staging (B) | Bundle + PCR baseline | 2 SP | 2×2 = 4 SP (upgrade-specific) |

Note: the total controller effort for B'/B is 5 SP raw (×2 = 10 SP effective), which
includes 3 SP for PCR baseline management and sealing policy work beyond the upgrade
flow. See Section 10 for the full breakdown.

## 9. ZFlash Integration

ZFlash is the tool used to prepare USB installer media. It is a Qt/QML desktop application
(fork of Raspberry Pi Imager) that writes EVE installer `.raw` images to USB sticks or
SD cards from a host machine (Windows, macOS, Linux). On EVE master today, ZFlash is a
straightforward image writer — it does not parametrize the installer image. It does not
represent a separate installation method; the actual installation runs on the target device
via the standard installer script (`pkg/installer/install`), as described in Section 7.

### Universal Image Support (local prototype, not yet pushed)

A local prototype adds support for universal EVE images with HV selection at flash time.
This code has not been pushed to the ZFlash repository and needs review before merging.
It will become relevant when EVE starts producing universal images (Section 4).

The prototype adds:

1. **Detect universal images**: Probe the source `.raw` file's CONFIG partition (GPT
   entry 4) for an `eve-hv-supported` file. If found, show the HV selection popup.
   If not found, behave as today.
2. **Let the user choose HV type**: Popup with KVM/Kubevirt/Xen buttons, enabled based
   on the supported list.
3. **Write HV type to CONFIG**: After flashing, write `eve-hv-type` to the CONFIG
   partition on the target USB media. On first boot, the installer copies CONFIG to the
   device, and GRUB reads the HV type on subsequent boots.

| Component | File (zflash repo) | Status |
|-----------|-------------------|--------|
| Universal image detection | `imagewriter.cpp` — `isEveImage()`, `getEveHvSupported()` | Local prototype |
| HV selection popup | `main.qml` — KVM/Kubevirt/Xen buttons | Local prototype |
| Post-flash HV write | `downloadthread.cpp` — `setEveCustomization()` | Local prototype |
| FAT12 filesystem support | `devicewrapperfatpartition.cpp` | Local prototype |
| CONFIG partition probing | `imagewriter.cpp` — reads GPT entry 4 | Local prototype |

### Split Rootfs Impact on ZFlash

ZFlash does not interact with the Extension Image directly. The Extension Image is bundled
inside the installer `.raw` image alongside the Core Image. The installer script running
on the target device handles placing Extension on PERSIST. ZFlash's awareness of split
rootfs is limited to optional UI enhancements:

| Change | Description | Effort |
|--------|-------------|--------|
| Extension presence indicator | Show in UI whether installer includes Extension Image | 0.25 SP |
| Validation | Verify Extension Image is present in source .raw for split images | 0.25 SP |
| Documentation | Update ZFlash user docs for universal + split images | Included |

**Total ZFlash effort: 0.5 SP** (UI polish and validation).

## 10. Effort Comparison Matrix

Reference: USB boot priority feature = 8 story points (pillar types + zedagent LPS
integration + KVM hypervisor + UEFI firmware patches + docs; ~2,700 hand-written lines
across 42 files in 6 subsystems, 3 contributors, ~9 weeks).

### Per-Workstream Effort (Development)

| Workstream | Description | Approach A | Approach B' | Approach B |
|------------|-------------|-----------|-------------|-----------|
| **Generic Core Image** | Runtime guards (~50 sites), build tag removal (~20 files), CONFIG HV selection | 2 | 2 | 2 |
| **Extension Loader** | dm-verity setup, erofs mount, service management, degraded mode. POC exists | 3 | 3 | 3 |
| **PCR measurement** | Userspace PCR extend + sentinel states. Follows existing TPM patterns | — | 1 | 1 |
| **PCR policy migration** | Change default PCR set constant | — | 0.5 | 0.5 |
| **Vault placement** | Extension in vault, first-boot staging, boot ordering | — | — | 1.5 |
| **Installer changes** | Add Extension copy to installer script | 0.5 | 0.5 | 0.5 |
| **baseosmgr upgrade** | Extension write, A/B file management, testing window | 2 | 2 | 2 |
| **ZFlash** | UI indicator, validation | 0.5 | 0.5 | 0.5 |
| **Build system** | mkrootfs-erofs pkg, dm-verity hash gen, build ordering, kernel CONFIG flags | 2 | 2 | 2 |
| **Documentation** | Operator docs, migration guide | 0.5 | 0.5 | 0.5 |
| **Dev subtotal** | | **10.5** | **12** | **13.5** |
| | | | | |
| **Testing: docs only** | Test case docs for verification team, no Eden code | 2 | 2.5 | 3 |
| **Testing: minimal Eden + docs** | One smoke test + full test case docs | 4 | 5 | 6 |
| **Testing: full Eden** | Comprehensive Eden automation (see breakdown below) | 15 | 18 | 20 |
| | | | | |
| **TOTAL (docs only)** | | **~12.5** | **~14.5** | **~16.5** |
| **TOTAL (minimal Eden + docs)** | | **~14.5** | **~17** | **~19.5** |
| **TOTAL (full Eden)** | | **~25.5** | **~30** | **~33.5** |
| **Controller team (×2)** | PCR baseline, health display, bundle format, policy | 2×2 = **4** | 5×2 = **10** | 5×2 = **10** |
| **GRAND TOTAL (docs only)** | | **~17** | **~25** | **~27** |
| **GRAND TOTAL (minimal Eden + docs)** | | **~19** | **~27** | **~30** |
| **GRAND TOTAL (full Eden)** | | **~30** | **~40** | **~44** |

Development estimates are calibrated against the development portion of USB boot priority
(~3 SP dev out of 8 SP total). Testing estimates are calibrated against its Eden testing
portion (~5 SP). The first Eden test suite (Generic Core) is the most expensive because it
sets up shared infrastructure (QEMU configs, CI/CD); subsequent suites reuse it and are
cheaper.

Controller effort carries a ×2 multiplier because it is outside our control. Their
schedule, priorities, and implementation approach are unpredictable. The raw estimate
(2/5/5 SP) reflects the work itself; the multiplier reflects the coordination overhead
and scheduling risk.

### Testing Breakdown

Full Eden testing is estimated at ~1.4–1.5× development effort, dominated by Eden
integration tests.
The USB boot priority feature required ~2,700 lines of EVE code but ~4,500 lines of Eden
test code (17 test cases, QEMU setup scripts, CI/CD integration, eclient endpoint
extensions). Split rootfs testing follows the same pattern: each scenario needs QEMU boot
cycles, controller interaction, partition state verification, and failure injection.

The first Eden test suite (Generic Core Image) is the most expensive because it
establishes shared test infrastructure — QEMU configurations, helper scripts, CI/CD
pipeline. Subsequent suites reuse this infrastructure and are cheaper.

| Test area | What it covers | A | B' | B |
|-----------|---------------|---|----|----|
| Generic Core Image | Eden: boot KVM, Xen, Kubevirt with same image; runtime guards; first test suite sets up shared QEMU/CI infrastructure | 4 | 4 | 4 |
| Install + first boot | Eden: USB installer places Extension on PERSIST; dm-verity verification; Extension services start | 3 | 3 | 3 |
| Upgrade + rollback | Eden: A/B update with Core+Extension; rollback on failure; A/B file integrity. Most complex scenario (multiple boot cycles) | 4 | 4 | 4 |
| Degraded mode | Eden: corrupt/delete Extension; device stays reachable; dm-verity rejects tampered image | 2 | 2 | 2 |
| Attestation + PCR | Eden: PCR extend with sentinel states; correct PCR values in quotes; baseline management | — | 3 | 3 |
| Vault + Extension ordering | Eden: Extension in vault; upgrade with vault recovery window; first-boot staging | — | — | 2 |
| Regression | Run existing Eden suites on split image; CI/CD integration for split builds | 2 | 2 | 2 |
| **Testing total (full Eden)** | | **15** | **18** | **20** |

### Testing Strategy: Test Case Docs vs Eden Automation

The estimates above assume full Eden integration tests for every scenario. Eden is the
best practice — automated, reproducible, runs in CI — but it is also the dominant cost
driver (~59% of device effort). We have successfully shipped features in the past by
providing **detailed test case documentation** for the verification team instead of full
Eden automation, and it worked well enough.

**Three testing tiers:**

| Tier | What | Effort | Ships with feature? |
|------|------|--------|---------------------|
| **Test case docs only** | Detailed step-by-step procedures covering all scenarios (install, upgrade, rollback, degraded mode, tamper, HV matrix). Written for the verification team to execute manually. No new Eden code. | ~2–3 SP total | Yes |
| **Minimal Eden + docs** | One or two Eden smoke tests (e.g., "install and boot with Extension") plus full test case docs for everything else | ~4–6 SP total | Yes |
| **Full Eden** | Comprehensive Eden automation of all scenarios | ~15–20 SP total | Ideally, but often deferred |

**Effort impact on Approach A (Phase 0+1):**

| Testing tier | Dev | Test | Device total |
|---|---|---|---|
| Test case docs only | 10.5 | 2 | **~12.5 SP** |
| Minimal Eden + docs | 10.5 | 4 | **~14.5 SP** |
| Full Eden | 10.5 | 15 | **~25.5 SP** |

**Honest risk assessment**: Test case docs have worked well enough for us in the past.
However, management should weigh the criticality: split rootfs touches the boot chain,
update mechanism, and security verification — a regression here can brick devices.
Furthermore, we have a pattern of planning to add Eden automation later but never
actually doing it, because the next urgent task takes priority. If Eden automation is
not built, the feature relies on manual verification indefinitely, which degrades as the
codebase evolves and the verification team rotates.

**Recommendation**: Ship with test case docs (or minimal Eden + docs) to meet the
timeline. Schedule full Eden automation as the **first task of the next phase**, not
as a separate backlog item. Accept that there is a real risk it will be deprioritized.

### Key Observations

1. **Generic Core Image (2 SP dev) is a prerequisite for all approaches.** It should start
   first and can proceed in parallel with Extension Loader development.

2. **Approach A has limited controller scope, not zero dependency.** The controller work
   (2 SP raw, 4 SP effective) is still required for production: split bundle handling and
   Extension health/degraded telemetry. These changes do not block device-side development
   or testing, but production rollout should wait for controller readiness.

3. **The jump from A to B'/B adds controller-side risk.** The controller work jumps to
   5 SP raw (10 SP effective), and it is a hard prerequisite: PCR-enabled images **cannot
   ship** until the controller team deploys the policy update fleet-wide. The device-side
   delta is +1.5 SP dev (+3 SP full Eden testing) for B', but the real risk is the
   controller team's schedule, which is outside our control.

4. **The jump from B' to B is small** — +1.5 SP dev (+2 SP full Eden testing). Vault
   placement adds complexity to the upgrade path but is incremental and has no additional
   controller dependency.

5. **Testing cost depends heavily on the chosen tier.** With full Eden automation, testing
   is ~59% of the device total (reflecting the USB boot priority experience where Eden
   test code exceeded EVE code). With docs-only testing, the split is ~84% dev / ~16%
   testing. See "Testing Strategy" above for tier comparison and risk assessment.

## 11. Controller-Side Dependencies

The controller team owns these changes. Device-side work can proceed independently for
most items, but some changes must be coordinated.

### Must-Have (All Approaches)

| Change | Why | When needed |
|--------|-----|-------------|
| Extension health status display | Operator must see Extension state (running/failed/missing) | Before production rollout |
| Update bundle format | Controller must deliver Core + Extension as bundled package | Before first split update |
| Degraded mode signaling | API field for Extension state in device info | Before production rollout |

### Needed for Approaches B, B' (PCR measurement)

| Change | Why | When needed |
|--------|-----|-------------|
| PCR baseline management for Extension PCR | Controller must recognize new non-zero PCR value | Before PCR-enabled images ship |
| Sealing policy update | Push VaultKeyPolicyPCR excluding Extension PCR to fleet | **Before** first PCR-enabled image ships |
| PCR pre-computation | Build system provides expected Extension PCR value per release | Nice-to-have for operator tooling |

**Critical sequencing for PCR approaches**: The sealing policy update must reach all
devices **before** the first EVE version that extends the Extension PCR is installed.
If a device installs a PCR-extending image without policy migration, vault unsealing
fails and the device needs manual recovery. The controller team must implement and
deploy the policy update before the device team ships PCR-enabled images.

### Nice-to-Have

| Change | Why |
|--------|-----|
| Extension-specific attestation UI | Show Extension PCR separately from Core PCR in operator view |
| Auto-baseline for known Extension | Pre-compute and auto-accept PCR changes for known EVE versions |
| Split update progress | Show Core and Extension write progress independently |

## 12. Recommended Phasing

Each phase below shows effort at three testing tiers. See "Testing Strategy" in
Section 10 for the rationale and risk assessment.

### Phase 0: Generic Core Image (prerequisite, can start immediately)
- Remove `//go:build k` tags, add runtime guards
- CONFIG-based HV selection (GRUB, storage-init, onboot)
- Universal Linuxkit template
- **Docs only: 2 SP dev + 0.5 SP docs = ~2.5 SP device**
- **Minimal Eden + docs: 2 SP dev + 1.5 SP test = ~3.5 SP device**
- **Full Eden: 2 SP dev + 4 SP test = ~6 SP device**
- **Controller dependency: none**
- **Can run in parallel with Phase 1**

### Phase 1: Extension Loader + Build System (solves 300MB problem)
- Build system: `pkg/mkrootfs-erofs`, dm-verity hash generation, build ordering,
  kernel CONFIG flags (erofs, dm-verity)
- Extension Loader (dm-verity setup, erofs mount, service management, degraded mode)
- Installer changes (Extension delivery to PERSIST)
- baseosmgr changes (Extension write, A/B management, testing window)
- ZFlash (Extension presence indicator)
- **Docs only: ~8.5 SP dev + ~1.5 SP docs = ~10 SP device**
- **Minimal Eden + docs: ~8.5 SP dev + ~2.5 SP test = ~11 SP device**
  (one Eden smoke: install + boot + Extension loaded; docs for everything else)
- **Full Eden: ~8.5 SP dev + ~11 SP test = ~19.5 SP device**
- **Controller dependency: low.** Health status display and bundle format (2 SP raw,
  4 SP effective) are needed for production but do not block device-side development
  or testing.
- **Result: Approach A functional** — strong local integrity, telemetry-based remote

### Phase 2: PCR Measurement + Policy Migration
- Extension Loader: PCR extend with sentinel states
- Controller: PCR baseline management for Extension PCR
- **Docs only: ~1.5 SP dev + ~0.5 SP docs = ~2 SP device**
- **Minimal Eden + docs: ~1.5 SP dev + ~1 SP test = ~2.5 SP device**
- **Full Eden: ~1.5 SP dev + ~3 SP test = ~4.5 SP device**
- **Controller dependency: high — this is the gating risk.** The controller team must
  deploy the sealing policy update (VaultKeyPolicyPCR excluding the Extension PCR) to
  the entire fleet **before** any PCR-enabled EVE image is installed. Device-side work
  can be developed and tested independently, but production rollout is blocked until
  the controller delivers. Controller effort: 3 SP raw (×2 = 6 SP effective).
  Plan for this lead time.
- **Result: Approach B' functional** — adds TPM-attested Extension state

### Phase 3: Vault Placement (optional, if offline DoS is a concern)
- Extension in vault directory, first-boot staging
- Upgrade path with vault recovery ordering
- **Docs only: ~1.5 SP dev + ~0.5 SP docs = ~2 SP device**
- **Minimal Eden + docs: ~1.5 SP dev + ~1 SP test = ~2.5 SP device**
- **Full Eden: ~1.5 SP dev + ~2 SP test = ~3.5 SP device**
- **Controller dependency: none**
- **Result: Approach B functional** — adds offline tamper protection

### Summary: Three Paths

| Phase | Docs only | Minimal Eden + docs | Full Eden |
|-------|-----------|---------------------|-----------|
| Phase 0: Generic Core | ~2.5 SP | ~3.5 SP | ~6 SP |
| Phase 1: Split Rootfs (300MB fix) | ~10 SP | ~11 SP | ~19.5 SP |
| **Phase 0+1 = Approach A** | **~12.5 SP** | **~14.5 SP** | **~25.5 SP** |
| + Phase 2: PCR | ~2 SP | ~2.5 SP | ~4.5 SP |
| **Phase 0+1+2 = Approach B'** | **~14.5 SP** | **~17 SP** | **~30 SP** |
| + Phase 3: Vault | ~2 SP | ~2.5 SP | ~3.5 SP |
| **Phase 0+1+2+3 = Approach B** | **~16.5 SP** | **~19.5 SP** | **~33.5 SP** |

The docs-only path for Phase 0+1 (Approach A) is **~12.5 SP** — about 1.6× USB boot
priority. With minimal Eden smoke tests, the same path is **~14.5 SP**.

Full Eden automation (~25.5 SP) can follow as a separate effort — but given our track
record, it should be scheduled as the first task of the next phase, not a backlog item.

### Parallel Tracks

```
Phase 0: Generic Core ──────────────────────►
Phase 1: Extension Loader + Build ──────────────────────────────►
                                    Phase 2: PCR ──────────►
                                              Phase 3: Vault ─────►
Controller: Health+Bundle ──────────────► PCR Policy ──────────►
```

Phases 0 and 1 can run in parallel before controller changes are delivered. For production
rollout of Approach A, controller Health+Bundle work is still required. Phase 2 cannot ship
to production until the controller team deploys the PCR policy update — this is the primary
scheduling risk. Phase 3 is independent of Phase 2 and has no additional controller
dependency.

## 13. Code Anchors

Key files referenced in this document:

### TPM and Security

| File | Purpose |
|------|---------|
| `pkg/pillar/evetpm/tpm.go:120-135` | Default sealing PCR set |
| `pkg/pillar/evetpm/tpm.go:171` | Attestation quote PCR list |
| `pkg/pillar/evetpm/tpm.go:478-514` | PCR policy validation |
| `pkg/pillar/cmd/tpmmgr/tpmmgr.go:302-360` | Attestation quote generation |
| `pkg/pillar/cmd/zedagent/attesttask.go:252-272` | PCR value encoding for attestation |
| `pkg/pillar/cmd/vaultmgr/vaultmgr.go:434-460` | Controller PCR policy handling |

### GRUB and Measurement

| File | Purpose |
|------|---------|
| `pkg/grub/rootfs.cfg:125` | `measurefs $root --pcr 13` |
| `pkg/grub/patches-2.06/0011-Add-measurefs-command.patch` | measurefs implementation |
| `pkg/measure-config/src/measurefs.go:23-32` | PCR 14 config measurement |

### Boot and Installation

| File | Purpose |
|------|---------|
| `pkg/installer/install` | Main installer script |
| `pkg/mkimage-raw-efi/make-raw` | Partition layout creation |
| `pkg/grub/rootfs.cfg` | 2nd-stage GRUB (boot logic) |
| `pkg/grub/embedded.cfg` | 1st-stage GRUB (minimal) |
| `pkg/eve/installer/ipxe.efi.cfg` | iPXE network boot config |
| `tools/makenet.sh` | iPXE/network installer preparation |

### Update Mechanism

| File | Purpose |
|------|---------|
| `pkg/pillar/cmd/baseosmgr/handlebaseos.go` | Update orchestration |
| `pkg/pillar/cmd/baseosmgr/worker.go` | Partition write worker |
| `pkg/pillar/zboot/zboot.go` | Partition state machine |
| `pkg/pillar/cmd/nodeagent/handletimers.go` | Testing window management |

### Split Rootfs (POC)

| File | Purpose |
|------|---------|
| `pkg/pillar/cmd/extsloader/external-services-loader.go` | Extension Loader agent |
| `images/rootfs_core.yml.in` | Core rootfs Linuxkit template |
| `images/rootfs_ext.yml.in` | Extension rootfs Linuxkit template |
| `images/rootfs_universal.yml.in` | Universal rootfs template |

### Generic Core Image

| File | Purpose |
|------|---------|
| `pkg/pillar/base/kubevirt.go` | `IsHVTypeKube()` runtime detection |
| `pkg/pillar/kubeapi/runtimeguard.go` | Runtime guard function |
| `pkg/pillar/hypervisor/hypervisor.go` | HV runtime selection |
| `pkg/pillar/scripts/device-steps.sh` | Conditional agent startup |
| `pkg/storage-init/storage-init.sh` | HV-aware storage init |

### Build System

| File | Purpose |
|------|---------|
| `Makefile` | Build targets for split rootfs |
| `tools/compose-image-yml.sh` | Linuxkit YAML template rendering |
| `tools/makerootfs.sh` | Rootfs image creation |
| `images/installer.yml.in` | Installer image recipe |
