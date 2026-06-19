# Split Rootfs: Remaining Work

This is a consolidated, branch-scoped tracker of what still needs to be done
to take the split-rootfs proof of concept (PR
[lf-edge/eve#6062](https://github.com/lf-edge/eve/pull/6062)) from "works
end-to-end on a custom kernel in QEMU/eden" to "mergeable and runnable on a
stock build." It complements the forward-looking delivery plan in
`SPLIT-ROOTFS-IMPLEMENTATION-ROADMAP.md` (§10–§12), which has the full
workstream/story-point breakdown and the G1→G4 dependency gates.

What the branch already does and what has been verified end-to-end is in
`SPLIT-ROOTFS.md` and `SPLIT-ROOTFS-DESIGN.md`. This document only lists the
open items.

## 1. Hard blockers for a stock build

These prevent the feature from running on an unmodified EVE/eve-kernel build.

- **Kernel config not yet upstream.** Stock `eve-core_defconfig` lacks
  `CONFIG_EROFS_FS`, `CONFIG_EROFS_FS_ZIP`, and `CONFIG_DM_VERITY`. The
  Extension is an erofs image (`mkfs.erofs -zlz4hc,9`, hence the ZIP option)
  protected by dm-verity, so without these the Extension cannot be mounted.
  Tracked by draft PR
  [lf-edge/eve-kernel#248](https://github.com/lf-edge/eve-kernel/pull/248)
  ("eve-core: enable EROFS + DM_VERITY for split-rootfs"). **After it merges,
  bump `kernel-commits.mk`** to the new kernel commit so split-rootfs builds
  against a stock kernel.

- **OTA partition-size check rejects split images.** On any device running
  EVE ≥ 10.2.0, `doBaseOsActivate` compares the *whole* content tree
  (`MaxDownloadSize` = Core + the `disk-0` Extension layer) against the rootfs
  partition and aborts the update, even though only the Core lands in the
  partition (the Extension goes to `/persist`). Fixed by draft PR
  [lf-edge/eve#6044](https://github.com/lf-edge/eve/pull/6044)
  ("baseosmgr: check rootfs size, not whole image"), which removes the
  `MaxDownloadSize` check from `doBaseOsActivate` and moves a split-agnostic
  size guard into `zboot.WriteToPartition` (bounds only the bytes actually
  written to the partition). This branch inherits the fix once #6044 merges.
  Until then OTA onto a ≥10.2.0 device fails. (The original eden OTA test
  started from 9.6.0, which predates the check, so it never exercised it —
  watch for this in any new test.)

## 2. Testing gaps

- **Zero Go unit tests for the feature surface.** The entire new surface —
  the `extsloader` agent (`pkg/pillar/cmd/extsloader/`), CAS self-heal
  Extension extraction, baseosmgr Extension handling, nodeagent readiness
  gating, the vaultmgr/zedagent extsloader-wait gates, and the new types in
  `pkg/pillar/types/extsloadertypes.go` — has no unit tests. e2e exists only
  as eden driver scripts under `tests/eden/`, which are not wired into CI.

- **eden tests not in CI.** The split-installer and OTA-from-old-image
  scripts run by hand; they need to be made CI-runnable (or a documented
  manual test matrix). The interactive GRUB HV-selection menu (universal
  image) is inherently interactive and has no automated coverage — OTA
  acceptance can still be driven through the existing eden upgrade workflow.

- **Stock-flavor guards not exercised.** The 300 MB Core size guard and the
  4096 MB OCI guard exist but are only hit by the `uni` build, not by stock
  CI flavors.

## 3. Settled design decisions (recorded for context)

These were debated earlier and are now **resolved and implemented** — listed
here only so they are not re-opened. The design/roadmap docs reflect them.

- **wwan is in Core (resolved).** `eve-wwan` lives in the Core image
  (`rootfs_core.yml.in`), not the Extension, so cellular-only devices stay
  manageable even if the Extension fails to load. Cost on the universal Core
  is +20.9 MB, still well under the 300 MB budget. See `SPLIT-ROOTFS-DESIGN.md`
  "Architectural Decisions".

- **Extension lives on plain `/persist`, not the vault (resolved).** extsloader
  must read and measure the Extension into PCR 12 *before* vault unlock, so the
  ordering is deliberately inverted: vaultmgr/zedagent wait for extsloader
  before seal/unseal/attest. The Extension therefore cannot live inside the
  vault. Integrity comes from dm-verity, not encryption (the Extension holds no
  secrets). See `SPLIT-ROOTFS-DESIGN.md` "Extension Image Placement".

- **PCR 12 is in the disk-key sealing set (resolved).** Code includes PCR 12 in
  `DefaultDiskKeySealingPCRs` (`pkg/pillar/evetpm/tpm.go`), consistent with how
  EVE already absorbs PCR churn (attestation → controller-escrowed key →
  re-seal).

## 4. Cleanup / loose ends

- Remove the `/run/extsloader-state.json` debug file (development artifact).
- The installer `eve-hv-supported` / `installer-split.raw` CONFIG list still
  omits `uni`; add it if ZFlash needs to validate the universal flavor.
- Document the as-built mechanisms that currently have no docs: the kube
  runtime guards that make one pillar binary safe on kvm, the
  vaultmgr/zedagent extsloader-wait gates, the disk-metric exclusions for the
  split service dirs, and the watcher service-override mechanism.
- Add an erofs-vs-squashfs performance benchmark to justify the format choice.
- The branch still carries WIP checkpoint commits and a few repo-root scratch
  scripts; squash into logical units and drop non-shipping files before this
  leaves draft.

## 5. Productionization (beyond the PoC)

These are larger items captured in the roadmap, not required to demonstrate
the feature but required before a production rollout:

- **Controller-side (informational only):** Extension health telemetry
  (`running/failed/missing/degraded`) and recovery-state visibility so
  operators can see why a device is degraded. No new controller-side security
  controls are planned.
- **Kernel module deferred loading.** PoC-validated overlay mechanism (mount
  Extension modules as an additional `lowerdir`, `depmod -a`, re-probe). Phase 1
  is low-risk (~1.7 MB of non-connectivity modules: bluetooth, CAN, NFS,
  iSCSI, HID, IIO). Phase 2 (move ~126 MB WiFi firmware to the Extension) is a
  product decision requiring acceptance of a ~30 s WiFi-only-device delay.
  Connectivity-critical drivers (ethernet, WiFi modules, WWAN, ZFS) stay in
  Core.
- Operator and migration docs; controller PCR 12 baseline awareness.

## Status snapshot

| Item | Tracked by | State (2026-06-19) |
|------|-----------|--------------------|
| Kernel EROFS/DM_VERITY config | eve-kernel#248 | OPEN (draft) — then bump `kernel-commits.mk` |
| OTA partition-size check fix | eve#6044 | OPEN (draft) — branch inherits on merge |
| Unit tests for feature surface | — | Not started |
| eden tests in CI | — | Not started |
| Design/doc reconciliation | this branch | Done (wwan→Core, Extension on /persist, PCR 12 all settled) |
| Controller telemetry / kernel module deferral | roadmap §11, §16 | Future work |
