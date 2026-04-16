# Split-Rootfs Installer Testing

Manual QEMU-based testing of the universal split-rootfs installer.

## Prerequisites

```bash
make pkgs              # build all OCI packages (once)
make pkg/grub          # rebuild after grub config changes
make installer-split   # build installer-split.raw (auto HV=uni)
```

## Test Matrix

| # | Variant | GRUB menu selection | What to verify |
|---|---------|-------------------|----------------|
| 1 | KVM (default) | Let 60s timeout expire | ext4 persist, 36MB EFI, extsloader ready, 8 services |
| 2 | Kubevirt | "Boot/Install EVE (Kubevirt / EVE-k)" | ext4 persist, 2GB EFI, 4GB rootfs, extsloader ready, 9 services (incl. kube), zedkube agent started |
| 3 | Kubevirt + ZFS | "Boot/Install EVE (Kubevirt / EVE-k + ZFS)" | ZFS persist pool, 2GB EFI, extsloader ready on ZFS, 9 services |
| 4 | Xen | "Boot/Install EVE (Xen)" | Xen boot chain (multiboot2), ext4 persist, extsloader ready |

## Running Tests

### Install

```bash
make run-installer-split
# Select the desired variant from the GRUB menu
# Installation completes and QEMU powers off
```

### Boot installed system

```bash
make run-target
```

### Verify from console

```bash
# HV type
cat /config/eve-hv-type       # kvm, k, or xen
cat /run/eve-hv-type           # same

# Extension loader
cat /run/extsloader-state.json
# Expected: {"state":"ready","partition":"IMGA",...}

# dm-verity mount
mount | grep verity
# Expected: /dev/mapper/exts-verity-ext-imga-img on /persist/exts type erofs (ro,...)

# Extension services
logread | grep 'started successfully' | grep extsloader

# For Kubevirt: zedkube agent
logread | grep 'HV flavor'
# Expected: HV flavor is 'k': enabling zedkube

# For ZFS: pool status
zpool status
zfs list
mount | grep persist
# Expected: persist on /persist type zfs
```

## Test Results (2026-04-15)

### Test 1: KVM (default timeout)

- GRUB menu: 3 HV entries + ZFS + Xen + Set Boot Options
- 60s timeout selected KVM automatically
- Installer: `Universal image: selected hypervisor kvm`
- Partition sizing: 36MB EFI (default), 512MB rootfs
- Persist: ext4
- Extension: copied to `/persist/ext-imga.img` (350MB)
- First boot: extsloader mounted dm-verity, state=ready
- Services: 8/9 started (kube skipped, not HV=k)
- **PASS**

### Test 2: Kubevirt (menu select)

- Selected "Boot/Install EVE (Kubevirt / EVE-k)" from GRUB menu
- Cmdline: `eve_hv_type=k` (single, no duplicate)
- Installer: `Universal image: selected hypervisor k`
- Partition sizing: 2GB EFI, 4GB rootfs (bug 5 fix verified)
- Persist: ext4 (single disk, no ZFS)
- Extension: copied, dm-verity mounted
- First boot: extsloader state=ready, 9/9 services (incl. kube)
- zedkube agent: `HV flavor is 'k': enabling zedkube`
- Kubernetes iptables rules: all k8s network marks created
- **PASS**

### Test 3: Kubevirt + ZFS (menu select)

- Selected "Boot/Install EVE (Kubevirt / EVE-k + ZFS)" from GRUB menu
- Cmdline: `eve_hv_type=k eve_install_zfs_with_raid_level=none`
- Installer: `Kubevirt image installing ZFS`, `ZFS raid level: none`
- ZFS pool created on sda9
- Extension: copied to ZFS persist (302MB), dm-verity mounted
- First boot: `persist on /persist type zfs`, extsloader state=ready
- Services: 9/9 including kube, all overlay mounts on ZFS
- **PASS**

### Test 4: Xen (not tested in QEMU)

- Xen menu entry added but not manually tested
- Xen boot chain requires multiboot2 which works differently in QEMU
- Covered by: GRUB menu entry exists, `set_xen_boot` is called,
  `eve_hv_type=xen` passed on cmdline, installer handles xen

## Bugs Found and Fixed

| # | Bug | Fix | Commit |
|---|-----|-----|--------|
| 1 | `runme.sh` bailed on `uni` HV | Add `uni` to case with k-sized media | `258d982fc` |
| 2 | Installer missing `xen` cmdline check | Add `elif cmdline eve_hv_type=xen` | `258d982fc` |
| 3 | GRUB menu had no Xen entry | Add Xen menuentry with arch-specific boot chain | `258d982fc` |
| 4 | `storage-init.sh` no `uni` guard | Explicit fallback to kvm with warning | `258d982fc` |
| 5 | `make-raw` wrong partition sizes for k from uni | Pass `EVE_HV` env var from installer | `258d982fc` |
| 6 | `_eve_uni` used as proxy for installer detection | Split into `_eve_installer` + `_eve_uni` | `258d982fc` |
| 7 | `installer-split.raw` missing `rootfs-ext.img` | Don't symlink over real file in Makefile | `0aeaa20c0` |
| 8 | GRUB `--MORE--` pager blocking unattended boot | `set pager=0` in grub_installer.cfg | `1b18f6140` |
| 9 | Duplicate `eve_hv_type=` on cmdline (kvm + k) | Only add default when no menu shown | `598b5081d` |

## Eden Automation

The `test-split-installer.sh` script automates KVM install via Eden:

```bash
# Default KVM install
./tests/eden/test-split-installer.sh

# Pre-parametrized Kubevirt (simulates ZFlash)
INSTALL_HV=k ./tests/eden/test-split-installer.sh

# Pre-parametrized Xen
INSTALL_HV=xen ./tests/eden/test-split-installer.sh

# Skip build
SKIP_BUILD=1 ./tests/eden/test-split-installer.sh
```

Interactive variants (Kubevirt, Xen, ZFS) require GRUB menu selection
which cannot be automated without keystroke injection.
