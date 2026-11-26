# Installer VM dev harness

Boots a small Ubuntu QEMU VM with **file-backed virtio disks**, an **swtpm**
emulated TPM, and **OVMF UEFI**, so you can develop/test the installer on the host
without building EVE and without any risk to your real disks or TPM.

## Requirements
Linux host with QEMU/KVM, OVMF, `swtpm`, `qemu-img`, `genisoimage`, `ssh`, and
outbound network (first boot runs cloud-init `apt`). `harness.sh build` checks
these.

## Quick start
```bash
pkg/installer/dev/harness.sh build          # one-time: image, ssh key, seed
pkg/installer/dev/harness.sh selftest       # L1 self-check (no EVE artifacts)

pkg/installer/dev/harness.sh up --disks 2   # boot with 2 fake disks (default 8G)
pkg/installer/dev/harness.sh ssh 'lsblk'    # /dev/vda = OS/boot, vdb.. = targets
pkg/installer/dev/harness.sh inspect        # partition tables / filesystems
pkg/installer/dev/harness.sh down           # stop VM (keeps OS overlay)
pkg/installer/dev/harness.sh down --purge   # also delete OS overlay + swtpm state
```
The VM stays up between `run`s; wipe a disk between tests with
`harness.sh ssh 'sudo sgdisk -Z /dev/vdb'` — no reboot needed.

## Building + running the installer
Build on the host, run in the VM (the repo is mounted read-only at `/repo`):
```bash
( cd pkg/installer && cargo build )
pkg/installer/dev/harness.sh run sudo /repo/pkg/installer/target/debug/installer --help
```

## Running make-raw (L2, needs EVE artifacts)
`make-raw` is at `/repo/pkg/mkimage-raw-efi/make-raw`. Stage the artifacts it
expects into `/parts` inside the VM (`rootfs.img`, `config.img`, `persist.img`,
`EFI/`), then:
```bash
pkg/installer/dev/harness.sh run sudo /repo/pkg/mkimage-raw-efi/make-raw \
    /dev/vdb efi efi_b imga imgb conf persist
pkg/installer/dev/harness.sh inspect        # expect EFI System, IMGA, IMGB, CONFIG, P3
```
Optional; the L1 `selftest` does not need artifacts.

## Safety
- The installer runs inside the VM: host disks and host TPM are unreachable.
- The only host↔guest links are the read-only `/repo` 9p share and the ssh
  forward; the guest cannot modify your working tree.
- `/dev/tpmrm0` is always swtpm; there is no host-TPM path.

## For SP-2a and later
After `up`, `work/harness-env` records `TEST_DISKS` and `BOOT_DISK`; the Rust disk
model uses these (its device allowlist + the boot disk to exclude).
