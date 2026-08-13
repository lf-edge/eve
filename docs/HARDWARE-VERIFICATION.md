# Verifying EVE-OS on edge nodes

Verification checks whether a new hardware model can operate correctly with
EVE-OS, and is normally run once per hardware model and EVE-OS version.

It is a stage of the EVE-OS installer that runs after EVE-OS has been written to
the target disk: it records a hardware inventory, checks which drivers claimed
which devices, tests dynamic (DHCP) and static network configuration on every
Ethernet port, measures the read performance of every disk with
[fio](https://github.com/axboe/fio), and — when the node has a TPM — runs a set
of TPM checks.

## Running verification

Produce an installer image and boot the node from it, as described in
[deployment](DEPLOYMENT.md); the checks then run on their own at the end of the
installation:

```console
docker run --rm lfedge/eve:latest installer_raw > installer.raw
docker run --rm lfedge/eve:<tag> installer_raw > installer.raw
```

Some BIOSes cannot boot from a disk-based image at all — remote consoles such as
HPE iLO and Dell DRAC typically expose virtual media as an optical drive — and
those need an ISO instead, which is also what iPXE serves when a node is
netbooted:

```console
docker run --rm lfedge/eve:<tag> installer_iso > installer.iso
```

The checks are the same either way, but only the raw installer can save their
results; from an ISO they have to be read off the installed node, as described
below. Prefer the raw installer wherever a node can boot from a USB stick or an
SD card.

To skip the checks, select `disable post-install verification` in the installer's
GRUB menu, which adds `eve_disable_verify` to the kernel command line.

Only the virtualization-capability check is limited to x86; the rest runs on
every architecture the installer supports.

## Where the results are stored

The results are always printed on the console as the installer runs. Whether
they are also saved depends on the boot media:

* `installer_raw`, written to a USB stick or an SD card or kept as a raw image
  file, carries a writable 40 MiB vfat **inventory partition** — partition 5,
  labeled `INVENTORY`. The report is stored there in a directory named after the
  node's soft serial number, so one stick accumulates one directory per node it
  has installed. Use the extraction script below to read it.

* `installer_iso` and `installer_net` have no inventory partition, because the
  ISO is a read-only squashfs image. The report is instead written to
  `/persist/installer` on the node that was just installed, and has to be
  retrieved from the node itself.

## What is collected

| File | Contents |
|---|---|
| `summary.log` | Hardware summary and the pass/fail lines of the tests, see below |
| `hardware-inventory/` | `hwinfo`, `lspci`, `lsusb`, `lsblk`, `dmesg`, `smartctl` per disk, `cpuinfo`, `meminfo` and the TPM PCR values |
| `hardwaremodel.txt` | `dmidecode` output |
| `controller-model*.json` | The hardware model to hand to the controller, as described in [HARDWARE-MODEL](./HARDWARE-MODEL.md) |
| `networking-checks/dhcp-<nic>.log`, `networking-checks/static-<nic>.log` | Connectivity test result per port and per addressing mode |
| `storage-performance/<disk>.log` | `fio` random-read benchmark per disk |
| `iommu_groups.out` | IOMMU groups, which determine what can be assigned to a guest |
| `watchdogs.log` | Available hardware watchdogs |
| `vmcap.log` | Virtualization capabilities of the CPU (x86 only) |
| `tpmchecks.log` | TPM test results, only when a TPM is present |
| `clock` | `hwclock` and `date` output, to spot an RTC that is not in UTC |
| `eve-release` | The EVE-OS version that ran the verification |
| `installer.log` | The full installer log |
| `device.cert.pem` | The device certificate, when one was created |

## The summary

`summary.log` is the one file to read first when deciding whether a hardware
model is usable. It opens with an identification and inventory block, calls out
every PCI device that no driver claimed — the most common reason a hardware
model does not work — and ends with the results of the individual tests: one
line per port for DHCP and for static addressing, and a marker if the TPM checks
failed. The detailed logs behind it are in `hardware-inventory/`.

```console
Hardware summary
================

System:  QEMU Standard PC (Q35 + ICH9, 2009)
Serial:  EVE-VERIFY-DEMO-001
Arch:    x86_64
Kernel:  6.12.96-linuxkit-core-bfc617435842
CPU:     13th Gen Intel(R) Core(TM) i5-1340P (4 cores)
Memory:  3771 MiB

Disks
-----
sda   32G QEMU HARDDISK
sdb    8G QEMU HARDDISK

PCI devices with no driver
--------------------------
00:00.0 Host bridge [0600]: Intel Corporation 82G33/G31/P35/P31 Express DRAM Controller [8086:29c0]
00:01.0 VGA compatible controller [0300]: Device [1234:1111] (rev 02)

Verification results
--------------------
eth0 with dhcp is working properly
eth0 with static configuration is working properly
```

A node that passes reports nothing further; a failure adds a line naming what
failed. The example above is from a QEMU guest, so the two devices with no
driver are emulated chipset functions that need none — on real hardware this is
the list to check against what the node is expected to provide.

## Extracting the results from the installer media

Plug the USB stick into your PC, or keep the raw image file, and run

```console
sudo ./tools/extract-verification-info.sh <USB_device_name|installer_img>
```

for example:

```console
sudo ./tools/extract-verification-info.sh /dev/disk4
sudo ./tools/extract-verification-info.sh installer.raw
```

The script mounts the inventory partition, copies every per-node directory it
finds into the current working directory, and prints `summary.log`. It needs
root because it mounts a partition. When given an image file rather than a block
device, the file name has to end in `.raw`.
