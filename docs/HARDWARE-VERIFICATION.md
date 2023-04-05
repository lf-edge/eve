# Verifying EVE on edge nodes

EVE verification aims to test whether a new hardware model can
operate correctly with EVE-OS. Therefore, we use verification once for
each hardware and EVE-OS version. It is a specialized version of EVE-OS
installer that installs EVE-OS on the underlying edge node and verifies its
compatibility. It checks if the necessary drivers are present, tests static
and dynamic networking configurations, tests the available storage devices, and
tests if EVE-OS can spawn a guest successfully. Verification is currently
supported on x86 edge nodes.

## Running the verification image from boot media

To produce the verification.raw image, we can execute the command
```docker run --rm lfedge/eve-verification:<tag> verification_raw > verification.raw```.
We must select the `<tag>` from `lfedge/eve-verification` dockerhub repository
(i.e., `https://hub.docker.com/r/lfedge/eve-verification/tags`). The `<tag>`
corresponds to the EVE version we want to verify against the hardware.

In cases such as using HPE iLO or Dell DRAC, your BIOS cannot boot
from a disk-based image, so we need an ISO image. The only difference is in
step #1 that then becomes
```docker run --rm lfedge/eve-verification:<tag> verification_iso > verification.iso```.
For example:

```console
docker run --rm lfedge/eve-verification:latest verification_raw > verification.raw
docker run --rm lfedge/eve-verification:10.4.0-kvm verification_raw > verification.raw
docker run --rm lfedge/eve-verification:10.4.0-kvm verification_iso > verification.iso
```

## Running the verification image via iPXE

[iPXE](https://en.wikipedia.org/wiki/IPXE) is a modern Preboot eXecution
Environment and a boot loader that allows operating system images to be
downloaded right at the moment of booting (checkout [deployment](DEPLOYMENT.md)).
To get the necessary images required by iPXE, we can execute the command
```docker run --rm lfedge/eve-verification:<tag> verification_net | tar xf -```.
Apart from the image, iPXE expects a configuration file at certain URLs
to proceed with the boot process. Here is an example of an iPXE
configuration file used to run an EVE-OS verification image locally in a
hardware lab. Note the changes made to both ```url``` and ```eve_args```
variables.

```console
#!ipxe
# set url https://github.com/lf-edge/eve/releases/download/snapshot/amd64.
set url https://10.0.0.2/eve/releases/download/snapshot/amd64.
# set eve_args eve_soft_serial=${ip} eve_reboot_after_install
set eve_args eve_soft_serial=${ip} eve_install_server=zedcontrol.hummingbird.zededa.net eve_reboot_after_install

# you are not expected to go below this line
set console console=ttyS0 console=ttyS1 console=ttyS2 console=ttyAMA0 console=ttyAMA1 console=tty0
set installer_args root=/initrd.image find_boot=netboot overlaytmpfs fastboot

# you need to be this ^ tall to go beyond this point
kernel ${url}kernel ${eve_args} ${installer_args} ${console} ${platform_tweaks} initrd=amd64.initrd.img initrd=amd64.verification.img initrd=amd64.initrd.bits initrd=amd64.rootfs.img
initrd ${url}initrd.img
initrd ${url}verification.img
initrd ${url}initrd.bits
initrd ${url}rootfs.img
boot
```

## Building verification from source

Similar to EVE-OS installer image (see [deployment](DEPLOYMENT.md)), we build
the verification image with the following steps:

1. Produce a disk-based installer image (e.g., by running
`make verification-raw`, which creates the raw image file for verification,
similar to what `make installer-raw` does).
2. Burn the resulting ```verification.raw``` image file onto a USB stick and
insert it into the edge node.
3. Have the machine boot from USB from BIOS.

## Logs of the verification process

The verification image uses multiple utilities to gather the logs during the
verification process. Among them, we find: cpuinfo, meminfo, dmesg, smartctl,
lsblk, lspci, lsusb, scsi, the hardware model as described in
[HARDWARE-MODEL](./HARDWARE-MODEL.md), etc. Additionally, it stores the results
of testing a static and a dynamic (i.e., using DHCP) network configuration and
the read performance of the available storage devices using
[fio](https://github.com/axboe/fio).

## Getting the results of the verification process

The verification image prints the results of tests on the screen and stores
them when possible (e.g., when we are using the raw version) in the
**inventory partition** of the boot media. We can get the verification process
results by running the command ```tools/extract_verification_info.sh <verification.raw>```
on the `verification.raw` image file or on the USB stick. To achieve that, we must
mount the USB stick or copy the image file to a PC and execute the script. The
script copies, among other things, the logs of the tests, details about the
hardware, etc. A file named ```summary.log``` contains a summary of the
verification process results to help the user quickly understand potential
problems.
