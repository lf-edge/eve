# Verifying EVE on edge nodes

EVE verification aims to test whether a new hardware model can
operate correctly with EVE-OS. Therefore, we use verification once for
each hardware and EVE-OS version. It is the normal version of EVE-OS
installer that installs EVE-OS on the underlying edge node and verifies its
compatibility. It checks if the necessary drivers are present, tests static
and dynamic networking configurations, tests the available storage devices, and
tests if EVE-OS can spawn a guest successfully. Verification is currently
supported on x86 edge nodes.

## Running the verification image from boot media

To produce the verification.raw image, we can execute the command
```docker run --rm lfedge/eve:<tag> installer_raw > installer.raw```.

In cases such as using HPE iLO or Dell DRAC, your BIOS cannot boot
from a disk-based image, so we need an ISO image. The only difference is in
step #1 that then becomes
```docker run --rm lfedge/eve:<tag> installer_iso > verification.iso```.
For example:

```console
docker run --rm lfedge/eve:latest installer_raw > installer.raw
docker run --rm lfedge/eve:10.4.0-kvm installer_raw > installer.raw
docker run --rm lfedge/eve:10.4.0-kvm installer_iso > installer.iso
```

## Running the verification via iPXE

[iPXE](https://en.wikipedia.org/wiki/IPXE) is a modern Preboot eXecution
Environment and a boot loader that allows operating system images to be
downloaded right at the moment of booting (checkout [deployment](DEPLOYMENT.md)).
To get the necessary images required by iPXE, we can execute the command
```docker run --rm lfedge/eve:<tag> installer_net | tar xf -```.
Apart from the image, iPXE expects a configuration file at certain URLs
to proceed with the boot process. Here is an example of an iPXE
configuration file used to run an EVE-OS verification image locally in a
hardware lab. Note the changes made to both ```url``` and ```eve_args```
variables.

```console
#!ipxe
# set url https://github.com/lf-edge/eve/releases/download/snapshot/amd64.
set url https://10.0.0.2/eve/releases/download/snapshot/amd64.
set console console=ttyS0 console=ttyS1 console=ttyS2 console=ttyAMA0 console=ttyAMA1 console=tty0
set eve_args eve_soft_serial=${mac:hexhyp} eve_install_server=zedcontrol.hummingbird.zededa.net eve_reboot_after_install getty
set installer_args root=/initrd.image find_boot=netboot overlaytmpfs fastboot

# a few vendor tweaks (mostly an example, although they DO work on Equinix Metal servers)
iseq ${smbios/manufacturer} Huawei && set console console=ttyAMA0,115200n8 ||
iseq ${smbios/manufacturer} Huawei && set platform_tweaks pcie_aspm=off pci=pcie_bus_perf ||
iseq ${smbios/manufacturer} Supermicro && set console console=ttyS1,115200n8 ||
iseq ${smbios/manufacturer} QEMU && set console console=hvc0 console=ttyS0 ||

iseq ${buildarch} x86_64 && chain ${url}EFI/BOOT/BOOTX64.EFI
iseq ${buildarch} aarch64 && chain ${url}EFI/BOOT/BOOTAA64.EFI
iseq ${buildarch} riscv64 && chain ${url}EFI/BOOT/BOOTRISCV64.EFI

boot
```

The above is the actual [`ipxe.cfg`](../pkg/eve/installer/ipxe.efi.cfg) distributed with EVE releases.

## Building installer from source

Simply build the EVE-OS installer image, see [deployment](DEPLOYMENT.md).

## Logs of the verification process

The verification stage of the installation uses multiple utilities to gather the logs during the
verification process. Among them, we find: cpuinfo, meminfo, dmesg, smartctl,
lsblk, lspci, lsusb, scsi, the hardware model as described in
[HARDWARE-MODEL](./HARDWARE-MODEL.md), etc. Additionally, it stores the results
of testing a static and a dynamic (i.e., using DHCP) network configuration and
the read performance of the available storage devices using
[fio](https://github.com/axboe/fio).

## Getting the results of the verification process

The verification stage prints the results of tests on the screen and stores
them when possible (e.g., when we are using a USB or a raw file) in the
**inventory partition** of the boot media. We can extract the logs of the
verification process results by running the command
```tools/extract-verification-info.sh <USB_device_name|verification_img>```
on the `verification.raw` image file or on the USB stick. To achieve that, we must
mount the USB stick or copy the image file to our PC and execute the script. The
script copies, among other things, the logs of the tests, details about the
hardware, etc. A file named ```summary.log``` contains a summary of the
verification process results to help the user quickly understand potential
problems.

## Publishing the results of the verification processes

Apart from extracting the logs of the verification process, we can upload
the results of verification in a dedicated web application.
For this, we need to plug the USB stick or copy the file containing the verification
on our PC and execute the script `tools/publish-verification-info.sh`.
Assuming the web application is running on `www.example.com:8999`, we can publish
the results by running the script as follows:
```./publish-verification-info.sh /dev/disk4 https://www.example.com:8999```
or ```./publish-verification-info.sh verification.raw https://www.example.com:8999```.
That way, we can access the logs of different verification processes in a centralized
and user-friendly manner.
