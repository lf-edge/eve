# BIOS and Firmware management with EVE

BIOS (or more generally firmware) are the only external pieces of software that
EVE has to depend on and sometimes manage. EVE itself depends on firmware during
the [boot phase](BOOTING.md) and can be currently bootstrapped on:

1. UEFI compliant firmware on both amd64 and arm64 architectures
2. Legacy PC BIOS on amd64
3. Legacy u-boot firmware (only version 2021.01 and higher) on arm64

Last option is presented mostly for completeness' sake, since the minimum
version of u-boot EVE depends on comes with a rather complete (although
not fully compliant) [UEFI implementation](https://elixir.bootlin.com/u-boot/v2019.04/source/doc/README.uefi)
which allows EVE to simply rely on it as an UEFI firmware (option #1).

## UEFI compliant firmware configuration on amd64

EVE expects

* VT-x
* VT-d (if available)
* hardware watchdog (if available)
* TPM 2.0 (if available)

options to be enabled by your BIOS/firmware. Most of the time this is a manual
step that an operator has to perform sitting in from of the console. On a few
pieces of hardware (most notable Dell IoT Gateway 300x family) there are ways
of manipulating firmware settings by means of a command line utility (e.g.
[cctk](https://www.dell.com/support/manuals/en-ae/dell-edge-gateway-3000-series-oem-ready/edge_gateway-3001-install_manual-oem/accessing-bios-settings?guid=guid-a8d2d3dc-68b4-4f59-9608-e0f75e374857)).

EVE currently doesn't support firmware updates, although preliminary work
to support [UEFI capsule](https://fwupd.org/) updates has been started.

EVE relies on UEFI implementation to correctly fill out SMBIOS and ACPI tables.
Unlike arm64 (see below), there's currently no way to patch those tables if
they are setup incorrectly.

## UEFI compliant firmware on arm64

From EVE's standpoint, ARM world is really bifurcated when it comes to firmware.
On rackable servers, EVE typically expects to find a self-contained UEFI
implementation which makes the rest indistinguishable from what was described
in the previous section for amd64 (even device trees are transparently passed
to EVE [from UEFI implementation](https://github.com/ARM-software/ebbr/blob/main/source/chapter2-uefi.rst#devicetree) without any extra effort).

On smaller ARM boards, the situation becomes much more complex. ARM boards typically
have different layers of firmware. Some that can be managed and easily and some that
can be not. For example, on a popular Raspberry Pi 4 ARM board there are at least
3 levels of firmware:

1. [Raspberry Pi 4 boot EEPROM](https://www.raspberrypi.org/documentation/hardware/raspberrypi/booteeprom.md) (formerly known as bootcode.bin)
2. [VideoCore boot firmware](https://github.com/raspberrypi/firmware)
3. [u-boot firmware](https://github.com/u-boot/u-boot/blob/master/configs/rpi_4_defconfig) or [UEFI firmware](https://github.com/tianocore/edk2-platforms/tree/master/Platform/RaspberryPi/RPi4)

EVE helps managing layers #2 and #3 and leaves #1 to the operator. In general,
as long as firmware can be derived from u-boot -- EVE can manage it by carrying
all the extra firmware blobs in its UEFI compliant exfat partiotion (UEFI doesn't
mind if extra files are present in that partition).

On ARM boards EVE leverages u-boot to provide UEFI environment and fill out SMBIOS
tables correctly. Unlike a fully compliant UEFI implementation, u-boot seems to
be a bit difficult when it comes to device tree pass-through via `EFI_DTB_GUID`.
Besides, there maybe situations when u-boot's own need for a particular set of
settings in the device tree might conflict with the needs of a hypervisor or
a kernel that is shipped as part of EVE. That's why on ARM boards EVE typically
has two device trees:

* u-boot specific device tree: typically located somewhere next to u-boot
binary/built right into u-boot or supplied by higher level firmware
* EVE specific device tree: shipped in EVE's rootfs image under `/boot/dtb/`.

EVE's grub config is in business of selecting an optional, EVE specific
device tree based on the vendor/product settings of the board it recognizes.
GRUB takes these values from SMBIOS tables and it is very important that they
are filled out correctly.

Luckily, starting from u-boot 2021.01 it is now possible to explicitly
specify vendor/product settings in the u-boot specific device tree
(either directly or via an overlay).

For example, on a stock Raspberry Pi 4, we are using the following [overlay](../pkg/u-boot/rpi/overlays/raspberrypi-rpi.dts)
and making sure it is explicitly set in config.txt in `dtoverlay=raspberrypi-rpi`
stanza. This has an effect of making GRUB pick up the correct EVE-specific
device tree from EVE's root filesystem. For products that bundle Raspberry Pi 4
with various HATs, the idea then is to have

* a product specific device tree always built as part of EVE
* an optional device tree overlay provided under overlays folder

This allows for a runtime re-configuration away from a stock Raspberry Pi 4
functionality to a more HAT-specific one by simply changing one line in
`config.txt`.

For example, for an industrial HAT produced by Advantech [UNO-220](https://www.advantech.com/products/9a0cc561-8fc2-4e22-969c-9df90a3952b5/uno-220-p4n2/mod_92d93912-216e-4ee9-a5ed-be94a5f1eca8)
here's how [EVE specific device tree](../pkg/new-kernel/patches-5.10.x/0021-Add-uno-220-dts.patch)
and a [u-boot specific overlay](../pkg/u-boot/rpi/overlays/raspberrypi-uno-220.dts)
would look like.
