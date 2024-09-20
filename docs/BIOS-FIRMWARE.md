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
all the extra firmware blobs in its UEFI compliant exfat partition (UEFI doesn't
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

## Using OVMF with EVE

### What is OVMF?

OVMF (Open Virtual Machine Firmware) is a project that provides a UEFI firmware
implementation for virtual machines. It is part of the TianoCore open-source
UEFI development project. OVMF allows virtual machines to leverage UEFI
features, offering a modern firmware interface compared to traditional BIOS.

### When is OVMF Used?

In the context of EVE, OVMF is used for:

1. Applications Running in FML Mode.
1. Applications running on ARM Devices.

### OVMF Files

OVMF firmware consists of several files, including:

1. `OVMF_CODE.fd`: Contains the firmware code.
1. `OVMF_VARS.fd`: Contains the firmware variables.
1. `OVMF.fd`: A combined firmware image that includes both the code and
   variables.

In EVE, we use both approaches, depending on the application's requirements:
the combined `OVMF.fd` file, or separate `OVMF_CODE.fd` and `OVMF_VARS.fd` files.

### OVMF Settings (_VARS File)

OVMF uses a variable store file, commonly named `OVMF_VARS.fd`, to
persist UEFI variables across reboots. This file contains essential firmware
settings, including boot entries, framebuffer resolution, and other UEFI
configurations.

In the context of EVE, we use the separate `OVMF_VARS.fd` and `OVMF_CODE.fd`
files to customize the firmware settings. Having separate files allows us to
provide a customized `_VARS` file when we need to provide some specific
predefined settings. At the moment, we provide a custom `_VARS` file only
for setting the framebuffer resolution.

#### How We Store OVMF Settings Files

In EVE, we store the OVMF settings per application in the `persist/vault/ovmf`
directory. Each application has its own `_VARS` file, which is a copy of the
original `OVMF_VARS.fd` file.

#### Generating OVMF Settings Files

At the moment, we customize the OVMF settings manually to provide a way to
choose a specific resolution for the framebuffer. For that purpose, we build
the original OVMF_VARS.fd file from the edk2 sources, which are compiled as part
of the UEFI package in our build system and based on this file vary the
settings as needed.

1. Build an original OVMF_VAR file from the edk2 sources
1. Start a virtual machine using the freshly built OVMF_CODE.fd and OVMF_VARS.fd
   files to initialize the UEFI environment.
1. Access the OVMF UEFI setup menu during the VM's boot sequence.
1. Navigate through the menu to set the necessary firmware configurations
   required by EVE.
1. Clean the unnecessary settings. It is important to remove any auto-detected
   boot entries to prevent another VM from booting into an unintended path.
1. Commit the changes to the OVMF_VARS.fd file and save it as the customized
   _VARS file.

By pre-configuring the _VARS file, we eliminate the need for manual UEFI
configuration on each VM instance, streamlining the deployment process.

#### Alternative Approach for OVMF Settings

In the future, we plan to provide a more automated way to generate the OVMF
settings files. We can achieve this by creating a tool that allows EVE to set
the necessary firmware configurations programmatically. An example of such a
tool can be found in some popular Linux distributions. Technically, it is the
same as the manual approach, but it is automated and can be run as a script.
