# NVIDIA's Jetson Xavier NX platform

Currently EVE supports the following devices from NVIDIA's Jetson Xavier NX platform:

1. Lenovo ThinkEdge SE70
1. NVIDIA Jetson Xavier NX developer kit

The Jetson Xavier NX platform has a complex boot flow[[1]](#references) that performs a lot of operations
to setup all the hardware: initialize memory controller, power up CPUs, load firmware components, etc. The last stage of
the bootloader provides an UEFI interface able to boot an UEFI capable Operating System. The bootloader can be present
in a bootable device, such as an SD Card, or at some internal memory of the device. EVE doesn't support embed the
bootloader on its image for the Jetson Xavier NX platform, so the bootloader must be already present in the device.

## Lenovo ThinkEdge SE70

The bootloader of the Lenovo ThinkEdge SE70 device is already present on its internal memory and it also supports
booting from an USB Stick. In order to install EVE (or run it from a live image) the corresponding image must be written
to an USB Stick and the device must be configured to try to boot first from external bootable devices. The boot order
can be changed in the bootloader's setup interface with the following steps:

1. Power on the device
1. Press F1 during initialization to enter in the bootloader setup interface. If key pressing doesn't work, perform a
   full recovery of the device[[2]](#references)
1. Inside the bootloader setup interface, navigate through the menus *Device Manager->NVIDIA Resource Configuration*
1. In the field *"Add new devices to Top or bottom of boot order"* set the option *"Top"*
1. Press F10 to save the new settings
1. Exit the bootloader setup and reboot the device

### Installing EVE on the ThinkEdge SE70

1. Build an installation raw image `make ZARCH=arm64 HV=kvm PLATFORM=nvidia installer-raw` (Only KVM is supported)
1. Flash the `dist/arm64/current/installer.raw` install EVE image onto an USB Stick [following these instructions](../README.md#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)
1. Insert the USB Stick and power on the device

The installation process will start and it will install EVE on the NVMe automatically.

> **:warning: WARNING !**
>
> The installation process will wipe off both eMMC and NVMe. Any data present on these devices will be lost.

If the installation succeed, the device will be powered off. Remove the USB Stick and power on the device again.

### Running a live image on the ThinkEdge SE70

1. Build a live raw image `make ZARCH=arm64 HV=kvm PLATFORM=nvidia live-raw` (Only KVM is supported)
1. Flash the `dist/arm64/current/live.raw` live EVE image onto an USB Stick [following these instructions](../README.md#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)
1. Insert the USB Stick and power on the device

EVE should boot the live image and run from the USB Stick. **NOTE** that the NVMe SSD must not contain an EVE installation,
otherwise it will conflict with the live image and **EVE will not run properly**.

## Jetson Xavier NX developer kit

The Jetson Xavier NX developer kit comes with a CoM (Computer on Module) without eMMC, so the entire OS should run from
an SD Card. However, the device has a small QSPI EEPROM where the bootloader can be written in order to boot the board.

### Flashing the bootloader to QSPI EEPROM

- Put the device into the recovery mode:

1. Power off the board
1. Connect the pin (using a jumper or a wire) **FC REC** to the **GND**. These are the second (GND) and third (FC REC) pins counting from the PWR BTN pin.
1. Attach it to a host computer through the micro USB port.
1. Power on the board

On the host computer, the following device should appear in the USB bus:

```sh
Bus 001 Device 120: ID 0955:7e19 NVIDIA Corp. APX
```

- Download and extract the NVIDIA's Jetpack tarball from the following [link](https://developer.nvidia.com/embedded/l4t/r35_release_v1.0/release/jetson_linux_r35.1.0_aarch64.tbz2):

```sh
wget https://developer.nvidia.com/embedded/l4t/r35_release_v1.0/release/jetson_linux_r35.1.0_aarch64.tbz2
tar -xvjf jetson_linux_r35.1.0_aarch64.tbz2
```

- Execute the flash.sh script tool to flash the bootloader to the QSPI EEPROM:

```sh
cd Linux_for_Tegra
sudo ./flash.sh jetson-xavier-nx-devkit-qspi internal
```

Once the procedure is done, power off the board and disconnect the pin *FC REC* from the *GND*.

### Running a live image on the Jetson Xavier NX developer kit

1. Make sure the bootloader is present in the QSPI EEPROM
1. Build a live raw image `make ZARCH=arm64 HV=kvm PLATFORM=nvidia live-raw` (Only KVM is supported)
1. Flash the `dist/arm64/current/live.raw` live EVE image onto an SD Card [following these instructions](../README.md#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)
1. Insert the SD Card and power on the board

## References

1. [Jetson Xavier NX BootFlow](https://docs.nvidia.com/jetson/archives/r35.2.1/DeveloperGuide/text/AR/BootArchitecture/JetsonXavierNxAndJetsonAgxXavierBootFlow.html)
1. [ThinkEdge SE70 Recovery process](https://smartsupport.lenovo.com/de/en/products/smart/smart-edge/thinkedge-se70/)
