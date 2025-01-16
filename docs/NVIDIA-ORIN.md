# NVIDIA's Jetson Orin platform

Currently EVE supports the following devices based on the NVIDIA's Jetson Orin platform:

1. [Aetina AIE-PX22](#aetina-aie-px22)
1. [Aetina AIE-KN32](#aetina-aie-kn32)
1. [Jetson Orin Nano developer kit](#jetson-orin-nano-developer-kit)

The Jetson Orin platform has a complex boot flow[[1]](#references) that performs a lot of operations
to setup all the hardware: initialize memory controller, power up CPUs, load firmware components, etc. The last stage of
the bootloader provides an UEFI interface able to boot an UEFI capable Operating System. The bootloader can be present
in a bootable device, such as an SD Card, or at some internal memory of the device. EVE doesn't support embed the
bootloader on its image for the Jetson Orin platform, so the bootloader must be already present in the device.

## Aetina AIE-PX22

The [Aetina AIE-PX22](https://www.onlogic.com/store/jetagx/) it's a
powerful device based on the Jetson AGX Orin module. EVE supports only the
Jetpack 6.x version for this device. Thus, the bootloader must be
compatible with this version. Detailed instructions on how to update the
device for Jetpack 6 can be found on the following link: [Upgrading to Jetpack 6 on Aetina Jetson Devices](https://github.com/onlogic/Updating-to-Jetpack-6-for-Aetina-Jetson/tree/main)

Once the device has the Jetpack 6 installed (with the bootloader), EVE can
be installed into the device (or run from a live image from an USB Stick).

### Installing EVE on the Aetina AIE-PX22

1. Build an installation raw image `make ZARCH=arm64 HV=kvm PLATFORM=nvidia-jp6 installer-raw` (Only KVM is supported)
1. Flash the `dist/arm64/current/installer.raw` install EVE image onto an USB Stick [following these instructions](../README.md#3-flash-the-image-to-the-device)
1. Insert the USB Stick and power on the device

The installation process will start and it will install EVE on the eMMC and setup the persist storage on the NVMe device automatically.

If the installation succeed, the device will be powered off. Remove the USB Stick and power on the device again.

### Running a live image on the Aetina AIE-PX22

1. Build a live raw image `make ZARCH=arm64 HV=kvm PLATFORM=nvidia-jp6 live-raw` (Only KVM is supported)
1. Flash the `dist/arm64/current/live.raw` live EVE image onto an USB Stick [following these instructions](../README.md#3-flash-the-image-to-the-device)
1. Insert the USB Stick and power on the device

EVE should boot the live image and run from the USB Stick. **NOTE** that the eMMC must not contain an EVE installation,
otherwise it will conflict with the live image and **EVE will not run properly**.

> [!TIP]
> In case the device doesn't boot automatically from the USB stick, you can also boot it
> from the UEFI setup menu by pressing _ESC_ and accessing _Boot Manager_.

## Aetina AIE-KN32

The [Aetina AIE-KN32](https://www.aetina.com/products-detail.php?i=554) it's a device based on the Jetson Orin NX module.
The installation process it's exactly the same applied for the
[Aetina AIE-PX22](#aetina-aie-px22). The only exception is that EVE will be
installed entire in the NVMe SSD disk since it's the only built-in storage
present on the device.

## Jetson Orin Nano developer kit

The Jetson Orin Nano developer kit comes with a CoM (Computer on Module) without eMMC, so the entire OS should run from
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

- Download and extract the NVIDIA's Jetpack tarball:

```sh
wget https://developer.nvidia.com/downloads/embedded/l4t/r36_release_v3.0/release/jetson_linux_r36.3.0_aarch64.tbz2
tar -xvjf jetson_linux_r36.3.0_aarch64.tbz2
```

- Execute the flash.sh script tool to flash the bootloader to the QSPI EEPROM:

```sh
cd Linux_for_Tegra
sudo ./flash.sh --no-systemimg -c bootloader/generic/cfg/flash_t234_qspi.xml jetson-orin-nano-devkit mmcblk0p1
```

Once the procedure is done, power off the board and disconnect the pin _FC REC_ from the _GND_.

### Running a live image on the Jetson Xavier NX developer kit

1. Make sure the bootloader is present in the QSPI EEPROM
1. Build a live raw image `make ZARCH=arm64 HV=kvm PLATFORM=nvidia-jp5 live-raw` (Only KVM is supported)
1. Flash the `dist/arm64/current/live.raw` live EVE image onto an SD Card [following these instructions](../README.md#3-flash-the-image-to-the-device)
1. Insert the SD Card and power on the board

## References

1. [Jetson AGX Orin BootFlow](https://docs.nvidia.com/jetson/archives/r35.1/DeveloperGuide/text/AR/BootArchitecture/JetsonAgxOrinBootFlow.html)
1. [Aetina AIE-PX22](https://www.onlogic.com/store/jetagx/)
1. [Aetina AIE-KN32](https://www.aetina.com/products-detail.php?i=554)
