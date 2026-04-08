# How to use EVE-OS on a NVIDIA Jetson platform

NVIDIA Jetpack is the NVIDIA's software stack for Jetson modules and
developer kits. EVE supports three versions of the Jetpack: 5.1.3, 6.0, and 7.1.
These versions covers different devices from different Jetson platforms, as
shown by the Tables __1__ and __2__.

|            | Jetson AGX Orin | Jetson AGX Orin Industrial | Jetson Orin NX / Orin Nano | Jetson AGX Xavier | Jetson AGX Xavier Industrial | Jetson Xavier NX |
|------------|-----------------|----------------------------|----------------------------|-------------------|------------------------------|------------------|
| Jetpack 6.0   |:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:| | | |
| Jetpack 5.1.3 |:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|:heavy_check_mark:|

Table __1__: Jetpack support. _Source: [Jetson Linux Archive](https://developer.nvidia.com/embedded/jetson-linux-archive)._

|            | Jetson T5000 | Jetson T4000 | Jetson AGX Orin | Jetson Orin NX | Jetson Orin Nano |
|------------|--------------|--------------|-----------------|----------------|------------------|
| Jetpack 7.1 |:heavy_check_mark:|:heavy_check_mark:| | | |

Table __2__: Jetpack 7.1 support. _Source: [Jetson Linux Archive](https://developer.nvidia.com/embedded/jetson-linux-archive)._

For each Jetpack version supported, EVE provides all default libraries and
related files present in a regular installation of Jetpack under
_/opt/vendor/nvidia_ in the host system. These libraries are available for
Edge Apps through a CDI (Container Device Interface) mechanism. For more
information on how to setup containers to make use of it see [Hardware
Model](./HARDWARE-MODEL.md) documentation.

It's important to point out that EVE uses its own kernel derived from the
original kernel of the Jetpack Linux distro. All kernel versions used by
EVE are available at the
[eve-kernel](https://github.com/lf-edge/eve-kernel) project.

Even though a device is based on any of the supported Jetson platforms, it
doesn't mean it will work with EVE out of the box. Usually, edge devices
based on these platforms are equipped with additional hardware that might
require kernel support. If you are looking for support for a device not listed
in this page, please, raise an issue on EVE's Git Hub project.

## How to use on a Jetson Orin platform

Currently EVE supports the following devices based on the NVIDIA's Jetson Orin platform:

1. Aetina AIE-PX22 (Jetson Orin AGX)
1. Aetina AIE-KN32 (Jetson Orin NX)
1. Jetson Orin Nano developer kit

See [NVIDIA-ORIN.md](./NVIDIA-ORIN.md) for instructions on how to build and deploy EVE on these devices.

## How to use on a Jetson Xavier NX platform

Currently EVE supports the following devices based on the NVIDIA's Jetson Xavier NX platform:

1. Lenovo ThinkEdge SE70
1. Siemens SIMATIC IPC520A
1. Jetson Xavier NX developer kit

See [NVIDIA-NX.md](./NVIDIA-NX.md) for instructions on how to build and deploy EVE on these devices.

## How to use on a Jetson Thor device

EVE supports Nvidia Jetpack 7.1 on the [Jetson Thor device](https://www.nvidia.com/en-us/autonomous-machines/embedded-systems/jetson-thor/). The installation process is pretty standard:

1. Build an installation raw image `make ZARCH=arm64 HV=<kvm or k> PLATFORM=nvidia-jp7 installer-raw` (`xen` is not supported)
1. Flash the `dist/arm64/current/installer.raw` install EVE image onto an USB Stick [following these instructions](../README.md#3-flash-the-image-to-the-device)
1. Insert the USB Stick and power on the device

The installation process will start and it will install EVE on the NVMe.

If the installation succeed, the device will be powered off. Remove the USB Stick and power on the device again.

## Partial supported devices

### How to use on a Jetson Nano 4GB ARM board

In Jetson Nano, from January 22, 2021, it became possible to save the u-boot to an internal qspi chip. Following the instructions from the first point and specifying the kernel and u-boot versions in the same way as in EVE, we can run it on the Jetson nano with 4GB of RAM.

1. Follow steps in [instruction](https://github.com/lf-edge/eve/blob/master/boards/nvidia/jetson/README.md) for flash jetson boot flow partitions to qspi.
1. Make sure you have a clean build directory (since this is a non-standard build) `rm -rf dist/arm64`
1. Build a live image `make ZARCH=arm64 HV=kvm live-raw` (Only KVM is supported)
1. Flash the `dist/arm64/current/live.raw` live EVE image onto your SD card by [following these instructions](../README.md#3-flash-the-image-to-the-device)

> **:warning: WARNING !**
>
> NVIDIA's kernel for Jetson Nano is based on an old Linux kernel version 4.x, not ported to EVE. Thus, the support for this device is limited.

## References

1. [Jetson Software](https://developer.nvidia.com/embedded/develop/software)
1. [Jetson Linux Archive](https://developer.nvidia.com/embedded/jetson-linux-archive)
