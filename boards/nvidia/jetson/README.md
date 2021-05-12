# jetson-vanilla-boot

In L4T version 23.5, all Jetson Nano versions have the ability to move boot flow partitions to qspi. We use this to run any possible EFI-enabled Linux distributions, but Nvidia Jetson from BSP package has kernel, dtb and u-boot very different from vanilla versions. We have to change them to vanilla to be able to run vanilla kernel based operating systems like EVE.

## Supported

* Jetson nano developer's kit with 4GB of ram. [p3450-0000]

## Dependencies

* make
* bc
* curl
* bison
* flex
* python3
* python3-dev
* swig

## How to

### Download Nvidia BSP

```sh
./get-bsp 210
```

### Switch to vanilla

We can set u-boot and kernel dtb versions.

```sh
./make-u-boot v2021.04
./make-kernel-dtbs 5.10.7
```

### Switch jetson to recovery mode

For example jetson nano 4GB.

1) Connect FC REC pin with GND pin.
2) Switch power supply to micro usb. (We need open J48 Jumper)
3) Connect Jetson nano micro usb to PC usb port. (Pay attention to the power supply on the USB port of the computer)
4) Enter lsusb command on PC. We must see NVIDIA Corp. APX device, example:

```sh
Bus 001 Device 005: ID 0955:7f21 NVIDIA Corp. APX
```

### Flash Jetson

jetson nano example.

```sh
cd BSP/t210/Linux_for_Tegra/
sudo ./flash.sh jetson-nano-qspi mmcblk0p1
```

### Cleanup

After flash make clean

```sh
./make-clean
```
