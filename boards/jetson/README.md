# jetson-vanilla-boot

In L4T version 23.5, all Jetson Nano versions have the ability to move boot flow partitions to qspi. We use this to run any possible EFI-enabled Linux distributions intact. For jetson nano, we build the kernel dtb and u-boot from source and flash it to qspi.

## Supported

* Jetson nano developer's kit with 4GB of ram.

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
./get-bsp 186
```

### Switch to vanilla

We can set u-boot and kernel dtb versions.

```sh
./make-u-boot v2021.01
./make-kernel-dtbs 5.4.51
```

### Switch jetson to recovery mode

For example jetson nano 4GB.

1) Connect FC REC pin with GND pin.
2) Connect Jetson nano micro usb to PC usb port. (Pay attention to the power supply on the USB port of the computer)
3) Enter lsusb command on PC, we can see

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
