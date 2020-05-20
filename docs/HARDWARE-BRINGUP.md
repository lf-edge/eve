# Bringing EVE up on new hardware

EVE currently support x86 and ARM Edge Nodes. It works best when hardware assisted virtualization is available, but it can run with reduced functionality on pretty much anything supported by the Linux kernel. Bringing EVE up on a new hardware configuration typically involves:

1. For ARM boards figure out the right device trees
2. Getting a reliable console (this could be graphical or serial) for early output
3. Figuring out your firmware/bootloader situation
4. Bringing up basic Linux kernel
5. Enabling at least one kind of persistent storage medium
6. Enabling KVM and Xen hypervisors
7. Enabling the rest of the hardware

## 1. Figuring out device trees for ARM

While x86 architecture is all about dynamic discovery of hardware via ACPI tables (more on that in Section 7) ARM architecture uses a static manifest called [Device Trees](https://elinux.org/Device_Tree_Reference) to describe all the hardware elements that kernel and hypervisors need to be aware of. This, in turn, creates a symbiotic relationship between what goes into a device tree manifest and a particular version of the kernel/hypervisor. Since at least type-1 hypervisors tend to stay rather hands-off when it comes to the kind of hardware that device tress describe (although there is still a minimum amount of [device tree handshake](https://wiki.xenproject.org/wiki/Xen_ARM_with_Virtualization_Extensions#Device_Trees)) it naturally follows that the source of truth for device trees stays within [Linux kernel](https://github.com/torvalds/linux/tree/master/arch/arm64/boot/dts). Linux kernel is also a place where you will find [tools](https://elinux.org/Device_Tree_Reference#Tools_in_Linux_kernel_source_tree) for working with device trees, with the most helpful being:

* `dtx_diff` allowing you to compare two device tree files
* `dt_to_config` telling you which Linux kernel options would be required for a given device tree

In the normal course of events, you can produce a device tree blob (dtb) matching your freshly built Linux kernel by simply running an equivalent of `make broadcom/bcm2711-rpi-4-b.dtb`. Once that is done you may still need to modify your device tree further. This is sometimes required so that a single device tree can be used by a Linux kernel and a type-1 Hypervisor and can be done by either editing the source of the device tree and rebuilding it with a `dtc` compiler or using a feature of device trees called an [overlay](https://www.raspberrypi.org/documentation/configuration/device-tree.md). Overlays are especially popular with manufacturers like Raspberry Pi since they allow them to ship single images that support various flavors of the boards they produce.

A lot of times, a device tree built from the kernel sources will be enough to get you going on a new piece of hardware. However, in certain cases you will be in need of a custom device tree provided only by a board manufacturer. In cases like those using a `dtx_diff` tool to inspect what was introduced and/or removed from a in-kernel device tree is the best way to make sure you enable your board without the need for a custom device tree (and worse yet a custom kernel).

## 1. Getting a reliable console

Having a reliable console as early in the edge node boot process as possible is a key to a frustration-free hardware enablement experience. Serial consoles work better than graphical ones (simply because you can easily cut-n-paste messages from it and you can script it as well). Fortunately, all component of the EVE stack (bootloaders, hypervisors, linux kernel) have a pretty good support for a variety of serial consoles as early as possible. In fact, even on ARM (where device trees are typically required for any kind of hardware interaction) early serial consoles can be specified explicitly -- all you have to do is find out the hardware handle for whatever piece of hardware drives your console. That said, it is absolutely critical that your device tree has a correct description of a serial console for a more steady-state console use (see section above on how to inspect device trees and make sure they contain something that looks like `console` `serial` or `uart` node).

### Early console for Linux kernel

Two options [earlycon=](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt#L1006) and [console=](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt#L627) are used to control console output. They both come with variety of options and a lot of times you simply need to cycle through them to pick one that works for you. For example, the following would work to give you an early console on Raspberry Pi 4 `console=uart8250,mmio32,0xfe215040 earlycon=uart8250,mmio32,0xfe215040`.

### Early console for Xen hypervisor

Note, that linux kernel actually has 3 level of different console output: a very early one (that needs to be statically configured in the kernel build), an `earlycon=` and then a regular `console=` console. Xen, on the other hand, only has an equivalent of the first and the 3d one.

The first kind of early console in Xen can be enabled during build as part of the DEBUG options. You can enable DEBUG either via Xen's build config UI (similar to Linux's `make menuconfig`) or through directly adding something like the following to your .config:

```console
CONFIG_DEBUG=y
CONFIG_EARLY_PRINTK=8250,0xfe215040,2
```

Here we're telling Xen to use 8250 UART with exactly the same address we gave to Linux kernel. Xen, however, also requires the 3d argument (2) which sets the offset for the UART I/O.

This early printk actually works pretty well, but the problem is: information about console is statically built into your Xen image (which means you'd have to have separate Xen images for different boards just to accommodate console output). A more flexible solution is to build a generic Xen image and tell it to use device trees to find out how to operate a console. Xen provides an option called `dtuart` and you can find more documentation on how to use it [here](https://wiki.xenproject.org/wiki/Xen_ARM_with_Virtualization_Extensions#Getting_Xen_output). In general `dtuart=<node in a device tree>` is what you would specify.

One word of caution: a lot of ARM board (like the ever popular Raspberry Pi) actually have multiple UARTs in them. A lot of times they can be switched back-and-forth using gpio pin muxing so you would use the same group of pins for different consoles. This means it is a bit of a trial and error to find the right setting in your device tree. In that sense, a statically configured earlyprintk may actually be an easier option to get going with the new board.

### Console in QEMU/ARM64

There are two subtle points when it comes to getting reliable console with QEMU/ARM64 emulation. First of all, QEMU only emulates pl011 UART (which means that things like earlyprintk on UART8250 as was described above won't wokr). Second point is that it is rather [futile](https://unix.stackexchange.com/questions/479085/can-qemu-m-virt-on-arm-aarch64-have-multiple-serial-ttys-like-such-as-pl011-t) to look for more than one pl011 UART with QEMU.

## Appendix

This is hall-of-fame for the manufacturers that provide extremely clear description of their hardware and what device drivers you need to use it:

* [Dell IoT Gateways 300x family](https://www.dell.com/support/manuals/us/en/04/dell-edge-gateway-3000-series/dell-edge_gateway-3002-install_manual/ubuntu-server-driver-information?guid=guid-d4a60c2c-be2e-4e46-b42b-eb26579e5ee1&lang=en-us)
