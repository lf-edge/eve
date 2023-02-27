# Bringing EVE up on new hardware

EVE-OS currently supports x86 and ARM Edge Nodes. It works best when minimum [hardware security requirement](SECURITY-HARDWARE.md) is met and hardware assisted virtualization is available (ideally from existing [Alpine Linux](https://alpinelinux.org) support for the hardware), but it can run with reduced functionality on pretty much anything supported by the Linux kernel. Bringing EVE-OS up on a new hardware configuration typically involves:

0. Confirming that Alpine Linux supports the processor architecture.
1. For ARM boards, figuring out the right device trees
2. Getting a reliable console (this could be graphical or serial) for early output
3. Figuring out your firmware/bootloader situation
4. Bringing up basic Linux kernel
5. Enabling at least one kind of persistent storage medium
6. Enabling KVM and Xen hypervisors
7. Enabling the rest of the hardware

## 1. Figuring out device trees for ARM

While x86 architecture is all about dynamic discovery of hardware via ACPI tables (more on that in Section 7) ARM architecture uses a static manifest called [Device Trees](https://elinux.org/Device_Tree_Reference) to describe all the hardware elements that kernel and hypervisors need to be aware of. This, in turn, creates a symbiotic relationship between what goes into a device tree manifest and a particular version of the kernel/hypervisor. Since at least type-1 hypervisors tend to stay rather hands-off when it comes to the kind of hardware that device trees describe (although there is still a minimum amount of [device tree handshake](https://wiki.xenproject.org/wiki/Xen_ARM_with_Virtualization_Extensions#Device_Trees)) it naturally follows that the source of truth for device trees stays within the [Linux kernel](https://github.com/torvalds/linux/tree/master/arch/arm64/boot/dts). Linux kernel is also a place where you will find [tools](https://elinux.org/Device_Tree_Reference#Tools_in_Linux_kernel_source_tree) for working with device trees, with the most helpful being:

* `dtx_diff` allowing you to compare two device tree files
* `dt_to_config` telling you which Linux kernel options would be required for a given device tree

In the normal course of events, you can produce a device tree blob (dtb) matching your freshly built Linux kernel by simply running an equivalent of `make broadcom/bcm2711-rpi-4-b.dtb`. Once that is done you may still need to modify your device tree further. This is sometimes required so that a single device tree can be used by a Linux kernel and a type-1 Hypervisor. Modification can be done by either editing the source of the device tree and rebuilding it with a `dtc` compiler or using a feature of device trees called an [overlay](https://www.raspberrypi.org/documentation/configuration/device-tree.md). Overlays are especially popular with manufacturers like Raspberry Pi since they allow them to ship single images that support various flavors of the boards they produce.

A lot of times, a device tree built from the kernel sources will be enough to get you going on a new piece of hardware. However, in certain cases you will be in need of a custom device tree provided only by the board manufacturer. In cases like those, using a `dtx_diff` tool to inspect what was introduced and/or removed from an in-kernel device tree is the best way to make sure you enable your board without the need for a custom device tree (and worse yet a custom kernel).

## 2. Getting a reliable console

Having a reliable console as early in the edge node boot process as possible is key to a frustration-free hardware enablement experience. Serial consoles provide more flexibility than graphical ones (simply because you can easily cut-n-paste messages from it and you can script it as well). Fortunately, all components of the EVE stack (bootloaders, hypervisors, linux kernel) have pretty good early access support for a variety of serial consoles. In fact, even on ARM (where device trees are typically required for any kind of hardware interaction), early serial consoles can be specified explicitly -- all you have to do is find out the hardware handle for whatever piece of hardware drives your console. That said, it is absolutely critical that your device tree has a correct description of your hardware's serial console so that you can depend on reliable console use. (See the section above on how to inspect device trees and make sure they contain something that looks like `console` `serial` or `uart` node).

### Early console for Linux kernel

Two options, [earlycon=](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt#L1006) and [console=](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/kernel-parameters.txt#L627), are used to control console output. They both come with a variety of options and often you simply need to cycle through them to pick one that works for you. For example, the following would work to give you an early console on Raspberry Pi 4 `console=uart8250,mmio32,0xfe215040 earlycon=uart8250,mmio32,0xfe215040`.

### Early console for Xen hypervisor

Note, that the Linux kernel actually has 3 levels of different console output: a very early one (that needs to be statically configured in the kernel build), an `earlycon=`, and a regular `console=` console. Xen, on the other hand, only has the equivalent of the first and third one.

The first kind of early console in Xen can be enabled during build as part of the DEBUG options. You can enable DEBUG either via Xen's build config UI (similar to Linux's `make menuconfig`) or through directly adding something like the following to your .config:

```console
CONFIG_DEBUG=y
CONFIG_EARLY_PRINTK=8250,0xfe215040,2
```

Here we're telling Xen to use 8250 UART with exactly the same address we gave to the Linux kernel. Xen, however, also requires the 3rd argument (2) which sets the offset for the UART I/O.

This early printk method works pretty well, but with one problem: information about the console is statically built into your Xen image (which means you'd need separate Xen images for different boards just to accommodate console output). A more flexible solution is to build a generic Xen image and tell it to use device trees to find out how to operate a console. Xen provides an option called `dtuart` and you can find more documentation on how to use it [here](https://wiki.xenproject.org/wiki/Xen_ARM_with_Virtualization_Extensions#Getting_Xen_output). In general `dtuart=<node in a device tree>` is what you would specify.

One word of caution: a lot of ARM boards (like the ever popular Raspberry Pi) actually have multiple UARTs in them. A lot of times they can be switched back-and-forth using gpio pin muxing so you would use the same group of pins for different consoles. This means it is a bit of a trial and error to find the right setting in your device tree. In that sense, a statically configured earlyprintk may actually be an easier option to get going with a new board.

### Console in QEMU/ARM64

There are two subtle points when it comes to getting a reliable console with QEMU/ARM64 emulation. First of all, QEMU only emulates pl011 UART (which means that things like earlyprintk on UART8250 as was described above won't work). Second point is that it is rather [futile](https://unix.stackexchange.com/questions/479085/can-qemu-m-virt-on-arm-aarch64-have-multiple-serial-ttys-like-such-as-pl011-t) to look for more than one pl011 UART with QEMU.

## 3. Figuring out your firmware/bootloader situation

Please refer to the [BIOS/Firmware management doc](BIOS-FIRMWARE.md) if you are interested in a generic introduction. A few useful tricks that may come in handy are:

* use custom/vendor provided device trees - just drop them into the config partition as `eve.dtb`
* `grub.cfg` in the config partition is very helpful to deal with one-off issues to provide a rapid edit-compile-run cycle
* initrd from the installer phase can be used when you don't have Linux kernel with storage support

## 4. Bringing up basic Linux kernel

It is recommended to focus on bringing up the basic Linux kernel first before you can proceed with the rest of hardware enablement. Doing so will allow you to use it as a tool to inspect your hardware further, which is especially useful in situations where you don't have working drivers for storage yet (see the section above on using initrd). The usual sequence is:

* Enabling at least one kind of persistent storage medium
* Enabling KVM and Xen hypervisors
* Enabling the rest of the hardware

If the last point sounds a lot like [draw the rest of the owl](https://knowyourmeme.com/memes/how-to-draw-an-owl) that's because it largely is. The good news is that unlike most traditional Linux distributions, EVE offloads a lot of the hardware management to user VMs running on top of it. All that EVE needs to do is make sure it can virtualize the buses that hardware is connected to AND enable a few critical hardware pieces for its own use:

* Wired networking (this allows EVE to talk to its controller and update its rootfs images via the network)
* TPM (or any other hardware trust element)
* Watchdog
* LEDs (to allow EVE to signal its state)
* USB
* [Radio hardware (WiFi, LTE, BLE, Zigbee, LoRA, etc.)](WIRELESS.md)
* I/O hardware (serial ports, GPIO, sensors, etc.)
* Any other hardware that you may discover in ACPI tables or device tree

### 4.1. Hardware discovery

Linux kernel tries to mostly stay away from probing the hardware and relies on firmware to provide it with a manifest. This manifest is expressed as [ACPI tables](https://lwn.net/Articles/367630/) on Intel and [device tree (or Open Firmware)](https://www.raspberrypi.org/documentation/configuration/device-tree.md) pretty much everywhere else. Linux kernel will attempt to traverse the manifest, create device objects for whatever it finds there, and later bind drivers to these objects. If the hardware manifest is done correctly, all of the hardware can be discovered and initialized. Given that Linux kernel is faithfully externalizing device and driver objects through the [sysfs filesystem](https://www.kernel.org/doc/html/latest/filesystems/sysfs.html), it becomes an indispensable tool for hardware bringup.

#### 4.1.1. Hardware discovery via ACPI tables

Crafting ACPI tables is UEFI/BIOS responsibility. The final set of tables is based on what is known about the hardware plus whatever selections were made inside of BIOS's interactive configuration screen (it is *very* easy to forget that tweaking those knobs will change your ACPI tables in subtle ways -- and those changes are especially opaque to an Operating System). One way for UEFI/BIOS to hide a piece of hardware from an operating system is to assign a `_STA` method to be 0. If an entry has that set, Linux kernel will skip it altogether (although you will still see it in the raw binary table).

Start exploring ACPI tables from the bottom up. The raw tables are available under `/sys/firmware/acpi/tables`. It is recommended that you copy them to the read-write location and then run an [iasl](https://pkgs.alpinelinux.org/package/edge/main/x86/iasl) to disassemble them into a human readable format. Grepping for `_HID` and `_DDN` will reveal some of the human readable names for the hardware elements (inspecting tables by hand is actually not that difficult). `_HID` strings are especially useful since you can grep Linux kernel source tree for them (or Google them) to reveal what drivers are expected to control this particular piece of hardware. Another extremely useful set of tools for exploring ACPI tables is [acpidump/acpixtract/acpiexec](https://ubuntu.com/blog/debug-dsdt-ssdt-with-acpica-utilities) from [acpica project](https://github.com/acpica/acpica). These tools allow not only for static inspection, but also for dynamic "what-if" execution of ACPI methods.

If there are nodes present in the table with their `_STA` methods returning 0 (disabled) you have two choices: figure out how to put the BIOS menu knobs into the right configuration OR resort to [ACPI](https://01.org/linux-acpi/documentation/overriding-dsdt) [live](https://forums.gentoo.org/viewtopic-t-122145-start-0.html) [patching](https://www.kernel.org/doc/html/latest/firmware-guide/acpi/method-customizing.html) to enable that node. Here is an example for how SPI nodes [get enabled on UP2 board](https://github.com/up-board/up-community/wiki/Pinout_UP2#installing-acpi-overrides-to-enable-spi-in-userspace).

The next level up from inspecting raw ACPI tables is inspecting the device hierarchy that got instantiated based on them by the Linux kernel (note we still don't care if there's a driver for that device -- just that the device object got created). You can do that by poking under `/sys/devices/LNXSYSTM:*` and trying to match its content with `_HID` and `_DDN` names.

#### 4.1.2. Hardware discovery via device tree

For device tree the process is effectively the same, although unlike ACPI tables, in most situations you can control how device tree looks to the Linux kernel directly. The trick with device trees and Linux kernel is that the two require a great deal of coupling and it is NOT uncommon to have device trees that would work with kernel version X and break with kernel version Y. This is exactly why most reliable device trees still come out of the linux kernel build (under `arch/X/boot/dts/` folder). EVE prefers all of its device trees to be available in the source form (to facilitate rebasing on newer kernels) and we try to use as much of the kernel own's device tree source as possible (by moving all the custom tweaks to device trees into standalone DTS files that include the bulk of the definitions from the kernel and simply tweak the rest - see [this as a good example](https://github.com/lf-edge/eve/blob/6.4.0/pkg/new-kernel/patches-5.11.x/0021-Add-uno-220-dts.patch)). Still there are times when you have to deal with vendor provided device tree binary blobs (either given to you as a file OR given to the Linux kernel by the UEFI BIOS). At that point you deal with them as you would deal with raw ACPI tables but you would use [dtc](https://pkgs.alpinelinux.org/package/edge/main/x86/dtc) tool to disassemble them via `dtc -I fs -O dts /sys/firmware/device-tree/base` and then manually inspect their elements.

The Linux kernel view of the device hierarchy created based on the information presented in a device tree is available under `/sys/devices/platform`.

### 4.2. Bus discovery

Having a manifest of all the hardware present on the system is only as useful as a CPU's ability to talk to all that hardware. Some of the hardware can be driven directly by memory mapped registers and DMA, other components require buses to be available. A bus itself is like a hardware device (at least the end of the bus that connects to the host CPU) and Linux kernel tracks all the buses it knows about under `/sys/bus/`. Before you try enabling a driver, make sure that the required bus is visible under `/sys/bus/BUS-NAME`. The most interesting subfolder under that is `/sys/bus/BUS-NAME/devices`. This is Linux kernel's idea of what devices sit on that bus. Sophisticated buses (like USB) allow for dynamic device enumeration and discovery so that `/sys/bus/usb/devices` is maintained up-to-date by the bus driver itself. Simpler buses (like I2C) don't allow for device discovery. The device sitting on such a bus has to either be described in an ACPI table or device tree entry OR it has to be [manually instantiated](https://www.kernel.org/doc/html/latest/i2c/instantiating-devices.html). For example, the following will instantiate device with the name `eeprom` at I2C address `0x50` on an I2C bus #3:

```console
echo eeprom 0x50 > /sys/bus/i2c/devices/i2c-3/new_device
```

When dealing with any bus (even sophisticated ones like USB), tools that aid in probing and discovery are a must (you will find most of them in EVE's debug container):

* [lspci](https://pkgs.alpinelinux.org/package/edge/main/x86_64/pciutils) for PCI discovery
* [lsusb](https://pkgs.alpinelinux.org/package/edge/main/x86/usbutils) for USB discovery
* [i2c-tools](https://pkgs.alpinelinux.org/package/edge/community/x86_64/i2c-tools) for I2C discovery
* [spi-tools](https://pkgs.alpinelinux.org/package/edge/community/x86_64/spi-tools) for SPI discovery

If all else fails you may need to write [your own client](https://www.kernel.org/doc/Documentation/i2c/writing-clients).

### 4.3 Pin control

Before PCIe, memory mapped registers, and DMA, hardware could only be accessed by a CPU via pins on its package (these pins are also known as GPIO). Electrically, a given digital IO pin can be either at 0 or 1 (represented by a low or high voltage level). The CPU has two ways of having pin values change:

* bit-banging: write a 0 or 1 to a certain memory mapped register that is associated with a pin
* pin muxing: arrange for the pin to be driven high or low by an external electronic component (often according to a specific protocol)

Bit-banging is generally slow (the speed at which you can oscillate between 1s and 0s is effectively determined by the speed at which your CPU executes instructions) but is [extremely flexible](http://web.mit.edu/6.115/www/document/psoc_vga_design.pdf). Pin muxing is much faster (to a point where you can [turn your RaspberyPi's GPIO into an FM transmitter](http://icrobotics.co.uk/wiki/index.php/Turning_the_Raspberry_Pi_Into_an_FM_Transmitter)) but depends on knowing exactly what kind of electronic components can be arranged to drive [certain pins](https://pinout.xyz/).

Linux kernel manages pin muxing through its [pin control subsystem](https://www.kernel.org/doc/html/latest/driver-api/pinctl.html) which is inextricably [linked with GPIO](https://www.kernel.org/doc/html/latest/driver-api/pinctl.html#interaction-with-the-gpio-subsystem). At the end of the day, when pin muxing has done its job, some pins will be made available to the user via [Linux's GPIO subsystem](https://www.kernel.org/doc/html/latest/driver-api/gpio/intro.html) and some will be attached to electronic components. The problem with pinmuxing in Linux kernel is that it is rather invisible. Its settings are controlled either via ACPI tables or device tree entries (sometimes it is even [statically defined](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/pinctrl/intel/pinctrl-baytrail.c#n109) in the source itself). Only the tip of the pinctrl iceberg is showing through the GPIO subsystem.

When it comes to the GPIO subsystem, the tools of the trade are `/sys/class/gpio/` and [gpiotools](https://pkgs.alpinelinux.org/package/edge/community/x86_64/libgpiod) (although on RaspberryPi an amazing [wiringpi](http://wiringpi.com/) toolset is also available). `gpioinfo` is particularly useful, since it tracks pin assignment as well (something that is not readily available from `sysfs`). The importance of the correct pin assignment (done by the pinctrl subsystem) can *not* be overstated: get it wrong and you will be cut off from the ability to communicate with eMMC cards, certain buses, and some really deep subsystems in your SoC. The rule of thumb is this: if something is mysteriously broken, check pinctrl first. A lot of times tracking the lineage of SoCs can be helpful in debugging pinctrl issues and one great resource for that is [WikiChip](https://en.wikichip.org/wiki/WikiChip)

Finally, be aware that GPIO can also be used for input. In fact, it can be used for input as early as firmware on some systems. For example, tying certain pins to ground (0, or low voltage) is how Raspberry Pi can allow [conditionals in its boot process](https://www.raspberrypi.org/documentation/configuration/config-txt/conditional.md).

### 4.4. LEDs

Physically, LEDs present on your system are likely to be connected to one of the GPIO pins. If your GPIO subsystem is showing all the GPIO chips available under `/sys/class/gpio`, you can try brute-forcing discovery of an LED by triggering each pin in sequence. Sometimes, however, the GPIO pins can [only be controlled through secret memory mapped registers](https://lab.whitequark.org/notes/2017-11-08/accessing-intel-ich-pch-gpios/), and if your Linux GPIO subsystem doesn't know about those, [writing your own device driver](https://github.com/lf-edge/eve/blob/6.4.0/pkg/new-kernel/patches-5.11.x/0022-siemens-ipc127-leds.patch) becomes your only option.

### 4.5. I/O hardware

Typically IoT-class I/O hardware (serial ports, GPIO, sensors, etc.) will be connected to the main system via a set of micro controllers speaking one of the IC protocols [I2C, SPI or LPSS](https://www.seeedstudio.com/blog/2019/09/25/uart-vs-i2c-vs-spi-communication-protocols-and-uses/). This arrangement also allows nesting, where a set of pins connected to the CPU will be pinctrl muxed to speak one of those protocols, but on the other side there will be a [GPIO chip](https://www.dialog-semiconductor.com/applications/configurable-mixed-signal-ic-solutions/gpio-expander) offering additional GPIO pins.

## 5. Working with drivers

At this point, you should have a reliable process for getting EVE to boot all the way from BIOS/Firmware to mounting a root filesystem from one of the permanent storage devices. While EVE may still not be able to talk to its controller if your networking hardware isn't supported by default, this now creates a stable point for the rest of hardware bringup. You can quickly boot, make durable changes to the boot process by modifying GRUB's override file in `/config/grub.cfg` and even experiment with rebuilding kernels without rebuilding EVE's entire rootfs (just put your experiments kernels in EFI partition). The rest of the process is typically focused on making sure that drivers responsible for the hardware elements behave in predictable ways.

The lifecycle process for working with drivers starts with the kernel issuing kmod events [with a given modalias](https://wiki.archlinux.org/index.php/Modalias). This triggers loading of the kernel module associated with that modalias, and will eventually result in the driver being *bound* to the piece of hardware. In rare cases, this automatic instantiation can get in the way and if so, you might need to control it by writing 0 to `/sys/bus/*/drivers_autoprobe` files. This becomes [much more difficult](http://lkml.iu.edu/hypermail/linux/kernel/0806.2/0653.html) with statically compiled drivers AND with bus auto discovery. Sometimes, even though the device driver gets bound automatically, it is safe to unbind it for debugging and then bind it again. This is done by writing a bus-specific ID to the `unbind` and `bind` files. For example, here's how it would look for a PCI and an I2C driver:

```console
# echo 0000:00:10.0 > /sys/bus/pci/drivers/xhci_hcd/unbind
# echo 0000:00:10.0 > /sys/bus/pci/drivers/vfio-pci/bind
# echo 2-0052 > /sys/bus/i2c/drivers/at24/unbind
# echo 2-0052 > /sys/bus/i2c/drivers/itx8/bind
```

Note that unbinding a device (and re-binding it to a special driver like `vfio-pci`) is what is used for devices that can be virtualized.

## Appendix

This section is the hall-of-fame for manufacturers that provide extremely clear descriptions of their hardware and what device drivers you will need to use it:

* [Dell Edge Gateway 300x family](https://www.dell.com/support/manuals/us/en/04/dell-edge-gateway-3000-series/dell-edge_gateway-3002-install_manual/ubuntu-server-driver-information?guid=guid-d4a60c2c-be2e-4e46-b42b-eb26579e5ee1&lang=en-us)
