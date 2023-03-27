# Kernel dump collection in EVE-OS

## Intruduction to kexec and kdump

`kdump` is a standard Linux mechanism to dump machine memory content on kernel crash. `kdump` is based on `kexec`. `kdump` utilizes two kernels: system kernel and dump-capture kernel. System kernel is a normal kernel that is booted with special kdump-specific flags. We need to tell the system kernel to reserve some amount of physical memory where dump-capture kernel will be loaded. We need to load the dump-capture kernel in advance because at the moment crash happens there is no way to read any data from disk because kernel is broken.

Once kernel crash happens the kernel crash handler uses `kexec` mechanism to boot dump-capture kernel. Please note that memory with system kernel is untouched and accessible from dump-capture kernel as seen at the moment of crash. Once dump-capture kernel is booted, the user can use the file `/proc/vmcore` to get access to memory of crashed system kernel. The dump can be saved to disk or copied over network to some other machine for further investigation.

In the EVE environment, the system kernel and the dump-capture kernel are the same. Since the EVE kernel is quite minimal and contains all the options needed for a dump-capture kernel, a single compiled kernel binary simplifies the entire build process and does not require additional disk space to store the capture kernel.

## Setup dump-capture kernel in EVE-OS

First, memory must be reserved for dump capture kernel. The EVE-OS grub configuration has a kernel parameter `crashkernel=128M` which is only specified for the x86_64 architecture. After the system kernel is booted, the `/etc/init.d/000-kexec` script loads the same kernel binary into the reserved area by calling the kexec system tool.

At the moment, the only architecture supported for capturing kernel dumps is x86_64 with kvm virtualization (see pkg/grub/rootfs.cfg for details).

`kexec` loads the dump-capture kernel reusing the same command line with a couple of important differences: `irqpoll nr_cpus=1 reset_devices nomodule`, where:

* The `irqpoll` boot parameter reduces driver initialization failures due to shared interrupts in the dump-capture kernel.

* We generally don't have to bring up a SMP kernel just to capture the dump, hence we specify `nr_cpus=1` option while loading dump-capture kernel to restrict number of CPUs to 1 and to save memory.

* `reset_devices` force drivers to reset the underlying device during initialization.

* `nomodule` disable module load: make system simple and prevent possible further crash in the dump-capture kernel

Once `kexec` is called the system kernel is ready to handle a system crash by jumping to a dump-capture kernel in case of a panic.

**Note**: `kexec` load happens as a one-time operation via an early boot service and then immediately any further `kexec` gets blocked by writing to `/proc/sys/kernel/kexec_load_disabled`.

## EVE-OS behaviour in case of a system crash (kernel panic)

After successfully loading the dump-capture kernel as previously described in the introduction, the system will reboot into the dump-capture kernel if a system crash is triggered.  Trigger points are located in panic(), die(), die_nmi() and in the sysrq handler (ALT-SysRq-c). After the dump-capture kernel is booted, the file `/proc/vmcore` is used to get access to the memory of the crashed system kernel.

EVE-OS has a `kdump` container that checks for `/proc/vmcore` and generates a minimal crash dump by calling the makedumpfile tool. The `kdump` container is part of the linuxkit onboot process and is run strictly after the storage is initialized. The minimal kernel dump collection includes the following steps:

* Minimal kernel dump will be generated in the `/persist/kcrashes` folder.
* Dmesg (kernel ring buffer) of the crashed kernel will be saved in the `/persist/kcrashes` folder.
* Only 5 fresh kernel dumps and dmesgs are stored in the folder, old files are deleted.
* The whole dmesg from the crashed system buffer is written to the EVE-OS `/persist/reboot-stack` file.
* Only kernel panic message from the crashed system buffer is redirected to the tty console in order to show it on the connected monitor for debug purposes.
* Boot reason string "BootReasonKernel" is written to the EVE-OS `/persist/boot-reason` file.
* Reboot reason string "kernel panic, kdump collected: $KDUMP_PATH" is written to the EVE-OS `/persist/reboot-reason` file.
* After the crash dump is created, the kernel will be rebooted according to the `/proc/sys/kernel/panic` timeout configuration value.

As was mentioned earlier `makedumpfile` generates minimal kernel dump which excludes zeroed, cache, private, free and user-space memory pages. This is done not only to minimize the resulting dump file, but also for security reasons: customer data does not leak.

## Analysis of minimal kernel crash dumps

All kernel dumps should be downloaded from the `/persist/kcrashes` folder of the EVE-OS to the stable system with 'crash' tool installed.

   [crash utility](https://github.com/crash-utility/crash)

Crash document can be found at:

   [crash doc](https://crash-utility.github.io/)

In order to debug a minimal crash dump the kernel debug information is stored in 'kernel-debug.tar' archive and should be extracted from the EVE-OS `lfedge/eve-kernel` container.
