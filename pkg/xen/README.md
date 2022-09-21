# How to hack Xen in EVE

## What to do if Xen hangs on boot

First things first: you should make sure that VT-x and VT-d are enabled in BIOS. And speaking of BIOS, you should keep an eye on the following options that may occasionally trip Xen up:

* ACPI C-state related options controlling [Xen power management](https://wiki.xenproject.org/wiki/Xen_power_management)
* Options controlling 2xAPIC being on or off

Tweaking this options back and forth may get you unstuck (or at least provide enough clue as to what to do next)

First things first: try booting Xen as an EFI payload directly from UEFI. This avoids GRUB in the middle and can sometime get Xen unstuck. Make sure to take xen.efi (different from default xen.gz available in our build) from the manual invocation of docker build . inside of pkg/xen folder and provide it with a xen.cfg looking something like:

```sh
[global]
default=xen

[xen]
options=console=vga,com1 com1=57600 loglvl=all noreboot <the rest of options from GRUB's Xen settings>
kernel=kernel root=/dev/sda2
```

Note that you DO have to supply *some* kind of a kernel (even if you're just trying to get Xen unstuck and not interested in dom0 booting)

It may actually be a good idea to rebuild Xen with the following tweak while you're at it:

```c
--- a/xen/include/asm-x86/apic.h
+++ b/xen/include/asm-x86/apic.h
@@ -5,7 +5,7 @@
 #include <asm/fixmap.h>
 #include <asm/msr.h>

-#define Dprintk(x...) do {} while (0)
+#define Dprintk printk
```

If that still doesn't provide you with any clue, start looking at tweaking Xen boot command line. Specifically:

* efi=[no-rs]
* cpuidle=0
* smt=0
* maxcpus=1
* nosmp
* iommu=no-igfx

As always, the [official documentation](https://xenbits.xen.org/docs/unstable/misc/xen-command-line.html) is your friend in all these tweaking.
