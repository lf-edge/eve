# EVE's use of hypervisors and hardware assisted virtualization

EVE is slightly unusual in how it looks at hypervisors and hardware assisted virtualization technology. Unlike some of the other systems that were clearly built as virtualization platforms (ESXi, Hyper-V, etc.) EVE's ultimate task is to be able to run [Edge Containers](ECOS.md) as efficiently (and securely!) as possible. A running ECO is represented as a series of tasks consuming resources provided by each Edge Node (such as CPU, RAM, volumes, network instances, etc.). Tasks can further improve their performance and security by requesting accelerator and/or isolation services typically provided by type-1 or type-2 hypervisors and backed by hardware assisted virtualization.

This mapping of Tasks to resources creates an interesting architecture where things like virtualization capabilities can be consumed transparently without the user explicitly tweaking the virtualization knobs like it would be the case with systems like libvirt/virsh.

The rest of this document summarizes various implementation details we leverage for providing acceleration and isolation services to tasks.

## Device models

Assigning resources to tasks involves two types of assignment:

* dedicated, where resources are assigned directly to the workload
* virtualized, where resource are assigned in a virtualized fashion, enabling the host to multiplex them among multiple guests and the host itself

Whenever a task gets isolated into a standalone domain, for performance or security reasons, domain gets assigned a certain, fixed amount of RAM and can have a number of virtual CPUs that would get multiplexed on top the physical CPUs available on the Edge Node. Additionally, a task may request a subset of PCI devices to be available to it exclusively, which makes them unavailable for any other domains and the host itself. Providing RAM, CPU and direct PCI assignment to a given task is one half of a job of any hypervisor. That's the easy part.

The difficult (or at least much more involved part) is how to present a series of devices (network, disk, GPU, console) to the task in such a way as to allow them to be multiplexed to the actual physical devices available on the host. This is know as providing a "device model" to the domain and it is where the art of virtualization really begins.

All domains get presented with a "device model" that consists of a virtual set of buses and virtual devices attached to those buses. Domains can initiate I/O to any of these buses/devices and that I/O gets routed by the hypervisor to the outside of the domain. Servicing that I/O on the host side can then be done either by:

1. Host Linux kernel directly
2. A user-space program

Normally, a user-space program will require more context switches and will always be slower than corresponding code running directly in the host kernel space. But even then, a user-space program can be thought of as a I/O emulation of "last resort" (if there's no direct support in the kernel for the corresponding bus and/or device). This kind of a user space program is known as a Virtual Machine Monitor (VMM). Qemu is the most featureful VMM that exists today in open source and currently EVE is using it for all the hypervisors it supports. However, depending on how our use cases evolve we may start using more lightweight (or specialized) VMMs in the future, such as:

* [Firecracker](https://github.com/firecracker-microvm/firecracker/blob/master/docs/design.md)
* [ukvm/solo5](https://www.usenix.org/sites/default/files/conference/protected-files/hotcloud16_slides_williams.pdf)
* [ACRN DM](https://projectacrn.github.io/latest/developer-guides/hld/hld-devicemodel.html)

Obviously, every time we have a choice (e.g. we have full control over the device drivers running in the task's kernel), we will make sure that tasks can use device models that are mostly satisfied by the Linux kernel itself. The following table summarizes the choices available for Xen and KVM:

|                      |Xen         |KVM                                                          |
|----------------------|------------|-------------------------------------------------------------|
|Specialized VMM Bus   | XEN_XENBUS | [Virtio-PCI, Virtio-MMIO](https://lwn.net/Articles/808235/) |
|PCI bus               | N/A        | VIRTIO_PCI, VOP (Virtio over PCIe)                          |
|Direct PCI assignment | XEN_PCIDEV_FRONTEND,BACKEND | [VFIO](https://www.kernel.org/doc/Documentation/vfio.txt) [QEMU intel-iommu](https://wiki.qemu.org/Features/VT-d) |
|Block devices         | XEN_BLKDEV_FRONTEND,BACKEND | VIRTIO_BLK                                 |
|SCSI block devices    | XEN_SCSI_BACKEND            | [VHOST_SCSI, SCSI_VIRTIO](https://www.ovirt.org/develop/release-management/features/storage/virtio-scsi.html) |
|POSIX filesystem      | NET_9P_XEN                  | NET_9P_VIRTIO                              |
|Network               | XEN_NETDEV_BACKEND/FRONTEND | VHOST_NET, VIRTIO_NET                      |
|Keyboard/console      | INPUT_XEN_KBDDEV_FRONTEND, HVC_XEN_FRONTEND  | VIRTIO_CONSOLE, VIRTIO_INPUT |
|Framebuffer           | XEN_FBDEV_FRONTEND          | DRM_VIRTIO_GPU (qemu -vga virtio)          |
|DRM framebuffer       | DRM_XEN_FRONTEND            | DRM_VIRTIO_GPU                             |
|Sound devices         | SND_XEN_FRONTEND            | N/A                                        |
|Crypto devices        | TCG_XEN                     | [CRYPTO_DEV_VIRTIO](http://events17.linuxfoundation.org/sites/events/files/slides/Introduction%20of%20virtio%20crypto%20device.pdf), HW_RANDOM_VIRTIO        |
|X-domain comms        | XEN_DEV_EVTCHN, XEN_PVCALLS_BACKEND,FRONTEND | VHOST_RING, VHOST_VSOCK, VIRTIO_VSOCKETS |

As a general rule of thumb, Xen uses [xenbus](https://wiki.xen.org/wiki/XenBus) and Front/Back paravirtualized device drivers. KVM uses [VirtIO framework](https://wiki.osdev.org/Virtio) that relies on a standard PCI bus interface with virtualized devices having VirtIO specific PCI VendorID and DeviceID.

Using QEMU as example: it emulates the control plane of virtio PCI device like device status, feature bits and device configuration space, while the implementation of virtqueue backend data plane has three options as of this writing:

* Virtio backend running inside QEMU virtqueue notification and actual data access are done directly by QEMU.
* Virtio backend running in separate userspace process. vhost-user or user space vhost is feature in QEMU that supports this hand-off.
* Virtio backend inside host kernel (VHOST_). QEMU helps setup kick/irq eventfd, vhost utilizes them to communicates with drivers in guest directly for virtqueue notification. Linux kernel module vhost sends/receives data via virtqueue with guest without exiting to host user space. vhost-worker is the kernel thread handling the notification and data buffer, the arrangement that enables it to access whole QEMU/guest address space is that: QEMU issues VHOST_SET_OWNER ioctl call to saves the mm context of qemu process in vhost_dev, then vhost-worker thread take on the specified mm context. Check use_mm() kernel function.

NOTE on virtio-bus vs virtio-pci-bus split: QEMU has gone through [a refactoring](https://wiki.qemu.org/Features/virtio-refactoring) where an abstract virtio-bus was introduced as an implementation detail. While it is now possible to construct transport/backend pairs manually by creating 1-1 correspondence between the two it is [much more convenient](https://lists.gnu.org/archive/html/qemu-discuss/2017-02/msg00060.html) to use aliases like virtio-net-pci that neatly wrap the two together.

## Device model implementations (anchor processes and resource accounting)

While conceptually creation of the domain itself (allocating RAM, CPU and setting up of an execution context) and supplying it with the device model are orthogonal, almost always the two get wrapped together into a single entry point managed by a user-space CLI utility. The job of any such utility is to take a configuration file that fully describes device model + hypervisor specific domain settings and execute all the necessary [hypervisor plumbing](https://lwn.net/Articles/658511/) and device model creation in a single shot:

* [xl for Xen](https://xenbits.xen.org/docs/unstable/man/xl.1.html). NOTE: xl by itself, can only instruct the Linux Kernel to provide device model to a domain. If, however, a true user-space device model implementation is required, xl delegates that to qemu by invoking it with the device model [crafted by xl](https://github.com/xen-project/xen/blob/master/tools/libxl/libxl_dm.c#L674) mostly corresponding to the virtual devices that are missing in the kernel. The *mostly* part is a tricky one, because xl tries to be smart and a lot of times (e.g. for disks) would create a kernel-based part of the device model AND a user-space based one just in case
* [acrn-dm for ACRN](https://github.com/projectacrn/acrn-hypervisor/blob/master/doc/user-guides/acrn-dm-parameters.rst)
* [qemu for KVM](https://qemu.weilnetz.de/doc/qemu-doc.html)
* [jailer for Firecracker](https://github.com/firecracker-microvm/firecracker/blob/master/docs/jailer.md)

All these utilities share one common trait: once they are done executing they always leave some kind of an *anchor process* daemonized process to keep track of state transitions in the running domain. Type-2 hypervisors have an additional benefit in that all the hypervisor-level resource accounting (RAM allocated vs. consumed, CPU assigned vs. running, etc.) can be attributed directly to the anchor process in a very traditional UNIX/Linux sense (or to put it a different way: you can get all that information by querying /proc filesystem). With type-1 hypervisors no direct attribution of this kind is possible and they all require a centralized daemon that keeps track of each domain's resource consumption:

* [xenstored for Xen](https://wiki.xen.org/wiki/XenStore)
* [acrnd for ACRN](https://projectacrn.github.io/1.0/tools/acrn-manager/README.html#acrnd)

Typically this anchor process is the same user-space process that serves up the device model, with the only exception to the rule here being Xen. As was noted above: xl actually delegates device model to qemu which means while xl itself serves as an anchor process, it actually has a child qemu process running as well.

Regardless of whether an anchor process runs by itself or, like in case of xl, forks off children, if one wants to interact with a running domain ones has to, somehow, talk to the anchor process. This is typically done by a custom protocol:

* [QMP for qemu based anchor processes](https://qemu.weilnetz.de/doc/qemu-qmp-ref.html)
* [Firecracker API for firecracker](https://github.com/firecracker-microvm/firecracker/blob/master/src/api_server/swagger/firecracker.yaml)
* [ACRN API for ACRN](https://github.com/projectacrn/acrn-hypervisor/blob/master/doc/api/devicemodel_api.rst)
* [A Hodge-Podge of APIs fronted by xl CLI](https://wiki.xen.org/wiki/Choice_of_Toolstacks)

## How EVE manages hypervisors

EVE has a pluggable hypervisor architecture defined in a [hypervisor package](../pkg/pillar/hypervisor). Any hypervisor implementation is expected to implement the [following methods](../pkg/pillar/hypervisor/hypervisor.go#L15).

On a running system, EVE keeps hypervisor state under `/run/hypervisor/<HYPERVISOR NAME>/<DOMAIN NAME>` and that state typically consists of:

* a file called `pid` that identifies an anchor process for the running domain
* a symlink called `cons` that points to a serial console of the running domain (you may want to use screen to see what's going on)
* a hypervisor specific pointer to the API channel (e.g. KVM uses `qmp` to point to qemu's QMP UNIX domain socket)

## IOMMU support

EVE relies on modern [IOMMU support](https://vfio.blogspot.com/2014/08/iommu-groups-inside-and-out.html) via [VT-d on Intel](https://software.intel.com/en-us/articles/intel-virtualization-technology-for-directed-io-vt-d-enhancing-intel-platforms-for-efficient-virtualization-of-io-devices) and [SMMU on ARM](https://developer.arm.com/architectures/system-architectures/system-components/system-mmu-support) to allow for direct assignment of PCI devices to domains. For type-1 hypervisors IOMMU support is provided by the hypervisor itself, while in type-2 hypervisor case we're relying on [VFIO support in the Linux Kernel](https://www.kernel.org/doc/Documentation/vfio.txt).

It must be noted, that given dual nature of IOMMU support in the Linux kernel itself (it can be used to optimized device drivers in addition to providing virtualization and user-space capabilities) they have an extra incentive to focus on properly enabling access controls via PCIe ACS (Access Control Services). Sadly, a lot of PCIe hardware is still [very](https://www.redhat.com/archives/vfio-users/2016-July/msg00043.html), [very](https://bugzilla.redhat.com/show_bug.cgi?id=1037684) badly broken and has to be worked around. For now, EVE takes a blunt approach of punting on fine-grained ACS controls with both [Xen](https://lists.gt.net/xen/devel/345180) and [KVM](https://lkml.org/lkml/2013/5/30/513) hypervisors.

Further details of Xen vs. KVM IOMMU handling are [documented here](https://docs.google.com/document/d/12-z6JD41J_oNrCg_c0yAxGWg5ADBQ8_bSiP_NH6Hqwo/edit#).

Hardware quirks aside, EVE uses the following hypervisor capabilities to manage IOMMU-based device assignments to domains:

* [Xen PCI Passthrough](https://wiki.xenproject.org/wiki/Xen_PCI_Passthrough) for Xen
* [HV Dev Passthrough](https://projectacrn.github.io/1.0/developer-guides/hld/hv-dev-passthrough.html) for ACRN
* [QEMU/VFIO Passthrough](https://wiki.archlinux.org/index.php/PCI_passthrough_via_OVMF) for KVM

While IOMMU tries to make hardware presented to the domain look indistinguishable from the bare-metal hardware, some device drivers running inside of the domain (most notably [NVidia ones](https://forum.level1techs.com/t/the-pragmatic-neckbeard-3-vfio-iommu-and-pcie/111251)) will try to detect this and degrade their capabilities. EVE uses hypervisor spoofing techniques to trick the drivers into thinking that they are truly operating on bare-metal hardware:

* [Xen spoofing](../pkg/xen-tools/patches-4.13.0/05-xen-spoofing.patch)
* [KVM spoofing](https://forum.level1techs.com/t/the-pragmatic-neckbeard-4-kvm-and-libvirt/112397)

Finally, BIOS/firmware running as part of the domain plays a big role in how well IOMMU capabilities can be utilized. EVE has an option of switching to [UEFI firmware](../pkg/uefi) from a more compact [SeaBIOS](https://seabios.org/SeaBIOS) implementation whenever needed.
