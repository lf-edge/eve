# Design and implementation of Edge Virtualization Engine

1. [Introduction](#introduction)
1. [Edge Containers](#edge-containers)
1. [Security](#security)
1. [EVE Controller](#eve-controller)
1. [Runtime Configuration](#runtime-configuration)
1. [Installing EVE on Edge Nodes](#installing-eve-on-edge-nodes)
1. [Runtime Lifecycle](#runtime-lifecycle)
1. [Building EVE](#building-eve)
1. [EVE Internals](#eve-internals)
1. [EVE CGroups](#eve-cgroups)

## Introduction

Edge Virtualization Engine (EVE) is a secure by design operating system
that supports running *Edge Containers* on compute devices deployed in
the field. These devices can be IoT gateways, Industrial PCs or general
purpose ruggedized computers; collectively, these are referred to as
*Edge Nodes*.

EVE is based on a type-1 hypervisor and it does not directly support
traditional POSIX-like application and processes. All applications
running on EVE have to be represented as [Edge Containers](ECOS.md) which
can be one of: Virtual Machines, Containers or Unikernels. EVE presents a
somewhat of a novel design for an operating systems, but at the same time
it is heavily inspired by ideas from [Qubes OS](https://www.qubes-os.org/),
[ChromeOS](https://www.chromium.org/chromium-os/chromiumos-design-docs),
[Core OS](https://coreos.com/) and [Smart OS](https://wiki.smartos.org/).

EVE is all you need to put on your Edge Nodes in order to run Edge Containers
there. You don't need to install traditional (or embedded) operating systems,
hypervisors, container engines or middleware. EVE provides all of that in
a tightly integrated, secure and space conscious package.

EVE's promise to its users is simple:

* Zero touch: you should never need physical access to your Edge Node,
  after installing EVE on it. All hardware and software management should
  be safely performed remotely
* Zero trust: not a single individual component could be fully trusted
  and the only way to build a trustworthy system is by utilizing
  defence-in-depth and state of the art cryptography primitives
* EVE will make *any kind of* application type, network environment and
  hardware be easily and safely manageable
* EVE promises to bring cloud-native, DevOps-centric principles of software
  development to Edge Computing

This documentation is a work-in-progress tracking the current state of EVE.
It is expected to evolve significantly based on community feedback and constant
addition of new functionality to EVE. The structure of this [README](README.md)
is aimed at providing just enough information to vector you off to a relevant
part  of the documentation. Even then, it can be too long for some readers and
we  provide a companion [FAQ](FAQ.md) for those simply trying to look random
facts  up. Finally, if you are interested in the gory details of how each
subcomponent of EVE is implemented you should refer to respective subcomponents
[docs folders](../pkg/) and especially [pillar docs](../pkg/pillar/docs/README.md).

EVE leverages many open source projects and it would *not* have been possible to
build EVE without relying on them. When it comes to developing EVE we practice
a strict [Upstream First](UPSTREAMING.md) policy.

## Edge Containers

Edge Container is a novel concept that allows an effective packaging and lifecycle
management of the following types of workloads:

* [Traditional Virtual Machines](https://en.wikipedia.org/wiki/Virtual_machine)
* [Unikernels](http://unikernel.org/)
* [Docker/OCI container](https://www.opencontainers.org)

EVE is *not* a traditional operating system in that it doesn't support applications
packaged as executables. Instead EVE expects its applications to be either Virtual
Machines, Unikernels or Docker/OCI containers. EVE introduces a novel notition of an
Edge Container that unifies all three.

Android has [APKs](https://en.wikipedia.org/wiki/Android_application_package),
Docker has [OCI Containers](https://www.opencontainers.org) - EVE has Edge Containers.

You can read a detailed specification of [Edge Containers](ECOS.md) and you should
expect them to be available for broad Linux Foundation adoption once we are ready
for formal submission of a self-contained specification.

The ECO installation and initialization process is available [here](./ECO-INIT.md).

## Security

What makes EVE a secure-by-design system is that it has been developed from the
ground up with security in mind. EVE doesn't rely on 3rd party or add-on components
to provide trust in the system, but rather offers a set of well-defined principles
on which a trust model can be built.

We have made an effort to provide users of EVE with a system that is both
practically secure and can be deployed in a zero-touch fashion. In order to achieve
our goals we put forward a [few guiding principles](SECURITY.md).

## EVE Controller

Each Edge Node with EVE running on it can participate in sophisticated
[Edge Computing scenarios](https://www.zdnet.com/article/10-scenarios-where-edge-computing-can-bring-new-value/)
ranging from simple [data collection](https://blog.equinix.com/blog/2017/11/29/how-iot-data-collection-and-aggregation-with-local-event-processing-work/)
all the way to [Edge Analytics and AI](https://www.datanami.com/2019/02/04/exploring-artificial-intelligence-at-the-edge/).
While EVE provides an incredible amount of functionality to support these use
cases, it needs to be told exactly how to orchestrate these functional building blocks
by a *Controller*. In other words, without Controller telling a fleet of Edge
Nodes what to do, EVE by itself may be capable, but it practically useless.

This is a fundamental point of EVE's design: an end user (lets call her Diane
The DevOps) trying to implement an Edge Computing scenario never communicates
directly with a running EVE instance. There are no user names, passwords or a
concept of "logging in" when it comes to EVE. All interactions that Diane will
have are going to be through the EVE Controller. Diane expresses her overall
intent to a controller using a Controller API and it is then the job of a
controller to build an execution plan for a fleet of Edge Nodes running EVE.
When each instance of EVE contacts the controller using EVE API it will receive
its own portion of the overall execution plan (note that EVE API communications
are  always initiated by EVE, never by the Controller):

![EVE Controller](pics/EVEController.png)

A good way to think about this is that Controller is to EVE what Kubernetes is
to Docker Engine.

An API between EVE and its Controller is considered a [public API of Project EVE](../api).
Refer to [API documentation](../api/APIv2.md) for detailed information on API
end points and message format.

EVE design makes the trust between an EVE instance and its controller extremely
important to the overall security of your Edge Nodes. An attack vector of
impersonating an EVE controller or an EVE instance can be used for extremely
malicious effects (like turning a [fleet of Edge Nodes into a botnet](https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/)).
EVE takes great care of making sure that an EVE instance can always trust its
Controller and the Controller can always trust EVE. All of these techniques
are documented in detail in the [EVE Security section](#security) of this document.

A decision of what controller to chose for maintaining a fleet of Edge Nodes
running EVE currently boils down to two options:

* Hyperscale, commercial, provided by LFEdge members, currently only [ZEDEDA Controller](https://zededa.com/demo-now/) (more to follow)
* Single Edge Node, Open Source [Adam Controller](https://github.com/lf-edge/adam)

Whatever option you chose it is your responsibility to make sure that a correct
URL for the Controller and its Root x509 certificate are made available during
[EVE Installation](#installing-eve-on-edge-nodes).

## Runtime Configuration

The heart of EVE API is a self-contained [configuration object](../api/APIv2.md#configuration)
that each instance of EVE receives from its controller. This object is
serialized into a protobuf message but it can also be represented as a JSON.
It is self-contained in a sense that a running EVE instance doesn't need to
have access to any other information but this configuration object in order to
perform tasks assigned to it by the controller.

EVE depends on its configuration object so much so that it can not even control
the hardware of the Edge Node (network interfaces, I/O ports, USB controllers,
etc.) without retrieving hardware specific information from its configuration
object. This model works very well from security and maintainability standpoint,
but it presents a chicken-and-an-egg problem in one particular case: network
interfaces. After all, EVE can only receive its configuration object from a
Controller via network-based API call. This, in turn, requires at least a single
functional hardware network interface and those can only be enabled after we
receive configuration object from the Controller.

EVE solves this problem by following a two-pronged approach:

1. Having an out-of-band set of mechanisms that allow for the first
   configuration object to be made available right after EVE instance boots
2. Maintaining sophisticated fallback semantics for the series of
   configuration objects that EVE keeps receiving from the Controller

The first part helps EVE bootstrap and configure itself during the initial boot
sequence, the second part ensures that EVE never ends up in a situation where
the new configuration object made it impossible to receive further configuration
objects due to erroneous configuration provided for network interfaces.

There are currently two mechanisms for delivering out-of-band configuration
object to EVE:

1. Installing it during the [normal EVE installation process](#installing-eve-on-edge-nodes)
2. Providing it to a running version of EVE on a specially formatted removable
   media (USB stick, CDROM, external hard drive, etc.)

Both methods start with obtaining a set of files (see the note below on how we
are working towards making it a single file) and either putting them into the
EVE configuration partition on the installation media (see [EVE Installation](#installing-eve-on-edge-nodes)
for details) or using [tools/makeusbconf.sh](../tools/makeusbconf.sh) script to format
removable media.

It must be noted that currently we are still not quite there with out-of-band
mechanism for delivery of EVE's configuration object. While ideal EVE
implementation would simply be able to consume exactly the same protobuf encoded
binary blob that it receives from the Controller, currently we still have to
rely on an ad-hoc collection of configuration files that serve the same purpose.
We expect these configuration files to go away relatively quickly, but for now
EVE is still stuck with at least *DevicePortConfig/global.json* and it is documented in [legacy configuration](CONFIG.md).
See [the following FAQ entry](FAQ.md) for how to manage both of these
legacy files.

### Runtime Configuration Properties

In addition to highly structured portions of the configuration object, EVE
allows for a flat namespace of random configuration properties that control
various settings in a running instance of EVE. From a Controller perspective
you can apply these types of settings to either and individual instance of
EVE or to all instances of EVE grouped together in a project. For examples,
if you are using ZEDEDA's Controller with zcli you will issue the following
zcli command to set a configuration property named key to a given value:

```bash
   zcli [device|project] update <name> [--config=<key:value>...]
```

Or to give a more specific example, here's how you can allow ssh access to
the device for debugging issues:

```bash
zcli edge-node update myqemu --config="debug.enable.ssh:`cat .ssh/id_rsa.pub`"
```

Most of the runtime configuration properties apply to an entire running EVE
instance. A set of property names, however, is reserved to only affected a
particular microservice within a running instance of EVE. These reserved names
always start with debug.*microservice*.

You can find a complete list of generic and microservices specific configuration
properties in [configuration properties table](CONFIG-PROPERTIES.md).

## Installing EVE on Edge Nodes

EVE expects to be installed into a persistent storage medium (disk, flash, etc.)
of Edge Nodes. While it is possible to have a live image of EVE running off of
a  removable media (USB stick, CDROM, etc.) it isn't typically very useful. EVE
currently does *not* support network [PXE booting](https://en.wikipedia.org/wiki/Preboot_Execution_Environment)
and given that Edge Nodes are typically deployed with very rudimentary networks
attached to them it is very unlikely that EVE will support that type of
booting. That said, it may be possible to use EVE's installer in a network boot
scenario to install EVE on Edge Nodes when they first do a network boot in a lab
or provisioning environment.

During the installation phase, EVE assumes the target storage medium to be either
empty or have been formatted with [GPT](https://en.wikipedia.org/wiki/GUID_Partition_Table)
that EVE can recognize and extend. Either way, after successful installation
EVE will have created the following entries in the GPT.

* EFI System (vfat formatted read-only filesystem that contains GRUB trampoline)
* IMGA (first copy of EVE's read-only root filesystem)
* IMGB (second copy of EVE's read-only root filesystem)
* CONFIG (vfat formatted read-only filesystem that contains Edge Node Identity specific configuration)
* P3 (read-write filesystem that extends to the rest of the available storage medium)

The partitioning scheme is similar to how [CoreOS does its partitioning](https://coreos.com/os/docs/latest/sdk-disk-partitions.html).
EVE does, indeed, leveraging the good work that CoreOS folks have done so much so
that we're using their patches for the GRUB bootloader to provide rootfs upgrade
functionality between IMGA and IMGB root filesystems. Unlike CoreOS, though, EVE
only relies on the partition symbolic names (and not offsets in the GPT) and hence
can extend any existing GPT that it can recognize. This comes handy on some of
the ARM platforms that reserve a few of the GPT entries to host things like
firmware. Finally, it must be said that EVE doesn't support legacy partitioning
schemes (such as MBR).

CONFIG partition is read-only from the standpoint of EVE itself, but it can be
written to under [certain debug and recovery scenarios](CONFIG.md). This stands
in contrast with EFI System partition that, while technically read-write, has
absolutely no reason of ever being written to past initial installation process.

P3 is a scratch space. Unlike CONFIG and EFI System partition, P3 can be wiped out
and re-created without affecting much of edge node behaviour. The content of CONFIG
and EFI System has to be preserved at all costs. Corrupting those partitions will
result in an edge node that needs to be re-installed (technically IMGA and IMGB
should be protected as well, but since they are always treated as read-only corrupting
them is much harder).

EVE's root filesystem is hosted in both IMGA and IMGB partitions. This allows
a running EVE instance to safely update itself. If you want to know more about
how this process works read [baseimage update](BASEIMAGE-UPDATE.md) documentation.

Both IMGA and IMGB host a filesystem containing the following software components

* Second stage [GRUB bootloader](../pkg/grub) and [its configuration](../pkg/grub/rootfs.cfg) in `/EFI` folder
* [Hypervisor](../pkg/xen) and [Linux Kernel](../pkg/kernel) in `/boot` folder
* [EVE microservices](../pkg/pillar) in `/containers` folder
* Minimalistic [Alpine Linux](https://alpinelinux.org)-derived UNIX environment

EVE microservices are ultimately responsible for providing the entire EVE
experience and they are described in greater details below.

## Runtime Lifecycle

EVE can be booted in a lot of different ways. The most common one is
booting EVE in UEFI environment. However, booting with legacy PC BIOS
and board specific firmware implementations (most commonly CoreBoot and
u-boot) is also possible. In all of these scenarios, we rely on GRUB
bootloader to figure out an active partition (either on IMGA or IMGB)
and do all the necessary steps to boot EVE residing in an active partition.

Because of how heterogeneous all these initial boot environments are,
EVE uses a number of techniques to maintain a single image that can
be booted in a variety of different scenarios. You can read about this
in greater details in the [booting EVE](BOOTING.md) section of our docs.

Regardless of the initial boot environment, though, after GRUB is done
loading ether:

* type-1 hypervisor (Xen, ACRN) plus Control Domain kernel
* Linux kernel (with type-2 KVM hypervisor support enabled)

the rest of the runtime sequence relies solely on what happens with EVE
microservices. All of these services are available under */containers/services*
folder in IMGA or IMGB root filesystem. Their lifecycle is currently managed
by [linuxkit init system](https://github.com/linuxkit/linuxkit/tree/master/pkg/init)
and monitored by a built-in [software watchdog](../pkg/watchdog). Software
watchdog, in turn, [relies](../pkg/pillar/scripts/device-steps.sh#L56) on
Edge Node's hardware watchdog to cope with unexpected software failures.

All EVE microservices are expected to communicate with each other by using
the EVE dedicated [IPC mechanism](COMMS.md).

## Building EVE

In order to run EVE on a piece of hardware you may need to produce one of the
following binary artifacts:

* EVE root filesystem image
* EVE bootable installer image
* EVE bootable live image (which is likely to be combined with installer image soon)

EVE build system is using a simple top-level [Makefile](../Makefile) which under
the hood uses [Linuxkit](https://github.com/linuxkit/linuxkit) to produce all
3 of these artifacts.

You should read [Building EVE](BUILD.md) if you want to know more about this
process.

## EVE Internals

For some of the details on EVE internals you may want to check out:

* [Domain Manager](../pkg/pillar/docs/domainmgr.md)
* [TPM Manager](../pkg/pillar/docs/tpmmgr.md)

## EVE CGroups

Resources like memory and CPU used by EVE services, containerd, memlogd and edge applications are controlled by their respective [CGroups](https://www.kernel.org/doc/Documentation/cgroup-v2.txt).
CGroups in EVE follows the below hierarchy:

```text
Parent cgroup (/sys/fs/cgroup/<subsystems>/)
├── eve
│   └── services
│   │   └── newlogd
│   │   └── ntpd
│   │   └── sshd
│   │   └── wwan
│   │   └── wlan
│   │   └── lisp
│   │   └── guacd
│   │   └── pillar
│   │   └── vtpm
│   │   └── watchdog
│   │   └── xen-tools
│   │
│   └── containerd
│   └── memlogd
│
└── eve-user-apps
    └── (edge applications)
```

Memory and CPU limits of `eve`, `eve/services` and `eve/containerd` cgroups can be changed via
`hv_dom0_*`, `hv_eve_*` and `hv_ctrd_*` respectively in `/config/grup.cfg`.

Example:

```text
set_global hv_dom0_mem_settings "dom0_mem=800M,max:800M"
set_global hv_dom0_cpu_settings "dom0_max_vcpus=1 dom0_vcpus_pin"
set_global hv_eve_mem_settings "eve_mem=650M,max:650M"
set_global hv_eve_cpu_settings "eve_max_vcpus=1"
set_global hv_ctrd_mem_settings "ctrd_mem=400M,max:400M"
set_global hv_ctrd_cpu_settings "ctrd_max_vcpus=1"
```
