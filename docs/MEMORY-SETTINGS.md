# EVE Memory Settings

## TL;DR

```text
set_global hv_dom0_mem_settings "dom0_mem=1G,max:2G"
```

sets the soft limit of the `/sys/fs/cgroup/memory/eve/` cgroup to 1G and the
hard limit to 2G.

```text
set_global hv_eve_mem_settings "eve_mem=1000M,max:1200M"
```

sets the soft limit of the `/sys/fs/cgroup/memory/eve/services/` cgroup to
1000M and the hard limit to 1200M.

```text
set_global hv_ctrd_mem_settings "ctrd_mem=700M,max:800M"
```

sets the soft limit of the `/sys/fs/cgroup/memory/eve/containerd/` cgroup to
700M and the hard limit to 800M.

## Cgroups in EVE

In EVE OS we use cgroups v1 to manage resources.

### What are cgroups

Cgroups are a Linux kernel feature that limits, accounts for, and isolates the
resource usage of a collection of processes. Cgroups are used to control the
memory, CPU, and I/O resources that a process can use.

Official documentation: [cgroups](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt)

### Cgroups memory limits

Each cgroup has its own memory limits. In EVE OS, we use the memory limits of
two types: soft and hard.

1. **Soft Limit** (`memory.soft_limit_in_bytes`):
   The soft limit is more of a guidance for memory allocation rather than a
   strict enforcement. It allows processes in the cgroup to use more memory than
   the soft limit if there is free memory available in the system. If the system
   is under memory pressure, the kernel will try to reclaim memory from
   processes in cgroups that have exceeded their soft limits before reclaiming
   from other processes that are within their soft limits.
2. **Hard Limit** (`memory.limit_in_bytes`):
   The hard limit is a strict upper boundary on the memory usage of a cgroup.
   Processes in the cgroup are not allowed to use more memory than this limit.
   If a process in the cgroup tries to allocate more memory than the hard limit
   allows, the allocation will fail, and this could result in the
   Out-Of-Memory (OOM) killer terminating processes within the cgroup to enforce
   the limit.

### EVE cgroups hierarchy

The cgroups hierarchy in EVE is as follows:

```text
├── <some on-boot cgroups>
├── eve                   <--- accumulates most of the EVE runtime services
│ ├── containerd          <--- internal containers like content trees, data blobs, etc.
│ └── services            <--- all other rather than containerd services
│     ├── <some services>
│     ├── pillar          <--- main Zedbox process + close related processes
│     └── <some services>
└── eve-user-apps
    ├── <uuid1>           <--- user application 1
    └── <uuid2>           <--- user application 2
```

The most important cgroups are `eve`, `pillar`, and `eve-user-apps`.

The `eve` cgroup is used to manage most of the EVE runtime services. It
accumulates all the services that are not related to user applications.

Note, that the `eve/containerd` service is used to manage internal containers
like content trees, data blobs, etc. It does not manage running user
applications of the container type.

The `eve/services` cgroup is used to manage all the services that are not
related to user applications and are not managed by the `eve/containerd`
service.

In the `eve/services` cgroup, the `pillar` service is the most important one,
as it is the main Zedbox process and all the processes that are closely related.
The `eve/services` cgroup also contains services necessary for the EVE OS to
function properly.

All the user applications are running in the sub-cgroup of the `eve-user-apps`
cgroup. Each user application has its own sub-cgroup.

### Memory settings in EVE

We use explicit memory settings for several of the cgroups. Namely, we set
memory limits for the `eve`, `eve/containerd`, `pillar`, and all the sub-cgroups
of the `eve-user-apps` cgroup.

By default, we set the soft memory limits to 80% of the hard memory limits. It's
done to give the Kernel target value for the memory usage of the cgroup.
When memory rebalancing is needed, the kernel will try to keep the memory usage
of the cgroup at the soft limit. The rebalancing is triggered in different
situations, for example, when the system is under memory pressure.

For the EVE-related cgroups, we set the memory limits in the kernel command line
arguments. For the user applications, we set the memory in runtime using the
values of RAM.

## EVE-services memory settings

The memory settings for the EVE services are set using the kernel command line
arguments.

### Kernel command line arguments

The memory settings in EVE are set using kernel command line arguments:

* dom0_mem
* eve_mem
* ctrd_mem

#### Format of memory settings

All "<cmd_component_name>_mem" settings have the following format:

```text
<cmd_component_name>_mem=<soft_limit>,max:<hard_limit>
```

where:

* `<cmd_component_name>` is one of the following: `dom0`, `eve`, `ctrd`
* `<soft_limit>` is the soft limit for the memory usage of the cgroup.
* `<hard_limit>` is the hard limit for the memory usage of the cgroup.

The `<soft_limit>` and `<hard_limit>` are values in human-readable format. They
can be specified in the following units: `M` (megabytes), `G` (gigabytes). If no
unit is specified, the value is treated as bytes. For example, `1G` means 1
gigabyte, `100M` means 100 megabytes, and `1000000` means 1000000 bytes.

If the hard limit is not specified, the soft limit is used as the hard limit.

#### Component to cgroup mapping

The mapping of the `<cmd_component_name>` to the cgroup is not straightforward
and is misleading. The following table shows the mapping:

| Component   | cgroup            | default soft limit | default hard limit |
|-------------|-------------------|--------------------|--------------------|
| `dom0`      | `eve`             | 640M               | 800M               |
| `ctrd`      | `eve/containerd/` | 320M               | 400M               |
| `eve`       | `eve/services/`   | 520M               | 650M               |
| `eve`       | `eve/services/*`  | 520M               | 650M               |

That way, the `dom0_mem` setting sets the memory limits for the `eve` cgroup,
the `ctrd_mem` setting sets the memory limits for the `eve/containerd` cgroup,
and the `eve_mem` setting sets the memory limits for the `eve/services` cgroup
and all the sub-cgroups of the `eve/services` cgroup.

For example, the following kernel command line arguments:

```text
dom0_mem=1G,max:2G eve_mem=1000M,max:1200M ctrd_mem=700M,max:800M
```

will set the soft limit of the `/sys/fs/cgroup/eve/` cgroup to 1G and the hard
limit to 2G, the soft limit of the `/sys/fs/cgroup/eve/services/` and all the
sub-cgroups to 1000M and the hard limit to 1200M, and the soft limit of the
`/sys/fs/cgroup/eve/containerd/` cgroup to 700M and the hard limit to 800M.

#### GRUB override file

These settings can be changed using the `set_global` command in the
GRUB override file.

```text
set_global hv_dom0_mem_settings "dom0_mem=<value>,max:<value>"
set_global hv_eve_mem_settings "eve_mem=<value>,max:<value>"
set_global hv_ctrd_mem_settings "ctrd_mem=<value>,max:<value>"
```

It can be done on the device by mounting the config partition and editing the
`grub.cfg` file. The changes will be applied after the device reboot.

```bash
eve config mount /mnt
echo "set_global hv_dom0_mem_settings \"dom0_mem=1G,max:2G\"" >> /mnt/grub.cfg
eve config unmount /mnt
reboot
```

## Golang runtime garbage collector settings

Golang runtime provides two parameters which impacts garbage collector (GC)
behavior, which are available through the EVE debug settings:

1. `gogc.memory.limit.bytes` provides the runtime with a soft memory limit.
   The runtime undertakes several processes to try to respect this memory
   limit, including adjustments to the frequency of garbage collections and
   returning memory to the underlying system more aggressively. The Go API
   call is described [here](https://pkg.go.dev/runtime/debug#SetMemoryLimit)

   By default, EVE setting is disabled (set to 0), meaning the Golang runtime
   memory limit will be set according to the following equation based on the
   `memory.limit_in_bytes` hard memory limit provided by the pillar `cgroups`:

   `limit = memory.limit_in_bytes * 0.6`

   The constant 0.6 was chosen empirically and is explained by simple logic:
   `memory.limit_in_bytes` is a hard limit for the whole pillar cgroup, meaning
   when reached, likely one of the processes will be killed by OOM. In turn
   Golang runtime memory limit is a soft limit, so the difference must be
   significant to ensure that after the soft limit is reached, there will be
   enough memory for the Go garbage collector to do its job and, fortunately,
   not to hit the hard limit.

2. `gogc.percent` sets the garbage collection target percentage: a collection
   is triggered when the ratio of freshly allocated data to live data remaining
   after the previous collection reaches this percentage. The Go API call is
   described [here](https://pkg.go.dev/runtime/debug#SetGCPercent)

Changing these parameters is recommended as a last resort, for example to debug
an OOM kill due to a bloated `zedbox` process. Before changing the values,
please read the [documentation](https://tip.golang.org/doc/gc-guide) carefully.

## Forced execution of the Golang runtime garbage collector settings

Setting a soft limit for Golang garbage collector may not be enough:
the whole system may experience memory pressure due to other
applications in the same of other memory cgroups. In such cases, GC
can be forced from the memory pressure event handler. The following
parameters are available for configuring this algorithm in order to
minimize frequent GC calls:

1. `gogc.forced.interval.seconds` sets minimum interval of forced GC
    loop in seconds, meaning that GC is called explicitly no more than
    once every 10 seconds.  Default value is 10 seconds. Setting
    interval to 0 disables the forced GC.

2. `gogc.forced.growth.mem.MiB` sets absolute amount of allocated
   memory since last reclaim, meaning that GC will be called again only
   if desired amount was allocated. Default value is 50 MiB.

3. `gogc.forced.growth.mem.percent` sets percent of last reclaimed
   memory, which should be allocated, meaning that GC will be called
   again only if desired percentage of reclaimed memory is allocated
   back. Default value is 20%.

Options 2 and 3 can be shortly described as the following limit and
`expected` value after which GC will be called again:

```text
   limit = MAX(50MB, reclaimed * 20%)
   expected = m.Alloc + limit
```

## User applications memory settings

Besides the obvious memory settings of RAM that comes from the controller, there
is an additional settings that can be set for the user applications.

### VMM overhead

The VMM overhead is the memory overhead for the app instance. Every app instance
consumes the memory that is used for its RAM, and some additional memory that is
used by the system to run the app instance.

This value is used to calculate the overall memory need for the app instance. It
is calculated during the app instance creation and is used to decide if the
app instance can be started. If the app instance can be started, the memory
overhead is added to the RAM value and the resulting value is used to
set the memory *limits for the cgroup* of the app instance.

#### VMM Overhead calculation

As mentioned above, the VMM overhead is calculated automatically in runtime if
the explicit value is not set. Currently, the VMM overhead is calculated as
follows:

* Base Overhead: 370 Mb
* Page Tables Overhead: RAM * 0.025 (2.5% of RAM)
* VCPU Overhead: 3 Mb per CPU assigned to a VM
* Device MMIO Overhead: it fluctuates between 0.66 and 0.81 % of MMIO total size

These values are from our estimations and can be changed in the future.

#### Overriding the VMM overhead

In most cases, the VMM overhead is calculated automatically and there is no need
to set it explicitly. But there is a possibility to set the memory overhead
manually.

There are two settings that can be used to override the VMM overhead estimation:

1. `memory.vmm.limit.MiB` is a setting in a global device configuration
   that sets the VMM overhead for all the app instances. If this setting is set,
   the VMM overhead is calculated as the value of this setting.
2. `VMMMaxMem` is a setting in the app configuration that sets the VMM overhead
   for the specific app instance. It is available in the app configuration on
   the controller.

The global `memory.vmm.limit.MiB` has priority over the app-specific `VMMMaxMem`
setting. So if both are set the real value comes from the global
`memory.vmm.limit.MiB` setting. If none of them is set, we count the
overhead in runtime.

## Recommendations

Below are recommendations on how to use the memory settings for different
components in EVE OS. For each setting, we provide guidelines on when it makes
sense to increase or decrease the values, as well as the potential impact of
setting them too high or too low.

### dom0_mem

The `dom0_mem` setting controls the memory allocated to the EVE OS's system
services: the `eve` cgroup. This cgroup includes the `eve/services` cgroup and
the `eve/containerd` cgroup.

#### When to increase `dom0_mem`?

Increase `dom0_mem` if you observe that the overall memory usage of the EVE
services and the containerd service is frequently reaching their memory limits.
It can be identified by instances where the Out-Of-Memory (OOM) killer is fired
with constraint `CONSTRAINT_MEMCG` and the `oom_memcg` value set `eve` cgroup:

```text
oom-kill:constraint=CONSTRAINT_MEMCG,...,oom_memcg=/eve/,...
```

Technically, it means that while not reaching the memory limits of any
sub-cgroup, the overall memory usage of the `eve` cgroup is too high. It is a
possible situation, as the default value of `dom0_mem` is set to 800M, while the
default value of `eve_mem` is set to 650M and the default value of `ctrd_mem` is
set to 400M. So the overall memory usage of the `eve` cgroup can be up to 1250M.

High memory usage of the EVE services or the containerd service can be caused by
intensive EVE management operations, such as updating apps, reconfiguring
settings, or downloading large blobs. If such operations are common, increasing
these memory settings can prevent OOM situations.

#### When to decrease `dom0_mem`?

Decrease `dom0_mem` limit if you find that user applications require more
memory, and you suspect that the current memory limits for EVE services are
unnecessarily high. Reducing the memory allocated to EVE services can free up
resources for user applications, improving their performance and stability.

You may want to have more memory available for user applications if you observe
that the user applications cannot start due to insufficient memory. In this case,
the EVE logs will contain a warning message:

```text
App instance needs <value> bytes but only have <value> bytes
```

On the controller side, the app instance will be in the `Error` state.

The indication that the user applications require more memory can be also the
situation when the user applications are frequently hitting memory limits and
the OOM killer is fired with constraint `CONSTRAINT_NONE` and the `oom_memcg`
value set to one of the cgroups of the user applications:

```text
oom-kill:constraint=CONSTRAINT_NONE,...,oom_memcg=/eve-user-apps/<uuid>,...
```

When decreasing `dom0_mem`, don't forget to decrease at least one or both of
`eve_mem` and `ctrd_mem` values as well, as the `eve` cgroup is a parent of
and `eve/services` and `eve/containerd` cgroups.

Also be sure not to decrease `dom0_mem` less than `eve_mem` or `ctrd_mem`, as
it is not possible for the parent cgroup to have less memory than any of its
children.

#### Impact of setting `dom0_mem` too high

In the simplest case setting `dom0_mem` too high may lead to inefficient use of
system resources, where memory is reserved but not fully utilized. It takes
memory away from the user applications, potentially preventing them from
starting or causing them to frequently hit memory limits.

See the section "When to decrease `dom0_mem`?" for more details.

#### Impact of setting `dom0_mem` too low

Setting `dom0_mem` too low could cause the EVE services or containerd processes
to frequently hit memory limits, triggering the OOM killer within the `eve`
cgroup.

See the section "When to increase `dom0_mem`?" for more details.

### eve_mem

The `eve_mem` setting controls the memory usage of the EVE services that are not
related to the containerd service. This cgroup includes the `eve/services` cgroup
and all the sub-cgroups of the `eve/services` cgroup.

#### When to increase `eve_mem`?

Increase `eve_mem` (along with `dom0_mem`, as it is its parent) if you observe
that the EVE services (under `eve/services/*` cgroup) are frequently reaching
their memory limits. This can be identified by instances where the
Out-Of-Memory (OOM) killer is fired with constraint `CONSTRAINT_MEMCG` and
`oom_memcg` values set to one of the services cgroups:

```text
oom-kill:constraint=CONSTRAINT_MEMCG,...,oom_memcg=/eve/services/<service>,...
```

One of the important cases when one of the `eve/services` services uses a lot of
memory is when some heavy operations are performed via SSH. For example, running
`collect-info.sh` script generates large files and can consume a lot of memory.
That's because the SSH session runs in one of the `eve/services/*` subgroups.

Another service that worth mentioning is the edge-view service.

Here is a full list of the services that are running in the `eve/services`
cgroup:

* debug
* edgeview
* guacd
* lisp
* memlogd
* newlogd
* pillar
* sshd
* vtpm
* watchdog
* wlan
* wwan
* xen-tools

Don't forget to increase `dom0_mem` value as well, as the `eve/services` cgroup
is a child of the `eve` cgroup.

#### When to decrease `eve_mem`?

Decrease `eve_mem` when you need to decrease the value of `dom0_mem`. See the
section "When to decrease `dom0_mem`?" for more details.

#### Impact of setting `eve_mem` too high

In the simplest case setting `eve_mem` too high leads to too high value of
`dom0_mem` (the `eve` cgroup), which can lead to inefficient use of system
resources, where memory is reserved and not available for user applications.

See the section "Impact of setting `dom0_mem` too high" for more details.

#### Impact of setting `eve_mem` too low

Setting `eve_mem` too low could cause the EVE services to frequently hit memory
limits, triggering the OOM killer within the `eve/services` cgroup. See the
section "When to increase `eve_mem`?" for more details.

### ctrd_mem

The `ctrd_mem` setting controls the memory usage of the containerd service. This
service is responsible for managing internal containers like content trees, data
blobs, etc.

#### When to increase `ctrd_mem`?

Increase `ctrd_mem` if you observe that the containerd service is reaching its
memory limits. This can be identified by instances where the Out-Of-Memory (OOM)
killer is fired with constraint `CONSTRAINT_MEMCG` and `oom_memcg` values set to
the `eve/containerd` cgroup:

```text
oom-kill:constraint=CONSTRAINT_MEMCG,...,oom_memcg=/eve/containerd,...
```

Don't forget to increase `dom0_mem` value as well, as the `eve/containerd` cgroup
is a child of the `eve` cgroup.

#### When to decrease `ctrd_mem`?

Decrease `ctrd_mem` when you need to decrease the value of `dom0_mem`. See the
section "When to decrease `dom0_mem`?" for more details.

#### Impact of setting `ctrd_mem` too high

In the simplest case setting `ctrd_mem` too high leads to too high value of
`dom0_mem` (the `eve` cgroup), which can lead to inefficient use of system
resources, where memory is reserved and not available for user applications.

See the section "Impact of setting `dom0_mem` too high" for more details.

#### Impact of setting `ctrd_mem` too low

Setting `ctrd_mem` too low could cause the containerd service to frequently hit
memory limits, triggering the OOM killer within the `eve/containerd` cgroup.

See the section "When to increase `ctrd_mem`?" for more details.

### VMM Overhead

The VMM overhead is the extra memory that is used by the system to run the app
instance. It is calculated automatically in runtime, but there is a possibility
to set it manually. It can be useful when the device has little memory and
the automatic calculation can be too high.

#### When to increase VMM Overhead?

You definitely should increase the VMM overhead if you observe the OOM killer
firing with constraint `CONSTRAINT_MEMCG` and the `oom_memcg` value set to one
of the cgroups of the user applications:

```text
oom-kill:constraint=CONSTRAINT_MEMCG,...,oom_memcg=/eve-user-apps/<uuid>,...
```

It means that the user application (the QEMU process) is reaching its memory
limits on the host.

#### When to decrease VMM Overhead?

Decrease the VMM overhead if you need to free up memory for the EVE services,
for example, if you need to give more memory to the EVE services. See the
sections "When to increase `dom0_mem`?", "When to increase `eve_mem`?", and
"When to increase `ctrd_mem`?" for more details.

Also, decreasing the VMM overhead can be useful if you want to try to run more
user applications on the device. The estimated VMM overhead can be too high in
some cases, and if you run several user applications on the device, it can lead
to a lot of memory being "wasted" and not available for the EVE services or
other user applications.

An indication that the EVE services require more memory can be the situation
when the EVE services are frequently hitting memory limits and the OOM killer is
fired with constraint `CONSTRAINT_NONE` and the `oom_memcg` value set to one of
the cgroups of the EVE services.

#### Global vs app-specific VMM Overhead

While the app-specific `VMMMaxMem` setting provides more granular control over
the VMM overhead, most of the cases when you may want to change the VMM overhead
are related to the overall memory usage of the device. In such cases, it is
better to set the global `memory.vmm.limit.MiB` setting, as it will affect all
the app instances on the device.

Nevertheless, if you need to set the VMM overhead for a specific app instance,
for example, if you know that this app instance causes an enormous memory usage,
you can set the `VMMMaxMem` setting in the app configuration exactly for this
app instance.

## Uncovered case of OOM killer

Theoretically, the OOM killer can be fired with the constraint `CONSTRAINT_NONE`
and the `oom_memcg` value set to one of the cgroups of the EVE services:

```text
oom-kill:constraint=CONSTRAINT_NONE,...,oom_memcg=/eve/services/<service>,...
```

or

```text
oom-kill:constraint=CONSTRAINT_NONE,...,oom_memcg=/eve/containerd,...
```

In general, it means that the overall memory usage of system is too high, but
it is not clear which exact process is responsible for that. Most likely, it is
a case when several processes are consuming a lot of memory, while none of them
is consuming too much to reach the memory limit. In this case step-by-step
debugging is required to find the solution to the problem.

## Where to find the OOM messages

The OOM messages can be found in the dmesg logs. They are also exposed via the
syslog subsystem, so they are aggregated in the controller logs.
