# Memory Monitor

## About the memory limitations in the EVE system

EVE uses cgroups to limit the memory usage of different components of the system.
In particular, EVE creates a dedicated cgroup "eve" to limit the memory usage of
its main components. This cgroup is further divided into several sub-cgroups,
including "eve/services", and, in particular, "eve/services/pillar".

So, a usual memory hierarchy in the EVE system looks like this:

```shell
$ tree /sys/fs/cgroup/memory/eve -d
/sys/fs/cgroup/memory/eve <--- is set from dom0_mem kernel argument, usually 800Mb (or 8GB for ZFS)
├── containerd <-------------- is set from ctrd_mem kernel argument, usually 400Mb
└── services <---------------- is set from eve_mem kernel argument, usually 650Mb
    ├── <some services>
    ├── pillar <-------------- is set from eve_mem kernel argument, usually 650Mb
    ├── <some other services>
    └── xen-tools
```

These limits are set within `pkg/dom0-ztools/rootfs/etc/init.d/010-eve-cgroup`
script. The "eve" cgroup limit is set according to the `dom0_mem` kernel
argument, and the "pillar" cgroup (along with the parent "services" cgroup
and all other sub-cgroups of "services" cgroup) limit is set according the
`eve_mem` kernel argument.

In its turn, the "pillar" cgroup encapsulates several processes, the most
important of which is `zedbox`:

```shell
$ for pid in $(cat /sys/fs/cgroup/memory/eve/services/pillar/cgroup.procs); do echo "CMD: $(cat /proc/$pid/cmdline | tr '\0' ' ')"; done
CMD: /bin/sh /init.sh
CMD: /bin/sh /opt/zededa/bin/device-steps.sh
CMD: /opt/zededa/bin/zedbox <--- zedbox process
CMD: /bin/sh /opt/zededa/bin/device-steps.sh
CMD: cat
CMD: dhcpcd: eth0 [ip4] [ip6]
CMD: dhcpcd: eth1 [ip4] [ip6]
CMD: /usr/sbin/ntpd -p pool.ntp.org
CMD: /opt/zededa/bin/dnsmasq -C /run/zedrouter/dnsmasq.bn1.conf
CMD: sleep 300
```

The other processes in the "pillar" cgroup are DHCP clients, NTP daemon, DNS
server, and some other services.

### RSS, cache, and the cgroup memory usage

Each cgroup contains a file that shows the memory usage of the cgroup:
`/sys/fs/cgroup/memory/*/memory.usage_in_bytes`. The same information is
used by the cgroup events subsystem to trigger events. The memory usage of
the cgroup is calculated as the sum of the memory usage of all processes
in the cgroup.

It is important to note that this value also includes cached memory. Cache is
usually easy to reclaim, so it is not considered a problem if the cgroup memory
usage is close to the limit. The problem arises when the Resident Set Size (RSS)
of the process is close to the limit.

Unfortunately, the cgroup memory threshold events are triggered based on the
cgroup memory usage, which includes cache. During the threshold events handling,
we take into account the cache size, not to report false positives.
However, for better results we also monitor the RSS of the zedbox process
separately in a dedicated thread, reading the `/proc/<zedbox_pid>/statm` file
every 5 seconds.

## Process Stall Information (PSI)

The PSI metrics are a set of metrics that can be used to detect when the system
is under memory pressure. They are tracked and exposed by the kernel. The
metrics show how much time the system is stalled on memory reclaim.

The PSI metrics are available in the `/proc/pressure`. In fact the PSI
metrics are available for CPU, memory, and IO, but in the scope of the
memory monitor we are interested in the memory PSI metrics.

### Format of the PSI metrics

The PSI metrics are available in the `/proc/pressure/memory` file. The file
contains the following fields:

```text
some avg10 avg60 avg300 total
full avg10 avg60 avg300 total
```

The `some` line shows the percentage of time at least one process in the system
is stalled on memory reclaim for the last 10, 60, and 300 seconds. The `full`
line shows the same, but for the whole system. The `total` field shows the
total number of the corresponding stall events.

### Additional information on the PSI metrics in EVE

More information about the PSI metrics can be found in the
[kernel documentation](https://www.kernel.org/doc/Documentation/accounting/psi.txt).

Also, EVE provides a tool `psi-collector` that can be used to collect the PSI
statistics. Documentation on the `psi-collector` tool can be found in the
[psi-collector README](../../pkg/pillar/agentlog/cmd/psi-collector/README.md).
Another tool that can be used to visualize the PSI metrics is `psi-visualizer`.
The documentation on the `psi-visualizer` tool can be found in the
[psi-visualizer README](../../tools/psi-visualizer/README.md).

## What the tool is monitoring?

The memory monitor is designed to track and respond to specific memory-related
events related to the zedbox process or the entire EVE system.

Here are the specific memory events that are being monitored:

* **zedbox process memory usage**: The memory usage of the zedbox process is
monitored. If the Resident Set Size (RSS) of the Zedbox process exceeds a
predefined threshold, a handler script is triggered. The RSS is checked every 5
seconds.
* **eve cgroup memory usage**: The memory usage of the eve cgroup is monitored
in two
ways:
  * **Threshold Event**: If the memory usage of the eve cgroup exceeds a certain
    percentage (98% by default) of its memory limit, a handler script is
    triggered.
  * **Pressure Event**: If the memory pressure level of the EVE cgroup reaches
    the "medium" level, a handler script is triggered. Memory pressure level is
    a measure of how the system is reclaiming memory from the cgroup. We set the
    level to "medium", not "low", to avoid triggering the event too often,
    for example, when the system reclaims cache memory.
* **Pillar Cgroup Memory Usage**: The memory usage of the pillar cgroup is also
monitored in two ways:
  * Threshold Event: If the memory usage of the pillar cgroup exceeds a
    predefined threshold in bytes, a handler script is triggered. Here we
    exclude cache from the memory usage calculation.
  * Pressure Event: If the memory pressure level of the pillar cgroup reaches
    the "low" level, a handler script is triggered.
* **PSI Metrics**: The PSI metrics are monitored. If the `full avg10` value of
  the PSI metrics exceeds a predefined threshold (90% by default), a handler
  script is triggered.

  The `full_avg10` metric is particularly useful for detecting situations where
  all processes are stalled due to memory pressure, making it an effective
  indicator of imminent OOM, especially in cases of rapid memory exhaustion
  ("fast" OOMs). We focus on `full_avg10` because `some_avg10` can spike when
  only some processes are experiencing memory pressure, which doesn’t
  necessarily lead to an OOM. Using `some_avg10` would be too sensitive and
  could result in false alarms, so we prioritize `full_avg10` for more accurate
  detection. Longer intervals like 60- and 300-second averages are not as
  reactive and may miss fast-approaching OOM conditions.

The handler script that is triggered in response to these events performs
various actions to log and manage memory usage. It can, for example, dump memory
allocation sites, trigger a heap dump, and log memory usage details.

## The tool integration

The memory monitor is started as a daemon on the EVE system. It runs in the
background and monitors the memory usage. It's started in a dedicated container
"memory-monitor" that is created by the containerd service.

The monitor binary and the handler script are located in the container version
of the `/sbin/` directory. The handler script is executed by the monitor binary
when a memory event is triggered and expected to be in the same directory.

The default configuration of the memory monitor is stored in the container version
of the `/etc/` directory.

Note, that these files are not seen in the host system, as they are located in
the container filesystem.

The container and its file system is available for investigation with the
following command:

```shell
eve enter memory-monitor
```

The tool than creates the output files in `/persist/memory-monitor/output`.
The persistent storage is mounted to the container, so the output files are
available in the host system.

### Enabling memory monitor

By default, the memory monitor is disabled: its container starts automatically
with the EVE boot but remains paused. To activate memory monitoring, set the
global configuration option `memory-monitor.enabled` to `true`. When Pillar
receives this update, it simply resumes the paused container. Conversely, if
you need to disable it again, setting the option to `false` will pause the
container.

This setup allows you to toggle memory monitoring on and off, which can be
especially useful if you suspect that the memory monitor's handler script might
be consuming excessive CPU or memory resources.

As the memory monitor is a new component in the EVE system, and very few
real-world testing was done with it, is important to be on the safe side, so we
disable the memory monitor by default. It can be enabled by the user if needed.

## Internals of the build and startup process

To deploy the memory monitor to the EVE system, we create a corresponding
container image. The container image is built using the `Dockerfile`. In the
Dockerfile, we copy the necessary files to the container image and build the
tool using the `make dist` command. The Makefile can be also used for building
the tool locally, for example, to test it on a local setup.

Later the container image is used by LinuxKit to deliver it to the EVE rootfs.
We start the container in the "services" section of LinuxKit configuration.
It means that the LinuxKit will start the container automatically when the EVE
system boots. And it will expect the process in the container to run as
foreground process and do not return control. Otherwise, the service will be
considered failed and the container will be stopped. To achieve this, the memory
monitor binary is started with the `-f` flag.

### Apparmor profile

There is an idea to use the apparmor profile for the memory monitor handler. It
should add a layer of security to the handler script that is executed by the
memory monitor by the `system()` call. The apparmor profile is not implemented
yet, but its template is located in the `sbin.memory-monitor-handler` file. It's
also copied to the dist directory, but not to the final container image.

## Note on the memory monitor and the memory cgroups

During the initialization the tool removes itself from the current memory cgroup
and moves to the root one, so it does not affect the memory usage  of the
eve cgroup.

Before the tool starts the handling script, part of which is to dump the memory
usage of the pillar, accessing the internal golang debugging http server, it
temporarily increases the memory limit of the pillar cgroup by 50Mb. This is
done to avoid the situation when the memory usage of the pillar cgroup is close
to the limit, and the handler script cannot run because of the lack of memory.
After the handler script finishes, the memory limit of the pillar cgroup is
restored to the original value.

## Run as a standalone tool on older versions of EVE

On the older versions of EVE, the memory monitor is not integrated into the
system as a container. But it can be run as a standalone tool.

To run it, you need to build the tool using the Makefile:

```shell
$ make dist
```

It will create a dist directory with the memory monitor binary, handler script,
and configuration file. To run the memory monitor, you need to copy the dist
directory to the EVE system and run the binary:

```shell
$ ./memory-monitor
```

The memory monitor will run daemonized in the background. To stop it, you can
send the `SIGTERM` signal to the process:

```shell
$ pkill -SIGTERM memory-monitor
```

The tool will create the output files in the `/persist/memory-monitor/output`.

## Output of the memory monitor

The memory events handling results are logged to the
`/persist/memory-monitor/output` directory. The output directory is created
automatically if it does not exist.

The output directory contains:

* Subdirectory for the last event triggered. The name of the subdirectory is
  the timestamp of the event. The subdirectory contains:
  * `event_info.txt`: A text file that contains metadata about the event. It
    includes the type of the event and the EVE version that was running when the
    event was triggered.
  * `heap_pillar.out`: A heap dump of the zedbox process. It's collected using
    the built-in go tool. It's a binary file that can be analyzed using the
    `pprof` tool. How to analyze the heap dump is described in the next section.
  * `memstats_pillar.out`: A memory usage report of the pillar cgroup. It
    contains the total memory usage of the pillar cgroup according to the cgroup
    itself, including the cache and the total Resident Set Size (RSS)
    according to the smaps file of all processes in the cgroup. It also contains
    the RSS of all processes in the pillar cgroup.
  * `memstat_eve.out`: A memory usage report of the EVE cgroup. It contains the
    total memory usage of the EVE cgroup according to the cgroup itself,
    including the cache and the total Resident Set Size (RSS) according to the
    smaps file. It also contains the RSS and per-mapping details of all the
    processes in the EVE cgroup.
  * `zedbox`: A symlink to the zedbox binary that was used to collect the heap
    dump.
* Tar archives of the previous event directories. The archives are created
  automatically by the handler script when a new event is triggered. The
  archives are created to save disk space (each event directory can be quite
  large, ~5-15Mb, while the archive is usually ~1Mb). We keep not more than
  100 Mb of archives: the oldest archives are deleted by the handler script
  when the total size of the archives exceeds 100 Mb.
  The archive does not contain the `zedbox` symlink.
* `events.log`: A log file that contains a timestamped list of all memory
  events, archives for which are still present in the output directory.
* `memory-monitor-handler.log`: A log file that contains the output of the
  handler script. It  is useful for debugging the handler script if it fails.
  It's cleared if the handler script run is successful.

### Logs of the memory monitor

The memory monitor logs its output to the syslog. Unfortunately, the syslog
logs are not shown with the `logread` command. Nevertheless, you can see them
in the logs files in `/persist/newlogd` directory. The memory monitor logs
are prefixed with the `memory-monitor` tag.

### How to analyze the heap dump

The heap dump (`heap_pillar.out`) is a binary file that can be analyzed using
`go tool pprof`. This tool is a part of the Go toolchain, so it is not
necessary to install anything extra to use it. To run it, first copy the
`heap_pillar.out` file and the `zedbox` binary to the same directory on your
local machine. Then, run the following command:

```shell
$ go tool pprof /path/to/zedbox /path/to/output/<event_timestamp>/heap_pillar.out
```

It will start the pprof tool in the interactive mode. You can use the `top`
command to see the top memory allocations. The `top` command will show you the
top memory allocations in the heap dump. You can also use other commands to
analyze the heap dump.

Another useful command is `list`. It shows the source code that corresponds to
a function with a given as a regular expression name. The name can be taken from
the `top` command output. Do not forget to escape special characters in the
function name (for example, `.`, `(`, `*`, etc) with a backslash.

To make it possible to see the source code of the memory allocations, you need
to have the source code of the zedbox binary. You can provide the path to the
source code to the `pprof` tool using the `-source_path` and `-trim_path` flags.
The first flag is used to provide the path to the source code, and the second
flag is used to trim the path embedded in the binary as they correspond to the
path on the build machine (container) that originally had the source code under
the `/pillar/` directory. Also, don't forget to use the source code of the
version of the zedbox binary that was used to collect the heap dump.

```shell
$ go tool pprof -source_path ../ -trim_path / /path/to/zedbox /path/to/output/<event_timestamp>/heap_pillar.out
```

The `pprof` tool can also generate an interactive graph of the memory
allocations. To do this, you can run the following command:

```shell
$ go tool pprof -source_path ../ -trim_path / -http=:8080 -call_tree -nodefraction=0 -lines /path/to/zedbox /path/to/output/<event_timestamp>/heap_pillar.out
```

## Configuration of the memory monitor

The memory monitor is configured using the `memory-monitor.conf` file.
The default configuration file is located in the `/etc/` directory of the
container image. But it can be overridden by the user by placing the
configuration file in the `/persist/memory-monitor/` directory.

To copy the default configuration file to the `/persist/memory-monitor/` for
editing, run the following command:

```shell
eve exec memory-monitor cp /etc/memory-monitor.conf /persist/memory-monitor/
```

To use the custom configuration values, the user should restart the memory
monitor tool by sending the `SIGHUP` signal to the memory monitor process. It
can be done by running the following command:

```shell
pkill -SIGHUP /sbin/memory-monitor
```

It can be also done by the eve cli command:

```shell
eve memory-monitor-update-config
```

The configuration file should contain the following fields:

```text
CGROUP_PILLAR_THRESHOLD_MB=<threshold in MB>
CGROUP_EVE_THRESHOLD_PERCENT=<threshold in percent>
PROC_ZEDBOX_THRESHOLD_MB=<threshold in MB>
PSI_THRESHOLD_PERCENT=<threshold in percent>
```

The fields are:

* `CGROUP_PILLAR_THRESHOLD_MB`: The threshold in megabytes for the memory usage
  of the Pillar cgroup. If the memory usage of the Pillar cgroup exceeds this
  threshold (we exclude cache), the handler script is triggered.
* `CGROUP_EVE_THRESHOLD_PERCENT`: The threshold for the memory usage of the EVE
  cgroup. The threshold then is calculated as a percentage of the memory limit
  of the eve cgroup, that is read from `/sys/fs/cgroup/memory/eve/memory.limit_in_bytes`
  in runtime.
* `PROC_ZEDBOX_THRESHOLD_MB`: The threshold in megabytes for the Resident Set
  Size (RSS) of the zedbox process. It will be compared every 5 second to the
  RSS of the zedbox process, read from the `/proc/<zedbox_pid>/statm` file.
* `PSI_THRESHOLD_PERCENT`: The threshold for the `full avg10` value of the PSI
  metrics. See the PSI section for more information.

If some of the fields are missing in the configuration file, the default values
will be used. The default values are:

```text
CGROUP_PILLAR_THRESHOLD_MB=400
CGROUP_EVE_THRESHOLD_PERCENT=98
PROC_ZEDBOX_THRESHOLD_MB=200
PSI_THRESHOLD_PERCENT=90
```

## Makefile targets

You can find help on the Makefile targets by running:

```shell
$ make help
```

Worth mentioning that the Makefile has a list of targets that can be used to
build, deploy, get and analyze the memory monitor output in a local setup with
an instance of the EVE system running in a VM, accessible via SSH by local_eve
alias. All these targets are prefixed with `local_`.

## Pressure tool

There is a tool `pressure` that can be used to allocate memory in the EVE system
to trigger the memory monitor events. The tool can be built using the Makefile:

```shell
$ make pressure
```

It will create a `pressure` binary in the `bin` directory. The binary can be
copied to the EVE system and run from any directory.

The tool takes amount of memory to allocate in MB as an argument.

For example, to allocate 100Mb of memory in the EVE system, run the following
command:

```shell
pressure 100
```

It will allocate 100Mb of memory and release it after user presses Enter.

It's worth mentioning that if you run the tool from an ssh session, it will
allocate memory in the ssh session cgroup, that is exactly a part of the eve
cgroup. So, it will trigger the eve cgroup memory event.
