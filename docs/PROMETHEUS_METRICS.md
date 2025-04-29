# Prometheus-Compatible Metrics in EVE

This document describes how EVE exposes system metrics in the Prometheus exposition format.

## Node Exporter Metrics

EVE exposes a broad set of metrics under the `node_exporter` style.
From the EVE itself, you can access these metrics at:

```text
https://localhost:9100/metrics
```

From an application instance, you can access these metrics at:

```text
http://169.254.169.254/metrics
```

This IP address is reachable from within any container or VM that EVE runs
through an interface which is connected to a local network instance.

The metrics endpoint behaves like a standard Prometheus target. You can consume
it from any Prometheus-compatible agent, library, or application. This endpoint
contains a request limiter of 1 rps with a burst of 10 for each IP address.

### Integration into EVE

`node_exporter` is defined as a service in `rootfs.yml.in`. The container
runs with host network and PID namespaces to access system-wide process and
networking information. Key system directories are mounted read-only under
`/hostfs` to allow safe metric collection without modifying the host.

The `Dockerfile` for the service is located in `pkg/node-exporter`, and its
runtime config is defined in `build.yml`. The image version is pinned via
`NODE_EXPORTER_TAG` in the build system (`tools/parse-pkgs.sh`), ensuring
consistent deployments.

To modify how metrics are collected or adjust the exporter’s flags, edit the
`CMD` in the `Dockerfile` or update bind mounts in build.yml.

Regarding the metadata server usage for exposing metrics to applications, you
can find the documentation in the [metadata server doc](./ECO-METADATA.md).

#### Limits Configuration

The metrics are exposed with a limit of 1 request per second (rps) and a burst of 10
for each IP address. This is done to prevent overloading the system with too many
requests.

The limits can be configured with the following global configuration options:

```text
msrv.prometheus.metrics.rps # Rate limit for requests per second
msrv.prometheus.metrics.burst # Burst limit for requests
msrv.prometheus.metrics.idletimeout.seconds # Timeout for requests
```

You can find description of these options in the [EVE configuration doc](./CONFIG-PROPERTIES.md).

#### iptables rules

To enhance security, EVE configures iptables rules to restrict access to the
node exporter metrics endpoint. Only connections from localhost (127.0.0.1
and ::1) are allowed to access TCP port 9100, while all remote access attempts
to this port are explicitly rejected. This ensures that metrics are not exposed
to the external network. It's done via DPCReconciler.

### Exposed Metrics Categories

#### System Uptime

- **node_boot_time_seconds** - Host boot timestamp.
- **node_time_seconds** - Current system time (epoch seconds).

#### CPU and Scheduler

- **node_cpu_seconds_total** - CPU time per mode.
- **node_cpu_guest_seconds_total** - CPU time for guest workloads.
- **node_context_switches_total** - Context switches count.
- **node_intr_total** - Total hardware interrupts.

#### Load

- **node_load1**, **node_load5**, **node_load15** - 1-, 5-, 15-minute load averages.

#### Memory

- **node_memory_MemTotal_bytes** - Total RAM.
- **node_memory_MemFree_bytes** - Unused RAM.
- **node_memory_MemAvailable_bytes** - Estimation of RAM available without swapping.
- **node_memory_Cached_bytes** - Page cache size.
- **node_memory_Buffers_bytes** - Buffer cache size.
- **node_memory_Slab_bytes** - Kernel slab allocations.
- **node_memory_KReclaimable_bytes** - Reclaimable slab memory.
- **node_memory_KernelStack_bytes** - Memory used by kernel stacks.
- **node_memory_Active_bytes**, **node_memory_Inactive_bytes** - Active/inactive pages.
- **node_memory_**\* - Other detailed fields (Dirty, Writeback, HugePages, etc.).

#### Disk I/O

- **node_disk_io_time_seconds_total** - Total I/O time.
- **node_disk_read_bytes_total**, **node_disk_written_bytes_total** - Total throughput.
- **node_disk_reads_completed_total**, **node_disk_writes_completed_total** - Number of I/O operations.
- **node_disk_read_time_seconds_total**, **node_disk_write_time_seconds_total** - Time spent on I/O.
- **node_disk_io_time_weighted_seconds_total** - Weighted I/O time.
- **node_disk_discards_**\*, **node_disk_flush_requests_**\* - TRIM and flush stats.
- **node_disk_info** - Disk metadata (model, vendor, etc.).

#### Filesystem

- **node_filesystem_size_bytes**, **node_filesystem_free_bytes**, **node_filesystem_avail_bytes** - Disk space metrics.
- **node_filesystem_files**, **node_filesystem_files_free** - Inode metrics.
- **node_filesystem_readonly** - Filesystem read-only flag.

#### Network Interfaces

- **node_network_receive_bytes_total**, **node_network_transmit_bytes_total** - Bytes received/sent.
- **node_network_receive_packets_total**, **node_network_transmit_packets_total** - Packet counters.
- **node_network_receive_multicast_total** - Multicast traffic.
- **node_network_speed_bytes** - Link speed.
- **node_network_carrier** - Link state (1 = up, 0 = down).
- **node_network_carrier_*_changes_total** - Link state transitions.
- **node_network_**\* - MTU, queue length, flags, protocol type, etc.
- **node_network_info** - Per-interface constant.

#### Processes and Threads

- **node_procs_running**, **node_procs_blocked** - Runnable and blocked processes.
- **node_processes_**\* - PIDs, thread counts, state breakdowns.

#### Cgroups

- **node_cgroups_cgroups** - Count of cgroups.
- **node_cgroups_enabled** - Cgroups enabled flag.

#### Entropy

- **node_entropy_available_bits** - Available entropy.
- **node_entropy_pool_size_bits** - Total entropy pool size.

#### Pressure Stall Information

- **node_pressure_*_waiting_seconds_total** - Time waiting for CPU, memory, I/O.
- **node_pressure_*_stalled_seconds_total** - Stalled time due to contention.

#### Time and Clock

- **node_timex_**\* - Clock timing, frequency, sync status.
- **node_time_clocksource_**\* - Clock source info.

#### Hardware and System Info

- **node_dmi_info** - BIOS and hardware identifiers.
- **node_uname_info** - Kernel version and architecture.

#### Network Protocol Counters

- **node_netstat_Icmp\*, Ip\*, Tcp\*, Udp**\* - Protocol stats.
- **node_netstat_Ip_Forwarding** - IP forwarding state.

#### ZFS (if applicable)

- **node_zfs_arc_**\* - ARC cache stats.
- **node_zfs_abd_*, node_zfs_dbuf_**\* - Buffer metrics.

#### Error Metrics

- **node_network_receive_errs_total** - Cumulative receive error count per interface.
- **node_network_transmit_errs_total** - Cumulative transmit error count per interface.
- **node_netstat_TcpExt_InErrs_total** - Bad inbound TCP packets.
- **node_netstat_TcpExt_RetransSegs_total** - TCP retransmits.
- **node_filesystem_device_error** - Errors returned by `statfs()` on each mounted filesystem.

It is not a full list of all metrics, to see all available metrics, please check
the `/metrics` endpoint.
