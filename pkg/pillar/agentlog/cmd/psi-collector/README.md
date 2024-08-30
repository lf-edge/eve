# Pressure Stall Information (PSI) Collector

The PSI is a kernel feature that provides information about the pressure on the
memory, CPU, and IO subsystems. In our case, we are interested in the memory
pressure.

The PSI collector is a tool that collects PSI metrics from the kernel and
outputs them in a format that can be consumed by a visualization tool.

## Requirements

The PSI collector requires the kernel to have the PSI feature enabled. The PSI
feature is available in the Linux kernel starting from version 4.20, but it is
disabled by default. To enable the PSI feature, the kernel must be compiled with
the `CONFIG_PSI` option enabled.

## Output

The output can be found in the `/persist/memory-monitor/output/psi.txt` file.

The output is a series of lines, where each line represents a single snapshot
of the PSI metrics. They are formatted as follows:

```text
date time someAvg10 someAvg60 someAvg300 someTotal fullAvg10 fullAvg60 fullAvg300 fullTotal
```

### Visualization

The PSI collector output can be visualized using the PSI visualizer tool. The
tool is available in [psi-visualizer](../../../../../tools/psi-visualizer).
For more information on how to use the PSI visualizer, see the tool's
[README](../../../../../tools/psi-visualizer/README.md).

## EVE Integration

The PSI collector is integrated with the Pillar agentlog component. The PSI
collector can be started and stopped by sending corresponding commands to the
Pillar. The command to start the PSI collector are integrated as a part of the
eve script.

### Start

To start the PSI collector, run the following command:

```sh
eve psi-collector start
```

### Stop

To stop the PSI collector, run the following command:

```sh
eve psi-collector stop
```

## Standalone Usage

For the older versions of EVE, the PSI collector can be run as a standalone
tool. For that one needs to build the PSI collector binary and copy it to the
target device.

Worth noting that in this case, EVE Kernel should have the PSI feature enabled.
Most probably, the kernel should be recompiled with the `CONFIG_PSI` option.

### Building

To build the PSI collector, run the following command:

```sh
make build
```

To build the binary for ARM architecture, run:

```sh
make build-arm
```

The binary will be placed in the `bin` directory.

### Running

After building the binary, copy it to the target device, preferably to the
`/persist/memory-monitor` directory. Then run the binary:

```sh
/persist/memory-monitor/psi-collector
```

## Local make targets

In the case of running EVE on a local machine, in QEMU, with SSH access enabled,
and available as `local_eve`, the following make targets can be used:

* local-install - install the binary on local_eve
* local-run - run the binary on local_eve
* local-get-results - get the results from local_eve
* local-view-results - view the results, using psi-visualizer
