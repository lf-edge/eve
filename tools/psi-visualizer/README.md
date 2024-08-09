# PSI (Process Stall Information) Visualizer

This tool visualizes PSI (Process Stall Information) data collected by the Linux
kernel. PSI is a feature introduced in Linux 4.20 that provides information
about various kinds of stalls that can happen in the kernel.
For more information about PSI, see the
[kernel documentation](https://www.kernel.org/doc/Documentation/accounting/psi.rst).

The tool creates an interactive plot that shows the memory pressure statistics
over time.

It can be used to understand the dynamics of memory pressure in the system and
to identify the processes that are causing the pressure.

## Grabbing PSI data

To collect PSI data that can be fed to the visualizer, you need to run the
`psi-collector` tool. The tool is available in the
[psi-collector](../../pkg/pillar/agentlog/cmd/psi-collector) directory.
Documentation on how to use the tool is available in the tool's
[README](../../pkg/pillar/agentlog/cmd/psi-collector/README.md).

## Preparing the environment

To build the PSI visualizer, you need to have the following dependencies
installed:

* Python 3
* pip

To install the dependencies, run:

```sh
make prepare-env
```

It will create a virtual environment in the `venv` directory and install the
required dependencies.

Then you have to activate the virtual environment:

```sh
source venv/bin/activate
```

## Running the PSI visualizer

To run the PSI visualizer, run:

```sh
python3 visualize.py <path-to-psi-file>
```
