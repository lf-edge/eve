# Domain Management Agent in EVE (aka domainmgr in code)

## Overview

Domainmgr is the interface to the hypervisor to start DomU instances:

- It starts, stops, and tracks the domUs
- It includes doing device assignment, i.e. assigning peripheral devices to DomU based on config.
- It has retry logic for when a domU fails to boot
- It reports metrics such as CPU and memory from the domains
- As part of device assignment it also manages the loading and unloading of USB kernel modules based on the debug.enable.usb configuration knob.

## Key Input/Output

Domain Manager interacts with the Cloud controller (e.g. zedcloud) indirectly using four key messages:

- DomainConfig from controller is fed to domainmgr. This contains the configuration information about a DomU instance. DomainConfig is defined in `pillar/types/domainmgrtypes.go`
- DomainStatus is fed from `domainmgr` to controller. This contains the operational information about a DomU instance. DomainStatus is defined in `pillar/types/domainmgrtypes.go`
- DomainMetric with CPU and memory metrics for the host and the applications
- PhysicalIOAdapterList specifies the set of physical I/O adapters which can potentially be used for adapter assignment.

zedmanager publishes DomainConfig and subscribes to DomainStatus, while zedagent publishes PhysicalIOAdapterList and subscribes to DomainMetric.

## PCI Device Management

- PCI passthrough hands a device to the guest through VFIO; the device is unbound from its host driver and bound to `vfio-pci` for the lifetime of the domain.
- Domain Manager assigns PCI devices that are not in use by the host to `vfio-pci` for use in guest domains, i.e. all PCI networking devices are assigned unless they are a port in DeviceNetworkStatus (from `pillar/cmd/nim`), and all USB controllers are assigned unless debug.enable.usb is set to true in the device configuration.
- Note that the assigning away doesn’t happen until domainmgr starts. domainmgr starts once the device has been successfully onboarded in the Cloud controller.
- Since each hardware model can have different set of network or USB adapters, for every hardware model, the controller provides a [PhysicalIO](https://github.com/lf-edge/eve-api/tree/main/proto/config/devmodel.proto) in the API which zedagent publishes as `PhysicalIOAdapterList`.

## Internal Operation

- Domain Manager implementation uses separate go routine for each key in DomainConfig
- Watches for status changes such as halted, or reboot (when the domain ID changes) and reports those in DomainStatus
- Avoids head-of-line blocking during large copy or slow shutdown operations
- Copies a read/write virtual disk configured for the guest domain, to a unique one in `/persist/img/`. This `/persist/img/` path is fed to the hypervisor's domain config to create the guest domain.
- If `Activate=false` in DomainConfig, or if the DomainStatus deleted then Domain Manager halts the domU
- When halting Domain manager first attempts a graceful shutdown; if the domU doesn’t shut down, it does a poweroff
- Renders the hypervisor's domain config into `/run/domainmgr/domains/dom<N>.cfg` (a QEMU config file on KVM) and starts the domain from it.

## Debugging

- Look at the respective input/output files:
- `/run/zedmanager/DomainConfig` and `/run/domainmgr/DomainStatus` shows the key input and output
- If domUs fail to boot domainmgr will retry after 10  minutes. You can control it with `timer.boot.retry` global configuration variable. The option value is in seconds. e.g. if you want to change retry time to 1 minute, then use `--config=timer.boot.retry:60`
- If USB keyboard disappears (stops working after boot) could be that domainmgr didn’t initially start; For instance, during onboarding domainmgr does not run hence USB is open
