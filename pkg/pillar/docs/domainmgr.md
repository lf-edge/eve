# Domain Management Agent in EVE (aka domainmgr in code)

## Overview
Domainmgr is the interface to the hypervisor to start DomU instances
- Starts, stops, and tracks the domUs
- Includes doing device assignment. i.e. Assigning peripheral devices to DomU based on config.
- Has retry logic for when a domU fails to boot

## Key input/output
- DomainConfig/DomainStatus for the domUs
- DomainConfig from controller is fed to domainmgr
- DomainStatus is fed from domainmgr to controller
- Assign away all PCI networking devices to pciback unless they are a port in DeviceNetworkStatus (from nim)
- Assign away all USB controllers to pciback unless debug.enable.usb is set to true
- Note that the assigning away doesn’t happen until domainmgr starts
- What is assigned away to pciback is what is listed in /var/tmp/zededa/AssignableAdapters/

 
## Internal Operation
- A separate go routine for each key in DomainConfig
- Watches for status changes such as halted, or reboot (when the domain ID changes) and reports those in DomainStatus
- Avoids head-of-line blocking during large copy or slow shutdown operations
- Creates a xl config file in /var/run/domainmgr/xen/xen*.cfg
- Copies a read/write virtual disk to a unique one in /persist/img/
- If Activate=false, or DomainStatus deleted then halt the domU
- When halting first do a graceful shutdown; if the domU doesn’t shut down then do a poweroff

## Debugging
- Look at the respective input/output files:
- /run/zedmanager/DomainConfig and /var/run/domainmgr/DomainStatus shows the key input and output
- We’ve seen cases where PV doesn’t boot but HVM does due to a missing dom0 qemu process (started by /etc/init.d/xencommons). So please check if "/usr/lib/xen/bin/qemu-system-i386 -xen-domid 0" is running
- If domUs fail to boot domainmgr will retry after 10  minutes. You can control it with --config=timer.boot.retry:60
- If USB keyboard disappears (stops working after boot) could be that domainmgr didn’t initially start; For instance, during onboarding domainmgr does not run hence USB is open
