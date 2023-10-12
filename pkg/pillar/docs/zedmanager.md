# Application Instance Management Agent in EVE (aka zedmanager)

## Overview

Zedmanager does the overall orchestration of application instances in EVE.
This means receiving configuration from the controller via zedagent, and reporting results to the controller via zedagent, and then using other EVE microservices to manage the different parts of the orchestration.

- Using volumemgr to create the (disk) volumes for the application instance
- Using zedrouter to create the network adapters and local services like DHCP and DNS for the application instance (note that zedrouter separately sets up the network instances to which these adapters are attached)
- Using domainmgr to assign any I/O adapters to the application instance
- Using domainmgr to run the application instance

## Overall flow for creation

- zedmanager handles an AppInstanceConfig received from zedagent.
- zedmanager uses the TBD ResolveConfig to ask that any content tags are resolved to hashes
- downloader does that resolution and responds with a ResolveStatus
- zedmanager uses the VolumeConfig to ask for the existence of the volumes it needs
- volumemgr handles that (using the downloader and verifier as needed) and responds with a VolumeStatus
- zedmanager uses AppNetworkConfig to request the existence of the network adapters
- zedrouter processes AppNetworkConfig, creates/updates Linux bridges, allocates IP addresses, etc and provides an AppNetworkStatus back
- zedmanager uses DomainConfig to ask for I/O adapter assignment
- zedmanager also uses DomainConfig to ask that the app instance be run (using the Activate field)
- domainmgr processes DomainConfig and provides a DomainStatus. It uses different hypervisor/runtime plugins for this purpose.

Throughout this processes there are state updates and progress indication, including transient and permanent errors, flowing in the reverse direction from the various above Status publications, which zedmanager collects and feeds back to zedagent using the AppInstanceStatus publication.

## Overall flow for deletion

In general this flows in the reverse direction of the create, in that the runtime needs to be halted before the I/O adapters, network bridges, and volumes can be released.

## Handling modifications

zedmanager can handle a set of modifications to the AppInstanceConfig object.
The key one is to be able to update the ACLs for the network part while the application instance keeps running.

zedmanager can also handle two commands; a restart and a purge command.

The restart means restarting/rebooting the application instance without any changes. This is fed down to domainmgr as a Activate=false followed by Activate=true sequence of operation.

The purge means replacing the first volume (the "boot disk") with a copy recreated from the immutable content. As part of that it is also possible to add and drop virtual disks, network adapters, and/or I/O adapters.

The purge orchestration takes pains to minimize the downtime for the application by creating the new volume or volumes (which might involve downloading and verifying new versions or new content) while the application is running using the old volumes. After that the application instance is halted, and the I/O and network adapters are released. Then the instance is recreated and booted using the new volumes and I/O plus networking adapters.
