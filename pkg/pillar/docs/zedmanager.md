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

## Communication

### zedmanager and volumemgr

Zedmanager communicates with the volumemgr by sending VolumeRefConfigs (VRC) and receiving VolumeRefStatuses (VRS). Both objects represent the link between a volume and an application instance and therefore contain parameters such as

- Volume UUID
- Volume Generation Counter
- Volume Local Generation Counter
- App Instance UUID

to represent that connection. There can be only one VolumeRefConfig and VolumeRefStatus per link, so these parameters also form a unique key to represent a VRC or VRS instance. Both VRC and VRS describing the same link will have the same key, so they can be easily matched.

The VRC, which initially comes from DeviceConfig and is part of AppInstanceConfig, also carries the information about the volume mount point for the application instance. This information is immutable.
Additionally, the VRC will carry a command (`vrc.VerifyOnly`) from zedmanager about how far the volume initialization should go. Initially, volumemgr will be instructed to only download and verify all volumes (`vrc.VerifyOnly == true`). Later in the process of starting the application instance, zedmanager will send a `vrc.VerifyOnly == false` command to volumemgr to actually create the volume.
Although the set of VRCs in the AppInstanceConfig is immutable, the zedmanager can control the creation and deletion of volumes by publishing (`MaybeAddVolumeRefConfig`) or unpublishing (`MaybeRemoveVolumeRefConfig`) the VRCs to the volumemgr.

The VRS is published by the volumemgr to the zedmanager to inform about the status of the volume creation process. However the zedmanager maintains it's own set of VRSs inside AppInstanceStatus which is created to resemble the corresponding set of VRCs upon their arrival. This set of VRSs is managed by the zedmanager and only occasionally synchronized with the state coming from the volumemgr. The VRSs in the AppInstanceStatus are used to keep track of the volumes even when their VRCs are removed from the AppInstanceConfig during an update or purge operation. They play a big part in determining the current state for zedmanager's state machine and it's logic. And of course the VRSs in the AppInstanceStatus are also used to inform the controller about the current state of the volumes.
