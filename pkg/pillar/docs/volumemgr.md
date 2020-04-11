# Volume Manager Management Agent in EVE (aka volumemgr)

## Volume versus image

There is a distinction between volumes and images:

- Images are immutable read/only blobs of data; could be called "content"
- Volumes are read/write or read/only mount points for one or more apps
- A volume might be created from one or more images, but it could also be created from blank space, or be a reference to some network storage

## Overview

Volumemgr is responsible for creating different storage volumes for applications. This includes interfacing with downloader, verifier, and containerd to download, verify checksums and signatures, and prepare VM and container volumes.
The preparation of VM images is currently quite simple it that it consists of copying a verified VM image to create a R/W image.

When a R/W image needs to be purged the volumemgr is instructed (by zedmanager) to create a new volume with a unique name.

Volumemgr is also used (by baseosmgr) to download and verify EVE images.
In this case baseosmgr is responsible to move the image into the proper partition since that is performed when the new image is activated and not when it is prepared.

Volumemgr uses a Key() definition (in `pillar/types/volumes.go`) with the intent of being able to support different types of volumes. The currently supported one is OriginTypeDownload, which are for volumes created from content which is downloaded (and have their hash and signatures verified). Planned ones are OriginTypeBlank (created from scratch), and OriginTypeCloudInit (CDROM volume created with cloud-init user data.) The Key format might evolve as new types are added.

Volumemgr also has an on-disk naming scheme for the volumes stored in /persist/img. It is key to retain backwards compatibility for this format to ensure that existing application instances do not loose their disk images as EVE is updated.

## Key Input/Output

Volume Manager interacts with the Cloud controller (e.g. zedcontrol) indirectly through zedmanager and baseosmgr using two key messages:

- VolumeConfig from baseosmgr and zedmanager is subscribed to by volumemgr. This contains requests that particular volumes should exist, and how to create them (e.g., by downloading stuff) if they do not. VolumeConfig is defined in `pillar/types/volumes.go`
- VolumeStatus is published by volumemgr and subscribed to by baseosmgr and zedmanager. This contains the current state of the volumes. VolumeStatus is defined in `pillar/types/volumes.go`

Both VolumeStatus and VolumeConfig use the agentScope mechanism to keep the baseosmgr and zedmanager use separately.

Volume Manager in turn requests work from downloader and verifier. This consists of a set of objects (all using the agentScope mechanism):

- PersistImageConfig is published by verifier for the verified images, including those found on disk after a device reboot.
- PersistImageStatus is published by volumemgr to track reference counts on the verified images, including a handshake when the verifier wishes to garbage collection unused images.
- DownloaderConfig is published by volumemgr and subscribed to by downloader. This specifies the desire to find a downloaded blob for a particular object.
- DownloaderStatus is publishes by downloader to capture progress, errors, and completion of downloading blobs.
- VerifyImageConfig is published volumemgr and subscribed to by the verifier. This specifies the desire to find a verified blob for a particular object.
- VerifyImageStatus is published by the verifier to capture progress, errors, and completion of verifying blobs.

Volume Manager also interacts with containerd using its API.

Volume Manager uses a VolumeStatus with the "unknown" agentScope to record and
publish information about the volumes it discovers on disk after a device reboots. It uses this publication internally to use those volumes as they are requested in a VolumeConfig.

In addition, Volume Manager is handling the certificates used for verifying image signatures. This area is subject to change as the EVE device API evolves, but it includes:

- CertObjConfig is published by zedagent based on what it receives from the controller.
- CertObjStatus is published by volumemgr and used internally to track the progress of the certificates.
- DownloaderConfig/DownloaderStatus with the certObj agentScope used as above to handle the downloading of the certificates.

Once the certificates have been downloaded they are stored in /persist/certs and used by the verifier.

## Flow

This gives an overview of the different flows which include the volume manager.

### Volume Manager startup

When volumemgr starts it finds existing volumes on disk and publishes those (for its own use) as VolumeStatus under the "unknown" agentScope.

### Requests to add volumes from zedmanager and baseosmgr

When volumemgr gets a request for a volume, it first looks whether it matches an existing volume. That might exist in the above "unknown" agentScope collection, in which case it is promoted to the agentScope for the particular requester. In this case its work is complete.

Otherwise (for the OriginTypeDownload), the volumemgr looks for any existing already verified blob in VerifyImageStatus and PersistImageStatus. If one is found, it ensures that there is a corresponding VerifyImageConfig and PersistImageConfig to retain a reference count on the verified image.

Once there is a VerifyImageStatus indicating a successful verification, it is used to construct the volume.

### Downloading blobs

If no existing volume nor verified image exists, then volumemgr will request the downloader to download stuff through the DownloaderConfig/DownloaderStatus interaction.

Once that has succeeded, then volumemgr will request the verifier to check the hashes and signatures for the downloaded blob using the VerifyImageConfig/VerifyImageStatus interaction.

Once there is a VerifyImageStatus indicating a successful verification, it is used to construct the volume.

### Constructing volumes

For a OriginTypeDownload which is not a container, this consist of creating a read/write image in /persist/img through a simple copy.
For a container this uses containerd to prepare the container for use.

### Destroying volumes

When zedmanager or baseosmgr deletes a VolumeConfig, then volumemgr will destroy the volume (and delete the VolumeStatus). This includes dropping any reference counts it has on a DownloaderConfig, VerifyImageConfig, and/or PersistImageConfig. Finally any Read/Write volume is deleted.

### Garbage collection

Any images in the above "unknown" agentScope are garbage collected if no VolumeConfig has claimed then after N minutes after zedagent received its configuration. By default that timer is one hour and is controlled by the timer.gc.vdisk configuration property.
