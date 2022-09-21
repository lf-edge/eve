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

## Asynchronous Programming

Volume Manager, like most of the rest of EVE, works using asynchronous
messages via pubsub. Each task is marked as complete, and a new task is started,
by creating and passing the right message, which a different process will consume.

### Security

For security reasons, EVE does not allow processes that can talk to the network
be the same processes that verify the bits that are downloaded. Thus, volumemgr
itself never actually performs a download or does verification. These steps are
handled by independent processes, `downloader` and `verifier`. volumemgr
interacts with these processes, as it interacts with zedmanager, using
async pubsub messages.

## Key Input/Output

Volume Manager interacts with the Cloud controller (e.g. zedcontrol) indirectly through zedmanager and baseosmgr using two key messages:

- VolumeConfig from baseosmgr and zedmanager is subscribed to by volumemgr. This contains requests that particular volumes should exist, and how to create them (e.g., by downloading stuff) if they do not. VolumeConfig is defined in `pillar/types/volumes.go`
- VolumeStatus is published by volumemgr and subscribed to by baseosmgr and zedmanager. This contains the current state of the
 volumes. VolumeStatus is defined in `pillar/types/volumes.go`. `VolumeStatus` has a property, `Content`, which contains all of the parts of the image that drives the individual volume, and their download and verification status.

Both VolumeStatus and VolumeConfig use the agentScope mechanism to keep the baseosmgr and zedmanager use separately.

Volume Manager in turn requests work from downloader and verifier. This consists of a set of objects (all using the agentScope mechanism):

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

Otherwise (for the `OriginTypeDownload`), the volumemgr looks for any existing already verified blob in `VerifyImageStatus`. If one is found, it ensures that there is a corresponding `VerifyImageConfig` to retain a reference count on the verified image.

Once there is a `VerifyImageStatus` indicating a successful verification, it is used to construct the volume.

### Downloading blobs

If no existing volume nor verified image exists, then volumemgr will manage the
download and verification of images.This happens in two phases, for each content element
that makes up the content tree for the image, using async messages.

As described earlier in this document, for security reasons, volumemgr itself
does not perform the download, and the part that can perform the download cannot
do the verification. Thus, the process must be:

1. Instruct a network-connected process to download bits
1. Instruct a non-network-connected process to verify the bits
1. Use the bits

The download and verification flow for each content blob that makes up the tree is:

- volumemgr requests that downloader download blobs through `DownloaderConfig` messages
- downloader informs volumemgr of the state of a download via `DownloaderStatus` messages

Once download of an individual blob is complete, volumemgr can request verification.

- volumemgr requests that verifier verify hashes and signatures for a blob on the filesystem via `VerifyImageConfig` messages
- verifier informs volumemgr of the success of failure of verification, and final location of the verified file, via `VerifyImageStatus` messages

Once there is a `VerifyImageStatus` indicating a successful verification for every element of the
content tree, volumemgr can use it to construct the volume.

A later section in this document describes the download process in detail.

#### Storage Locations

Responsibility for the locations of immutable data blobs is determined by the
appropriate owner.

- volumemgr controls the location of downloads. When it constructs a `DownloaderConfig`, it informs downloader where to place the downloader file.
- verifier, as the sole owner of verification and disconnected from the network, controls the location of verified files and the cache for files undergoing verification. Verifier alone has the right to modify files in directories under its control.

Since each one controls its own location, they can change.

In practice, to date, these have been the directories:

- Downloads: `/persist/downloads/{appImg.obj,baseOs.obj}/pending`
- Temporary cache for images undergoing verification: `/persist/downloads/{appImg.obj,baseOs.obj}/verifier`
- Verified: `/persist/downloads/{appImg.obj,baseOs.obj}/verified`

### Constructing volumes

For a OriginTypeDownload which is not a container, this consist of creating a read/write image in /persist/img through a simple copy.
For a container this uses containerd to prepare the container for use.

### Destroying volumes

When zedmanager or baseosmgr deletes a VolumeConfig, then volumemgr will destroy the volume (and delete the VolumeStatus). This includes dropping any reference counts it has on a DownloaderConfig, and/or VerifyImageConfig. Finally any Read/Write volume is deleted.

### Garbage collection

Any images in the above "unknown" agentScope are garbage collected if no VolumeConfig has claimed then after N minutes after zedagent received its configuration. By default that timer is one hour and is controlled by the timer.gc.vdisk configuration property.

## Download Details

On startup, volumemgr registers to receive notifications from agent `"zedmanager"`
of scope `types.AppImgObj`, i.e. notifications for application image objects.
It registers several handlers, the relevant one of which is `handleAppImgCreate`.

Whenever zedmanager requests the download of an application image that does not
yet exist, it creates the `appImgObj`. This triggers the handler `handleAppImgCreate`.

1. `handleAppImgCreate()` is triggered. This is just a handler for the event.
   1. `handleAppImgCreate()` calls `vcCreate()`
1. `vcCreate()`:
   1. creates a `VolumeStatus{}`
   1. Adds the base content reference to `VolumeStatus.Content`
   1. If the image is a container, indicates that the base content reference has children
   1. Publishes the `VolumeStatus`
   1. Calls `doUpdate()`
1. `doUpdate()` is called by `vcCreate()` as well as any time `updateVolumeStatus()` is called. `doUpdate()` is responsible for checking the status of a volume, based on its `VolumeStatus`, and then taking next steps, if needed. It is like a "switchboard" for `VolumeStatus` updates.
   - If the image is verified and the volume is created, we are done
   - If the image is verified and the volume is not created, create the volume
   - If the image is not verified, loop through each element in `VolumeStatus.Content`:
     - If `VERIFYING`, wait for next loop
     - If `DOWNLOADING`, wait for next loop
     - If `DOWNLOADED`, start verification for this blob (see below)
     - If `VERIFIED`, and has children, loop through each child and begin download+verification loop
   - If the image is not verified and all of the children are verified:
     1. Mark the image as `VERIFIED`
     1. Create the volume

### Downloads

The download is started by calling `AddOrRefcountDownloaderConfig()` which
creates and publishes `types.DownloaderConfig`; the downloader is listening for
this message to start a download.

The downloader indicates its status, including completion, by publishing
`types.DownloaderStatus`. Volume Manager registers the handler
`handleDownloaderStatusModify` to catch these events.

### Verification

The verification is started by calling `kickVerifier()` which calls
`MaybeAddVerifyImageConfig()`, which creates and publishes
`types.VerifyImageConfig`; The verifier is listening for this message to verify
a file.

The verifier indicates its status, including completion, by publishing
`types.VerifyImageStatus`. Volume Manager registers the handler
`handleVerifyImageStatusModify` to catch these events.

#### doUpdate

As described earlier, `doUpdate()` is like a "switchboard" for event processing.
It is called whenever there is an update.

- `handleDownloaderStatusModify`, upon receiving an event, calls `updateVolumeStatus`, which, in turn, calls `doUpdate()`.
- `handleVerifyImageStatusModify`, upon receiving an event, calls `updateVolumeStatus`, which, in turn, calls `doUpdate()`.

### Flow Summary

We can visualize the application download flow, based on the above, as follows. On the left
are subscription handlers. We do not look at anything outside of volumemgr.

```text
handleAppImgCreate
   |
   |---> vcCreate
             |
             |----> publish(VolumeStatus)
             |
             |----> doUpdate
                      |
                      |----> downloadBlob (foreach blob)
                               |----> AddOrRefcountDownloaderConfig
                                       |
                                       |----> publish(DownloaderConfig) --> downloader event handler

handleDownloaderStatusModify
   |
   |---> updateStatus
            |
            |----> doUpdate
                     |
                     |-----> kickVerifier
                               |
                               |---> MaybeAddVerifyImageConfig
                                        |
                                        |---> publish(VerifyImageConfig) --> verifier event handler

handleVerifyImageStatusModify
   |
   |---> updateVolumeStatus
            |
            |----> doUpdate
                     |
                     |----> publish(VolumeStatus)
```
