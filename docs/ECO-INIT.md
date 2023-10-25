# ECO Initialization

This document describes the ECO initialization process, specifically how
an ECO goes from "configured in the controller" to "launched and running".
This includes:

* configuration creation
* image download and verification
* network creation and initialization
* ECO launch

For a deeper understanding off ECOs, please read [ECOS.md](./ECOS.md).

## Process

The high-level process for preparing an ECO follows this flow. In each section, the
responsible component is placed in brackets. All communication between components,
i.e. configs and statuses, are performed using publish-subscribe via
[pubsub](./IPC.md).

1. Create App: An ECO is configured on a valid controller, e.g. [zedcloud](https://zededa.com)
1. Receive Device Config ([zedagent](../pkg/pillar/cmd/zedagent)): EVE device receives and [processes](../pkg/pillar/cmd/zedagent/handleconfig.go#L412) an updated device config message which contains the new ECO app
1. Create Local App Config ([zedagent](../pkg/pillar/cmd/zedagent)): [parse the app config](../pkg/pillar/cmd/zedagent/parseconfig.go#L453) in the device config message to [create and publish](../pkg/pillar/cmd/zedagent/parseconfig.go#L491-558) an [AppInstanceConfig](../pkg/pillar/types/zedmanagertypes.go#L46) for the ECO
1. Consolidate ECO management ([zedmanager](../pkg/pillar/cmd/zedmanager/)): [Retrieve and parse](../pkg/pillar/cmd/zedmanager/zedmanager.go#L443-L%40) the [AppInstanceConfig](../pkg/pillar/types/zedmanagertypes.go#L46), and launch the ECO using the following steps.
   1. Retrieve and verify image
   1. Prepare ECO networking
   1. Launch ECO

`zedmanager` itself does not do any of the downloading, preparation or launching. It only _orchestrates_
tasks between other microservices that do the actual work. Orchestration is via messages on the `pubsub`.

`zedmanager`'s main function for launching or updating ECOs is
[doUpdate()](../pkg/pillar/cmd/zedmanager/updatestatus.go#L308).
This calls one separate function for each of the three major steps in launching an ECO.

It is important to recall that all inter-process communication, including between `zedmanager`
and the microservices responsible for downloading and verifying images, preparing networking,
and activating an ECO, are performed asynchronously via [pubsub](./IPC.md). Thus, the
actual progression from "request action X" to "action X complete" is not synchronous.
Rather, one function will publish the request for action X, while a separate handler
will react to the status update that action X is complete and start the next stage.

### Image Download

[zedmanager#doInstall()](../pkg/pillar/cmd/zedmanager/updatestatus.go#L369) coordinates the downloading and verifying
of the image. It first downloads, then verifies the image.

1. Download the image
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): for each image in the [AppInstanceConfig](../pkg/pillar/types/downloadertypes.go#L28), create and publish a [DownloaderConfig](../pkg/pillar/types/downloadertypes.go#L29)
   1. [downloader](../pkg/pillar/cmd/downloader/): see the [DownloaderConfig](../pkg/pillar/types/downloadertypes.go#L29)
   1. [downloader](../pkg/pillar/cmd/downloader/): create and publish a [DownloaderStatus](../pkg/pillar/types/downloadertypes.go#L65) marked `PendingAdd`
   1. [downloader](../pkg/pillar/cmd/downloader/): create space and download the image. This contains the logic to handle different download types in [handleSyncOp()](../pkg/pillar/cmd/downloader/downloader.go#L1624)
   1. [downloader](../pkg/pillar/cmd/downloader/): update and publish the [DownloaderStatus](../pkg/pillar/types/downloadertypes.go#L65) as complete
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): retrieve the [DownloaderStatus](../pkg/pillar/types/downloadertypes.go#L65), download is complete
1. Verify the image
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): for each image successfully downloaded, create and publish a [VerifyImageConfig](../pkg/pillar/types/verifiertypes.go#L25)
   1. [verifier](../pkg/pillar/cmd/verifier/): see the [VerifyImageConfig](../pkg/pillar/types/verifiertypes.go#L25)
   1. [verifier](../pkg/pillar/cmd/verifier/): create and publish a [VerifyImageStatus](../pkg/pillar/types/verifiertypes.go#L53) marked `PendingAdd`
   1. [verifier](../pkg/pillar/cmd/verifier/): verify the image referenced in the verifier config
   1. [verifier](../pkg/pillar/cmd/verifier/): update and publish the [VerifyImageStatus](../pkg/pillar/types/verifiertypes.go#L53) as complete
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): retrieve the [VerifyImageStatus](../pkg/pillar/types/verifiertypes.go#L53), verification is complete

Image verification is validation of each component's actual sha256 hash matches that which was provided by the controller.

### Prepare Networking

[zedmanager#doPrepare()](../pkg/pillar/cmd/zedmanager/updatestatus.go#L696) coordinates the preparation of networking.

1. Set up networking
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): create and publish an [AppNetworkConfig](../pkg/pillar/types/zedrouter.types#L25)
   1. [zedrouter](../pkg/pillar/cmd/zedrouter/): see the [AppNetworkConfig](../pkg/pillar/types/zedrouter.types#L25)
   1. [zedrouter](../pkg/pillar/cmd/zedrouter/): set up network connectivity
   1. [zedrouter](../pkg/pillar/cmd/zedrouter/): create and publish an [AppNetworkStatus](../pkg/pillar/types/zedrouter.types#L101) marking as complete
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): retrieve [AppNetworkStatus](../pkg/pillar/types/zedrouter.types#L101), ECO networking preparation is complete

### Activate ECO

[zedmanager#doActivate()](../pkg/pillar/cmd/zedmanager/updatestatus.go#L763) coordinates activating the ECO.

1. Activate ECO
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): create and publish a [DomainConfig](../pkg/pillar/types/domainmgr.types#L19)
   1. [domainmanager](../pkg/pillar/cmd/domainmgr): see the [DomainConfig](../pkg/pillar/types/domainmgr.types#L19)
   1. [domainmanager](../pkg/pillar/cmd/domainmgr): start the domain
   1. [domainmanager](../pkg/pillar/cmd/domainmgr): create and publish a [DomainStatus](../pkg/pillar/types/domainmgr.types#L86)
   1. [zedmanager](../pkg/pillar/cmd/zedmanager/): see the [DomainStatus](../pkg/pillar/types/domainmgr.types#L86), ECO launch is complete

A diagram describing this flow is below:

[TO BE FILLED IN]

The list of subscriptions relevant to ECO initialization is as follows.

| Publisher | Topic | Subscribers |
|-----------|-------|-------------|
| `zedagent` | `AppInstanceConfig` | `zedmanager` |
| `zedmanager` | `DownloaderConfig` | `downloader` |
|    | `VerifyImageConfig` | `verifier` |
|    | `AppNetworkConfig` | `zedrouter` |
|    | `DomainConfig` | `domainmgr` |
|    | `AppInstanceStatus` | multiple |
| `downloader` | `DownloaderStatus` | `zedmanager` |
| `verifier` | `VerifyImageStatus` | `zedmanager` |
| `zedrouter` | `AppNetworkStatus` | `zedmanager` |
| `domainmgr` | `DomainStatus` | `zedmanager` |

## Image Download Architecture and Protocols

"Downloading images" means the following:

1. Reserve space on the device's disk for artifacts
1. Retrieve artifacts from remote locations
1. Place the artifacts in the reserved space

Artifacts may be one or more of:

* Disk images
* Kernel
* initrd
* OCI (container) images
* Configuration information (metadata / manifests)

`zedmanager`, when requesting download of artifacts, is mostly ignorant of the artifact types,
or even if they are images for VMs or OCI containers. It simply passes the download information
to `downloader`, which, in turn, retrieves the bits and places them on disk.

`downloader` itself supports multiple protocols, aware of the source only in one loop, which
is responsible for parsing the image source and retrieving it using the appropriate protocol.
This loop is in [handleSyncOp()](../pkg/pillar/cmd/downloader/downloader.go#L1624)),
specifically the `switch TransportMethod` statement [here](../pkg/pillar/cmd/downloader/downloader.go#L1712).

Once the transport-specific logic is complete, the artifact is in the target location,
and common processes continue.

### Adding New Download Protocols

To add a new download protocol:

1. Create a `func` in [downloader](../pkg/pillar/cmd/downloader/) that knows how
to download, given the credentials and information necessary. This method should
accept, as a parameter, the local path where it should deposit the artifact, and
return an `error`.
1. Add an entry for the type to the various `DsType*` constants and variables
in the api protobufs under [storage.proto](https://github.com/lf-edge/eve-api/tree/main/proto/proto/config/storage.proto) and
regenerate all of the API language imports.
1. Add a `case` statement for your new download protocol to the [switch dsCtx.TransportMethod](../pkg/pillar/cmd/downloader/downloader.go#L1712).
