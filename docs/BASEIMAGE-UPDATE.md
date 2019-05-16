# Baseimage update

The API and EVE code supports updating the base image (the EVE rootfs including the hypervisor, dom0 kernel, and the EVE agents/microservices) using dual partitions and priority boot support in grub. This is robust against getting a power failure during the write to the flash, and hung boot, as well as bugs in the EVE code or the dom0 kernel resulting in crashing or hung agents or e.g., a busted kernel Ethernet device driver which can no longer communicate.

The EVE code current makes sure the device remains functional (can connect to the controller and no agent crashes or hangs) for 10 minutes running the new version, and then the system commits to that new version. Plan is to add a handshake with the controller so that the user can run their own application tests before committing to the new version.

The timer behavior can be controlled by some variables specified in [global-config-variables.md](../pkg/pillar/docs/global-config-variables.md)

## API

The API for the baseimage update consists of specifying the image(s) to download and one to run using [BaseOSConfig](../api/proto/config/baseosconfig.proto). If activate is set to false the image is downloaded and verified, and if/when activate it set to true the image is also applied by writing to the unused partition, rebooting, and testing the new image for 10 minutes.

The status of the current image (its version) and any in-transit download and update is reported to the controller using [ZInfoDevSW](../api/proto/info/info.proto). Some of the information in ZInfoDevSW is for debugging purposes such as the name of the partition label. The normal user-visible information showing the progression of the download and update is captured in theses fields:
* BaseOsStatus userStatus = 11;
* string subStatusStr = 12;     // English formatted string
* BaseOsSubStatus subStatus = 13; // For Localization
* uint32 subStatusProgress = 14; // Context-dependent; percentage or time
* ErrorInfo swErr = 9; // If userStatus is FAILED

## Implementation

The baseimage update lifecycle is driven by [baseosmgr](../pkg/pillar/cmd/baseosmgr), with [zedagent](../pkg/pillar/cmd/zedagent) driving the 10 minute timer for testing.