# Baseimage update

The API and EVE code supports updating the base image (the EVE rootfs including the hypervisor, dom0 kernel, and the EVE agents/microservices) using dual partitions and priority boot support in grub. This is robust against getting a power failure during the write to the flash, and hung boot, as well as bugs in the EVE code or the dom0 kernel resulting in crashing or hung agents or e.g., a busted kernel Ethernet device driver which can no longer communicate.

The EVE code current makes sure the device remains functional (can connect to the controller and no agent crashes or hangs) for 10 minutes running the new version, and then the system commits to that new version. Plan is to add a handshake with the controller so that the user can run their own application tests before committing to the new version.

The timer behavior can be controlled by some variables specified in [configuration properties](CONFIG-PROPERTIES.md)

## API

The API for the baseimage update consists of specifying the image(s) to download and one to run using [BaseOSConfig](../api/proto/config/baseosconfig.proto). If activate is set to false the image is downloaded and verified, and if/when activate it set to true the image is also applied by writing to the unused partition, rebooting, and testing the new image for 10 minutes.

The status of the current image (its version) and any in-transit download and update is reported to the controller using [ZInfoDevSW](../api/proto/info/info.proto). Some of the information in ZInfoDevSW is for debugging purposes such as the name of the partition label. The normal user-visible information showing the progression of the download and update is captured in these fields:
* userStatus, which is an enum with high-level values such as "Updating"
* subStatus, which is an enum with more details, such as "update-testing"
* subStatusProgress, which is an integer containing time left (in the testing subStatus) or percentage done (in the downloading subStatus)
* subStatusStr, which is a string in English formatted using subStatus plus subStatusProgress. For other locales the controller/UI would construct the output using subStatus plus subStatusProgress.
* swErr is set when userStatus is "Failed" and is of type ErrorInfo with any error which occurred during the update.

If testing of the new version fails, EVE will automatically fall back to the old version and report the failure. In addition, if the controller continues to tell the device to run the failed version, the device will refuse to try it since it remembers that it tried and failed. That is reported as a "Failed" userStatus for the new/failed version.

## Implementation

The baseimage update lifecycle is driven by [baseosmgr](../pkg/pillar/cmd/baseosmgr), with [zedagent](../pkg/pillar/cmd/zedagent) driving the 10 minute timer for testing.
