# Device Connectivity

EVE needs to always be able to connect to the controller, yet the configuration of the ports might be both complex and changing over time.

In addition some ports might be designated to application usage, or the underlying I/O bus controllers (e.g., PCI controllers) be designated for assignment to applications. That part of the configuration can also change.

Such configuration changes can not turn the device into a brick; it needs to have a way to fall back to a working port configuration which works well enough to connect to the controller (and as part of that be able to receive more configuration changes.)

This is accomplished by logic to test connectivity to the controller (implemented in the Network Interface Manager [nim](../pkg/pillar/cmd/nim) with help from the [devicenetwork](../pkg/pillar/devicenetwork) package, and maintaining a list of current working and fallback configuration in ```/persist/status/nim/DevicePortConfigList/global.json```

## Sources of configuration

There are several sources from which nim gets the potential port configurations. Those all use the ```DevicePortConfig``` type. There are examples of such configurations in [legacy EVE configuration](CONFIG.md)

### Hardware-model based baseline

The device currently has one configuration derived from the hardware model, in the form a file in ```/var/tmp/zededa/DeviceNetworkConfig```.

Note that the output ```/opt/bin/zededa/hardwaremodel``` provides the model string which is used to find the name of that file.

Those files just describe the set of ports (so that we can specify that wwan0 is a choice, or to use eth3 instead of eh0) and is likely to be replaced with an approach instantiated from the controller instead of having json files in the EVE image.

Those input files are used to construct a file with the same information but using the ```DevicePortConfig``` type in ```/var/run/nim/DevicePortConfig```

### Override the configuration using a USB stick

If the deployment site requires use of http enterprise proxies and/or static IP configuration, then a file containing a DevicePortConfig can be placed on a USB stick. Note that this requires that the USB controller is enabled using debug.enable.usb as specified in [configuration properties](CONFIG-PROPERTIES.md)

There are examples of such configurations in [legacy EVE configuration](CONFIG.md)

### From the controller

The systemAdapter in the API specifies the intended port configuration.
This is fed into the logic in nim by [zedagent](../pkg/pillar/cmd/zedagent) publishing a ```DevicePortConfig``` item.

The API for this is [SystemAdapter](../api/proto/config/devmodel.proto).

Note that the device reports the status of all of the device connectivity using [SystemAdapterInfo](../api/proto/info/info.proto).

### Last resort

If the network.fallback.any.eth config is set to true as specified in [configuration properties](CONFIG-PROPERTIES.md), then there an additional lowest priority item in the list of DevicePortConfigs, based on finding all of the Ethernet and Ethernet-like interfaces (an example of the latter is WiFi) which are not used exclusively by applications.

## Prioritizing the list

The nim retains the currently working configuration, plus the following in priority order in ```/persist/status/nim/DevicePortConfigList```:
* The most recently received configuration from the controller
* The known working configuration from the controller
* An override file from a USB stick (if any)
* The hardware-model derived config
* The last resort if so enabled
