# Customizing the image for static IP or enterprise proxy; ssh access

It is possible to provide an initial DevicePortConfig and/or GlobalConfig
during the build.

The former can be used to specify proxies and static IP configuration for
the ports, if that is necessary to have the device connect to the controller.
But a DevicePortConfig can also be added to a USB stick in which case it
will be copied from the USB stick on boot. See [mkusb.sh](../scripts/mkusb.sh)
The format of the DevicePortConfig/global.json is specified with examples in
[static-and-proxy-config.md](static-and-proxy-config.md)

The latter can be used to specify the initial timers and ssh/usb behavior
which will be in place until the device connects to the controller and gets its
configuration from there. The variables are documented in [global-config-variables.md](global-config-variables.md)


To add either during the build, in EVE's conf directory create a
subdirectory called DevicePortConfig or GlobalConfig, respectively.
Then add the valid json file named as global.json in that directory.
Finally:
make config.img; make installer.raw
