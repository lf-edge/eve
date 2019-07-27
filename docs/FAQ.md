# EVE Frequently Asked Questions

## 1. How to ssh into a running instance of EVE

If you are running EVE in production there is *no* way to do that. For developer
or debug builds of EVE you can set a debug.enable.ssh property to your ssh public
key. E.g:
```bash
zcli device update myqemu --config="debug.enable.ssh:`cat .ssh/id_rsa.pub`"
```

## 2. Legacy method for out-of-band configuration delivery

It is possible to provide an initial DevicePortConfig and/or GlobalConfig during
the build. Read up on legacy EVE [configuration management](CONFIG.md) for more
details on how these are structured.

The DevicePortConfig can be statically put into EVE's configuration partition under */config/DevicePortConfig/global.json*
to specify proxies and static IPs for the ports. This could be required
to have your Edge Node connect to the controller. DevicePortConfig file can also be
put onto a USB stick that you will plug into your Edge Node in which case it will
be copied from the USB stick during boot and used.  See [mkusb.sh](../pkg/pillar/scripts/mkusb.sh)
for details. The format of the DevicePortConfig/global.json is specified with
examples in [legacy EVE configuration management](CONFIG.md)

The GlobalConfig can be used to specify the initial timers and ssh/usb behavior
which will be in place until the device connects to the controller and gets its
configuration from there. All of that is specified using [Runtime Configuration
Properties](CONFIG-PROPERTIES.md) in a json file included in */config/GlobalConfig/global.json*.
The format of that file is the natural json encoding of GlobalConfig as specified
in [types/global.go](../pkg/pillar/types/global.go). The variables are documented
in [configuration properties table](CONFIG-PROPERTIES.md)

To add either during the build, in EVE's conf directory create a
subdirectory called DevicePortConfig or GlobalConfig, respectively.
Then add the valid json file named as global.json in that directory.
Finally:

```bash
make config.img; make installer.raw
```

or just copy them into the partition called EVE on the writable installation medium.
