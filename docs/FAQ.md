# EVE Frequently Asked Questions

## 1. How to ssh into a running instance of EVE

If you are running EVE in production there is *no* way to do that. For developer
or debug builds of EVE you can set a debug.enable.ssh property to your ssh public
key. E.g:
```bash
zcli edge-node update myqemu --config="debug.enable.ssh:`cat .ssh/id_rsa.pub`"
```

## 2. Legacy method for out-of-band configuration delivery

It is possible to provide an initial DevicePortConfig during the build. Read up on [legacy EVE configuration management](CONFIG.md) for more details on how it is structured.

The DevicePortConfig can be statically put into EVE's configuration partition under */config/DevicePortConfig/global.json*
to specify proxies and static IPs for the ports. This could be required
to have your Edge Node connect to the controller. DevicePortConfig file can also be
put onto a USB stick that you will plug into your Edge Node in which case it will
be copied from the USB stick during boot and used.  See [tools/makeusbconf.sh](../tools/makeusbconf.sh)
for details. The format of the DevicePortConfig/global.json is specified with
examples in [legacy EVE configuration management](CONFIG.md)

To add it during the build, in EVE's conf directory create a subdirectory called DevicePortConfig. Then add the valid json file named as global.json in that directory.
Finally:

```bash
make config
make installer
```

or just copy them into the partition called EVE on the writable installation medium.
