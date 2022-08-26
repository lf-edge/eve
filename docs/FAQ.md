# EVE Frequently Asked Questions

## 1. How to ssh into a running instance of EVE?

If you are running EVE in production there is *no* way to do that. For developer
or debug builds of EVE you can set a debug.enable.ssh property to your ssh public
key. E.g:
```bash
zcli edge-node update myqemu --config="debug.enable.ssh:`cat .ssh/id_rsa.pub`"
```

## 2. How to apply (initial) device configuration needed to establish controller connectivity?

The preferred method is to build a single-use EVE installer with the initial, aka bootstrap, configuration baked in. To learn more about this, please refer to [CONFIG.md](./CONFIG.md), section "Bootstrap configuration".

A legacy method, which may be the only option available with older EVE versions, is to prepare "override" json file with `DevicePortConfig` and put it into the installer or deliver it to the device using a USB stick. To learn more about this, please refer to [CONFIG.md](./CONFIG.md), section "Legacy mechanism for off-line configuration management".
