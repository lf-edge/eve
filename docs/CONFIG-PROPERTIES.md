# EVE Runtime Configuration Properties

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| app.allow.vnc | boolean | false | allow access to the app using the VNC tcp port |
| timer.config.interval | integer in seconds | 60 | how frequently device gets config |
| timer.cert.interval | integer in seconds | 1 day (24*3600) | how frequently device checks for new controller certificates |
| timer.metric.interval  | integer in seconds | 60 | how frequently device reports metrics |
| timer.metric.diskscan.interval  | integer in seconds | 300 | how frequently device should scan the disk for metrics |
| timer.location.cloud.interval | integer in seconds | 1 hour | how frequently device reports geographic location information to controller |
| timer.location.app.interval | integer in seconds | 20 | how frequently device reports geographic location information to applications (to local profile server and to other apps via meta-data server) |
| timer.send.timeout | timer in seconds | 120 | time for each http/send |
| timer.dial.timeout | timer in seconds | 10 | maximum time allowed to establish connection |
| timer.reboot.no.network | integer in seconds | 7 days | reboot after no cloud connectivity |
| timer.update.fallback.no.network | integer in seconds | 300 | fallback after no cloud connectivity |
| timer.test.baseimage.update | integer in seconds | 600 | commit to update |
| timer.gc.vdisk | integer in seconds | 1 hour | garbage collect unused instance virtual disk |
| timer.defer.content.delete | integer in seconds | zero | if set, keep content trees around for reuse after they have been deleted |
| timer.download.retry | integer in seconds | 600 | retry a failed download |
| timer.download.stalled | integer in seconds | 600 | cancel a stalled download |
| timer.boot.retry | integer in seconds | 600 | retry a failed domain boot |
| timer.port.georedo | integer in seconds | 1 hour | redo IP geolocation |
| timer.port.georetry | integer in seconds | 600 | retry geolocation after failure |
| timer.port.testduration | integer in seconds | 30 | wait for DHCP to give address |
| timer.port.testinterval | timer in seconds | 300 | retest the current port config |
| timer.port.timeout | timer in seconds | 15 | time for each http/send |
| timer.port.testbetterinterval | timer in seconds | 600 | test a higher prio port config |
| network.fallback.any.eth | "enabled" or "disabled" | disabled (enabled forcefully during onboarding if no network config) | if no connectivity try any Ethernet, WiFi, or LTE with DHCP client |
| network.download.max.cost | 0-255 | 0 | [max port cost for download](DEVICE-CONNECTIVITY.md) to avoid e.g., LTE ports |
| debug.enable.usb | boolean | false | allow USB e.g. keyboards on device |
| debug.enable.vga | boolean | false | allow VGA console on device |
| debug.enable.ssh | authorized ssh key | empty string(ssh disabled) | allow ssh to EVE |
| debug.enable.console | boolean | false | allow console access to EVE (reboot required to disable) |
| debug.default.loglevel | string | info | min level saved in files on device |
| debug.default.remote.loglevel | string | warning | min level sent to controller |
| storage.dom0.disk.minusage.percent | integer percent | 20 | min. percent of persist partition reserved for dom0 |
| storage.apps.ignore.disk.check | boolean | false | Ignore disk usage check for Apps. Allows apps to create images bigger than available disk|
| timer.appcontainer.stats.interval | integer in seconds | 300 | collect application container stats |
| timer.vault.ready.cutoff | integer in seconds | 300 | reboot after inaccessible vault |
| maintenance.mode | "enabled" or "disabled" | "none" | don't run applications etc |
| force.fallback.counter | integer | 0 | forces fallback to other image if counter is changed |
| newlog.allow.fastupload | boolean | false | allow faster upload gzip logfiles to controller |
| memory.apps.ignore.check | boolean | false | Ignore memory usage check for Apps|
| memory.vmm.limit.MiB | integer | 0 | Manually override how much overhead is allocated for each running VMM |
| newlog.gzipfiles.ondisk.maxmegabytes | integer in Mbytes | 2048 | the quota for keepig newlog gzip files on device |
| process.cloud-init.multipart | boolean | false | help VMs which do not handle mime multi-part themselves |
| edgeview.authen.jwt | edgeview session jwt token | empty string(edgeview disabled) | format as standard JWT for websocket session for temporary testing, this configitem will be removed once controllers are setup to send EdgeViewConfig in configuration |

In addition, there can be per-agent settings.
The Per-agent settings begin with "agent.*agentname*.*setting*"
The following per-agent settings override the corresponding default ones:

| Name | Type | Description |
| ---- | ---- | ----------- |
| agent.*agentname*.loglevel | string | if set overrides debug.default.loglevel | (Legacy setting debug.*agentname*.loglevel still supported)
| agent.*agentname*.remote.loglevel | string | if set overrides debug.default.remote.loglevel | (Legacy setting debug.*agentname*.remote.loglevel)
