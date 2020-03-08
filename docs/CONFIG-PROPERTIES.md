# EVE Runtime Configuration Properties

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| app.allow.vnc | boolean | false | allow access to the app using the VNC tcp port |
| timer.config.interval | integer in seconds | 60 | how frequently device gets config |
| timer.metric.interval  | integer in seconds | 60 | how frequently device reports metrics |
| timer.send.timeout | timer in seconds | 120 | time for each http/send |
| timer.reboot.no.network | integer in seconds | 7 days | reboot after no cloud connectivity |
| timer.update.fallback.no.network | integer in seconds | 300 | fallback after no cloud connectivity |
| timer.test.baseimage.update | integer in seconds | 600 | commit to update |
| timer.use.config.checkpoint | integer in seconds | 600 | use checkpointed config if no cloud connectivity |
| timer.gc.download | integer in seconds |  600 | garbage collect unused downloaded objects |
| timer.gc.vdisk | integer in seconds | 1 hour | garbage collect unused instance virtual disk |
| timer.download.retry | integer in seconds | 600 | retry a failed download |
| timer.boot.retry | integer in seconds | 600 | retry a failed domain boot |
| timer.port.georedo | integer in seconds | 1 hour | redo IP geolocation |
| timer.port.georetry | integer in seconds | 600 | retry geolocation after failure |
| timer.port.testduration | integer in seconds | 30 | wait for DHCP to give address |
| timer.port.testinterval | timer in seconds | 300 | retest the current port config |
| timer.port.timeout | timer in seconds | 15 | time for each http/send |
| timer.port.testbetterinterval | timer in seconds | 0 (disabled) | test a higher prio port config |
| network.fallback.any.eth | "enabled" or "disabled" | enabled | if no connectivity try any Ethernet, WiFi, or LTE |
| network.allow.wwan.app.download | "enabled" or "disabled" | disabled | allow app image download over non-free ports like LTE |
| network.allow.wwan.baseos.download | "enabled" or "disabled" | enabled | allow baseos image download over non-free ports like LTE |
| debug.enable.usb | boolean | false | allow USB e.g. keyboards on device |
| debug.enable.ssh | boolean, or authorized ssh key | false | allow ssh to EVE |
| debug.default.loglevel | string | info | min level saved in files on device |
| debug.default.remote.loglevel | string | warning | min level sent to controller |
| storage.dom0.disk.minusage.percent | integer percent | 20 | min. percent of persist partition reserved for dom0 |
| storage.apps.ignore.disk.check | boolean | false | Ignore disk usage check for Apps. Allows apps to create images bigger than available disk|

In addition, for each agentname, there are specific overrides for the default ones with the names:

| Name | Type | Description |
| ---- | ---- | ----------- |
| debug.*agentname*.loglevel | string | if set overrides debug.default.loglevel |
| debug.*agentname*.remote.loglevel | string | if set overrides debug.default.remote.loglevel |
