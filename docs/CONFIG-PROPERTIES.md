# EVE Runtime Configuration Properties

| Name | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| app.allow.vnc | boolean | false (only local access) | allow access to EVE's VNC ports from external IPs |
| app.fml.resolution | string | notset | Set system-wide value of forced resolution for applications running in FML mode, it can be one of [predefined](/pkg/pillar/types/global.go) FmlResolution* values. |
| timer.config.interval | integer in seconds | 60 | how frequently device gets config |
| timer.cert.interval | integer in seconds | 1 day (24*3600) | how frequently device checks for new controller certificates |
| timer.metric.interval  | integer in seconds | 60 | how frequently device reports metrics |
| timer.metric.diskscan.interval  | integer in seconds | 300 | how frequently device should scan the disk for metrics |
| timer.location.cloud.interval | integer in seconds | 1 hour | how frequently device reports geographic location information to controller |
| timer.location.app.interval | integer in seconds | 20 | how frequently device reports geographic location information to applications (to local profile server and to other apps via meta-data server) |
| timer.ntpsources.interval | integer in seconds | 10 minutes | how frequently device forcibly reports information about NTP sources to which EVE has established a connection for the NTP synchronization. Requests are also sent to the controller if the list of NTP peers or NTP peer fields, such as mode, state, have changed. |
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
| debug.enable.vnc.shim.vm | boolean | false | allow VNC access to the container application shim VM (reboot required to disable) |
| debug.default.loglevel | string | info | min level saved in files on device. Used logrus log levels as described here ["https://pkg.go.dev/github.com/sirupsen/logrus"]: panic, fatal, error, warning, info, debug and trace.
| debug.syslog.loglevel | string | info | min level of the syslog messages saved in files on device. System default loglevel string representation should be used as described here ["https://man7.org/linux/man-pages/man3/syslog.3.html"]: emerg, alert, crit, err, warning, notice, info, debug. |
| debug.kernel.loglevel | string | info | min level of the kernel messages saved in files on device. System default loglevel string representation should be used as described here ["https://man7.org/linux/man-pages/man3/syslog.3.html"]: emerg, alert, crit, err, warning, notice, info, debug. |
| debug.default.remote.loglevel | string | warning | min level sent to controller. Should be used log levels as described in "debug.syslog.loglevel" settings. |
| storage.dom0.disk.minusage.percent | integer percent | 20 | min. percent of persist partition reserved for dom0 |
| storage.zfs.reserved.percent | integer percent | 20 | min. percent of persist partition reserved for zfs performance |
| storage.apps.ignore.disk.check | boolean | false | Ignore disk usage check for Apps. Allows apps to create images bigger than available disk|
| timer.appcontainer.stats.interval | integer in seconds | 300 | collect application container stats |
| timer.vault.ready.cutoff | integer in seconds | 300 | reboot after inaccessible vault |
| maintenance.mode | "enabled" or "disabled" | "none" | don't run applications etc |
| force.fallback.counter | integer | 0 | forces fallback to other image if counter is changed |
| newlog.allow.fastupload | boolean | false | allow faster upload gzip logfiles to controller |
| memory.apps.ignore.check | boolean | false | Ignore memory usage check for Apps|
| memory.vmm.limit.MiB | integer | 0 | Manually override how much overhead is allocated for each running VMM |
| gogc.memory.limit.bytes | integer | 0 | Golang runtime soft memory limit, see details in API doc ["https://pkg.go.dev/runtime/debug#SetMemoryLimit"] |
| gogc.percent | integer | 100 | Golang runtime garbage collector target percentage, see details in API doc ["https://pkg.go.dev/runtime/debug#SetGCPercent"] |
| gogc.forced.interval.seconds | integer in seconds | 10 | minimum interval of forced execution of the GC. Forced GC is disabled when interval is set to 0 |
| gogc.forced.growth.memory.MiB | integer in Mbytes | 50 | minimum allocated memory in MiB required for the next GC execution |
| gogc.forced.growth.memory.percent | integer | 20 | minimum allocated memory percentage from last reclaim required for the next GC execution |
| newlog.gzipfiles.ondisk.maxmegabytes | integer in Mbytes | 2048 | the quota for keepig newlog gzip files on device |
| process.cloud-init.multipart | boolean | false | help VMs which do not handle mime multi-part themselves |
| netdump.enable | boolean | true | enable publishing of network diagnostics (as tgz archives to /persist/netdump) |
| netdump.topic.preonboard.interval | integer in seconds | 1 hour | how frequently (in seconds) can be netdumps of the same topic published while device is not yet onboarded |
| netdump.topic.postonboard.interval | integer in seconds | 1 day | how frequently (in seconds) can be netdumps of the same topic published after device has been onboarded |
| netdump.topic.maxcount | integer | 10 | maximum number of netdumps that can be published for each topic. The oldest netdump is unpublished should a new netdump exceed the limit.
| netdump.downloader.with.pcap | boolean | false | include packet captures inside netdumps for download requests. However, even if enabled, TCP segments carrying non-empty payload (i.e. content which is being downloaded) are excluded and the overall PCAP size is limited to 64MB. |
| netdump.downloader.http.with.fieldvalue | boolean | false | include HTTP header field values in captured network traces for download requests (beware: may contain secrets, such as datastore credentials). |
| network.switch.enable.arpsnoop | boolean | true | enable ARP Snooping on switch Network Instances |
| wwan.query.visible.providers | bool | false | enable to periodically (once per hour) query the set of visible cellular service providers and publish them under WirelessStatus (for every modem) |
| network.local.legacy.mac.address | bool | false | enables legacy MAC address generation for local network instances for those EVE nodes where changing MAC addresses in applications will lead to incorrect network configuration |

In addition, there can be per-agent settings.
The Per-agent settings begin with "agent.*agentname*.*setting*"
The following per-agent settings override the corresponding default ones:

| Name | Type | Description |
| ---- | ---- | ----------- |
| agent.*agentname*.loglevel | string | if set overrides debug.default.loglevel | (Legacy setting debug.*agentname*.loglevel still supported)
| agent.*agentname*.remote.loglevel | string | if set overrides debug.default.remote.loglevel | (Legacy setting debug.*agentname*.remote.loglevel)
