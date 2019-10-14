# EVE configuration

While most of EVE's configuration is done via receiving a configuration object from a controller, there's always a question of a bootstrap. At the very minimum EVE has to know host name, port and certificate of the controller from which it can receive its first configuration object. On top of that there are some aspects of the early boot flow that may need to be tweaked in order for EVE to successfully bootstrap its microservices.

In general, EVE is trying to make sure that its controller always has the last word in tweaking any kind of configuration knobs. The following configuration files are the only exception to that rule:

* `grub.cfg` - local tweaks to an [otherwise readonly grub.cfg](README.md#runtime-lifecycle)
* `DevicePortConfig/override.json` - initial configuration for all of EVE's network interfaces (see below for details)
* `server` - contains a FQDN of a controller and its port (e.g. controller.acme.com:123)
* `root-certificate.pem` - contains an x509 root certificate for the controller
* `onboard.cert.pem` - onboarding certificate for the [initial registration](REGISTRATION.md) with the controller
* `wpa_supplicant.conf` - a legacy way of configuring EVE's WiFi
* `authorized_keys` - initial authorized SSH keys for accessing EVE's debug console

The initial content of these configuration files is stored in the EVE's source tree under [config](../config) folder. From there, these configuration files are baked into the EVE installer images. For the read-write bootable disk installer image these files can further be tweaked by mounting the CONFIG partition and editing those files directly on the installer image. This gives you an ability to take the default installer image and tweak it for your needs without re-building EVE from scratch (obviously this is not an option for a read-only ISO installer image). A typical workflow is to take an installer image from the official EVE build, flash it onto a USB flash drive, insert that USB flash drive into your desktop and edit file on the partition called EVE.

Once an installer has been run on an edge node, the content of the CONFIG partition found on the installer media is simply copied into the CONFIG partition on the edge node's local storage. From that point on, even though these files reside in the read-write CONFIG partition on the edge node, they can NOT be changed by the controller. The only option for tweaking these files is to have debug console access either via local terminal, remote ssh terminal or batch removable media configuration.

## Controlling EVE behavior via batch removable media configuration

EVE doesn't care how it gets its configuration objects as long as they come from the source that can be trusted. Almost always, this trusted source happens to be EVE's controller and the trust is established via TLS connection that is validated by the `root-certificate.pem`. If, for any reason, the network connection to the controller can not be established EVE can accept its configuration object on a specially formatted removable media (e.g. USB flash or hard drive). This is part of the batch removable media configuration process and it is still being actively developed.

We plan to completely transition to this way of configuring all aspects of EVE in off-line situations, but before that happens you still need to be aware of the legacy configuration management described below.

## Controlling EVE behavior at boot via legacy configuration management

When the device boots it determines the set of network interfaces.
By default this is determined by extracting the manufacturer and model
strings from dmidecode; /opt/zededa/bin/hardwaremodel does this determination.

That model string is used to look up a json file in /var/tmp/zededa/DeviceNetworkConfig/
If no such json file is found the device uses /var/tmp/zededa/DeviceNetworkConfig/default.json

Those files merely specify the set of management ports, plus which of them
do not have per usage charging (to separate out e.g., LTE modems).

The default.json is:

```json
{
    "Uplink":["eth0","wlan0","wwan0"],
    "FreeUplinks":["eth0","wlan0"]
}
```

Note that the above file uses the old "uplink" terminology; new terminology for
this concept is "management port".

This per-model comfiguration can be overridden by an optional file in
/config which is added when the image is built/installed.
That file is /config/DevicePortConfig/override.json
[Note that this file does not override cloud configuration. TBD: should we rename
it to local.json instead?]
And futher overridden by a USB memory stick plugged in when the device is powered
on. The [tools/makeusbconf.sh](../tools/makeusbconf.sh) can be used to create a
USB stick with a json file specifying the device connectivity based on the
examples below.
Finally, when the device is created or updated in the controller, the device
port configuration can be specified which will be sent to the device using the
systemAdapter part of the API. The most recent information DevicePortConfig
becomes the highest priority, but the device tests that it works before using it
(and falls back to a lower-priority working config.)

That build/USB file can specify multiple management interfaces, as well as
non-mananagement interface, and can specify static IP and DNS configuration
(for environments where DHCP is not used). In addition it can specify proxies
using several different mechanism.

### Example DevicePortConfig

An example file to specify using WPAD to retrieve proxy configuration on eth0 is:

```json
{
    "Version": 1,
    "Ports": [
        {
            "AddrSubnet": "",
            "Dhcp": 4,
            "DnsServers": null,
            "DomainName": "",
            "Exceptions": "",
            "Free": true,
            "Gateway": "",
            "IfName": "eth0",
            "Name": "Management",
            "IsMgmt": true,
            "NetworkProxyEnable": true,
            "NetworkProxyURL": "",
            "NtpServer": "",
            "Pacfile": "",
            "Proxies": null
        }
    ]
}
```

To specify fetching from a fixed WPAD URL one would set:

```json
            "NetworkProxyEnable": true,
            "NetworkProxyURL": "http://wpad.sc.zededa.net/wpad.dat",
```

To specify a particular set of http and https proxies with a set of
exceptions one would set:

```json
            "Proxies": [ { "Server": "proxy.example.com", "Port":1080, "Type":1 },
                       { "Server": "proxy.example.com", "Port":1080, "Type":0 } ],
            "Exceptions": "example.com",
```

To specify a PAC file inline one would base64 encode the PAC file and set the
result as the Pacfile e.g.,

```json
        Pacfile":"ZnVuY3Rpb24gRmluZFByb3h5Rm9yVVJMKHVybCxob3N0KSB7CmlmIChob3N0ID09ICIxMjcuMC4wLjEiKSB7cmV0dXJuICJESVJFQ1QiO30KaWYgKGhvc3QgPT0gImxvY2FsaG9zdCIpIHtyZXR1cm4gIkRJUkVDVCI7fQppZiAoaXNQbGFpbkhvc3ROYW1lKGhvc3QpKSB7cmV0dXJuICJESVJFQ1QiO30KZWxzZSB7IHJldHVybiAiUFJPWFkgcHJveHkucHJpdi5zYy56ZWRlZGEubmV0OjEwODAiO30KfQo=",
```

An example file with eth0 being static and eth1 using dhcp is:

```json
{
    "Version": 1,
    "Ports": [
        {
            "AddrSubnet": "38.108.181.238/24",
            "Dhcp": 1,
            "DnsServers": [
                "8.8.8.8"
            ],
            "DomainName": "example.com",
            "Free": true,
            "Gateway": "38.108.181.254",
            "IfName": "eth0",
            "Name": "Management1",
            "IsMgmt": true,
            "NtpServer": "38.108.181.254",
            "NetworkProxyEnable": false,
            "NetworkProxyURL": "",
            "NtpServer": "",
            "Pacfile": "",
            "Proxies": null
        },
        {
            "Dhcp": 4,
            "Free": true,
            "IfName": "eth1",
            "Name": "Management2",
            "IsMgmt": true
        }
    ]
}
```

To set up eth1 with the name Field in order to use it for a switch network,
use DHCP 0. For example,

```json
{
    "Version": 1,
    "Ports": [
        {
            "Dhcp": 4,
            "Free": true,
            "IfName": "eth0",
            "IsMgmt": true,
            "Name": "Management"
        },
        {
            "Dhcp": 0,
            "Free": true,
            "IfName": "eth1",
            "IsMgmt": false,
            "Name": "Field"
        }
    ]
}
```

If you want eth1 to be configured by zedrouter and used by applications but not
used for management traffic to the controller, make sure you have Version 1 and
IsMgmt false.

NOTE that if a static IP configuration is used with WPAD DNS discovery then the
DomainName needs to be set; the DomainName is used to determine where to look for
the wpad.dat file. Alternatively, an explicit NetworkProxyURL can be set.
The logic for how the device looks for the URL based on the DomainName is specified
in ```https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol```.
The device does not specify DHCP-based WPAD since most browsers do not.

In addition the above configurations be specified from the EV-controller by
specifying one or more networks with the proxy and/or static as part of the
zcli device create.

### Adding configuration to the install image

It is possible to provide an initial DevicePortConfig and/or GlobalConfig
during the build of the installation medium.

The former can be used to specify proxies and static IP configuration for
the ports, if that is necessary to have the device connect to the controller.
But a DevicePortConfig can also be added to a USB stick in which case it
will be copied from the USB stick on boot. See [tools/makeusbconf.sh](../tools/makeusbconf.sh)

The latter can be used to specify the initial timers and ssh/usb behavior
which will be in place until the device connects to the controller and gets its
configuration from there. The variables are documented in
[runtime configuration properties](CONFIG-PROPERTIES.md)

To add either during the build, in EVE's conf directory create a
subdirectory called DevicePortConfig or GlobalConfig, respectively.
Then add the valid json file named as global.json in that directory.
Finally:
make config.img; make installer.raw

### Creating USB sticks

The [tools/makeusbconf.sh](../tools/makeusbconf.sh) can run on any system that supports Docker to create a USB stick.
It takes a usb.json as an argument, plus a few additrional arguments:

* -d Create a dump directory on the stick, which Eve will use to deposit any
  diagnostics.
* -i Create an identity directory on the stick, which Eve will use to deposit
  its identity like the device certificate.

### Troubleshooting

The blinking pattern can be extracted from the shell using

```bash
cat /var/tmp/ledmanager/config/ledconfig.json
```

If the device does not have any usable IP addresses it will be 1,
if IP address but no cloud connectivity it will be 2,
if the cloud responds (even if it is an http error e.g, if the device is not yet
onboarded), it will be 3, and if a GET of /config works it will be 4.

One can test the connectivity to the controller using

```bash
    /opt/zededa/bin/diag
```

The logs for the onboarding attempts are in ```/persist/`zboot curpart`/log/client.log```

If there are no IP addresses, the logs for network interface manager can help:

```bash
    /persist/`zboot curpart`/log/nim.log
```

In addition zedagent.log, downloader.log, and /persist/log/logmanager.log will contain
errors if those agents can not reach the controller.

The ```/persist/status/nim/DevicePortConfigList/global.json``` contains the set
of DevicePortConfig which have been tried, any errors, last time they succeeded
and failed, etc. This is quite useful in a proxy or static IP setup, since there
can be IP routing issues, DNS issues, WPAD, or proxy issues.

If there is no console (display and keyboard) to run diag or look at these files,
the ```mkush.sh -d``` above can be used to get the diagnostics deposited on the
USB stick for inspection.

