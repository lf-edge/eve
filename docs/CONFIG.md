# EVE configuration

While most of EVE's configuration is done via receiving a configuration object from a controller, there's always a question of a bootstrap. At the very minimum EVE has to know host name, port and certificate of the controller from which it can receive its first configuration object. On top of that there are some aspects of the early boot flow that may need to be tweaked in order for EVE to successfully bootstrap its microservices.

In general, EVE is trying to make sure that its controller always has the last word in tweaking any kind of configuration knobs. The following configuration files are the only exception to that rule:

* `grub.cfg` - local tweaks to an [otherwise readonly grub.cfg](README.md#runtime-lifecycle)
* `DevicePortConfig/override.json` - initial configuration for all of EVE's network interfaces (see below for details)
* `server` - contains a FQDN of a controller and its port (e.g. controller.acme.com:123)
* `root-certificate.pem` - contains an x509 root certificate to trust for the controller for TLS in V1 API and object signing in V2 API
* `v2tlsbaseroot-certificates.pem` - contains the x509 root certificate to trust for the TLS to the controller when using the V2 API
* `onboard.cert.pem` - onboarding certificate for the [initial registration](REGISTRATION.md) with the controller
* `wpa_supplicant.conf` - a legacy way of configuring EVE's WiFi
* `authorized_keys` - initial authorized SSH keys for accessing EVE's debug console

The initial content of these configuration files is stored in the EVE's source tree under [config](../config) folder. From there, these configuration files are baked into the EVE installer images. For the read-write bootable disk installer image these files can further be tweaked by mounting the CONFIG partition and editing those files directly on the installer image. This gives you an ability to take the default installer image and tweak it for your needs without re-building EVE from scratch (obviously this is not an option for a read-only ISO installer image). A typical workflow is to take an installer image from the official EVE build, flash it onto a USB flash drive, insert that USB flash drive into your desktop and edit file on the partition called EVE.

Once an installer has been run on an edge node, the content of the CONFIG partition found on the installer media is simply copied into the CONFIG partition on the edge node's local storage. From that point on, even though these files reside in the read-write CONFIG partition on the edge node, they can NOT be changed by the controller. The only option for tweaking these files is to have debug console access either via local terminal, remote ssh terminal or batch removable media configuration.

## Controlling EVE behavior via batch removable media configuration

EVE doesn't care how it gets its configuration objects as long as they come from the source that can be trusted. Almost always, this trusted source happens to be EVE's controller and the trust is established via TLS connection that is validated by the `root-certificate.pem`. If, for any reason, the network connection to the controller can not be established EVE can accept its configuration object on a specially formatted removable media (e.g. USB flash or hard drive). This is part of the batch removable media configuration process and it is still being actively developed.

We plan to completely transition to this way of configuring all aspects of EVE in off-line situations, but before that happens you still need to be aware of the legacy configuration management described below.

## Controlling EVE behavior at boot via legacy configuration management

When the device boots the first time it determines the set of potentially usable network interfaces to use to reach the controller, as specified in [DEVICE-CONNECTIVITY last resort](DEVICE-CONNECTIVITY.md).

That default configuration can be overridden by an optional file in
/config which is added when the image is built/installed.
That file is /config/DevicePortConfig/override.json
And further it can be overridden by a USB memory stick plugged in when the device is powered
on. The [tools/makeusbconf.sh](../tools/makeusbconf.sh) can be used to create a
USB stick with a json file specifying the device connectivity based on the
examples below. Use [tools/makeusbconf.bat](../tools/makeusbconf.bat) for Windows OS.
Finally, when the device is created or updated in the controller, the device
port configuration can be specified which will be sent to the device using the
systemAdapter part of the API. The most recent information DevicePortConfig
becomes the highest priority, but the device tests that it works before using it
(and falls back to a lower-priority working config.)

More specifics in how this is handled, including load spreading and failover with multiple uplink ports, are in [DEVICE-CONNECTIVITY](DEVICE-CONNECTIVITY.md).

The above build/USB file can specify multiple management interfaces, as well as
non-management interface, and can specify static IP and DNS configuration
(for environments where DHCP is not used), plus WiFi and cellular modem specifics. In addition it can specify proxies using several different mechanism.

The build/USB file should include a TimePriority field, since this is used to determine whether the information from the file or from the controller should be applied; the more recent information is what will be used by EVE.

### Example DevicePortConfig

An example file to specify using WPAD to retrieve proxy configuration on eth0 is:

```json
{
    "Version": 1,
    "TimePriority": "2021-05-20T22:13:31.07683525Z",
    "Ports": [
        {
            "AddrSubnet": "",
            "Dhcp": 4,
            "DnsServers": null,
            "DomainName": "",
            "Exceptions": "",
            "Cost": 0,
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

To specify a particular set of http and https proxies with the MiTM proxy server
using the proxy server's certificate in PEM format with base64 encoding, here is an example:

```json
            "Proxies": [ { "Server": "proxy.example.com", "Port":3129, "Type":1 },
                       { "Server": "proxy.example.com", "Port":3129, "Type":0 } ],
            "NetworkProxyEnable": false,
            "NetworkProxyURL": "",
            "ProxyCertPEM": [
                "Ci0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlEMURDQ0FyeWdBd0lCQWdJSkFQNVMrWDNqYWpFZE1BMEdDU3FHU0liM0RRRUJDd1VBTUhveEN6QUpCZ05WCkJBWVRBbFZUTVJNd0VRWURWUVFJREFwRFlXeHBabTl5Ym1saE1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnkKWVRFUE1BMEdBMVVFQ2d3R1dtVmtaV1JoTVF3d0NnWURWUVFMREFOSlQxUXhJVEFmQmdrcWhraUc5dzBCQ1FFVwpFbTVoYVcxcGJtZEFlbVZrWldSaExtTnZiVEFlRncweE9URXlNRFF5TXpRNE1UUmFGdzB5TURFeU1ETXlNelE0Ck1UUmFNSG94Q3pBSkJnTlZCQVlUQWxWVE1STXdFUVlEVlFRSURBcERZV3hwWm05eWJtbGhNUlF3RWdZRFZRUUgKREF0VFlXNTBZU0JEYkdGeVlURVBNQTBHQTFVRUNnd0dXbVZrWldSaE1Rd3dDZ1lEVlFRTERBTkpUMVF4SVRBZgpCZ2txaGtpRzl3MEJDUUVXRW01aGFXMXBibWRBZW1Wa1pXUmhMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCCkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU43blhIQU4vT2ZuWnpSNFkzSk03Rld3WTEzcUtsU1Z1eHVaU0YvdTdidTAKZmFNTGZNK2dLMHB0NUZwa1NDZ2ZuODVNNkRtc0VHY2laeHd5bG95N2tMaXlRMk9vYUVGckpjQ1U0aHlJSUt5RAozMHY3S0MxU21KRGZxemZhRVZjem9Ca21SU2N6NXZQTUZlT09sSkNYZjJ5elhZdjVpbWpQQ1A1bVgxcnp4ZzlUCjh2Uld0TjliMkNYSmx2Z2RLek44d1F6RlJ0dE0vZXFxbkdlZkZKVFROTjB5cmNCc1NXSmNhTG5Ja05COE00YlMKeUNIalFIQjZyMWtiQ0UyamZTb2MyRVhnSU1INTlZZHduY2tzQjZKMjdvOXVpTHRiMW1WV041R1pva1NnckJBSAptQ3hvTTZ2dk1RUUpZTVdYejlQVENkamhrL2w2b21zRXNxQ2xUQThCM0pNQ0F3RUFBYU5kTUZzd0N3WURWUjBQCkJBUURBZ0VHTUIwR0ExVWREZ1FXQkJRZHl6dGlXdEk4cFhYdFUyVEF5WXhTbUNGMCtEQWZCZ05WSFNNRUdEQVcKZ0JRZHl6dGlXdEk4cFhYdFUyVEF5WXhTbUNGMCtEQU1CZ05WSFJNRUJUQURBUUgvTUEwR0NTcUdTSWIzRFFFQgpDd1VBQTRJQkFRQm9sVGwyQlNWR2dZNlQra1d4dWp6R1huS3BTd3YvbHVHQ0pTbDJqWGFObkxXdWhpSHFVS25RCllGem1XQUpqN2VyMUxmNXU0S1dUNHRaSm5RWW10YjZHYUNkcVVJenBPU1orR2ZhOWF3akRHdEkwQWZEbFUxTFcKaUlKWlpSRXBiZHdzL0llY1dFN3daRFBUQTc1a1BhcXo3MXYrZWJxVk9JMm9TNVp5NHpNWGNjS3dEK1ZQekZJeApkM2xsNWZ0TGVuOVpKVUl6aktURVVDSTE1YTN4eng5L3I2M2xUMmt2c2x2NTFYTmxPK3N6UWFxeVhXdjI2SENQCjZZNWlUNWxST3daMHB2T0hQWXNKeUIxcXNNMkx2VGJnVXduQUVaYVgzZjZEZUhLdVlYUExrbXBqb3RZRWt5WW4Ka3puVXhOU1V6OTFUNzIwZVpNRVJjeENUUHphOHFLOS8KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ=="
            ],
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
    "TimePriority": "2021-05-20T22:13:31.07683525Z",
    "Ports": [
        {
            "AddrSubnet": "38.108.181.238/24",
            "Dhcp": 1,
            "DnsServers": [
                "8.8.8.8"
            ],
            "DomainName": "example.com",
            "Cost": 0,
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
            "Cost": 0,
            "IfName": "eth1",
            "Name": "Management2",
            "IsMgmt": true
        }
    ]
}
```

To specify that wwan0 should be secondary (only used if eth0 can not be used to reach the controller), and eth1 only be if neither eth0 nor wwan0 works, one would set non-zero costs. For example,

```json
{
    "Version": 1,
    "TimePriority": "2021-05-20T22:13:31.07683525Z",
    "Ports": [
        {
            "Dhcp": 4,
            "Cost": 0,
            "IfName": "eth0",
            "IsMgmt": true,
            "Name": "Management0"
        },
        {
            "Dhcp": 4,
            "Cost": 1,
            "IfName": "wwan0",
            "IsMgmt": true,
            "Name": "Management1"
        }
        {
            "Dhcp": 4,
            "Cost": 2,
            "IfName": "eth1",
            "IsMgmt": true,
            "Name": "Management2"
        }
    ]
}
```

To set up eth1 with the name Field in order to use it for a switch network,
use DHCP 0. For example,

```json
{
    "Version": 1,
    "TimePriority": "2021-05-20T22:13:31.07683525Z",
    "Ports": [
        {
            "Dhcp": 4,
            "Cost": 0,
            "IfName": "eth0",
            "IsMgmt": true,
            "Name": "Management"
        },
        {
            "Dhcp": 0,
            "Cost": 0,
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
zcli edge-node create.

### Adding configuration to the install image

It is possible to provide an initial DevicePortConfig during the build of the installation medium.

It can be used to specify proxies and static IP configuration for
the ports, if that is necessary to have the device connect to the controller.
But a DevicePortConfig can also be added to a USB stick in which case it
will be copied from the USB stick on boot. See [tools/makeusbconf.sh](../tools/makeusbconf.sh)

To add it during the build, in EVE's conf directory create a
subdirectory called DevicePortConfig.
Then add the valid json file named as global.json in that directory.
Finally:
make config.img; make installer.raw

### Creating USB sticks

The [tools/makeusbconf.sh](../tools/makeusbconf.sh) can run on any system that supports Docker to create a USB stick.
It takes a usb.json as an argument, plus a few additional arguments:

* -d Create a dump directory on the stick, which Eve will use to deposit any
  diagnostics.
* -i Create an identity directory on the stick, which Eve will use to deposit
  its identity like the device certificate.

On Linux the USB image can be created directly on the USB stick.
After using e.g., lsblk to get the name of the USB stick block device (/dev/sdx in this example) run

```bash
tools/makeusbconf.sh -d -i -f ~/usb.json -s 8000 /dev/sdx
```

On MacOS the USB image can be placed in a image file e.g,

```bash
tools/makeusbconf.sh -d -i -f ~/usb.json -s 8000 usb.img
```

and then separately copied to the raw USB disk device.

Use [tools/makeusbconf.bat](../tools/makeusbconf.bat) for Windows OS. It will ask you for USB device to use.

### Troubleshooting

The blinking pattern can be extracted from the shell using

```bash
cat /run/global/LedBlinkCounter/ledconfig.json
```

If the device does not have any usable IP addresses it will be 1,
if IP address but no cloud connectivity it will be 2,
if the cloud responds (even if it is an http error e.g, if the device is not yet
onboarded), it will be 3, and if a GET of /config works it will be 4.

One can test the connectivity to the controller using

```bash
    /opt/zededa/bin/diag
```

The logs for the onboarding attempts are in the [directories](./LOGGING.md) under ```/persist/newlog/``` with a source field set to `client`.

If there are no IP addresses, the logs for network interface manager can help, which have a source field set to `nim`.

The ```/persist/status/nim/DevicePortConfigList/global.json``` contains the set
of DevicePortConfig which have been tried, any errors, last time they succeeded
and failed, etc. This is quite useful in a proxy or static IP setup, since there
can be IP routing issues, DNS issues, WPAD, or proxy issues.

If there is no console (display and keyboard) to run diag or look at these files,
the ```mkush.sh -d``` above can be used to get the diagnostics deposited on the
USB stick for inspection.
