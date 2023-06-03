# EVE configuration

While most of EVE's configuration is done via receiving a configuration object from a controller, there's always a question of a bootstrap. At the very minimum EVE has to know host name, port and certificate of the controller from which it can receive its first configuration object. On top of that there are some aspects of the early boot flow that may need to be tweaked in order for EVE to successfully bootstrap its microservices.

In general, EVE is trying to make sure that its controller always has the last word in tweaking any kind of configuration knobs. The following configuration files are the only exception to that rule:

* `grub.cfg` - local tweaks to an [otherwise readonly grub.cfg](README.md#runtime-lifecycle)
* `DevicePortConfig/override.json` - initial configuration for all of EVE's network interfaces (*deprecated*, see below for details)
* `server` - contains a FQDN of a controller and its port (e.g. controller.acme.com:123)
* `root-certificate.pem` - contains an x509 root certificate to trust for the controller for TLS in V1 API and object signing in V2 API
* `v2tlsbaseroot-certificates.pem` - contains the x509 root certificate to trust for the TLS to the controller when using the V2 API
* `onboard.cert.pem` - onboarding certificate for the [initial registration](REGISTRATION.md) with the controller
* `wpa_supplicant.conf` - a legacy way of configuring EVE's WiFi
* `authorized_keys` - initial authorized SSH keys for accessing EVE's debug console; DO NOT use options, we only accept 'keytype, base64-encoded key, comment' format
* `bootstrap-config.pb`- initial device configuration used only until device is onboarded (see below for details)

The initial content of these configuration files is stored in the EVE's source tree under [config](../config) folder. From there, these configuration files are baked into the EVE installer images. For the read-write bootable disk installer image these files can further be tweaked by mounting the "EVE" partition and editing those files directly on the installer image. This gives you an ability to take the default installer image and tweak it for your needs without re-building EVE from scratch (obviously this is not an option for a read-only ISO installer image). A typical workflow is to take an installer image from the official EVE build, flash it onto a USB flash drive, insert that USB flash drive into your desktop and edit file on the partition called EVE.

Once an installer has been run on an edge node, the content of the partition with label EVE found on the installer media is simply copied into the CONFIG partition on the edge node's local storage. From that point on, these files reside in the *read-only* CONFIG partition on the edge node and can NOT be changed by the controller.

## Bootstrap configuration

EVE doesn't care how it gets its configuration objects as long as they come from the source that can be trusted.
Normally, this trusted source happens to be EVE's controller and the trust is established via TLS connection that is validated by the `v2tlsbaseroot-certificates.pem` and furthermore by controller signing configuration objects and device validating these signatures against the `root-certificate.pem`.

However, in some scenarios, device might not be able to establish the initial controller connectivity using the default network configuration (for definition see "Last Resort" section in [DEVICE-CONNECTIVITY.md](./DEVICE-CONNECTIVITY.md)). For example, the network to which the device is connected may require that all traffic goes through a network proxy, otherwise it is blocked. Or the network may use static IP settings without providing DHCP service, expecting every endpoint to select and configure an appropriate IP address on its own. Or maybe device has only LTE connectivity and needs to know what APN to register into the network with.
In such cases it is required to deliver the initial, also known as *bootstrap*, device configuration off-line. The recommended method (over some legacy mechanisms described below) is to prepare a single-use EVE installation medium, carrying the bootstrap config for the target device inside the EVE partition.

The bootstrap configuration is modeled using the same Protobuf message that models device configuration delivered on-line: [EdgeDevConfig](../api/proto/config/devconfig.proto). Just like in the on-line config delivery, an instance of `EdgeDevConfig` is protobuf-encoded and put into the `AuthContainer` envelope alongside a signature (see [OBJECT-SIGNING.md](../api/OBJECT-SIGNING.md)). For the off-line signature verification (that must pass for the device to accept the configuration), it is necessary to further wrap `AuthContainer` together with the signing and all intermediary controller certificates inside [BootstrapConfig](../api/proto/config/devconfig.proto). Finally, `BootstrapConfig` should be protobuf-encoded and written in this binary format into the EVE partition of a single-use EVE installer as `bootstrap-config.pb`. During the EVE installation, this file is copied into the CONFIG partition.

The format of the bootstrap configuration is rather complex and intentionally binary to disincentivise users from preparing and editing the configuration manually. Instead, it is expected that the process of preparing and exporting the bootstrap configuration is done by the controller and the tools that it provides. To bake an exported bootstrap config into a single-use EVE installer, use [eve-gen-single-use-installer.sh](../tools/eve-gen-single-use-installer.sh) script (run with no arguments to print the script usage).

Currently, it is expected that the bootstrap configuration will only contain those attributes of `EdgeDevConfig` which are in one way or another related to device connectivity:

* `networks`
* `configItems`
* `systemAdapterList`
* `deviceIoList`
* `vlans`
* `bonds`
* `config_timestamp`

Anything else will be silently ignored.

The above allows to configure one or multiple management interfaces, as well as non-management interfaces, and can specify static IP and DNS configuration (for environments where DHCP is not used), plus the LTE configuration. In addition, it can specify proxies using several different mechanisms (explicitly, using WPAD, etc.). [Object level encryption](./OBJECT-LEVEL-ENCRYPTION.md) is not supported inside the bootstrap config, meaning that WiFi settings with the network password have to be left out it. Currently, it is therefore not possible to onboard device with WiFi-only connectivity using this mechanism.

For more information on how the network configuration is parsed and processed by EVE microservices, including topics on load spreading and failover with multiple uplink ports, please refer to [DEVICE-CONNECTIVITY.md](DEVICE-CONNECTIVITY.md).

Please note that the bootstrap configuration is used and applied only once. After that, EVE records SHA256 hash of `bootstrap-config.pb` into `/persist/ingested/bootstrap-config.sha` to avoid re-application and expects to receive further configuration changes only from the controller.

We plan to completely transition to this way of configuring all aspects (and not just networking) of EVE in off-line situations.
However, in the present state, EVE is only able to receive bootstrap configuration during the installation from the installer. It is not yet supported to inject bootstrap config in later stages of device life-cycle. For example, it would be useful to recover connectivity of a device which has been moved to a different location before it could have acquired an updated configuration from the controller. Even without changing the location, device can lose connectivity if the network to which it is attached undergoes configuration changes which are incompatible with the current device network config.
For these cases, and also with older EVE releases that do not support bootstrap config, it is necessary to use the legacy methods for off-line configuration management, described in the sections below.

## *Legacy* mechanism for off-line configuration management

The [bootstrap configuration](#bootstrap-configuration) described above is the preferred method for the off-line device configuration management. The previously used and now deprecated mechanism described in this section are only supported for backward-compatibility reasons. However, if the installed EVE is recent enough to support bootstrap config and the file `bootstrap-config.pb` is present in the CONFIG partition, these legacy methods are disabled and their inputs (`override.json`, `usb.json` - see below) are ignored (and the user is informed about this in device logs).

**Further in this section and its subsections we assume that bootstrap configuration is not present or not supported by the used EVE version.**

When the device boots the first time it determines the set of potentially usable network interfaces to use to reach the controller, as specified in [DEVICE-CONNECTIVITY last resort](DEVICE-CONNECTIVITY.md).

That default network configuration can be overridden by an optional file in
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
(for environments where DHCP is not used), plus WiFi and cellular modem specifics. In addition, it can specify proxies using several different mechanisms.

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

```shell
make config.img
make installer.raw
```

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
