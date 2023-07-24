# Support for wireless connectivity in EVE

Given that the biggest use case for EVE is in Edge Computing and IoT it is no surprise that wireless connectivity plays a major role in connecting edge applications. Currently EVE supports 2 kinds of wireless networking devices: WiFi cards and Cellular GSM Modems. When it comes to utilizing either of these EVE relies on its controller to supply two critical pieces of information:

* Name of the wireless network to be joined ([SSID](https://en.wikipedia.org/wiki/Service_set_(802.11_network)#SSID) for WiFi and [APN](https://en.wikipedia.org/wiki/Access_Point_Name) for Cellular).
* Pre-shared secret required to joining the network ([WPA/WPA2/WEP](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access) and [username/password](https://www.digi.com/resources/documentation/Digidocs/90001399-13/tasks/t-set-up-and-configure-mobile-connectivity.htm) for Cellular).

This dependency on a controller creates a bit of a chicken-and-an-egg problem when the wireless connectivity itself happens to be the only means of reaching the controller. In those cases EVE uses pre-loaded controller configuration to bootstrap the entire process.

The rest of this document will be focused on details of wireless support in EVE. It must be noted that currently we're relying on a patchwork of different open source projects to do that, but we're also looking at things like [oFono](https://en.wikipedia.org/wiki/OFono) and [Android's RIL](https://en.wikipedia.org/wiki/Radio_Interface_Layer) for a more holistic support.

## WiFi

In general, WiFi support in EVE is pretty straightforward and largely depends on enabling the required driver in the Linux kernel and finding an appropriate firmware binary blob to be loaded by the device driver. Please refer to our [new hardware bringup](HARDWARE-BRINGUP.md) document for more details on the former and make sure to checkout our [firmware package](../pkg/firmware) for the latter.

## Cellular GSM Modems

Compared to WiFi, cellular GSM modems present a major challenge. This is partially understandable, since radio regulations in different countries tend to be partially incompatible and at times [simply insane](https://www.afcea.org/content/disruptive-design-have-you-seen-flurry-acts-5g-security). All of this conspires to create a technology landscape where modem manufacturers are forced to produce highly capable and highly configurable units that take onto very different personalities when loaded with firmware and given their final configuration.

Given the complexity of the task that a GSM modem has to perform, it is no wonder that they evolved to be self-contained computers with very sophisticated internal state. This comparison with remote computers/servers is especially apt, since the way you can interact with this device is very API-driven with pretty much zero offloading to the host Linux kernel. Just like you would talk to a remote cloud service using a REST API you would talk to a GSM Modem using: AT commands, MBIM or QMI API.

Currently, EVE stays away from managing GSM modem's firmware and expects a modem unit to be fully configured by a hardware manufacturer to provide a [QMI interface](https://en.wikipedia.org/wiki/Qualcomm_MSM_Interface).

### Enabling a new GSM modem (or debugging an existing one)

As with any hardware, you will typically go through the following steps:

1. making sure that the modem device is connected to the host edge node through one of the common buses (this doesn't guarantee that the host can communicate with the device, but at least you should see it registered on the bus)
2. making sure that the modem is configured in such a way that you can actually communicate with it
3. making sure that you can drive the modem and instruct it to connect to the wireless provider
4. making sure that a modem connected to the wireless provider can establish a data connection and reflect it back to the host as a network interface (typically `wwanX`)

#### 1. Basic bus connectivity

Almost all well known GSM modems get hooked to a USB bus (most of them communicate using USB2 but some try USB3 and then [trouble may ensue](https://forum.sierrawireless.com/t/mc7455-not-recognized-at-boot/9735) and you may need to [do soldering](https://forum.sierrawireless.com/t/effect-of-removing-usb-3-0-pins-of-mc7455/12702/2)). From there, a single device will expose different interfaces to accommodate various ways of interacting with it. These include:

* traditional serial interface capable of accepting AT-commands (popular choices of drivers include [Qualcomm's qcserial](https://github.com/torvalds/linux/blob/master/drivers/usb/serial/qcserial.c) and [Sierra Wireless serial](https://github.com/torvalds/linux/blob/master/drivers/usb/serial/sierra.c)). This interface is NOT capable of directly transmitting Ethernet frames and requires an old-school PPP support
* traditional serial interface used for special purposes such as [GPS NMEA port](https://en.wikipedia.org/wiki/NMEA_0183) or [Diagnostic Monitoring](https://forum.sierrawireless.com/t/sierra-linux-qmi-dmcapture-sh-not-working/6373)
* One of the CDC (no, not [that CDC](https://www.cdc.gov/) - rather [communications device class](https://en.wikipedia.org/wiki/USB_communications_device_class)) interfaces capable of direct transport of Ethernet frames:
  * [CDC MBIM](https://www.kernel.org/doc/Documentation/networking/cdc_mbim.txt)
  * [CDC QMI](https://en.wikipedia.org/wiki/Qualcomm_MSM_Interface)

To put it all together, a single GSM modem is likely to look something like this when inspected by the `lsusb -t` command:

```console
/:  Bus 01.Port 1: Dev 1, Class=root_hub, Driver=ehci-pci/2p, 480M
    |__ Port 1: Dev 2, If 0, Class=Hub, Driver=hub/4p, 480M
        |__ Port 2: Dev 3, If 0, Class=Hub, Driver=hub/4p, 480M
            |__ Port 4: Dev 7, If 0, Class=Vendor Specific Class, Driver=qcserial, 480M
            |__ Port 4: Dev 7, If 3, Class=Vendor Specific Class, Driver=qcserial, 480M
            |__ Port 4: Dev 7, If 8, Class=Vendor Specific Class, Driver=qmi_wwan, 480M
            |__ Port 4: Dev 7, If 2, Class=Vendor Specific Class, Driver=qcserial, 480M
```

#### 2. Communicating with the modem on various USB interfaces

Our previous example had a modem that is Device 7 on Port 4 exposing 4 different interfaces: 3 serial ones and one QMI CDC. This magic number of 4 interfaces is interesting because most modems insist on mapping all of their different APIs to just 3 USB interface endpoints (this is really bizarre since its not like USB interface endpoints are a scarce commodity). This mapping is called a *usb composition* and it can be programmed by either issuing an appropriate AT command (typically `at!usbcomp=1,1,10d`) on a serial end point or by issuing a CDC/QMI command (if one of those interfaces is available). Sadly, there's no standard when it comes to AT commands (and worse yet whatever AT commands are available may not actually be able to program all of the usb compositions) and your best bet is something like (note that swi in --dms-swi stands for Sierra Wireless):

```bash
$ qmicli --device-open-mbim -p -d /dev/cdc-wdm0 --dms-swi-get-usb-composition
[/dev/cdc-wdm0] Successfully retrieved USB compositions:
            USB composition 6: DM, NMEA, AT, QMI
        [*] USB composition 8: DM, NMEA, AT, MBIM
            USB composition 9: MBIM
$ qmicli --device-open-mbim -p -d /dev/cdc-wdm0 --dms-swi-set-usb-composition=6
```

If all else fails you may try [swi_setusbcomp script](https://github.com/mavstuff/swi_setusbcomp) to switch to a desired USB composition:

```bash
$ swi_setusbcomp.pl --device=/dev/cdc-wdm0
  6  => 'DM   NMEA  AT    QMI',
  7  => 'DM   NMEA  AT    RMNET1 RMNET2 RMNET3',
  8  => 'DM   NMEA  AT    MBIM',
  9  => 'MBIM',
  10 => 'NMEA MBIM',
swi_setusbcomp.pl --device=/dev/cdc-wdm0 --usbcomp=6
```

Regardless of how you arrive at the desired USB composition, make sure to reboot and watch out for the following device and device drivers:

* `/dev/ttyUSB2` and qcserial driver serving as serial AT command capable endpoint
* `/dev/ttyUSBX` and qcserial and option (yes somebody had enough sense of humor to call a driver option)
* `/dev/cdc-wdm0` and either qmi_wwan or cdc_mbim drivers for QMI and MBIM endpoints

Even though MBIM is more of a standard EVE prefers QMI over it simply because QMI uses a more reliable NCM protocol underneath (after all MBIM is just the NCM protocol + a signaling channel and QMI is just the ECM protocol + a signaling channel). ECM is the Ethernet Control Model and NCM is the Network Control Model. ECM is an earlier standard and has some issues with latency while NCM resolves those issues and is designed for high speed operation. You can read more [here](https://en.wikipedia.org/wiki/Ethernet_over_USB#Protocols).

#### 3. Connecting to the wireless provider

While GSM modems may connect to any compatible wireless provider (roaming), depending on the SIM settings the state machine may only allow a very restricted kind of roaming (emergency calls only). It is tempting to think that open source software can drive much of this state machine, but in reality, we can rely on a modem+SIM doing the right thing and connecting to the given provider at a basic level. Once that happens we have a bit of control in driving the rest of the state machine that can give us a data connection.

All the configuration that makes your modem connect to a desired wireless provider resides in SIM and modem's NVRAM. Both of these settings are expected to be done once before the hardware unit ships and EVE stays away from fiddling with these. Still, sometimes it is important to troubleshoot basic (non-data) wireless connectivity issues and most of the time you would use AT commands for that.

When it comes to controlling GSM modems via AT commands, there's not much of a standard. Different vendors use different commands and worse yet the state machines of how modems operate tend to be very different. Some vendors (e.g. Sierra Wireless) [publish](https://source.sierrawireless.com/resources/airprime/minicard/74xx/4117727-airprime-em74xx-mc74xx-at-command-reference/#sthash.fPZTyQtd.dpbs) reasonably detailed references, but even those don't really contain enough details. Various [forums](https://ltehacks.com/viewtopic.php?t=33) tend to be a good source of information for what may work. In addition to that, here's a minimum set of AT commands to keep in mind when debugging GSM modem issues (they are roughly in order you'd use them):

* `AT!RESET` and `AT+CFUN=0` followed by `AT+CFUN=1,1` for resetting the modem
* `AT!ENTERCND="A710"` enter super user mode
* `AT+CPIN?` for working with SIM (make sure SIM is ready to use)
* `AT+CREG?` for figuring out network registration (make sure you are registered in the home network)
* `AT+COPS=?` for showing available networks and `AT+COPS=0` for triggering the network registration or `AT+COPS=1,2,"xxxxx",7` to manually connect to a given provider
* `AT+CSQ` (and especially `+WIND:`) for finding out signal quality and the connections
* `AT+CGATT=1` for attaching to the service
* `AT+CGDCONT?` and `AT+CGDCONT=1,"IP","apn.tmobile.com"` for defining Packet Data Protocol (PDP) context
* `AT+CGACT=1,1` for activating one of the PDP contexts
* `AT+CGPADDR=1` for requesting an IP address assigned by the context
* `AT!USBCOMP=1,1,10d` for changing USB composition
* `ATI` for general information and `AT!entercnd="A710"` (for Sierra Wireless) to enter extended command set
* `$GPS_START` to start receiving GPS data on a lot of Qualcomm modems

For example, the following may be a reasonable session to initialize your modem using AT commands:

```bash
picocom -b 115200 /dev/ttyUSB2

ati
at!entercnd="A710"
at+cpin?
  READY
at!custom="IPV6ENABLE",1
at+cgdcont=1,"ipv4v6","vzwinternet"
at!selrat=06
at!usbcomp = 1,1,1009
at!reset
```

#### 4. Establishing a data connection

Once your modem reliably connects to your desired wireless provider, the final step is making sure that you can request a data connection. Data connection is layered on top of the basic GSM connectivity and requires you knowing a recommended APN and credentials that are needed to connect to it (both can be set dynamically by EVE's controller). Managing that data connection is the job of EVE's [wwan](../pkg/wwan) package and that is all that it does (e.g. it does NOT manage firmware or basic GSM connectivity). `wwan` package uses `uqmi` utility to talk to the QMI-enabled USB endpoint (typically `/dev/cdc-wdmX`) and goes through the following stages:

```bash
# wait for modem to register with the network
uqmi --get-serving-system
# start data connection
uqmi --start-network --apn YOUR_APN --keep-client-id wds
# wait for data connection to be established
uqmi --get-data-status
# wait for IP setting (addr, DNS, etc.) to be available
uqmi --get-current-settings
```

In general, a single GSM modem can actually multiplex between different data networks (and thus provide multiple network interfaces) this is very rarely done in practice (and EVE certainly doesn't support it) but you need to keep in mind that each of these networks is distinguished by a separate Packet Data Handle (PDH) value. For example, your `uqmi --start-network ...` command will return a unique PDH handle back to you and if you ever want to reference that particular data connection you'll have to either use that value or use a catchall one `0xFFFFFFFF`.

Another concept that you will encounter when looking at QMI/MBIM protocols is that of a Client ID (CID). Think of it as an HTTP token in REST APIs -- something that uniquely identifies a stateful connection with a given client. If you're issuing a series of QMI/MBIM commands as a transaction you want to keep client ID the same for all of them. Take a look at how [this script](https://github.com/freedesktop/libqmi/blob/master/utils/qmi-network.in) handles both PDH and CID.

This idea of an token guaranteeing an active connection is actually a pretty important one. For example, another popular script for attaching to data connection in [MBIM mode](https://github.com/freedesktop/libmbim/blob/master/utils/mbim-network.in) goes out of its way to keep a single active connection between different invocations of the `mbimcli` utility (look for how it uses `--no-open` and `--no-close` options and caches transactions IDs so that the next call to `mbimcli` can pick it up and use it as an argument for `--no-open`)

### Frequencies and antennas

At some point you will have to care about frequencies and antennas. Most Sierra Wireless modems support all frequencies and both FDD-LTE and TDD-LTE (which are just two different ways of splitting upstream and downstream bandwidth). You can check on cellmapper.net which channels are supported by the cell towers near you and look up the corresponding frequencies [here](https://www.wiserepeater.com/4g-lte-bands-and-frequencies-tdd-fdd-lte). You can then either get a wideband antenna that covers all of the frequencies supported by your modem and the cell tower, or you can pick one or two frequencies and get an antenna for just those frequencies. Usually wideband antennas that support multiple frequencies don't have as much gain. You might want to try forcing your modem to use each of the frequencies in turn and check the bandwidth during peak times before you decide on the best antenna.

For the MC7455 you will probably need pigtails (antenna adaptors) from u.fl to either SMA or N-type connectors depending on your antenna. Other modems like the EM7565 use MHF4 connectors instead of u.fl. Remember that the longer the cable from your modem to the antenna, the more signal you will loose.

### Firmware

The fact that EVE itself stays out of Firmware upgrade business means that you may get into it. [Bootable ISO from Daniel E Wood](https://github.com/danielewood/sierra-wireless-modems) is probably the best option at this point.

### Open Source projects with focus on GSM modem support

Aside from vendor and system integrator's forums, a lot of great information and software is available at [ROOter Of Modems and Men](https://www.ofmodemsandmen.com/) and [Daniel Wood's GitHub](https://github.com/danielewood/sierra-wireless-modems).

## Radio Silence

Radio silence is the act of disabling all radio transmission for safety or security reasons.
This is commonly used to mitigate the risk of radio frequency interference with other instruments
in the vicinity of the edge node. However, often times it is just the regulations that prohibit
the use of radio devices in some areas or during certain procedures.

### Permanent radio silence

In some countries/regions or designated areas, it may be required that an edge node is deployed
with all wireless devices permanently disabled and with only wired connectivity options used
to communicate with the controller. This can be easily accomplished in EVE because the default
state for wireless devices (as imposed by EVE) is to disable radio transmission. This means
that as long as a `PhysicalIO` representing a cellular modem or a WiFi adapter has no network
associated with it, EVE will prevent the device from emitting any power over the radio.

### Temporary radio silence

In situations where wireless communication may interfere with other instruments during a certain
procedure of a limited duration, it may be necessary to temporarily disable radio transmission.
If there are no wired connection alternatives, the edge node will lose connectivity with
the controller, but it should not cause the node to reboot, fallback to previous network
configuration or to do anything else that may negatively affect applications running on it.
For safety reasons and due to uncertain accessibility to the controller, it is typically required
that the radio silence mode is switched ON and OFF locally and not managed remotely.

With these requirements in mind, EVE was designed to use the [Local profile server](https://github.com/lf-edge/eve-api/tree/main/PROFILE.md)
(a designated application overriding controller for a small subset of the config) with a separate
[Radio endpoint](https://github.com/lf-edge/eve-api/tree/main/PROFILE.md#Radio), to periodically obtain the required state of the radio
silence mode and to publish the actual state. Intentionally, it is not possible to enabled or disable
radio silence remotely through the controller. Still, the controller is at least used to deploy
the application, mark it as a Local profile server and to specify string token that the application
will have to present to EVE with each request to authenticate itself. This is submitted to the edge
node using the `local_profile_server` and `profile_server_token` fields from `EdgeDevConfig`.

#### Radio endpoint semantic

Without Local profile server deployed or configured (from the controller), the default behavior
is to enable radio transmission for all wireless devices with a network configuration attached
and disable the rest. In other words, a temporary radio silence is disabled by default and only
unused devices are (permanently) silenced.

Once a Local profile server has been deployed and the application transitioned to the "running"
state, EVE will start periodically making a POST request to the [Radio endpoint](https://github.com/lf-edge/eve-api/tree/main/PROFILE.md#Radio).
If this (optional) endpoint is not implemented, the default policy for radio transmission
will remain in effect. If the endpoint is available, EVE will provide an update of the
current state of wireless devices in the POST request body, formatted and marshalled using
the [RadioStatus](./proto/profile/local_profile.proto) proto message. This includes the state
of the radio silence mode, information about cellular modem(s) and SIM card(s), signal strength
metrics and packets counters as recorded by modem(s). Note that currently the state information
is limited to cellular connectivity and does not cover WiFi network adapters.

If a response from the application contains no content (response code 204), EVE assumes
that the intended radio silence state has not changed (initial intended state is a disabled
radio silence).
Application response with non-empty content (response code 200) is unmarshalled into
[RadioConfig](https://github.com/lf-edge/eve-api/tree/main/proto/profile/local_profile.proto) protobuf message. If the unmarshalling
succeeded and the token matches the expected value configured through the controller,
EVE will accept the new radio configuration. Currently, apart from the token, RadioConfig
contains only a single boolean field which determines if the radio silence should be imposed
or lifted.

Whenever the newly received intended state of the radio silence mode differs from
the currently applied state, EVE will trigger an operation of switching radio transmission
ON/OFF on all (used) wireless devices. This operation takes some time, during which EVE
stops publishing radio status updates and receiving new radio configs. This is purely
to simplify the implementation and avoid any interleaving between config updates and state
changes. Once the new radio config was applied (successfully or with an error),
EVE will restart the periodic radio status updates and will POST the outcome of the operation
back to the application via the radio endpoint.

A formal definition for the syntax and the semantics of the radio endpoint can be found
[here](https://github.com/lf-edge/eve-api/tree/main/PROFILE.md#Radio)

#### Persistence

The intended radio configuration received from Local profile server is persisted
by EVE (under `/persist` partition) and remains in effect even if the application
restarts or the edge node reboots (but please see [risks and limitations](#risks-and-limitations)
associated with the edge node reboot).
Only once the Local profile server is un-configured or un-deployed will EVE discard
the last radio config and restore the default behavior of disabled radio silence.

#### Controller connectivity

While the radio silence is imposed, it is perfectly normal for the edge node to lose access
to the controller, especially if there are no wired connectivity alternatives.
Normally, this could cause the network configuration to fallback to a previous state
in an attempt to restore the connectivity. However, in this case this behavior is not desirable,
therefore the network connectivity testing and the whole fallback mechanism is disabled
during the radio silence.

Please note that there is also a timer inside EVE to reboot the device if it has not had
controller connectivity for a prolonged time period - by default this is configured to one week.
Since it is not expected that a temporary radio silence would remain turned ON for such an extended
period of time in practice, this timer remains enabled even when radio communication is disabled.

#### Expected application behaviour

Application acting as a Local Profile Server for the radio management is expected
to behave as follows:

* Application provides UI on the user-side and runs HTTP server with `/api/v1/radio`
  endpoint on the EVE-side.
* The application UI should allow to:
  * Toggle the radio silence intended state (ON/OFF) and as a result change the message content
    that the HTTP server will respond with to `/api/v1/radio` POST calls.
  * Show the last received actual state and the last error if there was any
    (periodically POSTed to `/api/v1/radio` by EVE).
  * Show that an operation of changing the radio state is still ongoing (e.g. a "loading gif").
    This starts from a moment of user changing the intended state in the UI, continues
    through the next POST API call (from which EVE learns the new intended state,
    different from the actual state), up to the second next POST API call with the actual
    radio state after making the attempt to apply the new intended config
    (please remember that for simplicity's sake there will be no POST API calls while
    a change is ongoing).

#### Radio silence indication

When radio silence is temporarily imposed, the device status indicator (by default the disk LED)
will repeat a patter of blinking 5 times in a row. The pattern is the same regardless of what state
the device was in before the radio silence was imposed.
More information about the node state indication using LED can be found [here](LED-INDICATION.md).

Additionally, [Diagnostics](../pkg/pillar/cmd/diag) prints information about radio silence state
changes into the console, mostly for debugging purposes.

### Risks and Limitations

The current implementation of the radio silence mode has few limitations that users
should be aware of, especially if used for safety-critical use-cases.

* Currently supported are cellular modems and WiFi adapters.
  Bluetooth devices are NOT covered.
* For WiFi adapters, the Linux [rfkill subsystem](https://linux.die.net/man/1/rfkill) is used
  to enable/disable radio communication. This, however, requires that for every attached WiFi
  adapter there is a corresponding rfkill driver available and loaded into the kernel.
  Run `rfkill` command from the debug console and look for a table entry with `wlan` TYPE.
  For some devices it may be necessary to enable certain `*_RFKILL=y` kernel parameters
  to build their drivers (e.g. `CONFIG_ATH9K_RFKILL=y`).
* For cellular modems we use QMI and MBIM protocols for management. Both of these protocols
  provide APIs to enable/disable radio transmission. However, cellular modems that do not
  support any of these protocols (and likely only AT commands), cannot be managed by EVE
  and the radio transmission will remain in the modem's default state (which usually is ON).
* Radio silence only applies to wireless network adapters which are visible to EVE (host OS).
  Adapters directly assigned to applications are not covered. It is up to those applications
  to manage the state of radio transmission.
* The intended radio configuration is obtained from the Local profile server by means of periodic
  polling. However, because we want to limit the delay between a user turning radio silence ON/OFF
  and the requested change taking the effect, the polling period is set down to 5 seconds,
  i.e. substantially less than the default 1 minute period for edge node config retrieval
  from the controller.
  Still, expect that it may take several seconds to enable/disable radio silence.
  Especially with cellular modems and QMI/MBIM protocols there is some latency in response
  from the modem itself.
  Users should wait for the Local profile server application to display a confirmation
  in the UI of a finalized state change (and whether it actually succeeded).
* If the radio silence is imposed while the edge node reboots, there could be a short window
  between the boot and EVE microservices starting and applying the persisted state,
  during which wireless devices might in theory manage to quickly turn on and transmit some
  signals. This also applies to permanently disabled wireless devices (i.e. without network config).
  However, this risk is mitigated in EVE quite well. For WiFi cards this is actually completely
  avoided by using a kernel commandline parameter `rfkill.default_state=0`, to ensure that WiFi
  radios are initially all disabled and can be turned ON only by an EVE microservice.
  For cellular modems, however, we rely here on the modem to support configuration persistence.
  For example, SierraWireless modems `EM7565` and `MC7455`, that were tested and verified with EVE,
  do support persistence.
* The last limitation (not really a risk) is that by design the local profile override
  and the radio silence mode both have to be managed by the same application.

## Cellular info and metrics

The list of all cellular modems visible to the host (incl. the unused ones, without network config attached),
is published in `ZInfoDevice.cell_radios`. The `name` of each modem is simply a string that EVE guarantees
to be unique among all the modems in the list (for example IMEI if available). Information provided for each
modem may include IMEI (a globally unique modem ID), hardware model, firmware version, operating state
(radio silence is one of the states) and the protocol used for management (QMI or MBIM).

The list of all SIM cards inserted into cellular modems is published in `ZInfoDevice.sims`. The `name` of each
SIM card is simply a string that EVE guarantees to be unique among all the SIM cards in the list (for example
ICCID if available). Information provided for each SIM card may include ICCID (a globally unique SIM ID),
IMSI (a mobile subscriber identity) and a reference to the name of the modem to which it is inserted.
SIM card state is also defined but currently not provided.

Every device port associated with a cellular modem has `wireless_status` defined. It contains references
to the names of the modem and the SIM card being used, information about visible network providers
(with PLMN codes) and potentially also error messages if EVE failed to apply the last configuration for
this port or if the connectivity testing is failing.

EVE also collects metrics from cellular modems (i.e. stats recorded by modems themselves, not from the Linux
network stack). These are published in `deviceMetric.cellular`.  Included are packet and byte RX/TX
counters, drop/error counters and information about the signal strength: RSSI, RSRQ, RSRP, SNR.
Note that with MBIM control protocol, only RSSI is available. The maximum value of int32 (`0x7FFFFFFF`)
represents unspecified/unavailable metric (zero is a valid value).

## References

* [Sierra Wireless MC7455 stuck in MBIM-only USB composition](https://forum.sierrawireless.com/t/mc7455-stuck-in-mbim-only-usb-composition/8499)
* [AirPrime EM74xx-MC74xx AT Command Reference](https://source.sierrawireless.com/resources/airprime/minicard/74xx/4117727-airprime-em74xx-mc74xx-at-command-reference/#sthash.fPZTyQtd.dpbs)
* [Network Registration Issues](https://forum.sierrawireless.com/t/problem-about-network-registration/4333)
* [Sierra Wireless MC7455 | EM7455 -- AT! Command Guide](https://ltehacks.com/viewtopic.php?t=33)
* [Minicard GPS operation](https://forum.sierrawireless.com/uploads/short-url/2qSQfE8H2hxdS1kS3mdYtSWGtpr.pdf)
* [Gateworks LTE Guide](http://trac.gateworks.com/wiki/wireless/modem)
* [Embedded Pi documentation](http://www.embeddedpi.com/documentation/3g-4g-modems)
* [How to use 4G LTE modems like the MC7455 on both Debian/Ubuntu and OpenWRT using MBIM](https://gist.github.com/Juul/e42c5b6ec71ce11923526b36d3f1cb2c)
