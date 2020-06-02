# Support for wireless connectivity in EVE

Given that the biggest use case for EVE is in Edge Computing and IoT it is no surprise that wireless connectivity plays a major role in connecting edge applications. Currently EVE supports 2 kinds of wireless networking devices: WiFi cards and Cellular GSM Modems. When it comes to utilizing either of these EVE relies on its controller to supply two critical pieces of information:

* Name of the wireless network to be joined ([SSID](https://en.wikipedia.org/wiki/Service_set_(802.11_network)#SSID) for WiFi and [APN](https://en.wikipedia.org/wiki/Access_Point_Name) for Cellular).
* Pre-shared secret required to joining the network ([WPA/WPA2/WEP](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access) and [username/password](https://www.digi.com/resources/documentation/Digidocs/90001399-13/tasks/t-set-up-and-configure-mobile-connectivity.htm) for Cellular).

This dependency on a controller creates a bit of a chicken-and-an-egg problem when the wireless connectivity itself happens to be the only means of reaching the controller. In those cases EVE uses pre-loaded controller configuration to bootstrap the entire process.

The rest of this document will be focused on details of wireless support in EVE. It must be noted that currently we're relying on a patchwork of different open source projects to do that, but we're also looking at things like [oFono](https://en.wikipedia.org/wiki/OFono) and [Android's RIL](https://en.wikipedia.org/wiki/Radio_Interface_Layer) for a more hollistic support.

## WiFi

In general, WiFi support in EVE is pretty straightforward and largely depends on enabling the required driver in the Linux kernel and finding an appropriate firmware binary blob to be loaded by the device driver. Please refer to our [new hardware bringup](HARDWARE-BRINGUP.md) document for more details on the former and make sure to checkout our [firmware package](../pkg/firmware) for the latter.

## Cellular GSM Modems

Compared to WiFi, cellular GSM modems present a major challenge. This is partially understandable, since radio regulations in different countries tend to be partially incompatible and at times [simply insane](https://www.afcea.org/content/disruptive-design-have-you-seen-flurry-acts-5g-security). All of this conspires to create a technology landscape where modem manufacturers are forced to produce highly capable and highly configurable units that take onto very different personalities when loaded with firmware and given their final configuration.

Given the complexity of the task that a GSM modem has to perform, it is no wonder that they evolved to be self-contained computers with very sophisticated internal state. This comparison with remote computers/servers is especially apt, since the way you can interact with this device is very API-driven with pretty much zero offloading to ther host Linux kernel. Just like you would talk to a remote cloud service using a REST API you would talk to a GSM Modem using: AT commands, MBIM or QMI API.

Currently, EVE stays away from managing GSM modem's firmware and expects a modem unit to be fully configured by a hardware manufacturer to provide a [QMI interface](https://en.wikipedia.org/wiki/Qualcomm_MSM_Interface).

### Enabling a new GSM modem (or debugging an existing one)

As with any hardware, you will typically go through the following steps:

1. making sure that the modem device is connected to the host edge node through one of the common busses (this doesn't guarantee that the host can communicate with the device, but at least you should see it registered on the bus)
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

Our previous example had a modem that is Device 7 on Port 4 exposing 4 different interfaces: 3 serial ones and one QMI CDC. This magic number of 4 interfaces is interesting because most modems insist on mapping all of their different APIs to just 3 USB interface endpoints (this is really bizzare since its not like USB interface endpoints are a scarce commodity). This mapping is called a *usb composition* and it can be programmed by either issuing an appropriate AT command (typically `at!usbcomp=1,1,10d`) on a serial end point or by issuing a CDC/QMI command (if one of those interfaces is available). Sadly, there's no standard when it comes to AT commands (and worse yet whatever AT commands are available may not actually be able to program all of the usb compositions) and your best bet is something like (note that swi in --dms-swi stands for Sierra Wireless):

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

Even though MBIM is more of a standard EVE preferes QMI over it simply because QMI uses a more reliable NCM protocol underneath (after all MBIM is just the NCM protocol + a signaling channel and QMI is just the ECM protocol + a signaling channel). ECM is the Ethernet Control Model and NCM is the Network Control Model. ECM is an earlier standard and has some issues with latency while NCM resolves those issues and is designed for high speed operation. You can read more [here](https://en.wikipedia.org/wiki/Ethernet_over_USB#Protocols).

#### 3. Connecting to the wireless provider

While GSM modems may connect to any compatible wireless provider (roaming), depending on the SIM settings the state machine may only allow a very restricted kind of roaming (emergency calls only). It is tempting to think that open source software can drive much of this state machine, but in reality, we can rely on a modem+SIM doing the right thing and connecting to the given provider at a basic level. Once that happens we have a bit of control in driving the rest of the state machine that can give us a data connection.

All the configuration that makes your modem connect to a desired wireless provider resides in SIM and modem's NVRAM. Both of these settings are expected to be done once before the hardware unit ships and EVE stays away from fiddling with these. Still, sometimes it is important to troubleshoot basic (non-data) wireless connectivity issues and most of the time you would use AT commands for that.

When it comes to controlling GSM modems via AT commands, there's not much of a standard. Different vendors use different commands and worse yet the state machines of how modems operate tend to be very different. Some vendors (e.g. Sierra Wireless) [publish](https://source.sierrawireless.com/resources/airprime/minicard/74xx/4117727-airprime-em74xx-mc74xx-at-command-reference/#sthash.fPZTyQtd.dpbs) reasonably detailed references, but even those don't really contain enough details. Various [forums](https://ltehacks.com/viewtopic.php?t=33) tend to be a good source of information for what may work. In addition to that, here's a minimum set of AT commands to keep in mind when debugging GSM modem issues (they are roughly in order you'd use them):

* `AT!RESET` and `AT+CFUN=0` followed by `AT+CFUN=1,1` for resetting the modem
* `AT!ENTERCND="A710"` enter super user mode
* `AT+CPIN?` for working with SIM (make sure SIM is ready to use)
* `AT+CREG?` for figuring out network registration (make sure you are registred in the home network)
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

Once your modem reliably connects to your desired wireless provider, the final step is making sure that you can request a data connection. Data connection is layered on top of the basic GSM connectivity and requires you knowing a recommended APN and credentials that are needed to connect to it (both can be set dynamically by EVE's controller). Managing that data connection is the job of EVE's [wwan](../pkg/wwan) package and that is all that it does (e.g. it does NOT manage firmware or basic GSM connectvity). `wwan` package uses `uqmi` utility to talk to the QMI-enabled USB endpoint (typically `/dev/cdc-wdmX`) and goes through the following stages:

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

## References

* [Sierra Wireless MC7455 stuck in MBIM-only USB composition](https://forum.sierrawireless.com/t/mc7455-stuck-in-mbim-only-usb-composition/8499)
* [AirPrime EM74xx-MC74xx AT Command Reference](https://source.sierrawireless.com/resources/airprime/minicard/74xx/4117727-airprime-em74xx-mc74xx-at-command-reference/#sthash.fPZTyQtd.dpbs)
* [Network Registration Issues](https://forum.sierrawireless.com/t/problem-about-network-registration/4333)
* [Sierra Wireless MC7455 | EM7455 -- AT! Command Guide](https://ltehacks.com/viewtopic.php?t=33)
* [Minicard GPS operation](https://forum.sierrawireless.com/uploads/short-url/2qSQfE8H2hxdS1kS3mdYtSWGtpr.pdf)
* [Gateworks LTE Guide](http://trac.gateworks.com/wiki/wireless/modem)
* [Embedded Pi documentation](http://www.embeddedpi.com/documentation/3g-4g-modems)
* [How to use 4G LTE modems like the MC7455 on both Debian/Ubuntu and OpenWRT using MBIM](https://gist.github.com/Juul/e42c5b6ec71ce11923526b36d3f1cb2c)
