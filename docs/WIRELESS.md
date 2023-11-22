# Support for wireless connectivity in EVE

Given that the biggest use case for EVE is in Edge Computing and IoT it is no surprise that wireless
connectivity plays a major role in connecting edge applications. Currently, EVE supports 2 kinds
of wireless networking devices: WiFi cards and Cellular Modems. When it comes to utilizing
either of these, EVE relies on its controller to supply two critical pieces of information:

* Name of the wireless network to be joined ([SSID](https://en.wikipedia.org/wiki/Service_set_(802.11_network)#SSID)
  for WiFi and [APN](https://en.wikipedia.org/wiki/Access_Point_Name) for Cellular).
* Pre-shared secret required for joining the network ([WPA/WPA2/WEP](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access)
  for WiFi and username/password for Cellular network running [PAP](https://en.wikipedia.org/wiki/Password_Authentication_Protocol)
  or [CHAP](https://en.wikipedia.org/wiki/Challenge-Handshake_Authentication_Protocol)).

This dependency on a controller creates a bit of a chicken-and-an-egg problem when the wireless
connectivity itself happens to be the only means of reaching the controller. In those cases,
EVE uses pre-loaded controller configuration to bootstrap the entire process.

The rest of this document will be focused on details of wireless support in EVE.

## WiFi

In general, WiFi support in EVE is pretty straightforward and largely depends on enabling
the required driver in the Linux kernel and finding an appropriate firmware binary blob
to be loaded by the device driver. Please refer to our [new hardware bringup](HARDWARE-BRINGUP.md)
document for more details on the former and make sure to checkout our [firmware package](../pkg/fw)
for the latter.

### wlan microservice

EVE uses [wpa_suplicant](https://wiki.archlinux.org/title/wpa_supplicant) to perform WPA-PSK
or WPA-EAP authentication process when connecting to WiFi networks. This software is installed
into a standalone [wlan](../pkg/wlan) container and it expects configuration for every WiFi adapter
at the filepath `/run/wlan/wpa_supplicant.conf`. On any change of this configuration file,
a simple shell script simply restarts wpa_supplicant, pointing it to this config path.
The responsibility of maintaining and updating this configuration lies with the NIM microservice.

## Cellular connectivity

### Modems

Compared to WiFi, cellular modems present a significant challenge. This is partially due to the fact
that radio regulations in different countries tend to be partially incompatible. These regulations
can vary widely in terms of frequency bands, power limits, emission standards, and licensing
requirements. In some cases, these regulations can even appear complex or convoluted.
All of these factors conspire to create a technology landscape where modem manufacturers are compelled
to produce highly capable and highly configurable units. These modems need to be adaptable to different
regulatory environments and network infrastructures. They often take on very different characteristics
when loaded with firmware and configured for use in specific regions.

Given the complexity of the tasks that cellular modems are required to perform, it's no surprise that
they have evolved into self-contained computers with sophisticated internal states. This comparison
with remote computers or servers is particularly apt because of the way you interact with these
devices. Cellular modems often operate in a manner similar to remote cloud services, relying heavily
on APIs (Application Programming Interfaces) for communication and control. Instead of directly
interfacing with the host Linux kernel or operating system, you typically communicate with a cellular
modem using specialized protocols and APIs like AT commands,
[MBIM (Mobile Broadband Interface Model)](https://modemmanager.org/docs/libmbim/mbim-protocol/),
or [QMI (Qualcomm MSM Interface)](https://en.wikipedia.org/wiki/Qualcomm_MSM_Interface).
These APIs allow you to send and receive data, manage connections, and configure various modem
functions, offering a high level of control and customization.

Currently, EVE stays away from managing modem's firmware and expects a modem unit to be fully
configured by a hardware manufacturer to (preferably) provide a QMI or MBIM interface.

### wwan microservice

All components responsible for managing cellular modem devices and connections (including 3G, 4G, and 5G)
are enclosed within a self-contained [wwan container](../pkg/wwan). In the initial stages of development,
we constructed a rather limited management agent using a shell script, which controlled modems
through CLI (Command Line Interface) tools provided by the [libqmi](https://www.freedesktop.org/wiki/Software/libqmi/)
and [limbim](https://www.freedesktop.org/wiki/Software/libmbim/) libraries. Several releases later,
[we made the strategic decision](https://wiki.lfedge.org/display/EVE/ModemManager+Evaluation)
to transition to the use of [ModemManager](https://modemmanager.org/), aligning with the approach
adopted by many standard Linux distributions. In doing so, we only had to implement a lightweight
agent in Go, called [mmagent](../pkg/wwan/mmagent), which serves as an intermediary, facilitating
translations between the EVE API and ModemManager API.

For a comprehensive understanding of the wwan microservice's implementation details, we encourage
you to consult the documentation available at [wwan/README.md](../pkg/wwan/README.md).

### Cellular configuration

Cellular configuration for a given modem is defined within the `CellularConfig` proto message,
as specified in [netconfig.proto](https://github.com/lf-edge/eve-api/blob/main/proto/config/netconfig.proto).
To accommodate future multi-SIM capabilities, the formerly used singleton attribute `APN` has been
deprecated. Instead, the configuration now entails an array of `CellularAccessPoint` entries,
one for each SIM slot. Presently, it is typical to have only a single entry in this list submitted
by the controller.

Beyond specifying the Access Point Name (APN), this versatile configuration allows for fine-tuning
access points, including options for PAP or CHAP-based username/password authentication,
toggling roaming on or off, designating preferred network operators, and establishing an order
of preference for Radio Access Technologies (RATs). This comprehensive API empowers users to tailor
cellular connectivity settings to suit various network scenarios and SIM card configurations.

### Cellular info and metrics

The list of all cellular modems visible to the host (incl. the unused ones, without network config attached),
is published in `ZInfoDevice.cell_radios`. The `name` of each modem is simply a string that EVE guarantees
to be unique among all the modems in the list (for example IMEI if available). Information provided for each
modem may include IMEI (a globally unique modem ID), hardware model, firmware version, operating state
([radio silence](#radio-silence) is one of the states) and the protocol used for management (QMI or MBIM).

The list of all SIM cards inserted into cellular modems is published in `ZInfoDevice.sims`. The `name` of each
SIM card is simply a string that EVE guarantees to be unique among all the SIM cards in the list (for example
ICCID if available). Information provided for each SIM card may include ICCID (a globally unique SIM ID),
IMSI (a mobile subscriber identity) and a reference to the name of the modem to which it is inserted.
SIM card state is a string instead of enum because the set of possible values differs between QMI and MBIM.
But some SIM states are common:

* `absent`: SIM card is not present in the SIM slot.
* `present`: SIM card is present in the SIM slot (and there is no issue detected).
* `inactive` : SIM slot is not activated (SIM card presence may be unknown).
* `error`: SIM slot/card is in failed state.

Every device port associated with a cellular modem has `wireless_status` defined.
It contains references to the names of the modem and the SIM card(s) being used, information
about the currently used network provider (identified by PLMN code), and potentially,
error messages if EVE failed to apply the last configuration for this port or if connectivity
testing is failing.

It is also possible to request information about all visible providers by enabling
the [configuration property](CONFIG-PROPERTIES.md) `wwan.query.visible.providers`.
By default, this feature is disabled because the operation to scan visible cellular providers
is quite expensive and takes around 2 minutes to complete, during which the modem is practically
unmanageable. Therefore, even if enabled, the period for re-scanning visible providers
is quite long: 1 hour. For the user, it makes sense to enable scanning only temporarily,
for example, when troubleshooting a modem that is failing to register on the network.

EVE also collects metrics from cellular modems (i.e. stats recorded by modems themselves, not from the Linux
network stack). These are published in `deviceMetric.cellular`.  Included are packet and byte RX/TX
counters, drop/error counters and information about the signal strength: RSSI, RSRQ, RSRP, SNR.
Note that with MBIM control protocol, only RSSI is available. The maximum value of int32 (`0x7FFFFFFF`)
represents unspecified/unavailable metric (zero is a valid value).

### Frequencies and antennas

At some point you will have to care about frequencies and antennas. Most Sierra Wireless modems
support all frequencies and both FDD-LTE and TDD-LTE (which are just two different ways of splitting
upstream and downstream bandwidth). You can check on [cellmapper.net](https://www.cellmapper.net)
which channels are supported by the cell towers near you and look up the corresponding frequencies
[here](https://en.wikipedia.org/wiki/Cellular_frequencies).
You can then either get a wideband antenna that covers all the frequencies supported
by your modem and the cell tower, or you can pick one or two frequencies and get an antenna
for just those frequencies. Usually wideband antennas that support multiple frequencies
don't have as much gain. You might want to try forcing your modem to use each of the frequencies
in turn and check the bandwidth during peak times before you decide on the best antenna.

For the MC7455 you will probably need pigtails (antenna adaptors) from u.fl to either SMA or N-type
connectors depending on your antenna. Other modems like the EM7565 use MHF4 connectors
instead of u.fl. Remember that the longer the cable from your modem to the antenna, the more signal
you will lose.

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
[Radio endpoint](https://github.com/lf-edge/eve-api/tree/main/PROFILE.md#Radio), to periodically
obtain the required state of the radio silence mode and to publish the actual state. Intentionally,
it is not possible to enable or disable radio silence remotely through the controller. Still,
the controller is at least used to deploy the application, mark it as a Local profile server
and to specify string token that the application will have to present to EVE with each request
to authenticate itself. This is submitted to the edge node using the `local_profile_server` and
`profile_server_token` fields from `EdgeDevConfig`.

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
the [RadioStatus](https://github.com/lf-edge/eve-api/blob/main/proto/profile/local_profile.proto)
proto message. This includes the state of the radio silence mode, information about cellular modem(s)
and SIM card(s), signal strength metrics and packets counters as recorded by modem(s).
Note that currently the state information is limited to cellular connectivity and does not cover
WiFi network adapters.

If a response from the application contains no content (response code 204), EVE assumes
that the intended radio silence state has not changed (initial intended state is a disabled
radio silence).
Application response with non-empty content (response code 200) is unmarshalled into
[RadioConfig](https://github.com/lf-edge/eve-api/tree/main/proto/profile/local_profile.proto)
protobuf message. If the unmarshalling succeeded and the token matches the expected value
configured through the controller, EVE will accept the new radio configuration. Currently,
apart from the token, RadioConfig contains only a single boolean field which determines
if the radio silence should be imposed or lifted.

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
will repeat a pattern of blinking 5 times in a row. The pattern is the same regardless of what state
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
* Cellular modem must be [supported by ModemManager](https://www.freedesktop.org/wiki/Software/ModemManager/SupportedDevices/),
  otherwise it will not be recognized and the radio transmission will remain in the modem's
  default state (which usually is ON).
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
