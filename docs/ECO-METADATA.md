# EVE metadata server for app instances

EVE provides an old method to serve cloud-init metadata in the form of a read-only CDROM disk which is created on the fly when an app instance is booted if the API specifies userData/cipherData in the [AppInstanceConfig message](https://github.com/lf-edge/eve-api/tree/main/proto/config/appconfig.proto).

However, there is also a need to provide access to metadata which might change while the app instance is running.

The first data which is needed by applications is determining the external IP address of the edge node, so that when there is a portmap ACL in place the application instance can determine which IP plus port its peers should use to connect to it.

The initial metadata service provides merely that, but over time we expect to add the rest of the cloud-init content.

## Access Limitation

The metadata server endpoints (e.g. <http://169.254.169.254/eve/v1/network.json> and <http://169.254.169.254/eve/v1/external_ipv4>) are only accessible over a **local network instance** (the built-in host-NAT network). These endpoints are **not** available if the app or VM is running on a "switch network" or an "app-direct" network.

*See "Networking Modes" in the main EVE architecture guide for more details on local vs. switch/app-direct network.*

## Schema

There is no existing industry standard schema specifying a notion of an external IP; existing schemas contain public and private IP addresses but the external IP is a different thing necessitated by the internal NAT which EVE deploys for the local network instances.

Thus this particular part of the metadata uses an EVE-unique schema, which we do not expect for other meta-data information.

The API endpoint is <http://169.254.169.254/eve/v1/network.json>

The returned json contains

- caller-ip: a string with the IP address and TCP port of the requesting app instance
- external-ipv4: a string with the external IPv4 address
- hostname: a string with the UUID hostname assigned to the app instance
- app-instance-uuid: a string with the app instance UUID
- device-uuid: a string with the device UUID
- device-name: a string with the device name
- project-uuid: a string with the UUID of the project the device is associated with
- project-name: a string with the name of the project the device is associated with
- enterprise-id: a string with the id of the enterprise the device is associated with
- enterprise-name: a string with the name of the enterprise the device is associated with

Note that there is no need to specify the application instance identity since the metadata server in EVE determines that from the virtual network adapter the application instance is using to communicate with EVE.

## Example usage

curl <http://169.254.169.254/eve/v1/network.json>

{"caller-ip":"10.1.0.2:39380","external-ipv4":"192.168.1.10","hostname":"afa43e51-56b7-4021-a5fa-4272b0381913", "app-instance-uuid":"afa43e51-56b7-4021-a5fa-4272b0381913","device-uuid":"6c6cb828-b0be-4166-9daf-ab353430dbc1","device-name":"test-system","project-name":"test-project","project-uuid":"4d12659e-6c9f-44bc-8e98-d525347afae6","enterprise-name":"testing","enterprise-id":"AAFlABBtJ0mP_lhJjIyVzjzgMXiR"}

## Application instances with multiple network interface adapters

If an application instance has multiple network adapters it needs to specify a particular one by explicitly connecting out over a given adapter.
With curl that is done using the --interface option, e.g.,

curl --interface eth0 <http://169.254.169.254/eve/v1/network.json>

## Additional API endpoints

The schema also provides an API endpoint to avoid parsing json, however this endpoint might be deprecated in the future.

curl <http://169.254.169.254/eve/v1/external_ipv4>

192.168.1.10

## Location API endpoint

Metadata service allows applications to obtain geographic coordinates of the device,
determined using Global Navigation Satellite Systems. This is available only if device
has a supported LTE modem with an integrated GNSS receiver (e.g. Sierra Wireless EM7565).
Standalone GPS receivers are currently not supported.

However, by default EVE does not use the location service of the LTE modem and the location
information is therefore not available.
To enable location reporting for the device, the cellular modem adapter must be **configured as port
shared between applications and/or for device management** with **location tracking** enabled.
When the modem is disabled or directly assigned to an application, EVE is not able to access
the location service and obtain location information.
In EVE API this is done by setting the field `NetworkConfig.wireless.cellularCfg.location_tracking`
to `true`. For more details refer to [netconfig.proto](https://github.com/lf-edge/eve-api/tree/main/proto/config/netconfig.proto).

Provided that location tracking is enabled and the device has a good reception of GNSS signal,
a JSON-formatted location information is made available to all applications on the
`/eve/v1/location.json` endpoint.

For example:

```shell
curl 169.254.169.254/eve/v1/location.json 2>/dev/null | jq
{
  "logical-label": "wwan0",
  "latitude": 52.517679,
  "longitude": 13.377630,
  "altitude": 25.045,
  "utc-timestamp": 1650546498420,
  "horizontal-uncertainty": 16.000,
  "vertical-uncertainty": 25.100,
  "horizontal-reliability": "medium",
  "vertical-reliability": "low"
}
```

Logical label refers to the device which was used to obtain location coordinates.
If the GNSS receiver is integrated with an LTE modem, then this is the logical
label of the modem.
Geographic coordinates latitude and longitude are expressed using
[decimal degrees (DD) notation](https://en.wikipedia.org/wiki/Decimal_degrees),
with double-precision floating-point values. Note that if latitude or longitude
is not known, EVE will not update the published location information. This means
that the published location represents the last known position and applications
can use the attached UTC timestamp to determine when it was obtained.
If EVE has not been able to determine device location even once since the boot,
the API endpoint will return empty content with the HTTP code 204.
Altitude is in meters w.r.t. mean sea level. Just like latitude and longitude, it is
a floating-point value with double-precision. Value of -32768 is reported when altitude
is not known.
UTC timestamp is a unix timestamp in milliseconds, recorded by the GNSS clock.
Note that the limitation of having only millisecond resolution for the timestamp is imposed
by the QMI protocol, which is used to obtain the location information.
Zero value represents unavailable UTC timestamp.
Uncertainty and reliability fields describe how accurate the provided location information is.
(Circular) Horizontal uncertainty as well as vertical uncertainty are both in meters
with single-precision floating-point values. Negative values are not valid and represent
unavailable uncertainty.
Reliability is one of: `not-set` (unavailable), `very-low`, `low`, `medium` and `high`.
Note that Uncertainty and Reliability are no longer available in newer EVE versions
(returned are zero values).

The frequency at which EVE updates location information is configurable using the option
[timer.location.app.interval](../docs/CONFIG-PROPERTIES.md). By default, the interval is 20
seconds. This means that with a good continuous reception of the GNSS signal, the geographic
coordinates presented to applications are never older than 20 seconds.

## Cellular connectivity metadata

Using metadata server, applications are able to request information about the current state
of the cellular connectivity of the device. This covers all wireless wide area networks (WWANs)
configured for the device, with information about the installed cellular equipment (modem(s)
and SIM card(s)), identity information (IMEI, IMSI, ICCID), available network providers (PLMNs),
signal strength metrics (RSSI, RSRP, etc.), packet stats (RX/TX counters) and more.

This is split between two API endpoints:

- `/eve/v1/wwan/status.json`
- `/eve/v1/wwan/metrics.json`

The rationale is that metrics are much more dynamic and frequently changing, therefore they are
expected to be requested more often than status information. It would be therefore inefficient
to post status attributes alongside metrics.

### WWAN Status API endpoint

JSON-formatted WWAN-related status information can be requested by applications on the
`/eve/v1/wwan/status.json` endpoint.

For example:

```shell
curl 169.254.169.254/eve/v1/wwan/status.json 2>/dev/null | jq
{
  "networks": [
    {
      "logical-label": "wwan0",
      "physical-addrs": {
        "interface": "wwan0",
        "usb": "1:1",
        "pci": "0000:00:1d.7"
      },
      "cellular-module": {
        "imei": "353533102301374",
        "model": "EM7565",
        "revision": "SWI9X50C_01.08.04.00 dbb5d0 jenkins 2018/08/21 21:40:11",
        "control-protocol": "qmi",
        "operating-mode": "online-and-connected"
      },
      "sim-cards": [
        {
          "iccid": "8942104393400779111",
          "imsi": "231063511665993"
        }
      ],
      "config-error": "",
      "probe-error": "",
      "providers": [
        {
          "plmn": "231-01",
          "description": "Orange",
          "current-serving": false,
          "roaming": true
        },
        {
          "plmn": "231-03",
          "description": "SWAN SK",
          "current-serving": false,
          "roaming": true
        },
        {
          "plmn": "231-02",
          "description": "Telekom",
          "current-serving": false,
          "roaming": true
        },
        {
          "plmn": "231-06",
          "description": "Tesco - SK",
          "current-serving": false,
          "roaming": false
        },
        {
          "plmn": "231-06",
          "description": "Tesco - SK",
          "current-serving": true,
          "roaming": false
        }
      ]
    }
  ]
}
```

The underlying structure, used by EVE to store the information and output it as JSON,
is named `WwanStatus` and can be found in [wwan.go](../pkg/pillar/types/wwan.go).

The endpoint returns a list of entries, one for every cellular modem, with the modem's
logical label (from the device model) used as a reference. The physical connection between
the device and the modem is described by the provided physical addresses. For example,
`physical-addrs.usb` is a USB address in the format `<BUS>:[<PORT>]` (with nested ports
separated by dots), identifying the USB port through which the modem is connected with the device.

Information about the cellular modem is summarized inside the `cellular-module` structure.
It provides the modem identification number (`IMEI`), describes the hardware model (`model`)
and the version of the running firmware (`revision`).
`control-protocol` is either `qmi` or `mbim`, and it is the protocol used by EVE to manage
the modem.
`operating-mode` is one of: `online` (modem is online but not connected), `online-and-connected`
(modem is online and connected), `radio-off` (modem has disabled radio transmission), `offline`
(modem is offline), `unrecognized` (unrecognized operating mode).

The set of SIM cards inserted into the modem is listed under `sim-cards`. Included is
the identification number of the subscriber (`IMSI`) and the SIM card itself (`ICCID`).

If EVE fails to configure modem and put it into a desired state, `config-error` will explain
what exactly went wrong.
If enabled, EVE will periodically test connectivity by running a ping towards a remote
endpoint (with configurable address). If the last probing failed, `probe-error` will contain an error
message.

Lastly, the set of available network providers is listed under `providers`.
Each of them is referenced by the Public land mobile network (PLMN) code, identifying a country,
and a mobile network operator in that country. If the modem is connected to one of the networks,
that network will have attribute `current-serving` returned as `true`.

### WWAN Metrics API endpoint

JSON-formatted WWAN-related metrics can be requested by applications on the
`/eve/v1/wwan/metrics.json` endpoint.

For example:

```shell
curl 169.254.169.254/eve/v1/wwan/metrics.json 2>/dev/null | jq
{
  "networks": [
    {
      "logical-label": "cell-modem0",
      "physical-addrs": {
        "interface": "wwan0",
        "usb": "1:1",
        "pci": "0000:00:1d.7"
      },
      "packet-stats": {
        "rx-bytes": 504,
        "rx-packets": 6,
        "rx-drops": 0,
        "tx-bytes": 504,
        "tx-packets": 6,
        "tx-drops": 0
      },
      "signal-info": {
        "rssi": -60,
        "rsrq": -13,
        "rsrp": -87,
        "snr": 116
      }
    }
  ]
}
```

The underlying structure, used by EVE to store the information and output it as JSON,
is named `WwanMetrics` and can be found in [wwan.go](../pkg/pillar/types/wwan.go).

The endpoint returns a list of entries, one for every cellular modem, with the modem's
logical label (from the device model) used as a reference. Just like in the
[WWAN status API endpoint](#wwan-status-api-endpoint), the physical connection between
the device and the cellular modem is described by the `physical-addrs` structure.

Packet statistics contain RX/TX packet/byte counters (all `uint64`) as recorded by the modem itself.
This may differ from the Linux kernel counters (from `networkMetric` proto message) if, for example,
some packets were dropped by the modem.

Cellular signal strength is described using multiple different measurements:

- Received signal strength indicator (RSSI) measured in dBm (decibel-milliwatts)
- Reference Signal Received Quality (RSRQ) measured in dB (decibels)
- Reference Signal Receive Power (RSRP) measured in dBm (decibel-milliwatts)
- Signal-to-Noise Ratio (SNR) measured in dB (decibels)

All measurements are of type `int32`. Measured values are rounded to the nearest integers
(by the modem) and published without decimal places. The maximum value of `int32` (`0x7FFFFFFF`)
represents unspecified/unavailable metric.

### Network Status and Metrics endpoint

Applications might require to fetch data about the status and metrics of
network interfaces from the Edge Node. The endpoint `eve/v1/networks/metrics.json`
provides relevant information about all (used) device ports, which includes
physical (e.g. ethernet, WiFi, modems) and virtual interfaces created on
top of the physical ones - VLANs and LAGs. Virtual interfaces used for
applications connectivity (bridges, TAPs, etc.) are not included.

Example of usage:

```shell
curl -s http://169.254.169.254/eve/v1/networks/metrics.json | jq
```

```json
[
  {
    "IfName": "eth0",
    "Up": true,
    "TxBytes": 3640643,
    "RxBytes": 15997359,
    "TxDrops": 0,
    "RxDrops": 0,
    "TxPkts": 17745,
    "RxPkts": 25705,
    "TxErrors": 0,
    "RxErrors": 0,
    "TxACLDrops": 0,
    "RxACLDrops": 0,
    "TxACLRateLimitDrops": 0,
    "RxACLRateLimitDrops": 0
  },
  {
    "IfName": "eth1",
    "Up": true,
    "TxBytes": 2754016,
    "RxBytes": 1520664,
    "TxDrops": 0,
    "RxDrops": 0,
    "TxPkts": 7815,
    "RxPkts": 7783,
    "TxErrors": 0,
    "RxErrors": 0,
    "TxACLDrops": 0,
    "RxACLDrops": 0,
    "TxACLRateLimitDrops": 0,
    "RxACLRateLimitDrops": 0
  }
]
```

Note that the metrics provided by this endpoint are collected from Linux
counters, including for modem interfaces. However, the metrics provided by
the `/eve/v1/wwan/metrics.json` endpoint are collected directly from
modems. Thus, there can be differences, for instance, if the modem is
dropping packets.

### Signer API endpoint

Applications might want to get some application-specific data signed by EVE-OS so that they can verify it was indeed generated by an app instance running on a particular device.

This can be done using a POST to `/eve/v1/tpm/signer` endpoint.
The maximum support size is 64 kbytes.
The returned object is binary with protobuf message of type `AuthContainer` carrying the signature with the embedded posted payload (possibly encrypted). This protobuf message is specified in [OBJECT-SIGNING](https://github.com/lf-edge/eve-api/tree/main/OBJECT-SIGNING.md).

### Diag API endpoint

EVE is generating diagnostic output on a console (if there is one) which summarizes the state of connectivity to the controller, device status including remote attestation state, application status and errors, and download status and errors. In some cases it might make sense to have a local application instance retrieve this information.

This can be done using a GET to `/eve/v1/diag` endpoint.
The returned object is of Context-Type text - the same text which is sent to the console.

### Patch Envelope endpoints

Applications might want to get some updates/configurations in runtime, this can be done via Patch Envelopes.
More information on what Patch Envelopes are you can find in [PATCH-ENVELOPES.md](PATCH-ENVELOPES.md) doc.
There are several endpoints which allow application to handle Patch Envelopes

Get list of available Patch Envelopes `/eve/v1/patch/description.json`
For example:

```bash
curl -X GET -v http://169.254.169.254/eve/v1/patch/description.json
[

    {
        "PatchId":"699fbdb2-e455-448f-84f5-68e547ec1305",
        "BinaryBlobs":[
            {
                "file-name":"textfile1.txt",
                "file-sha":"%FILE_SHA",
                "file-meta-data":"YXJ0aWZhY3QgbWV0YWRhdGE=",
                "url":"http://169.254.169.254/eve/v1/patch/download/699fbdb2-e455-448f-84f5-68e547ec1305/textfile1.txt"
            },
            {
                "file-name":"textfile2.txt",
                "file-sha":"%FILE_SHA%",
                "file-meta-data":"YXJ0aWZhY3QgbWV0YWRhdGE=",
                "url":"http://169.254.169.254/eve/v1/patch/download/699fbdb2-e455-448f-84f5-68e547ec1305/textfile2.txt"
            }
        ],
        "VolumeRefs":null
    }

]
```

Files represented in BinaryBlobs section can be downloaded via this endpoint
`/eve/v1/patch/download/{patch}/{file}`

Where `patch` is Patch Envelope uuid and `file` is file name of binary blob.
In example above files are `textfile1.txt` and `textfile2.txt`
For example:

```bash
curl -X GET http://169.254.169.254/eve/v1/patch/download/699fbdb2-e455-448f-84f5-68e547ec1305/textfile1.txt

%base64-encoded file contents%
```

### Prometheus '/metrics' endpoint

The /metrics endpoint provides access to system-level metrics from the EVE host where your EdgeApp is running.
These metrics are sourced directly from a Node Exporter instance, expected to be available on localhost:9100 within the EVE host.

When a client inside the EdgeApp makes a request to '/metrics', the EdgeApp transparently forwards the request to the Node Exporter
and returns the response. The metrics are in Prometheus exposition format, making them compatible with Prometheus scraping and monitoring tools.

>About Prometheus:
[Prometheus](https://prometheus.io/) is an open-source systems monitoring and alerting toolkit. It collects and stores metrics as time series data, allowing users to query, visualize, and create alerts based on those metrics.

#### Key Details

- Target: Forwards all traffic internally to localhost:9100 on the EVE host.
- Metrics Format: Prometheus-compatible plain text format.
- Metrics Scope: Host-level metrics (not EdgeApp-specific).
- Availability: Exposed within the EdgeApp.

#### Rate Limiting

To protect the system from overload, a *rate limiter* per client IP address is enforced:

- Allowed Rate: 1 request per second.
- Burst Capacity: Up to 10 requests can be handled immediately before rate limiting applies.
- Idle Timeout: 4 minutes (if no requests are made from an IP for 4 minutes, the rate limit state is reset).

Exceeding the allowed rate may result in the request being temporarily rejected with an appropriate HTTP error code (e.g., `429 Too Many Requests`).

#### Usage Example

```bash
curl -X GET http://169.254.169.254/metrics
```

This command retrieves current host system metrics.

#### Notes

- Ensure that the Node Exporter service is running and accessible at localhost:9100 on the EVE host for this endpoint to function correctly.

- This endpoint is intended for observability and monitoring purposes. Avoid frequent polling to respect rate limits and ensure system stability.
