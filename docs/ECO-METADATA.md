# EVE meta-data server for app instances

EVE provides an old method to serve cloud-init meta-data in the form of a read-only CDROM disk which is created on the fly when an app instance is booted if the API specifies userData/cipherData in the [AppInstanceConfig message](../api/proto/config/appconfig.proto).

However, there is also a need to provide access to meta-data which might change while the app instance is running.

The first data which is needed by applications is determining the external IP address of the edge node, so that when there is a portmap ACL in place the application instance can determine which IP plus port its peers should use to connect to it.

The initial meta-data service provides merely that, but over time we expect to add the rest of the cloud-init content.

## Schema

There is no existing industry standard schema specifying a notion of an external IP; existing schemas contain public and private IP addresses but the external IP is a different thing necessitated by the internal NAT which EVE deploys for the local network instances.

Thus this particular part of the meta-data uses a EVE-unique schema, which we do not expect for other meta-data information.

The API endpoint is <http://169.254.169.254/eve/v1/network.json>

The returned json contains

- caller-ip: a string with the IP address and TCP port of the requesting app instance
- external-ipv4: a string with the external IPv4 address
- hostname: a string with the UUID hostname assigned to the app instance

Note that there is no need to specify the application instance identity since the meta-data server in EVE determines that from the virtual network adapter the application instance is using to communicate with EVE.

## Example usage

curl <http://169.254.169.254/eve/v1/network.json>

{"caller-ip":"10.1.0.2:39380","external-ipv4":"192.168.1.10","hostname":"afa43e51-56b7-4021-a5fa-4272b0381913"}

## Application instances with multiple network interface adapters

If an application instance has multiple network adapters it needs to specify a particular one by explicitly connecting out over a given adapter.
With curl that is done using the --interface option, e.g.,

curl --interface eth0 <http://169.254.169.254/eve/v1/network.json>

## Additional API endpoints

The schema also provides an API endpoint to avoid parsing json, however this endpoint might be deprecated in the future.

curl <http://169.254.169.254/eve/v1/external_ipv4>

192.168.1.10

## Location API endpoint

Meta-data service allows applications to obtain geographic coordinates of the device,
determined using Global Navigation Satellite Systems. This is available only if device
has a supported LTE modem with an integrated GNSS receiver (e.g. Sierra Wireless EM7565).
Standalone GPS receivers are currently not supported.

However, by default EVE does not use the location service of the LTE modem and the location
information is therefore not available.
To enable location reporting for the device, the `wwan*` adapter (corresponding to the LTE modem)
must be **configured as port shared between applications and/or for device management** with
**location tracking** enabled. When the modem is disabled or directly assigned to an application,
EVE is not able to access the location service and obtain location information.
In EVE API this is done by setting the field `NetworkConfig.wireless.cellularCfg.location_tracking`
to `true`. For more details refer to [netconfig.proto](../api/proto/config/netconfig.proto).

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

The frequency at which EVE updates location information is configurable using the option
[timer.location.app.interval](../docs/CONFIG-PROPERTIES.md). By default, the interval is 20
seconds. This means that with a good continuous reception of the GNSS signal, the geographic
coordinates presented to applications are never older than 20 seconds.
