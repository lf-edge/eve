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
