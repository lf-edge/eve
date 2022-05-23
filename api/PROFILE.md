# Local Profile API

This document defines the API for Local Profile Override.

This document is version 1, and all endpoints will begin with `/api/v1`.

## Server endpoint

EVE MUST use the server endpoint specified using the local_profile_server in [EdgeDevConfig](./proto/config/devconfig.proto) and use the associated profile_server_token to validate the responses. If no port number is specified in local_profile_server EVE MUST default to 8888.

If the local_profile_server is empty, then EVE MUST NOT invoke this API.
If the local_profile_server is cleared, then EVE MUST forget any profile information it had received from the local_profile_server.

## Mime Types

All `GET` requests MUST have no mime type set.
All `POST` requests MUST have the mime type set of `application/x-proto-binary`.
All responses with a body MUST have the mime type set of `application/x-proto-binary`.

## Endpoints

The following are the API endpoints that MUST be implemented by a profile server.

### Local Profile

Retrieve the local profile, which will override any global profile

   GET /api/v1/local_profile

Return codes:

* Valid: `200`
* Not implemented: `404`

Request:

The request MUST use HTTP for this request

The request MUST NOT contain any body content

Response:

The response mime type MUST be "application/x-proto-binary". The response MUST contain a single protobuf message of type [LocalProfile](./proto/profile/local_profile.proto).

The requester MUST verify that the response payload has the correct server_token.
If the profile is empty, it will reset any saved local profile but otherwise have no effect.

A non-empty profile will override the global_profile specified in
[EdgeDevConfig](./proto/config/devconfig.proto). The resulting current
profile will be used to determine which app instances are started and
stopped by matching against the [profile_list in AppInstanceConfig](./proto/config/appconfig.proto).

### Radio

Publish the current state of all wireless network adapters and optionally obtain radio configuration in the response:

   POST /api/v1/radio

Return codes:

* Success; with new radio configuration in the response: `200`
* Success; without radio configuration in the response: `204`
* Not implemented: `404`

Request:

The request mime type MUST be "application/x-proto-binary".
The request MUST have the body of a single protobuf message of type [RadioStatus](./proto/profile/local_profile.proto).

Response:

The response MAY contain the body of a single protobuf message of type [RadioConfig](./proto/profile/local_profile.proto)
encoded as "application/x-proto-binary".

The requester MUST verify that the response payload (if provided) has the correct server_token.
If the verification succeeds, it will apply the received radio configuration.

Device MUST stop publishing radio status until all changes in the received radio configuration are fully applied,
without any ongoing or pending operations left behind.
When device fails to apply the configuration, it SHOULD eventually stop retrying and publish the new radio status afterwards,
indicating the error condition inside the `RadioStatus.config_error` field.

### AppInfo

Publish the current state of app instances on the device to the local server and optionally obtain
a list of app commands to execute.

POST /api/v1/appinfo

Return codes:

* Success; with commands to execute as defined in the response body: `200`
* Success; without commands to execute: `204`
* Not implemented: `404`

Request:

The request mime type MUST be "application/x-proto-binary".
The request MUST have the body of a single protobuf message of type [LocalAppInfoList](./proto/profile/local_profile.proto).
Device publishes information repeatedly to keep the local server updated and to allow the server
to submit application commands for execution.
Local server MAY throttle or cancel this communication stream by returning the `404` code.

Response:

The response MAY contain the body of a single protobuf message of type [LocalAppCmdList](./proto/profile/local_profile.proto),
encoded as "application/x-proto-binary".

The requester MUST verify that the response payload (if provided) has the correct `server_token`.
If the verification succeeds, all entries of `app_commands` are iterated, and those
that successfully match a running application instance (by `id` and/or `displayname`)
are applied.

Currently, the method allows to request a locally running application instance
to be *restarted* or *purged* by EVE. This may help to resolve a case of an application
being in a broken state, and the user not being able to fix it (remotely) due to a lack
of connectivity between the device and the controller. Rather than rebooting the entire
device (locally), it is possible to restart/purge only a selected application.

A command request, as defined by `AppCommand` protobuf message, includes an important
field `timestamp` (`uint64`), which should record the time when the request was made
by the user. The format of the timestamp is not defined. It can be a Unix timestamp
or a different time representation. It is not even required for the timestamp to match
the real time or to be in-sync with the device clock.

What is required, however, is that two successive but distinct requests made for the same
application will have different timestamps attached.
This requirement applies even between restarts of the Local profile server. A request made
after a restart should not have the same timestamp attached as the previous request made
for the same application before the restart.

EVE guarantees that a newly added command request (into `LocalAppCmdList.app_commands`),
or a change of the `timestamp` field, will result in the command being triggered ASAP.
Even if the execution of a command is interrupted by a device reboot/crash, the eventuality
of the command completion is still guaranteed. The only exception is if Local Profile Server
restarts/crashes shortly after a request is made, in which case it can get lost before
EVE is able to receive it. For this scenario to be avoided, a persistence of command requests
on the side of the Local Profile server is necessary.

It is not required for the Local profile server to stop submitting command requests
that have been already processed by EVE. Using the `timestamp` field, EVE is able to determine
if a given command request has been already handled or not.
To check if the last requested command has completed, compare its timestamp with
`last_cmd_timestamp` field from `LocalAppInfo` message, submitted by EVE in the request
body of the API.

### DevInfo

Publish the current state of the device to the local server and optionally obtain
a command to execute.

POST /api/v1/devinfo

Return codes:

* Success; with a command to execute as defined in the response body: `200`
* Success; without a command to execute: `204`
* Not implemented: `404`

Request:

The request mime type MUST be "application/x-proto-binary".
The request MUST have the body of a single protobuf message of type [LocalDevInfo](./proto/profile/local_profile.proto).
Device publishes information repeatedly to keep the local server updated and to allow the server
to submit commands for execution.
Local server MAY throttle or cancel this communication stream by returning the `404` code.

Response:

The response MAY contain the body of a single protobuf message of type [LocalDevCmd](./proto/profile/local_profile.proto),
encoded as "application/x-proto-binary".

The requester MUST verify that the response payload (if provided) has the correct `server_token`.
If the verification succeeds, then the timestamp is checked to determine whether
or not the command has already been executed, and it not it is applied.

Currently, the method allows to request a graceful Shutdown (of all app instances)
or such a Shutdown followed by a Poweroff of EVE. This allows for graceful shutdown of applications and optionally a poweroff whether triggered by a user on the local profile server or a UPS interfacing with the local profile server.

The command request includes an important field `timestamp` (`uint64`), which
should record the time when the request was made
by the user. The format of the timestamp is not defined. It can be a Unix timestamp
or a different time representation. It is not even required for the timestamp to match
the real time or to be in-sync with the device clock.

What is required, however, is that two successive but distinct requests made for
the device will have different timestamps attached.
This requirement applies even between restarts of the Local profile server. A request made
after a restart should not have the same timestamp attached as the previous request made before the restart.

EVE guarantees that a newly added command request,
or a change of the `timestamp` field, will result in the command being triggered ASAP.
Even if the execution of a command is interrupted by a device reboot/crash, the eventuality
of the command completion is still guaranteed. The only exception is if Local Profile Server
restarts/crashes shortly after a request is made, in which case it can get lost before
EVE is able to receive it. For this scenario to be avoided, a persistence of command requests
on the side of the Local Profile server is necessary.

It is not required for the Local profile server to stop submitting command requests
that have been already processed by EVE. Using the `timestamp` field, EVE is able to determine
if a given command request has been already handled or not.
To check if the last requested command has completed, compare its timestamp with
`last_cmd_timestamp` field from `LocalDevInfo` message, submitted by EVE in the request
body of the API.

### Device Location Info (GNSS)

Publish the current location of the device as obtained from a GNSS receiver
to the local server.

POST /api/v1/location

Return codes:

* Success: `200`
* Not implemented: `404`

Request:

The request mime type MUST be "application/x-proto-binary".
The request MUST have the body of a single protobuf message of type [ZInfoLocation](./proto/info/info.proto).
Device publishes information repeatedly with a (default) period of 20 seconds to keep the local
server updated (configurable using [timer.location.app.interval](../docs/CONFIG-PROPERTIES.md)).
Local server MAY throttle or cancel this communication stream by returning the `404` code.

## Security

In addition to using a server_token it is recommended that ACLs/firewall rules are deployed so that the traffic
to/from the local profile server can not be directed to non-local destinations.
