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

## Security

In addition to using a server_token it is recommended that ACLs/firewall rules are deployed so that the traffic
to/from the local profile server can not be directed to non-local destinations.
