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

Security:

In addition to using a server_token it is recommended that ACLs/firewall rules are deployed so that the traffic to/from the local profile server can not be directed to non-local destinations.
