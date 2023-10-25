# Patch Envelopes

## Overview

Patch Envelopes are objects which are exposed to app instances via EVE meta-data server.
This objects can be useful to update any kind of information in a secure, isolated manner
(for instance, configuration parameters) on app instance without the need of rebooting it.
Alternatively, one can create new image for app instance, upload it to EVE, purge and restart
application instance with the new image, even if there was a small change in some configuration
file. To top that there will be a down-time during reboot of app instance. To summarise it,
patch envelopes goal is to make fleet management of app instances easier.

## Patch Envelope structure

Patch Envelope are created on controller and propagated to EVE via protobuf's `EvePatchEnvelope` message.
It consists of:

- *uuid*: uinque identified to reffer Patch Envelope object
- *action*: way this object should be treated
- *artifacts*: array of binary artifacts related to this Patch Envelope
- *appInstIdsAllowed*: list of app instances ids that can access this Patch Envelope

And other fields, for more information about additional fields in protobuf message reffer to API definition [here](https://github.com/lf-edge/eve-api/blob/main/proto/config/patch_envelope.proto)

Binary artifacts are objects that app instance can download and use (for instance, configuration files).
This artifacts are *opaque* to EVE: information is just transferred, never parsed, decoded, etc.
Currently, there are two types of Binary artifacts: *Inline* and *External*.

*Inline artifacts* are small (less or equal than 100KB) base64-encoded (not encrypted) strings with
optional meta data. They are part of Edge Device configuration.
*External artifacts* are referrencining volumes created on EVE. Size of volumes is not limited to 10KB

## How to use Patch Envelopes

When Patch Envelopes are created on controller and exposed to EVE via API, app instance can access
Patch Envelopes available to it from meta-data server using API defined in [metadata server](.ECO-METADATA.md)
