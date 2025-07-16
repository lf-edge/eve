# evetest-lps

A Local Profile Server (LPS) implementation for EVE integration testing.

This container application implements the
[LPS API specification](https://github.com/lf-edge/eve-api/blob/main/PROFILE.md)
and adds a management REST API and a web UI for controlling the server and
inspecting data received from EVE.

## Architecture

A single HTTP server runs on port **8888** with three path groups:

- `/api/v1/` -- LPS protocol endpoints (protobuf binary + one NDJSON
  stream, consumed by EVE)
- `/manage/v1/` -- Management REST API (JSON polling endpoints + one
  Server-Sent Events stream, for tests, programmatic control, and the UI)
- `/ui/` -- Web UI (push-driven page for human operators)

The container also runs an SSH daemon (port 22, `root:testpassword`) and uses
bash as PID 1 so that EVE console access works.

## LPS Protocol Endpoints

These implement the EVE LPS specification. Non-streaming endpoints use
`application/x-proto-binary` for both request and response bodies; the
`/api/v1/signal` stream uses `application/x-ndjson`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/local_profile` | Retrieve local profile |
| POST | `/api/v1/radio` | Publish radio status, get radio config |
| POST | `/api/v1/appinfo` | Publish app info, get app commands |
| POST | `/api/v1/devinfo` | Publish device info, get device command |
| POST | `/api/v1/location` | Publish GNSS location |
| POST | `/api/v1/network` | Publish network info, get local network config |
| POST | `/api/v1/appbootinfo` | Publish app boot info, get boot config |
| GET | `/api/v1/signal` | Long-lived NDJSON stream of pending-change notifications |

Protobuf definitions:

- [local_profile.proto][lp-proto]
- [network.proto][net-proto]
- [signal.proto][sig-proto]

## Management REST API

All endpoints use JSON encoding. GET endpoints return data that EVE has posted
to the LPS. PUT endpoints configure what the LPS sends back to EVE.

### Reading state

| Method | Path | Description |
|--------|------|-------------|
| GET | `/manage/v1/status` | Full state (config + all received data) |
| GET | `/manage/v1/config` | Current LPS config (token, profile, etc.) |
| GET | `/manage/v1/radio-status` | Last radio status from EVE |
| GET | `/manage/v1/appinfo` | Last app info list from EVE |
| GET | `/manage/v1/devinfo` | Last device info from EVE |
| GET | `/manage/v1/location` | Last location from EVE |
| GET | `/manage/v1/network` | Last network info from EVE |
| GET | `/manage/v1/appbootinfo` | Last app boot info from EVE |

GET endpoints return `404` if EVE has not yet posted data for that endpoint.

### Setting config

| Method | Path | Body (JSON) | Description |
|--------|------|-------------|-------------|
| PUT | `/manage/v1/token` | `{"token": "..."}` | Set server token |
| PUT | `/manage/v1/profile` | `{"profile": "..."}` | Set local profile |
| PUT | `/manage/v1/radio-config` | `{"radioSilence": true}` | Set radio silence |
| PUT | `/manage/v1/app-command` | [`AppCommand[]`][lp-proto] | Set app commands |
| PUT | `/manage/v1/dev-command` | [`LocalDevCmd`][lp-proto] | Set device command |
| PUT | `/manage/v1/app-boot-config` | [`AppBootConfig[]`][lp-proto] | Set app boot configs |
| PUT | `/manage/v1/network-config` | [`LocalNetworkConfig`][net-proto] | Set local network config |

[lp-proto]: https://github.com/lf-edge/eve-api/blob/main/proto/profile/local_profile.proto
[net-proto]: https://github.com/lf-edge/eve-api/blob/main/proto/profile/network.proto
[sig-proto]: https://github.com/lf-edge/eve-api/blob/main/proto/profile/signal.proto

#### Examples

Set the server token:

```bash
curl -X PUT -d '{"token":"my-secret"}' http://localhost:8888/manage/v1/token
```

Set a local profile:

```bash
curl -X PUT -d '{"profile":"office"}' http://localhost:8888/manage/v1/profile
```

Submit local network config (MTU override for one port):

```bash
curl -X PUT -H 'Content-Type: application/json' -d '{
  "serverToken": "my-secret",
  "ports": [
    {
      "logicalLabel": "ethernet1",
      "useDhcp": true,
      "mtu": 9000
    }
  ]
}' http://localhost:8888/manage/v1/network-config
```

Issue a device shutdown command:

```bash
curl -X PUT -d '{"timestamp":1234567890,"command":"COMMAND_SHUTDOWN"}' \
  http://localhost:8888/manage/v1/dev-command
```

Read the latest network info posted by EVE:

```bash
curl -s http://localhost:8888/manage/v1/network | jq .
```

### Event stream

| Method | Path | Description |
|--------|------|-------------|
| GET | `/manage/v1/events` | Server-Sent Events stream of live state changes |

`GET /manage/v1/events` is a push endpoint that delivers the current
LPS state (both config and received-from-EVE data) as Server-Sent
Events, so clients do not need to poll. Two event names are used:

- `event: snapshot` -- the full state, sent once on connect.
- `event: update` -- the full state, sent whenever anything changes
  (either a `/manage/v1/*` PUT or a new `/api/v1/*` post from EVE).

The payload in each `data:` line is the same JSON shape as
`GET /manage/v1/status`, with proto-typed fields serialized via canonical
protobuf JSON (camelCase, RFC3339 timestamps, symbolic enums, flattened
oneofs). Periodic SSE comment lines (`: heartbeat`) keep idle proxies
from dropping the connection.

Example (with `curl -N` to disable output buffering):

```bash
curl -N http://localhost:8888/manage/v1/events
```

## Web UI

Navigate to `http://<host>:8888/ui/` (or just `/` which redirects there).

The UI consumes the `/manage/v1/events` SSE stream and updates within
milliseconds of any state change -- no polling, no artificial latency.
A small indicator in the header shows whether the live-updates
connection is currently established.

The UI provides:

- **Monitoring panel** -- live display of all data EVE posts (device
  info, app info, radio status, location, network info, app boot info).
- **Control panel** -- forms to set the server token, local profile,
  radio silence, device commands, app commands, and local network
  configuration.

For local network configuration, the port-label field is a dropdown
populated from `NetworkInfo.latest_config`, so the operator can only
target ports that EVE has actually reported. Ports for which the
controller has not granted permission (proto field
`local_modifications_allowed = false`) appear in the dropdown as
"port-name (locked)", greyed out and non-selectable.
If a port becomes locked *after* a card has been added for it, that
card's inputs are disabled and a notice replaces the editable area.

## Building and Pushing

```bash
make build            # builds docker image
make push             # builds and pushes to Docker Hub
REPO=myrepo make push # use a different Docker Hub repository
```

## Command-line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `8888` | HTTP server port |
| `-token` | (empty) | Initial server token |
