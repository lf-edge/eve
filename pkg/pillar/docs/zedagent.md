# zedagent Microservice

`zedagent` is a central microservice responsible for retrieving, parsing and validating
the edge-node configuration and orchestrating communication with the controller, LOC
(Local Operator Console) and LPS (Local Profile Server).

## Responsibilities

- **Device configuration management**
  - Retrieves, parses, and validates edge-node configuration.
  - Periodically fetches device configuration from the cloud controller.
  - If the controller is unreachable and LOC is configured, attempts to fetch
    the configuration from LOC.
  - Publishes device configuration through pubsub to other microservices,
    split into logical parts, e.g.:
    - `DevicePortConfig` – networking configuration
    - `AppInstanceConfig` – application configuration
    - `NetworkInstanceConfig` – network instance configuration
    - `VolumeConfig` – volume configuration
    - etc.
  - Other microservices subscribe to the parts they are responsible for and apply
    configuration changes.

- **Information and metrics publishing**
  - zedagent subscribes to status, info, and metrics messages from other microservices,
    aggregates the relevant data, converts them to the appropriate protobuf messages,
    and publishes them to the controller and, if configured, to the LOC.
  - Runs separate Go routines (tasks) to publish info messages on change:
    - Device info
    - Network instance info
    - Volume info
    - App info
    - etc.
  - Publishes metrics such as resource utilization, packet counters, etc.

- **Certificate management**
  - Runs a Go routine to periodically fetch the latest controller certificate.
  - Also fetches certificates whenever signature verification fails, potentially
    indicating that the local copy of certificates is obsolete.

## Local Profile Server (LPS) Support

`zedagent` contains a component called **LocalCmdAgent**, which manages interaction
with LPS. Key points:

- LPS typically runs as an application on the same edge-node (see [LPS documentation](../../../docs/LPS.md)).
- `LocalCmdAgent` periodically performs a GET request to fetch the current local profile
  override from LPS (which determines the subset of applications to activate).
- `LocalCmdAgent` periodically publishes info messages to LPS:
  - Device info
  - App info
  - Wireless info
  - Location
- LPS may respond with commands to be executed locally:
  - Enable or disable radio silence
  - Reboot app / edge-node
  - Purge app
  - Shutdown applications
  - Device Power-off
  - Collect debug information (`collect-info.sh`)
- `LocalCmdAgent` checks the received LPS token, timestamps (if used in the given LPS endpoint),
  and calls `Apply*` methods on `zedagent`.
- `zedagent` publishes updated configuration via pubsub to the microservices responsible
  for applying the changes.
- Status messages are received back through pubsub, which `LocalCmdAgent` monitors to report
  operation success/failure to LPS.

```text
┌────────────────┐   LPS config (URL, token)    ┌──────────┐  publish info, status  ┌───────┐
│    zedagent    │ ───────────────────────────► │ LocalCmd │ ─────────────────────► │  LPS  │
│ (microservice) │                              │  Agent   │                        │ (App) │
│                │    Apply profile, commands   │          │  get profile, commands │       │
└───────┬────────┘ ◄─────────────────────────── └──────────┘ ◄───────────────────── └───────┘
        │                                            ▲
        │ publish controller config                  │
        │ merged with local config                   │ status reported from microservices
        │                                            │ handling the local commands
        ▼                                            │
┌────────────────┐                                   │
|     pubsub     |───────────────────────────────────┘
└────────────────┘
```
