# Local Profile Server (LPS)

The **Local Profile Server (LPS)** is an optional component in the EVE ecosystem.
It provides a way to perform **local control operations** on an EVE device — operations
that are more practical to manage locally than through the cloud controller.

Unlike the **Local Operator Console (LOC)**, which substitutes the cloud controller in
**air-gapped deployments** and manages the **entire device configuration (EdgeDevConfig)**,
the LPS only **complements** the controller.

- **LPS scope:** limited to local, operational commands (e.g., radio silence, app restarts,
                 graceful shutdown).
- **LOC scope:** full device config management when the cloud is unreachable, but it can
                 also **carry LPS-style operations** inside the `CompoundConfig` message.
                 This message combines the full device configuration with optional local
                 operational commands (the same format of command payloads as used for LPS).

## Purpose and Capabilities

The LPS typically runs as an **application deployed on the same edge node** that it manages.
However, it may also run externally. Its role is to:

- Periodically **receive state reports** from the device for:
  - Radio devices (e.g., WiFi, cellular modems)
  - Application instances
  - Edge device information (onboarding, status, maintenance mode, etc.)
  - Location data

- Override the global profile with a **local profile**, thereby controlling which apps are active.
  - Each app can be optionally configured with a set of profiles.
  - If the currently active profile is included **and** the controller has set `Activate=true`,
    the app will run.
  - If `Activate=false` in the controller config, the app will remain disabled regardless
    of the profile match.

- **Trigger local operational commands**, such as:
  - Enabling/disabling radio devices ([Radio Silence](WIRELESS.md#radio-silence))
  - Restarting or purging an application
  - Rebooting or shutting down the edge node gracefully

## Networking and Authentication

- **Transport:** plain HTTP (HTTPS not yet supported).
- **Default port:** `8888` (configurable).
- **Authentication:**
  - The controller provisions a **secret LPS token** to EVE.
  - The same token must be configured into LPS by the operator/admin
    (so that EVE and LPS agree on it).
  - Whenever LPS issues a command/change request, it must **include this token**.
  - EVE rejects any requests with a missing or invalid token.

## API Endpoints

LPS exposes the following REST endpoints
(see the [formal specification](https://github.com/lf-edge/eve-api/blob/main/PROFILE.md) for full details).
All endpoints use **HTTP POST**, except for the `local_profile` endpoint, which is accessed
via **HTTP GET**.

### 1. `/api/v1/local_profile`

- **From edge-node → LPS:** HTTP **GET** request for a possible local profile override.
- **From LPS → edge-node (response):** the **local profile override**, if configured
  (otherwise empty / HTTP code 204).
- **Effect:** controls which apps are activated or deactivated.
- **Interval:** EVE polls this endpoint periodically at a rate defined by `timer.config.interval`
  (default: 1 minute).

### 2. `/api/v1/radio`

- **From edge-node → LPS:** current radio state (list of wireless devices and their status + metrics).
- **From LPS → edge-node (response):** optional **radio silence configuration**.
- **Effect:** disable/enable radio transmission.
- **Interval:** every 5sec (normal), throttled to every 5min if LPS responds with *404*.
- See [Radio Silence documentation](./WIRELESS.md#radio-silence).

### 3. `/api/v1/devinfo`

- **From edge-node → LPS:** device info:
  - Node UUID
  - Edge-node state
  - Boot time, last boot reason
  - Maintenance mode reasons
  - Last applied device command timestamp
- **From LPS → edge-node (response):** optional **device command**, such as:
  - Edge-node reboot
  - Shutdown all applications
  - Graceful edge-node poweroff
  - Execute `collect-info.sh` to generate a tarball containing debug information
    and upload it to a local datastore.
- **Interval:** every 1min (normal), throttled to every 1h if LPS responds with *404*.

### 4. `/api/v1/appinfo`

- **From edge-node → LPS:** list of running app instances with:
  - UUID, version, display name
  - Current state
  - Errors (if any)
  - Last executed app command timestamp
- **From LPS → edge-node (response):** optional **app command**, e.g.:
  - Restart
  - Purge
- **Interval:** every 1min (normal), throttled to every 1h if LPS responds with *404*.

### 5. `/api/v1/location`

- **From edge-node → LPS:** current location obtained from a GNSS module integrated
  in a cellular modem (standalone GNSS receivers are not supported).
- **From LPS → edge-node (response):** none (status-only endpoint).
- **Interval:** triggered by zedagent when location changes (not periodic).

### 6. `/api/v1/network`

- **From edge-node → LPS:** current network state (configuration and status of all
  network adapters, excluding passthrough).
- **From LPS → edge-node (response):** optional locally-declared network configuration
  for one or more adapters, validated and applied by EVE if permitted by controller.
- **Effect:** enable local overrides of network adapter-level settings (IP, wireless, proxy).
  Non-overridable attributes (e.g., interface usage, cost, labels, L2 config) remain under
  controller control.
- **Interval:** every 1min (normal), throttled to every 1h if LPS responds with *404*.
- See [formal specification](https://github.com/lf-edge/eve-api/blob/main/PROFILE.md#network)

### 7. `/api/v1/appbootinfo`

- **From edge-node → LPS:** HTTP **POST** with effective boot order and source
  for each application (`AppBootInfoList`).
- **From LPS → edge-node (response):** optionally, boot configuration for one
  or more applications (`AppBootConfigList` with USB boot priority settings).
- **Effect:** Bidirectional endpoint for boot order management:
  - Allows LPS to display which configuration source "won" when multiple sources
    (LPS, Controller API, Device Property) are configured.
  - Allows LPS to send boot configuration updates in response.
- **Boot order values:**
  - `BOOT_ORDER_UNSPECIFIED`: No override - use next priority level
  - `BOOT_ORDER_USB`: Prioritize USB devices in boot order
  - `BOOT_ORDER_NOUSB`: Deprioritize USB devices (disk boots first)
- **Source values (in request):**
  - `BOOT_ORDER_SOURCE_UNSPECIFIED`: No explicit boot order configured
  - `BOOT_ORDER_SOURCE_LPS`: Set by LPS via this endpoint
  - `BOOT_ORDER_SOURCE_CONTROLLER`: Set by Controller API via `VmConfig.boot_order`
  - `BOOT_ORDER_SOURCE_DEVICE_PROPERTY`: Set by device property `app.boot.order`
- **HTTP status codes:**
  - `200`: Config included in response body
  - `204`: No changes needed; preserve current config
  - `404`: Not implemented or no config; clear cached config
- **Persistence:** Configuration is saved to disk and reapplied on EVE restart.
- **Interval:** every 1min (normal), throttled to every 1h if LPS responds with *404*.
- **Changes take effect:** On next VM restart.
- See [formal specification](https://github.com/lf-edge/eve-api/blob/main/PROFILE.md#app-boot-info)
  and [VM Boot Order documentation](./VM-BOOT-ORDER.md) for detailed usage.

## Implementation Notes

- There is currently **no open-source production-ready implementation** of the LPS.
- A **primitive console/file-based LPS** is available inside the
  [eden](https://github.com/lf-edge/eden/blob/master/tests/eclient/image/pkg/main.go) test
  framework, used for validation and development.

## Summary: LPS vs LOC

| Aspect                   | LPS (Local Profile Server)      | LOC (Local Operator Console)                    |
|--------------------------|---------------------------------|-------------------------------------------------|
| Runs on                  | Typically same edge node        | Separate non-EVE machine                        |
| Scope                    | Local operations only           | Full device config                              |
| Purpose                  | Complement cloud controller     | Replace cloud controller when unreachable       |
| Controls multiple nodes? | No (single device)              | Yes (multiple devices)                          |
| Transport                | HTTP (no TLS)                   | HTTP or HTTPS (depending on LOC implementation) |
| Signing                  | None (only token used for auth) | Config signed by the controller                 |
| Local ops support        | Yes                             | Yes (carried inside `CompoundConfig`)           |
