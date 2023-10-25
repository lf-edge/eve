# Edge-View Container and APIs

EVE provides the Edge-View mainly for device and application troubleshooting tasks. It is a system-level container similar to `newlogd`, `wlan`, etc.

Edge-View as a service on EVE, it needs to receive/update user configurations from the controller; and it needs to send/update Edge-View running status to the controller.

The software integration level of Edge-View is somewhere between the services like `newlogd` and `wlan`. `newlogd` is an integral part of the EVE, while `wlan` is a generic Linux service without any specific EVE related changes. The Edge-View container runs on the EVE device and has many tasks designed specifically for EVE device and application usage, but it can also run as a normal Linux docker container on any host; the same container is used for Edge-View client runs on the user's laptop. Thus design of Edge-View container tries to minimize the interaction with the rest of the EVE system while still being configured from the controller and sending status to the controller.

This Wiki page describes the provisioning, security and status update for Edge-View in [Edge-View Doc](https://wiki.lfedge.org/display/EVE/Edge-View).

## Edge-View Configuration

Edge-View configuration is part of the EVE device configuration. It contains mainly a JWT token string and policies. When `zedagent` receives the configuration update, it will write/modify the configuration file: `/run/edgeview/edge-view-config`. The configuration prefix strings are defined in `github.com/lf-edge/eve/pkg/pillar/type/edgeviewtypes.go`.

Edge-View container has a script running, constantly monitors the configuration file content. The script will run and pass the configuration items into the edge-view programs or shut down the edge-view programs.

## Edge-View Info Status

The status of Edge-View is defined as `EdgeviewStatus` type in `github.com/lf-edge/eve/pkg/pillar/type/edgeviewtypes.go`. When there is a status change, it will update and send the Edge-View status through the info message to the controller.

For security reasons, the Edge-View container has all the volumes mounted in 'read-only' mode. But for the status update, it needs to have write access on the device. Since the EVE pub/sub infrastructure mostly read/write into the '/run/{module}' directories, the Edge-View container volume mounts the `/run/edgeview` as 'read-write' mode as an exception for publishing the Edge-View status. It publishes status in `/run/edgeview` (this is similar to the `newlogd` container publishing status into `/run/newlogd` directory).

## Logging to Event

Edge-View logging is similar to other containers. For any user command received by Edge-View, it will log the client endpoint(IP address/port), the command and its parameters. The log entry will also be tagged with object-type of `log-to-event`, and the controller can optionally process those log entries and generate them as device events or alerts.
