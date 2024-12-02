# Monitor service implementation

The monitor service is a simple IPC server which uses a unix socket to communicate with external [rust client](../../monitor/Dockerfile) located at `pkg/monitor`. The server can send asynchronous updates about EVE status to the
connected client. The information is then used by rust client to display a TUI for the user.

## Client requests

Following requests are supported at the moment:

* `SetDPC` - sets a the current DPC with a key  set to `manual`. It is used to apply a network configuration specified by local user through TUI. `NIM` service has a special handling of `manual` DPC
* `SetServer` - updates server URL in `/config/server` file. The request fails if the node is already onboarded.

## Request/response representation

All requests and responses are sent in JSON format. Some internal EVE structures e.g. DPCList are serialized into JSON as-is and deserialized on the rust application side.
It introduces a problem in case a structure is updated on EVE side, but the rust application is not updated.
To avoid this problem a proxy structures should be created  on EVE side in future.
