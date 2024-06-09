# Verifier

This directory contains the verifier. The directory structure follows the pattern of all EVE pillar services as follows:

* [`lib/`](./lib/) contains core logic, has no dependency on being called command-line or pubsub. It is simply functions that can be called to handle file verification.
* [`pubsub/`](./pubsub/) contains functions to handle pubsub messages, including all handlers.
* [`cmd/`](./cmd/) contains CLI commands and sub-commands, all in package `main`. Can be called is `go run ./cmd`. Call either functions in `pubsub/` or `lib/` depending on the command.
* [`run.go`](./run.go) is the entrypoint for calling as part of zedbox, exposes the implementation of [`types.AgentRunner`](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar/types#AgentRunner).

To run as a CLI:

```bash
go run ./cmd
```

To include as a pubsub library elsewhere, like in pillar:

```go
import (
    "github.com/lf-edge/eden/pkg/verifier"
)

func main() {
    verifier.Run(pubSubImpl, logrusLogger, baseLogObject, []string{argument1, argument2})
}
```
