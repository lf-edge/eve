# EVE go sdk

SDK of generated message files for golang based on the protobuf message definitions in [api/proto](../../api/proto) in the root directory of this repository.

To use:

```go
import (
        "github.com/lf-edge/eve/api/go/register"
        "github.com/lf-edge/eve/api/go/config"
        "github.com/lf-edge/eve/api/go/info"
        "github.com/lf-edge/eve/api/go/logs"
        "github.com/lf-edge/eve/api/go/metrics"
        "github.com/lf-edge/eve/api/go/flowlog"
)
```

To build, go to the root directory of this repository and:

```bash
make proto
```

To vendor the result into a downstream dependency, e.g. pillar, do the following:

1. Commit the changes to this directory.
1. Open a Pull Request and merge it in.
1. Go to the root directory of the downstream dependency and:
```bash
go get -u github.com/lf-edge/eve/api/go@master
go mod vendor
```

For temporary testing _only_ you can reference the local copy of the generated code by adding the following
to the end of your `go.mod`:

```go
replace github.com/lf-edge/eve/api/go => ../../api/go
```

Do **not** commit the `replace` line to your changes, as they will **not** be accepted into a PR.
