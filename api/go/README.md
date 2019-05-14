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
)
```

To build, go to the root directory of this repository and:

```bash
make proto
```

To vendor the result into pillar (or any other go pacakge), go to the root directory of this repository and:

```bash
make proto-vendor
```
