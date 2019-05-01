# EVE go sdk

SDK of generated message files for golang based on the protobuf message definitions in [api/](../../api/) in the root directory of this repository.

To use:

```go
import (
	"github.com/zededa/eve/sdk/zconfig"
	"github.com/zededa/api/zmet"
)
```

To build, go to the root directory of this repository and:

```
make sdk
```

You may have protobuf issues due to `.go` files in this directory and subdirectories from a previous build. To avoid that issue, run:

```
make clean-sdk
```
