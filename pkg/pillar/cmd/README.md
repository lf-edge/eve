# Agent Services

This directory contains agent services for pillar.

Each subdirectory contains exactly one agent, whose name is the name of the directory.

Look at [verifier](./verifier/) for an example of the implementation.

## Design Pattern

The design pattern for each agent is as follows. When creating a new agent, ensure
that you follow the design pattern.

The package name in the agent's directory is the same as the directory name.
It should contain at least the following files:

* `README.md` describing the agent and its purpose.
* `run.go` containing the main library entry point for the agent.

In addition, it should contain the following subdirectories:

* `lib/` contains core logic, has no dependency on being called command-line or pubsub, unless pubsub is part of the core business logic. It is important to keep these functions as simple and straightforward as possible. Unit tests of business logic should be here as well.
* `pubsub/` contains functions to handle pubsub messages, including all handlers. There should be no business logic here, only pubsub message handling. For business logic, handlers should call business logic functions in `lib/`.
* `cmd/` contains CLI commands and sub-commands, all in package `main`. Can be called as `go run ./cmd`. Call either functions in `pubsub/` or `lib/` depending on the command.
* `run.go` is the entrypoint for calling as part of zedbox, exposes the implementation of [`types.AgentRunner`](https://pkg.go.dev/github.com/lf-edge/eve/pkg/pillar/types#AgentRunner).

To run as a CLI:

```bash
go run ./cmd
```

To include as a pubsub library elsewhere, like in pillar, for example `verifier`:

```go
import (
    "github.com/lf-edge/eden/pkg/verifier"
)

func main() {
    verifier.Run(pubSubImpl, logrusLogger, baseLogObject, []string{argument1, argument2})
}
```

## Agent entry point

The agent entry point is `run.go`. This file should contain the following:

```go
package verifier

import (
    "github.com/lf-edge/eve/pkg/pillar/base"
    myagent "github.com/lf-edge/eve/pkg/pillar/cmd/myagent/pubsub"
    "github.com/lf-edge/eve/pkg/pillar/pubsub"
    "github.com/sirupsen/logrus"
)

func Run(ps *pubsub.PubSub, logger *logrus.Logger, log *base.LogObject, arguments []string, baseDir string) int {
    ctx := myagentpubsub.NewContext(ps, logger, log)
    return ctx.Run(arguments, baseDir)
}
```

where `myagent` should be replaced with the name of the agent.

The `myagent/pubsub/` package should export a `NewContext()` function, which
should return an agent-specific `context` object, which exports
a `Run()` function that starts the agent.

The `context.Run()` function contains all of the initialization and
pubsub interaction.

## CLI functions

CLI functions in `myagent/cmd/` should be in package `main`. They should
include the following commands:

* `pubsub` - to start the agent as a long-running pubsub service. This must include the option `--pubsub-base-path` to direct the agent to a configurable pubsub base path.
* `single` - to start the agent in a mode that does one operation and then exits. This may not be relevant for all use cases. This should include the various flags to affect operation. In this mode, it should not interact with pubsub.

## Build validation

When building the agent, it is important to test its standalone capability. This
is done by checking if it can be built as a standalone CLI.

To build as a standalone CLI:

```bash
go -C ./cmd -o bin build
```

Change `bin` to the name of the binary you want to create, e.g. `verifier`.
Be sure to remove the binary after testing, and not commit into git or leave git as
dirty.

## Package optimization

The built agent includes a lot of dependencies, many of which likely are not
actually part of the agent's functionality but were imported. These grow the image
size and make it hard to build and test.

It is important to optimize the agent. To do this, ask the following questions:

* what is the size of the standalone CLI?
* what are the package dependencies?

To check the size of the binary:

```bash
ls -l ./bin
```

The size will be larger than you expect, due to a combination of the Go runtime and
included packages.

To check the package dependencies:

```bash
go version -m bin
```

Go through each package and determine if it is necessary. If not,
determine how and why it is included, and if it is transitive, how
to restructure the direct dependency to avoid it.

To check the sizes of the dependencies, use [go-size-analyzer (gsa)](https://github.com/Zxilly/go-size-analyzer). Install `gsa` per instructions.

Once it is installed, analyze the binary:

```bash
gsa ./bin
```

Sample output:

```text
+------------------------------------------------------------------------------+
| verifier                                                                     |
+---------+-----------------------------------------------+--------+-----------+
| PERCENT | NAME                                          | SIZE   | TYPE      |
+---------+-----------------------------------------------+--------+-----------+
| 10.76%  | __gopclntab __DATA_CONST                      | 1.9 MB | section   |
| 9.08%   | __zdebug_info __DWARF                         | 1.6 MB | section   |
| 8.83%   | __rodata __DATA_CONST                         | 1.5 MB | section   |
| 6.36%   | __zdebug_loc __DWARF                          | 1.1 MB | section   |
| 6.03%   | __rodata __TEXT                               | 1.1 MB | section   |
| 4.71%   | google.golang.org/protobuf                    | 824 kB | vendor    |
| 4.32%   | crypto                                        | 756 kB | std       |
| 4.31%   | __zdebug_line __DWARF                         | 755 kB | section   |
| 4.05%   | net                                           | 709 kB | std       |
| 3.76%   | runtime                                       | 659 kB | std       |
| 3.73%   | github.com/lf-edge/eve-api/go                 | 653 kB | vendor    |
| 1.76%   | __noptrdata __DATA                            | 307 kB | section   |
| 1.46%   | __zdebug_ranges __DWARF                       | 255 kB | section   |
| 1.24%   | github.com/lf-edge/eve/pkg/pillar             | 218 kB | vendor    |
| 1.19%   | __zdebug_frame __DWARF                        | 208 kB | section   |
| 1.07%   | github.com/google/go-cmp                      | 187 kB | vendor    |
| 1.06%   | reflect                                       | 185 kB | std       |
| 0.99%   | github.com/gabriel-vasile/mimetype            | 173 kB | vendor    |
| 0.95%   | github.com/go-playground/validator/v10        | 167 kB | vendor    |
| 0.90%   | text/template                                 | 158 kB | std       |
| 0.87%   | github.com/spf13/pflag                        | 153 kB | vendor    |
| 0.75%   | regexp                                        | 131 kB | std       |
| 0.68%   | math                                          | 119 kB | std       |
| 0.63%   | time                                          | 111 kB | std       |
| 0.62%   |                                               | 109 kB | generated |
| 0.60%   | github.com/spf13/cobra                        | 106 kB | vendor    |
| 0.60%   | internal/profile                              | 105 kB | std       |
| 0.58%   | encoding/json                                 | 102 kB | std       |
| 0.49%   | __data __DATA                                 | 85 kB  | section   |
| 0.46%   | encoding/xml                                  | 81 kB  | std       |
| 0.44%   | golang.org/x/text                             | 78 kB  | vendor    |
| 0.40%   | fmt                                           | 70 kB  | std       |
| 0.35%   | github.com/sirupsen/logrus                    | 61 kB  | vendor    |
| 0.34%   | os                                            | 59 kB  | std       |
| 0.33%   | syscall                                       | 57 kB  | std       |
| 0.30%   | internal/poll                                 | 53 kB  | std       |
| 0.28%   | encoding/asn1                                 | 49 kB  | std       |
| 0.26%   | compress/flate                                | 46 kB  | std       |
| 0.26%   | strconv                                       | 46 kB  | std       |
| 0.23%   | sync                                          | 40 kB  | std       |
| 0.22%   | strings                                       | 39 kB  | std       |
| 0.21%   | mime                                          | 36 kB  | std       |
| 0.20%   | internal/abi                                  | 35 kB  | std       |
| 0.18%   | vendor/golang.org/x/text/unicode/norm         | 32 kB  | std       |
| 0.18%   | flag                                          | 31 kB  | std       |
| 0.17%   | internal/reflectlite                          | 29 kB  | std       |
| 0.15%   | bufio                                         | 26 kB  | std       |
| 0.15%   | unicode                                       | 26 kB  | std       |
| 0.14%   | vendor/golang.org/x/net/route                 | 25 kB  | std       |
| 0.13%   | bytes                                         | 22 kB  | std       |
| 0.13%   | context                                       | 22 kB  | std       |
| 0.13%   | vendor/golang.org/x/net/http2/hpack           | 22 kB  | std       |
| 0.13%   | sort                                          | 22 kB  | std       |
| 0.13%   | io                                            | 22 kB  | std       |
| 0.11%   | vendor/golang.org/x/net/dns/dnsmessage        | 19 kB  | std       |
| 0.10%   | vendor/golang.org/x/crypto/cryptobyte         | 18 kB  | std       |
| 0.10%   | __typelink __DATA_CONST                       | 18 kB  | section   |
| 0.10%   | golang.org/x/net                              | 18 kB  | vendor    |
| 0.09%   | vendor/golang.org/x/net/idna                  | 16 kB  | std       |
| 0.09%   | github.com/fsnotify/fsnotify                  | 15 kB  | vendor    |
| 0.08%   | log                                           | 15 kB  | std       |
| 0.07%   | github.com/satori/go.uuid                     | 13 kB  | vendor    |
| 0.07%   | internal/bisect                               | 12 kB  | std       |
| 0.06%   | encoding/binary                               | 11 kB  | std       |
| 0.06%   | github.com/leodido/go-urn                     | 10 kB  | vendor    |
| 0.05%   | golang.org/x/crypto                           | 9.3 kB | vendor    |
| 0.05%   | encoding/csv                                  | 9.1 kB | std       |
| 0.05%   | text/tabwriter                                | 8.7 kB | std       |
| 0.05%   | vendor/golang.org/x/net/http/httpproxy        | 8.6 kB | std       |
| 0.05%   | compress/gzip                                 | 8.4 kB | std       |
| 0.05%   | path                                          | 8.3 kB | std       |
| 0.05%   | debug/dwarf                                   | 8.0 kB | std       |
| 0.04%   | __itablink __DATA_CONST                       | 6.5 kB | section   |
| 0.04%   | internal/godebug                              | 6.3 kB | std       |
| 0.04%   | internal/fmtsort                              | 6.2 kB | std       |
| 0.03%   | vendor/golang.org/x/crypto/chacha20           | 6.0 kB | std       |
| 0.03%   | encoding/base64                               | 5.7 kB | std       |
| 0.02%   | golang.org/x/sys                              | 4.1 kB | vendor    |
| 0.02%   | vendor/golang.org/x/crypto/chacha20poly1305   | 3.8 kB | std       |
| 0.02%   | github.com/vishvananda/netlink                | 3.7 kB | vendor    |
| 0.02%   | gopkg.in/yaml.v2                              | 3.2 kB | vendor    |
| 0.02%   | vendor/golang.org/x/net/http/httpguts         | 3.0 kB | std       |
| 0.02%   | encoding/pem                                  | 3.0 kB | std       |
| 0.02%   | internal/bytealg                              | 2.9 kB | std       |
| 0.02%   | errors                                        | 2.9 kB | std       |
| 0.02%   | hash/crc32                                    | 2.8 kB | std       |
| 0.02%   | internal/singleflight                         | 2.8 kB | std       |
| 0.02%   | internal/cpu                                  | 2.7 kB | std       |
| 0.02%   | __go_buildinfo __DATA                         | 2.7 kB | section   |
| 0.01%   | vendor/golang.org/x/crypto/internal/poly1305  | 2.4 kB | std       |
| 0.01%   | internal/intern                               | 2.4 kB | std       |
| 0.01%   | vendor/golang.org/x/text/unicode/bidi         | 2.3 kB | std       |
| 0.01%   | internal/syscall/unix                         | 2.0 kB | std       |
| 0.01%   | vendor/golang.org/x/crypto/hkdf               | 1.8 kB | std       |
| 0.01%   | __symbol_stub1 __TEXT                         | 1.7 kB | section   |
| 0.01%   | internal/testlog                              | 1.7 kB | std       |
| 0.01%   | vendor/golang.org/x/text/secure/bidirule      | 1.6 kB | std       |
| 0.01%   | internal/lazyregexp                           | 1.5 kB | std       |
| 0.01%   | __nl_symbol_ptr __DATA                        | 1.2 kB | section   |
| 0.01%   | encoding/hex                                  | 1.1 kB | std       |
| 0.00%   | github.com/go-playground/locales              | 694 B  | vendor    |
| 0.00%   | internal/itoa                                 | 627 B  | std       |
| 0.00%   | html                                          | 515 B  | std       |
| 0.00%   | hash/fnv                                      | 326 B  | std       |
| 0.00%   | go/token                                      | 307 B  | std       |
| 0.00%   | __zdebug_abbrev __DWARF                       | 299 B  | section   |
| 0.00%   | database/sql/driver                           | 275 B  | std       |
| 0.00%   | main                                          | 227 B  | main      |
| 0.00%   | x_cgo_sys_thread_create                       | 183 B  | std       |
| 0.00%   | _cgo_sys_thread_start                         | 183 B  | std       |
| 0.00%   | x_cgo_thread_start                            | 167 B  | std       |
| 0.00%   | __debug_gdb_scri __DWARF                      | 67 B   | section   |
| 0.00%   | __text __TEXT                                 | 4 B    | section   |
| 0.00%   | github.com/google/go-containerregistry        | 0 B    | vendor    |
| 0.00%   | github.com/lf-edge/eve/pkg/kube/cnirpc        | 0 B    | vendor    |
| 0.00%   | github.com/vishvananda/netns                  | 0 B    | vendor    |
| 0.00%   | github.com/go-playground/universal-translator | 0 B    | vendor    |
| 0.00%   | github.com/eriknordmark/ipinfo                | 0 B    | vendor    |
+---------+-----------------------------------------------+--------+-----------+
| 90.05%  | KNOWN                                         | 16 MB  |           |
| 100%    | TOTAL                                         | 18 MB  |           |
+---------+-----------------------------------------------+--------+-----------+%
```

In theory, you only should be pulling in packages that your agent directly references
exported components, and any that those refer to and include exported components.

In practice, the golang linker will include other libraries if:

* The [reflect](https://golang.org/pkg/reflect/) package is used, since the linker cannot know in advance what you will reflect upon.
* Any referenced library in any package, even transient, even if only referenced by a function that is not used, has an `init()` function, as the linker cannot know what the impact of it is.
