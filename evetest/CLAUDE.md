# Claude Code instructions for evetest

Before writing or reviewing any evetest code, familiarize yourself with the framework:

1. Read `evetest/README.md` for an architectural overview and the test writing guidelines
   (see **"Writing Tests -> Guidelines"**).
2. Read the core test interface files:
   - `evetest/harness.go` -- top-level harness methods (`Init`, `Close`, `Setup`,
     `Checkpoint`, `RunTestSuite`, etc.)
   - `evetest/devconfig.go` -- device configuration builder
   - `evetest/edgedevice.go` -- `EdgeDevice` interface (apply config, watch info/metrics,
     run shell scripts, etc.)
   - `evetest/edgecluster.go` -- `EdgeCluster` interface
   - `evetest/clusterconfig.go` -- cluster configuration builder
3. Familiarize yourself with the EVE API Go types used in assertions:
   `pkg/pillar/vendor/github.com/lf-edge/eve-api/go/`
4. Look at all existing fully-implemented tests under `evetest/tests/` to understand
   conventions and patterns before adding new ones.

When writing or reviewing tests, follow the guidelines in `evetest/README.md` under
**"Writing Tests -> Guidelines"**.

## After writing or modifying a test

Always run the following checks from the `evetest/` directory before considering the
work done:

```bash
GOWORK=off go fmt ./tests/...
GOWORK=off go vet ./tests/...
GOWORK=off go build ./tests/...
```

If it is possible to actually run the test in the current environment, do so -- static
checks only verify that the code compiles; they do not catch runtime assertion failures,
wrong timeouts, or incorrect EVE API usage:

```bash
EVETEST_PAUSE_ON_FAILURE=true make evetest NAME=<TestFunctionName>
```

## Running a test

```bash
# From the EVE repository root
make evetest NAME=<TestFunctionName>

# With debug logging
EVETEST_LOG_LEVEL=debug make evetest NAME=<TestFunctionName>

# Pause on failure to inspect the live environment
EVETEST_PAUSE_ON_FAILURE=true make evetest NAME=<TestFunctionName>

# Pause at a specific checkpoint
EVETEST_PAUSE_ON_CHECKPOINT=<checkpoint-name> make evetest NAME=<TestFunctionName>
```

## Inspecting a paused test

When the test is paused (on failure or at a checkpoint), use the `evetest` CLI in a
separate terminal to inspect the live environment:

```bash
evetest status                  # overall test status
evetest eve info -t             # print the latest ZInfoDevice message (-t without a value
                                # defaults to 1); omit -t to print all published messages
evetest eve logs                # EVE device logs
evetest eve ssh <command>       # run a single command on EVE
evetest eve collect-info        # collect a tar archive with a full debug snapshot from the
                                # device (logs, pubsub state, network info, etc.); use this
                                # as a first step when diagnosing an unexpected failure
evetest eve console             # interactive serial console (telnet); cannot be driven by
                                # Claude -- ask the user to run it when EVE is not yet
                                # IP-reachable (e.g. early boot failure)
evetest sdn status              # SDN status and any config errors
evetest sdn logs                # SDN logs
evetest continue                # resume the test
evetest exit                    # tear down and exit
```

Run `evetest eve`, `evetest sdn`, `evetest cluster`, or `evetest --help` to see the full
list of available subcommands and their descriptions.

All commands accept `--devicename <name>` when multiple devices are involved.
