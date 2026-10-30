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
evetest eve console             # serial console (telnet), already logged in as root; see below
evetest sdn status              # SDN status and any config errors
evetest sdn logs                # SDN logs
evetest continue                # resume the test
evetest exit                    # tear down and exit
```

### Using the EVE console

The console is the only way in when `evetest eve ssh` does not work, typically because
of a networking problem (no IP, wrong VLAN or DHCP lease, broken 802.1X) or an early
boot failure. Use it to investigate such problems (`ip addr`, `ip route`, `wpa_cli`,
`eve exec pillar ...`, logs under `/persist/newlog`), then fix or revert the cause.
Prefer `evetest eve ssh` whenever it works.

An AI agent cannot use the console interactively, but can pipe commands into it with a
timeout, pausing between them, and clean up the terminal escape codes:

```bash
(for c in "ip addr" "ip route"; do echo "$c"; sleep 4; done) | \
    timeout 60 evetest eve console 2>&1 | sed 's/\x1b\[6n//g' | tr -d '\r'
```

Run only short, non-interactive commands, and do not leave the console open in the
background.

Run `evetest eve`, `evetest sdn`, `evetest cluster`, or `evetest --help` to see the full
list of available subcommands and their descriptions.

All commands accept `--devicename <name>` when multiple devices are involved.
