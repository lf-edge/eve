# Code Coverage

## Test prioritization by microservice category

EVE microservices fall into two categories — **device management** and
**workload management** — described in
[MICROSERVICE-CLASSIFICATION.md](MICROSERVICE-CLASSIFICATION.md).

Device management microservices (`nim`, `zedagent`, `client`, `baseosmgr`,
`downloader`, `verifier`, `volumemgr`, `nodeagent`, `tpmmgr`,
`loguploader`) are critical for remote manageability.
A sustained bug in any of them can prevent the controller from reaching the
device, requiring physical intervention to recover. Coverage gaps in this group
therefore carry higher operational risk than equivalent gaps in workload
management code.

Workload management microservices (`domainmgr`, `zedrouter`, `zedmanager`,
`diag`, hypervisors, container runtime) handle running applications on the
device and diagnostics. Their failure is recoverable remotely. Coverage gaps
here matter, but are lower priority than equal-sized gaps in device management
code.

When choosing what to test next, prefer addressing device management gaps over
workload management gaps of similar size.

---

EVE supports several sources of Go basic-block code coverage that can be
merged into a single combined report:

| Source | How to produce | Output |
|---|---|---|
| Unit tests (`go test`) | `make test` | `pkg/pillar/coverage.txt` |
| evetest integration tests | `EVETEST_COLLECT_COVERAGE=true make evetest` on a `COVER=y` EVE | binary files under `${EVETEST_COLLECT_ARTIFACTS}/<test>/coverage/<device>/`, passed via `EXTRA_COVERAGE_DIR` |
| Extra binary coverage (optional) | `COVER=y` EVE on a separate device; copy `/persist/coverage/` | binary files passed via `EXTRA_COVERAGE_DIR` |
| Combined | `make coverage-merge` | `dist/<arch>/current/combined_coverage.txt` |

All sources use `-covermode=atomic` (basic-block granularity, safe for
concurrent code) so they share the same text format and can be consumed by
standard `go tool cover` tooling.

## Prerequisites

- Docker installed and running (required for all EVE builds and `make test`)
- Go 1.20 or later on the host (required for `go tool covdata textfmt` used
  to merge binary coverage)
- For evetest runs: see the prerequisites in [evetest/README.md](../evetest/README.md)

## Step 1 — Unit-test coverage

Run the standard test suite.  This builds a test container and executes
all Go unit tests inside it with coverage instrumentation:

```sh
make test
```

Coverage is written to `pkg/pillar/coverage.txt`.  To view it immediately:

```sh
go tool cover -func=pkg/pillar/coverage.txt
go tool cover -html=pkg/pillar/coverage.txt -o coverage_unit.html
```

## Step 2 — evetest integration coverage

[evetest](../evetest/README.md) collects coverage by itself from every EVE
device it runs, when EVE is built with `COVER=y` and
`EVETEST_COLLECT_COVERAGE=true` (together with `EVETEST_COLLECT_ARTIFACTS`)
is set.  The framework sends `SIGUSR2` to `zedbox` (and `kube-init` on eve-k)
before every device reboot and at the end of each test, then copies the
binary coverage files off the device into
`${EVETEST_COLLECT_ARTIFACTS}/<test>-<timestamp>/coverage/<device-name>/`.
Coverage collected before a reboot is thus preserved.

```sh
# Build coverage-instrumented pillar first (required), then the EVE image:
make COVER=y pkg/pillar
make COVER=y eve

# Run the tests (all suites if NAME is omitted) collecting coverage:
EVETEST_COLLECT_ARTIFACTS=/tmp/evetest-artifacts \
EVETEST_COLLECT_COVERAGE=true \
    make evetest NAME=<test-or-suite>
```

See the "Code Coverage" section of [evetest/README.md](../evetest/README.md)
for details and for merging the counters of all devices of a run with
`go tool covdata`.

The nightly evetest workflow
([evetest-nightly.yml](../.github/workflows/evetest-nightly.yml)) can do all of
this in CI: started manually with the `collect-coverage` input, it builds a
`COVER=y` image from HEAD, runs every suite against it, merges the coverage
of all suites and publishes a line-by-line HTML report to GitHub Pages.

## Step 3 — Merge the profiles

Once `make test` has been run and the binary coverage of an evetest run has been
collected (see Step 2):

```sh
make coverage-merge EXTRA_COVERAGE_DIR=/tmp/merged-coverage
```

This writes `dist/<arch>/current/combined_coverage.txt` by combining:

1. The unit-test profile from `pkg/pillar/coverage.txt` (required).
2. Any binary coverage directories specified via `EXTRA_COVERAGE_DIR`
   (see the next section).

To view the merged result:

```sh
# Per-function summary
go tool cover -func=dist/amd64/current/combined_coverage.txt

# HTML report
go tool cover -html=dist/amd64/current/combined_coverage.txt \
    -o coverage_combined.html
```

## Step 4 (optional) — Including extra binary coverage

If you have additional test runs that exercised a `COVER=y` EVE image
(e.g. a manually-driven hardware test or a separate automated suite), you
can merge their binary coverage into the combined profile.  The coverage
collected by evetest (Step 2) is merged the same way.

### Binary coverage file format

When `zedbox` is built with `COVER=y` and `GOCOVERDIR` is set (or defaults
to `/persist/coverage/`), Go writes binary coverage files to that directory:

| File pattern | Content |
|---|---|
| `covmeta.<hash>` | Package/function metadata |
| `covcounters.<hash>.<pid>.<time>` | Per-run basic-block counters |

Copy the entire `GOCOVERDIR` directory off the device after the test run
and pass its path to `coverage-merge` via `EXTRA_COVERAGE_DIR`.

`coverage-merge` converts each extra directory with
`go tool covdata textfmt -i <dir>` and appends the resulting lines to the
combined profile.

### Usage

```sh
# Single extra directory
make coverage-merge EXTRA_COVERAGE_DIR=/path/to/hw-test-cov

# Multiple extra directories (space-separated, quoted)
make coverage-merge EXTRA_COVERAGE_DIR="/path/to/run1 /path/to/run2"
```

You can combine this with `UNIT_COV_FILE` to point at a unit coverage
profile from a different build:

```sh
make coverage-merge \
    UNIT_COV_FILE=/path/to/other/coverage.txt \
    EXTRA_COVERAGE_DIR="/path/to/run1 /path/to/run2"
```

### Building and deploying a coverage-instrumented image

To collect coverage from tests run on a separate device or VM, first build a
coverage-instrumented EVE image.  Because `pkg/pillar` contains
`//go:build cover` conditional code, it must be built explicitly before the
full image to avoid picking up a stale cached version:

```sh
# Build coverage-instrumented pillar first (required):
make COVER=y pkg/pillar

# Then build the target image:
make COVER=y live        # for QEMU / VM
make COVER=y installer   # for bare-metal installation
make COVER=y rootfs      # to update an existing EVE device
```

Install the resulting image on the target device using the standard EVE
installation procedure.  Once booted, the `zedbox` binary is instrumented and
coverage counters accumulate automatically in `/persist/coverage/` as the
device operates — no extra configuration needed.

Run whatever tests or workloads you want to cover on that device.  Coverage
accumulates continuously across reboots (since `/persist` is preserved), and
each `zedbox` agent process writes its own counter files, so all agent
activity is captured.  When you are ready to collect, proceed to the next
section.

### Collecting binary coverage from a running EVE device

On a device running a `COVER=y` image, send `SIGUSR2` to each `zedbox`
process to flush current counters without restarting:

```sh
# From inside EVE (e.g. via `evetest eve ssh` or plain `ssh`):
pkill -USR2 zedbox

# On an eve-k (HV=k) image, also flush kube-init. The marker file exists
# only when kube-init was built with COVER=y and can flush:
[ -e /run/kube-init-cover ] && pkill -USR2 kube-init

# Then copy the coverage directory off the device:
scp -r -P 2222 root@127.0.0.1:/persist/coverage/ /local/my-run-cov/
```

Pass `/local/my-run-cov/` as `EXTRA_COVERAGE_DIR` to `coverage-merge`.

## Running all steps in sequence

```sh
make test
make COVER=y pkg/pillar && make COVER=y eve
EVETEST_COLLECT_ARTIFACTS=/tmp/evetest-artifacts EVETEST_COLLECT_COVERAGE=true make evetest
mkdir -p /tmp/merged-coverage
go tool covdata merge \
    -i "$(find /tmp/evetest-artifacts -path '*/coverage/*' -type d | paste -sd,)" \
    -o /tmp/merged-coverage
make coverage-merge EXTRA_COVERAGE_DIR=/tmp/merged-coverage
```

## Notes on the coverage mechanism

### GOCOVERDIR and /persist/coverage

When `zedbox` is built with `COVER=y`, a `//go:build cover` file
(`pkg/pillar/zedbox/coverage.go`) is compiled in.  Its `init()` function:

- Creates `/persist/coverage/` on EVE's persistent storage partition.
- Sets `GOCOVERDIR=/persist/coverage` so Go's coverage runtime writes
  counter files there on process exit.
- Registers a `SIGUSR2` signal handler that calls
  `runtime/coverage.WriteMetaDir` and `runtime/coverage.WriteCountersDir`
  to flush counters on demand.

This design means:

- Every `zedbox` agent process (there are many — `zedagent`, `nim`,
  `domainmgr`, etc., all symlinked to the same binary) writes its own
  counter file under `/persist/coverage/`.
- Coverage accumulates across the entire test run; a live snapshot can be
  taken at any point without stopping any agent.
- `/persist` survives QEMU reboots, so coverage from multiple boot cycles
  is preserved.

### Binary coverage file types

Go 1.20+ binary instrumentation writes two file types to `GOCOVERDIR`:

| File | Content |
|---|---|
| `covmeta.<hash>` | Package/function metadata (one per unique binary) |
| `covcounters.<hash>.<pid>.<time>` | Per-run counter values |

`go tool covdata textfmt` merges all counter files for a given metadata
hash and emits a text profile in the same format as `go test -coverprofile`.

### Merging profiles

The combined profile is produced by simple concatenation — one `mode:`
header followed by all coverage lines from all source profiles.  Lines covering
the same source statement from different runs are additive: `go tool cover`
sums the hit counts when both report the same statement, giving a correct
aggregate view of which lines were exercised by either test suite.

For more sophisticated merging (e.g. deduplication or per-package
breakdown) the `golang.org/x/tools/cmd/cover` package and third-party
tools such as `gocovmerge` can be used on the text profiles directly.
