# Code Coverage

EVE supports several sources of Go basic-block code coverage that can be
merged into a single combined report:

| Source | How to produce | Output |
|---|---|---|
| Unit tests (`go test`) | `make test` | `pkg/pillar/coverage.txt` |
| Eden end-to-end tests | `make eden-cover` | `dist/<arch>/current/eden_coverage/eden_e2e_coverage.txt` |
| Extra binary coverage (optional) | `COVER=y` EVE on a separate device; copy `/persist/coverage/` | binary files passed via `EXTRA_COVERAGE_DIR` |
| Combined | `make coverage-merge` | `dist/<arch>/current/combined_coverage.txt` |

Both profiles use `-covermode=atomic` (basic-block granularity, safe for
concurrent code) so they share the same text format and can be consumed by
standard `go tool cover` tooling.

## Prerequisites

- Docker installed and running (required for all EVE builds and `make test`)
- Go 1.20 or later on the host (required for `go tool covdata textfmt` used
  during Eden coverage collection)
- `ssh` and `scp` available on the host (used to retrieve coverage data
  from the running EVE VM)
- For Eden runs: QEMU with KVM support (or `ACCEL=false` for software
  emulation, which is much slower)

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

## Step 2 — Eden end-to-end coverage

### How it works

`make eden-cover` does the following:

1. Builds the entire EVE image with `COVER=y`, which causes the `pillar`
   package to be compiled with `go build -cover -covermode=atomic`.  Each
   `zedbox` agent process will accumulate basic-block counters in memory
   while running.

2. Clones and builds Eden from EDEN_REPO (default: github.com/lf-edge/eden)
   using EDEN_TAG (default: 1.0.16) which contains the coverage-collection
   extensions.

3. Starts the EVE VM under QEMU, onboards it, and runs the selected test
   scenarios exactly as `make eden` would.

   EVE also automatically flushes coverage data on controller-triggered
   reboots (including reboots caused by EVE updates), so coverage accumulated
   before a reboot is preserved in `/persist/coverage/` and included in the
   final collection.

4. After all test scenarios complete, sends `SIGUSR2` to every running
   `zedbox` process inside EVE.  Each process responds by writing its
   current coverage counters to `/persist/coverage/` (EVE's persistent
   storage) **without terminating**.

5. Copies the binary coverage files from `/persist/coverage/` off the VM
   via SCP and converts them to text profile format on the host using
   `go tool covdata textfmt`.

6. Writes the final text profile to
   `dist/<arch>/current/eden_coverage/eden_e2e_coverage.txt`.

### Building and running

`make eden-cover` handles the full pipeline in one target:

```sh
# Build coverage-instrumented EVE and run Eden E2E tests:
make eden-cover

# Equivalent long form with explicit options:
make eden-cover HV=kvm ZARCH=amd64 ACCEL=true TPM=false
```

Internally, `make eden-cover` runs `make COVER=y live` first to build the
coverage-instrumented EVE image, then invokes `tests/eden/run.sh`.  This
means the first invocation is slow (full EVE build).  The build is faster
on subsequent runs because Go and Docker build caches are warm and most
EVE component packages are already in the linuxkit cache.

The first Eden run also clones the Eden fork, builds its binaries, and
configures the test environment.  Subsequent runs with the same `dist/`
directory reuse the existing setup (certificates, QEMU image) unless
`EDEN_CLEANUP=1` is passed.

### Selecting which test scenarios to run

The same `TEST_*` environment variables that control `make eden` apply:

```sh
TEST_SMOKE=1  make eden-cover        # smoke tests only (default)
TEST_NET=1    make eden-cover        # networking tests
TEST_ALL=1    make eden-cover        # all test suites
```

### Coverage from individual eden test runs

When `COVER` is set, `run.sh` passes `--coverage-dir` to each
`eden test` invocation so coverage is also collected after every
individual scenario, not just at the very end.  If a scenario crashes EVE
the final sweep still attempts to collect whatever was written to
`/persist/coverage/` before the crash.

## Step 3 — Merge the profiles

Once `make test` and/or `make eden-cover` have been run:

```sh
make coverage-merge
```

This writes `dist/<arch>/current/combined_coverage.txt` by combining:

1. The unit-test profile from `pkg/pillar/coverage.txt` (required).
2. The Eden E2E profile from `dist/<arch>/current/eden_coverage/eden_e2e_coverage.txt`
   (included automatically if present; skipped if absent).
3. Any extra binary coverage directories specified via `EXTRA_COVERAGE_DIR`
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
can merge their binary coverage into the combined profile without re-running
Eden.

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
combined profile, just like the Eden E2E profile.

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
# From inside EVE (e.g. via `eden eve ssh`):
pkill -USR2 zedbox

# Then copy the coverage directory off the device:
scp -r -P 2222 root@127.0.0.1:/persist/coverage/ /local/my-run-cov/
```

Pass `/local/my-run-cov/` as `EXTRA_COVERAGE_DIR` to `coverage-merge`.

## Running all steps in sequence

```sh
# Unit tests and E2E tests can be run in either order.
# eden-cover includes the EVE build so no separate build step is needed.
make test && make eden-cover && make coverage-merge
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

### eden-cover vs eden

Both `make eden` and `make eden-cover` use the upstream Eden release
(`EDEN_TAG=1.0.16` from `github.com/lf-edge/eden`).  The difference is
that `make eden-cover` sets `COVER=y`, which causes `run.sh` to pass
`--coverage-dir` to each `eden test` invocation and to call
`eden eve collect-coverage` after all scenarios complete.

The upstream Eden release includes:

- `eden eve collect-coverage --output-dir <dir>` subcommand
- `eden test --coverage-dir <dir>` flag
- `SdnForwardSCPDirFromEve` for recursive directory copy from EVE
