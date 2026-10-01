# Coverage tooling

This directory holds the scripts that support EVE's code-coverage workflow:

| Script | Purpose |
|---|---|
| `filter_coverage_conflicts.py` | De-duplicate (file, range) blocks across merged profiles, dropping NumStmt mismatches. Used internally by `make coverage-merge`. |
| `compute_coverage.sh` | Compute aggregate **block-level** coverage across one or more text profiles. Dedupes correctly so `go tool cover -func`'s statement-weighted view and this script's block view answer different questions correctly. |
| `eden_run_lib.sh` | Sourceable Bash library of reusable helpers for driving multiple Eden suites in one Eden lifetime: SSH-based EVE-tag verification, between-suite state reset, single-suite execution with drift detection. |
| `run_eden_suites.sh` | Driver that uses the library to run a user-supplied list of suites with pre-flight + per-suite verification + optional coverage collection at the end. |

The data-flow concepts (unit / Eden e2e / extras → merge → analyze) are
described in [`../docs/CODE-COVERAGE.md`](../docs/CODE-COVERAGE.md). This
README is about the script interfaces and a worked example.

---

## When to use which script

| Question | Tool |
|---|---|
| "Did this function get exercised?" | `go tool cover -func=<profile>` |
| "What percentage of *blocks* did *any* test source hit?" | `compute_coverage.sh` |
| "Run smoke + baseosmgr + nodeagent suites in one Eden run, abort if EVE drifts" | `run_eden_suites.sh` |
| "I'm writing my own multi-suite driver" | Source `eden_run_lib.sh` |

---

## Worked example: coverage across a multi-PR integration branch

This is the workflow we used to measure combined coverage of a topic
branch (`coverage-allprs`) that merged six in-flight EVE PRs onto
master. The same shape applies to any other multi-source coverage
measurement.

### Setup

1. **Build a COVER=y EVE image** from the integration branch:

   ```sh
   cd ~/lf-edge/work/coverage-allprs/eve
   make COVER=y HV=kvm ZARCH=amd64 eve-pillar
   make COVER=y HV=kvm ZARCH=amd64 eve
   make COVER=y HV=kvm ZARCH=amd64 live
   ```

2. **Set up Eden** pointing at the new image (per
   [`../docs/CODE-COVERAGE.md`](../docs/CODE-COVERAGE.md) "Step 2"):

   ```sh
   eden setup --image-file dist/amd64/current/live.img
   eden start
   eden eve onboard
   ```

3. **Run unit tests** to produce `pkg/pillar/coverage.txt`:

   ```sh
   make test
   ```

### Multi-suite Eden run

With Eden up and EVE onboarded, drive the suites:

```sh
EVE_TAG=$(basename "$(readlink -f dist/amd64/current)")
export EVE_EXPECTED_TAG="${EVE_TAG}-kvm-amd64"
export EDEN=$EDEN_SRC/dist/bin/eden-linux-amd64
export EDEN_HOME=$PWD/dist/amd64/current/eden_config
export EVE_SSH_KEY=$EDEN_SRC/dist/default-certs/id_rsa
export EDEN_RUNLOGS=$PWD/dist/amd64/current/eden_runlogs

tools/run_eden_suites.sh \
    --coverage-dir "$PWD/dist/amd64/current/eden_coverage" \
    --assert-no-baseos \
    smoke:./tests/workflow:smoke.tests.txt \
    baseosmgr:./tests/baseosmgr:eden.baseosmgr.tests.txt
```

What this does, in order:

1. Verifies EVE is on `$EVE_EXPECTED_TAG` (catches "you forgot to update
   `eve.tag` after rebuilding").
2. Pre-flight resets adam state and re-verifies.
3. `--assert-no-baseos` flag: aborts if adam still has a baseos config
   from a prior run (useful for any suite that touches baseos —
   `baseosmgr`, `nodeagent`, `update_eve_image`).
4. For each `label:dir:scenario` spec:
   - Runs `eden test <dir> -s <scenario> --coverage-dir <dir>`.
   - Verifies EVE didn't swap to a different version mid-suite (the
     `retry_update.txt` / `force_fallback.txt` / `baseos_fallback_*.txt`
     tests all touch EVE's running version and don't always self-clean).
   - Resets adam state between suites.
5. After the last suite, `eden eve collect-coverage` rsyncs
   `/persist/coverage/` back to `--coverage-dir`, producing
   `eden_e2e_coverage.txt`.

### Merge and analyze

```sh
make coverage-merge EXTRA_COVERAGE_DIR="/path/to/hw-test-coverage"
# → dist/amd64/current/combined_coverage.txt

# Statement-weighted, per-function: use go tool cover.
go tool cover -func=dist/amd64/current/combined_coverage.txt | tail -1

# Block-level aggregate across all sources:
tools/compute_coverage.sh "all" \
    pkg/pillar/coverage.txt \
    dist/amd64/current/eden_coverage/eden_e2e_coverage.txt \
    /path/to/hw-test-coverage.txt
# → all   24239 / 42066 = 57.62 %
```

For incremental analysis (how much does each source add):

```sh
tools/compute_coverage.sh "unit"           pkg/pillar/coverage.txt
tools/compute_coverage.sh "unit + eden"    pkg/pillar/coverage.txt \
    dist/amd64/current/eden_coverage/eden_e2e_coverage.txt
tools/compute_coverage.sh "all"            pkg/pillar/coverage.txt \
    dist/amd64/current/eden_coverage/eden_e2e_coverage.txt \
    /path/to/hw-test-coverage.txt
```

---

## Suite-spec format

`run_eden_suites.sh` takes one or more positional `label:dir:scenario`
triples:

- **`label`** — used as the log filename (`$EDEN_RUNLOGS/<label>.log`)
  and in console output. Free-form, no spaces.
- **`dir`** — passed to `eden test <dir>`. A path to an eden test
  directory under `tests/`, typically `./tests/<area>`.
- **`scenario`** — passed to `eden test -s <scenario>`. The scenario
  file under `<dir>/`, e.g. `smoke.tests.txt`,
  `eden.baseosmgr.tests.txt`.

Examples:

```sh
smoke:./tests/workflow:smoke.tests.txt
baseosmgr:./tests/baseosmgr:eden.baseosmgr.tests.txt
nodeagent:./tests/nodeagent:eden.nodeagent.tests.txt
networking:./tests/workflow:networking.tests.txt
```

---

## Authoring your own driver

If `run_eden_suites.sh`'s flags don't fit, source `eden_run_lib.sh`
directly. The library exposes four functions; see the header comment in
`eden_run_lib.sh` for the contract:

```sh
. tools/eden_run_lib.sh

verify_eve_tag "before-anything" || exit 1
eden_reset_state "warm-up"
run_eden_suite "smoke" ./tests/workflow smoke.tests.txt || exit 1
# … custom logic between suites …
run_eden_suite "my-area" ./tests/my-area my-scenario.tests.txt || exit 1
```

Set the required env vars (`EDEN`, `EDEN_HOME`, `EVE_EXPECTED_TAG`,
`EVE_SSH_KEY`, `EDEN_RUNLOGS`) before sourcing or before calling.
