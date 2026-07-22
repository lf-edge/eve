# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

EVE (Edge Virtualization Engine) is an open, agnostic OS for edge devices, supporting ARM64, AMD64 and riscv64 (experimental) architectures and requiring hardware-assisted virtualization. It runs OCI containers and VMs on the edge through a hypervisor KVM (default and most supported) and Xen. A KVM based hypervisor variant called eve-k is used for kubernetes support. Almost everything ships as linuxkit packages composed into a bootable rootfs; the actual edge-device control plane is the Go monolith under `pkg/pillar`. EVE is normally driven by an external remote controller (e.g. Adam, run via [Eden](https://github.com/lf-edge/eden) test framework). The most notable commercial controller is provided by Zededa Inc.

The top-level `Makefile` is the entry point for almost everything. It composes Docker/linuxkit-based builds — you rarely build anything natively on the host. Three knobs drive nearly every target:

- `ZARCH` — target arch: `amd64` (default = host), `arm64`, `riscv64`
- `HV` — hypervisor flavor: `kvm` (default), `xen`, `mini` (used only for riscv64), `k` (kubevirt - the kubernetes variant)
- `PLATFORM` — `generic` (default), `nvidia-jp6`, `imx8mp_pollux`, `imx8mp_epc_r3720`, `imx8mq_evk`, `rt`, etc.

Build artifacts land under `dist/$(ZARCH)/$(ROOTFS_VERSION)/` with a `dist/$(ZARCH)/current` symlink to the latest. `make clean` wipes `dist/` and `images/out/`.

Conceptual layers (see `docs/BUILD.md` and `docs/images/build-process.png`):

1. **linuxkit OCI packages** in `pkg/` — built via `linuxkit pkg build` (e.g. `make pkg/pillar`)
2. **rootfs image** — composed from those packages (`make rootfs`)
3. **live image** — bootable disk including rootfs and EFI/grub (`make live`, `make live-raw`, `make live-gcp`, …)
4. **installer image** — flashable many-use installer (`make installer`, `make installer-raw`, `make installer-iso`, `make installer-net`)

`make` with no args prints a help summary of every commonly used target.

### Common build/run commands

```sh
make build-tools                    # one-time: builds linuxkit, etc. into build-tools/bin/
make live                           # build a kvm/host-arch live image
make run-live                       # Runs a live image on a QEMU VM
make ZARCH=arm64 HV=kvm live-raw    # ARM live image (e.g. for Raspberry Pi 4, FR201)
make ZARCH=arm64 HV=kvm PLATFORM=imx8mp_pollux live-raw   # NXP board variant
make ZARCH=arm64 HV=kvm PLATFORM=nvidia-jp5 installer-raw   # Installer image for NVIDIA Jetpack 5 based devices (e.g. Jetson Xavier)
make ZARCH=arm64 HV=kvm PLATFORM=nvidia-jp6 installer-raw   # Installer image for NVIDIA Jetpack 6 based devices (e.g. Jetson Orin Nano, Jetson Orin NX, etc)
make ZARCH=arm64 HV=kvm PLATFORM=nvidia-jp7 installer-raw   # Installer image for NVIDIA Jetpack 7 based devices (e.g. Jetson Thor)
make pkgs                           # pre-build all EVE linuxkit packages
make pkg/<name>                     # build a single linuxkit package (e.g. make pkg/pillar)
make run                            # alias for run-live: boot the built image in qemu
make run QEMU_MEMORY=2048 TPM=y PFLASH=true
make eden                           # full Eden E2E test cycle (clone, build, configure, onboard, test)
make shell                          # drop into the dockerized Go build env
make pkgs rootfs                    # Used to produce only the rootfs image that can be used to upgrade device from the remote controller or through Eden
make eve                            # Build and export eve image to docker. This image can be used to generate live/installer images
```

When running `make run-live` QEMU defaults to 8GB RAM and forwards ssh on port 2222. Exit with `Ctrl-A C` then `q`. Setting `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` in the environment propagates them into build containers automatically.

### Live updates during pillar dev

`LIVE_UPDATE=1 make live` rebuilds the live image with an ext4 RW rootfs and only repacks the rootfs tarball — significantly faster than a full rebuild. Use this for iterative pillar work; do not commit images produced this way.

## Tests

`make test` is the umbrella target — it runs pillar tests *in Docker* plus several smaller test suites. The most useful per-component invocations:

```sh
make test                                    # full suite (pillar + bpftrace-compiler + dnsmasq + debug + vtpm + newlog + edgeview)
make -C pkg/pillar test                      # pillar unit tests in docker (produces results.json/xml, coverage.txt)
make -C pkg/pillar fuzz-test                 # fuzz tests
make -C pkg/pillar fmt                       # gofmt -w -s
make -C pkg/pillar fmt-check                 # gofmt -l (CI-style check)
make -C pkg/pillar vet                       # go vet with build tags
make pillar-<target>                         # run any pillar Makefile target via DOCKER_GO wrapper (e.g. make pillar-fmt)
go test -C pkg/newlog/cmd/ -v -race          # single subpackage natively (requires local Go toolchain)
make eden TEST_SMOKE=1                       # Eden smoke tests (also TEST_NET, TEST_LOC, TEST_UPGRADE, TEST_UAPP, TEST_VIRT, TEST_STORAGE, TEST_ALL)
make eden EDEN_CLEANUP=1                     # nuke Eden config/certs and start over
make eden-cover                              # build COVER=y and collect E2E binary coverage
```

Running a single Go test (against the dockerized environment) goes through `make -C pkg/pillar test`, which currently runs `go test -tags k ... ./...`. For a tight iteration loop, drop into `make shell` and run `go test` by hand inside the builder image with `BUILD=local`.

## Linting / CI parity

```sh
make yetus                          # Apache Yetus full check (slow, builds an image first time)
make mini-yetus                     # Yetus only on files changed vs. master (much faster pre-PR check)
make check-docker-hashes-consistency # Check if packages are pointing to the latest version of dependency packages inside their Dockerfile. All packages should point to the same hashes of a common dependency (with a few exceptions)
```

`mini-yetus` accepts `MYETUS_SBRANCH`, `MYETUS_DBRANCH`, `MYETUS_VERBOSE=Y`. CI workflows live under `.github/workflows/` — `pr-gate.yml`, `go-tests.yml`, `yetus.yml`, `codeql.yml`, `build.yml`. The shellcheck config (`shellcheckrc`) disables SC3043.

## Debugging on a live device

- `eve version`, `zboot curpart` — running version and active IMGA/IMGB partition.
- EVE services cgroups: `/sys/fs/cgroup/memory/eve/services/<pillar|newlogd|...>/memory.usage_in_bytes`; per-app cgroups under `/eve-user-apps/<uuid>.<x>.<y>`.
- QMP sockets: `/run/hypervisor/kvm/<app-uuid>.<x>.<y>/qmp` (domain names are `<uuid>.<gen>.<instance>`).
- Pubsub state on disk: `/run/<agent>/<topic>/*.json` (ephemeral), `/persist/status/...` (persistent).
- Memory analysis docs: `docs/MEMORY-SETTINGS.md`, `docs/INTERNAL-MEMORY-MONITOR.md`, `pkg/memory-monitor/`. Config knob reference: `docs/CONFIG-PROPERTIES.md` (e.g. `debug.enable.ssh`, `memory.apps.ignore.check`, `memory.eve.limit.MiB`).
- Fault injection: `docs/FAULT-INJECTION.md`. QEMU crash debugging: `docs/QEMU-CRASH-DEBUGGING.md`.

## Pillar architecture (the part you'll touch most)

`pkg/pillar` is a Go monolith that contains ~34 microservices ("agents") in `pkg/pillar/cmd/`. They are all linked into a single binary, **`zedbox`**, and dispatched via symlinks (BusyBox-style). To add an agent you must register its `types.AgentRunner` in the `entrypoints` map in `pkg/pillar/zedbox/zedbox.go`. The per-agent design pattern is documented in `pkg/pillar/cmd/README.md`.

**IPC between agents is via `pubsub`** (`pkg/pillar/pubsub`): each agent publishes/subscribes typed objects. The standard pattern is a pair of types per object:

- `ObjectConfig` — declarative input (from the controller or generated)
- `ObjectStatus` — agent's view of current processing state (carries `SwState` and possibly sub-states)

Each object type has **exactly one publisher/owner**; everyone else subscribes read-only. State transitions for a given `ObjectStatus` should live in *one* function (commonly `doUpdate…`/`handleModify`), so the state machine is auditable in a single place. `SwState` and most cross-agent types live in `pkg/pillar/types/` (this is the shared vocabulary of the whole monolith; changing a type ripples across agents).

At runtime the default socket driver (`pubsub/socketdriver`) materializes pubsub on disk: ephemeral topics under `/run/<agent>/<topic>/*.json`, persistent topics under `/persist/status/<agent>/...`, the special global namespace under `/run/global/`, and per-agent sockets at `/var/run/<agent>.sock`. A `memdriver` backend exists for tests. These paths are the first place to look when debugging on a live device.

Long-running or blocking work is dispatched through the `worker` package (`pkg/pillar/worker`) so handlers stay fast.

The following EVE related projects are imported by Pillar:

- [eve-api](https://github.com/lf-edge/eve-api): API for communications between an EVE edge device and a remote controller.
- [eve-libs](https://github.com/lf-edge/eve-libs): Contains the libraries used by various other packages in EVE, including pillar.

### Microservice classes (affects review/test rigor)

Microservices split into two classes (see `docs/MICROSERVICE-CLASSIFICATION.md`) — this distinction matters when judging review/test rigor:

- **Device management** — `nim`, `zedagent`, `client`, `baseosmgr`, `downloader`, `verifier`, `volumemgr`, `nodeagent`, `tpmmgr`. A sustained bug here can lose remote manageability and require a truck roll. Treat changes here with extra care.
- **Workload management** — `domainmgr`, `zedrouter`, `zedmanager`. Failures are remotely recoverable by pushing new config.
- **Observability** — `diag`, `loguploader`.

The A/B rootfs partitioning (IMGA/IMGB) exists specifically to allow safe rollback of device management code. The command line tool `zboot` is used to check status and switch A/B partitions.

### Reconciler / intent pattern (networking)

Network agents don't imperatively mutate the system — they declare intended state as a dependency graph and let `eve-libs/reconciler` converge it. `dpcreconciler` (device port config → Linux/network-stack items in `dpcreconciler/linuxitems/` and `dpcreconciler/genericitems/`) and `nireconciler` (network instances) build `depgraph` item sets; the reconciler computes create/modify/delete operations. When changing networking, add/modify graph *items* and their dependencies rather than calling `ip`/netlink directly. Related: `dpcmanager` (port config selection/testing), `nistate` (observed network-instance state), `conntester`.

### Agent structure & lifecycle

Newer/refactored agents follow the layered layout from `cmd/README.md`: `run.go` (the `Run(ps, logger, log, args, baseDir) int` entrypoint exposing `types.AgentRunner`), `lib/` (pure business logic + unit tests, no pubsub/CLI deps), `pubsub/` (pubsub handlers only, delegating to `lib/`), and `cmd/` (standalone `package main` CLI, runnable via `go run ./cmd`). Many older agents still keep everything in one package — match the layout of the agent you're editing rather than imposing the new one.

Every agent embeds `agentbase` (`agentbase/agent.go`): `agentbase.Init(...)` wires up CLI flag parsing, the pidfile, and the **watchdog**. Long-lived agents must periodically call `ps.StillRunning(agentName, warningTime, errorTime)` — the watchdog reboots the device if an agent stops kicking. Keep pubsub handlers fast and non-blocking so the watchdog keeps getting kicked; offload anything slow (downloads, qemu, image verification) to the `worker` package (`pkg/pillar/worker`).

### Shared packages worth knowing before editing an agent

- `types/` — all Config/Status objects and `SwState`; the cross-agent contract.
- `pubsub/` — the IPC bus (`socketdriver`, `memdriver`).
- `worker/` — async job dispatch for slow work; keeps handlers watchdog-safe.
- `agentbase/`, `agentlog/`, `base/` — agent bootstrap, structured logging, `LogObject`.
- `hypervisor/` — KVM/Xen/kubevirt/`null` backends behind one interface (used by `domainmgr`).
- `containerd/`, `cas/` — container runtime + content-addressable store (image handling).
- `vault/`, `evetpm/`, `cipher/`, `attest/` — disk encryption, TPM, secret unwrapping, remote attestation.
- `controllerconn/` — HTTP(S) transport to the controller (used by `zedagent`/`client`/`nim`).
- `objtonum`, `persistcache`, `flextimer`, `sema`, `queuelock` — small cross-cutting utilities.

### Per-agent docs

Implementation docs live in `pkg/pillar/docs/` — consult the matching file before changing an agent: `zedagent.md`/`zedagent-internals.md`, `zedmanager.md`, `zedrouter.md`, `domainmgr.md`, `nim.md`, `zedkube.md`, `volumemgr.md`, `vaultmgr.md`, `tpmmgr.md`, `usbmanager.md`, `vcomlink.md`, `monitor.md`, `watcher.md`, plus topic docs `boot-order-internals.md`, `failover.md`, `radio-silence.md`, `app-snapshot.md`, `vnc-workflows.md`, `types-architecture.md`.

### Standalone agent build check

Refactored agents must stay buildable as a standalone CLI (`go -C ./cmd/<agent> build -o bin`) and dependency-lean — the linker pulls in transitive deps via `init()`/`reflect`, so audit with `go version -m bin` / `gsa bin` and remove unnecessary direct imports. Delete the test binary afterward; don't leave git dirty.

### Build tags / flavors in pillar

`pkg/pillar/Makefile` adds Go build tags based on env vars: `HV` (`kvm`/`xen`/`mini`/`k`), `RSTATS=y`, `IMM_PROFILING=y`, `ARTIFICIAL_LEAK=y`, `COVER=y`. `DEV=y` keeps debug symbols, disables `-s -w`, and adds `-gcflags="-N -l"` so `delve` works (see `docs/DEBUGGING.md` for the delve workflow over `ssh -L 2348:localhost:2345`).

### Pillar dependency hygiene

Pillar vendors deps (`go mod vendor`). **Do not** use `replace` directives pointing at local paths in committed `go.mod` — they break dependency tracking and SBOM/licensing. Use them only for local development, then publish the dep change properly and bump the version via the `make bump-eve-libs` / `bump-eve-api` / `bump-eve-pillar` / `bump-edge-containers` targets.

## Repository layout cheatsheet

- `pkg/` — linuxkit OCI packages (each has a `build.yml` and `Dockerfile`). Notable: `pillar/`, `kernel/` (via `eve-kernel` repo, pinned in `kernel-commits.mk`/`kernel-version.mk`), `grub/`, `mkimage-*`, `xen-tools/`, `kube/`, `edgeview/`, `vtpm/`, `newlog/`, `memory-monitor/`.
- `pkg/pillar/cmd/` — one directory per agent (zedagent, zedmanager, zedrouter, domainmgr, nim, …).
- `images/` — linuxkit YAML manifests assembled into rootfs images.
- `build-tools/` — vendored linuxkit + cross-compilers; `make build-tools` populates `build-tools/bin/`.
- `tools/` — shell/Python helper scripts referenced by Makefile targets.
- `conf/` — default config partition contents.
- `docs/` — design and operational docs. Start with `docs/BUILD.md`, `docs/MICROSERVICE-CLASSIFICATION.md`, `docs/HYPERVISORS.md`, `docs/NETWORKING.md`, `docs/DEBUGGING.md`, `docs/EVE-K.md`, `docs/LPS.md`, plus per-agent docs under `pkg/pillar/docs/`. Also useful: `docs/CONFIG-PROPERTIES.md` (all config knobs), `docs/MEMORY-SETTINGS.md`, `docs/INTERNAL-MEMORY-MONITOR.md`, `docs/FAULT-INJECTION.md`, `docs/QEMU-CRASH-DEBUGGING.md`.
- `tests/` — coverage, Eden harness pointers, tpm tests, semgrep rules.
- `eve-tools/` — auxiliary CLI tools (e.g. `bpftrace-compiler`).
- `kernel-commits.mk` / `kernel-version.mk` — kernel branch/commit pins per arch; coordinate kernel changes across all active `eve-kernel-*` branches (see `CONTRIBUTING.md` "Kernel development" and `tools/update_kernel_commits.py`).

## Contribution rules that affect what you produce

From `CONTRIBUTING.md` / `.github/pull_request_template.md`:

- Commits **must** be DCO-signed: use `git commit -s` so a `Signed-off-by` trailer is appended. PRs without this are rejected.
- Rebase, don't merge, when updating against master. Squash to logical units (typically one commit per PR).
- When fixing a batch of independent findings (e.g. from an audit), make one commit per logical fix rather than one big commit.
- When generating code, avoid excessive comments inside function bodies. In-function comments should be as summarized as possible — comment only non-obvious constraints or tricky logic, never narrate what each line does.
- Backport PRs follow a specific title format `[<stable-branch>] Original title`, with a body line `Backport of #<original-PR-number>` and `git cherry-pick -x` to preserve the source SHA.
- `mini-yetus` is the cheap pre-push check; full `make yetus` mirrors CI but is slow.
- Any changes on vendor files should always be committed on a dedicated commit. For eve-api, eve-libs, edge-containers and pillar there are specific make targets to automate bumping versions:

```sh
make bump-eve-api         # bump eve-api in all subprojects
make bump-eve-libs        # bump eve-libs in all subprojects
make bump-eve-pillar      # bump eve/pkg/pillar in all subprojects
make bump-edge-containers # bump edge-containers in all subprojects
```
