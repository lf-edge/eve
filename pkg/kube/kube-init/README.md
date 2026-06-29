# kube-init

`kube-init` is the Go daemon that drives the kube container's lifecycle on
EVE-K nodes: prerequisites, k3s install / config / supervision, components
(KubeVirt, CDI, Longhorn, Multus, descheduler), single↔HA cluster
transitions, and cluster-update orchestration. It replaces the previous
`pkg/kube/cluster-init.sh` shell pipeline.

`k3s-sctl` is the operator-facing CLI client that talks to the daemon's
control socket; the shell aliases `k3s-control`, `k3s-start`, `k3s-stop`,
`k3s-status` are thin wrappers around it.

## Architecture in one paragraph

`kube-init` is a state machine. Boot-time work (prereqs, identity, vault,
k3s install) runs sequentially. Once components are deployed, the FSM
moves to a steady-state RUNNING state with a per-tick health worker that
reapplies idempotent component config, runs storage policy, sweeps stale
masterleases, and watches for cluster-config changes. The supervisor
subprocess owns the k3s server; pre-restart hooks let kube-init insert
work (e.g. RT cgroup setup) between stop and start without re-implementing
the supervisor.

State markers under `/var/lib/` are the persistent crash-tolerant store.
Pillar-published pubsub topics are read via subscriptions
(see `pubsubclient`). Inter-process I/O with k3s goes through `kubectlx`,
which wraps `k3s kubectl` / `k3s ctr` / `crictl`.

## Package map

| Package | Responsibility |
|---|---|
| `main` | FSM: states, events, dispatch, signal handling. The control socket lives in `cmd/k3s-sctl`. |
| `state` | Marker primitives (`Mark`/`Unmark`/`IsMarked`), reboot reasons, atomic file write. |
| `prereqs` | Kernel modules, /persist mounts, vault wait, EdgeNodeInfo arrival, containerd launch. |
| `k3s` | k3s install, config rendering, supervisor, readiness, token rotation, cluster status. |
| `components` | Multus, KubeVirt, CDI, Longhorn, descheduler, debug-user RBAC, kube-vip, storage classes. |
| `deploy` | Declarative DAG runner for the deploy graph (parallelism, deps, BestEffort). |
| `clustermode` | Single↔HA transitions, startup-rank stagger, stale masterlease sweep. |
| `monitor` | Steady-state watchers: cluster-config polling, user-overrides, log rotation, node-label drift. |
| `update` | Cross-reboot upgrade flow for k3s + cluster components, KubeClusterUpdateStatus gating. |
| `images` | Pre-packaged tarball import (external-boot-image, rt-operator, KubeVirt/CDI/Longhorn). |
| `tiebreaker` | Three-node HA: label/cordon the tie-breaker, scale operator deployments, patch DaemonSets. |
| `vnc` | VNC proxy for KubeVirt VMIs; consumes `/run/edgeview/VncParams/`. |
| `mgmtproxy` | HTTPS_PROXY/NO_PROXY env injection for containerd; cni0 anchor IP; CDI proxy patch. |
| `pubsubclient` | Façade over pillar's pubsub library — shared `Manager` with deferred-activate + `MultiChannelWatch`. |
| `edgenodeinfo` | Subscription to `EdgeNodeInfo` (device identity). |
| `kubeconfig` | Subscription to `KubeConfig` (k3s version override). |
| `kcus` | Subscription to `KubeClusterUpdateStatus` (upgrade retry gating). |
| `encconfig` | Subscription to `EdgeNodeClusterConfig` (cluster shape, tie-breaker UUID). |
| `encstatus` | Subscription to `EdgeNodeClusterStatus` (bootstrap server, cluster UUID). |
| `kubectlx` | Thin wrappers around `k3s kubectl` / `k3s ctr` / `crictl`. |

## Pubsub migration status

As of Phase 5 of the port, all five pillar-published JSON files that
kube-init used to poll are now real pubsub subscriptions (see the
package list above). Three latent bugs were fixed by the migration —
JSON-tag mismatches in `KubeConfig` and `KubeClusterUpdateStatus`, and
a bootstrap-probe stat that missed the zero-UUID delete sentinel.

## Possible future improvements

The list below captures work deliberately deferred. Each item is
self-contained; no ordering between them.

### 1. Remove the last three controller-pushed file polls

Three files written by pillar are still read directly from disk
instead of subscribed via pubsub. Each would need a pillar-side change
(or a kube-init-side subscription to an existing topic that already
carries the data).

- **`/persist/vault/k3s-user-override.yaml`** — written by zedkube's
  `handleK3sConfigOverrideChanged` from the global setting
  `k3s.config.override` (a base64 string in `ConfigItemValueMap`).
  Options:
  - Subscribe to `ConfigItemValueMap` in kube-init and read
    `GlobalValueString(types.K3sConfigOverride)` directly (no new
    pillar topic; couples kube-init to the global-config schema).
  - Or pillar publishes a tiny `K3sUserOverride` topic post-decrypt.

- **`/persist/vault/manifests/registration.yaml`** — zedkube decrypts
  `EdgeNodeClusterConfig.CipherGzipRegistrationManifestYaml` and
  writes the result. The encrypted bytes already arrive via the
  `EdgeNodeClusterConfig` subscription kube-init has. Options:
  - Move the cipher-decrypt into kube-init's `encconfig` handler
    (requires exposing the decryption helper from pillar in a
    library-friendly form).
  - Or pillar publishes a dedicated `RegistrationManifest` topic
    post-decrypt.

- **`/run/eve-release`** — EVE's release-version string, written by
  some early-boot init step. Read once in `prereqs.RunAll` via a
  blocking `waitForFile`. Could ride on `EdgeNodeInfo` (one extra
  field) or get its own small topic. Static for the device's lifetime,
  so the 1 s poll cost is essentially nil; this is a "for purity"
  fix rather than a performance one.

### 2. Make `monitor.ClusterConfig` push-based end-to-end

The cluster-config monitor still runs on `clusterPollInterval` (5 s)
because its decision mixes the `EdgeNodeClusterStatus` subscription
(now push-based) with two kube-init-internal markers
(`AllComponentsInitialized`, `EdgeNodeClusterMode`) and a periodic
`CheckClusterTransitionDone` retry.

To make it fully push-driven:

- Convert the markers to in-process channel signals — the write site
  (`state.Mark` callers) notifies subscribed handlers. No filesystem
  polling needed for marker reads.
- Keep a small ticker just for `CheckClusterTransitionDone` (which
  genuinely needs cadence — it polls kubectl for Ready node count).
- The ENC-status part becomes a `pubsub.SubscriptionOptions.ModifyHandler`
  on `encstatus` that fires `restartCh` directly.

This is a kube-init-internal refactor — no pillar work.

### 3. Drop the bootstrap-probe `InsecureSkipVerify`

`k3s.waitForBootstrapServer` dials the bootstrap node's self-signed
cert with TLS verification disabled (documented + CodeQL-suppressed
at the call site). The architectural reason — the cluster UUID is the
load-bearing authentication, the TLS layer is bootstrap — is sound,
but the suppression is still a code-scanner finding the reviewer must
dismiss every time.

The cleanest fix is pinning the bootstrap cert fingerprint via the
ENC-status subscription. That requires pillar's zedkube to include a
fingerprint of the bootstrap node's k3s server cert in
`EdgeNodeClusterStatus`. Substantial pillar work; deferred until
someone wants to push hard on the audit finding.

### 4. Subscribe instead of file-watch for `eve-release`

If the eve-release file gets a pubsub topic (see item 1), the
`waitForFile` + `os.ReadFile` in `prereqs.RunAll` becomes a
`WaitForFirst`-style blocking subscription read, matching the shape
of `edgenodeinfo.WaitForFirst`. The shared `pubsubclient.Manager`
makes adding the wiring a single-Register call.

### 5. Push-ify the user-override apply loop

`monitor.UserOverridesLoop` polls `UserOverrideSrc` at
`overridePollInterval`. If item 1 lands, that file becomes a
subscription and the loop becomes a `ModifyHandler` that fires the
restart channel directly — same shape as the proposed
`monitor.ClusterConfig` cleanup.

### 6. Consolidate the `*JSON` test seeding patterns

The current encconfig/encstatus/kubeconfig/kcus/edgenodeinfo packages
each export their own `SetForTest`/`ResetForTest` helpers. The
helpers are nearly identical (mutex + cache pointer + first-channel
for ENI). A small test-only `pubsubtest` package could expose a
generic `Stage[T any](manager, label, value)` helper that drives the
real subscription's CreateHandler via reflection, removing the
per-package boilerplate. Low priority — the current pattern works
and stays out of production code.

### 7. CI drift check for the pillar pseudo-version

`go.mod` pins `github.com/lf-edge/eve/pkg/pillar` at a specific
upstream commit. When pillar's published types change, kube-init's
vendored copy will silently drift unless the pseudo-version is
bumped. mmagent has the same exposure. A CI check that diffs the
vendored `pkg/pillar/types/` against `HEAD` of `lf-edge/eve` on
relevant types would surface the gap. Out of scope for kube-init
specifically — repo-wide concern.

## Building locally

The kube-init Go module is self-contained:

```
cd pkg/kube/kube-init
go build ./...
go test ./...
```

For the full kube container image, the top-level Makefile target is
`pkg/kube` (or `make pkg/kube` from the repo root).
