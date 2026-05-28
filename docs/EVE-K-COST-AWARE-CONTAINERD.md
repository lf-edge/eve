# Cost-Aware Kubernetes / containerd Downloads

When EVE is built for Kubernetes (`HV=k`), several downloads happen outside
pillar's own downloader: the kube containerd pulls pod and system images, the
k3s installer fetches the k3s script and binary, and `kubectl apply -f
https://...` fetches component manifests. This document describes how EVE makes
those downloads honor the `network.download.max.cost` configuration through the
`mgmtproxy` pillar agent.

The `mgmtproxy` agent only exists in `HV=k` builds; on KVM/Xen builds it is a
no-op stub. Everything described here applies to Kubernetes-driven downloads
only.

## Overview

`network.download.max.cost` controls which network uplinks EVE uses for
downloads. Pillar's built-in downloader already honors it: it iterates
management ports in ascending cost order, binds the outbound socket to each
port's source IP, and uses the first port that provides working connectivity to
the destination.

The downloads listed above run in the host network namespace and use the
kernel's `table main` directly, so they do not participate in that per-port
selection. When the lowest-cost gateway is unreachable, `table main`'s default
route still points at it, and these downloads time out with no automatic
fallback to a healthy higher-cost uplink.

`mgmtproxy` closes that gap. It runs an HTTP CONNECT forward proxy on
`127.0.0.1:5443`, reusing the same source-IP-binding primitives as pillar's
downloader, and `HTTPS_PROXY` is injected into the affected subprocesses so
their HTTPS connections tunnel through it.

## Architecture

```text
┌──────────────────── pillar (starts before containerd) ───────────────┐
│                                                                      │
│  nim ────publishes──► DeviceNetworkStatus                            │
│                              │                                       │
│  zedagent ──publishes──► ConfigItemValueMap                          │
│                              │  (network.download.max.cost)          │
│  mgmtproxy ◄──subscribes─────┘                                       │
│     │  127.0.0.1:5443                                                │
│     └──publishes──► MetricsMap ──► edgeview url                      │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ CONNECT registry:443
                               │
      ┌────────────────────────┼──────────────────────────────────────┐
      │ HTTPS_PROXY injected   │                                      │
      │ at four places:        │                                      │
      │                        │                                      │
      ▼                        ▼                                      ▼
kube containerd       k3s installer + curl                  kubectl subprocess
(check_start_         (cluster-update.sh)                   (shell mgmtproxy_run
 containerd)                                                 + Go cmd.Env)
      │                        │                                      │
      └────────────────────────┴──────────────────────┬───────────────┘
                                                      │
                                            mgmtproxy dials outbound:
                                                      │
                        ┌─────────────────────────────┴──────────┐
                        │                                        │
                  1. eth0 (cost=0)                        2. eth1 (cost=1)
                  bind src=192.168.1.89                   bind src=10.0.0.5
                  ip rule → table-eth0                    ip rule → table-eth1
                  table-eth0: via gw-eth0 ✗               table-eth1: via gw-eth1 ✓
                  (dial timeout → skip)                          │
                                                                 │ TCP tunnel
                                                                 ▼
                                                       registry-1.docker.io:443
                                                       (or github.com:443,
                                                        raw.githubusercontent.com:443)
```

Binding the outbound socket to a port's source IP sends the packet through that
port's per-port routing table, bypassing `table main` entirely — so a dead
cost-0 gateway in `table main` never pins the connection to a broken uplink.

## How cost-aware routing works

NIM maintains one routing table per management port (kernel table index
`DPCBaseRTIndex + ifIndex`). For each port source IP it installs an IP rule:

```text
from <srcIP> lookup table-<port>
```

Each per-port table carries that port's own default route via its own gateway,
independent of `table main`. When a process binds its outbound socket to a
port's source IP, the packet is routed through that port's table — not `table
main`.

EVE's model is to select, per connection, the cheapest interface that provides
**working connectivity to the given destination** — it is not a single default
route shared by all traffic. Pillar's downloader implements this by trying each
port in cost order and binding to its source IP, treating an actual connection
attempt as the reachability signal. `mgmtproxy` exposes the same mechanism to
containerd and to kubectl-spawned HTTP clients via the standard `HTTPS_PROXY`
environment variable.

## The two containerd processes

An `HV=k` device runs two distinct containerd instances:

- **Pillar containerd** — runs inside the pillar container, used by pillar's own
  image management. It is already cost-aware via pillar's downloader
  (`controllerconn/send.go`) and is not involved here.
- **Kube containerd** — a standalone process launched by `cluster-init.sh`
  (`check_start_containerd`), used by k3s/Kubernetes to pull pod images, system
  component images (CoreDNS, Longhorn, KubeVirt, Multus, pause), and user
  application images. It uses `table main` directly.

The k3s server process (kubelet, apiserver, controller-manager, scheduler) is
separate from the kube containerd. `HTTPS_PROXY` is scoped to the kube
containerd process only — exporting it to the k3s server would route
in-cluster HTTPS through the proxy and break the cluster.

## How mgmtproxy works

- **Listeners.** `127.0.0.1:5443` (`ListenAddr`) serves host processes (kube
  containerd, k3s installer curl, kubectl subprocesses). On KubeVirt-enabled
  nodes a second listener on `169.254.100.1:5443` (`CNI0ListenAddr`, the cni0
  link-local anchor IP) serves CDI importer pods, which run in the pod network
  and cannot reach loopback. Both bind to specific internal IPs, never
  `0.0.0.0`.
- **CONNECT only.** `GET /healthz` returns a JSON state snapshot; anything else
  is rejected. Plain-HTTP forwarding is not implemented — every relevant target
  (registries, `get.k3s.io`, GitHub) is HTTPS.
- **Subscriptions.** `DeviceNetworkStatus` from nim (port enumeration, costs,
  source IPs, failure flags) and `ConfigItemValueMap` from zedagent
  (`network.download.max.cost`). The per-attempt dial timeout is taken from the
  existing `timer.dial.timeout` config item.
- **Per CONNECT request.** It calls `GetMgmtPortsSortedCostWithoutFailed`,
  filters out ports above the configured max cost, and tries each port's
  non-link-local source IP in turn, binding the outbound socket to it. Selection
  round-robins within a cost tier (the rotation argument) so load is shared
  across same-cost ports. The first port that connects wins.
- **Metrics.** It publishes a `MetricsMap` with per-interface, per-target byte
  counters, visible in `edgeview url` and queryable via `pub/mgmtproxy`.
- **Resilience.** A failed `listen` (port conflict) is logged and retried rather
  than crashing pillar.

## Where HTTPS_PROXY is injected

| Egress path | Mechanism | Cost-aware? |
| --- | --- | --- |
| k3s installer script + binary download | curl + spawned installer in `cluster-update.sh` | Yes — `HTTPS_PROXY` exported on both |
| Pod / system images (pause, CoreDNS, Longhorn, KubeVirt, Multus, app images) | kube containerd CRI | Yes — `HTTPS_PROXY` on containerd |
| External boot image import | `k3s ctr image import` → containerd socket | Yes — covered by containerd's env |
| KubeVirt CR install | `kubectl apply -f https://...` via `mgmtproxy_run` | Yes |
| CDI install / uninstall | `kubectl create/delete -f https://...` via `mgmtproxy_run` | Yes |
| Longhorn uninstall | `kubectl create/delete -f https://...` via `mgmtproxy_run` | Yes |
| Dynamic component upgrade | Go `KubectlApply` in `update-component`, injects `cmd.Env` for HTTPS paths | Yes |
| CDI importer pods (`source.http.url` DataVolumes) | CDI CR `importProxy.HTTPSProxy` → cni0 listener | Yes |
| KubeVirt launcher image | bundled in kube package, `PullNever` | n/a — never pulled at runtime |
| VM disk images | pillar downloader → PVC | already cost-aware |

Not covered, by design:

- **Pillar containerd** — already cost-aware.
- **Plain-HTTP targets** — `HTTP_PROXY` is not injected; all relevant targets
  are HTTPS.
- **Host-netns traffic outside the inventoried paths** — interactive shell
  sessions (`eve enter kube`), arbitrary host scripts, k8s components inside the
  k3s server process.
- **Local-file kubectl applies** — no external HTTP call; resulting image pulls
  go through containerd, which is covered.
- **Build-time downloads** — happen on the build machine, not the edge node.

## HTTPS_PROXY is per-process

The proxy env is injected onto specific subprocesses, never globally. This is
load-bearing for cluster correctness:

| Command | Through mgmtproxy? |
| --- | --- |
| `curl https://registry-1.docker.io/v2/` | No — direct via `table main` |
| `curl --proxy http://127.0.0.1:5443 https://registry-1.docker.io/v2/` | Yes |
| `crictl pull <image>` | Yes — real containerd path |
| `kubectl apply -f https://.../foo.yaml` (bare from shell) | No — direct via `table main` |
| `mgmtproxy_run kubectl apply -f https://...` (after sourcing `cluster-utils.sh`) | Yes |

- `cluster-init.sh:check_start_containerd` prepends `HTTPS_PROXY=...` inline on
  the `nohup containerd ...` command, so only the standalone containerd process
  gets it. The k3s server process does not.
- `cluster-update.sh` prepends it on the `curl https://get.k3s.io` and the
  spawned installer subprocess.
- `cluster-utils.sh:mgmtproxy_run` prepends it on whichever command is passed to
  it. Local-file kubectl calls are not wrapped.
- `update-component/upgrades.go:KubectlApply` sets `cmd.Env` on the kubectl
  subprocess only when the path is an HTTPS URL and the off-switch is absent.

`NO_PROXY` assembled at injection time covers loopback, the k3s pod and service
CIDRs, link-local (including the metadata server at `169.254.169.254`), the k8s
DNS suffixes, and the cluster node IP, so in-cluster and local traffic never
goes through the proxy.

## Off-switch

Creating `/run/kube/mgmtproxy-disable` makes both the shell `mgmtproxy_run`
helper and the Go `KubectlApply` run wrapped commands directly, without
`HTTPS_PROXY`. For containerd, `killall containerd` causes `cluster-init.sh` to
relaunch it without the proxy env. Useful for isolating whether mgmtproxy is the
cause of a download failure. Remove the flag (and restart containerd if killed)
to re-enable.

## Observability

- **Pillar logs.** One line per CONNECT at default level, e.g.
  `mgmtproxy: CONNECT registry-1.docker.io:443 via eth0 src 192.0.2.5 cost 0 (dial 12ms, 0 fallback(s))`.
  `N fallback(s)` reports how many ports were tried and failed before the
  winning one — automatic recovery without operator action.
- **Caller-side audit trail.** Each wrapped fetch logs a `mgmtproxy_run: ...` or
  `KubectlApply: ...` line in the kube install / upgrade logs that pairs with the
  pillar-side CONNECT entry.
- **`edgeview url`.** Shows a `mgmtproxy stats` block with per-target Recv/Sent
  bytes, connection counts, and total time.
- **`/healthz`.** `curl -s http://127.0.0.1:5443/healthz | jq` returns listening
  status, readiness, max port cost, per-port cost/error/addresses, counters, and
  the last success/error with timestamps.
- **Sentinel file.** `/run/mgmtproxy-containerd-env` records the exact env
  containerd was launched with. It is more reliable than `/proc/<pid>/environ`
  because containerd unsets `HTTPS_PROXY` from its own process env shortly after
  reading it.

The agent's package README (`pkg/pillar/cmd/mgmtproxy/README.md`) carries the
full debugging workflow and developer-facing implementation detail.

## Known limitations

- **Stale `NO_PROXY` on node-IP change.** If the cluster node IP changes after
  containerd starts, `NO_PROXY` is stale until containerd restarts. The wide
  CIDRs absorb most cases.
- **CONNECT only.** Plain-HTTP is not proxied.
- **IPv6.** Inherits `controllerconn`'s IPv4-centric mgmt-port iteration;
  IPv6-only registries would bypass cost gating.
- **Half-broken upstream.** A port that accepts the connection but blackholes
  payload causes a few minutes of `ImagePullBackOff` retries before NIM's
  failure flag skips it. Self-healing without operator action.

## Underlying gap and follow-up

EVE already selects, per connection, the cheapest interface with working
connectivity to a given destination — pillar's downloader and `mgmtproxy` both
work this way. The gap that `mgmtproxy` addresses is narrower: host-namespace
traffic that uses `table main` (the kube containerd and kubectl URL fetches)
does not participate in that per-destination selection, because `table main`
carries a single default route the kernel follows regardless of whether the
destination is actually reachable through it.

`mgmtproxy` closes the gap for the inventoried containerd and kubectl paths. A
broader follow-up could extend per-destination, cost-aware selection to all
host-namespace outbound traffic so that paths outside this inventory benefit
automatically.
