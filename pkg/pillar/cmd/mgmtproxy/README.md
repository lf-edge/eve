# mgmtproxy

Cost-aware HTTP CONNECT forward proxy on the loopback interface, used by EVE-K
to make containerd image pulls and the runtime k3s download honor
`network.download.max.cost`.

## Routing diagram

**Before — containerd uses `table main` directly:**

```text
containerd ──────────────► table main ──► eth0 gateway (dead) ──► TIMEOUT
                            (kernel picks                         ImagePullBackOff
                             lowest metric; unaware gw is down)       ✗
```

**After (this change) — containerd tunnels through the cost-aware proxy:**

```text
  ┌──────────────────────────────── pillar (starts before containerd) ──┐
  │                                                                      │
  │  nim ────publishes──► DeviceNetworkStatus                            │
  │                              │                                       │
  │  zedagent ──publishes──► ConfigItemValueMap                          │
  │                              │  (network.download.max.cost)          │
  │  mgmtproxy ◄──subscribes─────┘                                       │
  │     │  127.0.0.1:5443                                                │
  │     └──publishes──► MetricsMap ──► edgeview url                      │
  └──────────────────────────────┬───────────────────────────────────────┘
         HTTPS_PROXY=http://127.0.0.1:5443 (injected by cluster-init.sh)
                                 │ CONNECT registry:443
  ┌──────────────────────────────▼──────────────────────────────────────────┐
  │  kube containerd  (check_start_containerd; separate from pillar)        │
  │  /var/lib/rancher/k3s/data/current/bin/containerd                       │
  │  NOTE: pillar containerd (used by pillar's own downloader) is a         │
  │        different process and is already cost-aware — not patched here.  │
  └─────────────────────────────────────────────────────────────────────────┘
                                 │ CONNECT registry:443
                          mgmtproxy dials outbound:
                                 │
              ┌──────────────────┴──────────────────────┐
              │                                          │
        1. eth0 (cost=0)                          2. eth1 (cost=1)
        bind src=192.168.1.89                     bind src=10.0.0.5
        ip rule: from 192.168.1.89                ip rule: from 10.0.0.5
                 lookup table-eth0                         lookup table-eth1
        table-eth0: via gw-eth0 ✗                table-eth1: via gw-eth1 ✓
        (dial timeout → skip)                              │
                                                           │ TCP tunnel
                                                           ▼
                                                 registry-1.docker.io:443
```

**Key insight:** NIM maintains a per-port routing table (`DPCBaseRTIndex+ifIndex`)
with a `from <srcIP> lookup <table>` ip rule for each management port IP.  When
the proxy binds its outbound socket to a port's source IP the packet travels
through *that port's table* — bypassing `table main` entirely.  A dead cost-0
gateway in `table main` never pins containerd to a broken uplink.

## Why this exists

Pillar's downloader (`controllerconn/send.go`) iterates management ports in
ascending cost order and binds the outbound socket to each port's source IP.
NIM has installed `from <srcIP> lookup <port-table>` IP rules
(`dpcreconciler/linux.go:getIntendedSrcIPRules`), so packets bound to a port's
source IP go through that port's per-port routing table — not `table main`.
This is why pillar's downloader keeps working even when `table main`'s default
route still points at a dead gateway.

EVE-K has two containerd processes: the **pillar containerd** (inside the
`pillar` container, used by pillar's own image management, already cost-aware
via `controllerconn/send.go`) and the **kube containerd** (a standalone process
launched by `check_start_containerd` in `cluster-init.sh`, used by k3s to pull
pod and system images).
The kube containerd does its own image pulls using `table main` directly and has
no equivalent of the cost-aware loop. When the preferred (cost-0) uplink's
gateway is unreachable but a higher-cost backup is healthy, NIM updates per-port
tables and the DPC, but `table main` still points at the dead gateway and the
kube containerd times out (`ImagePullBackOff`).

`mgmtproxy` exposes pillar's existing source-IP-binding mechanism to
containerd via the standard `HTTPS_PROXY` env var. Containerd sends
`CONNECT <registry>:443` to `127.0.0.1:5443`; the proxy iterates mgmt ports
by ascending cost (filtered by `network.download.max.cost`) and tunnels via
the first port whose dial succeeds.

## What it covers

- **Kube containerd** image pulls (every k8s/kubevirt component image, plus user
  app images), via `HTTPS_PROXY` set on the standalone kube containerd at
  `check_start_containerd` in `pkg/kube/cluster-init.sh`. The pillar containerd
  is unaffected — it is a
  separate process already covered by pillar's own cost-aware downloader.
- `k3s ctr image import` for the external boot image — the `ctr` CLI talks to
  the running containerd's socket, so its env doesn't matter; what matters is
  that containerd dials outbound through the proxy.
- The k3s installer download (`curl https://get.k3s.io`) in `update_k3s`
  (`pkg/kube/cluster-update.sh`), via the same `HTTPS_PROXY` exported into
  the curl environment.
- **`kubectl apply -f https://...` manifest fetches** — KubeVirt CR, CDI
  operator/CR install + uninstall, and Longhorn uninstall use the
  `mgmtproxy_run` helper in `pkg/kube/cluster-utils.sh`. These calls
  bypass containerd entirely (kubectl does its own HTTP fetch) and would
  otherwise route through `table main` on every install/uninstall. Each call
  writes a `mgmtproxy_run: routing through proxy ...` line to the kube install
  log so it pairs 1:1 with the pillar-side `mgmtproxy: CONNECT ...` entry.
- **Dynamic component upgrades** — the Go `KubectlApply` in
  `pkg/kube/update-component/upgrades.go` injects `HTTPS_PROXY`/`NO_PROXY`
  into the `kubectl apply -f https://...` subprocess when the path is an
  HTTPS URL and the operator off-switch is not set. This covers
  arbitrary-version YAML pulls at upgrade time over expensive/slow links.

- **CDI importer pods** — when a Rancher/Helm chart deploys a VMIRS with a
  `DataVolumeTemplate` that uses `source.http.url` or `source.registry.url`,
  CDI creates an importer pod that fetches the VM disk image from the external
  URL. These pods run in the k3s pod network (10.42.x.x) and cannot reach
  `127.0.0.1:5443`. To cover them, `cluster-init.sh:setup_cni0_proxy_ip()`
  assigns a well-known link-local IP (`169.254.100.1/32`) to `cni0` on every
  kubevirt-enabled node (only when `install_kubevirt=1`). mgmtproxy gains a
  second listener on `169.254.100.1:5443`. After CDI installs,
  `cluster-init.sh:patch_cdi_proxy_config()` patches the CDI CR
  (`spec.config.importProxy.HTTPSProxy`) to inject
  `HTTPS_PROXY=http://169.254.100.1:5443` into every importer pod CDI creates.
  Link-local addresses are not routed by flannel across nodes, so each importer
  pod always reaches its own node's mgmtproxy — the right uplinks are used even
  in multi-node clusters. EVE-managed VM volumes (controller-deployed apps)
  are unaffected: they use `virtctl image-upload` → CDI upload-proxy service
  (10.43.x.x, already in NO_PROXY), which is a `source.upload` DataVolume —
  not an importer pod, no external fetch.

What it does **not** cover (by design): VM disk images already flow through
pillar's cost-aware downloader and are mounted as PVCs, so they need nothing
extra. KubeVirt launcher images are bundled in the kube package
(in the kube package `Dockerfile`, `ImagePullPolicy: PullNever`) and never
pulled at runtime.
Plain-HTTP forwarding is not implemented — every relevant target
(`get.k3s.io`, registries, GitHub) is HTTPS, and CONNECT-only keeps the
implementation small and avoids touching auth headers.

## Port choice and listeners

The proxy listens on two addresses:

- **`127.0.0.1:5443`** (`ListenAddr`) — host processes: kube containerd, k3s
  installer curl, kubectl subprocesses. Active from pillar startup.
- **`169.254.100.1:5443`** (`CNI0ListenAddr`) — CDI importer pods via the cni0
  bridge. Active after `cluster-init.sh:setup_cni0_proxy_ip()` assigns
  `169.254.100.1/32` to `cni0` (only on kubevirt-enabled amd64 nodes). The
  second goroutine retries silently every 30s until the IP is assigned, which
  may be several minutes after pillar starts.

Port 5443 is unused inside EVE and is not a well-known port for anything in
EVE-K — k8s/k3s use 6443/9345/10250-range, kubevirt and longhorn use other
ranges, and IANA's nominal `spss` registration is inactive in practice. The
known external conflict is VMware NSX-T (uses 5443 for its manager API), which
isn't relevant on EVE.

If a `listen` ever fails (port taken by something unexpected), the agent
logs an error and retries every 30s rather than crashing pillar. Containerd
pulls hit `ECONNREFUSED` while listen is blocked; kubelet's
`ImagePullBackOff` carries the retry. The off-switch flag
(`/run/kube/mgmtproxy-disable`) lets an operator bypass mgmtproxy entirely
if the conflict is permanent — see the Debugging section.

To change the port: edit `ListenAddr` and `CNI0ListenAddr` in `mgmtproxy.go`,
`MGMTPROXY_URL` and `MGMTPROXY_CNI0_URL` in `pkg/kube/cluster-utils.sh`, and
`mgmtproxyURL` in `pkg/kube/update-component/upgrades.go` together.

## Network exposure and firewall

Both listeners bind to **specific internal IPs** (`127.0.0.1` and the cni0
link-local `169.254.100.1`), never to `0.0.0.0`, so the proxy is not exposed on
any uplink IP. Inbound port 5443 from an external interface is blocked at three
layers:

1. **Binding** — nothing listens on an uplink IP, so an inbound SYN to
   `<uplink-ip>:5443` has no socket to reach.
2. **Per-uplink default-DROP** — EVE's filter `INPUT` chain ends with a
   `-i <uplink> -j DROP` for every L3 port (`dpcreconciler/linux.go`,
   `getIntendedFilterRules`); 5443 is never accepted, so it is dropped.
3. **Explicit per-uplink DROP for 5443** — on EVE-K (`HVTypeKube`),
   `getIntendedFilterRules` additionally emits an explicit
   `-i <uplink> -p tcp --dport 5443 -j DROP` per L3 uplink, for auditable
   defense-in-depth. It is **interface-scoped to uplinks**, so it never matches
   `lo` (host containerd / kubectl) or `cni0` (CDI importer pods,
   source `10.42.x.x`) — those intended paths keep working.

The cni0 link-local listener needs no NAT and no per-NI rule (unlike the
metadata server at `169.254.169.254`, which DNATs to the NI bridge IP and adds a
`physdev` DROP for switch NIs): `cni0` is a single, internal-only pod bridge
that is never bridged to a physical uplink, so there is no external L2 leak path
to block.

## Build tag

This agent only ships in EVE-K (`//go:build k`). On KVM/Xen builds the package
contains a no-op stub (`nomgmtproxy.go`), the same pattern `zedkube` uses.

## Why a dedicated agent

Downloader is RPC-driven (verb-shaped: "download this URL into this volume");
this proxy is connection-shaped (tunnel arbitrary CONNECT requests for
arbitrary registries). The lifecycles and concurrency models are different
enough that grafting the proxy onto downloader (or onto NIM) would mix
concerns. Following EVE's "one agent per concern" pattern.

## Subscriptions

- `DeviceNetworkStatus` from `nim` — used to enumerate management ports, their
  costs, source IPs, and `LastFailed` flags.
- `ConfigItemValueMap` from `zedagent` — reads `network.download.max.cost` (max
  port cost to use) and `timer.dial.timeout` (per-attempt upstream dial
  timeout).

## Observability

The proxy is built so a single tail of pillar logs tells you what it's doing.

**At default log level you see:**

- `mgmtproxy: listening on 127.0.0.1:5443` — once at startup.
- `mgmtproxy: CONNECT <target> from <clientAddr> via <ifName> src <ip> cost N (dial Xms, Y fallback(s))` —
  one line per CONNECT request, every time. `clientAddr` is the source of the
  incoming connection: `127.0.0.1:PORT` means a host process (containerd,
  kubectl); `10.42.x.x:PORT` means a CDI importer pod via the cni0 listener.
  `Y fallback(s)` is the number of attempts that failed before the winning one
  — `0` is the happy path, anything `>0` is automatic recovery.
- `mgmtproxy: CONNECT <target> from <clientAddr> FAILED after Xms: <details>` —
  one line per fully-failed request, with per-port attempt details.
- `mgmtproxy: tunnel idle for 30s, closing` — when the idle watchdog fires.

**`edgeview url`** shows mgmtproxy alongside the other agents that publish
`MetricsMap` (zedagent, downloader, nim, ...). The proxy publishes per-target
and per-interface byte counts, success/failure history, and total time at
`/run/mgmtproxy/MetricsMap/global.json`, refreshed every 10s. Read it via:

```sh
edgeview url
```

Look for the `- mgmtproxy stats` block. Each registry/host gets its own line
with `Recv (KBytes)`, `Sent`, `SentMsg`, and `Total Time(sec)`. The "TLS
resume" column is always 0 — the proxy CONNECTs but doesn't terminate TLS.

**Controller metrics.** `zedagent` subscribes to mgmtproxy's `MetricsMap`
(`cmd/zedagent/zedagent.go`, `AgentName: "mgmtproxy"`) and folds it into the
device `ZedcloudMetric` report via `mgmtProxyMetrics.AddInto(cms)` in
`handlemetrics.go` — the same aggregation path used for nim, downloader,
loguploader, and zedrouter. So mgmtproxy's per-interface success/failure
counts and per-URL byte/time counters reach zedcloud alongside the other
agents' connectivity metrics, not just `edgeview url`. On non-EVE-K builds the
agent is a no-op stub that never publishes, so the subscription stays empty and
contributes nothing.

**`/healthz` endpoint** at `http://127.0.0.1:5443/healthz` returns a JSON
snapshot. From the host (or via `crictl exec` on a debug pod):

```sh
curl -s http://127.0.0.1:5443/healthz | jq
```

Returns: `listening` (loopback address), `cni0Listening` (true once
`169.254.100.1:5443` is active — the CDI importer pod path), `ready` (pubsub
initialized), `maxPortCost`, an array of mgmt `ports` with their `cost`,
`hasError`, `lastError`, `numAddrs` and `usableAddr` (the source IP the dialer
would use), per-port success/failure counters, total bytes transferred, and
the `lastSuccess` / `lastError` summary with timestamps.

This is the single best signal for "is mgmtproxy seeing my pull, and which
port is winning?"

## How `HTTPS_PROXY` is scoped (read this first)

The proxy env is **per-command, not per-shell**. Specifically:

- `cluster-init.sh:check_start_containerd` prepends `HTTPS_PROXY=...` inline
  on the `nohup containerd ...` command — only the standalone containerd
  process gets the env. Kubelet, apiserver, controller-manager, scheduler
  (all inside the separate `k3s server` process started by `check_start_k3s`)
  do **not** see `HTTPS_PROXY`. This is intentional: a global export here would
  route
  intra-cluster HTTPS through the proxy and break the cluster.
- `cluster-update.sh:update_k3s` prepends `HTTPS_PROXY=...` inline on the
  `curl https://get.k3s.io` and the spawned installer subprocess.
- `cluster-utils.sh:mgmtproxy_run` (helper) prepends `HTTPS_PROXY=...` on
  whichever command is passed to it — used by `kubevirt-utils.sh` and
  `longhorn-utils.sh` to wrap `kubectl apply/create/delete -f https://...`
  manifest fetches. Local-file `kubectl` calls in those scripts are NOT
  wrapped — they don't make external HTTP calls.
- `update-component/upgrades.go:KubectlApply` (Go) sets `cmd.Env` on the
  `kubectl` subprocess when the path is an HTTPS URL and the off-switch
  flag is absent. Same scoping principle: only the kubectl subprocess gets
  the env, never the parent update-component or k3s server.

Practical consequence: when you `eve enter kube` and get an interactive
shell, you do **not** inherit `HTTPS_PROXY`. A bare `curl https://<host>`
from that shell goes out via the kernel's `table main` — which is exactly
the path that's broken when the cost-0 gateway is dead, and *not* the path
containerd takes.

This matters for diagnosis. These three commands answer different questions:

| Command | Path | Through mgmtproxy? |
| --- | --- | --- |
| `curl https://registry-1.docker.io/v2/` | direct via `table main` | **No** |
| `curl --proxy http://127.0.0.1:5443 https://registry-1.docker.io/v2/` | matches containerd's path | **Yes** |
| `crictl pull <image>` | real containerd pull | **Yes** |
| `kubectl apply -f https://github.com/.../foo.yaml` (bare from shell) | direct via `table main` | **No** |
| `mgmtproxy_run kubectl apply -f https://...` (after `. /usr/bin/cluster-utils.sh`) | matches install/uninstall scripts | **Yes** |

If a bare `curl` from `eve enter kube` succeeds but `crictl pull` fails,
**don't conclude the network is fine** — the bare `curl` does not exercise
the same code path as containerd. Use `--proxy` or `crictl pull` to
reproduce containerd's behavior.

To make a shell session behave like containerd does, source the helpers and
export the env:

```sh
. /usr/bin/cluster-utils.sh
export HTTPS_PROXY="$MGMTPROXY_URL"
export NO_PROXY="$(mgmtproxy_no_proxy)"
curl -v https://get.k3s.io/   # now goes through mgmtproxy
```

Unset both when you're done so the shell stops shadowing direct-path tests.

## Debugging workflow

When a pod is stuck in `ImagePullBackOff` or a VMI fails to start, work
through this in order:

**1. Did containerd actually get launched with HTTPS_PROXY?**

The authoritative answer is the sentinel file written by `cluster-init.sh`
at the moment of launch:

```sh
cat /run/mgmtproxy-containerd-env
# pid=14398
# started=2026-05-04T23:28:24+00:00
# HTTPS_PROXY=http://127.0.0.1:5443
# NO_PROXY=127.0.0.0/8,10.42.0.0/16,...,10.244.244.2
```

**Don't rely on `/proc/$PID/environ` for this check.** Containerd reads
`HTTPS_PROXY` at startup for its CRI image-pull client and then calls
`os.Unsetenv("HTTPS_PROXY")` to clear it from its own process env (a
Go-daemon convention). Within ~1s of launch, `cat /proc/$PID/environ`
will show `NO_PROXY` but **not** `HTTPS_PROXY`, even though the proxy
is correctly configured internally. Child processes spawned by containerd
(`containerd-shim-runc-v2`, `runc`, `iptables-restore`) still receive
`HTTPS_PROXY` in their env — visible via `cat /proc/<child-pid>/environ`
if you want corroborating evidence.

If the sentinel file says `HTTPS_PROXY=(disabled — flag ... present)`,
the off-switch is on (`/run/kube/mgmtproxy-disable`).
If the file is absent, the env-injecting branch of `check_start_containerd`
hasn't run since boot — check the logmsg in `/persist/kubelog/k3s-install.log`
for the matching `Started k3s-containerd at pid:N ...` line.

**2. Is mgmtproxy listening?**

```sh
ss -tln 'sport = :5443'
nc -zv 127.0.0.1 5443
curl -s http://127.0.0.1:5443/healthz | jq
```

If it's not listening, check pillar-side logs for `mgmtproxy:` lines —
particularly the `listening on` line at startup.

**3. Does the proxy see the pull request?**

Tail pillar logs and trigger a pull (`crictl pull <image>`). You should see:

```text
mgmtproxy: CONNECT registry-1.docker.io:443 via eth0 src 192.0.2.5 cost 0 (dial 12ms, 0 fallback(s))
```

Or run `edgeview url` and look at the `- mgmtproxy stats` block — the
per-target row for the registry should be growing.

If no `CONNECT` line appears and `edgeview url` shows no mgmtproxy entry for
that target, the pull traffic is bypassing the proxy — likely a `NO_PROXY`
match (cluster CIDR, etc.) or `HTTPS_PROXY` not set in containerd's env.

**3b. For kubectl URL-fetch failures (KubeVirt/CDI/Longhorn install/upgrade):**

The kubectl path leaves an audit trail in two places that should pair 1:1:

```sh
# Caller-side: did mgmtproxy_run fire at all?
grep "mgmtproxy_run:" /persist/kubelog/k3s-install.log

# Pillar-side: did the request reach mgmtproxy?
# (search via edgeview log search or local pillar log)
# look for: mgmtproxy: CONNECT github.com:443 ...
#                    or: raw.githubusercontent.com:443 ...
```

Equal counts within the same time window → wrapper wired correctly.
Caller log present but no CONNECT → the wrapper fired but the spawned
kubectl somehow didn't honor `HTTPS_PROXY` (would be a real bug; file).
Caller log absent → the call site is missing the `mgmtproxy_run` prefix
(grep `kubevirt-utils.sh longhorn-utils.sh` for raw `kubectl ... -f https://`).

For the Go upgrade path (`update-component/upgrades.go:KubectlApply`),
the equivalent caller log is in `/persist/kubelog/upgrade-component.log`:
`KubectlApply: routing through mgmtproxy: https://...`.

**4. Is the proxy succeeding but pulls still failing?**

Check the tunnel close line at Functionf level (raise log level if needed):

```text
mgmtproxy: tunnel <target> via <ifName> closed: up=N down=M duration=Xs idle=true|false
```

`idle=true` means the idle watchdog killed the tunnel — upstream stalled
mid-stream. `down=0` with a small `up` value means the upstream accepted the
connection but never sent response bytes (likely a half-broken firewall — the
"dial succeeds, content blackholes" case). Either way, kubelet retries with
`ImagePullBackOff` backoff and on retry NIM's `LastFailed` typically routes us
to a healthy port.

**5. Is mgmtproxy itself the issue? Bypass it temporarily.**

```sh
touch /run/kube/mgmtproxy-disable
killall containerd
# wait ~15s for cluster-init.sh's main loop to restart containerd without HTTPS_PROXY
```

Re-trigger the pull. If it now succeeds, the proxy or its config is the
issue; collect `/healthz` output and pillar logs and file. If it still fails,
the issue is in NIM's port state, the registry, or the network — mgmtproxy is
not the cause. Re-enable with `rm /run/kube/mgmtproxy-disable && killall containerd`.

**6. Is NIM's view of ports matching reality?**

Cross-reference `/healthz` output with NIM's published status:

```sh
cat /persist/status/nim/DeviceNetworkStatus/global.json | jq '.Ports[] | {IfName, Cost, IsMgmt, LastError, AddrInfoList: [.AddrInfoList[].Addr]}'
ip route show table main
ip rule list
```

If `/healthz` shows the proxy choosing a port that NIM marks `LastError`,
it's a fallback after `WithoutFailed` was empty — usually transient, but
worth investigating if persistent.

## Known v1 limitations / follow-ups

- **Stale `NO_PROXY` on cluster-node-IP change.** Containerd does not reload
  env on SIGHUP. If `${cluster_node_ip}` changes after containerd starts
  (e.g. a DHCP lease swap on the cluster interface), the `NO_PROXY` list
  shipped at launch is stale until containerd restarts. The wide CIDRs
  (`10.42.0.0/16`, `10.43.0.0/16`, `169.254.0.0/16`) and the full
  `ClusterIPPrefix` subnet absorb most of this; only if the node moves to
  an entirely different subnet would traffic misroute through the proxy.
  Auto-restart on cluster-node-IP change is a future enhancement.
- **CONNECT only, no plain-HTTP forwarding.** `HTTP_PROXY` is intentionally
  not injected.
- **IPv6.** Inherited from `controllerconn`'s mgmt-port iteration, which is
  IPv4-centric in practice. IPv6-only registries would silently bypass the
  cost gate; not a concern for any current deployment.
- **"Dial succeeds, then mid-stream blackhole".** A half-broken upstream that
  accepts SYN but drops payload packets pins the first attempt to that port.
  Mitigated by the 30s idle-tunnel timeout, NIM's `LastFailed` skipping on
  retry, and Kubernetes' `ImagePullBackOff` exponential backoff. Worst-case
  recovery is a few minutes of retries vs. operator intervention today.

## Underlying gap

The gap this proxy works around is that `table main`'s default route is
authoritative for host-namespace traffic, and EVE doesn't probe gateway
reachability before letting the kernel pick that route. A possible future
enhancement is "NIM owns `table main`'s default route based on per-port gateway
reachability probing, with hysteresis" (referred to below as Option B). Option B
and mgmtproxy are complementary, not sequential:

- **Option B** detects first-hop failure only. If the direct gateway responds
  to ARP/ping but a link several hops away is broken (ISP outage, upstream
  firewall failure, BGP flap), Option B's probe shows the port healthy and
  `table main` continues routing through the broken path. It extends
  cost-aware routing to all host-netns traffic beyond the containerd/kubectl
  paths, but it does not provide end-to-end reachability verification.
- **mgmtproxy** probes end-to-end by attempting a real TCP dial to the
  destination on each CONNECT. The per-attempt dial timeout (`timer.dial.timeout`)
  fires regardless of where in the path the failure occurs — first hop or ten
  hops away. This is the same reason pillar's downloader uses actual HTTP
  round-trips as the failure signal rather than ICMP pings to the gateway.

When Option B ships it will cover host-netns paths not in mgmtproxy's
inventory. mgmtproxy remains the correct mechanism for the containerd and
kubectl paths because it provides both cost-preference ordering and
end-to-end reachability verification on every request.
