# EVE-K VNC Workflows: Remote Console and Edgeview

## Overview

EVE-K (KubeVirt) VMs do not expose a VNC port directly from QEMU. Instead, a
`virtctl vnc --proxy-only` process must be launched in the kube container to
bridge the KubeVirt WebSocket/SPICE protocol onto a local TCP port that clients
can connect to.

Two independent callers can trigger this proxy:

| | **Remote Console** | **Edgeview VNC** |
|---|---|---|
| Initiator | zedkube (`runAppVNC`) | edgeview (`setAndStartProxyTCP`) |
| Trigger | `AppInstanceConfig.RemoteConsole=true` | TCP command `appUUID:4822` |
| Client | Guacamole (controller UI) | edgeview TCP relay to client |
| Coordination file | `vmiVNC.run` (no `CallerPID`) | `vmiVNC.run` (with `CallerPID`) |
| Cleanup owner | zedkube (RemoteConsole=false) | edgeview (`cleanupEveKVNC`) |
| Crash recovery | port probe at next start | `monitor_caller_pid` in vnc-proxy.sh |

Both flows write the same file and rely on the same `vnc-proxy.sh` functions in
the kube container. The `CallerPID` field is the discriminator between them.

---

## Components

```text
┌───────────────────────────────────────────────────────────────────────┐
│  pillar container                    (two independent paths)          │
│                                                                       │
│  ── Remote Console path ──────────────────────────────────────────    │
│   ┌─────────┐  AppInstanceConfig   ┌──────────┐                       │
│   │zedagent │─────────────────────►│ zedkube  │                       │
│   └─────────┘   (RemoteConsole)    └────┬─────┘                       │
│                                         │ runAppVNC()                 │
│  ── Edgeview VNC path ─────────────     │ write {no CallerPID}        │
│   ┌──────────┐  tcp/appUUID:4822        │                             │
│   │edgeview  │◄──────────────────     ┌─┘                             │
│   │ client   │  ┌──────────┐          │                               │
│   └──────────┘  │ edgeview │          │                               │
│                 │ (server) │          │                               │
│                 └────┬─────┘          │                               │
│                      │ setupEveKVNC() │                               │
│                      │ write {+       │                               │
│                      │  CallerPID}    │                               │
│                      └────────┬───────┘                               │
└───────────────────────────────┼───────────────────────────────────────┘
                                │ write (either path)
                    ┌───────────▼────────────────────────┐
                    │ /run/edgeview/VncParams/vmiVNC.run │
                    │ { VMIName, VNCPort, AppUUID,       │
                    │   CallerPID? }                     │
                    └───────────┬────────────────────────┘
                                │ inotifywait
┌───────────────────────────────┼───────────────────────────────────────┐
│  kube container               │                                       │
│                   ┌───────────▼────────┐                              │
│                   │  vnc-proxy.sh      │                              │
│                   │ monitor_vnc_config │                              │
│                   │ handle_vnc         │                              │
│                   │ monitor_caller_pid │                              │
│                   └─────────┬──────────┘                              │
│                             │ nohup                                   │
│                   ┌─────────▼───────────┐                             │
│                   │  virtctl vnc <VMI>  │                             │
│                   │  --proxy-only       │                             │
│                   │  --port <VNCPort>   │                             │
│                   └──────────┬──────────┘                             │
└──────────────────────────────┼────────────────────────────────────────┘
                               │ WebSocket/SPICE
                   ┌───────────▼──────────┐
                   │   KubeVirt VMI       │
                   └──────────────────────┘
          connects to 127.0.0.1:VNCPort
          ┌──────────────┐  ┌──────────────────┐
          │  Guacamole   │  │  edgeview relay  │
          │ (controller) │  │  to client       │
          └──────────────┘  └──────────────────┘
```

---

## vmiVNC.run — the coordination file

Path: `/run/edgeview/VncParams/vmiVNC.run`

```json
{
  "VMIName":   "ubuntu-vm-app-abc123",
  "VNCPort":   5910,
  "AppUUID":   "b3e2f1a0-...",
  "CallerPID": 4827
}
```

| Field | Remote Console | Edgeview VNC | Purpose |
|---|---|---|---|
| `VMIName` | set | set | virtctl target VMI |
| `VNCPort` | set | set | local proxy port (5900 + VncDisplay) |
| `AppUUID` | set | set | stale-file ownership check |
| `CallerPID` | **absent** | **set** | discriminator; crash-monitor target |

Rules:

- `CallerPID > 0` → edgeview owns this session; liveness via `/proc/<pid>/comm` **and** port probe.
  PID is checked first; if alive the VNC port is also checked. If the port is not listening the
  file is treated as stale (virtctl proxy crashed) and evicted. A known edge case: there is a
  short startup window between file creation and virtctl binding the port where an alive-PID +
  unbound-port could trigger premature eviction; this is accepted as an unlikely race.
- `CallerPID` absent → zedkube owns this session; liveness via port probe.
  (exposed to startup window: virtctl must be bound for the file to be considered live)

---

## Workflow 1: Remote Console

### Remote Console Start

```text
Controller                zedagent         zedkube            vmiVNC.run      vnc-proxy.sh      virtctl      Guacamole
    │                        │                │                    │                │               │              │
    │  RemoteConsole=true    │                │                    │                │               │              │
    │───────────────────────►│                │                    │                │               │              │
    │                        │  pub config    │                    │                │               │              │
    │                        │───────────────►│                    │                │               │              │
    │                        │                │ handleAppInstance  │                │               │              │
    │                        │                │ ConfigModify()     │                │               │              │
    │                        │                │ go runAppVNC()     │                │               │              │
    │                        │                │ getVMIdomainName() │                │               │              │
    │                        │                │ (retry up to 6×)   │                │               │              │
    │                        │                │ canClaimVNCFile()  │                │               │              │
    │                        │                │── (evict stale) ──►                 │               │              │
    │                        │                │  write             │                │               │              │
    │                        │                │  {VMIName,VNCPort, │                │               │              │
    │                        │                │   AppUUID}         │                │               │              │
    │                        │                │───────────────────►│                │               │              │
    │                        │                │                    │ inotify CREATE │               │              │
    │                        │                │                    │────────────────►               │              │
    │                        │                │                    │                │ handle_vnc()  │              │
    │                        │                │                    │                │ parse JSON    │              │
    │                        │                │                    │                │ no CallerPID  │              │
    │                        │                │                    │                │ nohup virtctl─►              │
    │                        │                │                    │                │ wait port     │              │
    │                        │                │                    │                │◄──────────────│ listening    │
    │                        │                │                    │                │ VNC_RUNNING=  │              │
    │                        │                │                    │                │  true         │              │
    │                        │                │                    │                │               │◄─────────────│
    │                        │                │                    │                │               │  connect     │
```

### Stop (RemoteConsole disabled)

```text
Controller           zedagent          zedkube          vmiVNC.run     vnc-proxy.sh     virtctl
    │                   │                 │                  │               │              │
    │  RemoteConsole=   │                 │                  │               │              │
    │  false            │                 │                  │               │              │
    │───────────────────►                 │                  │               │              │
    │                   │  pub config     │                  │               │              │
    │                   │────────────────►│                  │               │              │
    │                   │                 │ go runAppVNC()   │               │              │
    │                   │                 │ os.Remove()      │               │              │
    │                   │                 │─────────────────►│               │              │
    │                   │                 │                  │ inotify DELETE│              │
    │                   │                 │                  │───────────────►              │
    │                   │                 │                  │               │ kill -9      │
    │                   │                 │                  │               │─────────────►│
    │                   │                 │                  │               │ VNC_RUNNING= │
    │                   │                 │                  │               │  false       │
```

---

## Workflow 2: Edgeview VNC

### Edgeview VNC Start

```text
Edgeview              edgeview          ENCluster        vmiVNC.run     vnc-proxy.sh      virtctl
 Client               (server)         AppStatus dir          │               │              │
    │                    │                  │                 │               │              │
    │  tcp/appUUID:4822  │                  │                 │               │              │
    │───────────────────►│                  │                 │               │              │
    │                    │ setAndStart      │                 │               │              │
    │                    │ ProxyTCP()       │                 │               │              │
    │                    │ isEveKVNC        │                 │               │              │
    │                    │ Request()        │                 │               │              │
    │                    │ setupEveKVNC()   │                 │               │              │
    │                    │ removeStale      │                 │               │              │
    │                    │ VNCFile(true)────►─────────────────► (evict stale) │              │
    │                    │ read appUUID     │                 │               │              │
    │                    │ .json────────────►                 │               │              │
    │                    │◄─────────────────│ VMIName,VNCPort │               │              │
    │                    │ write            │                 │               │              │
    │                    │ {VMIName,VNCPort,│                 │               │              │
    │                    │  AppUUID,        │                 │               │              │
    │                    │  CallerPID=self}─►                 │               │              │
    │                    │                  │                 │ inotify CREATE│              │
    │                    │                  │                 │───────────────►              │
    │                    │                  │                 │               │ handle_vnc() │
    │                    │                  │                 │               │ parse JSON   │
    │                    │                  │                 │               │ CallerPID set│
    │                    │                  │                 │               │ monitor_     │
    │                    │                  │                 │               │ caller_pid() │
    │                    │                  │                 │               │  & (bg)      │
    │                    │                  │                 │               │ nohup virtctl►
    │                    │                  │                 │               │ wait port────►
    │                    │ waitForVirtctl   │                 │               │◄─────────────│
    │                    │ VNC(30s)         │                 │               │  listening   │
    │                    │ /proc/net/tcp    │                 │               │              │
    │                    │ poll...          │                 │               │              │
    │                    │ TCP relay ───────────────────────────────────────────────────────►│
    │◄───────────────────│ to client        │                 │               │              │
```

### Normal Stop (session ends)

```text
edgeview              vmiVNC.run     vnc-proxy.sh       virtctl
(server)                   │               │                │
    │  TCP closed /        │               │                │
    │  timer expired       │               │                │
    │ cleanupEveKVNC()     │               │                │
    │ os.Remove() ─────────►               │                │
    │ closeMessage ─►WSS   │ inotify DELETE│                │
    │                      │───────────────►                │
    │                      │               │ kill -9 ───────►
    │                      │               │ VNC_RUNNING=   │
    │                      │               │  false         │
    │                      │               │                │
    │                      │ monitor_caller_pid:            │
    │                      │ file gone → exits cleanly      │
```

### Crash Cleanup (edgeview dies without normal cleanup)

```text
edgeview           vmiVNC.run     vnc-proxy.sh           virtctl
(crashed)              │         monitor_caller_pid          │
    ✗                  │               │                     │
    │                  │  sleep 5s     │                     │
    │                  │               │                     │
    │                  │ file still    │                     │
    │                  │ present───────►                     │
    │                  │               │ kill -0 CallerPID   │
    │                  │               │  → ESRCH (dead)     │
    │                  │               │ re-read file:       │
    │                  │               │  CallerPID unchanged│
    │                  │               │ kill -9 ────────────►
    │                  │◄──────────────│ rm vmiVNC.run       │
    │                  │               │ monitor exits       │
```

---

## Stale File Resolution at Session Start

Before writing `vmiVNC.run`, both callers check whether an existing file
represents a live session. The logic branches on `CallerPID`.

> **Note on atomicity:** the read-check-write sequence is not atomic. A
> simultaneous edgeview VNC request and Remote Console activation can both
> read an absent file and both proceed to write. The last write wins and
> `vnc-proxy.sh` will restart virtctl for whichever file it sees. Avoiding
> parallel VNC requests from two sources is a user/operator responsibility.
> When this race occurs it is logged: `setupEveKVNC` and `runAppVNC` each
> do a post-write readback and log an `Errorf` if the file was overwritten,
> and `handle_vnc` in `vnc-proxy.sh` logs a `WARNING` when it receives a
> file-rewrite event while a session is already active.

### Edgeview: `removeStaleVNCFile(evictIdle)`

Called with `evictIdle=true` on a new VNC request; with `evictIdle=false` at
edgeview startup (where it must not disturb a remote-console session it does
not own).

```text
read vmiVNC.run
        │
        ▼
   absent? ──yes──► return true (proceed)
        │
        ▼ no
   parsable &
   VNCPort > 0? ──no──► remove file ──► return true
        │
        ▼ yes
   CallerPID > 0?
        │              yes
        ├──────────────────► OwnerAlive()?
        │                    (/proc/<pid>/comm == "edge-view")
        │                         │
        │                    alive─► port listening? ──yes──► return false (blocked)
        │                                │ no (virtctl proxy gone)
        │                                └──► remove file ──► return true
        │                    dead/reused ─► remove file ──► return true
        │
        │ no (remote-console file)
        ▼
   evictIdle=false? ──yes──► return true (startup: leave it alone)
        │
        ▼ no (request path)
   /proc/net/tcp: port listening?
        │
   yes──► return false (blocked)
   no───► remove file ──► return true
```

### zedkube: `canClaimVNCFile(appUUID)`

```text
read vmiVNC.run
        │
        ▼
   absent? ──yes──► return true (proceed)
        │
        ▼ no
   parsable &
   VNCPort > 0? ──no──► remove file ──► return true
        │
        ▼ yes
   CallerPID > 0?
        │              yes
        ├──────────────────► OwnerAlive()?
        │                         │
        │                    alive─► port listening? ──yes──► return false (blocked)
        │                                │ no (virtctl proxy gone)
        │                                └──► remove file ──► return true
        │                    dead/reused ─► remove file ──► return true
        │
        │ no (remote-console file)
        ▼
   same AppUUID?
        │
   yes──► remove own stale file ──► return true
        │
        ▼ no (different app)
   /proc/net/tcp: port listening?
        │
   yes──► return false (blocked)
   no───► remove file ──► return true
```

---

## Port Liveness Check

Both `removeStaleVNCFile` (edgeview) and `canClaimVNCFile` (zedkube) probe
whether a virtctl proxy is actually running before declaring a file stale.
Both delegate to `netutils.IsLocalPortListening`, which reads
`/proc/net/tcp[6]` directly — no TCP connection is made, so a live virtctl
VNC proxy on that port is not disrupted by the check.

The port probe applies to **both** ownership cases:

- **`CallerPID` absent (remote-console):** port probe is the sole liveness signal. If virtctl
  is not listening the file is evicted.
- **`CallerPID > 0` (edgeview):** PID liveness (`OwnerAlive`) is checked first. If the PID is
  alive the port is also checked. A live PID with no listening port means virtctl crashed; the
  file is evicted so the new request can proceed. (Startup-window caveat: the check could
  falsely evict in the ~30 s between edgeview writing the file and virtctl binding the port;
  this is accepted as an unlikely edge case.)

---

## Conflict Matrix

| Existing session | New request | Outcome |
|---|---|---|
| No file | Remote Console | zedkube writes file, virtctl starts |
| No file | Edgeview VNC | edgeview writes file, virtctl starts |
| Active Remote Console (port listening) | Edgeview VNC | edgeview blocked (`removeStaleVNCFile` returns false) |
| Active Edgeview VNC (CallerPID alive) | Remote Console | zedkube blocked (`canClaimVNCFile` returns false) |
| Stale edgeview file (PID dead/reused) | Any | File evicted, new session proceeds |
| Stale remote-console file (port not listening) | Any | File evicted, new session proceeds |
| Same app remote-console file | Same app Remote Console | zedkube reclaims own file, restarts |
