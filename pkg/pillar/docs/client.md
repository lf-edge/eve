# Client (zedclient)

## Overview

`client` is the EVE microservice (binary name `zedclient`) that
**onboards the device** to the controller during boot. It runs once as
a short-lived, separate process — not as part of the long-running
`zedbox` group — and exits when it has produced an `OnboardingStatus`
publication carrying the device UUID. Its responsibilities are:

* fetch and verify the **controller certificate chain** from the
  controller's `/certs` endpoint, checkpoint it to
  `/persist/checkpoint/controllercerts` for later reuse,
* **`selfRegister`** — upload the device certificate to the
  controller's `/register` endpoint, authenticated with the
  factory-installed *onboarding* cert/key,
* **`getUuid`** — call the controller's `/uuid` endpoint with the
  device cert/key to obtain the device UUID and an optional
  hardware-model override; if either of the two operations succeeds,
  publish `OnboardingStatus{DeviceUUID,HardwareModel}` and exit,
* persist the UUID to `/persist/status/uuid` and (if changed) the
  hardware model to `/persist/status/hardwaremodel`, and set the
  kernel hostname to the UUID string.

The two operations are independent flags on the command line:
`device-steps.sh` always passes `getUuid`, and additionally passes
`selfRegister` if the onboarding key pair is still present in
`/config`. A successful `getUuid` short-circuits any remaining
`selfRegister` retries. `zedclient` is intentionally minimal — it does
no config parsing, no metrics reporting beyond its own AgentMetrics,
and no long-lived subscriptions. Everything between this onboarding
step and the controller-config event loop lives in `zedagent`.

## Key Input/Output

**client consumes** (all via pubsub unless noted):

* global configuration properties
  * `ConfigItemValueMap` from `zedagent`
  * used only for log level and for the
    `NetworkSendTimeout` / `NetworkDialTimeout` values that
    parameterize the `controllerconn.Client`.
* device network status
  * `DeviceNetworkStatus` from `nim`
  * gates onboarding: requests are only attempted once
    `usableAddressCount > 0` and `DPCState` is `Success`,
    `FailWithIPAndDNS`, or `RemoteWait`. Proxy-cert changes here also
    trigger a TLS rebuild.
* cached DNS resolutions
  * `CachedResolvedIPs` from `nim`
  * read indirectly through `controllerconn.Client` to short-circuit
    DNS lookups for the controller hostname.
* evalmgr onboarding gate
  * `EvalStatus` from `evalmgr` (synchronous via
    `wait.ForEvalStatus`)
  * `Run()` blocks until evalmgr publishes a status whose
    `IsOnboardingAllowed()` is true; this is where image-evaluation /
    policy holds the device back from contacting the controller.
* on-disk identity (read at start, from `/config`)
  * `server` — controller hostname:port (re-read every backoff tick;
    a mid-run change forces a fresh `/certs` fetch),
  * `root-certificate.pem` — root CA for object signing,
  * `onboard.cert.pem` / `onboard.key.pem` — onboarding cert/key
    (only when `selfRegister` is requested),
  * `device.cert.pem` (+ `device.key.pem` / TPM-held key) — device
    cert, loaded via `controllerconn.GetClientCert`.
* existing onboarding state
  * persistent `OnboardingStatus` publication, picked up on entry
    to detect a pre-existing UUID and hardware model. Combined with
    `/persist/checkpoint/controllercerts` (or its `.bak`) it enables
    the 5-second fast path described in
    [The 5-second fast path](#the-5-second-fast-path).

**client publishes**:

* `OnboardingStatus` with key `"global"` (persistent) — the single
  artefact every other agent waits for. Carries `DeviceUUID` and
  `HardwareModel`. Persistence means the next boot can read it back
  and skip onboarding.
* `MetricsMap` with key `"global"` — `controllerconn.AgentMetrics`
  for the `/certs` + `/register` + `/uuid` traffic, published once
  on exit so `zedagent` can include it in the device metrics.
* on-disk side effects
  * `/persist/status/uuid` (text, with trailing newline) — readable
    by shell scripts (`device-steps.sh` reads it back),
  * `/persist/status/hardwaremodel` (text, no newline) — read by
    `ledmanager` for model-specific blink patterns,
  * `/persist/checkpoint/controllercerts` — DER-encoded V2 cert
    chain, written via `persist.MaybeSaveControllerCerts` (only when
    the parsed cert hashes differ from the previous checkpoint to
    avoid pointless churn),
  * kernel hostname set to the UUID via `/bin/hostname <uuid>`.
* LED state, via `utils.UpdateLedManagerConfig`:

  | Trigger | LED pattern |
  |---|---|
  | `/certs` could not be fetched/verified | `LedBlinkInvalidControllerCert` |
  | `/register` or `/uuid` returned 200/201 | `LedBlinkOnboarded` |
  | `/register` returned 400/500/504 | `LedBlinkOnboardingFailure` |
  | `/register` returned 403 (device unknown) | `LedBlinkOnboardingFailureNotFound` |
  | `/register` returned 409 / 304 | `LedBlinkOnboardingFailureConflict` |
  | Auth-container verification of response failed | `LedBlinkInvalidAuthContainer` |
  | Other recoverable controller errors | `LedBlinkConnectedToController` |

  During the `/certs` fetch itself `NoLedManager` is set on the
  controller client so a failure here does not light up the
  "onboarded" indicator.

## Components

`client` is a single source package with one event loop in `Run()`.
There are no separately-testable sub-components and no goroutines
beyond the main loop, the standard `stillRunning` ticker, the
exponential retry ticker, and the 5-second "do we already have a
UUID?" timer. The logical responsibilities are partitioned across the
two files:

### `client.go`

* `Run()` — the entire lifecycle. Builds the `clientContext`,
  parses CLI args (`-r <maxRetries>` plus the positional
  `selfRegister` / `getUuid` operation list), creates the two
  publications, brings up the three subscriptions, waits for
  `EvalStatus`, constructs the `controllerconn.Client`, loads the
  device cert (and, if needed, the onboarding cert), then enters
  the retry loop.
* `tryRegister` (closure inside `Run`) — the per-tick state
  machine: gate on usable address + DPC state, then for each
  enabled operation call `fetchCertChain` → `selfRegister` →
  `doGetUUID` in order, skipping ones already done. Increments
  `retryCount`; exits non-zero only when `-r N` is exceeded.
* `myPost(ctrlClient, tlsConfig, url, skipVerify, retry, body)` —
  the single HTTP helper. Drives `controllerconn.Client.SendOnAllIntf`,
  classifies the resulting `SenderStatus` / `HTTPResponse` into
  LED state and into the boolean "done / retry" answer, and
  verifies the response auth-container unless `skipVerify` is set
  (which it is, for `/certs`).
* `selfRegister` — builds and posts `register.ZRegisterMsg`
  (base64-encoded device-cert PEM + product/soft serial). Maps
  certain `/register` response codes onto the
  `LedBlinkOnboardingFailure*` family.
* `fetchCertChain` — posts an empty body to `/certs` (with the
  device TLS config), verifies the returned chain with
  `controllerconn.VerifyProtoSigningCertChain`, stashes the signer
  cert via `StoreServerSigningCert`, and checkpoints only on
  hash-set change (`compareControllerCertBytes` /
  `parseKeysFromControllerCerts`). Status codes 401/404/501/400 are
  treated as "controller does not speak V2 API".
* `haveControllerCertsCheckpoint` — boolean used by the 5-second
  fast-path timer to decide whether skipping the network wait is
  safe.
* `doGetUUID` — posts a `UuidRequest` to `/uuid`; on
  `SenderStatusCertMiss` re-arms `getCertsTimer` to refetch `/certs`
  (the cached cert hash is now stale). On success, logs peer-cert
  info (MITM detection aid) and returns the parsed UUID + hardware
  model.
* `handleDNSImpl` — translates `DeviceNetworkStatus` updates into
  `usableAddressCount` / `networkState`, and rebuilds
  `devtlsConfig.RootCAs` (and the onboarding TLS, if present) on
  proxy-cert changes via `UpdateTLSProxyCerts`.
* `handleGlobalConfigImpl` / `handleGlobalConfigDelete` — re-read
  agent log level. `handleGlobalConfigCreate` fires reliably during
  `zedclient`'s lifetime: `zedagent` (alive in parallel inside
  `zedbox`, started by the agent-spawn loop in `device-steps.sh`
  before `client` is invoked) publishes `ConfigItemValueMap` early in
  its own startup, before waiting for `OnboardingStatus`. The value
  comes from whichever `zedagent` finds first —
  `/persist/checkpoint/lastconfig`, the bootstrap config,
  `/config/GlobalConfig/`, or compiled-in defaults.
  `handleGlobalConfigModify` is theoretically reachable but rarely
  fires in practice (`zedagent`'s republish path runs after a fresh
  `/config` poll that typically completes after `zedclient` has
  exited). `handleGlobalConfigDelete` is unreachable in normal
  operation.

### `parseuuid.go`

* `parseUUIDResponse(resp, contents)` — unmarshals the controller's
  `eveuuid.UuidResponse` and formats the hardware model from
  `Manufacturer` + `ProductName`.
* `generateUUIDRequest` — builds the (empty) `UuidRequest` protobuf
  body that `doGetUUID` posts to `/uuid`.

## Control-flow

There is one control path, run on a flextimer with exponential
back-off (1 s → 10 min, ±0 jitter) and bounded by either
`-r maxRetries` or external success:

```text
Run()
  └─ create publications: MetricsMap, OnboardingStatus(persistent)
  └─ read existing OnboardingStatus    (oldUUID, oldHardwaremodel)
  └─ subscribe ConfigItemValueMap, CachedResolvedIPs, DeviceNetworkStatus
  └─ wait.ForEvalStatus()              (blocks until evalmgr allows onboarding)
  └─ ctrlClient = controllerconn.NewClient(...)
  └─ read /config/server               (re-read on every ticker tick)
  └─ if selfRegister: load onboard.cert.pem + onboard.key.pem,
                       deviceCertPem  → onboardTLSConfig
  └─ controllerconn.GetClientCert     → devtlsConfig
  └─ start ticker (exp 1s..10m), t1 (5s), stillRunning (25s)
  └─ event loop until done:
       ├ DNS change      → updateAddrs / proxyCerts → tryRegister()
       ├ CachedResolvedIPs / GlobalConfig change → process, no register
       ├ ticker tick     → re-read /config/server (refetch /certs if changed),
       │                   tryRegister()
       ├ t1 fires (5s)   → if oldUUID known AND controllercerts checkpoint
       │                   exists AND DPCState != Success → declare success
       │                   on the cached UUID; done
       └ getCertsTimer   → (re-)fetch /certs (set on cert-miss in /uuid)

tryRegister():
  if !usableAddr || !DPCStateOK            → return  // wait
  if !gotServerCerts:
     fetchCertChain(...)                    // POST /certs, verify, checkpoint
     LED: InvalidControllerCert on failure
  if selfRegister && !gotRegister:
     selfRegister(...)                      // POST /register, classify errors
     if !done && getUuid:
        doGetUUID(...)                      // skip future selfRegister on success
  if !gotUUID && getUuid:
     doGetUUID(...)                         // POST /uuid (on SenderStatusCertMiss
                                            //  → re-arm getCertsTimer)
  retryCount++
  if maxRetries && retryCount > maxRetries  → exit 1

After loop, if devUUID != nil:
  /bin/hostname <uuid>
  WriteFile /persist/status/uuid
  if hardwaremodel changed:
     WriteFile /persist/status/hardwaremodel
  pubOnboardStatus.Publish("global", {DeviceUUID,HardwareModel})
  agentMetrics.Publish("global")
  return 0
```

The 5-second `t1` timer is the only case where `zedclient` exits
without contacting the controller; see
[The 5-second fast path](#the-5-second-fast-path) below. Conversely,
if `/config/server` is changed mid-run (operator-edited image), the
next ticker tick re-reads it and forces a fresh `/certs` fetch —
`serverNameAndPort` is the only mutable global the agent recognizes
after start.

## The 5-second fast path

Onboarding normally requires a full `/certs` + `/uuid` round-trip
against the controller, which only completes once `nim` has brought
the device's network to `DPCStateSuccess`. To keep an
already-onboarded device from blocking boot when the WAN is degraded
— controller momentarily unreachable, proxy still authenticating,
DNS slow to converge — `zedclient` arms a 5-second timer (`t1`) that
fires once at startup and short-circuits the retry loop on the
cached UUID. The shortcut is taken only when **all** of:

* a prior boot's `OnboardingStatus` is loaded with a non-nil
  `DeviceUUID` (the device has been onboarded before),
* `/persist/checkpoint/controllercerts` (or its `.bak`) exists, so
  the next boot has a verified V2 cert chain to reuse without a
  network fetch,
* `DPCState != Success` at the 5-second mark — i.e. the network is
  *not* already healthy, so waiting for it would not have helped.

When taken, `zedclient` publishes the cached `OnboardingStatus` and
exits without contacting the controller. The fast path is silent —
there is no LED transition through `Onboarded`, and the operator's
view is indistinguishable from a successful real onboard. The only
on-device evidence is the log line `"Already have a UUID …;
declaring success"` in the `zedclient` log stream. When debugging
"the device looks fine but the controller never saw it", search the
on-device newlog (active and gzipped archives under
`/persist/newlog/`) for that log line — its appearance is the canary
that EVE→controller connectivity was broken and `zedclient` took the
shortcut.

### Disabling the fast path

Useful both in development (force the full `/certs` + `/uuid` round
trip and exercise the normal retry loop) and occasionally in
production (re-validate the device's identity end-to-end against
the controller without re-flashing). Remove the persistent
`OnboardingStatus` and reboot:

```sh
rm -f /persist/status/zedclient/OnboardingStatus/global.json
sync
reboot
```

On the next boot the publication is empty, so `oldUUID == nilUUID`
and the first pre-condition above fails — `zedclient` enters the
normal retry loop and contacts the controller. The rest of pillar
(zedagent, loguploader, monitor, scepclient) is gated as well:
their `OnboardingStatus` subscriptions are all `Persistent: true`
and read the same on-disk file at activation, so an empty
publication blocks them at their respective `waitUntilOnboarded`
points until `zedclient` re-publishes a fresh status. If the
onboarding cert is still in `/config`, `zedclient` will
re-`selfRegister`; otherwise it will re-`getUuid` against the
existing device cert.

Removing only `/persist/checkpoint/controllercerts*` does **not**
disable the fast path in the operator-visible sense. It forces
`zedclient` to refetch `/certs` on the next boot, but the
persistent `OnboardingStatus` on disk is unaffected — every
subscriber reads the cached UUID the moment it activates,
regardless of whether `zedclient` has run on this boot. The fast
path stops firing inside `zedclient`, but the rest of pillar
proceeds on the cached identity anyway. Use the controllercerts
removal only when you specifically want a fresh cert chain pulled
and don't mind the rest of the system continuing on the cached
UUID.

## Debugging

### PubSub

After a successful boot, on the device:

```sh
# What zedclient published — the device UUID seen by every other agent
cat /persist/status/zedclient/OnboardingStatus/global.json | jq

# The HTTP traffic counters (per-interface)
cat /run/zedclient/MetricsMap/global.json | jq

# What zedclient itself wrote to disk
cat /persist/status/uuid                        # text, with newline
cat /persist/status/hardwaremodel               # text, no newline
ls  /persist/checkpoint/controllercerts*        # verified V2 chain + .bak
```

A healthy device has `OnboardingStatus.DeviceUUID` non-nil and
`/persist/checkpoint/controllercerts` present. Persistent files of
interest under `/persist/`:

* `status/uuid`, `status/hardwaremodel` — written by zedclient,
  consumed by `device-steps.sh` and `ledmanager`.
* `checkpoint/controllercerts`, `checkpoint/controllercerts.bak` —
  V2 cert chain; the backup is consulted by `haveControllerCertsCheckpoint`
  so a corrupted primary still enables the 5-second fast path.

### Logs

Useful `grep` patterns (all in the `zedclient` log stream):

```text
"Found existing UUID"                 – picked up a UUID from a prior boot's OnboardingStatus
"Already have a UUID"                 – 5-second fast path took the shortcut
"Get Device Serial"                   – productSerial / softSerial seen at startup
"Waiting for usableAddressCount"      – held off by nim (no DPCStateSuccess)
"tryRegister: networkState"           – DPC state explicitly rejected this attempt
"fetchCertChain"                      – /certs round-trip (function-level traces)
"Fetched certs from"                  – /certs OK
"controller certificate signature verify fail" – /certs chain didn't verify
"ControllerCerts changed keys from"   – cert-set actually changed, checkpoint rewritten
"Registered at"                       – /register success
"Registration failed on URL"          – /register error path; full body logged
"client getUUID ok"                   – /uuid success
"doGetUUID: Cert miss"                – /uuid replied SenderStatusCertMiss → getCertsTimer re-armed
"Peer certificate:"                   – TLS peer cert chain (MITM-proxy diagnostic)
"Wrote UUID file"                     – /persist/status/uuid written
"Wrote hardwaremodel"                 – /persist/status/hardwaremodel written
"client done"                         – Run() returning 0
```

### Connectivity smoke check

Before trusting any observed `zedclient` behaviour on an existing
device or eden bringup, verify EVE can reach the controller. The
relevant `/etc/hosts` is the *pillar container's*, not the EVE root
namespace's, so the check must run inside pillar (where the agents
actually resolve the controller hostname):

```sh
eve exec pillar curl -sk --max-time 5 \
    "https://$(tr -d '\r\n' </config/server)/api/v2/edgedevice/ping" \
    -o /dev/null -w "%{http_code}\n"
```

Anything other than 200 means the EVE→controller route is broken. On
already-onboarded devices the 5-second fast path will silently mask
this failure (see the canary log line above); on a fresh device,
`zedclient` will report `LedBlinkInvalidControllerCert` and loop.

### Forcing transitions for development

* The onboarding step is exercised on every first boot of a freshly
  installed image. In eden it is driven by `eden adam start` plus the
  default eve image, which arrives with `onboard.cert.pem` /
  `onboard.key.pem` and triggers the `selfRegister` branch.
* To exercise the `selfRegister` failure paths, point `/config/server`
  at a controller that does not have the onboard cert provisioned
  (403 → `LedBlinkOnboardingFailureNotFound`). This relies on the
  controller honouring the eve-api `/register` spec — a controller
  that returns 401 instead leaves the `LedBlinkOnboardingFailureNotFound`
  branch dead.
* The `SenderStatusCertMiss` branch in `doGetUUID` is exercised by
  the unit test `dogetuuid_test.go::TestDoGetUUID_CertMissSchedulesTimer`
  against the seamed `controllerSender` fake. From e2e it is not
  reachable in `zedclient`'s lifetime: `fetchCertChain` runs at the
  top of every `tryRegister` and refreshes the cached signing-cert
  hash before any subsequent `doGetUUID` call, and failure paths
  from `/uuid` (404/401) return plain HTTP errors without an
  auth-container, so signature verification — the only producer of
  `SenderStatusCertMiss` — never runs. The matching path fires
  routinely in `zedagent`, whose long-running `controllerconn` does
  not re-fetch `/certs` every tick.
* To exercise the 5-second fast path, reboot a fully onboarded device
  with the network brought up after pillar starts (so `DPCState !=
  Success` at the 5-second mark) — `zedclient` will exit on the cached
  UUID without contacting the controller. To go the other way and
  force the full round-trip, see
  [Disabling the fast path](#disabling-the-fast-path).
* The `-r <N>` flag bounds the retry count; pass it via the
  `CLIENT_COMMANDS` variable in `device-steps.sh` to force the
  process to give up and exit non-zero (useful for fault-injection
  tests that want a clear failure signal rather than indefinite
  retry).
