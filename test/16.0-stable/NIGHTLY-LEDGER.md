# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

## [2026-11-26 -- 0.0.0-16.0-stable-57a75412 (run #58)](https://github.com/lf-edge/eve/actions/runs/45746054501)

[Full report](https://lf-edge.github.io/eve/test/16.0-stable/runs/58/)

### TestAppRoutingSuite: failure analysis

#### TestLocalNIWithMultiplePorts

##### Failure

```

Told to stop trying after 2.279s.
Stop waiting for: NI ONLINE with both static routes via ethernet0 and all connected routes present
Network instance is in error state
networkID:"4e4c8237-214e-4757-9789-ead7f119595a" networkVersion:"1" instType:2 displayname:"multi-port-ni" activated:true CurrentUplinkIntf:"eth0" ports:"eth0" ports:"eth1" ports:"eth2" ports:"eth3" bridgeNum:1 bridgeName:"bn1" bridgeIPAddr:"10.50.0.1" ipAssignments:{macAddress:"00:16:3e:06:00:01" ipAddress:"10.50.0.1"} networkErr:{description:"IP Route: {dst=0.0.0.0/0, gw=<nil>, port=internet, probe={enabledGwPing=true, gwPingMaxCost=5, userProbe=<none>}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port\nIP Route: {dst=10.88.88.0/24, gw=<nil>, port=httpserver, probe={enabledGwPing=true, gwPingMaxCost=0, userProbe=tcp://10.88.88.70:80}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port" timestamp:{seconds:1795665586 nanos:220969040} severity:SEVERITY_ERROR} state:ZNETINST_STATE_ERROR mtu:1500 ip_routes:{destination_network:"0.0.0.0/0" gateway:"192.168.30.1" port:"eth2"} ip_routes:{destination_network:"0.0.0.0/0" gateway:"172.22.10.1" port:"eth0"} ip_routes:{destination_network:"172.22.10.0/24" port:"eth0"} ip_routes:{destination_network:"192.168.30.0/24" port:"eth2"}
```

##### Claude's conclusion

Live evidence confirms table 801 now fully converged (0.0.0.0/0 via eth3/10.40.40.1, 10.88.88.0/24 via eth3, 172.22.10.0/24 and 192.168.30.0/24 connected routes), matching the "resolved moments after timeout" pattern from the ledger.

**Root cause:** This is the same known, recurring transient NI route-convergence race documented in the ledger since **2026-11-21** and recurring on **2026-11-25** and now again on **2026-11-26**. `gotest.json` shows the test gave up after only 2.279s (03:59:44–03:59:46), and the network instance transitioned `ERROR -> ONLINE` at 03:59:54 — just ~8 seconds later — confirmed live by `ip route show table all` now holding all expected static/connected routes (default via eth3, 10.88.88.0/24 via eth3, plus the eth0/eth2 connected routes) in table 801. As previously diagnosed, `TestLocalNIWithMultiplePorts` (`evetest/tests/networking/routing_test.go`) lacks the same tolerance for a brief transient `ERROR` state during NI reconciliation that its sibling `TestLocalNI` has, making it prone to this exact race on devices with multiple uplink ports. No other failures occurred earlier in this run to share a root cause with — this is purely the test's known sensitivity to a short self-resolving NIM/zedrouter convergence blip, now having recurred three nights running.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNIDeletedWithAppsAttached

##### Failure

```
timed out after 5m0.001107964s (excluding download) waiting for app "2d025cfb-95bc-40af-bef6-678660ded973" (app-1) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

Confirmed: a fresh curl from the device to the registry succeeds instantly, while the two stuck resolve connections remain ESTABLISHED with unacked data and 11 retransmits each (identical `tx_queue=0x10F`/retransmit count to the earlier occurrence) — a TCP black-hole on that specific connection, not a registry or app problem.

**Root cause:** `app-1`'s OCI tag resolve against the registry (`192.168.170.2:5000/lfedge/evetest-ubuntu-ctr:1.2`) started at `04:39:50.868` and then produced zero further log lines for the rest of the test; live inspection now shows the device's two resolve-related TCP connections to the registry still ESTABLISHED with data stuck unacknowledged in the send queue (`tx_queue=0x10F`, 11 retransmits each) — an on-path black-holed connection — while a brand-new `curl` to the same registry from the same device succeeds immediately. Because the OCI datastore resolve path sets no end-to-end timeout (only TCP-handshake/TLS timeouts), a single stalled connection hangs the resolve forever with no retry, leaving the app permanently stuck in `RESOLVING_TAG` until the test's 5-minute wait expires. This is a **known, recurring issue**: the ledger records the identical signature — same test (`TestSwitchNIDeletedWithAppsAttached`/`TestSwitchNetworkInstanceSuite`), same registry, same stuck-`RESOLVING_TAG` pattern with ESTABLISHED-but-black-holed connections, even the same `tx_queue=0x10F`/11-retransmit numbers — first observed on **2026-11-23** (run #43), alongside a sibling occurrence that same night in `TestFlowLog`. No other failure earlier in this run shares this cause, and it's purely an environment/network black-hole flake against the test registry, not a product or test-logic bug.

## [2026-11-25 -- 0.0.0-16.0-stable-be6386de (run #53)](https://github.com/lf-edge/eve/actions/runs/45536857253)

[Full report](https://lf-edge.github.io/eve/test/16.0-stable/runs/53/)

### TestAppRoutingSuite: failure analysis

#### TestLocalNIWithMultiplePorts

##### Failure

```

Told to stop trying after 0.694s.
Stop waiting for: NI ONLINE with both static routes via ethernet0 and all connected routes present
Network instance is in error state
networkID:"3fbd9c67-45de-4e23-abbd-6bdaf55e561c"  networkVersion:"1"  instType:2  displayname:"multi-port-ni"  activated:true  CurrentUplinkIntf:"eth0"  ports:"eth0"  ports:"eth1"  ports:"eth2"  ports:"eth3"  bridgeNum:1  bridgeName:"bn1"  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:06:00:01"  ipAddress:"10.50.0.1"}  networkErr:{description:"IP Route: {dst=0.0.0.0/0, gw=<nil>, port=internet, probe={enabledGwPing=true, gwPingMaxCost=5, userProbe=<none>}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port\nIP Route: {dst=10.88.88.0/24, gw=<nil>, port=httpserver, probe={enabledGwPing=true, gwPingMaxCost=0, userProbe=tcp://10.88.88.70:80}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port"  timestamp:{seconds:1795578667  nanos:420941029}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"192.168.30.1"  port:"eth2"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"172.22.10.1"  port:"eth0"}  ip_routes:{destination_network:"172.22.10.0/24"  port:"eth0"}  ip_routes:{destination_network:"192.168.30.0/24"  port:"eth2"}
```

##### Claude's conclusion

This confirms the routes did properly converge (table 801 for the NI now has all the static/connected routes it needed). This matches the known race exactly.

**Root cause:** This is a transient NI route-convergence race, not a real product bug, and it is a **known, recurring issue** — the identical failure signature (same test, same `multi-port-ni` display name, same "internet"/"httpserver" static-route "not matching any port" errors, same eth0/eth2 default-route ports) first appeared in the ledger on **2026-11-21** and is now recurring on **2026-11-25**. Live evidence: the harness paused at 03:51:07 after giving up after only 0.694s, but `gotest.json` shows the NI transitioned `ERROR -> ONLINE` at 03:51:17 (just ~10s later), and live `evetest eve ssh "ip route show table all"` now confirms table 801 holds all the expected static and connected routes (0.0.0.0/0 via eth0/eth2, 10.88.88.0/24, 172.22.10.0/24, 192.168.30.0/24) — i.e. the NI fully converged moments after the test aborted. As noted in the 2026-11-21 ledger entry, `TestLocalNIWithMultiplePorts` (`evetest/tests/networking/routing_test.go`) uses `.StopIf(niHasError)` on its NI-online wait without the same tolerance for transient `ERROR` states that the sibling `TestLocalNI` wait deliberately uses, making it susceptible to this exact race. This failure is unrelated to the other paused-at-start-of-run suite context (no other failure earlier in this run to share a cause with); it's purely this test's known sensitivity to a brief, self-resolving NIM/zedrouter convergence blip.

### TestDatastoreSuite: failure analysis

#### TestDownloadBurstWithDeadMgmtPorts

##### Failure

```

Timed out after 300.000s.
the downloader did not report a transport with 1 worker(s) after the reboot, so the downloader.transport.handlers property did not take effect
Expected
    <[]evetest.LogMsg | len:0, cap:0>: nil
not to be empty
```

##### Claude's conclusion

That's enough evidence already; I have a solid root cause without needing git history.

###### Root cause

The `downloader.transport.handlers=1` config change **did** take effect correctly: live SSH into the device confirms `ConfigItemValueMap` has `downloader.transport.handlers` = 1, and the post-reboot pillar process (pid 2882) logged `"zedUpload transport handlers: 1 (also the depth of its request queue)"` at `03:43:59.129`, just 1 second after the reboot completed (`REBOOTING -> ONLINE` at 03:43:58) — well inside the test's 5-minute `Eventually` window (03:43:58–03:48:58, derived from `RequestReboot(true)` blocking until the device came back online).

The actual bug is in the controller-side log pipeline, not the device: inspecting Adam's per-device log store directly (`adam-db/device/<uuid>/logs/`) shows that log batch containing this exact message wasn't written until the file timestamped `03:50:15` — over 6 minutes after the device logged it, and about 1m17s *after* the test's `Eventually` had already given up at 03:48:58. The device continuously POSTed `/newlogs` to Adam every few seconds throughout the whole window (confirmed in `adam-stdout`), so the log line was present on the wire, but reached Adam's queryable store too late — likely because the reboot generates a large burst of debug-level logs from many concurrent pillar agents (nim, watcher, zedagent, etc.), and the newlog pipeline uploads/ingests in order, so this particular line got queued behind that backlog and missed the test's timeout window purely due to upload/processing latency, not any functional defect in `downloader.transport.handlers`.

This is a brand-new failure signature — no prior entries for `TestDownloadBurstWithDeadMgmtPorts` or this newlog-delay pattern exist in the ledger — and it doesn't share a root cause with other failures in this run (e.g., the unrelated `TestBootstrapSuite`/Proxmox VM-creation entry from the previous night). Likely fix direction: increase the test's timeout/polling window for this specific check, or have it query the device directly rather than relying on controller log propagation, to absorb post-reboot log-upload backlog latency.

## [2026-11-24 -- 0.0.0-16.0-stable-be6386de (run #48)](https://github.com/lf-edge/eve/actions/runs/45316371575)

[Full report](https://lf-edge.github.io/eve/test/16.0-stable/runs/48/)

### TestBootstrapSuite: failure analysis

#### TestBootstrapWithStaticIP

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: failed waiting for VM 112 creation: timed out after 5m0s waiting for Proxmox task UPID:farfalle:002CB3A4:85262CC3:6B050654:qmcreate:112:root@pam:
```

##### Claude's conclusion

No prior ledger entries mention Proxmox VM-creation timeouts, qmcreate/qmdestroy, or TestBootstrapSuite failures. This is a new failure signature not previously logged.

###### Root cause

The live Proxmox broker log is unambiguous: the task `UPID:farfalle:002CB3A4:...:qmcreate:112:...` (creating VM 112, the SDN emulator VM for this test) never completed within the 5-minute wait, and the subsequent cleanup attempts to destroy that same VM 112 failed three times in a row with `can't lock file '/var/lock/qemu-server/lock-112.conf' - got timeout` — meaning the original `qmcreate` task was *still holding the VM's config lock* on the Proxmox host (`farfalle`) well after evetest gave up waiting on it, and `qmdestroy` couldn't even start because of that held lock. The broker eventually gave up and "leaked" VM 112 rather than removing it. This points to a stuck/overloaded Proxmox host-side VM-creation operation (e.g. slow/contended storage during qcow2 allocation) rather than any EVE/pillar or SDN-emulator defect — note the EVE device's own VM (105) was created successfully moments earlier (03:36:49), so it's specifically VM 112's create task that hung. Because setup never got far enough to bring up the SDN device, no EVE device or SDN client was ever created (`evetest status`/`eve collect-info`/`sdn status` all confirm "no devices"), so there's no pillar/EVE-side log evidence to inspect — this is purely a broker/Proxmox provisioning failure, isolated to this one test (no other failure earlier in this run to share a cause with). I checked `live-ledger.md`'s prior three nightly entries (2026-11-21, 2026-11-22, 2026-11-23) and found no previous occurrence of `TestBootstrapSuite` failures, VM-creation timeouts, or `qmcreate`/lock-file errors, so this is a new issue, not a previously known/recurring one — though it's thematically similar to last night's separately-logged Proxmox VM-deletion-timeout/orphan issue (`sdn-6b66f6e9` VM 107), suggesting the Proxmox host (`farfalle`) may have a broader pattern of slow/stuck VM lifecycle operations under load, even though the exact signature differs (creation hang vs. deletion hang).
#### TestBootstrapWithManualProxyConfig

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev": failed waiting for VM 110 creation: task failed on Proxmox: unable to create VM 110 - cannot import from 'local:import/ev-170-eve-db33565d-edge-dev-0.qcow2' - can't lock file '/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool' - got timeout (task UPID:farfalle:002CDA71:85278812:6B0509CD:qmcreate:110:root@pam:)
```

##### Claude's conclusion

This has enough evidence. The pattern is clear: both this run's failures trace to Proxmox host `farfalle` lock contention, now also showing deletion failures (VM 115 at 03:50) right before the VM 110 creation failure.

###### Root cause

Live `evetest status` and `gotest.json` confirm VM 110 (the EVE device's VM) failed to be created because the Proxmox task couldn't acquire the storage-pool lock `/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool` on host `farfalle`, retried twice (03:51:19, 03:51:36) and still timed out at 03:51:53. Notably, just minutes earlier in this same test's own teardown, the SDN VM 115's deletion hit an analogous lock timeout (`can't lock file '/var/lock/qemu-server/lock-115.conf'`, 03:50:34–03:50:49) — i.e. the host was already failing to release Proxmox locks before this VM-creation attempt was even made. This is the same underlying root cause already diagnosed earlier in this run for `TestBootstrapWithStaticIP` (VM 112 creation/deletion stuck on `lock-112.conf`), just manifesting against a different lock (the ZFS storage-pool lock this time instead of a per-VM config lock) — both point to the Proxmox host `farfalle` being unable to serialize/release its internal locks under load during VM create/destroy operations. This signature (Proxmox lock-timeout on `farfalle` during qmcreate/qmdestroy) does not appear in any of the three prior nightly ledger entries (2026-11-21, 2026-11-22, 2026-11-23), so while it shares a root cause with tonight's earlier `TestBootstrapWithStaticIP` failure, it is not yet a ledger-documented recurring issue — tonight looks like the start of a broader pattern of `farfalle` lock contention across both VM-level and storage-level locks.
#### TestBootstrapWithManualProxyConfigUsingOverrideJSON

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev": failed waiting for VM 110 creation: task failed on Proxmox: unable to create VM 110 - cannot import from 'local:import/ev-171-eve-db33565d-edge-dev-0.qcow2' - can't lock file '/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool' - got timeout (task UPID:farfalle:002CDD6A:8527ACD8:6B050A2B:qmcreate:110:root@pam:)
```

##### Claude's conclusion

No EVE device was ever created (setup failed before device registration), so there's nothing further to inspect on-device; the evidence is fully contained in the broker/Proxmox failure message itself, which I've confirmed live via `evetest status`.

###### Root cause

This test's setup failed identically to `TestBootstrapWithManualProxyConfig` earlier in this very run: VM 110 creation failed because the Proxmox task couldn't acquire `/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool` on host `farfalle` and timed out, blocking the qcow2 import from completing. This is the same underlying Proxmox host-side storage-pool lock contention already diagnosed for `TestBootstrapWithManualProxyConfig` in this run (same lock file, same VM slot/number 110, same host), so it shares that root cause rather than being a new/independent bug. It also fits the broader pattern already noted for `TestBootstrapWithStaticIP` earlier tonight (VM 112 stuck on a per-VM config lock), suggesting host `farfalle` is under sustained lock contention across multiple Proxmox lifecycle operations (both VM-config locks and the ZFS storage-pool lock) this run. Per `live-ledger.md`, this signature (Proxmox lock-timeout on `farfalle` during `qmcreate`/`qmdestroy`) does not appear in the three prior nightly runs (2026-11-21, 2026-11-22, 2026-11-23), so this is not yet a ledger-documented recurring issue — it's the third occurrence of the same `farfalle` lock-contention problem within tonight's run alone, strongly suggesting an infrastructure-level issue on the Proxmox host rather than anything in the EVE/pillar codebase.
#### TestBootstrapWithMgmtVLANUsingOverrideJSON

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev": failed waiting for VM 107 creation: timed out after 5m0s waiting for Proxmox task UPID:farfalle:002D40B4:852B1C01:6B0512F5:qmcreate:107:root@pam:
```

##### Claude's conclusion

This has sufficient evidence confirming the pattern.

**Root cause:** This is the same Proxmox host (`farfalle`) lock-contention issue already diagnosed three times earlier in this run. The broker log shows the `qmcreate:107` task (EVE device VM) starting at 04:33:12 and never completing within the 5-minute wait; the teardown that followed to clean up the failed VM 107 also hit a held lock (`can't lock file '/var/lock/qemu-server/lock-107.conf' - got timeout`, retried once before succeeding at 04:38:11) — identical in shape to the earlier `TestBootstrapWithStaticIP` (VM 112) and `TestBootstrapWithManualProxyConfig`/`TestBootstrapWithManualProxyConfigUsingOverrideJSON` (VM 110) failures recorded in `live-investigation.md`. No EVE device or SDN client was ever created, so there's no pillar/EVE-side evidence to add — this is purely a `farfalle` host-side VM lifecycle stall, now the fourth occurrence in this single run. Per `live-ledger.md` (checked for `qmcreate`/`qmdestroy`/lock/Proxmox-task/farfalle keywords across all prior nightly entries), this exact signature has never appeared before tonight, so it is not a previously known/recurring issue — it looks like tonight is the first night the `farfalle` Proxmox host has shown this sustained lock-contention pattern across VM create/destroy operations.

### TestSecuritySuite: failure analysis

#### TestVComContainer

##### Failure

```

vComLink check as uid 65534 failed:  
Unexpected error:
    <*fmt.wrapError | 0x2240c79e16e0>: 
    failed to execute script over SSH for app e2365ce9-2c7d-4990-9ef3-da587ecb551d: Process exited with status 120 (stderr: )
    {
        msg: "failed to execute script over SSH for app e2365ce9-2c7d-4990-9ef3-da587ecb551d: Process exited with status 120 (stderr: )",
        err: <*ssh.ExitError | 0x2240c7932140>{
            Waitmsg: {status: 120, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause analysis

The failing assertion is in the brand-new `TestVComContainer` (added by commit `551e9ff05`, its first-ever nightly run) at `evetest/tests/security/vcom_container_test.go:135-138`: the *first* loop iteration ("as root") succeeded, but the *second* iteration — running `setpriv --reuid 65534 --regid 65534 --clear-groups python3 /tmp/vcomcheck.py` inside the Ubuntu container app over SSH — came back as a clean, non-signal SSH `exit-status` of **120**, with **zero** stdout and **zero** stderr. Live `evetest eve app-info` confirms the app (`vcom-test-ctr`) is healthy and `RUNNING`, and `evetest eve logs` shows **no vcomlink, qemu/vsock, OOM, or any other error/warn activity whatsoever** on the EVE host during the exact failure window (05:09:07–05:10:10) — the host side is clean. Since the SSH client library only returns a concrete `*ssh.ExitError{status: 120}` (not `ExitMissingError`/`exit-signal`) when the remote shell genuinely reports that exit code, this was a real, silent, non-crashing exit from inside the guest — not a client-side timeout artifact, not a product/host-level issue, and not something I could reproduce because directly SSH-ing into the app container is blocked by this environment's tool permissions.

This is the first and only failure in this run's `gotest.json` (no earlier failure to share a root cause with), and `live-ledger.md` has no prior entry mentioning `TestVComContainer`, `vComLink`, or this exit-code-120 signature — this is not a known/recurring issue, it's new. Given the test is new and this is specifically the uid/gid-drop + vsock code path (not exercised by the sibling `TestVCom`, which only runs as root in a VM), the most likely explanation is a test/environment incompatibility in the privilege-drop step (`setpriv` or AF_VSOCK access as the unprivileged uid 65534 inside this container image) rather than an EVE product defect — but I can't confirm the exact mechanism behind exit code 120 without being able to shell into the running container directly, which this session's tooling doesn't permit.

## [2026-11-23 -- 0.0.0-16.0-stable-f3142331 (run #43)](https://github.com/lf-edge/eve/actions/runs/45103341150)

[Full report](https://lf-edge.github.io/eve/test/16.0-stable/runs/43/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```
timed out after 5m0.000188989s (excluding download) waiting for app "9cbac602-6303-451f-ac7e-d957282c9ad7" (passthrough-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live inspection shows the test actually succeeded shortly after the harness gave up: `evetest eve app-info` now reports `passthrough-app` in state `RUNNING`, and the on-device `VolumeStatus` JSON shows the volume's `CreateTime` was `2026-11-23T03:16:13` — about 53 seconds **after** the 5-minute `WaitUntilAppIsRunning` deadline (which fired at 03:15:20, with the volume having been requested back at ~03:10:06-03:10:10). So this is not a stuck/deadlocked volume worker (there was real recent concern about that class of bug — see commit `ae49853d7` "volumemgr,baseosmgr: don't drop work refused by a full pool" — but that fix is already present on this branch and the worker did complete, just slowly) — it's a plain timing near-miss.

The device is under heavy resource contention: `uptime`/`vmstat` show load average ~5.2-6.0 against `nproc`=1 visible core, with 42-45% iowait, and I caught the qemu-system-x86_64 process for this very app only spawning at 03:16 (after the test had already timed out and paused). This matches the environment-driven "slow volume/content-tree creation narrowly misses the test timeout" pattern already logged in the ledger for 2026-11-22's `TestUpgradeSuite/TestEVEUpgradeKVMtoKVMWithOCIDatastore` (there it was content-tree unpack taking ~7m29s against a 10m budget with the app reaching RUNNING just 17s after timeout; here it's volume creation taking ~6m against a 5m budget, finishing ~53s late). Both runs show the same signature of CPU/I/O-starved infrastructure causing legitimate-but-slow EVE operations to blow past test timeouts, rather than any product defect. I found no earlier ledger entry specifically for `TestAppNICsSuite`/`TestNetworkAdapterPassthrough`, so this specific test hasn't failed this way before, but it shares the same underlying root cause (host-level resource contention) as the prior day's `TestUpgradeSuite` flake.

### TestControllerFaultsSuite: failure analysis

#### TestInfoRetriedAfterServerError

##### Failure

```
timed out after 5m0.007577586s (excluding download) waiting for app "06ac57a8-349a-4807-bf55-f8bdb540fda3" (reported-app) on device "edge-dev" to reach RUNNING state (last state: INSTALLED)
```

##### Claude's conclusion

###### Root cause

The test failed in Phase 1 — a plain deploy-and-wait with no controller fault armed yet — because `zedrouter` went completely silent for ~3m36s on this freshly-booted device. Logs show `zedrouter` producing routine activity every few seconds up to `03:12:26.648` (right after it created the pending `AppNetworkStatus` for `reported-app`, `PendingAdd:true`), then **zero** log lines of any kind from `zedrouter` until `03:16:02` — no periodic ticks, no error, no warning, no external command invocation (`Calling command iptables…` only starts at `03:16:13`). Meanwhile `domainmgr` kept its own 5s metrics-collection cadence running throughout that same window, so this wasn't a VM-wide freeze (no kernel soft-lockup/RCU-stall messages either) — it was `zedrouter`'s own goroutine/event loop that stalled. Once it woke up at `03:16:02`, it rapidly ran the NI reconciler, applied the bridge/iptables/DHCP config, which let `zedmanager` finally call `MaybeAddDomainConfig`/`doActivate` at `03:16:16`, and the domain booted to RUNNING by `03:16:31` — about 3 minutes after the test's 5-minute `WaitUntilAppIsRunning` had already timed out (`03:15:13`), with the app stuck reporting `INSTALLED` the whole time. The live device now shows the app at `RUNNING` (`bootTime 03:16:21`), confirming it was a timing/deadline miss rather than a hung or broken app.

This is unrelated to the controller-fault logic the test actually exercises (that only arms in Phase 2, well after this failure point), so it does not share a root cause with the controller-fault-injection mechanism itself; it also doesn't match the earlier ledger entry about slow OCI-image unpacking (that was a disk-I/O/iowait bottleneck in `volumemgr`, whereas here the volume/image steps finished quickly and the stall was entirely inside `zedrouter`). I checked `live-ledger.md` and found no prior entry for `TestControllerFaultsSuite`/`TestInfoRetriedAfterServerError`, so this is a new, not-previously-recorded issue, not a known recurring flake. I can't pin down *why* `zedrouter` stalled (no error/lock/command evidence survives in the logs) — only that it did, during early-boot CPU/scheduling contention on this VM.

### TestDeviceConnectivitySuite: failure analysis

#### TestIntermittentConnectivity

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

This confirms no SDN client is currently set up (setup failed before devices were created), consistent with `evetest status` showing "No EVE devices found."

**Root cause:** This is a broker/Proxmox provisioner bug, not a product or test-logic issue. Comparing teardown cycles in `gotest.json`: after `TestPortFailover` (03:29:18) and `TestDHCPIPv4Only`'s successor (03:21:57), teardown logged removal of *both* `Removed Proxmox VM 106 for device "eve-...-edge-dev"` and `Removed Proxmox VM 107 for device "sdn-6b66f6e9"`. But after `TestNetworkConfigFallback` (teardown started 03:41:40), only the eve-device VM 106 removal was logged — the SDN VM 107 removal message never appeared, silently leaving the Proxmox VM `sdn-6b66f6e9` registered. When `TestIntermittentConnectivity`'s setup then tried to provision a fresh SDN device under the same deterministic name (`sdn-<client_id>`), it hit `device "sdn-6b66f6e9" already exists` at 03:44:38, failing setup. This does not share a root cause with any other failure in this run (the suite's earlier tests passed), and there is no prior entry in `live-ledger.md` for this suite/failure signature, so this is a newly-observed issue, not a known recurring one.
#### TestMgmtTrafficRoutedViaApp

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

###### Root cause

This is the **same root cause as the already-investigated `TestIntermittentConnectivity` failure** in this run, now cascading forward to a second test. The smoking gun is in `gotest.json`: at 03:42:47 during `TestIntermittentConnectivity`'s failed-setup teardown, the broker logged `Attempt 1/3: failed to destroy device "sdn-6b66f6e9" (will retry): failed to remove VM 107 for device "sdn-6b66f6e9": failed waiting for VM 107 deletion: context deadline exceeded` — the Proxmox SDN VM 107 never actually got removed despite the broker reporting "Removed Proxmox VM 107" messages look like they succeed elsewhere. Since every test in this suite reuses the same deterministic device ID (`6b66f6e9`), each subsequent test's setup tries to re-provision an SDN device named `sdn-6b66f6e9`, hits the same stuck/orphaned Proxmox VM 107, and fails identically: `TestMgmtTrafficRoutedViaApp` failed at 03:46:18 with the exact same `device "sdn-6b66f6e9" already exists` error, and its own failed-setup teardown again only removed VM 106 (the eve-device) — not VM 107 — perpetuating the orphan for the next test. `evetest status` currently shows "No EVE devices found," consistent with setup failing before device registration.

This is not in `live-ledger.md` under either prior nightly entry (2026-11-21 run #33 or 2026-11-22 run #38), so it is not a previously known/recurring issue by that record — it's a new-this-run Proxmox provisioner bug (VM deletion timing out and leaving a stale VM registered under a name the harness can't reuse) that is now failing every subsequent test in the suite until the orphaned VM 107 is cleaned up.
#### TestDeviceIPv6Connectivity

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

This is the exact same cascading failure already diagnosed in this run: this test's teardown (lines 561-564) again only logged removal of Proxmox VM 106 (the eve-device) and never logged a "Removed Proxmox VM 107" / SDN-VM-deletion message, leaving the orphaned SDN VM registered under the deterministic name `sdn-6b66f6e9`. `evetest status` confirms "No EVE devices found" — setup is failing before any device is created, consistent with the stuck orphan. This is the identical failure signature (`device "sdn-6b66f6e9" already exists`) already investigated for both `TestIntermittentConnectivity` and `TestMgmtTrafficRoutedViaApp` earlier in this same run, which traced it to a Proxmox VM 107 deletion that timed out (`context deadline exceeded`) during `TestIntermittentConnectivity`'s failed teardown — so this is a third consecutive test failing from that same stuck/orphaned Proxmox SDN VM, not a new bug. Per `live-ledger.md`, this exact failure signature does not appear in the 2026-11-21 or 2026-11-22 nightly entries, so it's not a previously known/recurring issue — it's new to this run (2026-11-23) and will keep cascading to every remaining test in the suite until the orphaned VM 107 is manually cleaned up out-of-band.
#### TestDeviceNTPConfig

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

This is the identical cascading failure already diagnosed three times earlier in this same run (`TestIntermittentConnectivity`, `TestMgmtTrafficRoutedViaApp`, `TestDeviceIPv6Connectivity`): setup for this 4th consecutive test again hit `device "sdn-6b66f6e9" already exists`, and the live `gotest.json` shows the identical pattern — teardown at 03:48:08 only logs `Removed Proxmox VM 110 for device "eve-6b66f6e9-edge-dev"` (the EVE device), with no corresponding "Removed Proxmox VM ... sdn-6b66f6e9" message, so the orphaned SDN VM (originally stuck mid-deletion with `context deadline exceeded` back during `TestIntermittentConnectivity`'s teardown) remains registered and keeps blocking every subsequent test that tries to reprovision under the same deterministic `client_id` (`6b66f6e9`). `evetest status` confirms "No EVE devices found," matching the pattern of setup failing before any device registration. This is not a new bug — it's the same Proxmox SDN-VM-deletion-timeout orphan already identified earlier in this run, and per `live-ledger.md` it has no prior occurrence in the 2026-11-21 or 2026-11-22 nightly entries, so it remains new to this run rather than a previously known recurring issue (though it will keep cascading to every remaining test in this suite until the orphaned VM is cleaned up out-of-band).
#### TestActiveBackupBond

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

This confirms the same pattern exactly as the prior failures in this run — teardown only removed Proxmox VM 110 (the eve-device), with no corresponding "Removed Proxmox VM ... sdn-6b66f6e9" line, leaving the orphaned SDN VM 107 registered under the deterministic name.

**Root cause:** This is the identical cascading failure already diagnosed four times earlier in this same run (`TestIntermittentConnectivity`, `TestMgmtTrafficRoutedViaApp`, `TestDeviceIPv6Connectivity`, `TestDeviceNTPConfig`). `gotest.json` at 03:49:18-19 shows `TestActiveBackupBond`'s setup hitting `device "sdn-6b66f6e9" already exists`, and its own failed-setup teardown again logs only `Removed Proxmox VM 110 for device "eve-6b66f6e9-edge-dev"` — no "Removed Proxmox VM ... sdn-6b66f6e9" message — perpetuating the orphaned SDN VM 107 that originated from the `context deadline exceeded` VM-deletion timeout during `TestIntermittentConnectivity`'s teardown. `evetest status` confirms "No EVE devices found," consistent with setup failing before registration. This is the fifth consecutive test in this run to fail from the same stuck/orphaned Proxmox SDN VM, not a distinct bug. Per `live-ledger.md`, this signature doesn't appear in the 2026-11-21 or 2026-11-22 entries, so it remains new to this run (2026-11-23), not a previously known recurring issue — but it will keep cascading until the orphaned VM is cleaned up out-of-band.
#### TestLACPBond

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

This is the sixth consecutive test in this run (`TestIntermittentConnectivity`, `TestMgmtTrafficRoutedViaApp`, `TestDeviceIPv6Connectivity`, `TestDeviceNTPConfig`, `TestActiveBackupBond`, now `TestLACPBond`) to hit the identical `device "sdn-6b66f6e9" already exists` error, confirmed by the same `evetest status` → "No EVE devices found" pattern (setup failing before device creation).

**Root cause:** This shares the exact same root cause already diagnosed earlier in this run — the orphaned Proxmox SDN VM 107 (`sdn-6b66f6e9`) that was left registered when its deletion timed out (`context deadline exceeded`) during `TestIntermittentConnectivity`'s failed-setup teardown back at 03:42:47. Because every test in this suite reuses the same deterministic `client_id` (`6b66f6e9`), each subsequent test's setup tries to re-provision an SDN device under that same name and fails identically against the stuck VM, perpetuating the orphan (each failed-setup teardown only removes the eve-device VM, never the stuck SDN VM). This is not a distinct bug — it's the same cascading failure that has now claimed six tests in this run. Per `live-ledger.md`, this signature doesn't appear in the 2026-11-21 or 2026-11-22 entries, so it remains new to this run (2026-11-23) rather than a previously known recurring issue, but it will keep cascading to every remaining test in the suite until the orphaned Proxmox VM 107 is cleaned up out-of-band.
#### TestVLANSubinterfaces

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

This is the identical, now seventh-consecutive failure of the exact same signature in this run: `device "sdn-6b66f6e9" already exists`, confirmed live by `evetest status` showing "No EVE devices found" (setup failing before any device registration), matching the pattern of every prior failure recorded in `live-investigation.md` for this run (`TestIntermittentConnectivity`, `TestMgmtTrafficRoutedViaApp`, `TestDeviceIPv6Connectivity`, `TestDeviceNTPConfig`, `TestActiveBackupBond`, `TestLACPBond`, now `TestVLANSubinterfaces`).

**Root cause:** This shares the exact same root cause already diagnosed earlier in this run — the orphaned Proxmox SDN VM 107 (`sdn-6b66f6e9`) left registered after its deletion timed out (`context deadline exceeded`) during `TestIntermittentConnectivity`'s failed-setup teardown. Because every test in this suite reuses the same deterministic `client_id` (`6b66f6e9`), each subsequent test's setup attempts to re-provision an SDN device under that same name and immediately collides with the stuck VM; each failed-setup teardown only removes the eve-device VM, never the orphaned SDN VM, so the cascade perpetuates itself. This is not a new or distinct bug — it's the same cascading Proxmox provisioner failure that has now claimed seven consecutive tests in this run. Per `live-ledger.md`, this signature does not appear in the 2026-11-21 or 2026-11-22 nightly entries, so it remains new to this run (2026-11-23) rather than a previously known recurring issue, and it will keep failing every remaining test in the suite until the orphaned Proxmox VM 107 is cleaned up out-of-band.
#### TestVLANSubinterfacesOnTopOfLAGs

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-6b66f6e9" already exists
```

##### Claude's conclusion

This is the identical `device "sdn-6b66f6e9" already exists` signature confirmed live by `evetest status` → "No EVE devices found" (setup failing before device registration), the same pattern as all eight prior failures recorded in `live-investigation.md` for this run.

**Root cause:** This shares the exact same root cause already diagnosed repeatedly in this run — the orphaned Proxmox SDN VM 107 (`sdn-6b66f6e9`) left registered after its deletion timed out (`context deadline exceeded`) during `TestIntermittentConnectivity`'s failed-setup teardown at 03:42:47. Since every test in this suite reuses the same deterministic `client_id` (`6b66f6e9`), each subsequent test's setup collides with the stuck orphaned VM and fails identically, and each failed-setup teardown only removes the eve-device VM, never the orphaned SDN VM, perpetuating the cascade. This is now the ninth consecutive test in this run to fail from this same stuck/orphaned Proxmox SDN VM — not a new or distinct bug. Per `live-ledger.md`, this signature doesn't appear in the 2026-11-21 or 2026-11-22 nightly entries, so it remains new to this run (2026-11-23) rather than a previously known recurring issue, and will keep cascading to any remaining tests until the orphaned Proxmox VM 107 is cleaned up out-of-band.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestFlowLog

##### Failure

```
timed out after 5m0.000938177s (excluding download) waiting for app "82060888-8af9-4cd3-9e61-47d833d9a230" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

###### Root cause

`TestFlowLog`'s app (`flowlog-test-app`) got permanently stuck in `RESOLVING_TAG` state (confirmed live via `AppInstanceStatus`/`ContentTreeStatus` on the device, `State:101`), because its container image reference `lfedge/evetest-ubuntu-ctr:1.0` needs an OCI tag→digest resolution against the registry/broker at `192.168.170.2:5000`. Device logs show the resolve call (`downloader.resolveTagsToHash` → `ociutil.manifestsDescImg`) started at `03:32:16.005` and then produced **zero** further resolve-related log lines for the rest of the run — no error, no retry, no completion — consistent with `objectMetadata()` in `pkg/pillar/cmd/downloader/download.go` using a bare `context.WithCancel(context.Background())` with no deadline, so a hung registry response blocks the resolve goroutine indefinitely instead of failing within a bounded time.

Probing the registry live confirms it's in a broken state: `/v2/lfedge/evetest-ubuntu-ctr/tags/list` and `/v2/library/busybox/tags/list` both return their tag lists fine, but a manifest `GET` for *any* tag of *either* repo (`evetest-ubuntu-ctr:1.0/1.1/1.2/1.3`, `busybox:latest`) returns `404 Not Found` — i.e. the registry's tag index is populated but its manifest storage is not serving anything, an infra-side (evetest-broker/registry mirror) problem, not an SDN issue (`evetest sdn status` reports no config errors).

This does not share a root cause with the other tests in this suite run — `TestLocalNI`, `TestNIReplace`, `TestMoveAppBetweenNIs`, and `TestLimitedIPSpace` all passed earlier in the same run. It's also not a known/recurring issue per `live-ledger.md`: the ledger has no prior entries mentioning `TestFlowLog`, `RESOLVING_TAG`, or registry/manifest problems (its only two entries, 2026-11-21 and 2026-11-22, cover unrelated NI-route-race, SSH-timing, and OCI-unpack-slowness flakes). The combination — a broken registry manifest store plus pillar's missing timeout on the resolve path — is the likely cause; no PR diff was provided for this investigation.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNIDeletedWithAppsAttached

##### Failure

```
timed out after 5m0.000531968s (excluding download) waiting for app "c331cb8f-d2e8-474f-824d-26bdfc7a8999" (app-1) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

###### Root cause analysis

The test's own apps (`app-1`, `app-2`) never got past `RESOLVING_TAG` for the entire 5-minute test. Device logs show the downloader's resolve goroutines started two OCI registry lookups (`192.168.170.2:5000/lfedge/evetest-ubuntu-ctr:1.2`) at `04:50:14.475`/`.481` (`manifestsDescImg(...) getting image ref ...`), and then **nothing more was ever logged for either request** — no success, no error, no retry — for the rest of the run (confirmed again live: `evetest eve app-info` still shows both apps stuck in `RESOLVING_TAG` an hour later).

Live inspection of the device confirms this isn't an app-level hang but a network-level one: `/proc/<zedbox-pid>/net/tcp` shows **two TCP connections to 192.168.170.2:5000 still ESTABLISHED with unacknowledged outbound data sitting in the send queue (`tx_queue=0x10F`) and 11 retransmits each**, i.e. the registry-bound packets are going unanswered (a TCP black-hole), while a fresh `curl` to the same registry from the same device succeeds instantly. Because `eve-libs/zedUpload`'s OCI datastore path sets no end-to-end HTTP timeout on `remote.Get()` (only TCP-handshake/TLS timeouts), a stalled-but-still-established connection blocks the resolve forever with no retry/backoff ever kicking in — matching the observed permanent `RESOLVING_TAG`.

This occurred during the test's initial app deployment (image resolve for both apps on the freshly created switch NI), before the "delete NI with apps attached" step was ever reached, so it looks like an environment/network flake unrelated to the NI-deletion logic under test, though it coincided closely with NIM applying ACL/flowlog mangle-table iptables rules on the device's mgmt interface a few hundred ms later — a plausible but unconfirmed trigger for the black hole. I found no unrelated earlier failure in this run to share a root cause with, and `live-ledger.md` has no prior entry for `TestSwitchNetworkInstanceSuite`/`TestSwitchNIDeletedWithAppsAttached`, so this is not a previously known/recurring issue — it's a new occurrence.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKVMtoKVM

##### Failure

```
timed out after 10m0.000788155s (excluding download) waiting for app "0c307c25-fe33-40f6-a0d0-3ab74c66eea8" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Still CREATING_VOLUME live. This gives a clear, consistent picture.

**Root cause:** Slow/contended disk I/O during container image unpack, same as the prior night's flake. Live device logs show `volumemgr` kicked off `CreateVolume`/`UnpackClientImage` for the same 56.7MB OCI image (`lfedge/evetest-ubuntu-ctr@sha256:333e5cba92...`) at 04:09:48, and as of now (04:18+, ~9 minutes later) it still hasn't logged completion — `app-info` still shows `CREATING_VOLUME` live. `vmstat`/`uptime` on the device confirm heavy disk contention: load average 4.0–5.4 on a 4-vCPU VM with ~37–40% iowait, nearly identical to the 2026-11-22 (run #38) `TestEVEUpgradeKVMtoKVMWithOCIDatastore` failure, which saw the exact same image unpack take ~7m29s under ~30% iowait/load ~3.8-3.95 and missed the deadline by only 17 seconds. Download/verify itself was fast here (content tree reached LOADED at 04:09:43, only ~1m50s after creation), so the entire 10-minute RUNNING-state budget was consumed by the subsequent containerd image-unpack step, not by downloading.

This is the same underlying root cause as the 2026-11-22 (run #38) entry in the ledger for `TestEVEUpgradeKVMtoKVMWithOCIDatastore` (same image, same symptom: slow unpack under disk I/O contention eating the whole 10-minute timeout budget), though that one is a different test (`TestEVEUpgradeKVMtoKVM` here vs. `...WithOCIDatastore` there) and only one night old, so I'd call it an emerging/recurring environment performance issue (since 2026-11-22) rather than a one-off, though not yet repeated enough times to be fully "known" in the ledger sense.
#### TestEVEUpgradeKVMtoKVMWithOCIDatastore

##### Failure

```
timed out after 10m0.000999987s (excluding download) waiting for app "629b5241-e471-4f43-affc-ab50f3514f0e" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

Load average and iowait (~23-33%) confirm continued disk contention, consistent with the earlier failures in this same run and the prior night's ledger entry.

**Root cause:** This is the same disk-I/O-contention pattern already identified twice tonight. Live device logs show `volumemgr` kicked off `CreateVolume` for the app's root volume (same 56.7MB OCI image `lfedge/evetest-ubuntu-ctr@sha256:333e5cba92...`) at 04:53:19.349, and `createContainerVolume(...) DONE` didn't fire until 04:59:44.650 — ~6m25s just to unpack the image, consuming nearly the entire 10-minute RUNNING-state budget. The app then raced through INSTALLED → BOOTING (bootTime 05:00:06.23) and the test's `WaitUntilAppIsRunning` timed out at 05:00:08.966, but the app reached RUNNING live at 05:00:12.98 — only ~4 seconds after the timeout fired. `uptime`/`vmstat` on the device right now still show load average 2.84–4.37 on a 4-vCPU VM with 7-33% iowait, consistent with ongoing disk contention.

This shares the same root cause as the `TestEVEUpgradeKVMtoKVM` failure earlier in this very suite run (recorded in `live-investigation.md`: slow unpack of the same image under disk contention, missing the deadline by seconds) and matches the `TestEVEUpgradeKVMtoKVMWithOCIDatastore` entry from the prior night (2026-11-22, run #38) in `live-ledger.md`, which saw the identical image/unpack pattern (~7m29s unpack, missed by 17s). This is a recurring, known issue first logged 2026-11-22 and now reproducing on consecutive nights with two different tests in the same suite — it looks like an environment-level performance regression (slow/contended disk I/O during container image unpack) rather than an EVE logic bug, and the fixed 10-minute timeout budget leaves essentially no margin for it.

## [2026-11-22 -- 0.0.0-16.0-stable-f3142331 (run #38)](https://github.com/lf-edge/eve/actions/runs/44978581836)

[Full report](https://lf-edge.github.io/eve/test/16.0-stable/runs/38/)

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKVMtoKVMWithOCIDatastore

##### Failure

```
timed out after 10m0.000041922s (excluding download) waiting for app "b1d7ffa6-7cfc-494e-b498-a53cebc050b0" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: INSTALLED)
```

##### Claude's conclusion

###### Root cause

This is a performance/timeout issue, not a logic bug. Device logs show the volume's `CreateVolume` → `UnpackClientImage` for the OCI container (`lfedge/evetest-ubuntu-ctr@sha256:333e5cba...`, ~56.7MB per `doUpdateContentTree: total size changed from 1240 to 56700535`) started at 03:58:58.007 and didn't finish (`createContainerVolume(...) DONE` / `PrepareContainerRootDir` logging the image config) until 04:06:27.146 — about **7m29s** to unpack a modest-sized image, with no errors logged in between (the only containerd-related log in that window is a benign "snapshot ... does not exist: not found" pre-create cleanup message). Because the test's RUNNING-state timeout is 10 minutes *excluding download time* and download had already been subtracted, this unpack alone consumed nearly all of the budget, and the test gave up (`WaitUntilAppIsRunning` timed out at 04:06:37, with last observed state INSTALLED) just **17 seconds** before the app actually reached BOOTING/RUNNING (bootTime 04:06:54, confirmed live via `evetest eve app-info`, which now shows the app already at RUNNING with containerd-shim/domain running). The device currently shows ~30% iowait and load average ~3.8-3.95 on a 4-vCPU VM, consistent with slow/contended disk I/O during the image-unpack step rather than a stuck process.

This does not share a root cause with the earlier `TestEVEUpgradeKVMtoKVM` test in the same suite run (that one completed and left its own logs, with no indication of trouble). I found no prior occurrence of `TestUpgradeSuite`/`TestEVEUpgradeKVMtoKVMWithOCIDatastore` in the ledger (`live-ledger.md` only has one entry, for 2026-11-21, covering `TestAppRoutingSuite`/`TestLocalNetworkInstanceSuite` failures), so this is not a previously known/recurring issue per the ledger — it appears to be a new, environment-driven slow-unpack/timeout flake.

## [2026-11-21 -- 0.0.0-16.0-stable-6ada0c8b (run #33)](https://github.com/lf-edge/eve/actions/runs/44858818992)

[Full report](https://lf-edge.github.io/eve/test/16.0-stable/runs/33/)

### TestAppRoutingSuite: failure analysis

#### TestLocalNIWithMultiplePorts

##### Failure

```

Told to stop trying after 2.482s.
Stop waiting for: NI ONLINE with both static routes via ethernet0 and all connected routes present
Network instance is in error state
networkID:"cea66d72-e546-48f1-9072-0d2859a38149"  networkVersion:"1"  instType:2  displayname:"multi-port-ni"  activated:true  CurrentUplinkIntf:"eth0"  ports:"eth0"  ports:"eth1"  ports:"eth2"  ports:"eth3"  bridgeNum:1  bridgeName:"bn1"  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:06:00:01"  ipAddress:"10.50.0.1"}  networkErr:{description:"IP Route: {dst=0.0.0.0/0, gw=<nil>, port=internet, probe={enabledGwPing=true, gwPingMaxCost=5, userProbe=<none>}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port\nIP Route: {dst=10.88.88.0/24, gw=<nil>, port=httpserver, probe={enabledGwPing=true, gwPingMaxCost=0, userProbe=tcp://10.88.88.70:80}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port"  timestamp:{seconds:1795231767  nanos:793036503}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"192.168.30.1"  port:"eth2"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"172.22.10.1"  port:"eth0"}  ip_routes:{destination_network:"172.22.10.0/24"  port:"eth0"}  ip_routes:{destination_network:"192.168.30.0/24"  port:"eth2"}
```

##### Claude's conclusion

###### Root cause

The failure is a transient NI route-convergence race, not a real product bug. The harness log shows `multi-port-ni` going `INIT -> ERROR` at 03:29:28 with "not matching any port" errors for the `internet`/`httpserver`-labeled static routes, then recovering to `ONLINE` on its own just 9 seconds later at 03:29:37 (confirmed in `TestPropagatedRoutes/TestLocalNIWithMultiplePorts` output and corroborated by the live `zedagent` ZInfoDevice snapshot, which shows `eth0`/`eth2` momentarily erroring with "no suitable IP address available" around the same timestamp — i.e. management port IPs briefly disappeared/reappeared while the new NI config was being applied).

`TestLocalNIWithMultiplePorts` (`evetest/tests/networking/routing_test.go:686`) uses `.StopIf(niHasError)` on the NI-online wait, so it aborts after only ~2.5s the moment the NI reports `ERROR`, instead of tolerating it. This is a known, documented race: `evetest/tests/networking/netinst_test.go` explicitly notes (lines ~48 and ~564) that `StopIf(niHasError)` is *intentionally not used* for the equivalent `TestLocalNI` wait, because "zedrouter/NIM races can briefly flag NI as errored before settling — the eventual ONLINE is what matters." `TestLocalNIWithMultiplePorts` doesn't follow that same precaution for its initial wait, so it is susceptible to exactly this race, and that's what happened here.

This is unrelated to the earlier `TestPropagatedRoutes` test in this run (which passed cleanly in 218s). I found no local ledger/known-issues file in the repo to cross-reference for recurrence history, but the pattern is explicitly called out as a known, previously-handled race elsewhere in this same test file, suggesting it's a recognized but not-yet-fully-guarded issue in this particular test.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestMoveAppBetweenNIs

##### Failure

```

Unexpected error:
    <*fmt.wrapError | 0x941793c8940>: 
    failed to execute script over SSH for app 89af5480-e061-4324-a681-7c349dec7b81: Process exited with status 1 (stderr: )
    {
        msg: "failed to execute script over SSH for app 89af5480-e061-4324-a681-7c349dec7b81: Process exited with status 1 (stderr: )",
        err: <*ssh.ExitError | 0x9417901f1c0>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

SDN reports no errors, ruling out network-emulator-side misconfiguration.

Root cause: `TestMoveAppBetweenNIs` failed at the very first connectivity assertion (ping1 → pong, both freshly deployed on NI "n1") with ping exiting status 1 (100% packet loss, no SSH/script error). Device-side logs show `pong`'s AppNetworkStatus only flipped `IPv4Assigned: true` at 03:26:51.19 (DHCPACK recorded), and its guest then re-sent two more back-to-back `DHCPREQUEST`/`DHCPACK` exchanges at 03:26:55.85-55.86 — i.e. pong's own guest network was still re-negotiating/settling only ~4 seconds before ping1 actually issued the ICMP probe at ~03:27:00. `ping1`'s equivalent DHCP/IP-assignment settled earlier and more cleanly (single DHCPACK at 03:26:46.39), and its own SSH connected fine. The bridge (`bn1`), vifs, and ACLs (ICMP allow-all on both `nbu1x1`/`nbu1x2`) were all correctly configured at the time, and SDN reports no errors, so this looks like a guest-readiness race rather than a config/NI/SDN problem: the test's `WaitUntilAppIsRunning`/VIF-IP-in-subnet check only waits for EVE's own pillar state, not for the pong guest's network stack to fully stabilize, so the first ping can land before pong's container has finished configuring its interface. TestLocalNI and TestNIReplace, which ran earlier in this same suite invocation, both passed, so this isn't a shared root cause from an earlier failure in this run. I found no ledger/known-issues file in the repo to check against, so I can't say whether this is a previously tracked recurring flake.
