# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

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
