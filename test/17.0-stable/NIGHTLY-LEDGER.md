# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

## [2026-11-15 -- 0.0.0-17.0-stable-20cb2032 (run #19)](https://github.com/lf-edge/eve/actions/runs/43691878564)

[Full report](https://lf-edge.github.io/eve/test/17.0-stable/runs/19/)

### TestLocalNetworkInstanceSuite: failure analysis

#### TestFlowLog

##### Failure

```
timed out after 5m0.001818169s (excluding download) waiting for app "6aaeb2ef-add5-450a-b0b1-2f3459fefac1" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

zedbox is alive and running (not crashed), consistent with a hung goroutine rather than a process death.

Root cause assessment:

The test app `flowlog-test-app` is permanently stuck in `RESOLVING_TAG` because the downloader's call to resolve `lfedge/evetest-ubuntu-ctr:1.0` against the SDN's local registry (`192.168.170.2:5000`) hung. Device logs show `resolveTagsToHash` → `manifestsDescImg` → `remote.Get(ref, options...)` (go-containerregistry) was entered at `08:55:35.117` and never logged a completion, error, or retry in the ~7 minutes since — zedbox is still alive (pid 2845), so this is a wedged goroutine, not a crash. Manually curling the same registry's `/v2/` and manifest endpoint from the device just now succeeded instantly, so the registry itself is healthy; the hang was specific to that one resolve attempt. Neither `resolveconfig.go` nor `syncop.go` import `context` at all, so the OCI resolve path has no deadline/timeout on the underlying HTTP(S) call — a single slow/stalled connection (e.g. a TLS handshake against what may be a plain-HTTP SDN registry, or a transient connect stall) blocks the resolver forever with no retry, which matches the test's 5-minute timeout. No other test in this run failed, so this doesn't share a cause with an earlier failure in the suite. I don't have access to a "known-issues ledger" from this session to say whether this is a recurring, tracked problem — no such tool or file was reachable here, so I can't confirm recurrence history.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```

vm2 did not fail back to its own designated node edge-dev3
Expected
    <string>: edge-dev1
to equal
    <string>: edge-dev3
```

##### Claude's conclusion

This is a fresh copy, so no PR diff to check against here; this is simply a test-harness bug. I have enough evidence now.

###### Root cause

The test's final placement check (`dnidbackup_test.go:622`) calls `cluster.FindDeviceHostingApp(vm2UUID, 2*time.Minute)` **without** `excludeDevNames`. That function's own doc comment warns this exact call pattern "can return a device that no longer hosts the app" because it checks each device's **last cached** `ZInfoKubeCluster` snapshot before waiting for a fresh one. Live inspection confirms this: `kubectl get vmi` on the cluster shows `vm2` genuinely `Running` on `edge-dev3` (the correct, designated node, VMI age ~77s at investigation time), but `edge-dev1`'s last published app info for vm2 is a stale snapshot from **09:27:49** (state `RUNNING`, `cluster_app_running:true`), dated well before the final purge/failback sequence — `edge-dev1` is simply checked first in the device iteration order and its outdated cached status is returned instead of waiting for `edge-dev3`'s current one.

This does not share a root cause with the earlier `TestVMIRSStrandedReplicasRecovery` run in this suite (it passed, and its `FindDeviceHostingApp` call correctly passes `excludeDevNames`). I have no ledger of past runs available to check for recurrence, and no PR diff was provided to judge relatedness, so I can't speak to either beyond what's visible here. This looks like a test-harness gap (missing `excludeDevNames: edge-dev1` on that specific call), not an EVE product defect — the actual failback appears to have succeeded correctly on the device side.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:172 with:
the surviving VMIRS must be the NEW generation "failover-purge-app-1310b-1", not a stale one
Expected
    <string>: failover-purge-app-1310b-0
to equal
    <string>: failover-purge-app-1310b-1
```

##### Claude's conclusion

###### Root cause

Live `kubectl get vmirs/vmi` on edge-dev2/edge-dev3 confirms the VMIRS/VMI are still at the **old** generation (`failover-purge-app-1310b-0`, VMI `...-0nvnnk` running on edge-dev3 since 09:56, well before the purge), even though both surviving nodes' `zedmanager` `UuidToNum` records show `purgeCmdCounter=1` — i.e. the purge config was received and the counter bumped, but nothing ever tore down/recreated the domain to produce generation `-1`.

The device-side logs explain why: `zedmanager` on edge-dev3 is stuck in a `HALTING`/`getKubeAppActivateStatus(...): not designated, ..., onTheDevice false` loop. `onTheDeviceForApp` only returns true if `placedHere` (`IsDNidNode || ScheduledOnThisNode`) or the backup-DNID path fires — and the test deliberately pins `dnidOutageThresholdKey` to 2h, disabling the backup-DNID path. `ScheduledOnThisNode`/`AppKubeStatus` are computed in `zedkube.checkAppsFailover` (`pkg/pillar/cmd/zedkube/failover.go`) by matching pod names against `contName`, which is built from the **new, post-purge** counter (`aiconfig.PurgeCmd.Counter+...`). Since the actually-running pod/VMI is still named for the **old** generation, it matches neither the "terminating" nor "new/case 2" prefix check, so `checkAppsFailover` reports it as if nothing were scheduled on this node at all (log line: `pod virt-launcher-failover-purge-app-1310b-0nvnnk-w5lc5, looking for cont failover-purge-app-1310b-1`). That leaves `ScheduledOnThisNode=false`/`AppKubeStatus=NotInCluster`, so `onTheDeviceForApp` never returns true, and `zedmanager` never hands a new domain config to `domainmgr` (domainmgr logs show zero activity for this app UUID) — a genuine chicken-and-egg deadlock: recognizing "already scheduled here" requires a pod matching the new generation name, but that pod can only exist once the recreation the test is waiting for has already happened.

This is a real EVE/pillar bug in the zedkube failover-detection pod-name matching, not a test-harness issue, and it does **not** share the root cause of the earlier `TestDNIDandBackupDNID` failure in this run (that one was a stale-cache read via `FindDeviceHostingApp` without `excludeDevNames`, a harness-side problem). Notably, this is exactly the deadlock scenario the test's own docstring warns about ("gating the teardown on... where a replica currently happens to be scheduled, would deadlock exactly this case") — the implementation appears to hit that very deadlock.


