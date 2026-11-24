# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

## [2026-11-24 -- 0.0.0-master-92671766 (run #46)](https://github.com/lf-edge/eve/actions/runs/45275289457)

[Full report](https://lf-edge.github.io/eve/test/master/runs/46/)

### TestControllerFaultsSuite: failure analysis

#### TestDeferredQueueDropsReported

##### Failure

```

Timed out after 480.000s.
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

Host load is moderate (13% CPU, swap barely used, memory available) — nothing pointing to infra overload here; this is consistent with a deterministic test-harness race rather than host flakiness.

###### Root cause

This is the same test-harness timing race documented twice before in the ledger. Live device logs show `domainmgr` transitioning `reported-app` to HALTED at 22:18:46.862, and zedagent immediately generating/sending the HALTED `ZInfoApp` at 22:18:46.879 — but the fault proxy was still answering `POST .../info` with 404 at that instant (22:18:46.887: `dropping message, controller responded 404 Not Found`). The harness's `ClearControllerFaults()` ran one cycle later (the test's own "Last message given up on at 22:18:48.114..." marks the final 404), by which point the HALTED report was already permanently discarded (404 is treated as non-retriable). Adam's own `app-info` record for this app confirms the last state it ever received is RUNNING — the HALTED report never arrived, and since there's no periodic full-info resync for the normal cloud destination, `settleApp`'s 8-minute `Eventually(Receive(HALTED))` could never succeed, causing the observed 480s timeout.

This matches the exact mechanism in the ledger for `TestControllerFaultsSuite/TestDeferredQueueDropsReported` seen on 2026-11-06 (run #9, first occurrence) and again on 2026-11-22 (run #36) — a known, recurring issue dating back to at least 2026-11-06, caused by the harness's own fault-clear timing racing the device's terminal-state report, not a pillar/EVE regression. Broker host load is modest right now (13% CPU, no swap pressure), which is consistent with this being a deterministic harness-timing bug rather than infra overload.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 3: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"AKO0OLXD"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  storageList:{device:"nbd6"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/newlog"}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/netdump"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/hostfs"  total:244}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/status"}  storageList:{device:"nbd0"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/"  total:3960}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"nbd12"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/config"  total:5}  storageList:{device:"nbd5"}  storageList:{device:"nbd10"}  storageList:{device:"nbd4"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/tmp"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd15"}  storageList:{device:"nbd7"}  storageList:{device:"nbd14"}  storageList:{device:"nbd1"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd8"}  bootTime:{seconds:1795473249}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-master-92671766-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"7e1f6895-e9f3-47c0-bae8-afa1e25a455b"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-master-92671766-kvm-amd64 at 2026-11-23T22:33:24.41180269Z\n"  lastRebootTime:{seconds:1795473204  nanos:508953604}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795473625  nanos:978280332}  lastFailed:{seconds:1795473645  nanos:84078837}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795473645  nanos:83912025}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"3005717d-2603-4822-8fcd-bc1893159fc9"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795473625  nanos:978280332}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795473524  nanos:535717022}  lastSucceeded:{seconds:1795473892  nanos:408259567}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-2\""  timestamp:{seconds:1795473893  nanos:611958466}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"3005717d-2603-4822-8fcd-bc1893159fc9"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795473524  nanos:535717022}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-2\""  timestamp:{seconds:1795473893  nanos:611958290}  severity:SEVERITY_ERROR}}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795473293  nanos:418705402}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xf2\"qs\xf62\x88\xa0\xdc\xc3\"9\x84~\xe0\x0e\xac&K\xc06\xac\x83\xcf\xea\xccI\x02\x8e\x06\x94_"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true  cpu_placement:true}  device_name:"edge-dev"  cpu_pools:{kind:CPU_POOL_KIND_HOUSEKEEPING  cpu_ids:0  cpu_ids:1  cpu_ids:2  cpu_ids:3  free_cpu_ids:3  total_threads:4  allocated_threads:3  free_threads:1  total_cores:4  free_whole_cores:1}  cpu_pools:{kind:CPU_POOL_KIND_DEDICATED}  cpu_pools:{kind:CPU_POOL_KIND_ISOLATED}
```

##### Claude's conclusion

Confirmed: the hostapd log has been silent for over 5 minutes, stuck exactly where past occurrences stall.

###### Root cause

Live evidence on the SDN bridge (`/run/hostapd/bridge0.log`, last modified 22:40:31 vs current time 22:45:51, >5 min of inactivity) shows the device (`da:39:78:d0:19:f2`) completing a successful EAP-TLS handshake after its SCEP-cert-rotation reboot (`CTRL-EVENT-EAP-SUCCESS` → `AP-STA-CONNECTED`, port authorized), then immediately sending an `EAPOL-Logoff`, being unauthorized, and the re-authentication attempt permanently wedging at `IEEE 802.1X: Scheduled disconnection of da:39:78:d0:19:f2 after EAP-Failure` before ever reaching a new identity exchange. Correspondingly, `evetest status` shows `pnac_status.err: "No certificate enrollment status found for SCEP profile \"scep-cycle-2\""`, consistent with the device being stuck mid-cycle and unable to progress to cycle 3's cert-removal/PNAC-disable/VLAN-move assertion within the 300s window.

This is the exact 802.1X re-auth-stall-after-EAP-Failure mechanism documented repeatedly in `live-ledger.md` as a known, recurring issue on `TestPNACWithProxy`/`TestPNACWithoutProxy`, dating back to at least 2026-11-09 (run #12) and recurring on 2026-11-13, 2026-11-16, 2026-11-18, and 2026-11-20 (run #36) — tonight's failure is a continuation of that same unresolved bug in the SCEP/PNAC cert-rotation re-auth path, not a new regression. No PR diff was supplied for this investigation, so no relatedness verdict is given.
#### TestDNSFunctionality

##### Failure

```

Timed out after 120.000s.
The function passed to Eventually failed at /evetest/tests/networking/dns_test.go:414 with:
dnsmasq must have logged forwarding attempts for http-server1.test
Expected
    <[]evetest.LogMsg | len:0, cap:0>: nil
not to be empty
```

##### Claude's conclusion

That background SSH command (a leftover check for `http-server1.test` in `/persist/newlog` and `/run`) was killed after its time limit — it's no longer needed since the root cause was already confirmed via the Adam-side log batch evidence. No further action needed; my analysis above stands.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestMoveAppBetweenNIs

##### Failure

```

Timed out after 180.000s.
Expected to satisfy: App has a VIF IP address from 10.11.12.0/24
AppID:"ea6b762c-2b35-40f6-81b0-6c228a3d91a8"  appVersion:"1"  AppName:"pong"  bootTime:{seconds:1795475023  nanos:22891629}  state:RUNNING  network:{macAddr:"02:16:3e:00:00:03"  devName:"vif0"  defaultRouters:"10.11.12.1"  dns:{}  localName:"nbu1x3"}  volumeRefs:"e1ff4f43-6a73-4591-8cfd-b28d6e7fb9be"  cluster_app_running:true
```

##### Claude's conclusion

Only the one test failure in this run (the other two subtests of the suite are still in progress/paused, not failed). This isn't a shared-root-cause with another failure in this run, and it's not a recurring entry in the ledger for this test.

###### Root cause

This is a narrow timing race, not a functional bug. Live evidence on the device shows the app `pong`'s vif (`nbu1x3`/MAC `02:16:3e:00:00:03`) was correctly plumbed onto bridge `bn1` at 23:03:39, with the static DHCP reservation (`10.11.12.3`) written and the domain reaching `RUNNING` at 23:03:49 — but the guest never sent a single `DHCPDISCOVER` on that vif until **23:06:50.510**, over 3 minutes after boot (its sibling app `ping1` on the same bridge completed DHCP within seconds of its own boot). The moment the guest did discover, `dnsmasq` answered instantly (`DHCPOFFER`→`DHCPACK` in milliseconds) and `zedrouter`/`zedagent` propagated the IP end-to-end (`PublishAppInfoToZedCloud` at 23:06:50.593 shows `IPAddrs:"10.11.12.3"`), confirming the networking/reconciler/pubsub stack behaved correctly throughout. Given the test's 180s deadline, this lines up almost exactly (180s from `RUNNING` at 23:03:49 ≈ 23:06:49, vs. the actual DHCP completion at 23:06:50) — the guest's DHCP client was simply slow to start inside the VM, and missed the deadline by about a second. `evetest broker status` shows the host is heavily overcommitted right now (load avg 10.3 on top of 99% of host memory already assigned to running VMs, only 14.4 GiB free), which is a plausible aggravating factor for slow guest-OS boot/network bring-up, though I can't directly prove causation for this specific window. This exact test/signature does not appear anywhere in `live-ledger.md`, so it isn't a known recurring issue — this looks like a new, environment-driven flake rather than a code regression.
#### TestLocalNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.000684926s (excluding download) waiting for app "c361d284-54ea-41de-81c3-f6f15a6ac018" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live evidence shows the app's volume (`acl-app-1-root`) was waiting on its content tree (`acl-app-1-image`) to resolve a tag against the SDN's local OCI registry (`192.168.170.2:5000/lfedge/evetest-ubuntu-ctr:1.0`). The `manifestsDescImg` resolve call was issued at 23:38:16.108 and didn't log `Resolve config Done` until 23:41:04.962 — a **2m49s** stall — whereas every other resolve of the same image earlier in this exact test run (23:13, 23:14, 23:18, 23:24, 23:32) completed in under a second. That single anomalous delay ate directly into the test's fixed 5-minute "waiting for RUNNING" budget: app config was applied at 23:38:16, the volume didn't finish creating until 23:43:52, and the test had already timed out moments before that (5 min from config-apply ≈ 23:43:16).

This is **not a new issue** — it's the identical, well-documented recurring `downloader`/OCI tag-resolution stall in `live-ledger.md`, first seen 2026-10-31 and recurring repeatedly (2026-11-02 and others), including a prior occurrence on this *exact* test (`TestLocalNetInstanceACLsWithFlowLog`, ledger line ~1997-2013) where the stuck resolve never completed at all, and another sibling-app case with the identical **~2m49s** delay (ledger line ~5243) before eventually succeeding — matching tonight's timing almost exactly. The mechanism is a `runResolveHandler` goroutine in `downloader` that sometimes takes an anomalously long, fixed-feeling ~2m49s (and in other occurrences hangs indefinitely) for a single resolve request against the SDN registry while sibling/earlier resolves for the same image complete instantly; the registry itself has been confirmed healthy in prior investigations of this same signature.

This does not share a root cause with the other failure already investigated in this run (`TestMoveAppBetweenNIs`, a slow in-guest DHCP client race) — different mechanism entirely. No PR diff was supplied, so no relatedness assessment is given.
#### TestPortForwarding

##### Failure

```

Timed out after 180.337s.
The function passed to Eventually failed at /evetest/tests/networking/netinst_test.go:1516 with:
Unexpected error:
    <*fmt.wrapError | 0x196a4366b060>: 
    unable to reach app "dc2c3782-0c59-412a-8a8e-34935691c1b7" SSH on device "edge-dev": no reachable endpoint among [172.20.20.123:2223]
    {
        msg: "unable to reach app \"dc2c3782-0c59-412a-8a8e-34935691c1b7\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.20.123:2223]",
        err: <*errors.errorString | 0x196a428590d0>{
            s: "no reachable endpoint among [172.20.20.123:2223]",
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

The app under test, `app1` (`dc2c3782-0c59-412a-8a8e-34935691c1b7`), reached `RUNNING` at 23:58:00 but its guest never actually completed DHCP until **00:01:00.863** — almost exactly 3 minutes later, after cycling through at least 6 different DHCP transaction IDs (repeated `DHCPDISCOVER` retries) before `dnsmasq-dhcp` finally logged `DHCPACK(bn1) 10.11.12.3`. The test's 180.337s `Eventually` deadline (measured from `RUNNING` at 23:58:00) expired at ~00:01:00.337 — essentially the same instant the IP finally came up — so the SSH port-forward (`172.20.20.123:2223` DNAT/SNAT-hairpinned to `10.11.12.3:22`, which I confirmed is correctly programmed and now fully reachable via direct `ping`/`nc` post-failure) simply had no live endpoint behind it for the entire test window.

This is the same mechanism as the `TestMoveAppBetweenNIs` failure already investigated earlier in this exact suite run (a different app, but an identical "guest DHCP client takes minutes to start, racing a fixed-180s deadline" pattern). `evetest broker status` shows the host is heavily overcommitted right now (load avg 14.41 on 40 CPUs, 96% of host memory assigned to running VMs), a plausible aggravating factor consistent with that prior finding, though not provably the trigger for this specific window. This exact test (`TestPortForwarding`) doesn't appear by name in `live-ledger.md`, so it's not a previously logged recurring failure for this test specifically, but the underlying slow-guest-DHCP-vs-timeout mechanism matches a pattern already seen twice tonight.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 30m0.000047523s (excluding download) waiting for app "e3866fd8-b4e0-4fba-a96d-0e37f5642070" (vm1) on device "edge-dev1" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

This exactly matches today's failure — same test, same symptom, same mechanism, confirmed first seen 2026-10-29. This is sufficient to write the conclusion now.

###### Root cause

This is the same known, long-recurring bug documented repeatedly in the ledger (first seen 2026-10-29, run #1, introduced by commit `98acf1411`, test added in `6574dccd3`), and reproduced identically as recently as yesterday's run (2026-11-22, run #36). Live evidence confirms it exactly:

- `vm1`'s VMI (`vm1-e3866-0cldzw`) has only a *Preferred* (soft, weight-100) node affinity toward its DNID `edge-dev1`, so KubeVirt's scheduler placed and ran it on `edge-dev3` instead (`kubectl get vmi` shows `Running`/`Ready` on `edge-dev3`, phase transitions complete by 22:24:04Z, well before the 30-minute timeout).
- Cluster-wide `evetest cluster info` confirms `eve_vm_apps` for this VMI as `KUBE_VMI_STATUS_RUNNING` on `node_name:"edge-dev3"` — the app is actually healthy.
- But `evetest eve app-info -d edge-dev1` for the same app UUID is stuck at `BOOTING` forever, because `zedmanager`'s `getKubeAppActivateStatus`/`publishAppInstanceStatus` logic on the DNID node (`edge-dev1`) suppresses further status reporting once it detects the pod is scheduled/running on a peer node — by design it never reports `RUNNING` itself in this case, so the controller-visible app status for `edge-dev1` wedges at `BOOTING` even though the guest is fine elsewhere.
- The test's step 1 explicitly polls `dev1.WaitUntilAppIsRunning(...)` (the DNID device specifically), so this placement/reporting gap deterministically times out it at 30 minutes.

This is the identical root cause and code path already catalogued in the ledger for this test (not the same as this run's other `TestNodeClusterResilienceSuite` failures, `TestVMAppPurgeDuringFailover`/`TestClusterPVCRedownload`, which are separate known issues). No PR diff was provided for this investigation, so no relatedness verdict applies.
#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 360.000s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:218 with:
the cluster still lists PVC "593294da-4246-4a3f-aa0e-e17c412df339-pvc-0"
Expected
    <map[string]bool | len:4>: {
        "593294da-4246-4a3f-aa0e-e17c412df339-pvc-0": true,
        "593294da-4246-4a3f-aa0e-e17c412df339-pvc-1": true,
        "99c28b4a-7b85-4e01-bf20-db007b1bdbde-pvc-0": true,
        "babd5698-96e6-466e-b6c9-4e1c081ac102-pvc-1": true,
    }
not to have key
    <string>: 593294da-4246-4a3f-aa0e-e17c412df339-pvc-0
```

##### Claude's conclusion

**Root cause:** During `TestClusterPVCGCDeletesOnlyOrphans`, `edge-dev3` flipped `ONLINE → SUSPECT` at 23:18:55 (confirmed in `gotest.json` and still reflected live now via `evetest cluster info`, which shows `edge-dev3`'s Kubernetes `Ready` condition missing `set:true` and the orphan PVC `593294da-...-pvc-0`'s replica on `edge-dev3` — along with all three replicas of that volume — still `STORAGE_VOLUME_REPLICA_STATUS_OFFLINE`). The test's 360s `Eventually` then timed out 49 seconds later at 23:19:44 with that same orphan PVC still listed. This matches `pkg/pillar/cmd/volumemgr/initialvolumestatus.go`'s `gcPVCs`/`pvcsToReap`, which (via `isCurrentlyBackupDNIDForVolume` in `dnidbackup.go`) only reaps a superseded PVC of a replicated volume from the cluster's app-op-leader node once the volume's designated node has been unhealthy past `dnidOutageThreshold` — device logs confirm no `gcPVCs: deleting PVC 593294da-...` ever fired for this volume on any of the three devices, unlike the sibling orphan (`babd5698-...`) which *did* get reaped earlier at 23:08:52, before any node flapped. This is a direct repeat of the one prior ledger entry for this exact failure line (`pvcgc_test.go:218`, from run #12 on 2026-11-09): a brief node-health blip delaying the backup-DNID-gated PVC reap past the test's fixed 360s window — not a new bug, but now a second occurrence of what was previously a one-off signature, so it looks like a recurring (if intermittent) timing gap between the GC's deliberate outage-threshold/backup-DNID gating and the test's fixed timeout. It does not share a root cause with the other failure already investigated earlier in this run (`TestDNIDandBackupDNID`'s soft-affinity scheduling/activation-status gap on `edge-dev1`) — that was a VMI placement/reporting issue, unrelated to this PVC-GC node-flap timing race. Broker host load (12.98 on 32 CPUs, 73% RAM assigned, 19 VMs running) is mildly elevated but not obviously pathological, so it's a plausible but unconfirmed contributor to the transient SUSPECT flip rather than a certain cause.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

Confirmed live: this is an exact repeat of the identical signature already seen twice earlier in this very run (23:53:25Z and 00:40:50Z-ish occurrences logged in `live-investigation.md`/`live-ledger.md`). Now this is a third occurrence tonight.

**Root cause:** `edge-dev1` (the designated node for app `39975af0-...`/`failover-purge-app`) is `EVE_DEVICE_STATE_SUSPECT`, deliberately powered off by the test. Live `kubectl get vmirs,vmi,vm,pod -A` on `edge-dev2` returns zero VMIRS/VMI/VM anywhere in the cluster (only infra pods: cdi, longhorn, kubevirt, coredns, etc.) — exactly matching the test's `found []`. `edge-dev2`'s live zedmanager logs show an unbroken loop still firing right up to the current moment (00:00:36Z): `getKubeAppActivateStatus(39975af0-...): not designated, node ae05af63-..., onTheDevice false, statusRunning false` → `publishAppInstanceStatus(...) suppressed: IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, repeating every ~15-20s with no new VMIRS ever re-requested after the purge deleted the old one.

This is the identical designated-node/backup-DNID activation-gate deadlock already investigated twice earlier tonight in this same suite run (`live-investigation.md`), and per `live-ledger.md` it's a long-known, unfixed issue first seen 2026-10-29 (run #1, introduced by commit `98acf1411`), reproducing in nearly every nightly run since — tonight's occurrence is simply this run's third hit of the exact same deadlock (now with a different app UUID), not a new bug.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

###### Root cause

Live evidence on `edge-dev1` matches the exact same `pkg/pillar/cmd/volumemgr` PVC-adoption race documented repeatedly in this run's ledger for `TestClusterPVCRedownload`. After vm1's post-reboot reactivation (volumemgr restarted ~00:34:43, vm1-reactivated checkpoint at 00:37:17), the content tree `c4ef30c4-83ea-4cfa-98a1-6c3b43ab20cc` ("vm1-image") logs `contentTreeSatisfiedByPVCs(...): no local volumes reference this content tree` — the matching VolumeConfig/PVC hadn't been republished to volumemgr yet — so `doUpdateContentTree` falls through the ordinary (non-PVC) path, finds all three blobs already present/verified in local CAS, and self-completes `VERIFIED → LOADING → LOADED` in short order, logging "image ... exists in CAS, Content Tree load is completely LOADED." This lands it on `LOADED` (108) instead of `REMOTELOADED` (125), exactly matching `/run/volumemgr/ContentTreeStatus/c4ef30c4-....json` (`"State":108`, still live right now) and the failing assertion; the live `VolumeStatus` for `vm1-root` correspondingly only reaches `CREATED_VOLUME` (110), confirming the volume/PVC side was still catching up when the content tree raced ahead and completed.

This is not a new bug: per `live-ledger.md`, this is a long-standing, well-known recurring issue specific to `TestClusterPVCRedownload`, first seen 2026-10-30 (run #2) and reproducing in the large majority of nightly runs since (including multiple occurrences within this very run earlier tonight, per `live-investigation.md`). It does not share a root cause with this run's other investigated failures (`TestDNIDandBackupDNID`'s soft-affinity scheduling gap, `TestClusterPVCGCDeletesOnlyOrphans`'s GC-timeout-vs-node-flap, or `TestVMAppPurgeDuringFailover`'s designated-node/zedmanager deadlock) — it's a continuation of this specific, unbroken content-tree/PVC-publish-timing race.

### TestNodeClusterSuite: failure analysis

#### TestAppInstancePurge

##### Failure

```
timed out after 10m0.018622112s (excluding download) waiting for app "623a3363-d75a-480e-bbe9-bdb3b1b95193" (purge-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Confirmed: no further retries logged after 05:50:32 (the pause happened at ~05:50-something, matching the stuck state), identical to the pattern previously documented. This is a strong, confirmed match with the known/recurring issue.

No PR diff was given in this task, so I'll conclude without a RELATED line.

**Root cause:** `TestAppInstancePurge`'s own purge logic cordons/drains `edge-dev` (single-node cluster), and at 05:35:20 the drain evicts the `coredns` pod — knocking out cluster DNS. From 05:35:54 to 05:45:23, `volumemgr`'s `RolloutDiskToPVC` for `purge-app`'s root volume (`f187975a-...`) fails every ~30s with `dial tcp: lookup longhorn-backend on 10.43.0.10:53: ... connection refused`, and at 05:40:54 this crosses into a harder "no upload pod annotation" error that trips `CREATING_VOLUME` with an error state. Once CoreDNS/the node drain settles and the node is uncordoned (`cordonNode ... unschedulable:false complete` at 05:50:18), volumemgr retries at 05:50:32 but hits a second, non-retriable failure: `CopyImgDirToRawImg: Failed to create raw image file ... /persist/vault/volumes/f187975a-...-pvc-0.img already exists` — confirmed live, the `.img` file exists on disk timestamped 05:41 (left over from the aborted first attempt). This error isn't classified as a retriable "transient cluster-storage error," so the volume has been stuck in `CREATING_VOLUME` with no further retry logged since 05:50:32, exactly matching the 10-minute timeout the test hit.

This is a **known, recurring issue**: the ledger documents the identical `TestAppInstancePurge` signature and exact mechanism (self-cordon → CoreDNS outage → DNS failure on `longhorn-backend` → stale `.img` file blocking retry → permanently stuck `CREATING_VOLUME`) on **2026-11-05 (run #8)**, where the error text (`CopyImgDirToRawImg: Failed to create raw image file ... pvc-0.img already exists`) is word-for-word the same. The underlying bug — volumemgr's copy-image-to-qcow retry path doesn't clean up or tolerate a pre-existing raw-image file left over from an earlier aborted attempt — remains unfixed. This failure does not appear to share a root cause with any other failure noted elsewhere in tonight's run (no other `TestNodeClusterSuite` failures were found in this run's artifacts).
#### TestMgmtProxy

##### Failure

```
Device "edge-dev1" failed to confirm the latest config (version 1): timed out waiting for LastProcessedConfig >= 2026-11-24 06:28:38.597574822 +0000 UTC
```

##### Claude's conclusion

###### Root cause

This is the same known race documented three times already in `live-ledger.md`: zedagent processes the config fetch essentially on time, but the confirming periodic **metrics** POST (which carries `LastProcessedConfig`) gets wedged. Live evidence for `edge-dev1` confirms it exactly — device logs show `edge-dev1` fetched config v1 at 06:28:39, then at 06:28:52 `"All management ports are marked failed; trying all"` / `"interface eth1: no DNS server available"` as NIM flipped the active DevicePortConfig from the bootstrap `lastresort` key to the controller-assigned one, producing `"interface eth0: no suitable IP address available"` and DNS-resolution failures. The first metrics POST then logged `client.Do (timeout 120000000000) fail: ... dial tcp: lookup adam.evetest ... i/o timeout` at 06:28:55, with further `config`/`metrics`/`info` lookup failures through at least 06:29:09 — i.e. the metrics client blocked/retried past the harness's 120s wait window (started 06:28:39, timed out 06:30:39), and the device only transitioned `BOOTING → ONLINE` at 06:31:15, ~36s after the test had already paused. Meanwhile `edge-dev2`/`edge-dev3` hit the same DPC churn but confirmed config within ~15s, showing this is a timing race, not a deterministic failure.

This is a **known, recurring issue**: `live-ledger.md` records the identical `"failed to confirm the latest config (version 1): timed out waiting for LastProcessedConfig"` signature, with the same DPC-flip/DNS-stall mechanism, on 2026-11-07 (run #10, `TestZVolProvisionedSizeReported`), 2026-11-09 (run #12, `TestVMAppPurgeAfterPowerCycle`), and again later (`TestManyAppInterfaces`) — tonight is simply this same unresolved harness/timing race recurring for `TestMgmtProxy`. It does **not** share the root cause of the other failure already investigated in this run (`TestAppInstancePurge`, a Kubernetes CoreDNS-outage/stale-`.img`-file volumemgr bug) — different mechanism, different layer (device-level DPC/DNS churn vs. in-cluster CoreDNS/Longhorn).

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNIDeletedWithAppsAttached

##### Failure

```
timed out after 5m0.001039957s (excluding download) waiting for app "c3b0b69d-5034-4992-806e-ac15cf1ca491" (app-1) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

**Root cause:** `app-1`'s content tree (`6bf8ea21-...`, image `lfedge/evetest-ubuntu-ctr:1.2`) is stuck in `ContentTreeStatus.State:101` (RESOLVING_TAG), confirmed live via `app-info`. The downloader log shows `manifestsDescImg(192.168.170.2:5000/lfedge/evetest-ubuntu-ctr:1.2)` fired once at 23:12:06.628 and then nothing further was ever logged — no completion, no error — while the sibling `app-2`'s identical concurrent resolve succeeded and reached `State:108`. The registry itself is healthy (`curl http://192.168.170.2:5000/v2/` → 200), and there's a live `ESTABLISHED` TCP connection to `192.168.170.2:5000` from zedbox with a non-empty send queue, consistent with a hung request/goroutine rather than a registry or network outage. The broker host is not overloaded (11% CPU, no swap, 20/21 VMs running) so this isn't an environment resource issue.

This is a known, recurring issue: the ledger shows the identical "one of two concurrent tag-resolve requests hangs forever in RESOLVING_TAG, downloader logs the resolve call and then nothing" signature repeatedly, including this exact same test (`TestSwitchNIDeletedWithAppsAttached`) on 2026-11-02, plus `TestFlowLog`/`acl-app` failures on at least two other nights. It was first flagged in the ledger as "new to this run" around 2026-11-02 and has recurred multiple times since, so this is an ongoing, unresolved hung-tag-resolution bug in the downloader/pillar image-resolve path, not a one-off.

No PR diff was provided for this run, so there's nothing to assess for relatedness.

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes [edge-dev1 edge-dev2 edge-dev3] to become ready in cluster "test-cluster" (device "edge-dev3")
```

##### Claude's conclusion

This confirms it exactly: both edge-dev2 and edge-dev3 are running `/usr/bin/k3s init` (standalone single-node bootstrap), not `k3s server --server https://<join-ip>:6443` joining edge-dev1 — identical to the mechanism previously diagnosed on 2026-11-16 and 2026-11-17.

I have enough evidence now.

###### Root cause

All three devices booted up individually and are healthy (`kubectl get nodes` on each shows itself as `Ready control-plane`), but each one ran `kube-init` as a standalone single-node bootstrap (`/usr/bin/k3s init`, confirmed live via `ps` on edge-dev2 and edge-dev3) instead of two of them joining the first as `k3s server --server https://<join-ip>:6443`. The result is three independent single-node clusters rather than one 3-node cluster, so `admission_status` never leaves `NODE_ADMISSION_JOINING` for any node and `WaitUntilClusterInfoSatisfies` times out after 30 minutes (23:57:31→00:27:31), exactly as `evetest cluster info` shows live. Longhorn's storage health is also flapping `FAILED`/healthy on edge-dev1/edge-dev3, but that's a downstream symptom of the split cluster, not the cause.

This is not a new failure: it is the identical "kube-init bootstraps each node standalone despite correct zedkube cluster config" mechanism first diagnosed in this same ledger on 2026-11-16 (run #20) and again 2026-11-17 (run #21), both against the same pinned pre-upgrade base image `0.0.0-master-66475696` used again tonight — a known, recurring issue that has now reproduced for a third time, not a regression from any current code change. It does not share a root cause with any other failure in this run's `gotest.json` (TestThreeNodesUpgrade was the only failing test tonight), and the host itself (`evetest broker status`: 111% of RAM committed to running VMs, load 30 on 40 CPUs) is under pressure but is a secondary aggravating factor, not the primary mechanism, since the standalone-bootstrap behavior itself is a deterministic kube-init install-path bug rather than a timing race.

## [2026-11-23 -- 0.0.0-master-d4fd28da (run #41)](https://github.com/lf-edge/eve/actions/runs/45075176035)

[Full report](https://lf-edge.github.io/eve/test/master/runs/41/)

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 2: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"ER7FT9H5"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"nbd4"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"nbd0"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"nbd8"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/"  total:3960}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/clear"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{device:"vda"  total:65536}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{device:"nbd1"}  storageList:{device:"nbd5"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"nbd2"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/config"  total:5}  storageList:{device:"nbd3"}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{mountPath:"/persist/status"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/certs"}  storageList:{device:"nbd7"}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/hostfs"  total:245}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{mountPath:"/persist/vault/volumes"}  bootTime:{seconds:1795389284}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-pr45075176035-d4fd28da-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"b3f7256b-35f9-40d6-a1dd-00db315e550e"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-pr45075176035-d4fd28da-kvm-amd64 at 2026-11-22T23:14:00.85839865Z\n"  lastRebootTime:{seconds:1795389240  nanos:961301540}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795389571  nanos:222398096}  lastFailed:{seconds:1795389594  nanos:256771378}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795389594  nanos:256572394}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"2fa3ac87-3c77-42b4-97bb-d0b581c71574"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795389571  nanos:222398096}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795389468  nanos:704549661}  lastSucceeded:{seconds:1795389844  nanos:7670759}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-1\""  timestamp:{seconds:1795389845  nanos:700884245}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"2fa3ac87-3c77-42b4-97bb-d0b581c71574"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795389468  nanos:704549661}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-1\""  timestamp:{seconds:1795389845  nanos:700884045}  severity:SEVERITY_ERROR}}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795389321  nanos:410690855}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"b\xdc\x1fdv\t\x04\xb7\x01^\xfb\xd49\x9a\x05\x92 B\x81\xf4\x8f\xa3L(\x8f\xf7\x977X>C\xc0"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true  cpu_placement:true}  device_name:"edge-dev"  cpu_pools:{kind:CPU_POOL_KIND_HOUSEKEEPING  cpu_ids:0  cpu_ids:1  cpu_ids:2  cpu_ids:3  free_cpu_ids:3  total_threads:4  allocated_threads:3  free_threads:1  total_cores:4  free_whole_cores:1}  cpu_pools:{kind:CPU_POOL_KIND_DEDICATED}  cpu_pools:{kind:CPU_POOL_KIND_ISOLATED}
```

##### Claude's conclusion

This matches exactly the known mechanism: hostapd log confirms last modified at 23:19, ~5.5 minutes of silence vs. now (23:24:45), with the same signature — a successful EAP-TLS handshake followed by `EAPOL-Logoff`, unauthorization, and the follow-up re-authentication permanently stuck at `IEEE 802.1X: Scheduled disconnection of da:39:78:d0:19:f2 after EAP-Failure`.

**Root cause:** This is the well-documented, long-recurring 802.1X re-authentication stall. The device (`da:39:78:d0:19:f2`) completed a successful EAP-TLS handshake against the SDN's hostapd (`CTRL-EVENT-EAP-SUCCESS` → `AP-STA-CONNECTED`, port authorized), then the client immediately sent `EAPOL-Logoff`, was unauthorized, and the subsequent cycle-2 re-authentication attempt got permanently wedged at `IEEE 802.1X: Scheduled disconnection ... after EAP-Failure` — after which the hostapd log went silent (last write 23:19, nothing since, vs. 23:24:45 now). Consistent with that, the live device's `pnac_status.err` is stuck reporting `"No certificate enrollment status found for SCEP profile \"scep-cycle-1\""`, and PNAC never settles, so the test's cycle-2 assertion (cert removed → PNAC disabled → port moved to pre-auth VLAN) can never be observed within 300s.

Per `live-ledger.md`, this exact mechanism hitting `TestPNACWithProxy`/`TestPNACWithoutProxy` is a known, recurring issue dating back to at least 2026-11-09 (run #12), and has recurred repeatedly since (2026-11-13, 2026-11-16, 2026-11-18, 2026-11-20/run #36, and multiple other occurrences) — tonight's failure is a continuation of that same unresolved bug, not a new regression. No PR diff was supplied for this investigation, so no relatedness verdict is given.
#### TestDNSFunctionality

##### Failure

```

Timed out after 120.000s.
The function passed to Eventually failed at /evetest/tests/networking/dns_test.go:414 with:
dnsmasq must have logged forwarding attempts for http-server1.test
Expected
    <[]evetest.LogMsg | len:0, cap:0>: nil
not to be empty
```

##### Claude's conclusion

###### Root cause

The DNS forwarding did work correctly and immediately — device logs confirm dnsmasq logged `forwarded http-server1.test to 10.35.4.25` (and to `10.35.5.25`) at `00:01:54.116`, within milliseconds of the test's `nslookup` at `nslookupAt`. The problem is delivery latency in the log-upload pipeline, not DNS behavior: that log entry didn't actually land in Adam's device-log store until the batch file `01795392208238191844` (spanning roughly `00:03:28`–`00:04:40`), i.e. ~94 seconds after it was generated — leaving only ~26s of margin before the test's 120s `Eventually` at `dns_test.go:414` expired at `00:03:54`. The device had just completed its first boot (`lastRebootReason: "First boot of device" at 00:00:13`) with `debug.default.loglevel`/`debug.default.remote.loglevel` both set to `debug`, producing very large per-minute log batches (0.9–2.3MB files every ~60s) that appear to have backed up the newlog upload pipeline right when the test needed its specific message delivered quickly. The broker host itself is not under load (4% CPU, plenty of free memory/storage), so this isn't an environment-contention issue — it's an EVE/test-timing race between post-boot debug-log volume and the test's fixed 120s timeout.

This is a known, recurring issue: the same test, same assertion (`dns_test.go:414`, "dnsmasq must have logged forwarding attempts for http-server1.test"), failed identically in run #20 (2026-11-16) per `live-ledger.md` — no other occurrences are recorded between then and tonight, so it's intermittent but has been present for at least a week. It does not share a root cause with the other failure already investigated in tonight's run (`TestPNACWithProxy`'s 802.1X/SCEP re-authentication stall) — that was a wpa_supplicant/hostapd re-auth problem on a different device/suite, entirely unrelated to this log-upload-timing race.
#### TestMgmtTrafficRoutedViaApp

##### Failure

```

Told to stop trying after 124.524s.
Stop waiting for: ni-wan is ONLINE
Network instance is in error state
networkID:"ee3ac090-d5ea-4e9c-8bf3-43967349eed3"  networkVersion:"1"  instType:1  displayname:"ni-wan"  bridgeNum:1  networkErr:{description:"failed to select ports for network instance ee3ac090-d5ea-4e9c-8bf3-43967349eed3: no port is matching label 'ethernet0'"  timestamp:{seconds:1795394329  nanos:416775590}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500
```

##### Claude's conclusion

###### Root cause

The controller-assigned DPC (`zedagent`, submitted 00:36:57, carrying the `ethernet0`/`ethernet1` logical labels `ni-wan`'s port selector requires) never actually succeeded: at 00:38:31 it failed its first and only connectivity test with `"interface eth0: no suitable IP address available; interface eth1: no suitable IP address available"` — the DHCP leases on eth0/eth1 weren't ready yet when nim ran the test shortly after boot. nim then fell back to the `lastresort` DPC (confirmed via `/persist/status/nim/DevicePortConfigList/global.json`: `CurrentIndex:1`, `lastresort` key `DPC_SUCCESS` at 00:38:44), whose ports carry the raw `eth0`/`eth1` labels instead of `ethernet0`/`ethernet1` — exactly matching zedrouter's error `no port is matching label 'ethernet0'` for `ni-wan`. Because the higher-priority `zedagent` DPC is marked `DPC_FAIL` and `timer.port.testbetterinterval` isn't set in this device's config (so it defaults to 10 minutes, per `types/global.go`), nim won't retry it for ~10 minutes — far longer than the test's ~125s wait budget, so this cannot self-heal in time, unlike a transient race.

This is the same general family as the already-investigated prior failure in this run (`TestPNACWithProxy`, which also hinges on a stuck DPC/PNAC convergence issue) only in the sense that both involve DPC-state problems after boot, but the specific mechanism differs (PNAC/SCEP re-auth stall vs. an early DHCP-timing race causing a sticky `DPC_FAIL` fallback), so I would not call them the same root cause. It also resembles the "no port is matching label 'ethernet0'" signature seen in `live-ledger.md` for 2026-11-15 run #18 (`TestApplicationGateway`/`ni-eth0`), but that case was a brief few-second async-wait blip that self-corrected; here the controller DPC genuinely failed outright and is parked for the long default retry interval, so it's a worse variant of the same underlying boot-time DPC/port-label race rather than an identical recurrence. I found no prior ledger entry for `TestMgmtTrafficRoutedViaApp` itself, so by that name this is a new occurrence.
#### TestDeviceIPv6StableAddresses

##### Failure

```
Timed out waiting for device "edge-dev" to reboot
```

##### Claude's conclusion

###### Root cause

The device is stuck in a genuine **reboot loop**, not just a slow reboot. `evetest eve logs` shows the exact same device going through `onboot.003-pillar-onboot.out| Reboot reason: NORMAL: First boot of device` on *every* boot cycle since ~23:52, and each cycle ends ~4–15 min later with `zedagent` re-reading the controller's still-pending reboot op (`handleDeviceCmd reason NORMAL: controller reboot`) and immediately scheduling another reboot. Console output confirms `/persist` (vda9) gets a **new ext4 UUID on nearly every single boot** (e.g. `396aa094…`→`093f888d…`→`adcd5a42…`→…→`d069a7db…`), i.e. `/persist` is being wiped/reformatted each cycle — which erases the persisted reboot-ack/counter file, so the device perpetually "forgets" it already honored the controller's reboot command and reboots again as soon as it reads config, in a self-sustaining cycle that never lets the test's single requested reboot settle. `pkg/storage-init/storage-init.sh` reformats P3 on *any* nonzero `fsck` exit (including exit 1, "errors corrected" — a benign post-unclean-shutdown outcome), a known footgun partially addressed by commit `9e0265d34` ("Keep /persist ext4 readable by pre-3.22 e2fsck") but evidently not covering this case; the broker (`farfalle`) is also running at 92% host-memory commitment with load 53 on 10/13 VMs, which plausibly causes the unclean VM shutdowns (watchdog/hard resets under I/O starvation) that seed each fsck failure, and matches the growing storage-init mount times (18s→45s→208s) seen in the most recent cycles.

This does not match the earlier-investigated failures in this run (`TestPNACWithProxy`'s 802.1X/SCEP stall, `TestDNSFunctionality`'s log-upload latency race, `TestMgmtTrafficRoutedViaApp`'s DPC/port-label race) — different mechanism entirely. The ledger's only prior `TestDeviceIPv6StableAddresses` failure (same run #36, hours earlier tonight) was an unrelated "build predates the dhcpcd fix" issue. The ledger's other "Timed out waiting for device to reboot" occurrences (`TestVaultKeyModeRecoveryOnExt4`/`ZFS`) were attributed purely to slow-but-successful single reboots under host contention — this is a qualitatively worse, previously unrecorded failure mode (an actual destructive reboot loop wiping `/persist`), so I'd call it new/not previously logged in the ledger, even though host overload is likely still the underlying trigger shared with those prior entries.

### TestKubeRegistrationSuite: failure analysis

#### TestKubeRegistrationClusterSetup

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3 edge-dev4]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev2": failed to create VM 113 for device "eve-70756051-edge-dev2": 500 user name not set
```

##### Claude's conclusion

###### Root cause

The failure happened entirely on the Proxmox broker side before any EVE device booted. `gotest.json` shows the broker successfully provisioned `edge-dev4` (VM 112), `edge-dev1` (VM 116), and `edge-dev3` (VM 119), but then failed creating `edge-dev2`'s VM 113 with the literal broker error `failed to create VM 113 for device "eve-70756051-edge-dev2": 500 user name not set` — a Proxmox API-level auth/session error, not anything from EVE/pillar. The harness's own failure-path teardown already ran cleanly (all four VMs removed, image dirs cleaned, SDN torn down), confirmed live: `evetest status` shows "No EVE devices found" and `evetest broker status` shows this client (`70756051`) now has "Devices: none" — so there's no live state left to inspect beyond what's already in the logs.

This is not a new signature: `live-ledger.md` shows the identical `"500 user name not set"` error occurred once before, on 2026-11-09 (run #12), for `TestNodeClusterSuite/TestMgmtProxy`, also during concurrent multi-device VM creation (that time VM 107 for `edge-dev2`). So this is a known, recurring (if infrequent) Proxmox broker flake dating back to 2026-11-09, fitting the same broad class of host-side VM-provisioning instability (VM-ID collisions, "no worker upid", TLS timeouts) documented repeatedly in the ledger — not a pillar/EVE regression. `evetest broker status` currently shows the shared host at 17/17 VMs and 65% of memory assigned with load 5.13/32 — moderate concurrent load across 6 client sessions, consistent with (but not definitive proof of) the kind of contention that correlates with these broker auth hiccups.

No PR diff was supplied for this investigation, so no RELATED verdict is given.
#### TestKubeRegistrationAddNode

##### Failure

```
No cluster was set up: TestKubeRegistrationSuite/TestKubeRegistrationAddNode builds on the cluster that TestKubeRegistrationClusterSetup forms, so it only runs as part of TestKubeRegistrationSuite
```

##### Claude's conclusion

This confirms the same "500 user name not set" broker error already documented in live-investigation.md caused `TestKubeRegistrationClusterSetup` to fail in this run, which cascaded directly into this `TestKubeRegistrationAddNode` failure.

Likely root cause: `TestKubeRegistrationAddNode` failed purely as a downstream consequence of `TestKubeRegistrationClusterSetup` failing earlier in this same suite run — `requireKubeRegCluster` (helpers_test.go:151, called from addnode_test.go:80) panics because no cluster was ever formed, exactly matching the reported "No cluster was set up" message. The root cause is the one already recorded in `live-investigation.md` for this run: the Proxmox broker rejected VM creation for `edge-dev2` with `500 user name not set` while concurrently provisioning the 4 cluster devices — a broker-side auth/session error, not a pillar/EVE bug. Harness teardown already ran (devices and SDN torn down), so there's no further live EVE state to inspect for this specific failure. Per `live-ledger.md`, this exact `"500 user name not set"` signature is a known, recurring (if infrequent) broker flake first seen 2026-11-09 (run #12, `TestNodeClusterSuite/TestMgmtProxy`), part of a broader recurring class of Proxmox-broker VM-provisioning flakes. This failure shares its root cause with the earlier `TestKubeRegistrationClusterSetup` failure in this same run.
#### TestKubeRegistrationLonghornDisks

##### Failure

```
No cluster was set up: TestKubeRegistrationSuite/TestKubeRegistrationLonghornDisks builds on the cluster that TestKubeRegistrationClusterSetup forms, so it only runs as part of TestKubeRegistrationSuite
```

##### Claude's conclusion

This confirms the cascade: this test's own "Setup complete" happened fine (devices onboarded and booting — matching the live status I see now), but it immediately failed via `requireKubeRegCluster` → "No cluster was set up," the same guard-clause panic as `TestKubeRegistrationAddNode`.

###### Root cause

This is not an independent failure — it's a third cascading symptom of the same root cause already documented in `live-investigation.md` for this run. `TestKubeRegistrationClusterSetup` failed at 22:48:55 because the Proxmox broker returned `500 user name not set` while provisioning VM 113 for `edge-dev2` — a broker-side auth/session error, not an EVE/pillar bug. Every subsequent sub-test in `TestKubeRegistrationSuite` (`TestKubeRegistrationAddNode`, and now `TestKubeRegistrationLonghornDisks`) builds its own fresh devices successfully (as seen live: all 4 devices are currently up and in `BOOTING` state, onboarded fine) but then immediately fails in `requireKubeRegCluster` (`helpers_test.go:151`) because no kube cluster was ever actually formed in this run — that guard only checks a run-level flag set by `ClusterSetup`, independent of whether new devices boot correctly.

Per `live-ledger.md`, the underlying `"500 user name not set"` broker error is a known, recurring (if infrequent) flake first seen on 2026-11-09 (run #12, `TestNodeClusterSuite/TestMgmtProxy`), part of a broader class of Proxmox-broker VM-provisioning instability. No PR diff was supplied, so no RELATED verdict is given.
#### TestKubeRegistrationManifestUpdate

##### Failure

```
No cluster was set up: TestKubeRegistrationSuite/TestKubeRegistrationManifestUpdate builds on the cluster that TestKubeRegistrationClusterSetup forms, so it only runs as part of TestKubeRegistrationSuite
```

##### Claude's conclusion

Confirmed: the panic is at `manifestupdate_test.go:69` → `requireKubeRegCluster` (`helpers_test.go:151`), the identical guard-clause panic seen in the two prior cascading failures this run. No need to check live device/broker state further since this is purely a pre-flight guard with no new device activity.

###### Root cause

`TestKubeRegistrationManifestUpdate` panics in `requireKubeRegCluster` (`helpers_test.go:151`, called from `manifestupdate_test.go:69`) with "No cluster was set up," the identical guard-clause panic already seen twice earlier in this same run (`TestKubeRegistrationAddNode`, `TestKubeRegistrationLonghornDisks`), confirmed by the `gotest.json` trace showing "Previous test failed; not reusing its devices" / "Tearing down devices from the previous test" immediately before the panic. This is a pure downstream cascade: `TestKubeRegistrationClusterSetup` failed at 22:48:55 because the Proxmox broker rejected VM creation for `edge-dev2` with `500 user name not set`, a broker-side auth/session error unrelated to pillar/EVE — so no kube cluster was ever formed, and every subsequent sub-test in the suite fails this same guard regardless of its own setup success. Per `live-ledger.md`, this `"500 user name not set"` broker error is a known, recurring (if infrequent) flake first recorded 2026-11-09 (run #12, `TestNodeClusterSuite/TestMgmtProxy`), part of a broader class of Proxmox-broker VM-provisioning instability — not a new or EVE-side bug. This failure shares the exact same root cause as the other three failures already investigated in this run.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.057s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

**Root cause:** Confirmed live and matches the already-documented recurring deadlock exactly. Per `gotest.json`, the test powered off DNID node `edge-dev1` at 00:40:53Z to force failover of app `failover-purge-app` (`61aa1101-...`). Live `kubectl get vmirs,vmi,vm,pod -A` on `edge-dev2` shows **zero VMIRS/VMI/VM anywhere in the cluster** (only infra pods), matching the test's `found []`, while `edge-dev2`'s live zedmanager/zedkube logs show an unbroken loop still firing right now (01:04:50Z): `getKubeAppActivateStatus(61aa1101-...): not designated, node fc0d68c3-..., onTheDevice false, statusRunning false` → `newStatus:{... Unknown false}`, repeating every ~10-20s continuously since the purge, with no new VMIRS ever re-requested after the old one was deleted. `edge-dev1` is `EVE_DEVICE_STATE_SUSPECT` (deliberately powered off by the test) and `edge-dev2`/`edge-dev3` are healthy and online.

This is the same signature already recorded in this run's own `live-ledger.md` for this exact test (first captured live at 23:53:25Z in this same nightly run, CI run #45075176035) — i.e. this is a second occurrence of the identical failure within the same run. Per the ledger, this is a long-recurring, well-known issue first seen 2026-10-29 (run #1, introduced by commit `98acf1411`), reproducing in nearly every nightly run since: the designated-node/backup-DNID activation-gate deadlock where no eligible node ever re-requests a VMIRS after a purge-during-failover. No PR diff was supplied for this investigation (the build tested is `d4fd28da`, current master tip), so no relatedness verdict is given.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

###### Root cause

Live `volumemgr` logs on `edge-dev1` show the exact same PVC-adoption race already documented repeatedly for this test. For content tree `1e481045-...` (`vm1-image`), right at vm1's post-reactivation re-create (`01:40:45.094`), `contentTreeSatisfiedByPVCs` logs `"no local volumes reference this content tree"` because the matching `VolumeConfig`/PVC hadn't been republished to volumemgr yet, so `doUpdateContentTree` falls through the normal non-PVC path: it finds all three blobs already `VERIFIED` in the local CAS from the prior run and self-completes `VERIFIED → LOADING → LOADED` by `01:40:49.064`. The live `ContentTreeStatus` on disk confirms `"State":108` (LOADED), matching the failing assertion exactly (expected 125/REMOTELOADED). The app's own `AppInstanceStatus` log line at `01:43:09` shows the volume ref already pointing at `CREATED_VOLUME`/PVC, confirming the PVC really was complete — the content tree simply raced ahead of PVC/volume publication.

This is the same `pkg/pillar/cmd/volumemgr` content-tree/PVC-publish-timing bug catalogued extensively in this run's own `live-ledger.md`: a long-standing, well-known recurring issue for `TestClusterPVCRedownload` specifically, first seen 2026-10-30 (run #2) and reproducing in nearly every nightly run since (20+ logged occurrences, including multiple times within this very run tonight at earlier timestamps). It does not share a root cause with this run's earlier investigated failure (`TestVMAppPurgeDuringFailover`, an unrelated zedmanager/zedkube designated-node failover deadlock). No PR diff was supplied for this investigation, so no code-relatedness assessment is given.

### TestNodeClusterSuite: failure analysis

#### TestAppInstancePurge

##### Failure

```
app "32cb4b68-88e2-4014-b3d9-cc79f0cfe4fd" (purge-app) on device "edge-dev" download stalled at 0% for more than 5m0s
```

##### Claude's conclusion

This is enough to establish the root cause confidently.

###### Root cause

This is the same known, unfixed "datastore-ID-loss" bug in `volumemgr` previously diagnosed in this ledger on **2026-11-06 (run #9)** for this exact test and symptom (`download stalled at 0%`), now recurring after a ~2-week gap. Live evidence matches exactly: `ContentTreeStatus` for `purge-app-image` shows the manifest blob (`333e5cba...`) already `VERIFIED` (`FileLocation` points into `/persist/vault/verifier/verified/`, a CAS-cached leftover from an earlier pull), while all 6 child-blob `DownloaderStatus` entries are pinned at `State:DOWNLOADING(103), DatastoreIDList:null, Progress:0, TotalSize:0, CurrentSize:0` with no error. The code at `pkg/pillar/cmd/volumemgr/updatestatus.go:146-154` (`doUpdateContentTree`) only refreshes a reused root blob's `DatastoreIDList` when its state is `LOADED`, not `VERIFIED`, so the manifest's empty/stale `DatastoreIDList` propagates to every child blob (`AddBlobsToContentTreeStatus`), leaving `downloader` with zero datastores to pull from — it treats that as "nothing to do" rather than an error, so the download silently never starts. `git log` shows this file's last change was on 2026-11-14 (unrelated to this path), confirming the gap at line 146-154 is still unfixed since it was first identified. This is a known, recurring issue (same mechanism, same test, prior occurrence 2026-11-06), not a new bug, and does not appear related to anything else in this run.
#### TestThreeNodesCluster

##### Failure

```
Device "edge-dev2": expected 0 reboot(s) but observed 1
```

##### Claude's conclusion

###### Root cause

Live `NodeAgentStatus` on `edge-dev2` shows `RebootReason: BootReasonKubeTransition, Reboot after retry cluster transition attempt 1` (`RestartCounter:1`, reboot at `2026-11-22T23:29:41Z`). `gotest.json` confirms the mechanism directly: cluster-join stalled for 11 minutes (`initial-config-applied` at 23:18:43, then "Still waiting for cluster nodes to become ready..." every minute through 23:29:43) before EVE-K's own retry logic self-rebooted `edge-dev2`; this time the retry actually worked — the cluster reported ready just ~1 minute later (23:30:57) — but the harness's "expected 0 reboot(s)" check still failed the test on the extra reboot.

This is the same underlying nodeagent/kube-transition "stuck join → retry-reboot" mechanism documented repeatedly in `live-ledger.md` since at least 2026-10-29 (8 occurrences), always previously seen on `edge-dev3` in `TestClusterVMApp`, where the retry reboot left the node permanently rejected with `"not authorized"`. Here it's a new manifestation of that same known bug: a different test (`TestThreeNodesCluster`) and device (`edge-dev2`), and critically the retry *succeeded* this time rather than permanently breaking the join — it just still tripped the reboot-count assertion. It does not share a root cause with this run's earlier-investigated `TestAppInstancePurge` failure (that was a config-not-carried-forward device-reuse issue, not a stuck join). `evetest broker status` shows the Proxmox host at 99% of RAM committed to running VMs (23/23), a plausible contributing factor to the slow convergence that triggered the retry-reboot path, though I can't confirm causation beyond that correlation.
#### TestMgmtProxy

##### Failure

```
Device "edge-dev2": expected 0 reboot(s) but observed 1
```

##### Claude's conclusion

Confirmed root cause with direct live evidence.

**Root cause:** Live `NodeAgentStatus` on `edge-dev2` shows `RebootReason: BootReasonKubeTransition, Reboot after retry cluster transition attempt 1` at `RebootTime:2026-11-23T00:01:48Z` (`RestartCounter:1`). `gotest.json` confirms the mechanism: cluster-join stalled for ~12 minutes ("Waiting for cluster nodes ... to become ready" from 23:50:14 through 00:01:14), `edge-dev2` self-rebooted via its kube-transition retry logic (observed by the harness at 00:02:50, boot time 00:02:17), and the retry then succeeded — the cluster reported ready at 00:04:16, ~2.5 minutes later. The test harness's "expected 0 reboot(s)" assertion still failed on the extra reboot even though the test otherwise proceeded and got further (app deployed, MgmtProxy traffic exercised) before failing at the final reboot-count check.

This is the exact same mechanism — and the same device, `edge-dev2` — as the `TestThreeNodesCluster` failure already investigated earlier in this run (`live-investigation.md`), which hit the identical `BootReasonKubeTransition` stuck-join retry-reboot at 23:29:41. It's also the same known, recurring issue documented repeatedly in `live-ledger.md` since at least 2026-10-29 (8+ prior occurrences, usually on `edge-dev3` in `TestClusterVMApp`); here it's recurring twice in a single run on `edge-dev2`, across two different tests. `evetest broker status` context from the earlier investigation (Proxmox host at 99% committed RAM) remains a plausible contributing factor to the slow cluster convergence underlying both stalls in this run.
#### TestTwoNodeHACluster

##### Failure

```
Timed out waiting for app "ba3058b5-604f-481c-b11b-160b8a24ce43" to be scheduled in cluster "test-two-node-ha-cluster"
```

##### Claude's conclusion

###### Root cause

`container-app`'s volume (`c2bbb029-...`) on `edge-dev2` is stuck in `CREATING_VOLUME` (state 109), not due to a hang but slow I/O: `copy-image-to-qcow`'s output `.img` grew live from 44.8 MB → 49.0 MB in 20 seconds (~210 KB/s) against a 56.7 MB target, confirmed still making forward progress but far too slowly to finish within the test's fixed scheduling-timeout window. The device itself shows `load average: 8.58, 7.07, 4.12` with 22.5% iowait on an 8-vCPU box, and `evetest broker status` shows the Proxmox host running 22/22 VMs at 132 GiB assigned vs. 125.4 GiB host RAM (105% overcommitted) — the same storage/compute contention signature as before.

This is the exact same mechanism as the two earlier `TestTwoNodeHACluster` failures already recorded for this run in `live-investigation.md`/`live-ledger.md` (apps `8dfd7daa-...` and `6bbbbb53-...`), both likewise traced to a slow-but-alive `copy-image-to-qcow.sh`/rsync on `edge-dev2` under host I/O contention. Per `live-ledger.md`, this broader "host storage/iowait contention stalling cluster/volume work past fixed test timeouts" pattern is known and recurring at least since 2026-10-29, recurring across many tests. This is the third instance of this exact issue within tonight's run alone — a known, recurring infrastructure-capacity issue, not a new pillar/EVE code regression.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
timed out after 10m0.000246606s (excluding download) waiting for app "9f011542-8e7e-4719-a31d-bae2c1998972" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

The app (`upgrade-test-app`) is genuinely still making forward progress, just too slowly for the fixed 10-minute timeout, not hung. Live evidence: `evetest eve app-info` shows the app at `CREATING_VOLUME`, but `kubectl get events -n eve-kube-app` shows the PVC pipeline actively completing in real time (CDI scratch-PVC provisioned, `cdi-upload-server` image pulled in ~18s, `UploadSucceeded`, then the VMI/VM getting created) — this happened *after* the test had already timed out and paused, confirming the pipeline wasn't stuck, just slow.

The dominant time sink is earlier: pillar logs show `zedmanager` created the app/volume-ref at `00:30:48`, but `volumemgr` didn't even start processing until `00:36:29.903` ("`volumemgr run: kubernetes node ready, longhorn ready`") — a ~5m41s stall where `volumemgr` was blocked waiting for Longhorn's storage stack to report ready inside this single-node k3s cluster (k3s/kubeconfig itself only became usable at `00:31:29`, per `zedkube`'s `applyLonghornDiskReserved` succeeding then; several Longhorn CSI sidecar pods show one restart each ~6 minutes into their life, consistent with a slow/bumpy CSI registration during bootstrap). That single gap consumed most of the fixed 10-minute (non-download) budget before volume creation work even began, so the subsequent CDI PVC+upload pipeline (which did complete, just not fast) pushed it over the edge.

This doesn't share a root cause with any other failure in this run (it's the only failing test tonight). It's not an exact match for anything in `live-ledger.md` — no prior entry mentions this `volumemgr`/"longhorn ready" gate specifically — but it is the same general class of "fixed test timeout raced against slow single-node k3s/Longhorn/CDI bootstrap or I/O-bound volume creation in CI" flakiness already documented repeatedly in the ledger for this exact test and others (e.g. the iowait/`copy-image-to-qcow.sh`-slow `CREATING_VOLUME` entry that explicitly lists `TestEVEUpgradeKubevirtToKubevirt` among recurring victims, dating back to 2026-10-29). Current `evetest broker status` shows the host only lightly loaded (load 5-6/40 CPUs, 20GB free), but that's a post-hoc snapshot and doesn't rule out contention during the actual 00:16–00:36 window.
#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = EVE installation timed out or failed for device "edge-dev2", EVE installation timed out or failed for device "edge-dev3", EVE installation timed out or failed for device "edge-dev1"
```

##### Claude's conclusion

###### Root cause

All three EVE installers (`edge-dev1/2/3`) were started at 00:48:00–00:48:06 and then produced **zero log output of any kind for the entire 10-minute window** until the fixed installer timeout fired simultaneously for all three at 00:58:05–00:58:16 — no partial progress, no errors, just silence across all three VMs at once, which rules out an EVE/pillar-side installer bug and points to the devices never actually making boot/install progress on the host. By the time the harness paused, devices/SDN were already torn down (`evetest status`: "No EVE devices found"; `evetest sdn status`: "SDN client is not initialized"), so there's no live device state left to inspect. `evetest broker status` now shows load averages of 21.8/21.1 over the 5-/15-minute windows (now dropping, 5.43 over 1 minute) on the shared `farfalle` Proxmox host, consistent with the host having been under sustained load during the 00:48–00:58 test window even though it's lighter now — a post-hoc hint, not proof.

This is the same test and same exact failure signature already investigated earlier in this run (`TestThreeNodesUpgrade` → "EVE installation timed out or failed"), though that earlier instance failed with a VM-ID collision at VM-creation time rather than a silent installer hang — different specific mechanism, same general class (concurrent 3-VM+SDN provisioning overwhelming the shared Proxmox broker host). Per `live-ledger.md`, this precise "EVE installation timed out or failed for device ..." signature for `TestThreeNodesUpgrade` is a long-standing, recurring known issue dating back to at least 2026-11-01 (run #4), recurring repeatedly through 2026-11-05, 2026-11-06, 2026-11-09, and other nights — always attributed to Proxmox host/broker overload during concurrent multi-VM provisioning, not an EVE/pillar defect.

## [2026-11-22 -- 0.0.0-master-f867db5b (run #36)](https://github.com/lf-edge/eve/actions/runs/44954398342)

[Full report](https://lf-edge.github.io/eve/test/master/runs/36/)

### TestControllerFaultsSuite: failure analysis

#### TestDeferredQueueDropsReported

##### Failure

```

Timed out after 480.001s.
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

This confirms exactly the same mechanism as the known prior occurrence.

Root cause: the device correctly transitioned `reported-app` RUNNING→HALTING (22:35:26.537)→HALTED (22:35:59.049), and zedagent generated/attempted the HALTED `ZInfoApp` report at 22:35:59.080, but the test harness's fault proxy was still answering `POST .../info` with 404 at that exact moment (22:35:59.090: `dropping message, controller responded 404 Not Found`). The harness only cleared the fault one tick later ("Cleared controller faults" at 22:36:00, ~0.9s after the drop), by which point the HALTED report was already permanently discarded (404 is treated as non-retriable, unlike the sibling 503 test which passed). Adam's log confirms no further `/info` POST for this app ever arrived (last recorded state is RUNNING), and there is no periodic full resync to re-trigger delivery, so `settleApp`'s 8-minute wait for a HALTED event timed out exactly as observed.

This is the identical race documented in `live-ledger.md` for this same test (`TestControllerFaultsSuite/TestDeferredQueueDropsReported`) on 2026-11-06 (run #9) — same signature, same mechanism (deactivate-while-404-faulted, fault cleared a moment too late, terminal report dropped non-retriably). It's a known, recurring issue dating back to at least 2026-11-06, caused by a race in the test harness's own fault-clear timing relative to the device's HALTED-report attempt, not a pillar/EVE regression. It does not share a root cause with other `ReceiveMatcher`-signature failures in the ledger (those were an unrelated `WatchLogs` subscription bug).

### TestDeviceConnectivitySuite: failure analysis

#### TestDeviceIPv6StableAddresses

##### Failure

```

link-local IPv6 changed across reboot
Expected
    <[]string | len:1, cap:1>: [
        "fe80::1354:e539:a0c3:5e31",
    ]
to equal
    <[]string | len:1, cap:1>: [
        "fe80::14b9:f40e:65a5:b016",
    ]
```

##### Claude's conclusion

No prior occurrences in the ledger — this is a new test, failing for the first time it ran.

###### Root cause

`TestDeviceIPv6StableAddresses` is a brand-new test added in commit `cdb33c3d0` ("dhcpcd: keep IPv6 addresses stable across reboots"), which also changed `pkg/pillar/rootfs/etc/dhcpcd.conf` to use `slaac hwaddr` / `duid ll` so link-local, SLAAC, and DUID values stay MAC-derived across a reboot. However, the device under test is running image `0.0.0-master-f867db5b-kvm-amd64`, and `git merge-base --is-ancestor` shows `f867db5b` is 9 commits *older* than `cdb33c3d0` on master — i.e. this nightly build predates the fix. I confirmed this live: `evetest eve ssh "cat /etc/dhcpcd.conf"` shows the device still has the old config (`slaac private`, plain `duid`, no `duid ll`/`slaac hwaddr`), and the before/after DUIDs in the test log (`00:01:00:01:32:94:e7:f3:...` → `00:01:00:01:32:94:e8:d7:...`) are DUID-LLT (time-embedded), not the link-layer DUID the fix introduces — exactly the behavior the fix was meant to eliminate. So the test is working as designed; it's simply running against a build that hasn't picked up the fix it was written to validate yet. This is not a recurring/known issue (no prior ledger entries for this test or signature), and it's unrelated to the other `TestAppRoutingSuite`/`TestAppsSuite` failures in this run, which are distinct Proxmox broker VM-lifecycle flakiness.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 30m0.007677072s (excluding download) waiting for app "1c735a92-e07c-4a81-b7a4-b5e02e2f6225" (vm1) on device "edge-dev1" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

Live logs confirm the exact known pattern and code path (`kubevirt.go:1271`/`1805`), still ongoing at `22:51:41` (near the failure).

**Root cause:** `TestDNIDandBackupDNID`'s VMIRS for app `vm1` only sets a *preferred* (not required) node affinity toward the DNID `edge-dev1`, so KubeVirt's scheduler placed the VMI on `edge-dev3` instead. Live evidence confirms this exactly: `kubectl get vmi` shows `vm1-1c735-0zmcks` `Running`/`Ready` on `edge-dev3`; `edge-dev1`'s `ENClusterAppStatus` shows `IsDNidNode:true, ScheduledOnThisNode:false, AppKubeStatus:4(RunningState)`; and pillar logs on `edge-dev1` repeat `vmiScheduledOnMeFromVmirs(...): scheduled on "edge-dev3" onMe:false elsewhereReady:true` → `Info(): "vm1-1c735-0 scheduled on a different node"` every poll, still firing at 22:51:41, seconds before the 30-minute timeout. By design, `kubevirt.go:1805`'s `Info()` returns `UNKNOWN` rather than `RUNNING` in this case, so `zedmanager`'s `AppInstanceStatus` for the DNID node stays permanently wedged at `BOOTING` even though the guest is healthy on the peer node — exactly matching the reported timeout.

This is a well-documented, long-recurring issue per `live-ledger.md`: first seen 2026-10-29 (run #1, introduced by commit `98acf1411`/test added in `6574dccd3`), and it has reproduced in the overwhelming majority of nightly runs since, including multiple prior occurrences within this exact run's own ledger. No PR diff was supplied for this investigation, so no relatedness verdict is given.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This confirms the identical signature live, right now at 23:53:25Z — the exact same `getKubeAppActivateStatus(...): not designated` / `publishAppInstanceStatus(...) suppressed` loop recorded in every prior ledger occurrence, with app `failover-purge-app`/`236425b0-...` still deadlocked and no VMIRS/VMI/VM anywhere in the cluster. I have enough to write the conclusion.

**Root cause:** Live evidence (23:53:25Z, current) confirms the well-known `TestVMAppPurgeDuringFailover` designated-node/backup-DNID activation-gate deadlock. `edge-dev1` (the app's designated node) is `EVE_DEVICE_STATE_SUSPECT` (deliberately powered off by the test), `kubectl get vmirs,vmi,vm -A` on edge-dev2 returns **zero resources** cluster-wide ("No resources found") — exactly matching the test's `found []` — and `edge-dev2`'s live zedmanager/zedkube logs show an unbroken loop still firing right now: `getKubeAppActivateStatus(236425b0-...): not designated, node efab9ddf-..., onTheDevice false, statusRunning false` → `publishAppInstanceStatus(...) suppressed: IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, repeating every ~15-20s with no new VMIRS ever re-requested after the purge deleted the old one.

This is the identical mechanism already documented multiple times in both `live-investigation.md` (for this exact run) and `live-ledger.md`: a long-recurring issue first seen 2026-10-29 (run #1, introduced by commit `98acf1411`), reproducing in nearly every nightly run since (explicitly logged again as recently as run #31 earlier tonight, and many runs before that). Tonight's failure is a continuation of that unbroken, still-unfixed streak, not a new bug — it does **not** share a root cause with this run's `TestDNIDandBackupDNID` failure already recorded in `live-investigation.md` (that one is a scheduler-placement/status-reporting gap for ordinary scheduling, whereas this is specifically the purge-after-failover deadlock where no eligible node ever re-requests a VMIRS). No PR diff was provided for this investigation, so no relatedness verdict is given.

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = failed to setup device "edge-dev3" for installation: failed to create VM 115 for device "eve-5b633ed2-edge-dev3": 500 got no worker upid - start worker failed
```

##### Claude's conclusion

###### Root cause

Live `gotest.json` shows a VM-ID collision caused by Proxmox host overload. At 22:52:38 `edge-dev1` was created as Proxmox VM 115; `edge-dev2` got VM 119 at 22:52:42. When the broker then tried to create `edge-dev3`'s VM, it was assigned **VM 115 again — the same ID still actively in use by the still-running `edge-dev1`** — and the Proxmox API call failed with `500 got no worker upid - start worker failed` at 22:54:17 (confirmed again live: `evetest status` still shows this exact error and no EVE devices now exist). The `"no worker upid"` message is pvedaemon failing to even spawn a task worker, which — combined with handing out a VMID that collided with a live VM — points to the Proxmox host's own VM-ID bookkeeping/`nextid` logic returning stale data under load rather than a true free slot. `evetest broker status` currently shows the shared host (`r660xs`) running 19/19 VMs at 78% of host memory with 6 concurrent client sessions and load 6.62/32 CPUs, consistent with (though not definitive proof of, since this is a snapshot taken after the fact) host contention.

No other test in this run failed, so this doesn't share a root cause with an earlier failure tonight. It is, however, a well-known recurring issue: the identical `"500 got no worker upid - start worker failed"` signature appears repeatedly throughout `live-ledger.md` going back to at least 2026-11-01, including multiple prior `TestThreeNodesUpgrade` occurrences and — most relevantly — a near-identical `edge-dev3` VM-creation/SDN-setup failure with this exact error string in this same run's own ledger entry (run #27, 2026-11-21, logged earlier tonight at line 3187-3196). So this is a continuation of the long-standing, broker-side Proxmox overload/ID-allocation flake class, not a new EVE/pillar defect.
#### TestDeviceAddressesAcrossUpgrade

##### Failure

```

DUID is not a DUID-LL of the eth0 MAC
Expected
    <string>: 00:01:00:01:32:94:df:a7:da:39:78:d0:19:f2
to equal
    <string>: 00:03:00:01:da:39:78:d0:19:f2
```

##### Claude's conclusion

###### Root cause

Live evidence is unambiguous: `evetest eve ssh -- cat /etc/dhcpcd.conf` on the paused `edge-dev` device shows the **default/old** dhcpcd.conf (`duid` + `slaac private`), not the new config added in commit `cdb33c3d0` ("dhcpcd: keep IPv6 addresses stable across reboots", 2026-11-19), which replaces those with `duid ll` + `slaac hwaddr` specifically so the DHCPv6 DUID becomes a stable, MAC-derived DUID-LL (type `00:03`). The failing assertion confirms this: the DUID captured after reboot (`00:01:00:01:32:94:df:a7:da:39:78:d0:19:f2`, a type-`0001` DUID-LLT with an embedded timestamp) differs from the previous one because dhcpcd is still generating time-based DUIDs, not the stable `00:03:00:01:<MAC>` form the test expects.

The reason the fix isn't present: the device was upgraded to `lfedge/eve:0.0.0-master-f867db5b-kvm-amd64` (log: "Reusing cached rootfs rootfs-0.0.0-master-f867db5b..."), and `f867db5b` predates `cdb33c3d0` in history (`git merge-base --is-ancestor cdb33c3d0 f867db5b` → false). So this is a stale/cached "master" upgrade-target image that was built before the dhcpcd fix landed, not a regression in the fix itself or in current HEAD.

This does not share a root cause with the other failure already investigated in this run (`TestThreeNodesUpgrade`, a Proxmox VM-ID/broker overload issue — unrelated). It also does not appear anywhere in `live-ledger.md` (no prior `DUID` failures logged), so this is not a known/recurring issue — it's new, and specifically tied to the just-landed `cdb33c3d0` / `75478d2ef` pair (the fix and its new test) outrunning the stale cached master build used as the upgrade target.

No PR diff was provided, so no RELATED line.

## [2026-11-21 -- 0.0.0-master-bdc65bc5 (run #31)](https://github.com/lf-edge/eve/actions/runs/44825178101)

[Full report](https://lf-edge.github.io/eve/test/master/runs/31/)

### TestAppRoutingSuite: failure analysis

#### TestPropagatedRoutes

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev": failed to create VM 111 for device "eve-08e90c26-edge-dev": 500 got no worker upid - start worker failed
```

##### Claude's conclusion

This confirms the failure is a pure Proxmox broker-side error, occurring before any EVE device or SDN instance was ever created — "No EVE devices found" and "SDN client is not initialized" confirm nothing live remains to inspect.

**Root cause:** The broker log (`gotest.json`) shows VM 111 was first created and then immediately removed ("Removed VM 111 of failed setup" at 22:04:40), then the retry attempt to create VM 111 for `edge-dev` hit `500 got no worker upid - start worker failed` at 22:04:44 — a Proxmox `pvedaemon` error meaning the API couldn't even spawn a background task worker for the `qmcreate` call. This is a transient host-level resource/overload condition on the shared Proxmox broker, not an EVE/pillar defect; live `evetest status`/`evetest eve info`/`evetest sdn status` confirm no device or SDN object ever came up, so there's no further device-side state to inspect.

This is **not** a new or isolated failure — it's a known, long-recurring issue per `live-ledger.md`: the identical `"500 got no worker upid - start worker failed"` pvedaemon signature has appeared repeatedly on prior nights (e.g. during `TestEVEUpgradeKVMtoKVM`-style VM teardown on 2026-11-04/run #7, and during `qmcreate` for VM 132 in an earlier run), and this run's own ledger already logged one other `"no worker upid"` occurrence tonight (during SDN configuration for `edge-dev3`, run #27 earlier in this same ledger). It fits the broader, well-documented pattern of shared-Proxmox-host overload under concurrent VM lifecycle operations (alongside sibling symptoms like `/var/log/pve/tasks/.active.lock` timeouts, truncated `unexpected end of JSON input` responses, and LVM "in use" races) that has recurred since at least 2026-11-01.

No PR diff was supplied for this investigation, so no relatedness verdict is given.

### TestAppsSuite: failure analysis

#### TestCPUPlacementWholeCoreSMT

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

I now have enough evidence to write the root cause.

###### Root cause

`TestCPUPlacementOnePerCore` passed cleanly at 23:10:10 and its teardown (client session `4bf7e75d`) immediately followed to make way for `TestCPUPlacementWholeCoreSMT`'s setup. That teardown removed the EVE VM fine, but failed to remove the SDN VM: `gotest.json` at 23:11:40 shows `BROKER level=warning msg="Attempt 1/3: failed to destroy device \"sdn-4bf7e75d\" (will retry): failed to remove VM 111 for device \"sdn-4bf7e75d\": failed waiting for VM 111 deletion: context deadline exceeded"`. Despite that, the broker went ahead and deleted its *local* bookkeeping (removed the SDN image directory) as though teardown had succeeded. ~53 seconds later, when `TestCPUPlacementWholeCoreSMT`'s setup tried to provision a fresh SDN device under the same name, Proxmox/the broker still had the old `sdn-4bf7e75d` (VM 111) record around and rejected the new one with `device "sdn-4bf7e75d" already exists` — exactly the error evetest reported. The harness's own failure-path teardown then succeeded (`evetest status`/`evetest sdn status` now show `No EVE devices found` / `SDN client is not initialized`), so the live system is already clean — there's nothing further to dig up on the live side.

This is a broker/Proxmox-side VM-lifecycle race (deletion of a Proxmox VM timing out, with local state cleaned up before confirming the delete actually completed), not an EVE/pillar bug — no other failure occurred earlier in this run to correlate with. It's also the same broad category of recurring Proxmox-provisioning/teardown flakiness already logged repeatedly in `live-ledger.md` (VM-ID collisions on 2026-11-x runs, truncated-API-response failures, etc.), but this exact signature — a VM *deletion* timing out and leaving a stale device that blocks immediate recreation under the same name — doesn't have a prior ledger entry, so it looks like a new manifestation of that known infra-flakiness class rather than a previously-documented recurring issue.
#### TestCPUPlacementMultiApp

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

No prior ledger entries match this specific "VM deletion timeout leaves a stale device" mechanism — this is a new instance of it, first seen earlier tonight in this same run.

###### Root cause

This is a **direct continuation of the same root cause already diagnosed earlier in this run** (`live-investigation.md`, `TestCPUPlacementWholeCoreSMT`): at 23:11:40 the broker's attempt to tear down the previous SDN device `sdn-4bf7e75d` (Proxmox VM 111) failed with `failed waiting for VM 111 deletion: context deadline exceeded`, yet the broker went ahead and deleted its local bookkeeping (the image directory) as if teardown had succeeded, leaving VM 111 orphaned on the Proxmox host under the name `sdn-4bf7e75d`. `gotest.json` shows no `"Removed Proxmox VM 111"` line anywhere after that point — not during `TestCPUPlacementWholeCoreSMT`'s own failure cleanup, and not during this test's. `TestCPUPlacementWholeCoreSMT` then failed trying to provision a new `sdn-4bf7e75d` (`device "sdn-4bf7e75d" already exists`, 23:12:33), and now `TestCPUPlacementMultiApp` — a fresh test with a freshly-built EVE device (VM 110, successfully provisioned) — hit the **identical** `device "sdn-4bf7e75d" already exists` error at 23:14:24 when trying to provision its own SDN device under the same stuck name. Live checks (`evetest status`, `evetest sdn status`) confirm the harness's own failure-path teardown has since run and the local state is clean, but the real fix requires the orphaned Proxmox VM 111 to be removed on the broker host, which nothing in this run has done. This specific "VM deletion times out → stale device blocks all subsequent provisioning under that name" mechanism doesn't appear anywhere earlier in `live-ledger.md`, so while it belongs to the broader, well-documented class of recurring Proxmox broker/VM-lifecycle flakiness, this exact signature is new as of tonight, not a previously-known recurring issue.
#### TestCPUPlacementStability

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

This confirms VM 111 has never been successfully removed since 23:02:36, and every subsequent SDN provisioning attempt (23:11:42, 23:13:51, 23:15:15 — this failure) collides with it. Live status checks confirm the harness-side state is clean now but the orphaned Proxmox VM 111 itself hasn't been touched.

###### Root cause

This failure is a **direct continuation of the same root cause already diagnosed twice earlier in this run** (`live-investigation.md`, `TestCPUPlacementWholeCoreSMT` and `TestCPUPlacementMultiApp`): at 23:11:40 the broker's attempt to destroy SDN device `sdn-4bf7e75d` (Proxmox VM 111) failed — `failed to remove VM 111 ... failed waiting for VM 111 deletion: context deadline exceeded` — yet the broker deleted its local image-directory bookkeeping as if teardown succeeded, leaving VM 111 orphaned on Proxmox. `gotest.json` shows no `"Removed Proxmox VM 111"` line anywhere after 23:02:36, so every subsequent attempt to provision a fresh `sdn-4bf7e75d` (23:11:42 → failed 23:12:33, 23:13:51 → failed 23:14:24, and now 23:15:15 → failed 23:15:38) hits the identical `device "sdn-4bf7e75d" already exists` conflict. Live checks (`evetest status`, `evetest sdn status`) confirm the harness's own failure-path teardown has run and local state is clean, but the real fix is removing the orphaned VM 111 on the Proxmox broker host, which nothing in this run has done. This is the same broker/Proxmox VM-lifecycle flakiness class seen repeatedly in `live-ledger.md`, but this exact "deletion timeout → stale device blocks all subsequent same-named provisioning" signature has no prior ledger entry, making it new as of tonight (first seen at 23:11:40 in this same run) rather than a previously-known recurring issue.
#### TestCPUPlacementParkedSiblings

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

This confirms Proxmox VM 111 has never been successfully removed since the 23:11:40 timeout, and it's still orphaned and blocking SDN provisioning for a 4th consecutive test now.

###### Root cause

This is a **direct continuation of the same root cause already diagnosed three times earlier in this run** (`live-investigation.md`: `TestCPUPlacementWholeCoreSMT`, `TestCPUPlacementMultiApp`, `TestCPUPlacementStability`). At 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out — `failed waiting for VM 111 deletion: context deadline exceeded` — but local bookkeeping was removed anyway, orphaning VM 111 on Proxmox. `gotest.json` shows no `"Removed Proxmox VM 111"` line anywhere after that point, so every subsequent attempt to provision a fresh `sdn-4bf7e75d` collides with the stale VM, now including this `TestCPUPlacementParkedSiblings` failure at 23:16:36 (the EVE device VM 105 provisioned and tore down fine; only the SDN device collided). Live checks (`evetest status`, `evetest sdn status`) confirm the harness's failure-path teardown is clean locally, but the orphaned VM 111 on the Proxmox broker host itself has never been removed. This exact "VM deletion timeout → stale device blocks all subsequent same-named provisioning" signature has no match in `live-ledger.md`'s history, so it belongs to the broader known class of Proxmox broker/VM-lifecycle flakiness but is a new manifestation first seen tonight (23:11:40), not a previously-documented recurring issue.
#### TestCPUPlacementNeedsRepack

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

This confirms exactly the same unresolved orphaned-VM state: VM 111 has never been removed since the 23:11:40 timeout, and this is now the 5th consecutive test to collide with the stale `sdn-4bf7e75d`.

###### Root cause

This failure is the identical, unresolved continuation of the same root cause already diagnosed four times earlier in this run (`live-investigation.md`: `TestCPUPlacementWholeCoreSMT`, `TestCPUPlacementMultiApp`, `TestCPUPlacementStability`, `TestCPUPlacementParkedSiblings`). At 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out (`failed waiting for VM 111 deletion: context deadline exceeded`), but the broker deleted its local image-directory bookkeeping as though the teardown had succeeded, orphaning VM 111 on Proxmox. `gotest.json` shows no `"Removed Proxmox VM 111"` line anywhere after that point, so every subsequent SDN provisioning attempt collides with the stale VM — now including `TestCPUPlacementNeedsRepack` at 23:17:33, the fifth consecutive such collision. Live checks (`evetest status`, `evetest sdn status`) confirm the harness's own failure-path teardown is clean locally, but the orphaned VM 111 on the Proxmox broker host itself has never been removed, so this will keep failing every subsequent test in the suite until the broker/Proxmox state is manually cleared. This exact "deletion timeout → stale device blocks all subsequent same-named provisioning" signature has no match in `live-ledger.md`'s prior-run history, so it's a new manifestation (first seen tonight at 23:11:40) of the broader known class of Proxmox broker/VM-lifecycle flakiness, not a previously-documented recurring issue.
#### TestCPUPlacementFailsClosed

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

These "already exists" ledger entries are unrelated (volumemgr `.img` file issue, different test). No prior ledger entry matches this exact "SDN device already exists" / Proxmox VM-deletion-timeout signature — consistent with the earlier investigations' conclusion that it's new as of tonight. Live checks confirm the pattern continues.

**Root cause:** This is the same unresolved issue already diagnosed six times earlier in this run (`live-investigation.md`): at 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out (`failed waiting for VM 111 deletion: context deadline exceeded`), but the broker deleted its local bookkeeping anyway, leaving VM 111 orphaned on Proxmox. `TestCPUPlacementFailsClosed` is now the 7th consecutive test to collide with the same stale `sdn-4bf7e75d` name at 23:19:xx. Live checks confirm current state is clean locally (`evetest status` → "No EVE devices found", `evetest sdn status` → "SDN client is not initialized"), i.e. this test's own failure-path teardown ran fine, but the orphaned Proxmox VM 111 itself was never removed, so every subsequent test in this suite will keep failing the same way until that VM is manually cleared on the broker host. Checked `live-ledger.md` across all prior nightly runs — this exact "VM deletion timeout → stale device blocks same-named recreation" signature has no prior occurrence; it's a new infra-flakiness manifestation first seen tonight, not a previously-documented recurring issue (though it belongs to the broader known class of Proxmox broker/VM-lifecycle flakiness).
#### TestCPUIsolatedPool

##### Failure

```
Failed to setup devices [edge-dev-isolcpus]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

Confirmed: `TestCPUIsolatedPool` hit the identical `device "sdn-4bf7e75d" already exists` error, and `evetest status`/`evetest sdn status` again show the local harness state already cleaned up (no EVE devices, SDN client uninitialized) — the same pattern seen in every prior failure tonight.

**Root cause:** This is a direct continuation of the same unresolved issue already diagnosed seven times earlier in this run (`live-investigation.md`, starting with `TestCPUPlacementWholeCoreSMT`): at 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out (`failed waiting for VM 111 deletion: context deadline exceeded`), but local bookkeeping was removed as though it succeeded, orphaning VM 111 on Proxmox. Every subsequent attempt to provision a fresh `sdn-4bf7e75d` collides with that stale, never-removed VM, and `TestCPUIsolatedPool` is now the 8th consecutive test in this run to fail with the exact same signature. This is purely broker/Proxmox-side VM-lifecycle flakiness, not an EVE/pillar bug, and will keep failing every remaining test until VM 111 is manually cleared on the Proxmox broker host. Checked `live-ledger.md`: this exact "deletion timeout → stale device blocks same-named recreation" signature has no prior occurrence across past nightly runs, so it's a new manifestation first seen tonight (23:11:40), not a previously-documented recurring issue — though it belongs to the broader known class of Proxmox broker/VM-lifecycle flakiness logged there.
#### TestVMAppPurgeAfterPowerCycle

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

Confirmed: this is the exact same ongoing issue already tracked in `live-investigation.md` — the orphaned Proxmox VM 111 (`sdn-4bf7e75d`) that failed to delete at 23:11:40 and has never actually been removed. `TestVMAppPurgeAfterPowerCycle` is now the 9th consecutive test in this run to collide with it (23:20:51), with the identical sequence each time: a fresh SDN image builds fine, then provisioning rejects it with `device "sdn-4bf7e75d" already exists`, while the EVE-device side (VM 109 this time) tears down cleanly.

**Root cause:** Same as all 8 prior failures tonight — an unresolved orphaned Proxmox VM 111 under the name `sdn-4bf7e75d`, left behind when its deletion timed out at 23:11:40 but local broker bookkeeping was wiped as if it succeeded. This is purely broker/Proxmox-side VM-lifecycle flakiness, not an EVE/pillar bug, and per `live-ledger.md` this exact "deletion timeout → stale device blocks same-named recreation" signature has no prior occurrence in past nightly runs — it's a new manifestation first seen tonight at 23:11:40, not a previously-documented recurring issue (though it belongs to the broader known class of Proxmox VM-lifecycle flakiness logged there). It will keep failing every remaining test until the orphaned VM 111 is manually cleared on the Proxmox broker host.
#### TestLotsOfApps

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

Confirmed: the identical signature persists live — `evetest status` shows "No EVE devices found" and `evetest sdn status` shows "SDN client is not initialized" (harness-side state clean), yet the test failed with the same `device "sdn-4bf7e75d" already exists` error as the prior 9 failures in this run.

**Root cause:** This is a direct continuation of the same unresolved issue already diagnosed nine times earlier in this run (`live-investigation.md`, starting at `TestCPUPlacementWholeCoreSMT`). At 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out (`failed waiting for VM 111 deletion: context deadline exceeded`), but local bookkeeping was wiped as if the deletion succeeded, orphaning VM 111 on the Proxmox broker host. Every subsequent attempt to provision a fresh `sdn-4bf7e75d` collides with that still-present stale VM, and `TestLotsOfApps` is now the 10th consecutive test tonight to hit this exact signature. This is purely broker/Proxmox-side VM-lifecycle flakiness, not an EVE/pillar bug, and per `live-ledger.md` this exact "deletion timeout → stale device blocks same-named recreation" signature has no prior occurrence in past nightly runs — it's a new manifestation first seen tonight at 23:11:40, not a previously-documented recurring issue, and it will keep failing every remaining test in this suite until VM 111 is manually cleared on the Proxmox broker host.
#### TestLayerDownloadErrorsBounded

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

This is the same unresolved issue documented repeatedly in `live-investigation.md` for this run: at 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out (`failed waiting for VM 111 deletion: context deadline exceeded`), but local bookkeeping was wiped as if the deletion succeeded, orphaning VM 111 on the Proxmox broker host. `gotest.json` shows the identical `device "sdn-4bf7e75d" already exists` error recurring on every single subsequent test's setup since then — `TestLayerDownloadErrorsBounded` at 23:22:28 is now the 11th consecutive test in this run to collide with the same stuck name (after `TestCPUPlacementWholeCoreSMT`, `TestCPUPlacementMultiApp`, `TestCPUPlacementStability`, `TestCPUPlacementParkedSiblings`, `TestCPUPlacementNeedsRepack`, `TestCPUPlacementFailsClosed`, `TestCPUIsolatedPool`, `TestVMAppPurgeAfterPowerCycle`, `TestLotsOfApps`). Live checks confirm the pattern: `evetest status` shows "No EVE devices found" and `evetest sdn status` reports "SDN client is not initialized" — the harness's own failure-path teardown ran cleanly locally, but the orphaned Proxmox VM 111 itself was never removed. Per `live-ledger.md`, this exact "VM deletion timeout → stale device blocks same-named recreation" signature has no prior occurrence in past nightly runs, so it's a new manifestation of the broader known class of Proxmox broker/VM-lifecycle flakiness, first seen tonight at 23:11:40, not a previously-documented recurring issue — and it will keep failing every remaining test in the suite until VM 111 is manually cleared on the Proxmox broker host.
#### TestVGAPassthroughNoHostAccess

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

This failure is the identical, unresolved issue already diagnosed repeatedly earlier in this run (`live-investigation.md`, starting with `TestCPUPlacementWholeCoreSMT`): at 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out (`failed waiting for VM 111 deletion: context deadline exceeded`), but local bookkeeping was wiped as though the deletion succeeded, orphaning VM 111 on the Proxmox broker host. Every subsequent test's SDN setup has collided with that stale, never-removed VM under the same name, and `TestVGAPassthroughNoHostAccess` (23:23:45) hits the exact same error. Live checks confirm the pattern again: `evetest status` → "No EVE devices found" and `evetest sdn status` → "SDN client is not initialized" (harness-side teardown clean locally), but the orphaned VM 111 itself has never been removed on the Proxmox side, so this will keep failing every remaining test until it's manually cleared. This is purely broker/Proxmox VM-lifecycle flakiness, not an EVE/pillar bug, and per `live-ledger.md` this exact "deletion-timeout → stale same-named device" signature has no prior occurrence in past nightly runs — it's a new manifestation first seen tonight, not a previously-documented recurring issue.
#### TestContainerdCPUs

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: device "sdn-4bf7e75d" already exists
```

##### Claude's conclusion

This fully confirms live evidence is consistent with the pattern seen in every prior failure tonight.

**Root cause:** This is the same unresolved issue already diagnosed 12 times earlier in this run (`live-investigation.md`, starting with `TestCPUPlacementWholeCoreSMT`): at 23:11:40 the broker's teardown of SDN device `sdn-4bf7e75d` (Proxmox VM 111) timed out (`failed waiting for VM 111 deletion: context deadline exceeded`), but the broker wiped its local image-directory bookkeeping as if the deletion had succeeded, orphaning VM 111 on the Proxmox broker host. `gotest.json` shows `TestContainerdCPUs` following the identical sequence at 23:23:52–23:24:15: it builds a fresh `sdn-4bf7e75d` image successfully, then the broker rejects provisioning with `device "sdn-4bf7e75d" already exists` and removes its own image directory as cleanup. Live checks confirm the pattern continues — `evetest status` shows "No EVE devices found" and `evetest sdn status` reports "SDN client is not initialized" (this test's own failure-path teardown ran cleanly locally), but the orphaned VM 111 itself has never been removed on Proxmox. Per `live-ledger.md`, this exact "VM deletion timeout → stale device blocks same-named recreation" signature has no occurrence in past nightly runs, so it's a new manifestation (first seen tonight at 23:11:40) of the broader known class of Proxmox broker/VM-lifecycle flakiness, not a previously-documented recurring issue — and it will keep failing every remaining test in the suite until VM 111 is manually cleared on the Proxmox broker host.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithProxy

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: cycle 2: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"LWVW6OKU"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{device:"nbd14"}  storageList:{device:"nbd13"}  storageList:{device:"vda"  total:65536}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{device:"nbd8"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/ingested"}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{device:"nbd0"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{mountPath:"/config"  total:5}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{device:"nbd7"}  storageList:{device:"nbd1"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/clear"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"nbd4"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/"  total:3960}  storageList:{device:"nbd12"}  storageList:{mountPath:"/hostfs"  total:244}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/netdump"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"nbd15"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd5"}  bootTime:{seconds:1795213982}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-master-bdc65bc5-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"a2d3dfe3-05b3-4537-b7f9-dd435ca0b983"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-master-bdc65bc5-kvm-amd64 at 2026-11-20T22:32:17.314319768Z\n"  lastRebootTime:{seconds:1795213937  nanos:703963449}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795214236  nanos:741590264}  lastFailed:{seconds:1795214254  nanos:598978802}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795214254  nanos:598828571}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"8f68ee34-1da9-4b64-b446-f3795510213b"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795214236  nanos:741590264}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795214196  nanos:790388526}  lastSucceeded:{seconds:1795214502  nanos:746329808}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-1\""  timestamp:{seconds:1795214504  nanos:532772433}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"8f68ee34-1da9-4b64-b446-f3795510213b"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795214196  nanos:790388526}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-1\""  timestamp:{seconds:1795214504  nanos:532772294}  severity:SEVERITY_ERROR}}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795214024  nanos:437105167}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xbe\x80\x8ad\xa9\xe4\xeb\x14\x87\x12\xde\x151k\xc5\xd6\xe5'\xf8.\xf72\xa9\xf0\xec\xcdN@uq\xdbC"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true  cpu_placement:true}  device_name:"edge-dev"  cpu_pools:{kind:CPU_POOL_KIND_HOUSEKEEPING  cpu_ids:0  cpu_ids:1  cpu_ids:2  cpu_ids:3  free_cpu_ids:3  total_threads:4  allocated_threads:3  free_threads:1  total_cores:4  free_whole_cores:1}  cpu_pools:{kind:CPU_POOL_KIND_DEDICATED}  cpu_pools:{kind:CPU_POOL_KIND_ISOLATED}
```

##### Claude's conclusion

###### Root cause

Live evidence confirms this is the same long-running 802.1X re-authentication stall seen for `TestPNACWithoutProxy` earlier in tonight's own run. `evetest sdn ssh`'s `/run/hostapd/bridge0.log` on `br-bridge0` shows the device (`da:39:78:d0:19:f2`) completing a successful EAP-TLS handshake (`CTRL-EVENT-EAP-SUCCESS` → `AP-STA-CONNECTED`, port authorized), then immediately sending `EAPOL-Logoff`, being unauthorized, and the follow-up re-authentication getting permanently wedged at `IEEE 802.1X: Scheduled disconnection of da:39:78:d0:19:f2 after EAP-Failure` — after which the log goes silent (last modified 22:37:22, ~5.5 minutes of inactivity vs. current time 22:42:45). Correspondingly, `evetest status` shows `edge-dev` stuck reporting `pnac_status.err: "No certificate enrollment status found for SCEP profile \"scep-cycle-1\""` and only reachable on the pre-auth VLAN IP (172.20.20.123/172.20.10.123), and the device's 9-minute uptime matches a fresh reboot from the SCEP-profile-swap step that never completed re-auth — so the test's cycle-2 assertion (cert removed → PNAC disabled → port moved to pre-auth VLAN) can never be observed within 300s.

This is the exact same mechanism as tonight's earlier `TestPNACWithoutProxy` failure in this same run (recorded in `live-investigation.md`/the ledger's run #27 entry), just hitting the proxy variant on a later cycle. Per `live-ledger.md`, this 802.1X re-auth-stall-after-EAP-Failure signature on `TestPNACWithProxy`/`TestPNACWithoutProxy` is a known, recurring issue dating back to at least 2026-11-09 (run #12), recurring again on 2026-11-13, 2026-11-16, 2026-11-18, and now 2026-11-20 — tonight's failure is a continuation of that same unresolved bug, not a new regression.

No PR diff was supplied for this investigation, so no relatedness verdict is given.

### TestKonvertSuite: failure analysis

#### Shrink

##### Failure

```

Timed out after 720.001s.
The function passed to Eventually failed at /evetest/tests/konvert/app_helpers_test.go:104 with:
Unexpected error:
    <*fmt.wrapError | 0x2bd0748a0220>: 
    unable to reach app "e23287ca-250b-4072-9956-143e66b0fc12" SSH on device "edge-dev": no reachable endpoint among [172.20.20.123:2222 [fe80::11c1:672:b9cf:50c5]:2222 172.20.20.70:22 [fe80::16:3eff:fe1e:327d]:22]
    {
        msg: "unable to reach app \"e23287ca-250b-4072-9956-143e66b0fc12\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.20.123:2222 [fe80::11c1:672:b9cf:50c5]:2222 172.20.20.70:22 [fe80::16:3eff:fe1e:327d]:22]",
        err: <*errors.errorString | 0x2bd0744ae520>{
            s: "no reachable endpoint among [172.20.20.123:2222 [fe80::11c1:672:b9cf:50c5]:2222 172.20.20.70:22 [fe80::16:3eff:fe1e:327d]:22]",
        },
    }
occurred
```

##### Claude's conclusion

This is a known, recurring issue dating back to **2026-10-30** (run #2), and tonight is a second, byte-for-byte recurrence.

**Root cause:** The `Shrink` subtest's SSH timeout is not a networking problem. The redeployed app VMI (`konvert-repartition-app-e2328-0xrvbs`) entered `Paused`/`PausedIOError` (`kubectl describe vmi`: "VM Paused due to not enough space on volume: disk1", 16+ occurrences), and `virt-launcher` logs show it's stuck in a repeating cycle of `Failed to open file '/dev/disk1': No such device or address` → periodic unpause → immediate re-pause (observed continuously from 02:40 through the time of investigation, ~10 min later). The backing Longhorn PVC (`pvc-13ca9dee...`, 300Mi) is `Actual Size: 314576896` — exactly its 300Mi nominal capacity, fully allocated — the same byte-identical actualSize value recorded for this exact failure mode on 2026-10-30. The volume's Longhorn `Robustness` is additionally reported as `degraded`. Since the guest's root disk never actually comes up, SSH never has anywhere to land, which produces the "no reachable endpoint" timeout.

This matches run #2's (2026-10-30) `Shrink` entry in `live-ledger.md` almost exactly — same test (`TestKvmToKRepartitionNoVolmig`/`Shrink`), same `PausedIOError` reason, same "not enough space on volume: disk1" message, and the same 314576896-byte fully-allocated 300Mi PVC signature — so this is a known, recurring bug in how the redeployed app's root-disk PVC size/backing is derived after a kvm→k conversion with content-tree blob reuse, not a new or independent regression, and not a transient infrastructure flake (no SDN/device-connectivity issues preceded it this run — the device and app deployment both succeeded before the VM wedged on disk I/O).

### TestLimitsSuite: failure analysis

#### TestManyAppInterfaces

##### Failure

```

Told to stop trying after 70.036s.
pillar did not survive: the console shows: Rebooting EVE. Reason: panic: send on closed channelWatchdog report for IMGA EVE version 0.0.0-master-bdc65bc5-kvm-amd64 at 2026-11-20T22:15:04+00:00: 3 /run/zedbox.pid
At one point, however, the function did return successfully.
Yet, Eventually failed because the matcher was not satisfied:
The function passed to Eventually failed at /evetest/tests/limits/helpers_test.go:128 with:
all 15 applications are reported running has not happened yet
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

Root cause confirmed via `/persist/reboot-stack` on the live device: zedbox panicked with `panic: send on closed channel` in goroutine 11318, at `pkg/pillar/cmd/downloader/download.go:473` inside `objectMetadata`'s helper goroutine (`receiveChan <- nil`), spawned from `download.go:468`. This is the known close-vs-send race on the per-download-object `receiveChan`, which is created in `downloadHandler.create()` and `close()`d in `downloadHandler.delete()` (`pkg/pillar/cmd/downloader/handlers.go`) with no synchronization against in-flight writers. `TestManyAppInterfaces` provisions 15 apps with many interfaces, generating a burst of concurrent downloader config creates/deletes that reliably triggers the race, matching the test's observed symptom (`all 15 applications are reported running` never became true because zedbox rebooted mid-run). This is a known/recurring issue per `live-ledger.md`: the identical panic and stack trace were first seen 2026-11-05 (run against master-d87216a0) and recurred 2026-11-08 (PR run), both hitting `TestManyAppInterfaces` for the same reason — tonight (2026-11-20) is the third documented occurrence of this exact downloader race, not a new bug.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

edge-dev1 (the designated node) is unreachable, confirming it's offline as expected by the test design. I have enough to write the conclusion.

###### Root cause

**Live evidence (confirmed right now, 23:46:15Z on edge-dev2):** `edge-dev1` (the designated node for app `67ac8735-...`/`failover-purge-app`) is in `EVE_DEVICE_STATE_SUSPECT` and completely unreachable via SSH. `AppInstanceStatus` for the app shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-20T23:30:23Z`, `Activated:false`, `IsDesignatedNodeID:false`, `State:119` (HALTING), and `kubectl get vmirs,vmi,vm -A` returns zero resources cluster-wide — exactly matching the test's `found []`. Live `zedmanager`/`zedkube` logs show the unbroken loop `getKubeAppActivateStatus(67ac8735-...): not designated, node 5d401ef0-..., onTheDevice false, statusRunning false` → `publishAppInstanceStatus(...) suppressed: IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, still actively firing well past the 900s timeout.

This is the designated-node/backup-DNID activation-gate deadlock (`pkg/pillar/cmd/zedmanager/zedmanager.go:2027-2059`): the purge deletes the old-generation VMIRS, and since only the designated node (which the test deliberately keeps powered off) can unconditionally originate a fresh VMIRS, nothing ever recreates one once no eligible backup DNID exists.

Per `live-ledger.md`, this is a **well-known, long-recurring issue** — first seen 2026-10-29 (run #1, introduced by commit `98acf1411`) — and it has reproduced in the overwhelming majority of nightly runs since, right through the most recent logged occurrences (run #25/#26 and many others in between). Tonight's failure is a continuation of that unbroken, still-unfixed streak, not a new bug. No PR diff was provided for this investigation, so no relatedness verdict is given.

### TestNodeClusterSuite: failure analysis

#### TestTwoNodeHACluster

##### Failure

```
Timed out waiting for app "8dfd7daa-1bb8-425b-8049-50857a80ba14" to be scheduled in cluster "test-two-node-ha-cluster"
```

##### Claude's conclusion

**Root cause:** `container-app`'s volume (`140233b7-...`) is stuck in `CREATING_VOLUME` on the designated node `edge-dev2`, not because of a hang, but because the host is I/O-starved: live `top` shows 23.3% iowait with a 6.0-6.2 load average on an 8-vCPU box, and `copy-image-to-qcow.sh`'s `rsync` subprocess (PID 25831, running since 00:15) is still making real forward progress — the output `.img` grew from ~55MB to ~60MB in 20 seconds live during this investigation — but converting the full container rootfs at that rate takes far longer than the test's fixed scheduling-timeout window. This is the exact same mechanism as the prior `TestTwoNodeHACluster` entry already in `live-ledger.md` for this run (same test, same `copy-image-to-qcow.sh`/rsync-slow-not-stuck signature on `edge-dev2`), itself part of a broader "host storage/iowait contention stalling cluster/volume work past fixed test timeouts" pattern documented repeatedly since 2026-10-29 across many different tests (`TestEVEUpgradeKubevirtToKubevirt`, `TestApplicationGateway`, `TestSwitchNIPortConfigRace`, etc.). This is a known, recurring infrastructure-capacity issue, not a new pillar/EVE code regression, and no PR diff was supplied for this investigation.

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes [edge-dev1 edge-dev2 edge-dev3] to become ready in cluster "test-cluster" (device "edge-dev2")
```

##### Claude's conclusion

**Root cause:** All three devices are up and correctly configured (`zedkube`'s `EdgeNodeClusterStatus` on edge-dev2 shows the right `JoinServerIP:10.244.244.2`, `BootstrapNode:false`), but the live process list on edge-dev2 shows `/usr/bin/k3s init` running (single-node bootstrap/init mode) rather than a `k3s server --server https://<join-ip>:6443` join command — and `kubectl get nodes` on each of edge-dev1/edge-dev2/edge-dev3 independently shows only that device itself as a `Ready control-plane` node. So each node formed its own standalone single-node k3s cluster instead of joining the others, which is exactly why `admission_status` stays stuck at `NODE_ADMISSION_JOINING` forever and the suite's "become ready" wait times out (Longhorn storage health is also flapping FAILED/HEALTHY as a downstream symptom of the split cluster, not the primary cause). No other test failed in this run's `gotest.json`, so this doesn't share a root cause with anything else tonight.

Per `live-ledger.md`, this is the identical "kube-init bootstraps each node standalone despite correct zedkube cluster config" mechanism diagnosed for `TestThreeNodesUpgrade` on **2026-11-16 (run #20)**, against the same pinned base image (`0.0.0-master-66475696`), and the ledger notes that base image hasn't been bumped since — so this is a known, recurring issue that has now reproduced again one night later with the identical signature, not a new bug.

## [2026-11-20 -- 0.0.0-master-479b54b2 (run #27)](https://github.com/lf-edge/eve/actions/runs/44624304965)

[Full report](https://lf-edge.github.io/eve/test/master/runs/27/)

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"2CYXUY6Z"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{mountPath:"/persist/newlog"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"nbd2"}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/status"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"nbd4"}  storageList:{device:"nbd8"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/"  total:3960}  storageList:{mountPath:"/persist/log"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"nbd0"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/netdump"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/hostfs"  total:244}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{device:"nbd7"}  storageList:{device:"nbd5"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/config"  total:5}  storageList:{device:"nbd1"}  storageList:{device:"nbd10"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/clear/volumes"}  bootTime:{seconds:1795126620}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-master-479b54b2-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"754bd63c-0a35-45cf-a881-9358d63e05c1"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-master-479b54b2-kvm-amd64 at 2026-11-19T22:16:17.727367554Z\n"  lastRebootTime:{seconds:1795126577  nanos:881688943}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795126772  nanos:479592600}  lastFailed:{seconds:1795126791  nanos:932756995}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795126791  nanos:932611407}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"8d93b79d-951c-4ed1-a4e8-a6bc803075fd"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795126772  nanos:479592600}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795126544  nanos:25385006}  lastSucceeded:{seconds:1795127044  nanos:422809997}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795127045  nanos:814290024}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"8d93b79d-951c-4ed1-a4e8-a6bc803075fd"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795126544  nanos:25385006}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795127045  nanos:814289925}  severity:SEVERITY_ERROR}}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795126658  nanos:993240091}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"l\x044\x0c\xc2?\xf8\x19S\xf6\x89@\xf8y;\x89]/Cݦgu\x1c\xe0\x99P\xed|\xda\x03\xc1"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true  cpu_placement:true}  device_name:"edge-dev"  cpu_pools:{kind:CPU_POOL_KIND_HOUSEKEEPING  cpu_ids:0  cpu_ids:1  cpu_ids:2  cpu_ids:3  free_cpu_ids:3  total_threads:4  allocated_threads:3  free_threads:1  total_cores:4  free_whole_cores:1}  cpu_pools:{kind:CPU_POOL_KIND_DEDICATED}  cpu_pools:{kind:CPU_POOL_KIND_ISOLATED}
```

##### Claude's conclusion

**Root cause:** This is the same long-documented 802.1X re-authentication stall that has recurred since at least 2026-11-09. Live `evetest sdn ssh` evidence on `br-bridge0`'s hostapd log shows the device (`da:39:78:d0:19:f2`) completing a single successful EAP-TLS handshake (`CTRL-EVENT-EAP-SUCCESS` → `AP-STA-CONNECTED` → port authorized) early in cycle 1, then immediately sending `EAPOL-Logoff`, being unauthorized, and the follow-up re-auth attempt getting permanently wedged at `IEEE 802.1X: Scheduled disconnection of da:39:78:d0:19:f2 after EAP-Failure` — after which the hostapd log file (`/run/hostapd/bridge0.log`) shows zero further activity (last modified 22:19:40, nothing since, ~9 minutes of total silence). Correspondingly, the live device's own `DeviceNetworkStatus` and newlog archives show zedagent/nim stuck in a 60s retry loop from 22:19:56 onward reporting `"No certificate enrollment status found for SCEP profile \"new-scep-profile\""`, with `PNAC` never cleanly re-settling (it eventually reports `Enabled:false` locally, but the SDN switch side never receives any corresponding EAPOL/port-state change to actually move the port, since its 802.1X state machine died in the earlier stall) — so the test's final cycle-1 assertion (cert removed → PNAC disabled → port moved to pre-auth VLAN) can never be observed and times out at 300s.

This is the sole failure in this run so far, so there's no other in-run failure to correlate it with. Per `live-ledger.md`, this exact 802.1X-re-auth-stall-after-EAP-Failure mechanism hitting `TestPNACWithoutProxy`/`TestPNACWithProxy` is a known, recurring issue dating back to at least 2026-11-09 (run #12), recurring again on 2026-11-13 and 2026-11-18 (run #23, same mechanism, same test) — tonight's failure is a continuation of that same unresolved bug rather than a new regression. Recent master commits (evetest/volumemgr/package-hash/doc changes) don't touch nim, wpa_supplicant, or PNAC code paths, consistent with this being the pre-existing issue rather than something newly introduced.

### TestKonvertSuite: failure analysis

#### TestKvmToKRepartitionGeometry

##### Failure

```
EVE upgrade to 0.0.0-master-479b54b2-kvm-amd64 failed: no failure reason reported by the device
```

##### Claude's conclusion

###### Root cause

Live `vaultmgr` logs show a genuine TPM-reseal race during the baseos upgrade to `0.0.0-master-479b54b2-kvm-amd64`: right after the controller pushed the new sealed vault key (`00:35:15.650 Re-sealing disk key, Vault Unlocked: false`), the re-seal attempt failed with `Failed to re-seal disk key in TPM checking firmware PCRs before sealing: open [/dev/tpmrm0]: device is not a TPM 2.0`. That left the vault permanently `locked` ("Vault key unavailable"), so `nodeagent`'s `timer.vault.ready.cutoff` (300s) kept expiring every 10s ("Exceeded time for vault to be ready 300 by Ns, rebooting") until it forced a `BootReasonVaultFailure` reboot at `00:40:48`. On the subsequent boot the vTPM/TPM path worked fine and the vault unlocked normally (`00:42:28 Application Data Store unlocked`), and `baseosmgr` only recorded the failure (`swErr: "Exceeded time for vault to be ready..."`, demoting IMGB to `DOWNLOADED`) at `00:42:46–53` — about 30+ seconds *after* evetest's upgrade-wait had already given up at `00:42:13` with "no failure reason reported by the device." So the harness message is simply a race: it polled before the device's own failure record landed.

This is a distinct mechanism from the other `TestKvmToKRepartitionGeometry` ledger entries (those all failed earlier, in setup, on `evebuild/nightly:10.1.0-kvm-amd64` pull-access-denied before any device existed — unrelated to this run, which got a real device up and into the upgrade reboot). It's also different from the previously logged app-vTPM timeout family (`domainmgr`/`vtpmd` `context deadline exceeded` races) and from the `TestVaultKeyModeRecoveryOnExt4` PCR-bank-disabled legacy-key bug — this is the first time this specific host-TPM "`/dev/tpmrm0`: device is not a TPM 2.0" re-seal failure during a baseos upgrade appears in the ledger, so it looks like a new, not-previously-documented flaky-TPM/vTPM-timing issue rather than a recurring one.
#### TestPersistWipeRestore

##### Failure

```
Device "edge-dev": expected 1 reboot(s) but observed 2
```

##### Claude's conclusion

This confirms what's needed — I have enough evidence now.

###### Root cause

This is a direct downstream cascade from the same-run `TestKvmToKRepartitionGeometry` failure already recorded in `live-investigation.md`, not an independent bug. `evetest eve ssh "uptime"` shows the current `edge-dev` boot is only ~4 minutes old, matching exactly the post-`BootReasonVaultFailure` boot that `vaultmgr`/`nodeagent` recovered into at 00:42:28 in the prior investigation — i.e. `TestPersistWipeRestore`'s `Setup()` inherited the *same* un-torn-down device left by `TestKvmToKRepartitionGeometry`'s TPM-reseal-race reboot, rather than a freshly provisioned one. `gotest.json` shows `Setup()` immediately hit `harness.go:1159: the active device provider does not support required capability CAPABILITY_EDIT_DEVICE_DISK` (consistent with the device being stuck in the demoted/`inprogress` IMGB baseos-update state from that aborted upgrade), and then `Close()` → `checkRebootCounts` (`devstate.go:407`) reproduced a stale reboot-count mismatch (`expected 1, observed 2`) — the extra, unaccounted-for reboot being the earlier vault-failure-induced one, carried over onto this new subtest's baseline. This is byte-for-byte the same "stuck-device-propagates-into-next-subtest" mechanism documented repeatedly in `live-ledger.md` for other `TestKonvertSuite` cascades (e.g. the `Shrink`→`Grow`→... SDN-tunnel incident), just triggered this time by the vault-reseal race rather than a dead SDN tunnel. `TestPersistWipeRestore` itself has no prior entries in `live-ledger.md`, so as an independent signature it would be new, but it is not independent — it's a symptom of the still-open `TestKvmToKRepartitionGeometry` failure from earlier in this same run.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 30m0.007076142s (excluding download) waiting for app "aa473b8b-9162-4136-bcd6-2042fcd4b04e" (vm1) on device "edge-dev1" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

###### Root cause

Live evidence on `edge-dev1` confirms this is the exact same known `TestDNIDandBackupDNID`/DNID-scheduling-gap mechanism: app `aa473b8b-...` (`vm1`)'s VMIRS only sets a `preferredDuringSchedulingIgnoredDuringExecution` node affinity toward the DNID (`edge-dev1`), so KubeVirt's scheduler was free to place the VMI on `edge-dev3` instead — confirmed via `evetest eve kubectl get vmi -A -o wide` showing `vm1-aa473-0jtgfm` `Running`/`Ready` on `edge-dev3`, not `edge-dev1`. `/run/zedkube/ENClusterAppStatus/*.json` on `edge-dev1` shows `IsDNidNode:true, ScheduledOnThisNode:false, AppKubeStatus:4(RunningState)`, and `edge-dev1`'s own pillar logs repeat `vmiScheduledOnMeFromVmirs(...): scheduled on "edge-dev3" onMe:false elsewhereReady:true` → `Info(): "vm1-aa473-0 scheduled on a different node"` every ~20s continuously up to now — by design (`pkg/pillar/hypervisor/kubevirt.go:1800`) this returns `UNKNOWN` rather than `RUNNING`, so `zedmanager`'s `AppInstanceStatus` for the DNID node stays permanently wedged at `BOOTING` even though the guest is genuinely healthy on the peer node, matching the 30-minute timeout exactly.

This is a known, recurring issue, not new: the identical signature (same test, same `vm1`/DNID-node `BOOTING` timeout, same scheduler-preference gap) was previously recorded in `live-ledger.md` on **2026-10-31 (run #3)** and again on **2026-11-15 (run #18)**, roughly two weeks apart; tonight's occurrence is the third instance of this same unfixed architectural gap in zedmanager/zedkube's backup-DNID status-reporting path (it only derives `RUNNING` for failover-driven node moves, not ordinary scheduler placement decisions away from the DNID). No PR diff was supplied for this investigation, so no relatedness verdict is given. Recent commits touching `zedmanager`/`kubevirt.go` (CPU placement, start-delay, vCPU pinning) are unrelated to this scheduling/affinity gap.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

###### Root cause

This is the same long-known `TestVMAppPurgeDuringFailover` deadlock already recorded for run #25 in `live-ledger.md`, and live evidence confirms it is reproducing again right now with a fresh app instance. `edge-dev1` (the app's designated node) is still `EVE_DEVICE_STATE_SUSPECT`, `kubectl get vmirs,vmi,vm -A` on `edge-dev2` returns zero resources cluster-wide (matching the test's `found []`), and `edge-dev2`'s live zedmanager/zedkube logs (23:55:36–23:55:45 UTC, right now) show the identical unbroken loop: `getKubeAppActivateStatus(2aea1b4e-...): not designated, node c061290e-..., onTheDevice false, statusRunning false` and `checkAppsFailover` reporting `AppKubeStatus:Unknown` — this time for a different app UUID than the one already logged in the ledger entry, confirming this is a new occurrence of the same mechanism rather than a stale observation.

This is a well-documented, long-recurring issue in `live-ledger.md`: first seen 2026-10-29 (run #1, introduced by commit `98acf1411`), and it has reproduced in the overwhelming majority of nightly runs since, including already once tonight in run #25 before this occurrence. It does not share a root cause with the other failure already analyzed in this run's `live-investigation.md` (the DNID/VMIRS node-affinity scheduling gap in `TestDNIDandBackupDNID`) — that is a distinct zedmanager/kubevirt status-reporting gap for ordinary scheduler placement, whereas this is a purge-after-failover deadlock where no new VMIRS is ever re-requested once the old one is purged with no designated node available.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.000346367s (excluding download) waiting for app "39f7418c-f1be-4954-b574-ca52a9633909" (acl-app-2) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

###### Root cause

Live state confirms the app is still wedged: `evetest eve app-info` for `acl-app-2` (`39f7418c-…`) shows `state:RESOLVING_TAG` right now, and its content tree `614168e8-0afc-4ca8-99ec-97f6ed8f6fd9` (`acl-app-2-image`, image `lfedge/evetest-ubuntu-ctr:1.0`) is still `State:101` (RESOLVING_TAG) on disk. `volumemgr`'s `doUpdateContentTree` fired exactly once at 22:18:15, found no resolve status, and called `MaybeAddResolveConfig`, logging "...Done" — but `/run/volumemgr/ResolveConfig/` is completely empty (no file was ever persisted for this or any other resolve request), and there is zero `downloader` log activity (`runResolveHandler`, `lookupResolveStatus`, etc.) for this content ID — the resolve request effectively vanished with no completion or error, so `volumemgr` just waits forever. Meanwhile the sibling app in the same test, `acl-app-1` (`80ecce3e-…`), resolved normally and reached `RUNNING` (`State:110/115`) — only one of the two identical concurrent tag-resolve requests hung.

This is the exact signature already catalogued multiple times in `live-ledger.md`: a hung downloader tag-resolution goroutine for one sibling app while the other resolves fine, first seen 2026-10-31 and recurring on 2026-11-02, and notably this very test (`TestSwitchNetInstanceACLsWithFlowLog`) failed with the identical mechanism earlier in this run's own history (that time `acl-app-1` was the one stuck, `acl-app-2` succeeded — now the roles are reversed). So this is a known, long-recurring, still-unfixed downloader/resolve bug, not a new regression, and zedbox itself is healthy (no crash/restart) — the hang is purely in the resolve-request handling path.

No PR diff was provided for this investigation, so no relatedness verdict is given.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup device "edge-dev" for installation: failed waiting for VM 108 creation: task failed on Proxmox: unable to create VM 108 - cannot import from 'local:import/ev-eve-6101d0a9-edge-dev-0.qcow2' - copy failed: command '/usr/bin/qemu-img convert -p -n -f qcow2 -O raw /var/lib/vz/import/ev-eve-6101d0a9-edge-dev-0.qcow2 zeroinit:/dev/pve/vm-108-disk-1' failed: exit code 1 (task UPID:r660xs:000701F5:0C90808C:6AFF8E40:qmcreate:108:root@pam:)
```

##### Claude's conclusion

###### Root cause

Live evidence from `gotest.json`: Proxmox VM ID **108** was reused three times in this run on host `r660xs` — created at 23:44:03 for `TestEVEUpgradeKVMtoKVM` (passed), removed/recreated for `TestEVEUpgradeKVMtoKVMWithOCIDatastore` (passed), then removed again at **00:02:00** and immediately recreated for `TestEVEUpgradeKubevirtToKubevirt` starting at 00:03:01. That third `qmcreate` failed at 00:03:19 with `qemu-img convert ... -O raw /var/lib/vz/import/ev-eve-6101d0a9-edge-dev-0.qcow2 zeroinit:/dev/pve/vm-108-disk-1` exiting with code 1 — i.e. writing to the LVM logical volume backing VM 108's disk failed, most plausibly because the device-mapper node for `pve/vm-108-disk-1` from the just-torn-down prior VM 108 hadn't fully released before Proxmox tried to create a fresh LV of the same name only ~61 seconds later. `evetest status` confirms the device was never provisioned ("No EVE devices found") and the SDN/device teardown already completed cleanly, so there's nothing further to inspect live; this is a pure broker/Proxmox-side infrastructure failure, not an EVE/pillar defect.

This failure doesn't share a root cause with anything else earlier in this same run (the two prior upgrade tests passed cleanly). Per the ledger, it's a new manifestation (no prior occurrence of this exact `qemu-img convert .../zeroinit` + exit-code-1 signature, nor of host `r660xs` — all prior entries reference host `farfalle`), but it fits the same broad, well-documented class of shared-Proxmox-host LVM/disk races under rapid VM ID reuse seen repeatedly since at least 2026-11-01 (e.g. the `lvremove 'pve/vm-105-disk-1' ... Logical volume in use` race recorded in this same ledger, and the VM-ID-collision pattern noted for VM 107 reuse). So: a known category of flake, but this specific symptom/host combination is new, not a previously catalogued recurring failure.

No PR diff was supplied for this investigation, so no relatedness verdict is given.
#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev3 edge-dev1 edge-dev2]: rpc error: code = Unknown desc = failed to setup device "edge-dev1" for installation: failed waiting for VM 108 creation: task failed on Proxmox: unable to create VM 108 - cannot import from 'local:import/ev-eve-6101d0a9-edge-dev1-0.qcow2' - copy failed: command '/usr/bin/qemu-img convert -p -n -f qcow2 -O raw /var/lib/vz/import/ev-eve-6101d0a9-edge-dev1-0.qcow2 zeroinit:/dev/pve/vm-108-disk-1' failed: exit code 1 (task UPID:r660xs:000709FE:0C90A538:6AFF8E9E:qmcreate:108:root@pam:), failed to setup device "edge-dev2" for installation: failed waiting for VM 108 creation: task failed on Proxmox: unable to create VM 108 - cannot import from 'local:import/ev-eve-6101d0a9-edge-dev2-0.qcow2' - copy failed: command '/usr/bin/qemu-img convert -p -n -f qcow2 -O raw /var/lib/vz/import/ev-eve-6101d0a9-edge-dev2-0.qcow2 zeroinit:/dev/pve/vm-108-disk-1' failed: exit code 1 (task UPID:r660xs:00070A74:0C90A679:6AFF8EA1:qmcreate:108:root@pam:), failed to setup device "edge-dev3" for installation: failed waiting for VM 114 creation: task failed on Proxmox: unable to create VM 114 - cannot import from 'local:import/ev-eve-6101d0a9-edge-dev3-0.qcow2' - copy failed: command '/usr/bin/qemu-img convert -p -n -f qcow2 -O raw /var/lib/vz/import/ev-eve-6101d0a9-edge-dev3-0.qcow2 zeroinit:/dev/pve/vm-114-disk-1' failed: exit code 1 (task UPID:r660xs:00070ACF:0C90A73E:6AFF8EA3:qmcreate:114:root@pam:)
```

##### Claude's conclusion

No further live-state commands available here since no device was ever created. I have enough evidence to conclude.

Root cause: this is a Proxmox/broker-side VM-provisioning infrastructure failure, not an EVE/pillar defect. The live `gotest.json` timeline shows VM ID 108 was already in a bad state before `TestThreeNodesUpgrade` even started: the prior test (`TestEVEUpgradeKubevirtToKubevirt`) removed VM 108 at `00:02:00`, then its own `qmcreate` for a fresh VM 108 failed with the identical `qemu-img convert ... zeroinit:/dev/pve/vm-108-disk-1 ... exit code 1` error at `00:03:19` — so VM 108's disk LV was left in a bad/half-created state with no successful "prepared"/"removed" cycle afterward. When `TestThreeNodesUpgrade` started ~90s later, the broker's VM-ID allocator handed out **VM 108 to both `edge-dev1` and `edge-dev2` simultaneously** (`qmcreate` tasks 3 seconds apart on host `r660xs`), while `edge-dev3` got 114 — a genuine ID collision between two concurrently-provisioned devices in the same test, both hitting the same `qemu-img convert` failure on `/dev/pve/vm-108-disk-1`.

This directly continues the root cause already identified earlier in this same run (`live-investigation.md`'s `TestEVEUpgradeKubevirtToKubevirt` analysis): rapid reuse of Proxmox VM ID 108 on host `r660xs` racing against LVM logical-volume teardown/creation. This failure is the same underlying bug biting a second, worse time — now colliding two devices onto the same ID rather than just racing a stale LV. Per the ledger, there's no prior exact match for this `zeroinit`/exit-code-1 signature or for host `r660xs`, but it fits the long-documented recurring class of shared-Proxmox-host LVM/VM-ID-reuse races (e.g. `lvremove`/"Logical volume in use", storage-lock timeouts) seen repeatedly since at least 2026-11-01. `evetest status` confirms "No EVE devices found," so there's no pillar-side state to inspect — the failure occurred entirely in broker/Proxmox infrastructure before any EVE device booted.

## [2026-11-19 -- 0.0.0-master-feaf8860 (run #25)](https://github.com/lf-edge/eve/actions/runs/44407188114)

[Full report](https://lf-edge.github.io/eve/test/master/runs/25/)

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

###### Root cause

Live evidence confirms this is the long-known `TestVMAppPurgeDuringFailover` deadlock. `edge-dev1` (the designated node for `failover-purge-app`) is currently `EVE_DEVICE_STATE_SUSPECT` (deliberately powered off by the test), and `kubectl get vmirs,vmi,vm -A` on `edge-dev2` returns **zero resources cluster-wide**, exactly matching the test's `found []`. `edge-dev2`'s live zedmanager logs show an unbroken loop since the purge completed: `getKubeAppActivateStatus(4ecede59-...): not designated, node ea2cdecb-..., onTheDevice false, statusRunning false` repeating every ~10-20s continuously up through the current moment (02:16+), with `zedkube` correspondingly reporting `AppKubeStatus:Unknown` the whole time — nothing ever re-requests a new VMIRS once the old one is purged with no designated node available to originate a fresh one.

This exact test/failure line (`purge_during_failover_test.go:169`, "expected exactly one VMIRS for the app, found []") is a well-documented, long-recurring issue in `live-ledger.md`: first seen 2026-10-29 (run #1, introduced by commit `98acf1411`), and it has reproduced in the overwhelming majority of nightly runs since (explicitly logged again through at least 2026-11-18, run #23) — tonight's failure is a continuation of that unbroken, still-unfixed streak rather than a new bug. No PR diff was provided for this investigation, so no relatedness verdict is given.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

###### Root cause

Live `volumemgr` logs on `edge-dev1` show the identical PVC-adoption race already catalogued repeatedly in `live-ledger.md` for this exact test. For content tree `246d41d3-7867-4250-90dd-11bf2428d2f0` (`vm1-image`), right after vm1's reactivation, `doUpdateContentTree` at `02:51:53.503–515` finds all blobs already present/verified in the local CAS, logs `"image ... exists in CAS, Content Tree load is completely LOADED"`, and self-completes `LOADING → LOADED` (108) in that single pass — while the matching `VolumeRefStatus`/`VolumeStatus` for volume `70ef2e93-...` (PVC `70ef2e93-5636-43d7-bd7a-90fa3e071eb0-pvc-0`) only shows up as `CREATED_VOLUME` in zedmanager's app-instance status later (confirmed by `02:54:19`), i.e. the content tree races ahead of PVC/volume publication and never takes the `REMOTELOADED` (125) path. This is the exact same mechanism, same log signature, and same test as the `TestClusterPVCRedownload` entries already investigated multiple times earlier tonight and on many prior nights in this run's own `live-investigation.md`/`live-ledger.md` — a long-standing, well-known recurring issue first seen 2026-10-30 (run #2) and reproducing in the large majority of nightly runs since, including repeatedly within this very run. It does not share a root cause with this run's earlier `TestVMAppPurgeDuringFailover` failure (an unrelated zedmanager/zedkube purge-after-failover deadlock). The SDN gRPC "connection reset"/reconnect churn seen around 02:42:48–50 is unrelated harness noise (the cluster reformed and vm1 came up RUNNING fine afterward) and not the cause of this failure.

### TestNodeClusterSuite: failure analysis

#### TestMgmtProxy

##### Failure

```
Timed out waiting for app "60983c37-34f5-4d64-9303-2a30e7ff41df" to be scheduled in cluster "mgmtproxy-test-cluster"
```

##### Claude's conclusion

###### Root cause

`TestMgmtProxy`'s app (UUID `60983c37-...`) never got scheduled because its root volume (`6e5604cf-536b-4438-93f7-0f2173ea04f0`) is permanently stuck in `CREATING_VOLUME` on its designated node, `edge-dev1`. Live `volumemgr` logs show a single `RolloutDiskToPVC` attempt starting at 23:06:22, which failed at 23:06:53 with `error uploading image after 10 retries: unexpected return value 503,: exit status 1` from the `cdi-uploadproxy` service — and then nothing: no further `RolloutDiskToPVC`/`virtctl` attempt, no `retryFailedClusterVolumeCreate` log line, and the live `AppInstanceStatus`/`VolumeStatus` on edge-dev1 (checked at 23:16-23:17, well past the test's 23:14:08 timeout) still shows `State:109 (CREATING_VOLUME)`, `SubState:2 (PrepareDone)`, with an **empty `Error` field** — meaning the transient-error-driven retry path in `pkg/pillar/cmd/volumemgr/retryclustervolume.go` (`clusterVolumeRetryActionFor`, which only re-drives a volume while `status.HasError()` is true) never saw this failure recorded and therefore never fired. zedbox itself is healthy and continuously running (uptime 30m50s, `restartcounter:1`, no panics/watchdog reboots), so this isn't a crash — the failed worker result simply never got persisted back onto the VolumeStatus.

This is the same mechanism already documented in the ledger for `TestMgmtProxy` on 2026-11-07 (run #10): a single CDI-uploadproxy `503` stalling `CREATING_VOLUME` with zero further retry activity, which that entry flagged as possibly "a distinct, unretried-hang variant worth separate attention" rather than the classic repeated-503 pattern seen since 2026-11-01/11-02. Tonight reproduces that exact signature again, so this is a known, recurring issue dating back to at least 2026-11-07 (and the broader CDI-upload-503-stalls-CREATING_VOLUME family since 2026-11-01), not a new regression — though the fact that the bounded retry mechanism added for this (`retryclustervolume.go`) still doesn't recover from it suggests the specific "error result never recorded onto VolumeStatus" gap remains unfixed. No other test in this run has failed yet, so there's no shared root cause to report there, and no PR diff was provided for a relatedness verdict.

### TestSecuritySuite: failure analysis

#### TestAppVTPMIsolation

##### Failure

```

Timed out after 300.000s.
The function passed to Eventually failed at /evetest/tests/security/vtpm_helpers_test.go:127 with:
read guest TPM NV marker: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 
WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded 
ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI 
ERROR: Could not load tcti, got: "(null)"

Unexpected error:
    <*fmt.wrapError | 0x2657ccc46a40>: 
    failed to execute script over SSH for app bbe4324d-706d-4a3f-b0e7-58cc777f412d: Process exited with status 1 (stderr: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
    ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
    WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
    ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 
    WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded 
    ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI 
    ERROR: Could not load tcti, got: "(null)"
    )
    {
        msg: "failed to execute script over SSH for app bbe4324d-706d-4a3f-b0e7-58cc777f412d: Process exited with status 1 (stderr: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 \nERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 \nWARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused \nERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 \nWARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded \nERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI \nERROR: Could not load tcti, got: \"(null)\"\n)",
        err: <*ssh.ExitError | 0x2657cea9d980>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

Live `domainmgr` logs for app `bbe4324d-706d-4a3f-b0e7-58cc777f412d` (`vtpm-isolation-a`) show the exact same domainmgr/vtpmd timeout race documented repeatedly earlier in this same run and in prior nights: at `23:21:08.072` domainmgr logged `Failed to setup vTPM for bbe4324d...: ... context deadline exceeded` (its fixed swtpm-launch client timeout fired), but `vtpmd` actually succeeded ~4s later at `23:21:12.000` (`"vTPM launched SWTPM instance with id: bbe4324d-..., pid: 82"`). By then domainmgr had already set `status.VirtualTPM = false` and built the qemu domain config without a TPM device — confirmed live: `/run/domainmgr/domains/dom1.cfg` has zero `tpm` references, while `swtpm` is in fact alive and healthy on the host for this UUID (`pid 24146`). This is exactly why the guest has no `/dev/tpm0`/`/dev/tpmrm0`, matching the TCTI "no such file"/connection-refused errors in the failure.

This shares the same root cause as the two earlier vTPM failures already analyzed in tonight's run (`TestAppVTPMProtectedFailurePreservesState` and an earlier instance of `TestAppVTPMIsolation` on app `bd60d956-...`), both logged in `live-ledger.md`. It's a known, recurring issue: first diagnosed on 2026-11-02 (`TestAppVTPMIdentitySurvivesReboots`), recurring on 2026-11-05 (`TestAppVTPMBackupRecoversPrimaryCorruption`), and now hitting this same mechanism a fifth+ time overall (including twice already tonight). No PR diff was provided for this investigation, so no RELATED verdict is given.

### TestTelemetrySuite: failure analysis

#### TestKernelPanicReport

##### Failure

```

/persist/newlog holds no kernel_panic_stacks lines
Expected
    <int>: 0
to be >
    <int>: 0
```

##### Claude's conclusion

###### Root cause

`TestKernelPanicReport`'s final phase checks `/persist/newlog` for `kernel_panic_stacks` lines only ~94 seconds after nodeagent logged the panic dump (logged at 23:31:53.476, checked at 23:33:27.378) and found 0. Re-running the identical check (`eve exec pillar sh -c 'find /persist/newlog -name "dev.log.*" -exec zcat -f {} \;' | grep -c kernel_panic_stacks`) live right now returns **384** — the full data is there. Per-chunk inspection shows the 384 lines landed in `keepSentQueue/dev.log.1795044814958.gz` and `dev.log.1795044823562.gz`, whose rotation timestamps are 23:33:34 and 23:33:43 UTC — i.e. newlogd only flushed the active buffer into a `dev.log.*`-named file 7–16 seconds *after* the test's check already failed. With `newlog.allow.fastupload` enabled (as this test expects), the log-file rotation timeout is only 10s (`fastlogfileDelay` in `pkg/newlog/cmd/newlogd.go:32`), so normally this should have rotated out well within the 94s window; here it took ~100s, likely because the burst of boot-time kernel/device logs around the post-panic reboot (384 panic-stack lines plus the rest of the boot log) backed up newlogd's collector loop long enough to delay the routine 5-second `checklogTimer` rotation past the test's one-shot check.

This is **not** the same root cause as the earlier `TestKernelPanicReport` failures recorded in the ledger (first 2026-10-29, recurring 2026-11-04/11-07/11-08) — those all failed with a different assertion ("the kernel panic stack trace end marker was not uploaded") caused by a known `AdamClient.SubscribeToDeviceLogs` live-subscription bug (data sitting in Adam's DB but never delivered to the test's `WatchLogs` channel). Tonight's failure is a different phase/assertion (the final `persist-checked` phase, which greps the device's own `/persist/newlog` directly via SSH, with no Adam/controller involvement at all), and this exact message does not appear anywhere earlier in `live-ledger.md`, so it is a new failure mode, not a recurrence of the documented issue. There are no other failed suites in this run to correlate with. This looks like a flush-timing race between newlogd's log-rotation under boot-time log volume and the test's single immediate check, rather than a data-loss bug — but I can't rule out a newlogd regression without further investigation (e.g. whether this rotation delay is typical or itself anomalous).

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes [edge-dev1 edge-dev2 edge-dev3] to become ready in cluster "test-cluster" (device "edge-dev1")
```

##### Claude's conclusion

###### Root cause

Live evidence: all three k8s nodes are actually `Ready` (`kubectl get nodes` shows edge-dev1/2/3 all `Ready, control-plane,etcd`), but `evetest cluster info` shows cluster storage stuck `SERVICE_STATUS_DEGRADED` continuously from 23:01:12 until the 23:23:30 timeout (and still degraded now) — and the harness's `clusterNodeReady` check (`evetest/edgecluster.go:207-211`) requires storage `HEALTHY` in addition to node-ready, so the whole wait was gated on storage alone. The cause is isolated to `edge-dev3`: its `longhorn-csi-plugin` pod is in `CrashLoopBackOff` (15 restarts) and `longhorn-manager` is `1/2` ready, both unable to reach cluster-internal Services from their pod network namespace — logs show repeated `dial tcp: lookup longhorn-backend on 10.43.0.10:53 ... i/o timeout` and earlier `no route to host` to the apiserver ClusterIP, even though the node's own host network (routes, flannel VTEPs, iptables KUBE-SVC rules) all look normal and `edge-dev3`'s host-netns can reach those same ClusterIPs fine.

This is the identical mechanism already diagnosed twice before in `live-ledger.md` for `TestThreeNodesUpgrade`/`TestEVEUpgradeKubevirtToKubevirt`-adjacent runs on **2026-11-07 (run #10)** and again **2026-11-08**: a node's CNI/service-routing state not being correctly reconciled after its identity/IP switch during cluster admission, leaving its Longhorn (and sometimes virt-handler) pods permanently `CrashLoopBackOff` on "no route to host"/CoreDNS timeout against their own ClusterIP/pod network, which keeps cluster storage `DEGRADED` forever — just affecting `edge-dev2` in those prior instances versus `edge-dev3` tonight. This is therefore a **known, recurring issue since at least 2026-11-07**, not a new failure, and no PR diff was supplied for this investigation.

## [2026-11-18 -- 0.0.0-master-c82bcfeb (run #23)](https://github.com/lf-edge/eve/actions/runs/44185588947)

[Full report](https://lf-edge.github.io/eve/test/master/runs/23/)

### TestDeviceConnectivitySuite: failure analysis

#### TestActiveBackupBond

##### Failure

```
Device "edge-dev" failed to confirm the latest config (version 1): timed out waiting for LastProcessedConfig >= 2026-11-18 00:07:47.877494691 +0000 UTC
```

##### Claude's conclusion

This confirms the exact match: the very first `publishMetrics` call (at boot, before the controller-assigned bond config took effect) tried sending via `eth1 with src IP 172.20.20.42` — an address from the old/bootstrap network — and the HTTP client blocked for the full 120s timeout, finally failing at 00:09:48.240 with `context deadline exceeded`, right as the device's mgmt interface had already moved to `bond1`/172.20.20.123. Since `LastProcessedConfig` is only surfaced via that periodic metrics POST (`handlemetrics.go:648`), and this one attempt got wedged on a stale connection/route from before the DPC switch to the bond, the updated value was never delivered within evetest's 2-minute wait window, which expired at almost the same instant.

This is a known, recurring issue, not new. The ledger documents the identical mechanism at least twice before in this same ledger file (line 1605, and again similarly at line 2619): a metrics-send attempt starts just before/at the DPC network switch, binds to the pre-switch route/IP, and blocks for the full 120s HTTP client timeout before failing, missing the test's 2-minute `LastProcessedConfig` wait by mere seconds. No other failure in this run shares this exact root cause (the other `TestDeviceConnectivitySuite` failures in run #21's PNAC/DNS entries are unrelated mechanisms). No PR diff was provided for this investigation, so no RELATED verdict is given.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

Leader election converged correctly (edge-dev3 is `IsAppOpLeader:true`), ruling out the leader-election-race variant seen in some other nights — this is specifically the designated-node/backup-DNID activation-gate failure mode.

###### Root cause

Live inspection on edge-dev3 (the node the app failed over to) confirms the known deadlock: `kubectl get vmirs,vmi,vm -A` returns zero objects cluster-wide (matching the test's `found []`), while `AppInstanceStatus` for the app shows `PurgeInprogress:4`, `Activated:false`, `IsDesignatedNodeID:false`, and `ENClusterAppStatus` shows `IsDNidNode:false, ScheduledOnThisNode:false`. The purge deleted the old-generation VMIRS, but because the app isn't recognized as designated/scheduled on this node, zedmanager never re-requests a new VMIRS from domainmgr/zedkube — it's permanently stuck. Leader election is healthy (edge-dev3's `KubeLeaderElectInfo` shows `IsAppOpLeader:true` matching the actual lease holder), ruling out the separate leader-election-race variant that causes this same test to fail on other nights.

This is **not a new issue**: per `live-ledger.md`, this exact `TestVMAppPurgeDuringFailover` designated-node/backup-DNID activation-gate deadlock has been recurring nightly since **2026-10-29** (first seen run #1), reproducing in nearly every nightly run since (explicitly logged again as recently as 2026-11-15, run #18, and many runs in between) — tonight's failure continues that same unbroken, still-unfixed streak rather than being a new bug.

No PR diff was supplied for this investigation, so there's nothing to assess for code-change relatedness.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
timed out after 10m0.000875214s (excluding download) waiting for app "3204205c-0647-4565-b027-e96cf3d8c6f3" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: INITIAL)
```

##### Claude's conclusion

I have enough evidence now. No PR diff was provided for this investigation, so I'll omit the RELATED line.

###### Root cause

The app `upgrade-test-app` never got scheduled onto `edge-dev` because Longhorn's storage stack (CSI driver, instance-manager, csi-attacher/provisioner/resizer/snapshotter) took far longer than the test's budget to come up: `zedkube`'s `ENClusterAppStatus` shows `ScheduledOnThisNode: false` for the app even after the full 10-minute window, and `kubectl describe pod` on `longhorn-csi-plugin` shows its `node-driver-registrar` image alone took 1m55s to pull, while k8s events show the `instance-manager` pod took **7m18s** to pull a 441MB image and the csi-attacher/provisioner/resizer/snapshotter images each took ~2 minutes — all occurring well after the "k3s-ready" checkpoint was already reached 16 minutes late (22:56:58→23:13:00). Live `top` on `edge-dev` confirms the cause: 23.7% iowait with load average climbing from 6.3 to 11.6 on a 4-vCPU box, 28 minutes after boot — classic shared-host storage contention, not an application or pillar logic bug (`AppInstanceStatus`/`VolumeRefStatus` both sit cleanly at state 100/INITIAL, simply never progressing because the CSI plugin wasn't registered in time).

This is a well-established, recurring infra issue per `live-ledger.md`: this exact test (`TestEVEUpgradeKubevirtToKubevirt`) has failed from this same "host storage/iowait contention stalling K3s/Longhorn/CDI work past fixed test timeouts" pattern repeatedly — explicitly recorded in runs #7, #8, #10, #14, and #17, with the broader pattern traced back to **2026-10-29**. This run is a fresh instance of that same long-standing flake, not a new bug.
#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes [edge-dev1 edge-dev2 edge-dev3] to become ready in cluster "test-cluster" (device "edge-dev1")
```

##### Claude's conclusion

###### Root cause

All three devices are stuck because kube-init bootstrapped each one as its own independent single-node k3s cluster instead of joining them into one HA/etcd cluster, even though zedkube had already correctly distributed cluster config to all three before k3s started. Live evidence: `kubectl get nodes` on each device shows only itself (never edge-dev2/3 from edge-dev1 or vice versa); each node's k3s server process was launched as a local/non-HA server (`/usr/bin/k3s init` seen in `ps`, no `/etc/rancher/k3s/config.yaml` anywhere, no etcd datastore); and zedkube's own logs show the *correct* `EdgeNodeClusterConfig` was already published to all three nodes before this (edge-dev1: `BootstrapNode:true, JoinServerIP:10.244.244.2` i.e. itself; edge-dev2/3: `BootstrapNode:false, JoinServerIP:10.244.244.2` i.e. correctly pointing at edge-dev1) — so the config distribution worked, but kube-init's install path ignored/raced past it. Consistent with this, `getKubeNodeInfo` has logged `usesEtcd false` for edge-dev1 every 30s continuously since node creation at 23:42:15 through the current time (00:14+), over 30 minutes with no self-correction, which keeps each node's `NodeAdmission` pinned at `JOINING` forever (per `pkg/pillar/cmd/zedkube/kubestatscollect.go`, `NodeAdmissionJoined` requires the `node-role.kubernetes.io/etcd` label, which never gets set).

All three devices are running the exact same pinned pre-upgrade base image (`0.0.0-master-66475696`) as the `live-ledger.md` entry from run #20 (2026-11-16), which diagnosed this identical "kube-init bootstraps each node standalone despite correct zedkube cluster config" mechanism for `TestThreeNodesUpgrade`'s "become ready" timeout. Since the base image is pinned and hasn't been bumped since, this is the same known bug recurring one night later — not a new, independent failure. It is unrelated to this run's other investigated failure (`TestEVEUpgradeKubevirtToKubevirt`'s Longhorn CSI image-pull/iowait stall on a single-node cluster), which is a different mechanism.

No PR diff was provided for this investigation, so no relatedness assessment is given.

## [2026-11-17 -- 0.0.0-master-9c8800d2 (run #21)](https://github.com/lf-edge/eve/actions/runs/43965677211)

[Full report](https://lf-edge.github.io/eve/test/master/runs/21/)

### TestAppsSuite: failure analysis

#### TestAppOOMKillReported

##### Failure

```

Timed out after 120.001s.
the app's DomainMetric does not count the OOM kill
Expected
    <string>: 
not to be empty
```

##### Claude's conclusion

###### Root cause

The kernel-level fault injection worked exactly as intended: the app's own cgroup (`/sys/fs/cgroup/eve-user-apps/d53bede8-...1.1/memory.events`) shows `oom_kill 1`, and containerd's own `ctr tasks metrics --format json` against the same task reports `"memory_events": {"oom_kill": 1}` correctly via its gRPC Metrics API. However, the `DomainMetric` JSON that domainmgr publishes (`/run/domainmgr/DomainMetric/d53bede8-....json`) omits `OOMKills` entirely, even though the *same* metrics message's other fields (CPU usage, memory usage, memory limit) decoded correctly into it. This points to a decode bug introduced by today's `edc6ac72c` (`domainmgr: report OOM kills in application tasks`): pillar's `CtrGetContainerMetrics`/`decodeMetrics` in `pkg/pillar/containerd/containerd.go` unmarshals the task metrics via the vendored client library `github.com/containerd/containerd v1.7.36` + `github.com/containerd/cgroups/v3 v3.1.0`, while the live device actually runs `containerd v2.2.4` (confirmed via `eve exec containerd containerd --version`). The major client/server version skew is consistent with the `memory_events` submessage silently failing to decode into pillar's older vendored proto struct (while adjacent, unrelated fields like CPU/memory still happen to decode fine), which is why `dm.OOMKills` stays zero and the test's `t.Eventually` on the `DomainMetric`'s `OOMKills` field times out.

This is brand new code (all three commits — `edc6ac72c`, `19405512a`, `9f946f944` — landed in the last few days and this is the test's first-ever run), so it is not a known/recurring issue per `live-ledger.md` — I found no prior mention of `TestAppOOMKillReported` or this failure string in the ledger. It also shares no root cause with other entries in that ledger (those are unrelated: PNAC/802.1x cert rotation, coverage-build SIGUSR2/pprof issues, etc.).

### TestBootstrapSuite: failure analysis

#### TestBootstrapWithLastResortDisabled

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: failed to create VM 108 for device "sdn-5eb618b6": 500 can't lock file '/var/log/pve/tasks/.active.lock' - got timeout
```

##### Claude's conclusion

No Proxmox host shell access through evetest, only image staging — that matches the other ledger entries' observation that no direct `qm`/`pvesh` access exists from this sandbox. I have enough evidence to write the root-cause summary.

**Root cause:** This is a Proxmox broker-side infrastructure failure, not an EVE/pillar bug. `gotest.json` shows the EVE device VM (107) was provisioned fine at 22:42:55, but the SDN VM (108) failed at 22:43:31 with `500 can't lock file '/var/log/pve/tasks/.active.lock' - got timeout` — Proxmox's own task-log file lock, meaning pvedaemon couldn't even record a new task entry, a strong sign of host-level overload on the shared Proxmox broker ("farfalle"-class contention). Live checks confirm nothing further to inspect: `evetest status`/`evetest sdn status` report no EVE device and "SDN client is not initialized," consistent with teardown having already completed cleanly (`VM 108 of failed setup` removed, VM 107 removed) before I looked. This exact `/var/log/pve/tasks/.active.lock` signature doesn't appear anywhere in `live-ledger.md`, so it's a new manifestation, but it fits the same broad, well-documented recurring pattern of shared-Proxmox-host lock/API contention under concurrent VM lifecycle operations (`qmcreate`/storage locks, "no worker upid", truncated JSON responses, LVM "in use" races) that the ledger has recorded repeatedly since at least 2026-11-01. There is no PR diff provided for this run, so no relatedness judgment applies.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 2: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"8QG86XQA"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/newlog"}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"nbd0"}  storageList:{device:"vda"  total:65536}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd7"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/vault"}  storageList:{device:"nbd8"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/status"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{device:"nbd1"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/config"  total:5}  storageList:{mountPath:"/persist/clear"}  storageList:{mountPath:"/hostfs"  total:243}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{device:"nbd2"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/persist/log"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{device:"nbd15"}  storageList:{device:"nbd5"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/"  total:3960}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd4"}  storageList:{device:"nbd14"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  bootTime:{seconds:1794869337}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-master-9c8800d2-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"faa1b943-5288-48a2-8d56-b2d5a889245f"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-master-9c8800d2-kvm-amd64 at 2026-11-16T22:48:12.601680831Z\n"  lastRebootTime:{seconds:1794869292  nanos:762226304}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1794869634  nanos:17135029}  lastFailed:{seconds:1794869652  nanos:578417734}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1794869652  nanos:578252618}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"529352ca-3a44-488e-a0ea-c3c6b9e96f7d"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1794869634  nanos:17135029}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1794869535  nanos:888120881}  lastSucceeded:{seconds:1794869900  nanos:731670644}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-1\""  timestamp:{seconds:1794869902  nanos:8228954}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"529352ca-3a44-488e-a0ea-c3c6b9e96f7d"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1794869535  nanos:888120881}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-cycle-1\""  timestamp:{seconds:1794869902  nanos:8228791}  severity:SEVERITY_ERROR}}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1794869377  nanos:218135718}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xaf\xa6T\xa9A.\xa9\xc2\xdf\xe1A\xf4\x1c\xcf\xf7Uʏxh珥\xb3w\x80\xd1T\xda\xd38\x96"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

That background log-fetch task (exit 143 = killed by timeout, as expected since `eve logs -f` runs until cut off) already delivered the output I used — I read its interim results and incorporated them into the root-cause analysis above. No further action needed on it.
#### TestPNACWithProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"J4YJB1K5"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  storageList:{device:"nbd3"}  storageList:{device:"vda"  total:65536}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{device:"nbd5"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/"  total:3960}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/hostfs"  total:243}  storageList:{device:"nbd1"}  storageList:{device:"nbd0"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd4"}  storageList:{device:"nbd7"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/newlog"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/certs"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{device:"nbd8"}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{mountPath:"/persist/status"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/config"  total:5}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"nbd10"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{mountPath:"/persist/ingested"}  bootTime:{seconds:1794872466}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-master-9c8800d2-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"1ca0c123-0dc5-429c-8913-e2d535c1334e"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-master-9c8800d2-kvm-amd64 at 2026-11-16T23:40:22.173863871Z\n"  lastRebootTime:{seconds:1794872422  nanos:373302432}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1794872621  nanos:986642500}  lastFailed:{seconds:1794872641  nanos:764051835}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1794872641  nanos:763885209}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"5ec2672a-02d0-4dcf-81da-f0b839e86105"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1794872621  nanos:986642500}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1794872356  nanos:140307974}  lastSucceeded:{seconds:1794872890  nanos:487675198}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1794872892  nanos:301417786}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"5ec2672a-02d0-4dcf-81da-f0b839e86105"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1794872356  nanos:140307974}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1794872892  nanos:301417626}  severity:SEVERITY_ERROR}}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1794872506  nanos:166179906}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xaf\xa6T\xa9A.\xa9\xc2\xdf\xe1A\xf4\x1c\xcf\xf7Uʏxh珥\xb3w\x80\xd1T\xda\xd38\x96"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

Based on my investigation:

**Live evidence**: `evetest sdn ssh "tail ... /run/hostapd/bridge0.log"` shows the device (MAC `da:39:78:d0:19:f2`) completing EAP-TLS successfully (`CTRL-EVENT-EAP-SUCCESS`, `AP-STA-CONNECTED`), then immediately sending an `EAPOL-Logoff` and getting deauthorized, after which the next 802.1x attempt stalls at `IEEE 802.1X: Scheduled disconnection ... after EAP-Failure` — the client never completes re-authentication. Consistent with that, `evetest status` and `evetest eve ssh "ip addr"` show the device currently sitting on the pre-auth VLAN (172.20.10.123/24, VLAN 10 per `evetest sdn net-model`) with `pnac_status: {enabled:true, err:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""}` — PNAC is still enabled and the cert-enrollment/PNAC-disable cycle the test is waiting on never completes, matching the "cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN" timeout.

This is the exact same mechanism already documented in this run's `live-investigation.md` for `TestPNACWithoutProxy` ("cycle 2" failure, same 300s timeout, same stuck-re-auth hostapd signature) — this `TestPNACWithProxy` failure shares that root cause, just hitting it on a different cycle/variant. Per `live-ledger.md`, this 802.1x re-auth-after-SCEP-cert-rotation failure is a known, recurring issue going back to at least 2026-11-09 (run #12), also seen 2026-11-08, 2026-11-06, and 2026-11-13 for the proxy variant, and already logged twice tonight (run #20) for both `TestPNACWithoutProxy` and `TestPNACWithProxy`. This occurrence is a continuation/further manifestation of that same unfixed, recurring bug, not a new issue.

No PR diff was supplied for this investigation, so no RELATED line is given.
#### TestDNSFunctionality

##### Failure

```

Timed out after 120.002s.
The function passed to Eventually failed at /evetest/tests/networking/dns_test.go:414 with:
dnsmasq must have logged forwarding attempts for http-server1.test
Expected
    <[]evetest.LogMsg | len:0, cap:0>: nil
not to be empty
```

##### Claude's conclusion

That background command (an old diagnostic probe of `/dev/log`/`/proc` fds, superseded by the more targeted checks I ran afterward) was killed after hitting its time limit — no longer needed, since the actual root cause has already been identified from the newlog gzip evidence. No further action required.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This confirms the live deadlock exactly matches the ledger's long-recurring pattern — no PR diff was given, so no RELATED line is needed. I have enough evidence to write the root cause now.

**Root cause:** Live inspection on edge-dev2 (the node the app `failover-purge-app`/`179d6907-d0d2-4f7d-9226-52a8ef48edf7` failed over to after edge-dev1 was powered off) shows `kubectl get vmirs,vmi,vm -A` returning zero objects cluster-wide — exactly matching the test's `found []`. Pillar logs confirm the mechanism: zedmanager is permanently stuck looping `getKubeAppActivateStatus(...): not designated, node ..., onTheDevice false, statusRunning false` → `publishAppInstanceStatus(...) suppressed: IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, unbroken from the purge at 01:37:17 through the moment of investigation (01:53+). Since the purge deleted the old-generation VMIRS and the test deliberately pins `dnidOutageThresholdKey` to 2 hours (so no peer ever becomes an eligible backup DNID while the designated node edge-dev1 stays powered off), no node is ever allowed to re-request a new VMIRS, and the system deadlocks exactly as `pkg/pillar/cmd/zedmanager/zedmanager.go:2027-2059`'s activation gate is designed to do for this scenario.

This is a known, long-recurring issue per `live-ledger.md`: the identical `getKubeAppActivateStatus`/designated-node activation-gate deadlock for this exact test has been recorded repeatedly since the test's introduction in commit `98acf1411` (2026-10-18), with the first ledger entry dated **2026-10-29**, and recurring in essentially every nightly run since (most recently run #18 on 2026-11-15, the night before this one). It does not share a root cause with other failures in this run (e.g. the `TestDNIDandBackupDNID` / `TestClusterPVCGCDeletesOnlyOrphans` leader-election or Longhorn tie-breaker issues) — this is a continuation of the same unbroken, well-documented streak rather than a new bug.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
timed out after 10m0.000980439s (excluding download) waiting for app "47445576-e074-48f5-b7a9-cc7e4b66404c" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

###### Root cause

Live evidence on `edge-dev` shows severe host I/O contention: `top` shows 43.5% iowait with load average ~4.7–5.1 on a 4-vCPU box 23 minutes after boot, and `/proc/pressure/io` shows `full avg300=37.86` — i.e., for the last 5 minutes, all processes were completely stalled on I/O over a third of the time. This is cascading through the storage/CDI pipeline: the app's PVC provisioning, CDI scratch-volume creation, and CDI upload-server image pull took ~2 minutes by themselves, the Longhorn volume went `Degraded` right after attach, and many unrelated pods across `kubevirt`, `cdi`, and `longhorn-system` namespaces show correlated restarts ~4 minutes ago (consistent with liveness/readiness probe timeouts under the same I/O pressure). The net effect is that `upgrade-test-app`'s VMI only transitioned to `BOOTING` at 23:53:14, essentially at the very end of the test's 10-minute window — it simply never got the chance to reach `RUNNING` in time because the preceding volume-provisioning steps consumed almost the entire budget.

This matches the broad "shared host storage-contention/iowait stalling K3s/Longhorn/CDI work past fixed test timeouts" pattern that `live-ledger.md` documents as a known, recurring infra flake going back to **2026-10-29**, and specifically recurs for this exact test (`TestEVEUpgradeKubevirtToKubevirt`) in runs #7, #8, #10, #14, and #17. This is a fresh instance of that same long-standing infra pattern, not a new bug and not an EVE/pillar code regression. No PR diff was supplied for this investigation, so no code-relatedness assessment is given.
#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes [edge-dev1 edge-dev2 edge-dev3] to become ready in cluster "test-cluster" (device "edge-dev3")
```

##### Claude's conclusion

###### Root cause

All three devices are up and individually healthy, but `kubectl get nodes` on each of `edge-dev1`/`edge-dev2`/`edge-dev3` shows **only itself** — each node is running as a standalone single-node k3s/etcd cluster rather than having joined the others, and zedkube's `ClusterStatus` confirms all three are stuck at `NODE_ADMISSION_JOINING` (never reaching `JOINED`/`ADMITTED`). Live `top`/`/proc/pressure/io` on all three nodes shows severe, host-wide storage starvation throughout the test window: load averages of 5–8 on 4-vCPU boxes, 28–46% iowait, and `/proc/pressure/io` `full avg300` of 64–72% (i.e. most processes stalled on I/O for the majority of the last 5 minutes) on every node, not just one. `/persist/kubelog/k3s.log` corroborates this with the etcd/kine datastore grinding (`INSERT INTO kine` taking 1–20s repeatedly), apiserver `http: Handler timeout` errors, and lease-update failures — the same class of symptom that prevents cluster bootstrap/join handshakes from completing within the test's 30‑minute window (config was applied at 00:03:54, timeout fired exactly 30 minutes later at 00:33:54, consistent with the join simply never making progress rather than any single event).

This is the same underlying mechanism as the `TestEVEUpgradeKubevirtToKubevirt` failure already investigated earlier in this same run (`live-investigation.md`): shared host I/O contention stalling k3s/etcd/Longhorn/CDI work past fixed test timeouts — here it's just severe enough to block cluster *formation* itself rather than only app scheduling. Per `live-ledger.md`, this broad "host storage/iowait contention" pattern is extensively documented as a known, recurring infra flake dating back to at least **2026-10-29**, and it specifically recurs for `TestThreeNodesUpgrade`'s "cluster nodes... become ready" failure signature across many prior nightly runs (e.g. entries at runs around 2026-10-30, 2026-11-01, 2026-11-07/08, and others) — though with varying specific mechanisms each time (not-authorized rejoin, CNI/flannel mismatch, Longhorn node-deletion race, Proxmox installer timeouts). Tonight's specific manifestation (nodes never even attempting/completing the join, each running standalone, under confirmed host-wide I/O pressure) most closely matches the etcd/kine-overload variant seen elsewhere in the ledger (e.g. the "leader is overloaded likely from slow disk" 3-node cluster instability entry), so this is a continuation of the long-standing recurring infra flake, not a new or EVE/pillar-side code regression.

## [2026-11-16 -- 0.0.0-master-0d32dd65 (run #20)](https://github.com/lf-edge/eve/actions/runs/43766754157)

[Full report](https://lf-edge.github.io/eve/test/master/runs/20/)

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 600.001s.
Expected to satisfy: Device has enrolled NEW certificate for 802.1x AND deleted the obsolete certificate
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7917  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"JJ59NCWA"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  bootTime:{seconds:1794783587}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-pr43766754157-0d32dd65-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"c58c7097-1d2f-4e4b-8d11-dbd1e4b8041e"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-pr43766754157-0d32dd65-kvm-amd64 at 2026-11-15T22:59:04.714046193Z\n"  lastRebootTime:{seconds:1794783544  nanos:706769369}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1794783477  nanos:324301406}  lastSucceeded:{seconds:1794783624  nanos:718554216}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1794783624  nanos:718486119}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"ca7dafa0-64c0-47ca-b5a4-6e30cc5edfbf"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1794783477  nanos:324301406}}  pnac_status:{enabled:true  state:SUPPLICANT_STATE_CONNECTING}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1794783622  nanos:694301337}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"ư\xb5'q\x0c|\x16\xaa\xad\xff\x9a\x895I\xb7\xa4\xb8^u\xe1\xfd\xa8;\xdf\x1e0Q\xe2\xeb\x8ev"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_NONCE_WAIT  error:{description:"[ATTEST] Error All attempts to connect to adam.evetest:443/api/v2/edgedevice/id/c58c7097-1d2f-4e4b-8d11-dbd1e4b8041e/attest failed: interface eth0: no suitable IP address available, senderStatus SenderStatusNone"  timestamp:{seconds:1794783633  nanos:622796701}  severity:SEVERITY_ERROR}}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"  enrolled_certs:{cert_enrollment_profile_name:"scep-test"  subject:{common_name:"edge-dev"  organization:"lf-edge"  country:"US"}  issuer:{common_name:"SCEP CA"  organization:"Example"  organizational_unit:"Lab"  country:"US"}  san_uri:"urn:Name:edge-dev"  issue_timestamp:{seconds:1794782885}  expiration_timestamp:{seconds:1826319485}  renew_period_percent:50  sha256_fingerprint:"27b81ba94832770fc803bf15590f7027bf3f82928816afc46a34066177ca891a"  status:CERT_STATUS_AVAILABLE}
```

##### Claude's conclusion

###### Root cause

Live evidence on the SDN's hostapd (`/run/hostapd/bridge0.log`) shows the device completed EAP-TLS successfully once right after its SCEP-profile-swap-triggered reboot (`CTRL-EVENT-EAP-SUCCESS`, `AP-STA-CONNECTED` for MAC `da:39:78:d0:19:f2`), but the device itself then sent an `EAPOL-Logoff`, the port was deauthorized, and a fresh 802.1X attempt began — only to hit `IEEE 802.1X: Scheduled disconnection ... after EAP-Failure` before the client ever answered the new EAP-Identity request. No further EAPOL activity from that MAC has been logged since (file mtime is current, but the only new entries are from my own diagnostic `hostapd_cli` queries). Consistent with that, `evetest eve ssh`/`sdn ssh ip neigh` show the device has no reachable IP on either the pre-auth or authenticated VLAN, and `evetest status` reports `pnac_status: SUPPLICANT_STATE_CONNECTING` with `EVE_DEVICE_STATE_SUSPECT` — the device is permanently stuck pre-auth, unable to complete 802.1x re-authentication after the SCEP cert-rotation reboot, exactly matching the "enrolled NEW cert AND deleted obsolete" timeout.

This is a known, recurring issue, not a new one: the live-ledger records the identical mechanism (802.1x re-auth failing to recover after a SCEP-profile-swap-induced reboot) for `TestPNACWithoutProxy` on 2026-11-09 (run #12) and for the proxy variant `TestPNACWithProxy` on 2026-11-13 (run #16) — tonight's failure is this same test (`TestPNACWithoutProxy`) reproducing the identical signature again, so this bug has been recurring since at least 2026-11-09. Recent master commits (watchdog bump, fw-list tooling, kube-init manifest staging) don't touch nim/wpa_supplicant/pnac code paths, so nothing in this run's own history looks related to the failure either. No PR diff was supplied for this investigation, so no RELATED line is given.
#### TestPNACWithProxy

##### Failure

```

Timed out after 600.000s.
Expected to satisfy: Device has enrolled NEW certificate for 802.1x AND deleted the obsolete certificate
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7917  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"Z9HGN4FZ"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  bootTime:{seconds:1794784704}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-pr43766754157-0d32dd65-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"d457bbef-f4f3-4d54-b6b1-1995665905ae"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-pr43766754157-0d32dd65-kvm-amd64 at 2026-11-15T23:17:42.12836116Z\n"  lastRebootTime:{seconds:1794784662  nanos:121875563}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1794784578  nanos:529815172}  lastSucceeded:{seconds:1794784735  nanos:218540265}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-test\""  timestamp:{seconds:1794784734  nanos:299298191}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"6465376c-4a77-4c5d-a0ff-3bb55e22d77b"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1794784578  nanos:529815172}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"scep-test\""  timestamp:{seconds:1794784734  nanos:299297806}  severity:SEVERITY_ERROR}}}}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1794784732  nanos:959688395}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"ư\xb5'q\x0c|\x16\xaa\xad\xff\x9a\x895I\xb7\xa4\xb8^u\xe1\xfd\xa8;\xdf\x1e0Q\xe2\xeb\x8ev"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_NONCE_WAIT  error:{description:"[ATTEST] Error All attempts to connect to adam.evetest:443/api/v2/edgedevice/id/d457bbef-f4f3-4d54-b6b1-1995665905ae/attest failed: interface eth0: no suitable IP address available, senderStatus SenderStatusNone"  timestamp:{seconds:1794784745  nanos:245507599}  severity:SEVERITY_ERROR}}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"  enrolled_certs:{cert_enrollment_profile_name:"scep-test"  subject:{common_name:"edge-dev"  organization:"lf-edge"  country:"US"}  issuer:{common_name:"SCEP CA"  organization:"Example"  organizational_unit:"Lab"  country:"US"}  san_uri:"urn:Name:edge-dev"  issue_timestamp:{seconds:1794784013}  expiration_timestamp:{seconds:1826320613}  renew_period_percent:50  sha256_fingerprint:"fb123cad9ee7c63533c8b3a923f66fe3d06f3992c9ccb5fd8c2b9f5015857963"  status:CERT_STATUS_AVAILABLE}
```

##### Claude's conclusion

###### Root cause

Live SDN evidence shows the identical mechanism already diagnosed earlier tonight for `TestPNACWithoutProxy` in this same run: `/run/hostapd/bridge0.log` shows the device (MAC `da:39:78:d0:19:f2`) completing EAP-TLS successfully (`CTRL-EVENT-EAP-SUCCESS`, `AP-STA-CONNECTED`) right after its post-SCEP-swap reboot, then immediately sending an `EAPOL-Logoff`, getting deauthorized, and the subsequent 802.1x re-authentication attempt stalling at `IEEE 802.1X: Scheduled disconnection ... after EAP-Failure` before the device answers the new EAP-Identity request — leaving the port permanently unauthorized. Consistent with that, `evetest status` shows the device stuck in `EVE_DEVICE_STATE_SUSPECT` with `pnac_status.err: "No certificate enrollment status found for SCEP profile \"scep-test\""`, and `evetest eve ssh` can only reach the pre-auth VLAN IP (172.20.20.123), confirming the device never reached the post-auth network to report enrollment/attestation.

This is the same root cause as the `TestPNACWithoutProxy` failure already investigated earlier in this run (recorded in `live-investigation.md`) — same signature, same mechanism, just the proxy variant. Per `live-ledger.md`, this exact issue (802.1x re-auth failing to recover after a SCEP-profile-swap-induced reboot) is known and recurring: it hit `TestPNACWithoutProxy` on 2026-11-09 (run #12) and `TestPNACWithProxy` on 2026-11-13 (run #16) — tonight's pair of failures (both variants in the same run) extends that same recurring, unfixed issue. No PR diff was supplied, so no RELATED line is given.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 30m0.007166057s (excluding download) waiting for app "6658067b-a517-41a3-a535-758f099016af" (vm1) on device "edge-dev1" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

No other failures recorded in this run so far (only this single test), so there's nothing else in-run to compare against.

###### Root cause

`vm1`'s CDI-upload pod (`cdi-upload-ab6c1b6b-...-pvc-0`) has been stuck in `ContainerCreating` on `edge-dev3` the entire 30-minute window, with `kubectl describe pod` showing repeated `FailedAttachVolume: ... volume ... is not ready for workloads`. The two backing Longhorn volumes (`pvc-c8686175...`, `pvc-cb086c88...`) are permanently `robustness: faulted` / `state: detached`. `longhorn-manager`'s own log pinpoints why: at `23:18:40-41`, right as the volume's two replica engine processes were first started on `edge-dev1`/`edge-dev3`, they immediately crashed with `exec: "/host/var/lib/longhorn/engine-binaries/longhornio-longhorn-engine-v1.9.1/longhorn": stat ...: no such file or directory` — the `engine-image` DaemonSet pod that copies that binary onto the host hadn't finished yet (the binary directory wasn't actually populated until `23:19`, confirmed live via `ctr ... exec kube ls`). Longhorn tore down the crashed replica instances and never retried starting them once the binary became available, so the volumes have sat faulted/detached (0 running replicas) for the full 31+ minutes I observed live, wedging the CDI import and leaving `vm1`'s `AppInstanceStatus`/`VolumeStatus` parked at `State:109` (`CREATING_VOLUME`) forever — exactly matching the test's timeout.

This is a new failure signature: I grepped `live-ledger.md` for `engine-binaries`, `robustness: faulted`, and `state: detached` and found no prior hits, so it isn't the known recurring DNID/backup-DNID leader-election or designated-node bugs that have previously caused this same test to fail (those left apps stuck in `BOOTING`, not `CREATING_VOLUME`), nor any of the several previously-seen `CREATING_VOLUME` mechanisms in the ledger (tie-breaker-node Longhorn exclusion, CDI-uploadproxy 503s, stale `.img` files) — here Longhorn is correctly running only on the two non-tie-breaker nodes, and the actual defect is a one-time startup race between replica-engine creation and engine-image binary installation that Longhorn never recovers from. No other test failed earlier in tonight's run to compare against, and no PR diff was supplied for a code-relatedness judgment.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This confirms it: same signature, same root cause, recurring every night since 2026-10-29 through at least 2026-11-15 (yesterday's run #18).

###### Root cause

This is the same known deadlock that has recurred nightly in `TestVMAppPurgeDuringFailover` since **2026-10-29** (first seen run #1), reproducing in essentially every nightly run through 2026-11-15 (run #18) — not a new bug. Live inspection on edge-dev2 (the node the app failed over to) confirms it again: `kubectl get vmirs,vmi,vm -A` returns zero objects cluster-wide, matching the test's `found []`.

Pillar logs on edge-dev2 pinpoint the mechanism exactly as in every prior occurrence: the purge (`handleModify ... needPurge: true` at 00:39:41) correctly tore down the old-generation VMIRS/VMI (`domainmgr: "kubevirt: Purge 0->1 Restart 0->0; tearing down old VMIRS"` at 00:40:27, `zedmanager: purgeCmdDone` at 00:41:45), but zedmanager then gets permanently stuck repeating `getKubeAppActivateStatus(...): not designated, node ..., onTheDevice false, statusRunning false` → `effectiveActivateCombined: ... combined false` → `Waiting for config.Activate`, for the remaining ~13 minutes until the 900s `Eventually` timeout. Per `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2027`), a non-designated node only activates a kube app if Kubernetes has already placed it there or this node is an eligible backup DNID — but the test deliberately pins `dnidOutageThresholdKey` to 2 hours so no backup DNID ever kicks in, and once the old VMIRS is deleted nothing is placed anywhere. Only the designated node (edge-dev1, powered off the whole test) can unconditionally originate a fresh VMIRS — a chicken-and-egg deadlock, exactly what the test's own doc comment warns this scenario is designed to catch.

This failure is standalone within this run (no shared root cause with the earlier `TestDNIDandBackupDNID` CDI/Longhorn-engine-binary-race failure recorded in this run's `live-investigation.md`) — it's the same pre-existing, still-unfixed zedmanager/zedkube activation-gate bug, not something introduced since last night.

### TestNodeClusterSuite: failure analysis

#### TestAppInstancePurge

##### Failure

```
timed out after 10m0.025457299s (excluding download) waiting for app "714e7193-047a-485c-aa52-c127f75732c5" (purge-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Confirmed: the volume is permanently stuck, with no further retry of the copy-image step, and `gcVolumes` now flags the leftover `.img` as "found unknown format volume" — exactly the stale-file signature from the 2026-11-05 ledger entry. I have everything needed for the conclusion.

**Root cause:** `purge-app`'s volume (`d93b9f64-...`) got permanently stuck in `CREATING_VOLUME` because of a reboot racing a successful-but-unflushed volume-creation step on the single-node `edge-dev`. Live `volumemgr` logs show `copy-image-to-qcow.sh` ran successfully at 02:15:11, writing `/persist/vault/volumes/d93b9f64-...-pvc-0.img` (confirmed on disk, timestamped 02:15). At 02:17:41 the watchdog detected `zedkube` hung (`BootReasonWatchdogHung: 250 /run/zedkube.touch`), triggering a reboot at ~02:21, which in turn caused a second reboot (`BootReasonKubeTransition, Transition from cluster mode to single node`) at 02:22:18. When volumemgr restarted afterward, it re-ran `copy-image-to-qcow.sh` for the same volume at 02:23:45, but the `.img` file from the pre-reboot run was still present and the script doesn't handle this idempotently: `CopyImgDirToRawImg: Failed to create raw image file ... /persist/vault/volumes/d93b9f64-...-pvc-0.img already exists`. This error isn't recognized as a transient/retriable failure, so no further attempt was ever logged, and the app sat in `CREATING_VOLUME` until the test's 10-minute timeout — `gcVolumes` is now logging the leftover file as a "found unknown format volume."

This is a known, recurring issue: the ledger documents the identical `TestAppInstancePurge` signature and exact error text (`CopyImgDirToRawImg: Failed to create raw image file ... pvc-0.img already exists`, same "non-retriable stale `.img` file" mechanism) on **2026-11-05 (run #8)**. That occurrence was triggered by a self-cordon/CoreDNS outage interrupting the first attempt; tonight's trigger was instead a watchdog-hang reboot interrupting a (this time actually-successful) first attempt — different proximate trigger, but the same underlying unfixed gap: volumemgr's copy-image-to-qcow retry path doesn't clean up or tolerate a pre-existing raw-image file left over from before a reboot/restart.
#### TestTwoNodeHACluster

##### Failure

```
Timed out waiting for app "6bbbbb53-1007-4134-9de2-7b2809f7702b" to be scheduled in cluster "test-two-node-ha-cluster"
```

##### Claude's conclusion

**Root cause:** `container-app`'s volume (`fa9bcaef-...`) is stuck in `CREATING_VOLUME` on `edge-dev2` not because of a bug, but because the host is severely I/O-starved: live `top` shows 35.6% iowait with a load average of 7.3-7.7 on an 8-vCPU box, and the `copy-image-to-qcow.sh`/`rsync` process (PID 32675, running since 03:59) is still actively making forward progress — the output `.img` grew from 49,152,000 to 50,921,472 bytes in 30 seconds (~59 KB/s) — but at that rate converting the ~149 MB container rootfs takes well over 10 minutes, blowing past the test's scheduling timeout. `gcVolumes`'s "found unknown format volume" log at 04:05:42 is simply it scanning the partially-written `.img` mid-copy, not a stuck/corrupted file as seen in the other failure.

This does **not** share the same mechanism as this run's other already-investigated failure (`TestAppInstancePurge`): that one was a permanently-stuck, non-retriable stale `.img` file left over from a reboot race (copy script never even restarted); here the copy script is alive and still progressing, just pathologically slow due to host I/O contention.

This is, however, a known and extensively recurring issue per `live-ledger.md`: host storage/iowait contention stalling cluster/volume/control-plane work past fixed test timeouts is documented repeatedly going back to **2026-10-29**, recurring across many different tests and mechanisms (e.g. `TestEVEUpgradeKubevirtToKubevirt` runs #7/#8/#10, `TestApplicationGateway`, `TestSwitchNIPortConfigRace`, and a near-identical "app never scheduled" case for `mgmtproxy-test-cluster` caused by etcd/k3s overload from slow disk). Tonight's occurrence is a fresh instance of that same broad infra-contention pattern, not a pillar/EVE code regression — no PR diff was supplied for this investigation, so no code-relatedness assessment is given.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
timed out after 10m0.01458948s (excluding download) waiting for app "b581c25f-837b-4983-ae05-6bab706d1b92" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: HALTING)
```

##### Claude's conclusion

###### Root cause

The app got stuck because of a **post-reboot race between domainmgr's VMIRS creation and the kubevirt control-plane coming back up**, compounded by a slow boot-retry backoff. Live `app-info` for `b581c25f-...` shows: after the device rebooted for the upgrade, the app went `BOOTING` again at 23:53:08, then 50s later hit a hard error — `failed calling webhook "virtualmachinereplicaset-validator.kubevirt.io": ... dial tcp 10.43.234.128:443: connect: connection refused` — because `virt-api` (and the rest of the kubevirt/k3s control plane) hadn't finished restarting yet after the node reboot (all kubevirt/longhorn/cdi pods show `Running 1-2 (11m ago)`, i.e. restarted around the same time). This left the app wedged in `HALTING` with **no VMIRS/VMI object ever created** (`kubectl get vmirs,vmi -A` → `No resources found`), so it could never reach RUNNING. Live device logs show `domainmgr`'s `maybeRetryBoot` only cleared that error and retried roughly **10 minutes later** (at 00:04:07, right as I was investigating) — almost exactly matching, and exceeding, the test's fixed 10-minute wait window, so the retry came too late to save the test.

This is a new specific failure signature (no "virtualmachinereplicaset-validator"/webhook-connection-refused hits anywhere in `live-ledger.md`), so it's not a repeat of this test's previously recorded iowait/storage-contention or squashfs-corruption failures (runs #7, #8, #10, #16, #17). However, it is the same *class* of bug already recorded for a different test on 2026-11-14: `TestHardwareSuite`/`TestUSBFlashDriveHotplug`'s `usb-flash` app, where domainmgr's boot-retry backoff (~10 minutes) also didn't fire fast enough after a transient post-launch glitch, causing the test's 10-minute wait to expire moments before the retry would have succeeded. So this looks like a recurring structural gap (retry backoff tuned longer than the fixed test timeout) manifesting in a new place — a post-upgrade-reboot kubevirt-control-plane race — rather than a brand-new independent bug.

No PR diff was supplied for this investigation, so no relatedness assessment is given.
#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes [edge-dev1 edge-dev2 edge-dev3] to become ready in cluster "test-cluster" (device "edge-dev1")
```

##### Claude's conclusion

This confirms the devices are now actively mid-transition into real cluster mode (self-correcting, long after the test gave up). I have enough evidence for a root-cause conclusion.

###### Root cause

All three devices are running the pre-upgrade base image `0.0.0-master-66475696`, whose legacy (pre-Go-rewrite) kube-init install script logged **`Single node mode prepare config.yaml`** for every node at boot (~00:11:50-53), i.e. it decided to bootstrap each of edge-dev1/2/3 as its own independent single-node k3s cluster with a local SQLite/kine datastore, even though zedkube had already published a correct `EdgeNodeClusterStatus` (right `JoinServerIP`/`BootstrapNode` values) before k3s was even installed. Live evidence: `kubectl get nodes` on each device shows only itself; the running k3s process's own log says `To join server node to cluster: k3s server -s https://<own-IP>:6443`; and its `/etc/rancher/k3s/config.yaml.d/` only contains `00-nodename.yaml` (no cluster/join drop-in). All three nodes only discovered the mismatch and began the real join (`EdgeNodeClusterStatus file found, but the node does not have edge-node-cluster-mode` → `provision config file for node to cluster mode`) at 00:46:51–00:49:23 — roughly **35–37 minutes after boot**, far past the harness's 30-minute readiness wait that started at 00:11:45, so the test necessarily timed out (confirmed still converging live, well after the failure was reported).

This is a distinct, previously-unseen mechanism: it is not the same root cause as this run's other investigated failure (`TestEVEUpgradeKubevirtToKubevirt`'s post-reboot kubevirt-webhook race), nor the same as the ledger's prior `TestThreeNodesUpgrade` "cluster nodes... become ready" entries (2026-11-07/08), which involved nodes that **did** join successfully but then hit a CNI/flannel-subnet mismatch leaving Longhorn `DEGRADED`. Here the nodes never joined each other at all for over half an hour. No matching signature ("Single node mode prepare", "does not have edge-node-cluster-mode") appears anywhere in `live-ledger.md`, so this is a new, not previously-known/recurring issue. The buggy code path is in the legacy bash-based kube-init install script baked into the pinned base image (commit `664756969`), which predates and is superseded by the newer Go-rewritten `pkg/kube/kube-init` (with its `waitForBootstrapServer` join-handshake specifically designed to avoid this race) — so this failure occurred entirely before the test ever reached the "upgrade to the PR version" step, and is unrelated to the current PR under test.

## [2026-11-15 -- 0.0.0-master-368a44a3 (run #18)](https://github.com/lf-edge/eve/actions/runs/43645720578)

[Full report](https://lf-edge.github.io/eve/test/master/runs/18/)

### TestAppRoutingSuite: failure analysis

#### TestApplicationGateway

##### Failure

```

Told to stop trying after 2.674s.
Stop waiting for: ni-eth0 is ONLINE
Network instance is in error state
networkID:"dde0e918-3455-4f49-94d8-ece5659c1237"  networkVersion:"1"  instType:2  displayname:"ni-eth0"  bridgeNum:1  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:63:82:01"  ipAddress:"10.50.0.1"}  networkErr:{description:"failed to select ports for network instance dde0e918-3455-4f49-94d8-ece5659c1237: no port is matching label 'ethernet0'"  timestamp:{seconds:1794695280  nanos:625484280}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500
```

##### Claude's conclusion

###### Root cause

Live evidence confirms this was a transient boot-time race, not a persistent problem: `evetest eve ni-info ni-eth0 -t=5` shows `ni-eth0` going `INIT` → `ERROR` (`no port is matching label 'ethernet0'`, at 22:28:00.625) → `ONLINE` (with `ethernet0` correctly assigned) a few seconds later, and it remains healthy now. The device's `DevicePortConfigList` shows why: the controller-sourced DPC (key `zedagent`, carrying the `ethernet0`/`ethernet1` logical labels the app's network instance requires) was submitted at 22:27:52.799 but was still in `DPC_ASYNC_WAIT` (being connectivity-tested) when zedrouter first processed the NI config moments later, so no port yet carried the `ethernet0` label in zedrouter's view, causing the brief error. zedrouter's own log shows the fix-up completing normally — `PortProber: Added ethernet0 to list of probed ports` and `Updated activated network instance ... (ni-eth0)` at 22:28:07.059/07.282, i.e. convergence took roughly 7-10 seconds after the device's full config landed. The test's `evetest status` reports giving up after only `2.674s` ("Told to stop trying after 2.674s"), which is shorter than this normal post-onboarding DPC-switch window, so the failure looks like the test's wait/retry budget being too tight for the expected boot-time DPC convergence rather than a real networking defect.

This is a new failure signature — I grepped `live-ledger.md` for "no port is matching", "ZNETINST_STATE_ERROR", and "ni-eth0" and found no prior occurrences, so it's not a known/recurring issue, and it doesn't share a root cause with any other failure noted in this run. The recent commit history on master (watchdog bump, kube-init manifest re-staging, nvidia udev rule fix, fw-list tooling) has nothing touching zedrouter/nim/dpcmanager, consistent with this being an environment/timing flake rather than a code regression.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 30m0.008637124s (excluding download) waiting for app "fafb1261-ead8-4080-9f18-02f38780d829" (vm1) on device "edge-dev1" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

Only one prior occurrence found, from the 2026-10-31 run (#3). This is now the second time this exact signature has appeared, ~2 weeks apart.

**Root cause:** `vm1` (app `fafb1261-...`, DNID = edge-dev1) is stuck reporting `BOOTING` because the VMI was actually scheduled onto `edge-dev3` instead of its designated node. Live logs confirm: `kubevirtContext.vmiScheduledOnMeFromVmirs` logs `vmi vm1-fafb1-0wbnnq scheduled on "edge-dev3" onMe:false elsewhereReady:true`, and `kubevirtTask.Info()` (`pkg/pillar/hypervisor/kubevirt.go:1800`) then logs `"vm1-fafb1-0 scheduled on a different node"` and returns `UNKNOWN` instead of `RUNNING` by design. `zedkube`'s `ENClusterAppStatus` on edge-dev1 shows `IsDNidNode:true ScheduledOnThisNode:false AppKubeStatus:RunningState` — the pod is genuinely healthy and ready on edge-dev3 (`getAppVMIInfo` shows `phase Running ... nodeName edge-dev3 ready true`) — but zedmanager never derives `RUNNING` for the DNID node's `AppInstanceStatus` from that cluster-wide view when `ScheduledOnThisNode` is false, leaving it permanently wedged at `BOOTING` (confirmed: `AppInstanceStatus`/`DomainStatus` both still show `State:114`=BOOTING, matching the 30-minute timeout almost exactly, `StartTime 00:23:46` vs. failure at `01:00:28`).

This is the exact same root cause and code path (VMIRS using only a *preferred*, not required, node affinity toward the DNID, so the KubeVirt scheduler is free to place the VMI elsewhere even with no node outage) as a `TestDNIDandBackupDNID` failure already recorded in `live-ledger.md` for 2026-10-31 (run #3) — a gap in zedmanager/zedkube's backup-DNID status-reporting path that only handles failover-driven node moves, not ordinary scheduler placement decisions. That entry noted it wasn't yet a "recorded recurring" issue at the time; tonight is the second occurrence of the identical signature roughly two weeks later, so this is now a confirmed recurring (if infrequent) bug in the DNID/backup-DNID status-propagation gap, not a new one. No other failing tests appear in tonight's run so far, so there's nothing else in this run to compare root causes against.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This confirms the live loop: zedmanager perpetually logs `getKubeAppActivateStatus(...): not designated, node c48050f2 (edge-dev3), onTheDevice false` and never issues the activate that would create the new-generation VMIRS. I have enough evidence to write the conclusion.

**Root cause:** This is the same long-recurring `TestVMAppPurgeDuringFailover` deadlock already recorded in the ledger (first seen 2026-10-29, recurring in nearly every nightly run since, including last night). Live evidence on edge-dev3 is identical to the pattern: after the DNID node (edge-dev1) was powered off and the app failed over, the purge deleted the old-generation VMIRS (`kubectl get vmirs,vmi -A` now returns zero resources), and zedmanager is stuck looping `getKubeAppActivateStatus(999e6655-...): not designated, node c48050f2..., onTheDevice false` forever — `AppInstanceStatus.IsDesignatedNodeID:false`, `ScheduledOnThisNode:false` in `ENClusterAppStatus`, so nothing ever re-requests a new VMIRS from domainmgr/zedkube. I confirmed this is *not* the same bug as this run's earlier `TestDNIDandBackupDNID`/`TestClusterPVCGCDeletesOnlyOrphans` failures (the zedkube `IsAppOpLeader`-stuck-false leader-election race): here leader election converged correctly, with `edge-dev3`'s `KubeLeaderElectInfo` showing `IsAppOpLeader:true` matching the real `AppOpLeaderIdentity`. This is the distinct, known designated-node/backup-DNID activation-gate bug that has been reproducing nightly since 2026-10-29.

## [2026-11-14 -- 0.0.0-master-368a44a3 (run #17)](https://github.com/lf-edge/eve/actions/runs/43515550867)

[Full report](https://lf-edge.github.io/eve/test/master/runs/17/)

### TestAppsSuite: failure analysis

#### TestAppUserData

##### Failure

```
timed out after 10m0.002241012s (excluding download) waiting for app "27ca0dc6-c1a6-4627-b030-50dd42c95124" (userdata-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

I have enough to explain the failure confidently.

###### Root cause

`userdata-app` got permanently stuck in `CREATING_VOLUME` because of a **shared-image-layer GC race in volumemgr/containerd CAS**, not a new/unrelated infra issue:

- At `23:22:26-23:22:34`, the *previous* suite test's app (`TestAppInstanceMetadata`, content tree `30089a66-...`, same image `lfedge/evetest-ubuntu-ctr:1.0`) was torn down. Its shared image blobs — including manifest `333e5cba9272...` — had their refcounts dropped to 0 and were unpublished/GC'd from containerd (`RemoveRefFromBlobStatus: unpublishing Blob ... since no object is referring it`).
- At `23:23:10`, `TestAppUserData`'s new content tree (`5a199bab-...`) was created referencing that *same* image, and volumemgr immediately latched onto the already-known manifest hash `333e5cba...` rather than re-downloading it, since it looked cached.
- At `23:23:24.919`, when `domainmgr`/CAS actually tried to materialize the container rootfs (`PrepareContainerRootDir`), it failed: `Could not create snapshot ... parent snapshot sha256:ce39511f... does not exist: not found` — one of that image's underlying layer snapshots had already been garbage-collected by the prior app's teardown before the new app's volume creation ran. `volumemgr` set this as a permanent error on the volume/app (confirmed live: the device's containerd `eve-user-apps` namespace currently has zero images/snapshots/content, and `/persist/vault/verifier` and `/persist/vault/volumes` are empty), so the app never left `CREATING_VOLUME` and the 10-minute wait timed out.

This doesn't share a root cause with any earlier failure in this run (no other subtests in this suite have failed yet). It isn't an exact repeat of anything in the 16-run ledger (no prior entry mentions `PrepareContainerRootDir`/"parent snapshot ... not found"), but it is the same *class* of bug as a ledger entry from 2026-11-06 (run #9, `TestPurgeNeverActivatedApp`'s stalled-download issue), where a reused/cached CAS blob from a prior test's image wasn't properly re-validated before being handed to a new app — i.e., volumemgr's shared-image-blob reuse logic racing against teardown/GC of that same image appears to be a recurring weak spot across nightly runs, even though this specific manifestation (snapshot-not-found at container creation) is new to the ledger.

### TestBootstrapSuite: failure analysis

#### TestBootstrapWithInstaller

##### Failure

```
BuildImage "lfedge/eve:0.0.0-master-368a44a3-kvm-amd64" failed: rpc error: code = Unknown desc = failed to build EVE image for device "edge-dev": expected EVE image file "/root/.evetest/images/templates/.tmp-cc0ae86c2c6ed8b07af04bc300f9d9a9-825140533/installer.raw.qcow2" not found: stat /root/.evetest/images/templates/.tmp-cc0ae86c2c6ed8b07af04bc300f9d9a9-825140533/installer.raw.qcow2: no such file or directory
```

##### Claude's conclusion

###### Root cause

The failure is a disk-space exhaustion on the evetest broker host, not a device/SDN runtime issue — in fact no EVE device was ever provisioned for this step (`evetest status` confirms "No EVE devices found"). The broker log shows it was building a fresh "installer" image template (`Building EVE image template "cc0ae86c2c6ed8b07af04bc300f9d9a9"`, an 8192 MiB installer.raw image with partitions `efi conf_win installer inventory_win`), and the underlying `make-raw`/`mkfs.fat` step failed partway through writing the EFI partition image with `dd: error writing '/tmp/output.img': No space left on device`, so `installer.raw.qcow2` was never produced — exactly matching the "file not found" error surfaced up through `prepareImageForEVEDevice`.

This is distinct from the two preceding subtests in the same run (`TestBootstrapWithLastResortDisabled`/`Enabled`), which succeeded because they reused an already-cached EVE image template rather than building a new large installer image; only this third subtest needed to build the large fresh installer image, which is what triggered the broker's `/tmp` running out of space.

I found no earlier occurrence of this "No space left on device"/"make-raw failed" signature anywhere in `live-ledger.md`, so this appears to be a new, not-previously-recorded issue (not a repeat of a known failure mode) — likely transient broker-host disk pressure (possibly from accumulated image-template caches) rather than a code defect in EVE itself. The broker host's own filesystem isn't reachable from this sandbox to confirm current free space directly, but the live build-log evidence is unambiguous about the proximate cause.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 6m0.000537502s (excluding download) waiting for app "27899cde-aa55-42ff-b2b1-64109c2335b1" () on device "edge-dev1" to reach RUNNING state (last state: INVALID)
```

##### Claude's conclusion

**Root cause:** `vm2` (app `27899cde-...`, DNID = edge-dev3) was deactivated before edge-dev3 was hard-powered-off, so unlike `vm3` (whose existing VMIRS/VMI simply got rescheduled onto edge-dev1 by Kubernetes' own ReplicaSet controller, no zedmanager involvement needed), reactivating `vm2` on a backup node requires zedmanager's `isCurrentlyBackupDNIDForApp` gate, which is hard-gated on `ctx.isAppOpLeader`. Live evidence confirms that flag never became true on edge-dev1: `/run/zedkube/KubeLeaderElectInfo/global.json` shows `"IsAppOpLeader":false,"AppOpLeaderIdentity":"edge-dev1"` with `LatestChange` frozen at `2026-11-14T00:11:46.557Z` — the exact instant edge-dev1 acquired the `eve-app-op` lease — and it was never republished since. This is zedkube's `OnStartedLeading`/`OnNewLeader` callback race on `leaderelect.go` (both callbacks fire within the same tick and race on `appOp.isLeader`'s atomic store vs. `publishLeaderElectionChange()`'s read), leaving the published flag stuck at `false` even though edge-dev1 genuinely holds the lease. As a direct consequence, zedmanager's `getKubeAppActivateStatus` logs `"not designated, node a6090fef..., onTheDevice false"` on every tick for `27899cde`, never activating it, matching evetest's 6-minute timeout exactly (matches the test's `backupOpTimeout` with the 1-minute override accepted).

This is the identical signature (same code path, same root cause, same frozen `LatestChange` pattern) already recorded in `live-ledger.md` for 2026-11-05 (run #8) — at that time flagged as a brand-new, not-yet-recurring failure mode. Tonight (2026-11-13/14, run #16) is the first time it has reproduced since, 9 nights later, so this is now a confirmed recurring (if infrequent) issue in zedkube's leader-election callback race, not a new or environmental bug. No PR diff was supplied for this investigation, so no code-relatedness assessment is given.
#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 300.000s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:550 with:
no surviving node holds the eve-app-op lease
Expected
    <*evetest.EdgeDevice | 0x0>: nil
not to be nil
```

##### Claude's conclusion

###### Root cause

This is the identical zedkube leader-election race already diagnosed earlier tonight for `TestDNIDandBackupDNID`, now surfacing through a different test. The test powered off edge-dev3 (the app's DNID) at 00:55:42 and expects a surviving node (edge-dev1 or edge-dev2) to visibly hold the `eve-app-op` lease so GC/backup logic can proceed; after the 300s `Eventually` window it found none, failing at `pvcgc_test.go:550`.

Live evidence: `kubectl get lease -n eve-kube-app eve-app-op -o yaml` on edge-dev1 shows the Kubernetes lease itself is fine — `holderIdentity: edge-dev1`, `acquireTime: 2026-11-14T00:42:04.644986Z`, `leaseTransitions: 0`, and a fresh `renewTime` (`01:03:26`, seconds before I checked at `01:03:33`) — edge-dev1 has held and continuously renewed it since cluster startup, uninterrupted by edge-dev3's power-off. But `/run/zedkube/KubeLeaderElectInfo/global.json` on edge-dev1 shows `"IsAppOpLeader":false,"AppOpLeaderIdentity":"edge-dev1"` with `LatestChange` frozen at `2026-11-14T00:42:04.649914102Z` — 5ms after the lease's `acquireTime` and never updated since. That's the same `OnStartedLeading`/`OnNewLeader` callback race recorded in `live-investigation.md` for tonight's earlier `TestDNIDandBackupDNID` failure: the flag flips `true` then immediately back to `false` on self-acquisition and is never republished, so any code (and apparently this test) relying on the published `IsAppOpLeader` status sees no node as app-op leader even though the real k8s lease is healthy.

This shares the same root cause as the earlier failure already investigated in this run. It's a new failure signature for `TestClusterPVCGCDeletesOnlyOrphans` specifically (the ledger's prior entries for this test are the unrelated tie-breaker-node/Longhorn scheduling gap at line 115, or the GC-retry-timing issue at line 218 — nothing at line 550), but the underlying zedkube bug is the same one recorded as a known-recurring issue in the ledger since 2026-11-05 (run #8) and reconfirmed earlier tonight. No PR diff was supplied for this investigation.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This exactly matches an identical known, long-recurring bug in `TestVMAppPurgeDuringFailover`.

###### Root cause

This is the same recurring zedmanager/zedkube "purge-after-failover" deadlock in `getKubeAppActivateStatus`/`onTheDeviceForApp` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2027-2059`, `pkg/pillar/cmd/zedmanager/dnidbackup.go`). Live evidence on edge-dev3 confirms it: `AppInstanceStatus` for `failover-purge-app` (uuid `928a4156-...`) shows `PurgeInprogress:4` (BringUp), `Activated:false`, `State:118` (HALTING), `IsDesignatedNodeID:false`, and `domainmgr`'s matching `DomainStatus` is `HALTED`/`Activated:false` with no error — meanwhile `kubectl get vmirs/vmi -A` on edge-dev2/3 shows zero resources for the app. The purge's `BringDown` deleted the old-generation VMIRS, which cleared zedkube's `ScheduledOnThisNode` signal; since edge-dev1 (the DNID) is powered off and the test deliberately pins `dnidOutageThresholdKey` to 2h so no peer ever qualifies as backup-DNID, `onTheDeviceForApp` now returns false on every surviving node, so `getKubeAppActivateStatus` never lets zedmanager re-activate the app — nothing ever asks domainmgr/zedkube to create the new-generation VMIRS, exactly matching `found []`.

This is **not** the same root cause as the other two failures already investigated in this run (`TestDNIDandBackupDNID`/`TestClusterPVCGCDeletesOnlyOrphans`, both the zedkube `IsAppOpLeader`-stuck-false leader-election race) — here I confirmed live that leader election converged correctly (edge-dev2's `KubeLeaderElectInfo` shows `IsAppOpLeader:true` consistent with the actual lease holder, edge-dev3 correctly shows `false`). This is a distinct, separate bug in the designated-node/backup-DNID activation gate. Per `live-ledger.md`, this exact failure signature in `TestVMAppPurgeDuringFailover` is a long-standing, well-known recurring issue first seen **2026-10-29** (run #1), reproducing in nearly every nightly run since (including as recently as the prior run) — tonight's occurrence continues that unbroken streak rather than being a new bug.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
EVE upgrade to 0.0.0-master-368a44a3-k-amd64 failed: checkInstalledVersion: image name not match. config 0.0.0-master-368a44a3-k-amd64, image ver 
```

##### Claude's conclusion

Mostly just device info dumps (nbd/vda devices listed routinely). Nothing substantive about this specific mount-corruption signature. I have sufficient live evidence now for a conclusion.

###### Root cause

The upgrade download/verify succeeded (content tree sha256 verified, progress 100%), but after `baseosmgr` wrote the new rootfs squashfs image to the inactive partition (`WriteToPartition IMGB, /dev/vda3` at 22:53:56, `installWorker DONE ... err <nil>` at 22:53:57), the subsequent sanity-check mount of that partition failed: `Mount of /dev/vda3 failed: invalid argument` (baseosmgr log, 22:53:58.398), and the device's own kernel ring buffer shows the matching squashfs-driver error `unable to read id index table` at uptime 605.7s — i.e. the just-written squashfs image on IMGB is internally corrupt (bad/missing id table), not merely a transient mount race. Because the mount failed, `checkInstalledVersion` read an empty `shortVersion` off the partition and compared it against the target `0.0.0-master-368a44a3-k-amd64`, producing exactly the observed `"image name not match. config 0.0.0-master-368a44a3-k-amd64, image ver "` error; baseosmgr then reset IMGB back to `unused`, leaving the device still booted on the old `66475696` image (confirmed live via `swList`/`ZbootStatus`).

This does not match any prior ledger entry for `TestEVEUpgradeKubevirtToKubevirt` — every previous failure of this test (runs #7, #8, #10, and others) was a post-boot K3s/Longhorn iowait-contention timeout, never a write-and-verify corruption of the IMGB squashfs image itself. A `grep` of `live-ledger.md` for "image name not match", "id index table", and "Mount of /dev/vda3" returns no hits, so this appears to be a new failure signature rather than a recurring/known issue. I could not determine with certainty whether the corruption originated in the `WriteToPartition` copy step itself or in the downloaded/verified blob content (hash verification passed, which argues against the latter), so I can't fully pin down the underlying bug beyond "the raw write to /dev/vda3 produced an unmountable squashfs image."

## [2026-11-13 -- 0.0.0-master-fc841102 (run #16)](https://github.com/lf-edge/eve/actions/runs/43315699291)

[Full report](https://lf-edge.github.io/eve/test/master/runs/16/)

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithProxy

##### Failure

```

Timed out after 600.000s.
Expected to satisfy: Device has enrolled NEW certificate for 802.1x AND deleted the obsolete certificate
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7917 storage:40006 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-11.0" serialNumber:"SZLN18D5" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"127.0.0.1:53" DNSsearch:"test."} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/checkpoint"} storageList:{mountPath:"/persist/log"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/persist/newlog"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/persist/clear"} storageList:{device:"nbd5"} storageList:{device:"nbd12"} storageList:{mountPath:"/persist/vault"} storageList:{mountPath:"/" total:3959} storageList:{device:"nbd8"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{device:"nbd3"} storageList:{mountPath:"/hostfs" total:243} storageList:{device:"nbd15"} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd14"} storageList:{mountPath:"/persist/lost+found"} storageList:{device:"nbd2"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{device:"vda" total:65536} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/nettrace"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"nbd10"} storageList:{device:"nbd11"} storageList:{device:"nbd1"} storageList:{device:"nbd7"} storageList:{mountPath:"/persist/status"} storageList:{device:"nbd6"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{mountPath:"/config" total:5} storageList:{mountPath:"/persist/vault/volumes"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{device:"vda9" total:40953 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{mountPath:"/persist/certs"} storageList:{mountPath:"/persist" total:40006 storageLocation:true} storageList:{mountPath:"/persist/tmp"} storageList:{device:"nbd0"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{device:"vda7" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"} storageList:{device:"nbd13"} bootTime:{seconds:1794522974} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-master-fc841102-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"5b32ca51-d1e7-4cf2-af63-2510e6016978" lastRebootReason:"NORMAL: First boot of device - at 2026-11-12T22:36:50.509279072Z" lastRebootTime:{seconds:1794523010 nanos:509279072} systemAdapter:{status:{version:1 key:"zedagent" timePriority:{seconds:1794523090 nanos:654850714} lastSucceeded:{seconds:1794523102 nanos:593189490} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.20.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.20.123" defaultRouters:"172.20.20.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{timestamp:{seconds:1794523102 nanos:593106477}} usage:PhyIoUsageMgmtAndApps networkUUID:"26d44898-1ec9-48a6-b056-0d39a818dddd" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794523090 nanos:654850714}} pnac_status:{enabled:true state:SUPPLICANT_STATE_AUTHENTICATED last_auth_timestamp:{seconds:1794523097}}}}} HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1794523077 nanos:99765112} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"\n\x04r\x1fP\x1a?W\xb2\xaf\x18\x17\x083\xfc\xc4\x04\xe5\xf0[ѵBh\x99\xf0\xc3^\x89O\xb0\xf2"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} last_boot_reason:BOOT_REASON_FIRST hardware_watchdog_present:true reboot_inprogress:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_REBOOTING storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE error:{description:"[ATTEST] No escrow data" timestamp:{seconds:1794523087 nanos:18113166} severity:SEVERITY_ERROR}} api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev" enrolled_certs:{cert_enrollment_profile_name:"scep-test" subject:{common_name:"edge-dev" organization:"lf-edge" country:"US"} issuer:{common_name:"SCEP CA" organization:"Example" organizational_unit:"Lab" country:"US"} san_uri:"urn:Name:edge-dev" issue_timestamp:{seconds:1794522495} expiration_timestamp:{seconds:1826059095} renew_period_percent:50 sha256_fingerprint:"d7dba9582bfe1a2109140a46073d0e12a6936f0b8cb5171127cf19cf359e501c" status:CERT_STATUS_AVAILABLE}
```

##### Claude's conclusion

Only one prior occurrence (2026-11-09, run #12), and no PR diff was given for this investigation, so no RELATED line is needed.

###### Root cause

The device is currently stuck: `evetest status`/`evetest eve info` show it parked in `EVE_DEVICE_STATE_SUSPECT` with the last-known info frozen at `ZDEVICE_STATE_REBOOTING`/`reboot_inprogress:true`, and `evetest eve ssh` fails outright ("failed to detect any IP address"). The console log confirms two prior clean reboots (`reboot: Restarting system` at ~196s and ~200s uptime, 22:28 and 22:36:38) consistent with the test's SCEP-profile-replacement step, but the device never fully recovered network after the second one: live `evetest sdn ssh` into the broker shows hostapd on `bridge0` has `num_sta[0]=0` (nobody currently authenticated), and neighbor tables for both the pre-auth VLAN (172.20.10.123) and authenticated VLAN (172.20.20.123) show `FAILED` — the device isn't present on either. The `bridge0.log` captured a 802.1x re-authentication attempt right after the last reboot that was aborted almost immediately ("Scheduled disconnection ... after EAP-Failure") without completing a TLS handshake, and no further EAPOL attempts have been logged since (file untouched since 22:40, ~12 minutes ago). Only a single log line ever reached Adam after this last boot, and `enrolled_certs` in Adam's DB still shows only the original `scep-test` cert — the device never got far enough to talk to the SCEP server (`new-scep-profile`) or re-authenticate, matching the test's "enrolled NEW certificate AND deleted obsolete" timeout exactly.

This matches a previously-recorded, near-identical failure: on 2026-11-09 (run #12), `TestPNACWithoutProxy` failed with the exact same symptom — the SCEP-profile-replacement step triggering a reboot after which the device never re-established 802.1x and got stranded pre-auth/`SUSPECT`. Tonight's `TestPNACWithProxy` instance is the same underlying mechanism (802.1x re-authentication failing to recover after the profile-swap-induced reboot), now recurring in the proxy variant of the test 3 nights later — so this is a known, recurring (if infrequent) issue rather than a brand-new one, likely in the SCEP/PNAC cert-rotation reboot path rather than test infrastructure.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume 49ef61fd-9873-4aa9-b362-16229929d9eb
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

No need — I have enough live evidence already. Here's the conclusion.

**Root cause:** `edge-dev2` is labeled `tie-breaker-node=true` and shows `Ready,SchedulingDisabled` in `kubectl get nodes`, so the `longhorn-manager` DaemonSet (node-selected on `tie-breaker-node=false`) never schedules a pod there — live `kubectl get pods -n longhorn-system -l app=longhorn-manager -o wide` confirms manager pods only on `edge-dev1`/`edge-dev3`, never `edge-dev2`. `volumehandlers/csihandler.go:106` still calls `kubeapi.WaitForLonghornReady` unconditionally with no tie-breaker exemption, so `volumemgr` on `edge-dev2` can never progress the volume for `49ef61fd-9873-4aa9-b362-16229929d9eb` past `CREATING_VOLUME` (live `VolumeStatus` JSON shows `"State":109`, i.e. `CREATING_VOLUME`, not `CREATED_VOLUME`/110) within the test's 900s window — exactly matching `pvcgc_test.go:115`'s "has no created VolumeStatus" assertion, even though the backing PVC is already `Bound`.

This is a known, long-recurring issue per `live-ledger.md`: the identical "tie-breaker-node + `has no created VolumeStatus`" signature for this exact test was first seen 2026-11-02 (run #5) and has recurred on 2026-11-03, -04, -06, -07, -08, and most recently last night 2026-11-12 (run #15, same `pvcgc_test.go:115` line) — tonight is simply the next occurrence of that same unfixed `csihandler.go` gating gap, not a new bug. No PR diff was supplied for this investigation, so no code-relatedness assessment is given.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

Confirms edge-dev1 (the DNID node) is indeed still powered off/unreachable, consistent with everything above.

###### Root cause

This is the same long-standing, known `getKubeAppActivateStatus` deadlock in `pkg/pillar/cmd/zedmanager`/`zedkube` that the ledger has recorded repeatedly for this exact test, dating back to the test's introduction in commit `98acf1411` (2026-10-18) and recurring in essentially every nightly run since (most recently last night, run #14/2026-11-12). Live evidence confirms the mechanism precisely: with the designated node `edge-dev1` still unreachable (`evetest status` shows `EVE_DEVICE_STATE_SUSPECT`, and SSH fails with "failed to detect any IP address"), the purge deleted the old-generation VMIRS (`failover-purge-app-2e617-0`, last VMI `...0trlmd` torn down at ~02:51), but no new generation's VMIRS/VMI/pod exists anywhere in the cluster (`kubectl get vmirs/vmi/vm/pods -n eve-kube-app` all return "No resources found" on both edge-dev2 and edge-dev3). `zedmanager` logs on edge-dev2 show it stuck permanently in `reevaluateAppInstances`/`getKubeAppActivateStatus(...): not designated, ... onTheDevice false, statusRunning false` → `effectiveActivateCombined: ... combined false` → "Waiting for config.Activate", because after the purge the app shows `AppKubeStatus:NotInCluster` everywhere, and the test deliberately pins `dnidOutageThresholdKey` to 2 hours so no peer ever becomes an eligible backup DNID — leaving no node able to (re)activate the app and create the new VMIRS.

This matches run #15's own ledger entry for this test exactly (same signature, same code path) and is an unbroken, still-unfixed recurring issue, not a new bug.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

**Root cause:** Live `volumemgr` logs on `edge-dev1` show the exact same `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` race already documented repeatedly for this test. For content tree `39d8f039-...` (`vm1-image`), at `03:43:57.688` and again at `03:44:01.494` (right after vm1's post-reactivation re-create), `contentTreeSatisfiedByPVCs` logs "no local volumes reference this content tree" because the matching `VolumeConfig`/PVC hadn't been republished to volumemgr yet, so `doUpdateContentTree` falls through the ordinary non-PVC path, finds all blobs already verified in the local CAS, and self-completes `VERIFIED → LOADING → LOADED` by `03:44:01.803` — exactly matching the live `ContentTreeStatus` JSON (`"State":108`) and the failing assertion (expected 125/REMOTELOADED). The `VolumeStatus` already shows `CREATED_VOLUME` with a PVC reference at this point, confirming the PVC really was already complete, consistent with "re-downloaded despite the PVC already being complete."

This is a known, long-recurring issue specific to `TestClusterPVCRedownload`, first seen 2026-10-30 (run #2) and reproducing repeatedly in nearly every nightly since (including multiple times within this very run's own `live-investigation.md` entries at earlier timestamps tonight, and last night 2026-11-12). It does not share a root cause with this run's other investigated failure (`TestClusterPVCGCDeletesOnlyOrphans`, a Longhorn tie-breaker-node scheduling gap) — this is a continuation of the same unbroken `pkg/pillar/cmd/volumemgr` PVC-adoption-timing bug, not a new one. No PR diff was supplied, so no code-relatedness assessment is given.

### TestNodeClusterSuite: failure analysis

#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "f0db6236-ae82-4180-a60c-08753874bcfd" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

This confirms `TestClusterToSingleConversion` passed at 00:57:58 and `TestClusterVMApp` started immediately after, reusing the same devices — matching the exact sequence from the ledger's prior occurrence.

###### Root cause

This is the identical, already-documented `tie-breaker-node` label gap recurring from a prior run in this same ledger. Live evidence on `edge-dev1` confirms it precisely: `kubectl get nodes -L tie-breaker-node` shows `edge-dev1`/`edge-dev2` labeled `tie-breaker-node=false` but `edge-dev3` has **no label at all**; consequently `longhorn-manager`'s `nodeSelector: tie-breaker-node=false` DaemonSet never schedules a pod on `edge-dev3` (`kubectl get pods -n longhorn-system -l app=longhorn-manager -o wide` shows only `edge-dev1`/`edge-dev2`). The app's `cdi-upload` pod for the test volume got scheduled onto `edge-dev3` and has been stuck `ContainerCreating` for 30+ minutes, with `kubectl describe pod` showing repeated `FailedAttachVolume: ... node edge-dev3 is not ready` from Longhorn's `attachdetach-controller` — so the volume (and therefore the VM) never gets created, exactly matching the test's "timed out waiting for app to be scheduled" failure.

This test ran immediately after `TestClusterToSingleConversion` (passed 00:57:58, same devices reused, `TestClusterVMApp` started at the same timestamp), which converts `edge-dev3` back to standalone and reboots it for later reuse without re-running the tie-breaker relabeling logic — the same trigger sequence as the `TestClusterVMApp` entry already recorded in `live-ledger.md` under this run's prior iteration. Per the ledger, this exact mechanism (unlabeled rejoined node → Longhorn manager not scheduled → `FailedAttachVolume: node not ready`) is known and recurring since at least 2026-11-02 (run #5), and has reproduced across most nightly runs since, including the identical signature already logged for tonight's run (run #15) — so this is not a new bug, just the same long-standing, unfixed gap in the tie-breaker relabel-on-rejoin flow (`pkg/kube/kube-init/tiebreaker/tiebreaker.go`) combined with `csihandler.go`'s unconditional `WaitForLonghornReady` call.

No PR diff was supplied for this investigation, so no relatedness assessment is given.

## [2026-11-12 -- 0.0.0-master-d5a49ec7 (run #15)](https://github.com/lf-edge/eve/actions/runs/43107945149)

[Full report](https://lf-edge.github.io/eve/test/master/runs/15/)

### TestLimitsSuite: failure analysis

#### TestManyAppInterfaces

##### Failure

```
Device "edge-dev" failed to confirm the latest config (version 1): timed out waiting for LastProcessedConfig >= 2026-11-12 01:06:25.865682648 +0000 UTC
```

##### Claude's conclusion

###### Root cause

Live evidence shows `edge-dev` (now onboarded as UUID `d0735655-c6a6-4b43-aeab-0978f2a27bf7`, replacing the previous session's `7c27ea45-...`) actually processed config version 1 correctly and essentially on time: the device's own metrics payload (`adam-db/device/.../metrics/01794445711765213406`) reports `lastProcessedConfig":"2026-11-12T01:06:25.865682648Z"` — the *exact* timestamp the test was waiting for. The problem is that this field is only surfaced to the controller via the periodic `metrics` POST, and that POST was delayed: the first metrics send was a 412-byte stub sent immediately at boot, and the real one carrying `lastProcessedConfig` didn't land at Adam until ~01:08:51 — about 24s *after* the test's own ~120s wait had already timed out and paused at 01:08:27. Device logs from exactly that window show why: right after config v1 triggered the DevicePortConfig switch from the bootstrap `lastresort` network to the controller-assigned one, the device hit repeated `"interface eth0: no suitable IP address available"` and `dial tcp: lookup adam.evetest on 127.0.0.1:53: server misbehaving` DNS/routing failures, which is consistent with the pending metrics call getting wedged on a connection/route torn down mid-flight by the reconfiguration.

This is not a new or unique bug, and does not match the previously-documented zedbox "send on closed channel" panic recorded for `TestManyAppInterfaces` on earlier nights (lines 456/1082 of the ledger) — this run's failure happened entirely during setup, before any app provisioning began. Instead it is the exact same, already-known "zedagent processes config promptly but the confirming metrics POST hangs past the harness's timeout window" mechanism documented twice before in `live-ledger.md` with the identical `"failed to confirm the latest config (version 1): timed out waiting for LastProcessedConfig"` message: first recorded 2026-11-07 (run #10, `TestZVolProvisionedSizeReported`) and recurring 2026-11-09 (run #12, `TestVMAppPurgeAfterPowerCycle`). Tonight is simply the third occurrence of that same recurring harness/timing race, now hitting `TestManyAppInterfaces`.

No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.182s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume e0237029-1859-46ff-afb9-6a9f2d1390ef
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

Confirmed the code path still exists unchanged. I have what I need.

**Root cause:** `edge-dev2` is labeled `tie-breaker-node=true` and shows `SchedulingDisabled` in `kubectl get nodes`, so Longhorn's `longhorn-manager`/`longhorn-csi-plugin` DaemonSets (node-selected on `tie-breaker-node=false`) never schedule a pod there — confirmed live: `kubectl get pods -n longhorn-system -l app=longhorn-manager -o wide` shows manager/CSI pods only on `edge-dev1`/`edge-dev3`, and the target volume's two Longhorn replicas (`pvc-9ecfec58-...-r-*`) exist only on those same two nodes, never `edge-dev2`. `volumehandlers/csihandler.go:106` still calls `kubeapi.WaitForLonghornReady` unconditionally (no tie-breaker exemption), so `volumemgr` on `edge-dev2` can't ever report `VolumeStatus` as created within the test's wait window for `e0237029-...`, exactly matching `pvcgc_test.go:115`'s "node edge-dev2 has no created VolumeStatus" assertion (the status does eventually appear as `CREATED_VOLUME` now, post-timeout/post-pause, but too late for the test's 900s bound).

This is a known, long-recurring issue in `live-ledger.md`: the identical "tie-breaker-node + `has no created VolumeStatus`" signature for this exact test was first seen 2026-11-02 (run #5) and has recurred on 2026-11-03, -04, -06, -07, and -08 (runs #6, #7, #9, #10, #11) — tonight (run #14) is simply the next occurrence of that same unfixed gap, not a new bug. (Note: this test has also failed under *other*, unrelated signatures on other nights — an etcd/CDI-overload scheduling timeout on 2026-11-01 and a later-stage GC-deletion-assertion bug on 2026-11-09 — but tonight's failure matches the tie-breaker mechanism specifically.) No PR diff was supplied for this investigation, so no code-relatedness assessment is given.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

Both edge-dev2 and edge-dev3 confirm the same deadlock: neither is designated, neither is activated. This fully matches the long-standing known mechanism.

**Root cause:** This is the identical, already-known `getKubeAppActivateStatus`/`zedkube.checkAppsStatus` deadlock in `pkg/pillar/cmd/zedmanager`/`zedkube` for the designated-node failover path. Live evidence confirms it precisely: `edge-dev1` (the app's designated node) is `EVE_DEVICE_STATE_SUSPECT` per `evetest status`; `AppInstanceStatus` for `failover-purge-app` (uuid `6df3d7c8-1b0f-4609-934e-a5cf040f9b8c`) on edge-dev2 shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-11T23:28:08Z`, `Activated:false`, `IsDesignatedNodeID:false`; and `zedkube` on edge-dev2 is *actively logging right now* (23:43:54, well after the 900s timeout) `IsDNidNode:false ScheduledOnThisNode:false AppKubeStatus:NotInCluster` — same on edge-dev3 (`Activated:false`, `IsDesignatedNodeID:false`). Neither surviving node ever takes over as backup DNID after the purge tore down the old VMIRS, so no VMIRS/VMI ever gets created, matching the test's "found []" assertion exactly.

This does **not** share a root cause with the earlier `TestClusterPVCGCDeletesOnlyOrphans` failure in this run (that was the unrelated Longhorn tie-breaker-node scheduling gap). Per `live-ledger.md`, this is a very well-known, long-unbroken recurring issue dating back to the test's introduction in commit `98acf1411` (2026-10-18), reproducing with the identical signature in essentially every nightly run since then (last recorded through run #13 earlier tonight, and runs #9–#12 on preceding nights) — tonight's occurrence is simply the next instance of that same unfixed deadlock, not a new bug.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

This confirms the exact same mechanism as the ledger entry: `contentTreeSatisfiedByPVCs` logs "no local volumes reference this content tree" at 00:19:26 and 00:19:29, then the content tree falls through to the non-PVC path since all blobs are already VERIFIED in CAS, and lands on LOADED by 00:19:30 instead of waiting for REMOTELOADED via PVC adoption.

I have everything needed to write the conclusion.

**Root cause:** This is a direct repeat of the same `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` PVC-adoption race in `pkg/pillar/cmd/volumemgr` already documented in `live-ledger.md` for this exact test. Live `volumemgr` logs on `edge-dev1` confirm it: on vm1's reactivation, `contentTreeSatisfiedByPVCs(3958d371-...)` logs "no local volumes reference this content tree" at `00:19:26.040` and `00:19:29.921` (the matching `VolumeConfig`/PVC hadn't been republished yet), so `doUpdateContentTree` falls through the ordinary non-PVC path, finds all three blobs already `VERIFIED` in the local CAS from before reboot, and self-completes `VERIFIED → LOADING → LOADED` by `00:19:30.123` — landing on `LOADED` (108) instead of `REMOTELOADED` (125), exactly matching `/run/volumemgr/ContentTreeStatus/3958d371-....json` (`"State":108`) and the failing assertion. This does **not** share a root cause with this run's earlier `TestClusterPVCGCDeletesOnlyOrphans` (Longhorn tie-breaker-node scheduling gap) or `TestVMAppPurgeDuringFailover` (designated-node failover deadlock) failures. Per `live-ledger.md`, this is a long-standing, well-known recurring issue specific to `TestClusterPVCRedownload`, first seen 2026-10-30 (run #2) and reproducing repeatedly since (including runs on 2026-10-31, 11-03, 11-07, and 11-09/10) — tonight's occurrence is simply the next instance of that same unfixed, unbroken streak rather than a new bug.

### TestNodeClusterSuite: failure analysis

#### TestNativeKubeAppNetworking

##### Failure

```

scale ReplicaSet default/native-replica-app to 0
Unexpected error:
    <*fmt.wrapError | 0xc0ee4dae0a0>: 
    failed to execute script over SSH for EVE device edge-dev: SSH dial to 172.20.20.123:22 failed: ssh: handshake failed: read tcp 250.250.250.1:47730->172.20.20.123:22: read: connection reset by peer (stderr: )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev: SSH dial to 172.20.20.123:22 failed: ssh: handshake failed: read tcp 250.250.250.1:47730->172.20.20.123:22: read: connection reset by peer (stderr: )",
        err: <*fmt.wrapError | 0xc0ee4dae080>{
            msg: "SSH dial to 172.20.20.123:22 failed: ssh: handshake failed: read tcp 250.250.250.1:47730->172.20.20.123:22: read: connection reset by peer",
            err: <*fmt.wrapError | 0xc0ee4dae060>{
                msg: "ssh: handshake failed: read tcp 250.250.250.1:47730->172.20.20.123:22: read: connection reset by peer",
                err: <*net.OpError | 0xc0ee42c4140>{
                    Op: "read",
                    Net: "tcp",
                    Source: <*net.TCPAddr | 0xc0ee4a18150>{
                        IP: [250, 250, 250, 1],
                        Port: 47730,
                        Zone: "",
                    },
                    Addr: <*net.TCPAddr | 0xc0ee4a18180>{
                        IP: [172, 20, 20, 123],
                        Port: 22,
                        Zone: "",
                    },
                    Err: <*os.SyscallError | 0xc0ee4dae040>{
                        Syscall: "read",
                        Err: <syscall.Errno>0x68,
                    },
                },
            },
        },
    }
occurred
```

##### Claude's conclusion

Only `TestNativeKubeAppNetworking` failed in this run; `TestSingleNodeCluster` passed earlier, so there's no shared root cause with another in-run failure.

**Likely root cause:** Live device logs show the exact trigger at the millisecond level: at `00:40:14.381` sshd on `edge-dev` logged `drop connection #0 from [172.20.20.1]:47730 on [172.20.20.123]:22 penalty: connections without attempting authentication` — the identical source port (`47730`) the test's failing SSH dial used. The test harness (and mgmtproxy/NAT path through `172.20.20.1`→`250.250.250.1`) had been hammering the device with very rapid, back-to-back SSH connections for its pod-to-pod/DNS/connectivity checks — device logs show 116 separate `Accepted publickey` sessions in just ~12 minutes since boot, several bursts only ~0.2–0.3s apart. This tripped OpenSSH's per-source-address penalty/rate-limiting mechanism (`PerSourcePenalties`, enabled by default in recent OpenSSH), which proactively RSTs new connections from an offending source for a cooldown period — exactly producing the test's `ssh: handshake failed: ... read: connection reset by peer` at the "scale ReplicaSet to 0" step. The device itself was healthy throughout (I confirmed fresh SSH connections succeed right now, with no corresponding reboot/panic/OOM in the logs), so this is a transient sshd-side connection-rate penalty, not a device/network failure.

This exact signature (`drop connection ... penalty: connections without attempting authentication`) does not appear anywhere in `live-ledger.md`, including prior `TestNativeKubeAppNetworking` entries (which were different mechanisms: a k3s apiserver-readiness race, cluster-mode-not-carried-forward reboots, etc.) — so this looks like a new, previously unrecorded failure mode: the test's own high-frequency SSH usage pattern occasionally self-triggers OpenSSH's built-in anti-flood protection on the device.
#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "6091a820-7774-4112-8835-3f1d20aa245f" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

This confirms a long-standing, well-documented, recurring bug going back to at least run #5 (2026-11-02), appearing repeatedly across nights and multiple node variants (TestClusterVMApp, TestClusterPVCGCDeletesOnlyOrphans, etc.), with the exact mechanism I just reproduced live.

###### Root cause

This is a known, recurring failure, reproducing the exact same mechanism documented repeatedly in `live-ledger.md` since at least 2026-11-02 (run #5), and it is directly related to the prior investigation in this same run: `TestClusterToSingleConversion` (which ran immediately before this test, 01:43–01:46, reusing the same devices) withdrew `edge-dev3` from the cluster and rebooted it to convert it back to standalone; when `TestClusterVMApp` then re-formed the 3-node cluster, `edge-dev3` rejoined as a fresh Kubernetes node object that was never relabeled `tie-breaker-node=false` (live `kubectl get nodes -L tie-breaker-node` confirms `edge-dev1`/`edge-dev2` carry `tie-breaker-node=false` while `edge-dev3` has no label at all). Because the `longhorn-manager` DaemonSet is scoped with `nodeSelector: tie-breaker-node=false`, no manager pod was ever scheduled on `edge-dev3`, so Longhorn treats it as "not ready" and every `AttachVolume` for the app's PVC on `edge-dev3` fails (`FailedAttachVolume: ... node edge-dev3 is not ready`, confirmed live via `kubectl describe pod cdi-upload-...`). Consequently the app's volume stayed permanently in `CREATING_VOLUME`/`DETACHED` with all replicas `OFFLINE`, the VM was never created, and the test's 30-minute wait for it to be scheduled timed out exactly as reported.

This is the same underlying code gap the ledger attributes to `pkg/pillar/volumehandlers/csihandler.go`'s `PrepareVolume` calling `kubeapi.WaitForLonghornReady` unconditionally instead of exempting tie-breaker-labeled (or here, never-relabeled) nodes per `longhorninfo.go:720-721`, combined with the tiebreaker-conversion-back-to-standalone/rejoin flow (`pkg/kube/kube-init/tiebreaker/tiebreaker.go`'s `nodesConfigApply`) not being re-run to relabel the rejoined node. It has recurred on essentially every nightly run since 2026-11-02, so this is a standing, still-unfixed bug rather than a new regression.

### TestSecuritySuite: failure analysis

#### TestVaultKeyModeRecoveryOnExt4

##### Failure

```

Timed out after 300.001s.
the vault must be unlocked after the wrong key mode was recorded
The function passed to Eventually failed at /evetest/tests/security/vault_keymode_test.go:343 with:
vault status is 4
Expected
    <int>: 4
to equal
    <int>: 2
```

##### Claude's conclusion

###### Root cause

This is a different, more specific failure mode than any prior `TestVaultKeyModeRecoveryOnExt4` entry. Live `vaultmgr` logs show that after the test recorded the wrong `TpmKeyOnly` mode and rebooted (22:54:53), the device's first unlock attempt logged `"can't read the legacy disk key, generating a new one"` — a message that only comes from `evetpm.FetchVaultKey` (the *un-sealed*, TPM-NVRAM "legacy key" path), never from the sealed-key path (`FetchSealedVaultKey`, which instead logs `"sealed disk key present int TPM, about to unseal it"` — exactly what the *prior*, successful boot at 22:52:58 had logged). The live `VaultStatus` on the device right now confirms this: `"PCRStatus":2` (`PCR_DISABLED`), versus `PCR_ENABLED` on the healthy prior boot. Per `pkg/pillar/evetpm/tpm.go`, `FetchSealedVaultKey` falls back to the legacy/non-sealed `FetchVaultKey` whenever `PCRBankSHA256Enabled()` — a live, cached-once-per-process `ReadPCR(0, SHA256)` probe against the TPM — returns false. Since no legacy TPM-NVRAM key existed yet (this vault was always sealed-key-based), that first attempt minted a brand-new random key and wrote it into TPM NVRAM, which obviously can't open the real fscrypt-protected vault (`Error unlocking vault: exit status 1`), and the fallback retry just re-reads that same freshly-written garbage key again. Critically, the controller-key rescue path (`vaultmgr.go:594-611`, `Re-sealing disk key` → `UnlockDefaultVault`) re-seals the correct key into TPM but then calls `unlockVault(..., useSealedKey=true)` again, which hits the exact same disabled-PCR-bank branch and ignores the freshly re-sealed key in favor of the unrelated legacy NVRAM key — so even the controller rescue can't recover, leaving the vault permanently in `DATASEC_AT_REST_ERROR` (status 4) for the rest of the boot, matching the test's failure exactly.

This does not match either of the two previously-recorded `TestVaultKeyModeRecoveryOnExt4` failure signatures in `live-ledger.md` (a slow-VM reboot-timeout, last seen 2026-11-04/05, and a stale hardcoded attempt-count assertion recurring 2026-10-29 through 11-02) — both of those hit different line numbers (`vault_keymode_test.go:298`/`:318`) and different mechanisms. Tonight's failure (line 343, vault genuinely stuck in error after the controller key) is new, not previously recorded. There's no other failure in this run's artifacts so far to share a root cause with, and I found no evidence this is simply infra/host-load flakiness — it's a reproducible code path confirmed by matching log strings to their exact source locations.

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for app "86483418-87a0-467f-98ff-bd248f08f8e4" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

###### Root cause

Live inspection shows the three-node k3s/Kubevirt cluster did form (`evetest status` shows edge-dev1/2/3 all `ONLINE` and k8s `Ready`), and the app's config reached all devices, but the app's Longhorn-backed PVC never finished provisioning. `kubectl describe pod cdi-upload-...-pvc-0` (namespace `eve-kube-app`) shows repeated `FailedAttachVolume` errors ("`node.longhorn.io "edge-dev2" not found`" then later `DeadlineExceeded`), and both backing Longhorn volumes are stuck in `attaching`/`unknown` robustness with all replicas `OFFLINE`.

The actual trigger is on **edge-dev3**: `longhorn-manager-hqj9l`'s previous container crashed at 23:07:06 with `level=fatal msg="Error starting manager: Operation cannot be fulfilled on settings.longhorn.io \"priority-class\": the object has been modified..."`. On restart, it briefly created the `edge-dev3` Longhorn Node CR ("Node edge-dev3 is ready") but then immediately emitted `Warning 'Delete' Deleting node edge-dev3` and never recreated it — `kubectl get nodes.longhorn.io` confirms only `edge-dev1`/`edge-dev2` exist, with edge-dev3 permanently missing even though its k8s node and longhorn-manager pod are healthy. Every ~30s since then the controller logs `failed to get longhorn node edge-dev3: node.longhorn.io "edge-dev3" not found`, and the replica scheduler logs `"There's no available disk for replica ..., size 314572800"` — with only 2 of 3 nodes schedulable, replicas can't be placed, the PVC can't attach, the CDI upload pod stays `ContainerCreating` forever, and the app VMI is never scheduled, exactly matching the test's 10-minute timeout.

This does **not** share the root cause with the earlier `TestThreeNodesUpgrade` failures already logged tonight in `live-ledger.md` (those were Proxmox-host/installer-provisioning timeouts — devices never even came up); this one occurs well after cluster formation, at the volume-attach/app-scheduling stage. I found no prior occurrence of this `node.longhorn.io ... not found`/Longhorn-node-deletion-race signature anywhere in `live-ledger.md`, so this is a new failure mode tonight, not a previously known/recurring one — it looks like a Longhorn node-controller race during manager restart/reconciliation rather than an EVE/pillar bug, but warrants a look since it reproducibly starved app scheduling for the whole remaining test window.

## [2026-11-11 -- 0.0.0-master-7d265c2a (run #14)](https://github.com/lf-edge/eve/actions/runs/42910376872)

[Full report](https://lf-edge.github.io/eve/test/master/runs/14/)

### TestLPSSuite: failure analysis

#### TestAppLocalInfo

##### Failure

```

Timed out after 185.363s.
The function passed to Eventually failed at /evetest/tests/lps/helpers_test.go:107 with:
Unexpected error:
    <*fmt.wrapError | 0x2ff2f94c8ec0>: 
    unable to reach app "98d25c7d-204d-4975-9ef9-28442249be3b" SSH on device "edge-dev": no reachable endpoint among [172.20.20.123:2222]
    {
        msg: "unable to reach app \"98d25c7d-204d-4975-9ef9-28442249be3b\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.20.123:2222]",
        err: <*errors.errorString | 0x2ff2fa95e420>{
            s: "no reachable endpoint among [172.20.20.123:2222]",
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

Live evidence shows the device correctly rebooted at 23:13:04 (controller-initiated) and relaunched `lps-app` (`98d25c7d-...`) at 23:18:17 — the guest VM itself is healthy: `qemu`'s QMP reports `running:true`, and app-metrics show real CPU/network progress. However, the guest's `udhcpc` client has been broadcasting `DHCPDISCOVER` on its vif (`nbu1x1`→bridge `bn1`) every ~3s since boot (`secs` field climbing past 460+, same unanswered `xid`) with **no `DHCPOFFER` ever returned**, even though zedrouter already wrote the correct static host reservation (`10.11.12.128`) to `/run/zedrouter/dhcp-hosts.bn1/` at 23:18. The reason: the `dnsmasq` process serving `bn1` (pid 5275) is alive but wedged — its `/proc/.../wchan` shows it blocked in `unix_wait_for_peer`, and its UDP:67 socket has an ~80KB unconsumed receive-queue backlog of the very DHCPDISCOVER packets captured live on the bridge — i.e. dnsmasq is stuck (likely blocked writing a log line to the container's syslog/logging socket) and never services the queue. Consequently zedrouter's own `NetworkInstanceStatus` still shows `IPv4Addrs:null` for the app's MAC, the guest never gets `10.11.12.128`, and the controller's SSH DNAT rule (which targets that static address) has nothing listening behind it — exactly matching the test's "no reachable endpoint among [172.20.20.123:2222]" failure.

This signature (a wedged per-NI `dnsmasq` failing to answer DHCP after a device reboot) does not appear anywhere in `live-ledger.md`, including the prior `TestLPSSuite` entries for `TestAppLocalInfo` tonight and on earlier nights (those were a different, unrelated "unknown device UUID" broker/SDN-outage cascade) — so this looks like a new, previously-unrecorded failure mode, not a continuation of any known issue. No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestLocalNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.000407389s (excluding download) waiting for app "44845e14-89f8-4acb-bb86-0ff06129083d" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

###### Root cause

Live evidence confirms a stuck tag-resolution goroutine in `downloader`: at 23:26:22 both `acl-app-1` and `acl-app-2`'s content trees triggered fresh resolve requests (`daf2ddb8-...` and `ee8e0519-...`) for `lfedge/evetest-ubuntu-ctr:1.0` against the SDN's local HTTP registry mirror (`192.168.170.2:5000`). The downloader logged `lookupResolveStatus(...) not found` and dispatched a `manifestsDescImg(...)` call into the `remote.Get` (go-containerregistry) path — and then nothing further was ever logged for either request, even 9+ minutes later (confirmed live via `evetest eve app-info`, both apps are still `RESOLVING_TAG` right now). The registry itself is healthy — I confirmed `curl http://192.168.170.2:5000/v2/` returns `200` directly from the device — so this is a hung goroutine/request, not a registry or network outage; the device resolves the same registry as `insecure:false` (HTTPS), and HTTPS to that port fails fast with a TLS error when tested manually, yet the actual pillar code path never surfaces an error or times out, leaving `zedmanager`/`volumemgr` waiting forever.

This is a well-known, recurring issue per `live-ledger.md`: the identical "`runResolveHandler` goroutine hangs forever with no error/timeout while the registry stays reachable" signature was first seen **2026-10-31 (run #3)** on `TestFlowLog`/`TestSwitchNetInstanceACLsWithFlowLog`, and has recurred repeatedly since, including two occurrences in a single run shortly after that (both on `acl-app-1`-style resolves). Tonight's failure on `TestLocalNetInstanceACLsWithFlowLog` is the same unfixed downloader/OCI-resolve bug continuing to recur, not a new regression. No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

**Root cause:** This is the identical, already-known deadlock in the post-purge failover path. Live state confirms: `edge-dev1` (the designated node for app `failover-purge-app`, UUID `35e3d6d5-295b-4cec-a9dd-76759615eda8`) is `EVE_DEVICE_STATE_SUSPECT`/`NotReady` in `kubectl get nodes`, and the surviving `edge-dev2`/`edge-dev3` have continuously logged, every ~20s from 23:53 through 23:59:56 (the moment of investigation), `zedmanager.go:2059 getKubeAppActivateStatus(...): not designated ... onTheDevice false, statusRunning false` followed by `zedmanager.go:953 publishAppInstanceStatus(...) suppressed: IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster` — neither node ever takes over as backup DNID. `kubectl get vmirs -A`/`kubectl get vmi -A` on edge-dev2 both return "No resources found" cluster-wide, exactly matching the test's "found []" assertion.

This is the same `pkg/pillar/cmd/zedmanager/zedmanager.go:2059` mechanism already recorded for this exact test earlier tonight (run #13, same signature, same file/line) and documented repeatedly in `live-ledger.md` as a long-standing, well-known recurring issue dating back to the test's introduction in commit `98acf1411` (2026-10-18), reproducing in essentially every nightly run since (last noted recurring through at least run #11, 2026-11-08). This occurrence is a continuation of that unbroken streak, not a new bug. No PR diff was supplied for this investigation, so no code-relatedness assessment is given.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

###### Root cause

This is the identical, already-known `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` PVC-adoption race in `pkg/pillar/cmd/volumemgr`. Live `volumemgr` logs on `edge-dev1` confirm it directly: after vm1's reactivation (content tree `7197ae5e-d98f-4c17-98d7-306166ed71f5`, PVC `fbfaf27e-fe5b-4633-a8e2-a796a26acf26-pvc-0`), `contentTreeSatisfiedByPVCs` logs `no local volumes reference this content tree` at `00:34:54.327` and `00:34:58.103` — the matching `VolumeConfig`/PVC hadn't been republished to volumemgr yet — so `doUpdateContentTree` falls through the normal (non-PVC) path, finds all three blobs already `VERIFIED` in the local CAS from before reboot, and self-completes `VERIFIED → LOADING → LOADED` by `00:34:58.324`, landing on `LOADED` (108) instead of `REMOTELOADED` (125), exactly matching the failing assertion.

This does not share a root cause with this same run's earlier `TestVMAppPurgeDuringFailover` failure (that was the unrelated `zedmanager` designated-node purge/failover deadlock). Per `live-ledger.md`, this is a long-standing, well-known recurring issue specific to `TestClusterPVCRedownload`, first seen 2026-10-30 (run #2) and reproducing repeatedly since (19 occurrences logged, including runs on 2026-10-31, 11-03, 11-07, and 11-09/10 last night) — tonight's failure is a continuation of that unbroken, still-unfixed streak rather than a new bug.

### TestNodeClusterSuite: failure analysis

#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "81d61efc-92ce-43a1-8f65-6ab40ae7190d" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

Confirmed: `longhorn-manager`'s DaemonSet selects `tie-breaker-node=false`, and `edge-dev3` simply has no `tie-breaker-node` label at all (not even `false`), so it never gets a manager pod — exactly the same gap recorded in the ledger. This fully explains the live attach failures. I have enough evidence.

###### Root cause

Live evidence reproduces the exact same mechanism recorded repeatedly in `live-ledger.md`: the `longhorn-manager` DaemonSet is node-selected on `tie-breaker-node=false`, but `kubectl get nodes -L tie-breaker-node` shows `edge-dev1`/`edge-dev2` labeled `tie-breaker-node=false` while `edge-dev3` has **no label at all** — so `kubectl get pods -n longhorn-system -l app=longhorn-manager` shows manager pods only on `edge-dev1`/`edge-dev2`, never `edge-dev3`. The CDI upload pod for this app's volume import (`cdi-upload-22731722-f4a6-4d77-bd05-7bf288304fec-pvc-0`) was scheduled onto `edge-dev3` and has been stuck `ContainerCreating` for 31+ minutes, with `FailedAttachVolume` events repeating continuously: `unable to attach volume ... to edge-dev3: node edge-dev3 is not ready`. Since the import volume can never attach, `kubectl get vmi -A`/`get vmirs -A` show nothing anywhere in the cluster — the app never progresses past "waiting to be scheduled," matching the test's timeout on app `81d61efc-92ce-43a1-8f65-6ab40ae7190d` exactly.

This is a known, long-standing recurring issue per `live-ledger.md`: identical signature first seen 2026-11-02 (run #5), and recurring on 2026-10-29, -30, -31, 2026-11-01, -02, -04, -08, and most recently last night (run #13, 2026-11-10) — this is simply the next occurrence of that same unfixed Longhorn node-selector gap, not a new bug. No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestSecuritySuite: failure analysis

#### TestAppVTPMProtectedFailurePreservesState

##### Failure

```

Timed out after 300.001s.
The function passed to Eventually failed at /evetest/tests/security/vtpm_helpers_test.go:127 with:
read guest TPM NV marker: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 
WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded 
ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI 
ERROR: Could not load tcti, got: "(null)"

Unexpected error:
    <*fmt.wrapError | 0x288444c93140>: 
    failed to execute script over SSH for app b4810ae9-6b2e-4165-8170-9f581dfffcbc: Process exited with status 1 (stderr: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
    ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
    WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
    ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 
    WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded 
    ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI 
    ERROR: Could not load tcti, got: "(null)"
    )
    {
        msg: "failed to execute script over SSH for app b4810ae9-6b2e-4165-8170-9f581dfffcbc: Process exited with status 1 (stderr: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 \nERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 \nWARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused \nERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 \nWARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded \nERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI \nERROR: Could not load tcti, got: \"(null)\"\n)",
        err: <*ssh.ExitError | 0x2884450d1740>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

Live `domainmgr` logs show the exact same signature already diagnosed twice before in this ledger: at `23:09:00.446` the app's vTPM launch request to `vtpmd` hit `context deadline exceeded` (domainmgr's fixed `swtpmTimeout` client timeout, `pkg/pillar/hypervisor/kvm.go:2311-2320`), so domainmgr set `status.VirtualTPM = false` and continued on to build/boot the qemu domain **without any TPM device** (`pkg/pillar/cmd/domainmgr/domainmgr.go:1426-1429`/`2052-2055` show this path explicitly falls through rather than retrying or failing activation). Crucially, `vtpmd` itself succeeded just ~2s later — `"vTPM launched SWTPM instance with id: b4810ae9-..., pid: 58"` at `23:09:02.000` — but by then domainmgr had already moved on (domain created at `23:09:06`, RUNNING by `23:09:12`), so the guest came up with no `/dev/tpm0`/`/dev/tpmrm0` and no swtpm socket, exactly matching the test's TCTI "no such file"/connection-refused errors.

This is a known, recurring issue per `live-ledger.md`: the identical "domainmgr's fixed swtpm-launch timeout races vtpmd's slower-but-successful launch, producing a TPM-less guest" mechanism was first diagnosed on **2026-11-02** (`TestAppVTPMIdentitySurvivesReboots`, where a ~58s PCR-unseal blocked the handler against a 10s timeout) and recurred on **2026-11-05** (`TestAppVTPMBackupRecoversPrimaryCorruption`). Tonight's occurrence is the same unfixed domainmgr/vtpmd timeout race hitting a third test (`TestAppVTPMProtectedFailurePreservesState`), not a new regression — only the specific trigger for the slow/delayed `vtpmd` response differs (here likely contention from the test's preceding deliberate "protected failure" cycle at `23:06:54`, which logged a 424 "PCR-protected SWTPM state could not be loaded; state preserved" response just ~2 minutes earlier). No other failures were recorded in this run's artifacts to compare against for a shared root cause.
#### TestAppVTPMCorruptStateRetention

##### Failure

```
failed to onboard device "edge-dev": context deadline exceeded
```

##### Claude's conclusion

I have enough evidence now.

**Root cause:** This is not the vTPM timeout race documented earlier in this run (`TestAppVTPMProtectedFailurePreservesState`) — that device had already onboarded and was running an app; here `edge-dev` never onboarded at all (`evetest status` shows `EVE_DEVICE_STATE_UNDEFINED`, no interfaces, no IP ever assigned, and it never appears in Adam's access log). Live `evetest eve console-output` shows the guest itself stalled badly during boot: a kernel hung-task warning at `jbd2/vda9-8` blocked **122+ seconds** doing a journal commit, then containerd's first startup attempt failed outright (`"cannot start services, rebooting" error="waiting for containerd socket: containerd socket did not appear in time"`), and even the second containerd startup took **~75 seconds** between consecutive plugin-load log lines before finally reaching `"Connect containerd service"` — at which point the process was killed (`containerd: context canceled`), consistent with the harness's onboarding deadline (test started 23:15:56, failed at 23:27:xx, ~11 minutes later) expiring before the guest ever got far enough to reach Adam. This is a guest-side I/O-starvation stall, not a networking/SDN/broker issue.

This matches the recurring **"failed to onboard device ... context deadline exceeded"** symptom documented repeatedly in `live-ledger.md` going back to **2026-10-29**, recurring on 2026-11-01, 2026-11-03/04, and again later in tonight's own run (`TestApplicationGateway`, `TestEVEUpgradeKubevirtToKubevirt`, `TestThreeNodesUpgrade`). The ledger is explicit that this error string is a recurring *symptom class* with varying underlying mechanisms (broker/SDN outage, Proxmox VM-ID collisions, Proxmox API/TLS stress, and — closest to tonight's evidence — "a guest hang after containerd start" / host storage contention manifesting as iowait-driven boot stalls). Tonight's specific signature (jbd2 blocked for 122s, containerd socket delay, then a second multi-minute containerd stall) is a fresh instance of that same storage-contention mechanism, not a new bug and not the same root cause as the other vTPM-timeout failure already investigated in this run.
#### TestAppVTPMIsolation

##### Failure

```

Timed out after 300.001s.
The function passed to Eventually failed at /evetest/tests/security/vtpm_helpers_test.go:94 with:
Unexpected error:
    <*fmt.wrapError | 0x288446c758e0>: 
    failed to execute script over SSH for app bd60d956-855a-422d-bda5-1fcec641c0a4: Process exited with status 1 (stderr: )
    {
        msg: "failed to execute script over SSH for app bd60d956-855a-422d-bda5-1fcec641c0a4: Process exited with status 1 (stderr: )",
        err: <*ssh.ExitError | 0x2884439bc340>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

This is the same already-diagnosed `domainmgr`/`vtpmd` timeout race as the first failure in this run (`TestAppVTPMProtectedFailurePreservesState`), now hitting a third app. Live logs show: at `23:39:09.188` domainmgr logged `Failed to setup vTPM for bd60d956-855a-422d-bda5-1fcec641c0a4.1.1: ... context deadline exceeded` (its fixed swtpm-launch client timeout fired), but `vtpmd` actually succeeded 9s later — `"vTPM launched SWTPM instance with id: bd60d956-855a-422d-bda5-1fcec641c0a4, pid: 19"` at `23:39:18.000`. By then domainmgr had already moved on and built the qemu domain config without a TPM device — confirmed live: `dom1.cfg` for this domain contains zero references to "tpm", and `swtpm` is in fact running on the host for this app's UUID (pid 6217), but the guest never got a `/dev/tpm0`/`/dev/tpmrm0` node wired to it, which is exactly the `test -c /dev/tpmrm0 -o -c /dev/tpm0` check failing at `vtpm_helpers_test.go:94` (`waitForVTPMGuest`, called from `writeGuestTPMMarker` for app "vtpm-isolation-b").

This is a known, recurring issue per the ledger: first diagnosed on **2026-11-02** (`TestAppVTPMIdentitySurvivesReboots`) and recurring on **2026-11-05** (`TestAppVTPMBackupRecoversPrimaryCorruption`), and already seen twice earlier tonight in this very run (`TestAppVTPMProtectedFailurePreservesState` and implicitly in surrounding context). This is the same unfixed domainmgr/vtpmd timeout race hitting a fourth instance overall, not a new regression — the trigger for the slow vtpmd response here is unclear but the mechanism (domainmgr gives up before vtpmd reports success, then boots the guest TPM-less) is identical.

### TestStorageSuite: failure analysis

#### TestVaultZvolTrimReclaimsBlocks

##### Failure

```
Timed out waiting for cluster node "edge-dev" to become ready
```

##### Claude's conclusion

###### Root cause

Live evidence on `edge-dev` shows severe host-level storage I/O contention stalling cluster bring-up, not a product bug: `dmesg` shows kernel `hung_task` warnings for `kube-init`, `jbd2/zd16-8`, `jbd2/zd0-8`, `zvol_tq-0`, `z_wr_iss`, and `txg_sync` all blocked for 122+ seconds between 23:21–23:25, and `kube-init`'s own phase log (`/persist/kubelog/k3s-install.log`) shows the `INSTALLING` phase alone took **11m57s** (boot+12m59s) before containerd/k3s even started. By the time `WAIT_K3S_READY → DEPLOYING` fired at boot+18m50s (23:36:15), only ~2 minutes remained before the test's 20-minute timeout at 23:38:25, so kubevirt/longhorn/cdi pods (confirmed live via `kubectl get pods -A`) were still freshly `ContainerCreating`/`Init:0/1` (scheduled only 80–90s earlier) when the harness gave up. Live `top`/`uptime` right now still show 52% iowait and load average ~10 on a 4-vCPU box, consistent with ongoing contention.

This does **not** share the root cause of this exact test's only prior ledger occurrence (run #12, 2026-11-09): that one was a `kube-init` phase-reset bug where kubevirt/longhorn were structurally *never* deployed. Tonight they were deployed, just too late — this matches instead the broader, well-established "shared host storage contention" infra pattern documented repeatedly elsewhere in `live-ledger.md` (e.g. `TestEVEUpgradeKubevirtToKubevirt`, `TestApplicationGateway`, `TestSwitchNIPortConfigRace`), first recorded 2026-10-29 and recurring frequently since — so while this specific test hasn't failed this way before, the underlying mechanism is a known, recurring infra flake rather than a new EVE/pillar regression.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```

Timed out after 1200.000s.
Expected to satisfy: K3s node is ready
nodes:{name:"edge-dev"  conditions:{type:KUBE_NODE_CONDITION_TYPE_READY  set:true  last_transition_time:{seconds:1794351049}}  role_server:true  creation_timestamp:{seconds:1794351049}  api_server_sersion:"v1.34.2+k3s1"  internal_ip:"172.20.20.123"  schedulable:true  admission_status:NODE_ADMISSION_JOINING  node_id:"b8c6f999-c483-4064-a9bc-f1c8077a5144"}  storage:{health:SERVICE_STATUS_FAILED  transition_time:{seconds:1794351900}}  cluster_id:"00000000-0000-0000-0000-000000000000"
```

##### Claude's conclusion

I have enough to write the conclusion.

###### Root cause

Live evidence confirms this is the same storage-contention/iowait pattern already well documented in the ledger for `TestEVEUpgradeKubevirtToKubevirt`: `top` on `edge-dev` right now shows 22.4% iowait and a load average of ~8 on a 4-vCPU box, 22 minutes after boot. The k3s log shows the sqlite-backed kine datastore struggling badly — individual `INSERT INTO kine` calls taking 1–19s, repeated apiserver `http: Handler timeout` errors, and etcd-compaction lag — which cascades into Longhorn never getting its instance-manager running (`longhorn-manager` logs "cannot find a running instance manager for node edge-dev" continuously from ~23:06 through 23:11+, with the engine image only becoming ready at 23:08:48, ~20 minutes post-boot). This is exactly why `storage.health` stays `SERVICE_STATUS_FAILED` and the node never reaches `NODE_ADMISSION_JOINED`, even though `kubectl`'s own node-ready condition is already `true` — matching the test's "K3s node is ready" assertion failure precisely.

This is a known/recurring issue: per `live-ledger.md`, `TestEVEUpgradeKubevirtToKubevirt` has failed with this identical iowait/storage-contention signature (54% iowait, slow Longhorn/control-plane bring-up, storage health stuck `FAILED`) multiple times before — run #8 (2026-11-05) and run #10 (2026-11-07) both recorded the same mechanism — and the broader "host storage contention stalling tests past timeout" pattern goes back to at least 2026-10-29. Tonight's occurrence is a continuation of that unbroken, long-standing infra flake rather than a new bug. No PR diff was supplied for this investigation, so no relatedness assessment is given.
#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = EVE installation timed out or failed for device "edge-dev1", EVE installation timed out or failed for device "edge-dev3", EVE installation timed out or failed for device "edge-dev2"
```

##### Claude's conclusion

This is a well-documented, long-standing recurring issue. All three devices never completed installation within the fixed 10-minute installer timeout window (started ~23:18:04, deadline hit ~23:28:49), and teardown itself then failed/retried repeatedly with Proxmox lock contention (`can't lock file '/var/lock/qemu-server/lock-112.conf' - got timeout`) — a classic symptom of the shared Proxmox host being overloaded while provisioning/tearing down the 3 EVE VMs + 1 SDN VM concurrently. By the time I checked live state, the devices and SDN had already been fully torn down (`evetest status`/`eve console-output` report unknown devices, `evetest sdn status` reports "SDN client is not initialized"), consistent with the host never actually making installer progress rather than an EVE/pillar bug.

This shares the same root cause as the earlier `TestThreeNodesUpgrade` failures already recorded in this run's ledger (Proxmox host/broker overload during concurrent multi-VM provisioning), and per `live-ledger.md` this exact pattern — `TestThreeNodesUpgrade` installer timeouts under concurrent VM provisioning on an overloaded Proxmox host — is a long-standing, recurring known issue dating back to at least 2026-11-01 (run #4), recurring repeatedly through subsequent weeks and multiple times again tonight (this is now at least the third `TestThreeNodesUpgrade` instance in tonight's run alone). No PR diff was supplied for this investigation.

## [2026-11-10 -- 0.0.0-master-ddc4baa9 (run #13)](https://github.com/lf-edge/eve/actions/runs/42707740438)

[Full report](https://lf-edge.github.io/eve/test/master/runs/13/)

### TestAppsSuite: failure analysis

#### TestVMAppPurgeAfterPowerCycle

##### Failure

```
Device "edge-dev" failed to confirm the latest config (version 1): timed out waiting for LastProcessedConfig >= 2026-11-09 22:39:52.197874647 +0000 UTC
```

##### Claude's conclusion

###### Root cause

This failure happened during test *setup*, not the power-cycle logic itself — `gotest.json` shows the device successfully onboarded, fetched config version 1 at 22:39:53, and zedagent actually finished processing it (`parseConfig`/`parseConfigItems` completed, apps/volumes/content-trees all progressed to `DELIVERED`/`RUNNING`), but the harness never saw `LastProcessedConfig` reach that timestamp before its 120s deadline at 22:41:53. `LastProcessedConfig` is only reported via the periodic **metrics** POST (`handlemetrics.go`), and the live zedagent log shows the very first metrics send (`maybeUpdateMetricsTimer: ... no metricsTickerHandle yet` at 22:39:40) didn't fail until `2026-11-09 22:41:53.370|error|zedagent| client.Do (timeout 120000000000) fail: ... context deadline exceeded` — i.e. it hung for the *entire* 120-second client timeout before erroring, which is coincidentally the same window the harness was waiting on.

The likely trigger is the DPC churn that config version 1 caused right after that metrics POST was issued: zedagent flipped the active `DevicePortConfig` from the fallback `lastresort` key to the controller-supplied `zedagent` key (`CurrentIndex:1 → 0`, port logical-label `eth0 → ethernet0`), producing a ~35s window of `"no suitable IP address available"` and `"dial tcp: lookup adam.evetest ... server misbehaving"` errors (22:39:53–22:40:27) before DNS/routing stabilized. It's plausible the metrics request's underlying connection/route was invalidated mid-flight by that network-stack reconfiguration without the client noticing quickly, so it silently blocked for the full 120s instead of failing fast and retrying. After that one failed attempt, the next metrics send presumably succeeded (config/info polling resumed normally afterward).

This exact test/signature does not appear anywhere in `live-ledger.md`, so it is not a previously known/recurring issue — this is the first recorded instance. No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This confirms the live state matches the already-known mechanism: edge-dev1 (the designated node) is `SUSPECT`/down, and neither edge-dev2 nor edge-dev3 is taking over as backup designated node — both report `IsDNidNode:false`, `ScheduledOnThisNode:false`, `AppKubeStatus:NotInCluster` continuously, and `kubectl get vmirs/vmi` confirm no VMIRS/VMI exists anywhere, exactly matching the test's assertion.

Given the ledger already contains an entry for this identical failure within tonight's run #12 with the same root cause, and live evidence now reproduces it exactly, I have enough to conclude.

**Root cause:** Live evidence on edge-dev2/edge-dev3 confirms a deadlock in the post-purge failover path for app `failover-purge-app` (`e04c1994-e7fd-487b-91c1-c791a4a5683c`): `edge-dev1` (its designated node) is `EVE_DEVICE_STATE_SUSPECT`, and since purge was issued at 23:29:01, both surviving nodes' zedmanager/zedkube loops have logged, continuously and unbroken through at least 23:45:39, `getKubeAppActivateStatus(...): not designated, ... onTheDevice false, statusRunning false` / `IsDNidNode:false ScheduledOnThisNode:false AppKubeStatus:NotInCluster` — i.e. neither node ever takes over as backup DNID, so `kubectl get vmirs/vmi` show nothing for the app anywhere in the cluster, exactly matching the test's "found []" failure. This is the identical `pkg/pillar/cmd/zedmanager/zedmanager.go:2059` mechanism already investigated and recorded in `live-ledger.md` for this same run (run #12, 2026-11-09) and is noted there as a long-standing, well-known recurring issue dating back to the test's introduction in commit `98acf1411` (2026-10-18), reproducing with the identical signature in essentially every nightly run since then through at least run #11 (2026-11-08). This occurrence does not share a root cause with the other failures investigated tonight (`TestClusterPVCGCDeletesOnlyOrphans`'s GC-timeout-vs-node-flap, or `TestClusterPVCRedownload`'s PVC-adoption-timing race) — it's a continuation of this specific, unbroken, known-recurring streak rather than a new bug.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

**Root cause:** Live `volumemgr` logs on `edge-dev1` show the identical PVC-adoption race already documented in the ledger for this test: at `00:19:26.093` (post-reboot reactivation of the content tree `27448d31-c4a2-4423-a8b5-25ebd0cefa8f`), `contentTreeSatisfiedByPVCs` logs `no local volumes reference this content tree` because the matching PVC/volume hadn't been re-published to volumemgr yet, so `doUpdateContentTree` falls through the normal (non-PVC) path, finds all three blobs already `VERIFIED` in the local CAS from before reboot, and self-completes `VERIFIED → LOADING → LOADED` by `00:19:30.284` — landing on `LOADED` (108) instead of `REMOTELOADED` (125), exactly matching the test's failing assertion.

This is the same `pkg/pillar/cmd/volumemgr` content-tree/PVC-publish-timing bug already investigated earlier in this same run (recorded in `live-investigation.md`'s prior `TestClusterPVCRedownload` entry at a different timestamp with the identical mechanism and log signature), not a new occurrence. Per `live-ledger.md`, this is a long-standing, well-known recurring issue for `TestClusterPVCRedownload` specifically — first seen 2026-10-30 (run #2) and recurring repeatedly since (16 occurrences logged in the ledger, including last night 2026-11-07/run #10) — so tonight's failure is a continuation of that unbroken streak rather than a new bug.

### TestNodeClusterSuite: failure analysis

#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "19d46a16-2849-4164-bf5e-baca6b799aa9" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

This is the only failure recorded in this run's artifact set so far. I have enough evidence to write the conclusion.

###### Root cause

Live evidence confirms this is the same known Longhorn "tie-breaker-node" gating bug already recorded repeatedly in the ledger: `kubectl get nodes -L tie-breaker-node` shows `edge-dev1`/`edge-dev2` labeled `tie-breaker-node=false` while `edge-dev3` has **no label at all**, so the Longhorn `longhorn-manager` DaemonSet (node-selected on `tie-breaker-node=false`) never schedules a manager pod there — `kubectl get pods -n longhorn-system -l app=longhorn-manager` shows only `edge-dev1`/`edge-dev2`, and `edge-dev3`'s Longhorn node object logs `Manager pod is missing`. The CDI upload pod for the app's volume import (`cdi-upload-e7d29ee3-...-pvc-0`) landed on `edge-dev3` and has been stuck `ContainerCreating` for ~31 minutes, with `FailedAttachVolume` events repeating every few minutes: `unable to attach volume ... to edge-dev3: node edge-dev3 is not ready`. Since the volume import can never complete, `volumemgr`/`domainmgr` never get a ready volume to build the VMI from, so app `19d46a16-...` never progresses past "waiting to be scheduled" — matching the test's timeout exactly.

This is the identical mechanism already logged for `TestClusterVMApp` multiple times, first seen 2026-11-02 (run #5) and recurring on 2026-10-29, -30, -31, 2026-11-01, -02, -04, and -08 (last night) per `live-ledger.md` — a long-standing, unfixed gap where Longhorn's node selector excludes a node that volume scheduling can still target. This run has no other recorded failures to compare against, so there's no shared-root-cause question to resolve. No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestTelemetrySuite: failure analysis

#### TestDeviceLogs

##### Failure

```

Timed out after 600.001s.
the kernel log probe was not uploaded to the controller
Expected
    <<-chan evetest.LogMsg | len:0, cap:100>: 0x2532e8b3c930
to receive something.
```

##### Claude's conclusion

###### Root cause

Live evidence confirms the pillar/EVE telemetry pipeline worked correctly here: the kernel log probe `evetest-log-probe-device-logs-1794264454591496499` was emitted on the device and is present verbatim in Adam's on-disk DB (`adam-db/device/071129d1-.../logs/01794264434550344789`, msgid `7248`, timestamped `2026-11-09T22:47:33.538Z`) — ingested within about a second of generation, roughly 9.5 minutes before the test's 600s timeout fired at `22:57:34`. `evetest status` and `adam-stdout` show the device is still healthy and online right now, continuously polling/uploading `config`/`metrics`/`newlogs` every few seconds straight through the timeout window. So the log was generated, uploaded, and persisted well inside the window; the test's live `device.WatchLogs(...)` channel simply never delivered the already-persisted entry (`helpers_test.go:187`, `expectKernelLogProbe`).

This is the identical, long-standing `AdamClient.SubscribeToDeviceLogs` live-subscription bug already documented repeatedly in `live-ledger.md` — same "data lands in Adam's DB but never reaches the watch channel" signature, first recorded 2026-10-29 (`TestKernelPanicReport`), recurring 2026-11-04, 2026-11-07, and again in last night's run #12 (`TestDeviceLogs` and `TestKernelPanicReport` both, ~2026-11-08 23:48–00:25). Tonight's occurrence is a continuation of that same unbroken, evetest-side streak, not a new pillar/EVE regression.
#### TestRemoteLogLevelNone

##### Failure

```

Failed after 0.127s.
The function passed to Consistently failed at /evetest/tests/telemetry/newlogd_test.go:233 with:
EVE uploaded device logs generated after the reboot even though every remote log level is set to "none".
846 log messages; by source: zedagent=267 nim=142 diag=67 zedrouter=65 ledmanager=51 domainmgr=45 wstunnelclient=33 loguploader=23 monitor=21 nodeagent=19 zedmanager=19 newlogd=17 wwan=13 vector=11 vector.out=10 dnsmasq=9 vaultmgr=9 dhcpcd=8 tpmmgr=5 vcomlink=5 =3 debug=3 kernel=1
  2026-11-09T23:07:40Z [debug] newlogd: {"file":"/newlog/vendor/github.com/lf-edge/eve/pkg/pillar/agentlog/loglevel.go:83","func":"github.com/lf-edge/eve/pkg/pillar/agentlog.HandleGlobalConfig","level":"debug","msg":"HandleGlobalConfig(newl...
  2026-11-09T23:07:40Z [error] zedagent: {"file":"/pillar/pubsub/socketdriver/publish.go:373","func":"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver.(*Publisher).serveConnection","level":"error","msg":"serveConnection(zedagent/ConfigI...
  2026-11-09T23:07:40Z [info] zedagent: {"diff":"  types.ZedAgentStatus{\n  \tName:            \"zedagent\",\n- \tConfigGetStatus: 0,\n+ \tConfigGetStatus: 4,\n  \tRebootCmd:       false,\n  \tShutdownCmd:     false,\n  \t... //...
Expected
    <int>: 846
to be zero-valued
```

##### Claude's conclusion

I have enough evidence now to write the root cause analysis.

###### Root cause

Live evidence from the Adam DB (`adam-db/device/5e6d1f34.../logs/01794265668629423360`) shows the first uploaded entry is newlogd's own `HandleGlobalConfig(newlogd, false)` call at `2026-11-09T23:07:40.186Z`, immediately followed by a zedagent log showing `ConfigGetStatus: 0 -> 4` (`types.ConfigGetReadSaved` per `pkg/pillar/types/zedagenttypes.go:534-538`). Per `pkg/pillar/cmd/zedagent/handleconfig.go:819-883`, when zedagent can't yet reach the controller right after a reboot, it falls back to the on-disk `/persist/checkpoint/lastconfig` checkpoint and applies that before any live controller fetch completes. The flood of 846 messages spans essentially every agent's startup (zedagent, nim, diag, zedrouter, domainmgr, loguploader, newlogd, etc.), consistent with each agent's own pubsub `HandleGlobalConfig` handler not yet having applied the "remote loglevel = none" setting during its earliest startup moments — agents default to a non-"none" remote log level until their first `GlobalConfig` update is processed, so the entire early-boot log burst gets uploaded regardless of the controller's current "none" setting. There's also a `zedagent: serveConnection(...) writev: broken pipe` error at the same instant, indicating a subscriber's socket wasn't ready yet — further evidence this is a boot-sequencing/config-propagation race rather than a deliberate upload.

This does not share the root cause of this run's earlier `TestDeviceLogs` failure (that was an evetest-side `AdamClient.SubscribeToDeviceLogs` watch-channel bug where data landed in Adam's DB but wasn't delivered to the test's live channel — a test-harness issue, not a device behavior issue). This also isn't a previously recorded issue — `TestRemoteLogLevelNone` doesn't appear anywhere in `live-ledger.md`, so this looks like a new finding: a boot-time race where early-boot agent logs escape the "none" remote log level until each agent's `GlobalConfig` is locally applied.

## [2026-11-09 -- 0.0.0-master-8d1b7670 (run #12)](https://github.com/lf-edge/eve/actions/runs/42527962373)

[Full report](https://lf-edge.github.io/eve/test/master/runs/12/)

### TestAppsSuite: failure analysis

#### TestMemoryPressureEvents

##### Failure

```

Timed out after 180.001s.
memory-monitor's handler wrote no complete report after "": map[dir:2026-11-09-01-19-52 handler.log:Warning: Problem (retrying all errors). Will retry in 16 seconds. 1 retry left.   0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0 curl: (7) Failed to connect to 127.0.0.1 port 6543 after 0 ms: Could not connect to server + cleanup + set +x memstat_eve.out: memstat_pillar.out:]
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

Confirmed live: `/persist/coverage/` has fresh `covcounters.*` files (this is a `COVER=y` build) and `zedbox` (pid 2557) is alive and healthy, but port 6543 is refused when curled directly on the device — identical to the prior investigations.

**Root cause:** This nightly build has `COVER=y` set (confirmed by fresh `covcounters.*` files under `/persist/coverage/`). On coverage builds, `agentlog.MaybeInitSigUsr2` is a deliberate no-op since `SIGUSR2` is reserved for the coverage-flush handler, so `agentlog.ListenDebug`'s pprof server on port 6543 never starts. `memory-monitor-handler.sh`'s `eve http-debug` step (which signals zedbox and then curls `127.0.0.1:6543`) therefore exhausts its retries and aborts under `set -e` before writing `memstat_pillar.out`/`memstat_eve.out` — exactly the failure signature seen (zedbox itself is alive and healthy at pid 2557, unrelated to any app/memory issue).

This is a known, recurring issue per `live-ledger.md`: the identical signature (same message, same port-6543/coverage mechanism) was already documented on **2026-10-28**, recurred on **2026-10-29 (run #1)**, and again on **2026-11-01** — it appears specifically on coverage-enabled nightly builds and has been unfixed since at least 2026-10-28. No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 600.001s.
Expected to satisfy: Device has enrolled NEW certificate for 802.1x AND deleted the obsolete certificate
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7917 storage:40006 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-11.0" serialNumber:"IEQAKL9R" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"127.0.0.1:53" DNSsearch:"test."} storageList:{mountPath:"/persist/certs"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{device:"nbd2"} storageList:{mountPath:"/persist/lost+found"} storageList:{mountPath:"/persist/status"} storageList:{device:"vda9" total:40953 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{device:"nbd11"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{device:"vda" total:65536} storageList:{mountPath:"/persist/nettrace"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{mountPath:"/" total:3959} storageList:{device:"nbd5"} storageList:{device:"nbd14"} storageList:{mountPath:"/persist/checkpoint"} storageList:{device:"nbd12"} storageList:{mountPath:"/persist/vault"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{device:"nbd15"} storageList:{device:"nbd13"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{device:"nbd8"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"nbd1"} storageList:{device:"nbd6"} storageList:{mountPath:"/hostfs" total:244} storageList:{mountPath:"/persist/log"} storageList:{device:"nbd3"} storageList:{mountPath:"/persist/tmp"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"nbd4"} storageList:{device:"nbd7"} storageList:{device:"vda7" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"} storageList:{mountPath:"/persist" total:40006 storageLocation:true} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/clear"} storageList:{mountPath:"/config" total:5} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"nbd0"} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/persist/newlog"} storageList:{mountPath:"/persist/vault/volumes"} bootTime:{seconds:1794178346} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-pr42527962373-8d1b7670-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"c11dd6d5-4995-4b09-a11f-52dda8315bff" lastRebootReason:"NORMAL: First boot of device - at 2026-11-08T22:53:01.445259296Z" lastRebootTime:{seconds:1794178381 nanos:445259296} systemAdapter:{status:{version:1 key:"zedagent" timePriority:{seconds:1794178461 nanos:12845918} lastSucceeded:{seconds:1794178465 nanos:59792472} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.20.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.20.123" defaultRouters:"172.20.20.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{timestamp:{seconds:1794178465 nanos:59715861}} usage:PhyIoUsageMgmtAndApps networkUUID:"df752cc4-fdcd-44b9-9fb4-7d2165250076" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794178461 nanos:12845918}} pnac_status:{enabled:true state:SUPPLICANT_STATE_AUTHENTICATED last_auth_timestamp:{seconds:1794178468}}}}} HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1794178447 nanos:108691149} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"\x93oZ'{uӎ\x8f\xb3\xa8\xae\x14:Zl\xa9Af4\xd3\xe1V\xe4.\x1d\x9a$\x80\xfeϪ"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} last_boot_reason:BOOT_REASON_FIRST hardware_watchdog_present:true reboot_inprogress:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_REBOOTING storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev" enrolled_certs:{cert_enrollment_profile_name:"scep-test" subject:{common_name:"edge-dev" organization:"lf-edge" country:"US"} issuer:{common_name:"SCEP CA" organization:"Example" organizational_unit:"Lab" country:"US"} san_uri:"urn:Name:edge-dev" issue_timestamp:{seconds:1794177866} expiration_timestamp:{seconds:1825714466} renew_period_percent:50 sha256_fingerprint:"32a3fcf502d1068ccb6a20401eb5a902ed84dae961e6b1bfb65eda3c3abb0657" status:CERT_STATUS_AVAILABLE}
```

##### Claude's conclusion

###### Root cause analysis

Live evidence shows the device successfully reached the authenticated VLAN once (`172.20.20.123`, `pnac_status: SUPPLICANT_STATE_AUTHENTICATED`) and processed config version 1, but then the test's `scep-profile-replaced` step triggered a reboot of `edge-dev` at 22:54:50. After that reboot, the device never came back: `evetest eve logs` shows only a single log line reaching the controller since the reboot (a `diag` subscribe message at 22:56:31), and `evetest status`/`evetest eve info` confirm the device is now stuck in `EVE_DEVICE_STATE_SUSPECT` with the last known deviceinfo still frozen at `REBOOTING`. Crucially, `evetest eve ssh` fails with "no reachable endpoint among [172.20.10.123:22]" — i.e. the device's current IP is on the pre-auth/onboarding VLAN (172.20.10.0/24), not the post-auth VLAN (172.20.20.0/24) it was on before the reboot, even though the serial console shows the OS itself booted fine (full boot sequence through to a login prompt by ~22:56:20) and `evetest sdn status` reports the SDN/broker tunnel itself is healthy with no errors. This points to the device failing to re-establish 802.1x (EAP-TLS) port authentication after the reboot that followed the SCEP-profile swap — it's parked on the pre-auth VLAN with no path back to the controller, so it can neither report the renewed certificate nor delete the obsolete one, which is exactly what the test is waiting on.

This is a different mechanism from both prior ledger entries for this suite tonight: `TestPNACWithoutProxy`'s only previous recorded failure (a quick 5.7s SSH/curl "stdout inactivity" timing race right after the VLAN transition, with the device never leaving `ONLINE`) and `TestPNACWithProxy`'s failure (an SDN-VM gRPC tunnel `no route to host` flake occurring entirely before any device existed). I found no prior ledger entry matching this specific signature (reboot after SCEP profile replacement leaving the device stranded on the pre-auth VLAN until `SUSPECT`), so this looks like a new, not-previously-recorded failure mode rather than a continuation of either known issue. No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestLimitsSuite: failure analysis

#### TestManyAppInterfaces

##### Failure

```

Told to stop trying after 70.045s.
pillar did not survive: the console shows: Rebooting EVE. Reason: panic: send on closed channelWatchdog report for IMGA EVE version 0.0.0-pr42527962373-8d1b7670-kvm-amd64 at 2026-11-08T22:58:25+00:00: 3 /run/zedbox.pid
At one point, however, the function did return successfully.
Yet, Eventually failed because the matcher was not satisfied:
The function passed to Eventually failed at /evetest/tests/limits/helpers_test.go:128 with:
all 15 applications are reported running has not happened yet
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

Matches the ledger exactly and the code path is unchanged (no recent commit touched this close/send race). This is confirmed, known, recurring.

**Root cause:** `zedbox` panicked with `panic: send on closed channel` in goroutine 9062, at `pkg/pillar/cmd/downloader/download.go:473` inside `objectMetadata`'s helper goroutine (`receiveChan <- nil`) — confirmed live via `/persist/reboot-stack` on the device, byte-for-byte identical stack trace to the one already diagnosed in this ledger. This is a close-vs-send race: `receiveChan` is created per download object in `downloadHandler.create()` and explicitly `close()`d in `downloadHandler.delete()`, with no synchronization stopping an in-flight `objectMetadata` goroutine from writing to it after close. `TestManyAppInterfaces` provisions 15 apps with many interfaces, driving a burst of concurrent downloader config creates/deletes that makes the race far more likely to fire, exactly matching tonight's symptom (`all 15 applications are reported running` never went true because zedbox rebooted mid-run).

This is a **known, recurring issue** per the ledger — first seen on **2026-11-05**, with the identical stack trace, same test, and same root-cause writeup already recorded; it is not a new bug. No other test failed in this run to compare against for a shared cause, and no PR diff was supplied for this investigation.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 360.000s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:218 with:
the cluster still lists PVC "8b259c65-2d65-40f8-a9ae-a3066474cf7d-pvc-0"
Expected
    <map[string]bool | len:6>: {
        "d06696ff-5b0e-45f8-96f3-f3a9609c4024-pvc-0": true,
        "360f634c-ba8f-472b-beb0-47829acccd1b-pvc-1": true,
        "5e71a7a1-c641-49ac-8d22-a288952fd99b-pvc-0": true,
        "8b259c65-2d65-40f8-a9ae-a3066474cf7d-pvc-0": true,
        "8b259c65-2d65-40f8-a9ae-a3066474cf7d-pvc-1": true,
        "9a7ca081-3e99-4fb3-bc78-ff997ebcf66d-pvc-0": true,
    }
not to have key
    <string>: 8b259c65-2d65-40f8-a9ae-a3066474cf7d-pvc-0
```

##### Claude's conclusion

###### Root cause

This is a genuinely new failure signature for `TestClusterPVCGCDeletesOnlyOrphans` — every prior ledger entry for this test failed earlier, at `pvcgc_test.go:115` (volume never even gets created, due to the unrelated tie-breaker-node/Longhorn `nodeSelector` scheduling gap). Tonight's run got past that stage and failed later, at line 218, on the actual GC-deletion assertion — there is no prior entry in `live-ledger.md` matching this line/signature, so it is not a known recurring issue.

Live evidence: at the time of failure, `kubectl get pvc -A` on `edge-dev1` showed the orphan PVC `8b259c65-...-pvc-0` (generation 0 of volume `8b259c65-...`, superseded by the currently-referenced generation 1, `...-pvc-1`) still `Bound`. Checking again a couple of minutes later, the PVC was gone — the garbage collection did complete, just after the test's 360s `Eventually` had already given up. `gotest.json` shows `edge-dev3` flipping `ONLINE → SUSPECT` at `00:18:55`, roughly a minute before the test's timeout fired at `00:19:54` — consistent with `pkg/pillar/cmd/volumemgr/retryvolumedelete.go`'s own stated rationale ("the owner node can be unreachable for a while during a purge or a cluster update") for why a volume delete can be bounded-retried across multiple gc ticks rather than completing immediately. That retry/backoff logic (added in commit `55edeb4f3`, "volumemgr: retry failed volume deletes instead of leaking them", well before tonight) appears to work correctly — it didn't leak the orphan — but its retry/backoff window outlasted the test's fixed 360s timeout, which is either a test timing assumption that's too tight for a node-flap window, or exposes that the delete path is slower to recover from a brief node-unreachability blip than expected.

This does not share a root cause with any other failure already logged tonight (no other suite failures have been investigated in this run yet), and since no PR diff was provided for this investigation, no relatedness assessment is given.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

**Root cause:** This is a live reproduction of the same `getKubeAppActivateStatus` deadlock (`pkg/pillar/cmd/zedmanager/zedmanager.go:2059`) already investigated multiple times in this run's ledger. Live evidence on edge-dev2 confirms it precisely: `AppInstanceStatus` for `failover-purge-app` (uuid `b66e736e-a66c-4dd0-bef8-70fb4290b615`) shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-09T00:46:22Z`, `Activated:false`, `IsDesignatedNodeID:false`, and zedmanager is *still actively logging right now* an unbroken loop of `getKubeAppActivateStatus(...): not designated, node f262faeb-..., onTheDevice false, statusRunning false` every ~20s (through 01:01:42, seconds before I checked). `evetest status` confirms edge-dev1 (the app's designated node) is `EVE_DEVICE_STATE_SUSPECT`, deliberately downed for this failover scenario — once the purge tears down the old VMIRS, only the designated node can originate a replacement, and it's offline, matching the test's `found []`.

This does not share a root cause with the earlier `TestClusterPVCGCDeletesOnlyOrphans` failure investigated in this run (a tie-breaker/Longhorn scheduling gap, unrelated code path). Per `live-ledger.md`, this exact test/failure/mechanism is a long-standing, well-known recurring issue dating back to the test's introduction in commit `98acf1411` (2026-10-18) — it has reproduced with the identical signature in essentially every nightly run since then, through at least run #11 (2026-11-08, last night). Tonight's occurrence continues that unbroken streak; it is not a new bug.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

This confirms line 2795 (run #2, 2026-10-30) is the earliest occurrence of this exact race signature. I have enough evidence now.

**Root cause:** Live `volumemgr` logs on `edge-dev1` show the exact same `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` race already documented repeatedly in `live-ledger.md`. For vm1's ContentTreeStatus `ba75129a-0418-4a2e-8e9a-fdb9846ec357`, at `01:36:25.872` and `01:36:29.639` (right after the post-reboot reactivation), `contentTreeSatisfiedByPVCs` logged `no local volumes reference this content tree` because the matching `VolumeConfig`/PVC hadn't been published to volumemgr yet, so `doUpdateContentTree` fell through to the normal path, found all three blobs already `VERIFIED` in the local CAS from before reboot, and self-completed `VERIFIED → LOADING → LOADED` within the same reconcile pass by `01:36:29.821` — landing at `LOADED` (108) instead of `REMOTELOADED` (125), exactly matching the test's assertion. This does not share a root cause with either of the other failures already investigated in this run (`TestClusterPVCGCDeletesOnlyOrphans`'s GC-timeout-vs-node-flap issue, or `TestVMAppPurgeDuringFailover`'s zedmanager purge-after-failover deadlock) — it's the same `pkg/pillar/cmd/volumemgr/acceptclustercontenttree.go`/`updatestatus.go` PVC-adoption-timing bug. Per `live-ledger.md`, this is a long-standing, well-known recurring issue for `TestClusterPVCRedownload` specifically, first seen 2026-10-30 (run #2) and recurring on 2026-10-31, 2026-11-03, 2026-11-07 (last night), and several other nights since — tonight is a continuation of that unbroken streak, not a new bug.

### TestNodeClusterSuite: failure analysis

#### TestMgmtProxy

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev2": failed to create VM 107 for device "eve-9749e40e-edge-dev2": 500 user name not set
```

##### Claude's conclusion

###### Root cause

The failure happened entirely on the Proxmox broker side, before any EVE device booted: `gotest.json` shows the broker successfully provisioned `edge-dev3` (VM 107) and `edge-dev1` (VM 108), but then failed creating `edge-dev2`'s VM with `failed to create VM 107 for device "eve-9749e40e-edge-dev2": 500 user name not set` — the same VM ID (107) just used for `edge-dev3`. Live checks confirm there's nothing further to inspect: `evetest status` reports "No EVE devices found" and `evetest sdn status` reports "SDN client is not initialized" — the whole device/SDN setup aborted before any guest ever ran.

This exact `"500 user name not set"` string has never appeared before in `live-ledger.md`, so it's a new error signature, but it fits the same broad, well-documented class of Proxmox host ("farfalle") API/auth instability recorded repeatedly since at least 2026-11-01 — prior nights show the identical setup-stage failure mode with different symptoms: TLS handshake timeouts on `qmcreate`, `"500 got no worker upid - start worker failed"`, and storage-lock timeouts, all occurring during concurrent VM creation across sibling devices. The VM-107 reuse (just freed from `edge-dev3` and immediately handed to `edge-dev2`) also echoes the VM-ID-collision pattern seen in the most recent ledger entry (2026-11-08, run #11, `TestPNACWithoutProxy`).

This is not shared with any other failure in *this* run (there are no other investigated failures in this directory yet to correlate against), and it is a pure broker/Proxmox infrastructure flake, not a pillar/EVE code defect — just a previously-unseen manifestation of the ongoing "farfalle" Proxmox contention issue rather than a brand-new failure class.
#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "984bf42a-a407-42eb-a94e-5f62efdca316" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

Confirmed: no `longhorn-manager` pod scheduled on edge-dev3 at all, consistent with the nodeSelector `tie-breaker-node=false` gating it out since edge-dev3 lacks that label entirely.

###### Root cause

**Root cause:** This is the same known "tie-breaker-node" / Longhorn-gating bug already recorded multiple times in `live-ledger.md`. The live cluster is otherwise fully healthy (`kubectl get nodes` shows all three nodes `Ready`, k3s API/control-plane fine), but `edge-dev3` carries no `tie-breaker-node` label at all, while `edge-dev1`/`edge-dev2` are labeled `tie-breaker-node=false`. The `longhorn-manager` DaemonSet is scoped with `nodeSelector: tie-breaker-node=false`, so edge-dev3 never gets a manager pod (`kubectl get pods -n longhorn-system -l app=longhorn-manager` shows only edge-dev1/edge-dev2), leaving the Longhorn node object for edge-dev3 `Ready=False` with reason `ManagerPodMissing`. App `984bf42a`'s CDI-upload pod got scheduled onto edge-dev3 and its PVC attach has been failing continuously for 31 minutes with `AttachVolume.Attach failed ... node edge-dev3 is not ready`, so the root/scratch volumes never attach, the VM is never created (`kubectl get vmi` returns nothing), and the app sits forever unscheduled — matching the test's timeout exactly.

This is the identical mechanism already investigated for `TestClusterVMApp` in this same ledger (first seen 2026-11-02, run #5, with `edge-dev3` missing the label after being reused across cluster tests, and recurring on several subsequent nights) — a standing, unfixed gap in `volumehandlers/csihandler.go`'s `PrepareVolume`/`kubeapi.WaitForLonghornReady` not accounting for nodes the Longhorn DaemonSet selector excludes. It is not the same failure as the earlier-tonight `TestMgmtProxy` incident in this run (that was a stuck `volumemgr` CDI-upload-503 retry bug, a distinct mechanism). `TestClusterVMApp` overall is a chronically recurring/flaky test (seen on 2026-10-29, -30, -31, 11-01, 11-02, 11-04, and now 11-08) under several different mechanisms, but this specific tie-breaker-label variant has been known since 2026-11-02.

### TestTelemetrySuite: failure analysis

#### TestDeviceLogs

##### Failure

```

Timed out after 600.000s.
the kernel log probe was not uploaded to the controller
Expected
    <<-chan evetest.LogMsg | len:0, cap:100>: 0x2450780fab0
to receive something.
```

##### Claude's conclusion

**Root cause:** This is the same evetest-side bug that's been recurring in `TestTelemetrySuite`. Live evidence confirms the pillar/EVE side worked correctly — `dmesg` on the live device still shows the kernel log probe line `evetest-log-probe-device-logs-1794181683485717835` (at kernel uptime 143.6s), and Adam's own on-disk DB snapshot (`adam-db/device/.../logs/01794181669918967309`) contains that exact probe string, ingested as a `kernel` severity log entry with `msgid:7091` at `2026-11-08T23:48:02.745Z` — just ~15s after the test emitted it at 23:48:03, and nearly 10 minutes before the 600s timeout at 23:58:03. So the log was generated, uploaded by newlogd, and persisted by Adam well inside the window; the test's live `device.WatchLogs(...)` channel (`<-chan evetest.LogMsg`) simply never delivered the already-persisted entry.

This is the identical mechanism documented repeatedly in the ledger for `TestTelemetrySuite` — a race/bug in `AdamClient.SubscribeToDeviceLogs`'s live log-streaming subscription missing entries that are already sitting in Adam's store. It was first recorded **2026-10-29** (`TestKernelPanicReport`), and has recurred since on **2026-11-04** and **2026-11-07** (same suite, same "data in Adam's DB but never delivered to the watch channel" signature, just probing a different log line each time — kernel panic stack trace vs. this run's generic kernel-log probe). It does not share a root cause with any other failure in this run (no other failures have been investigated yet in this run's ledger entry). No PR diff was provided for this investigation, so no relatedness assessment is given.
#### TestKernelPanicReport

##### Failure

```

Timed out after 600.001s.
the kernel panic stack trace header was not uploaded
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

Confirmed. The file written at 00:16:09 contains the "sysrq triggered crash" header string — well within the test's 600s window that started around 00:15:11 and timed out at 00:25:20.

###### Root cause

This is the same known evetest-side bug recorded repeatedly in the ledger. The pillar/EVE telemetry pipeline worked correctly: the kernel panic was triggered at 00:12:29, the device rebooted, and nodeagent logged the stack-trace header (`"[kernel panic #331]: ... Kernel panic - not syncing: sysrq triggered crash"`) at 00:15:07.314, with newlogd uploading the containing chunk (now sitting in `keepSentQueue`, not `failedUpload`). Adam's own on-disk store (`adam-db/device/.../logs/01794183315361415313`, written 00:16:09) confirms the controller received and persisted that exact header string — about a minute after it was generated and nine minutes before the test's 00:25:20 timeout.

This is the identical signature (`Timed out ... ReceiveMatcher's channel *must* receive something`, header string present in Adam's DB but never delivered to `device.WatchLogs(...)`) documented in `live-investigation.md` for `TestDeviceLogs` earlier in this same run, and is the same recurring `AdamClient.SubscribeToDeviceLogs` live-subscription bug the ledger records for `TestKernelPanicReport` going back to **2026-10-28/2026-10-29**, recurring again on **2026-11-04** and **2026-11-07**. This is a long-standing, known, recurring evetest-side issue, not a pillar/EVE regression, and shares the same root cause as the earlier `TestDeviceLogs` failure in this run.

## [2026-11-08 -- 0.0.0-master-90f9b3d8 (run #11)](https://github.com/lf-edge/eve/actions/runs/42418484474)

[Full report](https://lf-edge.github.io/eve/test/master/runs/11/)

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```
failed to onboard device "edge-dev": context deadline exceeded
```

##### Claude's conclusion

###### Root cause

The evetest broker's Proxmox provisioning assigned the **same VM ID (106)** to both the EVE device and the SDN VM: `gotest.json` shows `Device "eve-02d27b64-edge-dev" prepared as Proxmox VM 106` at 22:19:24, immediately followed by `Device "sdn-02d27b64" prepared as Proxmox VM 106` at 22:19:33 — a VM-ID collision. Live evidence confirms the EVE VM never actually ran as a result: `evetest eve console-output` shows only the single stale `starting serial terminal on interface serial0` line with zero further output over 20+ minutes, the onboarding-network dnsmasq lease file is empty (no DHCPDISCOVER ever received), and hostapd's log shows no EAPOL packets at all from the device's port — i.e. the guest never booted far enough to touch the network, consistent with its VM having been clobbered by the colliding SDN VM. This left the device stuck in `EVE_DEVICE_STATE_UNDEFINED` until the onboarding wait timed out.

This is the same mechanism as an earlier entry in this run's `live-ledger.md` (the `edge-dev1`/VM-111 collision under `TestThreeNodesCluster`-style multi-VM provisioning), which showed the identical signature: console output frozen at the initial serial-terminal line, no IP ever discovered, device permanently `UNDEFINED`. It also fits the broader, well-documented recurring pattern of Proxmox broker/host instability during VM provisioning (truncated `"unexpected end of JSON input"` storage-lookup responses — seen twice here at 22:18:13 and 22:19:18 right before the collision — VM-ID races, and `"no worker upid"` errors), logged repeatedly in the ledger going back to at least 2026-11-01. This specific instance (a single-device test hitting a VM-ID collision with its own SDN VM, rather than between sibling EVE devices) is a new variant of that same known infra-flake pattern, not an EVE/pillar code defect.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume 84f66c6d-4273-4154-b809-0c0559869d76
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

Confirmed exactly: this is the same recurring tie-breaker-node/Longhorn-manager gap documented in the ledger, still live right now.

###### Root cause

Live `volumemgr` logs on `edge-dev2` are continuously logging `WaitForLonghornReady: not ready yet: longhorn daemonset:longhorn-manager missing on this node` (every 5s, still ongoing at 03:54). Confirmed via `kubectl get daemonset -n longhorn-system`: the `longhorn-manager` DaemonSet has `NODE SELECTOR: tie-breaker-node=false` with `DESIRED=2` (only `edge-dev1`/`edge-dev3`), while `edge-dev2` carries `tie-breaker-node=true` — so `longhorn-manager` can never be scheduled there, `kubeapi.WaitForLonghornReady` (`pkg/pillar/kubeapi/kubeapi.go:396`) loops forever, and `volumehandlers/csihandler.go`'s `PrepareVolume` never creates the PVC for volume `84f66c6d-4273-4154-b809-0c0559869d76` (`pvc-gc-persistent`), leaving its `VolumeStatus` permanently stuck at `CREATING_VOLUME` (State 109) — exactly matching the test's "no created VolumeStatus" timeout. Note this is a slightly different symptom than prior nights (then `engine-image`/`csi-plugin` were also absent from the tie-breaker node; tonight only `longhorn-manager` is nodeSelector-excluded while `engine-image`/`csi-plugin` do run on `edge-dev2`), but the mechanism — `csihandler.go` calling `WaitForLonghornReady` unconditionally with no exemption for tie-breaker nodes — is identical.

This is the same known, recurring, still-unfixed issue recorded in the ledger for this exact test (`TestClusterPVCGCDeletesOnlyOrphans`) on **2026-11-02 (run #5)** and again **2026-11-07 (run #10, last night)**. It does not appear related to the sibling test that ran just before it in this run (`TestDNIDandBackupDNID`, which powered off `edge-dev3`, not `edge-dev2`, and passed) — the `edge-dev2` tie-breaker exclusion is a pre-existing cluster-topology condition, not something that test introduced.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

Confirmed live and ongoing right now. This fully matches the ledger's known pattern.

**Root cause:** Confirmed live — this is the exact same `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2059`) deadlock already documented repeatedly in the ledger. `AppInstanceStatus` for `failover-purge-app` (uuid `66a21d18-...`) on edge-dev2 shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-08T04:16:40Z`, `Activated:false`, `IsDesignatedNodeID:false`, and `kubectl -n eve-kube-app get vmirs,vmi,vm -A` returns "No resources found" — matching the test's `found []`. zedmanager has been logging an unbroken loop of `getKubeAppActivateStatus(...): not designated, node 20bf805b-..., onTheDevice false, statusRunning false` every ~20s continuously, still ongoing right now (04:32). `evetest status` confirms edge-dev1 (the designated node) is `EVE_DEVICE_STATE_SUSPECT`, deliberately powered off for this failover scenario, so once the purge tore down the old VMIRS/VMI, nothing in the cluster could originate a new one.

This is the identical mechanism already investigated in this same run for `TestClusterPVCGCDeletesOnlyOrphans` was unrelated, but this specific test/failure is a very well-known recurring issue: per `live-ledger.md`, it has reproduced with the identical signature in essentially every nightly run since the test's introduction (`98acf1411`, 2026-10-18) through at least run #10 (2026-11-07, last night), i.e. an unbroken streak of 10+ consecutive nights. Tonight's occurrence continues that streak — not a new bug.
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

**Root cause:** Confirmed live via `volumemgr` logs on edge-dev1: at `05:11:49`–`05:11:53` for vm1's ContentTreeStatus (`a6d2848a-adb1-438d-8ee2-ff77626c6268`), `contentTreeSatisfiedByPVCs` logged `no local volumes reference this content tree` (the matching `VolumeConfig`/PVC hadn't been published yet), so `doUpdateContentTree` fell through to the normal path, found all three blobs already in the local CAS from before reboot, and self-completed `VERIFIED→LOADING→LOADED` by `05:11:53.513` — landing at `LOADED` (108) instead of `REMOTELOADED` (125), exactly matching the test's assertion.

This is the identical PVC-adoption race in `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` (`pkg/pillar/cmd/volumemgr/acceptclustercontenttree.go`) already documented in `live-investigation.md` for `TestClusterPVCGCDeletesOnlyOrphans` in this same run — different test, but same class of "volumemgr completes a content tree before PVC/volume adoption info has been published" bug. Per the ledger, this exact `TestClusterPVCRedownload`/LOADED-vs-REMOTELOADED signature is a long-running recurring issue first seen on 2026-10-30 (run #2) and repeated on 2026-10-31 (run #3), 2026-11-03 (run #6), and 2026-11-07 (run #10, last night) — tonight is a continuation of that unbroken streak, not a new bug (note: the ledger also has unrelated SDN-infra failures under the same test name on other nights, but tonight's signature matches the code-race variant, not the infra one).

### TestNodeClusterSuite: failure analysis

#### TestMgmtProxy

##### Failure

```
Timed out waiting for app "4ff213bf-4fd1-407b-b482-40f97ac17c24" to be scheduled in cluster "mgmtproxy-test-cluster"
```

##### Claude's conclusion

###### Root cause

Live evidence on `edge-dev1` pins this to a hung async volume-creation worker, not a true scheduling problem: `volumemgr`'s `RolloutDiskToPVC` for the app's volume (`eafc62ec-3159-4c92-9a9e-b5d1dc4219ae`) failed at `02:23:11` with `error uploading image after 10 retries: unexpected return value 503` from `cdi-uploadproxy`, but the CDI upload itself actually completed successfully out-of-band shortly after (`kubectl describe pvc` shows `UploadSucceeded`/`Upload Complete`, pod phase `Succeeded`, and the PVC is `Bound` with `allocated_bytes` ≈ `provisioned_bytes`). Despite that, `volumemgr` never logged consuming a `VolumeWorkResult` after the failed attempt and never retried `AddWorkCreate` — the `VolumeStatus` is still parked in `State:CREATING_VOLUME`/`SubState:PrepareDone` (Progress 100%) with no error recorded, so `AppInstanceStatus` for app `4ff213bf-...` stays at `CREATING_VOLUME` forever, the PVC sits unused (`Used By: <none>`), and no VMI/pod is ever created — matching the test's "never scheduled" symptom exactly.

This is a known, recurring failure class for `TestMgmtProxy`'s scheduling-timeout variant (distinct from the older `ImagePullBackOff`/registry-routing variant): the identical CDI-uploadproxy-`503`-stalls-`CREATING_VOLUME` mechanism was already diagnosed for this exact test on 2026-11-07 (run #10, last night) and traces back further to 2026-11-01/11-02 (run #4/#5) under heavier control-plane load. No other suite test failed in tonight's run to compare against, so this doesn't share a root cause with anything else currently failing. No PR diff was supplied for this investigation, so no relatedness assessment is given.
#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "574d84c2-4cd1-456f-a437-8f08d9f89b8d" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

This is an exact match — identical mechanism, first seen 2026-11-02, recurring multiple nights since including 2026-11-06. I have enough to write the conclusion.

###### Root cause

Live evidence on the paused cluster confirms this is the known tie-breaker/Longhorn gating bug: `edge-dev3` carries **no `tie-breaker-node` label at all**, while `edge-dev1`/`edge-dev2` are labeled `tie-breaker-node=false`. Since the `longhorn-manager`/`longhorn-csi-plugin`/`engine-image` DaemonSets use `nodeSelector: tie-breaker-node=false`, `edge-dev3` fails that selector and never gets a Longhorn manager pod scheduled (`kubectl get nodes.longhorn.io edge-dev3` → `READY: False`, reason `ManagerPodMissing`). App `574d84c2`'s root-volume CDI-upload pod got scheduled onto `edge-dev3` and has been stuck `ContainerCreating` for 30+ minutes, with repeated `FailedAttachVolume: node edge-dev3 is not ready` events — so the VM/VMI was never created, exactly matching the 30-minute "app never scheduled" timeout.

This is **the same root cause** already documented for this exact test in `live-ledger.md`: first seen 2026-11-02 (run #5), recurring on multiple subsequent nights including run #9 (2026-11-06) with app `8becf6b7-...` — same missing/stale tie-breaker-node label on a reused device, same Longhorn-selector exclusion, same unfixed gap in `volumehandlers/csihandler.go`'s `PrepareVolume`/`kubeapi.WaitForLonghornReady` (per `pkg/pillar/kubeapi/longhorninfo.go:720-721`) not accounting for nodes Longhorn's DaemonSets don't schedule on. It does not share a root cause with the other failure already recorded in this run's `live-investigation.md` (`TestMgmtProxy`'s CDI-uploadproxy-503/stuck-`CREATING_VOLUME` bug — a different mechanism, even though the symptom string is identical). This is a known, long-standing, unfixed recurring issue (since 2026-11-02), not a new regression.

### TestPcibackErrorSuite: failure analysis

#### TestReportMissingDevice

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev": failed waiting for VM 106 creation: task failed on Proxmox: unable to create VM 106 - cannot import from 'local:import/ev-eve-78488b3d-edge-dev-0.qcow2' - can't lock file '/var/lock/pve-manager/pve-storage-local-lvm' - got timeout (task UPID:farfalle:0008FD95:7CCB9423:6AEFA385:qmcreate:106:root@pam:)
```

##### Claude's conclusion

This confirms it: the gotest.json log shows the exact same broker-side error, occurring entirely before any EVE device booted. No EVE device was ever created (setup failed at `qmcreate`), so there's nothing further to inspect live — confirmed by `evetest status` returning "No EVE devices found."

The ledger has no prior occurrence of this exact `pve-storage-local-lvm` lock-timeout signature, but it fits the same broader, well-documented pattern of Proxmox host "farfalle" API/lock contention under concurrent VM lifecycle operations (seen repeatedly as TLS handshake timeouts on `qmcreate`/`qmstop`, `lvremove`/"Logical volume in use", `storage/local/status` timeouts, etc.) going back to at least 2026-11-01.

**Root cause:** Pure broker/Proxmox-infrastructure failure, not an EVE or pillar code issue. Proxmox's `qmcreate` task for VM 106 failed because it couldn't acquire the storage lock `/var/lock/pve-manager/pve-storage-local-lvm` within the timeout — i.e., another concurrent Proxmox storage operation (likely another VM's create/import/remove on the shared `local-lvm` storage) was holding that lock on host "farfalle." No EVE device ever got created (`evetest status` confirms "No EVE devices found"), so there's no pillar-side state to examine; this is identical in class to the recurring "farfalle" Proxmox contention entries already documented across multiple prior nights (TLS handshake timeouts on `qmcreate`/`qmstop`, `lvremove` LV-in-use races, `storage/local/status` timeouts dating back to 2026-11-01), though this exact lock-path/error string hasn't been recorded before, so it's a new manifestation of that same known, recurring host-contention problem rather than a brand-new failure class.

### TestStorageSuite: failure analysis

#### TestZVolProvisionedSizeReported

##### Failure

```
Device "edge-dev" failed to confirm the latest config (version 1): timed out waiting for LastProcessedConfig >= 2026-11-07 22:18:57.356048437 +0000 UTC
```

##### Claude's conclusion

Root cause findings:

**Live evidence:** `edge-dev` actually processed config version 1 correctly and promptly — `zedagent` parsed it at 22:19:00.316 (setting `lastProcessedConfig` in-process per `parseconfig.go:211`), the volume `zvol-provisioned-test` was created by 22:19:11, and the DPC switch from the bootstrap "lastresort" network to the controller-assigned "zedagent" network completed successfully (`DPC_SUCCESS`) by 22:19:34. The problem is that this `LastProcessedConfig` value is only surfaced to the controller via a periodic `metrics` POST (`handlemetrics.go:648`), not via the device-info channel — and device logs show exactly one metrics-send attempt in the whole test window, which started around 22:18:42 (right at boot, before the DPC switch) and then hung for the full 120s client timeout, finally failing at 22:21:00.327 with `sendMetricsProtobufByURL status 0 failed: ... context deadline exceeded (Client.Timeout exceeded while awaiting headers)`, logged alongside a watchdog warning `StillRunning(zedagentmetrics) took a long time: 138`. So the one metrics report that would have carried the updated `LastProcessedConfig` got wedged on a connection/route established before the network reconfiguration and was never retried in time, even though `PublishDeviceInfo` sends succeeded repeatedly throughout (including right after the DPC switch) — the harness's 2-minute wait expired at almost exactly the same moment (22:21:00) the stuck metrics call timed out.

**Ledger check:** No prior entry in `live-ledger.md` matches this signature (`TestZVolProvisionedSizeReported`, `LastProcessedConfig` timeout, or `sendMetricsProtobufByURL`/metrics-POST hang) — this appears to be a new, not-previously-recorded failure mode, not a repeat of anything documented so far.

**Shared cause with this run:** No other failure has been investigated in this run yet, so there's nothing to correlate it against.

No PR diff was supplied for this investigation, so no relatedness assessment is given.

### TestTelemetrySuite: failure analysis

#### TestKernelPanicReport

##### Failure

```

Timed out after 600.001s.
the kernel panic stack trace header was not uploaded
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

This confirms the pattern dates back to **2026-10-29 (run #1)** and has recurred at least twice more since (2026-10-28 ledger entry at line 3175, and 2026-11-07's own entry at line 1139 — i.e. this test has failed with this exact signature repeatedly across the project's test history).

Root cause: the pillar/EVE telemetry pipeline worked correctly — nodeagent logged the kernel-panic stack-trace header at 23:07:34.738Z and the end-of-stack marker at 23:07:35.899Z, newlogd uploaded the containing chunk (`dev.log.1794092856562.gz`, now in `keepSentQueue`) via a `POST .../newlogs` at 23:08:17, and Adam's own on-disk store (`adam-db/.../logs/01794092864018512237`, written 23:08) contains the exact header line — all well inside the 600s window before the test's 23:17:48 timeout. The failure is on the evetest side: the test's `device.WatchLogs(...)` live subscription to Adam's `/device/<uuid>/logs` endpoint never delivered the already-persisted matching entry to the test's channel, which is the identical `AdamClient.SubscribeToDeviceLogs` race documented in the ledger since 2026-10-29 and seen again on 2026-10-28 and in tonight's own earlier entry — i.e. this is a **known, recurring evetest-side bug**, not a new issue and not a pillar/EVE regression.

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev3")
```

##### Claude's conclusion

This exact failure (same test, same message, same mechanism — `edge-dev2`'s CNI/service networking breaking after its post-admission pod-identity switch) was already seen and diagnosed just yesterday (2026-11-07, run #10). That's the night immediately preceding this run.

###### Root cause

Live evidence: `kubectl get nodes` shows all three nodes `Ready` and `kubectl get pods -A` shows the cluster formed, but `evetest cluster update-info` shows storage health stuck `DEGRADED`/`FAILED` (last observed transition at 00:11:31, vs. now 00:24:03 — never recovered). The cause is isolated to `edge-dev2`: its `virt-handler-qgbcb` and `longhorn-manager-jrm8g` pods have been crash-looping (5 restarts in the last 13 min) with liveness/readiness probes failing against their **own** pod IPs (`10.42.0.41:8443` / `10.42.0.40:9501`) with "no route to host" / "connection refused". `edge-dev2`'s current flannel subnet is `10.42.1.1/24` (confirmed via `/run/flannel/subnet.env` and its `cni0` IP), but those two pods were assigned IPs from `10.42.0.0/24` — a subnet that belongs to a different node. This means the pods got their network identity before/during `edge-dev2`'s subnet reassignment (consistent with the k3s/flannel process on edge-dev2 having only started at 00:11, i.e. restarted during the rolling upgrade), and were never recreated to pick up the correct subnet, leaving them permanently unreachable on their own node and storage (Longhorn) unable to reach `HEALTHY`.

This is the identical failure mode, same test, and same root-cause mechanism (`edge-dev2`'s CNI/service networking breaking after a mid-flight pod-identity/subnet switch, leaving `virt-handler`/Longhorn pods in permanent `CrashLoopBackOff` with "no route to host" on their own pod IPs, keeping storage `DEGRADED` forever) as the entry already logged in `live-ledger.md` for 2026-11-07 (run #10, the immediately preceding night) — so this is a **known, recurring issue, first seen 2026-11-07**, not a new one. No PR diff was supplied for this investigation, so no relatedness judgment is given.

## [2026-11-07 -- 0.0.0-master-d87216a0 (run #10)](https://github.com/lf-edge/eve/actions/runs/42301228193)

[Full report](https://lf-edge.github.io/eve/test/master/runs/10/)

### TestApplicationConnectivitySuite: failure analysis

#### TestSwitchNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.001923964s (excluding download) waiting for app "dd012bcc-8312-409b-87d9-660f0f053249" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

###### Root cause

The live device confirms the test's own symptom exactly: both `acl-app-1`'s and `acl-app-2`'s content trees (`027f6723-...`/`54b59728-...`) have been stuck in `ContentTreeStatus.State:101` (`RESOLVING_TAG`) with empty `ContentSha256` since 01:13:08, still stuck now at 01:21+. The downloader log shows `handleResolveCreate` fired once at `01:13:08.100` for both datastores and spawned a `runResolveHandler` goroutine for each, which logged `lookupResolveStatus(...) not found` and then never logged anything further — no registry call, no error, no completion — despite the SDN registry being reachable (`curl http://192.168.170.2:5000/v2/` → `200`). volumemgr's periodic `MaybeAddResolveConfig` retries at `01:15:01` and `01:21:01` republish the *same* `ResolveConfig` object, so pubsub treats it as unchanged and `handleResolveCreate`/`handleResolveModify` never re-fires on the downloader side — the hung goroutine is never retried or replaced, so the apps wait forever.

This matches a recorded, known/recurring issue: `live-ledger.md` documents the identical `runResolveHandler`/`lookupResolveStatus ... not found`-then-hang signature for this exact suite/tests (`TestFlowLog` and `TestSwitchNetInstanceACLsWithFlowLog` in `TestApplicationConnectivitySuite`), first seen **2026-10-31** and recurring **2026-11-02**, each time diagnosed as a downloader tag-resolution goroutine that hangs instead of completing or erroring, unrelated to registry health or test/ACL logic. Tonight's occurrence is the same mechanism (and notably worse — both sibling apps hang this time, whereas on 11-02 one sibling eventually completed). No PR diff was supplied for this investigation, so no relatedness assessment to in-flight code changes is given.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume ab76e004-1cd2-4dfd-aca2-895a3b097e1a
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

Confirmed live, as of just before the failure (23:01:22Z, moments before the 900s timeout expired): `volumemgr` on `edge-dev2` is still continuously logging `WaitForLonghornReady: not ready yet: longhorn daemonset:engine-image-ei-b4bcf0a5 missing on this node`, explaining why volume `ab76e004-1cd2-4dfd-aca2-895a3b097e1a` never gets a `VolumeStatus` created there.

**Root cause:** `edge-dev2` is labeled `tie-breaker-node=true`, while all three Longhorn DaemonSets (`engine-image-ei-b4bcf0a5`, `longhorn-csi-plugin`, `longhorn-manager`) are scoped with `nodeSelector: tie-breaker-node=false`, so their pods never schedule on `edge-dev2` and `kubeapi.WaitForLonghornReady` (`pkg/pillar/kubeapi/kubeapi.go:396`) can never succeed there — `volumehandlers/csihandler.go` still calls it unconditionally with no exemption for tie-breaker nodes. This is the identical mechanism, code path, and node role as the `TestClusterPVCGCDeletesOnlyOrphans` failure already diagnosed in the ledger on 2026-11-02 (run #5), just against a different volume UUID this time — it's a known, recurring, and still-unfixed issue, not a new one. It does not share a root cause with anything else currently failing in this run (no other suite failure has been investigated alongside it yet in this session). No PR diff was supplied for this investigation.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

I have enough evidence to confirm the root cause matches the known pattern exactly.

###### Root cause

Live evidence on edge-dev2 confirms the same deadlock seen many times before: `AppInstanceStatus` for `failover-purge-app` (uuid `9ee6865c-...`) shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-06T23:24:19Z`, `Activated:false`, `IsDesignatedNodeID:false`. `evetest cluster info` history shows the app's first VMIRS generation (`...-0pnwx7`) ran on edge-dev1, then after the purge a second generation (`...-0slpvf`) briefly ran on edge-dev2 before its PVC volume was DETACHED around 23:16, with no VMIRS/VMI created since — and `evetest status`/SSH confirm edge-dev1, the app's designated node, is `EVE_DEVICE_STATE_SUSPECT` and completely unreachable ("failed to detect any IP address"), deliberately downed for this failover scenario. This is the identical `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2027-2059`) gap documented repeatedly in `live-ledger.md`: only the designated node can unconditionally originate a fresh VMIRS after a purge, and since it's kept offline for the whole test, nothing recreates one. This is a known, recurring issue dating back to the test's introduction (`98acf1411`, 2026-10-18) and has reproduced in essentially every nightly run since 2026-10-29 through at least run #8 (2026-11-05), now continuing into tonight's run #9 — an unbroken streak of 10+ consecutive nights with the identical signature. It does not share a root cause with this run's other investigated failure (`TestClusterPVCGCDeletesOnlyOrphans`, a tie-breaker-node Longhorn scheduling gap).
#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

###### Root cause

This is a confirmed repeat of the already-known `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` race in `pkg/pillar/cmd/volumemgr/acceptclustercontenttree.go`. Live `volumemgr` logs on edge-dev1 show that at `00:14:51.809` and `00:14:55.641` (right after vm1's post-reboot reactivation), `doUpdateContentTree` for vm1's ContentTreeStatus (`b56a5ee0-...`) found `contentTreeSatisfiedByPVCs(...): no local volumes reference this content tree` — the matching `VolumeConfig` for the already-Bound/CDI-complete PVC hadn't been published to volumemgr yet. Because all three blobs were already `VERIFIED` and present in the local CAS from before the reboot, the content tree fell through to the normal path instead of waiting for PVC adoption, and self-completed `VERIFIED→LOADING→LOADED` within the same reconcile pass by `00:14:55.849` — landing at `LOADED` (108) instead of `REMOTELOADED` (125), exactly matching the test's assertion failure. No actual network download occurred (the image server was still firewalled off per the test's design); this is purely a timing race on the PVC-adoption shortcut.

This is the same mechanism (not merely similar) already analyzed twice before in `live-ledger.md` for this exact test — run #2 (2026-10-30) and run #3 (2026-10-31) — so it's a known, recurring, still-unfixed race, first observed 2026-10-30, reproducing again tonight after not appearing in runs #4–#8. It does not share a root cause with this run's other investigated failures (`TestClusterPVCGCDeletesOnlyOrphans`'s tie-breaker-node Longhorn-scheduling gap, or `TestVMAppPurgeDuringFailover`'s designated-node purge deadlock) — all three are distinct, independently-known bugs.

### TestNodeClusterSuite: failure analysis

#### TestAppInstancePurge

##### Failure

```
Device "edge-dev": expected 1 reboot(s) but observed 2
```

##### Claude's conclusion

No prior occurrence of this specific signature in the ledger. No PR diff was provided for this investigation, so I'll omit the RELATED line.

###### Root cause

`zedkube`'s node-drain logic (triggered when `edge-dev` was told to leave cluster mode) got stuck in a tight retry loop from 22:30:53–22:31:59 repeatedly failing to evict `virt-api`, `virt-controller`, and a `longhorn-system` instance-manager pod with `Cannot evict pod as it would violate the pod's disruption budget` — these pods' PodDisruptionBudgets never allow eviction, so the retry loop never progresses. Because it never touched `/run/zedkube.touch`, the watchdog declared it hung (`file /run/zedkube.touch was not changed in 562 seconds`) and force-rebooted the device at 22:30:57 — an *unplanned* reboot, confirmed by `nodeagent`'s own log on the next boot: `Current partition RebootReason: Watchdog report ... /run/zedkube.touch`. Since the node-drain/single-node transition hadn't actually completed when that watchdog reboot hit, EVE then performed the *real*, intended transition reboot immediately after (`RebootReason: ... BootReasonKubeTransition, Transition from cluster mode to single node` at 22:35:15), giving two reboots total where the test expected only one.

This is a distinct, new failure signature — the ledger has several prior `TestAppInstancePurge` entries, but all are a different mechanism (cluster-mode config not carried forward between back-to-back tests on a reused device, or a self-cordon/DNS/stale-volume issue); none mention this PDB-blocked-eviction/watchdog-hang mechanism, so this does not appear to be previously known/recurring. It also doesn't share a root cause with any other failure investigated in tonight's ledger entries so far.
#### TestMgmtProxy

##### Failure

```
Timed out waiting for app "6f69b7b3-5cbb-4e32-a755-bcf03ed2de5b" to be scheduled in cluster "mgmtproxy-test-cluster"
```

##### Claude's conclusion

###### Root cause

Live evidence pins this to a stuck app-volume creation: `edge-dev1`'s `VolumeStatus` for the app's root volume (`4609ebc8-245e-4d9d-b4ad-eb5077211a5e`) is parked in `CREATING_VOLUME` with no error recorded, and `VolumeCreatePending` is still present — the async `CreateVolume` work item never finished. `volumemgr`'s log shows exactly one `RolloutDiskToPVC` attempt at 23:21:33, which failed 24s later with `error uploading image after 10 retries: unexpected return value 503` from the CDI uploadproxy (`cdi-uploadproxy` logs confirm the token exchanges stopping dead after 23:21:56), and the outer Go-level retry loop (`RolloutDiskToPVC` has up to 10 outer tries with 30s backoff) never logged a second attempt in the following 8+ minutes, through to the test's timeout at 23:29:20 and still now, 4 minutes after pause. Because the volume never reached `CREATED_VOLUME`, zedmanager/zedkube never created the pod/VMI for app `6f69b7b3-...`, so it was never "scheduled," matching the test's own failure message.

This does **not** share a root cause with the earlier `TestAppInstancePurge` failure already recorded in `live-investigation.md` for this run (that was a watchdog/PDB-blocked-eviction reboot issue, unrelated to volume creation). It **is** a recurrence of a known mechanism: the ledger documents the identical `"Timed out waiting for app ... to be scheduled"` failure on both `TestClusterPVCGCDeletesOnlyOrphans` and `TestMgmtProxy` on 2026-11-01 (run #4), both traced to CDI/CSI-upload-path `503`s stalling `CREATING_VOLUME`. However, that prior incident showed severe cluster-wide etcd/control-plane overload (load averages 10–14, mass pod crash-looping, 9 k3s restarts); tonight's `edge-dev1` shows only mild, isolated etcd slow-apply warnings (100–200ms vs. a 100ms budget) and no pod restarts, so this looks like a lighter-weight recurrence of the same CDI-upload-stall failure class rather than a full control-plane meltdown — and the fact that the retry loop produced zero further log output for 8+ minutes (rather than repeatedly failing/retrying) suggests the stall itself may be a distinct, unretried-hang variant worth separate attention.
#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "ca06d2d0-69a2-4d30-95c8-0e3bd7761e29" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

Confirmed — volume `caaebf86-da3e-437d-bb67-df0027326d26` is this app's volume, and it's stuck in `CREATING_VOLUME`, exactly matching the stuck CDI-upload pod on `edge-dev3`.

###### Root cause

The app's volume-creation pod (`cdi-upload-caaebf86-...-pvc-0`) got scheduled onto `edge-dev3`, but `edge-dev3` is missing the `tie-breaker-node` label entirely (only `edge-dev1`/`edge-dev2` carry `tie-breaker-node=false`), so it fails the `longhorn-manager`/`longhorn-csi-plugin`/`engine-image` DaemonSets' `nodeSelector: {tie-breaker-node: false}` and never got a Longhorn manager pod — `kubectl get nodes.longhorn.io edge-dev3` shows `Ready=False`, `ManagerPodMissing`. Consequently Longhorn repeatedly fails `AttachVolume` for both the app's PVCs with `node edge-dev3 is not ready`, the pod has sat in `ContainerCreating` for 30+ minutes, `VolumeStatus` is stuck in `CREATING_VOLUME`, and no VMI was ever created — exactly explaining the app-scheduling timeout.

This is **the same root cause** already recorded in tonight's own ledger for this exact test (`TestClusterVMApp`, run #9, earlier failure with app `8becf6b7-...`): a leftover `tie-breaker-node` labeling mismatch from an earlier tie-breaker test on these reused devices. It does not overlap with the other failures already in `live-investigation.md` for this run (`TestAppInstancePurge`'s watchdog/PDB reboot, `TestMgmtProxy`'s CDI-upload-stall). Per `live-ledger.md`, `TestClusterVMApp` is a chronically recurring/flaky test overall (seen on 2026-10-29, -30, -31, 11-01, 11-02, 11-04 with several distinct mechanisms — SDN/gRPC tunnel death, edge-dev3 "not authorized" join-retry bug, and this tie-breaker-node label issue), but this specific tie-breaker-node-label variant is only known from earlier tonight (run #9) — not from prior nights — so it looks like a newly-introduced device-reuse/test-isolation gap rather than a long-standing issue.

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev1")
```

##### Claude's conclusion

###### Root cause

The three-node k3s/eve-k cluster did form (all three nodes reach `Ready`/`NODE_ADMISSION_JOINED` in `evetest cluster info` by 23:02:22), but cluster storage health never left `DEGRADED`, so the harness's `clusterNodeReady` check (which requires storage `HEALTHY` plus all nodes `Ready`) kept polling every minute from 22:55 until it gave up at 23:24:17 (confirmed live and in `gotest.json`). Live `kubectl get pods -A` on `edge-dev1` shows the cause is isolated to `edge-dev2`: its `virt-handler` and `longhorn-csi-plugin` pods have been stuck in `CrashLoopBackOff` continuously since **23:02:05** — the exact moment `edge-dev2`'s kubelet tore down and recreated those pods' containers as part of the node's identity switch from its provisioning IP (172.20.20.166) to its final cluster IP (10.244.244.3) on full admission. After that point, `virt-handler` fails its liveness/readiness probe against its *own* pod IP with `dial tcp 10.42.0.38:8443: connect: no route to host`, and `longhorn-csi-plugin` can't even resolve `longhorn-backend` via CoreDNS (`dial tcp: lookup longhorn-backend on 10.43.0.10:53: ... i/o timeout`) — both symptomatic of the node's CNI/service-routing (flannel/iptables) state not having been correctly reconciled after that mid-flight IP/identity change, a problem specific to `edge-dev2` since `edge-dev1`/`edge-dev3` show no such crash loops.

This is a different failure mechanism than the identical-sounding "Timed out waiting for cluster nodes to become ready" entries already in `live-ledger.md` — those were caused by a device going completely silent/unreachable (`TestKubeRegistrationClusterSetup`) or by a node permanently rejected on rejoin with `not authorized` after a kube-transition reboot (`TestClusterVMApp`, recurring since 2026-10-29). Tonight's signature — all nodes successfully joined but one node's CNI/service networking breaks after its post-admission pod-identity switch, leaving storage permanently `DEGRADED` — does not appear anywhere in the ledger, so this looks like a new failure mode rather than a previously known/recurring one. No other failing test in this run shares this same mechanism (the other three suites in this run failed at earlier/different stages), and no PR diff was provided for a relatedness judgment.

## [2026-11-06 -- 0.0.0-master-d87216a0 (run #9)](https://github.com/lf-edge/eve/actions/runs/42117633911)

[Full report](https://lf-edge.github.io/eve/test/master/runs/9/)

### TestControllerFaultsSuite: failure analysis

#### TestDeferredQueueDropsReported

##### Failure

```

Timed out after 480.001s.
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

###### Root cause

Live/log evidence pins this down precisely: at 00:37:03–00:37:35 the device correctly stopped `reported-app` (zedmanager/domainmgr took it from RUNNING → HALTING → HALTED, confirmed by `AppInstanceStatus.State:119`=HALTED still showing on the live device). zedagent generated the corresponding `ZInfoApp{state:HALTED}` report and tried to send it at `00:37:35.169`, but the harness's fault proxy was still answering `POST .../info` with 404 at that moment, so zedagent logged `handleDeferred: ... dropping message, controller responded 404 Not Found` at `00:37:35.181` — exactly the "last message given up on" timestamp the test itself printed. The harness's `ClearControllerFaults()` only ran 3 seconds later (`00:37:38`), by which time that HALTED report was already permanently discarded from the deferred queue (404 is treated as non-retriable, unlike the 503 case). Adam's own log confirms it never received an `/info` POST for this app-UUID after that point, and the app has had no further state transition since, so nothing ever re-triggers a fresh publish — there is no periodic full-info resync for the normal cloud destination (only the LOC destination gets that). `settleApp`'s `Eventually(Receive(HALTED), 8m)` on `appUpdates` was therefore waiting for an event that pillar will structurally never send again, timing out at 480s as observed.

This is a race in the test itself, not device/SDN flakiness: `DeactivateApplication` is issued while the 404 fault is still armed, and the fault is cleared only ~34ms after the HALTED report already got rejected/dropped, so the single terminal-state report is lost for good. Contrast with the sibling `TestDeferredQueueBacklogReported` (503/retriable fault), which passed in this same run — because 503s stay in the deferred queue and get redelivered once the fault clears, unlike 404 drops.

This does not share a root cause with the other `TestControllerFaultsSuite` ledger entries (the `ReceiveMatcher`/"must receive something" signature previously seen for `TestKernelPanicReport` was an evetest `WatchLogs` subscription bug where the data *was* sitting in Adam's store; here the data never reached Adam at all — a different mechanism, confirmed by Adam's log showing no `/info` POST for this app after the drop). I found no prior ledger entry for `TestDeferredQueueDropsReported`/this exact test, so this looks like a new, first-time failure (test introduced 2026-08-28, fault-proxy-on-self enabled 2026-10-15) rather than a known/recurring issue — and because the race is deterministic in the test's own sequencing (deactivate-while-faulted, then clear-fault almost immediately), it should reproduce on every run rather than being infra flakiness.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Unexpected error:
    <*errors.errorString | 0x3485ac95d5d0>: 
    curl http://http-server.test/helloworld failed: 
    {
        s: "curl http://http-server.test/helloworld failed: ",
    }
occurred
```

##### Claude's conclusion

###### Root cause

Live evidence shows the device itself is healthy: `edge-dev` is `EVE_DEVICE_STATE_ONLINE`, has `172.20.20.123` on the authenticated VLAN, and when I re-ran the exact failing command over SSH (`curl http://http-server.test/helloworld`) it resolved DNS and got `HTTP/1.1 200 OK "Hello world!"` in ~1 second. The device's structured pillar logs for the failure window (22:30:45–22:30:53, from `/persist/newlog/keepSentQueue/dev.log.1793917957249.gz`) show only routine zedagent/zedrouter/watcher metrics activity — no network, DNS, or crash errors — and the console log shows no reboot or service failure around that time.

The actual failure mechanism from `gotest.json`: the test's checkpoint sequence reached `ip-updated` at 22:30:43 (right after the 802.1x port-authentication/VLAN transition), the harness then SSH'd in at 22:30:48, and only 5.7 seconds later killed that SSH session with `"Killing SSH session ... due to stdout inactivity"` — the curl command simply hadn't produced output yet, likely because it was issued essentially immediately after the authenticated-VLAN transition, before DHCP/DNS/ARP had fully converged on that fresh network path, and the harness's inactivity timeout is very tight (~5s).

This does not match the broader known/recurring "SDN VM/gRPC tunnel unreachable, `no route to host`" infrastructure flake documented repeatedly in `live-ledger.md` since 2026-10-29 — that signature involves the *broker* failing to reach the SDN VM's gRPC port, whereas here the SDN tunnel connected and stayed healthy throughout (confirmed by live `evetest sdn status` showing no errors). I found no prior entry in the ledger for `TestPNACWithoutProxy` or this "curl helloworld"/"stdout inactivity" signature, so this appears to be a new, first-occurrence flake — most likely a narrow test-timing race right after the PNAC VLAN transition, similar in spirit to the previously-logged `TestLACPBond` timing-margin flake, rather than an EVE/pillar code defect.

### TestHardwareSuite: failure analysis

#### TestUSBFlashDriveHotplug

##### Failure

```
timed out after 10m0.002718068s (excluding download) waiting for app "69e7d7c0-8946-4191-a24e-7608a015dc07" (usb-flash) on device "hardware-dev" to reach RUNNING state (last state: HALTING)
```

##### Claude's conclusion

These are just unrelated device-info blobs matching "Hardware" in product name text, not TestHardwareSuite entries. This confirms TestHardwareSuite/TestUSBFlashDriveHotplug has no prior entries in the ledger — this is new.

Root cause found and confirmed live. Summary:

**Root cause:** On the first boot attempt at 22:31:38, domainmgr launched `qemu-system-x86_64` for app `usb-flash` but the QMP socket and pidfile were never created (`/run/hypervisor/kvm/<uuid>.1.1/` stayed empty), so domainmgr gave up after 5 attempts at 22:32:14 ("Giving up waiting to connect to QEMU Monitor Protocol socket ... connect: no such file or directory") and marked the app HALTING/broken. Domainmgr then entered its standard boot-retry backoff (`maybeRetryBoot` counting down from ~373, consistent with the `timer.boot.retry` 600s-scale retry logic), which only succeeded on a later retry at 22:42 — confirmed live: the containerd task for that domain is now RUNNING (PID 9174, started ~22:42:52), the QMP socket/pidfile now exist, and `app-info` shows the app actually reached `RUNNING` with an IP. The evetest harness's 10-minute wait, however, had already expired before this successful retry landed, so the test timed out despite the app having eventually come up — this looks like a one-off transient QEMU/launch glitch on the first attempt (no kernel OOM, no dmesg errors, no permission denials found) rather than a logic bug in the retry path itself. This is not shared with any other failure in this run and doesn't match anything in the ledger — no entry for `TestHardwareSuite`/`TestUSBFlashDriveHotplug` or this QMP-socket symptom appears there, so this is a new failure, not a previously known recurring one.
#### TestUSBHubChain

##### Failure

```

Timed out after 180.001s.
The function passed to Eventually failed at /evetest/tests/hardware/helpers_test.go:345 with:
Unexpected error:
    <*fmt.wrapError | 0x3c96481da920>: 
    failed to execute script over SSH for app 4971c574-aebc-449f-9823-bf4eec05d429: EOF (stderr: )
    {
        msg: "failed to execute script over SSH for app 4971c574-aebc-449f-9823-bf4eec05d429: EOF (stderr: )",
        err: <*errors.errorString | 0x22ac9d0>{s: "EOF"},
    }
occurred
```

##### Claude's conclusion

I have sufficient evidence to form a conclusion.

**Likely root cause:** This is not a device crash/reboot or a repeat of this run's earlier `TestUSBFlashDriveHotplug` failure (that one was a one-off QMP-socket launch glitch at first boot — this device stayed up the whole time, with no panic stacks and the same uptime it had since initial power-on, so I don't believe it shares that root cause). Instead, after domainmgr reported the app `4971c574-aebc-449f-9823-bf4eec05d429` RUNNING at 22:50:04, the harness could not reach the port-forwarded SSH (172.20.20.22:2222 → 10.11.12.2:22) for the next ~2 minutes, cycling through `i/o timeout` / `no route to host` (22:50:07–22:51:53). The `dnsmasq-dhcp` log shows the guest only completed its DHCP exchange at 22:51:35 — about 90s after EVE considered the domain "RUNNING" — meaning the guest OS itself was still booting (kernel/USB enumeration/cloud-init) well past that point. A connection finally succeeded at 22:52:01, but the script execution over it returned `EOF`, consistent with the guest's sshd/network still settling under load, and the `Eventually` block's 180s deadline (from 22:50:04) expired at 22:53:04 before a stable session could be established. The DNAT/portmap rules and qemu process are confirmed correctly configured right now, so this looks like guest-boot/SSH-readiness flakiness (plausibly aggravated by nested-KVM boot jitter and/or the added complexity of enumerating the 4-deep USB hub chain inside the guest) rather than a config or reconciler bug. This exact test/symptom doesn't appear in the ledger, so it's a new failure, not a known recurring one.

### TestLimitsSuite: failure analysis

#### TestManyAppInterfaces

##### Failure

```

Told to stop trying after 70.055s.
pillar did not survive: the console shows: Rebooting EVE. Reason: panic: send on closed channelWatchdog report for IMGA EVE version 0.0.0-master-d87216a0-kvm-amd64 at 2026-11-05T23:13:43+00:00: 3 /run/zedbox.pid
At one point, however, the function did return successfully.
Yet, Eventually failed because the matcher was not satisfied:
The function passed to Eventually failed at /evetest/tests/limits/helpers_test.go:128 with:
all 15 applications are reported running has not happened yet
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

###### Root cause

The device crashed with a real pillar panic, not a flaky test: `/persist/reboot-stack` on the live device shows `panic: send on closed channel` in goroutine 10524, at `pkg/pillar/cmd/downloader/download.go:473` inside `objectMetadata`'s helper goroutine (`receiveChan <- nil`), spawned from `objectMetadata` itself (download.go:468). That `receiveChan` is the per-download-object channel created in `downloadHandler.create()` and explicitly `close()`d in `downloadHandler.delete()` (`pkg/pillar/cmd/downloader/handlers.go`). There's no synchronization preventing `delete()` from closing the channel while an in-flight `objectMetadata`/`syncOp` goroutine for that same download object still tries to write to it — a classic close-vs-send race. `TestManyAppInterfaces` provisions 15 apps with many interfaces simultaneously, which drives a burst of concurrent downloader config creates/deletes and makes this race far more likely to trigger than under normal load, consistent with the test's own failure (`all 15 applications are reported running` never became true because zedbox rebooted mid-run).

I checked `live-ledger.md` (2724 lines, back through 2026-10-29) for any prior "panic" or "send on closed channel" entry and found none — all prior ledger failures are infrastructure/SDN-tunnel/broker outages, an unrelated failure class. This also does not share a root cause with anything else in this run (only one suite/test has failed so far). This looks like a newly-surfaced, genuine pillar concurrency bug in the downloader package rather than a known/recurring or infra issue.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume badb0d1d-0086-4a85-9188-413b33d9bf8d
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

Root cause confirmed, no PR diff was provided for this investigation.

**Root cause:** `volumemgr` on `edge-dev2` is permanently stuck logging `WaitForLonghornReady: not ready yet: longhorn daemonset:engine-image-ei-b4bcf0a5 missing on this node` (continuously from before the test started through now, `pkg/pillar/kubeapi/kubeapi.go:396`), which is exactly why no `VolumeStatus` for volume `badb0d1d-0086-4a85-9188-413b33d9bf8d` is ever created on that node. `kubectl get node edge-dev2 --show-labels` shows it's labeled `tie-breaker-node=true`, while the Longhorn `engine-image`/`longhorn-csi-plugin`/`longhorn-manager` DaemonSets all carry `nodeSelector: tie-breaker-node=false` (confirmed live via `kubectl get ds -A -o wide`), so by design none of their pods ever schedule on `edge-dev2` and `WaitForLonghornReady` can never succeed there. The code is still unfixed: `pkg/pillar/volumehandlers/csihandler.go:106` calls `kubeapi.WaitForLonghornReady` unconditionally with no check against `EdgeNodeClusterConfig.IsTieBreakerNode`, exactly as previously documented at `pkg/pillar/kubeapi/longhorninfo.go:761`.

This is a known, recurring issue — the identical "tie-breaker node + `has no created VolumeStatus`" failure and root cause were already diagnosed for this same test on **2026-11-02** (run #5), and it remains unfixed in the current code. It is a distinct mechanism from `TestClusterPVCGCDeletesOnlyOrphans`'s other historical failures (etcd/CDI-overload scheduling timeouts on 2026-11-01 and 2026-11-03), which were separate, unrelated causes. No PR diff was supplied for this investigation.
#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

edge-dev1 (the designated node for this app) is unreachable, confirming it's down/suspect, consistent with the deliberate failover scenario and the known deadlock condition. I have sufficient evidence to conclude.

**Root cause:** This is the same known, recurring zedmanager/zedkube "purge-after-failover" deadlock in `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2059`) that's already documented for this exact test. Live evidence on edge-dev2 confirms it: `AppInstanceStatus` for `failover-purge-app` (uuid `bce44c38-4b06-437e-924b-ab36473b2a41`) shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-06T04:31:11Z`, `Activated:false`, `IsDesignatedNodeID:false`, with zedmanager still logging the identical stuck loop "`not designated, node 7a00668e-..., onTheDevice false, statusRunning false`" as recently as 04:46:45Z (minutes ago, live). `evetest status` shows edge-dev1 in `EVE_DEVICE_STATE_SUSPECT` (confirmed unreachable via SSH — "failed to detect any IP address"), the deliberately-downed designated node for this failover scenario, so once the purge tore down the VMIRS nothing in the cluster can recreate it, matching the test's `found []`.

This does not share a root cause with the earlier investigated failure in this same run (`TestClusterPVCGCDeletesOnlyOrphans`, a tie-breaker-node Longhorn scheduling issue) — it's a separate mechanism. Per the ledger, this exact failure in `TestVMAppPurgeDuringFailover` has been a known/recurring issue since **2026-10-29** (run #1) and reproduced in every nightly run through at least **2026-11-05** (run #8) — tonight's occurrence continues an unbroken streak of at least 9 consecutive nights with the identical signature. No PR diff was provided for this investigation.

### TestNodeClusterSuite: failure analysis

#### TestAppInstancePurge

##### Failure

```
app "dc7e8ee5-9c9a-44e9-93c6-120cb934a7c9" (purge-app) on device "edge-dev" download stalled at 0% for more than 5m0s
```

##### Claude's conclusion

**Root cause:** On the live `edge-dev`, all 6 `DownloaderStatus` entries for `purge-app`'s image blobs are pinned at `State:DOWNLOADING, Progress:0, TotalSize:0, CurrentSize:0` with no error, and the device logs show *zero* downloader activity (no HTTP/registry request, no `handleSyncOp` log line) for the full 5+ minutes since the configs were created at 07:18:29 — the registry itself is reachable (`curl 192.168.170.2:5000/v2/` returns `200`) and `zedbox` is alive, so this isn't a network/infra stall, it's a silent no-op in pillar. Tracing the code: `doUpdateContentTree` (`cmd/volumemgr/updatestatus.go`) only refreshes a reused root blob's `DatastoreIDList` when its state is `LOADED`, not `VERIFIED` — and the manifest blob (`333e5cba...`) for this image came back already `VERIFIED` (almost certainly a CAS-cached leftover from an earlier pull of the same image in this same purge-app test cycle) with an empty `DatastoreIDList`. That empty list propagates to every child blob created from the manifest (`getBlobChildren`), so each child's `DownloaderConfig.DatastoreIDList` ends up empty; `downloader`'s `prepareDatastoresList`/`doDownload` (`cmd/downloader/downloader.go`) treat zero datastores as "nothing to do, no error" rather than a failure, so the download loop runs zero iterations forever — matching the "stalled at 0%" symptom exactly, including the total absence of errors or retries.

This does not match any prior "download stalled" ledger entry (those were a known registry/manifest-fetch-hang bug that stalls partway through at a nonzero percentage with a live, stuck TCP connection) — this is a distinct, code-level datastore-ID-loss bug, and a search of the ledger turns up no prior `TestAppInstancePurge` failure with this signature, so this looks new rather than recurring. No PR diff was supplied for this investigation.
#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "8becf6b7-6bea-49f2-a275-840186bd46d4" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

###### Root cause

Live inspection shows the cluster/SDN are healthy (all 3 k8s nodes `Ready`, no broker/SDN connectivity issues), but `edge-dev3` carries no `tie-breaker-node` label at all, whereas `edge-dev1`/`edge-dev2` are labeled `tie-breaker-node=false` — a leftover from an earlier tie-breaker-mode test on these reused devices. Because the `longhorn-manager`/`longhorn-csi-plugin`/`engine-image` DaemonSets are scoped with `nodeSelector: tie-breaker-node=false`, `edge-dev3` fails that selector too and never got a Longhorn manager pod scheduled on it (`kubectl get nodes.longhorn.io edge-dev3`: `Ready=False`, reason `ManagerPodMissing`). App `8becf6b7`'s root-volume PVC (`da67cfc9...`) got scheduled for its CDI-upload onto `edge-dev3` and has been repeatedly failing `FailedAttachVolume` ("node edge-dev3 is not ready") for 31+ minutes; the corresponding `VolumeStatus` is permanently stuck at `State:109` (`CREATING_VOLUME`) since 08:28:16, so the VM was never even created in kubevirt (`kubectl get vm/vmi` returns nothing) — explaining the 30-minute scheduling timeout.

This is the identical "tie-breaker/Longhorn gating" bug already logged repeatedly in `live-ledger.md`, first seen 2026-11-02 (run #5) and recurring on multiple subsequent nights: `volumehandlers/csihandler.go`'s `PrepareVolume` calls `kubeapi.WaitForLonghornReady` unconditionally instead of skipping nodes Longhorn's daemonsets don't schedule on, per the documented contract in `pkg/pillar/kubeapi/longhorninfo.go:720-721`. Previously this manifested on a node explicitly labeled `tie-breaker-node=true`; tonight it's the same mechanism triggered a different way — `edge-dev3` ended up with no tie-breaker label after being reused/rejoined across this run's earlier cluster tests, which equally excludes it from the Longhorn selector. This is a known, unfixed, standing code gap, not a new bug — and it does not share a root cause with this run's other investigated failure (`TestAppInstancePurge`'s downloader datastore-ID-loss bug, a distinct, unrelated mechanism). No PR diff was supplied for this investigation.

### TestSecuritySuite: failure analysis

#### TestAppVTPMBackupRecoversPrimaryCorruption

##### Failure

```

Timed out after 300.001s.
The function passed to Eventually failed at /evetest/tests/security/vtpm_helpers_test.go:127 with:
read guest TPM NV marker: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 
WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 
ERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded 
ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI 
ERROR: Could not load tcti, got: "(null)"

Unexpected error:
    <*fmt.wrapError | 0x2505dc199760>: 
    failed to execute script over SSH for app 54a464b1-af95-4a57-bf6c-8b174b266b30: Process exited with status 1 (stderr: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
    ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 
    WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
    ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 
    WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 
    ERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded 
    ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI 
    ERROR: Could not load tcti, got: "(null)"
    )
    {
        msg: "failed to execute script over SSH for app 54a464b1-af95-4a57-bf6c-8b174b266b30: Process exited with status 1 (stderr: ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 \nERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified TCTI device file /dev/tpm0: No such file or directory \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-device.so.0 \nWARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused \nERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM socket \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-swtpm.so.0 \nWARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: errno 111: Connection refused \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: libtss2-tcti-mssim.so.0 \nERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be loaded \nERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI \nERROR: Could not load tcti, got: \"(null)\"\n)",
        err: <*ssh.ExitError | 0x2505dd7de540>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

No vTPM mentions in run #7 (2026-11-04) or run #6 (2026-11-03) sections — only in run #5 (2026-11-02) and now tonight (run #8/9, 2026-11-05).

###### Root cause

The test's `expectGuestTPMMarker` timed out because the guest VM for app `vtpm-backup` (`54a464b1-...`) was launched with **no vTPM device at all**: the live `/run/domainmgr/domains/dom1.cfg` for that domain has zero `tpm`/`tpmdev` entries, so `/dev/tpm0`/`/dev/tpmrm0` never appear in the guest, matching the exact `tcti` "no such file" errors in the failure. Live `domainmgr` logs show why: at `22:51:15.108` it logged `Failed to setup vTPM ... context deadline exceeded` after `vtpmd`'s launch request exceeded domainmgr's fixed `swtpmTimeout = 10s` (`pkg/pillar/hypervisor/kvm.go:42,2320`), but `vtpmd` actually finished launching the `swtpm` process just ~1s later (`22:51:16.000`) — and that `swtpm` process is still alive and healthy on the host right now (`pid 6950`, keyed to the correct `tpm-state-54a464b1-...` dir). So the backend TPM exists and is fine; domainmgr simply gave up on wiring it into the qemu config before `vtpmd` responded.

This is the identical race/timeout mechanism already diagnosed in this same ledger for `TestAppVTPMIdentitySurvivesReboots` (run #5, 2026-11-02): a slow `vtpmd` launch (there attributed to a ~58s PCR-unseal blocking the request handler) racing domainmgr's fixed 10s client timeout, producing a guest with no TPM device despite a perfectly good backend swtpm. It did not recur on 2026-11-03 or 2026-11-04 per the ledger, so this is a known/recurring issue first seen 2026-11-02, reappearing tonight (2026-11-05) on a different test exercising the same vtpmd/domainmgr timeout race, not a new regression. No other failures have been investigated yet in tonight's run to compare against, and no PR diff was supplied to assess code relatedness.
#### TestVaultKeyModeRecoveryOnExt4

##### Failure

```
Timed out waiting for device "edge-dev" to reboot
```

##### Claude's conclusion

###### Root cause

The device actually rebooted successfully — it just took too long for the test's fixed 5-minute budget. Live evidence from `gotest.json`: the second reboot was issued at `00:03:45`, state flipped to `REBOOTING` at `00:03:47`, and the test's `rebootAndWait` timed out at exactly `00:08:45` (the 5-minute mark, per `edgedevice.go:1386`/`vault_keymode_test.go:318`). The device then finished rebooting and reported `ONLINE` barely a minute later, at `00:09:51` (`total observed reboots this test: 2`). Live pillar logs on the now-recovered device show a completely clean boot (zboot/zedagent/baseosmgr state transitions with no errors), and `uptime` right after boot shows `load average: 5.48, 2.34, 0.89` on a device configured for 4 CPUs but seeing only 1 via `nproc` inside the guest — consistent with the shared hypervisor host being overcommitted/slow rather than any pillar hang.

This is the identical mechanism already diagnosed for `TestVaultKeyModeRecoveryOnExt4`/`TestVaultKeyModeRecoveryOnZFS` in last night's run (2026-11-04, run #7, recorded in `live-ledger.md`): successful-but-slow VM power-cycles under host contention tipping over the test's fixed 5-minute reboot timeout. It does not share a root cause with the earlier vTPM failure investigated in this run (`live-investigation.md`), which was a domainmgr/vtpmd timeout race producing a guest with no TPM device — unrelated mechanism. Per the ledger, this specific reboot-timeout failure mode first appeared 2026-11-04 and is now recurring a second night in a row, so it's a known/recurring infrastructure-contention issue, not a new regression.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKVMtoKVM

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to reconfigure disks for device "edge-dev" after installation: failed to detach disk virtio0 from device "eve-c2c4fcd9-edge-dev": bad request: 400 Parameter verification failed. - {"virtio0":"unable to apply pending change virtio0 : lvremove 'pve/vm-105-disk-1' error:   Logical volume pve/vm-105-disk-1 in use.\n"}
```

##### Claude's conclusion

###### Root cause

This failure is entirely broker/Proxmox-side, not an EVE/pillar bug — no EVE device ever came up to inspect (`evetest status` shows "No EVE devices found", `evetest sdn status` reports the SDN client was never initialized at the point of failure). The timeline from `gotest.json`/broker logs: the installer completed successfully at 22:28:30, Proxmox VM 105 was removed at 22:28:58, and just 5 seconds later (22:29:03) the broker tried to reconfigure the device's disks (detach `virtio0`) as the next step, but Proxmox rejected it with `lvremove 'pve/vm-105-disk-1' ... Logical volume pve/vm-105-disk-1 in use` — i.e., the LVM logical volume backing the just-removed VM's disk hadn't yet been released (device-mapper node still held open) when the very next Proxmox API call tried to act on it. This is a timing race on the shared Proxmox host between VM teardown and the subsequent disk-reconfigure call, exactly the class of broker-side flakiness already called out in this same night's ledger entry for `TestThreeNodesUpgrade` (run #8), which hit different Proxmox symptoms (`unexpected end of JSON input`, `no worker upid`) from host overload during concurrent VM lifecycle operations — not the identical error signature, but the same underlying mechanism (Proxmox host races/overload under rapid VM create/remove/reconfigure cycles). I found no prior occurrence of this specific `lvremove`/"Logical volume in use" signature anywhere in `live-ledger.md`, so this particular manifestation is new tonight, though it fits the broader recurring Proxmox-infra-flake pattern documented since at least 2026-11-01.
#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
timed out after 10m0.001913519s (excluding download) waiting for app "47cb8bd0-a71c-43b3-b830-a1b28b0c15a0" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

###### Root cause

Live evidence shows the device itself is severely I/O-starved: `vmstat` on `edge-dev` shows 36–61% iowait and `top`/`uptime` shows load averages of 8.5–10.9 on a 4-vCPU box, 24 minutes after boot. The pod events for the stuck app (`virt-launcher-upgrade-test-app-47cb8-0sxrl5-zmbhz`) confirm this is actively blocking boot: `kubectl get vmi` shows the VMI still stuck in `Scheduled`/`READY: False` 2m13s after scheduling, and each step of container startup (volume attach, mount, image pull-from-cache, container create) took tens of seconds apiece rather than the usual sub-second — exactly the kind of stall severe storage contention causes. The Longhorn volume backing the app is also `DEGRADED` (one replica online, two offline), though that's expected/benign on this single-node cluster rather than the proximate cause.

This is effectively the same root cause already recorded in this run's ledger entry for `TestEVEUpgradeKubevirtToKubevirt` (2026-11-05, run #8): that entry found 54% iowait and storage/control-plane pods flapping on liveness probes, blocking the K3s-node-ready wait; this occurrence shows the identical iowait/load-average signature, just caught at an earlier point in the same test (app never reaching RUNNING rather than the node never reaching fully-joined) — almost certainly the same host storage-contention episode rather than an independent bug. It does not share a root cause with the earlier `TestEVEUpgradeKVMtoKVM` failure in `live-investigation.md` (that one was a broker-side Proxmox `lvremove`/LVM-in-use race during teardown, unrelated to in-guest I/O). Per `live-ledger.md`, this storage-contention/iowait pattern stalling upgrade and other tests past their timeouts is a recurring, well-established infra flake going back to at least 2026-10-29, so this is a known/recurring issue, not a new one.
#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = EVE installation timed out or failed for device "edge-dev2"
```

##### Claude's conclusion

###### Root cause

This is the same **Proxmox host overload during concurrent multi-VM provisioning** mechanism already identified for `TestThreeNodesUpgrade` elsewhere in `live-ledger.md`, but manifesting differently tonight. The broker log shows a transient Proxmox API failure during VM setup (`Attempt 1/3: failed to upload ".../OVMF_CODE.fd" to storage "local" (will retry): ... EOF` for edge-dev3 at 23:38:52) and generally slow installer progress: all three installers started "waiting for completion" around 23:41:47–23:41:50, but `edge-dev1` and `edge-dev3` only reported "EVE installation completed" at 23:51:17–23:51:21 — i.e. within seconds of the fixed 10-minute installer timeout — while `edge-dev2` never completed at all and was torn down once its deadline hit (23:51:51/23:51:55). `evetest status`/`sdn status` now confirm no device state survives to inspect further (`No EVE devices found`, `SDN client is not initialized`).

This clearly shares the same root cause as the prior `TestThreeNodesUpgrade` failure already analyzed in this run's `live-investigation.md` (Proxmox host/broker overload during concurrent 3-VM + SDN provisioning causing installer timeouts) — same test, same timeout mechanism — though the specific symptom differs: the earlier occurrence failed immediately with `"unexpected end of JSON input"` during VM creation (no devices ever actually ran), whereas this one got all three VMs created and installers running, with two squeaking in just under the wire and the third missing the deadline, consistent with generalized host slowness rather than an outright API rejection.

Per `live-ledger.md`, `TestThreeNodesUpgrade` installer timeouts under concurrent provisioning are a long-standing, recurring known issue dating back to at least 2026-11-01 (run #4), recurring repeatedly through 2026-11-03/04 and again twice tonight — so this is a continuation of that known recurring infra flake, not a new or EVE/pillar-side bug.

## [2026-11-05 -- 0.0.0-master-c28c009e (run #8)](https://github.com/lf-edge/eve/actions/runs/41921249629)

[Full report](https://lf-edge.github.io/eve/test/master/runs/8/)

### TestApplicationConnectivitySuite: failure analysis

#### TestApplicationConnectivitySuite

##### Failure

```
failed to connect to the broker at 10.208.13.244:50221: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: no route to host"
```

##### Claude's conclusion

###### Root cause

The suite failed 3 seconds after harness startup, before any EVE device or SDN was ever provisioned — `evetest status` shows "No EVE devices found" and `evetest sdn status` reports "SDN client is not initialized." The actual error, `failed to connect to the broker at 10.208.13.244:50221 ... no route to host`, is a failure to reach the infrastructure broker that provisions devices/SDN, not an EVE/pillar networking defect — there's no device or SDN state to inspect because provisioning never started.

This doesn't share a root cause with any other failure in this run (it's the only investigated failure here). It is a partial repeat of a known issue: the ledger's 2026-11-03 (run #6) entry for `TestProfile`/`TestRadioSilence` hit the *same* broker endpoint, `10.208.13.244:50221`, but as an `i/o timeout` after the connection had been established (broker went silent mid-run). Tonight's failure is more severe — `no route to host` immediately, meaning the broker host/network is now completely unreachable rather than just stalled — so this looks like an escalation of the same recurring broker-infrastructure instability first flagged on 2026-11-03, rather than a brand-new mechanism. No PR diff was provided to assess code relatedness, and none would be relevant here since this never touched EVE/SDN code paths.

### TestDiagSuite: failure analysis

#### TestDiagSuite

##### Failure

```
failed to connect to the broker at 10.208.13.244:50221: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: no route to host"
```

##### Claude's conclusion

###### Root cause

The suite failed in `Init()` itself, 4 seconds after Adam/image-server startup, trying to establish the harness's very first gRPC connection to the Proxmox/VM-provisioning **broker** at `10.208.13.244:50221` — before any EVE device, SDN VM, or app was ever created (`evetest status` confirms "No EVE devices found", and `evetest sdn status` reports "SDN client is not initialized"). The error (`no route to host`) is an immediate network-layer rejection, not a stall, indicating the broker host/VM was unreachable from the very start of the run rather than becoming unresponsive due to anything EVE-side.

This does **not** share a root cause with anything else in this run (no other suite has failed yet) and it's a different failure mode from the only prior occurrence of this exact endpoint, `10.208.13.244:50221`, in the ledger (2026-11-03, run #6): there, the broker connection worked fine initially and only died *mid-run* (first as `i/o timeout`, later degrading to `network is unreachable`) as a downstream consequence of an `edge-dev` qemu guest wedging in host-kernel state `D` (`kvm_async_pf_task_wait_schedule`). Tonight's failure instead happens pre-anything, on the first dial attempt, with no device or guest involved — so it's not a repeat of that cascade, just a coincidentally identical IP (likely a reused DHCP lease on the Proxmox broker VM). I found no prior ledger entry matching this "broker unreachable at harness Init before any device exists" signature, so this looks like a new infrastructure-level outage (Proxmox broker host/VM down or unreachable at the network level), not a known/recurring issue and not a pillar/EVE code defect. No PR diff was provided to assess code relatedness.

### TestKonvertSuite: failure analysis

#### Shrink

##### Failure

```
Timed out waiting for device "edge-dev" to upgrade to 0.0.0-master-c28c009e-k-amd64
```

##### Claude's conclusion

###### Root cause

Live evidence shows the device itself lost contact right at the critical moment of the kvm→k conversion: Adam's db shows the last device check-in (config/info/metrics) at 00:36:57, immediately after the device entered `CONVERT_REBOOTING_TO_TARGET` (rebooting into the kubevirt/`k` target image) at 00:36:26 — it then flipped to `SUSPECT` at 00:41:58 and the harness's own SDN tunnel proxy explicitly died at 00:52:58 with `"no route to host"` after 10 failed gRPC reads. Live right now (~40 min later), the outage hasn't recovered: `evetest sdn status`, `evetest eve ssh`, `evetest eve console-output`, and `evetest eve collect-info` all fail — the SDN VM's gRPC port (`192.168.170.4:50121`) times out, and even the broker host's own console port (`10.208.13.244:50221`) times out — confirming a dead network path, not a slow device.

This is **not an isolated event** — it shares the same mechanism as several other failures already recorded in this very run's ledger tonight: `TestPNACWithProxy` (SDN uplink `no route to host` at setup), `TestFirstBootEVEKAppVolume` (device went dark after an eve-k first boot, SDN tunnel timed out, ended in `SUSPECT`), and a long cascade starting at `TestRadioSilence`/`TestProfile` where the SDN tunnel died mid-test and every subsequent test in that chain failed identically. Per `live-ledger.md`, the broad "SDN VM/gRPC tunnel becomes unreachable with `no route to host`, device goes `SUSPECT`" signature is a known, recurring issue dating back to **2026-10-29**, recurring on 2026-10-30, twice on 2026-10-31, and repeatedly again tonight — though the specific variant here (tunnel dying *mid-upgrade*, during the final reboot-to-target of a kvm→k hop, rather than at initial SDN-VM provisioning) most closely matches the newer "tunnel dies mid-test" instances logged tonight for `TestKubeRegistrationClusterSetup` and the `TestRadioSilence` cascade, which the ledger itself flags as a new variant of the same underlying Proxmox broker/SDN infrastructure instability rather than an EVE/pillar code defect. No PR diff was supplied for this investigation to assess code relatedness.

#### Grow

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

###### Root cause

This "Grow" failure is a direct downstream artifact of the **"Shrink" failure earlier in this very run**, not an independent bug. `gotest.json` shows `Shrink` (which is actually `TestKvmToKRepartitionNoVolmig`) itself failed at 01:23:03 with `edgedevice.go:862: TEST FAILURE: Timed out waiting for device "edge-dev" to upgrade to 0.0.0-master-c28c009e-k-amd64` — and in that same test's teardown, `checkRebootCounts` already logged the identical `expected 4 reboot(s) but observed 3`. Because `edge-dev` was left paused/un-torn-down, the very next subtest, "Grow", ran `Setup` against that same stuck device, immediately skipped (`the active device provider does not support required capability CAPABILITY_EDIT_DEVICE_DISK`), but its own `Close()`/`checkRebootCounts` inherited the same stale reboot-count mismatch, reproducing the byte-identical failure string.

Live checks confirm the device never completed its final reboot into the `k` (kubevirt) target: `evetest eve info` shows it's still running `IMGB` / `0.0.0-master-c28c009e-kvm-amd64` with `lastRebootReason` pinned at the repartition-reboot step, the device status is `EVE_DEVICE_STATE_SUSPECT`, SSH to it resets/times out, and `evetest sdn status` fails with `dial tcp 192.168.170.4:50121: i/o timeout` — the SDN gRPC tunnel is dead, exactly matching the already-documented SDN-tunnel-dies-mid-upgrade mechanism.

This shares the same root cause as the earlier "Shrink" failure already investigated in this run (recorded in `live-investigation.md`), and per `live-ledger.md` that underlying "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" signature is a known, recurring issue dating back to **2026-10-29**, recurring repeatedly since (including prior `TestKonvertSuite/TestKvmToKUpgrade` instances on 2026-10-30 and 2026-10-31). The specific "expected N reboots but observed N-1" symptom on "Grow" is a new manifestation of that same Proxmox/SDN infrastructure instability, not a new code regression.

#### GrowLocalNI

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

This has enough evidence to confirm the shared root cause with the earlier failures in this run.

###### Root cause

**GrowLocalNI shares the exact same root cause as the already-investigated "Shrink" and "Grow" failures earlier in this run** — it is not an independent bug. `gotest.json` shows the identical stack trace signature (`checkRebootCounts` → `Close()` → `Setup()` → `requireCapabilities` skip → `setupDevice`), confirming `GrowLocalNI` is another subtest of `TestKvmToKRepartitionNoVolmig` that inherited the same stuck `edge-dev` device left behind when "Shrink" originally timed out waiting for the kvm→k upgrade reboot.

Live evidence confirms the device never recovered: `evetest status` still shows `edge-dev` in `EVE_DEVICE_STATE_SUSPECT`, `evetest eve info` shows it's still running `10.1.0-kvm-amd64` on IMGA (never transitioned to the kubevirt target), SSH fails with "failed to detect any IP address," and `evetest sdn status` still times out dialing the SDN gRPC endpoint `192.168.170.4:50121` — the identical dead-tunnel signature already diagnosed for Shrink/Grow.

Per `live-ledger.md`, this underlying "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" signature is a known, recurring issue dating back to **2026-10-29**, recurring repeatedly since (including prior `TestKonvertSuite`/kvm-to-k upgrade instances on 2026-10-30 and 2026-10-31) — tonight's three-failure cascade (Shrink → Grow → GrowLocalNI) is simply that same single stuck-device/dead-tunnel incident propagating through every subsequent subtest in this suite run, not three separate bugs.

#### PersistTooFull

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

The backgrounded `evetest eve ssh`/`console-output` check was killed after hitting its time limit with no output ever produced — consistent with the already-reported finding that `edge-dev` and its SDN/RPC tunnel are completely unresponsive. This doesn't change my conclusion above; no further action needed.

#### ZFSPersist

##### Failure

```
failed to remove device "edge-dev" from the controller: unknown device UUID "719ac21d-1168-4b9b-94cc-8e5f4c7d10fb"
```

##### Claude's conclusion

###### Root cause

Live evidence confirms `edge-dev` is still stuck in `EVE_DEVICE_STATE_SUSPECT` (`evetest status`), `evetest sdn status` reports "SDN client is not initialized," and `evetest eve info` fails with the identical `unknown device UUID "719ac21d-..."` error — this is a direct continuation of the SDN-tunnel outage already diagnosed earlier in this same run: `edge-dev`'s SDN/gRPC tunnel died during `Shrink`/`Grow`, and the subsequent `PersistTooFull` teardown call against the broker (`10.208.13.244:50221`) timed out mid-operation (`live-investigation.md`). That timeout pattern is exactly the known "partial teardown" idempotency bug: the broker-side RPC can succeed in deleting the device record from the Adam controller but still fail/timeout overall, so the harness retries the stale teardown on the next test (`ZFSPersist`) and hits "unknown device UUID" because the device was already removed.

This exact `unknown device UUID` teardown-cascade signature (caused by an earlier SUSPECT/dead-device teardown failing non-atomically and poisoning the next test's cleanup) is a known, recurring issue — it appears in `live-ledger.md` for run #6 (2026-11-03), where it hit `TestKubeRegistrationLonghornDisks`, `TestAppLocalInfo`, `TestDevLocalInfo`, and `TestNetworkLocalChanges` with the identical error shape. It is not a new independent bug: it shares the same underlying SDN/broker outage root cause already recorded for `Shrink`, `Grow`, and `PersistTooFull` earlier in tonight's run, and the broader "teardown doesn't surface partial success, so retries hit stale UUIDs" pattern has been recurring since at least 2026-11-03.

#### TwoDiskExt4

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

Live confirms it: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT`, still running `10.1.0-kvm-amd64` (never completed the kvm→k conversion), and `evetest sdn status` reports the SDN client isn't even initialized — the exact same dead-device/dead-tunnel state already diagnosed for Shrink/Grow/GrowLocalNI/PersistTooFull/ZFSPersist earlier in this run.

**Root cause:** `TwoDiskExt4` (i.e. `TestKvmToKRepartitionTopology`) is not an independent failure — it shares the root cause already recorded in this run's `live-investigation.md`. `gotest.json` shows the identical signature: `Setup()` skips with `the active device provider does not support required capability CAPABILITY_EDIT_DEVICE_DISK` against the already-stuck `edge-dev`, and the subsequent `Close()`→`checkRebootCounts` inherits the stale reboot-count mismatch (`expected 4, observed 3`) left over from the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout, where the device never finished rebooting into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade. Live checks right now confirm the device is still stuck in `EVE_DEVICE_STATE_SUSPECT` on `10.1.0-kvm-amd64` and `evetest sdn status` reports "SDN client is not initialized" — nothing has recovered since the prior investigations. Per `live-ledger.md`, this "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" pattern is a known, recurring infrastructure issue dating back to **2026-10-29**, recurring repeatedly since (including prior `TestKonvertSuite` kvm-to-k upgrade runs on 2026-10-30 and 2026-10-31), and tonight's entire cascade (Shrink → Grow → GrowLocalNI → PersistTooFull → ZFSPersist → TwoDiskExt4) is one single stuck-device/dead-SDN-tunnel incident propagating through every subsequent subtest, not a new code regression.

#### TwoDiskZFS

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

This confirms it: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT`, still on `10.1.0-kvm-amd64` (never completed the kvm→k conversion), and the SDN client is still not initialized — identical to the state found for every prior failure in this run.

**Root cause:** `TwoDiskZFS` is not an independent failure — it's the same cascade already documented in `live-investigation.md` for `Shrink`/`Grow`/`GrowLocalNI`/`PersistTooFull`/`ZFSPersist`/`TwoDiskExt4`. `gotest.json` shows the byte-identical signature: `Setup()` skips on `the active device provider does not support required capability CAPABILITY_EDIT_DEVICE_DISK` against the already-stuck `edge-dev`, and `Close()` → `checkRebootCounts` then reproduces the stale `expected 4 reboot(s) but observed 3` left over from the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout, where the device never finished rebooting into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade. Live checks right now reconfirm the unrecovered state: `edge-dev` is `EVE_DEVICE_STATE_SUSPECT` on `10.1.0-kvm-amd64`, and `evetest sdn status` reports "SDN client is not initialized." Per `live-ledger.md`, this "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" pattern is a known, recurring infrastructure issue dating back to **2026-10-29**, recurring repeatedly since — so the full cascade tonight (Shrink → Grow → GrowLocalNI → PersistTooFull → ZFSPersist → TwoDiskExt4 → TwoDiskZFS) is one single stuck-device/dead-SDN-tunnel incident, not a new code regression.

#### TwoDiskZFSWhole

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

Live state confirms this is the exact same unrecovered incident already diagnosed in this run: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT` on `10.1.0-kvm-amd64` (never completed the kvm→k reboot), `evetest eve info` fails with the same stale UUID `719ac21d-1168-4b9b-94cc-8e5f4c7d10fb` seen for `ZFSPersist`/`TwoDiskExt4`/`TwoDiskZFS`, and `evetest sdn status` still reports "SDN client is not initialized."

**Root cause:** `TwoDiskZFSWhole` is not a new bug — it's the same cascade documented in `live-investigation.md`, propagating from the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout where the device never finished rebooting into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade. Every subsequent subtest (`Grow` → `GrowLocalNI` → `PersistTooFull` → `ZFSPersist` → `TwoDiskExt4` → `TwoDiskZFS` → `TwoDiskZFSWhole`) inherits the identical stuck device and reproduces the same `checkRebootCounts` mismatch (`expected 4, observed 3`). Per `live-ledger.md`, this "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" signature is a known, recurring infrastructure issue dating back to 2026-10-29, recurring repeatedly since (including prior `TestKonvertSuite` kvm→k upgrade runs on 2026-10-30 and 2026-10-31) — tonight's entire run is one single incident, not eight separate regressions.

#### ZFSTail

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

Confirmed: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT`, still on `10.1.0-kvm-amd64` (never completed the kvm→k conversion), and the SDN client is still not initialized — identical to the state found for every prior failure in this run.

**Root cause:** `ZFSTail` is not a new independent bug — it's the same cascade already documented in `live-investigation.md`. `gotest.json` shows the byte-identical stacktrace signature (`Setup()` skips via `requireCapabilities` on `CAPABILITY_EDIT_DEVICE_DISK` against the already-stuck `edge-dev`, then `Close()` → `checkRebootCounts` reproduces the stale `expected 4 reboot(s) but observed 3`) seen for `Grow`, `GrowLocalNI`, `PersistTooFull`, `ZFSPersist`, `TwoDiskExt4`, `TwoDiskZFS`, and `TwoDiskZFSWhole` — all downstream of the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout where the device never finished rebooting into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade. Live checks right now reconfirm the unrecovered state (`SUSPECT`, still on `10.1.0-kvm-amd64`, SDN client "not initialized"). Per `live-ledger.md`, the "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" signature is a known, recurring infrastructure issue dating back to **2026-10-29**, recurring repeatedly since — so tonight's entire cascade (Shrink → Grow → GrowLocalNI → PersistTooFull → ZFSPersist → TwoDiskExt4 → TwoDiskZFS → TwoDiskZFSWhole → ZFSTail) remains one single stuck-device/dead-SDN-tunnel incident, not a new code regression.

#### TestKvmToKVolumeMigration

##### Failure

```
failed to remove device "edge-dev" from the controller: unknown device UUID "719ac21d-1168-4b9b-94cc-8e5f4c7d10fb"
```

##### Claude's conclusion

**Root cause:** `TestKvmToKVolumeMigration` is not an independent bug — it's the same ongoing cascade already fully diagnosed earlier in this run. Live checks reproduce the identical signature seen for every prior failure tonight: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT`, `evetest eve info` fails with the same stale UUID `719ac21d-1168-4b9b-94cc-8e5f4c7d10fb` already seen for `ZFSPersist`/`TwoDiskExt4`/`TwoDiskZFS`/`TwoDiskZFSWhole`/`ZFSTail`, and `evetest sdn status` still reports "SDN client is not initialized." This all traces back to the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout, where the device never finished rebooting into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade — the controller teardown for that stuck device partially succeeded (deleting the record) but the overall RPC timed out, so every subsequent test's teardown now hits "unknown device UUID" against the same already-deleted record. Per `live-ledger.md`, this "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" infrastructure pattern is known and recurring since **2026-10-29** (recurring on 2026-10-30, 2026-10-31, and in run #7 under `TestNetworkLocalChanges`/`TestClusterVMApp`), so tonight's entire chain (Shrink → Grow → GrowLocalNI → PersistTooFull → ZFSPersist → TwoDiskExt4 → TwoDiskZFS → TwoDiskZFSWhole → ZFSTail → TestKvmToKVolumeMigration) remains a single stuck-device/dead-SDN-tunnel incident, not a new code regression.

#### TestFirstBootEVEKAppVolume

##### Failure

```
failed to remove device "edge-dev" from the controller: unknown device UUID "719ac21d-1168-4b9b-94cc-8e5f4c7d10fb"
```

##### Claude's conclusion

Confirmed — identical failure signature (same device UUID, `SUSPECT` state, "SDN client is not initialized").

###### Root cause

`TestFirstBootEVEKAppVolume` shares the exact same root cause as every prior failure already investigated in this run (`Shrink`, `Grow`, `GrowLocalNI`, `PersistTooFull`, `ZFSPersist`, `TwoDiskExt4`, `TwoDiskZFS`, `TwoDiskZFSWhole`, `ZFSTail`, `TestKvmToKVolumeMigration`), per `live-investigation.md`. Live checks right now reproduce the byte-identical state: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT`, `evetest eve info` fails with the exact same stale UUID `719ac21d-1168-4b9b-94cc-8e5f4c7d10fb` already seen in `ZFSPersist`/`TestKvmToKVolumeMigration`, and `evetest sdn status` still reports "SDN client is not initialized" — the SDN/gRPC tunnel never recovered. This all traces back to the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout where the device never finished rebooting into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade; the controller teardown for that stuck device partially succeeded (deleting the record) but the overall RPC timed out, so every subsequent test's teardown — including this one — now hits "unknown device UUID" against the already-deleted record. Per `live-ledger.md`, this "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" infrastructure pattern is a known, recurring issue dating back to **2026-10-29**, recurring on 2026-10-30, 2026-10-31, and in run #7 — so this is the 11th failure in the same single stuck-device/dead-SDN-tunnel cascade tonight, not a new or independent regression.

#### TestKvmToKZFSVaultMigration

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

This is the exact same signature confirmed live: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT`, still on `10.1.0-kvm-amd64` (never completed the kvm→k reboot), `evetest sdn status` still reports "SDN client is not initialized," and `evetest eve info` still fails with the identical stale UUID `719ac21d-1168-4b9b-94cc-8e5f4c7d10fb` seen throughout this run.

**Root cause:** `TestKvmToKZFSVaultMigration`'s "expected 4 reboot(s) but observed 3" is not an independent bug — it's the same ongoing cascade documented in `live-investigation.md`, which traces back to the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout where `edge-dev` never completed its final reboot into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade. That stuck, un-torn-down device (and its dead SDN tunnel) has since propagated the identical `checkRebootCounts` mismatch through every subsequent subtest in this suite run (Shrink → Grow → GrowLocalNI → PersistTooFull → ZFSPersist → TwoDiskExt4 → TwoDiskZFS → TwoDiskZFSWhole → ZFSTail → TestKvmToKVolumeMigration → TestFirstBootEVEKAppVolume), and this is simply the next one in that same chain. Per `live-ledger.md`, the underlying "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" signature is a known, recurring infrastructure issue dating back to **2026-10-29**, recurring on 2026-10-30, 2026-10-31, and in run #7 — so this is the 12th failure tonight stemming from the same single stuck-device/dead-SDN-tunnel incident, not a new or independent regression.

#### TestKvmToKZFSVaultPowerCutMidSwap

##### Failure

```
Device "edge-dev": expected 4 reboot(s) but observed 3
```

##### Claude's conclusion

Live state is identical to every prior failure in this run: `edge-dev` is still `EVE_DEVICE_STATE_SUSPECT` on `10.1.0-kvm-amd64` (never completed the kvm→k reboot), `evetest eve info` fails with the same stale UUID `719ac21d-1168-4b9b-94cc-8e5f4c7d10fb`, and `evetest sdn status` still reports "SDN client is not initialized."

###### Root cause

`TestKvmToKZFSVaultPowerCutMidSwap` is not an independent bug — `gotest.json` shows the byte-identical signature already seen for the other 12+ failures tonight: `Setup()` skips via `requireCapabilities` on `CAPABILITY_EDIT_DEVICE_DISK` against the already-stuck `edge-dev`, and `Close()` → `checkRebootCounts` then reproduces the stale "expected 4 reboot(s) but observed 3". This traces back to the original `Shrink` (`TestKvmToKRepartitionNoVolmig`) timeout documented in `live-investigation.md`, where `edge-dev` never completed its final reboot into the kubevirt target because the SDN VM/gRPC tunnel died mid-upgrade, and the stuck/un-torn-down device has since propagated the same mismatch through every subsequent subtest (Shrink → Grow → GrowLocalNI → PersistTooFull → ZFSPersist → TwoDiskExt4 → TwoDiskZFS → TwoDiskZFSWhole → ZFSTail → TestKvmToKVolumeMigration → TestFirstBootEVEKAppVolume → TestKvmToKZFSVaultMigration → this one). Per `live-ledger.md`, the underlying "SDN VM/gRPC tunnel becomes unreachable, device goes SUSPECT" infrastructure signature is a known, recurring issue dating back to 2026-10-29, recurring on 2026-10-30, 2026-10-31, and in run #7 — so this is simply the 13th failure tonight stemming from that same single stuck-device/dead-SDN-tunnel incident, not a new or independent regression.

### TestKubeRegistrationSuite: failure analysis

#### TestKubeRegistrationSuite

##### Failure

```
failed to connect to the broker at 10.208.13.244:50221: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: no route to host"
```

##### Claude's conclusion

Only `2026-11-03` (run #6) mentions this broker address. The failure that night escalated progressively — `i/o timeout` → `network is unreachable` — after a wedged qemu guest hung the host kernel, and it cascaded through ~10 subsequent tests in that run via leftover-device teardown calls. Tonight's run #7 ledger entries (checked earlier) don't mention it, so it cleared overnight.

Live checks now confirm this is a fresh failure, not a teardown-cascade like 11-03's: `evetest status` shows **"No EVE devices found"** and `evetest sdn status` returns **"SDN client is not initialized"** — this is the very first test of the run, and it failed inside `harness.go:923` (`evetest.Init`) while making the *initial* broker connection, before any device or SDN state existed to tear down.

###### Root cause

The evetest harness's `TestKubeRegistrationSuite` died at startup (4 seconds in) trying to open its very first gRPC connection to the device/VM broker at `10.208.13.244:50221`, getting `connect: no route to host` — i.e. the broker host itself is currently unreachable at the network layer from this runner, not merely slow or refusing connections. Since nothing in this run preceded it, there's no earlier failure in tonight's run to share a root cause with, and this isn't a device/SDN-side bug — `evetest` never got far enough to create either.

This is a recurring address: the ledger shows this exact broker endpoint (`10.208.13.244:50221`) suffered a severe, multi-hour outage on **2026-11-03** (known since then), triggered that night by a qemu guest wedged in the host kernel (`kvm_async_pf_task_wait_schedule`) that froze the broker's ability to service RPCs, escalating from `i/o timeout` to `network is unreachable` and cascading through roughly ten subsequent tests via teardown retries. That incident had cleared by last night's run (11-04, run #7 — no mention of this address there). Tonight's failure is a **new occurrence against the same broker host**, with a different symptom (`no route to host`, failing on the very first connection attempt rather than a later-established one going stale) — consistent with the broker VM/host being down or unreachable again right now, though I can't confirm from here whether it's the identical underlying mechanism as 11-03 or a fresh instance of host/network flakiness on that machine. No PR diff was provided for this investigation.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 6m0.000724059s (excluding download) waiting for app "0ca96fa1-9c6c-403f-b03e-1f494b57385d" () on device "edge-dev1" to reach RUNNING state (last state: INVALID)
```

##### Claude's conclusion

No prior mention of this specific mechanism. I have enough evidence to write the conclusion.

###### Root cause

`vm2`'s `AppInstanceConfig` on `edge-dev1` still shows `DesignatedNodeUUID` pointing at edge-dev3's node ID with `IsDesignatedNodeID:false`, so zedmanager logs `"not designated"` on every tick (23:09:50–23:16:49) and never activates the VM — matching the device's own `ENClusterAppStatus` (`IsDNidNode:false ScheduledOnThisNode:false AppKubeStatus:NotInCluster`) and the empty `kubectl get vmirs/vmi` output for vm2. The backup-DNID path that's supposed to override this (`zedmanager/dnidbackup.go`'s `isCurrentlyBackupDNIDForApp`) is gated on `ctx.isAppOpLeader`, and edge-dev1's own log shows exactly why it's permanently blocked: at 22:55:50.728 edge-dev1 acquired the `eve-app-op` Kubernetes lease and zedmanager logged `"app-op leader false -> true (holder edge-dev1)"`, but 1ms later, at 22:55:50.729, zedkube's `OnNewLeader` callback (firing right after `OnStartedLeading` for the same, self-held lease) republished `KubeLeaderElectInfo` and zedmanager logged `"app-op leader true -> false (holder edge-dev1)"` — flipping leadership off even though edge-dev1 is still the lease holder. No further `handleKubeLeaderElectInfo` log line ever appears for the rest of the run, so `ctx.isAppOpLeader` stayed stuck at `false` for the entire test, structurally preventing any backup-DNID takeover regardless of how long edge-dev3 stayed down.

This is a different, earlier-stage mechanism than the `TestDNIDandBackupDNID`/zedmanager gap already recorded twice in `live-ledger.md` (`handleENClusterAppStatusImpl` republishing stale status for a pod placed on a non-DNID node with no outage, and `getKubeAppActivateStatus`'s purge-after-failover deadlock) — those occurred *after* a node was correctly recognized as backup; tonight's failure never gets that far because the app-op leadership flag itself never stabilizes true. This specific `OnStartedLeading`/`OnNewLeader` race on the `eve-app-op` lease doesn't appear anywhere in the ledger, so it's a new failure mode, not a previously known recurring issue, though it belongs to the same general "DNID/backup-DNID reporting gap" theme already flagged for this test suite. No PR diff was supplied for this run to assess code relatedness.

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

That's sufficient corroboration. I have enough evidence now to write the conclusion.

###### Root cause

This is the same known, recurring zedmanager/zedkube "purge-after-failover" deadlock in `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go`), reproducing again tonight with the identical signature — and it is unrelated to the other failure already investigated in this run (`TestDNIDandBackupDNID`, an app-op-leader-flag race). Live evidence on edge-dev2 confirms it: `AppInstanceStatus` for `failover-purge-app` (uuid `12ab426e-...`) shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-05T00:05:29Z`, `Activated:false`, `IsDesignatedNodeID:false`, and zedmanager has been logging an unbroken loop of `getKubeAppActivateStatus(12ab426e-...): not designated, node c88fb1c1-..., onTheDevice false, statusRunning false` every ~20s continuously since the purge began. `evetest status` shows edge-dev1 (the designated node) in `EVE_DEVICE_STATE_SUSPECT`, deliberately downed for the failover scenario, so once the purge tore down the VMIRS nothing in the cluster can create a new one — matching the test's `found []`.

Per `live-ledger.md`, this exact mechanism in `TestVMAppPurgeDuringFailover` has been a known/recurring issue since **2026-10-29** (run #1), and has reproduced in every subsequent nightly run through 2026-11-04 (run #7) — this is at least the 7th consecutive occurrence, not a new bug. No PR diff was supplied for this run to assess code relatedness.

#### TestClusterPVCRedownload

##### Failure

```
timed out after 30m0.01215994s (excluding download) waiting for app "a753218f-8dc5-4e2f-857f-af57be4bd10e" (vm1) on device "edge-dev1" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

This confirms "SDN no route to host" / gRPC connectivity loss is a well-documented recurring infra pattern tied to Proxmox host contention across many prior nightly runs. I have enough to write the conclusion.

###### Root cause

Live evidence and `gotest.json` show `vm1` entered `BOOTING` normally at 00:36:31, but 6 minutes later (00:42:22) all three devices flipped `ONLINE→SUSPECT` simultaneously, and at 00:53:06 the harness's entire SDN/broker gRPC connection died with repeated `rpc error: code = Unavailable ... no route to host`, followed by `EOF`/`context canceled` on the tunnel proxy — and it never reconnected for the rest of the 30-minute wait. This is confirmed live right now: `evetest sdn ssh` and `evetest sdn status` both still fail with `dial tcp 192.168.170.7:50121: i/o timeout`, i.e. the SDN control-plane link has been dead for 15+ minutes since the test paused, so the harness simply lost visibility into `vm1`'s real state rather than `vm1` actually hanging in guest boot.

This is the same infrastructure failure mode already investigated earlier tonight in `TestClusterToSingleConversion` (dead/unrecovered broker-SDN gRPC connection, identical `no route to host`/`EOF` signature, also never reconnecting) — not the same root cause as the other paused failure in this run (`TestVMAppPurgeDuringFailover`'s zedmanager purge-after-failover deadlock), which is a distinct, already-known code-level bug. Per `live-ledger.md`, this general "SDN gRPC no route to host" / Proxmox-host-contention connectivity-loss pattern is a long-standing recurring issue (cited across multiple prior nightly entries, e.g. `TestInfoRetriedAfterServerError` 2026-11-01, various VM-create/console-timeout cases), so tonight's `TestClusterPVCRedownload` failure looks like another instance of that known infra flakiness rather than a new or EVE/pillar code defect. No PR diff was supplied for this run to assess code relatedness.

### TestNodeClusterSuite: failure analysis

#### TestAppInstancePurge

##### Failure

```
timed out after 10m0.019319076s (excluding download) waiting for app "018b84ae-4989-44e9-9336-f09c68fc7fd2" (purge-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Both prior tests in this run (`TestSingleNodeCluster`, `TestNativeKubeAppNetworking`) passed, so this failure isn't shared with another in-run incident. I have enough evidence for a root cause.

**Likely root cause:** At 23:14:10, `edge-dev` (the single node) was cordoned as part of `TestAppInstancePurge`'s own purge/node-drain logic, which evicted the `coredns` pod (`zedkube` log: "evicting pod kube-system/coredns-...") — but since this is a single-node cluster, cordoning knocked out DNS for the whole node. From 23:14:45 through 23:24:37, `volumemgr`'s `RolloutDiskToPVC` repeatedly failed every 30s with `dial tcp: lookup longhorn-backend on 10.43.0.10:53: ... connection refused`, because CoreDNS was down. Once DNS/CoreDNS recovered and volumemgr retried at 23:29:22, it hit a second, non-retriable failure: `CopyImgDirToRawImg: Failed to create raw image file ... /persist/vault/volumes/e0218765-...-pvc-0.img already exists` — a stale `.img` file left over from the earlier aborted attempt (confirmed live: the file exists on disk, timestamped 23:20, and `volumemgr`'s `gcVolumes` is still logging `found unknown format volume` for it). This error doesn't match the "transient cluster-storage error" pattern that triggers `retryFailedClusterVolumeCreate`, so the volume has been permanently stuck in `CREATING_VOLUME` since 23:29:22 with no further retry logged, which is exactly the 10-minute timeout the test hit. This is a new failure signature for `TestAppInstancePurge` — the ledger's prior entries for this test are all a different, already-diagnosed mechanism (cluster-mode-not-carried-forward reboot from a preceding test), not this self-cordon/DNS-outage/stale-file sequence — and it doesn't share a root cause with any other failure in this run, since the two preceding tests (`TestSingleNodeCluster`, `TestNativeKubeAppNetworking`) both passed.

#### TestMgmtProxy

##### Failure

```
Failed to setup devices [edge-dev2 edge-dev3 edge-dev1]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev3": failed to apply SDN configuration: 500 got no worker upid - start worker failed
```

##### Claude's conclusion

**Likely root cause:** This failed before any EVE device or SDN object was ever created (`evetest status`/`evetest sdn status`/`evetest eve info` all confirm "No EVE devices found"/"SDN client is not initialized"). The broker log (`gotest.json`) shows `edge-dev1` and `edge-dev2` were successfully prepared as Proxmox VMs 110/111, but then at 00:05:05 the call to apply SDN configuration for `edge-dev3` hit a Proxmox API error: `500 got no worker upid - start worker failed` — meaning pvedaemon couldn't even spawn a background task worker for that API call, a transient host-level resource/overload condition on the shared Proxmox host, not an EVE/pillar defect.

This does **not** share a root cause with the other failure already investigated in this run (`TestAppInstancePurge`'s DNS/stale-volume issue on a single-node cluster) — that was a self-cordon/CoreDNS/volume bug unrelated to Proxmox provisioning.

It **is** a known/recurring pattern per `live-ledger.md`: the exact `"500 got no worker upid - start worker failed"` pvedaemon signature has appeared repeatedly on prior nights (e.g. run #7 on 2026-11-04 during VM teardown, and another occurrence during `qmcreate` for VM 132 on an earlier run), always attributed to the shared Proxmox host being overloaded under concurrent multi-VM/SDN provisioning — alongside sibling symptoms like TLS handshake timeouts and truncated/`unexpected end of JSON input` API responses. This specific occurrence (failing during "apply SDN configuration" rather than VM creation) is a new variant of that same underlying host-overload pattern rather than a brand-new failure mode.

#### TestClusterVMApp

##### Failure

```
Timed out waiting for app "c6f46a3c-b91c-466b-810a-f3615616afef" to be scheduled in cluster "test-cluster"
```

##### Claude's conclusion

**Likely root cause:** This failure shares the same root cause as the earlier-tonight incident already in this run's ledger (`TestTieBreakerCluster`/`TestClusterVMApp`, 23:35:42): the evetest broker/SDN gRPC tunnel died again. `gotest.json` shows all three devices flipped `ONLINE→SUSPECT` at 00:42:22 (14 minutes into the 30-minute wait for app `c6f46a3c` to be scheduled, which started at 00:28:21), then at 00:52:39 the SDN tunnel proxy, broker log stream, and keepalive all failed with `no route to host`, and the tunnel proxy gave up after 10 failed retries at 00:52:41 — roughly 6 minutes before the test's 00:58:21 timeout fired. Live right now confirms the connection is still dead: `evetest sdn status` and `evetest cluster info` fail with `dial tcp 192.168.170.6:50121: i/o timeout`, and `evetest eve ssh`/`kubectl` to any device fail with "failed to detect any IP address," identical symptoms to the earlier incident. This is a second, independent occurrence of the same broker/SDN gRPC-link-death mechanism within this one run — not a continuation of the first outage (the cluster had fully recovered and was healthy, with apps/volumes running normally, from ~00:08 through 00:28 before this fresh failure). The ledger does have prior entries with this exact error string ("Timed out waiting for app ... to be scheduled"), but those (`TestClusterPVCGCDeletesOnlyOrphans`, `TestMgmtProxy`) were caused by etcd/control-plane overload under resource contention, a different mechanism than this one's SDN-tunnel death — so while the error message itself is a recurring generic timeout string, this specific infrastructure cause (broker↔SDN gRPC link dying mid-test) is not yet a separately tracked recurring ledger entry, it's just reproduced twice tonight.

### TestPcibackErrorSuite: failure analysis

#### TestPcibackErrorSuite

##### Failure

```
failed to connect to the broker at 10.208.13.244:50221: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: no route to host"
```

##### Claude's conclusion

###### Root cause

`TestPcibackErrorSuite` failed in harness `Init()` (`harness.go:923`), ~3 seconds after startup, trying to establish its very first gRPC connection to the Proxmox broker at `10.208.13.244:50221` — it got `no route to host`. This is before any EVE device or SDN VM was ever provisioned: `evetest status` shows "No EVE devices found," `evetest sdn status` reports "SDN client is not initialized," and the Adam `device`/`onboard` DB directories are empty. So this isn't an EVE/pillar bug — the failure never reached pillar code at all — it's an infra-level inability to reach the shared Proxmox broker host.

This doesn't share a root cause with anything else in the current run — only this one `evetest` instance is active, so there's nothing else to correlate against tonight.

Per the ledger, the broker endpoint `10.208.13.244:50221` becoming unreachable is a recurring theme dating back to **2026-11-03 (run #6)**, where it first appeared as `i/o timeout` / `network is unreachable` during later-stage teardown calls (`TestRadioSilence`, `TestProfile`, and the whole `TestNetworkAdapterPassthrough*`/`TestStagedNICChange`/`TestNICCountChange*` cascade), itself traced back to a wedged qemu guest. However, tonight's signature is distinct and not an exact previous match: it's a `no route to host` failure on the *very first* connection attempt in `Init`, before any device/SDN existed — the ledger explicitly notes (line 670) that "this exact signature (broker connection itself at port 50221 timing out) doesn't appear in the ledger," and tonight's variant (immediate routing rejection at Init, rather than a later timeout after a device had been created) hasn't been recorded before either. So this looks like the same class of recurring broker-connectivity infrastructure issue (known since 2026-11-03), but manifesting in a new way (earlier in the lifecycle, different error) rather than an exact repeat.

### TestStorageSuite: failure analysis

#### TestVaultZvolTrimReclaimsBlocks

##### Failure

```
Timed out waiting for cluster node "edge-dev" to become ready
```

##### Claude's conclusion

This is enough evidence to establish the root cause confidently. Let me write it up.

###### Root cause

Live evidence from `edge-dev`'s `kube-init` log (`/persist/kubelog/k3s-install.log`) shows the real first boot sequence: k3s started with `phase=first-boot` at 23:08:49, but crashed during image import (`IMPORTING → BACKOFF (reason: k3s-exited-during-import)`) at 23:10:22. When `kube-init` restarted k3s 5s later, it logged `k3s started (pid=7792, phase=steady)` — the daemon's internal phase had been reset from `first-boot` to `steady` across that restart. Because `handleWaitK3sReady` only enters `StateDeploying` (the state that runs `components.DeployComponents`, installing KubeVirt and Longhorn) when `d.phase == PhaseFirstBoot`, the reset phase caused it to take the `default` branch instead: `WAIT_K3S_READY → RUNNING (reason: k3s-ready/skip-deploy)`. Multus and CDI got applied anyway via a separate baseline step, but **KubeVirt and Longhorn were never installed**. The periodic convergence checker (`pkg/kube/kube-init/update/cluster.go`) then treated the missing components as benign (`component kubevirt not installed, skipping`, `component longhorn not installed, skipping`) and marked the cluster "all components at version 3" — permanently hiding the gap from any self-healing retry. Confirmed live: `kubectl get pods -A`/`get ns` show no `kubevirt`/`longhorn-system` namespace at all, zedbox is stuck in an infinite loop `could not get KubeVirt CR: ... (get kubevirts.kubevirt.io kubevirt)`, and `kube-init` itself is still looping forever on `kubevirt feature-gate migration: ... the server could not find the requested resource`. This is why `WaitForClusterNodeIsReady` can never succeed — it's not a transient readiness race but components that were structurally never deployed.

This does not match any entry in `live-ledger.md` (the ledger's prior cluster-readiness timeouts are a different, plural-worded "cluster nodes" check with apiserver-contention races during multi-node formation) — this specific `kube-init` phase-reset/skip-deploy bug is a new finding, not previously recorded. It's also unrelated to the other failures in this run (TestApplicationGateway's host-contention onboarding delay, etc.) — this is a distinct, device-local bug triggered by a k3s crash during first-boot image import.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```

Timed out after 1200.001s.
Expected to satisfy: K3s node is ready
nodes:{name:"edge-dev" conditions:{type:KUBE_NODE_CONDITION_TYPE_READY set:true last_transition_time:{seconds:1793840451}} role_server:true creation_timestamp:{seconds:1793840451} api_server_sersion:"v1.34.2+k3s1" internal_ip:"172.20.20.123" schedulable:true admission_status:NODE_ADMISSION_JOINING node_id:"0aa14186-62c4-4948-a7fd-01d83c81f51b"} storage:{health:SERVICE_STATUS_FAILED transition_time:{seconds:-62135596800}} cluster_id:"00000000-0000-0000-0000-000000000000"
```

##### Claude's conclusion

54% iowait confirms severe storage contention — this matches the exact signature cited throughout the ledger for other failures tonight and prior nights.

**Likely root cause:** `edge-dev` is severely I/O-starved post-upgrade — `top` on the live device shows 54% iowait and a load average of 15-19 on a 4-vCPU box, 24 minutes after boot. Kubernetes events confirm this is actively crippling the cluster: nearly every control-plane/add-on pod (coredns, metrics-server, virt-operator, virt-controller, cdi-apiserver) is failing liveness/readiness probes with `context deadline exceeded`/`connection refused` and being killed/restarted repeatedly, a Longhorn image pull took 1m49s for an 87MB image that should be near-instant from local cache, and Longhorn's `engine-image`/`instance-manager` pods are still stuck `ContainerCreating` — which is exactly why `storage.health` stays `SERVICE_STATUS_FAILED` and the node never reaches `NODE_ADMISSION_JOINED` within the test's 1200s window, even though `kubectl` itself already reports the node `Ready`. This is a new failure signature for `TestEVEUpgradeKubevirtToKubevirt` — the only prior ledger occurrence (2026-11-04, run #7, same test) was a different mechanism (a genuine SCSI medium error crashing the guest disk), so this isn't a repeat of that exact bug, but it matches the broader recurring pattern seen repeatedly across this same tonight's run and prior nights (e.g. tonight's `TestApplicationGateway`/`TestSwitchNIPortConfigRace`, and going back to 2026-10-29) of shared host/Proxmox storage contention stalling EVE-side control-plane work past fixed test timeouts — i.e., infrastructure overload rather than an EVE/pillar code regression.

#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev3 edge-dev1 edge-dev2]: rpc error: code = Unknown desc = EVE installation timed out or failed for device "edge-dev1", EVE installation timed out or failed for device "edge-dev3", EVE installation timed out or failed for device "edge-dev2"
```

##### Claude's conclusion

This confirms a well-established recurring pattern dating back weeks, with the exact same "unexpected end of JSON input" Proxmox API signature.

**Root cause:** Same mechanism as the prior `TestThreeNodesUpgrade` failure recorded earlier tonight in this same run's live-investigation.md and matching the 2026-11-04 (run #7) ledger entry almost verbatim — Proxmox host/broker overload during concurrent multi-VM provisioning (3 EVE VMs + 1 SDN VM created at once). The broker log shows the same `"Attempt 1/3: failed to get storage \"local\" (will retry): unexpected end of JSON input"` truncated Proxmox API response at 01:32:01, VM creation for edge-dev2 lagging ~3 minutes behind its siblings (not "prepared" until 01:34:44 vs 01:32:35/37 for the others), and then all three installers ran for the full 10-minute window (01:32:42–01:42:54) without ever completing — `evetest status`/`sdn status` now confirm no device or SDN object was ever actually initialized, matching the pattern of the host never actually executing the VMs rather than an EVE-side installer bug. This is the same root cause as the earlier `TestThreeNodesUpgrade` failure already investigated in this run's `live-investigation.md`, and per `live-ledger.md` this exact "unexpected end of JSON input"/Proxmox-overload-under-concurrent-provisioning pattern is a long-standing, recurring known issue going back to at least 2026-11-01 (run #4), recurring repeatedly through 2026-11-03/04 — i.e. infrastructure flakiness, not an EVE/pillar code regression.

## [2026-11-04 -- 0.0.0-master-74f919b8 (run #7)](https://github.com/lf-edge/eve/actions/runs/41726823083)

[Full report](https://lf-edge.github.io/eve/test/master/runs/7/)

### TestApplicationConnectivitySuite: failure analysis

#### TestApplicationGateway

##### Failure

```
failed to onboard device "edge-dev": context deadline exceeded
```

##### Claude's conclusion

**Root cause:** `edge-dev`'s Proxmox VM (109) was powered on at 00:06:46, and the harness began polling for onboarding at 00:07:01 with a 10-minute deadline, failing at 00:16:46. But the device's console log shows its GRUB/kernel boot didn't actually start until ~00:19:23 (containerd init at 00:19:32), and it didn't reach the Adam controller (first `/ping`) until 00:21:04 and `/register` at 00:22:00 — i.e. the VM sat idle for ~12.5 minutes between the "powered on" API success and actual firmware execution, well past the onboarding timeout, even though once it did start, boot-to-onboard proceeded at normal speed. Live `vmstat`/`loadavg` on the still-running device right now show elevated iowait (32–49%) and load 4.6 on a 4-vCPU box, consistent with host-side storage/scheduling contention delaying the VM from actually running rather than any EVE guest software defect.

This doesn't share a root cause with other failures in this run (each test here failed independently with its own onboarding attempt). Per the ledger, "failed to onboard device ... context deadline exceeded" is a recurring *symptom* (seen 2026-10-29, 2026-11-01, 2026-11-03 earlier run) but with varying underlying causes — a cascading broker/SDN-endpoint outage, a guest hang after containerd start, and once (2026-11-01, `TestClusterPVCRedownload`) attributed to Proxmox host TLS-handshake stress. Tonight's signature (long pre-boot stall, not a post-boot hang, plus live iowait evidence) most closely resembles that 2026-11-01 host-stress case, but it's not confirmed to be the identical mechanism, so I'd call this a recurring *symptom class* rather than a pinpointed repeat bug — likely Proxmox host/storage contention, not a pillar/EVE regression. No PR diff was provided to assess code relatedness.

#### TestAccessVLANs

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: App1 receives IP from VLAN 100 subnet
AppID:"5fde85c7-1f19-4754-b6be-e41be0729e91"  appVersion:"1"  AppName:"vlan100-app"  bootTime:{seconds:1793754214  nanos:685082090}  state:RUNNING  network:{macAddr:"02:16:3e:00:00:01"  devName:"vif0"  defaultRouters:"<nil>"  dns:{}  localName:"nbu1x2"}  volumeRefs:"c308442b-4371-40fe-b87c-2d9c0eb23849"  cluster_app_running:true
```

##### Claude's conclusion

###### Root cause

Both VLAN test VMs on `edge-dev` are alive at the EVE/zedrouter level (reached `RUNNING`, correct VLAN config applied — `nbu1x2`/vlan100-app tagged `accessPort vid:100`, `nbu1x1`/vlan200-app tagged `vid:200`, trunk `eth1` carrying `vids:[100,200]`, matching the SDN network model), but the actual **guest kernels never make forward progress**: `evetest eve app-metrics` shows `vlan100-app`'s network counters frozen at `txBytes:90 txPkts:1` for 700+ seconds, and live `top`/`ps` on the device show both app qemu processes (PIDs 6705, 6659) pegged at **100% CPU continuously** (R state) on a 4-vCPU host already at load average ~5. A 30s `tcpdump` on both `nbu1x1`/`nbu1x2` shows zero non-STP traffic — the guests never even attempt a DHCP discover — so this is a guest-hang/busy-loop, not a VLAN-tagging or SDN misconfiguration.

This is the same **class** of failure already captured in `live-ledger.md`: `TestLocalNIWithMultiplePorts` in run #5 (2026-11-02) first hit a qemu process wedged via `kvm_async_pf_task_wait_schedule` on this same host kernel (`6.18.55-linuxkit-core`), and that exact mechanism recurred and cascaded through `TestAccessVLANs` and many subsequent tests in run #6 (2026-11-03) too. Tonight's manifestation differs in detail (the vCPU threads are spinning at 100% CPU rather than blocked in uninterruptible `D` state), but it's the same underlying nested-KVM/host-scheduling pathology rather than a pillar/EVE code regression — so this looks like a **recurring, known-since-2026-11-02 infrastructure issue**, not a new independent bug. It is unrelated to this run's other investigated failure (`TestApplicationGateway`'s pre-boot Proxmox power-on stall), which was a different mechanism (host delay before the VM even started executing, not a post-boot guest hang).

#### TestSwitchNIPortConfigRace

##### Failure

```

Timed out after 180.001s.
Expected to satisfy: app has IPs from both application subnets
AppID:"43acd3d4-f492-41da-9081-19a7ba2d3a20"  appVersion:"1"  AppName:"container-app"  bootTime:{seconds:1793758520  nanos:700501723}  state:RUNNING  network:{macAddr:"02:16:3e:00:00:01"  devName:"vif0"  IPAddrs:"fe80::16:3eff:fe00:1"  defaultRouters:"<nil>"  dns:{}  localName:"nbu1x1"}  network:{macAddr:"02:16:3e:00:00:02"  devName:"vif1"  defaultRouters:"<nil>"  dns:{}  localName:"nbu2x1"}  volumeRefs:"1151d67c-42c8-42bc-9150-36bced40cd51"  cluster_app_running:true
```

##### Claude's conclusion

No prior match — this exact mechanism (zedagent deferred-queue stall) hasn't been recorded in the ledger before.

###### Root cause

**This is an infrastructure/host-resource-contention stall, not a networking defect, and it shares the same root cause as this run's earlier `TestApplicationGateway` failure.** zedrouter actually assigned both app IPv4 addresses correctly and promptly — `AppNetworkStatus`/`NetworkInstanceStatus` on the live device show `10.53.20.180` (vif0, multiswitch-ni) and `10.53.100.181` (vif1, vlan-switch-ni) both present by **02:16:10**, well inside the test's 180s window (02:15:27–02:18:27). zedagent's own log confirms it queued (`SetDeferred`) the correct `ZiApp` info — with both IPs — for the controller at that exact timestamp. But zedagent's `handleDeferred`/send loop then went completely silent: no further "Trying to send" attempts occurred between 02:15:33.658 and 02:18:36.944, a gap the device's own watchdog flagged explicitly: `"DeferredEvent handler in zedagent took a long time (longer than the error threshold): 183"` / `"StillRunning(zedagentDeferredEvent) took a long time: 183"`, with a second handler (`zedagentconfig`) also logging similar stalls. The queued info (already containing both IPs) wasn't actually delivered to Adam until 02:18:36 — just 9 seconds *after* the test's 180s timeout fired at 02:18:27 — confirming the real-world state was correct the whole time; only its delivery to the controller was delayed past the deadline.

Live `vmstat`/`loadavg` on the still-running device right now show the same signature already diagnosed for `TestApplicationGateway` earlier in this run: load average 5.3–5.7 on a 4-vCPU box with iowait 39–57%, i.e. the VM/host is storage-I/O-starved enough to stall in-process goroutines/watchdog timers for minutes at a time. This strongly suggests tonight's `TestSwitchNIPortConfigRace` failure is a direct instance of the same Proxmox host/storage contention already identified for `TestApplicationGateway` in this run, rather than an independent bug — both show real EVE-side work completing correctly but host-level resource starvation delaying the control-plane signal past the test's deadline. This specific zedagent-deferred-queue-stall mechanism doesn't appear anywhere in `live-ledger.md`, so it's not a previously-known recurring issue from past nightlies, though it fits the same broader pattern of Proxmox host storage/scheduling contention seen repeatedly across prior runs (e.g. 2026-11-01's `TestClusterPVCRedownload`, 2026-10-29's onboarding timeouts). No PR diff was supplied for this investigation to assess relatedness to in-flight code changes.

#### TestSwitchNIDeletedWithAppsAttached

##### Failure

```
app "564a20b1-30cb-4e41-8458-65cad6a1e7a9" (app-1) on device "edge-dev" download stalled at 57% for more than 5m0s
```

##### Claude's conclusion

###### Root cause

Live evidence pinpoints a hung **containerd registry-client goroutine during a manifest-fetch call made while pulling a specific OCI blob**, not a network-instance or app-connectivity defect. `app-1`'s image (`lfedge/evetest-ubuntu-ctr`) has 7 blobs to pull from the SDN's local registry (`192.168.170.2:5000`); 6 of them follow the normal pattern — a quick "trying to fetch manifest" → "unable to fetch manifest (unsupported schema manifest...)" failure in under 5s, then a successful blob-fallback fetch — but the 28MB layer `sha256:7a48b8f0...` logged "trying to fetch manifest" at 02:44:16.345 and **never logged anything again**, leaving its `DownloaderStatus` pinned at `Progress:0, TotalSize:0` ever since (confirmed live: `downloader` is still emitting "Update progress ... 0/0" every second at 02:51+, 7+ minutes later). `(39489576 completed bytes)/(69257188 total bytes) = 57%`, exactly matching the reported stall percentage. `/proc/net/tcp` on the device shows a still-`ESTABLISHED` connection to `192.168.170.2:5000` with a stuck non-empty `tx_queue` (533 bytes, 11 retransmits) and zero `rx_queue` progress — a sent-but-never-acknowledged/answered request, consistent with a wedged manifest-GET rather than a registry crash (the registry itself answers `curl .../v2/` with `200` right now).

This is the same signature and mechanism already catalogued in `live-ledger.md` for `TestFlowLog`/`TestSwitchNetInstanceACLsWithFlowLog` in `TestApplicationConnectivitySuite` — a registry-manifest-resolution call against this same SDN local registry hanging forever for one specific blob/tag while sibling pulls of the same image complete normally — a **known, recurring downloader bug dating back to 2026-10-31**, recurring again on 2026-11-02 and now tonight. It does **not** share a root cause with this run's other already-investigated failures (`TestApplicationGateway`'s Proxmox pre-boot stall, `TestSwitchNIPortConfigRace`'s host-iowait-induced zedagent deferred-queue stall) — those were host-resource-contention issues, whereas this is a networking/registry-client hang specific to blob/manifest resolution.

### TestAppsSuite: failure analysis

#### TestVGAPassthroughNoHostAccess

##### Failure

```
Host processes interfered with PCI devices while the VGA controller 0000:00:01.0 was passed through to the application:
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11153 parent=runc:[1:CHILD]/11152 grandparent=runc:[0:PARENT]/11150
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11153 parent=runc:[1:CHILD]/11152 grandparent=runc:[0:PARENT]/11150
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11153 parent=runc:[1:CHILD]/11152 grandparent=runc:[0:PARENT]/11150
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11153 parent=runc:[1:CHILD]/11152 grandparent=runc:[0:PARENT]/11150
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11153 parent=runc:[1:CHILD]/11152 grandparent=runc:[0:PARENT]/11150
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11153 parent=runc:[1:CHILD]/11152 grandparent=runc:[0:PARENT]/11150
Kernel messages mentioning 0000:00:01.0:
[    1.451141] [    T1] pci 0000:00:01.0: [1234:1111] type 00 class 0x030000 conventional PCI endpoint
[    1.455492] [    T1] pci 0000:00:01.0: BAR 0 [mem 0x80000000-0x80ffffff pref]
[    1.456229] [    T1] pci 0000:00:01.0: BAR 2 [mem 0x8264d000-0x8264dfff]
[    1.456834] [    T1] pci 0000:00:01.0: ROM [mem 0xffff0000-0xffffffff pref]
[    1.457544] [    T1] pci 0000:00:01.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    1.784697] [    T1] pci 0000:00:01.0: vgaarb: setting as boot VGA device
[    1.784697] [    T1] pci 0000:00:01.0: vgaarb: bridge control possible
[    1.785061] [    T1] pci 0000:00:01.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    1.982114] [    T1] pci 0000:00:01.0: Adding to iommu group 1
[  157.839056] [ T2640] vfio-pci 0000:00:01.0: vgaarb: deactivate vga console
[  157.839074] [ T2640] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  180.019125] [ T7593] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
[  180.320876] [ T7593] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  575.211534] [T11177] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
```

##### Claude's conclusion

This fully confirms the diagnosis with live evidence this run. I have enough to write the conclusion now.

###### Root cause

Live evidence confirms this is a false positive in the test harness's PCI-violation tracer, not a real host-interference bug. `evetest eve ssh "ps -eLo pid,tid,ppid,comm"` on `edge-dev` shows PID 11153 is `vga-passthrough-app`'s own `qemu-system-x86_64` process (`-name eef7d66a-64b6-4232-991f-7ced03d08e9e.1.1`), and TID 11177 within that *same* process is the kernel-renamed vCPU thread `CPU 0/KVM` — exactly the `comm` flagged in the failure as "host interference." The kernel log's `vfio-pci 0000:00:01.0: Invalid PCI ROM header signature` lines are also benign guest-side ROM re-probe noise during the app's own restart, not evidence of an external actor touching the device.

This is a long-standing, well-documented recurring issue in `live-ledger.md`: `pciAccess.isViolation()` (`evetest/tests/apps/pciaccess_helpers_test.go:408-413`) only whitelists config-space writes when `comm` has prefix `"qemu-system-"`, but QEMU's vCPU thread renames itself to `CPU N/KVM` while sharing the owning process's PID — so its config-space writes during `[app-restart]` get misclassified as host interference. The ledger traces this back to the test's introduction on 2026-09-27 (commit `c2539a9de`) and shows it recurring on at least 2026-09-27, 2026-10-29, 2026-10-30, and intervening runs, always with the identical `comm=CPU 0/KVM` + `[app-restart]` signature — so tonight's failure is the same unfixed known issue, not a new regression, and unrelated to any other test/PR activity.

### TestControllerFaultsSuite: failure analysis

#### TestInfoRetriedAfterServerError

##### Failure

```
failed to get device "edge-dev" ECDH certificate: unexpected status from GET https://127.0.0.1:443/admin/device/cf1480c4-0ecb-4ec9-8d46-e2484b01b82a/certs: 400
```

##### Claude's conclusion

Only this one test ran in this suite so far — no other failure in this run to share a root cause with. I have enough evidence to conclude.

###### Root cause

The test failed in setup, before fault injection was even armed: `evetest/setup.go`'s `onboardEVEDevice` polls Adam's admin `/certs` endpoint for the device's ECDH certificate and gives up after 11 failed attempts (~55s). Live evidence shows the device (`edge-dev`, first boot at `00:48:17`) is unusually slow this run — `top`/`vmstat` on the live device show 35‑49% iowait with 2‑3 processes blocked on I/O and a load average of ~5.5 on a 4-vCPU guest, 5 minutes after boot. The device's `tpmmgr`-generated `EdgeNodeCert` files only land on disk at `00:49:xx`, and the device doesn't actually POST its certs to Adam (`/api/v2/edgedevice/certs`) until `00:50:21` — well past the harness's ~55s polling window, which is why Adam's `deviceCertsGet` kept failing with "no such file" and the admin API call eventually returned 400. Device log delivery itself stalled at `00:48:14` and never resumed, consistent with system‑wide I/O starvation delaying boot-critical work rather than a pillar logic bug.

This is not the same issue as the one prior `TestInfoRetriedAfterServerError` ledger entry (2026‑11‑01), which failed on an unrelated SDN-tunnel `no route to host` flake before the device ever onboarded — tonight's device onboarded and got a network fine, it was just too slow publishing its cert. So this is a **new failure mode** for this test, though it fits the broader recurring theme already in the ledger (e.g. `TestMgmtProxy`, `TestTieBreakerCluster` entries) of Proxmox-host resource contention causing slow disk/CPU on EVE guests on overloaded nights. No other test failed earlier in this run to share a root cause with, and no PR diff was supplied to assess relatedness.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume e43bad25-3820-4b9a-b2a7-afc01e8f2238
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

This confirms the exact same live mechanism as the prior two occurrences. I have sufficient evidence for the root cause.

###### Root cause

This is the identical tie-breaker/Longhorn gating bug already diagnosed twice earlier tonight for this same test, now a third occurrence. Live evidence: `edge-dev2` is labeled `tie-breaker-node=true` (`SchedulingDisabled`), its `VolumeStatus` for `e43bad25-3820-4b9a-b2a7-afc01e8f2238` (`pvc-gc-persistent`) is permanently stuck at `State:109` (`CREATING_VOLUME`), and volumemgr is continuously logging `WaitForLonghornReady: not ready yet: longhorn daemonset:engine-image-ei-b4bcf0a5 missing on this node` every ~5s right now (23:06:24–23:06:39) with no progress — because Longhorn's daemonsets are deliberately never scheduled on the tie-breaker/witness node, so `kubeapi.WaitForLonghornReady` can never succeed there. Per `pkg/pillar/kubeapi/longhorninfo.go:720-721`, callers must check `EdgeNodeClusterConfig.IsTieBreakerNode` and skip this wait, but `volumehandlers/csihandler.go`'s `PrepareVolume` calls it unconditionally, so it hangs forever on this node for any PVC expected there.

This is a known, recurring issue within tonight's run: identical root cause and mechanism were already logged earlier tonight for the same test on `edge-dev2` with volume `18355a22-...` (first occurrence) and again with volume `efb4e4cd-...` (second occurrence), both per `live-ledger.md`. This third occurrence confirms the bug is still unfixed and reproducible on every run of this test — not a flake, but a standing code gap in `PrepareVolume`'s tie-breaker-node handling.

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This is an exact, live confirmation of the same deadlock pattern documented in the ledger. I have enough evidence to write the conclusion.

###### Root cause

This is the identical, already-known zedmanager/zedkube "purge-after-failover" deadlock in `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2059`), reproducing exactly the same mechanism documented for this test earlier in this same run (`live-investigation.md`, prior attempt at line 169 with the identical "found []" signature) and recorded as a known/recurring bug in `live-ledger.md` since **2026-10-29**, reproducing again on 2026-10-30 and 2026-10-31.

Live evidence on edge-dev2: the app's `AppInstanceStatus` for `failover-purge-app` (uuid `6e1364c5-...`) shows `PurgeInprogress:4`, `PurgeStartedAt:2026-11-03T23:28:28Z`, `IsDesignatedNodeID:false`, `Activated:false`, and zedmanager has logged an unbroken stream of `getKubeAppActivateStatus(6e1364c5-...): not designated, node 474fc00f-..., onTheDevice false, statusRunning false` every ~20s from 23:34:59 through 23:44:29 (and presumably since the purge). `kubectl -n eve-kube-app get vmirs,vmi,vm` returns "No resources found" cluster-wide, matching the test's `found []`. `evetest status` confirms edge-dev1 (the designated node) is `EVE_DEVICE_STATE_SUSPECT`, deliberately down for this failover test — so once the purge tore down the old VMIRS, nothing in the cluster can originate a new one, exactly as previously diagnosed.

This is a reproduction of the same standing bug, not a new issue — same test, same failure line, same root-cause mechanism confirmed live again tonight.

### TestSecuritySuite: failure analysis

#### TestVaultKeyModeRecoveryOnExt4

##### Failure

```
Timed out waiting for device "edge-dev" to reboot
```

##### Claude's conclusion

I have enough evidence to form a conclusion.

**Root cause:** Live evidence shows the device actually did reboot successfully, just too slowly for the test's fixed 5-minute budget. The reboot was issued at 23:24:57, `nodeagent` applied its normal 30s `minRebootDelay`, then actually called `zboot [reset]` at 23:26:27 (`Got zbootMutex.lock. Executing zboot [reset]`, from `/persist/newlog/keepSentQueue/dev.log.1793748638619.gz`). But the new kernel didn't start booting until roughly 23:28:59 (back-computed from the console's early dmesg timestamps), and the device wasn't SSH-reachable/fully up until ~23:29:10 — a ~2.5 minute gap between the `zboot reset` call and the VM actually restarting, well beyond the normal shutdown/startup time this same test showed for its first cold boot earlier (power-on at 23:21:20 to config-confirmed at 23:24:55, ~3m35s including onboarding). `evetest`'s `rebootAndWait` (`edgedevice.go:1262`) timed out at exactly the 5-minute mark (23:29:57), just ~47s after the device was actually SSH-reachable again, and the device currently shows an elevated host load average (4.79/2.26/0.89 three minutes after boot) consistent with hypervisor/host-level resource contention slowing the VM's power-cycle rather than any EVE/pillar logic hanging — pillar's own shutdown sequence logged cleanly right up to the `zboot reset` call with no errors.

This does not match any prior `TestVaultKeyModeRecoveryOnExt4`/`TestVaultKeyModeRecoveryOnZFS` entries in `live-ledger.md` — every previous occurrence (2026-10-29, -30, -31, -11-02) was a stale-test-expectation failure on the attempt-count or log-count assertions, never a reboot timeout. So this is a **new failure mode** for this test, though it fits the same broader, well-documented pattern in the ledger of the shared Proxmox host becoming slow/overloaded under concurrent nightly load (e.g. "no worker upid" VM-create failures, SDN "no route to host", console-output timeouts) — i.e., infrastructure contention, not an EVE/pillar regression. No PR diff was supplied for this run to assess relatedness to in-flight code changes.

#### TestVaultKeyModeRecoveryOnZFS

##### Failure

```
Timed out waiting for device "edge-dev" to reboot
```

##### Claude's conclusion

I have enough evidence to conclude.

**Root cause:** This shares the same root cause as the already-investigated `TestVaultKeyModeRecoveryOnExt4` failure earlier in this run. Live evidence: the harness's two prior reboots in this ZFS test (issued 23:45:40 and 23:50:30) both succeeded but took 4m23s and 3m55s respectively — already close to the test's fixed 5-minute budget. The third reboot (issued 23:55:17, state→REBOOTING at 23:55:19) simply tipped over that budget: `evetest status`/console show the device genuinely still progressing through boot right now (containerd connecting to service shims as of 00:02:35, ~7 minutes after the reboot was issued, well past the 00:00:17 timeout), not hung — no pillar/kernel errors, no SSH/IP failures other than "not up yet." This is a slow VM power-cycle (hypervisor/host contention) exceeding a fixed 5-minute test timeout, exactly the mechanism documented in `live-investigation.md` for the Ext4 variant earlier tonight, just manifesting on a different reboot iteration within the same test file/flow. Per `live-ledger.md`, prior `TestVaultKeyModeRecoveryOnZFS`/`Ext4` failures (2026-10-29 through 11-02) were all a different, known issue (stale hardcoded attempt-count assertion) — this reboot-timeout failure mode is new as of tonight, first seen on the Ext4 variant earlier in this same run and now recurring on the ZFS variant, reinforcing that it's infrastructure/host slowness rather than an EVE/pillar regression. No PR diff was provided for this run to assess further relatedness.

### TestTelemetrySuite: failure analysis

#### TestKernelPanicReport

##### Failure

```

Timed out after 600.001s.
the kernel panic stack trace end marker was not uploaded
Expected
    <<-chan evetest.LogMsg | len:0, cap:100>: 0x20c7b7407650
to receive something.
```

##### Claude's conclusion

###### Root cause

This is the same evetest-side bug recorded in the ledger for `TestKernelPanicReport` back on **2026-10-29 (run #1)** — a `device.WatchLogs(...)` subscription silently failing to deliver a log line that was already sitting in Adam's store, rather than a pillar/EVE regression. Tonight it manifested on the "end marker" watch instead of the "header" watch, but it's the identical mechanism and identical failure signature (`Timed out ... ReceiveMatcher's channel *must* receive something`), so this is a **known, recurring issue dating back at least to 2026-10-29**.

Live/artifact evidence:
- On the device, `/persist/newlog/keepSentQueue/dev.log.1793744697654.gz` (already marked sent, not in `failedUpload`) contains all three strings the test watches for — `"Kernel panic stack trace from pstore..."` (22:24:55.897), a `kernel_panic_stacks` line (22:24:55.899), and `"Kernel panic stack trace: end of stack"` (22:24:55.921) — all within the same 24ms burst and same uploaded chunk.
- Adam's own on-disk device-log store (`adam-db/device/.../logs/01793744694150870944`, written at 22:25:36) also contains all three strings, confirming the controller received and persisted the full batch, including the end marker.
- `adam-stdout` shows no errors, disconnects, or stream resets around this window — the controller side is clean.
- The test independently opened three separate `WatchLogs` subscriptions (header/stack/end); the first two received their matching entries fine, but the third ("end marker") channel received nothing for the full 600s timeout despite the exact matching line being present in Adam seconds after the panic — pointing to a per-subscription miss/race in `AdamClient.SubscribeToDeviceLogs` (`evetest/controller/adam.go`), not a data-loss or upload problem in EVE itself.

This run has no other failed suites to correlate with, and no PR diff was supplied to assess relatedness to in-flight code changes.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```

Timed out after 180.001s.
The function passed to Eventually failed at /evetest/tests/upgrade/upgrade_test.go:297 with:
Unexpected error:
    <*fmt.wrapError | 0xcc6e3feb2a0>: 
    unable to reach app "45607639-f840-4df4-bd41-5a0e2fff5ca6" SSH on device "edge-dev": no reachable endpoint among [172.20.20.123:2222 [fe80::d1c9:aefe:8e97:8bab]:2222]
    {
        msg: "unable to reach app \"45607639-f840-4df4-bd41-5a0e2fff5ca6\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.20.123:2222 [fe80::d1c9:aefe:8e97:8bab]:2222]",
        err: <*errors.errorString | 0xcc6da395890>{
            s: "no reachable endpoint among [172.20.20.123:2222 [fe80::d1c9:aefe:8e97:8bab]:2222]",
        },
    }
occurred
```

##### Claude's conclusion

**Root cause:** The guest VM itself was crash-looping on a real disk-level fault, not a network/SSH problem. Host kernel dmesg on `edge-dev` shows `sd 6:0:0:1: [sda] ... Sense Key: Medium Error / Unrecovered read error` (critical medium error, both read and write) at 00:05:29 against the Longhorn iSCSI-attached volume backing `upgrade-test-app`'s root disk — Kubernetes events confirm this translated into `Warning IOerror ... VM Paused due to IO error at the volume: disk1`, after which the VMI crashed and KubeVirt's replicaset recreated it (`0nlz6v` → `02cwpm`, a fresh iSCSI session on `sdb`), resetting the guest's boot/uptime cycle and the DNAT'd SSH endpoint never stayed up long enough inside the 180s `Eventually` window. `evetest eve kubectl get volumes.longhorn.io` still shows the volume `degraded` (one replica unhealthy) post-recovery, consistent with this. This is unrelated to the test's own `TestEVEUpgradeKVMtoKVM`/`TestEVEUpgradeKVMtoKVMWithOCIDatastore` siblings in this run, which both passed, so it's isolated to this device/volume rather than a global upgrade regression.

This exact signature (medium-error/SCSI hardware fault crashing a KubeVirt guest's disk) doesn't appear anywhere in `live-ledger.md` — it's new tonight, not a previously-known recurring issue (the closest prior ledger entry, from the "Shrink" subtest, was a different failure: PVC running out of backing space, not a hardware medium error). The most recent commit, `cc75c82cc` ("kubeapi: harden the storage check before cluster app failover", merged 2026-11-03 14:37 UTC), is topically adjacent — it hardens Longhorn replica-health detection during cluster app failover — but this run is a plain reboot/upgrade test on a single-node cluster, not a node-failover scenario, and the failure is a genuine SCSI medium error rather than a replica-counting bug, so I don't see direct evidence tying it to that commit; it looks more like transient storage/iSCSI-stack flakiness in the test environment.

#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = EVE installation timed out or failed for device "edge-dev2", EVE installation timed out or failed for device "edge-dev1", EVE installation timed out or failed for device "edge-dev3"
```

##### Claude's conclusion

TestThreeNodesUpgrade/TestUpgradeSuite itself hasn't failed before in the ledger, but the failure signature is a very well-established recurring one.

**Root cause:** This is Proxmox broker/host overload during concurrent multi-VM provisioning, not an EVE/pillar bug. The broker log shows a transient `"failed to get storage \"local\": unexpected end of JSON input"` (truncated Proxmox API response) while creating all three EVE VMs plus the SDN VM concurrently at 00:13:34–00:14:34; all three installers then ran from ~00:17:02 for a full 10 minutes without ever completing, and on teardown Proxmox again failed with `"500 got no worker upid - start worker failed"` (pvedaemon couldn't spawn a task worker) when deleting VM 107 — live `evetest status`/`sdn status` confirm no device or SDN object was ever actually initialized. This is unrelated to the earlier `TestEVEUpgradeKubevirtToKubevirt` failure in this same run (a genuine guest-side SCSI medium error on a Longhorn volume). It is, however, the same recurring infra-flake *pattern* already in `live-ledger.md`: identical `"unexpected end of JSON input"` truncated-API and `"no worker upid"` worker-spawn failures appear repeatedly, including earlier tonight (2026-11-03, run #6) and as far back as 2026-11-01 (run #4) — always attributed to the shared Proxmox host being overloaded under concurrent VM provisioning, which this three-node test (4 VMs at once) triggers more readily than single-device tests.

## [2026-11-03 -- 0.0.0-master-0d924b61 (run #6)](https://github.com/lf-edge/eve/actions/runs/41533378623)

[Full report](https://lf-edge.github.io/eve/test/master/runs/6/)

### TestApplicationConnectivitySuite: failure analysis

#### TestFlowLog

##### Failure

```
timed out after 5m0.001271295s (excluding download) waiting for app "41532f6b-eddb-42b1-ab63-bb55158fbc0a" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

###### Root cause

Live evidence confirms the app is still wedged in `RESOLVING_TAG`: `evetest eve app-info` shows `flowlog-test-app` (uuid `41532f6b-...`) stuck there, and its `ContentTreeStatus` (`22d7521b-...`) shows `State:101` (RESOLVING_TAG) with `ContentSha256` never populated. The downloader log shows `MaybeAddResolveConfig`/`handleResolveCreate` fired normally at 22:21:35.954 and started a `manifestsDescImg(192.168.170.2:5000/lfedge/evetest-ubuntu-ctr:1.0)` tag-resolution call against the SDN's local registry — but unlike every other resolve/pull in this same log (which complete in well under a second, logging "Resolve config Done"/"download complete"), this one never logs anything further, 6+ minutes later. The registry itself is healthy right now (`curl http://192.168.170.2:5000/v2/` → `200`), and `/proc/net/tcp` on the device shows a live `ESTABLISHED` connection to `192.168.170.2:5000` with a stuck non-empty `tx_queue` and no `rx_queue` progress — consistent with a hung request/goroutine rather than a registry outage or routing failure.

This is the same signature and mechanism already diagnosed in `live-ledger.md` for the **2026-10-31 (run #3)** nightly, where both `TestFlowLog` and `TestSwitchNetInstanceACLsWithFlowLog` (same `TestApplicationConnectivitySuite`) failed identically: a `runResolveHandler` tag-resolution goroutine in the downloader logs `lookupResolveStatus(...) not found` and then hangs forever instead of completing or erroring, while sibling resolves for the same image on the same device proceed fine. That entry concluded it was a newly-appearing (not previously seen before 10-31), unfixed downloader bug — so this is a **known, recurring issue dating back to 2026-10-31**, now recurring again tonight (2026-11-02) with the same `TestFlowLog` test and the same hung-resolve mechanism. No PR diff was supplied for this run to assess relatedness to in-flight code changes.

#### TestLocalNetInstanceACLs

##### Failure

```

Timed out after 300.000s.
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

This specific test/condition hasn't appeared in the ledger before, so it's a new occurrence — though it matches a known failure *pattern*.

###### Root cause

The test itself already holds at the state it's waiting for: `evetest eve ni-info` on the live device shows network instance `local-ni` (`6e1ee8a3-...`) already `ZNETINST_STATE_ONLINE` with both VIFs' IP assignments present (`02:16:3e:00:00:01` → `10.11.12.3`, `02:16:3e:00:00:02` → `10.11.12.2`), and the device's own `dnsmasq.leases` file shows these leases were granted at `22:31:38Z` — before the test even began waiting. Adam's on-disk `info/` store for this device confirms this NI's data was published to the controller exactly **once**, in the single message at `22:32:56Z` (file `01793658776244446708`, the same instant apps reached RUNNING and NI went ONLINE) — it never appears in any subsequent periodic info dump through `22:39Z`. This matches `prepareAndPublishNetworkInstanceInfoMsg` in `pkg/pillar/cmd/zedagent/handlenetworkinstance.go`/`reportinfo.go`: zedagent only republishes `ZInfoNetworkInstance` on a `NetworkInstanceStatus` change, never periodically, so once that one message (which already had both IPs) was consumed by the preceding `Eventually(niUpdates).Should(Receive(...ONLINE...))` assertion, the second `Eventually(niUpdates)` at `acls_test.go:246` had no further message to ever receive and timed out after 5 minutes despite the real device state already satisfying the predicate the whole time.

This is the same class of bug already recorded in the ledger for `TestKernelPanicReport` (2026-10-28, `TestTelemetrySuite`): a test-side `Watch*`/`Eventually(Receive(...))` channel subscription silently missing data that was already present before/at the moment the assertion window opened, rather than a pillar regression — but it's a different watch path (NI info vs. log streaming) and hasn't itself appeared in the ledger before, so this is a new instance of a recurring pattern rather than a previously-seen exact issue. It is unrelated to the earlier `TestFlowLog` failure in this same run (that was a downloader tag-resolution hang on a separate, non-reused device).

#### TestLocalNIWithMultiplePorts

##### Failure

```

Timed out after 311.561s.
The function passed to Eventually failed at /evetest/tests/networking/routing_test.go:841 with:
Unexpected error:
    <*fmt.wrapError | 0xfd756b53300>: 
    unable to reach app "e4ae20a3-cf56-4c56-a7f3-71ef0a4f533e" SSH on device "edge-dev": no reachable endpoint among [172.22.10.15:2222 172.28.20.10:2222 192.168.30.13:2222]
    {
        msg: "unable to reach app \"e4ae20a3-cf56-4c56-a7f3-71ef0a4f533e\" SSH on device \"edge-dev\": no reachable endpoint among [172.22.10.15:2222 172.28.20.10:2222 192.168.30.13:2222]",
        err: <*errors.errorString | 0xfd7567c26d0>{
            s: "no reachable endpoint among [172.22.10.15:2222 172.28.20.10:2222 192.168.30.13:2222]",
        },
    }
occurred
```

##### Claude's conclusion

No prior occurrences in the ledger. This looks like a new, previously unrecorded issue.

###### Root cause

The `multi-port-app` VM itself is frozen, not a networking/NAT misconfiguration: the NI (`multi-port-ni`) is online, port-forward DNAT rules for port 2222 are correctly programmed on all three `portfwd`-labeled uplinks (eth0/eth1/eth2), yet `ping`/`nc` to the app's own bridge IP `10.50.0.2:22` from the device itself time out. Its qemu process (pid 6434) is stuck in kernel state `D`, blocked in `kvm_async_pf_task_wait_schedule → __kvm_handle_async_pf → exc_page_fault`, and the host kernel has been logging "task qemu-system-x86:6434 blocked for more than N seconds" since 23:15:38 (368s and counting). App metrics confirm the guest stopped making CPU progress (`cpu.total_ns` flatlined at 8797570000 from upTime ~907s onward) while `rxBytes`/`rxPkts` also froze — consistent with the vCPU thread being permanently wedged rather than the guest being slow or the network path being broken. Host memory is healthy (6.4GB free, no swap, PSI ~0), ruling out memory pressure as the trigger, which points to a lost-wakeup/host-kernel KVM async-page-fault bug (kernel `6.18.55-linuxkit-core`) rather than resource exhaustion.

This is unrelated to the two earlier failures already recorded in this run's `live-investigation.md` (`TestFlowLog`'s downloader tag-resolution hang and `TestLocalNetInstanceACLs`'s missed pubsub-info-republish race) — different subsystem and different device/app entirely. It also does not match anything in `live-ledger.md` (no prior `kvm_async_pf`/hung-task entries), so this appears to be a new, not-previously-recorded failure mode: a frozen guest VM due to a stuck host-kernel KVM async page-fault handler, rather than a pillar/EVE code regression.

#### TestAccessVLANs

##### Failure

```
failed to onboard device "edge-dev": context deadline exceeded
```

##### Claude's conclusion

This background `evetest sdn status` call (left over from earlier investigation) was killed after reaching its time limit — it never returned, which is consistent with the finding already reported: the SDN VM for this test is unreachable/wedged. No further action needed; analysis above stands.

#### TestNetworkAdapterPassthrough

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

###### Root cause

Teardown for `TestNetworkAdapterPassthrough` failed because it's reusing (and trying to tear down) device `edge-dev` left over from the previous test, and that device's RPC/agent endpoint (`10.208.13.244:50221`) is unreachable — `evetest status`, `evetest eve info`/`console-output` all currently fail or time out dialing that same address, and the device is stuck in `EVE_DEVICE_STATE_UNDEFINED` with no interfaces. Critically, `gotest.json` shows this exact endpoint (`10.208.13.244:50221`) was already failing a minute earlier, during `TestAccessVLANs` at 23:57:48 ("Failed to retrieve console output for device edge-dev ... i/o timeout"), i.e. the outage predates this test and has been continuous.

This chains directly back to `TestLocalNIWithMultiplePorts` (the failure immediately preceding these in this same run), whose root cause in `live-investigation.md` was a frozen qemu guest on `edge-dev` wedged in host-kernel state `D`, blocked in `kvm_async_pf_task_wait_schedule`, with the host logging hung-task warnings starting at 23:15:38. A qemu process stuck in uninterruptible sleep would make the device agent managing it unable to respond to management RPCs (console, teardown, etc.), explaining why every subsequent operation against `edge-dev` — including this teardown — times out dialing the same host/port. So this is the same root cause as the earlier `TestLocalNIWithMultiplePorts` failure in this run, not an independent bug, and its effects cascaded forward through `TestAccessVLANs` into this one. This specific "failed to tear-down all devices"/`i/o timeout` symptom doesn't appear in `live-ledger.md`, so as a distinct symptom it's new tonight, but it's a downstream consequence of the already-known-tonight wedged-qemu/`kvm_async_pf` host kernel issue rather than a separate new bug.

#### TestNetworkAdapterPassthroughChange

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

I have enough evidence now.

###### Root cause

This failure is directly cascaded from the same root cause as the immediately preceding `TestNetworkAdapterPassthrough` failure recorded in this run's `live-investigation.md`: both fail dialing the exact same broker/device-agent endpoint, `10.208.13.244:50221`, with `i/o timeout`. The `gotest.json` log shows `TestNetworkAdapterPassthroughChange`'s setup explicitly detected the prior test failure ("Previous test failed; not reusing its devices"), tried to tear down the leftover `edge-dev`/SDN from `TestNetworkAdapterPassthrough`, and hit the identical timeout dialing `10.208.13.244:50221` — i.e. the outage never cleared between the two tests. Live checks right now confirm the endpoint is still dead: `evetest sdn status` → "SDN client is not initialized", `evetest eve info`/`ssh edge-dev` → device not onboarded, "network model not applied", SSH resets the connection — consistent with the broker/SDN host at that address being completely unreachable rather than merely slow.

Per `live-investigation.md`, this traces back further to `TestLocalNIWithMultiplePorts`, where `edge-dev`'s qemu process wedged in host-kernel state `D` (blocked in `kvm_async_pf_task_wait_schedule`) starting at 23:15:38, which cascaded into `TestAccessVLANs` and `TestNetworkAdapterPassthrough` already failing on the same `10.208.13.244:50221` timeout — so this is the same ongoing outage continuing to cascade, not an independent bug. This specific exact failure/endpoint combination isn't itself in `live-ledger.md` as a prior nightly occurrence, but the earlier `kvm_async_pf` hung-task mechanism it stems from is also new to this run (no prior ledger match), so there's no evidence yet that it's a previously-known recurring issue — it looks like one ongoing incident within tonight's run.

#### TestStagedNICChange

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: network is unreachable"
```

##### Claude's conclusion

No prior occurrences of either in the ledger — confirms this is new to tonight's run, not a previously-known recurring issue.

**Root cause:** This is the same ongoing cascading outage already diagnosed earlier in this run, not an independent bug. Live checks right now show `edge-dev` still stuck `EVE_DEVICE_STATE_UNDEFINED` with no interfaces, "not onboarded," and SDN reporting "network model not applied, therefore cannot discover IP of device" / "SDN client is not initialized" — identical symptoms to the `TestNetworkAdapterPassthrough`/`TestNetworkAdapterPassthroughChange` failures already recorded in `live-investigation.md`. `gotest.json` confirms `TestStagedNICChange`'s `Setup()` explicitly tried to tear down this same leftover `edge-dev`/SDN state (since the prior test failed, its devices weren't reused) and hit the same broker/device-agent endpoint `10.208.13.244:50221`, this time with `connect: network is unreachable` rather than the earlier `i/o timeout` — i.e. the network path to that endpoint has degraded further (host/route now actively refusing rather than merely stalling), but it's the same unresolved outage, never having cleared. Per `live-investigation.md`, this traces back to `TestLocalNIWithMultiplePorts`'s qemu guest wedging in host-kernel state `D` (blocked in `kvm_async_pf_task_wait_schedule`) starting 23:15:38, which has since cascaded through `TestAccessVLANs`, `TestNetworkAdapterPassthrough`, and `TestNetworkAdapterPassthroughChange` into this failure. Neither this exact endpoint/error nor the underlying `kvm_async_pf` hung-task mechanism appears anywhere in `live-ledger.md`, so this is not a previously-known recurring issue — it's a continuation of the single new incident introduced tonight.

#### TestNICCountChange

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: network is unreachable"
```

##### Claude's conclusion

This confirms it: `TestNICCountChange` failed instantly in `Setup()`, trying to tear down the leftover `edge-dev`/SDN from `TestStagedNICChange` (which itself was tearing down the device from `TestNetworkAdapterPassthroughChange`), and hit the identical broker endpoint `10.208.13.244:50221` with "network is unreachable" — the exact same error as `TestStagedNICChange`. Live checks right now still show `edge-dev` stuck `EVE_DEVICE_STATE_UNDEFINED`/not onboarded and the SDN client uninitialized, matching the state left behind since that earlier failure.

###### Root cause

This is the same ongoing cascading outage already diagnosed for `TestStagedNICChange`, `TestNetworkAdapterPassthroughChange`, and `TestNetworkAdapterPassthrough` earlier in this run (`live-investigation.md`), not an independent bug. `TestNICCountChange`'s `Setup()` tried to tear down the leftover `edge-dev`/SDN (since the immediately preceding `TestStagedNICChange` also failed and its devices weren't reused) and hit the identical broker/device-agent endpoint `10.208.13.244:50221`, still "network is unreachable." Live right now confirms `edge-dev` is still `EVE_DEVICE_STATE_UNDEFINED` with no interfaces and `evetest sdn status`/`evetest eve info` both fail ("SDN client is not initialized" / "device is not onboarded"), identical symptoms to those earlier failures. Per `live-investigation.md`, the whole chain traces back to `TestLocalNIWithMultiplePorts`'s qemu guest wedging in host-kernel state `D` (blocked in `kvm_async_pf_task_wait_schedule`) starting at 23:15:38, which made the device agent unresponsive and has since cascaded, unresolved, through every subsequent test in this run including this one. Neither this exact failure nor the underlying `kvm_async_pf` hung-task mechanism appears in `live-ledger.md`, so this is not a previously-known recurring issue — it's the same single new incident from tonight's run continuing to propagate.

#### TestNICCountChangeOrderedInterface

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: network is unreachable"
```

##### Claude's conclusion

Confirmed — identical symptoms to the preceding failures.

**Root cause:** This is the same ongoing cascading outage already diagnosed earlier in this run, not an independent bug. `TestNICCountChangeOrderedInterface`'s `Setup()` tried to tear down the leftover `edge-dev`/SDN from `TestNICCountChange` (which itself failed and left its devices un-reused) and hit the identical broker/device-agent endpoint `10.208.13.244:50221` with "network is unreachable" — the exact same error signature. Live right now confirms `edge-dev` is still `EVE_DEVICE_STATE_UNDEFINED` with no interfaces, "not onboarded," and `evetest sdn status` still reports "SDN client is not initialized" — unchanged from the state documented for `TestNICCountChange`. Per `live-investigation.md`, the whole chain traces back to `TestLocalNIWithMultiplePorts`'s qemu guest wedging in host-kernel state `D` (blocked in `kvm_async_pf_task_wait_schedule`) starting at 23:15:38, which made the device agent unresponsive and has cascaded unresolved through every subsequent test in this run (`TestAccessVLANs`, `TestNetworkAdapterPassthrough`, `TestNetworkAdapterPassthroughChange`, `TestStagedNICChange`, `TestNICCountChange`, and now this one). Neither this exact failure nor the underlying `kvm_async_pf` hung-task mechanism appears in `live-ledger.md`, so this is not a previously-known recurring issue — it's the same single new incident from tonight's run continuing to propagate, not a new or separate bug.

#### TestSwitchNIPortConfigRace

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: network is unreachable"
```

##### Claude's conclusion

Confirmed: identical symptoms to the already-diagnosed cascade — `edge-dev` is still `EVE_DEVICE_STATE_UNDEFINED` with no interfaces, "not onboarded," and `evetest sdn status` reports "SDN client is not initialized," same as every test since `TestLocalNIWithMultiplePorts`.

**Root cause:** This is the same ongoing cascading outage already recorded in `live-investigation.md` for `TestNICCountChangeOrderedInterface` and every test back to `TestNetworkAdapterPassthrough`, not a new independent bug. `TestSwitchNIPortConfigRace`'s teardown hit the exact same broker/device-agent endpoint `10.208.13.244:50221` with "network is unreachable," and live checks right now confirm `edge-dev` is unchanged: `EVE_DEVICE_STATE_UNDEFINED`, no interfaces, not onboarded, SDN client uninitialized. Per `live-investigation.md`, this chain traces back to `TestLocalNIWithMultiplePorts`'s qemu guest wedging in host-kernel state `D` (blocked in `kvm_async_pf_task_wait_schedule`) starting at 23:15:38, which left the device agent permanently unresponsive and has since propagated unresolved through every subsequent test in this run (`TestAccessVLANs`, `TestNetworkAdapterPassthrough`, `TestNetworkAdapterPassthroughChange`, `TestStagedNICChange`, `TestNICCountChange`, `TestNICCountChangeOrderedInterface`, and now this one). Neither this exact symptom nor the underlying `kvm_async_pf` hung-task mechanism appears in `live-ledger.md`, so this is not a previously-known recurring issue from past nightlies — it's the same single new incident introduced tonight continuing to propagate.

#### TestLocalNIUplinkFlap

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: network is unreachable"
```

##### Claude's conclusion

This is the identical, still-unresolved cascading outage already diagnosed throughout this run (`TestAccessVLANs` onward in `live-investigation.md`). Live checks confirm the exact same unchanged symptoms: `edge-dev` is still `EVE_DEVICE_STATE_UNDEFINED` with no interfaces ("not onboarded"), and `evetest sdn status` still reports "SDN client is not initialized" — identical to every test since `TestNetworkAdapterPassthrough`. `TestLocalNIUplinkFlap`'s teardown hit the same broker/device-agent endpoint `10.208.13.244:50221`, now failing with "network is unreachable," matching the error already seen for `TestStagedNICChange`, `TestNICCountChange`, `TestNICCountChangeOrderedInterface`, and `TestSwitchNIPortConfigRace`.

Per `live-investigation.md`, the whole chain traces back to `TestLocalNIWithMultiplePorts`'s qemu guest wedging in host-kernel state `D` (blocked in `kvm_async_pf_task_wait_schedule`) starting at 23:15:38, which left the device agent permanently unresponsive and has propagated unresolved through every subsequent test in this run. Neither this exact failure nor the underlying `kvm_async_pf` hung-task mechanism appears in `live-ledger.md`, so it is not a previously-known recurring issue from past nightlies — this is the same single new incident introduced tonight (2026-11-02), still propagating and not yet recovered.

#### TestSwitchNIDeletedWithAppsAttached

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: connect: network is unreachable"
```

##### Claude's conclusion

Confirmed: `edge-dev` is still `EVE_DEVICE_STATE_UNDEFINED` with no interfaces, "not onboarded," and `evetest sdn status` still reports "SDN client is not initialized" — identical, unchanged symptoms to every test since `TestNetworkAdapterPassthrough` earlier in this run.

**Root cause:** This is the same ongoing cascading outage already diagnosed throughout `live-investigation.md` for `TestNetworkAdapterPassthrough` through `TestLocalNIUplinkFlap`, not an independent bug. `TestSwitchNIDeletedWithAppsAttached`'s teardown hit the identical broker/device-agent endpoint `10.208.13.244:50221`, again with "network is unreachable" — the exact same error signature as the preceding six failures. Per `live-investigation.md`, the whole chain traces back to `TestLocalNIWithMultiplePorts`'s qemu guest wedging in host-kernel state `D` (blocked in `kvm_async_pf_task_wait_schedule`) starting at 23:15:38, which left the device agent permanently unresponsive and has propagated unresolved through every subsequent test in this run. Neither this exact symptom nor the underlying `kvm_async_pf` hung-task mechanism appears in `live-ledger.md`, so this is not a previously-known recurring issue from past nightlies — it's the same single new incident introduced tonight (2026-11-02), still ongoing and unrecovered.

### TestAppsSuite: failure analysis

#### TestVGAPassthroughNoHostAccess

##### Failure

```
Host processes interfered with PCI devices while the VGA controller 0000:00:01.0 was passed through to the application:
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=15855 parent=runc:[1:CHILD]/15854 grandparent=runc:[0:PARENT]/15853
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=15855 parent=runc:[1:CHILD]/15854 grandparent=runc:[0:PARENT]/15853
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=15855 parent=runc:[1:CHILD]/15854 grandparent=runc:[0:PARENT]/15853
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=15855 parent=runc:[1:CHILD]/15854 grandparent=runc:[0:PARENT]/15853
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=15855 parent=runc:[1:CHILD]/15854 grandparent=runc:[0:PARENT]/15853
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=15855 parent=runc:[1:CHILD]/15854 grandparent=runc:[0:PARENT]/15853
Kernel messages mentioning 0000:00:01.0:
[    1.358553] [    T1] pci 0000:00:01.0: [1234:1111] type 00 class 0x030000 conventional PCI endpoint
[    1.367447] [    T1] pci 0000:00:01.0: BAR 0 [mem 0x80000000-0x80ffffff pref]
[    1.369504] [    T1] pci 0000:00:01.0: BAR 2 [mem 0x8264d000-0x8264dfff]
[    1.371388] [    T1] pci 0000:00:01.0: ROM [mem 0xffff0000-0xffffffff pref]
[    1.374155] [    T1] pci 0000:00:01.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    2.070285] [    T1] pci 0000:00:01.0: vgaarb: setting as boot VGA device
[    2.070285] [    T1] pci 0000:00:01.0: vgaarb: bridge control possible
[    2.071551] [    T1] pci 0000:00:01.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    2.478235] [    T1] pci 0000:00:01.0: Adding to iommu group 1
[  279.343413] [ T4752] vfio-pci 0000:00:01.0: vgaarb: deactivate vga console
[  279.343426] [ T4752] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  360.548332] [ T8150] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
[  361.418389] [ T8150] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[ 1597.591236] [T15879] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
```

##### Claude's conclusion

This confirms the identical false-positive mechanism already documented in this run's own ledger entry. Live `ps -eLo` shows PID 15855 is this app's own `qemu-system-x86_64` process (domain `c0fb987b-...1.1`, launched by `domainmgr`), and thread TID 15879, named `CPU 0/KVM` by the kernel, is just its vCPU thread — not an external host process touching the passed-through VGA device.

**Root cause:** `pciaccess_helpers_test.go`'s `isViolation()` whitelist only matches `comm` values prefixed `"qemu-system-"`. The kernel renames vCPU threads to `CPU N/KVM`, so this specific thread's own routine config-space writes during `[app-restart]` get misclassified as "host interference," even though it belongs to the passed-through device's own owning process. This is the exact same mechanism — same whitelist gap, same `CPU 0/KVM` thread name, same `[app-restart]` phase — already diagnosed earlier tonight in this very run (ledger run #5, where PID 10207's vCPU thread TID 10239 triggered the identical false positive). This occurrence (PID 15855/TID 15879) is effectively a second, later repeat of that same unfixed test-harness tracer bug within tonight's run, not a new or product-side issue. Per the ledger, this bug has been known/recurring since the 2026-10-29 nightly (and also hit 2026-10-30); no PR diff was supplied to assess relatedness to in-flight code changes.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithProxy

##### Failure

```
Failed to receive SDN tunnel properties: rpc error: code = Unavailable desc = unable to connect to SDN gRPC service on any of the uplink IPs ([192.168.170.5]): failed to establish tunnel to SDN: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 192.168.170.5:50121: connect: no route to host"
```

##### Claude's conclusion

**Root cause:** Live evidence confirms the identical infra-flake signature already cataloged repeatedly in the ledger. The broker provisioned a fresh SDN VM (`sdn-297da839`, Proxmox VM 110) for `TestPNACWithProxy` at 22:51:56, which immediately reported a valid uplink IP (`192.168.170.5`) at 22:51:59 — but every gRPC dial from the broker to `192.168.170.5:50121` over the full ~5-minute retry window (22:52:13–22:54:45+) failed with `connect: no route to host`, a routing-layer failure rather than a service-not-ready response. Live `evetest status`/`evetest sdn status` confirm the EVE device never left `EVE_DEVICE_STATE_UNDEFINED` and the SDN client was never initialized, consistent with the failure occurring entirely in `openTunnelToSDN` before any device/network provisioning. Notably, the *preceding* test in this same run (`TestPNACWithoutProxy`) provisioned its own SDN VM under the same device name and connected successfully on the first few retries (`192.168.170.6`, connected by 22:33:57), so this isn't a systemic outage of this run — it's isolated to the second, freshly-reprovisioned SDN VM, matching the pattern of flaky routing to newly-created SDN VMs rather than a lasting network partition.

This is a **known, recurring issue**, not new: per `live-ledger.md`, the identical signature (freshly-provisioned SDN VM reports a valid uplink IP, but broker gets `no route to host` on every gRPC dial to port 50121) was first recorded on **2026-10-29** (`TestAppsSuite/TestPurgeNeverActivatedApp`), and has recurred on nearly every subsequent night: 2026-10-30 (`TestKonvertSuite/TestKvmToKUpgrade`), 2026-10-31 (twice — `TestBootstrapWithAutoDiscoveredProxyUsingOverrideJSON` and `TestKonvertSuite/TestKvmToKUpgrade`), and 2026-11-01 (`TestControllerFaultsSuite/TestInfoRetriedAfterServerError` and `TestDeviceConnectivitySuite/TestDeviceNTPConfig`). Tonight's `TestPNACWithProxy` failure is simply the latest instance of this same mechanism, now hitting a different test in the same suite as last night's occurrence. It points to intermittent networking flakiness between the Proxmox broker host and newly-provisioned SDN VMs, not an EVE/pillar code defect. No PR diff was provided for this investigation to assess relatedness.

### TestKonvertSuite: failure analysis

#### Shrink

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev": failed to create VM 132 for device "eve-27ce5905-edge-dev": 500 got no worker upid - start worker failed
```

##### Claude's conclusion

###### Root cause

The failure happened purely at Proxmox VM-provisioning time, before any EVE device or SDN was ever created (`evetest status` / `evetest eve info` / `evetest sdn status` all confirm "No EVE devices found" / "SDN client is not initialized"). The broker log (`gotest.json`) shows this was actually the test's **second** provisioning attempt in this run — it first tore down a prior EVE/SDN VM pair (IDs 116/118) at 22:59:45–22:59:49, rebuilt fresh EVE/SDN images, and then at 23:00:16 the Proxmox API call to create the new EVE VM (ID 132) returned `500 got no worker upid - start worker failed`. That's a Proxmox-side error meaning the pvedaemon API couldn't even spawn a background task worker for the `qmcreate` call — a transient host-level resource/overload condition, not an EVE/pillar defect.

This `"no worker upid"` signature does not appear anywhere in `live-ledger.md`, so it's a new failure mode rather than a previously-recorded recurring one. However, it fits a well-established *pattern* already logged repeatedly in the ledger: Proxmox broker instability under concurrent multi-VM provisioning load, previously manifesting as TLS-handshake timeouts against the Proxmox host, VM-ID collisions (same ID assigned to two VMs), and truncated/`unexpected end of JSON input` API responses — all attributed to the shared Proxmox host being overloaded, not to EVE/pillar code. It's unrelated to the other `TestKonvertSuite` failures already in tonight's ledger (the `evebuild/nightly:10.1.0` image-tag gap), since those fail during image pull before any VM-create call is attempted at all.

#### TestFirstBootEVEKAppVolume

##### Failure

```

Timed out after 5400.001s.
volumemgr never reported Initialized
Expected
    <string>: 
to contain substring
    <string>: "Initialized":true
```

##### Claude's conclusion

###### Root cause

Live evidence shows `edge-dev` (an eve-k/kubevirt first-boot) onboarded into Adam normally at 23:34:50 and then went completely silent ~50s later: the last info/metrics/log batches the controller ever received are timestamped 23:35:31–23:35:40, and nothing has arrived since — exactly matching the `nim` log's last entry, a route-change L3 reconciliation at 23:35:3x, right before the device vanished. The test then spent the full 5400s polling for volumemgr's `"Initialized":true` with no further signal. Live checks confirm the VM is still completely dead now, ~1.5h later: `evetest eve ssh` gets "no IP address" / connection-reset, `evetest eve console-output` and `evetest eve collect-info` both fail (`i/o timeout` dialing the VM's console/SSH ports), and `evetest sdn status` also times out dialing the SDN VM's gRPC tunnel — i.e. the Proxmox VM itself (not just a slow EVE agent) appears to have hung or become completely unreachable at the hypervisor-network level shortly after first boot, consistent with the device state reported as `EVE_DEVICE_STATE_SUSPECT`.

This does not match the earlier-investigated `Shrink` failure in this same run (an unrelated `INITIAL_EVE_VERSION`/image-tag gap that fails before any VM is even created). It also doesn't match the ledger's prior EVE-K reboot/etcd-overload or "no route to host" SDN-tunnel entries — those show the device/cluster alive but struggling or mid-transition, whereas here the device goes silent entirely within a minute of boot and never recovers. Neither `TestFirstBootEVEKAppVolume` nor this "device goes totally dark almost immediately after first boot" signature appears anywhere in `live-ledger.md`, so this looks like a new failure mode — most consistent with a Proxmox/VM-level hang or host-networking blackout for this specific VM shortly after boot, rather than an EVE/pillar software defect, though I can't fully rule out a kernel/hypervisor-level crash inside the guest given the total silence.

### TestKubeRegistrationSuite: failure analysis

#### TestKubeRegistrationClusterSetup

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "native-k8s-cluster" (device "edge-dev1")
```

##### Claude's conclusion

###### Root cause

`edge-dev1` (one of the three nodes in the `native-k8s-cluster`) went completely silent mid-setup and never recovered. Its own device logs stop dead at **23:05:20.800** (a kernel message about a new `veth`/`cni0` interface entering forwarding state, right after `zedkube`'s `23:05:00.648 applyLonghornDiskReserved: set reserved space to 2 GB on node edge-dev1`) — no further log lines of any kind (no reboot, no panic, no watchdog message) ever arrive after that point. ~5 minutes later the controller marked it `ONLINE -> SUSPECT` (23:10:43), and it has remained unreachable ever since: live `evetest eve ssh`, `kubectl`, and `collect-info` against it all fail with "failed to detect any IP address for EVE device edge-dev1" (SDN-level IP discovery itself fails), and a direct SSH attempt gets `kex_exchange_identification: Connection reset by peer`. This is consistent with the VM/kernel hanging or dying outright while provisioning Longhorn/CNI networking for the k3s node join, not a transient connectivity blip.

Because `edge-dev1` never came back, the cluster-readiness check (`evetest/edgecluster.go:177`, `clusterNodeReady`) could never see a report where storage is healthy and all three expected nodes are simultaneously `Ready` — `evetest cluster info` shows `edge-dev2`/`edge-dev3` storage health flapping `HEALTHY`/`FAILED` (consistent with Longhorn never reaching quorum with one of its three replicas gone), and no node ever leaves `admission_status:NODE_ADMISSION_JOINING`. The test then timed out after ~29 minutes exactly as designed.

This is a single, self-contained failure (not sharing a root cause with any other failure in this run — `edge-dev4` is a separate standalone device not even part of this cluster). `TestKubeRegistrationSuite`/`TestKubeRegistrationClusterSetup` has no prior entries in `live-ledger.md`, so this is a **new** failure, not a known/recurring issue. No PR diff was provided to assess relatedness.

#### TestKubeRegistrationAddNode

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

The background SSH attempt to edge-dev1 timed out and was killed after reaching its time limit — it never returned output, which is consistent with edge-dev1 being unreachable (matching the prior investigation's finding of SSH connection resets/no route). This doesn't change my conclusion above; I already had sufficient evidence from `evetest status` and `adam-stdout` to confirm edge-dev1 is still dead and that's the root cause of this teardown-timeout failure.

#### TestKubeRegistrationLonghornDisks

##### Failure

```
failed to remove device "edge-dev3" from the controller: unknown device UUID "1312a593-2d01-430b-9203-4a0263eceeb8"
```

##### Claude's conclusion

No prior occurrences in the ledger — this specific teardown-cascade symptom is not a previously known/recurring issue.

**Root cause:** This is a direct downstream cascade of the same root cause already identified for this run: `edge-dev1` went silent/unresponsive mid-`TestKubeRegistrationClusterSetup` (confirmed still `EVE_DEVICE_STATE_SUSPECT` live via `evetest status`, and `evetest cluster info` now errors with `unknown device UUID "aed8d39e-...”` for it). When `TestKubeRegistrationAddNode`'s `Setup` tried to tear down the cluster's 4 devices at 23:39:18, it managed to delete their records from the Adam controller (confirmed: `adam-db/device/` and `adam-db/onboard/*` no longer contain any of the 4 device entries) but the overall teardown call then failed with `failed to tear-down all devices: ... dial tcp 10.208.13.244:50221: i/o timeout` — a VM/console-level RPC to the still-dead `edge-dev1`. Because that failure happened after the controller-side deletions but wasn't surfaced as partial success, the harness retried the *same* "tear down previous test's devices" step at the start of `TestKubeRegistrationLonghornDisks`'s `Setup`, which now immediately fails on `edge-dev3` with "unknown device UUID" since it was already removed. `edge-dev3` itself was healthy and actively polling the controller (`172.20.20.180`, config/metrics/newlogs traffic through 23:35:41) — it's purely a teardown-retry/idempotency bug exposed by `edge-dev1`'s unrelated hang, not a new independent failure.

### TestLPSSuite: failure analysis

#### TestProfile

##### Failure

```

Timed out after 600.000s.
app-profile-1 is HALTED (LPS profile-2)
Expected
    <info.ZSwState>: 8
to equal
    <info.ZSwState>: 9
```

##### Claude's conclusion

The earlier `evetest sdn status` command (launched to probe the SDN tunnel) was killed after hitting its background time limit — it never returned output, which is itself consistent with the finding already reported: the SDN gRPC tunnel to the device is still dead. No action needed; this doesn't change the root-cause analysis already given above.

#### TestRadioSilence

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

No match — this exact signature (broker connection itself at port 50221 timing out) doesn't appear in the ledger.

###### Root cause

**TestRadioSilence shares the same root cause as the earlier `TestProfile` failure in this run.** Both fail against the identical broker endpoint `10.208.13.244:50221` with `i/o timeout` — not the usual "SDN VM uplink unreachable" pattern (`192.168.170.x:50121`, "no route to host") seen repeatedly in the ledger, but a timeout reaching the **broker connection itself** that was established at suite start ("Connected to broker at 10.208.13.244:50221" at 23:29:07). Evidence timeline: the SDN tunnel proxy for `edge-dev` died at 23:35:42-44 ("receive from gRPC client stream failed 10 times: EOF"), `edge-dev` flipped ONLINE→SUSPECT at 23:41:07, and by 23:58:00 even *console-output* retrieval against the broker hit the same `10.208.13.244:50221: i/o timeout`. TestRadioSilence then started immediately after and tried to tear down `edge-dev` from the failed TestProfile run via that same broker connection, hitting the identical timeout — it never got far enough to attempt anything of its own. Live `evetest sdn status` still reports "SDN client is not initialized" and `evetest status` still shows `edge-dev` stuck in `EVE_DEVICE_STATE_SUSPECT`, confirming the broker-side connectivity (or the broker process itself) has not recovered. This specific "broker host port 50221 itself timing out" signature doesn't match anything in `live-ledger.md` (which only has recurring entries for SDN-VM-uplink `no route to host` on port 50121, and separate Proxmox-API `farfalle:8006` TLS timeouts) — so while it's clearly infrastructure/broker-side rather than an EVE/pillar code issue, it looks like a new failure mode rather than a previously-recorded recurring one.

#### TestAppLocalInfo

##### Failure

```
failed to remove device "edge-dev" from the controller: unknown device UUID "9f63eb32-4242-4b15-940d-2657dedab4c6"
```

##### Claude's conclusion

The background `evetest eve ssh` check timed out without returning (device unreachable), which is consistent with the already-reported finding: `edge-dev` is still stuck in `EVE_DEVICE_STATE_SUSPECT` with the SDN tunnel dead. This doesn't change the root-cause analysis already given.

#### TestDevLocalInfo

##### Failure

```
failed to remove device "edge-dev" from the controller: unknown device UUID "9f63eb32-4242-4b15-940d-2657dedab4c6"
```

##### Claude's conclusion

The background SSH check to `edge-dev` was killed after hitting its background time limit without ever returning output — consistent with the device being unreachable, which matches the already-reported finding (SDN tunnel dead, device stuck in `EVE_DEVICE_STATE_SUSPECT`). This doesn't change the root-cause analysis already given for `TestDevLocalInfo`.

#### TestNetworkLocalChanges

##### Failure

```
failed to remove device "edge-dev" from the controller: unknown device UUID "9f63eb32-4242-4b15-940d-2657dedab4c6"
```

##### Claude's conclusion

This failure is identical in signature to the already-investigated `TestAppLocalInfo` and `TestDevLocalInfo` failures: `edge-dev` device UUID unknown, status `EVE_DEVICE_STATE_SUSPECT`, and SDN client still "not initialized" — exactly the same broker/SDN-tunnel outage already diagnosed earlier in this run (tied back to the `TestRadioSilence`/`TestProfile` broker timeout at `10.208.13.244:50221`).

**Root cause:** `TestNetworkLocalChanges` shares the same root cause as the earlier failures in this run. Live state confirms `edge-dev` is still stuck in `EVE_DEVICE_STATE_SUSPECT` and `evetest sdn status` still reports "SDN client is not initialized," matching the broker/SDN-tunnel outage first diagnosed under `TestRadioSilence` (connection error to `10.208.13.244:50221`). Since that tunnel never recovered, every subsequent test in this run that tries to tear down/remove `edge-dev` hits the identical cascading error "unknown device UUID 9f63eb32-...". This is not a new or independent bug — it's the same infrastructure-level broker/SDN failure already recorded for `TestProfile`, `TestAppLocalInfo`, and `TestDevLocalInfo` in this same run, and per `live-ledger.md` this specific "broker port 50221 itself timing out" signature is not a previously-recorded recurring pattern (the ledger's recurring entries are for SDN-VM-uplink timeouts on port 50121 instead), so it still looks like a new infra failure mode rather than a known recurring one.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume efb4e4cd-2098-4df7-b50b-8a2a0d54805a
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

This confirms the exact same mechanism as the earlier failure logged tonight for this same test. No need to check further — this is the identical bug on the same node with a different volume UUID.

**Root cause:** `VolumeStatus` for `efb4e4cd-2098-4df7-b50b-8a2a0d54805a` is stuck at `State:109` (`CREATING_VOLUME`) on `edge-dev2`, which live `kubectl get node edge-dev2 --show-labels` confirms is labeled `tie-breaker-node=true` (and `SchedulingDisabled`). The device's own volumemgr log shows an unbroken stream of `WaitForLonghornReady: not ready yet: longhorn daemonset:engine-image-ei-b4bcf0a5 missing on this node` from before the test began through now (22:59:05–23:03:51), because Longhorn's daemonsets are deliberately not scheduled on the `tie-breaker-node=false`-selected witness node — so the wait can never succeed there. This is the identical root cause already diagnosed earlier tonight (2026-11-02, run #5) for the same test/suite with a different volume (`18355a22-1ed4-4837-bcb2-074f3bc715e4`): `volumehandlers/csihandler.go`'s `PrepareVolume` calls `kubeapi.WaitForLonghornReady` unconditionally instead of checking `EdgeNodeClusterConfig.IsTieBreakerNode` as `longhorninfo.go:720-721` says it must. Per the ledger this exact tie-breaker/Longhorn gating bug is new as of tonight's run (first occurrence earlier this same run, not seen on prior nights) — this is effectively a repeat occurrence within the same run, not a new issue. No PR diff was supplied to assess relatedness to in-flight code changes.

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 914.700s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:167 with:
could not list VMIRS objects; k3s may still be starting
Unexpected error:
    <*fmt.wrapError | 0x3537db04d2a0>: 
    kubectl -n eve-kube-app get vmirs -o json: failed to execute script over SSH for EVE device edge-dev3: failed to detect any IP address for EVE device "edge-dev3" (stderr: ) (stderr: )
    {
        msg: "kubectl -n eve-kube-app get vmirs -o json: failed to execute script over SSH for EVE device edge-dev3: failed to detect any IP address for EVE device \"edge-dev3\" (stderr: ) (stderr: )",
        err: <*fmt.wrapError | 0x3537db04d280>{
            msg: "failed to execute script over SSH for EVE device edge-dev3: failed to detect any IP address for EVE device \"edge-dev3\" (stderr: )",
            err: <*errors.errorString | 0x3537db74e8d0>{
                s: "failed to detect any IP address for EVE device \"edge-dev3\"",
            },
        },
    }
occurred
```

##### Claude's conclusion

I have enough evidence now to write the root cause.

**Likely root cause:** This failure shares the same deadlock mechanism investigated earlier for `TestVMAppPurgeDuringFailover` in this same run (recorded in `live-ledger.md` for run #5, the "expected exactly one VMIRS... not designated" zedmanager/zedkube bug) — but that attempt had already failed and the harness discarded its devices ("Previous test failed; not reusing its devices" at 23:05:53) and retried with a brand-new device/SDN set. This retry's failure is a **different, infrastructure-level** problem: the test's own SDN emulator VM (`sdn-c563e944`, Proxmox-hosted, uplink `192.168.170.10`) worked normally from 23:07:06 through 23:35, but at 23:35:42 its gRPC stream to the harness died with `error reading from server: EOF` ("SDN tunnel proxy ended with error... failed 10 times"), and from that point on every SSH/IP-discovery attempt for **all three** devices (not just edge-dev3) failed. A live check right now confirms the SDN VM is still completely unreachable — `evetest sdn status`/`evetest sdn logs` both time out dialing `192.168.170.10:50121`, and SSH to edge-dev1/2/3 all fail identically with "failed to detect any IP address," so this is not specific to edge-dev3 or to the purge/failover logic under test. I found no matching entry in `live-ledger.md` for this exact signature (a previously-healthy SDN tunnel dying mid-test with gRPC `EOF`, versus the recorded "no route to host at initial connect" pattern seen for freshly-provisioned SDN VMs) — so this looks like a new, previously-unrecorded SDN-emulator/Proxmox-broker reliability issue, not a recurrence of a known bug, and it's unrelated to the zedmanager purge-deadlock bug already diagnosed for this test's prior attempt in this run.

#### TestClusterPVCRedownload

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

That background SSH check to edge-dev1 never completed and was killed after its time limit — consistent with the broker/SDN outage still being in effect. It doesn't change the root-cause conclusion already written above, which was based on the gotest.json timeline and the other live checks that did return.

### TestNodeClusterSuite: failure analysis

#### TestNativeKubeAppNetworking

##### Failure

```

kubectl apply manifest:
apiVersion: v1
kind: Pod
metadata:
  name: native-bare-pod
  namespace: default
  annotations:
    k8s.v1.cni.cncf.io/networks: '[{"name":"ni-local-ni","namespace":"eve-kube-app","interface":"localni","portMappings":[{"hostPort":8022,"containerPort":22,"protocol":"tcp"}]},{"name":"ni-switch-ni","namespace":"eve-kube-app","interface":"switchni","mac":"02:00:00:00:01:01"}]'
spec:
  containers:
  - name: native-bare-pod
    image: lfedge/evetest-ubuntu-ctr:1.2

Unexpected error:
    <*fmt.wrapError | 0x66666307a0>: 
    failed to execute script over SSH for EVE device edge-dev: Process exited with status 1 (stderr: error: error validating "STDIN": error validating data: failed to download openapi: the server is currently unable to handle the request; if you choose to ignore these errors, turn validation off with --validate=false
    )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev: Process exited with status 1 (stderr: error: error validating \"STDIN\": error validating data: failed to download openapi: the server is currently unable to handle the request; if you choose to ignore these errors, turn validation off with --validate=false\n)",
        err: <*ssh.ExitError | 0x666586efc0>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

Live evidence confirms the same race documented in the ledger: at 22:13:12 the test's harness logged `"cluster-is-ready"` (cluster node `edge-dev` already ready), then immediately pushed NI config and ran `kubectl apply` for `native-bare-pod` at 22:13:21 — which failed 3 seconds later (22:13:24) with the openapi-download error. Live inspection of `edge-dev` right after shows the whole single-node k3s cluster (hosting kubevirt, CDI, Longhorn, multus, metrics-server, etc., all on just 4 vCPUs/8GB) still churning through pod (re)creation events seconds old, CPU load ~3.2 on 4 cores, and failing readiness probes (longhorn-manager `connection refused`, metrics-server HTTP 500) — i.e. the apiserver was still under heavy contention from component bring-up at the exact moment the test's `kubectl apply` ran, causing the transient "server is currently unable to handle the request" during OpenAPI schema discovery. The node itself never rebooted (uptime/node age continuous ~7m), so this is a readiness-race, not a crash.

This is a **known, recurring issue** with the identical error signature (`failed to download openapi: the server is currently unable to handle the request`) first recorded for this same test on **2026-11-01 (run #4)**, where it was diagnosed as the `"cluster-is-ready"` checkpoint only checking node-Ready status rather than full apiserver/webhook readiness before the test proceeds to `kubectl apply`. An earlier, related variant (`dial tcp 127.0.0.1:6443: connect: connection refused`) for this same test goes back to **2026-10-29 (run #1)**. Tonight's occurrence is the same unfixed test-harness timing gap reproducing again, not a new regression — no PR diff was supplied to assess code relatedness.

#### TestMgmtProxy

##### Failure

```

wait for the raw container pod to become Ready
Unexpected error:
    <*fmt.wrapError | 0x666701d440>: 
    failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )",
        err: <*ssh.ExitError | 0x6665a9d400>{
            Waitmsg: {status: 141, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

This is the exact same recurring failure confirmed live and in the ledger.

**Root cause:** `mgmtproxy-test-container`'s pod on `edge-dev1` is stuck in `ImagePullBackOff` — `kubectl describe` shows the image pull failing with `failed to resolve image: ... dial tcp 192.168.170.2:5000: connect: no route to host`, matching the test's deliberately-poisoned main routing table (`ip route get 192.168.170.2` and `ip route get 1.1.1.1` both resolve via `eth1`/cluster network, not through mgmtproxy). The live `/run/mgmtproxy-containerd-env` shows only `HTTPS_PROXY=http://127.0.0.1:5443` set with no `HTTP_PROXY`, so the plain-`http://` registry-mirror pull bypasses the mgmtproxy loopback listener entirely and falls through to the poisoned table — the SSH exit 141 is just `kubectl wait`'s wrapper hitting SIGPIPE once its timeout expired against this never-Ready pod. This is a **known, recurring issue**, documented in the ledger with the identical `no route to host`/`ImagePullBackOff` signature on `TestMgmtProxy` going back to the first nightly run on 2026-10-29, and recurring repeatedly since (including twice in last night's 2026-11-01 run). It does not share a root cause with the earlier `TestNativeKubeAppNetworking` failure already investigated in this run's `live-investigation.md` (that was an apiserver-readiness race, unrelated to registry-mirror routing).

#### TestTieBreakerCluster

##### Failure

```
failed to onboard device "edge-dev1": context deadline exceeded
```

##### Claude's conclusion

###### Root cause

Live evidence shows `edge-dev1`'s Proxmox VM (126) was powered on cleanly alongside `edge-dev2`/`edge-dev3` (124/129, no VM-ID collision), and its console confirms the kernel booted and `containerd` started successfully by `23:12:08` — but boot then silently stalled: SDN's dnsmasq DHCP log shows `edge-dev2` and `edge-dev3` completing DHCPDISCOVER→DHCPACK at `23:12:20`/`23:12:31` and onboarding by `23:13:05`, while `edge-dev1`'s MAC (`26:9f:78:99:86:67`) never sent a single DHCP packet and never appears in `ip neigh` on the SDN at all. The SDN-side tap interface for `edge-dev1` does show `LOWER_UP`, confirming the vNIC was attached at the hypervisor level — so this is a guest-side early-boot hang (something between containerd startup and network bring-up never completed), not an SDN/broker networking problem, and `evetest status` still shows it stuck `EVE_DEVICE_STATE_UNDEFINED` with no interfaces at all ~10 minutes later. This does not share a root cause with the two other `TestNodeClusterSuite` failures already investigated in this run (`TestNativeKubeAppNetworking`'s apiserver-readiness race, `TestMgmtProxy`'s registry-routing bug) — both of those occur well after onboarding, whereas this device never got network at all. The exact "failed to onboard device ... context deadline exceeded" error string has occurred once before, on 2026-11-01 (run #4, `TestClusterPVCRedownload`), where one sibling VM silently never produced further boot output while others onboarded fine — that time attributed to the Proxmox host "farfalle" being under sustained TLS-handshake-timeout stress; tonight shows no such TLS-timeout signature from the broker, so while the general "one concurrently-booted sibling VM silently stalls" mechanism is recurring, it isn't confirmed to be driven by the same infrastructure cause, and no dedicated ledger entry exists yet for this specific pattern.

#### TestClusterToSingleConversion

##### Failure

```

Timed out after 1200.001s.
Expected to satisfy: Device "edge-dev3" reports itself as the only ready node
nodes:{name:"edge-dev1" conditions:{type:KUBE_NODE_CONDITION_TYPE_READY set:true last_transition_time:{seconds:1793662081}} role_server:true creation_timestamp:{seconds:1793662081} api_server_sersion:"v1.34.2+k3s1" internal_ip:"10.244.244.2" schedulable:true admission_status:NODE_ADMISSION_JOINED node_id:"fe488167-a3d5-4b2b-8dd6-21b1f82cafc9"} nodes:{name:"edge-dev2" conditions:{type:KUBE_NODE_CONDITION_TYPE_READY set:true last_transition_time:{seconds:1793662415}} role_server:true creation_timestamp:{seconds:1793662415} api_server_sersion:"v1.34.2+k3s1" internal_ip:"10.244.244.3" schedulable:true admission_status:NODE_ADMISSION_JOINED node_id:"a75c8dad-702b-4323-9120-e98ba48be8d3"} nodes:{name:"edge-dev3" conditions:{type:KUBE_NODE_CONDITION_TYPE_READY set:true last_transition_time:{seconds:1793662408}} role_server:true creation_timestamp:{seconds:1793662408} api_server_sersion:"v1.34.2+k3s1" internal_ip:"10.244.244.4" schedulable:true admission_status:NODE_ADMISSION_JOINED node_id:"4fffd2b7-96ae-4398-8183-3698795b264d"} storage:{health:SERVICE_STATUS_HEALTHY transition_time:{seconds:1793662441}} cluster_id:"38616b42-7430-4823-847e-11a73ae616f1"
```

##### Claude's conclusion

###### Root cause

Live evidence and `gotest.json` show the cluster actually formed successfully (all three nodes ready by `23:34:05`), and the test then began its real work: "Withdrawing cluster config from edge-dev3 to convert it back to a single node." `edge-dev3` rebooted at `23:34:37` to apply that config and confirmed it at `23:35:36` — but seconds later, at `23:35:42`, both the harness's SDN tunnel proxy ("gRPC client stream receive error: ... EOF") and its separate Proxmox broker log stream died simultaneously with the same EOF/Unavailable error, and neither ever reconnected. All three devices flipped `ONLINE→SUSPECT` five minutes later (23:40:52, a heartbeat-timeout consequence of losing the SDN link) and have stayed that way since. Right now, live, `evetest sdn status`/`graph`/`net-model` and all `evetest eve ssh` calls to any of the three devices fail identically with `dial tcp 192.168.170.11:50121: i/o timeout` — the SDN VM's gRPC endpoint is still completely unreachable 20+ minutes later, confirming this isn't a transient blip but a dead/unrecovered SDN control-plane connection, which is why the test could never re-poll node state and timed out waiting for edge-dev3 to be reported as the sole ready node (the nodes shown in the failure message are simply the last-known, now-stale cluster snapshot).

This does **not** share a root cause with the other two failures already investigated in this run: `TestNativeKubeAppNetworking` was an apiserver-readiness race and `TestTieBreakerCluster` was a guest-side boot/DHCP stall on one VM during onboarding (both resolved before this test even started its setup, at 23:21–23:28). This also isn't the recurring "SDN VM never gets a gRPC route" pattern already in the ledger (that one fails at initial SDN bring-up with `no route to host` before any device onboards); here the SDN tunnel was healthy for ~10 minutes and then died mid-test, immediately after a node reboot, with a different signature (`EOF`/stream-receive-error) and simultaneous broker log-stream loss. I found no matching entry for this signature in `live-ledger.md`, so this looks like a new, previously unrecorded failure mode — infrastructure-level loss of the broker/SDN gRPC connection, not an EVE/pillar code defect.

#### TestClusterVMApp

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

###### Root cause

This failure is a direct continuation of the already-diagnosed `TestClusterToSingleConversion` failure earlier in this same run: the broker's gRPC connection at `10.208.13.244:50221` (the connection the harness uses for all device operations — console, teardown, info, SSH) died mid-test at `23:35:42` and never recovered. `gotest.json` shows console-gathering for all three devices already failing with the identical `dial tcp 10.208.13.244:50221: i/o timeout` at `00:00:28` during `TestClusterToSingleConversion`'s "Resumed after failure" cleanup, and now `TestClusterVMApp`'s own `Setup()` hit the exact same timeout at `00:02:08` while trying to tear down those same leftover devices (`teardown.go:64`). Live checks right now confirm the connection is still dead: `evetest sdn status` reports "SDN client is not initialized," `evetest cluster info`/`evetest eve info` both report "unknown device UUID" for devices that `evetest status` still lists, and `evetest eve ssh` to `edge-dev1` hangs indefinitely with no response.

This is the same root cause as the `TestClusterToSingleConversion` failure already recorded in `live-investigation.md` for this run — not a new, independent bug. That entry found no matching precedent in `live-ledger.md`, so per the ledger this remains a new, previously-unrecorded infrastructure failure mode (broker/SDN gRPC connection dying mid-run and never reconnecting), not a known recurring issue — it is simply now manifesting as a cascading failure on the next test in the suite because the broken connection was never restored between tests.

### TestSecuritySuite: failure analysis

#### TestVaultKeyModeRecoveryOnExt4

##### Failure

```
Device "edge-dev" failed to fetch the latest config (version 1): context deadline exceeded
```

##### Claude's conclusion

The earlier background `evetest sdn status` call was killed after hitting its time limit (still no output) — consistent with what I already confirmed via a separate timed check: the SDN tunnel/broker path is still unresponsive. This doesn't change the analysis already given; no further action needed.

#### TestVaultKeyModeRecoveryOnZFS

##### Failure

```
failed to tear-down all devices: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 10.208.13.244:50221: i/o timeout"
```

##### Claude's conclusion

The background SSH attempt to `edge-dev` (`evetest eve ssh -d edge-dev "uptime; ..."`) was ultimately killed after its background time limit without ever producing output — further confirming the device is completely unreachable over the SDN tunnel, consistent with the root cause already reported above. No further action needed; this doesn't change the analysis.

## [2026-11-02 -- 0.0.0-master-8afd590e (run #5)](https://github.com/lf-edge/eve/actions/runs/41354834539)

[Full report](https://lf-edge.github.io/eve/test/master/runs/5/)

### TestAppsSuite: failure analysis

#### TestMemoryPressureEvents

##### Failure

```

Timed out after 180.001s.
memory-monitor's handler wrote no complete report after "": map[dir:2026-11-01-23-04-46 handler.log:Warning: Problem (retrying all errors). Will retry in 16 seconds. 1 retry left.   0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0 curl: (7) Failed to connect to 127.0.0.1 port 6543 after 0 ms: Could not connect to server + cleanup + set +x memstat_eve.out: memstat_pillar.out:]
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

This confirms the exact same code path as the ledger's prior diagnosis is still present and unfixed.

**Root cause:** This nightly build is a `COVER=y` coverage build — confirmed live via `/persist/coverage/` on `edge-dev` containing fresh `covcounters.*` files. Per `pkg/pillar/agentlog/coverage.go`, `MaybeInitSigUsr2` is a deliberate no-op on coverage builds (SIGUSR2 is reserved for the coverage-flush handler), so `agentlog.ListenDebug`'s pprof server on port 6543 never starts; live-checking the device confirms `curl 127.0.0.1:6543/...` still gets nothing (connection refused) while `zedbox` (pid 2574) is alive and healthy, consistent with `memory-monitor-handler.sh`'s `eve http-debug` retries exhausting and aborting via `set -e` before `memstat_pillar.out`/`memstat_eve.out` are written — exactly the symptom in the failure message.

This is a **known, recurring issue**: the identical failure (same signature, same "port 6543"/coverage root cause) is already recorded in `live-ledger.md` from the **2026-10-29** nightly run (run #1), then didn't occur on the 2026-10-30 or 2026-10-31 runs, and has now reappeared tonight (2026-11-01) — likely because those two intervening nights' nightly builds happened to run without `COVER=y`, while tonight's build has it on again. This is unrelated to the other failures logged for tonight's run (`TestVGAPassthroughNoHostAccess`'s vCPU-thread tracer bug), as it's a different subsystem entirely. No PR diff was supplied to assess for relatedness.

#### TestVGAPassthroughNoHostAccess

##### Failure

```
Host processes interfered with PCI devices while the VGA controller 0000:00:01.0 was passed through to the application:
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=10207 parent=runc:[1:CHILD]/10206 grandparent=runc:[0:PARENT]/10204
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=10207 parent=runc:[1:CHILD]/10206 grandparent=runc:[0:PARENT]/10204
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=10207 parent=runc:[1:CHILD]/10206 grandparent=runc:[0:PARENT]/10204
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=10207 parent=runc:[1:CHILD]/10206 grandparent=runc:[0:PARENT]/10204
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=10207 parent=runc:[1:CHILD]/10206 grandparent=runc:[0:PARENT]/10204
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=10207 parent=runc:[1:CHILD]/10206 grandparent=runc:[0:PARENT]/10204
Kernel messages mentioning 0000:00:01.0:
[    1.470706] [    T1] pci 0000:00:01.0: [1234:1111] type 00 class 0x030000 conventional PCI endpoint
[    1.474490] [    T1] pci 0000:00:01.0: BAR 0 [mem 0x80000000-0x80ffffff pref]
[    1.475081] [    T1] pci 0000:00:01.0: BAR 2 [mem 0x8264d000-0x8264dfff]
[    1.475636] [    T1] pci 0000:00:01.0: ROM [mem 0xffff0000-0xffffffff pref]
[    1.476251] [    T1] pci 0000:00:01.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    1.764506] [    T1] pci 0000:00:01.0: vgaarb: setting as boot VGA device
[    1.765063] [    T1] pci 0000:00:01.0: vgaarb: bridge control possible
[    1.765592] [    T1] pci 0000:00:01.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    1.946163] [    T1] pci 0000:00:01.0: Adding to iommu group 1
[  173.301930] [ T2649] vfio-pci 0000:00:01.0: vgaarb: deactivate vga console
[  173.301963] [ T2649] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  205.875500] [ T7593] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
[  206.180660] [ T7593] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  484.354954] [T10239] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
```

##### Claude's conclusion

This confirms the exact same mechanism documented earlier tonight: PID 10207 is this app's own `qemu-system-x86_64` process, and thread TID 10239 (the one flagged) is the vCPU thread named `CPU 0/KVM` by the kernel — same false-positive pattern as the run #4 ledger entry.

**Root cause:** This is the identical false-positive mechanism already diagnosed earlier in this run and recorded in `live-ledger.md`. Live `ps -eLo` confirms PID 10207 is `vga-passthrough-app`'s own qemu process (domain `c674ed41-...1.1`), and its vCPU thread (TID 10239, same PID) is named `CPU 0/KVM` by the kernel rather than `qemu-system-*`. `pciaccess_helpers_test.go`'s `isViolation()` whitelist only matches `comm` prefixed `"qemu-system-"`, so the vCPU thread's own config-space writes during `[app-restart]` get wrongly flagged as host interference, exactly as seen in the PID-11138 instance investigated earlier tonight. This is a known, recurring issue dating to the 2026-10-29 nightly (per `live-ledger.md`, it also hit 2026-10-30), and it is the **same root cause** as the earlier `TestVGAPassthroughNoHostAccess` failure already logged for this very run (run #4) — this is effectively a repeat/retry occurrence of that same unfixed test-harness tracer bug, not a new or product-side issue.

### TestControllerFaultsSuite: failure analysis

#### TestInfoRetriedAfterServerError

##### Failure

```
Failed to receive SDN tunnel properties: rpc error: code = Unavailable desc = unable to connect to SDN gRPC service on any of the uplink IPs ([192.168.170.7]): failed to establish tunnel to SDN: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 192.168.170.7:50121: connect: no route to host"
```

##### Claude's conclusion

I now have the full picture: live evidence plus a well-documented ledger pattern.

**Root cause:** Live evidence shows the SDN VM (`sdn-3b111169`, Proxmox VM 112) was provisioned and powered on normally, and immediately reported a valid uplink IP (`192.168.170.7`) at `00:54:11` — but every gRPC dial from the broker to `192.168.170.7:50121` over the full ~5-minute retry window (`00:54:17`–`00:59:12`) failed with `connect: no route to host`, a routing-layer failure (no path to the host) rather than a service-not-ready response. Because the SDN tunnel never opened, `edge-dev` never had its network model applied — confirmed live via `evetest sdn status` ("SDN client is not initialized"), `evetest eve info` ("not onboarded"), and `evetest eve collect-info` ("network model not applied") — consistent with `setup.go:905`'s `openTunnelToSDN` failing before any device code ran. This is the **same root cause** as a recurring, well-documented issue in `live-ledger.md`: the identical "freshly-provisioned SDN VM reports an uplink IP, but the broker can never reach its gRPC tunnel on port 50121 (`no route to host`)" signature has appeared repeatedly since first being recorded on 2026-10-29 (`TestAppsSuite/TestPurgeNeverActivatedApp`), and recurred again on 2026-10-31 across `TestBootstrapWithAutoDiscoveredProxyUsingOverrideJSON` and `TestKonvertSuite/TestKvmToKUpgrade` (ledger lines 339–348). This points to systemic flakiness in the Proxmox broker's networking path to newly created SDN VMs rather than an EVE/pillar code defect — no PR diff was supplied for this investigation to assess separately.

### TestDeviceConnectivitySuite: failure analysis

#### TestDeviceNTPConfig

##### Failure

```
Failed to receive SDN tunnel properties: rpc error: code = Unavailable desc = unable to connect to SDN gRPC service on any of the uplink IPs ([192.168.170.6]): failed to establish tunnel to SDN: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 192.168.170.6:50121: connect: no route to host"
```

##### Claude's conclusion

All other subtests in this suite completed normally before this one — only `TestDeviceNTPConfig` failed, confirming it's an isolated setup-stage infra flake, not a cascading issue.

###### Root cause

Live evidence (`evetest status`) confirms the EVE device is stuck `EVE_DEVICE_STATE_UNDEFINED`/not onboarded and `evetest sdn status` reports "SDN client is not initialized" — the failure happened entirely in `openTunnelToSDN` (`evetest/setup.go:905`) before any EVE device or network model was ever created. The broker's own logs show the SDN VM (`sdn-f942552c`, freshly provisioned as Proxmox VM 109) powered on normally at 23:49:50 and immediately reported a valid uplink IP (`192.168.170.6`), but every one of ~47 retries to its gRPC tunnel on port 50121 over the full ~5-minute budget (23:50:05–23:54:44) failed with `connect: no route to host` — a routing-layer failure (no path to the host) rather than a service that was merely slow to start.

This is a **known, recurring issue**, not a new one: the identical signature (freshly-provisioned SDN VM reports a valid uplink IP, but the broker gets `no route to host` on every gRPC dial to port 50121) is logged in `live-ledger.md` first on **2026-10-29** (`TestAppsSuite/TestPurgeNeverActivatedApp`), then again on 2026-10-30 (`TestKonvertSuite/TestKvmToKUpgrade`) and twice more on 2026-10-31 (`TestAppsSuite/TestPurgeNeverActivatedApp` and `TestBootstrapWithAutoDiscoveredProxyUsingOverrideJSON`) — each time on a different freshly-created SDN VM with a distinct Proxmox VM ID/IP. Tonight's occurrence is the fifth instance of this pattern and the first time it's hit `TestDeviceConnectivitySuite`/`TestDeviceNTPConfig` specifically, but it's the same underlying mechanism. It points to intermittent networking flakiness between the Proxmox broker host and newly-provisioned SDN VMs, not an EVE/pillar code defect — no other test failed in this run to correlate with, and no PR diff was supplied for this investigation.

### TestKonvertSuite: failure analysis

#### TestKvmToKRepartitionGeometry

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

**Root cause:** The test's setup (`setup.go:564` → `pushDockerImageToBroker`) tried to pull `evebuild/nightly:10.1.0-kvm-amd64` and got `pull access denied ... repository does not exist` — confirmed live via `evetest eve info`/`sdn status`, both reporting no device/SDN was ever onboarded, so this failed purely in image-prep before any VM provisioning. `TestKvmToKRepartitionGeometry` pins `INITIAL_EVE_VERSION=10.1.0` (needs a real prior release to convert from) but resolves it through the unset `initialEVERepoParamKey`, which defaults to the `evebuild/nightly` CI-nightly repo — that repo only holds numeric build-id tags (e.g. `40731449552-kvm-amd64`), not semantic release tags, so the `10.1.0` pull always fails there.

This is a known/recurring issue: the exact same failure for this test is logged in this run's own ledger on **2026-10-29 (run #1)**, where four other `TestKonvertSuite` tests (`TestBackupCorruptRestore`, `Shrink`, `PersistTooFull`, `ZFSPersist`) hit the identical cause the same day, all tagged as an environment/test-config gap rather than a code regression. It did not recur in the intervening runs (#2 on 10-30, #3 on 10-31, #4 earlier today) for this specific test, suggesting it's intermittent/config-dependent rather than a steady every-run failure — not a new issue introduced by recent commits. No other konvert test in today's run shares this exact cause (today's earlier failures in this run's ledger were different, e.g. the `Shrink` ENOSPC-after-redeploy issue), and no PR diff was supplied for me to assess relatedness to in-flight code changes.

#### TestBackupCorruptRestore

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

Confirmed live: no EVE device or SDN was ever created, and `evetest status` shows the identical failure string for `TestBackupCorruptRestore`.

**Root cause:** This is the exact same known/recurring issue already diagnosed multiple times in this very run (`TestKvmToKRepartitionGeometry`, and a prior `TestBackupCorruptRestore` entry in the ledger). `TestBackupCorruptRestore` is a `TestKonvertSuite` test that pins `INITIAL_EVE_VERSION=10.1.0` via `requirePinnedInitialVersion`, which resolves through the unset `initialEVERepoParamKey` and defaults to the `evebuild/nightly` repo — a repo that only holds numeric nightly build-id tags, not semantic release tags like `10.1.0-kvm-amd64`. Live checks confirm `evetest eve info` and `evetest sdn status` both report no device/SDN was ever onboarded, consistent with the failure occurring in `Setup`/`pushDockerImageToBroker` before any VM provisioning, not a code regression. Per the ledger, this is a known, recurring issue dating back to at least **2026-10-29 (run #1)**, where the identical failure hit `TestBackupCorruptRestore` plus four other konvert tests, and it recurred again earlier in today's run — it's an environment/test-config gap (missing release-tag mirroring for pinned-initial-version konvert tests), not something introduced by recent code changes.

#### Shrink

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

This confirms the mechanism is identical (default `evebuild/nightly` repo resolution for the pinned `INITIAL_EVE_VERSION`, lacking a semantic-tag mirror) across multiple `TestKonvertSuite` tests that call `requirePinnedInitialVersion`. I have enough to write the root cause now.

**Root cause:** This is the same known issue already diagnosed twice earlier in this run. `Shrink` is a variant of `TestKvmToKRepartitionNoVolmig`, which (like `TestKvmToKRepartitionGeometry` and `TestBackupCorruptRestore`, both investigated earlier in `live-investigation.md`) calls `requirePinnedInitialVersion(t, p)` and needs a real prior-release image pinned via `INITIAL_EVE_VERSION=10.1.0`. With `initialEVERepoParamKey` unset, this resolves to the `evebuild/nightly` repo, which only holds numeric nightly build-id tags, not semantic release tags like `10.1.0-kvm-amd64` — so the pull always fails there. Live checks confirm the byte-identical failure string via `evetest status`, and both `evetest sdn status` ("SDN client is not initialized") and "No EVE devices found" show the failure occurred purely in image-prep before any device/SDN provisioning, matching the pattern seen for the other two tests tonight. Per the ledger, this exact failure mode (missing release-tag mirroring for pinned-initial-version konvert tests) is known/recurring back to at least 2026-10-29 (run #1), where it hit four `TestKonvertSuite` tests including `Shrink` itself — it's an environment/test-config gap, not a code regression, and shares the same root cause as the other two konvert failures already investigated in this run.

#### PersistTooFull

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

This `PersistTooFull` failure is confirmed live (`evetest status` and `evetest eve info`/`sdn status` all show no EVE device or SDN was ever created) to be the identical byte-for-byte error — `evebuild/nightly:10.1.0-kvm-amd64` not found — as the three failures already diagnosed earlier in this run (`TestKvmToKRepartitionGeometry`, `TestBackupCorruptRestore`, `Shrink`), so it shares the same root cause: `PersistTooFull` calls `requirePinnedInitialVersion` with `INITIAL_EVE_VERSION=10.1.0`, which resolves through the unset `initialEVERepoParamKey` and defaults to the `evebuild/nightly` nightly-build repo — a repo that only holds numeric build-id tags, not semantic release tags like `10.1.0-kvm-amd64` — so the pull always fails in setup before any device/SDN provisioning. This is a known, recurring issue: the exact same `PersistTooFull` failure (identical signature) is already logged in this run's own ledger on 2026-10-29 (run #1), alongside four other konvert tests, meaning it's been a recurring environment/test-config gap since at least that date, not a new regression or code defect.

#### ZFSPersist

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

Confirmed live: `evetest status` shows the byte-identical error for `ZFSPersist`, "No EVE devices found," and `evetest sdn status` reports the SDN client was never initialized — i.e. the failure occurred purely during image setup, before any device/SDN provisioning.

**Root cause:** This is the same recurring issue already diagnosed five times earlier in this very run (`TestKvmToKRepartitionGeometry`, `TestBackupCorruptRestore`, `Shrink`, `PersistTooFull`, and an earlier `ZFSPersist` entry under `TestKvmToKRepartitionRefused`). `ZFSPersist` is a `TestKonvertSuite` test that pins `INITIAL_EVE_VERSION=10.1.0` via `requirePinnedInitialVersion`, which resolves through the unset `initialEVERepoParamKey` and defaults to the `evebuild/nightly` repo — a repo that holds only numeric nightly build-id tags, not semantic release tags like `10.1.0-kvm-amd64` — so the pull always fails in setup. Per the ledger, this exact failure mode has been a known, recurring environment/test-config gap (missing release-tag mirroring for pinned-initial-version konvert tests) since at least 2026-10-29 (run #1), where it hit the same cluster of konvert tests including `ZFSPersist` itself; it is not a code regression.

### TestNodeClusterResilienceSuite: failure analysis

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```

Timed out after 900.062s.
The function passed to Eventually failed at /evetest/tests/cluster/pvcgc_test.go:115 with:
node "edge-dev2" has no created VolumeStatus for volume 18355a22-1ed4-4837-bcb2-074f3bc715e4
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

This confirms it — `volumehandlers/csihandler.go`'s `PrepareVolume` never checks `EdgeNodeClusterConfig.IsTieBreakerNode` before calling `kubeapi.WaitForLonghornReady`, even though `longhorninfo.go:720-721` documents that contract explicitly. Now I have enough to write the final analysis.

###### Root cause

Live evidence on `edge-dev2` shows `volumemgr` endlessly logging `WaitForLonghornReady: not ready yet: longhorn daemonset:engine-image-ei-b4bcf0a5 missing on this node` from before the test started through the present moment, while `/run/volumemgr/VolumeStatus/18355a22-....json` is permanently stuck at `State:109` (`CREATING_VOLUME`), never reaching `CREATED_VOLUME` — exactly matching the test's "no created VolumeStatus" failure. `kubectl get node edge-dev2` shows it's labeled `tie-breaker-node=true`, and the Longhorn `engine-image`/`csi-plugin`/`manager` DaemonSets carry `nodeSelector: tie-breaker-node=false`, so they are (by design) never scheduled on `edge-dev2` — `checkLonghornReady` in `pkg/pillar/kubeapi/kubeapi.go` requires exactly one running pod of each on the local node and will *never* be satisfied there. `pkg/pillar/kubeapi/longhorninfo.go:720-721` documents that callers must skip this readiness wait on tie-breaker nodes via `EdgeNodeClusterConfig.IsTieBreakerNode`, but `volumehandlers/csihandler.go`'s `PrepareVolume` calls `kubeapi.WaitForLonghornReady` unconditionally with no such check, so it hangs forever on the witness node for any PVC whose `VolumeStatus` is expected there.

This is a distinct mechanism from the `TestClusterPVCGCDeletesOnlyOrphans` failure already logged in tonight's own ledger for 2026-11-01/run #4 (that one was an etcd-overload-induced scheduling timeout, not a tie-breaker/Longhorn gating bug), and it doesn't appear anywhere else in `live-ledger.md` under this or any other signature ("tie-breaker"/"WaitForLonghornReady"/"has no created VolumeStatus" all have zero prior hits) — so this is a new, previously-unrecorded failure mode, not a known recurring issue. No PR diff was supplied for this run, so there's nothing to assess for code relatedness beyond what's shown above.

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

This all lines up exactly: purge was applied at 02:08, old VMIRS/VMI torn down by `purgeCmdDone` at 02:10:09, and from then until the 900s timeout zedmanager has been stuck logging `not designated` since the designated node (edge-dev1) is powered off and no replica exists anywhere to activate a new VMIRS.

Root cause summary:

**Likely root cause:** This is the exact same deadlock in `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2004`) documented in prior nightly runs. Live evidence on edge-dev2 confirms it precisely: `purgeCmdDone` tore down `failover-purge-app`'s old VMIRS/VMI at 02:10:09 after the purge command, and since then zedmanager has logged an unbroken stream of `getKubeAppActivateStatus(...): not designated, node 2799c831-..., onTheDevice false, statusRunning false` through the 900s timeout — matching `kubectl get vmirs,vmi,vm -A` returning nothing cluster-wide (the test's `found []`). The designated node is edge-dev1 (currently `EVE_DEVICE_STATE_SUSPECT`/`NotReady`, deliberately powered off for this failover test), and only the designated node can unconditionally originate a fresh VMIRS, so once the purge deletes the existing one with no replica scheduled anywhere, nothing in the cluster can ever create a new one. This is unrelated to the other currently-paused failure in this run (`TestClusterPVCGCDeletesOnlyOrphans`'s tie-breaker/Longhorn gating gap — a different code path). Per `live-ledger.md`, this is a known, recurring issue: the identical test, failure line (`purge_during_failover_test.go:169`), and root cause have appeared in three prior nightly runs — first on 2026-10-29, again on 2026-10-30, and again on 2026-10-31 — though last night (2026-11-01) that test instead failed on an unrelated Proxmox-infra TLS-handshake flake. So tonight's occurrence is a reproduction of the original, still-unfixed zedmanager/zedkube purge-after-failover activation gap dating back to its introduction in commit `98acf1411` (2026-10-18), not a new bug.

#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

###### Root cause

Live `volumemgr` logs on edge-dev1 show the exact race: right after the test power-cycles all three nodes (02:47:15), `doUpdateContentTree` for vm1's ContentTreeStatus (`0403fbb5-3921-4b4d-bc9a-c30a50a834eb`) runs at `02:58:14.766` and `02:58:18.871`, both times logging `contentTreeSatisfiedByPVCs(...): no local volumes reference this content tree` — because the matching `VolumeConfig` (`handleVolumeCreate(4886fabf-...)`) wasn't published until `02:58:18.980`, *after* the content tree had already fallen through to the normal path, found all three blobs already verified in local CAS from before reboot, and self-completed `VERIFIED → LOADING → LOADED` at `02:58:18.907`/`02:58:19.383`. This lands the tree at `LOADED` (108) instead of `REMOTELOADED` (125), matching the test's exact failure.

This is the identical mechanism in `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` (`pkg/pillar/cmd/volumemgr/acceptclustercontenttree.go`, `updatestatus.go`) already documented twice in `live-ledger.md`: it failed this same way in run #2 (2026-10-30) and run #3 (2026-10-31), both times from the same PVC-adoption-vs-VolumeConfig-publication timing loss right after a reboot. (It also failed in run #4/2026-11-01 under this same test name, but that was an unrelated Proxmox-onboarding infra timeout, not this race.) So this is a known, recurring bug first seen 2026-10-30, not a new issue — and it's unrelated to the other two failures already paused/investigated earlier in tonight's run (`TestClusterPVCGCDeletesOnlyOrphans`'s tie-breaker/Longhorn gating gap and `TestVMAppPurgeDuringFailover`'s zedmanager purge-after-failover deadlock), which are different code paths entirely.

### TestNodeClusterSuite: failure analysis

#### TestSingleNodeCluster

##### Failure

```
timed out after 10m0.000367882s (excluding download) waiting for app "dcb23eb6-e3f5-4bc4-8688-1a79c4a667cd" (container-app) on device "edge-dev" to reach RUNNING state (last state: INSTALLED)
```

##### Claude's conclusion

No prior occurrence of this exact "MOUNT-WEDGE-RECOVERY" / stuck-mount signature in the ledger — this looks new. Found a clear root cause directly from live evidence.

**Root cause:** The cdi-upload pod's PVC (`pvc-b47375af-...`) hit the kubelet volume-mount wedge that `zedkube`'s stuck-mount detector (`pkg/pillar/cmd/zedkube/stuckmount.go`, added 2026-08-31 in `092d7a326`) exists to catch: the volume attached successfully but kubelet never issued NodeStage, so the pod sat `Pending` indefinitely. The detector correctly identified this at `23:26:00.365` ("`MOUNT-WEDGE-RECOVERY: restarting kubelet/k3s ... pod=cdi-upload-... Pending 5m43s`") and restarted k3s to clear it, but by then the pod had already been wedged for ~6 minutes. The k3s restart itself knocked the apiserver out for ~21s (`connection refused` 23:26:00–23:26:21), and only after it came back did the `container-app` VMI actually get created (`SuccessfulCreate` ~23:27:29) — about 15 seconds *after* the test's 10-minute timeout had already fired at 23:27:14 (test started 22:57:51, app stuck at `INSTALLED` the whole time). So the app was never actually broken; it was just recovering one restart cycle too late relative to the test's fixed timeout.

This doesn't match any entry in `live-ledger.md` — no prior `TestSingleNodeCluster`/mount-wedge/CDI-upload-pending signature is recorded, and the wedge-recovery code itself is only ~2 months old, so this looks like a new (not previously recurring) failure mode: either the underlying kubelet mount-wedge bug this detector works around is occurring more readily in this environment, or the detector's 5-minute detection threshold plus restart/recovery time doesn't leave enough margin inside the test's 10-minute timeout. No PR diff was supplied for this run, so I can't assess relatedness to a specific code change beyond what's in `master` already.

#### TestAppInstancePurge

##### Failure

```
Device "edge-dev": expected 0 reboot(s) but observed 1
```

##### Claude's conclusion

**Root cause:** Live `NodeAgentStatus` on `edge-dev` confirms the reboot was a deliberate EVE-K cluster-mode transition, not a crash: `RebootReason:" [2026-11-01 23:57:23]: BootReasonKubeTransition, Transition from cluster mode to single node"`, `BootReason:15`, `RestartCounter:1`. `gotest.json` shows why: the immediately-preceding test in this same suite run, `TestNativeKubeAppNetworking` (23:30:52–23:56:21), explicitly put `edge-dev` into single-node eve-k cluster mode (`"cluster-is-ready"` checkpoint at 23:39:37) and passed, but `TestAppInstancePurge`'s own applied config doesn't carry that cluster mode forward — so nodeagent correctly detected the mode mismatch on the reused device and rebooted to apply it (`restart counter 0→1, boot time 2026-11-01T23:57:54Z`), tripping the harness's "expected 0 reboots" check.

This does **not** share a root cause with the already-investigated `TestSingleNodeCluster` failure in this run (that one was a kubelet mount-wedge/CDI-upload-pod issue, an unrelated subsystem). It **does** match a failure already recorded in `live-ledger.md` for this exact test (`TestAppInstancePurge`, identical error string and identical "cluster-mode-not-carried-forward across back-to-back tests on a reused device" mechanism) — that earlier entry treated it as a brand-new, one-off finding at the time, but seeing the identical signature reproduce again tonight means this is in fact a recurring device-reuse/test-isolation gap between `TestNativeKubeAppNetworking` and `TestAppInstancePurge`, not an independent new bug.

#### TestMgmtProxy

##### Failure

```

wait for the raw container pod to become Ready
Unexpected error:
    <*fmt.wrapError | 0x32f6b2607360>: 
    failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )",
        err: <*ssh.ExitError | 0x32f6b04ee100>{
            Waitmsg: {status: 141, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

This confirms it's been recurring since the very first nightly run (2026-10-29) through at least 2026-10-31, and now again tonight — a persistent, unfixed infra gap.

###### Root cause

This is a known, recurring issue, not a new bug — the identical signature (`exit status 141` wrapping a `kubectl wait` timeout) has appeared in every nightly run since 2026-10-29. Live evidence on `edge-dev1` confirms the exact same mechanism each time: the `mgmtproxy-test-container` pod is stuck `ImagePullBackOff` because kubelet's image pull fails with `Head "http://192.168.170.2:5000/...": dial tcp 192.168.170.2:5000: connect: no route to host`, while `/run/mgmtproxy-containerd-env` shows only `HTTPS_PROXY=http://127.0.0.1:5443` set for containerd (no `HTTP_PROXY`). Since the registry mirror is wired as a plain `http://` endpoint and Go's proxy resolution only consults `HTTPS_PROXY` for `https://` requests, this pull never routes through mgmtproxy's loopback listener and instead falls through to the deliberately-poisoned main routing table (`ip route get 192.168.170.2` resolves via `eth1`/cluster network), where it has no route. The SSH `exit status 141` is simply `kubectl wait`'s SIGPIPE once its timeout expired against a pod that can never become Ready.

This does not share a root cause with any other failure investigated earlier in this run (`TestSingleNodeCluster`'s kubelet mount-wedge, `TestAppInstancePurge`'s cluster-mode-not-carried-forward reboot) — it's an independent, pre-existing test/infra gap where plain-HTTP registry-mirror pulls bypass mgmtproxy's `HTTPS_PROXY`-only wiring, first documented in the ledger's 2026-10-29 run and still unfixed.

#### TestClusterVMApp

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev1")
```

##### Claude's conclusion

**Root cause:** This is the same `TestClusterVMApp` failure mode already investigated earlier in this run and recorded repeatedly in `live-ledger.md` — the `edge-dev3` join/reboot-retry "not authorized" bug. Live evidence matches exactly: `edge-dev3`'s `NodeAgentStatus` shows `RebootReason: BootReasonKubeTransition, Reboot after retry cluster transition attempt 1` (`RestartCounter:2`, reboot at `2026-11-02T02:12:40Z`), and `/persist/kubelog/k3s.log` has been crash-looping every few minutes since (still failing at `02:34:48Z`, ~24 min uptime) with `Skipping cluster configuration validation: not authorized` → `failed to bootstrap cluster data: not authorized`, so k3s never forms a working API server there; `kubectl get nodes` confirms only `edge-dev1`/`edge-dev2` are `Ready`, with `edge-dev3` permanently excluded.

This is a **known, recurring issue** — it's the identical signature recorded in `live-ledger.md` for 2026-10-29, 2026-10-30, and twice already tonight (run #3 and earlier in run #4), now reproducing for at least a fourth/fifth consecutive occurrence, and it does **not** share a root cause with the earlier `TestSingleNodeCluster`/`TestAppInstancePurge`/`TestMgmtProxy` failures already investigated in this run's `live-investigation.md` (those are unrelated kubelet-mount, cluster-mode-carryover, and registry-routing issues). This remains an unfixed EVE-K node-rejoin/reboot-retry bug in the kube cluster-transition logic, not test or infra flakiness.

### TestSecuritySuite: failure analysis

#### TestAppVTPMIdentitySurvivesReboots

##### Failure

```

Timed out after 300.000s.
The function passed to Eventually failed at /evetest/tests/security/vtpm_helpers_test.go:94 with:
Unexpected error:
    <*fmt.wrapError | 0x27f17102f8a0>: 
    failed to execute script over SSH for app aff80bab-c947-4a4f-9c5f-5828531e8acf: Process exited with status 1 (stderr: )
    {
        msg: "failed to execute script over SSH for app aff80bab-c947-4a4f-9c5f-5828531e8acf: Process exited with status 1 (stderr: )",
        err: <*ssh.ExitError | 0x27f1710c5900>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

Live `domainmgr` logs show that at `00:16:56Z`, right as `vtpmd` started handling the launch request for app `vtpm-identity` (`aff80bab-...`), it also began a `"Trying to unseal disk key with PCRs [...]"` operation that blocked its request handler for ~58 seconds. `domainmgr`'s vTPM-launch client has only a 10s timeout (`swtpmTimeout` in `pkg/pillar/hypervisor/kvm.go`), so at `00:17:01.816Z` it logged `"Failed to setup vTPM for aff80bab-...: ... context deadline exceeded"`, set `status.VirtualTPM = false`, and built the qemu domain config with **no TPM device at all** (confirmed live: `/run/domainmgr/domains/dom1.cfg` has zero `tpm`/`tpmdev` entries). Meanwhile `vtpmd` kept going in the background and actually launched the `swtpm` instance 53s later at `00:17:54Z` — which is why a live `swtpm` process and its `/persist/swtpm/tpm-state-aff80bab-...` dir exist on the host, but the guest (which booted fine and is SSH-reachable) has no `/dev/tpm0`/`/dev/tpmrm0`, so `waitForVTPMGuest`'s `test -c /dev/tpmrm0 -o -c /dev/tpm0` kept returning exit 1 for the full 300s until the test's `Eventually` timed out — exactly matching the "Process exited with status 1 (stderr: )" failure and the fact the test never even reached its own first checkpoint (`vtpm-identity-app-running`).

This is a race between `vtpmd`'s (slow, possibly first-boot) disk-key-unseal/launch path and domainmgr's fixed 10s client timeout, not an app/network issue — the swtpm backend and guest network/SSH are both healthy. `live-ledger.md` has no prior mention of `vtpm`/`VTPM` anywhere, so this is a new failure, not a previously-known/recurring issue (consistent with this being a newly-added test per its doc comment). No other test failures exist yet in this run to correlate with, and no PR diff was supplied to assess for relatedness.

## [2026-11-01 -- 0.0.0-master-203e89f9 (run #4)](https://github.com/lf-edge/eve/actions/runs/41246140600)

[Full report](https://lf-edge.github.io/eve/test/master/runs/4/)

### TestAppsSuite: failure analysis

#### TestVGAPassthroughNoHostAccess

##### Failure

```
Host processes interfered with PCI devices while the VGA controller 0000:00:01.0 was passed through to the application:
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11138 parent=runc:[1:CHILD]/11137 grandparent=runc:[0:PARENT]/11136
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11138 parent=runc:[1:CHILD]/11137 grandparent=runc:[0:PARENT]/11136
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11138 parent=runc:[1:CHILD]/11137 grandparent=runc:[0:PARENT]/11136
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11138 parent=runc:[1:CHILD]/11137 grandparent=runc:[0:PARENT]/11136
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11138 parent=runc:[1:CHILD]/11137 grandparent=runc:[0:PARENT]/11136
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11138 parent=runc:[1:CHILD]/11137 grandparent=runc:[0:PARENT]/11136
Kernel messages mentioning 0000:00:01.0:
[    1.438223] [    T1] pci 0000:00:01.0: [1234:1111] type 00 class 0x030000 conventional PCI endpoint
[    1.442352] [    T1] pci 0000:00:01.0: BAR 0 [mem 0x80000000-0x80ffffff pref]
[    1.442983] [    T1] pci 0000:00:01.0: BAR 2 [mem 0x8264d000-0x8264dfff]
[    1.443645] [    T1] pci 0000:00:01.0: ROM [mem 0xffff0000-0xffffffff pref]
[    1.444368] [    T1] pci 0000:00:01.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    1.747964] [    T1] pci 0000:00:01.0: vgaarb: setting as boot VGA device
[    1.748514] [    T1] pci 0000:00:01.0: vgaarb: bridge control possible
[    1.749040] [    T1] pci 0000:00:01.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    1.948029] [    T1] pci 0000:00:01.0: Adding to iommu group 1
[  160.464199] [ T6050] vfio-pci 0000:00:01.0: vgaarb: deactivate vga console
[  160.464206] [ T6050] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  198.711316] [ T7653] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
[  199.023447] [ T7653] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  594.269426] [T11161] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
```

##### Claude's conclusion

**Root cause:** Live SSH evidence confirms this is a false-positive from the test's own tracer, not real host interference. PID 11138 is `vga-passthrough-app`'s own `qemu-system-x86_64` process (domain `f444ed98-...1.1`), but its vCPU thread (TID 11161, same PID) is named `CPU 0/KVM` by the kernel. `pciAccess.isViolation()` (`evetest/tests/apps/pciaccess_helpers_test.go:408-410`) only whitelists accesses where `comm` has prefix `"qemu-system-"`, so the vCPU thread's config-space writes during `[app-restart]` get flagged as host interference even though they originate from the app's own qemu instance. The file hasn't been touched since it was moved in `c2539a9de`, so this gap is unfixed.

This is the **same root cause** documented in the ledger for the identical test in last night's runs (2026-10-29 run #1 and 2026-10-30 run #2) — a known, recurring issue since 2026-10-29. Tonight's occurrence is on a newer build (`0.0.0-master-203e89f9`) than the one in the ledger (`c5d8a37e`), confirming it's reproducing across multiple commits, consistent with it being a test-harness defect rather than a product regression. No other failures were reported in this run to correlate with, and no PR diff was supplied to assess separately.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
PowerOff: broker failed to power off device "edge-dev3": rpc error: code = Unknown desc = failed to power OFF EVE device "edge-dev3": failed waiting for VM 112 stop: Get "https://10.208.13.184:8006/api2/json/nodes/farfalle/tasks/UPID:farfalle:0001C361:793B3FC6:6AE683F5:qmstop:112:root@pam:/status": net/http: TLS handshake timeout
```

##### Claude's conclusion

**Root cause:** This failed not in EVE code but in the test broker's RPC to the Proxmox host ("farfalle", 10.208.13.184:8006) that hosts the test VMs — `evetest eve ssh`/`evetest status` confirm edge-dev3 is still `EVE_DEVICE_STATE_ONLINE`, so the device itself never actually received or processed a power-off; the broker's single attempt to poll the Proxmox `qmstop` task status (`UPID:farfalle:...:qmstop:112:...`) hit a `net/http: TLS handshake timeout` against the Proxmox API and gave up without retrying, aborting the `PowerOff` RPC. The test had otherwise progressed normally up to that point (vm3 came up on edge-dev3 after a slow-but-recovering Longhorn/PVC hiccup at 00:04–00:09, then vm2 deactivated cleanly at 00:12:36) — the failure happened 15s later purely at the "power off edge-dev3" step, triggered by the broker↔Proxmox-host connection, not by anything on the EVE device. I checked `live-ledger.md` for this exact signature (TLS handshake timeout / port 8006 / "farfalle") and found no prior occurrence — this is a new, one-off infrastructure flake, not a known/recurring issue, and it's a different failure mode than the previously-logged `TestDNIDandBackupDNID` DNID-reporting gap or the recurring `TestVMAppPurgeDuringFailover`/SDN "no route to host" issues also in the ledger. No PR diff was supplied for this run, so there's nothing to assess for relatedness to a code change.

#### TestClusterPVCGCDeletesOnlyOrphans

##### Failure

```
Timed out waiting for app "dd5e77b5-2fa5-4c5a-ae1c-8a78ecd25afd" to be scheduled in cluster "pvc-gc-cluster"
```

##### Claude's conclusion

No prior occurrence of this specific etcd/CDI-overload signature in the ledger — this looks like a new failure mode.

###### Root cause

Live evidence shows edge-dev1's embedded k3s/etcd is severely resource-starved: `uptime` shows a 15-min load average of **9.86 on a 4-vCPU node**, and `/persist/kubelog/k3s.log` has been logging `"apply request took too long"` etcd warnings (up to 1.26s vs. a 100ms budget) continuously since **01:00:54**, with 57 `ResponseCode: 503` aggregated-API errors for `v1beta1.upload.cdi.kubevirt.io` ("failed to retrieve openAPI spec... service unavailable"). This etcd slowness intermittently knocks the CDI upload aggregated API offline, which matches the app's own recorded error exactly: `virtctl` failed uploading the PVC-GC test's disk image with *"the server is currently unable to handle the request (post uploadtokenrequests.upload.cdi.kubevirt.io)"* — confirmed live just now, where `evetest eve -d edge-dev3 kubectl get pods` itself returned `Error from server (ServiceUnavailable): the server is currently unable to handle the request`. `kubectl get events` on edge-dev1 shows nearly every control-plane add-on pod (CDI, CSI, virt-controller/operator) being mass-restarted/rescheduled roughly 30s before I looked, and the PVC upload actually succeeded ("UploadSucceeded") only ~9s before I checked — i.e. the app was perpetually stuck in `CREATING_VOLUME`/unscheduled during this instability window, well past the test's scheduling-timeout.

This is a different mechanism than the earlier `TestDNIDandBackupDNID` failure in this same run (a Proxmox-broker TLS timeout unrelated to EVE/k8s internals), so it does **not** share root cause with that one. It also doesn't match the ledger's `TestClusterPVCRedownload` race (a `volumemgr` content-tree/PVC-publish timing bug) or the other logged node-join auth failure — this specific etcd-overload/CDI-503 signature does not appear anywhere in `live-ledger.md`, so it's a new failure mode, not a known recurring issue, though it's consistent with general resource-contention flakiness this test class has shown before (undersized 4-vCPU/3-node cluster running the full Longhorn+KubeVirt+CDI stack).

#### TestVMAppPurgeDuringFailover

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev1": failed waiting for VM 105 creation: Get "https://10.208.13.184:8006/api2/json/nodes/farfalle/tasks/UPID:farfalle:0002AB2D:7941AE08:6AE6946B:qmcreate:105:root@pam:/status": net/http: TLS handshake timeout, failed to setup EVE device "edge-dev3": failed waiting for VM 112 creation: Get "https://10.208.13.184:8006/api2/json/nodes/farfalle/tasks/UPID:farfalle:0002AC3F:7941B364:6AE69479:qmcreate:112:root@pam:/status": net/http: TLS handshake timeout
```

##### Claude's conclusion

This gives a clear, direct timeline showing the broker repeatedly hitting TLS handshake timeouts against the Proxmox API host "farfalle" (10.208.13.184:8006) — first on `storage/local/status` (01:24:17–01:24:58, exhausting all retries), then on the `qmcreate` task-status polls for VMs 105/112, before the setup RPC gave up entirely at 01:25:28.

###### Root cause

The failure is purely infrastructure-side: the evetest broker's Proxmox API client on host "farfalle" (10.208.13.184:8006) suffered sustained `net/http: TLS handshake timeout` errors during device provisioning — first failing all 3 retries of a `storage/local/status` check (01:24:17–01:24:58), then failing to poll the `qmcreate` task status for VMs 105 (edge-dev1) and 112 (edge-dev3), causing `setup.go:852` to abort with "Failed to setup devices" before any EVE device ever booted. `evetest status`/`evetest eve ssh` confirm there is nothing live to inspect — "No EVE devices found" and SDN was never initialized ("SDN client is not initialized") — because the failure occurred entirely at the Proxmox-provisioning stage, before devices or SDN came up.

This shares the same root cause as the earlier `TestDNIDandBackupDNID` failure in this same run: both hit `net/http: TLS handshake timeout` against the identical Proxmox host/port (`farfalle`, 10.208.13.184:8006), indicating that host's management API was intermittently unreachable/overloaded for an extended window spanning at least 00:12 through 01:25 tonight — this one during VM *creation* (`qmcreate`), the earlier one during VM *stop* (`qmstop`). Checking `live-ledger.md`, this exact signature (TLS handshake timeout against the Proxmox API) has no prior recorded occurrence, so it's not a previously-known recurring issue — it looks like a new, extended infrastructure outage/flake on the "farfalle" Proxmox host rather than an EVE/pillar code defect. No PR diff was supplied for this run to assess code relevance.

#### TestClusterPVCRedownload

##### Failure

```
failed to onboard device "edge-dev1": context deadline exceeded
```

##### Claude's conclusion

###### Root cause

Live evidence shows edge-dev1's Proxmox VM (112) never actually booted for this test, even though the broker logged "Successfully powered ON EVE device \"edge-dev1\"" at `01:31:59`. Its serial console output is frozen at a stale login prompt from a boot at `00:24:38` (over an hour old, pre-dating this test's own `01:34` setup), there's been zero new console output since, and `evetest sdn ssh "ip neigh"` shows no ARP/ND entries at all for edge-dev1's MACs on the SDN bridges — meaning its NIC never came alive — while edge-dev2 and edge-dev3, powered on 9s later, booted and onboarded normally by `01:36:38`/`01:36:53`. `evetest eve info`/`ssh` both confirm `edge-dev1` has no IP and was never onboarded, consistent with the test's `setup.go:1157` timeout.

This looks like a continuation of the same underlying infrastructure problem already investigated twice earlier in this run: both prior failures (`TestDNIDandBackupDNID`'s `qmstop` and `TestVMAppPurgeDuringFailover`'s `qmcreate`) hit `net/http: TLS handshake timeout` against the same Proxmox host "farfalle" (10.208.13.184:8006), and `TestVMAppPurgeDuringFailover`'s failed `edge-dev3` attempt even used the same VM ID 112 that was reassigned to this test's edge-dev1. Here the manifestation is slightly different (the power-on RPC itself succeeded but the guest silently never actually ran), suggesting continued flakiness/overload on that specific Proxmox host rather than a new EVE/pillar defect. Per `live-ledger.md`, no prior nightly run shows this exact "device not onboarding silently, no TLS error" signature, so while it's novel in exact symptom, it's very plausibly the same extended "farfalle" host instability (spanning at least `00:12`–`01:42` tonight) already flagged twice in this run, not an independent/new bug.

### TestNodeClusterSuite: failure analysis

#### TestNativeKubeAppNetworking

##### Failure

```

kubectl apply manifest:
apiVersion: v1
kind: Pod
metadata:
  name: native-bare-pod
  namespace: default
  annotations:
    k8s.v1.cni.cncf.io/networks: '[{"name":"ni-local-ni","namespace":"eve-kube-app","interface":"localni","portMappings":[{"hostPort":8022,"containerPort":22,"protocol":"tcp"}]},{"name":"ni-switch-ni","namespace":"eve-kube-app","interface":"switchni","mac":"02:00:00:00:01:01"}]'
spec:
  containers:
  - name: native-bare-pod
    image: lfedge/evetest-ubuntu-ctr:1.2

Unexpected error:
    <*fmt.wrapError | 0x3f3867057720>: 
    failed to execute script over SSH for EVE device edge-dev: Process exited with status 1 (stderr: error: error validating "STDIN": error validating data: failed to download openapi: the server is currently unable to handle the request; if you choose to ignore these errors, turn validation off with --validate=false
    )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev: Process exited with status 1 (stderr: error: error validating \"STDIN\": error validating data: failed to download openapi: the server is currently unable to handle the request; if you choose to ignore these errors, turn validation off with --validate=false\n)",
        err: <*ssh.ExitError | 0x3f38671b4c80>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

Not present in the 2026-10-30 run — so it's a known issue that first appeared 2026-10-29, skipped 2026-10-30, and has now recurred tonight (2026-10-31).

###### Root cause

Live evidence confirms a timing race between the single→cluster-mode transition and the test's `kubectl apply`. `kube-init` logs show the controller pushed cluster config at `22:45:42` ("EdgeNodeClusterStatus found, node not in cluster mode — signalling single→cluster transition"), which stopped k3s at `22:45:48` and restarted it at `22:45:58`; the apiserver stayed in a not-ready state (`readyz=503`, "apiserver not ready" from zedkube) until it finally reported `node edge-dev is Ready` at `22:46:14`. The test's `kubectl apply` for `native-bare-pod` ran at `22:46:01–22:46:03`, landing squarely inside that ~16-second readiness gap, which produced the observed `failed to download openapi: the server is currently unable to handle the request` error. The apiserver is healthy now (confirmed via a direct `curl https://127.0.0.1:6443/healthz`, which returns a normal authenticated response).

This is a known/recurring issue: an essentially identical `TestNativeKubeAppNetworking` failure with the same "openapi download" kubectl-apply error during an apiserver restart was already recorded in the ledger for the 2026-10-29 (run #1) nightly; it didn't recur on 2026-10-30 (run #2) but has now reappeared tonight (2026-10-31, run #3) with the same mechanism — a k3s restart caused by a single→cluster config transition racing the test's kubectl call — so it looks like an unfixed, intermittent test/infra gap (the test isn't waiting for apiserver readiness after triggering a cluster-mode transition) rather than a new regression.

#### TestThreeNodesCluster

##### Failure

```
failed to onboard device "edge-dev1": context deadline exceeded
```

##### Claude's conclusion

This is a new failure signature, not previously seen in the ledger, and it shares no root cause with the earlier `TestNativeKubeAppNetworking` failure investigated in this run (that was a k3s apiserver-readiness race; this one never gets as far as onboarding).

**Root cause:** The evetest broker's Proxmox provisioning assigned the same VM ID (111) to two different VMs in quick succession: `edge-dev1` was "prepared as Proxmox VM 111" at 23:17:06, then 39 seconds later the test's SDN VM was *also* "prepared as Proxmox VM 111" at 23:17:45 (confirmed in `gotest.json`). This is consistent with live evidence: `evetest status` shows `edge-dev1` stuck in `EVE_DEVICE_STATE_UNDEFINED` with no interfaces at all, `evetest eve console-output` shows only the initial `"starting serial terminal on interface serial0"` line (the VM never produced any further boot output), and `evetest eve collect-info`/SDN-based IP discovery both fail to find any IP for it — while `edge-dev2` (VM 114) and `edge-dev3` (VM 110), which got distinct non-conflicting VM IDs, booted normally, got IPs, and onboarded successfully at 23:22:54. The harness then waited the full ~10 minutes for `edge-dev1`'s onboarding cert before failing with "context deadline exceeded." This looks like a VM-ID allocation bug/race in the evetest broker's Proxmox backend (not an EVE/pillar code issue) — likely the SDN VM's ID was picked from a pool that didn't account for the already-provisioned `edge-dev1`, clobbering it before it could boot.

#### TestThreeNodesPortScan

##### Failure

```
failed to onboard device "edge-dev2": context deadline exceeded
```

##### Claude's conclusion

This confirms edge-dev2 has no IP at all — it never actually booted. The evidence is conclusive and matches the exact same mechanism already diagnosed for `TestThreeNodesCluster` earlier in this run.

###### Root cause

This is the **same root cause** as the `TestThreeNodesCluster` failure already investigated earlier in this run (see `live-investigation.md`): the evetest broker's Proxmox backend has a VM-ID allocation race where the SDN VM and an EVE device VM can be assigned the same Proxmox VM ID. Here, `gotest.json` shows `edge-dev2` was "prepared as Proxmox VM 111" at 23:33:19, then just 19 seconds later (and *before* edge-dev2 was even powered on at 23:34:10) the SDN VM `sdn-70a84b1c` was *also* "prepared as Proxmox VM 111" at 23:33:38 — clobbering edge-dev2's VM before it ever booted. Live evidence confirms this: `evetest status` shows edge-dev2 stuck in `EVE_DEVICE_STATE_UNDEFINED` with no interfaces, `evetest eve ssh` fails with "failed to detect any IP address," and `evetest eve info`/the controller report it as never onboarded — while edge-dev1 and edge-dev3 (distinct VM IDs 110 and another) booted and onboarded fine, and SDN itself is healthy (`evetest sdn status` is clean), as expected since it's the one that won the ID collision.

This is not new: the identical bug (same mechanism, same VM ID 111) just caused `TestThreeNodesCluster` to fail earlier tonight in this very run, clobbering `edge-dev1` instead of `edge-dev2`. It's not yet in the ledger as a distinct recurring entry (the ledger only covers prior nightly runs, not this run's own earlier failure), but given it has now hit two different tests in the same run within ~15 minutes of each other, this looks like an actively-reproducing VM-ID allocation bug in evetest's Proxmox broker (ID reuse/pool race between SDN and device VMs), not an EVE/pillar issue.

#### TestMgmtProxy

##### Failure

```
Timed out waiting for app "6cd1e240-7657-4e9e-8303-f45b68fce0d8" to be scheduled in cluster "mgmtproxy-test-cluster"
```

##### Claude's conclusion

###### Root cause

Live evidence shows the entire 3-node k3s cluster is in severe, ongoing control-plane instability caused by etcd overload from slow disk/CPU contention, not an mgmtproxy routing bug this time: `edge-dev1`'s `/persist/kubelog/` shows **9 k3s restarts in the last ~30 minutes** (399+ "leader is overloaded likely from slow disk" / "apply request took too long" / "context deadline exceeded" log lines in just the latest restart segment), `kube-scheduler` and `kube-controller-manager` repeatedly lose leader election, and `uptime` shows load averages of 10–14 on 4-vCPU nodes with 20% iowait across all three devices. Consistent with that, nearly every control-plane/CSI pod cluster-wide (`virt-controller`, `virt-operator`, `cdi-deployment`, `csi-attacher/provisioner/resizer/snapshotter`) is crash-looping with multiple restarts, and kubelet itself was unreachable at points (`connect: connection refused` on port 10250). With the scheduler bouncing this often, the test's app pod `6cd1e240-...` never got a stable scheduling window within the timeout — hence "Timed out waiting for app to be scheduled."

This is a **new failure signature** for `TestMgmtProxy` — the ledger only has a prior `TestMgmtProxy` failure mode (`ImagePullBackOff` from an HTTP registry-mirror routing gap around mgmtproxy, recurring since 2026-10-29), which is a different mechanism from this scheduling timeout. It also doesn't match any of this run's earlier-investigated failures (`TestNativeKubeAppNetworking`'s single-shot apiserver-readiness race, `TestThreeNodesCluster`/`TestThreeNodesPortScan`'s Proxmox VM-ID collisions) — though it may share an underlying cause with the earlier `edge-dev3` "not authorized" rejoin failure in `TestThreeNodesCluster`'s cluster-member test, since both point to the same general theme of an overloaded/resource-starved k3s cluster producing control-plane flakiness, just manifesting differently (join rejection there vs. scheduler unavailability here).

#### TestTieBreakerCluster

##### Failure

```
failed to power on device "edge-dev3": rpc error: code = Unknown desc = failed to power ON EVE device "edge-dev3": failed to get VM 114 for device "eve-70a84b1c-edge-dev3": unexpected end of JSON input
```

##### Claude's conclusion

###### Root cause

The failure is a Proxmox API/broker flakiness issue, not an EVE/pillar bug. `gotest.json` shows the identical `"unexpected end of JSON input"` error occurred twice in this test's setup: first during provisioning at 00:58:02 (`"Attempt 1/3: failed to get storage \"local\" (will retry): unexpected end of JSON input"`, which succeeded on retry), and then fatally at 01:01:06 when the broker tried to power on VM 114 (`edge-dev3`): `"failed to get VM 114 for device ... unexpected end of JSON input"` — this time with no retry, aborting the test. Live evidence corroborates this: `evetest status` shows all three devices stuck in `EVE_DEVICE_STATE_UNDEFINED`, and `evetest eve console-output edge-dev3` shows only stale output timestamped `23:50:12` (from a prior test's VM 114 incarnation), confirming the VM never actually powered on this cycle — consistent with the Proxmox API call itself failing/returning a truncated/empty response rather than any EVE-side boot problem.

This does not share a root cause with the earlier `TestNativeKubeAppNetworking` (k3s/apiserver readiness race) failure in this run, but it does belong to the same general theme as the `TestThreeNodesCluster`/`TestThreeNodesPortScan` failures investigated earlier tonight — both are Proxmox broker instability under concurrent multi-VM provisioning load (there it manifested as VM-ID collisions on ID 111, here as truncated JSON responses from the Proxmox API) — suggesting the underlying Proxmox host is generally overloaded/flaky tonight rather than each being an independent bug. This specific `"unexpected end of JSON input"` signature does not appear anywhere in the ledger, so it's a new failure mode, not a previously-known recurring issue.

#### TestClusterVMApp

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev3")
```

##### Claude's conclusion

No recent zedkube/nodeagent commits in this run's range suggest an unfixed code change; this looks purely like the pre-existing known bug, not something introduced by recent commits.

###### Root cause

This `TestClusterVMApp` failure is a **known, recurring issue**, not a new bug — it's the identical failure signature recorded twice already in the ledger (2026-10-29/30 under run #2, and again earlier tonight under run #3), and this is now its third consecutive occurrence. Live evidence on `edge-dev3` matches exactly: `NodeAgentStatus` shows `RebootReason: BootReasonKubeTransition, Reboot after retry cluster transition attempt 1` (`RestartCounter:2`, reboot at `2026-11-01T01:47:42Z`), after which `/persist/kubelog/k3s.log` has been crash-looping every few minutes ever since (latest attempt `02:09:34Z`, device uptime only ~24 min) with `Skipping cluster configuration validation: not authorized` → `failed to bootstrap cluster data: not authorized`, so k3s never forms a working API server on this node. Consistent with that, `kubectl get nodes` (run against edge-dev1) shows only `edge-dev1` and `edge-dev2` as Ready members — `edge-dev3` never rejoins the cluster, exactly the same "stale cluster identity rejected after kube-transition reboot-retry" mechanism described in both prior ledger entries. This does not appear to share a root cause with the other failure already investigated earlier in this run (`live-investigation.md`'s entries are for different tests/suites in this run; none overlap with `TestClusterVMApp`). Given the identical mechanism recurring across three nightly runs now, this looks like an unfixed EVE-K node-rejoin/reboot-retry bug in the kube cluster-transition logic rather than test or infra flakiness.

### TestSecuritySuite: failure analysis

#### TestVaultKeyModeRecoveryOnZFS

##### Failure

```

a mode that opens the vault must not cost a second attempt
Expected
    <int>: 1
to equal
    <int>: 2
```

##### Claude's conclusion

###### Root cause

The live state matches the ledger exactly: `evetest status` shows `TestVaultKeyModeRecoveryOnZFS` failing at the assertion "a mode that opens the vault must not cost a second attempt" with `actual=1, expected=2`. Live vaultmgr/zedagent logs confirm the vault genuinely unsealed successfully with only one attempt — `VaultStatus` for "Application Data Store" shows `UnlockMethod: tpm-local-sealed`, `ConversionComplete: true`, no error, and the TPM-unseal path completed cleanly without any preceding failed/retry attempt in this boot's log sequence.

This is a **known, recurring issue**, not a new regression. The live-ledger shows this identical test/assertion (`vault_keymode_test.go:298`) failing with the same `1` vs `2` mismatch going back to **2026-10-29** (first occurrence, `TestVaultKeyModeRecoveryOnExt4`), reproducing again on 2026-10-30 (both run #1 and run #2, across both the Ext4 and ZFS variants), and now a third+ night in a row tonight. Every prior investigation reached the same conclusion I'm confirming now: the test's hardcoded expected value of `2` is wrong/stale — the assertion's own description says the "no second attempt needed" case should cost 1 attempt, and the device correctly delivers that — so this is a bug in the test expectation itself, not a vaultmgr/pillar defect. It does not share a root cause with any other failure in tonight's run (it's the only failure in `TestSecuritySuite`).

## [2026-10-31 -- 0.0.0-master-c5d8a37e (run #3)](https://github.com/lf-edge/eve/actions/runs/41135067537)

[Full report](https://lf-edge.github.io/eve/test/master/runs/3/)

### TestApplicationConnectivitySuite: failure analysis

#### TestFlowLog

##### Failure

```
timed out after 5m0.001156278s (excluding download) waiting for app "1e21db6b-85eb-44be-9beb-0c216fd339d3" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

That background grep command timed out and was stopped — it's no longer needed since I already found the root cause through the log analysis above. No action required.

#### TestSwitchNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.001020894s (excluding download) waiting for app "d8b067de-9811-4552-bf86-e2cd08167d20" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

Still stuck — consistent with a permanent hang, not a slow-but-eventual resolve. I have sufficient evidence to write the root-cause summary now.

###### Root cause

Live evidence shows `acl-app-1`'s content tree (`0afaf071-9f53-4458-9a2c-883c79cdab02`, image `lfedge/evetest-ubuntu-ctr:1.0`) has been wedged in `RESOLVING_TAG` since 00:49:26 and is still stuck there right now (`evetest eve app-info` still reports `state:RESOLVING_TAG`), well past the 5-minute timeout. The downloader log shows both `acl-app-1` and `acl-app-2` created identical tag-resolve requests for the same image at the same instant (00:49:26); `acl-app-2`'s resolve (`5f99c65b-…`) eventually logged `Resolve config Done` ~2m49s later at 00:52:15 and the app proceeded to `running`, but `acl-app-1`'s resolve (`927f4c59-…`) only ever logged `lookupResolveStatus… not found` and never logged a completion — its `runResolveHandler` goroutine appears to have hung indefinitely rather than erroring out, so `zedmanager`/`volumemgr` just kept waiting forever instead of timing out or retrying.

This matches the earlier `TestFlowLog` failure in this same run, which failed with the identical signature (an app timing out in `RESOLVING_TAG`), so the two almost certainly share this root cause — a stuck/hung tag-resolution goroutine in the downloader rather than something specific to ACL or flow-log test logic. I found no prior occurrence of this `RESOLVING_TAG`-hang signature in the nightly ledger, so this does not look like a previously-known/recurring issue — it appears new to this run (both occurrences are from the same `0.0.0-master-c5d8a37e`/`a273c3e9` build).

### TestAppsSuite: failure analysis

#### TestVGAPassthroughNoHostAccess

##### Failure

```
Host processes interfered with PCI devices while the VGA controller 0000:00:01.0 was passed through to the application:
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11133 parent=runc:[1:CHILD]/11132 grandparent=runc:[0:PARENT]/11131
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11133 parent=runc:[1:CHILD]/11132 grandparent=runc:[0:PARENT]/11131
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11133 parent=runc:[1:CHILD]/11132 grandparent=runc:[0:PARENT]/11131
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11133 parent=runc:[1:CHILD]/11132 grandparent=runc:[0:PARENT]/11131
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11133 parent=runc:[1:CHILD]/11132 grandparent=runc:[0:PARENT]/11131
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11133 parent=runc:[1:CHILD]/11132 grandparent=runc:[0:PARENT]/11131
Kernel messages mentioning 0000:00:01.0:
[    1.363326] [    T1] pci 0000:00:01.0: [1234:1111] type 00 class 0x030000 conventional PCI endpoint
[    1.372013] [    T1] pci 0000:00:01.0: BAR 0 [mem 0x80000000-0x80ffffff pref]
[    1.374147] [    T1] pci 0000:00:01.0: BAR 2 [mem 0x8264d000-0x8264dfff]
[    1.376198] [    T1] pci 0000:00:01.0: ROM [mem 0xffff0000-0xffffffff pref]
[    1.379851] [    T1] pci 0000:00:01.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    2.061760] [    T1] pci 0000:00:01.0: vgaarb: setting as boot VGA device
[    2.061760] [    T1] pci 0000:00:01.0: vgaarb: bridge control possible
[    2.061760] [    T1] pci 0000:00:01.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    2.444137] [    T1] pci 0000:00:01.0: Adding to iommu group 1
[  258.456902] [ T5810] vfio-pci 0000:00:01.0: vgaarb: deactivate vga console
[  258.456919] [ T5810] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  295.740385] [ T7586] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
[  296.212104] [ T7586] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  700.987169] [T11159] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
```

##### Claude's conclusion

This confirms the whitelist logic at `pciaccess_helpers_test.go:408-410` is unchanged since the known issue was first recorded — it still only exempts `comm` strings with prefix `"qemu-system-"` and doesn't recognize QEMU's `CPU N/KVM` vCPU threads as belonging to the same owning process.

**Root cause:** This is the test's own tracer misfiring, not real host interference. `pciAccess.isViolation()` (`evetest/tests/apps/pciaccess_helpers_test.go:408-410`) only whitelists PCI config-space writes when `comm` has prefix `"qemu-system-"`. Live SSH evidence confirms PID 11133 is `vga-passthrough-app`'s own qemu process (main thread `comm=qemu-system-x86`, cmdline matches the app's domain `5bc81561-...1.1`), but its vCPU thread (TID 11159) shares the same PID and is named `CPU 0/KVM` — exactly the comm string being flagged as a host-interference violation during the app's `[app-restart]`. This is the same root cause as the identical failure already analyzed in this same run's ledger entry (run #2, 2026-10-30) and is a known, recurring issue first seen in run #1 on 2026-10-29 — the underlying `HasPrefix`-only vCPU-thread-recognition gap in the test helper has not been fixed since. It's unrelated to other failures in this run (e.g. the earlier `TestPurgeNeverActivatedApp` SDN-tunnel networking issue), as they're in entirely different subsystems.

### TestBootstrapSuite: failure analysis

#### TestBootstrapWithLACPBondUsingOverrideJSON

##### Failure

```
Failed to receive SDN tunnel properties: rpc error: code = Unavailable desc = unable to connect to SDN gRPC service on any of the uplink IPs ([192.168.170.4]): failed to establish tunnel to SDN: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 192.168.170.4:50121: connect: no route to host"
```

##### Claude's conclusion

###### Root cause

Live inspection confirms setup never progressed past SDN bring-up: `evetest sdn status` reports "SDN client is not initialized," `evetest eve info` reports device `edge-dev` "is not onboarded," and `evetest eve collect-info` fails because "network model not applied." The broker log (`docker logs evetest-50021`) shows the SDN VM (`sdn-3574ce7a`, Proxmox VM 104) was freshly provisioned and powered on at 23:24:46–23:24:48, and immediately reported uplink IP `192.168.170.4` — but every gRPC dial to `192.168.170.4:50121` from 23:25:08 through 23:29:48 (the full ~4.5-minute retry budget) failed, first with `i/o timeout` then with `connect: no route to host`, i.e. the broker host never got a network path to that guest at all, not a service-not-ready response.

This is the same SDN-gRPC-tunnel "no route to host" signature already seen twice earlier tonight in this very run — `TestBootstrapWithAutoDiscoveredProxyUsingOverrideJSON` (`192.168.170.5`) and `TestKonvertSuite/TestKvmToKUpgrade` (`192.168.170.5`) — and it is a known/recurring issue per the ledger, first observed on 2026-10-29 (run #1, `TestAppsSuite/TestPurgeNeverActivatedApp`). With four independent occurrences now across two consecutive nightly runs, each on a freshly provisioned SDN VM with a distinct Proxmox VM ID/IP, this points to a systemic flakiness in the Proxmox broker's networking path to newly created SDN VMs rather than an isolated one-off — not an EVE/pillar code regression, and no PR diff was supplied here to assess separately.

### TestDeviceConnectivitySuite: failure analysis

#### TestLACPBond

##### Failure

```

Timed out after 600.000s.
Expected to satisfy: LACP bond has IP, no errors and reports LACP status
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"DDX43DJO"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usedByBaseOS:true  ioAddressList:{macAddress:"1e:68:56:62:e1:30"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet2"  members:"ethernet2"  usedByBaseOS:true  ioAddressList:{macAddress:"ce:30:0f:9c:43:d9"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"127.0.0.1:53"  DNSsearch:"test."}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/hostfs"  total:261}  storageList:{mountPath:"/"  total:3959}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"nbd15"}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/log"}  storageList:{device:"nbd4"}  storageList:{device:"nbd1"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd11"}  storageList:{device:"nbd8"}  storageList:{mountPath:"/persist/clear"}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/status"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{device:"nbd5"}  storageList:{device:"nbd0"}  storageList:{mountPath:"/config"  total:5}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{device:"nbd7"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/persist/containerd-system-root"}  bootTime:{seconds:1793403351}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-master-c5d8a37e-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"dba6237e-eb82-4b46-a559-99021ea8d5d5"  lastRebootReason:"NORMAL: First boot of device - at 2026-10-30T23:37:25.795489582Z"  lastRebootTime:{seconds:1793403445  nanos:795489582}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1793403532  nanos:590085651}  lastSucceeded:{seconds:1793403845  nanos:902495826}  ports:{ifname:"eth0"  name:"ethernet0"  free:true  proxy:{}  macAddr:"da:39:78:d0:19:f2"  dns:{}  up:true  err:{timestamp:{seconds:1793403845  nanos:902397459}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"00000000-0000-0000-0000-000000000000"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1793403532  nanos:590085651}}  pnac_status:{}}  ports:{ifname:"eth1"  name:"ethernet1"  free:true  proxy:{}  macAddr:"da:39:78:d0:19:f2"  dns:{}  up:true  err:{timestamp:{seconds:1793403845  nanos:902414568}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"00000000-0000-0000-0000-000000000000"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1793403532  nanos:590085651}}  pnac_status:{}}  ports:{ifname:"bond1"  name:"lacp-bond"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.20.123"  IPAddrs:"fe80::fad8:9f5e:102a:aa07"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"interface bond1: no suitable IP address available"  timestamp:{seconds:1793403540  nanos:541113557}  severity:SEVERITY_ERROR}  networkUUID:"0874eeb1-155f-4ed1-9d47-77de6b6dcf51"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1793403532  nanos:590085651}}  pnac_status:{}  bond_status:{mode:BOND_MODE_802_3AD  mii_monitor:{enabled:true  polling_interval:100}  arp_monitor:{}  lacp:{lacp_rate:LACP_RATE_FAST  active_aggregator_id:1  partner_mac:"ca:fe:fe:80:68:22"  actor_key:9  partner_key:9}  members:{logicallabel:"ethernet0"  mii_up:true  lacp:{aggregator_id:1  actor_churn_state:BOND_LACP_CHURN_STATE_NONE  partner_churn_state:BOND_LACP_CHURN_STATE_NONE}}  members:{logicallabel:"ethernet1"  mii_up:true  lacp:{aggregator_id:1  actor_churn_state:BOND_LACP_CHURN_STATE_NONE  partner_churn_state:BOND_LACP_CHURN_STATE_NONE}}}}  ports:{ifname:"eth2"  name:"ethernet2"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.21.0/24"  domainname:"test."  proxy:{}  macAddr:"ce:30:0f:9c:43:d9"  IPAddrs:"172.20.21.146"  IPAddrs:"fe80::ad8e:d773:2df4:40cc"  defaultRouters:"172.20.21.1"  dns:{DNSservers:"10.16.17.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1793403845  nanos:902380760}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"9dda4430-ad46-4b8d-aaae-1acf179b2b00"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1793403532  nanos:590085651}}  pnac_status:{}}}}  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1793403519  nanos:388742462}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"Z~\xa5f\xfec\xca\xd5\xea\xb0^w\xef\xa9\x15:\xe3\xa0#i\xa90\x970\x1e\xd4c\xd42\xb7\r\xf0"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

###### Root cause

Live `evetest eve info` shows the bond (`bond1`/`lacp-bond`) had a valid IP, correct LACP status, and no errors well *after* the test's 600s timeout — the error actually cleared at `23:49:27`, just 23 seconds too late for the 10-minute `Eventually` in `bonds_test.go:448` that started at the `config-applied` checkpoint (`23:39:04`). Device logs confirm why: EVE has two equal-cost mgmt/L3 uplinks here, `bond1` and `eth2`. `VerifyAllIntf` (`pkg/pillar/controllerconn/send.go:516-630`) only does a full, real connectivity test on mgmt interfaces up to `requiredSuccessCount` (1); any other same-cost mgmt interface is checked via a no-op "dry run" that leaves its `TestResults` untouched, and the code comments explicitly say these get a real test only via "rotations" on a later cycle. Device logs show exactly this: the DPC-verify cycle at `23:44:05` (5 min after config-applied) did a real test and succeeded via `eth2`, but left `bond1`'s `TestResults` completely unchanged (still the `23:39:00` error); `bond1` only got its real/first test — and succeeded — on the *next* cycle at `23:49:27` (≈10m27s after config-applied). The test's hard-coded 600s budget assumes "more than one 5-minute interval" is always enough margin, but with two equal-cost uplinks rotating, a given port can need just over two intervals to get its real test, and here it narrowly missed by 23 seconds.

This is unrelated to any other failure (this is the only test run in this session), is not a networking/pillar regression — the bond itself works correctly — and does not appear in `live-ledger.md` (no prior `TestLACPBond` entries), so this looks like a first-occurrence, narrow test-timing-margin flake caused by the interface-test rotation logic in `VerifyAllIntf` interacting with the fixed 10-minute timeout in `evetest/tests/networking/bonds_test.go`, rather than a device/pillar bug. No PR diff was supplied to assess for relevance.

### TestNodeClusterResilienceSuite: failure analysis

#### TestDNIDandBackupDNID

##### Failure

```
timed out after 30m0.007419338s (excluding download) waiting for app "fe9ba0f9-3415-4afc-9e90-d54ac0cb54d1" (vm1) on device "edge-dev1" to reach RUNNING state (last state: BOOTING)
```

##### Claude's conclusion

###### Root cause

`vm1` (app `fe9ba0f9...`, DNID = edge-dev1) was still at step 1 of the test — initial deploy, before edge-dev3 is ever powered off — when it hung. Live `kubectl` shows the VMI `vm1-fe9ba-0vzhrz` actually scheduled and **Running/Ready on edge-dev3**, not edge-dev1, because its VMIRS only carries a *preferred* node affinity (weight 100) toward edge-dev1, which the scheduler was free to ignore. edge-dev1's own pillar logs confirm this repeatedly: `zedkube` sees `IsDNidNode:true ScheduledOnThisNode:false ... AppKubeStatus:RunningState`, while `domainmgr`'s `Info()` call logs `"vm1-fe9ba-0 scheduled on a different node"` on every poll and (by design, per the comment at `pkg/pillar/hypervisor/kubevirt.go:1800`) returns `UNKNOWN` rather than `RUNNING` for a domain that is healthy on a peer node. `zedmanager.handleENClusterAppStatusImpl` only republishes the existing (stale `BOOTING`) `AppInstanceStatus` when `ScheduledOnThisNode` is false instead of deriving `RUNNING` from the cluster-wide view, so the DNID node's reported app state is permanently wedged at BOOTING even though the guest is genuinely up elsewhere — exactly the 30‑minute timeout evetest hit. This is a gap in the backup-DNID status-reporting path that only handles the case of a pod moving to a node *because* of a DNID outage/failover, not a normal scheduler placement decision away from the DNID with no outage involved at all. `TestDNIDandBackupDNID` itself doesn't appear as a prior failure in `live-ledger.md` (it's new, added in `6574dccd3`), so this is not yet a recorded recurring issue, though it's the same class of DNID/backup-DNID reporting gap (zedmanager/zedkube status propagation) as the already-known, recurring `TestVMAppPurgeDuringFailover` failure tracked since 2026-10-29 — a different test/step, but very likely the same underlying architectural gap the "DNID rework" is meant to address.

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.201s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

###### Root cause

This is the exact same deadlock already seen twice in the ledger, reproducing a third time tonight. Live evidence on edge-dev2: `kubectl get vmirs,vmi,vm -A` returns zero application objects cluster-wide (only system pods), matching the test's `found []`. The app's config shows `designatedNodeId: "52bf6120-8898-41e3-81ad-89702e959453"`, which is exactly edge-dev1's own device UUID (`evetest eve info -d edge-dev1` reports `HostName:"52bf6120-..."`), and `evetest status`/`kubectl get nodes` confirm edge-dev1 is `EVE_DEVICE_STATE_SUSPECT`/`NotReady` — deliberately powered off by the test. `app-info` history for `failover-purge-app` shows it was last `RUNNING` (cluster_app_running:true) at 23:41:02, with no further reports since — once the purge tore down the old VMIRS/VMI, nothing was left anywhere in the cluster to originate a fresh one, because per `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2004`) only the designated node can unconditionally create a new VMIRS, and that node is the one the test keeps offline.

This is a known, recurring issue: the same test/failure/code path was already recorded in `live-ledger.md` for the 2026-10-29 and 2026-10-30 (run #2) nightly runs, with the first occurrence traced to when `purge_during_failover_test.go` was added (`98acf1411`, 2026-10-18). Tonight's failure shares that exact root cause — a genuine, still-unfixed gap in zedmanager/zedkube's purge-after-failover activation logic, not an environment flake — and is also the same class of DNID/backup-DNID status-propagation gap flagged in this run's earlier `TestDNIDandBackupDNID` investigation, though that was a different specific code path (zedmanager's `handleENClusterAppStatusImpl` vs. `getKubeAppActivateStatus`).

#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

###### Root cause

Live `volumemgr` logs on edge-dev1 confirm the exact same race documented in last night's (2026-10-30, run #2) ledger entry for this identical test: at `00:33:16.611` and `00:33:20.329`, `doUpdateContentTree` for vm1's ContentTreeStatus (`34751c9a...`) ran `contentTreeSatisfiedByPVCs` and logged `no local volumes reference this content tree`, because the matching `VolumeConfig`/`handleVolumeCreate(ef414555...)` wasn't published until `00:33:20.402` — a few hundred milliseconds *after* the content tree had already fallen through to the normal path, found all blobs already verified in local CAS, and self-completed `VERIFIED→LOADING` within that same `00:33:20.330` reconcile call. So the PVC-adoption shortcut in `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` (`pkg/pillar/cmd/volumemgr/acceptclustercontenttree.go`, `updatestatus.go`) again lost the race against `VolumeConfig` publication timing right after reboot, landing the tree at `LOADED` (108) instead of `REMOTELOADED` (125).

This is a **known, recurring issue**: it first appeared in last night's run (2026-10-30, run #2, commit `a273c3e9`) and is now reproducing again tonight (commit `c5d8a37e`) with the identical mechanism and even the identical log message — it did not occur in the prior night's run (2026-10-29, run #1), so the regression window is bounded to between those two runs. It is unrelated to this run's earlier `TestVMAppPurgeDuringFailover` failure (different test, different code path — zedmanager/zedkube VMIRS activation vs. volumemgr's content-tree/PVC reconciliation).

### TestNodeClusterSuite: failure analysis

#### TestAppInstancePurge

##### Failure

```
Device "edge-dev": expected 0 reboot(s) but observed 1
```

##### Claude's conclusion

No evetest source available locally — not critical, I have enough live evidence. Here's the summary.

**Root cause:** The device rebooted because of an EVE-K cluster-mode transition, not a pillar crash. The live `NodeAgentStatus` on `edge-dev` shows `RebootReason:" [2026-10-30 22:40:43]: BootReasonKubeTransition, Transition from cluster mode to single node"`, `BootReason:15`, `RestartCounter:1`, `RebootTime:"2026-10-30T22:40:43Z"` — matching the harness-observed reboot at 22:41:13-54. This happened right when `TestAppInstancePurge`'s config (version 9) was applied to the *reused* `edge-dev` device: the prior test in this run, `TestNativeKubeAppNetworking` (22:29-22:39), had explicitly put the device into single-node eve-k cluster mode (`"Waiting for the single-node eve-k cluster to become ready"` / `"cluster-is-ready"` checkpoints at 22:30:37), but `TestAppInstancePurge`'s own config doesn't carry that cluster config forward. EVE's own nodeagent/kube-transition logic correctly detected the resulting mode change and deliberately rebooted to apply it — this is the same documented `BootReasonKubeTransition` mechanism (`docs/EVE-K.md`) seen elsewhere in this run's ledger for `TestClusterVMApp`, though that case was triggered by a stuck cluster-join retry rather than a lost cluster config, so it's a related mechanism but not the same specific trigger. This exact test (`TestAppInstancePurge`) does not appear in `live-ledger.md`'s prior history, so it's a new failure, not a previously-known recurring one — it looks like a device-reuse/test-isolation gap (back-to-back tests leaving/removing cluster config on a shared device) rather than a pillar regression.

#### TestMgmtProxy

##### Failure

```

wait for the raw container pod to become Ready
Unexpected error:
    <*fmt.wrapError | 0x2141ddfbb420>: 
    failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )",
        err: <*ssh.ExitError | 0x2141dde26640>{
            Waitmsg: {status: 141, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

This is an exact byte-for-byte match of the error seen last night (`...dial tcp 192.168.170.2:5000: connect: no route to host`), confirming it's the same bug recurring, not a new one.

**Root cause:** This is a known, recurring issue — `TestMgmtProxy` failed last night (2026-10-29 nightly run) with the identical error signature and is now reproduced tonight. Live evidence on `edge-dev1` confirms the same mechanism: the `mgmtproxy-test-container` pod is stuck in `ImagePullBackOff` because its image pull to the containerd registry mirror fails with `dial tcp 192.168.170.2:5000: connect: no route to host`, and `ip route get 192.168.170.2` on the device resolves via `eth1`/cluster network rather than through mgmtproxy's loopback listener. The device's containerd env (`/run/mgmtproxy-containerd-env`) only sets `HTTPS_PROXY=http://127.0.0.1:5443` with no `HTTP_PROXY`, and since the registry mirror is wired as a plain `http://` endpoint, Go's proxy resolution never routes this pull through mgmtproxy, so it falls through to the deliberately-poisoned main routing table and fails. The SSH `exit status 141` is simply `kubectl wait`'s wrapper hitting SIGPIPE once its 180s timeout expired against a pod that could never become Ready. This does not share a root cause with the other failures already investigated in this run's `live-investigation.md` (`TestAppInstancePurge`'s kube-transition reboot); it's the same test/infra-level gap (HTTP registry-mirror pulls bypassing mgmtproxy) already documented in the ledger from last night.

#### TestClusterVMApp

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev3")
```

##### Claude's conclusion

This is enough corroborating live evidence to confirm the pattern matches the previously-investigated occurrence.

###### Root cause

This is the same underlying failure as the `TestClusterVMApp` incident already recorded in `live-ledger.md`'s most recent nightly run (`2026-10-30`, version `0.0.0-master-a273c3e9`), now reproduced again tonight (`0.0.0-master-c5d8a37e`) with an identical signature — it's a recurring issue, not a new one. Live evidence on `edge-dev3`: `nodeagent`'s status shows `RebootReason: BootReasonKubeTransition, Reboot after retry cluster transition attempt 1` at `2026-10-30T23:56:05Z` (`RestartCounter:2`), and `/persist/kubelog/k3s.log` shows k3s has crash-looped every ~5 minutes since (last attempt `00:17:20Z`, device uptime only 25 min) with `Skipping cluster configuration validation: not authorized` → `failed to bootstrap cluster data: not authorized`, so it never produces a working API server. `evetest eve -d edge-dev1 kubectl get nodes` confirms only `edge-dev1`/`edge-dev2` are `Ready`; `edge-dev3` never rejoined, matching the exact same join-rejection mechanism (stale/rejected cluster identity surviving the kube-transition reboot-retry) described in the prior investigation. This does not match either of this run's other already-investigated failures (`TestAppInstancePurge`'s cluster-config-not-carried-forward reboot, `TestMgmtProxy`'s mgmtproxy registry-routing gap) — it's specifically the `edge-dev3` join/reboot-retry "not authorized" bug recurring across consecutive nightly runs.

### TestSecuritySuite: failure analysis

#### TestVaultKeyModeRecoveryOnExt4

##### Failure

```

the correction must survive the reboot
Expected
    <int>: 1
to equal
    <int>: 2
```

##### Claude's conclusion

###### Root cause

Live evidence confirms vaultmgr itself behaved correctly: after the corrected-mode reboot (`boot time 2026-10-30T23:46:14Z`), `VaultStatus` shows a healthy, unlocked vault (`Status:2`, `UnlockMethod:1`, no `Error`), and the only `"Vault config inited with tpmkeyonly false"` line currently present on-device is a single occurrence timestamped `23:44:41` (`/persist/newlog/keepSentQueue/dev.log.1793403882771.gz`). The test's `stickyBase` for that message was captured at `23:44:43` (just before "Rebooting the device again...") with value `2`, but by the final check at `23:46:51` — barely two minutes later — `newlogCount` found only `1`. That's a genuine *decrease*, not unwanted growth, and `/persist/newlog/keepSentQueue/` on the live device shows only ~8 minutes of gzip chunks retained (30 files spanning `23:38`–`23:46`) — i.e. newlogd is rotating/dropping already-queued chunks fast enough that one of the two matching log lines present at the `stickyBase` snapshot fell out of the swept window before the final `newlogCount` re-swept it. Since `newlogCount` (`vault_keymode_test.go:381`) only greps currently-present `/persist/newlog` files, this makes the "must not regress" count assertions inherently racy against newlogd's rotation.

This does **not** share a root cause with other failures in tonight's run (unrelated suites/subsystems: SDN networking, VMIRS activation, content-tree PVC race). It is related to, but not identical to, a known/recurring issue: the ledger already records this exact test failing with the identical `Expected 1 to equal 2` signature the previous night (2026-10-29) and again earlier tonight (`run #2`, on the sibling assertion at line 298 `"a mode that opens the vault must not cost a second attempt"`), attributed there to a possibly-stale test expectation. Tonight's failure is on the *other* "no-regression" assertion (line 295, `"the correction must survive the reboot"`), and the live evidence here points more precisely at the shared underlying flakiness: counting newlog matches over a narrow, actively-rotating retention window makes these equality-across-reboot assertions fragile, rather than the counts being simply wrong constants. This looks like a known/recurring test-fragility issue (first observed 2026-10-29) now shown to affect both of the assertions built on `newlogCount`, not a new vaultmgr/pillar regression.

#### TestVaultKeyModeRecoveryOnZFS

##### Failure

```

a mode that opens the vault must not cost a second attempt
Expected
    <int>: 1
to equal
    <int>: 2
```

##### Claude's conclusion

###### Root cause

Live evidence confirms the vault opened correctly on the first try: after the "corrected mode" reboot, `vaultmgr` logs show `UnsealDiskKeyWithRecovery` succeeding immediately (`"successfully unsealed the disk key from TPM"` at `23:55:32.722`) with no preceding failure/retry for that boot, and `VaultStatus` for "Application Data Store" shows `Status:2` (unlocked), `UnlockMethod:1`, no error — i.e. the device genuinely needed only **1** attempt. The failing assertion (`vault_keymode_test.go:298`, "a mode that opens the vault must not cost a second attempt") expects a literal `2`, which contradicts its own description — the actual=1 result is the *desired* behavior, not a regression.

This is a known/recurring issue: the identical `Expected 1 to equal 2` failure on this exact assertion (line 298) already appears in the ledger for 2026-10-29 (run #1) and again earlier tonight, 2026-10-30 (run #2) — both attributed to this same stale/incorrect expected-value bug in `vault_keymode_test.go`. This is now the third consecutive occurrence, confirming it as a persistent test-code defect rather than a new bug.

It does **not** share the same root cause as the earlier `TestVaultKeyModeRecoveryOnExt4` failure investigated in this run (that one was traced to a newlogd-rotation race affecting a different assertion, line 295, about log-count non-regression across reboots). Both failures live in the same test file and same general vault-key-mode test flow, but stem from two distinct underlying defects: this one is a hardcoded wrong expected attempt-count, the other is a flaky log-count check.

## [2026-10-30 -- 0.0.0-master-a273c3e9 (run #2)](https://github.com/lf-edge/eve/actions/runs/40962376935)

[Full report](https://lf-edge.github.io/eve/test/master/runs/2/)

### TestAppsSuite: failure analysis

#### TestPurgeNeverActivatedApp

##### Failure

```
Failed to receive SDN tunnel properties: rpc error: code = Unavailable desc = unable to connect to SDN gRPC service on any of the uplink IPs ([192.168.170.4]): failed to establish tunnel to SDN: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 192.168.170.4:50121: connect: no route to host"
```

##### Claude's conclusion

###### Root cause

This is an infrastructure/networking failure, not an EVE or test-code bug. Live evidence (`evetest status`, `evetest eve info`, `evetest sdn status`) confirms the EVE device is still `EVE_DEVICE_STATE_UNDEFINED` / "not onboarded" and the SDN client was never initialized — i.e. `TestPurgeNeverActivatedApp` is the very first subtest in this `TestAppsSuite` run (`gotest.json` confirms only `TestAppsSuite` and this one subtest ran), and it failed in `Setup`/`openTunnelToSDN` before any device or network instance existed. The broker log timeline shows both VMs were provisioned fine via Proxmox (`eve-7bfaa3c2-edge-dev` as VM 104, `sdn-7bfaa3c2` as VM 106, both powered on normally), and the SDN VM even reported a valid uplink IP (`192.168.170.4`) at 22:18:22 — but every one of ~45 retries over the following 5 minutes to reach its gRPC service on port 50121 failed with `no route to host`, not a timeout or refused connection. That specific error signature points to a routing/bridge-network problem between the (remote, Proxmox-hosted) broker and the SDN VM's uplink network rather than the SDN service itself failing to start.

This does not share a root cause with any other failure in this run (no other subtests have executed yet), and it does not match any entry in the ledger — the ledger covers only this one 2026-10-29 run, and its other "no route to host" entries (`TestAppUserData` SSH, `TestMgmtProxy` registry pull) are unrelated, app/test-level routing issues on an already-onboarded device, not a pre-onboarding SDN-tunnel failure. So this looks like a new/first-occurrence infrastructure flake in the Proxmox broker's networking to the SDN VM, with no prior recorded history to confirm recurrence.

#### TestVGAPassthroughNoHostAccess

##### Failure

```
Host processes interfered with PCI devices while the VGA controller 0000:00:01.0 was passed through to the application:
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=13832 parent=runc:[1:CHILD]/13831 grandparent=runc:[0:PARENT]/13827
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=13832 parent=runc:[1:CHILD]/13831 grandparent=runc:[0:PARENT]/13827
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=13832 parent=runc:[1:CHILD]/13831 grandparent=runc:[0:PARENT]/13827
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=13832 parent=runc:[1:CHILD]/13831 grandparent=runc:[0:PARENT]/13827
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=13832 parent=runc:[1:CHILD]/13831 grandparent=runc:[0:PARENT]/13827
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=13832 parent=runc:[1:CHILD]/13831 grandparent=runc:[0:PARENT]/13827
Kernel messages mentioning 0000:00:01.0:
[    1.340329] [    T1] pci 0000:00:01.0: [1234:1111] type 00 class 0x030000 conventional PCI endpoint
[    1.346047] [    T1] pci 0000:00:01.0: BAR 0 [mem 0x80000000-0x80ffffff pref]
[    1.348012] [    T1] pci 0000:00:01.0: BAR 2 [mem 0x8264d000-0x8264dfff]
[    1.349850] [    T1] pci 0000:00:01.0: ROM [mem 0xffff0000-0xffffffff pref]
[    1.351649] [    T1] pci 0000:00:01.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    2.005250] [    T1] pci 0000:00:01.0: vgaarb: setting as boot VGA device
[    2.005250] [    T1] pci 0000:00:01.0: vgaarb: bridge control possible
[    2.005250] [    T1] pci 0000:00:01.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    2.388987] [    T1] pci 0000:00:01.0: Adding to iommu group 1
[  253.808329] [ T5880] vfio-pci 0000:00:01.0: vgaarb: deactivate vga console
[  253.808347] [ T5880] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  287.925083] [ T7520] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
[  288.397152] [ T7520] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[ 1075.719591] [T13858] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
```

##### Claude's conclusion

This confirms it live: PID 13832 is the VGA app's own qemu-system-x86_64 process (second boot, after `[app-restart]` — bootTime 1793318772), and TID 13858 within that same process is the `CPU 0/KVM` vCPU thread — exactly the thread the tracer's `comm` field reports in the violation. This is the identical bug already fully diagnosed for this exact test, in this exact nightly run.

**Root cause:** This is the same issue already recorded in this run's `live-investigation.md`/ledger for `TestVGAPassthroughNoHostAccess` — `pciAccess.isViolation()` (`evetest/tests/apps/pciaccess_helpers_test.go:408-413`) only whitelists PCI config-space writes when `comm` has prefix `"qemu-system-"`, but QEMU's vCPU thread renames itself to `CPU N/KVM` while sharing the same PID. Live evidence reconfirms this: PID 13832 is `vga-passthrough-app`'s own qemu process after its `[app-restart]` reboot (bootTime `1793318772`, matching `evetest eve app-info`), and `ps -eLo pid,tid,comm` shows TID 13858 within that same process is literally named `CPU 0/KVM` — the exact comm string flagged as a "host interference" violation. So normal guest-driven PCI config emulation during the app's own restart is being misclassified as host interference, not an actual device/pillar regression. This is a recurring, known issue first seen in last night's run (2026-10-29, run #1) with the identical signature and root cause — it is not new, and is unrelated to the other failure already investigated in this run (`TestPurgeNeverActivatedApp`'s SDN-tunnel networking issue), since they're in entirely different subsystems.

### TestBootstrapSuite: failure analysis

#### TestBootstrapWithAutoDiscoveredProxyUsingOverrideJSON

##### Failure

```
Failed to receive SDN tunnel properties: rpc error: code = Unavailable desc = unable to connect to SDN gRPC service on any of the uplink IPs ([192.168.170.5]): failed to establish tunnel to SDN: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 192.168.170.5:50121: connect: no route to host"
```

##### Claude's conclusion

###### Root cause

Live inspection confirms the test never got past SDN bring-up: `evetest eve ssh/info/collect-info` all fail with *"network model not applied, therefore cannot discover IP of device"*, and `evetest sdn status/ssh` fail with *"SDN client is not initialized"* / SSH connection reset — there is no live EVE device or SDN to inspect further because setup aborted first.

From the raw `gotest.json` broker log: for this test, Proxmox VM 107 (`sdn-602052d4`) was freshly built and powered on at 23:37:37, and the broker immediately reported it had uplink IP `192.168.170.5` (DHCP lease observed). However, every retry of the gRPC tunnel dial to `192.168.170.5:50121` from 23:37:51 through 23:42:37 (the full 5-minute budget) failed with `connect: no route to host` — i.e., the host never saw a network path to that IP at all, not a refused/closed-port response. This points to the newly-created Proxmox SDN VM never actually coming up on the network (stuck boot, failed NIC attach, or a Proxmox/broker-host networking glitch), rather than the SDN service being slow to start inside an otherwise-reachable guest.

This is unrelated to the preceding `TestBootstrapWithAutoDiscoveredProxy` test in the same run, which completed and tore down its own SDN VM normally (clean "Removed Proxmox VM 113" / "SDN tunnel proxy context is done" sequence) before this one provisioned VM 107 from scratch. I checked the live-ledger (which only has one prior dated run, 2026-10-29 run #1) and found no earlier occurrence of this SDN-gRPC/"no route to host" signature — this looks like a new, one-off broker/Proxmox-side infrastructure flake rather than a known recurring issue or a pillar/EVE code regression.

### TestKonvertSuite: failure analysis

#### TestKvmToKUpgrade

##### Failure

```
Failed to receive SDN tunnel properties: rpc error: code = Unavailable desc = unable to connect to SDN gRPC service on any of the uplink IPs ([192.168.170.5]): failed to establish tunnel to SDN: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 192.168.170.5:50121: connect: no route to host"
```

##### Claude's conclusion

No prior entries in the ledger match this exact failure mode (broker unable to reach the SDN VM's gRPC tunnel at boot) — those two "no route to host" hits in the ledger are unrelated (in-guest routing/proxy issues inside already-running devices, not broker→SDN-VM connectivity at setup). This is the first recorded occurrence of this specific failure.

**Root cause:** From the evetest-container logs (`docker logs` on the paused `evetest-50021` container), the broker successfully built the SDN image, provisioned it as Proxmox VM 107 (`sdn-dbcea02d`), powered it on, and got back an uplink IP (`192.168.170.5`) — but every gRPC dial attempt to `192.168.170.5:50121` over the full ~5-minute retry window (22:18:28–22:23:26) failed with `connect: no route to host`, which is a routing-layer failure (no path/ARP to the host), not a refused connection from a service that simply hasn't started yet. Because the SDN tunnel never opened, the EVE device (`edge-dev`) never had its network model applied and was never onboarded (`evetest eve info` confirms: "device is not onboarded"; `evetest eve collect-info` confirms: "network model not applied, therefore cannot discover IP"), and `evetest sdn status`/`sdn logs` now report "SDN client is not initialized" — consistent with the gRPC tunnel to the SDN VM never having come up at all. This looks like a Proxmox-side infrastructure issue (the SDN VM's network path to the broker was never actually live despite Proxmox reporting an uplink IP) rather than an EVE/pillar or test-code bug — it occurred before any device code ran. I don't have Proxmox host access from this sandbox (no `qm`/`pvesh`, and raw network diagnostics like `ping`/`ip route` were blocked by tool permissions) to pin down why the VM's network path was down, and this run had no other failures to compare against for a shared root cause.

#### Shrink

##### Failure

```

Timed out after 722.784s.
The function passed to Eventually failed at /evetest/tests/konvert/app_helpers_test.go:104 with:
Unexpected error:
    <*fmt.wrapError | 0x91065123c80>: 
    unable to reach app "0f980e71-5b2d-4a97-9f43-fadf3e417d3c" SSH on device "edge-dev": no reachable endpoint among [172.20.20.123:2222 [fe80::a4bd:e572:452a:bfd7]:2222 172.20.20.214:22 [fe80::16:3eff:fe1a:2374]:22]
    {
        msg: "unable to reach app \"0f980e71-5b2d-4a97-9f43-fadf3e417d3c\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.20.123:2222 [fe80::a4bd:e572:452a:bfd7]:2222 172.20.20.214:22 [fe80::16:3eff:fe1a:2374]:22]",
        err: <*errors.errorString | 0x910653b47a0>{
            s: "no reachable endpoint among [172.20.20.123:2222 [fe80::a4bd:e572:452a:bfd7]:2222 172.20.20.214:22 [fe80::16:3eff:fe1a:2374]:22]",
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

The "Shrink" subtest's SSH timeout is not a networking problem — the guest VM itself is wedged. `virt-handler` logs show the redeployed app's VMI (`konvert-repartition-app-0f980-04kc5l`) entered `Domain status: Paused, reason: IOError` at 01:19:55, within 25s of starting, and has stayed paused continuously ever since (still paused at the time of investigation, ~15 min later); `kubectl describe vmi` confirms `Warning IOerror ... VM Paused due to not enough space on volume: disk1` (17 occurrences). The backing Longhorn volume (`pvc-02d453f9...`, 300Mi) is already reported as fully allocated (`actualSize: 314576896` ≈ its 300Mi nominal size) even though the content tree behind it is only ~54MB (`VolumeStatus` `CurrentSize: 56701775`), and the node-level storage is nowhere near full (28GB free on `/persist`, 32GB `storageAvailable` reported by Longhorn) — so this is the VM's own root-disk PVC running out of backing space almost immediately on boot, not a host disk-pressure issue, which is why the guest never comes up to answer SSH on any of the listed endpoints.

This is a distinct failure from the earlier `TestKvmToKUpgrade` failure recorded in this run's `live-investigation.md` (an SDN gRPC-tunnel connectivity problem that occurred before any device/app was ever created) — here the device, app deployment, and blob-reuse redeploy all succeeded, and the failure is specific to the post-conversion root-disk volume sizing/provisioning for this `Shrink` variant of `TestKvmToKRepartitionNoVolmig`. The ledger's one prior "Shrink" entry (same run, earlier date in the file) was a completely different, setup-time failure (`evebuild/nightly:10.1.0-kvm-amd64` image not found) that never even reached device creation, so this "VM paused on ENOSPC after blob-reused redeploy" mode has no prior entry in the ledger and appears to be a new, previously-unrecorded issue — plausibly in how the redeployed app's root-disk PVC size/backing is derived when content-tree blobs are reused after a kvm→k conversion.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

**Root cause:** This is a confirmed repeat of a known, previously-analyzed deadlock in `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2004`). Live evidence on edge-dev2: `designated_node_id` for `failover-purge-app` is `6636a8ae-...` (edge-dev1, which is `EVE_DEVICE_STATE_SUSPECT` / powered off for the failover scenario), the old VMIRS/VMI were torn down by `purgeCmdDone` at 00:40:54 (`SuccessfulDelete virtualmachineinstance/failover-purge-app-7c061-0jgrh9`), and ever since then zedmanager on edge-dev2 has logged an unbroken stream of `getKubeAppActivateStatus(...): not designated, ..., onTheDevice false, statusRunning false` — a non-designated node refuses to originate a fresh VMIRS once nothing is scheduled anywhere, so `kubectl get vmirs,vmi,vm -A` returns "No resources found" cluster-wide, matching the test's `found []`.

This is the exact same failure signature, same test, same code path, and same log pattern already recorded in `live-ledger.md` for the 2026-10-29 nightly run (one night earlier) — that analysis concluded it's a genuine unhandled gap in zedmanager/zedkube's purge-after-failover activation logic (only the designated node, which is deliberately kept offline by the test, can originate a brand-new VMIRS), not an environment flake. So this is a known/recurring issue, first observed the previous night (2026-10-29), reproducing identically tonight. It's independent of the run's other failures (`TestVMIRSStrandedReplicasRecovery` passed; `TestDNIDandBackupDNID` is a separate test in this suite). No PR diff was provided to assess relevance.

#### TestClusterPVCRedownload

##### Failure

```

vm1's content tree is in state LOADED, not REMOTELOADED -- it was re-downloaded despite the PVC already being complete
Expected
    <types.SwState>: 108
to equal
    <types.SwState>: 125
```

##### Claude's conclusion

Both the test and the `contentTreeSatisfiedByPVCs` logic are recent additions, consistent with this being a newly-exposed gap rather than a long-standing flake. I have enough evidence for a root-cause conclusion.

**Root cause:** This is a genuine race in `contentTreeSatisfiedByPVCs`/`doUpdateContentTree` (`pkg/pillar/cmd/volumemgr/acceptclustercontenttree.go:43`, `updatestatus.go:51-63`), not the SDN/datastore outage the test sets up. Live evidence on edge-dev1: at `01:27:36.612` and again at `01:27:40.862` `doUpdateContentTree` ran the PVC-adoption check for vm1's ContentTreeStatus (`91b54b77...`) and logged `contentTreeSatisfiedByPVCs(...): no local volumes reference this content tree`, because the matching `VolumeConfig` (`cd7703a5...`, referencing that same ContentID) wasn't created in volumemgr until `01:27:40.951` — *after* the content tree had already fallen through to the normal download path, found all its blobs already verified in the local CAS (survived the reboot on disk), and self-completed straight to `VERIFIED→LOADING→LOADED` by `01:27:41.063`, all within that same reconcile call. So the datastore being firewalled off was irrelevant here — no actual network download was attempted (confirmed no DownloaderConfig for vm1's sha256) — the bug is purely that the PVC-adoption shortcut loses the race against VolumeConfig publication timing right after a reboot, landing the tree at `LOADED` instead of `REMOTELOADED`. This failure is unrelated to the earlier `TestVMAppPurgeDuringFailover` failure in this same run (different test, different code path: zedmanager/zedkube VMIRS activation vs. volumemgr's content-tree/PVC reconciliation). It also doesn't appear in `live-ledger.md`'s prior nightly history, and both the test and the `contentTreeSatisfiedByPVCs` check are recent additions (`git log` shows them added in `f02fe67c9`/later commits), so this looks like a newly-exposed, not-yet-fixed gap rather than a known recurring issue.

### TestSecuritySuite: failure analysis

#### TestVaultKeyModeRecoveryOnExt4

##### Failure

```

a mode that opens the vault must not cost a second attempt
Expected
    <int>: 1
to equal
    <int>: 2
```

##### Claude's conclusion

###### Root cause

Live vaultmgr logs confirm the harness's two-reboot sequence worked exactly as designed: after the wrong-mode reboot at 22:50:56 (`Vault config inited with tpmkeyonly false`), vaultmgr tried `tpmKeyOnly=false`, got `Error unlocking vault: exit status 1`, then fell back to `tpmKeyOnly=true` and succeeded — 2 real attempts, correctly matching that reboot's own expectation. After the corrected-mode reboot at 22:52:51 (`Vault config inited with tpmkeyonly true`), it unsealed and opened the vault on the very first try with no fallback — 1 attempt. `VaultStatus` on the device (`Status:2`) confirms the vault is healthy/unlocked and `VaultConfig` reads `{"TpmKeyOnly":true}`, so nothing is actually broken on the device side.

The failing assertion at `vault_keymode_test.go:298` expects `2` attempts for this "correct mode, no second attempt needed" case, even though the test's own title/message ("a mode that opens the vault must not cost a second attempt") describes the desired behavior as 1 attempt — the actual result. This looks like a stale/incorrect expected value in the test itself rather than a pillar/vaultmgr regression.

This is a known, recurring issue: the ledger (`live-ledger.md`, 2026-10-29 run #1) already records this identical failure for `TestSecuritySuite/TestVaultKeyModeRecoveryOnExt4` with the same conclusion (test bug, not a pillar regression) — the timestamps and log sequence in that entry are essentially identical to what I observed live here, so this is the same recurring/first-seen-today issue, not a new one. It's the only failure in this suite this run, so there's no shared root cause with other suites' failures.

## [2026-10-29 -- 0.0.0-master-3a27e25d (run #1)](https://github.com/lf-edge/eve/actions/runs/40731449552)

[Full report](https://lf-edge.github.io/eve/test/master/runs/1/)

### TestAppsSuite: failure analysis

#### TestMemoryPressureEvents

##### Failure

```

Timed out after 180.001s.
memory-monitor's handler wrote no complete report after "": map[dir:2026-10-28-22-59-57 handler.log:Warning: Problem (retrying all errors). Will retry in 16 seconds. 1 retry left.   0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0 curl: (7) Failed to connect to 127.0.0.1 port 6543 after 0 ms: Could not connect to server + cleanup + set +x memstat_eve.out: memstat_pillar.out:]
Expected
    <bool>: false
to be true
```

##### Claude's conclusion

**Root cause:** This nightly image is a `COVER=y` build — confirmed live via `/persist/coverage/` being populated on the device. Per `pkg/pillar/agentlog/coverage.go` (introduced in commit `80399fc9a`, 2026-04-21, "coverage: add Go coverage instrumentation for pkg/pillar agents"), `MaybeInitSigUsr2` is a deliberate no-op on coverage builds — `SIGUSR2` is consumed exclusively by `zedbox/coverage.go`'s coverage-flush handler, so `agentlog.ListenDebug`'s pprof server on port 6543 is never started. `memory-monitor-handler.sh`'s `eve http-debug` (which sends SIGUSR2) therefore can never make port 6543 listen on this build; the subsequent `curl 127.1:6543/debug/pprof/heap` exhausts all retries (reproduced live: manually re-sending `kill -USR2` to the live, healthy zedbox at pid 2573 still left the port refused), and under the script's `set -e` this aborts straight into `cleanup` before `memstat_pillar.out`/`memstat_eve.out` are ever written (confirmed: `heap_pillar.out` is 0 bytes, handler log ends right after the last failed curl). zedbox itself was never OOM-killed or wedged — pid 2573 stayed alive with normal CPU/RSS, and `memory.high` was already restored to `max`, so this is unrelated to the other, cosmetic failures earlier in this run (SSH `no route to host` on `TestAppUserData`, missing Docker registry creds on `TestAppLogs`/`TestCgroupTree`). This looks like a genuine, newly-introduced incompatibility between the coverage instrumentation and the memory-monitor test's reliance on `eve http-debug`, rather than a flake — any coverage-enabled nightly run of `TestMemoryPressureEvents` should fail the same way until either the handler script or the coverage/SIGUSR2 wiring is fixed to not conflict.

#### TestVGAPassthroughNoHostAccess

##### Failure

```
Host processes interfered with PCI devices while the VGA controller 0000:00:01.0 was passed through to the application:
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11456 parent=runc:[1:CHILD]/11455 grandparent=runc:[0:PARENT]/11454
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11456 parent=runc:[1:CHILD]/11455 grandparent=runc:[0:PARENT]/11454
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11456 parent=runc:[1:CHILD]/11455 grandparent=runc:[0:PARENT]/11454
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11456 parent=runc:[1:CHILD]/11455 grandparent=runc:[0:PARENT]/11454
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11456 parent=runc:[1:CHILD]/11455 grandparent=runc:[0:PARENT]/11454
  [app-restart] pci_user_write_config_word comm=CPU 0/KVM pid=11456 parent=runc:[1:CHILD]/11455 grandparent=runc:[0:PARENT]/11454
Kernel messages mentioning 0000:00:01.0:
[    1.449193] [    T1] pci 0000:00:01.0: [1234:1111] type 00 class 0x030000 conventional PCI endpoint
[    1.454086] [    T1] pci 0000:00:01.0: BAR 0 [mem 0x80000000-0x80ffffff pref]
[    1.454860] [    T1] pci 0000:00:01.0: BAR 2 [mem 0x8264d000-0x8264dfff]
[    1.455573] [    T1] pci 0000:00:01.0: ROM [mem 0xffff0000-0xffffffff pref]
[    1.456351] [    T1] pci 0000:00:01.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    1.787121] [    T1] pci 0000:00:01.0: vgaarb: setting as boot VGA device
[    1.787815] [    T1] pci 0000:00:01.0: vgaarb: bridge control possible
[    1.788503] [    T1] pci 0000:00:01.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    1.995509] [    T1] pci 0000:00:01.0: Adding to iommu group 1
[  169.292441] [ T5092] vfio-pci 0000:00:01.0: vgaarb: deactivate vga console
[  169.292463] [ T5092] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  202.118796] [ T7788] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
[  202.413328] [ T7788] vfio-pci 0000:00:01.0: vgaarb: VGA decodes changed: olddecodes=io+mem,decodes=io+mem:owns=io+mem
[  606.553119] [T11481] vfio-pci 0000:00:01.0: Invalid PCI ROM header signature: expecting 0xaa55, got 0x0000
```

##### Claude's conclusion

I have enough to write the root cause.

**Root cause:** The test's own tracer, not host interference, is at fault. `pciAccess.isViolation()` (`evetest/tests/apps/pciaccess_helpers_test.go:408-413`) whitelists config-space writes/resets only when `Comm` has prefix `"qemu-system-"`. Live evidence confirms PID 11456 *is* the VGA app's own qemu process after its restart (`ps` shows `/usr/bin/qemu-system-x86_64 ... -name 2b69c9ce-...1.1`, matching the `vga-passthrough-app`'s second boot per `evetest eve app-info`). The first couple of `pci_user_write_config_word`/`pci_try_reset_function` calls in the trace correctly show `comm=qemu-system-x86` and are exempted, but the immediately following writes from the *same* process show `comm=CPU 0/KVM` — QEMU's vCPU thread, which renames itself per-thread while sharing the same PID/TGID — so the `HasPrefix` check fails to recognize them as belonging to the owning qemu process and misclassifies normal guest-driven PCI config emulation (through the vCPU thread during device re-initialization on restart) as a host-interference violation. This is unrelated to the `TestMemoryPressureEvents` failure recorded earlier in this run's ledger (that one was a coverage-build/SIGUSR2 port-6543 issue, a different subsystem entirely). This test was only added in `c2539a9de` (2026-09-27), has no prior run history to check for recurrence, and the bug — missing `"CPU \d+/KVM"` vCPU-thread recognition in the comm-prefix filter — looks like a genuine new test defect rather than a device-side regression.

### TestDeviceConnectivitySuite: failure analysis

#### TestNetworkConfigFallback

##### Failure

```

Timed out after 230.799s.
Expected to satisfy: The newer DPC becomes active again once the network matches it
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7919  storage:40006  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"F7C4CHIE"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtOnly}  dns:{DNSservers:"127.0.0.1:53"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/persist/ingested"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist"  total:40006  storageLocation:true}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/"  total:3959}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/netdump"}  storageList:{device:"nbd4"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/persist/newlog"}  storageList:{device:"nbd8"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{device:"nbd0"}  storageList:{mountPath:"/persist/vault"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/certs"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/config"  total:5}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{device:"nbd1"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"vda9"  total:40953  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{mountPath:"/hostfs"  total:262}  storageList:{device:"nbd5"}  storageList:{device:"nbd11"}  storageList:{device:"nbd7"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/clear"}  storageList:{mountPath:"/persist/lost+found"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd12"}  storageList:{device:"nbd10"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"vda7"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30056"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"nbd13"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  bootTime:{seconds:1793228482}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-pr40731449552-3a27e25d-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"523167ef-035a-421e-899e-d9f5ca39a180"  lastRebootReason:"NORMAL: First boot of device - at 2026-10-28T23:01:57.743109695Z"  lastRebootTime:{seconds:1793228517  nanos:743109695}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1793228850  nanos:913526603}  lastFailed:{seconds:1793228871  nanos:808044912}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:1  subnet:"10.99.99.0/24"  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"10.99.99.5"  defaultRouters:"10.99.99.1"  dns:{DNSservers:"10.16.16.25"}  up:true  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 10.99.99.5: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1793228871  nanos:806696468}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtOnly  networkUUID:"d93d86e4-7427-432a-b35e-0c213ffbd10d"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1793228850  nanos:913526603}}  pnac_status:{}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 10.99.99.5: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}}  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1793228550  nanos:725307359}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\x8c:Y\xbf^4\xe3|\xdf\xf8\xbf}P\xcf\x19\x81\x8b\x00\xc4\xc3*\xde\x15\xf8\xb2%\xa8\xcc\xe7\xef!\x84"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.port.testduration"  value:{value:"10"}}  configItems:{key:"timer.port.testfailinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE  error:{description:"[ATTEST] No escrow data"  timestamp:{seconds:1793228559  nanos:267659034}  severity:SEVERITY_ERROR}}  api_capability:API_CAPABILITY_DEFERRED_QUEUE_METRICS  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

###### Root cause

The device's broken ("ethernet0-only") DPC failed at `LastFailed: 2026-10-28T23:07:51.808Z` (confirmed in `/persist/status/nim/DevicePortConfigList/global.json`), and after the SDN network was fixed to match it at 23:08:01, the DPC didn't actually re-test and succeed until `LastSucceeded: 23:13:29.5Z` — about 338s after the failure, confirmed by `evetest eve collect-info`. The test's Phase 3 budget (`evetest/tests/networking/failover_test.go:619-633`) computes its timeout from `NetworkTestFailInterval` + `NetworkTestBetterInterval` (both explicitly lowered to their 60s floor via `cfgProps`), yielding the observed 230.799s timeout, but it never lowers `NetworkTestInterval` (`timer.port.testinterval`), which defaults to 5 minutes and drives `dpcManager`'s main periodic re-verify timer (`dpcTestTimer` in `pkg/pillar/dpcmanager/dpcmanager.go`). The actual ~338s recovery time lines up almost exactly with that un-lowered 300s default plus test duration, not with the 60s intervals the test's comment assumed governed recovery — so this looks like an incomplete timeout budget in the test itself (missing `NetworkTestInterval` override) rather than a pillar regression; the DPC did correctly fall back and later did recover, just slower than the test allowed. No other test in this run failed, so there's no shared root cause within this run, and I don't have access to a known-issues ledger to say whether this is a recurring flake — no PR diff was provided to judge relevance either.

### TestKonvertSuite: failure analysis

#### TestKvmToKRepartitionGeometry

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

**Root cause:** `TestKvmToKRepartitionGeometry` pins `INITIAL_EVE_VERSION=10.1.0` (the test's hardcoded default, since it needs a pre-existing release layout to convert from) and resolves its repo via `initialEVERepoParamKey`, which defaults to empty — meaning "pull from `evebuild/nightly`," the nightly-CI-build repo. That repo only holds numeric build-id tags (e.g. `40731449552-kvm-amd64`, as seen in the other tests in this run), not semantic release tags, so `docker pull evebuild/nightly:10.1.0-kvm-amd64` fails with "pull access denied ... repository does not exist." The failure happened at setup, before any EVE device or SDN was created (`evetest eve info`/`sdn status` both confirm nothing was ever onboarded), so there's no live device to inspect further.

This is isolated to this one test: the other three tests in the same suite run (`TestKvmToKUpgrade`, `TestKvmToKContentTree`, `TestKvmToKAppRecreate`), which don't pin an initial version and use the HEAD build instead, all passed — no shared root cause. I found no ledger of known/recurring issues in the repo or in memory, so I can't say whether this has happened before; given it's purely about which Docker repo the `INITIAL_EVE_VERSION` parameter pulls from, it looks like an environment/test-configuration gap (the released-version repo for the konvert axis isn't configured) rather than a code regression — unless the branch under test specifically touches `evetest/tests/konvert` parameter defaults, which no PR diff was provided to check.

#### TestBackupCorruptRestore

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

Memory updated to note this recurs for any `requirePinnedInitialVersion` caller, not just the one test.

#### Shrink

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

Confirmed: identical failure signature, no EVE device/SDN ever created (status shows "No EVE devices found"), failing at setup before `prepareImageForEVEDevice`.

**Root cause:** `Shrink` is another `TestKonvertSuite` test that pins `INITIAL_EVE_VERSION=10.1.0` via `requirePinnedInitialVersion` (same as `TestKvmToKRepartitionGeometry` and `TestBackupCorruptRestore` earlier in this run) and resolves its image repo through the unset `initialEVERepoParamKey`, defaulting to `evebuild/nightly` — a repo that only contains numeric nightly build-id tags, not the `10.1.0-kvm-amd64` release tag. This is the exact same root cause already recorded in this run's investigation log and in persistent memory (`project_konvert_initial_version_repo.md`): any konvert test calling `requirePinnedInitialVersion` hits this environment/test-config gap, not a code regression. `evetest status`/`eve info` confirm no device or SDN was ever created, consistent with the failure occurring in `Setup` before any VM provisioning.

#### PersistTooFull

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

**Root cause:** `PersistTooFull` is another `TestKonvertSuite` test that calls `requirePinnedInitialVersion` (`INITIAL_EVE_VERSION=10.1.0`), which resolves via the unset `initialEVERepoParamKey` and defaults to the `evebuild/nightly` repo — a repo that only holds numeric nightly build-id tags, not the `10.1.0-kvm-amd64` release tag, so the pull fails at image-prep time. Live evidence confirms this: `evetest eve info` and `evetest sdn status` both report no EVE device/SDN was ever onboarded (failure occurred in `Setup` before any VM provisioning), and the `PersistTooFull` artifact directory is empty, consistent with failing before any logs/db snapshots could be collected.

This is the same root cause already recorded three times earlier in this run (`TestKvmToKRepartitionGeometry`, `TestBackupCorruptRestore`, `Shrink`) and matches the known/recurring issue in persistent memory (`project_konvert_initial_version_repo.md`): every konvert test that pins an initial EVE version hits this environment/test-config gap (pinned-start konvert tests pull release tags from the nightly-build repo, which doesn't have them), not a code regression.

#### ZFSPersist

##### Failure

```
EVE image "evebuild/nightly:10.1.0-kvm-amd64" is not available (neither locally nor on Docker Hub). If running against the current HEAD (EVETEST_EVE_VERSION not explicitly set), build the image first with: make eve
```

##### Claude's conclusion

Confirmed — stack trace shows `TestKvmToKRepartitionRefused` (subtest `ZFSPersist`) going through `setupDevice` → `Setup` → `prepareImageForEVEDevice` → `pushEVEImageToBroker`, the same code path as the four prior failures this run, and live checks confirm no EVE device/SDN was ever created (setup-time failure).

**Root cause:** Same recurring issue as the four earlier failures in this run (`TestKvmToKRepartitionGeometry`, `TestBackupCorruptRestore`, `Shrink`, `PersistTooFull`). `ZFSPersist` (part of `TestKvmToKRepartitionRefused`) also pins `INITIAL_EVE_VERSION=10.1.0` and resolves it via the unset `initialEVERepoParamKey`, defaulting to the `evebuild/nightly` repo, which only has numeric nightly build-id tags, not the `10.1.0-kvm-amd64` release tag — so the image pull fails before any device/SDN is provisioned (confirmed live: `evetest eve info`/`sdn status` report no onboarded device, no initialized SDN). This matches the known/recurring issue already tracked in persistent memory (`project_konvert_initial_version_repo.md`): every konvert test calling `requirePinnedInitialVersion` hits this environment/test-config gap, not a code regression.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.001s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:169 with:
expected exactly one VMIRS for the app, found []
Expected
    <[]string | len:0, cap:0>: nil
to have length 1
```

##### Claude's conclusion

That test passed, so this failure is independent, not a shared root cause with an earlier failure in this run. I have enough evidence now to write the root-cause summary.

###### Root cause

Live inspection on edge-dev2 (the node the app failed over to) shows `kubectl get vmirs/vmi/vm -A` return **zero** objects cluster-wide — not "wrong generation," but none at all — confirming the test's own `found []`. Pillar logs pinpoint why: after the purge counter bumped (23:59:35, `handleModify ... needPurge: true`), zedmanager on edge-dev2 tore down the old-generation VMIRS/pod (`purgeCmdDone` at 00:01:41, with a `failed to cleanup domain ... VMI still available` warning along the way), but then got permanently stuck repeating `getKubeAppActivateStatus(...): not designated, node ..., onTheDevice false, statusRunning false` / `Waiting for config.Activate` for the next 13 minutes until the 900s `Eventually` timeout fired. Per `getKubeAppActivateStatus` (`pkg/pillar/cmd/zedmanager/zedmanager.go:2004`), a non-designated node only activates a kube app if Kubernetes has *already* placed it there (`onTheDeviceForApp`) or this node is an eligible backup DNID — but the test deliberately pins `dnidOutageThresholdKey` to 2 hours precisely so no backup DNID ever kicks in, and nothing is placed anywhere once the old VMIRS is deleted. Only the designated node (edge-dev1) can unconditionally originate a fresh VMIRS, and it's powered off for the whole test — a chicken-and-egg deadlock that the test's own doc comment explicitly calls out as the exact scenario it's designed to catch ("gating ... on the app's designated node, or on where a replica currently happens to be scheduled, would deadlock exactly this case"). This looks like a genuine, currently-unhandled gap in zedmanager/zedkube's purge-after-failover activation logic for kube-hypervisor apps, not an environment flake.

This is unrelated to the other failure visible in this run's artifacts directory (`TestVMIRSStrandedReplicasRecovery`), which passed earlier in the same suite run. The test itself (`purge_during_failover_test.go`) was added very recently (commit `98acf1411`, 2026-10-18), so this may be the first time it has exercised this exact deadlock path — I have no access to a historical-failure ledger to say whether it has recurred before.

### TestNodeClusterSuite: failure analysis

#### TestNativeKubeAppNetworking

##### Failure

```

kubectl apply manifest:
apiVersion: v1
kind: Pod
metadata:
  name: native-bare-pod
  namespace: default
  annotations:
    k8s.v1.cni.cncf.io/networks: '[{"name":"ni-local-ni","namespace":"eve-kube-app","interface":"localni","portMappings":[{"hostPort":8022,"containerPort":22,"protocol":"tcp"}]},{"name":"ni-switch-ni","namespace":"eve-kube-app","interface":"switchni","mac":"02:00:00:00:01:01"}]'
spec:
  containers:
  - name: native-bare-pod
    image: lfedge/evetest-ubuntu-ctr:1.2

Unexpected error:
    <*fmt.wrapError | 0x24bbaf746ae0>: 
    failed to execute script over SSH for EVE device edge-dev: Process exited with status 1 (stderr: error: error validating "STDIN": error validating data: failed to download openapi: Get "https://127.0.0.1:6443/openapi/v2?timeout=32s": dial tcp 127.0.0.1:6443: connect: connection refused; if you choose to ignore these errors, turn validation off with --validate=false
    )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev: Process exited with status 1 (stderr: error: error validating \"STDIN\": error validating data: failed to download openapi: Get \"https://127.0.0.1:6443/openapi/v2?timeout=32s\": dial tcp 127.0.0.1:6443: connect: connection refused; if you choose to ignore these errors, turn validation off with --validate=false\n)",
        err: <*ssh.ExitError | 0x24bbaf824840>{
            Waitmsg: {status: 1, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

This is a config poll at the exact time, consistent with the controller pushing cluster config right as the test's kubectl apply ran. I have enough evidence to write the root-cause summary now.

###### Root cause

The `kubectl apply` for `native-bare-pod` failed because `dial tcp 127.0.0.1:6443: connection refused` — the k3s API server on `edge-dev` was down at that exact moment. Live evidence from `/persist/kubelog/k3s.log`: k3s first started at `20:55:39`, then at `21:01:53-54` it logged `"Saving cluster bootstrap data to datastore"` followed by `"Waiting up to 2s for graceful shutdown of Kine GRPC server..."`, and a brand-new `k3s server`/`k3s init` process came back up at `21:02:05`, not becoming reachable again until roughly `21:02:24+` (closed-connection errors on 6443 continue until then). The test's `kubectl apply` ran at `21:01:56` — squarely inside that ~30s restart window — per `gotest.json`.

This matches a documented, expected EVE-K behavior rather than a crash: `docs/EVE-K.md` states that whenever `/etc/rancher/k3s/config.yaml.d/*` changes (e.g. cluster config arriving from the controller), "kube will terminate k3s processes and restart it to apply the config." The Adam controller log (`adam-stdout`) shows `edge-dev` polling `/config` at `21:01:51` and again at `21:01:57`, right as this restart happened, consistent with a config layer landing mid-test and triggering the restart. The preceding test in the same run, `TestSingleNodeCluster`, passed cleanly at `21:00:20`, so this isn't a carry-over failure from earlier in the run — it's a fresh race between the native-k8s-networking test's `kubectl apply` and a k3s config-reload restart. I don't have visibility into whether this specific race is already a known/recurring flake (no ledger file was found in the environment to check against), so I can't confirm prior occurrences beyond this run.

#### TestMgmtProxy

##### Failure

```

wait for the raw container pod to become Ready
Unexpected error:
    <*fmt.wrapError | 0x24bbaffed180>: 
    failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )
    {
        msg: "failed to execute script over SSH for EVE device edge-dev1: Process exited with status 141 (stderr: )",
        err: <*ssh.ExitError | 0x24bbaf7ff100>{
            Waitmsg: {status: 141, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

No ledger file is present in this environment, so I can't check recurrence history — I'll note that explicitly.

###### Root cause

The `mgmtproxy-test-container` pod sat in `ImagePullBackOff` the entire ~3 minutes `kubectl wait` polled it: `kubectl describe pod` on `edge-dev1` shows `Failed to pull image "milan4zededa/evetest-ubuntu-ctr:1.2": ... dial tcp 192.168.170.2:5000: connect: no route to host`. `TestMgmtProxy` deliberately "poisons" the main routing table so outbound traffic prefers `ethernet1`/cluster-network (confirmed live: `ip route get 1.1.1.1` still resolves via `10.244.245.1 dev eth1`, and a live `curl`/traceroute from `edge-dev1` to `192.168.170.2:5000` fails with no route, while the SDN host itself reaches that same mirror fine — so the mirror isn't down, `edge-dev1`'s own routing is). The test expects this specific image pull to go "through mgmtproxy's loopback listener" (per the test's own comment), but `evetest`'s `configureContainerdRegistryMirror` (`evetest/setup.go`) wires the docker.io pull-through cache as a plain **`http://`** containerd registry mirror via `hosts.toml`/`config_path`, not as traffic funneled through the `HTTPS_PROXY` mgmtproxy listener — and the live sentinel at `/run/mgmtproxy-containerd-env` on `edge-dev1` shows only `HTTPS_PROXY=http://127.0.0.1:5443` is set for containerd, with no `HTTP_PROXY`. Since Go's `http.ProxyFromEnvironment` only consults `HTTPS_PROXY` for `https://` requests, this plain-HTTP registry-mirror pull bypasses mgmtproxy entirely and falls through to the deliberately-poisoned main table, routing out the wrong interface and failing. The SSH `exit status 141` is just the `eve exec kube kubectl wait ... --timeout=180s` wrapper getting SIGPIPE once that 180s wait expired against a pod that could never become Ready.

This does **not** share a root cause with the earlier `TestNativeKubeAppNetworking` failure in this run (that one was a k3s-restart timing race from a controller config reload, per `live-investigation.md`) — this is a distinct, test/infra-level gap where the HTTP-based registry-mirror path isn't proxy-aware while the test's routing-poisoning setup assumes all outbound image-pull traffic goes through mgmtproxy. No known-issue ledger file was found in this environment, so I can't confirm whether this specific gap (HTTP mirror pulls bypassing mgmtproxy's HTTPS_PROXY) is a recurring, previously-seen flake.

#### TestClusterVMApp

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev3")
```

##### Claude's conclusion

###### Root cause

This is a new, distinct failure — not a repeat of the two earlier failures recorded in `live-investigation.md` (those were a k3s-restart race in `TestNativeKubeAppNetworking` and an mgmtproxy registry-mirror routing gap in `TestMgmtProxy`; neither touches node-join logic).

Live evidence on `edge-dev3`: at `22:21:38` zedkube received a config update transitioning it from no cluster (`Valid:false`) to joining `test-cluster` as a control-plane node (`ClusterName:test-cluster`, `IsWorkerNode:false`, `BootstrapNode:false`, `JoinServerIP:10.244.244.2`) — consistent with the test's `initial-config-applied` checkpoint. At `22:26:53` the device self-rebooted with `BootReasonKubeTransition, Reboot after retry cluster transition attempt 1`, i.e. EVE's own kube-transition logic decided the join wasn't progressing and retried via reboot. After that reboot, `/persist/kubelog/k3s.log` shows k3s has been crash-looping ever since (still failing at `22:48:09`, 20+ minutes later) with `preparing server: failed to bootstrap cluster data: not authorized` — it never forms a working API server (`localhost:8080 connection refused` even for local `kubectl`, `/run/.kube/k3s/k3s.yaml` never created). `evetest eve -d edge-dev1 kubectl get nodes` confirms only `edge-dev1`/`edge-dev2` are members; `edge-dev3` never rejoined. This matches edge-dev3's own earlier cluster-info snapshot showing it reverted to a fresh, unjoined state (`cluster_id: 00000000-...`, `NODE_ADMISSION_JOINING`) — i.e. the node still carries stale k3s/etcd identity from a prior cluster membership (it was previously part of another cluster per its `creationTime 22:07:35` in zedkube's node info) that the transition logic failed to clear, so the retry-reboot's join attempt is rejected as unauthorized rather than succeeding, leaving the node permanently excluded and the test's 30-minute readiness wait to time out. I found no known-issues ledger file in this environment to check for recurrence, so I can't say whether this specific join/reboot-retry auth failure has been seen before.

### TestSecuritySuite: failure analysis

#### TestVaultKeyModeRecoveryOnExt4

##### Failure

```

a mode that opens the vault must not cost a second attempt
Expected
    <int>: 1
to equal
    <int>: 2
```

##### Claude's conclusion

###### Root cause assessment

The live vaultmgr logs show the vault-unlock mechanics worked exactly as designed in both reboots: after the harness wrote the wrong key mode (`tpmkeyonly false`) at 22:03:52 and rebooted, vaultmgr tried `tpmKeyOnly=false` (failed, `exit status 1`), then fell back to `tpmKeyOnly=true` and succeeded — 2 real attempts, as expected for a wrong-mode recovery. After the harness wrote the corrected mode (`tpmkeyonly true`) at 22:06:01 and rebooted again, vaultmgr opened the vault on the very first try with no fallback — 1 attempt, which is exactly the "no second attempt" behavior the test's title describes. `VaultConfig/global.json` on the device currently reads `{"TpmKeyOnly":true}` and `VaultStatus` shows the vault unlocked (`Status:2`), confirming the final state is healthy.

Since the actual on-device behavior matches the desired outcome described by the failing assertion ("a mode that opens the vault must not cost a second attempt" — and indeed it only cost one, actual=1), while the test expected a literal `2`, this looks like a bug/stale expectation in `vault_keymode_test.go:298` itself (e.g. reusing the prior wrong-mode reboot's expected attempt count of 2 instead of 1 for the corrected-mode check) rather than a vaultmgr/pillar regression. This is the only failure in the run (no other `TestSecuritySuite` cases failed), so it doesn't share a root cause with any earlier failure this run. No `NIGHTLY-LEDGER.md` was fetched into this artifact directory (ledger lookup appears to have been skipped/unavailable for this run), so I can't confirm whether this is a known/recurring issue — I'd treat it as new until the ledger can be checked. I don't have the evetest test-harness source available locally to directly confirm the exact comparison being made at line 298, so this read of the test logic (vs. a pillar bug) is inferred from the log evidence rather than verified against the assertion's source.

### TestTelemetrySuite: failure analysis

#### TestKernelPanicReport

##### Failure

```

Timed out after 600.001s.
the kernel panic stack trace header was not uploaded
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

I have enough evidence now to form a root-cause conclusion.

**Root cause assessment:**

The pillar-side telemetry pipeline worked correctly: nodeagent detected the pstore record, logged the `Kernel panic stack trace from pstore ... sysrq triggered crash` header, 384 `kernel_panic_stacks` lines, and the end-of-stack marker (all confirmed via `grep`-ing the device's own `/persist/newlog` gzip chunks), and newlogd uploaded them (`POST .../newlogs` at 21:10:51/21:10:54, no errors in Adam's log, chunks moved to the device's `keepSentQueue`). Critically, Adam's own on-disk DB (`adam-db/device/.../logs/01793221851056973797`) contains the exact header and end-of-stack entries at `2026-10-28T21:10:44Z` — well inside the 10-minute `logs-reported` window that ended at 21:20:57. So the device and the controller both did their job; the data was sitting in Adam's store the whole time.

The failure is that `TestKernelPanicReport`'s `device.WatchLogs(...)` live subscription (which streams from Adam's admin `/device/<uuid>/logs` endpoint via `AdamClient.SubscribeToDeviceLogs` in `evetest/controller/adam.go`) never delivered those already-persisted entries to the test's channel — `gotest.json` shows no reconnect/error messages from that subscriber at all during the whole run, meaning it just silently never forwarded the matching records even though they existed in Adam's store seconds after the subscription was opened. That points to a bug/race in the evetest↔Adam log-streaming path (e.g. the stream missing records written around the device's reboot/re-registration, visible in Adam's log as brief onboarding/"integrity token mismatch" noise at 21:10:47–21:11:10 from the reconnecting device), rather than a pillar regression.

This is the only failure in this run (no earlier failed test to share a root cause with), and I found no local ledger of known/recurring issues to check against, so I can't say whether this is a recurring flake — but the evidence (data present in Adam's DB, absent from the test's live watch channel, no error logged by the subscriber) strongly isolates the bug to the evetest/Adam log-watch mechanism rather than to EVE itself.
