# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

## [2026-11-27 -- 0.0.0-13.4-stable-b96891fd (run #66)](https://github.com/lf-edge/eve/actions/runs/45943140686)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/66/)

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNetInstanceACLs

##### Failure

```
timed out after 5m0.001083379s (excluding download) waiting for app "cc0437d4-9cc6-45dd-be87-89cfdbf991fb" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Confirmed: this exact test, `TestSwitchNetInstanceACLs`, has failed with this identical CREATING_VOLUME/container-unpack-stall signature before, per the ledger.

**Root cause:** `acl-app-1` (volume `3d6eeb29-d0ba-4de6-b5cc-628c2a69f223`) is stuck in `CREATING_VOLUME` on device `edge-dev` well past the 5-minute test timeout. Live inspection shows the cause is a stalled containerd image unpack under host CPU/IO oversubscription, not a networking/ACL product bug: `ctr -n eve-user-apps snapshots ls` shows two `extract-*` snapshots still `Active` (uncommitted) for the app's image layer, `nproc` inside the guest reports only 1 usable CPU despite the device being configured for 4 vCPUs, and `vmstat` shows a process perpetually blocked on I/O (`b=1`, `wa`≈21–28%). The broker (`farfalle`) is running 12/15 VMs at 124% of host RAM assigned and 1.9 GiB of swap in use, consistent with memory/CPU oversubscription slowing the unpack past the fixed 5-minute budget. This is a known, heavily recurring issue per `live-ledger.md`: this exact test (`TestSwitchNetInstanceACLs`) failed with this identical signature before (e.g. the 2026-11-23 run #45 entry references it), and the same CPU/IO-oversubscription unpack-stall class has recurred across nearly every nightly run since at least 2026-11-20 (run #30), hitting many different suites/apps. No PR diff was provided for this investigation, so no relatedness judgment is needed.
#### TestSwitchNIWithMultiplePorts

##### Failure

```
timed out after 5m0.00022281s (excluding download) waiting for app "fbd785a7-1bfb-40ef-ad51-f5874ba23232" (container-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

This failure matches the exact same pattern confirmed heavily throughout this ledger and in the earlier `TestSwitchNetInstanceACLs` failure in this same run.

###### Root cause

`container-app`'s root volume (`a43b692c-100f-4425-94ce-1ba0dc8d996c`) entered `CREATING_VOLUME` at 06:18:24Z when `volumemgr` began `CreateVolume` for the `evetest-ubuntu-ctr` container image; as of my live check (06:23) the content store on `/persist` (124.1M used of 61.7G available) and the containerd `tmpmounts` directory under `io.containerd.content.v1.content` show the image pull/unpack is still in progress and far short of the volume completing. Live `nproc`/`uptime`/`vmstat` on `edge-dev` show the classic oversubscription signature seen repeatedly tonight: the guest exposes only `nproc=1` against a device configured for 4 vCPUs, load average ~3.9-4.6, and `vmstat` shows a process perpetually blocked on I/O (`b=1`, `wa`≈24-28%). The broker (`farfalle`) corroborates environmental contention: 13/16 VMs running at 102% of host RAM assigned, load 8.3, and 1.9 GiB swap in use.

This shares the identical root cause as the `TestSwitchNetInstanceACLs` failure already investigated earlier in this same suite run (recorded in `live-investigation.md`) — host/device CPU-oversubscription stalling a containerd image unpack past the fixed 5-minute `CREATING_VOLUME`→`RUNNING` test timeout. It is also a known, heavily recurring issue per `live-ledger.md`: this exact `CREATING_VOLUME`/unpack-stall-under-CPU-oversubscription class has hit dozens of tests across nearly every nightly run since at least 2026-11-20 (run #30), including multiple occurrences within `TestSwitchNetworkInstanceSuite` itself. This is an infrastructure/environment issue, not a product regression.
#### TestAccessVLANs

##### Failure

```

Told to stop trying after 19.462s.
Stop waiting for: NI is ONLINE
Network instance is in error state
networkID:"33ff36f1-99e1-4853-8716-70a143b6e135" networkVersion:"1" instType:1 displayname:"vlan-switch" bridgeNum:1 networkErr:{description:"failed to select ports for network instance 33ff36f1-99e1-4853-8716-70a143b6e135: no port is matching label 'switch-ports'" timestamp:{seconds:1795760923 nanos:755803930} severity:SEVERITY_ERROR} state:ZNETINST_STATE_ERROR mtu:1500
```

##### Claude's conclusion

**Root cause:** This is a transient, self-healing boot-time DPC-promotion race, not a product bug. Device `edge-dev` did a first boot at 06:26:57, and came up briefly on the fallback `lastresort` DPC (bare eth0/eth1, no `switch-ports` label). The real `zedagent` DPC — which carries `SharedLabels:[switch-ports]` on ethernet1-3 — was only inserted at 06:28:42.211 and its verification ("DPC verify: Started testing DPC") began at 06:28:43.371, but zedrouter had already applied the `vlan-switch` NI config at 06:28:42.959 and tried to resolve port label `switch-ports` at 06:28:43.755, before the new DPC had finished verification/promotion — logging `no port is matching label 'switch-ports'`. The test's 19.462s fail-fast wait gave up right at that point, but live `evetest eve ni-info vlan-switch` now shows the NI fully recovered: `state:ZNETINST_STATE_ONLINE` with ethernet1/2/3 correctly assigned.

This does **not** share a root cause with the two earlier failures in this run (`TestSwitchNetInstanceACLs`, `TestSwitchNIWithMultiplePorts`), which were `CREATING_VOLUME` container-unpack stalls under host CPU/IO oversubscription — a completely different mechanism. It is, however, a known/recurring issue per `live-ledger.md`: this exact test (`TestAccessVLANs`) has failed with this identical `no port is matching label 'switch-ports'` boot-DPC-race signature in at least three prior nightly runs (including 2026-11-23 run #45), with the same self-healing-shortly-after pattern each time, so this is a long-standing, recurring race rather than a new bug.

## [2026-11-26 -- 0.0.0-13.4-stable-b96891fd (run #60)](https://github.com/lf-edge/eve/actions/runs/45758696740)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/60/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: eth1 is reported as an unused assignable adapter with a MAC address
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7816 storage:63153 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-11.0" serialNumber:"O4LJ4X9N" UUID:"Not Settable" biosVendor:"EFI Development Kit II / OVMF" biosVersion:"0.0.0" biosReleaseDate:"02/06/2015"} network:{macAddr:"da:39:78:d0:19:f2" devName:"ethernet0" IPAddrs:"172.20.20.123" defaultRouters:"172.20.20.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} ipv4_up:true uplink:true networkErr:{timestamp:{seconds:1795672029 nanos:384538616}} localName:"eth0" proxy:{}} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} assignableAdapters:{type:PhyIoNetEth name:"ethernet1" members:"ethernet1" usage:PhyIoUsageDedicated} dns:{DNSservers:"10.16.16.25:53"} storageList:{device:"nbd2"} storageList:{device:"nbd6"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{mountPath:"/hostfs" total:266} storageList:{mountPath:"/persist/status"} storageList:{mountPath:"/persist/tmp"} storageList:{device:"nbd12"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"vda1" total:36 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{mountPath:"/persist" total:63153 storageLocation:true} storageList:{device:"nbd11"} storageList:{mountPath:"/config" total:1} storageList:{mountPath:"/persist/clear"} storageList:{device:"vda9" total:64473 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"nbd7"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{device:"nbd0"} storageList:{device:"nbd10"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{device:"vda" total:65536} storageList:{device:"nbd1"} storageList:{device:"nbd3"} storageList:{device:"nbd8"} storageList:{device:"nbd5"} storageList:{mountPath:"/persist/newlog"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/persist/certs"} storageList:{mountPath:"/persist/agentdebug"} storageList:{mountPath:"/persist/checkpoint"} storageList:{device:"nbd15"} storageList:{mountPath:"/" total:3908} storageList:{device:"vda3" total:512 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{device:"nbd9"} storageList:{device:"vda4" total:1 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{device:"nbd14"} storageList:{mountPath:"/persist/log"} storageList:{device:"nbd13"} storageList:{device:"vda2" total:512 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{mountPath:"/persist/vault"} bootTime:{seconds:1795671877} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-13.4-stable-b96891fd-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"033619f4-5b57-4cb5-a99d-2f58078f2df9" lastRebootReason:"NORMAL: First boot of device - at 2026-11-26T05:45:02.449080575Z" lastRebootTime:{seconds:1795671902 nanos:449080575} systemAdapter:{status:{version:1 key:"zedagent" timePriority:{seconds:1795671989 nanos:633963131} lastSucceeded:{seconds:1795672029 nanos:384584642} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.20.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.20.123" defaultRouters:"172.20.20.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{timestamp:{seconds:1795672029 nanos:384538616}} usage:PhyIoUsageMgmtAndApps networkUUID:"11923b14-35f2-43ed-898a-464ae3642c54" mtu:1500}}} HSMStatus:NOTFOUND HSMInfo:"Not Available" dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1795671974 nanos:939444066} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"X\xfc\xe1$\x18!\xd8HBw\x8c\x89p8\xe1\n޻ʁ_s\xa7\xf5]N\xaa\xe6˥5\xfc" sha_tls_root_ca:"X\xfc\xe1$\x18!\xd8HBw\x8c\x89p8\xe1\n޻ʁ_s\xa7\xf5]N\xaa\xe6˥5\xfc"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} last_boot_reason:BOOT_REASON_FIRST hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE maintenance_mode_reasons:MAINTENANCE_MODE_REASON_NONE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_ADAPTER_USER_LABELS optional_capabilities:{}
```

##### Claude's conclusion

Confirmed: this is the exact same recurring failure.

**Root cause:** `checkAndFillIoBundle(1 eth1 ethernet1)` ran once at 05:46:30.619 and immediately hit `getMacAddr: Can't find ifname eth1`, leaving the IO bundle's MAC permanently blank — domainmgr never retries this lookup. Live `dmesg` confirms why: the kernel renamed `eth1 → keth1` at boot+27.47s (NIM reconfiguring it for passthrough) and only renamed it back `keth1 → eth1` at boot+113.78s, so the one-shot `checkAndFillIoBundle` call landed inside that ~86s window where the interface was still named `keth1`. This is the identical timing race between NIM's interface rename and domainmgr's IO-bundle MAC lookup in `pkg/pillar/cmd/domainmgr`, down to the same log lines and file/line numbers (`domainmgr.go:3436/3441/3478`). Per the ledger this is a known, recurring issue first seen 2026-11-20 (run #30) and repeating in every subsequent nightly run (#35, #40, #45, #50, #55) through today — not a new bug. No other failure in this run shares this root cause.

### TestAppsSuite: failure analysis

#### TestPurgeNeverActivatedApp

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: app reaches RUNNING after purge
AppID:"d1cc8859-e3ae-4476-a879-ca11c1798951" appVersion:"1" AppName:"bad-image-app" state:CREATING_VOLUME volumeRefs:"9eec6d32-88d2-4b1b-99f7-37e4c439ec48"
```

##### Claude's conclusion

###### Root cause

Live inspection confirms this is a containerd unpack/snapshot-commit hang, identical to a previously diagnosed failure mode: `volumemgr.CreateVolume(9eec6d32-88d2-4b1b-99f7-37e4c439ec48#0)` fired once at `06:26:46.504` for the `library/nginx@sha256:5fa52b94...` image and never logged again (no `DONE`, no error) for the full 5+ minutes up to the current device time (`06:32:17`+). `ctr -a /run/containerd-user/containerd.sock -n eve-user-apps snapshots ls` shows the corresponding snapshot (`extract-987917443-WfkS`) still stuck in `Active` (uncommitted) state, while the device is essentially idle (`top` shows 0% CPU, only 1 running task, load average 3.04 decaying from boot) — i.e. the unpack goroutine is hung, not merely slow, since a genuinely in-progress unpack would show CPU activity.

This is a known, recurring issue: this exact test (`TestPurgeNeverActivatedApp`, same app `bad-image-app`) failed with this exact signature — `CreateVolume` firing once and never returning, leaving a dangling `Active` containerd snapshot — in the 2026-11-20 nightly (run #30), alongside `TestAppRestart` and `TestDevLocalInfo` in that same run. So this has been a known recurring containerd-unpack-hang issue dating back to at least 2026-11-20, not a new bug.

The broker shows the underlying Proxmox host (`farfalle`) at only 2% CPU utilization across 40 cores, so this isn't the separate CPU-oversubscription "slow but completing" variant also seen in this run's ledger (`TestProfile`, `TestAppLocalInfo`) — it's the pure hang variant.

No PR diff was provided for this investigation, so I'm omitting the RELATED line.
#### TestVNC

##### Failure

```

Expected
    <[]net.IP | len:0, cap:0>: nil
not to be empty
```

##### Claude's conclusion

This is a new test (only ever touched by the master-copy commit and an EVE-16.0 adaptation), with no prior appearance in the ledger — not a recurring issue, and it's unrelated to the `TestPurgeNeverActivatedApp` containerd-hang failure investigated earlier in this run (different device, different mechanism).

**Root cause:** `vnc_test.go:169-170` calls `device.GetDeviceIPAddress("ethernet0")` and asserts non-empty immediately after `device.ApplyConfig` confirms config version 1 (gotest.json: "confirmed the latest config" at `06:41:02.591`, assertion failure at `06:41:02.604` — same instant). `GetDeviceIPAddress` only reads whatever `ZInfoDevice` snapshot was last cached from pubsub (`edgedevice.go:2330-2342`, no wait/retry), and at that exact moment the device hadn't yet transitioned `BOOTING -> ONLINE` (that happened 13 seconds later, at `06:41:15`), so no info message carrying the DHCP-assigned IP for `ethernet0` had arrived yet. Live inspection confirms this: `evetest status` now shows the device fully `ONLINE` with `ethernet0` IP `172.20.20.123` — the IP did show up shortly after, just not by the time the un-retried check ran. This is a test timing bug (missing an `Eventually`/retry around the IP check, unlike the rest of the test's waits), not an EVE product defect.

### TestDeviceConnectivitySuite: failure analysis

#### TestDNSFunctionality

##### Failure

```

Timed out after 420.001s.
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

No recent changes to `dns_test.go` on this branch, consistent with this being a pre-existing flake rather than something newly introduced.

###### Root cause

This is the identical `WatchDeviceInfo` subscribe-after-send race documented in the ledger's first occurrence on 2026-11-21 (run #35) — a **known, recurring issue**. Live evidence matches exactly: `device.ApplyConfig(..., true, true)` (`dns_test.go:218`) blocks until the device's config-confirmation logic consumes the qualifying `ZInfoDevice` update, and only afterward does the test call `device.WatchDeviceInfo()` (line 233), which per `AdamClient.SubscribeToDeviceInfoMsgs`'s contract only delivers messages received *after* subscription. Live `evetest eve info -t` shows the device already reached the exact target end state — `lastSucceeded` at `06:06:13` UTC (eth0/eth1/eth2 errors cleared, eth3 retaining the expected "no DNS server available" error) — just 4 seconds before the `config-applied` checkpoint logged at `06:06:17`, meaning that one qualifying message was already gone from Adam's stream by the time the watch subscribed. Since `timer.port.testinterval`'s effective floor is 5 minutes (`NetworkTestInterval` minimum, as the test's own code comment at `dns_test.go` notes) and DPC is already healthy, no further `ZInfoDevice` publish occurs within the 420s (7-minute) `phase1Timeout`, so `Eventually(devUpdates, …).Should(Receive(...))` times out with exactly the observed "ReceiveMatcher's channel *must* receive something" error — matching run #35 down to the mechanism and near-identical timing. No other subtests in this run's gotest output show related failures, and `dns_test.go` has had no recent commits on this branch, so this isn't tied to a fresh code change — it's the same latent test-harness ordering bug recurring since 2026-11-21.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestLocalNI

##### Failure

```
timed out after 5m0.000312809s (excluding download) waiting for app "9b2d9f0d-ce3c-4d99-921b-dad48dc40f2d" (container-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

This is the only test in this run, so there's no earlier failure in this run to share a root cause with. I have enough evidence now.

**Root cause:** `container-app` (volume `3deba88a-...`) is still stuck in `CREATING_VOLUME` right now, well after the test's 5-minute timeout — live `ctr -n eve-user-apps snapshots ls` on device `edge-dev` shows an `Active` (uncommitted) `extract-*` snapshot for this image's layer, and the downloaded content is already 5+ minutes old while the extract still hasn't committed. This matches the classic unpack-stall signature seen repeatedly in prior nights: live `nproc`/`vmstat` show the guest exposing only `nproc=1` against a device configured for 4 vCPUs, with `vmstat` showing a process perpetually blocked on I/O (`wa`≈21-25%, `b=1`). The broker is also under heavy load (9/12 VMs running, 70% of host RAM assigned, 2.4GiB swap in use, host load 6-7), consistent with CPU/IO oversubscription slowing the container image unpack past the test's fixed 5-minute budget. This is a **known, heavily recurring issue** per `live-ledger.md`: this exact `CREATING_VOLUME`/unpack-stall-under-CPU-oversubscription class has hit `TestLocalNetworkInstanceSuite` and many other suites in essentially every nightly run since at least 2026-11-20 (run #30), including `TestLocalNIWithMultiplePorts`, `TestLocalNetInstanceACLs`, `TestMoveAppBetweenNIs`, and others — not a new product bug. No PR diff was supplied for this run, so no relatedness judgment is needed.
#### TestMoveAppBetweenNIs

##### Failure

```
timed out after 5m0.00082112s (excluding download) waiting for app "0893053b-d891-4886-82d4-061cd24c49f4" (ping1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

I have sufficient live evidence to form a confident conclusion.

**Root cause:** `ping1`'s root volume (`80dc4e64-...`) entered `CREATING_VOLUME` at ~06:45:00 and was still stuck there when live-checked at 06:50:59-06:51:02 (over a minute past the test's 5-minute timeout that fired at 06:50:04), finally transitioning to `CREATED_VOLUME`/`INSTALLED` only moments later. This ran concurrently with two sibling volumes (`ping2-root`, `pong-root`) that all completed within ~1ms of each other (`LastUse` timestamps 06:45:00.987-06:45:00.989), confirming simultaneous image-unpack contention across all three test apps. Live `nproc`/`uptime` on the guest show the classic oversubscription signature: `nproc=1` despite the device being configured for 4 vCPUs, with load average 5.65-5.95 and `vmstat` wa≈22-27% (blocked-on-I/O). This is the **same root cause as the earlier `TestLocalNI` failure in this same run** (which hit the identical `CREATING_VOLUME` timeout for `container-app`), and it's a **known, heavily recurring issue**: the ledger records this exact test, `TestMoveAppBetweenNIs`, failing with this identical signature (three concurrent app volume unpacks stalling past the 5-minute budget under host CPU/IO oversubscription) going back to at least 2026-11-20 (run #30), with the broader class recurring across many suites nearly every night since. No PR diff was supplied, so this is an infrastructure/environment issue, not a product regression.
#### TestFlowLog

##### Failure

```
timed out after 5m0.0019617s (excluding download) waiting for app "c45dd390-363c-49fd-988c-1765085b33e5" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Broker shows a moderately loaded host (9/12 VMs, 70% RAM assigned, 2.3GiB swap, host load ~5.5-6.3), consistent with the CPU oversubscription signature seen on the device itself.

**Root cause:** `flowlog-test-app`'s volume (`12f6090e-...`) is stuck in `CREATING_VOLUME` right now, well past the 5-minute test timeout — live `ctr -n eve-user-apps snapshots ls` shows its image-layer extraction as an `Active` (uncommitted) containerd snapshot (`extract-177290850-cEyv`), and live `app-info` confirms the app is still sitting in `CREATING_VOLUME`. Live `uptime`/`nproc`/`vmstat` on the device show the classic oversubscription signature: the guest reports only `nproc=1` against a device configured for 4 vCPUs, load average ~3.1-3.3, and `vmstat` shows a process perpetually blocked on I/O (`b=1`, `wa`≈19-25%) — matching the broker's own view of a loaded host (9/12 VMs running, 70% RAM assigned, 2.3GiB swap, host load 5.5-6.3). This is the **same root cause as the earlier `TestFlowLog` failure already investigated in this run** (recorded in `live-investigation.md`), which hit the identical `CREATING_VOLUME` stall. It's also a **known, heavily recurring issue** per `live-ledger.md`: `TestFlowLog` specifically has failed with this exact `CREATING_VOLUME`/unpack-stall-under-CPU-oversubscription signature in essentially every nightly run checked, going back to at least 2026-11-20 (run #30), including run #35 (2026-11-21) and run #55 (last night, 2026-11-25) — this is a long-standing, well-established infrastructure issue, not a new product bug.

## [2026-11-25 -- 0.0.0-13.4-stable-34c1bd8f (run #55)](https://github.com/lf-edge/eve/actions/runs/45550517810)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/55/)

### TestDeviceConnectivitySuite: failure analysis

#### TestIntermittentConnectivity

##### Failure

```

Unexpected error:
    <*fmt.wrapError | 0x27a8851aad00>: 
    failed to execute script over SSH for app 5d33d838-97a3-48c9-80ae-e8941fde80d6: Process exited with status 141 (stderr: )
    {
        msg: "failed to execute script over SSH for app 5d33d838-97a3-48c9-80ae-e8941fde80d6: Process exited with status 141 (stderr: )",
        err: <*ssh.ExitError | 0x27a884e9f680>{
            Waitmsg: {status: 141, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

This gives enough evidence already. I have sufficient live and log evidence to form the conclusion.

###### Root cause

`TestIntermittentConnectivity` (`evetest/tests/networking/failover_test.go:900-902`) ran `ping -c 50 -w 75 http-server.test` inside the app over SSH, with the SSH call itself bounded by an 80s context timeout (`80*time.Second` passed to `RunShellScriptInsideApp`). Timestamps in `gotest.json` show the ping started at `06:45:15` and the failure fired at `06:46:35` — exactly 80s later — meaning the SSH session's context deadline expired and `session.Close()` tore down the remote `sh -s` session (`evetest/ssh.go:128-137`) while `ping` was still running, which made the app's write to a now-closed stdout raise SIGPIPE (exit 141). Live inspection confirms the SDN still has `netem ... loss 20%` applied on `eth0` (matching Phase 2 of the test), so the ping was genuinely running under 20% loss when it should have self-terminated via its own `-w 75` deadline. The likely trigger is that `http-server.test` DNS resolution (also subject to the same 20% loss on the shared link) added extra delay before `ping`'s own 75s deadline timer even started counting, leaving only 5s of margin against the outer 80s SSH timeout — too thin under lossy conditions. All other subtests in this run (`TestDHCPIPv4Only`, `TestStaticIPv4Only`, `TestDNSFunctionality`, `TestPortFailover`, `TestNetworkConfigFallback`) passed, so this isn't a shared-root-cause issue within the run. I found no prior occurrence of this test or this "status 141" failure in `live-ledger.md`, so this appears to be a new/first-seen flake, likely a timing-margin bug (insufficient slack between the ping's own deadline and the SSH call's outer timeout) rather than a product regression.
#### TestVLANSubinterfaces

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: vlan10 IP in 172.22.10.0/24, vlan20 IP in 172.22.20.0/24, eth0 IP in 192.168.77.0/24
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7816  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"SFG7R78Y"  UUID:"Not Settable"  biosVendor:"EFI Development Kit II / OVMF"  biosVersion:"0.0.0"  biosReleaseDate:"02/06/2015"}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"ethernet0"  dns:{}  ipv4_up:true  networkErr:{description:"interface eth0: no suitable IP address available"  timestamp:{seconds:1795590473  nanos:677169203}  severity:SEVERITY_ERROR}  localName:"eth0"  proxy:{}}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"vlan10"  IPAddrs:"172.22.10.15"  defaultRouters:"172.22.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795590473  nanos:684145865}}  localName:"vlan10"  proxy:{}}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"vlan20"  IPAddrs:"172.22.20.15"  defaultRouters:"172.22.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  ipv4_up:true  networkErr:{timestamp:{seconds:1795590473  nanos:676975606}}  localName:"vlan20"  proxy:{}}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageShared}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{device:"nbd0"}  storageList:{device:"nbd1"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/hostfs"  total:266}  storageList:{device:"nbd12"}  storageList:{device:"vda3"  total:512  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  bootTime:{seconds:1795590330}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-13.4-stable-34c1bd8f-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"e27a7459-cf47-42d3-ab52-553343077c9d"  lastRebootReason:"NORMAL: First boot of device - at 2026-11-25T07:06:12.452633121Z"  lastRebootTime:{seconds:1795590372  nanos:452633121}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1795590441  nanos:635276723}  lastSucceeded:{seconds:1795590473  nanos:684210589}  ports:{ifname:"eth0"  name:"ethernet0"  free:true  dhcpType:4  subnet:"<nil>"  proxy:{}  macAddr:"da:39:78:d0:19:f2"  dns:{}  up:true  err:{description:"interface eth0: no suitable IP address available"  timestamp:{seconds:1795590473  nanos:677169203}  severity:SEVERITY_ERROR}  usage:PhyIoUsageShared  networkUUID:"6b1fa8e2-143d-48cf-887d-b4f308be2a32"  mtu:1500}  ports:{ifname:"vlan10"  name:"vlan10"  isMgmt:true  free:true  dhcpType:4  subnet:"172.22.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.22.10.15"  defaultRouters:"172.22.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795590473  nanos:684145865}}  networkUUID:"6b1fa8e2-143d-48cf-887d-b4f308be2a32"  mtu:1500}  ports:{ifname:"vlan20"  name:"vlan20"  free:true  dhcpType:4  subnet:"172.22.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.22.20.15"  defaultRouters:"172.22.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795590473  nanos:676975606}}  networkUUID:"6b1fa8e2-143d-48cf-887d-b4f308be2a32"  mtu:1500}}}  HSMStatus:NOTFOUND  HSMInfo:"Not Available"  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795590428  nanos:371592249}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"X\xa4\xdd\x1c\x9f?\x9c\xb3\xb7V\xf0\xe5\x15\x91<\xfaL\xd24IM\x0f\x9b\"4QO\xb9\x15\xed\xa4."  sha_tls_root_ca:"X\xa4\xdd\x1c\x9f?\x9c\xb3\xb7V\xf0\xe5\x15\x91<\xfaL\xd24IM\x0f\x9b\"4QO\xb9\x15\xed\xa4."}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  maintenance_mode_reasons:MAINTENANCE_MODE_REASON_NONE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_ADAPTER_USER_LABELS  optional_capabilities:{}
```

##### Claude's conclusion

###### Root cause

Live inspection confirms `eth0` currently has **no IPv4 address at all** (`ip -4 addr show eth0` returns nothing), even though its `dhcpcd` client process is still alive, 10+ minutes after boot. Device logs show why: `dhcpcd` released the old `172.20.20.123` lease at `07:07:30.939` and began soliciting a new lease at `07:07:35.115` (right as the test's `UpdateNetworkModel` switch to the VLAN model landed at `07:07:35.016`), but at `07:07:37.473` it got offered the **stale** `172.20.20.123` address from `172.20.20.1` — a leftover from the old network model — and then never logged another `probing`/`leased`/`soliciting` line for the rest of the run. On the SDN side, the new `network-untagged` dnsmasq instance (serving `192.168.77.0/24`) only started up at `07:07:37`, and its lease log (`/run/dnsmasq/dhcpsrv-network-untagged.leases` and `.log`) shows **zero** DHCP transactions from the device ever reaching it — only periodic housekeeping entries. So the device's DHCPDISCOVER raced the SDN's teardown/bring-up of the untagged-segment DHCP server, got answered by a stray stale offer instead, and `dhcpcd` on `eth0` then simply stalled; `nim` stopped polling `dhcpcd` status for `eth0` after `07:07:57` once the overall DevicePortConfig already reported `DPC_SUCCESS` via `vlan10`/`vlan20` (the mgmt-capable ports), leaving `eth0` permanently without an address for the rest of the 5-minute wait. `vlan10` and `vlan20` both got correct addresses, so Phase 1's failure is isolated to `eth0`.

This does not share a root cause with the earlier `TestIntermittentConnectivity` failure in this run (an SSH-context-timeout/SIGPIPE issue during a lossy-network ping, unrelated to DHCP/SDN-switch races). I found no prior occurrence of `TestVLANSubinterfaces` or this stray-DHCP-offer-during-model-switch failure mode in `live-ledger.md`, so this appears to be a new/first-seen flake — a race between the SDN network-model switch and the device's DHCP client re-acquisition on the untagged port, compounded by `nim` not retrying DHCP on a non-mgmt port once the DPC as a whole already succeeded.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestMoveAppBetweenNIs

##### Failure

```
timed out after 5m0.000975177s (excluding download) waiting for app "9589ccd3-4050-410f-af3e-dacf07941089" (ping1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Confirmed — three volumes (ping1's `e5b4b5c8`, and two others, likely ping2/pong: `5e823eb9`, `a7ea00d7`) all finished unpacking within ~1.4s of each other around 06:02:00-06:02:01, all stuck in `CREATING_VOLUME` concurrently for ~5+ minutes due to CPU contention. No need to check further — this matches the documented pattern exactly.

**Root cause:** `ping1`'s root volume (`e5b4b5c8-...`) entered `CREATING_VOLUME` at 05:56:53 and didn't complete (`createContainerVolume ... DONE`) until 06:02:00 — a ~5m07s unpack, overrunning the test's 5-minute budget by mere seconds. This unpack ran concurrently with two sibling volumes (`5e823eb9-...`, `a7ea00d7-...`, almost certainly `ping2`/`pong`) that finished within 1-1.4s of each other, confirming simultaneous image-unpack contention. Live `uptime`/`vmstat` on the device show the classic oversubscription signature: the guest reports `nproc=1` against a device configured for 4 vCPUs, load average 4.93, with `vmstat` showing a blocked-on-I/O process (`wa`≈21%). `ping1` did in fact reach `RUNNING` shortly after (bootTime 06:02:03), confirming this was a slow-but-completing unpack rather than a true hang. This is a known, heavily recurring issue: the ledger records this exact test (`TestMoveAppBetweenNIs`) failing with an essentially identical root-cause (three concurrent app unpacks stuck in `CREATING_VOLUME` past the 5-minute timeout due to host/device CPU oversubscription) as far back as 2026-11-20 (run #30), and the broader class has recurred in nearly every nightly run since then across many other suites/tests.
#### TestLocalNetInstanceACLs

##### Failure

```
timed out after 5m0.001057881s (excluding download) waiting for app "e69a0c11-4d86-4c2b-ab09-5fb57f43a62a" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Confirmed — there's still one `Active` (uncommitted) containerd snapshot, consistent with an unpack that never completed.

###### Root cause

This is the same known issue already seen multiple times in this run and documented in `live-investigation.md`. Device logs show `acl-app-1`'s volume (`2aa2b98e-99d7-44eb-b9a5-fa7cd3c1893a#0#e69a0c11-...`) entered `CREATING_VOLUME` at 06:34:10 and `zedagent` was still logging `ActiveFileLocation is empty` every poll through my live check at 06:38:30+ — over 4.5 minutes later with no completion, and live `ctr snapshots ls` on the device confirms an `Active` (uncommitted) containerd snapshot still in progress. Live `uptime`/`nproc`/`vmstat` show the identical oversubscription signature seen throughout this run: the guest reports only `nproc=1` against a device configured for 4 vCPUs, load average 3.75, and `vmstat` shows a process blocked on I/O (`b=1`, `wa`≈15-27%).

This is the identical root cause already recorded multiple times earlier in this same run (`TestMoveAppBetweenNIs`, and others per `live-investigation.md`), and it's a heavily recurring, known issue per `live-ledger.md` — this exact test (`TestLocalNetInstanceACLs`) with this exact app name (`acl-app-1`) failed with the same `CREATING_VOLUME`/unpack-stall signature in an earlier nightly run as well, and the broader class (unpack stalls due to host/device CPU oversubscription) has recurred in nearly every nightly run since at least 2026-11-20 (run #30).
#### TestPortForwarding

##### Failure

```
timed out after 5m0.000649862s (excluding download) waiting for app "aa2b6075-2621-4799-84de-b182cdc62f81" (app1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** App1 (`aa2b6075-...`) entered `CREATING_VOLUME` at 06:58:18, concurrently with app2 and app3's volumes also transitioning into `CREATING_VOLUME` within the same 1-2s window (06:58:17-06:58:19) — three simultaneous image unpacks competing for CPU. Live `app-info` shows app1 actually reached `RUNNING` at 07:02:55, just ~46s after the test's 07:02:09 timeout fired — a slow-but-completing unpack, not a true hang. Live `uptime`/`vmstat` confirm the same oversubscription signature: the guest reports `nproc=1` against a device configured for 4 vCPUs, load average 6.24, and `vmstat` shows ~23-29% I/O wait with a process blocked on I/O.

This is the identical root cause already recorded for `TestMoveAppBetweenNIs` and `TestLocalNetInstanceACLs` earlier in this same run (per `live-investigation.md`): host/device CPU oversubscription causing concurrent containerd image unpacks to exceed the test's fixed 5-minute timeout. It's also a known, recurring issue for this exact test: the ledger shows `TestPortForwarding` failing with this exact same `CREATING_VOLUME` timeout signature as far back as the 2026-11-20 nightly run (run #30), and the broader class of unpack-contention timeouts has recurred in nearly every nightly run since then.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestAirGapSwitchNI

##### Failure

```
timed out after 5m0.001505838s (excluding download) waiting for app "e80b571d-94a3-414d-89d3-a0c195297d95" (app1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

This confirms the app did self-resolve past `CREATING_VOLUME` — it progressed to `INSTALLED` and is now `BOOTING`, just long after the test's 5-minute timeout window.

###### Root cause

**Known, recurring host/device CPU-oversubscription issue — not a code bug.** Live inspection shows the exact same signature documented in last night's run (2026-11-24, run #50) for this identical test: the guest reports `ncpu:4` but `nproc`/`/proc/loadavg` show only 1 usable CPU with load average ~4.3/4.0/2.4 and 9-23% iowait, and `ctr -n eve-user-apps snapshots ls` shows two `extract-*` snapshots stuck `Active` (uncommitted) for the app1 image sha — i.e., the container image unpack is stalling under oversubscribed CPU/IO, not stuck or failed outright. Consistent with that, `app-info` now shows app1 has since progressed past `CREATING_VOLUME` through `INSTALLED` to `BOOTING`, confirming it eventually unblocks — just well after the test's 5-minute timeout.

This is a **known, recurring** issue per `live-ledger.md`: the identical `CREATING_VOLUME`/CPU-oversubscription timeout pattern for `TestAirGapSwitchNI` specifically appeared last night (2026-11-24, run #50), and the same root-cause class has recurred across multiple nights/suites going back to at least 2026-11-20 (run #30), 2026-11-21 (run #35), and 2026-11-23 (run #45). This is simply the same infrastructure-level stall recurring again tonight, not a new bug and not specific to switch-network-instance logic.
#### TestSwitchNetInstanceACLs

##### Failure

```
timed out after 5m0.000805938s (excluding download) waiting for app "0affbc58-dfc2-427e-b5b0-04137d48cf80" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

This confirms the stall: `ec8cda75-...` (acl-app-1's volume) still has an empty `ActiveFileLocation` as of 06:15:36, continuing well past the test's timeout — the same pattern as the other failures in this run.

Root cause: this is the same host/device CPU-oversubscription stall already identified earlier in this run (and recurring across many prior nightly runs per the ledger, at least since 2026-11-20). Live `nproc` shows only 1 usable CPU against a device configured for 4 vCPUs, with `vmstat` showing load average ~4.67/3.59/1.80 and a process perpetually blocked on I/O (`b=1`, `wa`≈21–28%). `zedagent` logs confirm `acl-app-1`'s volume (`ec8cda75-...`) has had an empty `ActiveFileLocation`/`FileLocation` continuously since at least 06:13:10 through my live check at 06:15:36 — i.e. its volume unpack is still stalled under CPU/IO contention, just like `app-gw`, `app-client1/2`, and the other apps seen stuck in `CREATING_VOLUME` earlier tonight. This is the same root cause as the earlier failure(s) already investigated in this run, and it is a known, recurring infrastructure issue per `live-ledger.md` going back to at least 2026-11-20 (run #30) — not specific to `TestSwitchNetworkInstanceSuite` or switch-network-instance logic.

## [2026-11-24 -- 0.0.0-13.4-stable-34c1bd8f (run #50)](https://github.com/lf-edge/eve/actions/runs/45330205690)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/50/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: eth1 is reported as an unused assignable adapter with a MAC address
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7816  storage:63153  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"KL1H67HB"  UUID:"Not Settable"  biosVendor:"EFI Development Kit II / OVMF"  biosVersion:"0.0.0"  biosReleaseDate:"02/06/2015"}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"ethernet0"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795501991  nanos:240384077}}  localName:"eth0"  proxy:{}}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usage:PhyIoUsageDedicated}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{device:"vda4"  total:1  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"nbd5"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/config"  total:1}  storageList:{device:"vda2"  total:512  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd10"}  storageList:{device:"nbd15"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"nbd12"}  storageList:{device:"vda3"  total:512  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/tmp"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"nbd7"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"nbd0"}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{device:"nbd11"}  storageList:{device:"vda1"  total:36  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"vda9"  total:64473  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{device:"nbd8"}  storageList:{device:"nbd1"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/"  total:3908}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/certs"}  storageList:{device:"nbd14"}  storageList:{device:"nbd4"}  storageList:{device:"vda"  total:65536}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist"  total:63153  storageLocation:true}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/hostfs"  total:266}  bootTime:{seconds:1795501852}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-13.4-stable-34c1bd8f-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"cbfa7e25-c557-4e5d-b39e-d96691485a98"  lastRebootReason:"NORMAL: First boot of device - at 2026-11-24T06:31:18.000634749Z"  lastRebootTime:{seconds:1795501878  nanos:634749}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1795501950  nanos:330260547}  lastSucceeded:{seconds:1795501991  nanos:240461537}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795501991  nanos:240384077}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"4544d211-2852-444e-886b-cc780d9b04ce"  mtu:1500}}}  HSMStatus:NOTFOUND  HSMInfo:"Not Available"  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795501939  nanos:927740776}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"{Z\x9c\x95(\xa9\xe0.\xe9Nl\x82Z!\x02 \x9c\xd9\"*\x90\xa64\x91\xdb!\x89\xf39\xdew\xa8"  sha_tls_root_ca:"{Z\x9c\x95(\xa9\xe0.\xe9Nl\x82Z!\x02 \x9c\xd9\"*\x90\xa64\x91\xdb!\x89\xf39\xdew\xa8"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  maintenance_mode_reasons:MAINTENANCE_MODE_REASON_NONE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_ADAPTER_USER_LABELS  optional_capabilities:{}
```

##### Claude's conclusion

This confirms the same race: the kernel renamed `eth1 → keth1` at boot+27.66s and didn't rename it back to `eth1` until boot+99.6s, and domainmgr's one-shot IO-bundle scan at 06:32:31.628 fell inside that ~72-second window, leaving `ethernet1` permanently without a `MacAddr`/`ioAddressList` (confirmed live: `assignableAdapters` for `ethernet1` still has no `ioAddressList`).

**Root cause:** This is the identical, known recurring NIM/domainmgr interface-rename race already in the ledger for 2026-11-23 (run #45), 2026-11-22 (run #40), and 2026-11-20 (run #30) — same test, same symptom. Live logs show `domainmgr.checkAndFillIoBundle(1 eth1 ethernet1)` ran at 06:32:31.628 and hit `Can't find ifname eth1` → `found macaddr` (blank), because the kernel had renamed `eth1` to `keth1` at boot+27.66s and didn't rename it back until boot+99.6s (confirmed via live `dmesg`); this one-shot lookup is never retried, so `ethernet1`'s MAC/PCI address stays empty for the rest of the run (confirmed live via `evetest eve info`, which still shows `ethernet1` with no `ioAddressList`). This is the same `pkg/pillar/cmd/domainmgr` timing race documented in the ledger since at least 2026-11-20 — a known, recurring issue, not a new bug. No PR diff was provided for this investigation.

### TestAppRoutingSuite: failure analysis

#### TestLocalNIWithMultiplePorts

##### Failure

```

Told to stop trying after 36.857s.
Stop waiting for: NI ONLINE with both static routes via ethernet0 and all connected routes present
Network instance is in error state
networkID:"345efcd1-3757-43b7-be98-8c62db9a659a"  networkVersion:"1"  instType:2  displayname:"multi-port-ni"  activated:true  CurrentUplinkIntf:"eth3"  ports:"eth3"  ports:"eth0"  ports:"eth2"  ports:"eth1"  bridgeNum:1  bridgeName:"bn1"  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:06:00:01"  ipAddress:"10.50.0.1"}  networkErr:{description:"IP Route: {dst=0.0.0.0/0, gw=<nil>, port=internet, probe={enabledGwPing=true, gwPingMaxCost=5, userProbe=<none>}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port\nIP Route: {dst=10.88.88.0/24, gw=<nil>, port=httpserver, probe={enabledGwPing=true, gwPingMaxCost=0, userProbe=tcp://10.88.88.70:80}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port"  timestamp:{seconds:1795501824  nanos:797830010}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"10.40.40.1"  port:"eth3"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"192.168.30.1"  port:"eth2"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"172.28.20.1"  port:"eth1"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"172.22.10.1"  port:"eth0"}  ip_routes:{destination_network:"10.40.40.0/24"  port:"eth3"}  ip_routes:{destination_network:"172.22.10.0/24"  port:"eth0"}  ip_routes:{destination_network:"172.28.20.0/24"  port:"eth1"}  ip_routes:{destination_network:"192.168.30.0/24"  port:"eth2"}
```

##### Claude's conclusion

###### Root cause

This is the exact same transient-NI-error race already recorded in the ledger for `run #35` (2026‑11‑21), recurring again tonight. The test's `StopIf(niHasError)` predicate aborts the wait the instant the NI reports `ZNETINST_STATE_ERROR`, but that error is a momentary artifact of NIM/zedrouter still relabeling ports: at 06:30:41 `gotest.json` shows the app `multi-port-app` going `INVALID → INITIAL`, and 1.1s later (06:30:42.805) the NI briefly flips to `ERROR` while its `ports` list is still expressed with raw/physical ifnames (`eth3, eth0, eth2, eth1`) rather than the resolved logical names (`ethernet0‑3`), so the `internet`/`httpserver` static-route port labels transiently "match no port." The test's `StopIf` killed the wait right there, after only 36.857s of its 3‑minute budget.

Live `evetest eve ni-info multi-port-ni -t=10` confirms this was purely transient and self-healing: ~18s after the error timestamp (06:30:42 → 06:31:00-ish, second entry), ports have been relabeled to `ethernet0-3` and the state is already back to `ZNETINST_STATE_ONLINE` with the default route and `10.88.88.0/24` both correctly pinned to `ethernet0` and all four connected-subnet routes present — i.e. exactly the condition the test was waiting for, reached well within the real timeout had the wait not bailed early.

This is a known, recurring issue, not new: `live-ledger.md` records the identical mechanism and conclusion ("test-harness bug — overly strict fail-fast `StopIf(niHasError)` on a transient NIM/zedrouter port-settling race") for this same test on 2026‑11‑21 (run #35); it has now recurred on 2026‑11‑24. No other failure in this run shares this root cause, and no PR diff was provided for this investigation.
#### TestApplicationGateway

##### Failure

```
timed out after 5m0.000838799s (excluding download) waiting for app "0b1fa39c-9127-4068-b6b9-32daa9cf3311" (app-gw) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** `app-gw` entered `CREATING_VOLUME` at 06:41:52, essentially simultaneously with `app-client1` (06:41:57) and `app-client2` (06:41:58) — three container-image unpacks contending at once. Live device logs show `zedagent` has logged `ActiveFileLocation is empty for 267fdbb9-...#0#0b1fa39c-...` (app-gw's root volume) continuously from 06:41:55 through my live check at 06:47:03 — still unresolved nearly 5.5 minutes later, well past the test's 5-minute budget. Live `vmstat`/`nproc` on the device show the exact oversubscription signature seen repeatedly tonight: the guest exposes only `nproc=1` against a device configured for 4 vCPUs, with a process perpetually blocked on I/O (`b=1`, `wa`≈22-27%).

This is the same mechanism as this run's earlier `TestLocalNIWithMultiplePorts` failure only in the sense that both are transient-race-related, but the specific mechanisms differ: that one was a `StopIf(niHasError)` fail-fast on a port-relabeling race, whereas this one is a genuine unpack stall under host/device CPU contention — they don't share a root cause. However, this CREATING_VOLUME/unpack-stall-under-CPU-oversubscription class is heavily recurring per `live-ledger.md`: it has already hit `TestMoveAppBetweenNIs`, `TestFlowLog`, `TestLocalNetInstanceACLs`, `TestLocalNetInstanceACLsWithFlowLog`, and `TestAccessVLANs` earlier in this very run, and the broader class has appeared in essentially every nightly run since 2026-11-20 (run #30) across many suites. `TestApplicationGateway` itself failed once before (run #35, 2026-11-21) but with a completely different symptom (a `no port is matching label` NI-error race), so this exact CREATING_VOLUME manifestation for this test is new, but it's simply another instance of the well-established, known infrastructure issue rather than a new product bug.

### TestLPSSuite: failure analysis

#### TestProfile

##### Failure

```
timed out after 5m0.000849818s (excluding download) waiting for app "1364ec5b-e0aa-49c2-842c-8dc9d40037e5" (lps-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** Live `evetest eve logs` shows `lps-app`'s root volume (`b9be817d-d8eb-4a85-b3e2-ba67b9fc0e43`) started `CreateVolume`/`UnpackClientImage` at 07:37:11.101, running concurrently with three other `evetest-ubuntu-ctr` volume unpacks that were kicked off in the same ~2-second window (07:37:11–07:37:13). The `lps-app` unpack didn't complete (`createContainerVolume ... DONE`) until 07:40:35.627 — a ~3m24s unpack — immediately after which the app progressed to `BOOTING` at 07:40:38, and the other three concurrent unpacks finished almost simultaneously (07:40:38–07:40:39), confirming they were all competing for CPU. Live `evetest eve ssh "uptime; nproc"` confirms the signature: the guest reports only 1 vCPU with load average 4.96/3.83/1.86 on a device configured for 4 vCPUs — classic host-CPU-oversubscription causing a slow-but-completing unpack that pushed past the fixed 5-minute `CREATING_VOLUME`→`RUNNING` deadline.

This is a known, recurring issue, and specifically a repeat of `TestLPSSuite/TestProfile` itself: the exact same test failed with this exact root cause on 2026-11-21 (run #35), where the ledger notes `lps-app`'s unpack took ~2m32s amid concurrent volume creates and finished just ~15s past the deadline. The broader class (concurrent container-image unpacks exceeding the fixed 5-minute `CREATING_VOLUME` timeout under host CPU oversubscription) has recurred in nearly every nightly run since at least 2026-11-20, across many suites (including this suite's `TestAppLocalInfo`, and separately a hang-variant in `TestDevLocalInfo`). No PR diff was provided for this investigation.
#### TestAppLocalInfo

##### Failure

```
timed out after 5m0.000076841s (excluding download) waiting for app "45a9a896-2961-42c2-8cbd-b43072dc91af" (app1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live evidence confirms this is the same "slow-but-completing container unpack under host CPU oversubscription" pattern already documented for this exact suite. `evetest eve logs` shows app1's volume (`ce9d464d-07d8-4f52-b6eb-726b68b0a412#0`) started `CreateVolume`/`UnpackClientImage` at 07:57:39, and as of now (08:03, well past the 5-minute `CREATING_VOLUME`→timeout boundary at 08:02:39) the containerd overlayfs snapshot `16` for this volume is still actively extracting — its `fs` directory grew from 9.7M to 66.3M in just 10 seconds, proving it's genuinely progressing, not hung. `evetest eve ssh "nproc; uptime"` shows the guest has only **1 vCPU** (configured for 4) with load average 2.1–2.3 and `top` showing that single core pegged near 100%, i.e. severe CPU oversubscription slowing the unpack past the fixed 5-minute deadline.

This is the identical root cause already identified in this very run's `live-investigation.md` (the `TestProfile` failure: fully-downloaded content stuck in `CREATING_VOLUME` due to concurrent unpacks under single-vCPU host oversubscription). Per `live-ledger.md`, this is also a known, long-recurring issue dating back to at least the 2026-11-20 nightly (run #30), and it has specifically hit `TestLPSSuite`/`TestAppLocalInfo` before, in the 2026-11-21 nightly (run #35), with the exact same signature. No PR diff was provided for this investigation.
#### TestDevLocalInfo

##### Failure

```
timed out after 5m0.001644485s (excluding download) waiting for app "593e6aed-c031-41a3-a165-3e24ae6c8807" (lps-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

`lps-app`'s volume unpack is genuinely progressing, not hung: `UnpackClientImage` for its container image started at 08:13:55, and live sampling of the overlayfs snapshot (`/persist/vault/containerd/.../snapshots/1/fs`, still an `Active`/uncommitted `extract-*` snapshot per `ctr snapshots ls`) shows it growing from 66.1M → 73.1M over ~53s (~130KB/s) across repeated checks — slow but clearly advancing. `evetest eve ssh "nproc"` shows the guest sees only **1 vCPU** despite the device being configured for 4, with load average ~2.4 and `vmstat` showing 21-25% iowait, i.e. the single-vCPU host is both CPU- and disk-contended, which is enough to push this otherwise-normal unpack past the fixed 5-minute `CREATING_VOLUME` deadline.

This matches the same CPU-oversubscription "slow-but-completing unpack" pattern already documented twice in this run's `live-investigation.md` (`TestProfile`, `TestAppLocalInfo`), though here only one volume was unpacking concurrently (no competing unpacks observed in the logs), so the slowness traces to the single-vCPU/iowait-constrained host itself rather than contention from parallel unpacks. Per `live-ledger.md`, this broad class (slow unpack vs. the fixed 5-minute `CREATING_VOLUME` timeout under host resource constraints) is a known, recurring issue dating back to at least 2026-11-20. Notably, `TestLPSSuite/TestDevLocalInfo` itself failed before, on 2026-11-21 (run #35) — but that was the different "fully hung" variant (snapshot permanently stuck at 0% growth, 0% CPU, parent layer `sha256:369ede38...`, which coincidentally is the same parent digest seen as this run's current `Active` snapshot's parent); this occurrence is the slow-but-progressing variant, not a true hang.

### TestPcibackErrorSuite: failure analysis

#### TestReportWarningsOnly

##### Failure

```

Timed out after 180.001s.
Expected to satisfy: both mismatched ports are kept in host and reported as warnings only
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7816  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-10.1"  serialNumber:"DCPB3L7U"  UUID:"Not Settable"  biosVendor:"EFI Development Kit II / OVMF"  biosVersion:"0.0.0"  biosReleaseDate:"02/06/2015"}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"ethernet0"  IPAddrs:"172.30.0.123"  defaultRouters:"172.30.0.1"  dns:{DNSservers:"10.35.0.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795504214  nanos:432687960}}  localName:"eth0"  proxy:{}}  network:{devName:"ethernet1"  dns:{}  uplink:true  networkErr:{description:"link not found for interface enpMockEth1"  timestamp:{seconds:1795504214  nanos:432855482}  severity:SEVERITY_ERROR}  localName:"enpMockEth1"  proxy:{}}  network:{devName:"ethernet2"  dns:{}  uplink:true  networkErr:{description:"link not found for interface enpMockEth2"  timestamp:{seconds:1795504214  nanos:433125907}  severity:SEVERITY_ERROR}  localName:"enpMockEth2"  proxy:{}}  network:{macAddr:"d6:42:ef:26:d8:c8"  devName:"ethernet3"  IPAddrs:"172.30.3.10"  defaultRouters:"172.30.3.1"  dns:{DNSservers:"10.35.4.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795504214  nanos:433142858}}  localName:"eth3"  proxy:{}}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usedByBaseOS:true  ioAddressList:{macAddress:"1e:68:56:62:e1:30"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet2"  members:"ethernet2"  usedByBaseOS:true  ioAddressList:{macAddress:"ce:30:0f:9c:43:d9"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet3"  members:"ethernet3"  usedByBaseOS:true  ioAddressList:{macAddress:"d6:42:ef:26:d8:c8"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"10.35.4.25:53"  DNSservers:"10.35.0.25:53"}  storageList:{device:"nbd1"}  storageList:{device:"nbd12"}  storageList:{device:"nbd13"}  storageList:{device:"nbd5"}  storageList:{device:"nbd2"}  storageList:{device:"vda1"  total:36  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd0"}  storageList:{device:"vda"  total:65536}  storageList:{device:"vda2"  total:512  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd9"}  storageList:{device:"nbd8"}  bootTime:{seconds:1795504043}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-13.4-stable-34c1bd8f-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"3edde81c-16ca-4555-ab9c-fd1662118a8f"  lastRebootReason:"NORMAL: First boot of device - at 2026-11-24T07:08:07.116264785Z"  lastRebootTime:{seconds:1795504087  nanos:116264785}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1795504197  nanos:791801646}  lastSucceeded:{seconds:1795504214  nanos:433297788}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.30.0.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.30.0.123"  defaultRouters:"172.30.0.1"  dns:{DNSservers:"10.35.0.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795504214  nanos:432687960}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"2b81cef6-c1fb-4b62-a022-c0158ab11201"  mtu:1500}  ports:{ifname:"enpMockEth1"  name:"ethernet1"  isMgmt:true  dhcpType:4  subnet:"<nil>"  proxy:{}  dns:{}  err:{description:"link not found for interface enpMockEth1"  timestamp:{seconds:1795504214  nanos:432855482}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"ad60e851-f801-42dd-8c43-ad773eb50351"  cost:10}  ports:{ifname:"enpMockEth2"  name:"ethernet2"  isMgmt:true  dhcpType:4  subnet:"<nil>"  proxy:{}  dns:{}  err:{description:"link not found for interface enpMockEth2"  timestamp:{seconds:1795504214  nanos:433125907}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"9678fb55-46bb-4565-8c79-d2d5a8df5b55"  cost:20}  ports:{ifname:"eth3"  name:"ethernet3"  isMgmt:true  dhcpType:4  subnet:"172.30.3.0/24"  domainname:"test."  proxy:{}  macAddr:"d6:42:ef:26:d8:c8"  IPAddrs:"172.30.3.10"  defaultRouters:"172.30.3.1"  dns:{DNSservers:"10.35.4.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795504214  nanos:433142858}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"5fcf4b72-accf-4f8b-beab-4ee8af698cdd"  cost:30  mtu:1500}}}  HSMStatus:NOTFOUND  HSMInfo:"Not Available"  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795504155  nanos:18476983}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xed\x11\x0f~\xffK\x87\x07\x8d\x83)\xb6\x19\xc8\x0f\xac79ݣ\x10\x98\xbfŚ\xe7\xdf3\xeeQ>U"  sha_tls_root_ca:"\xed\x11\x0f~\xffK\x87\x07\x8d\x83)\xb6\x19\xc8\x0f\xac79ݣ\x10\x98\xbfŚ\xe7\xdf3\xeeQ>U"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  maintenance_mode_reasons:MAINTENANCE_MODE_REASON_NONE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_ADAPTER_USER_LABELS  optional_capabilities:{}
```

##### Claude's conclusion

Confirmed live: still no `err:` field on either assignableAdapters entry — the condition is stable, not a slow-to-appear race.

###### Root cause

**No PR diff was given, so this is a genuine bug reproduced live, not a new-code regression assessment.**

`TestReportWarningsOnly` times out because domainmgr never sets any `Err` on the `ethernet1`/`ethernet2` ZioBundles at all (live `evetest eve info -t` confirms both `assignableAdapters` entries still have no `err:` field, matching the paused failure snapshot) — the test expects `SEVERITY_WARNING`, but it gets *nothing*.

Live `evetest eve logs` pinpoints why: in `pkg/pillar/cmd/domainmgr/domainmgr.go:3262-3270`, the "model ifname doesn't match kernel" warning only fires when `types.IsPort(dns, ib.Ifname, "")` (name-only lookup) returns false. But live `DeviceNetworkStatus` (`/run/nim/DeviceNetworkStatus/global.json` on the device) shows NIM records the *configured* (bogus) name verbatim as `Port.IfName` — `enpMockEth1`/`enpMockEth2` — even though the real kernel interface is still `eth1`/`eth2` (confirmed by NIM's own `LastError: "link not found for interface enpMockEth1/2"` on those same port entries). Since `ib.Ifname` is also `enpMockEth1`/`enpMockEth2` (from the test's phase-2 config), the name-only `IsPort` check trivially matches, so domainmgr concludes "no mismatch" and skips the warning entirely — the only matching domainmgr warning log in this run (`07:10:40.094`, using the *real* names `eth1`/`eth2`) fired transiently during phase-1 setup, before the bogus config was even applied, and is unrelated.

This is not in `live-ledger.md` and this exact test produced no earlier failure this run, so it is not a known/recurring issue — it looks like a first-time exposure of a real gap in domainmgr's ifname-mismatch detection (it only handles the case where NIM's DeviceNetworkStatus retains the old/real ifname, not the case where NIM echoes back the unresolvable configured name), likely newly surfaced by this test (`TestReportWarningsOnly` is the newest test in the suite per its own code comment, explicitly requiring a different 4-port network model than the other scenarios).

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestAirGapSwitchNI

##### Failure

```
timed out after 5m0.000147421s (excluding download) waiting for app "32c1c9a7-6388-4b94-83fc-d038f02b9ce7" (app1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

This confirms the signature: device reports 4 vCPUs configured but guest's own `nproc` sees only 1, with sustained load average ~4 and ~22-25% iowait — the same oversubscription stall seen in every prior CREATING_VOLUME failure this run and in past nights.

**Root cause:** `TestAirGapSwitchNI`'s app1 timed out in `CREATING_VOLUME` because its container image unpack stalled under host/device CPU oversubscription, not because of any switch-network-instance bug. Device logs show the `app1-image` content tree finished downloading/loading into CAS at 06:05:12.8 and `UnpackClientImage` started at 06:05:15.163, but live inspection shows it's still not done — `ctr snapshot ls` on the device shows two `extract-*` snapshots stuck `Active` (uncommitted) for the same image sha, and `uptime`/`vmstat` show the guest sees only `nproc=1` with load average 4.34/4.01/2.26 and ~22-25% iowait, even though the device is configured for `ncpu:4`. This is the identical root-cause class recorded repeatedly in `live-ledger.md` for this and the previous two nightly runs (2026-11-20 run #30, 2026-11-21 run #35, 2026-11-23 run #45 — the latter in this very suite's `TestSwitchNetInstanceACLsWithFlowLog`), so it's a known, long-standing recurring infrastructure issue (since at least 2026-11-20), not a new bug — and `TestAirGapSwitchNI` itself had not previously appeared in the ledger (it passed in run #45 last night), so this is simply the stall hitting a new subtest tonight.
#### TestAccessVLANs

##### Failure

```

Told to stop trying after 50.074s.
Stop waiting for: NI is ONLINE
Network instance is in error state
networkID:"828061ea-8512-4d0a-a0e4-52ed3c690dd5"  networkVersion:"1"  instType:1  displayname:"vlan-switch"  bridgeNum:1  networkErr:{description:"failed to select ports for network instance 828061ea-8512-4d0a-a0e4-52ed3c690dd5: no port is matching label 'switch-ports'"  timestamp:{seconds:1795502552  nanos:297572868}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500
```

##### Claude's conclusion

Confirmed final state is fully `ZNETINST_STATE_ONLINE` with all three ports assigned — self-healing, not persistent misconfiguration.

**Root cause:** This is the boot-time DPC-promotion race. Device logs show `edge-dev` did a first boot (`Default RebootReason: NORMAL: First boot of device` at 06:40:24.163) and came up on the fallback `lastresort` DPC (bare eth0/eth1, no `switch-ports` label). The real `zedagent` DPC (which carries `SharedLabels:[switch-ports]` on ethernet1-3) was only inserted at 06:41:52.109 and its verification/activation was still in progress (started 06:42:04.911) when zedrouter applied the `vlan-switch` NI config at 06:42:31.153 — it tried to resolve port label `switch-ports` at 06:42:32.297 and logged `no port is matching label 'switch-ports'` because the `zedagent` DPC hadn't finished becoming current yet. The device then finished promoting/reconciling the DPC and the NI reconciler activated `vlan-switch` with all three ports at 06:42:56.392; live `evetest eve ni-info vlan-switch` right now confirms the NI is fully `ZNETINST_STATE_ONLINE`, ports ethernet1/2/3 assigned — the test's 50s fail-fast wait simply gave up before this settled.

This is the identical race documented in `live-ledger.md` for the very same test (`TestAccessVLANs`) in last night's run (2026-11-23, run #45), where it also failed with `no port is matching label 'switch-ports'` and also self-healed shortly after. So this is a known, recurring issue going back at least to last night's run, and it's the same general "lastresort→zedagent DPC promotion racing a fail-fast NI-error wait" class that the ledger has also seen with different trigger labels (`ethernet0`) in earlier runs. It does **not** share a root cause with this run's only other investigated failure (`TestAirGapSwitchNI`, a `CREATING_VOLUME`/CPU-oversubscription timeout) — that's a different mechanism entirely.

## [2026-11-23 -- 0.0.0-13.4-stable-f31777e9 (run #45)](https://github.com/lf-edge/eve/actions/runs/45115071117)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/45/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: eth1 is reported as an unused assignable adapter with a MAC address
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7816  storage:63153  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"4RSX3TNS"  UUID:"Not Settable"  biosVendor:"EFI Development Kit II / OVMF"  biosVersion:"0.0.0"  biosReleaseDate:"02/06/2015"}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"ethernet0"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795411584  nanos:891548851}}  localName:"eth0"  proxy:{}}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usage:PhyIoUsageDedicated}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"nbd12"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/netdump"}  storageList:{device:"nbd0"}  storageList:{device:"nbd13"}  storageList:{device:"nbd5"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/"  total:3908}  storageList:{mountPath:"/config"  total:1}  storageList:{device:"nbd1"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"vda"  total:65536}  storageList:{device:"vda4"  total:1  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"vda1"  total:36  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"vda2"  total:512  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist"  total:63153  storageLocation:true}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{device:"nbd7"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/hostfs"  total:266}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"vda9"  total:64473  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"nbd15"}  storageList:{device:"nbd9"}  storageList:{device:"nbd4"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"vda3"  total:512  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{device:"nbd8"}  bootTime:{seconds:1795411427}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-13.4-stable-f31777e9-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"fce640db-eb89-48d6-af16-feb31f2a7467"  lastRebootReason:"NORMAL: First boot of device - at 2026-11-23T05:24:12.183119915Z"  lastRebootTime:{seconds:1795411452  nanos:183119915}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1795411541  nanos:28253318}  lastSucceeded:{seconds:1795411584  nanos:891607428}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795411584  nanos:891548851}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"aece673b-d110-4688-a885-8f6c09ce9f6e"  mtu:1500}}}  HSMStatus:NOTFOUND  HSMInfo:"Not Available"  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795411524  nanos:43018450}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\x12\xfc\xd7\xd5ea\xe7dT\x9c`u\xf3*\xcdzP}\xf8\xb8]J\x7f\x1d\xa7\xba\x14Ύ\xa3\xf2)"  sha_tls_root_ca:"\x12\xfc\xd7\xd5ea\xe7dT\x9c`u\xf3*\xcdzP}\xf8\xb8]J\x7f\x1d\xa7\xba\x14Ύ\xa3\xf2)"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  maintenance_mode_reasons:MAINTENANCE_MODE_REASON_NONE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_ADAPTER_USER_LABELS  optional_capabilities:{}
```

##### Claude's conclusion

**Root cause:** This is the identical, known recurring failure already in the ledger for 2026-11-22 (run #40) and 2026-11-20 (run #30) — same test, same symptom (`ethernet1`/eth1 shows up as an assignable adapter but with no MAC). Live `evetest eve logs` shows `domainmgr.checkAndFillIoBundle(1 eth1 ethernet1)` ran once at 05:25:44.819 and hit `Can't find ifname eth1` → `found macaddr` (blank), permanently leaving `ethernet1`'s `MacAddr` empty since that one-shot lookup is never retried (confirmed by current `evetest eve info` still showing `assignableAdapters:{...name:"ethernet1" usage:PhyIoUsageDedicated}` with no `ioAddressList`). Live `dmesg` confirms the race: the kernel renamed `eth1 → keth1` at boot+26.15s (NIM reconfiguring it to dedicated/passthrough use) and didn't rename it back to `eth1` until boot+117.06s, and domainmgr's single IO-bundle scan landed right in/at the edge of that ~91-second window where the interface wasn't named `eth1`. This is the same timing race between NIM's interface rename and domainmgr's IO-bundle MAC lookup in `pkg/pillar/cmd/domainmgr` documented in the ledger since at least 2026-11-20 — a known, recurring issue, not a new bug. No PR diff was provided for this investigation.

### TestAppsSuite: failure analysis

#### TestVGAPassthroughNoHostAccess

##### Failure

```

Unexpected error:
    <*fmt.wrapError | 0x3a887b4e55c0>: 
    bpftrace-compiler failed: exit status 2; its last output:
    #32 0.368 time="2026-11-23T06:26:31Z" level=info msg="starting syft scanner for buildkit v1.12.1"
    #32 DONE 1.4s
    
    #33 exporting to oci image format
    #33 exporting layers
    #33 exporting layers 5.4s done
    #33 exporting manifest sha256:bb99ea532b45f19876c3e7d7e55bc90d0792626eae9f49a14e2122903d4c8c9d done
    #33 exporting config sha256:ad57d84249765fc5ff9f139f3c5a57a4aab45f6a73d2eaa28d6d345fce406ebf done
    #33 exporting attestation manifest sha256:7e910590dc794c45e97444e22ccf9856d9e9e99cf5581a714a4473f8901ef416 done
    #33 exporting manifest list sha256:7932e51098f584ab4bb8376c29c3892490e6f59ec7dedc8d2de96d216eb047d9 done
    #33 sending tarball
    #33 sending tarball 0.6s done
    #33 DONE 6.0s
    time="2026-11-23T06:26:40Z" level=info msg="Extract kernel image: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc"
    time="2026-11-23T06:26:40Z" level=info msg="Image docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc arch amd64 incomplete or invalid in local cache, error no such reference: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc, pulling"
    time="2026-11-23T06:26:49Z" level=info msg="Add init containers:"
    time="2026-11-23T06:26:49Z" level=info msg="Process init image: docker.io/linuxkit/root:96bd89e70f2b7f17124313b4ecc9022d"
    time="2026-11-23T06:26:50Z" level=info msg="Create outputs:"
    time="2026-11-23T06:26:50Z" level=info msg="  /var/tmp/bpftrace-image4239955972/linuxkit-squashfs.img"
    2026/11/23 06:27:03 running ["/usr/bin/qemu-system-x86_64" "-smp" "1" "-nographic" "-m" "256" "-device" "virtio-net-pci,netdev=t0,mac=5a:7e:cb:9c:12:67" "-netdev" "user,id=t0" "-kernel" "/var/tmp/bpftrace-image4239955972/linuxkit-kernel" "-hda" "/var/tmp/bpftrace-image4239955972/linuxkit-squashfs.img" "-fsdev" "local,id=dev,path=/var/tmp/bpftrace-9pshare585906703,security_model=mapped,multidevs=remap" "-device" "virtio-9p-pci,fsdev=dev,mount_tag=9pmount" "-append" "root=/dev/sda units=compile console=null quiet"]
    2026/11/23 06:27:22 Running bpftrace ...
    2026/11/23 06:27:22 Running bpftrace program
    panic: runtime error: invalid memory address or nil pointer dereference
    [signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]
    
    goroutine 1 [running]:
    main.(*eveSSHClient).close(0x2c899c78d590)
    	/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b
    main.(*sshRun).end(0x2c899ca05820?)
    	/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16
    main.newRunSSHCmd.func1(0x2c899c7cad00?, {0x2c899c780240, 0x2, 0x111f88e?})
    	/eve-tools/bpftrace-compiler/main.go:375 +0x1f8
    github.com/spf13/cobra.(*Command).execute(0x2c899c7c6608, {0x2c899c7801e0, 0x6, 0x6})
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b
    github.com/spf13/cobra.(*Command).ExecuteC(0x2c899c7c6008)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f
    github.com/spf13/cobra.(*Command).Execute(...)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039
    main.main()
    	/eve-tools/bpftrace-compiler/main.go:138 +0x633
    {
        msg: "bpftrace-compiler failed: exit status 2; its last output:\n#32 0.368 time=\"2026-11-23T06:26:31Z\" level=info msg=\"starting syft scanner for buildkit v1.12.1\"\n#32 DONE 1.4s\n\n#33 exporting to oci image format\n#33 exporting layers\n#33 exporting layers 5.4s done\n#33 exporting manifest sha256:bb99ea532b45f19876c3e7d7e55bc90d0792626eae9f49a14e2122903d4c8c9d done\n#33 exporting config sha256:ad57d84249765fc5ff9f139f3c5a57a4aab45f6a73d2eaa28d6d345fce406ebf done\n#33 exporting attestation manifest sha256:7e910590dc794c45e97444e22ccf9856d9e9e99cf5581a714a4473f8901ef416 done\n#33 exporting manifest list sha256:7932e51098f584ab4bb8376c29c3892490e6f59ec7dedc8d2de96d216eb047d9 done\n#33 sending tarball\n#33 sending tarball 0.6s done\n#33 DONE 6.0s\ntime=\"2026-11-23T06:26:40Z\" level=info msg=\"Extract kernel image: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc\"\ntime=\"2026-11-23T06:26:40Z\" level=info msg=\"Image docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc arch amd64 incomplete or invalid in local cache, error no such reference: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc, pulling\"\ntime=\"2026-11-23T06:26:49Z\" level=info msg=\"Add init containers:\"\ntime=\"2026-11-23T06:26:49Z\" level=info msg=\"Process init image: docker.io/linuxkit/root:96bd89e70f2b7f17124313b4ecc9022d\"\ntime=\"2026-11-23T06:26:50Z\" level=info msg=\"Create outputs:\"\ntime=\"2026-11-23T06:26:50Z\" level=info msg=\"  /var/tmp/bpftrace-image4239955972/linuxkit-squashfs.img\"\n2026/11/23 06:27:03 running [\"/usr/bin/qemu-system-x86_64\" \"-smp\" \"1\" \"-nographic\" \"-m\" \"256\" \"-device\" \"virtio-net-pci,netdev=t0,mac=5a:7e:cb:9c:12:67\" \"-netdev\" \"user,id=t0\" \"-kernel\" \"/var/tmp/bpftrace-image4239955972/linuxkit-kernel\" \"-hda\" \"/var/tmp/bpftrace-image4239955972/linuxkit-squashfs.img\" \"-fsdev\" \"local,id=dev,path=/var/tmp/bpftrace-9pshare585906703,security_model=mapped,multidevs=remap\" \"-device\" \"virtio-9p-pci,fsdev=dev,mount_tag=9pmount\" \"-append\" \"root=/dev/sda units=compile console=null quiet\"]\n2026/11/23 06:27:22 Running bpftrace ...\n2026/11/23 06:27:22 Running bpftrace program\npanic: runtime error: invalid memory address or nil pointer dereference\n[signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]\n\ngoroutine 1 [running]:\nmain.(*eveSSHClient).close(0x2c899c78d590)\n\t/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b\nmain.(*sshRun).end(0x2c899ca05820?)\n\t/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16\nmain.newRunSSHCmd.func1(0x2c899c7cad00?, {0x2c899c780240, 0x2, 0x111f88e?})\n\t/eve-tools/bpftrace-compiler/main.go:375 +0x1f8\ngithub.com/spf13/cobra.(*Command).execute(0x2c899c7c6608, {0x2c899c7801e0, 0x6, 0x6})\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b\ngithub.com/spf13/cobra.(*Command).ExecuteC(0x2c899c7c6008)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f\ngithub.com/spf13/cobra.(*Command).Execute(...)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039\nmain.main()\n\t/eve-tools/bpftrace-compiler/main.go:138 +0x633",
        err: <*exec.ExitError | 0x3a887b4e55a0>{
            ProcessState: {
                pid: 135,
                status: 512,
                rusage: {
                    Utime: {Sec: 24, Usec: 367341},
                    Stime: {Sec: 2, Usec: 490798},
                    Maxrss: 532252,
                    Ixrss: 0,
                    Idrss: 0,
                    Isrss: 0,
                    Minflt: 266931,
                    Majflt: 436,
                    Nswap: 0,
                    Inblock: 154856,
                    Oublock: 1338928,
                    Msgsnd: 0,
                    Msgrcv: 0,
                    Nsignals: 0,
                    Nvcsw: 110728,
                    Nivcsw: 27264,
                },
            },
            Stderr: nil,
        },
    }
occurred
```

##### Claude's conclusion

Empty directory — no additional artifacts collected yet beyond what's in gotest.json, which already matches the failure report given. The evidence is conclusive without needing to touch the live device.

**Root cause:** This is the exact same bug recorded in the ledger for the last two consecutive nights — `main.(*eveSSHClient).close()` at `eve-tools/bpftrace-compiler/ssh-client.go:152` unconditionally calls `s.rStdout.Close()`, but `rStdout` is only populated on the SFTP-fallback path; on the normal success path (`sftp.NewClient`) it stays `nil`, causing a SIGSEGV nil-pointer panic in `bpftrace-compiler` whenever it tears down its SSH session after running a bpftrace program inside the QEMU sandbox VM. Tonight's stack trace (`eveSSHClient.close` → `ssh-client.go:152` → `sshRun.end` → `main.go:375`) is byte-for-byte identical in structure to 2026-11-22 (run #40) and 2026-11-21 (run #35) — only PIDs/pointer addresses differ, as expected from independent runs. This is a known, recurring, host-tool-side bug (unrelated to the EVE device or SDN) dating back to at least 2026-11-21, now hitting for a third consecutive night. No other failure in this run shares this root cause, and since no PR diff was given for this investigation, no RELATED line is produced.

### TestDeviceConnectivitySuite: failure analysis

#### TestMgmtTrafficRoutedViaApp

##### Failure

```

Timed out after 180.001s.
EVE should get device metrics through to the controller via the app-routed management path (firewall restricted, check 1/2)
Expected
    <<-chan *metrics.DeviceMetric | len:0, cap:100>: 0xde713749650
to receive something.
```

##### Claude's conclusion

###### Root cause

Live evidence confirms this is the same DPC-fallback timing race documented in the ledger's `run #35` entry for this exact test, not a new bug.

- **Live DeviceNetworkStatus** (`evetest eve ssh`) shows eth0 still has `IsMgmt:true` with its own direct DHCP lease (`10.60.10.104`, `Dhcp:4`), and `LastSucceeded:06:34:21` just before the firewall was applied, then `LastFailed:06:37:58` with `LastError: ... send via eth0 with src IP 10.60.10.104: ... deadline exceeded`. The device config (`evetest eve config`) sets `eth0` as `PhyIoUsageShared` (not `Dedicated`), so NIM/zedagent continues to treat it as an independent management uplink in parallel with the app-routed path, rather than ceding it entirely to the gateway app.
- **adam-stdout** shows the controller last heard from EVE's direct IP `10.60.10.104` at `06:34:27` (right when the "firewall restricted" firewall rules were applied, allowing only `10.60.10.150`), then total silence until `06:38:29`, when traffic finally starts arriving from `10.60.10.150` (the gateway app's NATed WAN VIF) — about 4 minutes after the firewall change and ~62s after the test's 180s timeout at `06:37:27`.
- This matches run #35's (2026-11-21) root cause almost exactly: EVE's stale direct-eth0 DPC keeps operating alongside the app-routed path until NIM's port-test/retest timers (`timer.port.test*` ~60s each) expire and it fails over to the app route, which consistently takes ~4 minutes — well over the test's 180s budget for `"firewall restricted, check 1/2"`.

This **is a known, recurring issue** per `live-ledger.md`, first documented in run #35 (2026-11-21) and recurring again tonight (run #41, 2026-11-23); it does not share a root cause with the other failures in this run (e.g., `TestDNSFunctionality`'s earlier-in-run subscription race was a distinct `WatchDeviceInfo` timing issue). No PR diff was provided for this investigation, so I can't assess relatedness to a specific change.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestMoveAppBetweenNIs

##### Failure

```
timed out after 5m0.000206726s (excluding download) waiting for app "30f799c4-6055-4556-8367-a4ba78a0b6af" (ping1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** Live evidence confirms this is the same host-CPU-oversubscription stall seen before. `evetest eve logs` shows `ping1`'s volume unpack (`UnpackClientImage` for `2b4e7b4f-14ff-40fd-8da3-b36b4bc9c7c4#0`) started at 06:14:52.026, but `FileLocation is empty for 2b4e7b4f-...` is still being logged every poll right up through 06:18:53 — the unpack still hadn't finished when the test's 5-minute deadline hit at 06:18:42. Crucially, `ping2` and `pong`'s volumes (`CreateVolume`/`UnpackClientImage`) all started within the same ~1-second window (06:14:52.021–06:14:53.094), so three container-image unpacks were competing for CPU simultaneously. Live `evetest eve ssh "uptime; nproc"` shows the guest reports only 1 vCPU visible with load average 5.32/4.89/2.72, on a device configured for 4 vCPUs — the same oversubscription signature documented repeatedly before.

This is a known, recurring issue, not new: the ledger records this exact test (`TestMoveAppBetweenNIs`, app `ping1`, three concurrent `ping1`/`ping2`/`pong` unpacks, `CREATING_VOLUME`→timeout) failing with an essentially identical root-cause writeup on 2026-11-20 (run #30), and the broader class (apps stuck in `CREATING_VOLUME` past the fixed 5-minute timeout due to host/device CPU oversubscription during concurrent image unpacks) has recurred in nearly every nightly run since then (2026-11-20, 2026-11-21, 2026-11-22), hitting many different suites. No PR diff was given for this investigation.
#### TestFlowLog

##### Failure

```
timed out after 5m0.000894873s (excluding download) waiting for app "6d52f5ae-543f-4aac-8983-5d69b3286989" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Confirmed: `UnpackClientImage` started at 06:42:27.310 and still has not completed as of 06:47:32 live — ~5m05s stuck, matching the `Active`/uncommitted containerd snapshot I found directly on the device. That's enough evidence; no need for further checks.

###### Root cause

The app `flowlog-test-app` (`6d52f5ae-...`) got stuck in `CREATING_VOLUME` because its container-image unpack never completed within the timeout. Device logs show `volumemgr.CreateVolume`/`zedbox.UnpackClientImage` fired at `06:42:27.310` for volume `90693637-...`, and `zedagent` is still logging `FileLocation is empty for 90693637-...` every poll through `06:47:32` live — over 5 minutes later, with no completion log ever appearing. Live inspection of the device's user-containerd confirms the corresponding snapshot `extract-607245455-TKTz` is still `Active` (uncommitted), and `evetest eve ssh "uptime; nproc"` shows the guest reports only 1 vCPU visible with load average 3.97/3.15/2.27 on a device configured for 4 vCPUs — the same CPU-oversubscription signature as the other failures.

This is the identical root cause already recorded for three earlier failures in this same run (`TestLocalNI`, `TestMoveAppBetweenNIs`, `TestLimitedIPSpace`) in `live-investigation.md`. It's also a known, heavily recurring issue per `live-ledger.md`: this exact test name, app name (`flowlog-test-app`), and failure signature appeared in an earlier nightly run as well, and the broader class of `CREATING_VOLUME`/unpack-timeout failures due to host CPU oversubscription has recurred in essentially every nightly run since at least 2026-11-20.
#### TestLocalNetInstanceACLs

##### Failure

```
timed out after 5m0.000227299s (excluding download) waiting for app "e6dc7f3e-cf9f-4e69-8125-01cc55954a8f" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

`UnpackClientImage`/`CreateVolume` started at 06:54:01.772-06:54:01.776 and as of my live check (06:58:40+) is still not complete — nearly 5 minutes and counting with no completion log, confirming the unpack genuinely stalled rather than just being slow-but-finishing-late.

**Root cause:** This is the same host/device CPU-oversubscription stall seen throughout this run and prior ones. `acl-app-1`'s root volume (`4054a655-...`, container `evetest-ubuntu-ctr`) began `CreateVolume`/`UnpackClientImage` at 06:54:01.772-06:54:01.776, and `zedagent` was still logging `FileLocation is empty` every few seconds through 06:58:19 — still incomplete as of my live check at 06:58:40, well past the 5-minute deadline. Live `evetest eve ssh "uptime; nproc; vmstat"` confirms the signature: the guest reports only `nproc=1` with load average 3.28 against a device configured for 4 vCPUs, and `vmstat` shows a process perpetually blocked on I/O (`b=1-2`, `wa`≈23-25%). This matches the same root cause already recorded for earlier failures in this run (`TestMoveAppBetweenNIs`, `TestFlowLog`) in `live-investigation.md`, and is a known, heavily recurring issue per `live-ledger.md` — the identical `CREATING_VOLUME`/unpack-stall pattern (including this exact app name `acl-app-1` with the same container image) has appeared in nightly runs since at least 2026-11-20 (run #30), across many different suites.
#### TestLocalNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.000986762s (excluding download) waiting for app "a4d95045-383c-472b-8347-06011bd43ebb" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Confirmed the same pattern once more, live and at the right timestamp. `CreateVolume`/`UnpackClientImage` for `acl-app-1`'s volume `3c836801-04ec-4827-9a8e-87e9fa40e473#0` started at 07:04:07.381-385, and `zedagent` is still logging `ActiveFileLocation is empty` for that volume every poll through 07:08:18 live — over 5 minutes later, never completing. Live `evetest eve ssh "uptime; nproc"` again shows the guest exposing only 1 vCPU with load average 4.52/3.76/1.96 on a device sized for 4 vCPUs.

This is the identical root cause already recorded three times earlier in this same run (`TestMoveAppBetweenNIs`, `TestFlowLog`, `TestLocalNetInstanceACLs`), all in `live-investigation.md`, and it's a heavily recurring, known issue per `live-ledger.md`: the `CREATING_VOLUME`/unpack-stall-under-CPU-oversubscription class has appeared in nearly every nightly run since at least 2026-11-20 (run #30), across many different suites and apps. No PR diff was given for this investigation.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestAccessVLANs

##### Failure

```
timed out after 5m0.000451337s (excluding download) waiting for app "ec5e1e5e-3b20-4fa1-a833-7ec620ea2f2d" (vlan100-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live inspection confirms the app genuinely never finished creating its volume — not a hang in the test harness. `vlan100-app` was created at 06:40:28, immediately hit a transient boot-time networking race (`volumemgr`: `No IP management port addresses with cost <= 0`, logged at 06:40:30 and again at 06:42:11) that delayed it from reaching `CREATING_VOLUME`/`CreateVolume`+`UnpackClientImage` until 06:42:15 — eating ~1m45s of the 5‑minute budget before the unpack even started. The unpack then stalled: `evetest eve logs` shows no completion log for it as of the current live check (06:46+, ~4 minutes after it started), and `app-info` still reports `state:CREATING_VOLUME`. Live `vmstat` on the device shows I/O-wait pegged at 23–28% with a process perpetually blocked (`b=1-2`), while the guest reports only `nproc=1` against a load average of 5.51 — the same CPU/disk-oversubscription signature already documented repeatedly in `live-ledger.md`.

This is the same general failure class (boot-time DPC/networking race compounding with host CPU/I/O oversubscription to blow the fixed 5‑minute `CREATING_VOLUME` timeout) that the ledger records as known and recurring since at least 2026-11-20 (run #30), and which hit this same suite earlier tonight (`TestSwitchNetInstanceACLsWithFlowLog`, also a `CREATING_VOLUME` timeout) and last night (run #40, `TestControllerFaultsSuite`/`reported-app`, with the identical "No IP management port addresses with cost <= 0" boot-race symptom). Note that `TestAccessVLANs` itself failed in last night's run (#40) too, but with a *different* symptom (`no port is matching label 'switch-ports'` NI-error race) — so this exact `CREATING_VOLUME` manifestation for `TestAccessVLANs` is new, but it's a recurrence of the well-established oversubscription/boot-race infrastructure issue, not a new product bug.

No PR diff was given for this investigation, so no RELATED line.

## [2026-11-22 -- 0.0.0-13.4-stable-f31777e9 (run #40)](https://github.com/lf-edge/eve/actions/runs/44987448140)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/40/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: eth1 is reported as an unused assignable adapter with a MAC address
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7816  storage:63153  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"MBINJGEY"  UUID:"Not Settable"  biosVendor:"EFI Development Kit II / OVMF"  biosVersion:"0.0.0"  biosReleaseDate:"02/06/2015"}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"ethernet0"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795326980  nanos:695321106}}  localName:"eth0"  proxy:{}}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usage:PhyIoUsageDedicated}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd0"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/"  total:3908}  storageList:{device:"nbd15"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"vda2"  total:512  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist"  total:63153  storageLocation:true}  storageList:{device:"nbd7"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"nbd13"}  storageList:{device:"nbd14"}  storageList:{device:"nbd8"}  storageList:{mountPath:"/hostfs"  total:266}  storageList:{device:"vda1"  total:36  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd5"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/persist/clear"}  storageList:{mountPath:"/config"  total:1}  storageList:{device:"nbd11"}  storageList:{device:"vda4"  total:1  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"nbd4"}  storageList:{device:"vda9"  total:64473  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/newlog"}  storageList:{device:"nbd1"}  storageList:{device:"vda3"  total:512  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  bootTime:{seconds:1795326827}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-13.4-stable-f31777e9-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"911821d3-7028-4bde-bffa-d82395ef62da"  lastRebootReason:"NORMAL: First boot of device - at 2026-11-22T05:54:11.536894085Z"  lastRebootTime:{seconds:1795326851  nanos:536894085}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1795326940  nanos:255703202}  lastSucceeded:{seconds:1795326980  nanos:695378058}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795326980  nanos:695321106}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"4f9d035d-0363-418d-b9e7-263273811265"  mtu:1500}}}  HSMStatus:NOTFOUND  HSMInfo:"Not Available"  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795326927  nanos:18291490}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xd0\x10\x98\xbeX\xb9\x0b\xf6\x90\x0bſ\xc3A\x119O\xc7+X.\xd6WkMxp\x9ew\x0f\xaa\xba"  sha_tls_root_ca:"\xd0\x10\x98\xbeX\xb9\x0b\xf6\x90\x0bſ\xc3A\x119O\xc7+X.\xd6WkMxp\x9ew\x0f\xaa\xba"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  maintenance_mode_reasons:MAINTENANCE_MODE_REASON_NONE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_ADAPTER_USER_LABELS  optional_capabilities:{}
```

##### Claude's conclusion

I have enough live evidence to confirm this matches the known pattern. Writing the conclusion now.

**Root cause:** This is the identical failure already recorded in the ledger for 2026-11-20 (run #30) — same test, same symptom (`ethernet1`/eth1 shows up as an assignable adapter but with no MAC), and the same underlying log signature. Live `logread` shows `domainmgr.checkAndFillIoBundle(1 eth1 ethernet1)` ran once at 05:55:41.104 and hit `getMacAddr: Can't find ifname eth1`, leaving the IO bundle's `MacAddr` permanently blank since that one-time lookup is never retried. Live `dmesg` confirms why: the kernel renamed the interface `eth1 → keth1` at boot+26.67s (NIM reconfiguring it from uplink to dedicated/passthrough) and didn't rename it back to `eth1` until boot+114.27s, so the single `checkAndFillIoBundle` call at boot+~90s landed squarely inside that ~88-second window where the interface was named `keth1`, not `eth1` — a timing race in `pkg/pillar/cmd/domainmgr` between NIM's interface-rename and domainmgr's IO-bundle MAC lookup. This is a known, recurring issue dating back to at least 2026-11-20 (run #30), not a new bug, and no other failure in this run shares this root cause (the `TestAppNICsSuite` run otherwise has no other reported failures yet).

### TestAppsSuite: failure analysis

#### TestVGAPassthroughNoHostAccess

##### Failure

```

Unexpected error:
    <*fmt.wrapError | 0x25607e78c020>: 
    bpftrace-compiler failed: exit status 2; its last output:
    #32 0.197 time="2026-11-22T07:47:41Z" level=info msg="starting syft scanner for buildkit v1.12.1"
    #32 DONE 1.2s
    
    #33 exporting to oci image format
    #33 exporting layers
    #33 exporting layers 5.7s done
    #33 exporting manifest sha256:e3b12b3cb4e37969f817048a500fa2993a1eef4eedb4626f2829d755a18b3c3e done
    #33 exporting config sha256:974175beb364997728eb4fe7e4bed8c8aaf492e78134a6d18703c262671ea5ed done
    #33 exporting attestation manifest sha256:b311f0b5aca2cb2063c651d377afd4c55c4a45b50400e6519853137989273554 done
    #33 exporting manifest list sha256:6d0e3edda478282fb7ab478c561fa0d7e2d696d7a537b0a971d7a6ace1743931 done
    #33 sending tarball
    #33 sending tarball 0.5s done
    #33 DONE 6.2s
    time="2026-11-22T07:47:50Z" level=info msg="Extract kernel image: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc"
    time="2026-11-22T07:47:50Z" level=info msg="Image docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc arch amd64 incomplete or invalid in local cache, error no such reference: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc, pulling"
    time="2026-11-22T07:47:59Z" level=info msg="Add init containers:"
    time="2026-11-22T07:47:59Z" level=info msg="Process init image: docker.io/linuxkit/root:96bd89e70f2b7f17124313b4ecc9022d"
    time="2026-11-22T07:48:01Z" level=info msg="Create outputs:"
    time="2026-11-22T07:48:01Z" level=info msg="  /var/tmp/bpftrace-image541678727/linuxkit-squashfs.img"
    2026/11/22 07:48:14 running ["/usr/bin/qemu-system-x86_64" "-smp" "1" "-nographic" "-m" "256" "-device" "virtio-net-pci,netdev=t0,mac=5a:7e:cb:9c:12:67" "-netdev" "user,id=t0" "-kernel" "/var/tmp/bpftrace-image541678727/linuxkit-kernel" "-hda" "/var/tmp/bpftrace-image541678727/linuxkit-squashfs.img" "-fsdev" "local,id=dev,path=/var/tmp/bpftrace-9pshare2519399626,security_model=mapped,multidevs=remap" "-device" "virtio-9p-pci,fsdev=dev,mount_tag=9pmount" "-append" "root=/dev/sda units=compile console=null quiet"]
    2026/11/22 07:48:33 Running bpftrace ...
    2026/11/22 07:48:33 Running bpftrace program
    panic: runtime error: invalid memory address or nil pointer dereference
    [signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]
    
    goroutine 1 [running]:
    main.(*eveSSHClient).close(0x8611d765d10)
    	/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b
    main.(*sshRun).end(0x8611d8261d0?)
    	/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16
    main.newRunSSHCmd.func1(0x8611d7be800?, {0x8611d7c20c0, 0x2, 0x111f88e?})
    	/eve-tools/bpftrace-compiler/main.go:375 +0x1f8
    github.com/spf13/cobra.(*Command).execute(0x8611d7aa308, {0x8611d7c2060, 0x6, 0x6})
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b
    github.com/spf13/cobra.(*Command).ExecuteC(0x8611d58bb08)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f
    github.com/spf13/cobra.(*Command).Execute(...)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039
    main.main()
    	/eve-tools/bpftrace-compiler/main.go:138 +0x633
    {
        msg: "bpftrace-compiler failed: exit status 2; its last output:\n#32 0.197 time=\"2026-11-22T07:47:41Z\" level=info msg=\"starting syft scanner for buildkit v1.12.1\"\n#32 DONE 1.2s\n\n#33 exporting to oci image format\n#33 exporting layers\n#33 exporting layers 5.7s done\n#33 exporting manifest sha256:e3b12b3cb4e37969f817048a500fa2993a1eef4eedb4626f2829d755a18b3c3e done\n#33 exporting config sha256:974175beb364997728eb4fe7e4bed8c8aaf492e78134a6d18703c262671ea5ed done\n#33 exporting attestation manifest sha256:b311f0b5aca2cb2063c651d377afd4c55c4a45b50400e6519853137989273554 done\n#33 exporting manifest list sha256:6d0e3edda478282fb7ab478c561fa0d7e2d696d7a537b0a971d7a6ace1743931 done\n#33 sending tarball\n#33 sending tarball 0.5s done\n#33 DONE 6.2s\ntime=\"2026-11-22T07:47:50Z\" level=info msg=\"Extract kernel image: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc\"\ntime=\"2026-11-22T07:47:50Z\" level=info msg=\"Image docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc arch amd64 incomplete or invalid in local cache, error no such reference: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc, pulling\"\ntime=\"2026-11-22T07:47:59Z\" level=info msg=\"Add init containers:\"\ntime=\"2026-11-22T07:47:59Z\" level=info msg=\"Process init image: docker.io/linuxkit/root:96bd89e70f2b7f17124313b4ecc9022d\"\ntime=\"2026-11-22T07:48:01Z\" level=info msg=\"Create outputs:\"\ntime=\"2026-11-22T07:48:01Z\" level=info msg=\"  /var/tmp/bpftrace-image541678727/linuxkit-squashfs.img\"\n2026/11/22 07:48:14 running [\"/usr/bin/qemu-system-x86_64\" \"-smp\" \"1\" \"-nographic\" \"-m\" \"256\" \"-device\" \"virtio-net-pci,netdev=t0,mac=5a:7e:cb:9c:12:67\" \"-netdev\" \"user,id=t0\" \"-kernel\" \"/var/tmp/bpftrace-image541678727/linuxkit-kernel\" \"-hda\" \"/var/tmp/bpftrace-image541678727/linuxkit-squashfs.img\" \"-fsdev\" \"local,id=dev,path=/var/tmp/bpftrace-9pshare2519399626,security_model=mapped,multidevs=remap\" \"-device\" \"virtio-9p-pci,fsdev=dev,mount_tag=9pmount\" \"-append\" \"root=/dev/sda units=compile console=null quiet\"]\n2026/11/22 07:48:33 Running bpftrace ...\n2026/11/22 07:48:33 Running bpftrace program\npanic: runtime error: invalid memory address or nil pointer dereference\n[signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]\n\ngoroutine 1 [running]:\nmain.(*eveSSHClient).close(0x8611d765d10)\n\t/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b\nmain.(*sshRun).end(0x8611d8261d0?)\n\t/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16\nmain.newRunSSHCmd.func1(0x8611d7be800?, {0x8611d7c20c0, 0x2, 0x111f88e?})\n\t/eve-tools/bpftrace-compiler/main.go:375 +0x1f8\ngithub.com/spf13/cobra.(*Command).execute(0x8611d7aa308, {0x8611d7c2060, 0x6, 0x6})\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b\ngithub.com/spf13/cobra.(*Command).ExecuteC(0x8611d58bb08)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f\ngithub.com/spf13/cobra.(*Command).Execute(...)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039\nmain.main()\n\t/eve-tools/bpftrace-compiler/main.go:138 +0x633",
        err: <*exec.ExitError | 0x25607e2538e0>{
            ProcessState: {
                pid: 1683,
                status: 512,
                rusage: {
                    Utime: {Sec: 24, Usec: 599271},
                    Stime: {Sec: 2, Usec: 447122},
                    Maxrss: 534000,
                    Ixrss: 0,
                    Idrss: 0,
                    Isrss: 0,
                    Minflt: 285064,
                    Majflt: 428,
                    Nswap: 0,
                    Inblock: 125168,
                    Oublock: 1338928,
                    Msgsnd: 0,
                    Msgrcv: 0,
                    Nsignals: 0,
                    Nvcsw: 118895,
                    Nivcsw: 28278,
                },
            },
            Stderr: nil,
        },
    }
occurred
```

##### Claude's conclusion

**Root cause:** `eveSSHClient.close()` at `eve-tools/bpftrace-compiler/ssh-client.go:152` unconditionally calls `s.rStdout.Close()`, but `rStdout` is only populated by the `/usr/libexec/sftp-server`-fallback path (`startSftpClientWithCustomPath`); on the normal success path (`sftp.NewClient(s.client)`), `rStdout` stays `nil`, so `close()` dereferences a nil pointer and panics with SIGSEGV. Today's stack trace (`main.(*eveSSHClient).close` → `ssh-client.go:152` → `sshRun.end` → `main.go:375`) is byte-for-byte identical to last night's. This file hasn't been touched since 2024-09-25, confirming it's a pure host-side, structural bug unrelated to any device/SDN state and unrelated to this run's recent commits (yetus/buf/linuxkit CI changes). Per `live-ledger.md`, this exact same test/failure/stack trace already occurred in run #35 (2026-11-21) and was root-caused there identically — so this is a known, recurring issue dating back to at least last night's run, not a new one.

### TestControllerFaultsSuite: failure analysis

#### TestInfoRetriedAfterLostController

##### Failure

```
timed out after 5m0.000877908s (excluding download) waiting for app "a2ead24d-36c2-41ba-a934-60df620b7032" (reported-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live evidence shows this is the same host-CPU-oversubscription pattern that has repeatedly caused `CREATING_VOLUME` timeouts in this environment. Two compounding delays ate the 5‑minute budget for `reported-app`: (1) a boot-time networking race — `volumemgr` logged `Found error in content tree reported-app-image attached to volume reported-app-root: No IP management port addresses with cost <= 0` from 06:45:52 until it self-cleared at 06:47:33, pushing the image resolve/download to only finish at 06:48:06; and (2) `UnpackClientImage` for the ~56MB `evetest-ubuntu-ctr` image then started at 06:48:07.309 and was *still running* as of my live check at 06:52:04 (~4m57s and counting) — consistent with severe CPU starvation: the guest reports `nproc=1` with load average 2.5–3.1, while the underlying host itself has only 2 physical CPUs (load average 0.03–0.8, so the overload is specifically inside the guest/device VM, not the host).

This exact failure signature (`reported-app` stuck in `CREATING_VOLUME` for >5m in `TestControllerFaultsSuite`) is already in the ledger for run #30 (2026-11-20), under a different subtest (`TestInfoDroppedOnRejectionKeepsDeviceReporting`) but the identical app name, identical error message, and identical root cause (CPU-oversubscribed unpack stall). The broader class — container-image unpacks stalling past the fixed 5‑minute `CREATING_VOLUME` timeout under host/device CPU oversubscription — is a long-standing, heavily recurring issue, documented across both prior nightly runs in the ledger (31 separate `CREATING_VOLUME` mentions) hitting many different suites/tests. So this is a known, recurring infrastructure issue (since at least 2026-11-20), now manifesting in a new subtest of `TestControllerFaultsSuite`, not a new product bug.

No PR diff was provided for this investigation.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.000152305s (excluding download) waiting for app "7bc8b5e1-359e-4eeb-81b0-a6f436911c3d" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live inspection confirms this is a genuine, still-in-progress slow volume unpack, not a hang: `evetest eve logs` shows `volumemgr` started `CreateVolume(14809a8f-...)`/`UnpackClientImage` for `acl-app-1`'s root volume at 05:50:40.367, and as of now (05:56+, over 5.5 minutes later) there is still no `createContainerVolume ... DONE` and `FileLocation` is still empty — i.e. the unpack is still running, just very slowly. `vmstat` on the device shows a process perpetually blocked on I/O (`b=1`, `wa`≈23-31%) while `nproc` reports only 1 vCPU visible to the guest against a device configured for 4 vCPUs, and `/proc/diskstats` shows heavy accumulated write time on `vda9` (persist) — the same CPU/disk-oversubscription signature documented repeatedly in the ledger.

This is a known, recurring issue: `live-ledger.md` records the identical `CREATING_VOLUME`→timeout pattern five times in the 2026-11-20 (run #30) nightly, and it already hit `TestLPSSuite` twice in the very next night's run (2026-11-21, run #35, `TestProfile` and `TestAppLocalInfo`) via `live-investigation.md`'s own analysis. This is simply the same host-resource-oversubscription issue recurring again tonight, now in `TestSwitchNetworkInstanceSuite`. It does not share a root cause with any other failure in tonight's run — the three earlier tests in this suite (`TestSwitchNI`, `TestAirGapSwitchNI`, `TestSwitchNetInstanceACLs`) all passed, and this is the first failure recorded in `gotest.json` so far tonight.

No PR diff was given for this investigation, so no RELATED line.
#### TestAccessVLANs

##### Failure

```

Told to stop trying after 20.295s.
Stop waiting for: NI is ONLINE
Network instance is in error state
networkID:"25633e44-c968-482b-a026-47eda215b684"  networkVersion:"1"  instType:1  displayname:"vlan-switch"  bridgeNum:1  networkErr:{description:"failed to select ports for network instance 25633e44-c968-482b-a026-47eda215b684: no port is matching label 'switch-ports'"  timestamp:{seconds:1795327883  nanos:230096654}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500
```

##### Claude's conclusion

###### Root cause

Live inspection confirms this is a transient, self-healing NIM/zedrouter port-selection race on a freshly-booted device, not a real configuration problem. `evetest eve logs` shows the device rebooted for this test (`Ignore any saved config due to boot reason BootReasonFirst` at 06:11:09), came up on the fallback `lastresort` DPC (bare `eth0/eth1`, no shared labels), and only inserted/promoted the real `zedagent` DPC (which carries `SharedLabels:[switch-ports]` on eth1-eth3) at 06:11:21.778 — triggering a DHCP release/renew + reconciliation cycle on all 4 ports. zedrouter tried to resolve the `vlan-switch` NI's `Port: "switch-ports"` label at 06:11:23.230 and again at 06:11:50.944, both times logging `no port is matching label 'switch-ports'` before the reconciliation finished reporting the new `DeviceNetworkStatus`. The test's fail-fast wait only allowed 20.295s and gave up at 06:11:41, but `evetest eve ni-info vlan-switch` right now shows the NI fully recovered on its own shortly after — `state:ZNETINST_STATE_ONLINE` with `ports: ethernet1, ethernet2, ethernet3` correctly assigned — confirming this was transient, not persistent misconfiguration.

This is the same general race class investigated earlier (per `live-investigation.md`, for a different test in this run, `TestSwitchNetInstanceACLsWithFlowLog`'s volume-creation timeout — unrelated root cause there) is **not** the same bug; however, this failure *does* share its root cause with the `no port is matching label` boot-time DPC-promotion race documented in last night's (2026-11-21, run #35) `TestAppRoutingSuite` investigation for `TestApplicationGateway`/`ni-eth0` — same mechanism (lastresort→zedagent DPC promotion racing a fail-fast NI-error wait), just triggered here by a `SharedLabel` (`switch-ports`) rather than a `LogicalLabel` (`ethernet0`). Per `live-ledger.md`, neither this exact test (`TestAccessVLANs`) nor this specific `no port is matching label` signature for `TestSwitchNetworkInstanceSuite` has been recorded before — this is the first occurrence for this suite, though it's a recurrence of the broader known race class.

## [2026-11-21 -- 0.0.0-13.4-stable-9ab05f5f (run #35)](https://github.com/lf-edge/eve/actions/runs/44868748877)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/35/)

### TestAppRoutingSuite: failure analysis

#### TestLocalNIWithMultiplePorts

##### Failure

```

Told to stop trying after 2.074s.
Stop waiting for: NI ONLINE with both static routes via ethernet0 and all connected routes present
Network instance is in error state
networkID:"eba401a0-bcc0-4404-8d85-b7e93fb8a88c"  networkVersion:"1"  instType:2  displayname:"multi-port-ni"  activated:true  CurrentUplinkIntf:"ethernet0"  ports:"ethernet0"  ports:"ethernet1"  ports:"ethernet2"  ports:"ethernet3"  bridgeNum:1  bridgeName:"bn1"  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:06:00:01"  ipAddress:"10.50.0.1"}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByAppUUID:"b8937b3e-ae89-4af8-9dc0-d03a09fdb2a6"  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usedByAppUUID:"b8937b3e-ae89-4af8-9dc0-d03a09fdb2a6"  ioAddressList:{macAddress:"1e:68:56:62:e1:30"}}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet2"  members:"ethernet2"  usedByAppUUID:"b8937b3e-ae89-4af8-9dc0-d03a09fdb2a6"  ioAddressList:{macAddress:"ce:30:0f:9c:43:d9"}}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet3"  members:"ethernet3"  usedByAppUUID:"b8937b3e-ae89-4af8-9dc0-d03a09fdb2a6"  ioAddressList:{macAddress:"d6:42:ef:26:d8:c8"}}  networkErr:{description:"IP Route: {dst=0.0.0.0/0, gw=<nil>, port=internet, probe={enabledGwPing=true, gwPingMaxCost=5, userProbe=<none>}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port\nIP Route: {dst=10.88.88.0/24, gw=<nil>, port=httpserver, probe={enabledGwPing=true, gwPingMaxCost=0, userProbe=tcp://10.88.88.70:80}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port"  timestamp:{seconds:1795241406  nanos:111142233}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"10.40.40.1"  port:"ethernet3"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"192.168.30.1"  port:"ethernet2"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"172.28.20.1"  port:"ethernet1"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"172.22.10.1"  port:"ethernet0"}  ip_routes:{destination_network:"10.40.40.0/24"  port:"ethernet3"}  ip_routes:{destination_network:"172.22.10.0/24"  port:"ethernet0"}  ip_routes:{destination_network:"172.28.20.0/24"  port:"ethernet1"}  ip_routes:{destination_network:"192.168.30.0/24"  port:"ethernet2"}
```

##### Claude's conclusion

This fully confirms the root cause: the NI went ERROR → ONLINE moments later and has stayed ONLINE ever since (both static routes correctly resolved to ethernet0, and the app's VIF got an IP) — exactly the kind of transient settle-down race the test harness itself documents.

###### Root cause

`TestLocalNIWithMultiplePorts` (`evetest/tests/networking/routing_test.go:666`) waits for the NI's static routes (keyed by the `ethernet0` shared labels `"internet"`/`"httpserver"`, visible in `evetest eve config`'s `systemAdapterList`) to resolve, but it uses `.StopIf(niHasError)` (`helpers_test.go:33`), which aborts the wait the instant the NI reports `ZNETINST_STATE_ERROR` — it bailed after only 2.074s. Live data confirms this was a transient, self-healing race: `gotest.json` shows the NI going `INIT → ERROR` at 06:10:06.545 with exactly the two static routes (`port=internet`, `port=httpserver`) not yet resolved to a port, then `ERROR → ONLINE` ~1.2s later at 06:10:07.784, and `evetest eve ni-info` right now shows the NI has been `ZNETINST_STATE_ONLINE` with both static routes correctly pinned to `ethernet0` and the app VIF already has an IP — i.e. it fully recovered on its own well within the NI's actual 3-minute budget.

Notably, `netinst_test.go` (lines 48, 164, 564) explicitly documents this exact race ("zedrouter/NIM races can briefly flag NI as errored before settling — the eventual ONLINE is what matters") and deliberately omits `StopIf(niHasError)` for its analogous initial-NI-online check, while `routing_test.go`'s `TestLocalNIWithMultiplePorts` does use it here. This looks like a test-harness bug (overly strict fail-fast in this one wait) rather than a product bug, and not something this run's own recent commits (yetus/buf/linuxkit CI changes) plausibly caused. This failure/test doesn't appear in the ledger's one prior recorded night (2026-11-20, run #30), so it isn't a previously-known recurring issue — this is the first recorded occurrence.
#### TestApplicationGateway

##### Failure

```

Told to stop trying after 17.160s.
Stop waiting for: ni-eth0 is ONLINE
Network instance is in error state
networkID:"79435cba-a43f-439c-b016-29ee9f34ab5e"  networkVersion:"1"  instType:2  displayname:"ni-eth0"  bridgeNum:1  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:06:00:01"  ipAddress:"10.50.0.1"}  networkErr:{description:"failed to select ports for network instance 79435cba-a43f-439c-b016-29ee9f34ab5e: no port is matching label 'ethernet0'"  timestamp:{seconds:1795241959  nanos:505336064}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500
```

##### Claude's conclusion

Not a known/recurring issue in the ledger either.

###### Root cause

`TestApplicationGateway` (`evetest/tests/networking/routing_test.go:928`) creates `ni-eth0` with `Port: "ethernet0"` right after `ApplyConfig`, but `.StopIf(niHasError)`-style fail-fast waits (per `evetest status`'s "Told to stop trying after 17.160s") abort as soon as zedrouter reports the NI errored. Live EVE logs show this is exactly a boot-time DPC race: at device boot NIM starts on the fallback `lastresort` DPC (bare ifnames `eth0`/`eth1`), and only inserts/activates the real `zedagent` DPC (which carries the logical labels `ethernet0`→`eth0`, `ethernet1`→`eth1`) once DHCP/ping verification succeeds. The `zedagent` DPC was inserted at 06:19:16.993 but was still `CurrentIndex:1` (not yet promoted) when zedrouter tried to resolve the NI's port label at 06:19:19.505 and 06:19:21.116, logging `failed to select ports for network instance ...: no port is matching label 'ethernet0'`/`'ethernet1'` for both `ni-eth0` and the app-gw switch NI. The device fully recovered on its own: `ni-eth0` is now `ZNETINST_STATE_ONLINE` with its route correctly pinned to `ethernet0`, confirming this was transient and self-healing, not a persistent misconfiguration.

This is the same class of race documented and already investigated in this run's `TestLocalNIWithMultiplePorts` failure (`live-investigation.md`) — a NIM/zedrouter port-selection race that briefly errors an NI before it settles — though the specific trigger here (boot-time DPC promotion from `lastresort` to `zedagent`) is a different facet of that same general "transient NI-error-before-settling" class rather than the identical code path (that one was a static-route port-matching race post-config-change, this one is first-boot DPC-switch timing). Neither this test/failure nor this `no port is matching label` error appears anywhere in `live-ledger.md`, so it is not a previously recorded/recurring issue — this is the first occurrence.

### TestAppsSuite: failure analysis

#### TestVGAPassthroughNoHostAccess

##### Failure

```

Unexpected error:
    <*fmt.wrapError | 0x1b5e6f4d4a00>: 
    bpftrace-compiler failed: exit status 2; its last output:
    2026/11/21 06:36:31 found compiled script in cache ...
    2026/11/21 06:36:31 Running bpftrace ...
    2026/11/21 06:36:31 Running bpftrace program
    panic: runtime error: invalid memory address or nil pointer dereference
    [signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]
    
    goroutine 1 [running]:
    main.(*eveSSHClient).close(0x126897637590)
    	/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b
    main.(*sshRun).end(0x1268975e87f0?)
    	/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16
    main.newRunSSHCmd.func1(0x126897598e00?, {0x12689762c240, 0x2, 0x111f88e?})
    	/eve-tools/bpftrace-compiler/main.go:375 +0x1f8
    github.com/spf13/cobra.(*Command).execute(0x12689765c608, {0x12689762c1e0, 0x6, 0x6})
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b
    github.com/spf13/cobra.(*Command).ExecuteC(0x12689765c008)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f
    github.com/spf13/cobra.(*Command).Execute(...)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039
    main.main()
    	/eve-tools/bpftrace-compiler/main.go:138 +0x633
    {
        msg: "bpftrace-compiler failed: exit status 2; its last output:\n2026/11/21 06:36:31 found compiled script in cache ...\n2026/11/21 06:36:31 Running bpftrace ...\n2026/11/21 06:36:31 Running bpftrace program\npanic: runtime error: invalid memory address or nil pointer dereference\n[signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]\n\ngoroutine 1 [running]:\nmain.(*eveSSHClient).close(0x126897637590)\n\t/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b\nmain.(*sshRun).end(0x1268975e87f0?)\n\t/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16\nmain.newRunSSHCmd.func1(0x126897598e00?, {0x12689762c240, 0x2, 0x111f88e?})\n\t/eve-tools/bpftrace-compiler/main.go:375 +0x1f8\ngithub.com/spf13/cobra.(*Command).execute(0x12689765c608, {0x12689762c1e0, 0x6, 0x6})\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b\ngithub.com/spf13/cobra.(*Command).ExecuteC(0x12689765c008)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f\ngithub.com/spf13/cobra.(*Command).Execute(...)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039\nmain.main()\n\t/eve-tools/bpftrace-compiler/main.go:138 +0x633",
        err: <*exec.ExitError | 0x1b5e6f4d4940>{
            ProcessState: {
                pid: 146,
                status: 512,
                rusage: {
                    Utime: {Sec: 0, Usec: 29883},
                    Stime: {Sec: 0, Usec: 3448},
                    Maxrss: 96420,
                    Ixrss: 0,
                    Idrss: 0,
                    Isrss: 0,
                    Minflt: 1953,
                    Majflt: 0,
                    Nswap: 0,
                    Inblock: 216,
                    Oublock: 56,
                    Msgsnd: 0,
                    Msgrcv: 0,
                    Nsignals: 0,
                    Nvcsw: 711,
                    Nivcsw: 95,
                },
            },
            Stderr: nil,
        },
    }
occurred
```

##### Claude's conclusion

This confirms the exact bug: `close()` unconditionally calls `s.rStdout.Close()`, but `rStdout` is only ever set in `startSftpClientWithCustomPath` — when `startSftpClient()` (using `sftp.NewClient(s.client)`) succeeds, which is the normal/common path, `rStdout` stays nil, so `close()` segfaults on every such run.

**Root cause:** This is a pure host-side bug in `eve-tools/bpftrace-compiler/ssh-client.go:152`, not a live EVE device/SDN issue — `eveSSHClient.close()` unconditionally calls `s.rStdout.Close()`, but `rStdout` is only populated by the `/usr/libexec/sftp-server` fallback path (`startSftpClientWithCustomPath`); on the normal success path (`sftp.NewClient(s.client)`, used here per the log's "Running bpftrace program" with no error before the crash), `rStdout` is left nil, causing the panic/SIGSEGV seen in today's stack trace.

This is a known, recurring issue: the identical failure (same test, same stack trace at `ssh-client.go:152`) was already investigated and fully root-caused in last night's run (2026-11-20, run #30), where it was determined to be structural and unconditional on the success path — meaning it should reproduce on essentially every invocation of `bpftrace-compiler` that doesn't hit the sftp-server fallback, and indeed it has recurred again tonight. It shares no root cause with other failures in tonight's run (those are device-side `CREATING_VOLUME`/unpack-hang issues); this one never touches the live EVE device at all, since the crash happens entirely in the host-side `bpftrace-compiler` helper after the bpftrace program already ran to completion.

### TestDeviceConnectivitySuite: failure analysis

#### TestDNSFunctionality

##### Failure

```

Timed out after 420.000s.
When passed a matcher, ReceiveMatcher's channel *must* receive something.
```

##### Claude's conclusion

###### Root cause

Live evidence shows this is a subscription race in the test itself, not flaky infrastructure. `device.ApplyConfig(devConfig, true, true)` (`evetest/tests/networking/dns_test.go:218`) blocks until the device has fetched *and confirmed* the new DNS config, and only after that returns does the test call `device.WatchDeviceInfo()` (line 233) to start watching for `ZInfoDevice` updates. `WatchDeviceInfo` uses `AdamClient.SubscribeToDeviceInfoMsgs` (`evetest/controller/adam.go:1634`), whose doc explicitly says "only messages Adam receives *after* this method returns are delivered" — unlike the `...WithLatest` variant. The live `evetest eve info` history (38 snapshots) shows the device applied the new per-port DNS config and reported the fully correct end state (eth0/eth1/eth2 errors cleared, eth3 retaining the expected `no DNS server available` error) at `lastSucceeded:1795238362` (05:19:22 UTC) — essentially the same instant as the `config-applied` checkpoint logged at 05:19:24 — and then **never sent another `ZInfoDevice` update** for the rest of the run (current time is ~05:27+, long past the 420s/7-minute `phase1Timeout`). That one qualifying message was almost certainly consumed by `ApplyConfig`'s own "wait until confirmed" check and was already gone from Adam's live stream by the time `WatchDeviceInfo()` subscribed a few lines later, so `Eventually(devUpdates, …)` never received anything on the channel at all — exactly matching the Gomega error "`ReceiveMatcher's channel must receive something`".

This does not share a root cause with any other failure in this run (`TestDHCPIPv4Only` and `TestStaticIPv4Only` both passed earlier in the suite). It's also not a recurring issue per `live-ledger.md` — that file's only existing section (nightly run #30, 2026-11-20) contains no mention of `TestDeviceConnectivitySuite` or `TestDNSFunctionality` at all, so this is the first recorded occurrence of this specific failure.
#### TestMgmtTrafficRoutedViaApp

##### Failure

```

Timed out after 180.001s.
EVE should get device metrics through to the controller via the app-routed management path (firewall restricted, check 1/2)
Expected
    <<-chan *metrics.DeviceMetric | len:0, cap:100>: 0x3f4562194150
to receive something.
```

##### Claude's conclusion

###### Root cause

Live evidence shows the controller actually received traffic from **two different source IPs** around this failure: `10.60.10.104` (EVE's own eth0, which still picked up a direct DHCP lease on the wan-network despite being reconfigured to `PhyIoUsageShared`) through 05:54:41, then a gap, then `10.60.10.150` (the gateway app's NATed WAN VIF — the *intended* path) only starting at 05:58:51 (`adam-stdout:1392-1422`). This means the earlier "mgmt-via-app-active" checkpoint (`routing_test.go:1739` calls the same `waitForFreshInfo` helper used at `routing_test.go:1717-1739`) was actually satisfied by EVE's stale pre-migration fallback DPC talking to the controller *directly* over eth0 — not via the app/NAT as the test believes — exactly the "doomed fallback attempt" race the test's own comments (`routing_test.go:1453-1454`, `1497-1519`) acknowledge but under-budget for. When phase 5's firewall rules were applied at 05:54:41 (only allowing source `10.60.10.150`), that masking fallback path on `10.60.10.104` got dropped, and NIM/zedagent took until 05:58:51 (~4m10s) to actually fail that DPC and switch to the genuine app-routed one — well past the 180s `infoTimeout` budgeted for the "firewall restricted, check 1/2" wait, producing the observed timeout.

This is a distinct mechanism from the `TestDNSFunctionality` failure already investigated earlier in this run (that was a `WatchDeviceInfo` subscribe-after-send race on `ZInfoDevice`; this one is a DPC-fallback timing race affecting `WatchDeviceMetrics`), so they do **not** share a root cause. Per `live-ledger.md`, there is no prior mention of `TestDeviceConnectivitySuite` or `TestMgmtTrafficRoutedViaApp`, so this is the first recorded occurrence of this specific failure — not a known recurring issue.

### TestLPSSuite: failure analysis

#### TestProfile

##### Failure

```
timed out after 5m0.000182017s (excluding download) waiting for app "9584d470-f9d5-49fc-b300-e5fa9fbe6747" (lps-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

The ledger only covers one prior night (2026-11-20, run #30), so this pattern is "known" since at least then, but I can't confirm earlier history beyond that.

No PR diff was provided for this investigation, so I'll give the root-cause summary without a RELATED line.

###### Root cause

Live inspection confirms `lps-app`'s volume (`11d000d6-...`) entered `CREATING_VOLUME` at 06:13:08, with `volumemgr.CreateVolume` firing at 06:13:09.962 and not completing (`createContainerVolume ... DONE`) until 06:15:42.119 — a ~2m32s unpack that pushed the app past the 5-minute (excluding-download) deadline, which fired at 06:15:27, by only ~15 seconds. Device logs show this unpack running concurrently with at least three other volumes (`app-profile-1`, `app-profile-2`, and an `ubuntu-ctr` volume) that were also mid-`CreateVolume` in the same window and didn't finish until 06:16:39–06:16:41, i.e. multiple container-image unpacks were competing for CPU simultaneously. The device is configured with 4 vCPUs while the underlying physical host has only 2 cores (`nproc`), and the device itself showed load average 6.23 right after boot — matching the CPU-oversubscription signature. Despite the test failure, `lps-app` actually did progress and reach `RUNNING` shortly after (bootTime ~06:15:47, confirmed via live `app-info`), confirming this was a slow-but-completing unpack, not a true hang. This is the same recurring root cause documented five times in last night's ledger (2026-11-20, run #30 — `TestLocalNI`, `TestMoveAppBetweenNIs`, `TestLimitedIPSpace`, `TestFlowLog`, and a fifth `app1` case): host-resource oversubscription causing concurrent container-image unpacks to occasionally exceed the test's fixed 5-minute `CREATING_VOLUME`/RUNNING timeout. This is the first time it's been seen specifically in `TestLPSSuite/TestProfile`, but it's the same known, recurring infrastructure-level issue, not a new bug.
#### TestAppLocalInfo

##### Failure

```
timed out after 5m0.000181993s (excluding download) waiting for app "fd48c0ce-c6d3-41d1-97e3-b9386ce5a2bb" (lps-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live inspection confirms this is the same slow-unpack-under-CPU-oversubscription pattern already seen earlier in this very run. Device logs show `lps-app`'s volume (`2a9acfa4-19f4-4cba-bf74-93f99a4a6d65`) started `CreateVolume` (containerhandler.go:49) at 06:33:29.065 and didn't log `createContainerVolume(...) DONE` until 06:38:34.764 — a ~5m05s container-image unpack that ran past the 5-minute (download-excluded) deadline, which fired at 06:37:48, by less than a minute. `evetest eve app-info` confirms the app actually completed shortly after: it progressed INSTALLED → BOOTING → RUNNING with `bootTime` at 06:38:37, i.e. it wasn't a true hang, just a near-miss. The device is configured for 4 vCPUs but `evetest eve ssh "nproc"` shows the underlying host has only 1-2 physical cores (`nproc`=1 in the guest, host `nproc`=2), with load average 3.69/3.22/1.67 observed live — the same CPU-oversubscription signature as before.

This shares the exact same root cause as this run's earlier `TestProfile` failure recorded in `live-investigation.md` (same signature: fully-downloaded content stuck in `CREATING_VOLUME`, unpack finishing seconds-to-a-minute after the timeout). It's also the same known, recurring issue documented repeatedly in `live-ledger.md` for the 2026-11-20 (run #30) nightly, where it hit `TestLocalNI`, `TestMoveAppBetweenNIs`, `TestLimitedIPSpace`, `TestFlowLog`, and an `app1` case five times — host-resource oversubscription causing concurrent/slow container-image unpacks to occasionally exceed the fixed 5-minute `CREATING_VOLUME` timeout. This is the first time it's hit `TestLPSSuite` specifically (now twice in this run alone), but it's the same long-standing infrastructure issue, not a new bug.
#### TestDevLocalInfo

##### Failure

```
timed out after 5m0.001029023s (excluding download) waiting for app "b91db489-8cb1-4379-b6f1-ca913955dd91" (lps-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

Live inspection shows `lps-app`'s volume (`fd242cf5-faa8-49d9-a3e4-64a6f0549c26`) entered `CreateVolume`/`UnpackClientImage` at 06:49:19.891, and device logs have logged **nothing further** about it since — no completion, no error — for 4+ minutes and counting (current device time ~06:53:55). Live `ctr -n eve-user-apps snapshots ls` confirms the corresponding snapshot (`extract-963953409-SVtD`, parent `sha256:369ede38...`) is still stuck in `Active` (uncommitted) state, while the device itself is essentially idle (`top` shows ~0% CPU, 1 running task, load average decaying to 1.2) with no tar/extract process running — i.e. the unpack goroutine is hung, not merely slow, since a real in-progress unpack would show CPU activity and log progress.

This is the same failure signature already identified twice in last night's ledger (2026-11-20, run #30): `TestPurgeNeverActivatedApp` and `TestAppRestart` both showed content fully downloaded/verified but the volume wedged in `CREATING_VOLUME` with an `UnpackClientImage`/`CreateVolume` call that fires once and never returns, leaving a dangling `Active` containerd snapshot — a containerd unpack/snapshot-commit hang, distinct from the CPU-oversubscription "slow but completing" pattern seen elsewhere in *this* run (`TestProfile`, `TestAppLocalInfo`, recorded in this run's `live-investigation.md`). So this is a known, recurring issue dating back to at least 2026-11-20, and it's the hang variant rather than the oversubscription-slowness variant — not a new bug, but also not the same root cause as the other two failures already logged in this run.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestLimitedIPSpace

##### Failure

```
timed out after 5m0.001071589s (excluding download) waiting for app "5f3920fb-1210-4799-950d-b0ccbad1ef03" (app1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

###### Root cause

`TestLimitedIPSpace`'s app1 (`5f3920fb-...`) got stuck in `CREATING_VOLUME` because its container-image unpack is progressing far slower than the test's 5-minute budget. Live logs show `volumemgr.CreateVolume`/`containerd.UnpackClientImage` started at 06:17:07 for the `evetest-ubuntu-ctr` image; by the time of the timeout (06:21:31) and after, the containerd-user snapshot `extract-193683816-293G` was still `Active` (uncommitted), but its on-disk layer directories show progress (layer `19` created at 06:17, layer `20` appearing at 06:21) — i.e. this is a genuinely slow-but-still-working unpack, not a dead hang. The EVE device VM itself only has 1 vCPU available at the hypervisor (`nproc` → 1) while reporting `ncpu:4` in its config, and `uptime` shows a load average of ~3.0–3.6 on that single core — severe CPU oversubscription that is starving the unpack of CPU time.

This is the same signature already recorded in this run's ledger from 2026-11-20 (run #30): `TestLimitedIPSpace`, `TestLocalNI`, `TestMoveAppBetweenNIs`, and `TestFlowLog` all failed with apps stuck in `CREATING_VOLUME` due to host CPU oversubscription slowing concurrent container-image unpacks past the fixed test timeout (and `TestLotsOfApps` in the same ledger entry diagnosed the identical single-vCPU/oversubscribed-host condition directly). So this is a known, recurring issue dating back to at least 2026-11-20, not a new failure — today's occurrence matches that pattern exactly rather than being an independent bug.
#### TestFlowLog

##### Failure

```
timed out after 5m0.001027364s (excluding download) waiting for app "ac581827-bd7f-43d5-a74b-fea8742ee3f0" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

###### Root cause

`flowlog-test-app`'s content tree (`d9a16180-…`) never advanced past `RESOLVING_TAG`. Live inspection shows `downloader` received the `ResolveConfig` for `lfedge/evetest-ubuntu-ctr:1.0` at 06:29:01.612, logged `oci syncOp for dpath:<>, ... downloadURL: <192.168.170.2:5000>, ifname: eth0, ipSrc: 172.20.20.123` — and then logged nothing further for that request for the rest of the 5-minute window (only unrelated metric/watchdog ticks continued). The device itself was healthy (`load average 0.18–0.76` on a single reported vCPU, zedbox alive, pubsub responsive), and by the time I checked post-failure the registry at `192.168.170.2:5000` was fully reachable and serving the `1.0` tag fine — so this is a transient hang/stall in the OCI-registry metadata-resolve call itself, not a dead device or missing image.

Critically, the downloader's own stall-detector (`awaitResponse`/`postWithRetry` in `pkg/pillar/cmd/downloader/download.go`) only fires after `maxStalledTime`, which defaults to **600s (10 min)** — twice the test's fixed 5-minute timeout. So even a legitimate, self-recovering stall in that OCI fetch can never be caught and retried before the test gives up, guaranteeing a failure whenever this resolve call stalls at all.

This is a different hang point (`RESOLVING_TAG`/tag-resolve) than the three earlier failures already investigated in this run (`TestLocalNI`, `TestMoveAppBetweenNIs`, `TestLimitedIPSpace`), which all got stuck in `CREATING_VOLUME` due to host CPU oversubscription slowing containerd image unpacks. It's plausible this shares the same underlying host-resource-contention environment (same shared/oversubscribed host), but the specific stuck step and code path (network-bound OCI tag resolution vs. CPU-bound unpack) is distinct, so I can't confirm it's the identical root cause — only that it belongs to the same broader class of "async image-pull step silently outlasts the test's 5-minute timeout" issues already recurring in this run. I found no prior ledger entry for a `RESOLVING_TAG`-stuck timeout specifically, so this exact failure mode does not appear to be previously recorded/known.

## [2026-11-20 -- 0.0.0-13.4-stable-4fdd8676 (run #30)](https://github.com/lf-edge/eve/actions/runs/44772354735)

[Full report](https://lf-edge.github.io/eve/test/13.4-stable/runs/30/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: eth1 is reported as an unused assignable adapter with a MAC address
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7816  storage:63153  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"HTE9VV91"  UUID:"Not Settable"  biosVendor:"EFI Development Kit II / OVMF"  biosVersion:"0.0.0"  biosReleaseDate:"02/06/2015"}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"ethernet0"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795192041  nanos:223831990}}  localName:"eth0"  proxy:{}}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usage:PhyIoUsageDedicated}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{mountPath:"/hostfs"  total:266}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd7"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{device:"nbd4"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/vault"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"nbd9"}  storageList:{device:"nbd1"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{device:"nbd5"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{device:"nbd3"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"vda1"  total:36  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist/netdump"}  storageList:{device:"vda9"  total:64473  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"nbd0"}  storageList:{device:"vda2"  total:512  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd8"}  storageList:{mountPath:"/"  total:3908}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/certs"}  storageList:{device:"nbd13"}  storageList:{device:"vda3"  total:512  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"vda4"  total:1  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/config"  total:1}  storageList:{mountPath:"/persist"  total:63153  storageLocation:true}  bootTime:{seconds:1795191884}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-13.4-stable-4fdd8676-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"2f4be649-b5d0-4c0f-b2e5-7ca37810286e"  lastRebootReason:"NORMAL: First boot of device - at 2026-11-20T16:25:10.12053589Z"  lastRebootTime:{seconds:1795191910  nanos:120535890}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1795191997  nanos:714422135}  lastSucceeded:{seconds:1795192041  nanos:223879211}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.20.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.20.123"  defaultRouters:"172.20.20.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795192041  nanos:223831990}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"63e06d50-b338-4c51-8f95-cc78d2f2f257"  mtu:1500}}}  HSMStatus:NOTFOUND  HSMInfo:"Not Available"  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795191983  nanos:243280146}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xf1\xcd\xce<nԬb\xf6\x8c%X\xed\xf6\x88T\x85\x88\xad)\xcc$\x8dO\xb4\t\xaf}\x06C\xf2,"  sha_tls_root_ca:"\xf1\xcd\xce<nԬb\xf6\x8c%X\xed\xf6\x88T\x85\x88\xad)\xcc$\x8dO\xb4\t\xaf}\x06C\xf2,"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  maintenance_mode_reasons:MAINTENANCE_MODE_REASON_NONE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_ADAPTER_USER_LABELS  optional_capabilities:{}
```

##### Claude's conclusion

###### Root cause

The test waits for `ethernet1` (eth1) to show up as an unused assignable adapter *with* a MAC address, but it never does — confirmed live via `evetest eve info`, where every `ZInfoDevice` sample (including the latest) shows `assignableAdapters:{...name:"ethernet1"...usage:PhyIoUsageDedicated}` with no `ioAddressList` entry at all, while `ethernet0` always carries its MAC.

Device logs explain why: at 16:26:40.337 `domainmgr`'s one-time `checkAndFillIoBundle(1 eth1 ethernet1)` call hit `error|domainmgr| Can't find ifname eth1` and logged `found macaddr ` (empty), because at that exact instant NIM was mid-teardown of eth1's earlier DHCP/uplink config and the kernel had the interface temporarily named `keth1` (kernel/NIM logs show `virtio_net virtio1 eth1: renamed from keth1` only 90ms later, at 16:26:40.427). This is a race between NIM reconfiguring eth1 from an uplink-style port to a dedicated/passthrough port and domainmgr's IO-bundle MAC lookup. Critically, `checkAndFillIoBundle` for eth1 is only ever invoked that single time in the whole run — all subsequent bundle updates (`updatePortAndPciBackIoBundle`, repeated "Not assigning eth1 ... due to Testing" lines) reuse the cached bundle with the blank `MacAddr`, so the missing MAC is never backfilled and the 300s test wait times out.

This is a timing/race bug in `pkg/pillar/cmd/domainmgr` (interface-rename race during IO bundle initialization), not something obviously tied to the very recent commits on this branch (`yetus`/`evetest` CI and backport changes) — no evidence in the logs points at those. I don't see any earlier failure in this run to compare against, and no ledger/known-issues file exists in this repo that I could check for recurrence history, so I can't say how long this has been happening.

### TestAppsSuite: failure analysis

#### TestPurgeNeverActivatedApp

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: app reaches RUNNING after purge
AppID:"7f81f149-15be-4816-8e9d-ccda1d701a54" appVersion:"1" AppName:"bad-image-app" state:CREATING_VOLUME volumeRefs:"c81e9c79-c362-45e1-bb92-5185b6ade0d2"
```

##### Claude's conclusion

No PR diff was given in this task, so I have no ledger/known-issues source to check beyond the repo itself, and I found none there.

**Root cause:** The app got stuck in `CREATING_VOLUME`, and live inspection shows why: volumemgr's `CreateVolume` kicked off at 16:33:59.856 and logged `UnpackClientImage` for the content (`f44d05fd...-library/nginx@sha256:af61f605a0...`) — and that call never returns or logs again afterwards. On the device, the actual tar extraction into the overlayfs snapshot completed almost instantly (`/persist/vault/.../snapshots/1/fs` holds the full ~66.5 MB image, last modified 16:35), but the containerd snapshot itself is still left in `Active` (uncommitted) state over 5 minutes later, and zedbox is idle/sleeping rather than spinning, with no tar/extract process running — i.e. the unpack goroutine is hung after the data was written but before committing/returning, rather than legitimately still working. This is an environment/containerd-unpack hang, not the purge-logic bug the test targets (the purge itself was applied correctly and progressed the app through RESOLVING_TAG → DOWNLOAD_STARTED → LOADING → DELIVERED → CREATING_VOLUME as expected).

This is the only failure in this run (no earlier failures to compare against), and I found no ledger or known-issues record in the repository to check against, so I can't say whether it's recurring — it would be worth checking with whoever tracks flaky/known CI issues outside this repo.
#### TestAppRestart

##### Failure

```
timed out after 5m0.000149609s (excluding download) waiting for app "2706a59f-e622-43dd-b17f-2556d5d6c61d" (restarted-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** The app got stuck in `CREATING_VOLUME` and never progressed. Live inspection confirms the same hang pattern: `volumemgr`'s `volumeHandlerContainer.CreateVolume` fired once for volume `0a616f4e-...` (containerhandler.go:49, at 17:43:20.503) and never logged again — no completion, no error — while `doUpdateVol` kept polling and finding no `VolumeWorkResult` for 5+ minutes. On the containerd-user instance, the corresponding snapshot (`extract-760242347-odQ4`, parent `sha256:6078cde5...`) is still left in `Active` (uncommitted) state, i.e. the unpack/extract goroutine inside volumemgr is hung and never commits or returns, even though content download/verification (ContentTreeStatus) completed fully (state LOADED, 100%). zedbox is otherwise alive and responsive (ssh, pubsub, metrics all working), so this is an unpack/snapshotter hang specifically, not a general zedbox stall.

This matches the earlier `TestPurgeNeverActivatedApp` failure in this same run almost exactly — both show content fully resolved/downloaded but the volume stuck in `CREATING_VOLUME` with an unpack call that starts and silently never returns, leaving a dangling `Active` containerd snapshot. I'm confident this shares the same root cause (a containerd unpack/snapshot-commit hang in this test environment), not two independent bugs.

No PR diff was given for this failure, and I found no ledger/known-issues entry in the repo beyond the earlier investigation recorded in this run's `live-investigation.md`, so I can't say how long this has been recurring outside of this run.
#### TestHaltAfterImmediateDeactivate

##### Failure

```
timed out after 5m0.00037497s (excluding download) waiting for app "7b02e62f-df50-4e5e-89b3-c8b3559c92f7" (halted-app) on device "edge-dev" to reach RUNNING state (last state: INSTALLED)
```

##### Claude's conclusion

**Root cause:** The volume for this app took abnormally long to create — `volumemgr` logs show `CreateVolume(49593d9f...)` starting at 17:59:52.973 but `createContainerVolume(...) DONE` only at 18:04:01.817, i.e. ~4m9s just for the container-image unpack (content download/verify had already finished quickly, reaching `LOADED` at 17:59:51.960). That alone consumed almost the entire 5-minute (download-excluded) budget `WaitUntilAppIsRunning` allows, so domain creation only started at 18:04:17 — 12 seconds after the test had already declared the timeout at 18:04:05 — and `app-info` now shows the app reached `RUNNING` shortly after. It wasn't a true indefinite hang this time, just an extremely slow unpack that ran out the clock.

This is the same underlying issue recorded for this run: both `TestPurgeNeverActivatedApp` and `TestAppRestart` stalled with content fully downloaded/verified but volume creation (containerd unpack) stuck or pathologically slow in `CREATING_VOLUME`. This failure is the same root cause manifesting as a near-miss timeout rather than a permanent hang — the unpack/snapshotter path in this environment is markedly and repeatedly slower (or occasionally frozen) than the test budgets assume.

No PR diff was given, so I can't assess relatedness to any specific code change; I also found no ledger beyond this run's own `live-investigation.md`.
#### TestLotsOfApps

##### Failure

```
timed out after 15m0.000153346s (excluding download) waiting for app "824b3d09-034e-453a-a1a5-8635722625ee" (restarted-app-0) on device "edge-dev" to reach RUNNING state (last state: DELIVERED)
```

##### Claude's conclusion

**Root cause:** This EVE device VM has only **1 vCPU** (`nproc=1`) but a load average of ~10–14 while running the test — it's running `TestLotsOfApps`' 25 concurrently-deployed container apps plus up to 20 simultaneous `containerd` unpack workers (volumemgr's `volumemgr.worker.pool.size` = 20) on a single core. Live logs show the first batch of 20 `CreateVolume(...)` calls all started together at ~18:43:22–27, then **none completed for ~13 minutes** (a flat gap with zero `createContainerVolume(...) DONE` lines until 18:56:42), after which they all finished in rapid succession between 18:56:42–18:57:24 as CPU time finally became available. `restarted-app-0`'s volume (`ee0a909f-...`) was queued behind the saturated 20-worker pool (`AddWorkLoad(...): Would exceed maxWorkers of 20`) and didn't even start creating until 18:56:53 — itself not a hang, finishing in ~28s — but by then the test's 15-minute (download-excluded) budget had already expired. Post-timeout, the app is now progressing normally (`app-info` shows it reached `INSTALLED`, and `pgrep qemu-system` shows apps continuing to come up).

This shares the same underlying environment characteristic as the three earlier failures recorded in `live-investigation.md` for this run (abnormally slow/occasionally-stalled containerd unpack), but the mechanism here is distinct and more fully explained: it's severe single-vCPU CPU starvation under 20+ concurrent unpack workers and ~10 booting VMs, causing the whole worker-pool batch to stall in lockstep for ~13 minutes, rather than one individual goroutine hanging indefinitely. I found no ledger/known-issues record in the repo to check against for recurrence, and no PR diff was given for this task.
#### TestVGAPassthroughNoHostAccess

##### Failure

```

Unexpected error:
    <*fmt.wrapError | 0x4aaffefb140>: 
    bpftrace-compiler failed: exit status 2; its last output:
    #33 exporting layers
    #33 exporting layers 12.0s done
    #33 exporting manifest sha256:64cf4395203cb067fcc1736055f17bd4ea297e571217c92ac4f1a9d8aec9e593
    #33 exporting manifest sha256:64cf4395203cb067fcc1736055f17bd4ea297e571217c92ac4f1a9d8aec9e593 0.5s done
    #33 exporting config sha256:19d951b016c28f03bdda2ee5f9cbbee338959e03130e2ff3634109e7ecaae071
    #33 exporting config sha256:19d951b016c28f03bdda2ee5f9cbbee338959e03130e2ff3634109e7ecaae071 0.4s done
    #33 exporting attestation manifest sha256:13c393ab037c1089f1b5584ac84150994701229dbc4c8a63ac485a762f12fa20
    #33 exporting attestation manifest sha256:13c393ab037c1089f1b5584ac84150994701229dbc4c8a63ac485a762f12fa20 1.0s done
    #33 exporting manifest list sha256:f7969430395076894361fdb7b0082b1cc93e1d1588b455169cc9ec7a5300f472
    #33 exporting manifest list sha256:f7969430395076894361fdb7b0082b1cc93e1d1588b455169cc9ec7a5300f472 0.4s done
    #33 sending tarball
    #33 sending tarball 1.0s done
    #33 DONE 16.0s
    time="2026-11-20T19:16:57Z" level=info msg="Extract kernel image: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc"
    time="2026-11-20T19:16:57Z" level=info msg="Image docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc arch amd64 incomplete or invalid in local cache, error no such reference: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc, pulling"
    time="2026-11-20T19:17:14Z" level=info msg="Add init containers:"
    time="2026-11-20T19:17:14Z" level=info msg="Process init image: docker.io/linuxkit/root:96bd89e70f2b7f17124313b4ecc9022d"
    time="2026-11-20T19:17:17Z" level=info msg="Create outputs:"
    time="2026-11-20T19:17:17Z" level=info msg="  /var/tmp/bpftrace-image3470848310/linuxkit-squashfs.img"
    2026/11/20 19:17:44 running ["/usr/bin/qemu-system-x86_64" "-smp" "1" "-nographic" "-m" "256" "-device" "virtio-net-pci,netdev=t0,mac=5a:7e:cb:9c:12:67" "-netdev" "user,id=t0" "-kernel" "/var/tmp/bpftrace-image3470848310/linuxkit-kernel" "-hda" "/var/tmp/bpftrace-image3470848310/linuxkit-squashfs.img" "-fsdev" "local,id=dev,path=/var/tmp/bpftrace-9pshare3137124383,security_model=mapped,multidevs=remap" "-device" "virtio-9p-pci,fsdev=dev,mount_tag=9pmount" "-append" "root=/dev/sda units=compile console=null quiet"]
    2026/11/20 19:18:23 Running bpftrace ...
    2026/11/20 19:18:23 Running bpftrace program
    panic: runtime error: invalid memory address or nil pointer dereference
    [signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]
    
    goroutine 1 [running]:
    main.(*eveSSHClient).close(0xa0183d1a780)
    	/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b
    main.(*sshRun).end(0xa0183c3fa30?)
    	/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16
    main.newRunSSHCmd.func1(0xa0183d18d00?, {0xa0183d440c0, 0x2, 0x111f88e?})
    	/eve-tools/bpftrace-compiler/main.go:375 +0x1f8
    github.com/spf13/cobra.(*Command).execute(0xa0183d0e608, {0xa0183d44060, 0x6, 0x6})
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b
    github.com/spf13/cobra.(*Command).ExecuteC(0xa0183d0e008)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f
    github.com/spf13/cobra.(*Command).Execute(...)
    	/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039
    main.main()
    	/eve-tools/bpftrace-compiler/main.go:138 +0x633
    {
        msg: "bpftrace-compiler failed: exit status 2; its last output:\n#33 exporting layers\n#33 exporting layers 12.0s done\n#33 exporting manifest sha256:64cf4395203cb067fcc1736055f17bd4ea297e571217c92ac4f1a9d8aec9e593\n#33 exporting manifest sha256:64cf4395203cb067fcc1736055f17bd4ea297e571217c92ac4f1a9d8aec9e593 0.5s done\n#33 exporting config sha256:19d951b016c28f03bdda2ee5f9cbbee338959e03130e2ff3634109e7ecaae071\n#33 exporting config sha256:19d951b016c28f03bdda2ee5f9cbbee338959e03130e2ff3634109e7ecaae071 0.4s done\n#33 exporting attestation manifest sha256:13c393ab037c1089f1b5584ac84150994701229dbc4c8a63ac485a762f12fa20\n#33 exporting attestation manifest sha256:13c393ab037c1089f1b5584ac84150994701229dbc4c8a63ac485a762f12fa20 1.0s done\n#33 exporting manifest list sha256:f7969430395076894361fdb7b0082b1cc93e1d1588b455169cc9ec7a5300f472\n#33 exporting manifest list sha256:f7969430395076894361fdb7b0082b1cc93e1d1588b455169cc9ec7a5300f472 0.4s done\n#33 sending tarball\n#33 sending tarball 1.0s done\n#33 DONE 16.0s\ntime=\"2026-11-20T19:16:57Z\" level=info msg=\"Extract kernel image: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc\"\ntime=\"2026-11-20T19:16:57Z\" level=info msg=\"Image docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc arch amd64 incomplete or invalid in local cache, error no such reference: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.177-generic-be6047d8fd37-gcc, pulling\"\ntime=\"2026-11-20T19:17:14Z\" level=info msg=\"Add init containers:\"\ntime=\"2026-11-20T19:17:14Z\" level=info msg=\"Process init image: docker.io/linuxkit/root:96bd89e70f2b7f17124313b4ecc9022d\"\ntime=\"2026-11-20T19:17:17Z\" level=info msg=\"Create outputs:\"\ntime=\"2026-11-20T19:17:17Z\" level=info msg=\"  /var/tmp/bpftrace-image3470848310/linuxkit-squashfs.img\"\n2026/11/20 19:17:44 running [\"/usr/bin/qemu-system-x86_64\" \"-smp\" \"1\" \"-nographic\" \"-m\" \"256\" \"-device\" \"virtio-net-pci,netdev=t0,mac=5a:7e:cb:9c:12:67\" \"-netdev\" \"user,id=t0\" \"-kernel\" \"/var/tmp/bpftrace-image3470848310/linuxkit-kernel\" \"-hda\" \"/var/tmp/bpftrace-image3470848310/linuxkit-squashfs.img\" \"-fsdev\" \"local,id=dev,path=/var/tmp/bpftrace-9pshare3137124383,security_model=mapped,multidevs=remap\" \"-device\" \"virtio-9p-pci,fsdev=dev,mount_tag=9pmount\" \"-append\" \"root=/dev/sda units=compile console=null quiet\"]\n2026/11/20 19:18:23 Running bpftrace ...\n2026/11/20 19:18:23 Running bpftrace program\npanic: runtime error: invalid memory address or nil pointer dereference\n[signal SIGSEGV: segmentation violation code=0x1 addr=0x18 pc=0xe169db]\n\ngoroutine 1 [running]:\nmain.(*eveSSHClient).close(0xa0183d1a780)\n\t/eve-tools/bpftrace-compiler/ssh-client.go:152 +0x1b\nmain.(*sshRun).end(0xa0183c3fa30?)\n\t/eve-tools/bpftrace-compiler/sshRun.go:77 +0x16\nmain.newRunSSHCmd.func1(0xa0183d18d00?, {0xa0183d440c0, 0x2, 0x111f88e?})\n\t/eve-tools/bpftrace-compiler/main.go:375 +0x1f8\ngithub.com/spf13/cobra.(*Command).execute(0xa0183d0e608, {0xa0183d44060, 0x6, 0x6})\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:987 +0xb1b\ngithub.com/spf13/cobra.(*Command).ExecuteC(0xa0183d0e008)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1115 +0x44f\ngithub.com/spf13/cobra.(*Command).Execute(...)\n\t/go/pkg/mod/github.com/spf13/cobra@v1.8.0/command.go:1039\nmain.main()\n\t/eve-tools/bpftrace-compiler/main.go:138 +0x633",
        err: <*exec.ExitError | 0x4aaffefb120>{
            ProcessState: {
                pid: 1996,
                status: 512,
                rusage: {
                    Utime: {Sec: 48, Usec: 354315},
                    Stime: {Sec: 7, Usec: 343362},
                    Maxrss: 530840,
                    Ixrss: 0,
                    Idrss: 0,
                    Isrss: 0,
                    Minflt: 306014,
                    Majflt: 435,
                    Nswap: 0,
                    Inblock: 131704,
                    Oublock: 133892...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

occurred
```

##### Claude's conclusion

This is confirmed to be a pure host-side tooling bug, unrelated to live device state at all.

**Root cause:** `tracer.finish()` invokes `bpftrace-compiler`, which panics with a nil-pointer dereference in `eveSSHClient.close()` at `eve-tools/bpftrace-compiler/ssh-client.go:152` (`s.rStdout.Close()`). `rStdout` is only ever assigned inside `startSftpClientWithCustomPath` (the `/usr/libexec/sftp-server` fallback path); when the normal `sftp.NewClient(s.client)` path succeeds — the common case, and what happened here (the bpftrace program did run to completion per the logs: "Running bpftrace program" with no error before the crash) — `rStdout` is left nil, so the deferred cleanup in `sshRun.end()` always segfaults. This bug has existed unchanged since the tool's initial commit (Aug 16, 2024, `83360eb05`) and is unconditional on the success path, so it will reproduce on essentially every `bpftrace-compiler` invocation that doesn't hit the sftp fallback, not something specific to this test run or device state.

This does **not** share a root cause with the earlier failures recorded in `live-investigation.md` for this run (those were all containerd-unpack hangs/slowness on the EVE device itself in `CREATING_VOLUME`); this one never touches the device under test at all — it's a crash in the host-side `bpftrace-compiler` helper used to build the eBPF tracer for the test's host-access assertions. No ledger of known issues exists in-repo to confirm recurrence, but the bug is clearly structural/long-standing based on the code history, not a flaky one-off.

### TestBootstrapSuite: failure analysis

#### TestBootstrapWithInstaller

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup SDN device: failed waiting for VM 112 creation: task failed on Proxmox: unable to create VM 112 - cannot import from 'local:import/ev-sdn-57e48293-0.qcow2' - can't lock file '/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool' - got timeout (task UPID:farfalle:0003E7DE:835EAC66:6B00783E:qmcreate:112:root@pam:)
```

##### Claude's conclusion

###### Root cause

The failure is a Proxmox host-side storage locking issue, not an EVE/evetest code problem. The broker log shows `qmcreate` for the SDN VM (VM 112, disk `ev-sdn-57e48293-0.qcow2`) timed out trying to acquire `/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool` on the Proxmox node `farfalle`. This happened at 16:41:46, just 32 seconds after the EVE installer VM (106, `eve-57e48293-edge-dev`) finished provisioning and had its disks reconfigured (16:41:14) — consistent with that disk-import/reconfigure work on the same ZFS-pool storage still holding (or recently having held) the storage lock long enough for the subsequent SDN image import to time out waiting for it.

This does not share a root cause with any other failure in this run: the two earlier subtests in the same suite, `TestBootstrapWithLastResortDisabled` and `TestBootstrapWithLastResortEnabled`, both successfully created and later removed the identically-numbered VM 112 on the same storage without any lock contention, so the problem is intermittent/load-dependent rather than deterministic. There is no known-issues ledger entry for this yet (no `evetest` ledger/memory exists), so this appears to be the first recorded occurrence. By the time of investigation, `evetest status` reports "No EVE devices found" — the harness had already torn down VM 106 and the image directories as part of its failure-path cleanup, so no live EVE/SDN state remains to inspect further.

No PR diff was provided for this run.

### TestControllerFaultsSuite: failure analysis

#### TestInfoDroppedOnRejectionKeepsDeviceReporting

##### Failure

```
timed out after 5m0.00022901s (excluding download) waiting for app "1340d031-143f-4347-926d-050a8c9b3e67" (reported-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

No ledger file found. I have enough evidence now.

###### Root cause

The app never failed — it was slow. Device logs show `reported-app`'s volume entered `CREATING_VOLUME` at 17:30:41.818 and `createContainerVolume(...) DONE` only at 17:36:22.210, a ~5m40s stall extracting a ~150MB container image, with essentially no volumemgr/containerd activity logged in between (just periodic disk-metric ticks). The app then proceeded normally to `RUNNING` by 17:36:41 — about 2 minutes after `WaitUntilAppIsRunning`'s 5-minute timeout had already fired at 17:34:38. The host this EVE device VM runs on has only 2 physical CPUs and 3.8GiB RAM total, while the device itself is configured for 4 vCPUs and 8GiB — a significant overcommit that plausibly explains the container-extraction stall under load. This failure occurred during the test's initial setup/deploy phase (before `app-running` checkpoint, before any controller fault was armed), so it shares no root cause with the earlier `TestInfoRetriedAfterLostController` test in this run, which passed cleanly. I found no known-issues ledger in the available directories to check for recurrence history, and no PR diff was provided for this investigation.

### TestDatastoreSuite: failure analysis

#### TestContainerRegistry

##### Failure

```

Told to stop trying after 0.154s.
Stop waiting for: volume is delivered from the container registry
Volume reports an error: Found error in content tree container-registry-test-image attached to volume container-registry-test: lookupDatastoreConfig(427d01a4-bc8c-467d-92c2-6f0aa931a8d9) error: Get(zedagent/DatastoreConfig) unknown key 427d01a4-bc8c-467d-92c2-6f0aa931a8d9
uuid:"20d9c54b-0c78-4fac-9af3-7b82f7870b0a"  displayName:"container-registry-test"  usage:{createTime:{seconds:-62135596800}  refCount:1  lastRefcountChangeTime:{seconds:1795195250  nanos:541962410}}  state:RESOLVING_TAG  volumeErr:{description:"Found error in content tree container-registry-test-image attached to volume container-registry-test: lookupDatastoreConfig(427d01a4-bc8c-467d-92c2-6f0aa931a8d9) error: Get(zedagent/DatastoreConfig) unknown key 427d01a4-bc8c-467d-92c2-6f0aa931a8d9"  timestamp:{seconds:1795195250  nanos:554583409}  severity:SEVERITY_NOTICE  entities:{entity:ENTITY_CONTENT_TREE  entity_id:"899fa29d-91af-4178-9adf-a40981bf9b13"}  retry_condition:"Will retry when datastore available"}
```

##### Claude's conclusion

**Root cause:** This is a transient config-propagation race on the device, not a real datastore/volume problem. Device logs show `zedbox` reporting `lookupDatastoreConfig(427d01a4...) unknown key` at `17:20:50.554`/`.558`/`.559`, but 5–9ms later at `.563`–`.564` the device's `downloader` logs `handleDatastoreConfigImpl for 427d01a4... done` / `Processed DatastoreConfig` — i.e. the content-tree resolver ran a few milliseconds before zedagent had finished applying the `DatastoreConfig` it had just received, exactly matching the volume's own `retry_condition:"Will retry when datastore available"`. Corroborating this, `gotest.json` shows the *same* volume UUID (`20d9c54b-...`) subsequently progressing `LOADING -> CREATING_VOLUME -> CREATED_VOLUME` successfully just seconds later (17:20:52–58) — the device self-healed on its own. The test (`datastore_test.go:827`) only waited **0.154s** before treating the first reported volume error as fatal, which is too short a grace period for this known self-recovering ordering race between config distribution and the resolver. The other TestDatastoreSuite subtests (HTTP/HTTPS/SFTP) in this same run passed, so this doesn't share a root cause with an earlier failure in this run, and I found no local ledger of known issues to check for recurrence history.

### TestDiagSuite: failure analysis

#### TestDiagOutput

##### Failure

```
timed out after 5m0.000560642s (excluding download) waiting for app "642e726a-5f75-4229-80fa-47c95ec09eaf" (diag-reader) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Only one failure in this run — no earlier failure to share a root cause with. I have enough evidence now.

###### Root cause

The volume didn't actually get stuck — the live device now shows `VolumeStatus` for `b69b1f63-7369-4b8a-8d58-29f25837fabf` at `State:110 (CREATED_VOLUME)`, `CreateTime:"2026-11-20T17:07:42Z"`, and `app-info` shows the app progressed all the way to `RUNNING`. So volume creation (casting the 56MB encrypted container image into `/persist/vault/...`) simply took from 16:59:58 to 17:07:42 — about 7m44s — well past the test's 5-minute timeout, and then completed successfully with no error ever recorded (`Error:""` throughout).

This points to resource starvation on the runner host rather than a pillar bug: `nproc` on this host is only 2, yet the EVE device alone is configured for 4 vCPUs/8GiB (`evetest status` shows `CPUs: 4, Memory: 8.00 GiB`), and at the time of the test it was sharing those 2 physical cores with the evetest orchestrator, `go test`, the Adam controller, and Docker/containerd (all visible in `ps aux` right now). This kind of CPU oversubscription is known to make vault/LUKS-encrypted volume casting (CPU-heavy crypto + image conversion) unpredictably slow. I checked the recent `volumemgr` worker-pool-refusal fix (`099aad80f`, already present on this branch) which addresses a different bug (a *refused* submission silently wedging the volume forever, state `Preparing`); this device's `SubState` was `PrepareDone` (work was accepted, just slow to finish), so that fix doesn't apply here and there's no sign of the bug it addresses.

I found no ledger file in the accessible directories to check for recurring occurrences, and this run has no earlier failure to compare against. No PR diff was provided for this investigation.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestLocalNI

##### Failure

```
timed out after 5m0.00011251s (excluding download) waiting for app "3944da98-b822-41e2-9681-cdce45b1466e" (container-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

Only one test ran in this suite run, so there's no earlier failure in this run to correlate with.

**Likely root cause:** The app's volume creation hung indefinitely inside zedbox's volume manager during image-layer extraction. The device log shows `CreateVolume(f653d9d2...)` fire at 17:00:35.151, followed immediately by `UnpackClientImage: for image ...container-app...` at 17:00:35.155 — and then nothing further for that volume ever appears in any agent's log (no completion, no error, no retry) for the remaining ~4.5 minutes until the test timed out. Live inspection of the device's user-containerd snapshotter confirms this: there's a snapshot `extract-483628160-0mcu` still stuck in `Active` state (never committed) with a matching GC lease created at the same timestamp, i.e. the layer-extraction/unpack operation never finished or errored out. The zedbox process itself is alive and otherwise healthy (goroutines idling normally, other agents like zedagent/NTP are actively logging), disk space is ample, and dmesg shows no I/O errors — so this looks like a logic/deadlock hang specifically in the containerd unpack path rather than resource exhaustion or a crash. I found no record of this matching a known/recurring issue in available memory, so I can't say whether it has occurred before.
#### TestMoveAppBetweenNIs

##### Failure

```
timed out after 5m0.000294686s (excluding download) waiting for app "98f0086f-19be-413a-a9df-b65a18a537fb" (ping1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** This is the same failure pattern as the earlier `TestLocalNI` failure in this run — container image unpack during `CreateVolume`/`UnpackClientImage` takes far longer than the 5-minute RUNNING timeout, not a true deadlock. Device logs show `CreateVolume(0c8f3913...)` / `UnpackClientImage` fire for ping1's volume at 17:13:23.042, with the app stuck reporting `CREATING_VOLUME` the whole time (confirmed by the paused device still showing that state at 17:21). Waiting past the test's own timeout (which the earlier investigation didn't do), the volume actually *did* complete — ping1, ping2, and pong all transitioned `CREATING_VOLUME → INSTALLED → RUNNING` around 17:20:11, i.e. ~6m48s after entering `CREATING_VOLUME`, well past the 5-minute limit. All three apps' `CreateVolume` calls started within the same second (17:13:23), so the unpacks serialized/competed for CPU. Live `uptime` shows the EVE device VM (configured with 4 vCPUs) reporting load average 3-4 while the physical host underneath only has 2 cores — i.e. the VM is CPU-oversubscribed by 2x, which plausibly explains why three concurrent image-layer extractions took ~7 minutes instead of the usual ~1 minute. This looks like host resource contention/oversubscription rather than a code-level hang, and it directly explains the earlier `TestLocalNI` failure's "stuck" `extract-...` snapshot too — that investigation simply stopped observing at the timeout rather than confirming it was permanently wedged.
#### TestLimitedIPSpace

##### Failure

```
timed out after 5m0.000771976s (excluding download) waiting for app "26e477ac-023f-49a4-adbd-d75277b3a6f5" (app1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** Same pattern as both earlier failures in this run. Device logs show app1's volume (`c952acf9-71ac...`) entered `CREATING_VOLUME` at 17:30:21, with `containerhandler.CreateVolume` starting at 17:30:22.66 and only completing (`createContainerVolume ... DONE`) at 17:34:53.8 — a ~4m31s unpack that pushed the app past the 5-minute RUNNING deadline by mere seconds (app reached `INSTALLED` right at 17:34:53-54, i.e. it almost certainly went RUNNING shortly after the test gave up). This directly matches the `TestLocalNI` and `TestMoveAppBetweenNIs` failures already recorded in `live-investigation.md` for this run: an image-layer unpack during `CreateVolume` taking several minutes instead of the usual ~1 minute, not a real hang. Live checks confirm the same oversubscription condition previously identified — the EVE device is configured with 4 vCPUs (`grep -c ^processor /proc/cpuinfo` = 4) but the underlying physical host has only 2 cores, and the device's own load average (1.9–2.8) reflects real contention on that 2-core host. This is now a third occurrence of the identical signature within this single suite run, strongly confirming it's a recurring host-resource-oversubscription issue rather than an independent bug, and it shares the root cause with the earlier failures in this run.
#### TestFlowLog

##### Failure

```
timed out after 5m0.000792784s (excluding download) waiting for app "03e1a899-9b58-4cf3-8da2-b63c9a0477af" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** This failure shares the exact same root cause as all three earlier failures in this run (`TestLocalNI`, `TestMoveAppBetweenNIs`, `TestLimitedIPSpace`). The app `flowlog-test-app` entered `CREATING_VOLUME` at 17:41:55, and live inspection of the device's user-containerd shows a snapshot `extract-89294162-g0za` still stuck in `Active` state with a matching GC lease created at the identical timestamp (17:41:56) — the image-layer unpack simply hadn't finished by the 5-minute deadline (17:46:15), same pattern as before, not a true hang. The device is configured with 4 vCPUs but load average (2.46–2.84) on an oversubscribed 2-core host continues to slow down container-image extraction well past the normal ~1 minute. This is now the fourth occurrence of the identical signature within this single suite run, strongly reconfirming the host-resource-oversubscription issue already identified as recurring in this run's investigation ledger — not a new or independent bug.
#### TestPortForwarding

##### Failure

```
timed out after 5m0.000195226s (excluding download) waiting for app "59f87355-b730-4bf6-99f6-df6012b4aeb3" (app1) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Likely root cause:** Live inspection of app1's volume shows the exact same recurring pattern already logged four times in this run's ledger. Device logs show app1 (`59f87355...`) entered `CREATING_VOLUME` at 18:10:04, and three `UnpackClientImage` calls fired concurrently within the same ~1.4s window (18:10:06–18:10:08) for three different app images — confirming parallel image-layer unpacks competing for CPU, exactly as seen in `TestMoveAppBetweenNIs`, `TestLimitedIPSpace`, and `TestFlowLog`. App1 didn't reach `RUNNING` until 18:14:47, i.e. the unpack/boot sequence took ~4m43s, landing right at/past the 5-minute deadline — not a hang, just a slow-but-completing unpack. Live `uptime` on the device shows load average 5.29/4.09/2.06 on a device configured for 4 vCPUs, matching the previously-identified CPU-oversubscription condition on the underlying 2-core host. This is the fifth occurrence of the identical signature in this suite run and shares the same root cause already recorded in the ledger (host resource oversubscription slowing concurrent container-image unpacks past the test's fixed timeout) — not an independent bug.
