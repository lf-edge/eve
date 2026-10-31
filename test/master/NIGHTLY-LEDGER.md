# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

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
