# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

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


