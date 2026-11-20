# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

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


