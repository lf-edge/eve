# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

## [2026-11-22 -- 0.0.0-17.0-stable-c6776e7c (run #37)](https://github.com/lf-edge/eve/actions/runs/44969326123)

[Full report](https://lf-edge.github.io/eve/test/17.0-stable/runs/37/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:4, cap:4>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15abc60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204538, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x80dbdb2c830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e16a0,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x80dbdb192c0>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescripto...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 5
```

##### Claude's conclusion

Live evidence confirms the exact same signature already in the ledger: `evetest eve app-info passthrough-app` shows the app reach `state:RUNNING` with `assignedAdapters:{name:"ethernet1", members:"eth1"}` correctly populated, but its `network:` list remains stuck at 4 entries (`vif0`, `newvif1`, `newvif2`, `newvif3`) — `ethernet1` never gets added as a 5th network entry, matching the `len:4`/`to have length 5` test failure exactly.

**Root cause:** `zedagent`'s app-info/metrics publisher builds `ZInfoApp.Network` only from virtual VIFs and never merges passthrough (`IoAdapterList`) adapters. The fix (commit `979ea453c`, "zedagent: report passthrough NICs in app info and metrics") exists on master but is confirmed **absent** from `17.0-stable` (`git merge-base --is-ancestor` returns ABSENT against current HEAD). This is a known, recurring, unfixed backport gap already documented in `live-ledger.md` as occurring on 2026-11-17, 18, 19, 20, and now 21 — this is at least the sixth consecutive night this exact issue has reproduced. No PR diff was given for this run, so no relatedness judgment is needed.
#### TestNetworkAdapterPassthroughChange

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:1, cap:1>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15abc60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204538, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x80dbdb2c830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e16a0,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x80dbdb192c0>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescripto...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 2
```

##### Claude's conclusion

###### Root cause

This is the same bug as the already-investigated `TestNetworkAdapterPassthrough` failure in this same run, and it's the same known/recurring gap documented in the ledger (seen nightly since at least 2026-11-17 through today).

Evidence from `gotest.json` for `TestNetworkAdapterPassthroughChange`: the test deploys app `passthrough-app`, lets it reach RUNNING with just one virtio NIC (`vif0`), then pushes config version 3 adding adapter `eth1` as a passthrough device. The app correctly restarts (HALTED→BOOTING→RUNNING) and the in-guest `ip addr` output confirms `eth1` is actually attached and up inside the VM. However, from `02:10:54` through `02:14:57` (180s of polling), zedagent's reported app info (`network[0]`) never shows more than the original `vif0` entry — the passthrough `eth1` adapter is never added to `ZInfoApp.Network`, so the test's `Eventually(...).Should(HaveLen(2))` at `nicchange_test.go:177` times out.

This matches exactly the root cause already identified for the earlier `TestNetworkAdapterPassthrough` failure in this run: zedagent's app-info/metrics publisher only builds `ZInfoApp.Network` from virtual VIFs and never merges passthrough (`IoAdapterList`) adapters — a fix for this exists on master (commit `979ea453c`) but is absent from `17.0-stable`. Per the ledger this has been failing nightly since at least 2026-11-17, so this is the same long-standing backport gap, not a new or distinct bug.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7797  storage:42022  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"9IFMELHA"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd13"}  storageList:{device:"nbd0"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"nbd7"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"vda9"  total:43001  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{mountPath:"/persist/log"}  storageList:{device:"nbd4"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/"  total:3898}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"nbd5"}  storageList:{mountPath:"/config"  total:5}  storageList:{mountPath:"/persist/clear"}  storageList:{mountPath:"/hostfs"  total:280}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{mountPath:"/persist/ingested"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{device:"nbd14"}  storageList:{device:"nbd12"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/persist"  total:42022  storageLocation:true}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{device:"nbd1"}  storageList:{device:"nbd3"}  storageList:{device:"nbd6"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"nbd8"}  storageList:{device:"nbd2"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/newlog"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  bootTime:{seconds:1795312845}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-pr44969326123-17.0.1-lts-80-gc6776e7c-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"de2a614b-e947-44ed-8819-99aaaf88b65b"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-pr44969326123-17.0.1-lts-80-gc6776e7c-kvm-amd64 at 2026-11-22T02:00:03.208730948Z\n"  lastRebootTime:{seconds:1795312803  nanos:221794146}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795312950  nanos:41165586}  lastFailed:{seconds:1795312966  nanos:557200585}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795312966  nanos:557079494}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"e93e7b6b-e527-4591-9b68-7d4140b47d3e"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795312950  nanos:41165586}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795312772  nanos:134636748}  lastFailed:{seconds:1795312981  nanos:619756350}  lastSucceeded:{seconds:1795312911  nanos:963306180}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795312986  nanos:961560654}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"e93e7b6b-e527-4591-9b68-7d4140b47d3e"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795312772  nanos:134636748}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795312986  nanos:961560013}  severity:SEVERITY_ERROR}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795312867  nanos:503009992}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xc8e\x92\x95t\n\xf6z\xc4gW%𤋮\x1f;\xe4,\"\xc9\x0f$\xad\xc2\xc0Vl\x03e,\xda"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

This matches the same known, recurring pattern documented in the ledger.

**Root cause:** Live evidence on the paused device confirms the identical oscillation documented repeatedly in the ledger: `DevicePortConfigList/global.json` shows the new cycle-1 DPC (TimePriority `02:02:30`, `PNAC.Enabled:false`, the disable/pre-auth-VLAN step) never succeeding (`LastSucceeded: 0001-01-01`) because it can't reach the controller from the pre-auth VLAN (`src IP 172.20.20.123`, `context deadline exceeded`), so `dpcmanager`/`CurrentIndex:1` falls back to the prior DPC (TimePriority `01:59:32`, still `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`), which itself now fails with "No certificate enrollment status found for SCEP profile" since the enrolled cert was already removed as part of cycle 1. `eth0` is still live at `172.20.10.123/24`, confirming the port never actually moved to the pre-auth VLAN — exactly the condition the test's `Eventually` is stuck waiting for at 300s. This is the same `TestPNACWithoutProxy` PNAC-disable/DPC-fallback oscillation recorded in `live-ledger.md` as a known, recurring, unresolved issue first seen 2026-11-17 and repeated on 2026-11-18, 2026-11-19, and 2026-11-20/21 — tonight is at least the fifth consecutive occurrence, not a new regression. No PR diff was provided, so no relatedness judgment applies.
#### TestPNACWithProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7797  storage:42022  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"O0ZELVGU"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{device:"nbd3"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{device:"nbd8"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/hostfs"  total:280}  storageList:{device:"nbd9"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/config"  total:5}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"nbd4"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{device:"nbd7"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-1.dat"}  storageList:{device:"vda"  total:65536}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/log"}  storageList:{device:"nbd13"}  storageList:{device:"nbd2"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-1.dat"}  storageList:{mountPath:"/persist/ingested"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/"  total:3898}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/status"}  storageList:{device:"nbd1"}  storageList:{device:"vda9"  total:43001  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"nbd0"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"nbd5"}  storageList:{mountPath:"/persist/tmp"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/persist"  total:42022  storageLocation:true}  storageList:{device:"nbd11"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd10"}  bootTime:{seconds:1795315058}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-pr44969326123-17.0.1-lts-80-gc6776e7c-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"d15d505a-ec58-4d4b-9169-bd7fa68f8326"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-pr44969326123-17.0.1-lts-80-gc6776e7c-kvm-amd64 at 2026-11-22T02:36:56.858017803Z\n"  lastRebootTime:{seconds:1795315016  nanos:849759130}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795315156  nanos:100651245}  lastFailed:{seconds:1795315172  nanos:864597716}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795315172  nanos:864463122}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"54a62d48-ebad-47d7-bbe2-78073e7a94c3"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795315156  nanos:100651245}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795314984  nanos:931604480}  lastFailed:{seconds:1795315187  nanos:938552409}  lastSucceeded:{seconds:1795315132  nanos:704747982}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795315190  nanos:220681074}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"54a62d48-ebad-47d7-bbe2-78073e7a94c3"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795314984  nanos:931604480}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795315190  nanos:220680682}  severity:SEVERITY_ERROR}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795315085  nanos:929763313}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\xc8e\x92\x95t\n\xf6z\xc4gW%𤋮\x1f;\xe4,\"\xc9\x0f$\xad\xc2\xc0Vl\x03e,\xda"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

Live evidence confirms the identical, well-documented oscillation. This is enough to write the conclusion.

###### Root cause

Live inspection of `/persist/status/nim/DevicePortConfigList/global.json` on the paused device shows the exact same PNAC-disable/DPC-fallback oscillation documented in both the earlier investigation in this run (`TestPNACWithoutProxy`) and the ledger: the new DPC entry (TimePriority `02:39:16`, `PNAC.Enabled:false`, the cycle-1 disable/pre-auth-VLAN step) has `LastSucceeded: 0001-01-01` — it never succeeds because it can't reach the controller from the pre-auth VLAN (`src IP 172.20.20.123`, "context deadline exceeded"). `dpcmanager` is therefore stuck on `CurrentIndex:1`, the stale prior DPC (TimePriority `02:36:24`, still `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`), which itself now fails since the enrolled SCEP cert was already removed in the test's step 1 ("No certificate enrollment status found for SCEP profile \"new-scep-profile\""). `eth0` is confirmed still live at `172.20.10.123/24`, the authenticated VLAN, so the port never actually moved — the combined "PNAC disabled + pre-auth VLAN" state the test's `Eventually` polls for never becomes true, hence the 300s timeout.

This shares the same root cause as the `TestPNACWithoutProxy` failure already investigated earlier in this same suite run (`live-investigation.md`) — identical mechanism and signature, just the `WithProxy` test variant. Per `live-ledger.md`, this is a long-standing known/recurring issue: the PNAC-disable/DPC-fallback oscillation first appeared 2026-11-15/17 and has recurred on nearly every nightly run since (2026-11-17 through 2026-11-21), affecting both `TestPNACWithProxy` and `TestPNACWithoutProxy`. Tonight's failure is a continuation of that same unresolved bug, not a new regression.

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

Both surviving nodes confirm the same deadlock, permanently stuck. This is enough evidence. No PR diff was supplied with this task, so no relatedness verdict is needed.

**Root cause:** Confirmed live on both surviving nodes (edge-dev2, edge-dev3) for app `failover-purge-app` / UUID `5d19d1d6-419a-40e5-826b-bdab9a88b922`: after `edge-dev1` (the DNID node) was powered off at 03:40:05 and the purge was issued (checkpoint reached 03:48:00), `kubectl get vmirs,vmi,pods -n eve-kube-app` on both surviving nodes shows **zero objects** — nothing was ever recreated. Live `zedbox` logs show the same permanent-suppression loop on both nodes, still looping as of right now (04:04): `zedkube.checkAppsStatus` repeating `IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, `zedmanager.getKubeAppActivateStatus` logging `not designated, ... onTheDevice false` continuously, and `publishAppInstanceStatus` permanently "suppressed" — so no new domain config is ever handed to `domainmgr` and no VMIRS of any generation is created.

This is the same known, recurring `zedkube`/`zedmanager` failover-detection deadlock tracked in `live-ledger.md`, first documented 2026-11-15 (run #19) and recurring on nearly every subsequent nightly run (2026-11-17, 2026-11-18, 2026-11-19, 2026-11-20, 2026-11-21) — tonight is at least its 7th consecutive/near-consecutive occurrence. The exact failure variant (zero VMIRS found, vs. the "stale generation-0 survives" variant) previously appeared on 2026-11-19 and 2026-11-20, so this is not a new issue — it's the same unresolved product bug in the zedkube pod-name-matching / failover-detection logic.

## [2026-11-21 -- 0.0.0-17.0-stable-205b9f1e (run #32)](https://github.com/lf-edge/eve/actions/runs/44847444403)

[Full report](https://lf-edge.github.io/eve/test/17.0-stable/runs/32/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 180.001s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:4, cap:4>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15abc60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204538, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0xcdd20a2c830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e16a0,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0xcdd20a154a0>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescripto...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 5
```

##### Claude's conclusion

This is the same known, recurring issue already in the ledger (first seen 2026-11-17, repeated 2026-11-18, 2026-11-19, and 2026-11-20) — tonight is at least a fifth consecutive occurrence.

**Root cause:** Live `evetest eve app-info passthrough-app` shows `passthrough-app` reach `state:RUNNING` with `assignedAdapters:{name:"ethernet1", members:"eth1"}` correctly populated, but its `network:` list only ever contains the 4 virtual VIFs (`vif0`, `newvif1`, `newvif2`, `newvif3`) — `ethernet1` is never added, exactly matching the `len:4`/`to have length 5` signature the test is stuck on at `nicchange_test.go:177`. In pillar, `zedagent`'s app-info/metrics publisher builds `ZInfoApp.Network` solely from the app's virtual interface list, never merging passthrough (`IoAdapterList`) adapters. The fix, commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics"), exists on master but `git merge-base --is-ancestor` confirms it is **not** present on `17.0-stable` (current HEAD `dc1e7b55f`). Per `live-ledger.md`, this exact failure (same test, same root cause, same signature) was already recorded on 2026-11-17, 2026-11-18, 2026-11-19, and 2026-11-20 — tonight is at least the fifth consecutive night reproducing this same known, unfixed backport gap, not a new issue.
#### TestNetworkAdapterPassthroughChange

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:1, cap:1>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15abc60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204538, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0xcdd20a2c830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e16a0,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0xcdd20a154a0>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescripto...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 2
```

##### Claude's conclusion

**Root cause:** Confirmed live via `evetest eve app-info passthrough-app` — the app reaches `state:RUNNING` with `assignedAdapters:{name:"ethernet1", members:"eth1"}` correctly populated, but `network:` permanently stays at just `vif0` (len:1), never adding `ethernet1` (which would make it len:2, matching the `to have length 2` the test is stuck waiting on). This is `zedagent`'s app-info publisher building `ZInfoApp.Network` only from virtual VIFs and never merging passthrough (`IoAdapterList`) adapters. The fix, commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics"), is confirmed still absent from `17.0-stable` (`git merge-base --is-ancestor` fails against current HEAD `205b9f1e6`).

This shares the exact same root cause already documented in this run's `live-investigation.md` for `TestNetworkAdapterPassthrough` (the len:4→5 variant), and matches the identical `TestNetworkAdapterPassthroughChange` entry in `live-ledger.md` from 2026-11-20 (run #28), which in turn traces back to the same bug first seen 2026-11-17 for `TestNetworkAdapterPassthrough`. This is a known, recurring, unfixed backport gap — now its second consecutive-night occurrence as `TestNetworkAdapterPassthroughChange` specifically, and at least the sixth overall occurrence of this root cause across the two sibling tests since 2026-11-17.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7797  storage:42022  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"VXJTL7P2"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{device:"nbd5"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/persist/certs"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"nbd14"}  storageList:{device:"vda9"  total:43001  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"vda"  total:65536}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd12"}  storageList:{device:"nbd3"}  storageList:{device:"nbd1"}  storageList:{mountPath:"/persist/tmp"}  storageList:{mountPath:"/persist/log"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"nbd0"}  storageList:{mountPath:"/hostfs"  total:279}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/config"  total:5}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{device:"nbd13"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{device:"nbd10"}  storageList:{device:"nbd8"}  storageList:{device:"nbd4"}  storageList:{device:"nbd15"}  storageList:{device:"nbd7"}  storageList:{mountPath:"/persist"  total:42022  storageLocation:true}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/"  total:3898}  bootTime:{seconds:1795223261}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-17.0-stable-205b9f1e-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"ab9ba9be-8a87-4baa-b48c-9589cc98b2ab"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-205b9f1e-kvm-amd64 at 2026-11-21T01:07:00.223599995Z\n"  lastRebootTime:{seconds:1795223220  nanos:211355908}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795223680  nanos:717713042}  lastFailed:{seconds:1795223697  nanos:160418576}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795223697  nanos:160316848}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"c7ecc520-6bf8-40aa-bc5f-8340772cb4c3"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795223680  nanos:717713042}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795223190  nanos:40264049}  lastFailed:{seconds:1795223712  nanos:206032205}  lastSucceeded:{seconds:1795223621  nanos:810138029}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795223714  nanos:606604141}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"c7ecc520-6bf8-40aa-bc5f-8340772cb4c3"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795223190  nanos:40264049}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795223714  nanos:606603927}  severity:SEVERITY_ERROR}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795223294  nanos:637092013}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\x89\xf3}r\xfa\xe8\xdc,\n\x9dbo\xe3\x89[)\\\n\xf6Q\xb2\xdbh :e̘x\xd6ۥ"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

**Root cause:** Live inspection of `/persist/status/nim/DevicePortConfigList/global.json` on the paused device shows the new DPC entry (TimePriority `01:14:40`, `PNAC.Enabled:false`, the cycle-1 disable/pre-auth-VLAN step) never succeeds (`LastSucceeded: 0001-01-01`) because it cannot reach the controller from the pre-auth VLAN (`src IP 172.20.20.123`, `context deadline exceeded`). `dpcmanager` then falls back to the stale prior DPC (`CurrentIndex:1`, TimePriority `01:06:30`, still `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`), which itself fails PNAC validation with "No certificate enrollment status found for SCEP profile" since the enrolled cert was already removed as part of cycle 1. The live `eth0` interface is still at `172.20.10.123/24`, confirming the port never actually moved to the pre-auth VLAN — exactly the simultaneous condition the test's `Eventually` is stuck waiting for, hence the 300s timeout. This is the identical signature previously analyzed on this same branch, and per `live-ledger.md` this exact PNAC-disable/DPC-fallback oscillation has recurred on 2026-11-17 (`TestPNACWithProxy`), 2026-11-18, 2026-11-19 (both `TestPNACWithoutProxy` and `TestPNACWithProxy`), and now again tonight (2026-11-20/21) — a known, recurring, unresolved issue rather than a new regression. No PR diff was provided for this run, so no relatedness judgment applies.
#### TestPNACWithProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7797  storage:42022  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"UD4FDCC6"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtAndApps}  dns:{DNSservers:"10.16.16.25:53"}  storageList:{mountPath:"/persist/status"}  storageList:{device:"nbd13"}  storageList:{mountPath:"/persist/log"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"nbd10"}  storageList:{mountPath:"/config"  total:5}  storageList:{mountPath:"/persist/vault"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"vda9"  total:43001  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{device:"nbd1"}  storageList:{device:"nbd2"}  storageList:{mountPath:"/persist/netdump"}  storageList:{device:"nbd8"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{mountPath:"/persist/memory-monitor/output"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/hostfs"  total:279}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{device:"vda2"  total:10240  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{device:"nbd12"}  storageList:{device:"nbd7"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{device:"nbd3"}  storageList:{device:"nbd9"}  storageList:{device:"vda1"  total:2048  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd5"}  storageList:{mountPath:"/persist/certs"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"nbd4"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"vda4"  total:5  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/"  total:3898}  storageList:{mountPath:"/persist"  total:42022  storageLocation:true}  storageList:{mountPath:"/persist/ingested"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"vda"  total:65536}  storageList:{device:"nbd0"}  storageList:{mountPath:"/persist/nettrace"}  storageList:{device:"vda3"  total:10240  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  bootTime:{seconds:1795225827}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-17.0-stable-205b9f1e-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"82d69579-204c-4e4d-83b0-304df4824e39"  lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-205b9f1e-kvm-amd64 at 2026-11-21T01:49:45.196740804Z\n"  lastRebootTime:{seconds:1795225785  nanos:188238328}  systemAdapter:{currentIndex:1  status:{version:1  key:"zedagent"  timePriority:{seconds:1795225974  nanos:571679545}  lastFailed:{seconds:1795225991  nanos:97044712}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  proxy:{}  dns:{}  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"  timestamp:{seconds:1795225991  nanos:96936969}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"8728dc51-a0d0-4a1f-ad43-dff0cc5c6295"  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795225974  nanos:571679545}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}  status:{version:1  key:"zedagent"  timePriority:{seconds:1795225752  nanos:843284903}  lastFailed:{seconds:1795226006  nanos:179285791}  lastSucceeded:{seconds:1795225891  nanos:431998494}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  free:true  dhcpType:4  subnet:"172.20.10.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.20.10.123"  defaultRouters:"172.20.10.1"  dns:{DNSservers:"10.16.16.25"  DNSdomain:"test."}  up:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795226008  nanos:577795829}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"8728dc51-a0d0-4a1f-ad43-dff0cc5c6295"  mtu:1500  config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER  submitted_at:{seconds:1795225752  nanos:843284903}}  pnac_status:{enabled:true  err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\""  timestamp:{seconds:1795226008  nanos:577795547}  severity:SEVERITY_ERROR}}}  lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}}  restartCounter:1  HSMStatus:NOTFOUND  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795225849  nanos:500159323}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\x89\xf3}r\xfa\xe8\xdc,\n\x9dbo\xe3\x89[)\\\n\xf6Q\xb2\xdbh :e̘x\xd6ۥ"}  configItemStatus:{configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"scep.retry.interval"  value:{value:"300"  error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.deviceinfo.interval"  value:{value:"30"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testbetterinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  rebootConfigCounter:1  last_boot_reason:BOOT_REASON_REBOOT_CMD  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE}  api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE  optional_capabilities:{hw_inventory_support:true}  device_name:"edge-dev"
```

##### Claude's conclusion

This confirms the identical mechanism live: `eth0` is still at `172.20.10.123/24` (not the pre-auth VLAN), and the `DevicePortConfigList` shows `CurrentIndex:1` pointing at the stale DPC entry with `PNAC.Enabled:true` and `CertEnrollmentProfileName:"new-scep-profile"` (whose enrolled cert was already removed), while the newer cycle-1 DPC entry (`PNAC.Enabled:false`, the correct disable step) has `LastSucceeded: 0001-01-01` because it can't reach `adam.evetest` from the pre-auth VLAN (`src IP 172.20.20.123`, `context deadline exceeded`).

**Root cause:** This is the same PNAC-disable/DPC-fallback oscillation already analyzed in this same run for `TestPNACWithoutProxy` (in `live-investigation.md`): the cycle-1 DPC entry that disables PNAC and expects the pre-auth VLAN never succeeds because the controller is unreachable from that VLAN, so `dpcmanager` falls back to the prior stale DPC which still has PNAC enabled and references the now-removed SCEP enrollment, producing the "No certificate enrollment status found" error the test is stuck waiting to clear. Live evidence (`ip addr show eth0` still `172.20.10.123/24`, `DevicePortConfigList` `CurrentIndex:1` with `PNAC.Enabled:true`/stale cert) confirms it exactly mirrors the earlier failure in this run. Per `live-ledger.md`, this is a known, recurring issue going back to 2026-11-17 (`TestPNACWithProxy`, run #22), repeating on 2026-11-18, 2026-11-19, and 2026-11-20 — this is at least the fifth consecutive nightly occurrence, not a new regression. No PR diff was provided for this investigation, so no relatedness verdict applies.
#### TestIntermittentConnectivity

##### Failure

```

Unexpected error:
    <*fmt.wrapError | 0x9639d645580>: 
    failed to execute script over SSH for app 96fb9b09-ee40-4b50-adbe-df070205bcdc: Process exited with status 141 (stderr: )
    {
        msg: "failed to execute script over SSH for app 96fb9b09-ee40-4b50-adbe-df070205bcdc: Process exited with status 141 (stderr: )",
        err: <*ssh.ExitError | 0x9639d81e700>{
            Waitmsg: {status: 141, signal: "", msg: "", lang: ""},
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

`TestIntermittentConnectivity` deliberately applies 20% packet loss on `eth0` via the SDN (`tc`-based `trafficControl.lossProbability: 20`, confirmed still active in `evetest sdn net-model`) and then, over that very same lossy link, opens an SSH session to the app's forwarded port (`172.20.20.123:2222` → app `10.50.0.2:22`) to run a script that pings `http-server.test`. The test log shows the SSH *connection* itself succeeded ("Connected to endpoint 172.20.20.123:2222 on attempt 1/3") but the remote *script execution* then exited with status 141 (SIGPIPE) rather than a connection error.

Live inspection shows the app and EVE device are otherwise completely healthy: `zedmanager` reports the app continuously `RUNNING`, `app-metrics` show steady, uninterrupted `vif0` traffic growth with no gaps, and pinging the app's internal IP (`10.50.0.2`) from the device's own namespace gives 0% loss. This points to the SIGPIPE being a side effect of the test's own fault injection — the externally-routed SSH session over the artificially 20%-lossy `eth0` link got disrupted mid-command (likely a `ping | ...` pipeline on the remote end losing its reader when the SSH channel glitched), rather than any EVE agent misbehaving.

This is a different test/suite mechanism from the PNAC DPC-fallback oscillation already analyzed earlier in this run (`TestPNACWithoutProxy`/`TestPNACWithProxy`), so it does not share that root cause. It also doesn't match the separate `TestDeviceIPv6Connectivity` timeout-vs-retest-interval race noted elsewhere in the ledger. `TestIntermittentConnectivity` with this SIGPIPE/status-141 signature does not appear anywhere in `live-ledger.md`, so this is a new failure signature, not a previously known recurring issue — though it plausibly reflects an inherent flakiness in how the test's SSH-over-deliberately-lossy-link diagnostic is implemented rather than a product bug.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:172 with:
the surviving VMIRS must be the NEW generation "failover-purge-app-acc4b-1", not a stale one
Expected
    <string>: failover-purge-app-acc4b-0
to equal
    <string>: failover-purge-app-acc4b-1
```

##### Claude's conclusion

This is a fully confirmed, exact match to the known recurring issue.

**Root cause:** This is the identical `zedkube`/`zedmanager` failover-detection deadlock already tracked in the ledger (first documented 2026-11-15/run #19, recurring 2026-11-17, 2026-11-18, and others as this "stale generation-0 survives" variant). Live evidence: `edge-dev1` (original DNID) was powered off at 02:01:22 to force failover, the app came up on `edge-dev3` with pod `virt-launcher-failover-purge-app-acc4b-0rkdf4-zl4tl` (generation `-0`), and the purge checkpoint was reached at 02:09:10 — but `kubectl get vmirs,vmi,pods -n eve-kube-app` on `edge-dev3` still shows only the **old** generation `-0` VMIRS/VMI (23m old), with no generation `-1` object ever created. `zedbox` logs on `edge-dev3` show the exact same mechanism as before: `zedkube.checkAppsFailover` repeatedly logs "pod virt-launcher-failover-purge-app-acc4b-0rkdf4-zl4tl, looking for cont failover-purge-app-acc4b-1" (never matching, since the live pod name is still the old generation), keeping `IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, `zedmanager.getKubeAppActivateStatus` logging `onTheDevice false` continuously, and `publishAppInstanceStatus` permanently "suppressed" — so no new-generation domain config is ever handed to `domainmgr`, and the stale generation-0 VMIRS simply sits there through the 900s timeout.

This shares the same root cause as the earlier ledger entries for this exact test and is a known, recurring issue dating back at least to 2026-11-15 (run #19), recurring again on 2026-11-17, 2026-11-18, and other nights since — this is at least its 5th documented occurrence, not a new bug.

### TestStorageSuite: failure analysis

#### TestVaultZvolTrimReclaimsBlocks

##### Failure

```

fstrim should reclaim at least ~256 MiB of ghost blocks; trimmed 183631872 bytes (output: "/persist/vault: 175.1 MiB (183631872 bytes) trimmed\n")
Expected
    <int64>: 183631872
to be >=
    <int>: 209715200
```

##### Claude's conclusion

###### Root cause analysis

Live inspection confirms the test ran into the same resource-contention window documented previously for this suite, just manifesting as a different symptom. At the moment the fstrim assertion failed (01:52:34), `kubectl get pods -A` shows the entire kubevirt+CDI+longhorn stack still mid first-boot bring-up on this 4-vCPU/8GB VM — `virt-handler` still `0/1` ready, `longhorn-csi-plugin` `2/3` ready, and CSI/instance-manager/virt-controller pods only 14s–2m40s old, all started within the preceding couple of minutes right after the cluster became ready at 01:52:15. `vmstat` at that time shows load average 9.41 with up to 7 processes blocked on I/O and 23–25% iowait, and `ps aux` shows ZFS write-issue/interrupt kernel threads (`z_wr_iss`, `z_wr_int`) consuming 4–7% CPU each; `/proc/diskstats` for `zd16` (the `/persist/vault` zvol) shows ~434s of cumulative write time against only a few minutes of uptime — i.e. the zpool backing the vault was under sustained heavy concurrent write load from the simultaneous kubevirt/CDI/longhorn startup exactly when the test attempted to measure how many ghost blocks fstrim could reclaim, plausibly leaving some blocks not yet free/trimmable (183.6 MiB reclaimed vs. ~200 MiB expected).

This shares the same underlying root cause already recorded in the ledger for `TestVaultZvolTrimReclaimsBlocks` on 2026-11-18 and 2026-11-19 ("heavy zvol-trim I/O competing with k3s/kine/etcd writes and simultaneous first-boot kubevirt+CDI+longhorn bring-up on a single 4vCPU/8GB VM"), making this a known/recurring resource-contention problem with this test going back at least to 2026-11-18. However, the specific failure signature is new: the prior two occurrences timed out entirely in `WaitForClusterNodeIsReady` before the test could even reach the trim step, whereas tonight the cluster became ready in ~2 minutes and the test proceeded to fstrim, which then under-reclaimed due to residual contention — a milder manifestation of the same systemic issue rather than an identical repeat.

No PR diff was provided for this run, so no relatedness judgment is given.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNIPortConfigRace

##### Failure

```

Told to stop trying after 9.625s.
Stop waiting for: multiswitch-ni is ONLINE with 2 assigned adapters
Network instance is in error state
networkID:"a65235cf-e0e8-4b80-85c1-1ba3b151ebdc"  networkVersion:"1"  instType:1  displayname:"multiswitch-ni"  bridgeNum:1  networkErr:{description:"failed to select ports for network instance a65235cf-e0e8-4b80-85c1-1ba3b151ebdc: no port is matching label 'multiswitch-ports'"  timestamp:{seconds:1795229207  nanos:409692795}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500
```

##### Claude's conclusion

I have enough evidence now, confirming the same convergence race pattern and timing as previously documented.

###### Root cause

This is the same transient port-selection/convergence race the test's name describes, not a real misconfiguration — live `evetest eve config` confirms `ethernet1`/`ethernet2` are correctly labeled `multiswitch-ports`. Device logs (`evetest eve logs`) show zedrouter raised `no port is matching label 'multiswitch-ports'` at **02:46:47.409**, right in the middle of a DPC port-config churn: nim's DPC verification for the new port config was still in `DPC_ASYNC_WAIT`/`DPC_IPDNS_WAIT` until **02:46:46.564**, and zedrouter's port-selection ran in the gap before eth1/eth2 picked up their bridge association. The NI only flipped to `Activated network instance ... (multiswitch-ni)` at **02:46:51.863** — about 4.5s after the error — and currently (post-failure, paused state) the live `NetworkInstanceStatus` for `multiswitch-ni` shows `Ports: ["ethernet1","ethernet2"]` with no outstanding error, i.e. it did converge, just not within the test's wait window (`Told to stop trying after 9.625s`).

This shares the exact same root cause as the 2026-11-18 run #24 occurrence recorded in the ledger (identical error string, identical `BridgeIfInstanceID:0`/DPC-retry mechanism, same eventual self-resolution) — so this is a known, recurring issue for `TestSwitchNetworkInstanceSuite/TestSwitchNIPortConfigRace`, first seen 2026-11-18, not present in the 11-19 or 11-20 runs, and now recurring today. The test's timeout appears too tight relative to the DPC/bridge convergence time actually observed on this hardware, rather than an EVE regression.

### TestUpgradeSuite: failure analysis

#### TestThreeNodesUpgrade

##### Failure

```

Timed out after 905.090s.
The function passed to Eventually failed at /evetest/tests/upgrade/cluster_upgrade_test.go:191 with:
Unexpected error:
    <*fmt.wrapError | 0x783e28a18e0>: 
    unable to reach app "ade0f5b0-290b-4d30-9318-b31e56dfb538" SSH on device "edge-dev1": no reachable endpoint among [172.20.20.226:2222]
    {
        msg: "unable to reach app \"ade0f5b0-290b-4d30-9318-b31e56dfb538\" SSH on device \"edge-dev1\": no reachable endpoint among [172.20.20.226:2222]",
        err: <*errors.errorString | 0x783e22a69f0>{
            s: "no reachable endpoint among [172.20.20.226:2222]",
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

Live evidence shows the app itself is healthy, just not where the test is looking for it. `kubectl get vmi,vm,vmirs -n eve-kube-app` on the paused cluster shows `upgrade-app-ade0f-0` is `Running`/`Ready` on **edge-dev2**, not edge-dev1. Kubernetes events explain why: edge-dev1 was the last node upgraded in this rolling-upgrade test — it went `NodeNotReady` around 02:02 while being cordoned/drained and rebooted for the baseos upgrade (per `pkg/pillar/docs/zedkube.md`'s documented drain flow), the VMIRS evicted the old pod (`...msmcw`, originally on edge-dev1) via `TaintManagerEviction`, and created a replacement VMI (`...f2fxg`) that landed on edge-dev2 instead. `evetest eve app-info` on edge-dev1 confirms this: it shows the app transiting RUNNING→BOOTING (with `dial tcp 127.0.0.1:6443: connect: connection refused` while edge-dev1's local apiserver was still coming up) and finally settling into `state:INITIAL` once edge-dev1 stopped hosting it at all — there is no Service/Endpoints object routing cross-node, so the test's fixed SSH target `edge-dev1:172.20.20.226:2222` (`cluster_upgrade_test.go:191`) genuinely had nothing listening there for the full 905s wait, even though the app is fine on edge-dev2.

This doesn't match either of the last two `TestThreeNodesUpgrade` ledger entries (2026-11-19's k3s single-node-bootstrap race, 2026-11-20's Proxmox `qmcreate` lock timeout) — those were different mechanisms — so this exact failure signature is new for this test. However, it closely matches a *known class* of test-harness bug already documented twice in the ledger (2026-11-15 and a later recurrence) for a different test (`dnidbackup_test.go`'s `FindDeviceHostingApp`): the harness resolving/polling a fixed or stale device instead of the node currently hosting a migrated workload, rather than a pillar/EVE defect. Given the app's own designated-node migration here looks like expected drain/reschedule behavior, this looks like the same class of harness gap now surfacing in `cluster_upgrade_test.go`, rather than a new product bug — though I can't confirm the exact harness code path since `cluster_upgrade_test.go` lives in the evetest repo, not this checkout.

## [2026-11-20 -- 0.0.0-17.0-stable-dc1e7b55 (run #28)](https://github.com/lf-edge/eve/actions/runs/44657616698)

[Full report](https://lf-edge.github.io/eve/test/17.0-stable/runs/28/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 180.001s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:4, cap:4>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x3db69adac830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x3db69ad954a0>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 5
```

##### Claude's conclusion

This confirms the exact same signature: the final `RUNNING` state has `assignedAdapters:{name:"ethernet1"...}` correctly reported but `network:` only ever lists the 4 virtual VIFs (vif0, newvif1, newvif2, newvif3) — `ethernet1` never appears there, matching the len:4 the test is stuck polling at. No PR diff was provided for this run, so no relatedness judgment is needed.

**Root cause:** Live `evetest eve app-info passthrough-app` shows `passthrough-app` reach `state:RUNNING` with `assignedAdapters:{name:"ethernet1", members:"eth1"}` correctly populated, but its `network:` list only ever contains the 4 virtual VIFs (`vif0`, `newvif1`, `newvif2`, `newvif3`) — `ethernet1` is never added — exactly the len:4 the `Eventually` at `nicchange_test.go:177` is stuck waiting to become len:5. In pillar, `zedagent`'s app-info/metrics publisher builds `ZInfoApp.Network` solely from the app's virtual interface list, never merging the passthrough (`IoAdapterList`) adapters. The fix for this is commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics"), which exists on master but `git merge-base --is-ancestor` confirms is **not** present on `17.0-stable` (current HEAD `dc1e7b55f`). Per the ledger, this exact failure (same test, same root cause) was already recorded on 2026-11-17, 2026-11-18, and again 2026-11-19 — this is the fourth consecutive night reproducing the same known, unfixed backport gap, not a new issue.
#### TestNetworkAdapterPassthroughChange

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:1, cap:1>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x3db69adac830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x3db69ad954a0>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 2
```

##### Claude's conclusion

Confirmed live: after `ethernet1` is passed through (`assignedAdapters:{name:"ethernet1"...}`) and the app reaches `state:RUNNING`, `network:` only ever lists `vif0` — never `ethernet1` — exactly the `len:1` stuck against the expected `len:2`.

Root cause: this is the identical bug already identified for `TestNetworkAdapterPassthrough` earlier in this run — `zedagent`'s app-info publisher builds `ZInfoApp.Network` only from the app's virtual VIFs and never merges passthrough (`IoAdapterList`) adapters, so any passthrough NIC is permanently missing from `ZInfoApp.Network` regardless of how many virtual NICs are also present. The fix, commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics"), is on master but not yet backported to `17.0-stable` (current HEAD `dc1e7b55f`). Per the ledger this exact passthrough-reporting gap has already recurred on 2026-11-17, 2026-11-18, and 2026-11-19 (previously manifesting via `TestNetworkAdapterPassthrough`); this is the same known, unfixed backport gap now also tripping its sibling test `TestNetworkAdapterPassthroughChange` on the same nightly run.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-11.0" serialNumber:"CLB84UR8" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{device:"nbd7"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{mountPath:"/persist/clear"} storageList:{mountPath:"/persist/status"} storageList:{device:"vda" total:65536} storageList:{mountPath:"/persist/newlog"} storageList:{device:"nbd5"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"nbd15"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{device:"nbd14"} storageList:{device:"nbd3"} storageList:{mountPath:"/persist/checkpoint"} storageList:{mountPath:"/persist/certs"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{device:"nbd6"} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/nettrace"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/persist/log"} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/" total:3898} storageList:{mountPath:"/persist/vault"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-1.dat"} storageList:{mountPath:"/persist/netdump"} storageList:{device:"nbd1"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{device:"nbd11"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/agentdebug"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{mountPath:"/persist/tmp"} storageList:{device:"nbd2"} storageList:{device:"nbd13"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-1.dat"} storageList:{device:"nbd4"} storageList:{device:"nbd9"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd8"} storageList:{device:"nbd0"} storageList:{device:"nbd12"} storageList:{mountPath:"/config" total:5} storageList:{mountPath:"/hostfs" total:279} storageList:{mountPath:"/persist/patchEnvelopesCache"} bootTime:{seconds:1795141324} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-dc1e7b55-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"6cb2405e-9ec0-44ba-83ec-140fa2e6b6f2" lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-dc1e7b55-kvm-amd64 at 2026-11-20T02:21:22.345753909Z\n" lastRebootTime:{seconds:1795141282 nanos:341995318} systemAdapter:{currentIndex:1 status:{version:1 key:"zedagent" timePriority:{seconds:1795141467 nanos:609652795} lastFailed:{seconds:1795141484 nanos:362337214} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 proxy:{} dns:{} err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)" timestamp:{seconds:1795141484 nanos:362240054} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"5ddf5a9d-6e59-4a0d-98ed-2a8c87f7fc0d" config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795141467 nanos:609652795}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"} status:{version:1 key:"zedagent" timePriority:{seconds:1795141252 nanos:222475582} lastFailed:{seconds:1795141499 nanos:456275793} lastSucceeded:{seconds:1795141388 nanos:899831043} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795141501 nanos:803640472} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"5ddf5a9d-6e59-4a0d-98ed-2a8c87f7fc0d" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795141252 nanos:222475582}} pnac_status:{enabled:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795141501 nanos:803640169} severity:SEVERITY_ERROR}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}} restartCounter:1 HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1795141347 nanos:76179805} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"4Y\x86AP\xa4\x0f\x11\xf5\x12\xf2\xd79\xb06\xa6\x87\xb7\x8eZ\xaf\xbf<\xd7B\x8f\x96^\xf2\x99\x1c\r"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} rebootConfigCounter:1 last_boot_reason:BOOT_REASON_REBOOT_CMD hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

###### Root cause

Live inspection of `/persist/status/nim/DevicePortConfigList/global.json` on the paused device shows the identical DPC-fallback oscillation already documented in the ledger: the new DPC entry (`TimePriority 02:24:27`, `PNAC.Enabled:false` — the disable/VLAN-move step for cycle 1) never succeeds (`LastSucceeded: 0001-01-01`), permanently failing with "All attempts to connect to adam.evetest:443 ... src IP 172.20.20.123 ... context deadline exceeded" because it can't reach the controller from the pre-auth VLAN. Meanwhile the stale prior DPC (`TimePriority 02:20:52`, still `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`) remains `CurrentIndex:1` (active, last succeeded 02:23:08) because `dpcmanager` falls back to it when the new disable config fails — and that fallback config itself now fails PNAC with "No certificate enrollment status found for SCEP profile \"new-scep-profile\"" (matching the device status report), since the enrolled cert was already removed per the test's cycle 1. The live interface (`eth0`) is still on `172.20.10.123`, the authenticated VLAN, confirming the port never actually moved — exactly the simultaneous "PNAC disabled + pre-auth VLAN" condition the test polls for, hence the 300s timeout.

This is a known, recurring issue per `live-ledger.md`: the same PNAC-disable/DPC-fallback oscillation first appeared 2026-11-17 (`TestPNACWithProxy`, run #22) and repeated 2026-11-18 and 2026-11-19 (run #24, #26) for both `TestPNACWithoutProxy` and `TestPNACWithProxy`, with the identical failure signature each time. Tonight's failure is the same mechanism reproducing again, not a new regression. No PR diff was provided for this run.
#### TestPNACWithProxy

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-11.0" serialNumber:"QSXBCBGJ" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{device:"nbd6"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-1.dat"} storageList:{device:"nbd15"} storageList:{device:"nbd14"} storageList:{mountPath:"/persist/certs"} storageList:{mountPath:"/persist/log"} storageList:{mountPath:"/persist/vault"} storageList:{mountPath:"/persist/clear"} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/config" total:5} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-1.dat"} storageList:{device:"nbd13"} storageList:{mountPath:"/hostfs" total:279} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{mountPath:"/persist/checkpoint"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{mountPath:"/persist/status"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{device:"vda" total:65536} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/newlog"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{device:"nbd11"} storageList:{device:"nbd1"} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"nbd3"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{mountPath:"/" total:3898} storageList:{mountPath:"/persist/nettrace"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{device:"nbd8"} storageList:{device:"nbd12"} storageList:{device:"nbd2"} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/tmp"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"nbd7"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{device:"nbd0"} storageList:{device:"nbd5"} bootTime:{seconds:1795143580} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-dc1e7b55-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"5e1e3c19-f344-4ab6-80b3-77678c625ab0" lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-dc1e7b55-kvm-amd64 at 2026-11-20T02:58:57.693101442Z\n" lastRebootTime:{seconds:1795143537 nanos:680535846} systemAdapter:{currentIndex:1 status:{version:1 key:"zedagent" timePriority:{seconds:1795144007 nanos:801621656} lastFailed:{seconds:1795144023 nanos:553619274} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 proxy:{} dns:{} err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)" timestamp:{seconds:1795144023 nanos:553493231} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"c507a589-d22f-485e-8359-c2e457d3c7b9" config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795144007 nanos:801621656}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"} status:{version:1 key:"zedagent" timePriority:{seconds:1795143507 nanos:943530356} lastFailed:{seconds:1795144038 nanos:624522001} lastSucceeded:{seconds:1795143951 nanos:37184343} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795144040 nanos:960961952} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"c507a589-d22f-485e-8359-c2e457d3c7b9" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795143507 nanos:943530356}} pnac_status:{enabled:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795144040 nanos:960961747} severity:SEVERITY_ERROR}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}} restartCounter:1 HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1795143611 nanos:849866203} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"4Y\x86AP\xa4\x0f\x11\xf5\x12\xf2\xd79\xb06\xa6\x87\xb7\x8eZ\xaf\xbf<\xd7B\x8f\x96^\xf2\x99\x1c\r"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} rebootConfigCounter:1 last_boot_reason:BOOT_REASON_REBOOT_CMD hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

This confirms the exact same DPC-fallback oscillation mechanism identified earlier in this run.

**Root cause:** Live inspection of `/persist/status/nim/DevicePortConfigList/global.json` on the paused device shows the new DPC entry (`TimePriority 03:06:47`, `PNAC.Enabled:false` — cycle 1's disable/VLAN-move step) has `LastSucceeded: 0001-01-01` (never succeeded), failing with "All attempts to connect to adam.evetest:443 ... src IP 172.20.20.123 ... context deadline exceeded" because it can't reach the controller from the pre-auth VLAN. `dpcmanager` therefore falls back to the stale prior DPC (`TimePriority 02:58:27`, `CurrentIndex:1`, still `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`), which itself fails PNAC with "No certificate enrollment status found for SCEP profile \"new-scep-profile\"" since the enrolled cert was already removed earlier in the test cycle. The device's live `eth0` IP (`172.20.10.123`) confirms the port never actually moved to the pre-auth VLAN.

This is identical to the `TestPNACWithoutProxy` failure already diagnosed earlier in this same run (recorded in `live-investigation.md`) — same device image, same mechanism, same signature. Per `live-ledger.md`, this is a known, recurring issue in the PNAC-disable/DPC-fallback interaction, first observed 2026-11-17 (`TestPNACWithProxy`, run #22) and repeating 2026-11-18 and 2026-11-19 (run #24, #26) for both test variants. Tonight's failure (now the second instance in this run, third+ occurrence overall) is the same bug reproducing again, not a new regression.
#### TestDeviceIPv6Connectivity

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: DPC LastSucceeded has advanced
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-11.0" serialNumber:"0C6LAZ4R" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"[fd23:131b:6500::1]:53"} storageList:{mountPath:"/persist/clear"} storageList:{mountPath:"/persist/checkpoint"} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"nbd6"} storageList:{device:"nbd0"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/certs"} storageList:{mountPath:"/hostfs" total:279} storageList:{device:"nbd13"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{mountPath:"/config" total:5} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/log"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{device:"nbd8"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{mountPath:"/persist/nettrace"} storageList:{device:"nbd1"} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{device:"nbd11"} storageList:{mountPath:"/persist/vault"} storageList:{mountPath:"/persist/newlog"} storageList:{device:"nbd2"} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/persist/tmp"} storageList:{device:"nbd12"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"vda" total:65536} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"nbd7"} storageList:{device:"nbd5"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{mountPath:"/persist/status"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{device:"nbd3"} storageList:{mountPath:"/" total:3898} storageList:{mountPath:"/persist/netdump"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd15"} storageList:{device:"nbd14"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} bootTime:{seconds:1795148169} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-dc1e7b55-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"a9250306-2079-4e85-81ab-82ca1209359d" lastRebootReason:"NORMAL: First boot of device - at 2026-11-20T04:16:46.703261645Z" lastRebootTime:{seconds:1795148206 nanos:703261645} systemAdapter:{status:{version:1 key:"zedagent" timePriority:{seconds:1795148285 nanos:494835081} lastSucceeded:{seconds:1795148289 nanos:277035309} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"fd3f:89fd:78c5::/64" proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"fd3f:89fd:78c5:0:e73d:f953:f42f:7432" IPAddrs:"fe80::e29:d021:ffd1:13d7" defaultRouters:"fe80::445c:d8ff:feed:a6f2" dns:{DNSservers:"fd23:131b:6500::1"} up:true err:{timestamp:{seconds:1795148289 nanos:276550925}} usage:PhyIoUsageMgmtAndApps networkUUID:"9f4c0822-5f7e-4ef4-9e61-12d75ebbfe93" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795148285 nanos:494835081}} pnac_status:{}}}} HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1795148272 nanos:223325142} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"4Y\x86AP\xa4\x0f\x11\xf5\x12\xf2\xd79\xb06\xa6\x87\xb7\x8eZ\xaf\xbf<\xd7B\x8f\x96^\xf2\x99\x1c\r"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} last_boot_reason:BOOT_REASON_FIRST hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE error:{description:"[ATTEST] No escrow data" timestamp:{seconds:1795148282 nanos:50305536} severity:SEVERITY_ERROR}} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

No prior mention in the ledger — this is a new failure signature, not previously recorded.

**Root cause:** `TestDeviceIPv6Connectivity` captures `firstSucceeded` from the DPC's `LastSucceeded` timestamp (04:18:09, confirmed in the embedded device-info and in `nim` logs — `DPC verify: DPC passed network test` for the `zedagent` DPC) and then waits up to exactly 5 minutes for it to advance. Live inspection after the pause shows `/persist/status/nim/DevicePortConfigList/global.json` now reports `LastSucceeded: 2026-11-20T04:23:09Z` — i.e. the next periodic connectivity probe did fire and succeed, but exactly 300s later, which is NIM's default `NetworkTestInterval` (`pkg/pillar/types/global.go:1226`, 5 minutes). The test's own `Eventually` budget (`timeout := 5 * time.Minute` in `evetest/tests/networking/ipv6_test.go:166`) is identical to that production retest cadence, so any normal scheduling/propagation jitter is enough for the real advance to land a moment after the test gives up — exactly what happened here (timed out at 300.001s while the device's actual next success landed at the ~300s mark). This looks like an inherent test-timing race rather than a device/networking regression, since the device itself is healthy (IPv6 connectivity, DNS, and controller reachability all working, confirmed live).

This is unrelated to the `TestPNACWithoutProxy`/`TestPNACWithProxy` failures already diagnosed earlier in this run (those are a DPC-fallback/SCEP oscillation bug, not a timeout-vs-retest-interval race) and does not appear in `live-ledger.md`, so this is a new failure signature, not a previously known recurring issue — though the underlying race (test timeout == production retest interval) is likely to recur intermittently going forward unless the test's timeout is lengthened or decoupled from `NetworkTestInterval`.

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

###### Root cause

Live evidence shows the cluster is actually healthy right now: `kubectl get vmi,vmirs,pods -n eve-kube-app` confirms `vm2` is genuinely `Running`/`Ready` on **edge-dev3** (its correct designated node, VMI only ~69s old at investigation time). The failure is driven by a stale/erroneous status cached on **edge-dev1**: `app-info` for vm2 there shows its last published state is `RUNNING` (bootTime ~03:08:18) carrying an `appErr` of `"New volumeRefConfig ... not allowed unless purged"`. Live `zedmanager`/`domainmgr` logs on edge-dev1 explain this directly — at 03:07:49 edge-dev1 raced to locally reactivate vm2 (creating `VirtualMachineInstanceReplicaSet vm2-d56ef-1` with `nodeName:edge-dev1`) concurrently with edge-dev3 reclaiming the app, hit a volume-ownership conflict, and never corrected that cached status because once `zedkube` on edge-dev1 settled on `IsDNidNode=false ScheduledOnThisNode=false` (confirmed happening live at 03:13:26), `publishAppInstanceStatus` is permanently "suppressed" there, freezing the stale erroneous `RUNNING` snapshot.

This exact assertion (`"vm2 did not fail back to its own designated node ... edge-dev1 vs edge-dev3"`) appeared once before in the ledger, on **2026-11-15 (run #19)** — four days before any other recurrence — and was diagnosed there as a test-harness gap: the final placement check reads per-device cached `AppInstanceStatus` and can pick a stale snapshot from the wrong device (`FindDeviceHostingApp` without `excludeDevNames`) instead of waiting for the currently-hosting node's fresh status. Today's failure shares that same harness-visible symptom, so it is a recurring/known issue, though the live device-side evidence here also shows a genuine backup-DNID race (a conflicting local reactivation attempt with a volume ownership error) that wasn't documented in the 2026-11-15 write-up, so it may be a deeper variant rather than an identical repeat. This run's other suite member, `TestVMIRSStrandedReplicasRecovery`, passed (empty artifact dir) and is unrelated. No PR diff was supplied for this investigation.
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

###### Root cause

This is the same recurring `zedkube`/`zedmanager` failover-detection deadlock already tracked in the ledger for `TestNodeClusterResilienceSuite/TestVMAppPurgeDuringFailover`, now confirmed live for a 4th time. Per the harness log, `edge-dev1` (the original DNID node, app `failover-purge-app` / `cce76ad7-ddf1-4879-b55e-480fd3509c6c`) was powered off at 03:32:09 to force failover, the app failed over to `edge-dev3` at 03:39:45, and a purge was issued immediately after — then the test waited 900s for exactly one VMIRS and found none. Live inspection on `edge-dev3` confirms `kubectl get vmirs,vmi,pods -n eve-kube-app` shows **zero** objects (the namespace has nothing), and `zedbox` logs there show the same permanent-suppression loop seen before: `zedkube.checkAppsStatus` repeating `IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, `zedmanager.getKubeAppActivateStatus` logging `onTheDevice false` continuously from shortly after the purge through the present (still looping at 03:56, well past the 03:54:45 pause), and `publishAppInstanceStatus` permanently "suppressed" — so no new-generation domain config is ever handed to `domainmgr` and no VMIRS of any generation is created.

This shares the exact same root cause as the earlier `TestVMAppPurgeDuringFailover` failure already analyzed in this run's `live-investigation.md` (the "zero VMIRS" variant, not the "stale generation-0 survives" variant) — same deadlock mechanism, different device names only (`edge-dev2`→`edge-dev3` this time). It is **not** related to this run's `TestDNIDandBackupDNID` failure (that was a test-harness stale-cache read on a healthy backend).

Per `live-ledger.md`, this is a known/recurring issue: first seen 2026-11-15 (run #19), then 2026-11-17 (run #22), 2026-11-18 (run #23), and now 2026-11-20 — four separate nightly occurrences of this same `checkAppsFailover`/suppressed-`publishAppInstanceStatus` deadlock, always in this same test. No PR diff was supplied for this investigation.

### TestSecuritySuite: failure analysis

#### TestAppVTPMIdentitySurvivesReboots

##### Failure

```

Timed out after 306.789s.
The function passed to Eventually failed at /evetest/tests/security/vtpm_helpers_test.go:127 with:
read guest TPM NV marker: 
Unexpected error:
    <*fmt.wrapError | 0x27313c1a21e0>: 
    unable to reach app "c132e97d-25fa-4b90-b713-502bda2ac8fc" SSH on device "edge-dev": no reachable endpoint among [172.20.20.123:2222]
    {
        msg: "unable to reach app \"c132e97d-25fa-4b90-b713-502bda2ac8fc\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.20.123:2222]",
        err: <*errors.errorString | 0x27313b80f240>{
            s: "no reachable endpoint among [172.20.20.123:2222]",
        },
    }
occurred
```

##### Claude's conclusion

Confirmed, same code path as before.

**Root cause:** After the device reboot completed and came back online at 02:49:16, `zedmanager`'s `checkLowPriorityApps` ran before `/persist/vault/active-app-instance-config/` existed (02:49:12.268: `"failed to load active app instance UUIDs: ... no such file or directory"`), so it marked the single app `vtpm-identity` as a "low priority app" even though it's the only/active app. Since `activeMap` contains only itself, `runningCount >= len(activeMap)` can never be satisfied self-referentially, so the only way out is the hardcoded `waitForAppsToStartTimeout = 5 * time.Minute` fallback (`pkg/pillar/cmd/zedmanager/zedmanager.go:41,702`). The app's domain is consequently not started until 02:54:17 — exactly 5:01 after the device reported online — which lands 2 seconds past the test's 306.789s `Eventually` budget, so the SSH port-forward to `172.20.20.123:2222` genuinely had no reachable endpoint during the whole wait.

This is the identical mechanism (same code, same gating logic, same ~5-minute gap) documented in this ledger for **2026-11-18, run #24**, on the same `TestAppVTPMIdentitySurvivesReboots` test — so this is a known, recurring issue, now confirmed on its second occurrence (2026-11-18 → 2026-11-20), not a new bug. No other failure in tonight's run shares this root cause (it's the sole failure in `TestSecuritySuite`). No PR diff was provided for this investigation, so no relatedness verdict is given.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKVMtoKVM

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup device "edge-dev" for installation: failed to upload disk image "/root/.evetest/images/eve-64f61083-edge-dev/disk.qcow2" to storage "local": Post "https://10.208.13.184:8006/api2/json/nodes/farfalle/storage/local/upload": write tcp 10.208.13.250:44942->10.208.13.184:8006: write: broken pipe
```

##### Claude's conclusion

###### Root cause

Live evidence confirms the EVE device was never created: `evetest eve info` returns "no EVE devices are currently onboarded" and `evetest sdn status` returns "SDN client is not initialized" — teardown had already run after the failure, consistent with the `gotest.json` trace showing the Proxmox VM (`qmcreate`) for device `edge-dev` was never even issued because the disk-image upload step failed first.

From `gotest.json`: the broker made 3 attempts to upload `disk.qcow2` to Proxmox node `farfalle`'s `local` storage via `https://10.208.13.184:8006/api2/json/nodes/farfalle/storage/local/upload` — attempt 1 failed with `unexpected end of JSON input`, attempts 2 and 3 both failed with `write: broken pipe` from the test runner (`10.208.13.250`) to the Proxmox API host (`10.208.13.184:8006`). This is a connection being dropped mid-upload by (or on the path to) the Proxmox API endpoint, not an EVE/pillar code path — no EVE image ever booted, so there's no zedbox/pillar state to inspect.

This isn't the same failure as any earlier entry in this run (only one suite failure this run). Per the ledger, the `farfalle` Proxmox host has a recurring history of host-side provisioning instability — a `qmcreate` storage-lock timeout (`can't lock file '.../pve-storage-farfalle-pve-zfs-pool'`) and a `"no worker upid"` task-spawn failure, both logged as Proxmox-host resource-contention issues rather than EVE defects. Today's failure is a new specific symptom (broken pipe/truncated JSON during disk upload) of that same broader class — infrastructure instability on the `farfalle` Proxmox host/network path — but this exact error text doesn't appear verbatim in the ledger, so it's a first occurrence of this particular symptom rather than a tracked recurring one.

No PR diff was supplied for this investigation, so no relatedness judgment is given.
#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
timed out after 10m0.020383144s (excluding download) waiting for app "0533c808-24c0-44d5-b1ff-5eb06031613f" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: HALTING)
```

##### Claude's conclusion

Still stuck in HALTING ~9 minutes later, same as at test-timeout time. This confirms the app is genuinely stalled, not just slow to retry within the window.

I now have enough evidence to write the conclusion.

**Root cause:** The upgrade-test-app got stuck because, during the post-baseos-upgrade reboot, kubevirt's `virt-api` pod was mid-restart (it shows `RESTARTS: 1/2/3 (11m ago)` on all kubevirt control-plane pods, matching the reboot timing) when domainmgr tried to recreate the VMIRS for the app's new boot — the webhook call `POST https://virt-api.kubevirt.svc:443/virtualmachinereplicaset-validate` hit `connect: connection refused` because the `virt-api` ClusterIP (`10.43.246.147`) had no healthy backend at that instant, driving the app into `HALTING` at 03:06:53 UTC. Unlike last night's occurrence of this exact failure, the app never recovered: `virt-api` is now `1/1 Running` and its service has a healthy endpoint again, yet `upgrade-test-app` is still stuck in `HALTING` (confirmed ~9 minutes after the error, same as at test-timeout) with `kubectl get vmi,vm,vmirs` returning "No resources found" — so whatever retry path handles this webhook failure isn't re-driving the VMIRS/VMI creation even though the webhook is reachable again.

This is the same test (`TestEVEUpgradeKubevirtToKubevirt`), the same failure signature (`HALTING` after the 10-minute `RUNNING`-wait timeout), and the same underlying mechanism (kubevirt `virt-api` webhook unreachable right after the post-upgrade reboot) documented in last night's ledger entry (2026-11-19, run #26) — this is a recurring, known issue, first seen 2026-11-19, and it reproduced again tonight. The one difference from last night is that in that prior run the app eventually recovered to `RUNNING` ~2 minutes after the timeout, whereas tonight it remains stuck even longer after — consistent with the same root cause but a slightly worse/stalled recovery this time.
#### TestThreeNodesUpgrade

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = failed to setup device "edge-dev3" for installation: failed waiting for VM 108 creation: task failed on Proxmox: unable to create VM 108 - cannot import from 'local:import/ev-eve-64f61083-edge-dev3-1.qcow2' - can't lock file '/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool' - got timeout (task UPID:farfalle:003E5DC1:83151573:6AFFBBDA:qmcreate:108:root@pam:)
```

##### Claude's conclusion

This confirms the pattern: three VM creations (edge-dev1/2/3) were kicked off nearly simultaneously at 03:17:34, and the one for `edge-dev3` (VM 108, `qmcreate`) failed because it couldn't acquire the `pve-storage-farfalle-pve-zfs-pool` lock within Proxmox's internal timeout — concurrent disk imports contending for the same ZFS pool lock on the `farfalle` host, before EVE ever booted (`evetest eve info`/`sdn status` confirm no device/SDN state exists, consistent with teardown having already run post-failure).

**Root cause:** This is a Proxmox host-side resource-contention failure, not an EVE/pillar defect — `edge-dev3`'s `qmcreate:108` disk import timed out waiting for the `/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool` lock while `edge-dev1`/`edge-dev2`'s installers were concurrently running on the same host, exactly the kind of multi-VM provisioning race the ledger has seen before. This does not share a root cause with the earlier `TestEVEUpgradeKVMtoKVM`/`TestEVEUpgradeKubevirtToKubevirt` failures already investigated in this run (those were an upload broken-pipe and a kubevirt webhook stall, respectively) — this is a distinct, third failure in the same run. Per the ledger, this is a known/recurring issue class on the `farfalle` host: the identical lock file and error text (`can't lock file '.../pve-storage-farfalle-pve-zfs-pool' - got timeout`) was seen on 2026-11-17 for `TestPcibackErrorSuite/TestReportWarningsOnly`, and a related `"no worker upid - start worker failed"` Proxmox task-spawn failure under similarly concurrent multi-VM creation was seen in an earlier `TestNodeClusterSuite` entry — both pointing to `farfalle` struggling with concurrent `qmcreate`/storage-import operations, a recurring theme rather than a new bug. No PR diff was supplied, so no relatedness judgment is given.

## [2026-11-19 -- 0.0.0-17.0-stable-53602206 (run #26)](https://github.com/lf-edge/eve/actions/runs/44441046705)

[Full report](https://lf-edge.github.io/eve/test/17.0-stable/runs/26/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:4, cap:4>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x385eb38e6830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x385eb38d2d20>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 5
```

##### Claude's conclusion

This matches the live evidence perfectly: the final app-info entry shows `state:RUNNING` with `assignedAdapters:{name:"ethernet1"...}` but the `network:` list only has 4 entries (`vif0`, `newvif1`, `newvif2`, `newvif3`) — never `ethernet1` — exactly the gap the test's `Eventually` is waiting on.

**Root cause:** Live `evetest eve app-info passthrough-app` on the paused device shows the app settles into `RUNNING` with `assignedAdapters` correctly reporting passthrough adapter `ethernet1` (member `eth1`), but the `network:` list only ever contains the 4 virtual VIFs (`vif0`, `newvif1`, `newvif2`, `newvif3`) — it never includes `ethernet1` — so the test's `Eventually` at `nicchange_test.go:177` polling for 5 network entries times out after 180s. In pillar, `pkg/pillar/cmd/zedagent/handlemetrics.go` builds `ZInfoApp.Network` solely from `aiStatus.GetAppInterfaceList()` (virtual VIFs), never merging `aiStatus.IoAdapterList` (passthrough adapters). This is a **known, recurring issue**: the fix exists on master as commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics"), but `git merge-base --is-ancestor 979ea453c HEAD` confirms it's still not backported to `17.0-stable` (current HEAD `53602206a`). Per the ledger, this exact failure (same test, same root cause) was already documented on 2026-11-17 and again on 2026-11-18 — today's is the third consecutive night reproducing the same unfixed backport gap, not a new bug.
#### TestNetworkAdapterPassthroughChange

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:1, cap:1>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x385eb38e6830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x385eb38d2d20>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 2
```

##### Claude's conclusion

Live evidence confirms it: the app settles into `RUNNING` with `assignedAdapters:{name:"ethernet1"...}` correctly reported, but `network:` only ever contains the single `vif0` entry (len:1), never `ethernet1` — exactly the gap the test's `Eventually` (expecting len:2) times out on.

**Root cause:** This is the same missing-backport bug already recorded earlier in this run's `live-investigation.md` for `TestNetworkAdapterPassthrough`: `pkg/pillar/cmd/zedagent/handlemetrics.go`'s `PublishAppInfoToZedCloud` builds `ZInfoApp.Network` only from `aiStatus.GetAppInterfaceList()` (virtual VIFs), with no merge of `IoAdapterList` passthrough adapters, so a directly-assigned NIC like `ethernet1` never appears in the `network:` list even though it correctly shows under `assignedAdapters`. The fix exists on master as commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics") but is not backported to `17.0-stable` (HEAD `53602206a`). Per the ledger, this exact `TestNetworkAdapterPassthroughChange` failure (len:1→2) was already seen on 2026-11-18, tracing back to 2026-11-15 when the restored NIC-change tests first exposed this backport gap — this is a third+ consecutive recurrence of a known, unfixed issue, not a new bug.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-10.1" serialNumber:"ZQWHYESO" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{device:"nbd6"} storageList:{mountPath:"/config" total:5} storageList:{device:"nbd15"} storageList:{mountPath:"/persist/clear"} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/ingested"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{mountPath:"/persist/tmp"} storageList:{device:"nbd11"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{mountPath:"/persist/newlog"} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/status"} storageList:{device:"nbd13"} storageList:{mountPath:"/persist/checkpoint"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{device:"nbd14"} storageList:{mountPath:"/" total:3898} storageList:{device:"nbd5"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{device:"nbd7"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{device:"nbd8"} storageList:{mountPath:"/persist/agentdebug"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"nbd0"} storageList:{device:"nbd12"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/certs"} storageList:{device:"nbd1"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"vda" total:65536} storageList:{mountPath:"/hostfs" total:279} storageList:{device:"nbd3"} storageList:{device:"nbd2"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{mountPath:"/persist/log"} storageList:{mountPath:"/persist/vault"} storageList:{mountPath:"/persist/nettrace"} bootTime:{seconds:1795054619} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-53602206-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"433cff5c-4f09-4655-8cc4-3d27ec8b42fd" lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-53602206-kvm-amd64 at 2026-11-19T02:16:15.348347076Z\n" lastRebootTime:{seconds:1795054575 nanos:389351881} systemAdapter:{currentIndex:1 status:{version:1 key:"zedagent" timePriority:{seconds:1795054786 nanos:528321580} lastFailed:{seconds:1795054806 nanos:343824908} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 proxy:{} dns:{} err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)" timestamp:{seconds:1795054806 nanos:343656425} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"2769b9ad-0fd2-4204-a2b5-5ab45e0d5e36" config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795054786 nanos:528321580}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"} status:{version:1 key:"zedagent" timePriority:{seconds:1795054545 nanos:593324114} lastFailed:{seconds:1795054822 nanos:144778910} lastSucceeded:{seconds:1795054699 nanos:489249653} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795054825 nanos:341502973} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"2769b9ad-0fd2-4204-a2b5-5ab45e0d5e36" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795054545 nanos:593324114}} pnac_status:{enabled:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795054825 nanos:341502749} severity:SEVERITY_ERROR}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}} restartCounter:1 HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1795054662 nanos:124757415} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"L\xefO\x14b\r\xacn\xcct\xbd\x18\xc1\xb2*\x04r\x81h\xa9\x14\xc6n\xc4G\x9e\x15\xc2\xf3\xf7\"\xba"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} rebootConfigCounter:1 last_boot_reason:BOOT_REASON_REBOOT_CMD hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

Live evidence confirms it exactly: both DPC entries are marked `DPC_FAIL_WITH_IPANDDNS` and `getNextTestableDPCIndex` finds "nothing testable", so `dpcmanager` is permanently wedged with `CurrentIndex:1` pointing at the stale PNAC-enabled DPC whose SCEP cert was already removed. The interface physically moved to the pre-auth VLAN (`172.20.10.123`) but the DPC state the test polls for (PNAC disabled + pre-auth VLAN together) can never be reported since that DPC entry never succeeds.

###### Root cause

This is the identical DPC-fallback oscillation bug already analyzed earlier in this same run and in prior nightlies: the new DPC entry (submitted 02:19:46, `PNAC.Enabled:false`) only ever reaches the authenticated VLAN (`src IP 172.20.20.123`) and times out reaching `adam.evetest`, so it's marked `DPC_FAIL_WITH_IPANDDNS` and never succeeds; `dpcmanager` falls back to `CurrentIndex:1`, the prior DPC which still has `PNAC.Enabled:true, CertEnrollmentProfileName:"new-scep-profile"` — but that one now fails too, since the SCEP cert was already stripped per the test's cycle-1 action ("No certificate enrollment status found for SCEP profile"). `nim` logs show both DPCs as `DPC_FAIL_WITH_IPANDDNS` and `getNextTestableDPCIndex` reporting "nothing testable," so the device is permanently wedged between two broken configs even though `eth0` has physically settled on the pre-auth VLAN (`172.20.10.123`).

Per the ledger, this is a known, recurring issue in the PNAC-disable/DPC-fallback interaction, first observed 2026-11-17 (`TestPNACWithProxy`, run #22) and repeating 2026-11-18 for both `TestPNACWithoutProxy` and `TestPNACWithProxy` (run #24) with the exact same signature. Today's failure is the same mechanism reproducing again, not a new bug.
#### TestPNACWithProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-10.1" serialNumber:"1DE1VVBG" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{mountPath:"/persist/vault"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"nbd5"} storageList:{device:"nbd7"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{mountPath:"/config" total:5} storageList:{mountPath:"/persist/nettrace"} storageList:{mountPath:"/persist/status"} storageList:{mountPath:"/persist/clear"} storageList:{device:"nbd15"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{device:"nbd11"} storageList:{device:"nbd1"} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{device:"nbd8"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/log"} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{device:"nbd6"} storageList:{device:"vda" total:65536} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/certs"} storageList:{device:"nbd3"} storageList:{mountPath:"/persist/ingested"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"nbd0"} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{device:"nbd2"} storageList:{device:"nbd14"} storageList:{mountPath:"/persist/tmp"} storageList:{mountPath:"/" total:3898} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{mountPath:"/hostfs" total:279} storageList:{mountPath:"/persist/checkpoint"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/newlog"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd13"} storageList:{device:"nbd12"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} bootTime:{seconds:1795057017} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-53602206-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"d0b89cbe-ecda-4d25-b036-0ac564162e75" lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-53602206-kvm-amd64 at 2026-11-19T02:56:12.321973412Z\n" lastRebootTime:{seconds:1795056972 nanos:467341940} systemAdapter:{currentIndex:1 status:{version:1 key:"zedagent" timePriority:{seconds:1795057122 nanos:246519860} lastFailed:{seconds:1795057138 nanos:552938455} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 proxy:{} dns:{} err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)" timestamp:{seconds:1795057138 nanos:552486773} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"5c03bb3a-f566-4e07-bff3-752d53f3da99" config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795057122 nanos:246519860}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"} status:{version:1 key:"zedagent" timePriority:{seconds:1795056942 nanos:401136539} lastFailed:{seconds:1795057154 nanos:487641418} lastSucceeded:{seconds:1795057088 nanos:550708919} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795057157 nanos:595672988} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"5c03bb3a-f566-4e07-bff3-752d53f3da99" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1795056942 nanos:401136539}} pnac_status:{enabled:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1795057157 nanos:595672520} severity:SEVERITY_ERROR}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}} restartCounter:1 HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1795057057 nanos:842241368} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"L\xefO\x14b\r\xacn\xcct\xbd\x18\xc1\xb2*\x04r\x81h\xa9\x14\xc6n\xc4G\x9e\x15\xc2\xf3\xf7\"\xba"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} rebootConfigCounter:1 last_boot_reason:BOOT_REASON_REBOOT_CMD hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

This confirms it exactly. Both DPC entries on the device (index 0 — new PNAC-disabled config, and index 1 — the old PNAC-enabled config whose SCEP cert was already stripped) are stuck in `DPC_FAIL_WITH_IPANDDNS`, and `getNextTestableDPCIndex`/`restartVerify` logs repeatedly report `current index 1 new -1` / `DPC verify: nothing testable` — so `dpcmanager` is permanently wedged and can never report the combined "PNAC disabled + pre-auth VLAN" state the test polls for, even though `eth0` has physically moved to the pre-auth VLAN (`172.20.10.123`).

This is the exact same DPC-fallback oscillation bug already diagnosed for `TestPNACWithoutProxy` earlier in this same run (same suite, same device image `53602206`, identical log signature). Per the ledger it's a known, recurring issue first seen 2026-11-17 (`TestPNACWithProxy`, run #22) and repeating on 2026-11-18 (run #24) for both `TestPNACWithoutProxy` and `TestPNACWithProxy` — today's failure is the same mechanism reproducing again, not a new regression.

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

This confirms the exact same deadlock mechanism documented in the ledger: permanently stuck `IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, `onTheDevice false`, and `publishAppInstanceStatus` permanently "suppressed" on edge-dev2, continuing steadily from well before through well after (and still ongoing at 04:31, past the test's 900s timeout). This is the identical `zedkube`/`zedmanager` failover-detection mechanism recorded in the ledger.

I have sufficient evidence to write the root cause now.

**Root cause:** This is the same known `zedkube`/`zedmanager` failover-detection deadlock documented in the ledger, first seen 2026-11-15 (run #19) and recurring on 2026-11-17 (#22) and 2026-11-18 (#23) — today makes four consecutive nightly occurrences. After `edge-dev1` (the original DNID node) was powered off at 04:06:10 and went `SUSPECT` at 04:11:16, the app correctly failed over and briefly ran on `edge-dev2` (confirmed via `app-info`: `RUNNING`/`cluster_app_running:true` at 04:13:52), but the purge was issued at 04:13:59, right as/after that transition. Live logs on edge-dev2 show `zedkube.checkAppsStatus` and `zedmanager.getKubeAppActivateStatus`/`publishAppInstanceStatus` permanently stuck at `IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, `onTheDevice false`, with `publishAppInstanceStatus` continuously "suppressed" from before the test's checkpoint through now (04:31, well past the 900s timeout) — identical to the 2026-11-15/17/18 signature. `kubectl get vmirs,vmi,pods -n eve-kube-app` on all three devices confirms zero objects exist for the app, matching the "found []" variant from the 2026-11-15 entry exactly (as opposed to the "stale generation" variant from other nights). This is a recurring, known issue, not a new bug, and no PR diff was supplied for this investigation.

### TestNodeClusterSuite: failure analysis

#### TestMgmtProxy

##### Failure

```
Timed out waiting for app "c6953e4a-31cd-450a-9c25-d5e1a76676b0" to be scheduled in cluster "mgmtproxy-test-cluster"
```

##### Claude's conclusion

Root cause found with strong live/log evidence.

**Root cause:** The app (`mgmtproxy-test-app`, UUID `c6953e4a…`) never got scheduled because its root volume never left `CREATING_VOLUME` on the designated node (`edge-dev1`) — confirmed live via `VolumeStatus`/`AppInstanceStatus` (`State:109`, `SubState:2`=`PrepareDone`, no error) and `zedkube`'s `ENClusterAppStatus` reporting `AppKubeStatus:NotInCluster` (no pod ever created, no `DomainConfig` ever published). Pillar logs pinpoint the moment it broke: at 03:03:51 volumemgr's async create-worker ran `virtctl image-upload` against the CDI uploadproxy (`RolloutDiskToPVC`), and at 03:04:20 that call exhausted its 10 internal retries and failed with `unexpected return value 503` (the uploadproxy wasn't yet routable to the freshly-created upload pod). The underlying CDI upload pod it had spawned kept running independently in the cluster and actually completed successfully a little later (~03:04:49, confirmed by the `cdi-upload-…` pod's k8s events and the PVC's `cdi.kubevirt.io` annotations all showing `Upload Complete`/`Succeeded`), but volumemgr never logged picking up a corresponding `VolumeWorkResult` (error or success) afterward — the volume was simply left parked in `CREATING_VOLUME/PrepareDone` with no error and nothing to re-drive it, so the 15-minute scheduling wait in `WaitUntilAppIsRunning`/`FindDeviceHostingApp` (edgecluster.go:305) timed out. CPU/iowait on the node was normal (not resource starvation like the `TestVaultZvolTrimReclaimsBlocks` entry).

This is distinct from the two prior `TestNodeClusterSuite` entries in the ledger (one a Proxmox VM-provisioning "no worker upid" failure, the other a `TestThreeNodesCluster` apiserver-discovery/REST-mapper cache bug) and from the containerd-snapshot `CREATING_VOLUME` stall seen for `TestAppLocalInfo`/`lps-app` — none involve this virtctl/CDI-uploadproxy race. `TestMgmtProxy` itself, and this `RolloutDiskToPVC`/uploadproxy-503/stuck-`PrepareDone` mechanism, do not appear anywhere in the ledger, so this looks like a first occurrence, not a known/recurring issue — notably, the volumemgr files implementing this clustered-PVC create/retry path (`retryclustervolume.go`, `acceptclustercontenttree.go`, `pvcadoptprobe.go`) are very recent additions (last touched 2026-10-27), consistent with a still-maturing code path. No PR diff was supplied for this investigation, so no relatedness judgment is given.

### TestPortScanSuite: failure analysis

#### TestExternalPortScanKubevirt

##### Failure

```
Timed out waiting for cluster node "edge-dev" to become ready
```

##### Claude's conclusion

###### Root cause

Live inspection shows `edge-dev`'s k3s node reports `Ready=True`, but `evetest cluster info` shows `storage:{health:SERVICE_STATUS_FAILED}` and `admission_status:NODE_ADMISSION_JOINING` — the node never finishes joining because Longhorn storage never comes up. `kubectl get pods -A` confirms most of `longhorn-system` (csi-attacher/provisioner/resizer/snapshotter, longhorn-csi-plugin, the instance-manager) are stuck in `ContainerCreating`/`CreateContainerError`. Events show why: image pulls for these small (15-35MB) CSI sidecars are taking **5-8 minutes each** instead of seconds, and once pulled, containerd fails with `context deadline exceeded` and `failed to reserve container name ... is reserved for <id>` (a stuck/duplicate container-create race). `uptime`/`vmstat` on the device show load average **9.93 on a 4-vCPU VM** with CPU `wa` (iowait) at 55-64% — the node is severely overloaded, not genuinely broken.

This is the same resource-contention failure mode documented twice already in the ledger: the 2026-11-17 `TestVaultZvolTrimReclaimsBlocks` entry (disk/control-plane starvation from simultaneous kubevirt+CDI+longhorn first-boot on a single 4vCPU/8GB VM) and the 2026-11-15 `edge-dev3` entry (longhorn/CRD stuck during the same rapid-fire bring-up). The exact test (`TestPortScanSuite/TestExternalPortScanKubevirt`) and its generic `WaitForClusterNodeIsReady` message haven't appeared in the ledger before, so this is a new symptom, but it shares the same underlying known/recurring root cause (HV=k single-node bring-up overwhelming a 4vCPU/8GB test VM) that has now manifested at least three times since 2026-11-15.

### TestStorageSuite: failure analysis

#### TestVaultZvolTrimReclaimsBlocks

##### Failure

```
Timed out waiting for cluster node "edge-dev" to become ready
```

##### Claude's conclusion

This confirms the identical mechanism: "housekeeping took too long" kubelet stalls, slow kine SQL inserts (1.3s), and pod image pulls taking 5+ minutes — all symptoms of the same disk/CPU-starvation-driven control-plane slowness seen yesterday.

###### Root cause

Live evidence on the paused device matches last night's (2026-11-18, run #24) `TestStorageSuite/TestVaultZvolTrimReclaimsBlocks` failure almost exactly: `vmstat` shows 40–49% iowait with up to 5 processes blocked on disk, kubelet logs repeated "Housekeeping took longer than expected" (up to 5.7s) and a 1.3s slow SQL insert into the k3s `kine` sqlite store, and `kubectl get pods -A` shows the entire longhorn CSI stack (csi-attacher/provisioner/resizer/snapshotter/csi-plugin) stuck in `ContainerCreating` for 2+ minutes while `cdi-apiserver`, `cdi-deployment`, `cdi-operator`, and both `virt-operator` replicas have already restarted once. `evetest cluster info` confirms `storage:{health:SERVICE_STATUS_FAILED}` even though the k8s node `Ready` condition is `true` — the same contradictory signature as yesterday.

This is a **known, recurring issue**: the identical test, failure message ("Timed out waiting for cluster node \"edge-dev\" to become ready"), and root-cause mechanism (heavy zvol-trim I/O competing with first-boot kubevirt/CDI/longhorn bring-up on a resource-constrained 4-vCPU/8GB VM, starving k3s/kine control-plane writes) was already documented in last night's ledger entry (2026-11-18), where it was noted as the *first* occurrence. Tonight is the second consecutive night this exact failure has reproduced, confirming it as an ongoing resource-starvation problem on this test rather than a one-off flake — it is not a new independent bug.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKubevirtToKubevirt

##### Failure

```
timed out after 10m0.017100613s (excluding download) waiting for app "a15c8270-107b-41d6-8736-a3141867c702" (upgrade-test-app) on device "edge-dev" to reach RUNNING state (last state: HALTING)
```

##### Claude's conclusion

**Root cause:** The app failed to reach RUNNING within the test's 10-minute window because the kubevirt control plane was still recovering from the device reboot performed as part of the baseos upgrade. Live evidence: `app-info` shows the VM's first post-upgrade boot attempt at 04:26:33 hit `appErr: "...failed calling webhook \"virtualmachinereplicaset-validator.kubevirt.io\": ... dial tcp 10.43.17.52:443: connect: connection refused"` at 04:27:23, driving the app into `HALTING` where it stayed (no VMI/VM/VMIRS existed at all afterward — confirmed via `kubectl get vmi,vm,vmirs` returning "No resources found" at the time of the test timeout). `kubectl describe pod virt-api` corroborates: its sandbox was recreated ~10 minutes before investigation (consistent with the post-upgrade reboot), the container restarted later, and its readiness probe was still failing minutes after that due to cert-secret mount races (`object "kubevirt"/"kubevirt-virt-api-certs" not registered`). domainmgr/zedmanager did eventually retry and succeed — `app-info` now shows a new successful boot at 04:38:19 with `state:RUNNING` — but that recovery landed after the test's fixed 10-minute timeout had already fired at ~04:36. The two sibling KVM-hypervisor upgrade tests in the same run (`TestEVEUpgradeKVMtoKVM`, `TestEVEUpgradeKVMtoKVMWithOCIDatastore`) passed, confirming this is specific to the kubevirt control-plane's slow post-reboot bring-up, not a generic upgrade-path regression.

This failure shares its root cause with no other failure in this run — it stands alone. I searched `live-ledger.md` for `kubevirt`, `virt-api`, `webhook`, `virtualmachinereplicaset-validator`, and `TestEVEUpgradeKubevirtToKubevirt` and found no prior match; the ledger's existing kubevirt-related entries concern unrelated issues (zvol-trim I/O contention, longhorn CRD discovery cache corruption, a failover/pod-naming deadlock). So this appears to be a new/first-seen failure mode, not a previously known recurring issue.
#### TestThreeNodesUpgrade

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev2")
```

##### Claude's conclusion

I have enough evidence to conclude.

**Root cause:** All three nodes in `TestThreeNodesUpgrade` independently fell into k3s single-node bootstrap mode instead of joining as a cluster — `k3s-install.log` on edge-dev1, edge-dev2, and edge-dev3 all show `First time for k3s install` / `Single node mode prepare config.yaml for <node>` within the same second the config was applied (04:47:57–04:48:03), confirming `cluster-init.sh`'s one-shot, no-retry check for the `/var/lib/edge-node-cluster-mode` marker lost the race against zedkube processing the `EdgeNodeClusterConfig` on every node this run (not just one, as in the prior occurrence). `kubectl get nodes` on each device independently shows only itself, and the cluster's reported storage health stays `SERVICE_STATUS_FAILED` because each node then tries to stand up its own full kubevirt+CDI+longhorn stack alone, overloading the 4-CPU/8GB VM: `cdi-operator`/`virt-operator` are crash-looping on `leader election lost: context deadline exceeded` against a throttled apiserver, and Longhorn's `engine-image`/`instance-manager` pods have been stuck in `ContainerCreating` for 6+ minutes.

This shares the identical root-cause mechanism as the `TestThreeNodesCluster`/`TestNodeClusterSuite` failure already in the ledger (first recorded 2026-11-15, run #19): the same `cluster-init.sh` first-boot race leaving a node in standalone single-node mode. That prior occurrence affected only `edge-dev3`; this run is a more severe manifestation where all three nodes lost the race simultaneously. So this is a known, recurring issue (present since at least 2026-11-15) rather than a new bug, and it is unrelated to the earlier `TestEVEUpgradeKubevirtToKubevirt` failure investigated in this same run (that one was a post-reboot kubevirt-webhook timing issue in a different suite/test, with no connection to cluster-join bootstrap timing).

## [2026-11-18 -- 0.0.0-17.0-stable-53602206 (run #24)](https://github.com/lf-edge/eve/actions/runs/44219982308)

[Full report](https://lf-edge.github.io/eve/test/17.0-stable/runs/24/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:4, cap:4>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x17ee49a2c830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x17ee499fb860>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 5
```

##### Claude's conclusion

**Root cause:** The test (`passthrough_test.go:396` → `ensureNetworkOrder`/`ensureNetworkInfoOrder` at `nicchange_test.go:177-188`) expects the app's `Network` list in `ZInfoApp` to include the passthrough adapter `ethernet1` alongside the virtual NICs. Live `evetest eve app-info passthrough-app` on the paused device confirms the gap directly: once the app settles into its final `RUNNING` state, `assignedAdapters` correctly reports `ethernet1` (member `eth1`), but `network:` only lists the 4 virtual VIFs (`vif0`, `newvif1`, `newvif2`, `newvif3`) — never `ethernet1` — so the list never reaches the 5 entries the test's `Eventually` polls for, and it times out after 180s. In pillar, `pkg/pillar/cmd/zedagent/handlemetrics.go:1209` builds this `ifNames`/`Network` list solely from `aiStatus.GetAppInterfaceList()` (virtual adapters), with no merge of `aiStatus.IoAdapterList` (passthrough adapters).

This is the identical root cause documented in yesterday's (2026-11-17, run #22) ledger entry for this same test: master commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics") adds exactly this merge via an `orderedAppNetworkEntries` helper, but `git merge-base --is-ancestor 979ea453c HEAD` confirms it is still not present on `17.0-stable` (current HEAD `53602206a`). This is a known, recurring issue — first surfaced in the 2026-11-17 nightly after the NIC-change tests were restored from master on 2026-11-03 — and today's failure is a straightforward repeat of that unfixed backport gap, not a new bug.
#### TestNetworkAdapterPassthroughChange

##### Failure

```

Timed out after 180.000s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:1, cap:1>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x17ee49a2c830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x17ee499fb860>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 2
```

##### Claude's conclusion

Live evidence confirms the pattern exactly: after the app is reconfigured to add passthrough adapter `ethernet1` (member `eth1`) and settles into `RUNNING`, `assignedAdapters` correctly lists it, but `network:` still reports only `vif0` — the test's `Eventually` at `nicchange_test.go:177` keeps waiting for 2 network entries that will never arrive, hence the 180s timeout (`len:1` vs expected `2`).

This is the exact same root cause already documented in this run's `live-investigation.md` for `TestNetworkAdapterPassthrough` (and in the ledger as a known/recurring issue first surfacing 2026-11-17): zedagent's `PublishAppInfoToZedCloud` (`pkg/pillar/cmd/zedagent/handlemetrics.go`) builds the app's `Network` list purely from `aiStatus.GetAppInterfaceList()` (virtual VIFs), with no merge of `IoAdapterList` passthrough adapters. The fix exists on master (commit `979ea453c`, "zedagent: report passthrough NICs in app info and metrics", via an `orderedAppNetworkEntries` helper) but is not present on `17.0-stable` (current HEAD `53602206a`). This `TestNetworkAdapterPassthroughChange` failure is the same missing-backport gap as the other test in this suite run, just manifesting on the "change" variant of the scenario (1 entry present vs. 2 expected, instead of 4 vs. 5) — not a new or independent bug.

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-10.1" serialNumber:"F70G3379" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{mountPath:"/persist/clear"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{mountPath:"/persist/nettrace"} storageList:{mountPath:"/config" total:5} storageList:{mountPath:"/persist/newlog"} storageList:{mountPath:"/persist/status"} storageList:{mountPath:"/persist/vault"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{device:"nbd15"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{device:"nbd5"} storageList:{device:"nbd8"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{device:"nbd3"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{device:"nbd10"} storageList:{device:"nbd12"} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"nbd11"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd2"} storageList:{device:"nbd6"} storageList:{device:"nbd14"} storageList:{mountPath:"/hostfs" total:279} storageList:{device:"nbd1"} storageList:{mountPath:"/" total:3898} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{mountPath:"/persist/ingested"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{device:"nbd13"} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/tmp"} storageList:{mountPath:"/persist/log"} storageList:{device:"nbd7"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{device:"vda" total:65536} storageList:{device:"nbd0"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{mountPath:"/persist/checkpoint"} storageList:{mountPath:"/persist/certs"} storageList:{mountPath:"/persist/memory-monitor/output"} bootTime:{seconds:1794977251} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-53602206-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"b87d3268-7f95-4c0f-94fa-75c720350e2a" lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-53602206-kvm-amd64 at 2026-11-18T04:46:43.769865882Z\n" lastRebootTime:{seconds:1794977204 nanos:112195549} systemAdapter:{currentIndex:1 status:{version:1 key:"zedagent" timePriority:{seconds:1794977490 nanos:212940881} lastFailed:{seconds:1794977535 nanos:429163179} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 proxy:{} dns:{} err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)" timestamp:{seconds:1794977535 nanos:428967601} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"2527b87d-b124-439d-9475-45931e0ea60f" config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794977490 nanos:212940881}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"} status:{version:1 key:"zedagent" timePriority:{seconds:1794977172 nanos:876133708} lastFailed:{seconds:1794977551 nanos:363417873} lastSucceeded:{seconds:1794977321 nanos:356154279} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1794977555 nanos:682111510} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"2527b87d-b124-439d-9475-45931e0ea60f" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794977172 nanos:876133708}} pnac_status:{enabled:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1794977555 nanos:682111330} severity:SEVERITY_ERROR}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}} restartCounter:1 HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1794977292 nanos:643429058} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"\x0cb{E\x99\\\xee\x19\xad#\xc4gy\x99c\x08\xd3&\x02\xd4\x1c\xaf\x9f\xc5Lϟ88\x9eh\x9d"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} rebootConfigCounter:1 last_boot_reason:BOOT_REASON_REBOOT_CMD hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

###### Root cause

Live inspection of `/persist/status/nim/DevicePortConfigList/global.json` shows exactly the mechanism the test is stuck waiting on. There are two DPC entries: the new one (`TimePriority 04:51:30`, `PNAC.Enabled:false` — the disable step) never succeeds (`LastSucceeded: 0001-01-01`, permanently failing with "context deadline exceeded" reaching `adam.evetest` from `src IP 172.20.20.123`, the authenticated-network/VLAN‑20 subnet), while the stale prior DPC (`TimePriority 04:46:12`, still `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`) is the one actually active (`CurrentIndex:1`) and succeeding — but now failing PNAC with "No certificate enrollment status found for SCEP profile" (the cert was already removed in step 1, per the test's own cycle). The live interface (`eth0` = `172.20.10.123`) has in fact already reverted to the pre-auth VLAN (10) physically, but `dpcmanager` is still presenting the old, now-broken PNAC-enabled config as current rather than the new disabled one, so the combined condition the test polls for (PNAC disabled *and* pre-auth VLAN) never becomes simultaneously true, hence the 300s timeout.

This is the same class of bug as last night's (2026‑11‑17, run #22) `TestDeviceConnectivitySuite/TestPNACWithProxy` failure, which failed with the identical message "cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN" and the same mechanism (a PNAC-disable/VLAN-move DPC that can't be verified/promoted, leaving `dpcmanager` oscillating back to the stale cert-broken config). It isn't literally logged in the ledger under this test name before, but the identical failure signature appeared the previous night against the sibling `TestPNACWithProxy` test in the same suite — so this is a recurring issue as of 2026‑11‑17, now reproducing in the `WithoutProxy` variant as well, pointing to a shared bug in the PNAC-disable/DPC-fallback interaction rather than two independent flakes.
#### TestPNACWithProxy

##### Failure

```

Timed out after 300.000s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-10.1" serialNumber:"7XVTNEKF" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{device:"nbd11"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"nbd3"} storageList:{mountPath:"/" total:3898} storageList:{mountPath:"/persist/vault/volumes"} storageList:{device:"nbd7"} storageList:{device:"nbd15"} storageList:{mountPath:"/hostfs" total:279} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{mountPath:"/persist/vault/verifier"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/config" total:5} storageList:{device:"nbd1"} storageList:{mountPath:"/persist/certs"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-1.dat"} storageList:{device:"nbd0"} storageList:{device:"nbd2"} storageList:{mountPath:"/persist/log"} storageList:{device:"nbd8"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{device:"nbd6"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/netdump"} storageList:{device:"nbd9"} storageList:{device:"nbd5"} storageList:{device:"nbd12"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/newlog"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd13"} storageList:{mountPath:"/persist/tmp"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{mountPath:"/persist/nettrace"} storageList:{mountPath:"/persist/checkpoint"} storageList:{mountPath:"/persist/status"} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{mountPath:"/persist/vault"} storageList:{device:"nbd14"} storageList:{mountPath:"/persist/clear"} storageList:{device:"vda" total:65536} storageList:{device:"nbd4"} bootTime:{seconds:1794979872} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-53602206-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"0c108a15-ccd4-40ed-9698-88523e0cff6a" lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-53602206-kvm-amd64 at 2026-11-18T05:30:28.803793961Z\n" lastRebootTime:{seconds:1794979829 nanos:80977214} systemAdapter:{currentIndex:1 status:{version:1 key:"zedagent" timePriority:{seconds:1794980399 nanos:741927833} lastFailed:{seconds:1794980416 nanos:128584378} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 proxy:{} dns:{} err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)" timestamp:{seconds:1794980416 nanos:128426592} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"3c02a588-7cdb-4570-8b22-0004472a6d2b" config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794980399 nanos:741927833}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"} status:{version:1 key:"zedagent" timePriority:{seconds:1794979798 nanos:342299629} lastFailed:{seconds:1794980431 nanos:240414183} lastSucceeded:{seconds:1794980288 nanos:659552349} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1794980436 nanos:644143897} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"3c02a588-7cdb-4570-8b22-0004472a6d2b" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794979798 nanos:342299629}} pnac_status:{enabled:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1794980436 nanos:644143597} severity:SEVERITY_ERROR}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}} restartCounter:1 HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1794979911 nanos:121947342} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"\x0cb{E\x99\\\xee\x19\xad#\xc4gy\x99c\x08\xd3&\x02\xd4\x1c\xaf\x9f\xc5Lϟ88\x9eh\x9d"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} rebootConfigCounter:1 last_boot_reason:BOOT_REASON_REBOOT_CMD hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

###### Root cause

Live inspection of `/persist/status/nim/DevicePortConfigList/global.json` on the paused device shows the identical mechanism already documented in this run's `live-investigation.md` for `TestPNACWithoutProxy`: the new DPC entry (`TimePriority 05:39:59`, `PNAC.Enabled:false` — the disable/VLAN-move step) never succeeds (`LastSucceeded: 0001-01-01`), permanently failing with "All attempts to connect to adam.evetest:443 ... src IP 172.20.20.123 ... context deadline exceeded" — i.e. it can't reach the controller from the pre-auth VLAN. Meanwhile the stale prior DPC (`TimePriority 05:29:58`, still `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`) remains `CurrentIndex:1` (active, last succeeded 05:38:08) because `dpcmanager` falls back to it when the new disable config fails — and that fallback config is itself failing PNAC with "No certificate enrollment status found for SCEP profile \"new-scep-profile\"" (the cert having already been removed per the test's cycle 1). The device's live interface (`eth0`) is still on `172.20.10.123`, the authenticated VLAN, confirming it never actually moved. This is exactly the oscillation pattern the test polls for (disabled PNAC *and* pre-auth VLAN simultaneously) that never resolves, hence the 300s timeout.

This shares the same root cause as the earlier `TestPNACWithoutProxy` failure already investigated in this run (recorded in `live-investigation.md`) — identical failure signature and identical DPC-fallback mechanism. It is also the same class of bug as last night's (2026-11-17, run #22) `TestPNACWithProxy` failure in the ledger, which failed with the exact same message via the same DPC-oscillation mechanism. This is therefore a known, recurring issue in the PNAC-disable/DPC-fallback interaction, now reproducing for the third time across the last two nightly runs (both `WithProxy` and `WithoutProxy` variants), not a new or isolated flake.

### TestLPSSuite: failure analysis

#### TestAppLocalInfo

##### Failure

```
timed out after 5m0.033474174s (excluding download) waiting for app "690f14e4-842b-4eac-a8b4-27f05fac6542" (lps-app) on device "edge-dev" to reach RUNNING state (last state: CREATING_VOLUME)
```

##### Claude's conclusion

**Root cause:** `TestAppLocalInfo` reused device `edge-dev` immediately after `TestRadioSilence` (the previous suite test) deliberately rebooted it via the controller at 02:52:54 (device back up at 02:54:15). When `lps-app`'s volume was created at 02:55:30, `logread` on the device shows `CreateVolume` failing with `PrepareContainerRootDir: Could not create snapshot f81ab362...#0.container... parent snapshot sha256:ff3b32ec... does not exist: not found`, and live inspection confirms containerd's `eve-user-apps` namespace currently has **zero images and zero snapshots** (`ctr -n eve-user-apps image ls` / `snapshot ls` both empty). The pubsub trace shows the content tree's `VolumeRefConfig.VerifyOnly` flipping `true → false` right before volumemgr jumped straight to `CreateVolume`, i.e. volumemgr treated the content as already downloaded/verified (stale persisted `VolumeStatus=LOADED` from before the reboot) and skipped re-populating containerd, but the actual containerd content/snapshot for that image didn't survive the reboot. volumemgr never retried after the single failed attempt at 02:55:31, so the app sat in `CREATING_VOLUME` for the full 5-minute timeout. This does not share a cause with any earlier entry, and a ledger search for "snapshot"/"containerd"/"PrepareContainerRootDir" found no prior occurrence, so this appears to be a new/not-previously-recorded failure mode (post-reboot volumemgr/containerd content desync) rather than a known recurring issue. No PR diff was supplied for this investigation, so no relatedness judgment is given.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestFlowLog

##### Failure

```
timed out after 5m0.002310373s (excluding download) waiting for app "8965a203-c484-459f-80d0-cb01053fc970" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

I have sufficient evidence to write the conclusion.

**Root cause:** `flowlog-test-app`'s content tree (`e2105587-9107-4e0b-95cf-c75f34e1a1ed`, image `lfedge/evetest-ubuntu-ctr:1.0`) entered `RESOLVING_TAG` at 04:07:33 and never progressed — its live `ContentTreeStatus` still shows `State:101` (RESOLVING_TAG) with an empty `ContentSha256` at the time of pause, 5 minutes later. `zedbox` (pid 2932, 23 threads) is alive and the watchdog isn't tripped, and no `ResolveStatus` was ever published (only a `restarted` marker exists, no error/retry record), consistent with the downloader's resolve goroutine being wedged in its very first `resolveTagsToHash`/`remote.Get` call against the SDN registry rather than having hit and recorded a retryable error. `pkg/pillar/cmd/downloader/resolveimg.go` and `syncop.go` still have no `"context"` import, so that OCI tag-resolve path still has no deadline on the underlying registry HTTP call — unchanged from before.

This is the identical, already-documented recurring issue: the ledger shows the exact same `TestLocalNetworkInstanceSuite/TestFlowLog` failure (stuck in `RESOLVING_TAG`, 5-minute timeout, wedged no-timeout resolver) on 2026-11-15 (run #19) and again on 2026-11-17 (run #22), both attributed to this same missing-timeout code path. It is not related to the other unrelated failures logged for this run's suite (e.g. the TestAppNICsSuite passthrough gap, TestDeviceConnectivitySuite SCEP/PNAC issues) — those are separate suites/mechanisms. No PR diff was supplied for this investigation, so no relatedness verdict is given.
#### TestLocalNetInstanceACLsWithFlowLog

##### Failure

```
timed out after 5m0.000064541s (excluding download) waiting for app "8bb9fcf2-d858-46d4-b9cc-f6e7c6f7f327" (acl-app-1) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

**Root cause:** `acl-app-1`'s (and simultaneously `acl-app-2`'s) content-tree resolve of `lfedge/evetest-ubuntu-ctr:1.0` entered `manifestsDescImg`/`remote.Get` against the SDN registry at 04:20:54.321 and never logged completion, error, or retry in the ~5.5 minutes before timeout — no `ResolveStatus` was ever published for either app (`ls /run/downloader/ResolveStatus/` is empty), and `zedbox` (pid 2923) is alive and unwatchdogged, so this is a wedged goroutine, not a crash. I confirmed the registry itself is healthy: `curl` from the device to the same manifest endpoint with the correct Accept headers returns 200 instantly, so the hang is isolated to the resolver's own HTTP call, not the registry.

This is the same root cause already identified for `TestFlowLog`'s failure earlier in this same suite run (also RESOLVING_TAG, same image, same wedged `manifestsDescImg`/`remote.Get` pattern, no ResolveStatus emitted) — both trace back to `pkg/pillar/cmd/downloader/resolveimg.go`/`syncop.go` still lacking any `context` import, meaning the OCI tag-resolve path has no deadline on the underlying registry HTTP call. Per the ledger, this exact failure signature (stuck in RESOLVING_TAG under the 5-minute timeout, attributed to the same missing-timeout resolver code) is a known recurring issue going back to at least 2026-11-15 (run #19) and recurring again on 2026-11-17 (run #22); this is simply a second test within the same nightly run hitting the identical unfixed bug.

### TestNodeClusterResilienceSuite: failure analysis

#### TestVMAppPurgeDuringFailover

##### Failure

```

Timed out after 900.000s.
The function passed to Eventually failed at /evetest/tests/cluster/purge_during_failover_test.go:172 with:
the surviving VMIRS must be the NEW generation "failover-purge-app-98c03-1", not a stale one
Expected
    <string>: failover-purge-app-98c03-0
to equal
    <string>: failover-purge-app-98c03-1
```

##### Claude's conclusion

This confirms the exact same mechanism documented in the ledger: `checkAppsFailover` on edge-dev2 is looking for a pod named for the new generation (`failover-purge-app-98c03-1`) but the actually-running pod is still named for the old generation (`failover-purge-app-98c03-0xpmsv-jxhxv`), so it never matches, `ScheduledOnThisNode`/`AppKubeStatus` stay `false`/`NotInCluster`, `onTheDevice` stays `false`, and `zedmanager.publishAppInstanceStatus` stays permanently suppressed — so no new-generation domain config is ever issued and the stale generation-0 VMIRS just sits there.

###### Root cause

This is the **same known `zedkube`/`zedmanager` failover-detection deadlock recorded in the ledger**, first seen 2026-11-15 (run #19) and recurring again 2026-11-17 (run #22) and now 2026-11-18 (run #23) — three consecutive nightly occurrences, always in `TestNodeClusterResilienceSuite/TestVMAppPurgeDuringFailover`.

Live evidence on edge-dev2 confirms the mechanism directly: `kubectl get vmirs/vmi/pods -n eve-kube-app` shows only the **old**-generation `failover-purge-app-98c03-0` VMIRS/VMI still running (pod `virt-launcher-failover-purge-app-98c03-0xpmsv-jxhxv`), 23 minutes old, with no generation-`1` object ever created. Logs show `zedkube.checkAppsFailover` repeatedly logging `pod virt-launcher-failover-purge-app-98c03-0xpmsv-jxhxv, looking for cont failover-purge-app-98c03-1` — the pod-name match against the new (post-purge) generation never succeeds because the actually-scheduled pod is still the old generation. This leaves `ScheduledOnThisNode=false`/`AppKubeStatus=NotInCluster`, so `zedmanager.getKubeAppActivateStatus` reports `onTheDevice false` continuously (03:44–03:45 and throughout the 900s wait), `publishAppInstanceStatus` stays permanently "suppressed," and `zedmanager` never hands a new domain config to `domainmgr` — so the old-generation VMIRS simply never gets replaced, producing exactly the "stale generation-0 survives" assertion failure seen here.

This is a recurring, known issue (not new), unrelated to the `TestDNIDandBackupDNID`/`TestVMIRSStrandedReplicasRecovery` failures also present in this run's artifact directory. No PR diff was supplied for this investigation.

### TestNodeClusterSuite: failure analysis

#### TestThreeNodesCluster

##### Failure

```
Failed to setup devices [edge-dev1 edge-dev2 edge-dev3]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev1": failed to create VM 118 for device "eve-17216b61-edge-dev1": 500 got no worker upid - start worker failed
```

##### Claude's conclusion

###### Root cause

The test never got a chance to run — `evetest status` confirms the suite failed entirely during device setup, and `evetest eve ssh`/`sdn status` both report **no devices exist** (SDN client not initialized), since teardown wiped everything after the failed setup attempt.

Looking at the `gotest.json` trace: `edge-dev2` (VM 118) and `edge-dev3` (VM 119) were successfully prepared as powered-off Proxmox VMs at 03:19:33 and 03:19:36, but the parallel VM-creation call for `edge-dev1` (also assigned VM id 118, reused from an earlier failed/torn-down attempt) failed at 03:19:36 with `500 got no worker upid - start worker failed` — a Proxmox API error meaning the host's task-worker process couldn't even be spawned for that `qmcreate` call. This happened purely on the Proxmox hypervisor host, before any EVE image booted, so there's no pillar/zedbox state to inspect.

This is the same general class of failure as `TestPcibackErrorSuite/TestReportWarningsOnly` in the 2026-11-17 ledger entry — a Proxmox-side VM-provisioning failure (that one was a storage-lock timeout, `"can't lock file ... got timeout"`) rather than an EVE/pillar defect — but with a different specific error text (`"no worker upid"` vs. the lock-timeout message), and it doesn't appear verbatim anywhere in the ledger, so by the ledger's own search it's not a recorded/known occurrence of this exact message. It does share a plausible mechanism with that prior incident though: both are Proxmox host resource-contention failures surfacing when multiple VMs are provisioned in quick succession (this suite stands up 3 EVE VMs + an SDN VM nearly simultaneously), suggesting a recurring theme of Proxmox host-side task/worker-queue strain under concurrent VM creation rather than two unrelated one-off glitches.

No PR diff was supplied for this investigation, so no relatedness verdict is given.

### TestSecuritySuite: failure analysis

#### TestAppVTPMIdentitySurvivesReboots

##### Failure

```

Timed out after 305.788s.
The function passed to Eventually failed at /evetest/tests/security/vtpm_helpers_test.go:127 with:
read guest TPM NV marker: 
Unexpected error:
    <*fmt.wrapError | 0x1da817e237a0>: 
    unable to reach app "61a6d5d1-de5d-4de2-8574-d3b686eb1ad7" SSH on device "edge-dev": no reachable endpoint among [172.20.20.123:2222]
    {
        msg: "unable to reach app \"61a6d5d1-de5d-4de2-8574-d3b686eb1ad7\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.20.123:2222]",
        err: <*errors.errorString | 0x1da8187f0680>{
            s: "no reachable endpoint among [172.20.20.123:2222]",
        },
    }
occurred
```

##### Claude's conclusion

No direct match — confirmed this is a new finding, not previously recorded in the ledger. I have enough evidence to write the conclusion.

###### Root cause

**Confirmed from live evidence**, not a known/recurring issue per the ledger (no match for `TestAppVTPMIdentitySurvivesReboots` or this failure signature there), and it does not share a root cause with any earlier failure in this run — this was the only failure for `TestSecuritySuite` tonight.

After the test's device reboot completed (~02:55:11), the guest VM for app `vtpm-identity` did not actually come back up until **03:00:18** — a flat 5-minute gap, confirmed via `evetest eve app-info` (no `bootTime` entry between 02:54 and 03:00:18) and via domainmgr's persisted logs, which show zero activity on this app's UUID for that entire window. The guest's SSH port-forward (`172.20.20.123:2222`) was therefore genuinely unreachable the whole time, not a networking bug — current NAT/ACL rules on the device are correct, confirming this. The test's own 305.8s `Eventually` budget expired 2 seconds *before* the VM actually started booting, i.e. this was a hairline-tight race against a fixed internal delay rather than a hang.

Zedmanager's logs pinpoint the mechanism exactly: at the first post-reboot `doUpdate` for this app (02:55:14.140), `checkLowPriorityApps`'s active-app-UUID lookup (`activeapp.LoadActiveAppInstanceUUIDs`, `pkg/pillar/cmd/zedmanager/updatestatus.go:190-210`) returned empty, so the app — even though it really was the active app pre-reboot — got marked `NoBootPriority=true` ("low priority app ..."). Three seconds later the same lookup *did* find this UUID, but that's irrelevant: once `NoBootPriority` is set, the app can only be released by `checkLowPriorityApps` (`pkg/pillar/cmd/zedmanager/zedmanager.go:690-716`), gated by `runningCount >= len(activeMap)` **or** a hardcoded `waitForAppsToStartTimeout = 5 * time.Minute` fallback (`zedmanager.go:41`). Since this device runs only this one app, `activeMap` = {itself}, and it can never count as "running" while it's the very thing being gated — a self-referential deadlock that only the 5-minute timeout can break. That is exactly why the VM booted at 03:00:18, 5:04 after the 02:55:14 gating decision.

This is a genuine zedmanager boot-order logic gap (a race between `activeapp.LoadActiveAppInstanceUUIDs` and the first post-reboot config pass, worsened by the single-app degenerate case), not test flakiness — it will deterministically cost ~5 minutes on every device reboot that hits this race, which is why it landed just over this test's timeout budget.

### TestStorageSuite: failure analysis

#### TestVaultZvolTrimReclaimsBlocks

##### Failure

```
Timed out waiting for cluster node "edge-dev" to become ready
```

##### Claude's conclusion

###### Root cause

Live inspection shows the device is **I/O-saturated**, not actually stuck: `vmstat` shows 64–71% iowait with 11 processes blocked on disk, and `dmesg` shows a clocksource watchdog skip of 4.4s (a multi-second scheduling stall). `/persist/kubelog/k3s.log` shows the root cause chain: k3s's sqlite-backed `kine` store is timing out (`rpc error: ... DeadlineExceeded ... kine.sock`), which cascades into apiserver `http: Handler timeout`s on nearly every request, which in turn causes repeated leader-election losses for `cdi-operator`, `cdi-controller`, and `virt-operator` (`context deadline exceeded` on `coordination.k8s.io` lease PUTs). Those operators are consequently CrashLoopBackOff'ing, and the longhorn CSI plugin/csi-attacher/csi-provisioner pods have been stuck in `ContainerCreating` for 2+ minutes — so storage never reaches ready. `evetest cluster info` confirms this directly: `storage:{health:SERVICE_STATUS_FAILED}` even though the k8s node `Ready` condition itself is `true`.

`TestVaultZvolTrimReclaimsBlocks` is a heavy zvol-trim I/O test running under `HV=k` (kubevirt/k3s), so its own disk workload is competing with k3s/kine/etcd writes and the simultaneous first-boot bring-up of kubevirt+CDI+longhorn on a single 4-vCPU/8GB VM — overwhelming the shared disk and starving the control plane's lease/heartbeat traffic within the test's 20-minute `WaitForClusterNodeIsReady` window.

This is a different mechanism from the `TestNodeClusterSuite/TestThreeNodesCluster` ledger entry (2026-11-17), which was a kube-apiserver discovery/REST-mapper cache bug after a first-boot single-vs-cluster race — here the apiserver's discovery works fine, it's genuine I/O/CPU resource starvation. `TestStorageSuite`/`TestVaultZvolTrimReclaimsBlocks` does not appear anywhere in `live-ledger.md`, so this is the first recorded occurrence of this specific failure — not a known/recurring issue as far as the ledger shows, though it shares a superficial symptom (stuck longhorn/CDI pods) with that unrelated cluster-suite bug from the prior run.

### TestSwitchNetworkInstanceSuite: failure analysis

#### TestSwitchNIPortConfigRace

##### Failure

```

Told to stop trying after 2.152s.
Stop waiting for: multiswitch-ni is ONLINE with 2 assigned adapters
Network instance is in error state
networkID:"20dca189-65b4-4892-9638-09904a5aba59" networkVersion:"1" instType:1 displayname:"multiswitch-ni" bridgeNum:1 networkErr:{description:"failed to select ports for network instance 20dca189-65b4-4892-9638-09904a5aba59: no port is matching label 'multiswitch-ports'" timestamp:{seconds:1794976050 nanos:191116047} severity:SEVERITY_ERROR} state:ZNETINST_STATE_ERROR mtu:1500
```

##### Claude's conclusion

###### Root cause

This is a transient convergence race, not a real network-instance misconfiguration. The live config (`evetest eve config`) confirms `ethernet1`/`ethernet2` are correctly labeled `multiswitch-ports`, and the device's live `ni-info` shows `multiswitch-ni` *did* reach `ZNETINST_STATE_ONLINE` with both `ethernet1`/`ethernet2` assigned — just not within the window the test allowed.

Device logs pulled directly from `/persist/newlog/collect` on the paused device show why: right after the port config was applied, `DeviceNetworkStatus` briefly carried `BridgeIfInstanceID: 0` for the two `multiswitch-ports`-labeled interfaces (eth1/eth2), i.e. zedrouter/nim hadn't yet finished associating those ports with their bridges in the DPC. Zedrouter's port-selection ran during exactly this gap at 04:27:30 and (correctly, for that instant) reported "no port is matching label 'multiswitch-ports'" → NI state ERROR. The DPC was still in `DPC_IPDNS_WAIT`/retry at 04:27:36 (`nim` log: "DPC verify: ports ... not ready: will retry"), and only once eth1/eth2 got their IP/DNS test results populated did the bridge association settle and the NI flip ERROR→ONLINE at 04:27:37 — about 7s after the error, but the test's `Eventually` only waited 2.152s before failing (`switch_config_race_test.go:318`).

This is literally the race the test's name (`TestSwitchNIPortConfigRace`) is designed to exercise, but its timeout here is too tight for the convergence time actually observed in this run; it's not an independent regression unrelated to the suite's purpose. The ledger has no prior entry for `TestSwitchNetworkInstanceSuite`/`TestSwitchNIPortConfigRace` (only `TestAppNICsSuite`, `TestDeviceConnectivitySuite`, `TestLocalNetworkInstanceSuite`, `TestNodeClusterResilienceSuite`, `TestNodeClusterSuite`, `TestPcibackErrorSuite` appear in the 2026-11-15/11-17 entries), so this is a new/first occurrence, not a known recurring failure, and it shares no root cause with those earlier logged failures.

## [2026-11-17 -- 0.0.0-17.0-stable-1f5bee62 (run #22)](https://github.com/lf-edge/eve/actions/runs/43999720381)

[Full report](https://lf-edge.github.io/eve/test/17.0-stable/runs/22/)

### TestAppNICsSuite: failure analysis

#### TestNetworkAdapterPassthrough

##### Failure

```

Timed out after 180.001s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:4, cap:4>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x18669ce00830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x18669cdecd20>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 5
```

##### Claude's conclusion

I have enough evidence; no need for further lookups.

**Root cause:** The test's final assertion (`ensureNetworkOrder` at `passthrough_test.go:397`, resolving through `ensureNetworkInfoOrder` at `nicchange_test.go:177`) expects the app's reported `Network` list to include the directly-assigned passthrough adapter `ethernet1` alongside the four virtual NICs (5 entries total). Live `evetest eve app-info` on the paused device shows only 4 `network` entries (`vif0`, `newvif1`, `newvif2`, `newvif3`) — `ethernet1` is reported solely under `assignedAdapters`, never added to `Network`. This matches the current `pkg/pillar/cmd/zedagent/handlemetrics.go::PublishAppInfoToZedCloud`, whose `Network` loop is built purely from `aiStatus.GetAppInterfaceList()` (virtual VIFs only, via `AppNetAdapters`) with no code path for `IoAdapterList`/passthrough adapters. On `master`, commit `979ea453c` ("zedagent: report passthrough NICs in app info and metrics") adds exactly this behavior via a new `orderedAppNetworkEntries` helper that merges virtual and directly-assigned adapters — but that commit is not an ancestor of this `17.0-stable` branch. This `evetest` test file was restored unmodified from master (`aff0ee204`, "evetest: restore NIC change tests"), so it carries an expectation the corresponding pillar feature backport never brought along. This is not a flake and doesn't share a cause with the unrelated `TestFlowLog`/cluster failures in the 2026-11-15 ledger entry; it is also not previously listed in the ledger, so this appears to be a newly-surfaced gap (missing backport) rather than a recurring/known issue, first exposed now that the NIC-change tests were restored on 2026-11-03.
#### TestNetworkAdapterPassthroughChange

##### Failure

```

Timed out after 180.001s.
The function passed to Eventually failed at /evetest/tests/networking/nicchange_test.go:177 with:
Expected
    <[]*info.ZInfoNetwork | len:1, cap:1>: [
        {
            state: {
                NoUnkeyedLiterals: {},
                DoNotCompare: [],
                DoNotCopy: [],
                atomicMessageInfo: {
                    GoReflectType: <*reflect.rtype | 0x15a7e60>{
                        t: {Size_: 0x8, PtrBytes: 0x8, Hash: 300382088, TFlag: 41, Align_: 8, FieldAlign_: 8, Kind_: 22, Equal: 0x41a620, GCData: 1, Str: 204503, PtrToThis: 0},
                    },
                    Desc: <*filedesc.Message | 0x18669ce00830>{
                        Base: {
                            L0: {
                                FullName: "org.lfedge.eve.info.ZInfoNetwork",
                                ParentFile: {
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescriptor: ..., NumEnums: ..., NumMessages: ..., NumExtensions: ..., NumServices: ..., TypeResolver: ..., FileRegistry: ...},
                                        allEnums: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allMessages: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        allExtensions: [],
                                        allServices: [],
                                    },
                                    L1: {
                                        Syntax: 3,
                                        Edition: 999,
                                        Path: "info/info.proto",
                                        Package: "org.lfedge.eve.info",
                                        Enums: {List: ..., once: ..., byName: ...},
                                        Messages: {List: ..., once: ..., byName: ...},
                                        Extensions: {List: ..., once: ..., byName: ...},
                                        Services: {List: ..., once: ..., byName: ...},
                                        EditionFeatures: {
                                            StripEnumPrefix: ...,
                                            IsFieldPresence: ...,
                                            IsLegacyRequired: ...,
                                            IsOpenEnum: ...,
                                            IsPacked: ...,
                                            IsUTF8Validated: ...,
                                            IsDelimitedEncoded: ...,
                                            IsJSONCompliant: ...,
                                            GenerateLegacyUnmarshalJSON: ...,
                                            APILevel: ...,
                                        },
                                    },
                                    once: 1,
                                    mu: {
                                        _: {},
                                        mu: {state: ..., sema: ...},
                                    },
                                    L2: {
                                        Options: 0x8e0b20,
                                        Imports: [..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ..., ...],
                                        OptionImports: nil,
                                        Locations: {List: ..., File: ..., once: ..., byPath: ...},
                                    },
                                },
                                Parent: <*filedesc.File | 0x18669cdecd20>{
                                    fileRaw: {
                                        builder: {GoPackagePath: ..., RawDescrip...

Gomega truncated this representation as it exceeds 'format.MaxLength'.
Consider having the object provide a custom 'GomegaStringer' representation
or adjust the parameters in Gomega's 'format' package.

Learn more here: https://onsi.github.io/gomega/#adjusting-output

to have length 2
```

##### Claude's conclusion

This confirms it: live `app-info` shows `assignedAdapters` now contains `ethernet1` (the passthrough NIC added at runtime via adapter-change), but `network` still only has the single `vif0` entry — `ethernet1` never gets added to the `Network` list the test checks.

**Root cause:** Same gap as the earlier `TestNetworkAdapterPassthrough` failure in this run — zedagent's `PublishAppInfoToZedCloud` (`pkg/pillar/cmd/zedagent/handlemetrics.go`) builds `Network` only from `aiStatus.GetAppInterfaceList()` (virtual VIFs), with no path for directly-assigned/passthrough adapters (`IoAdapterList`). Live `evetest eve app-info` confirms this directly: after the adapter-change config bumps the app to use passthrough `ethernet1` (`eth1`), the status correctly shows `assignedAdapters:{...name:"ethernet1"...}`, but `network` still lists only `vif0` — exactly matching `ensureNetworkInfoOrder` expecting 2 entries and getting 1. This is the master-only fix (`979ea453c`, "zedagent: report passthrough NICs in app info and metrics") not being present on `17.0-stable`, which the NIC-change tests (restored from master via `aff0ee204`) now exercise. This is the identical root cause documented in this run's earlier `TestNetworkAdapterPassthrough` failure, not a separate bug, and it is not yet listed in the ledger since this is the first nightly run to surface it (following the 2026-11-03 test restoration).

### TestDeviceConnectivitySuite: failure analysis

#### TestPNACWithoutProxy

##### Failure

```

Timed out after 180.001s.
Expected to satisfy: Device has enrolled certificate for 802.1x
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-10.1" serialNumber:"TNJ8YBB4" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"nbd0"} storageList:{mountPath:"/persist/agentdebug"} storageList:{mountPath:"/persist/newlog"} storageList:{mountPath:"/persist/log"} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{device:"nbd14"} storageList:{device:"nbd3"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{device:"nbd15"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{device:"nbd10"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/" total:3898} storageList:{device:"nbd1"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd12"} storageList:{device:"nbd2"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"nbd5"} storageList:{mountPath:"/persist/nettrace"} storageList:{mountPath:"/persist/clear"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{mountPath:"/hostfs" total:279} storageList:{mountPath:"/persist/vault/volumes"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{mountPath:"/persist/tmp"} storageList:{device:"nbd9"} storageList:{mountPath:"/persist/checkpoint"} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{device:"nbd8"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/certs"} storageList:{device:"nbd6"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/clear/volumes"} storageList:{device:"nbd11"} storageList:{mountPath:"/persist/vault"} storageList:{device:"nbd7"} storageList:{mountPath:"/persist/status"} storageList:{mountPath:"/config" total:5} storageList:{device:"vda" total:65536} storageList:{mountPath:"/persist/vault/verifier"} storageList:{device:"nbd13"} bootTime:{seconds:1794881727} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-1f5bee62-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"87866b12-5946-4178-894d-8fe5c6a889f9" lastRebootReason:"NORMAL: First boot of device - at 2026-11-17T02:15:58.453655005Z" lastRebootTime:{seconds:1794881758 nanos:453655005} systemAdapter:{status:{version:1 key:"zedagent" timePriority:{seconds:1794881841 nanos:619860731} lastSucceeded:{seconds:1794881849 nanos:997066748} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"SCEP GetCACert failed: SCEP GetCACert request failed (HTTP status 0): All attempts to connect to http://scep-server.test:8080/scep?message=scep-test&operation=GetCACert failed: send via eth0 with src IP 172.20.10.123: Get \"http://scep-server.test:8080/scep?message=scep-test&operation=GetCACert\": dial tcp: lookup scep-server.test on 127.0.0.1:53: skipped nameserver 127.0.0.1:53: DNS server is from a different network" timestamp:{seconds:1794881852 nanos:319498222} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"bd8d6a38-1b1f-403c-87a7-ba040eab25fe" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794881841 nanos:619860731}} pnac_status:{enabled:true err:{description:"SCEP GetCACert failed: SCEP GetCACert request failed (HTTP status 0): All attempts to connect to http://scep-server.test:8080/scep?message=scep-test&operation=GetCACert failed: send via eth0 with src IP 172.20.10.123: Get \"http://scep-server.test:8080/scep?message=scep-test&operation=GetCACert\": dial tcp: lookup scep-server.test on 127.0.0.1:53: skipped nameserver 127.0.0.1:53: DNS server is from a different network" timestamp:{seconds:1794881852 nanos:317423708} severity:SEVERITY_ERROR}}}}} HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1794881826 nanos:863416223} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"o\xf6\x8eb\xe93o+}~\xfd\xbc\xc5\xdd\xf4\xb9\xbaOm5\xb7q\x82\xdb\xf6\xc0\x92\xc8u\xc8\x1d\x88"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} last_boot_reason:BOOT_REASON_FIRST hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE error:{description:"[ATTEST] No escrow data" timestamp:{seconds:1794881830 nanos:744794011} severity:SEVERITY_ERROR}} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev" enrolled_certs:{cert_enrollment_profile_name:"scep-test" subject:{} issuer:{} renew_period_percent:50 status:CERT_STATUS_ENROLLMENT_FAILED err:{description:"SCEP GetCACert failed: SCEP GetCACert request failed (HTTP status 0): All attempts to connect to http://scep-server.test:8080/scep?message=scep-test&operation=GetCACert failed: send via eth0 with src IP 172.20.10.123: Get \"http://scep-server.test:8080/scep?message=scep-test&operation=GetCACert\": dial tcp: lookup scep-server.test on 127.0.0.1:53: skipped nameserver 127.0.0.1:53: DNS server is from a different network" timestamp:{seconds:1794881852 nanos:317423708} severity:SEVERITY_ERROR}}
```

##### Claude's conclusion

###### Root cause

The test's own config intentionally set `scep.retry.interval` to `10` seconds (visible in the device's reported `configItemStatus`), presumably so SCEP/802.1x enrollment retries would be fast enough for a 180s test window — but pillar's `SCEPRetryInterval` global setting enforces a minimum of 60s (`types/global.go:1394`: `AddIntItem(SCEPRetryInterval, 5*MinuteInSec, MinuteInSec, HourInSec)`), so the value was rejected and silently fell back to the **5-minute default**. On the device, the first enrollment attempt (right after boot/DHCP) hit two transient network-bringup errors in a row — `bind: cannot assign requested address` (source IP not yet usable) then a DNS resolve that fell through to `127.0.0.1:53` and got skipped as "from a different network" (`controllerconn/send.go:1037`) — both around 02:17:16–02:17:32. Because the effective retry interval was 300s rather than the intended 10s, the next attempt didn't fire until 02:22:17, and enrollment actually succeeded there (cert published, WPA-Supplicant/802.1x config pushed at 02:22:20) — about 5 minutes after boot, well past the test's 180s timeout, so the test saw the stale `CERT_STATUS_ENROLLMENT_FAILED` snapshot and timed out on a condition that in fact resolved itself shortly after.

This doesn't match any entry in the ledger (which only covers `TestLocalNetworkInstanceSuite`/`TestNodeClusterResilienceSuite` failures from 2026-11-15), so this is the first occurrence of this `TestDeviceConnectivitySuite`/`TestPNACWithoutProxy` failure, not a known recurring issue. It also doesn't share a root cause with the earlier-logged failures (those were a wedged image-resolve goroutine and cluster-failover bugs, unrelated to SCEP/DNS). The underlying issue is best characterized as a test/config mismatch (the attempted 10s interval silently clamped to 300s) compounded by a brief, early-boot DNS flakiness — not a product-side bug in the enrollment logic itself.
#### TestPNACWithProxy

##### Failure

```

Timed out after 300.001s.
Expected to satisfy: cycle 1: enrolled certificate removed, PNAC disabled and the port moved to the pre-auth VLAN
machineArch:"x86_64" cpuArch:"x86_64" platform:"x86_64" ncpu:4 memory:7797 storage:42022 powerCycleCounter:-1 minfo:{manufacturer:"QEMU" productName:"Standard PC (Q35 + ICH9, 2009)" version:"pc-q35-10.1" serialNumber:"6LMZWK1V" UUID:"Not Settable" biosVendor:"EDK II" biosVersion:"unknown" biosReleaseDate:"02/02/2022"} assignableAdapters:{type:PhyIoNetEth name:"ethernet0" members:"ethernet0" usedByBaseOS:true ioAddressList:{macAddress:"da:39:78:d0:19:f2"} usage:PhyIoUsageMgmtAndApps} dns:{DNSservers:"10.16.16.25:53"} storageList:{mountPath:"/hostfs" total:279} storageList:{mountPath:"/persist/agentdebug"} storageList:{device:"nbd0"} storageList:{device:"nbd4"} storageList:{mountPath:"/persist/vault/downloader"} storageList:{device:"vda2" total:10240 partitionLabel:"IMGA" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"} storageList:{device:"nbd2"} storageList:{device:"vda1" total:2048 partitionLabel:"EFI System" partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"} storageList:{device:"nbd7"} storageList:{device:"vda" total:65536} storageList:{mountPath:"/persist/clear/volumes"} storageList:{mountPath:"/persist/containerd-system-root"} storageList:{mountPath:"/persist/vault/verifier"} storageList:{mountPath:"/persist/vault/volumes"} storageList:{device:"nbd3"} storageList:{device:"nbd9"} storageList:{device:"/persist/vector/data/buffer/v2/dev_upload_socket/buffer-data-0.dat"} storageList:{device:"nbd14"} storageList:{mountPath:"/persist/nettrace"} storageList:{device:"nbd1"} storageList:{mountPath:"/persist/vault/containerd"} storageList:{device:"nbd11"} storageList:{mountPath:"/persist/patchEnvelopesCache"} storageList:{mountPath:"/persist/certs"} storageList:{device:"nbd12"} storageList:{mountPath:"/persist/tmp"} storageList:{mountPath:"/config" total:5} storageList:{mountPath:"/persist" total:42022 storageLocation:true} storageList:{mountPath:"/persist/checkpoint"} storageList:{device:"nbd15"} storageList:{device:"nbd5"} storageList:{mountPath:"/persist/newlog"} storageList:{mountPath:"/persist/patchEnvelopesUsageCache"} storageList:{device:"vda9" total:43001 partitionLabel:"P3" partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"} storageList:{mountPath:"/persist/log"} storageList:{mountPath:"/persist/netdump"} storageList:{mountPath:"/persist/vault"} storageList:{device:"vda4" total:5 partitionLabel:"CONFIG" partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"} storageList:{mountPath:"/persist/memory-monitor/output"} storageList:{device:"nbd8"} storageList:{mountPath:"/persist/pubsub-large"} storageList:{device:"nbd6"} storageList:{mountPath:"/persist/ingested"} storageList:{mountPath:"/persist/status"} storageList:{device:"nbd10"} storageList:{mountPath:"/" total:3898} storageList:{device:"/persist/vector/data/buffer/v2/keep_sent_queue_socket/buffer-data-0.dat"} storageList:{device:"nbd13"} storageList:{device:"vda3" total:10240 partitionLabel:"IMGB" partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6" partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"} storageList:{mountPath:"/persist/clear"} bootTime:{seconds:1794882565} swList:{activated:true partitionLabel:"IMGA" partitionDevice:"/dev/vda2" partitionState:"active" status:INSTALLED shortVersion:"0.0.0-17.0-stable-1f5bee62-kvm-amd64" downloadProgress:100 userStatus:UPDATED} swList:{partitionLabel:"IMGB" partitionDevice:"/dev/vda3" partitionState:"unused" status:INITIAL} HostName:"10eae1f4-e713-48b7-9c6c-04c96c4bc0b2" lastRebootReason:"NORMAL: controller reboot at EVE version 0.0.0-17.0-stable-1f5bee62-kvm-amd64 at 2026-11-17T02:28:42.796640498Z\n" lastRebootTime:{seconds:1794882522 nanos:835699880} systemAdapter:{currentIndex:1 status:{version:1 key:"zedagent" timePriority:{seconds:1794882740 nanos:463465742} lastFailed:{seconds:1794882761 nanos:558542964} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 proxy:{} dns:{} err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)" timestamp:{seconds:1794882761 nanos:558222303} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"19160941-6dbb-4be5-aa2a-d70d6aa5a8a8" config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794882740 nanos:463465742}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"} status:{version:1 key:"zedagent" timePriority:{seconds:1794882489 nanos:592912654} lastFailed:{seconds:1794882778 nanos:189751146} lastSucceeded:{seconds:1794882638 nanos:3850083} ports:{ifname:"eth0" name:"ethernet0" isMgmt:true free:true dhcpType:4 subnet:"172.20.10.0/24" domainname:"test." proxy:{} macAddr:"da:39:78:d0:19:f2" IPAddrs:"172.20.10.123" defaultRouters:"172.20.10.1" dns:{DNSservers:"10.16.16.25" DNSdomain:"test."} up:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1794882782 nanos:116715925} severity:SEVERITY_ERROR} usage:PhyIoUsageMgmtAndApps networkUUID:"19160941-6dbb-4be5-aa2a-d70d6aa5a8a8" mtu:1500 config_source:{origin:NETWORK_CONFIG_ORIGIN_CONTROLLER submitted_at:{seconds:1794882489 nanos:592912654}} pnac_status:{enabled:true err:{description:"No certificate enrollment status found for SCEP profile \"new-scep-profile\"" timestamp:{seconds:1794882782 nanos:116715758} severity:SEVERITY_ERROR}}} lastError:"All attempts to connect to adam.evetest:443/api/v2/edgedevice/ping failed: send via eth0 with src IP 172.20.20.123: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}} restartCounter:1 HSMStatus:NOTFOUND dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED info:"TPM is either absent or not in use" vaultList:{name:"Application Data Store" status:DATASEC_AT_REST_DISABLED vaultErr:{description:"TPM is either absent or not in use" timestamp:{seconds:1794882606 nanos:719915134} severity:SEVERITY_ERROR} pcrStatus:PCR_DISABLED unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}} sec_info:{sha_root_ca:"o\xf6\x8eb\xe93o+}~\xfd\xbc\xc5\xdd\xf4\xb9\xbaOm5\xb7q\x82\xdb\xf6\xc0\x92\xc8u\xc8\x1d\x88"} configItemStatus:{configItems:{key:"app.allow.vnc" value:{value:"true"}} configItems:{key:"debug.default.loglevel" value:{value:"debug"}} configItems:{key:"debug.default.remote.loglevel" value:{value:"debug"}} configItems:{key:"debug.enable.console" value:{value:"true"}} configItems:{key:"debug.enable.ssh" value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}} configItems:{key:"newlog.allow.fastupload" value:{value:"true"}} configItems:{key:"scep.retry.interval" value:{value:"300" error:"***ParseItem: Error in parsing Item. Replacing it with existing Value. key: scep.retry.interval, value: 10, Existing Value: {Key:scep.retry.interval ItemType:1 IntValue:300 StrValue: BoolValue:false TriStateValue:0}. Err: value out of bounds. Parsed value: 10, Max: 3600, Min: 60"}} configItems:{key:"timer.config.interval" value:{value:"5"}} configItems:{key:"timer.deviceinfo.interval" value:{value:"30"}} configItems:{key:"timer.download.retry" value:{value:"60"}} configItems:{key:"timer.location.app.interval" value:{value:"20"}} configItems:{key:"timer.location.cloud.interval" value:{value:"300"}} configItems:{key:"timer.metric.interval" value:{value:"20"}} configItems:{key:"timer.port.testbetterinterval" value:{value:"60"}} configItems:{key:"timer.test.baseimage.update" value:{value:"60"}}} rebootConfigCounter:1 last_boot_reason:BOOT_REASON_REBOOT_CMD hardware_watchdog_present:true capabilities:{HWAssistedVirtualization:true IOVirtualization:true} state:ZDEVICE_STATE_ONLINE storage_info:{pool_name:"/persist" storage_type:STORAGE_TYPE_INFO_EXT4 storage_state:STORAGE_STATUS_ONLINE disks:{disk_name:{name:"/dev/vda9" serial:"unknown"} status:STORAGE_STATUS_ONLINE smart_status:"failed"}} attestation_info:{state:ATTESTATION_STATE_COMPLETE} api_capability:API_CAPABILITY_APP_INSTANCE_NET_INTERFACE_CHANGE optional_capabilities:{hw_inventory_support:true} device_name:"edge-dev"
```

##### Claude's conclusion

I have enough evidence now to write the root cause.

###### Root cause

Live inspection of the device's `DevicePortConfigList` (`/run/nim/dummy/DevicePortConfig/*.json` and `/run/nim/DeviceNetworkStatus/global.json`) shows the device never settled into the state the test waits for. The controller pushed a new DPC at `02:32:20` with `PNAC.Enabled:false` (the disable step); that DPC moved the port to a different VLAN (DHCP gave it `172.20.20.123` instead of the authenticated `172.20.10.123`) but then **failed permanently** — `LastFailed:02:32:41`, `LastSucceeded: 0001-01-01` — with the error "All attempts to connect to adam.evetest:443 ... src IP 172.20.20.123 ... context deadline exceeded", i.e. the pre-auth VLAN has no path back to the controller for this DPC. Because that disable/VLAN-move DPC never succeeds, `dpcmanager` falls back to the prior, still-cached DPC (submitted `02:28:09`, `PNAC.Enabled:true`, `CertEnrollmentProfileName:"new-scep-profile"`), which is the one currently active (`CurrentIndex:1` in `DeviceNetworkStatus`) and successfully reaches the controller every ~5s. But that fallback config is now failing continuously with `"No certificate enrollment status found for SCEP profile \"new-scep-profile\""`, consistent with the enrolled cert for that profile already having been removed (step 1 of the test's cycle). So the device is oscillating: cert removed ✓, but PNAC-disable/VLAN-move DPC can't survive because it can't reach the controller (this is the "WithProxy" variant, so it presumably needs a working proxy path through the pre-auth VLAN that isn't functioning here), causing `dpcmanager` to keep reverting to the old PNAC-enabled config and never reporting the combined "disabled + pre-auth VLAN" state the test polls for — hence the 300s timeout.

This shares the general theme of the earlier `TestPNACWithoutProxy` failure logged in this same run (both are PNAC/SCEP state-machine timing issues in `TestDeviceConnectivitySuite`), but the proximate mechanism is different: that one was a SCEP-retry-interval clamp (10s silently became 300s) delaying CA enrollment, whereas this one is a DPC-fallback loop caused by the PNAC-disable/VLAN-move config being unable to reach the controller. Not a mechanical duplicate, but plausibly the same class of bug in the PNAC/DPC interaction under this test suite. This specific failure doesn't appear in the ledger (which only has 2026-11-15 entries for unrelated suites), so it's not yet a known/recurring issue for `TestDeviceConnectivitySuite`.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestFlowLog

##### Failure

```
timed out after 5m0.000062907s (excluding download) waiting for app "0346148d-d62f-421a-95d5-7656e7e90cad" (flowlog-test-app) on device "edge-dev" to reach RUNNING state (last state: RESOLVING_TAG)
```

##### Claude's conclusion

I have enough evidence now to write the conclusion.

**Root cause:** `flowlog-test-app` is stuck permanently in `RESOLVING_TAG`. Live device logs show downloader entered `Resolving config <lfedge/evetest-ubuntu-ctr:1.0>` at `03:14:10.783` for content-tree `a0fdf633-...` and never logged a completion ("Resolve config Done"), error, or retry in the ~6 minutes since (two earlier, unrelated resolves of the same image for `app1`/`app2` completed in under half a second each, so this is a hang specific to this one attempt, not a slow registry). `zedbox` (pid 2882) is still alive and the watchdog is unaffected — this is a wedged goroutine, not a crash. Manually querying the SDN registry (`192.168.170.2:5000`) for `/v2/`, `/v2/_catalog`, and the manifest (with correct Accept headers) all succeeded instantly just now, confirming the registry itself is healthy and the hang is isolated to that one resolve call. `pkg/pillar/cmd/downloader/resolveconfig.go` and `syncop.go` still import no `context` package on this branch, so the OCI tag-resolve path still has no deadline on the underlying HTTP call to the registry — unchanged since the last occurrence.

This is the same failure, with the same root cause, as the `TestFlowLog` entry in the ledger from the 2026-11-15 nightly run (#19): a resolver goroutine wedged on `remote.Get`/manifest resolution with no timeout, timing out the test at 5 minutes. This is therefore a known, recurring issue, first recorded on 2026-11-15 and still present/unfixed on 2026-11-17. No PR diff was provided for this run, so no relatedness verdict applies.

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

This confirms the deadlock: `AppKubeStatus=NotInCluster`, `ScheduledOnThisNode=false`, `IsDNidNode=false` persisting steadily on edge-dev2 for the whole 15-minute wait, with `zedmanager.publishAppInstanceStatus` permanently "suppressed" and `onTheDevice false` — zedmanager never hands a new-generation domain config to domainmgr, so no VMIRS of either generation is ever created after the old one is torn down. I have enough evidence.

**Root cause:** This is the same `zedkube`/`zedmanager` failover-detection deadlock documented in the ledger's 2026-11-15 entry (also `TestVMAppPurgeDuringFailover`, a different assertion line but the identical mechanism): with `dnidOutageThresholdKey` pinned high, `onTheDeviceForApp` on the node now hosting the app (edge-dev2) never returns true because `checkAppsFailover`'s pod-name matching can't recognize the app as scheduled there once the purge renames the expected pod to the new generation, so `zedmanager` never issues the new domain config. Live evidence from edge-dev2 confirms it directly: `kubectl get vmirs/vmi/pods -n eve-kube-app` show **zero** objects for the app (the old generation's VMI/pod were torn down by ~03:08–03:09 and nothing was ever recreated), while `zedkube.checkAppsStatus`/`zedmanager.getKubeAppActivateStatus` logs repeat `IsDNidNode=false ScheduledOnThisNode=false AppKubeStatus=NotInCluster`, `onTheDevice false` continuously from shortly after the purge (03:07:38) through the 900s timeout (03:22:38) and beyond, with `publishAppInstanceStatus` permanently "suppressed." This run's failure is a harder manifestation of the same bug (no VMIRS at all vs. a stale one surviving), not a new issue — the ledger shows this test hitting exactly this deadlock since at least 2026-11-15 (run #19). No PR diff was supplied for this investigation.

### TestNodeClusterSuite: failure analysis

#### TestThreeNodesCluster

##### Failure

```
Timed out waiting for cluster nodes to become ready in cluster "test-cluster" (device "edge-dev3")
```

##### Claude's conclusion

###### Root cause

`edge-dev3` never joined the 3-node cluster — it bootstrapped and is still running as its own standalone single-node k3s cluster (`kubectl get nodes` from `edge-dev1`/`edge-dev2` shows only each other; `edge-dev3`'s own `kubectl get nodes` shows only itself, with `internal_ip:172.20.20.180`, the *management* interface, instead of the cluster interface `10.244.244.4` used by the other two).

The device logs show why: `pkg/kube/cluster-init.sh`'s first-boot path (`First time for k3s install`) checks for the `/var/lib/edge-node-cluster-mode` marker **once, with no retry**, and falls back to single-node setup if it's missing — unlike the restart-case branch, which loops waiting for `EdgeNodeClusterStatus`. zedkube/zedagent did receive and parse the real `EdgeNodeClusterConfig` at `03:13:24` (`JoinServerIP: 10.244.244.2`, `BootstrapNode: false` — correctly configured to join), but `cluster-init.sh` ran its first-boot check 21s later at `03:13:45` and lost the race, logging `"Single node mode prepare config.yaml for edge-dev3"`.

Having gone down the single-node path, `edge-dev3` then got permanently stuck installing its own (unneeded) standalone kubevirt/CDI/longhorn stack: the k3s install log stops dead at `03:15:12 : Installing longhorn version v1.9.1` and never progresses. Live inspection shows `longhorn-driver-deployer`'s init container has been looping on `curl http://longhorn-backend:9500/v1 != 200` for 30+ minutes, because `longhorn-manager`'s informers are stuck with `"the server could not find the requested resource"` for every `longhorn.io` CRD type — even though those CRDs exist (created at `03:15:13`) — because k3s's kube-apiserver logged repeated `"stale GroupVersion discovery"` errors for `cdi.kubevirt.io`/`subresources.kubevirt.io` right after the rapid-fire kubevirt+CDI+longhorn CRD installs, and its discovery/REST-mapper cache never recovered. Since the single-to-cluster transition logic (`check_cluster_config_change`) is gated on `/var/lib/all_components_initialized` (only set once the single-node Longhorn install finishes), and Longhorn never finishes, `edge-dev3` can never transition to join the real cluster — matching the test's exact timeout (30 min from config-applied to all three "waiting for nodes" messages expiring).

This is a new failure — it does not match either of the two prior nightly entries in the ledger (`TestLocalNetworkInstanceSuite/TestFlowLog` download hang, and `TestNodeClusterResilienceSuite`'s stale-cache/zedkube-failover bugs from 2026-11-15); `TestNodeClusterSuite/TestThreeNodesCluster` does not appear there before, so this is not a known/recurring issue as far as the ledger records. No PR diff was supplied for this run, so I can't assess relatedness to a specific code change — the mechanism itself (a first-boot race in `cluster-init.sh` combined with a stuck kube-apiserver CRD-discovery cache) points to a genuine EVE/k3s-provisioning bug rather than a test-harness issue.

### TestPcibackErrorSuite: failure analysis

#### TestReportWarningsOnly

##### Failure

```
Failed to setup devices [edge-dev]: rpc error: code = Unknown desc = failed to setup EVE device "edge-dev": failed waiting for VM 111 creation: task failed on Proxmox: unable to create VM 111 - cannot import from 'local:import/ev-eve-a28439fe-edge-dev-0.qcow2' - can't lock file '/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool' - got timeout (task UPID:farfalle:001E5676:8188E4C9:6AFBC59B:qmcreate:111:root@pam:)
```

##### Claude's conclusion

###### Root cause assessment

This failure occurred entirely at VM-provisioning time on the physical test host, before EVE itself ever booted — `evetest eve` reports "No EVE devices found" because the device was never successfully created. The first 7 subtests of `TestPcibackErrorSuite` passed reusing one device/VM; only the final subtest, `TestReportWarningsOnly`, needed to set up a *new* device, triggering a fresh qcow2 import onto Proxmox host `farfalle`. That import (`qmcreate:111`) failed because it couldn't acquire `/var/lock/pve-manager/pve-storage-farfalle-pve-zfs-pool` within Proxmox's internal timeout — a storage-lock contention error on the hypervisor host itself, not an EVE/pillar defect.

This is a different failure mode from anything in `live-ledger.md` (which covers `TestLocalNetworkInstanceSuite` and `TestNodeClusterResilienceSuite`), and a search of the ledger for "farfalle"/Proxmox/lock-related terms returns zero hits, so this is **not a previously recorded/known issue** — it's the first occurrence in the ledger's history. It also shares no root cause with anything else in this run, since no other suite/subtest failure is reported.

Likely explanation: transient resource contention on the `farfalle` Proxmox host (e.g., another concurrent VM import/teardown holding the ZFS storage lock) rather than any systemic or code-level problem. Since no device ever came up, there's no live pillar/zedbox state to further corroborate or rule this out — the evidence is confined to the broker/Proxmox task error itself.

No PR diff was provided in this investigation, so I'm omitting the RELATED line.

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
