# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

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
