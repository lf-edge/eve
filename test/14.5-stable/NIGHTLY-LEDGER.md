# Evetest Nightly Ledger

One section per nightly run with at least one failing suite.

## [2026-11-22 -- 0.0.0-14.5-stable-e70cea0b (run #39)](https://github.com/lf-edge/eve/actions/runs/44983074033)

[Full report](https://lf-edge.github.io/eve/test/14.5-stable/runs/39/)

### TestAppRoutingSuite: failure analysis

#### TestLocalNIWithMultiplePorts

##### Failure

```

Timed out after 600.000s.
Expected to satisfy: Default route fails over to ethernet3 and HTTP server route to ethernet2
networkID:"296bb95b-0c56-4dfd-af1d-c7f99a122002"  networkVersion:"1"  instType:2  displayname:"multi-port-ni"  activated:true  CurrentUplinkIntf:"ethernet0"  ports:"ethernet0"  ports:"ethernet1"  ports:"ethernet2"  ports:"ethernet3"  bridgeNum:1  bridgeName:"bn1"  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:06:00:01"  ipAddress:"10.50.0.1"}  ipAssignments:{macAddress:"02:16:3e:00:02:00"  ipAddress:"10.50.0.2"}  vifs:{vifName:"nbu1x1"  macAddress:"02:16:3e:00:02:00"  appID:"ca6aff20-3cf4-4b5e-b567-f281efe05861"}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByAppUUID:"22548feb-4b01-460a-9ccc-8dee8ff35024"  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usedByAppUUID:"22548feb-4b01-460a-9ccc-8dee8ff35024"  ioAddressList:{macAddress:"1e:68:56:62:e1:30"}}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet2"  members:"ethernet2"  usedByAppUUID:"22548feb-4b01-460a-9ccc-8dee8ff35024"  ioAddressList:{macAddress:"ce:30:0f:9c:43:d9"}}  assignedAdapters:{type:PhyIoNetEth  name:"ethernet3"  members:"ethernet3"  usedByAppUUID:"22548feb-4b01-460a-9ccc-8dee8ff35024"  ioAddressList:{macAddress:"d6:42:ef:26:d8:c8"}}  state:ZNETINST_STATE_ONLINE  mtu:1500  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"10.40.40.1"  port:"ethernet3"}  ip_routes:{destination_network:"10.88.88.0/24"  gateway:"172.22.10.1"  port:"ethernet0"}  ip_routes:{destination_network:"10.40.40.0/24"  port:"ethernet3"}  ip_routes:{destination_network:"172.22.10.0/24"  port:"ethernet0"}  ip_routes:{destination_network:"172.28.20.0/24"  port:"ethernet1"}  ip_routes:{destination_network:"192.168.30.0/24"  port:"ethernet2"}
```

##### Claude's conclusion

That background `evetest sdn logs` grep was killed after timing out — not needed though, since the device-side `PortProber` logs already gave a conclusive timeline for the root cause I reported above.

### TestDeviceConnectivitySuite: failure analysis

#### TestDNSFunctionality

##### Failure

```

Timed out after 420.001s.
Expected to satisfy: All four ports have expected DNS servers; eth3 has DNS resolution error; DPC is healthy
machineArch:"x86_64"  cpuArch:"x86_64"  platform:"x86_64"  ncpu:4  memory:7814  storage:63153  powerCycleCounter:-1  minfo:{manufacturer:"QEMU"  productName:"Standard PC (Q35 + ICH9, 2009)"  version:"pc-q35-11.0"  serialNumber:"LTO96YZ8"  UUID:"Not Settable"  biosVendor:"EDK II"  biosVersion:"unknown"  biosReleaseDate:"02/02/2022"}  network:{macAddr:"da:39:78:d0:19:f2"  devName:"ethernet0"  IPAddrs:"172.30.0.123"  defaultRouters:"172.30.0.1"  dns:{DNSservers:"10.35.5.25"  DNSservers:"10.35.0.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795324252  nanos:785570729}}  localName:"eth0"  proxy:{}}  network:{macAddr:"1e:68:56:62:e1:30"  devName:"ethernet1"  IPAddrs:"172.30.1.42"  defaultRouters:"172.30.1.1"  dns:{DNSservers:"10.35.6.25"  DNSservers:"10.35.1.25"  DNSservers:"10.35.2.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{timestamp:{seconds:1795324192  nanos:745511700}}  localName:"eth1"  proxy:{}}  network:{macAddr:"ce:30:0f:9c:43:d9"  devName:"ethernet2"  IPAddrs:"172.30.2.146"  defaultRouters:"172.30.2.1"  dns:{DNSservers:"10.35.7.25"  DNSservers:"10.35.3.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth2 with src IP 172.30.2.146: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": interface eth2: no DNS server available"  timestamp:{seconds:1795324252  nanos:781094053}  severity:SEVERITY_ERROR}  localName:"eth2"  proxy:{}}  network:{macAddr:"d6:42:ef:26:d8:c8"  devName:"ethernet3"  IPAddrs:"172.30.3.10"  defaultRouters:"172.30.3.1"  dns:{DNSservers:"10.35.4.25"  DNSdomain:"test."}  ipv4_up:true  uplink:true  networkErr:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth3 with src IP 172.30.3.10: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": dial tcp: lookup adam.evetest on 10.35.1.25:53: skipped nameserver 10.35.1.25: DNS server is from a different network"  timestamp:{seconds:1795324252  nanos:780652594}  severity:SEVERITY_ERROR}  localName:"eth3"  proxy:{}}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet0"  members:"ethernet0"  usedByBaseOS:true  ioAddressList:{macAddress:"da:39:78:d0:19:f2"}  usage:PhyIoUsageMgmtOnly}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet1"  members:"ethernet1"  usedByBaseOS:true  ioAddressList:{macAddress:"1e:68:56:62:e1:30"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet2"  members:"ethernet2"  usedByBaseOS:true  ioAddressList:{macAddress:"ce:30:0f:9c:43:d9"}  usage:PhyIoUsageMgmtAndApps}  assignableAdapters:{type:PhyIoNetEth  name:"ethernet3"  members:"ethernet3"  usedByBaseOS:true  ioAddressList:{macAddress:"d6:42:ef:26:d8:c8"}  usage:PhyIoUsageMgmtOnly}  dns:{DNSservers:"10.35.4.25:53"  DNSservers:"10.35.0.25:53"  DNSservers:"10.35.1.25:53"}  storageList:{device:"nbd8"}  storageList:{mountPath:"/persist/certs"}  storageList:{mountPath:"/persist/vault/containerd"}  storageList:{device:"nbd9"}  storageList:{mountPath:"/persist/clear"}  storageList:{device:"nbd11"}  storageList:{mountPath:"/persist/clear/volumes"}  storageList:{mountPath:"/hostfs"  total:265}  storageList:{device:"nbd4"}  storageList:{mountPath:"/persist/newlog"}  storageList:{mountPath:"/persist/tmp"}  storageList:{device:"nbd14"}  storageList:{mountPath:"/persist/vault/downloader"}  storageList:{device:"nbd0"}  storageList:{mountPath:"/persist/pubsub-large"}  storageList:{device:"nbd13"}  storageList:{device:"vda3"  total:512  partitionLabel:"IMGB"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30053"}  storageList:{mountPath:"/persist/agentdebug"}  storageList:{mountPath:"/persist/ingested"}  storageList:{device:"nbd7"}  storageList:{device:"vda1"  total:36  partitionLabel:"EFI System"  partitionTypeGuid:"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30051"}  storageList:{device:"nbd15"}  storageList:{mountPath:"/persist/log"}  storageList:{device:"nbd3"}  storageList:{device:"vda4"  total:1  partitionLabel:"CONFIG"  partitionTypeGuid:"13307e62-cd9c-4920-8f9b-91b45828b798"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30054"}  storageList:{device:"nbd12"}  storageList:{mountPath:"/persist/vault"}  storageList:{mountPath:"/persist/vault/volumes"}  storageList:{mountPath:"/persist/checkpoint"}  storageList:{device:"vda"  total:65536}  storageList:{device:"vda2"  total:512  partitionLabel:"IMGA"  partitionTypeGuid:"5dfbf5f4-2848-4bac-aa5e-0d9a20b745a6"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30052"}  storageList:{mountPath:"/config"  total:1}  storageList:{mountPath:"/persist/patchEnvelopesUsageCache"}  storageList:{mountPath:"/persist/status"}  storageList:{mountPath:"/persist/containerd-system-root"}  storageList:{device:"vda9"  total:64473  partitionLabel:"P3"  partitionTypeGuid:"5f24425a-2dfa-11e8-a270-7b663faccc2c"  partitionUuid:"ad6871ee-31f9-4cf3-9e09-6f7a25c30059"}  storageList:{mountPath:"/persist"  total:63153  storageLocation:true}  storageList:{mountPath:"/persist/vault/verifier"}  storageList:{device:"nbd6"}  storageList:{mountPath:"/persist/netdump"}  storageList:{mountPath:"/"  total:3907}  storageList:{device:"nbd10"}  storageList:{device:"nbd5"}  storageList:{device:"nbd2"}  storageList:{device:"nbd1"}  storageList:{mountPath:"/persist/patchEnvelopesCache"}  storageList:{mountPath:"/persist/memory-monitor/output"}  bootTime:{seconds:1795323762}  swList:{activated:true  partitionLabel:"IMGA"  partitionDevice:"/dev/vda2"  partitionState:"active"  status:INSTALLED  shortVersion:"0.0.0-14.5-stable-e70cea0b-kvm-amd64"  downloadProgress:100  userStatus:UPDATED}  swList:{partitionLabel:"IMGB"  partitionDevice:"/dev/vda3"  partitionState:"unused"  status:INITIAL}  HostName:"56482f2c-4094-486d-8ffe-b19bfd0f89ac"  lastRebootReason:"NORMAL: First boot of device - at 2026-11-22T05:03:18.573176768Z"  lastRebootTime:{seconds:1795323798  nanos:573176768}  systemAdapter:{status:{version:1  key:"zedagent"  timePriority:{seconds:1795323877  nanos:319752750}  lastSucceeded:{seconds:1795324252  nanos:785634474}  ports:{ifname:"eth0"  name:"ethernet0"  isMgmt:true  dhcpType:4  subnet:"172.30.0.0/24"  domainname:"test."  proxy:{}  macAddr:"da:39:78:d0:19:f2"  IPAddrs:"172.30.0.123"  defaultRouters:"172.30.0.1"  dns:{DNSservers:"10.35.5.25"  DNSservers:"10.35.0.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795324252  nanos:785570729}}  usage:PhyIoUsageMgmtOnly  networkUUID:"786ec294-67c1-46b3-ab58-9da1b43b7e87"  cost:2  mtu:1500}  ports:{ifname:"eth1"  name:"ethernet1"  isMgmt:true  dhcpType:4  subnet:"172.30.1.0/24"  domainname:"test."  proxy:{}  macAddr:"1e:68:56:62:e1:30"  IPAddrs:"172.30.1.42"  defaultRouters:"172.30.1.1"  dns:{DNSservers:"10.35.6.25"  DNSservers:"10.35.1.25"  DNSservers:"10.35.2.25"  DNSdomain:"test."}  up:true  err:{timestamp:{seconds:1795324192  nanos:745511700}}  usage:PhyIoUsageMgmtAndApps  networkUUID:"82580985-c621-48b6-9c61-e4ea1ee9a95f"  cost:2  mtu:1500}  ports:{ifname:"eth2"  name:"ethernet2"  isMgmt:true  dhcpType:4  subnet:"172.30.2.0/24"  domainname:"test."  proxy:{}  macAddr:"ce:30:0f:9c:43:d9"  IPAddrs:"172.30.2.146"  defaultRouters:"172.30.2.1"  dns:{DNSservers:"10.35.7.25"  DNSservers:"10.35.3.25"  DNSdomain:"test."}  up:true  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth2 with src IP 172.30.2.146: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": interface eth2: no DNS server available"  timestamp:{seconds:1795324252  nanos:781094053}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtAndApps  networkUUID:"a8e65b6e-8843-435a-b84e-41bea7fd5f12"  cost:1  mtu:1500}  ports:{ifname:"eth3"  name:"ethernet3"  isMgmt:true  free:true  dhcpType:4  subnet:"172.30.3.0/24"  domainname:"test."  proxy:{}  macAddr:"d6:42:ef:26:d8:c8"  IPAddrs:"172.30.3.10"  defaultRouters:"172.30.3.1"  dns:{DNSservers:"10.35.4.25"  DNSdomain:"test."}  up:true  err:{description:"All attempts to connect to https://adam.evetest:443/api/v2/edgedevice/ping failed: send via eth3 with src IP 172.30.3.10: Get \"https://adam.evetest:443/api/v2/edgedevice/ping\": dial tcp: lookup adam.evetest on 10.35.1.25:53: skipped nameserver 10.35.1.25: DNS server is from a different network"  timestamp:{seconds:1795324252  nanos:780652594}  severity:SEVERITY_ERROR}  usage:PhyIoUsageMgmtOnly  networkUUID:"a9c079d2-0f8d-4f66-ada7-25aefcdb3141"  mtu:1500}}}  HSMStatus:NOTFOUND  HSMInfo:"Not Available"  dataSecAtRestInfo:{status:DATASEC_AT_REST_DISABLED  info:"TPM is either absent or not in use"  vaultList:{name:"Application Data Store"  status:DATASEC_AT_REST_DISABLED  vaultErr:{description:"TPM is either absent or not in use"  timestamp:{seconds:1795323865  nanos:49850321}  severity:SEVERITY_ERROR}  pcrStatus:PCR_DISABLED  unlock_method:VAULT_UNLOCK_METHOD_NO_TPM}}  sec_info:{sha_root_ca:"\x1f\x0f\xfbvt\xb9O\xfb\x03\x06{\n\xb7.G\xab\xbd\xb9}\xe1;T\x1c\xf8\x01\x9en\xce\xec宋"}  configItemStatus:{configItems:{key:"agent.nim.debug.loglevel"  value:{value:"debug"}}  configItems:{key:"agent.nim.debug.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"app.allow.vnc"  value:{value:"true"}}  configItems:{key:"debug.default.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.default.remote.loglevel"  value:{value:"debug"}}  configItems:{key:"debug.enable.console"  value:{value:"true"}}  configItems:{key:"debug.enable.ssh"  value:{value:"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJgGpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYcH7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7Nd2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6CIzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZkUusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7vGdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2GjMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laIM8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgorf/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvnbFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH053U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="}}  configItems:{key:"newlog.allow.fastupload"  value:{value:"true"}}  configItems:{key:"timer.config.interval"  value:{value:"5"}}  configItems:{key:"timer.download.retry"  value:{value:"60"}}  configItems:{key:"timer.location.app.interval"  value:{value:"20"}}  configItems:{key:"timer.location.cloud.interval"  value:{value:"300"}}  configItems:{key:"timer.metric.interval"  value:{value:"20"}}  configItems:{key:"timer.port.testduration"  value:{value:"10"}}  configItems:{key:"timer.port.testinterval"  value:{value:"60"}}  configItems:{key:"timer.test.baseimage.update"  value:{value:"60"}}}  last_boot_reason:BOOT_REASON_FIRST  hardware_watchdog_present:true  capabilities:{HWAssistedVirtualization:true  IOVirtualization:true}  state:ZDEVICE_STATE_ONLINE  storage_info:{pool_name:"/persist"  storage_type:STORAGE_TYPE_INFO_EXT4  storage_state:STORAGE_STATUS_ONLINE  disks:{disk_name:{name:"/dev/vda9"  serial:"unknown"}  status:STORAGE_STATUS_ONLINE  smart_status:"failed"}}  attestation_info:{state:ATTESTATION_STATE_COMPLETE  error:{description:"[ATTEST] No escrow data"  timestamp:{seconds:1795323874  nanos:967292424}  severity:SEVERITY_ERROR}}  api_capability:API_CAPABILITY_CELLULAR_ATTACH_CONFIG  optional_capabilities:{}
```

##### Claude's conclusion

###### Root cause

Phase 1 of `TestDNSFunctionality` never satisfies its predicate because **ethernet2** repeatedly reports a connectivity error of `interface eth2: no DNS server available`, even though its own `DevicePort.dns.DNSservers` consistently lists both valid DNS servers (`10.35.7.25` static + `10.35.3.25` DHCP) — the test only expects eth3 (the deliberately-broken port) to have an error, so the `Eventually` loop keeps timing out over the full 420s/5-plus-minute budget.

Live log evidence from `/run/nim/DeviceNetworkStatus/global.json` and the nim debug log shows this is **not transient**: at 05:11:52, 05:12:52, 05:13:52 and 05:14:52 (once per DPC-verify cycle), nim's `TestConnectivity`/`SendOnIntf` fails eth2 with `types.DNSNotAvailError` (raised by `controllerconn.prepareHTTPClientConfig` when `types.GetDNSServers()` returns zero entries for eth2), yet the `DeviceNetworkStatus` published milliseconds later in that *same* verify cycle already shows eth2's `DNSServers` populated with both entries. This points to a real timing race in EVE's own DNS-verification path — `dpcmanager.updateDNS()`/`netmonitor.GetInterfaceDNSInfo()` samples a stale/empty per-interface resolv.conf view (the boot-time log even shows `"No resolv.conf for eth2"` entries) right before the connectivity probe runs, so the probe for eth2 fails every single retest cycle even though the DNS data it needs is correct and available. eth0/eth1/eth3 never exhibit this: eth0 and eth1 reach `LastSucceeded` normally, and eth3's error is the expected one (bad DNS server, different-network skip).

This does not match any failure in the current run's earlier history (TestDNSFunctionality is the first test in this suite run), and it does not appear in `live-ledger.md`, which only covers 2026-11-20 and 2026-11-21 and has no prior mention of `TestDNSFunctionality` or this DNS-availability race — so this looks like a newly-observed, reproducible EVE-side bug rather than a known/recurring flake or a test-harness defect.

## [2026-11-21 -- 0.0.0-14.5-stable-b4cd0a12 (run #34)](https://github.com/lf-edge/eve/actions/runs/44863882597)

[Full report](https://lf-edge.github.io/eve/test/14.5-stable/runs/34/)

### TestAppRoutingSuite: failure analysis

#### TestLocalNIWithMultiplePorts

##### Failure

```

Told to stop trying after 2.116s.
Stop waiting for: NI ONLINE with both static routes via ethernet0 and all connected routes present
Network instance is in error state
networkID:"e885d244-90d9-4cc1-8e71-c71bfeff1674"  networkVersion:"1"  instType:2  displayname:"multi-port-ni"  activated:true  CurrentUplinkIntf:"eth0"  ports:"eth0"  ports:"eth1"  ports:"eth2"  ports:"eth3"  bridgeNum:1  bridgeName:"bn1"  bridgeIPAddr:"10.50.0.1"  ipAssignments:{macAddress:"00:16:3e:06:00:01"  ipAddress:"10.50.0.1"}  networkErr:{description:"IP Route: {dst=0.0.0.0/0, gw=<nil>, port=internet, probe={enabledGwPing=true, gwPingMaxCost=5, userProbe=<none>}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port\nIP Route: {dst=10.88.88.0/24, gw=<nil>, port=httpserver, probe={enabledGwPing=true, gwPingMaxCost=0, userProbe=tcp://10.88.88.70:80}, preferLowerCost=true, preferStrongerWwanSignal=false} is not matching any port"  timestamp:{seconds:1795236601  nanos:313267473}  severity:SEVERITY_ERROR}  state:ZNETINST_STATE_ERROR  mtu:1500  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"192.168.30.1"  port:"eth2"}  ip_routes:{destination_network:"0.0.0.0/0"  gateway:"172.22.10.1"  port:"eth0"}  ip_routes:{destination_network:"172.22.10.0/24"  port:"eth0"}  ip_routes:{destination_network:"192.168.30.0/24"  port:"eth2"}
```

##### Claude's conclusion

###### Root cause analysis

Live inspection shows the NI genuinely recovered on its own: the current `/run/zedrouter/NetworkInstanceStatus/e885d244-....json` on the device (modified at 04:52:15, ~2m13s after the failure at 04:50:02) now shows `"Error":""`, both static routes resolved to `SelectedPort:"ethernet0"`, and all four port subnets present in `CurrentRoutes` — exactly what the test is waiting for. The device's logs pinpoint why it took that long: at 04:51:51 zedrouter was still logging `IP Route: {... port=internet ...} is not matching any port` and `{... port=httpserver ...} is not matching any port`, and the `NetworkInstanceStatus` diff at that moment shows the kernel/zedrouter route state was still churning — `CurrentRoutes` transiently contained *three* simultaneous `0.0.0.0/0` entries (via `ethernet3`, `ethernet2`, and `ethernet1`), including bogus default routes on ports (eth1, eth2) that by design (per the test's own topology comment) should never have outside/default reachability. This is a startup convergence race: four differently-configured ports (two DHCP, two static) were brought up together with a brand-new NI, and until the route/port state settled (~2 minutes), the shared-label route resolver saw an inconsistent/incomplete picture and flagged the NI as `ERROR`. The test's `niHasError` `StopIf` callback (evetest/tests/networking/helpers_test.go:33) treats the very first sighting of `ZNETINST_STATE_ERROR` as fatal, so `Eventually` bailed after only 2.1s instead of tolerating this transient convergence window — `TestPropagatedRoutes`, which ran immediately before in this same suite run, passed cleanly, so this isn't shared with an earlier failure in the run. This specific test doesn't appear in `live-ledger.md` (which only has one prior night, 2026-11-20, and doesn't mention `TestLocalNIWithMultiplePorts` or `TestAppRoutingSuite`), so it's not a confirmed recurring/known issue yet, though it echoes the same general theme as that night's `TestMgmtTrafficRoutedViaApp` failure (slow convergence of network-port state after a config change outrunning the test's wait/fail logic).

### TestStorageSuite: failure analysis

#### TestVolumes

##### Failure

```

Told to stop trying after 0.021s.
Stop waiting for: volume v-vmdk is created
Volume reports an error: Found error in content tree v-vmdk-image attached to volume v-vmdk: Retry download in 1m0s: v-vmdk.vmdk failed: lookupDatastoreConfig(479a4390-6a97-4442-9e05-08740d4aa16d) error: Get(zedagent/DatastoreConfig) unknown key 479a4390-6a97-4442-9e05-08740d4aa16d
uuid:"ccc21634-0756-418d-89cd-c257859ccfc9" displayName:"v-vmdk" usage:{createTime:{seconds:-62135596800} refCount:1 lastRefcountChangeTime:{seconds:1795237353 nanos:860599180}} state:DOWNLOAD_STARTED volumeErr:{description:"Found error in content tree v-vmdk-image attached to volume v-vmdk: Retry download in 1m0s: v-vmdk.vmdk failed: lookupDatastoreConfig(479a4390-6a97-4442-9e05-08740d4aa16d) error: Get(zedagent/DatastoreConfig) unknown key 479a4390-6a97-4442-9e05-08740d4aa16d" timestamp:{seconds:1795237355 nanos:674388261} severity:SEVERITY_NOTICE entities:{entity:ENTITY_CONTENT_TREE entity_id:"5b157b6e-d1bf-473f-a771-d9c785fd65ee"} retry_condition:"Will retry in 1m0s; have retried 0 times"}
```

##### Claude's conclusion

###### Root cause

The volume `v-vmdk` hit a one-time, self-healing race at creation time, and the test harness treated that transient blip as fatal.

Live/log evidence:
- At **05:02:35** the content tree first entered `DOWNLOAD_STARTED`, and by **05:02:37** it logged `lookupDatastoreConfig(479a4390-...) error: Get(zedagent/DatastoreConfig) unknown key` — i.e. the downloader's own pubsub subscription to `zedagent/DatastoreConfig` hadn't yet received the datastore object that zedagent/volumemgr had just created in the same initial config-apply batch.
- The volume **self-healed immediately**: `DOWNLOAD_STARTED -> LOADING` at 05:02:41 and `LOADING -> CREATED_VOLUME` at 05:02:43 — confirmed live too, since `evetest eve ssh` shows `/run/zedagent/DatastoreConfig/479a4390-...json` present and correctly populated (written at 05:02, well before the pause).
- The test's `Eventually(v.updates).Should(Receive(...).StopIf(volumeHasError))` for `v-vmdk` only started draining its buffered channel after the earlier `v-docker`/`v-qcow2`/`v-qcow` waits finished (~05:06:50). The first buffered message it dequeued was the stale `DOWNLOAD_STARTED` update carrying that transient error (`timestamp:1795237355` = 05:02:35), and `StopIf(volumeHasError)` fires on `Match`, immediately returning `gomega.StopTrying` — so `Eventually` aborts right there and never gets to the later `CREATED_VOLUME` message that was already sitting right behind it in the channel buffer.

So the actual EVE-side event was a harmless, already-recovered pubsub-propagation race (downloader momentarily racing zedagent's datastore-config publish), and the test failure is a pre-existing gap in `StopIf(volumeHasError)`/`volumeHasError` in `evetest/tests/storage/volumes_test.go` and `matchers.StopIf`: it doesn't tolerate a transient error that the volume subsequently clears.

This does **not** share a cause with any other failure in this run (TestVolumes is the only test that ran), and it is not in the live-ledger (which only has one prior dated entry, 2026-11-20, for unrelated suites/tests) — this looks like a first-seen flake. It is also unrelated to the two most recent commits on this branch (`b4cd0a126`/`534055411`, "keep loaded content when only its URL changes"): those only affect `handleContentTreeModify`'s behavior for content trees already in `LOADED` state reacting to a config *Modify*, whereas `v-vmdk` was going through its very first `Create` here and never reached `LOADED` before the transient error, so that code path was never exercised.

## [2026-11-20 -- 0.0.0-14.5-stable-be30b7fb (run #29)](https://github.com/lf-edge/eve/actions/runs/44746514937)

[Full report](https://lf-edge.github.io/eve/test/14.5-stable/runs/29/)

### TestDeviceConnectivitySuite: failure analysis

#### TestMgmtTrafficRoutedViaApp

##### Failure

```

Timed out after 180.000s.
EVE should get device metrics through to the controller via the app-routed management path (mgmt path migrated to the gateway app)
Expected
    <<-chan *metrics.DeviceMetric | len:0, cap:100>: 0x11bf8a46b260
to receive something.
```

##### Claude's conclusion

All previous tests in this suite run passed — no shared earlier failure. I have enough evidence now.

**Root cause:** The migrated DPC (eth1 switching from DHCP to the static `10.60.20.5/24` config with gateway `10.60.20.150` and DNS server `10.16.16.25`) was computed correctly by nim at 14:21:53, but nim's DPC reconciler did not actually recreate the eth1 `dhcpcd` client item (the one that programs the real DNS server into the OS) until **14:25:18** — about 3.5 minutes later, and only after the test had already paused on failure at 14:24:55. In the interim, zedagent repeatedly failed to resolve/reach `adam.evetest` with the telltale error `interface eth1: no DNS server available`, exactly matching nim's own DPC test result (`LastError:interface eth1: no DNS server available`) the whole time, even though the DPC's `DhcpConfig` for eth1 already listed `DNSServers:[10.16.16.25]` from the start. Live investigation after the pause confirms this: eth1 now has the correct DNS server, DNS/ping/HTTPS to the controller all work fine (`nslookup adam.evetest` resolves, `ping`/`curl` to the controller succeed), and `DeviceNetworkStatus` shows `LastSucceeded: 14:26:30` — i.e. everything self-healed once nim finally finished applying the reconfiguration, well past the test's 3-minute (`infoTimeout`) budget for the metrics wait. This looks like a nim DPC-reconciler delay/stall in actually committing a DHCP→static port-config change to the OS network stack, not a problem with the test's gateway-app NAT/routing setup (SSH, routing, and MASQUERADE on the app were all confirmed fine earlier in the run). No earlier failure in this suite run shares this cause (all prior subtests passed), and no PR diff or known-issue ledger entry was provided to check against, so I can't say whether it's a recurring/known issue.

### TestHardwareSuite: failure analysis

#### TestUSBFlashDriveHotplug

##### Failure

```
BuildImage "lfedge/eve:0.0.0-14.5-stable-be30b7fb-kvm-amd64" failed: rpc error: code = Unknown desc = failed to build EVE image for device "hardware-dev": failed to create device image dir "/root/.evetest/images/eve-92543bfc-hardware-dev": mkdir /root/.evetest/images/eve-92543bfc-hardware-dev: no space left on device
```

##### Claude's conclusion

Stable at 46%/17G free. I have enough to write up the finding.

###### Root cause

The failure happened at the very start of the suite (gotest.json shows the evetest gRPC server coming up at `14:41:11.328`, then the `BuildImage` RPC failing one second later at `14:41:11.403`), meaning the very first image-directory creation attempt (`/root/.evetest/images/eve-92543bfc-hardware-dev`) hit `ENOSPC` before any device or SDN was even created (`evetest eve --help`-driven checks confirm "No EVE devices found"). That directory lives inside the `evetest` container's own writable overlay layer (its bind mounts only cover `/home/lf-edge/.evetest`, `/home/lf-edge/.cache/go-build`, `/home/lf-edge/.linuxkit/cache`, etc. — not `/root/.evetest`), which is backed by the host's `/` filesystem. Right now, barely 90 seconds later, that same filesystem is only 46% used with 17G free, inodes are nowhere near exhausted, and `docker images`/cache sizes on host (go-build cache 3.6G, two evetest images ~3.4G combined) don't come close to filling a 30G disk — so the ENOSPC was a transient disk-pressure spike at the exact moment this container's entrypoint tried to create its image dir, not a sustained/genuine capacity shortfall. I can't pin down the other consumer of that transient space (couldn't run `docker system df`/`docker info`/`docker exec` here — those require approval I don't have in this read-only investigation), but the recent `b1f4f706e` change shows this host's CI workflow runs `docker system prune --all --force --volumes` and `sudo rm -fr ~/.linuxkit` as part of "clean stale state from previous runs," so a slow-draining prune/cleanup from a prior job overlapping with this job's startup is the most plausible explanation. This is the only test that ran in this suite instance (no earlier failure in this run to compare against), and I have no memory/ledger record of this specific ENOSPC pattern recurring before, so I can't confirm it's a known recurring issue — it looks like an environmental/host disk-pressure race rather than a bug in the test or in EVE itself.

### TestLocalNetworkInstanceSuite: failure analysis

#### TestLocalNIUplinkFlap

##### Failure

```

Timed out after 300.001s.
The function passed to Eventually failed at /evetest/tests/networking/uplink_flap_test.go:352 with:
Unexpected error:
    <*fmt.wrapError | 0x9490ada6e20>: 
    unable to reach app "2e0d7642-3686-4a55-ad54-7719098ffd20" SSH on device "edge-dev": no reachable endpoint among [172.20.21.42:2222]
    {
        msg: "unable to reach app \"2e0d7642-3686-4a55-ad54-7719098ffd20\" SSH on device \"edge-dev\": no reachable endpoint among [172.20.21.42:2222]",
        err: <*errors.errorString | 0x9490a525a50>{
            s: "no reachable endpoint among [172.20.21.42:2222]",
        },
    }
occurred
```

##### Claude's conclusion

###### Root cause

This failure happened in Phase 1 (baseline), before any uplink flap was ever injected — the test's own checkpoints show `phase1-app-running` was reached at 15:33:09, after which it spent the full 5-minute SSH-readiness `Eventually` failing until timeout at 15:38:09. Live inspection confirms the guest VM itself never finished bringing up networking:

- EVE's own `ZInfoApp` for the app shows `RUNNING` with a `network` block that has **no IP address at all** (`AppIPAddr:""`, `IPv4Assigned:false` in `DomainStatus`), so the SSH port-forward (2222→22) had nothing to forward to — matching the "no reachable endpoint" error exactly.
- The NI's bridge (`bn1`)/vif (`nbu1x1`) side is healthy: dnsmasq is running, the NI is online, and `ip addr`/`brctl show` confirm `nbu1x1` is correctly enslaved to `bn1`.
- But traffic counters on `nbu1x1` show `RxPkts` frozen at 12 packets from first boot through the entire 5‑minute wait (and still only ~1KB received 10 minutes later) — the guest never sent a DHCP discover or any other traffic onto the bridge.
- The app's console log (via `newlog`) shows the kernel booting cleanly through `Mounting root: ok.` and printing the "Welcome to Alpine Linux 3.24" login banner, then **nothing further** — no OpenRC/cloud-init/dhcpcd output at all, consistent with the guest's init/cloud-init sequence stalling right after reaching the console prompt and never configuring `eth0`.

So the proximate cause is the Alpine cloud-init guest failing to bring up its network (and thus never reaching cloud-init/sshd), not a zedrouter/dnsmasq/EVE-side defect — all EVE-side state (port config, NI, dnsmasq) looks correct. All 9 other tests in this suite run passed; this is the only one using this pinned Alpine cloud qcow2 image with a real in-guest DHCP client, so the failure mode is isolated to that image/test. I don't have access to a known-issues ledger in this environment to confirm whether this specific hang is a recurring flake with the pinned Alpine cloud image, so I can't say whether it's previously known — but nothing in the live evidence points to a regression in the uplink-flap logic itself, since the failure occurred before phase 2 (the first flap) ever ran.

### TestUpgradeSuite: failure analysis

#### TestEVEUpgradeKVMtoKVM

##### Failure

```
BuildImage "lfedge/eve:14.5.0-lts-kvm-amd64" failed: rpc error: code = Unknown desc = failed to build EVE image for device "edge-dev": expected EVE image file "/root/.evetest/images/templates/.tmp-c56465bf857dac1feb40f5c0bdee0c02-1177405050/installer.raw.qcow2" not found: stat /root/.evetest/images/templates/.tmp-c56465bf857dac1feb40f5c0bdee0c02-1177405050/installer.raw.qcow2: no such file or directory
```

##### Claude's conclusion

###### Root cause

The failure happened during image build on the evetest-broker, before any EVE device was ever created (`evetest status` confirms "No EVE devices found"). The broker ran `docker run lfedge/eve:14.5.0-lts-kvm-amd64 -f qcow2 installer_raw` to produce the installer qcow2, and its captured output shows the real cause: after successfully creating the GPT partitions and FAT filesystems, the build hit `dd: error writing '/tmp/output.img': No space left on device`, so `installer.raw.qcow2` was never written — the "file not found" error reported by evetest is just a downstream symptom of that disk-full condition inside the broker's build container.

This is the only test that ran in this suite so far (no earlier failures in this run to share a cause with), and I found no known-issues/ledger file in the repo or in memory to check against, so I can't say whether this is a recurring issue. The broker itself runs on a separate remote host (10.208.13.244:50221) rather than this runner (whose own disk is only 46% used), so the space exhaustion is on that broker host/container and isn't inspectable with the `evetest eve`/`sdn` tools since no device was provisioned.
#### TestEVEUpgradeKVMtoKVMWithOCIDatastore

##### Failure

```
BuildImage "lfedge/eve:0.0.0-14.5-stable-42a70aa5-kvm-amd64" failed: rpc error: code = Unknown desc = failed to build EVE image for device "edge-dev": failed to inspect docker image "lfedge/eve:0.0.0-14.5-stable-42a70aa5-kvm-amd64": Error response from daemon: No such image: lfedge/eve:0.0.0-14.5-stable-42a70aa5-kvm-amd64
```

##### Claude's conclusion

This confirms it directly: the broker tried to pull `lfedge/eve:0.0.0-14.5-stable-42a70aa5-kvm-amd64` and failed with containerd's content-store ingest write hitting **"no space left on device"** on the broker, which left no image to inspect/tag, producing the "No such image" error. This is the exact same broker-disk-exhaustion failure mode documented in the previous `TestEVEUpgradeKVMtoKVM` failure in this same run (also `no space left on device`, same remote broker at 10.208.13.244:50221), just manifesting during an image *pull* instead of a `dd` write during image *build*.

Root cause: the evetest-broker host has run out of disk space, and every subsequent test in this suite that needs to build/pull an EVE image on that broker fails as a downstream symptom. This failure shares the same root cause as the earlier `TestEVEUpgradeKVMtoKVM` failure in this run (both are `no space left on device` on the broker filesystem, just hit at different points in the broker's image pipeline — one during `dd` into `installer.raw.qcow2`, the other during a containerd content-store ingest write). No EVE device was created for this test either, consistent with the failure occurring purely in the broker's pre-provisioning image pipeline, not on the device itself.
