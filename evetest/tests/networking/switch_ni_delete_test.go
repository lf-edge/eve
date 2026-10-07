// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// arpSnoopExpiryKey is types.ARPSnoopIPExpiry of pillar. It is spelled out here
// because the pillar module used by evetest is pinned to a version released before
// the config property was introduced.
const arpSnoopExpiryKey pillartypes.GlobalSettingKey = "network.switch.arpsnoop.expiry"

// TestSwitchNIDeletedWithAppsAttached is a regression test for zedrouter hanging
// (and the device being rebooted by the watchdog) when a Switch NI is deleted
// together with the apps connected to it, as happens when the controller
// replaces the whole device config (redeploy).
//
// The hang was caused by a deadlock inside the NI state collector (pkg/pillar/nistate)
// of zedrouter: zedrouter waited for the packet capture of the Switch NI to stop, the
// capture was blocked sending a packet to the collector event loop, and the event
// loop was blocked sending an IP assignment update to zedrouter. It therefore needed
// an IP assignment update to be pending in the collector at the time when the NI was
// being deleted. Such updates are produced by changes of the IP addresses of app
// VIFs, and the IPs that EVE learns from ARP snooping keep expiring and being learned
// again for apps that send ARP packets less often than the expiration time. This is
// the churn of IP addresses that the test replicates (using a shortened expiration
// time of ARP-learned IPs, and apps which send ARP less often than that), together
// with a busy packet capture (the packet buffer of the capture fills up quickly when
// the event loop is blocked), to make the deadlock likely to happen during the NI
// deletion. The hang was seen on a node running many apps whose IP addresses were
// learned from ARP and were being expired and learned again (apps which replace
// the IP received over DHCP with a static one, e.g. using cloud-init, are known
// only through ARP).
//
// The same scenario also verifies that the collector stays up to date about the VIFs
// of apps being removed when the config of their network instance is already gone
// (zedrouter keeps such an NI until the last app is removed), that the expiration of
// ARP-learned IP addresses can be configured, and that the flows of every app of a
// Switch NI with flow logging enabled are reported under that app (the connection
// marks used for this used to be applied by the ingress ACLs of whichever VIF was
// traversed first).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+apps port. The Switch NI is bridged
//     with the port, the apps get their initial IP over DHCP from the SDN router.
//
// Device configuration
// --------------------
//   - ethernet0: DHCP, mgmt+apps.
//   - Config property network.switch.arpsnoop.expiry set to 10 seconds (default
//     is 10 minutes), so that ARP-learned IPs expire and are learned again
//     over and over, which keeps IP assignment updates flowing.
//   - one Switch NI ("switch-ni") on ethernet0, flow logging enabled.
//   - two container apps (lfedge/evetest-ubuntu-ctr:1.0) connected to the NI.
//
// Phases
// ------
//  1. Deploy the Switch NI with both apps, wait until the apps are running
//     and have an IP address.
//  2. Every app opens an HTTP connection to a different remote endpoint. Require
//     the flow log of each app to eventually contain the flow to its own endpoint
//     (from the app IP, with the ACE of the allow-all ACL) and none of the flow
//     of the other app (marking of connections initiated by apps), and the inbound
//     flow of the SSH session opened by the test (marking of connections
//     initiated from outside by the ingress ACL of the VIF). This takes several
//     minutes, because the flow is reported only after the conntrack entry of
//     the closed connection times out.
//  3. In each app start a background script which first replaces the DHCP
//     address with a static one (like cloud-init does) and then sends ARP
//     from the static IP less often than the configured expiry, and floods
//     DNS port with UDP packets to keep the packet capture of the Switch NI busy.
//  4. The static IP of every app is learned from ARP, expires and is learned
//     again at least twice (visible in the app info).
//  5. Delete the NI from the config while the apps are still using it (the
//     config is edited manually because the framework refuses to create such
//     config). Zedrouter keeps the NI until the last app is gone.
//  6. Delete both apps. Require the apps to be removed and the NI to be gone
//     without zedrouter getting stuck (it would be rebooted by the watchdog only
//     after more than 8 minutes, therefore the teardown timeout is shorter), and
//     without zedrouter failing to update the state collector for the apps being
//     removed, even though the config of their NI is already gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestSwitchNIDeletedWithAppsAttached(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	const (
		arpExpiry       = 10 * time.Second
		arpPeriod       = 25 * time.Second // must be longer than arpExpiry
		gatewayIP       = "172.20.20.1"
		dnsServerIP     = "10.16.16.25"
		timeout         = 5 * time.Minute
		teardownTimeout = 5 * time.Minute
		flowLogTimeout  = 6 * time.Minute
		sshTimeout      = 20 * time.Second
		allowAllAceID   = int32(1)
		ipProtoTCP      = int32(6)
	)
	appAuth := evetest.UsernamePasswordAuth{Username: "root", Password: "testpassword"}
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(arpSnoopExpiryKey, uint32(arpExpiry.Seconds()))
	devConfig.SetConfigProperties(cfgProps)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("port-config-applied")

	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "switch-ni",
		Port:          "ethernet0",
		MTU:           1500,
		EnableFlowlog: true,
	})
	type testApp struct {
		name     string
		mac      string
		staticIP string
		// Remote HTTP endpoint (SDN) contacted by the app to produce a flow.
		serverHost string
		serverIP   string
		serverPort int32
		dhcpIP     string // learned over DHCP before the static IP is configured
		uuid       uuid.UUID
		updates    <-chan *eveinfo.ZInfoApp
		stop       func()
	}
	apps := []*testApp{
		{
			name: "app-1", mac: "02:16:3e:00:00:01", staticIP: "172.20.20.250",
			serverHost: "http-server.test", serverIP: "10.17.17.25", serverPort: 80,
		},
		{
			name: "app-2", mac: "02:16:3e:00:00:02", staticIP: "172.20.20.251",
			serverHost: "http-server2.test", serverIP: "10.18.18.25", serverPort: 8080,
		},
	}
	for _, app := range apps {
		app.uuid = devConfig.AddApplication(evetest.ApplicationInstanceConfig{
			DisplayName: app.name,
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.2",
			},
			VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
			CPUs:               1,
			MemoryBytes:        500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
					MAC:                 evetest.MACAddress(app.mac),
					ACLAllowRules: []evetest.ACLAllowRule{
						{
							Protocol:     evetest.NetworkProtocolAny,
							RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
						},
					},
				},
			},
		})
		app.updates, app.stop = device.WatchAppInfo(app.uuid)
		defer app.stop()
	}
	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	device.ApplyConfig(devConfig, false, false)

	var niInfo *eveinfo.ZInfoNetworkInstance
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	t.Expect(niInfo.BridgeName).To(Equal("eth0"))
	for _, app := range apps {
		device.WaitUntilAppIsRunning(app.uuid, timeout)
		t.Eventually(app.updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			app.name+" has an IP address",
			func(info *eveinfo.ZInfoApp) bool {
				if len(info.Network) != 1 {
					return false
				}
				for _, ipAddr := range info.Network[0].IPAddrs {
					if ip := evetest.IPAddress(ipAddr); ip.To4() != nil && ip.IsGlobalUnicast() {
						app.dhcpIP = ipAddr
						return true
					}
				}
				return false
			}).StopIf(appHasError)))
		// The app is RUNNING and has an IP before its SSH daemon starts.
		t.Eventually(func(g Gomega) {
			_, _, err := device.RunShellScriptInsideApp(app.uuid, appAuth,
				"true", sshTimeout, 0)
			g.Expect(err).ToNot(HaveOccurred())
		}, timeout, 3*time.Second).Should(Succeed(), "SSH of %s is not reachable", app.name)
	}
	evetest.Checkpoint("apps-running")

	// Every app opens a connection to a different remote endpoint. The ACL of the
	// VIFs allows everything (ACE 1).
	flowsStart := time.Now()
	for _, app := range apps {
		url := fmt.Sprintf("http://%s:%d/helloworld", app.serverHost, app.serverPort)
		output, _, err := device.RunShellScriptInsideApp(app.uuid, appAuth,
			"curl -sS --max-time 10 "+url, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("Hello world"))
	}
	evetest.Checkpoint("flows-generated")

	// With flow logging enabled, connections are marked with the ID of the app
	// and of the ACL rule, and the flow is reported under the app that
	// originated it. The flow of an app must never be reported under the other app,
	// which is what happened when the marks of all the connections of a Switch NI
	// were applied by the ingress ACLs of the VIF traversed first.
	// Records of a closed connection are reported only after the remaining timeout of
	// the conntrack entry drops below a threshold and the table is swept, which
	// takes several minutes (see TestFlowLog).
	for _, app := range apps {
		other := apps[0]
		if app == apps[0] {
			other = apps[1]
		}
		t.Eventually(func(g Gomega) {
			records := device.GetAppFlowLogs(app.uuid, evetest.FlowLogMatch{
				VirtualNetAdapter: "vif0",
				NetworkInstance:   niUUID,
				NotBefore:         flowsStart,
			})
			g.Expect(findFlowRecord(records, flowRecordMatch{
				aclID: allowAllAceID, srcIP: app.dhcpIP, dstIP: app.serverIP,
				dstPort: app.serverPort, protocol: ipProtoTCP,
			})).ToNot(BeNil(), "no flow record from %s to %s:%d under %s",
				app.dhcpIP, app.serverIP, app.serverPort, app.name)
			g.Expect(findFlowRecord(records, flowRecordMatch{
				aclID: allowAllAceID, dstIP: other.serverIP, dstPort: other.serverPort,
			})).To(BeNil(), "flow of %s to %s:%d is reported under %s",
				other.name, other.serverIP, other.serverPort, app.name)

			// The SSH session opened by the test to run the commands above was
			// initiated from outside. It is marked by the ingress ACL of the VIF
			// (applied by the FORWARD chain, where the output port of the bridge is
			// known) and reported as an inbound flow of the app. The ingress ACL
			// has to override the mark of the device-wide SSH rule, which is applied
			// earlier to every connection with dport 22.
			// There is no NotBefore: record timestamps come from the clock of the
			// device, which can be slightly behind the clock of the test host, and
			// the SSH session of an app is opened just before the flow of the app.
			// Any inbound SSH flow of the app will do, there were no others before.
			inbound := device.GetAppFlowLogs(app.uuid, evetest.FlowLogMatch{
				VirtualNetAdapter: "vif0",
				NetworkInstance:   niUUID,
				Inbound:           true,
			})
			sshRec := findFlowRecord(inbound, flowRecordMatch{
				aclID: allowAllAceID, inbound: true, srcIP: app.dhcpIP,
				protocol: ipProtoTCP,
			})
			g.Expect(sshRec).ToNot(BeNil(),
				"no inbound flow record (SSH session) of %s from %s", app.name, app.dhcpIP)
			g.Expect(sshRec.GetFlow().GetSrcPort()).To(BeEquivalentTo(22))
		}, flowLogTimeout, 10*time.Second).Should(Succeed())
	}
	evetest.Checkpoint("flow-logs-attributed")

	// Replace the DHCP IPs with static ones and start generating traffic.
	for _, app := range apps {
		startSwitchNITraffic(t, device, app.uuid, app.staticIP, gatewayIP,
			dnsServerIP, arpPeriod)
	}
	evetest.Checkpoint("traffic-started")

	// The static IP is learned only from ARP, which is seen less often than
	// the expiry, therefore it keeps being reported and withdrawn.
	for _, app := range apps {
		var present bool
		var learned, expired int
		t.Eventually(app.updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			app.name+" static IP is repeatedly learned from ARP and expires",
			func(info *eveinfo.ZInfoApp) bool {
				hasIP := appHasIP(info, app.staticIP)
				if hasIP && !present {
					learned++
				} else if !hasIP && present {
					expired++
				}
				present = hasIP
				return learned >= 2 && expired >= 2
			}).StopIf(appHasError)))
		log.Infof("%s: static IP %s was learned %d and expired %d times",
			app.name, app.staticIP, learned, expired)
	}
	evetest.Checkpoint("ip-churn-observed")

	// Delete the NI from the config while the apps still use it, as it
	// happens when the controller replaces the whole config. The config API of
	// the framework refuses to do this (DeleteNetworkInstance), therefore the
	// NI is removed manually. Zedrouter keeps the NI until the last VIF is gone.
	niDeleteTime := time.Now()
	devConfig.NetworkInstances = slices.DeleteFunc(devConfig.NetworkInstances,
		func(ni *eveconfig.NetworkInstanceConfig) bool {
			return ni.GetUuidandversion().GetUuid() == niUUID.String()
		})
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(func() []evetest.LogMsg {
		return device.GetLogs(evetest.LogMsgMatch{
			Source:          "zedrouter",
			MsgHasSubstring: "Network instance config delete",
			NotBefore:       niDeleteTime,
		})
	}, timeout, 5*time.Second).ShouldNot(BeEmpty(),
		"zedrouter did not receive the deletion of the NI config")
	evetest.Checkpoint("ni-config-deleted")

	// Now delete the apps. Their VIFs are removed one by one from the NI, which
	// is no longer present in the config.
	appDeleteTime := time.Now()
	for _, app := range apps {
		devConfig.DeleteApplication(app.uuid)
	}
	device.ApplyConfig(devConfig, false, false)

	for _, app := range apps {
		t.Eventually(app.updates, teardownTimeout).Should(Receive(matchers.SatisfyPredicate(
			app.name+" is deleted",
			func(info *eveinfo.ZInfoApp) bool {
				return info.State == eveinfo.ZSwState_INVALID
			})), "zedrouter is probably stuck")
	}
	t.Eventually(niUpdates, teardownTimeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is UNSPECIFIED",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		})), "zedrouter is probably stuck")
	evetest.Checkpoint("ni-and-apps-deleted")

	// Zedrouter keeps the NI until the last app is gone and the state collector
	// has to be told about every VIF which is being removed even though the config
	// of the NI was already deleted. Zedrouter logs an error whenever it cannot.
	for _, failure := range []string{
		"failed to get config for network instance",
		"needed to update VIF arguments for state collecting",
		"needed to update IPs assigned to VIF",
	} {
		t.Expect(device.GetLogs(evetest.LogMsgMatch{
			Source:          "zedrouter",
			MsgHasSubstring: failure,
			NotBefore:       appDeleteTime,
		})).To(BeEmpty(), "zedrouter logged %q while apps were being removed", failure)
	}
}
