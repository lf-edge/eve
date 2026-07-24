// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"net"
	"strings"
	"testing"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// TestStagedNICChange verifies that a change to the set of network adapters
// of a running application is only *staged* by the device: no part of the
// new adapter set may take effect -- neither in the reported device state
// nor inside the guest -- until the application is restarted, regardless of
// what other configuration is reconciled in the meantime.
//
// Network model: SingleEthWithDHCP -- a single management port is all that
// is needed; the test is about application NIC staging, not uplink topology.
//
// Device configuration: two Local NIs on the single uplink; app1 with two
// virtual adapters (vif0 on ni1, vif1 on ni2, both with pinned MACs, SSH
// port forwarding and allow-all ACLs); later app2 with one adapter on ni2
// (shared with app1's vif1, so deploying it reprograms the very bridge and
// iptables state that app1's staged change also touches).
//
// Phases:
//  1. Deploy app1, wait until it is RUNNING with both NICs reported with an
//     IP address and reachable over SSH; record the boot time and the name
//     of app1's VIF on ni2 as the baseline.
//  2. Stage a NIC addition: add vif2 (on ni2, pinned MAC, with an SSH
//     port-forwarding rule) to app1 *without* bumping the restart counter,
//     by reverting the counter bump made by UpdateApplication directly in
//     the device configuration. Wait until the device confirms it has
//     processed the new config.
//  3. Soak: repeatedly assert that nothing has changed -- app1 still
//     RUNNING with the baseline boot time (no restart), still exactly two
//     NICs in the reported app info, app1's VIF set on ni2 unchanged (the
//     same single VIF with the baseline name), the guest still sees only
//     the two original MACs, and the ACL state is untouched: the two
//     original port-forwarding rules keep accepting connections while the
//     staged one must not accept any yet.
//  4. Stir reconciliation: deploy app2 on ni2 and wait until it is RUNNING
//     and reachable over SSH (proving zedrouter reprogrammed the shared NI
//     for the new app). Then repeat the phase-3 soak for app1.
//  5. Restart app1 (restart-counter bump). The staged adapter must now take
//     effect: the boot time advances, the guest sees all three MACs with
//     an IPv4 address on each NIC and the staged port-forwarding rule
//     starts accepting connections. (Volume preservation across such a
//     restart is already covered by TestNICCountChange.)
//  6. Cleanup: remove both applications.
func TestStagedNICChange(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(evetest.HypervisorParameter())

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	// Kubevirt is only supported by cluster tests.
	evetest.SkipIfHypervisorKubevirt()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    hypervisor,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	tc := newStagedNICChangeTest(t, devName)
	evetest.Checkpoint("setup-done")

	tc.deployApp1()
	evetest.Checkpoint("app1-deployed")
	tc.recordBaseline()
	evetest.Checkpoint("baseline-recorded")

	tc.stageNICAddition()
	evetest.Checkpoint("nic-add-staged")
	tc.assertNothingAppliedEarly("right after staging")
	evetest.Checkpoint("staged-change-inert")

	tc.deployUnrelatedApp()
	evetest.Checkpoint("unrelated-app-deployed")
	tc.assertNothingAppliedEarly("after deploying another app on the shared NI")
	evetest.Checkpoint("staged-change-still-inert")

	tc.restartApp1()
	evetest.Checkpoint("app1-restarted")
	tc.verifyStagedNICApplied()
	evetest.Checkpoint("staged-change-applied-on-restart")

	tc.cleanup()
}

// stagedNICChangeTest carries the state shared between the phases of
// TestStagedNICChange.
type stagedNICChangeTest struct {
	t          *WithT
	device     *evetest.EdgeDevice
	devConfig  *evetest.EdgeDeviceConfig
	app1Config evetest.ApplicationInstanceConfig
	app1UUID   uuid.UUID
	app2UUID   uuid.UUID
	ni2UUID    uuid.UUID
	appAuth    evetest.UsernamePasswordAuth

	timeout     time.Duration
	sshTimeout  time.Duration
	polling     time.Duration
	soak        time.Duration
	soakPolling time.Duration

	app1MACs []string // vif0 (ni1), vif1 (ni2), vif2 (ni2, staged)
	app2MAC  string
	allowAll []evetest.ACLAllowRule

	baselineBootTime time.Time
	baselineVifName  string
}

// newStagedNICChangeTest builds the base device configuration (uplink, two
// Local NIs) and the initial two-NIC configuration of app1.
func newStagedNICChangeTest(t *WithT, devName string) *stagedNICChangeTest {
	tc := &stagedNICChangeTest{
		t:      t,
		device: evetest.GetEdgeDevice(devName),
		appAuth: evetest.UsernamePasswordAuth{
			Username: "root",
			Password: "testpassword",
		},
		timeout:    5 * time.Minute,
		sshTimeout: 20 * time.Second,
		polling:    3 * time.Second,
		// The soak must span at least one info-publish interval so that the
		// repeated assertions run against state reported after the staging.
		soak:        90 * time.Second,
		soakPolling: 10 * time.Second,
		app1MACs: []string{
			"02:16:3e:00:00:01", // vif0 (ni1)
			"02:16:3e:00:00:02", // vif1 (ni2)
			"02:16:3e:00:00:03", // vif2 (ni2), staged in phase 2
		},
		app2MAC: "02:16:3e:00:00:04",
		allowAll: []evetest.ACLAllowRule{
			{
				Protocol:     evetest.NetworkProtocolAny,
				RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
			},
		},
	}

	tc.devConfig = evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := tc.devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	tc.devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	ni1UUID := tc.devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni1",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	tc.ni2UUID = tc.devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni2",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.13.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.13.2"),
			End:   evetest.IPAddress("10.11.13.254"),
		},
		Gateway: evetest.IPAddress("10.11.13.1"),
		MTU:     1500,
	})

	tc.app1Config = evetest.ApplicationInstanceConfig{
		DisplayName: "staged-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: ni1UUID,
				MAC:                 evetest.MACAddress(tc.app1MACs[0]),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: tc.allowAll,
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: tc.ni2UUID,
				MAC:                 evetest.MACAddress(tc.app1MACs[1]),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2224,
						AppPort:      22,
					},
				},
				ACLAllowRules: tc.allowAll,
			},
		},
	}
	return tc
}

// runInApp executes a shell script inside the given application over SSH.
func (tc *stagedNICChangeTest) runInApp(appUUID uuid.UUID,
	script string) (stdout, stderr string, err error) {
	return tc.device.RunShellScriptInsideApp(appUUID, tc.appAuth, script,
		tc.sshTimeout, 0)
}

// deployApp1 (phase 1) deploys app1 with its two initial NICs and waits
// until it is RUNNING with both NICs reported with an IP address. The boot
// time of this first boot becomes the baseline that the staged phases must
// not disturb.
func (tc *stagedNICChangeTest) deployApp1() {
	tc.app1UUID = tc.devConfig.AddApplication(tc.app1Config)
	appUpdates, stopAppWatch := tc.device.WatchAppInfo(tc.app1UUID)
	defer stopAppWatch()
	tc.device.ApplyConfig(tc.devConfig, true, true)
	tc.device.WaitUntilAppIsRunning(tc.app1UUID, tc.timeout)

	var appInfo *eveinfo.ZInfoApp
	tc.t.Eventually(appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App is RUNNING with both NICs reported and boot time known",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			if info.State != eveinfo.ZSwState_RUNNING || info.GetBootTime() == nil {
				return false
			}
			return reportedIPsForMACs(info, tc.app1MACs[:2])
		}).StopIf(appHasError)))
	tc.baselineBootTime = appInfo.GetBootTime().AsTime()
}

// recordBaseline (phase 1) verifies app1 is reachable over SSH and records
// the name of app1's VIF on ni2, which must not change while the NIC
// addition is staged.
func (tc *stagedNICChangeTest) recordBaseline() {
	log := evetest.Logger()
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app1 SSH daemon to become reachable...")
		output, _, err := tc.runInApp(tc.app1UUID, "ip a")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(tc.app1MACs[0]))
		t.Expect(output).To(ContainSubstring(tc.app1MACs[1]))
	}, tc.timeout, tc.polling).Should(Succeed())
	tc.t.Eventually(func(t Gomega) {
		var vifCount int
		tc.baselineVifName, vifCount = tc.app1VifsOnNI2()
		t.Expect(vifCount).To(Equal(1))
		t.Expect(tc.baselineVifName).ToNot(BeEmpty())
	}, tc.timeout, tc.polling).Should(Succeed())
}

// app1VifsOnNI2 returns the name of app1's VIF with the vif1 MAC address as
// reported by ni2, together with the total count of app1 VIFs on ni2.
func (tc *stagedNICChangeTest) app1VifsOnNI2() (vifName string, count int) {
	niInfo := tc.device.GetNetworkInstanceInfo(tc.ni2UUID)
	if niInfo == nil {
		return "", 0
	}
	for _, vif := range niInfo.Vifs {
		if vif.AppID != tc.app1UUID.String() {
			continue
		}
		count++
		if vif.MacAddress == tc.app1MACs[1] {
			vifName = vif.VifName
		}
	}
	return vifName, count
}

// stageNICAddition (phase 2) adds vif2 to app1 in the controller
// configuration without a restart command, so that the device can only
// stage the change.
func (tc *stagedNICChangeTest) stageNICAddition() {
	tc.app1Config.NetworkAdapters = append(tc.app1Config.NetworkAdapters,
		evetest.VirtualNetworkAdapter{
			LogicalLabel:        "vif2",
			NetworkInstanceUUID: tc.ni2UUID,
			MAC:                 evetest.MACAddress(tc.app1MACs[2]),
			// The port-forwarding rule makes the staged ACL state externally
			// observable: the DNAT rule for port 2228 must not be programmed
			// while the change is staged and must start working after the
			// restart.
			PortFwdRules: []evetest.PortFwdRule{
				{
					Protocol:     evetest.NetworkProtocolTCP,
					EdgeNodePort: 2228,
					AppPort:      22,
				},
			},
			ACLAllowRules: tc.allowAll,
		})
	// UpdateApplication bumps the restart counter whenever the adapter set
	// changes; revert the bump directly in the device configuration so that
	// the NIC addition reaches the device without a restart command and
	// therefore stays staged.
	var app1Proto *eveconfig.AppInstanceConfig
	for _, app := range tc.devConfig.Apps {
		if app.Uuidandversion.Uuid == tc.app1UUID.String() {
			app1Proto = app
			break
		}
	}
	tc.t.Expect(app1Proto).ToNot(BeNil())
	restartCounterBefore := app1Proto.GetRestart().GetCounter()
	tc.devConfig.UpdateApplication(tc.app1UUID, tc.app1Config)
	app1Proto.Restart.Counter = restartCounterBefore
	// waitUntilConfirmed=true: return only after the device reports the new
	// config as processed by zedagent, so the soaks that follow run against
	// a device that already holds the staged change.
	tc.device.ApplyConfig(tc.devConfig, true, true)
}

// assertNothingAppliedEarly (phases 3 and 4) asserts repeatedly, over a
// period longer than the info-publish interval, that neither the reported
// device state nor the guest shows any trace of the staged adapter.
func (tc *stagedNICChangeTest) assertNothingAppliedEarly(phase string) {
	log := evetest.Logger()
	log.Infof("Asserting the staged NIC change has no effect (%s)...", phase)
	tc.t.Consistently(func(t Gomega) {
		info := tc.device.GetAppInfo(tc.app1UUID)
		t.Expect(info).ToNot(BeNil())
		t.Expect(info.State).To(Equal(eveinfo.ZSwState_RUNNING),
			"app must stay RUNNING while the change is staged")
		t.Expect(info.GetBootTime()).ToNot(BeNil())
		t.Expect(info.GetBootTime().AsTime().Equal(tc.baselineBootTime)).To(BeTrue(),
			"boot time must not advance while the change is staged")
		t.Expect(info.Network).To(HaveLen(2),
			"only the two original NICs may be reported while the change is staged")
		vifName, vifCount := tc.app1VifsOnNI2()
		t.Expect(vifCount).To(Equal(1),
			"no additional app1 VIF may appear on ni2 while the change is staged")
		t.Expect(vifName).To(Equal(tc.baselineVifName),
			"app1's VIF on ni2 must keep its name while the change is staged")
		output, _, err := tc.runInApp(tc.app1UUID, "ip a")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(tc.app1MACs[0]))
		t.Expect(output).To(ContainSubstring(tc.app1MACs[1]))
		t.Expect(output).ToNot(ContainSubstring(tc.app1MACs[2]),
			"the staged NIC must not appear inside the guest")
		t.Expect(tc.devicePortReachable("2222")).To(BeTrue(),
			"port forwarding of an existing adapter must keep working "+
				"while the change is staged")
		t.Expect(tc.devicePortReachable("2224")).To(BeTrue(),
			"port forwarding of an existing adapter must keep working "+
				"while the change is staged")
		t.Expect(tc.devicePortReachable("2228")).To(BeFalse(),
			"the staged NIC's port-forwarding ACL must not be programmed "+
				"while the change is staged")
	}, tc.soak, tc.soakPolling).Should(Succeed())
}

// devicePortReachable reports whether a TCP connection can be established
// to the given port on any of the device's uplink IP addresses.
func (tc *stagedNICChangeTest) devicePortReachable(port string) bool {
	for _, ip := range tc.device.GetDeviceIPAddress("ethernet0") {
		conn, err := net.DialTimeout("tcp",
			net.JoinHostPort(ip.String(), port), 3*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// deployUnrelatedApp (phase 4) deploys app2 on the NI shared with app1's
// vif1 to force zedrouter to reconcile the very bridge/iptables state that
// app1's staged change also touches.
func (tc *stagedNICChangeTest) deployUnrelatedApp() {
	log := evetest.Logger()
	app2Config := evetest.ApplicationInstanceConfig{
		DisplayName: "reconciler-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: tc.ni2UUID,
				MAC:                 evetest.MACAddress(tc.app2MAC),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2226,
						AppPort:      22,
					},
				},
				ACLAllowRules: tc.allowAll,
			},
		},
	}
	tc.app2UUID = tc.devConfig.AddApplication(app2Config)
	tc.device.ApplyConfig(tc.devConfig, true, true)
	tc.device.WaitUntilAppIsRunning(tc.app2UUID, tc.timeout)
	// app2 being reachable over SSH proves zedrouter reprogrammed the shared
	// NI (DNAT and filtering rules) while app1's change was staged.
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app2 SSH daemon to become reachable...")
		_, _, err := tc.runInApp(tc.app2UUID, "true")
		t.Expect(err).ToNot(HaveOccurred())
	}, tc.timeout, tc.polling).Should(Succeed())
}

// restartApp1 (phase 5) restarts app1 via a restart-counter bump and waits
// until it is RUNNING again with an advanced boot time.
func (tc *stagedNICChangeTest) restartApp1() {
	appUpdates, stopAppWatch := tc.device.WatchAppInfo(tc.app1UUID)
	defer stopAppWatch()
	tc.device.RebootApplication(tc.app1UUID, false, 0)
	tc.t.Eventually(appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App has restarted (advanced boot time) and is RUNNING",
		func(info *eveinfo.ZInfoApp) bool {
			return info.GetBootTime() != nil &&
				info.GetBootTime().AsTime().After(tc.baselineBootTime) &&
				info.State == eveinfo.ZSwState_RUNNING
		}).StopIf(appHasError)))
}

// verifyStagedNICApplied (phase 5) verifies that the restart applied the
// staged adapter: the guest must see all three MACs with an IPv4 address
// on each NIC.
//
// Note: the reported (controller-visible) IP address of the newly added NIC
// is deliberately not asserted here: zedrouter currently updates the
// state-collecting machinery before publishing the new AppNetworkStatus, so
// the new NIC's IP is not attributed until that ordering is fixed. Extend
// the assertion to reportedIPsForMACs(info, tc.app1MACs) once it is.
func (tc *stagedNICChangeTest) verifyStagedNICApplied() {
	log := evetest.Logger()
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app1 to come back with all three NICs...")
		output, _, err := tc.runInApp(tc.app1UUID, "ip a")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(tc.app1MACs[0]))
		t.Expect(output).To(ContainSubstring(tc.app1MACs[1]))
		t.Expect(output).To(ContainSubstring(tc.app1MACs[2]),
			"the restart must apply the staged NIC")
		// Each NIC must obtain an IPv4 address from its NI subnet
		// (10.11.12.0/24 or 10.11.13.0/24).
		t.Expect(strings.Count(output, "inet 10.11.")).To(BeNumerically(">=", 3))
		t.Expect(tc.devicePortReachable("2228")).To(BeTrue(),
			"the restart must apply the staged NIC's port-forwarding ACL")
	}, tc.timeout, tc.polling).Should(Succeed())
}

// cleanup (phase 6) removes both applications.
func (tc *stagedNICChangeTest) cleanup() {
	tc.devConfig.DeleteApplication(tc.app1UUID)
	tc.devConfig.DeleteApplication(tc.app2UUID)
	tc.device.ApplyConfig(tc.devConfig, false, false)
}

// reportedIPsForMACs reports whether info contains, for every MAC address in
// macs, a network entry with at least one assigned IP address.
func reportedIPsForMACs(info *eveinfo.ZInfoApp, macs []string) bool {
	for _, mac := range macs {
		var found bool
		for _, network := range info.Network {
			if network.MacAddr == mac && len(network.IPAddrs) > 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
