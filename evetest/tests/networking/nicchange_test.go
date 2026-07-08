// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"net"
	"testing"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// TestNICCountChange exercises changing the set of network adapters of a
// running application through restarts (no purge): a NIC is added, the two
// NICs are swapped, the device is rebooted and one NIC is removed again,
// with the app disk preserved throughout.
//
// Network model: SingleEthWithDHCP -- a single management port is all that
// is needed.
//
// Device configuration: one Local NI at first (a second one is added in
// phase 2); a container app starting with one virtual adapter (pinned MAC,
// SSH port forwarding, allow-all ACLs).
//
// Phases:
//  1. Deploy the app with one NIC; wait until its IP address is reported in
//     both the app info and the NI status, verify it is reachable over SSH
//     and write a file to the app disk (purge canary).
//  2. Add a second Local NI with a second app NIC (the restart counter is
//     bumped by UpdateApplication); the guest must see both NICs and the
//     canary must survive.
//  3. Swap the two adapters in the configuration; the guest's eth0 must
//     switch from the first to the second adapter's MAC address.
//  4. Reboot the device; the app must come back with both NICs.
//  5. Remove one adapter (after the swap this is the adapter with the first
//     MAC); the app must come back with a single NIC and the canary intact.
//  6. Cleanup: remove the application.
func TestNICCountChange(test *testing.T) {
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
	tc := newNICCountChangeTest(t, devName)
	evetest.Checkpoint("setup-done")

	tc.deployAppWithOneNIC()
	evetest.Checkpoint("ni-with-app-created")
	tc.recordBaseline()

	tc.addSecondNIC()
	evetest.Checkpoint("adding another NI to app")
	tc.verifyGuestSeesBothNICs()
	evetest.Checkpoint("app has two interfaces")
	tc.verifyCanary()
	evetest.Checkpoint("app disk has not been purged")

	tc.swapNICs()
	tc.rebootDeviceAndVerify()

	tc.removeSecondNIC()
	evetest.Checkpoint("removing second NI from app")
	tc.waitAppBackWithOneNIC()
	evetest.Checkpoint("app is back")
	tc.verifyGuestSeesOneNIC()
	tc.verifyCanary()
	evetest.Checkpoint("app disk has not been purged")

	tc.cleanup()
}

// nicCountChangeTest carries the state shared between the phases of
// TestNICCountChange.
type nicCountChangeTest struct {
	t         *WithT
	device    *evetest.EdgeDevice
	devConfig *evetest.EdgeDeviceConfig
	appConfig evetest.ApplicationInstanceConfig
	appUUID   uuid.UUID
	ni1UUID   uuid.UUID
	ni2UUID   uuid.UUID
	appAuth   evetest.UsernamePasswordAuth

	timeout    time.Duration
	sshTimeout time.Duration
	polling    time.Duration

	appMACs []string // vif0 (ni1), vif1 (ni2, added in phase 2)
	appIP   net.IP

	appUpdates   <-chan *eveinfo.ZInfoApp
	stopAppWatch func()
	niUpdates    <-chan *eveinfo.ZInfoNetworkInstance
	stopNIWatch  func()
}

// newNICCountChangeTest builds the base device configuration (network and
// uplink adapter only -- the network instances and the application are added
// by the phases).
func newNICCountChangeTest(t *WithT, devName string) *nicCountChangeTest {
	tc := &nicCountChangeTest{
		t:      t,
		device: evetest.GetEdgeDevice(devName),
		appAuth: evetest.UsernamePasswordAuth{
			Username: "root",
			Password: "testpassword",
		},
		timeout:    5 * time.Minute,
		sshTimeout: 20 * time.Second,
		polling:    3 * time.Second,
		appMACs: []string{
			"02:16:3e:00:00:01", // vif0 (ni1)
			"02:16:3e:00:00:02", // vif1 (ni2), added in phase 2
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
	return tc
}

// runInApp executes a shell script inside the application over SSH.
func (tc *nicCountChangeTest) runInApp(script string) (stdout, stderr string, err error) {
	return tc.device.RunShellScriptInsideApp(tc.appUUID, tc.appAuth, script,
		tc.sshTimeout, 0)
}

// deployAppWithOneNIC (phase 1) applies the base device configuration, adds
// the first Local NI with the app connected to it and waits until the app
// is RUNNING.
func (tc *nicCountChangeTest) deployAppWithOneNIC() {
	// Apply the initial device configuration, without including any network
	// instances for now.
	tc.device.ApplyConfig(tc.devConfig, true, true)

	// Create NI with an app connected to it.
	tc.ni1UUID = tc.devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni1",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:     evetest.IPAddress("10.11.12.1"),
		MTU:         1500,
		ForwardLLDP: false,
	})
	tc.appConfig = evetest.ApplicationInstanceConfig{
		DisplayName: "container-app",
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
				NetworkInstanceUUID: tc.ni1UUID,
				MAC:                 evetest.MACAddress(tc.appMACs[0]),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	}
	tc.appUUID = tc.devConfig.AddApplication(tc.appConfig)

	tc.niUpdates, tc.stopNIWatch = tc.device.WatchNetworkInstanceInfo(tc.ni1UUID)
	tc.appUpdates, tc.stopAppWatch = tc.device.WatchAppInfo(tc.appUUID)
	tc.device.ApplyConfig(tc.devConfig, true, true)

	tc.device.WaitUntilAppIsRunning(tc.appUUID, tc.timeout)
}

// recordBaseline (phase 1) waits until the app's IP address is reported in
// both the app info and the NI status, verifies the app is reachable over
// SSH (port forwarding) and writes the purge canary to the app disk.
func (tc *nicCountChangeTest) recordBaseline() {
	log := evetest.Logger()

	// Wait until application receives IP address from the NI subnet.
	var appInfo *eveinfo.ZInfoApp
	tc.t.Eventually(tc.appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App receives IP address",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			return len(appInfo.Network) == 1 && len(appInfo.Network[0].IPAddrs) == 1
		}).StopIf(appHasError)))
	tc.appIP = evetest.IPAddress(appInfo.Network[0].IPAddrs[0])
	tc.stopAppWatch()

	// Confirm that application IP address is (eventually) reported in the
	// network instance status.
	tc.t.Eventually(tc.niUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App IP is reported inside the NI status",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo := info
			if len(niInfo.Vifs) == 0 || len(niInfo.IpAssignments) == 0 {
				return false
			}
			for _, ipAssignment := range niInfo.IpAssignments {
				if ipAssignment.MacAddress == tc.appMACs[0] {
					return generics.ContainsItem(ipAssignment.IpAddress, tc.appIP.String())
				}
			}
			return false
		}).StopIf(niHasError)))
	tc.stopNIWatch()

	log.Infof("Testing port forwarding")
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		output, _, err := tc.runInApp("ip a")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("eth0"))
		t.Expect(output).To(ContainSubstring(tc.appMACs[0]))
	}, tc.timeout, tc.polling).Should(Succeed())
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Writing something to the disk to ensure it is not purged")
		_, stderrOutput, err := tc.runInApp("echo -n foo > ~/foo.txt")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(stderrOutput).To(BeEmpty())
	}, tc.timeout, tc.polling).Should(Succeed())
}

// addSecondNIC (phase 2) adds a second Local NI with a second app NIC.
// UpdateApplication bumps the restart counter, so the device applies the
// change by restarting the application.
func (tc *nicCountChangeTest) addSecondNIC() {
	tc.ni2UUID = tc.devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni2",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.13.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.13.2"),
			End:   evetest.IPAddress("10.11.13.254"),
		},
	})
	tc.appConfig.NetworkAdapters = append(tc.appConfig.NetworkAdapters,
		evetest.VirtualNetworkAdapter{
			LogicalLabel:        "vif1",
			NetworkInstanceUUID: tc.ni2UUID,
			MAC:                 evetest.MACAddress(tc.appMACs[1]),
			PortFwdRules: []evetest.PortFwdRule{
				{
					Protocol:     evetest.NetworkProtocolTCP,
					EdgeNodePort: 2224,
					AppPort:      22,
				},
			},
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
		})
	tc.devConfig.UpdateApplication(tc.appUUID, tc.appConfig)
	tc.device.ApplyConfig(tc.devConfig, true, true)
}

// verifyGuestSeesBothNICs (phase 2) waits until the restarted app is
// reachable again and the guest sees both NICs.
func (tc *nicCountChangeTest) verifyGuestSeesBothNICs() {
	log := evetest.Logger()
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable after adding another NI...")
		output, _, err := tc.runInApp("ip a")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("eth1"))
		t.Expect(output).To(ContainSubstring(tc.appMACs[0]))
		t.Expect(output).To(ContainSubstring(tc.appMACs[1]))
	}, tc.timeout, tc.polling).Should(Succeed())
}

// verifyCanary (phases 2 and 5) verifies the file written in phase 1 is
// still on the app disk, i.e. the app volume was not purged.
func (tc *nicCountChangeTest) verifyCanary() {
	log := evetest.Logger()
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Reading from disk to check it has not been purged")
		output, stderrOutput, err := tc.runInApp("cat ~/foo.txt")
		t.Expect(stderrOutput).To(BeEmpty())
		t.Expect(output).To(BeEquivalentTo("foo"))
		t.Expect(err).ToNot(HaveOccurred())
	}, tc.timeout, tc.polling).Should(Succeed())
}

// swapNICs (phase 3) swaps the two adapters in the configuration (applied
// via another restart) and verifies that the guest's eth0 switches from the
// first to the second adapter's MAC address.
func (tc *nicCountChangeTest) swapNICs() {
	log := evetest.Logger()
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		output, _, err := tc.runInApp("ip a show dev eth0")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("eth0"))
		t.Expect(output).To(ContainSubstring(tc.appMACs[0]))
	}, tc.timeout, tc.polling).Should(Succeed())

	na := tc.appConfig.NetworkAdapters[0]
	tc.appConfig.NetworkAdapters[0] = tc.appConfig.NetworkAdapters[1]
	tc.appConfig.NetworkAdapters[1] = na
	tc.devConfig.UpdateApplication(tc.appUUID, tc.appConfig)
	tc.device.ApplyConfig(tc.devConfig, true, true)

	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable after NI swap...")
		output, _, err := tc.runInApp("ip a show dev eth0")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("eth0"))
		t.Expect(output).To(ContainSubstring(tc.appMACs[1]))
	}, tc.timeout, tc.polling).Should(Succeed())
}

// rebootDeviceAndVerify (phase 4) reboots the device and verifies the app
// comes back with both NICs.
func (tc *nicCountChangeTest) rebootDeviceAndVerify() {
	log := evetest.Logger()
	tc.device.RequestReboot(true)
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable after reboot...")
		output, _, err := tc.runInApp("ip a")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("eth0"))
		t.Expect(output).To(ContainSubstring("eth1"))
		t.Expect(output).To(ContainSubstring(tc.appMACs[0]))
		t.Expect(output).To(ContainSubstring(tc.appMACs[1]))
	}, tc.timeout, tc.polling).Should(Succeed())
}

// removeSecondNIC (phase 5) removes one adapter from the configuration
// (after the swap in phase 3 this is the adapter with the first MAC),
// applied via another restart.
func (tc *nicCountChangeTest) removeSecondNIC() {
	log := evetest.Logger()
	tc.appConfig.NetworkAdapters = tc.appConfig.NetworkAdapters[:1]
	log.Infof("remaining network adapter: %+v", tc.appConfig.NetworkAdapters)
	tc.devConfig.UpdateApplication(tc.appUUID, tc.appConfig)
	tc.appUpdates, tc.stopAppWatch = tc.device.WatchAppInfo(tc.appUUID)
	tc.device.ApplyConfig(tc.devConfig, true, true)
}

// waitAppBackWithOneNIC (phase 5) waits until the app is reported with a
// single NIC again.
func (tc *nicCountChangeTest) waitAppBackWithOneNIC() {
	var appInfo *eveinfo.ZInfoApp
	tc.t.Eventually(tc.appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App receives IP address",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			return len(appInfo.Network) == 1 && len(appInfo.Network[0].IPAddrs) == 1
		}).StopIf(appHasError)))
	tc.appIP = evetest.IPAddress(appInfo.Network[0].IPAddrs[0])
	tc.stopAppWatch()
}

// verifyGuestSeesOneNIC (phase 5) verifies the guest is left with only the
// remaining adapter's NIC.
func (tc *nicCountChangeTest) verifyGuestSeesOneNIC() {
	log := evetest.Logger()
	tc.t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		output, _, err := tc.runInApp("ip a")
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("eth0"))
		t.Expect(output).ToNot(ContainSubstring("eth1"))
		t.Expect(output).To(ContainSubstring(tc.appMACs[1]))
		t.Expect(output).ToNot(ContainSubstring(tc.appMACs[0]))
	}, tc.timeout, tc.polling).Should(Succeed())
}

// cleanup (phase 6) removes the application.
func (tc *nicCountChangeTest) cleanup() {
	tc.devConfig.DeleteApplication(tc.appUUID)
	tc.device.ApplyConfig(tc.devConfig, false, false)
}

func TestNICCountChangeInterfaceOrdering(test *testing.T) {
}
