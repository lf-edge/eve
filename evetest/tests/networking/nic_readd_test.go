// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"encoding/base64"
	"fmt"
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

// TestNICReaddNoStaleIP verifies that a network adapter removed from a
// running application and added back right away is reported without the IP
// address its predecessor had: the device must not resurrect the DHCP lease
// of the removed adapter for the new one.
//
// The scenario mirrors a controller showing a stale IP address on an app
// interface: a VM with two NICs on one Local NI, running a DHCP client on
// eth0 only, got an address on eth1 through a manual DHCP run; eth1 was then
// removed and added back through app restarts in quick succession. The
// re-added eth1 (same adapter slot, hence the same EVE-generated MAC) was
// reported with the old address although the guest never configured it, and
// the address only went away once the old lease expired, more than an hour
// later.
//
// Network model: SingleEthWithDHCP -- a single management port is all that
// is needed. Internet connectivity is required to pull the Alpine cloud
// image.
//
// Device configuration: one Local NI on the uplink; an Alpine Linux VM app
// (cloud-init image, root SSH login enabled through user-data) with two
// virtual adapters on that NI, both with pinned MACs: vif0 with SSH port
// forwarding and vif1 without. cloud-init's fallback network configuration
// runs DHCP on eth0 only, so eth1 stays unconfigured across restarts, like
// the VM in the scenario above.
//
// Phases:
//  1. Deploy the app; wait until it is RUNNING, reported with an IP address
//     on vif0 and reachable over SSH. Verify that the guest's eth0 carries
//     vif0's MAC, that the NIC with vif1's MAC has no IPv4 address and that
//     the app info reports no IP address for vif1.
//  2. Run a one-shot DHCP client on vif1's NIC inside the guest, with a
//     script that only configures the leased address (no routes, no DNS);
//     wait until the app info reports an IP address for vif1 and record it.
//  3. Remove vif1 (restart-counter bump by UpdateApplication, no purge);
//     wait until the app info reports vif0 as the only NIC and the guest no
//     longer sees vif1's MAC.
//  4. Immediately add vif1 back with the same MAC on the same NI (another
//     restart); wait until the guest sees vif1's MAC again and verify that
//     its NIC has no IPv4 address. Then refresh eth0's lease with a one-shot
//     DHCP client that leaves the guest configuration untouched: a lease
//     file update on the NI is the event that makes the device re-evaluate
//     the leases of all VIFs connected to it.
//  5. Wait until the app info reports the re-added vif1 and assert that it
//     carries no IP address; keep asserting this on every app info message
//     for a soak window, then check the latest app info once more.
//  6. Cleanup: remove the application.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestNICReaddNoStaleIP(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(evetest.HypervisorParameter())

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
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
		evetest.RequireInternetConnectivity{},
	)
	tc := newNICReaddTest(t, devName)
	evetest.Checkpoint("setup-done")

	tc.deployApp()
	evetest.Checkpoint("app-running")
	tc.verifyBaseline()
	evetest.Checkpoint("baseline-verified")

	tc.leaseIPOnSecondNIC()
	tc.waitSecondNICReportedWithIP()
	evetest.Checkpoint("second-nic-reported-with-ip")

	tc.removeSecondNIC()
	tc.waitAppBackWithoutSecondNIC() // TODO: remove this line?
	evetest.Checkpoint("second-nic-removed")

	tc.reAddSecondNIC()
	tc.waitAppBackWithSecondNIC()
	evetest.Checkpoint("second-nic-readded")
	tc.refreshFirstNICLease()

	tc.verifyNoStaleIP()
	evetest.Checkpoint("no-stale-ip-reported")

	tc.cleanup()
}

// dhcpAddrOnlyScript is a udhcpc script which only configures the leased
// address on the interface, leaving routes and DNS untouched so that the
// guest keeps its SSH reachability through eth0.
const dhcpAddrOnlyScript = `#!/bin/sh
case "$1" in
bound|renew)
	ip addr flush dev "$interface"
	ip addr add "$ip/$mask" dev "$interface"
	;;
esac
`

// nicReaddTest carries the state shared between the phases of
// TestNICReaddNoStaleIP.
type nicReaddTest struct {
	t         *WithT
	device    *evetest.EdgeDevice
	devConfig *evetest.EdgeDeviceConfig
	appConfig evetest.ApplicationInstanceConfig
	appUUID   uuid.UUID
	appAuth   evetest.UsernamePasswordAuth

	// vif0 carries the SSH port forwarding; vif1 is the adapter removed and
	// added back.
	vif0, vif1 evetest.VirtualNetworkAdapter
	// guestIf0 and guestIf1 are the names of the NICs with vif0's and
	// vif1's MAC inside the guest.
	guestIf0, guestIf1 string
	// leasedIP is the address the guest leased on vif1 in phase 2.
	leasedIP string

	timeout       time.Duration
	deployTimeout time.Duration // covers the image download
	sshTimeout    time.Duration
	polling       time.Duration
	soakWindow    time.Duration

	appUpdates   <-chan *eveinfo.ZInfoApp
	stopAppWatch func()
}

// newNICReaddTest builds the base device configuration: the uplink adapter,
// the Local NI and the two virtual adapters (the application is added by
// deployApp).
func newNICReaddTest(t *WithT, devName string) *nicReaddTest {
	tc := &nicReaddTest{
		t:      t,
		device: evetest.GetEdgeDevice(devName),
		appAuth: evetest.UsernamePasswordAuth{
			Username: "root",
			Password: "testpassword",
		},
		timeout:       5 * time.Minute,
		deployTimeout: 10 * time.Minute,
		sshTimeout:    20 * time.Second,
		polling:       5 * time.Second,
		soakWindow:    2 * time.Minute,
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
	niUUID := tc.devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
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
	allowAll := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolAny,
			RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
		},
	}
	tc.vif0 = evetest.VirtualNetworkAdapter{
		LogicalLabel:        "vif0",
		NetworkInstanceUUID: niUUID,
		MAC:                 evetest.MACAddress("02:16:3e:00:00:01"),
		PortFwdRules: []evetest.PortFwdRule{
			{
				Protocol:     evetest.NetworkProtocolTCP,
				EdgeNodePort: 2222,
				AppPort:      22,
			},
		},
		ACLAllowRules: allowAll,
	}
	tc.vif1 = evetest.VirtualNetworkAdapter{
		LogicalLabel:        "vif1",
		NetworkInstanceUUID: niUUID,
		MAC:                 evetest.MACAddress("02:16:3e:00:00:02"),
		ACLAllowRules:       allowAll,
	}
	return tc
}

// cloudConfig returns the base64-encoded cloud-init user-data enabling root
// login over SSH with the test password.
func (tc *nicReaddTest) cloudConfig() string {
	cloudConfig := fmt.Sprintf(`#cloud-config
ssh_pwauth: true
chpasswd:
  list: |
    root:%s
  expire: false
write_files:
  - path: /etc/ssh/sshd_config.d/99-allow-root-password.conf
    content: |
      PermitRootLogin yes
runcmd:
  - rc-service sshd restart
`, tc.appAuth.Password)
	return base64.StdEncoding.EncodeToString([]byte(cloudConfig))
}

// runInApp executes a shell script inside the VM over SSH.
func (tc *nicReaddTest) runInApp(script string) (stdout, stderr string, err error) {
	return tc.device.RunShellScriptInsideApp(tc.appUUID, tc.appAuth, script,
		tc.sshTimeout, 0)
}

// waitForSSH waits until the VM is reachable over SSH through the port
// forwarding on vif0.
func (tc *nicReaddTest) waitForSSH() {
	log := evetest.Logger()
	tc.t.Eventually(func(g Gomega) {
		log.Infof("Waiting for the VM SSH daemon to become reachable...")
		_, _, err := tc.runInApp("echo ok")
		g.Expect(err).ToNot(HaveOccurred())
	}, tc.timeout, tc.polling).Should(Succeed())
}

// expectNoIPv4InGuest asserts that the given guest NIC has no IPv4 address.
func (tc *nicReaddTest) expectNoIPv4InGuest(ifName string) {
	output, _, err := tc.runInApp("ip addr show dev " + ifName)
	tc.t.Expect(err).ToNot(HaveOccurred())
	tc.t.Expect(output).ToNot(ContainSubstring("inet "),
		"guest NIC %s unexpectedly has an IPv4 address:\n%s", ifName, output)
}

// deployApp (phase 1) applies the base device configuration, adds the VM
// app with both adapters and waits until it is RUNNING.
func (tc *nicReaddTest) deployApp() {
	// Apply the initial device configuration, without the application for
	// now.
	tc.device.ApplyConfig(tc.devConfig, true, true)

	arch := tc.device.GetArch()
	image, ok := alpineCloudImages[arch]
	tc.t.Expect(ok).To(BeTrue(), "no pinned Alpine cloud image for arch %q", arch)
	tc.appConfig = evetest.ApplicationInstanceConfig{
		DisplayName: "nic-readd-vm",
		Activate:    true,
		Image: evetest.HTTPStorage{
			ImageFormat:       eveconfig.Format_QCOW2,
			ImageSHA256:       image.sha256,
			MaxDownloadBytes:  image.sizeBytes,
			ImageRelativePath: image.relativePath,
			ServerAddress:     "dl-cdn.alpinelinux.org",
			UseHTTPS:          true,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		UserData:           tc.cloudConfig(),
		NetworkAdapters:    []evetest.AppNetworkAdapter{tc.vif0, tc.vif1},
	}
	tc.appUUID = tc.devConfig.AddApplication(tc.appConfig)

	tc.appUpdates, tc.stopAppWatch = tc.device.WatchAppInfo(tc.appUUID)
	tc.device.ApplyConfig(tc.devConfig, true, true)
	tc.device.WaitUntilAppIsRunning(tc.appUUID, tc.deployTimeout)
}

// verifyBaseline (phase 1) waits until vif0 is reported with an IP address
// and the VM is reachable over SSH, then checks the guest side of the
// starting point: eth0 is vif0's NIC and vif1's NIC has no IPv4 address,
// which the app info agrees with.
func (tc *nicReaddTest) verifyBaseline() {
	mac0, mac1 := tc.vif0.MAC.String(), tc.vif1.MAC.String()

	tc.t.Eventually(tc.appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App info reports an IP address for vif0",
		func(info *eveinfo.ZInfoApp) bool {
			return len(reportedIPsForMAC(info, mac0)) > 0
		}).StopIf(appHasError)))
	tc.stopAppWatch()

	tc.waitForSSH()

	// cloud-init's fallback network configuration runs DHCP on eth0 only,
	// which therefore has to be vif0's NIC for the port forwarding (and the
	// scenario as a whole) to apply.
	output, _, err := tc.runInApp(listGuestNICs)
	tc.t.Expect(err).ToNot(HaveOccurred())
	tc.guestIf0 = ifNameByMAC(output, mac0)
	tc.t.Expect(tc.guestIf0).To(Equal("eth0"),
		"vif0 (%s) is not the guest's eth0:\n%s", mac0, output)
	tc.guestIf1 = ifNameByMAC(output, mac1)
	tc.t.Expect(tc.guestIf1).ToNot(BeEmpty(),
		"vif1 (%s) is missing in the guest:\n%s", mac1, output)
	tc.expectNoIPv4InGuest(tc.guestIf1)

	tc.t.Expect(reportedIPsForMAC(tc.device.GetAppInfo(tc.appUUID), mac1)).To(BeEmpty(),
		"an IP address is reported for vif1 (%s) although the guest did not configure it",
		mac1)
}

// leaseIPOnSecondNIC (phase 2) runs a one-shot DHCP client on vif1's NIC
// inside the guest, configuring only the leased address.
func (tc *nicReaddTest) leaseIPOnSecondNIC() {
	log := evetest.Logger()
	tc.appUpdates, tc.stopAppWatch = tc.device.WatchAppInfo(tc.appUUID)

	log.Infof("Running a one-shot DHCP client on the guest's %s (%s)...",
		tc.guestIf1, tc.vif1.MAC)
	script := fmt.Sprintf("echo %s | base64 -d > /root/dhcp-addr-only.sh && "+
		"chmod +x /root/dhcp-addr-only.sh && "+
		"ip link set dev %s up && "+
		"udhcpc -i %s -n -q -t 5 -s /root/dhcp-addr-only.sh && "+
		"ip addr show dev %s",
		base64.StdEncoding.EncodeToString([]byte(dhcpAddrOnlyScript)),
		tc.guestIf1, tc.guestIf1, tc.guestIf1)
	output, stderr, err := tc.device.RunShellScriptInsideApp(tc.appUUID, tc.appAuth,
		script, time.Minute, 0)
	tc.t.Expect(err).ToNot(HaveOccurred(), "DHCP on %s failed: %s", tc.guestIf1, stderr)
	tc.t.Expect(output).To(ContainSubstring("inet "),
		"no IPv4 address on %s after DHCP:\n%s", tc.guestIf1, output)
}

// waitSecondNICReportedWithIP (phase 2) waits until the app info reports an
// IP address for vif1 and records it.
func (tc *nicReaddTest) waitSecondNICReportedWithIP() {
	log := evetest.Logger()
	mac1 := tc.vif1.MAC.String()

	var appInfo *eveinfo.ZInfoApp
	tc.t.Eventually(tc.appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App info reports an IP address for vif1",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			return len(reportedIPsForMAC(info, mac1)) > 0
		}).StopIf(appHasError)))
	tc.stopAppWatch()
	tc.leasedIP = reportedIPsForMAC(appInfo, mac1)[0]
	log.Infof("vif1 (%s) is reported with the leased IP address %s", mac1, tc.leasedIP)
}

// removeSecondNIC (phase 3) removes vif1 from the application configuration;
// UpdateApplication bumps the restart counter, so the device applies the
// change by restarting the application.
func (tc *nicReaddTest) removeSecondNIC() {
	tc.appConfig.NetworkAdapters = []evetest.AppNetworkAdapter{tc.vif0}
	tc.devConfig.UpdateApplication(tc.appUUID, tc.appConfig)
	tc.appUpdates, tc.stopAppWatch = tc.device.WatchAppInfo(tc.appUUID)
	tc.device.ApplyConfig(tc.devConfig, true, true)
}

// waitAppBackWithoutSecondNIC (phase 3) waits until the app info reports
// vif0 as the only NIC and the restarted guest no longer sees vif1's MAC.
func (tc *nicReaddTest) waitAppBackWithoutSecondNIC() {
	log := evetest.Logger()
	mac0, mac1 := tc.vif0.MAC.String(), tc.vif1.MAC.String()

	tc.t.Eventually(tc.appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App info reports vif0 as the only NIC",
		func(info *eveinfo.ZInfoApp) bool {
			return len(info.GetNetwork()) == 1 &&
				reportedNetworkForMAC(info, mac0) != nil
		}).StopIf(appHasError)))
	tc.stopAppWatch()

	tc.t.Eventually(func(g Gomega) {
		log.Infof("Waiting for the restarted VM to come back without vif1...")
		output, _, err := tc.runInApp(listGuestNICs)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(ifNameByMAC(output, mac0)).ToNot(BeEmpty(),
			"vif0 (%s) is missing in the guest:\n%s", mac0, output)
		g.Expect(ifNameByMAC(output, mac1)).To(BeEmpty(),
			"vif1 (%s) is still present in the guest:\n%s", mac1, output)
	}, tc.timeout, tc.polling).Should(Succeed())
}

// reAddSecondNIC (phase 4) adds vif1 back to the application configuration
// with the same MAC on the same NI, applied via another restart.
func (tc *nicReaddTest) reAddSecondNIC() {
	tc.appConfig.NetworkAdapters = []evetest.AppNetworkAdapter{tc.vif0, tc.vif1}
	tc.devConfig.UpdateApplication(tc.appUUID, tc.appConfig)
	// The watch stays open into verifyNoStaleIP so that no app info
	// published after the re-add is missed.
	tc.appUpdates, tc.stopAppWatch = tc.device.WatchAppInfo(tc.appUUID)
	tc.device.ApplyConfig(tc.devConfig, true, true)
}

// waitAppBackWithSecondNIC (phase 4) waits until the restarted guest sees
// vif1's MAC again and verifies that its NIC has no IPv4 address.
func (tc *nicReaddTest) waitAppBackWithSecondNIC() {
	log := evetest.Logger()
	mac1 := tc.vif1.MAC.String()

	tc.t.Eventually(func(g Gomega) {
		log.Infof("Waiting for the restarted VM to come back with vif1...")
		output, _, err := tc.runInApp(listGuestNICs)
		g.Expect(err).ToNot(HaveOccurred())
		tc.guestIf1 = ifNameByMAC(output, mac1)
		g.Expect(tc.guestIf1).ToNot(BeEmpty(),
			"vif1 (%s) is missing in the guest:\n%s", mac1, output)
	}, tc.timeout, tc.polling).Should(Succeed())
	tc.expectNoIPv4InGuest(tc.guestIf1)
}

// refreshFirstNICLease (phase 4) refreshes the DHCP lease of vif0's NIC
// with a one-shot client that leaves the guest configuration untouched. A
// lease file update on the NI is the event that makes the device re-evaluate
// the leases of all VIFs connected to it; the guest's eth0 did that already
// when it booted, this repeats it now that the re-added NIC is known to the
// device.
func (tc *nicReaddTest) refreshFirstNICLease() {
	log := evetest.Logger()
	log.Infof("Refreshing the DHCP lease of the guest's %s...", tc.guestIf0)
	_, stderr, err := tc.device.RunShellScriptInsideApp(tc.appUUID, tc.appAuth,
		fmt.Sprintf("udhcpc -i %s -n -q -t 5 -s /bin/true", tc.guestIf0),
		time.Minute, 0)
	tc.t.Expect(err).ToNot(HaveOccurred(),
		"DHCP lease refresh on %s failed: %s", tc.guestIf0, stderr)
}

// verifyNoStaleIP (phase 5) asserts that the re-added vif1 is reported
// without an IP address: in the first app info mentioning it, in every app
// info published during the soak window and in the latest one afterwards.
func (tc *nicReaddTest) verifyNoStaleIP() {
	log := evetest.Logger()
	mac1 := tc.vif1.MAC.String()
	staleIPMessage := func(info *eveinfo.ZInfoApp) func() string {
		return func() string {
			return fmt.Sprintf("an IP address is reported for the re-added vif1 (%s), "+
				"which the guest never configured (the removed vif1 had leased %s):\n%s",
				mac1, tc.leasedIP, info)
		}
	}

	var appInfo *eveinfo.ZInfoApp
	tc.t.Eventually(tc.appUpdates, tc.timeout).Should(Receive(matchers.SatisfyPredicate(
		"App info reports the re-added vif1",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			return reportedNetworkForMAC(info, mac1) != nil
		}).StopIf(appHasError)))
	tc.t.Expect(reportedIPsForMAC(appInfo, mac1)).To(BeEmpty(), staleIPMessage(appInfo))

	log.Infof("Soaking for %v: no app info may report an IP address for vif1...",
		tc.soakWindow)
	tc.t.Consistently(func(g Gomega) {
		for {
			select {
			case info, ok := <-tc.appUpdates:
				g.Expect(ok).To(BeTrue(), "the app info watch was closed")
				g.Expect(reportedIPsForMAC(info, mac1)).To(BeEmpty(), staleIPMessage(info))
			default:
				return
			}
		}
	}, tc.soakWindow, tc.polling).Should(Succeed())
	tc.stopAppWatch()

	appInfo = tc.device.GetAppInfo(tc.appUUID)
	tc.t.Expect(reportedIPsForMAC(appInfo, mac1)).To(BeEmpty(), staleIPMessage(appInfo))
}

// cleanup (phase 6) removes the application.
func (tc *nicReaddTest) cleanup() {
	tc.devConfig.DeleteApplication(tc.appUUID)
	tc.device.ApplyConfig(tc.devConfig, false, false)
}
