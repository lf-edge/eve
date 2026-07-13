// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"google.golang.org/protobuf/proto"
)

// TestActiveBackupBond verifies that EVE creates an active-backup bond from
// two physical Ethernet adapters, gets a DHCP lease on the bond interface,
// publishes the bond status (active member, ARP monitor, member list),
// detects a link failure via the ARP monitor and fails over to the surviving
// member, and reports a non-zero link-failure counter in bond metrics.
//
// Network model
// -------------
//   - netmodels.TwoMgmtPortsOneBridge: eth0 and eth1 on the SAME SDN bridge,
//     reaching the same network/DHCP/controller. Active-backup is
//     transparent to the upstream switch -- only one member transmits at a
//     time -- so no SDN-side LAG is required.
//
// Device configuration
// --------------------
//   - PhysicalIO for eth0 and eth1 (each as a SystemAdapter-less Ethernet
//     port; they become bond members).
//   - One DHCP NetworkConfig.
//   - One BondConfig "active-backup-bond" (interface name "bond1" -- "bond0"
//     is reserved in Linux) aggregating eth0+eth1 in BOND_MODE_ACTIVE_BACKUP
//     with ARP monitoring (interval 1000 ms, target = the SDN gateway).
//     ARP monitoring is chosen over MII because virtio-net does not
//     propagate link-down state into the EVE VM; the ARP probe actively
//     detects loss of upstream when an SDN port is taken AdminUp=false.
//
// Phases
// ------
//   - Wait for DevicePortStatus to report the bond with an IPv4 address from
//     the SDN subnet, no error, and a BondStatus with 2 members and a
//     non-empty ActiveMember. Assert mode, ARP-monitor config (enabled,
//     interval, IP targets) and that MII monitor is disabled.
//   - SSH-side smoke test: `echo bond-ssh-ok` runs over SSH, proving that
//     control-plane reachability across the bond works.
//   - Runtime config change: bump ARP-monitor interval to 1500 ms via
//     UpdateBond + re-ApplyConfig; assert BondStatus reflects the new
//     interval.
//   - Failover phase: identify the currently active member, set that port's
//     AdminUp=false in the SDN model, then assert:
//   - SSH over the bond keeps working (using a fresh attempt -- the
//     previous TCP flow may break).
//   - DevicePortStatus.BondStatus reports a DIFFERENT ActiveMember and
//     the previously active member with MiiUp=false.
//   - DeviceMetric.BondMetrics shows non-zero LinkFailureCount for the
//     failed member.
//   - Restore the SDN model (link back up).
//
// Hypervisor
// ----------
//   - Hardcoded WithHypervisor=HypervisorKVM in RequireEdgeDevice -- this
//     test lives in TestDeviceConnectivitySuite and does not parameterize
//     the hypervisor.
func TestActiveBackupBond(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    evetest.HypervisorKVM,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	// Active-backup bond is transparent to the network switch -- only one
	// member transmits at a time, so no switch-side LAG/bond is needed.
	// We just need both ports on the same bridge to reach the same network.
	// (For 802.3ad/LACP, the SDN network model would need a Bond on the
	// bridge side to participate in LACP negotiation.)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.TwoMgmtPortsOneBridge,
	}
	evetest.Setup(requiredDevice, requiredNetModel)

	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build device config: two physical adapters without direct network
	// assignment, bonded together as active-backup.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet1",
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	bondConfig := evetest.BondConfig{
		LogicalLabel:  "active-backup-bond",
		InterfaceName: "bond1", // bond0 is reserved in Linux
		MemberLabels:  []string{"ethernet0", "ethernet1"},
		BondMode:      evecommon.BondMode_BOND_MODE_ACTIVE_BACKUP,
		// Use ARP monitoring instead of MII because virtio-net does not
		// propagate link-down state from the SDN side to the EVE VM.
		// ARP monitoring actively probes the gateway and will detect
		// the failure when the SDN port is set AdminUp=false.
		ARPMonitor: &eveconfig.ArpMonitor{
			Interval:  1000,
			IpTargets: []string{"172.20.20.1"}, // gateway from TwoMgmtPortsOneBridge
		},
		NetworkUUID: dhcpNet,
		Usage:       evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	}
	devConfig.AddBond(bondConfig)

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	devMetrics, stopDevMetricsWatch := device.WatchDeviceMetrics()
	defer stopDevMetricsWatch()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Wait for device info to report the bond interface with an IP address,
	// no errors, and an active member.
	timeout := 5 * time.Minute
	var bondIP net.IP
	var activeMember string
	var bondStatus *eveinfo.BondStatus
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Bond interface has IP, no errors and reports active member",
		func(info *eveinfo.ZInfoDevice) bool {
			port := getDevicePort("active-backup-bond", info)
			if port == nil {
				return false
			}
			if port.GetErr() != nil && port.GetErr().GetDescription() != "" {
				return false
			}
			bondIP = getPortIPv4Addr("active-backup-bond", info)
			if bondIP == nil {
				return false
			}
			bondStatus = port.GetBondStatus()
			if bondStatus == nil || len(bondStatus.GetMembers()) != 2 {
				return false
			}
			activeMember = bondStatus.GetActiveMember()
			return activeMember != ""
		})))
	evetest.Checkpoint("bond-has-ip")
	t.Expect(bondStatus.GetMode()).To(Equal(evecommon.BondMode_BOND_MODE_ACTIVE_BACKUP))
	t.Expect(bondStatus.GetArpMonitor().GetEnabled()).To(BeTrue())
	t.Expect(bondStatus.GetArpMonitor().GetIpTargets()).To(Equal([]string{"172.20.20.1"}))
	t.Expect(bondStatus.GetArpMonitor().GetPollingInterval()).To(BeEquivalentTo(1000))
	t.Expect(bondStatus.GetMiiMonitor().GetEnabled()).To(BeFalse())
	netSubnet := evetest.IPSubnet("172.20.20.0/24") // from the network model
	t.Expect(netSubnet.Contains(bondIP)).To(BeTrue())
	evetest.Logger().Infof("Currently active member: %s", activeMember)
	t.Expect(activeMember).To(BeElementOf("ethernet0", "ethernet1"))

	// Verify we can SSH into EVE through the bond interface.
	var stdout string
	t.Eventually(func() error {
		var stderr string
		var err error
		stdout, stderr, err = device.RunShellScript("echo bond-ssh-ok", 0, 5*time.Second)
		if err != nil {
			return fmt.Errorf("SSH over bond failed: %s", stderr)
		}
		return nil
	}, time.Minute, 5*time.Second).Should(Succeed())
	t.Expect(stdout).To(ContainSubstring("bond-ssh-ok"))
	evetest.Checkpoint("ssh-over-bond-works")

	// Verify that bond config change is applied.
	bondConfig.ARPMonitor.Interval = 1500
	devConfig.UpdateBond(bondConfig)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("bond-config-updated")
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Bond ARP monitor interval is updated",
		func(info *eveinfo.ZInfoDevice) bool {
			port := getDevicePort("active-backup-bond", info)
			if port == nil {
				return false
			}
			bondStatus = port.GetBondStatus()
			return bondStatus.GetArpMonitor().GetPollingInterval() == 1500
		})))

	// Simulate link failure on the active member by setting AdminUp=false
	// in the network model.
	// Map the active member logical label to the SDN port index.
	var activeMemberIdx int
	switch activeMember {
	case "ethernet0":
		activeMemberIdx = 0
	case "ethernet1":
		activeMemberIdx = 1
	}
	updatedModel := proto.Clone(netmodels.TwoMgmtPortsOneBridge).(*api.NetworkModel)
	updatedModel.Ports[activeMemberIdx].AdminUp = false
	evetest.UpdateNetworkModel(updatedModel)
	evetest.Checkpoint("active-member-link-down")

	// Eventually SSH to EVE should work again (after failover).
	t.Eventually(func() error {
		var stderr string
		var err error
		stdout, stderr, err = device.RunShellScript("echo failover-ok", 0, 5*time.Second)
		if err != nil {
			return fmt.Errorf("SSH after failover failed: %s", stderr)
		}
		return nil
	}, time.Minute, 5*time.Second).Should(Succeed())
	t.Expect(stdout).To(ContainSubstring("failover-ok"))
	evetest.Checkpoint("ssh-after-failover-works")

	// Verify the active member has changed and the failed member reports MII down.
	var newActiveMember string
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Bond failover to different member with MII down on failed member",
		func(info *eveinfo.ZInfoDevice) bool {
			port := getDevicePort("active-backup-bond", info)
			if port == nil {
				return false
			}
			bs := port.GetBondStatus()
			if bs == nil {
				return false
			}
			newActiveMember = bs.GetActiveMember()
			if newActiveMember == "" || newActiveMember == activeMember {
				return false
			}
			// Check that the original active member (now failed) has MII down.
			for _, member := range bs.GetMembers() {
				if member.GetLogicallabel() == activeMember {
					return !member.GetMiiUp()
				}
			}
			return false
		})))
	evetest.Logger().Infof("Active member after failover: %s", newActiveMember)
	evetest.Checkpoint("failover-verified")

	// Verify that bond metrics report a non-zero link failure count
	// for the member that went down.
	t.Eventually(devMetrics, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Bond metrics report link failure for failed member",
		func(metrics *evemetrics.DeviceMetric) bool {
			for _, bm := range metrics.GetBondMetrics() {
				if bm.GetLogicallabel() != "active-backup-bond" {
					continue
				}
				for _, member := range bm.GetMembers() {
					if member.GetLogicallabel() == activeMember &&
						member.GetLinkFailureCount() > 0 {
						return true
					}
				}
			}
			return false
		})))
	evetest.Checkpoint("bond-metrics-verified")

	// Restore the network model (bring the port back up).
	evetest.UpdateNetworkModel(netmodels.TwoMgmtPortsOneBridge)
	evetest.Checkpoint("link-restored")
}

// TestLACPBond verifies that EVE forms a working 802.3ad (LACP) bond with
// the SDN-side LACP peer, negotiates a non-zero partner MAC, gets a DHCP
// lease, reports BondStatus with LACP sub-status (LacpRate, active
// aggregator id, per-member aggregator membership), and that BondMetrics
// includes LACP sub-metrics for every member.
//
// Network model
// -------------
//   - Starts with netmodels.TwoMgmtPortsOneBridge so EVE can onboard via
//     individual ports without needing an LACP-aware peer at boot. After
//     EVE applies the device config (with the bond), the test switches the
//     SDN side to netmodels.TwoMgmtPortsWithLACPBond, where eth0/eth1 are
//     aggregated by an SDN-side LACP bond and LACP negotiation can complete.
//     The "switch to LACP after config" trick avoids the bootstrap
//     chicken-and-egg problem (covered separately by
//     TestBootstrapWithLACPBond).
//
// Device configuration
// --------------------
//   - PhysicalIO eth0 + eth1 (no SystemAdapter on either; both become bond
//     members).
//   - One DHCP NetworkConfig.
//   - BondConfig "lacp-bond" (interface "bond1") aggregating eth0+eth1 in
//     BOND_MODE_802_3AD with LacpRate=FAST and MIIMonitor (interval 100 ms).
//
// Phases
// ------
//   - Apply the device config (bond + members + DHCP NI), then update the
//     network model to TwoMgmtPortsWithLACPBond so the SDN side starts
//     speaking LACP.
//   - Wait for DevicePortStatus to report the bond port with:
//   - an IPv4 address from the SDN subnet,
//   - no error,
//   - BondStatus with mode=802_3AD, MIIMonitor enabled (interval 100,
//     updelay/downdelay zero), ARPMonitor disabled,
//   - LACP sub-status with a non-zero partner MAC (i.e. LACP negotiation
//     succeeded) and LacpRate=FAST,
//   - All members report MiiUp=true and belong to the same active
//     aggregator (no split aggregation).
//   - SSH-side smoke test: `echo lacp-ssh-ok` over SSH proves data-plane
//     reachability via the LACP bond.
//   - DeviceMetric.BondMetrics has an entry for "lacp-bond" with both
//     ethernet0 and ethernet1 in its Members list, and every member has
//     LACP sub-metrics populated.
//
// Hypervisor
// ----------
//   - Hardcoded WithHypervisor=HypervisorKVM in RequireEdgeDevice -- this
//     test lives in TestDeviceConnectivitySuite and does not parameterize
//     the hypervisor.
func TestLACPBond(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    evetest.HypervisorKVM,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	// Start with individual ports on a bridge so that EVE can onboard
	// using standalone interfaces. The SDN-side LACP bond will be
	// configured after EVE applies the bond config.
	// Note that we do this to avoid the bootstrapping challenge,
	// which is for LACP bonds already covered by TestBootstrapWithLACPBond.
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.TwoMgmtPortsOneBridge,
	}
	// LACP requires the provider to forward LACPDUs across the simulated
	// links between EVE and the SDN; skip on providers that cannot.
	requiredCaps := evetest.RequireCapabilities{
		Capabilities: []api.Capability{api.Capability_CAPABILITY_FORWARD_LACP},
	}
	evetest.Setup(requiredDevice, requiredNetModel, requiredCaps)

	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet1",
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	devConfig.AddBond(
		evetest.BondConfig{
			LogicalLabel:  "lacp-bond",
			InterfaceName: "bond1",
			MemberLabels:  []string{"ethernet0", "ethernet1"},
			BondMode:      evecommon.BondMode_BOND_MODE_802_3AD,
			LACPRate:      evecommon.LacpRate_LACP_RATE_FAST,
			MIIMonitor: &eveconfig.MIIMonitor{
				Interval: 100,
			},
			NetworkUUID: dhcpNet,
			Usage:       evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	devMetrics, stopDevMetricsWatch := device.WatchDeviceMetrics()
	defer stopDevMetricsWatch()
	// waitUntilConfirmed=false: after the model switch below, EVE may temporarily
	// lose controller connectivity while the LACP bond negotiates.
	device.ApplyConfig(devConfig, true, false)
	// Give EVE a moment to process the bond config before switching the SDN side.
	time.Sleep(10 * time.Second)
	evetest.Checkpoint("config-applied")

	// Now switch the SDN side to LACP so both ends can negotiate.
	// EVE has already created its LACP bond from the applied config;
	// the SDN side needs a matching LACP bond for negotiation to succeed.
	evetest.UpdateNetworkModel(netmodels.TwoMgmtPortsWithLACPBond)
	evetest.Checkpoint("sdn-lacp-enabled")

	// Wait for device info to report the LACP bond interface with an IP address,
	// no errors, and LACP status.
	timeout := 5 * time.Minute
	var bondIP net.IP
	var bondStatus *eveinfo.BondStatus
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"LACP bond has IP, no errors and reports LACP status",
		func(info *eveinfo.ZInfoDevice) bool {
			port := getDevicePort("lacp-bond", info)
			if port == nil {
				return false
			}
			if port.GetErr() != nil && port.GetErr().GetDescription() != "" {
				return false
			}
			bondIP = getPortIPv4Addr("lacp-bond", info)
			if bondIP == nil {
				return false
			}
			bondStatus = port.GetBondStatus()
			if bondStatus == nil {
				return false
			}
			lacpStatus := bondStatus.GetLacp()
			if lacpStatus == nil {
				return false
			}
			// Ensure LACP negotiation has completed — partner MAC must be
			// a valid non-zero address (not 00:00:00:00:00:00).
			partnerMac, err := net.ParseMAC(lacpStatus.GetPartnerMac())
			if err != nil {
				return false
			}
			// Check not all zeros.
			for _, b := range partnerMac {
				if b != 0 {
					return true
				}
			}
			return false
		})))
	evetest.Checkpoint("lacp-bond-has-ip")
	netSubnet := evetest.IPSubnet("172.20.20.0/24")
	t.Expect(netSubnet.Contains(bondIP)).To(BeTrue())
	t.Expect(bondStatus.GetMode()).To(Equal(evecommon.BondMode_BOND_MODE_802_3AD))
	t.Expect(bondStatus.GetArpMonitor().GetEnabled()).To(BeFalse())
	t.Expect(bondStatus.GetMiiMonitor().GetEnabled()).To(BeTrue())
	t.Expect(bondStatus.GetMiiMonitor().GetPollingInterval()).To(BeEquivalentTo(100))
	t.Expect(bondStatus.GetMiiMonitor().GetUpdelay()).To(BeZero())
	t.Expect(bondStatus.GetMiiMonitor().GetDowndelay()).To(BeZero())
	activeAggID := bondStatus.GetLacp().GetActiveAggregatorId()
	t.Expect(activeAggID).ToNot(BeZero())
	t.Expect(bondStatus.GetLacp().GetLacpRate()).To(Equal(
		evecommon.LacpRate_LACP_RATE_FAST))
	// Verify all members are in the active aggregator (no split aggregation).
	for _, member := range bondStatus.GetMembers() {
		t.Expect(member.GetLogicallabel()).To(BeElementOf("ethernet0", "ethernet1"))
		t.Expect(member.GetMiiUp()).To(BeTrue())
		t.Expect(member.GetLacp().GetAggregatorId()).To(Equal(activeAggID))
	}

	// Verify we can SSH into EVE through the LACP bond.
	var stdout string
	t.Eventually(func() error {
		var stderr string
		var err error
		stdout, stderr, err = device.RunShellScript("echo lacp-ssh-ok", 0, 5*time.Second)
		if err != nil {
			return fmt.Errorf("SSH over LACP bond failed: %s", stderr)
		}
		return nil
	}, time.Minute, 5*time.Second).Should(Succeed())
	t.Expect(stdout).To(ContainSubstring("lacp-ssh-ok"))
	evetest.Checkpoint("ssh-over-lacp-bond-works")

	// Verify that bond metrics are reported with both members and LACP sub-metrics.
	t.Eventually(devMetrics, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Bond metrics report both members with LACP metrics",
		func(metrics *evemetrics.DeviceMetric) bool {
			for _, bm := range metrics.GetBondMetrics() {
				if bm.GetLogicallabel() != "lacp-bond" {
					continue
				}
				var memberLabels []string
				for _, member := range bm.GetMembers() {
					if member.GetLacp() == nil {
						return false
					}
					memberLabels = append(memberLabels, member.GetLogicallabel())
				}
				return generics.EqualSets(memberLabels,
					[]string{"ethernet0", "ethernet1"})
			}
			return false
		})))
	evetest.Checkpoint("lacp-metrics-verified")
}
