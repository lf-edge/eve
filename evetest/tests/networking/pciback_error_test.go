// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// This suite verifies that device-model inconsistencies in the assignable-I/O
// (PhysicalIO) part of the config are reported back to the controller on the
// relevant ZioBundle (ZInfoDevice.assignableAdapters), with the right severity.
// Hard errors (the device is unusable as modeled) are reported as ERROR;
// adjustments EVE works around are reported as WARNING.

const pcibackErrDevName = "edge-dev"

// pcibackReportTimeout bounds how long we wait for EVE to process a config
// change and republish device info with the expected ZioBundle error.
const pcibackReportTimeout = 3 * time.Minute

// netConfigWithEth1 builds a config with two management ports on the
// TwoMgmtPorts model. eth0 is the preferred controller uplink (always correct);
// eth1's model interface name and PCI address are supplied so tests can make
// them disagree with reality. Tests add inconsistent PhysicalIO entries on top.
func netConfigWithEth1(devName, eth1IfName, eth1PCI string) *evetest.EdgeDeviceConfig {
	cfg := evetest.NewEdgeDeviceConfig(devName)
	eth0Net := cfg.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	cfg.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		Cost:          0,
	})
	eth1Net := cfg.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	cfg.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: eth1IfName,
		PCIAddress:    eth1PCI,
		NetworkUUID:   eth1Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		Cost:          10,
	})
	return cfg
}

// newBaseNetConfig builds the correct two-management-port config.
func newBaseNetConfig(devName string) *evetest.EdgeDeviceConfig {
	return netConfigWithEth1(devName, "eth1", "")
}

// portPciLong reads domainmgr's resolved PCI address for the given physical
// label from the on-device AssignableAdapters status, retrying until present.
func portPciLong(t *WithT, device *evetest.EdgeDevice, phylabel string) string {
	var pci string
	t.Eventually(func() string {
		stdout, _, err := device.RunShellScript(
			"eve exec pillar cat /run/domainmgr/AssignableAdapters/global.json 2>/dev/null",
			60*time.Second, 0)
		if err != nil {
			return ""
		}
		i := strings.IndexByte(stdout, '{')
		if i < 0 {
			return ""
		}
		var aa struct {
			IoBundleList []struct {
				Phylabel string
				PciLong  string
			}
		}
		if json.Unmarshal([]byte(stdout[i:]), &aa) != nil {
			return ""
		}
		for _, b := range aa.IoBundleList {
			if b.Phylabel == phylabel {
				pci = b.PciLong
				return pci
			}
		}
		return ""
	}, 2*time.Minute, 5*time.Second).ShouldNot(BeEmpty(),
		"domainmgr should resolve a PCI address for %s", phylabel)
	return pci
}

// assignableAdapterErr returns the reported error of the ZioBundle whose members
// include memberLabel, or nil if the bundle is absent or has no error.
func assignableAdapterErr(info *eveinfo.ZInfoDevice, memberLabel string) *eveinfo.ErrorInfo {
	for _, z := range info.GetAssignableAdapters() {
		for _, m := range z.GetMembers() {
			if m == memberLabel {
				return z.GetErr()
			}
		}
	}
	return nil
}

// TestReportMissingDevice: a PhysicalIO whose PCI address does not exist on the
// device must be reported as a hard error on its ZioBundle.
func TestReportMissingDevice(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)

	cfg := newBaseNetConfig(pcibackErrDevName)
	cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:  "phantom-missing",
		PhysicalLabel: "phantom-missing",
		Type:          evecommon.PhyIoType_PhyIoOther,
		PCIAddress:    "0000:99:00.0", // no such device
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(cfg, true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"phantom device with a non-existent PCI address is reported as an error",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "phantom-missing")
			return e != nil &&
				e.GetSeverity() == eveinfo.Severity_SEVERITY_ERROR &&
				strings.Contains(e.GetDescription(), "does not exist")
		})))
}

// TestReportParentAssigngrp: a PhysicalIO whose parent assignment group is its
// own assignment group is an invalid dependency and must be reported as an error.
func TestReportParentAssigngrp(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)

	cfg := newBaseNetConfig(pcibackErrDevName)
	cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:          "phantom-parent",
		PhysicalLabel:         "phantom-parent",
		Type:                  evecommon.PhyIoType_PhyIoOther,
		AssignmentGroup:       "grpx",
		ParentAssignmentGroup: "grpx", // own parent -> invalid
		Usage:                 evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(cfg, true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"self-parent assignment group is reported as an error",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "phantom-parent")
			return e != nil &&
				e.GetSeverity() == eveinfo.Severity_SEVERITY_ERROR &&
				strings.Contains(e.GetDescription(), "own parent")
		})))
}

// TestReportCycleDetected: a multi-node parentassigngrp cycle (grpa's parent is
// grpb and grpb's parent is grpa) must be reported as a hard error on the
// members of the affected groups. This is distinct from a self-parent
// (TestReportParentAssigngrp): it exercises the cycle-detection walk that
// follows parent links until a group repeats, not the single-node own-parent
// check.
func TestReportCycleDetected(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)

	cfg := newBaseNetConfig(pcibackErrDevName)
	cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:          "cycle-a",
		PhysicalLabel:         "cycle-a",
		Type:                  evecommon.PhyIoType_PhyIoOther,
		AssignmentGroup:       "grpa",
		ParentAssignmentGroup: "grpb",
		Usage:                 evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})
	cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:          "cycle-b",
		PhysicalLabel:         "cycle-b",
		Type:                  evecommon.PhyIoType_PhyIoOther,
		AssignmentGroup:       "grpb",
		ParentAssignmentGroup: "grpa",
		Usage:                 evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(cfg, true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"parentassigngrp cycle is reported as an error",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "cycle-a")
			return e != nil &&
				e.GetSeverity() == eveinfo.Severity_SEVERITY_ERROR &&
				strings.Contains(e.GetDescription(), "Cycle detected")
		})))
}

// TestReportCollision: two devices in the same assignment group that collide on
// their USB address must be reported as an error, reported once for the group.
func TestReportCollision(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)

	cfg := newBaseNetConfig(pcibackErrDevName)
	for _, ll := range []string{"phantom-usb-a", "phantom-usb-b"} {
		cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
			LogicalLabel:    ll,
			PhysicalLabel:   ll,
			Type:            evecommon.PhyIoType_PhyIoUSB,
			AssignmentGroup: "usbcollide",
			USBAddress:      "1:1", // same address -> collision
			Usage:           evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
		})
	}

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(cfg, true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"USB collision is reported once as an error for the group",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "phantom-usb-a")
			return e != nil &&
				e.GetSeverity() == eveinfo.Severity_SEVERITY_ERROR &&
				strings.Count(e.GetDescription(), "ioBundle collision") == 1
		})))
}

// TestReportIfnameMismatch: eth1's model interface name disagrees with the
// kernel while its PCI address is correct. domainmgr must keep the in-use port
// in the host (matched by PCI) and report the adjustment as a warning, not an
// error. eth0 stays correct so the device remains reachable throughout.
func TestReportIfnameMismatch(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	// Phase 1: correct config; let EVE resolve eth1's real PCI address.
	device.ApplyConfig(newBaseNetConfig(pcibackErrDevName), true, true)
	pci := portPciLong(t, device, "eth1")

	// Phase 2: give eth1 a bogus model interface name but the real PCI address.
	device.ApplyConfig(
		netConfigWithEth1(pcibackErrDevName, "enpMockEth1", pci), true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"ethernet1 kept in host and reported as a warning despite the ifname mismatch",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "ethernet1")
			return e != nil && e.GetSeverity() == eveinfo.Severity_SEVERITY_WARNING
		})))
}

// TestReportAssignmentGroupConflict: a device declared at an in-use port's PCI
// but in a different assignment group is a contradictory model (the two cannot
// be assigned independently) and must be reported as an error.
func TestReportAssignmentGroupConflict(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	device.ApplyConfig(newBaseNetConfig(pcibackErrDevName), true, true)
	pci := portPciLong(t, device, "eth1")

	cfg := newBaseNetConfig(pcibackErrDevName)
	cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:    "phantom-audio",
		PhysicalLabel:   "phantom-audio",
		Type:            evecommon.PhyIoType_PhyIoAudio,
		AssignmentGroup: "phantomgrp", // different group than eth1's port
		PCIAddress:      pci,          // same PCI controller as eth1
		Usage:           evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})
	device.ApplyConfig(cfg, true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"a device sharing an in-use port's PCI in another group is an error",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "phantom-audio")
			return e != nil &&
				e.GetSeverity() == eveinfo.Severity_SEVERITY_ERROR &&
				strings.Contains(e.GetDescription(), "same PCI controller")
		})))
}

// TestReportWarningPlusError: when a bundle carries both an advisory warning
// (ifname matched by PCI) and a hard error (assignment-group conflict), the
// reported severity is ERROR — the hard error dominates.
func TestReportWarningPlusError(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	device.ApplyConfig(newBaseNetConfig(pcibackErrDevName), true, true)
	pci := portPciLong(t, device, "eth1")

	// eth1 gets a wrong ifname (warning) and a phantom shares its PCI in another
	// group (hard error) -- both land on eth1's bundle.
	cfg := netConfigWithEth1(pcibackErrDevName, "enpMockEth1", pci)
	cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:    "phantom-audio",
		PhysicalLabel:   "phantom-audio",
		Type:            evecommon.PhyIoType_PhyIoAudio,
		AssignmentGroup: "phantomgrp",
		PCIAddress:      pci,
		Usage:           evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})
	device.ApplyConfig(cfg, true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"a bundle with a warning and a hard error is reported as an error",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "ethernet1")
			return e != nil &&
				e.GetSeverity() == eveinfo.Severity_SEVERITY_ERROR &&
				strings.Contains(e.GetDescription(), "same PCI controller")
		})))
}

// TestReportClearsOnFix: an inconsistency reported to the controller is cleared
// from the report once the model is corrected (verifies the per-source reconcile
// end to end). It uses a self-parent assignment group, which is reversible in
// place: the offending bundle stays in the model and only its parent field
// changes, so a genuine reconcile-clear is observed. An ifname mismatch is
// unsuitable here because its remediation renames the kernel interface, a side
// effect that reverting the model cannot undo.
func TestReportClearsOnFix(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.TwoMgmtPorts},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	// phantomParentConfig adds a dedicated PhysicalIO whose parent assignment
	// group is parentGroup: "grpx" (its own group) is invalid; "" is valid.
	phantomParentConfig := func(parentGroup string) *evetest.EdgeDeviceConfig {
		cfg := newBaseNetConfig(pcibackErrDevName)
		cfg.AddPhysicalIO(evetest.PhysicalIOConfig{
			LogicalLabel:          "phantom-parent",
			PhysicalLabel:         "phantom-parent",
			Type:                  evecommon.PhyIoType_PhyIoOther,
			AssignmentGroup:       "grpx",
			ParentAssignmentGroup: parentGroup,
			Usage:                 evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
		})
		return cfg
	}

	// Break it: self-parent -> error reported.
	device.ApplyConfig(phantomParentConfig("grpx"), true, true)
	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"self-parent assignment group is reported as an error",
		func(info *eveinfo.ZInfoDevice) bool {
			e := assignableAdapterErr(info, "phantom-parent")
			return e != nil &&
				e.GetSeverity() == eveinfo.Severity_SEVERITY_ERROR &&
				strings.Contains(e.GetDescription(), "own parent")
		})))

	// Fix it: valid parent -> the error must clear while the bundle remains.
	device.ApplyConfig(phantomParentConfig(""), true, false)
	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"phantom-parent error clears once the model is corrected",
		func(info *eveinfo.ZInfoDevice) bool {
			return assignableAdapterErr(info, "phantom-parent") == nil
		})))
}

// manyPortsConfig builds a config with four management DHCP ports on the
// ManyDNSServers model. eth0 (and eth3) are always correct; eth1 and eth2 take
// the supplied interface name and PCI address so a test can make them disagree
// with reality.
func manyPortsConfig(devName, eth1IfName, eth1PCI, eth2IfName, eth2PCI string) *evetest.EdgeDeviceConfig {
	cfg := evetest.NewEdgeDeviceConfig(devName)
	ports := []struct {
		ll, phy, ifn, pci string
		cost              uint8
	}{
		{"ethernet0", "eth0", "eth0", "", 0},
		{"ethernet1", "eth1", eth1IfName, eth1PCI, 10},
		{"ethernet2", "eth2", eth2IfName, eth2PCI, 20},
		{"ethernet3", "eth3", "eth3", "", 30},
	}
	for _, p := range ports {
		net := cfg.AddNetwork(evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
		cfg.AddNetworkAdapter(evetest.NetworkAdapterConfig{
			LogicalLabel:  p.ll,
			PhysicalLabel: p.phy,
			InterfaceName: p.ifn,
			PCIAddress:    p.pci,
			NetworkUUID:   net,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			Cost:          p.cost,
		})
	}
	return cfg
}

// TestReportWarningsOnly: two in-use ports each have a model interface-name
// mismatch (and nothing has a hard error). Both are kept in the host and each
// is reported as a warning; a bundle that carries only warnings must never be
// reported as an error. Uses a four-port model so eth0 stays a healthy uplink.
// Runs last in TestPcibackErrorSuite since it needs a different network model
// than the other (TwoMgmtPorts) scenarios.
func TestReportWarningsOnly(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              pcibackErrDevName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.ManyDNSServers},
	)
	device := evetest.GetEdgeDevice(pcibackErrDevName)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	// Phase 1: correct config; resolve eth1 and eth2 real PCI addresses.
	device.ApplyConfig(manyPortsConfig(pcibackErrDevName, "eth1", "", "eth2", ""), true, true)
	pci1 := portPciLong(t, device, "eth1")
	pci2 := portPciLong(t, device, "eth2")

	// Phase 2: eth1 and eth2 both get a bogus model interface name but the real PCI.
	device.ApplyConfig(
		manyPortsConfig(pcibackErrDevName, "enpMockEth1", pci1, "enpMockEth2", pci2),
		true, false)

	t.Eventually(devUpdates, pcibackReportTimeout).Should(Receive(matchers.SatisfyPredicate(
		"both mismatched ports are kept in host and reported as warnings only",
		func(info *eveinfo.ZInfoDevice) bool {
			e1 := assignableAdapterErr(info, "ethernet1")
			e2 := assignableAdapterErr(info, "ethernet2")
			return e1 != nil && e1.GetSeverity() == eveinfo.Severity_SEVERITY_WARNING &&
				e2 != nil && e2.GetSeverity() == eveinfo.Severity_SEVERITY_WARNING
		})))
}
