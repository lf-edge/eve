// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	evecommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// devName is the single device every test in this package drives.
const devName = "edge-dev"

// deviceParams are the axes every test in this package resolves before Setup.
type deviceParams struct {
	initialVersion    string
	initialRepo       string
	initialHypervisor evetest.Hypervisor
	targetVersion     string
	targetHypervisor  evetest.Hypervisor
	withTPM           bool
	ramMiB            uint32
	cpus              uint8
	diskMiB           uint32
}

// defineSharedParameters declares the parameters every test in this package
// understands, for a test that starts the device on a release. Tests add their
// own on top.
func defineSharedParameters(extra ...evetest.TestParameterDefinition) {
	defineParameters(evetest.TestParameterDefinition{
		Key:          initialEVEVersionParamKey,
		DefaultValue: defaultInitialEVEVersion,
		Description: evetest.TestParameterDescription{
			Summary: "Released EVE version the device boots before the conversion",
			Default: defaultInitialEVEVersion,
		},
	}, extra...)
}

// defineCrossFlavorParameters declares them for a test that hops between the
// two flavors of one version, which has to be the build under test: the
// relaxation that lets a flavor switch through is in no release, and no release
// publishes both flavors.
func defineCrossFlavorParameters() {
	defineParameters(evetest.TestParameterDefinition{
		Key:          initialEVEVersionParamKey,
		DefaultValue: "",
		Description: evetest.TestParameterDescription{
			Summary: "EVE version the device boots before the flavor switch",
			Default: "\"\" (the build under test)",
		},
	}, altParameterDefinitions()...)
}

// defineParameters declares the shared set around the given initial-version
// axis, which is the one axis the two entry points above differ on.
func defineParameters(initialVersion evetest.TestParameterDefinition,
	extra ...evetest.TestParameterDefinition) {
	shared := []evetest.TestParameterDefinition{
		evetest.EVEVersionParameter(),
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
		evetest.DiskSizeMiBParameter(),
		evetest.RAMSizeMiBParameter(),
		evetest.CPUsParameter(),
		initialVersion,
		{
			Key:          initialEVERepoParamKey,
			DefaultValue: "",
			Description: evetest.TestParameterDescription{
				Summary: "Repository the initial EVE version is pulled from",
				Default: "\"\" (the repo under test)",
			},
		},
		{
			Key:          initialHypervisorParamKey,
			DefaultValue: evetest.HypervisorKVM,
			Description: evetest.TestParameterDescription{
				Summary:       "Hypervisor flavor the device starts on",
				Default:       "kvm",
				AllowedValues: "kvm|xen|kubevirt",
			},
		},
	}
	evetest.DefineTestParameters(append(shared, extra...)...)
}

// resolveDeviceParams reads the shared parameters and applies this package's
// defaults, which are eden's: 4 vCPUs, 8 GiB of RAM, a 64 GiB boot disk.
func resolveDeviceParams(t Gomega) deviceParams {
	p := deviceParams{
		initialVersion:    evetest.GetTestParameter[string](initialEVEVersionParamKey),
		initialRepo:       evetest.GetTestParameter[string](initialEVERepoParamKey),
		initialHypervisor: evetest.GetTestParameter[evetest.Hypervisor](initialHypervisorParamKey),
		targetVersion:     evetest.GetEVEVersionParameterValue(),
		targetHypervisor:  evetest.GetHypervisorParameterValue(),
		withTPM:           evetest.GetTPMParameterValue(),
		ramMiB:            evetest.GetRAMSizeMiBParameterValue(),
		cpus:              evetest.GetCPUsParameterValue(),
		diskMiB:           evetest.GetDiskSizeMiBParameterValue(),
	}
	if p.ramMiB == 0 {
		p.ramMiB = deviceRAMMiB
	}
	if p.cpus == 0 {
		p.cpus = deviceCPUs
	}
	if p.diskMiB == 0 {
		p.diskMiB = bootDiskMiB
	}
	return p
}

// requirePinnedInitialVersion asserts the test was given a release to start
// from. Tests that convert a released image need one; a test that converts the
// build under test deliberately leaves it unset.
func requirePinnedInitialVersion(t Gomega, p deviceParams) {
	t.Expect(p.initialVersion).NotTo(BeEmpty(),
		"this test needs a released EVE version to start from (%s)",
		initialEVEVersionParamKey)
}

// setupDevice brings up one device on the initial released image and returns
// it, with a management network applied.
//
// filesystem selects /persist's format, and extraDisks attaches additional
// blank disks; both default to the plain single-ext4-disk case a caller that
// passes their zero values gets.
func setupDevice(t Gomega, p deviceParams, filesystem evetest.Filesystem,
	extraDisks []uint64, reusePolicy evetest.ExistingEdgeDeviceReusePolicy,
	extraRequirements ...evetest.Requirement) *evetest.EdgeDevice {

	requirements := []evetest.Requirement{
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithEVEVersion:    p.initialVersion,
			WithEVERepo:       p.initialRepo,
			WithHypervisor:    p.initialHypervisor,
			WithTPM:           p.withTPM,
			WithFilesystem:    filesystem,
			MinDiskSizeInMiB:  p.diskMiB,
			MinRAMInMiB:       p.ramMiB,
			MinCPUs:           p.cpus,
			ExtraDisks:        extraDisks,
			DeviceReusePolicy: reusePolicy,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	}
	evetest.Setup(append(requirements, extraRequirements...)...)
	return evetest.GetEdgeDevice(devName)
}

// applyMgmtNetwork gives the device its management port, which everything else
// depends on.
func applyMgmtNetwork(device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig) {
	networkUUID := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "eth0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   networkUUID,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, false, false)
}

// growBootDiskTail powers the device down, enlarges its boot disk so there is
// unallocated space past the last partition, and brings it back.
//
// The tail cannot be arranged when the device is created: EVE's image generator
// sizes the partitions to fill whatever disk it is handed, so the space has to
// be added once the layout is already written.
func growBootDiskTail(t Gomega, device *evetest.EdgeDevice, totalMiB uint32) {
	evetest.Logger().Infof("growing the boot disk to %d MiB to leave a free tail", totalMiB)
	device.SyncDisks()
	device.PowerOff()
	device.GrowDisk(uint64(totalMiB) << 20)
	// PowerOn does not wait here: nodeagent does not reliably republish
	// LastRebootTime after an external power cycle, which is the signal that
	// wait watches for, so it can time out on a device that came back fine.
	// Waiting for the device to answer is the signal that does hold.
	device.PowerOn(false)
	waitDeviceResponds(t, device)
}

// waitDeviceResponds blocks until EVE answers a trivial command, which is how a
// device that was power-cycled rather than rebooted is confirmed back.
func waitDeviceResponds(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "echo device-is-up")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("device-is-up"))
	}, 15*time.Minute, 15*time.Second).Should(Succeed())
}
