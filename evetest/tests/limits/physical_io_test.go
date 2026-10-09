// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package limits_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// physicalIOParamKey selects how many I/O adapters TestManyPhysicalIOAdapters
// adds to the device model.
const physicalIOParamKey = "PHYSICAL_IO_ADAPTERS"

// defaultPhysicalIO is the adapter count at which the adapter list outgrows a
// pubsub message with margin; see the test's description.
const defaultPhysicalIO = 200

// physicalIOPrefix starts the labels of the adapters the test adds.
const physicalIOPrefix = "usb-port-"

// TestManyPhysicalIOAdapters verifies that a device model with many I/O
// adapters is handled without crashing the device: every adapter shows up in
// the assignable adapters the device reports, and the device stays up.
//
// The I/O adapters of the device model (every PCI, USB and serial device the
// controller knows about) travel as one PhysicalIOAdapterList that zedagent
// publishes and domainmgr turns into the AssignableAdapters it publishes.
// Nothing limits their number. Measured on the real types, with USB adapters:
// 150 put the list at 61 KB on the wire, just under the 64 KiB a pubsub
// message may carry, so the default of 200 (81 KB) is where an unfixed
// zedagent exits with "Too large message" while publishing the list -- and
// keeps doing so after every reboot, since the device configuration is
// checkpointed and re-read. Servers with many SR-IOV virtual functions or
// USB ports reach such counts.
//
// Network model: netmodels.SingleEthWithDHCP.
//
// Device config: one DHCP management port, a 5-second metrics interval, and
// PHYSICAL_IO_ADAPTERS USB adapters, dedicated to applications, at USB
// addresses nothing is plugged into.
//
// Phases:
//  1. Apply the base configuration and wait until it is processed.
//  2. Add the adapters, apply, and wait until the device reports all of them
//     as assignable adapters, with the device still reporting metrics
//     afterwards. Stop at once if the device crashes.
//
// Parameters: HYPERVISOR (shared with the suite), PHYSICAL_IO_ADAPTERS
// (default 200).
//
// Suite placement: TestLimitsSuite.
func TestManyPhysicalIOAdapters(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          physicalIOParamKey,
			DefaultValue: defaultPhysicalIO,
			Description: evetest.TestParameterDescription{
				Summary: "Number of I/O adapters added to the device model",
				Default: fmt.Sprint(defaultPhysicalIO),
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	numAdapters := evetest.GetTestParameter[int](physicalIOParamKey)

	device := setupDevice(hypervisor, 0)
	evetest.Checkpoint("setup-done")
	log := evetest.Logger()
	devConfig, _ := applyBaseConfig(device, hypervisor)
	evetest.Checkpoint("base-config-applied")
	crash := device.WatchForCrash()
	defer crash.Stop()

	// Phase 2: the adapters.
	for i := range numAdapters {
		label := fmt.Sprintf("%s%03d", physicalIOPrefix, i)
		devConfig.AddPhysicalIO(evetest.PhysicalIOConfig{
			LogicalLabel:  label,
			PhysicalLabel: label,
			Type:          evecommon.PhyIoType_PhyIoUSB,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
			USBAddress:    fmt.Sprintf("%d:%d", i/8+1, i%8+1),
		})
	}
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("adapters-applied")

	var latest *eveinfo.ZInfoDevice
	awaitWhileAlive(t, device, crash,
		fmt.Sprintf("the device reports %d assignable adapters", numAdapters),
		10*time.Minute, func() bool {
			for drained := false; !drained; {
				select {
				case info, ok := <-devUpdates:
					drained = !ok
					if ok {
						latest = info
					}
				default:
					drained = true
				}
			}
			return countAssignableAdapters(latest, physicalIOPrefix) >= numAdapters
		})
	log.Infof("The device reports %d assignable adapters with the %q prefix",
		countAssignableAdapters(latest, physicalIOPrefix), physicalIOPrefix)
	evetest.Checkpoint("adapters-reported")
}

// countAssignableAdapters counts the assignable adapters in dinfo whose name
// or members start with prefix.
func countAssignableAdapters(dinfo *eveinfo.ZInfoDevice, prefix string) int {
	count := 0
	for _, bundle := range dinfo.GetAssignableAdapters() {
		if strings.HasPrefix(bundle.GetName(), prefix) {
			count++
			continue
		}
		for _, member := range bundle.GetMembers() {
			if strings.HasPrefix(member, prefix) {
				count++
				break
			}
		}
	}
	return count
}
