// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the device info (ZInfoDevice) that EVE reports to the controller.

package telemetry_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestDeviceInfo verifies the ZInfoDevice message EVE publishes to the
// controller: EVE must report the network configuration it actually applied,
// a plausible hardware inventory, and the state of its hardware security
// module.
//
// Since the test owns the device configuration, the reported port is asserted
// exactly rather than by pattern, and the surrounding hardware fields are
// checked in the same message.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+apps port with DHCP. A single
//     port keeps the expected DevicePortStatus unambiguous.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//     Nothing else: this test is about what EVE reports, not about what it
//     runs.
//
// Phases / assertions
// -------------------
//
//  1. setup-done -> config-applied.
//
//  2. port-info-reported: wait until the device info reports the
//     controller-pushed DPC as current and healthy --
//     SystemAdapter.CurrentIndex==0, a single DevicePortStatus keyed
//     "zedagent" (the key identifies the config source; "zedagent" means the
//     controller's config won over bootstrap/last-resort), empty
//     DPC.LastError, and a single port that has an IP address and no error
//     recorded. These health conditions are part of the Eventually predicate
//     rather than assertions after it, so a transient error early in the DPC
//     verification does not flake the test.
//     Then assert the port itself:
//     - Ifname=eth0, Name=ethernet0 (the logical label round-trips),
//     - IsMgmt=true, Up=true,
//     - at least one IP address and one default router from DHCP,
//     - the DPC has a LastSucceeded timestamp, i.e. EVE verified controller
//     connectivity over it.
//
//     Note that DevicePort.Err is never nil: zedagent encodes the port test
//     results into it unconditionally and on success it carries only the
//     LastSucceeded timestamp, so "no error" means an empty Description.
//
//  3. Hardware inventory in the same message is plausible: MachineArch and
//     CpuArch non-empty, Ncpu >= the requested minimum, Memory and Storage
//     non-zero, HostName set, BootTime set and in the past.
//
//  4. HSMStatus matches the TPM parameter: ENABLED when the device was
//     created with an emulated TPM, and anything but ENABLED when it was not.
//
// Test params
// -----------
//   - TPM. Drives both whether the device VM gets an emulated TPM and the
//     expected HSMStatus.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite. No application is deployed, so the hypervisor is
//     hardcoded to KVM like the other non-app suites.
func TestDeviceInfo(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	const minCPUs = 4
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			MinCPUs:           minCPUs,
			WithHypervisor:    evetest.HypervisorKVM,
			WithTPM:           useTPM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	devConfig := singleMgmtPortConfig()
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Phase 2: EVE reports the network configuration it applied.
	timeout := 5 * time.Minute
	var devInfo *eveinfo.ZInfoDevice
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device reports the controller-pushed port configuration as current",
		func(info *eveinfo.ZInfoDevice) bool {
			devInfo = info
			sa := info.GetSystemAdapter()
			if sa == nil || sa.GetCurrentIndex() != 0 || len(sa.GetStatus()) != 1 {
				return false
			}
			dpc := sa.GetStatus()[0]
			if dpc.GetKey() != "zedagent" || dpc.GetLastError() != "" ||
				len(dpc.GetPorts()) != 1 {
				return false
			}
			// Note: DevicePort.Err is never nil - zedagent encodes the port
			// test results into it unconditionally, and on success it carries
			// just the LastSucceeded timestamp. An empty description means
			// neither an error nor a warning was recorded.
			port := dpc.GetPorts()[0]
			return len(port.GetIPAddrs()) > 0 && port.GetErr().GetDescription() == ""
		})))

	dpc := devInfo.GetSystemAdapter().GetStatus()[0]
	t.Expect(dpc.GetLastSucceeded().IsValid()).To(BeTrue())

	port := dpc.GetPorts()[0]
	t.Expect(port.GetIfname()).To(Equal(portIfName))
	t.Expect(port.GetName()).To(Equal(portLogicalLabel))
	t.Expect(port.GetIsMgmt()).To(BeTrue())
	t.Expect(port.GetUp()).To(BeTrue())
	t.Expect(port.GetIPAddrs()).ToNot(BeEmpty())
	t.Expect(port.GetDefaultRouters()).ToNot(BeEmpty())
	evetest.Checkpoint("port-info-reported")

	// Phase 3: the hardware inventory reported alongside it is plausible.
	t.Expect(devInfo.GetMachineArch()).ToNot(BeEmpty())
	t.Expect(devInfo.GetCpuArch()).ToNot(BeEmpty())
	t.Expect(devInfo.GetNcpu()).To(BeNumerically(">=", minCPUs))
	t.Expect(devInfo.GetMemory()).To(BeNumerically(">", 0))
	t.Expect(devInfo.GetStorage()).To(BeNumerically(">", 0))
	t.Expect(devInfo.GetHostName()).ToNot(BeEmpty())
	t.Expect(devInfo.GetBootTime().IsValid()).To(BeTrue())
	t.Expect(devInfo.GetBootTime().AsTime()).To(BeTemporally("<", time.Now()))

	// Phase 4: the reported HSM state matches how the device was created.
	if useTPM {
		t.Expect(devInfo.GetHSMStatus()).To(
			Equal(eveinfo.HwSecurityModuleStatus_ENABLED))
	} else {
		t.Expect(devInfo.GetHSMStatus()).ToNot(
			Equal(eveinfo.HwSecurityModuleStatus_ENABLED))
	}
}
