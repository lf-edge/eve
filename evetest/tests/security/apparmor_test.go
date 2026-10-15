// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestAppArmorEnabled verifies that EVE's kernel has AppArmor compiled in
// and enabled, by reading the kernel's own status flag directly over the
// device's management SSH.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- not needed by the check itself, but the
//     network model is compared before device requirements are, so declaring the
//     same one as the rest of the suite is what keeps the SDN and EVE VMs from
//     being rebuilt after this test.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestAppArmorEnabled(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithTPM:           true,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	out, _, err := device.RunShellScript(
		"cat /sys/module/apparmor/parameters/enabled", 20*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSpace(out)).To(Equal("Y"), "AppArmor is not enabled")
}
