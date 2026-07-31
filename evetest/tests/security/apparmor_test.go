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
)

// TestAppArmorEnabled verifies that EVE's kernel has AppArmor compiled in
// and enabled, by reading the kernel's own status flag directly over the
// device's management SSH.
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

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithTPM:           true,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	out, _, err := device.RunShellScript(
		"cat /sys/module/apparmor/parameters/enabled", 20*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSpace(out)).To(Equal("Y"), "AppArmor is not enabled")
}
