// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package hardware_test covers what EVE does with the hardware of the device
// it runs on, exercised by changing that hardware at runtime through the
// hypervisor: hot-plugging USB devices and hubs and passing the devices
// through to an application.
//
// File layout: testsuite_test.go registers the suite, helpers_test.go holds
// the device setup, its configuration, the application factory and the
// predicates shared by the tests, and usb_hotplug_test.go the USB hot-plug
// tests themselves.
package hardware_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestHardwareSuite runs the hardware tests against one shared device. Every
// test declares the HYPERVISOR parameter and states the same device
// requirements through setupHardwareTestDevice, so the framework reuses a
// single VM across the suite.
//
// Subtests
// --------
//   - TestUSBFlashDriveHotplug -- a USB flash drive plugged into the running
//     device through the hypervisor shows up in EVE, is passed through to an
//     application that claims it, and follows unplugging and re-plugging.
//   - TestUSBHubChain -- a flash drive behind four chained hubs is enumerated
//     at its full port path; among five applications claiming it by every
//     prefix of that path and by the path itself, the most specific claim
//     gets the drive and the next one inherits it when that application goes.
func TestHardwareSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestUSBFlashDriveHotplug,
		},
		evetest.TestCase{
			Test: TestUSBHubChain,
		},
	)
}
