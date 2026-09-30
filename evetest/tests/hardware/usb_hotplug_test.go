// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
)

const (
	// flashDriveID names the hot-plugged drive towards the hypervisor and is
	// what the guest sees as its USB serial number.
	flashDriveID = "evtest-flash"
	// flashDriveSize is deliberately small: on the proxmox provider the whole
	// image is uploaded to the PVE host.
	flashDriveSize = 16 << 20

	// QEMU's emulated usb-storage device identifies itself with these ids
	// (hw/usb/dev-storage.c).
	qemuUSBVendorID         = 0x46f4
	qemuUSBStorageProductID = 0x0001

	// The guest kernel enumerates a hot-plugged USB device well within a
	// second; the rest is SSH round trips.
	usbEnumerationTimeout  = time.Minute
	usbEnumerationInterval = 2 * time.Second
)

// TestUSBFlashDriveHotplug verifies that a USB flash drive hot-plugged into the
// running device through the hypervisor is enumerated by EVE, disappears again
// when unplugged, and can be plugged in again under the same identity.
//
// The drive is QEMU's emulated usb-storage device backed by a blank scratch
// image on the hypervisor host, attached to the VM's xHCI controller by
// EdgeDevice.AttachUSBStorage. The kernel's view is read from
// /sys/bus/usb/devices (EdgeDevice.ListUSBDevices): EVE's hardware inventory
// (ZInfoHardware) is published once per boot, so it cannot show a device
// plugged in later without a reboot, and the drive is not modeled as an
// adapter, so no other EVE API reports it. The serial number is the drive's
// identity: bus numbers are assigned by the kernel, and the port depends on
// which xHCI port QEMU picked.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the test is not about networking; a single
//     port gives the device controller connectivity and SSH reachability.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), nothing else.
//
// Phases / assertions
// -------------------
//
//  1. setup-done -> config-applied.
//
//  2. flash-drive-attached: AttachUSBStorage, then ListUSBDevices eventually
//     shows a device with the drive's serial number and QEMU's usb-storage
//     vendor and product ids.
//
//  3. flash-drive-detached: DetachUSBStorage, then no device with that serial
//     number is enumerated any more.
//
//  4. flash-drive-reattached: AttachUSBStorage under the same id succeeds and
//     the drive shows up again, which proves that detaching released the
//     device id, the block node and the scratch image. The drive is detached
//     at the end, so the device is clean for the next test.
//
// Test params
// -----------
//   - HYPERVISOR. Not asserted on; declared so that every test in the suite
//     states the same device requirements and the framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestHardwareSuite.
func TestUSBFlashDriveHotplug(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupHardwareTestDevice(hypervisor)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	device.ApplyConfig(singleMgmtPortConfig(), true, false)
	if hypervisor == evetest.HypervisorKubevirt {
		test.Skip("K does not support advanced USB passthrough")
	}
	evetest.Checkpoint("config-applied")

	// Phase 2: plug the drive in.
	device.AttachUSBStorage(flashDriveID, flashDriveSize)
	t.Eventually(device.ListUSBDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("EVE enumerates the flash drive",
			hasUSBDevice(flashDriveID, qemuUSBVendorID, qemuUSBStorageProductID)))
	evetest.Checkpoint("flash-drive-attached")

	// Phase 3: unplug it.
	device.DetachUSBStorage(flashDriveID)
	t.Eventually(device.ListUSBDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("the flash drive is gone from EVE",
			lacksUSBDevice(flashDriveID)))
	evetest.Checkpoint("flash-drive-detached")

	// Phase 4: plug it in again under the same id.
	device.AttachUSBStorage(flashDriveID, flashDriveSize)
	t.Eventually(device.ListUSBDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("EVE enumerates the flash drive again",
			hasUSBDevice(flashDriveID, qemuUSBVendorID, qemuUSBStorageProductID)))
	evetest.Checkpoint("flash-drive-reattached")

	device.DetachUSBStorage(flashDriveID)
}
