// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
)

const (
	// flashDriveID names the hot-plugged drive towards the hypervisor and is
	// what the guests see as its USB serial number.
	flashDriveID = "evtest-flash"
	// flashDriveSize is deliberately small: on the proxmox provider the whole
	// image is uploaded to the PVE host.
	flashDriveSize = 16 << 20

	// A kernel enumerates a hot-plugged USB device well within a second;
	// the rest is usbmanager reacting to the uevent and SSH round trips.
	usbEnumerationTimeout  = time.Minute
	usbEnumerationInterval = 2 * time.Second
)

// TestUSBFlashDriveHotplug verifies that a USB flash drive hot-plugged into the
// running device through the hypervisor is enumerated by EVE, is passed
// through to an application that claims it in the device model by its bus and
// port, follows unplugging and re-plugging while that application runs, and
// is passed through as well when claimed by a bus-wide usbaddr wildcard.
//
// The drive is QEMU's emulated usb-storage device backed by a blank scratch
// image on the hypervisor host, attached to the EVE VM's xHCI controller by
// EdgeDevice.AttachUSBStorage. Kernels' views are read from
// /sys/bus/usb/devices, on EVE (EdgeDevice.ListUSBDevices) and inside the
// application (EdgeDevice.ListUSBDevicesInsideApp): EVE's hardware inventory
// (ZInfoHardware) is published once per boot, so it cannot show a device
// plugged in later without a reboot. The serial number is the drive's
// identity: bus numbers are assigned by the kernel, and the port depends on
// which xHCI port QEMU picked. The passthrough itself is asserted twice: on
// the EVE API, where the assignable adapter is reported as used by the app,
// and inside the app, where a device with the drive's serial number appears.
//
// USB passthrough is done by usbmanager, which attaches a matching device to
// the app's QEMU domain over QMP whenever the device or the domain appears,
// so the test also covers the hot-plug into an already running domain. It
// runs under KVM only, where usbmanager runs.
//
// The apps come from the usbFlashApps factory (helpers_test.go): start claims
// the drive under a label by a usbaddr and deploys an app with that adapter,
// stop takes the app and its model entry down again in the order the device
// needs.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the test is not about networking; a single
//     port gives the device controller connectivity, SSH reachability and the
//     uplink of the local network instance the apps hang off.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - From phase 3: a local network instance on eth0, a PhysicalIO of type USB
//     device, "usb-flash", claiming the drive by its exact "bus:port" usbaddr
//     in an assignment group of its own, and the ubuntu test container as an
//     HVM app with a VIF on the network instance (sshd port-forwarded) and
//     "usb-flash" as directly assigned adapter.
//   - Phase 7 replaces the entry and the app by "usb-flash-wildcard", claiming
//     the drive's bus with a "bus:*" usbaddr, and an app assigned that.
//
// Phases / assertions
// -------------------
//
//  1. setup-done -> config-applied.
//
//  2. flash-drive-attached: AttachUSBStorage, then WaitForUSBDevice returns
//     the device enumerated with the drive's serial number. Its bus and port
//     decide the usbaddr claimed.
//
//  3. app-running: the model entry and the app are applied; the app reaches
//     RUNNING and answers over SSH, and ZInfoDevice reports "usb-flash" as an
//     assignable adapter without error and used by the app.
//
//  4. flash-drive-passed-through: inside the app, a device with the drive's
//     serial number is enumerated.
//
//  5. flash-drive-detached: DetachUSBStorage; the drive disappears from the
//     app and from EVE.
//
//  6. flash-drive-reattached: AttachUSBStorage under the same id; EVE
//     enumerates the drive at the same bus and port again (the helper plugs a
//     re-plugged drive into the port it left) and it is enumerated inside the
//     running app again, i.e. usbmanager hot-plugged it into the live domain.
//
//  7. flash-drive-wildcard-passed-through: the drive is detached and the app
//     stopped; a second app claims the drive's whole bus with a "bus:*"
//     usbaddr wildcard under another label, and the drive plugged in again is
//     enumerated inside that app. Needs an EVE with usbaddr wildcard support.
//     The drive is detached and the app stopped at the end, so the device is
//     clean for the next test.
//
// Test params
// -----------
//   - HYPERVISOR. The test skips unless it is KVM; declared so that every
//     test in the suite states the same device requirements.
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
	if hypervisor != evetest.HypervisorKVM {
		evetestT.Skipf("HYPERVISOR is %s: USB passthrough to applications is done by "+
			"usbmanager, which runs under KVM only", hypervisor)
	}

	// Set up the test harness and specify the test prerequisites.
	device := setupHardwareTestDevice(hypervisor)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	devConfig := singleMgmtPortConfig()
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("config-applied")

	driveEnumerated := hasUSBDevice(flashDriveID)

	// Phase 2: plug the drive in; EVE enumerates it.
	device.AttachUSBStorage(flashDriveID, flashDriveSize)
	drive := device.WaitForUSBDevice(t, flashDriveID, usbEnumerationTimeout, usbEnumerationInterval)
	evetest.Checkpoint("flash-drive-attached")

	usbAddr := fmt.Sprintf("%d:%s", drive.Bus, drive.Port)
	evetest.Logger().Infof("Flash drive enumerated as %s, usbaddr %q", drive, usbAddr)

	// Phase 3: deploy the app with the drive claimed by its exact address.
	apps := newUSBFlashApps(t, device, devConfig)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	app := apps.start(usbFlashLabel, usbAddr)
	t.Eventually(devUpdates, devInfoTimeout).Should(Receive(matchers.SatisfyPredicate(
		"the flash drive is reported as used by the app",
		adapterUsedBy(usbFlashLabel, app.uuid))))
	evetest.Checkpoint("app-running")

	// Phase 4: the drive is passed through to the app.
	t.Eventually(app.usbDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("the app enumerates the flash drive", driveEnumerated))
	evetest.Checkpoint("flash-drive-passed-through")

	// Phase 5: unplug it; it leaves the app and EVE.
	device.DetachUSBStorage(flashDriveID)
	t.Eventually(app.usbDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("the flash drive is gone from the app",
			lacksUSBDevice(flashDriveID)))
	t.Eventually(device.ListUSBDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("the flash drive is gone from EVE",
			lacksUSBDevice(flashDriveID)))
	evetest.Checkpoint("flash-drive-detached")

	// Phase 6: plug it in again, into the same port; EVE enumerates it there
	// and usbmanager hot-plugs it into the running app.
	device.AttachUSBStorage(flashDriveID, flashDriveSize)
	replugged := device.WaitForUSBDevice(t, flashDriveID, usbEnumerationTimeout, usbEnumerationInterval)
	t.Expect(fmt.Sprintf("%d:%s", replugged.Bus, replugged.Port)).To(Equal(usbAddr),
		"the re-plugged drive is back in the port it left")
	t.Eventually(app.usbDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("the app enumerates the flash drive again", driveEnumerated))
	evetest.Checkpoint("flash-drive-reattached")

	// Phase 7: claim the drive by a bus-wide wildcard instead.
	device.DetachUSBStorage(flashDriveID)
	app.stop()
	appWildcard := apps.start(usbFlashWildcardLabel, fmt.Sprintf("%d:*", drive.Bus))
	device.AttachUSBStorage(flashDriveID, flashDriveSize)
	t.Eventually(appWildcard.usbDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
		matchers.SatisfyPredicate("the app enumerates the flash drive via the wildcard",
			driveEnumerated))
	evetest.Checkpoint("flash-drive-wildcard-passed-through")

	// Leave the device as found: no drive, no app, no model entry for it.
	device.DetachUSBStorage(flashDriveID)
	appWildcard.stop()
}

const (
	// hubChainLength is how many hubs are plugged into each other; the drive
	// below the last one has a port path of hubChainLength+1 components. USB
	// allows five hubs between the root hub and a device.
	hubChainLength = 4
	// chainedDriveID names the drive behind the hubs towards the hypervisor
	// and is its USB serial number.
	chainedDriveID = "evtest-chained"
)

// TestUSBHubChain verifies that a USB flash drive plugged in behind a chain of
// four hubs is enumerated by EVE at its full port path and that, among
// applications claiming it by every prefix of that path, usbmanager passes it
// through to the one with the most specific claim and hands it down to the
// next one when that application goes away.
//
// The hubs are QEMU's emulated usb-hub, plugged into each other through the
// hypervisor by EdgeDevice.AttachUSBHub; the drive is the usb-storage device
// of TestUSBFlashDriveHotplug, plugged into the last hub by
// EdgeDevice.AttachUSBStorageBehind. EVE's kernel reports the drive at the
// port path the framework plugged it into, "1.1.1.1.1" when the controller's
// first port is free, so the paths the device model claims can be predicted
// from the plugging. A hub cannot be passed through, and the devices behind
// one enumerate below its port, which is what the usbaddr wildcard exists
// for: "bus:1.*" claims everything below the outermost hub, "bus:1.1.1.1.*"
// everything below the innermost one. usbmanager ranks an exact port claim
// above any wildcard and a longer wildcard prefix above a shorter one, so
// with five applications claiming the drive by "bus:1.*", "bus:1.1.*",
// "bus:1.1.1.*", "bus:1.1.1.1.*" and its exact "bus:1.1.1.1.1", the drive
// belongs to the exact claim, and to the longest remaining prefix once that
// application is gone.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- as in TestUSBFlashDriveHotplug.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - From phase 3: a local network instance and, one by one, five PhysicalIO
//     entries of type USB device named after the port path they claim,
//     "usb-claim-1.*" to "usb-claim-1.1.1.1.1", and for each entry the ubuntu
//     test container as an HVM app with that adapter (see usbFlashApps).
//     Phase 4 removes them again, "usb-claim-1.1.1.1.1" first.
//
// Phases / assertions
// -------------------
//
//  1. setup-done -> config-applied.
//
//  2. hub-chain-attached: four hubs are plugged into each other and the drive
//     into the last one. EVE enumerates the drive at the port path the
//     framework plugged it into, five components deep, and a hub with QEMU's
//     hub ids at each of the four prefixes of that path, all on one bus.
//
//  3. flash-drive-with-exact-claim: the five apps are deployed in the order
//     above, each claim outranking the one before. After each deployment the
//     new app enumerates the drive and the previous holder no longer does.
//     With all five running, ZInfoDevice reports every entry as used by its
//     app.
//
//  4. flash-drive-handed-down: the apps are stopped from the exact claim
//     downwards; after each stop the app with the next shorter prefix
//     enumerates the drive. The drive and then the hubs, innermost first, are
//     detached at the end, so the device is clean for the next test.
//
// Test params
// -----------
//   - HYPERVISOR. The test skips unless it is KVM; declared so that every
//     test in the suite states the same device requirements.
//
// Suite placement
// ---------------
//   - TestHardwareSuite.
func TestUSBHubChain(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor != evetest.HypervisorKVM {
		evetestT.Skipf("HYPERVISOR is %s: USB passthrough to applications is done by "+
			"usbmanager, which runs under KVM only", hypervisor)
	}

	// Set up the test harness and specify the test prerequisites.
	device := setupHardwareTestDevice(hypervisor)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	devConfig := singleMgmtPortConfig()
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("config-applied")

	// Phase 2: plug the hubs into each other and the drive into the last one;
	// EVE enumerates the whole chain.
	hubIDs := make([]string, hubChainLength)
	hubPaths := make([]string, hubChainLength)
	parentHub := ""
	for i := range hubIDs {
		hubIDs[i] = fmt.Sprintf("evtest-hub%d", i+1)
		hubPaths[i] = device.AttachUSBHub(hubIDs[i], parentHub)
		parentHub = hubIDs[i]
	}
	drivePath := device.AttachUSBStorageBehind(parentHub, chainedDriveID, flashDriveSize)
	drive := device.WaitForUSBDevice(t, chainedDriveID, usbEnumerationTimeout, usbEnumerationInterval)
	t.Expect(drive.Port).To(Equal(drivePath), "the drive's port path as EVE enumerates it")
	t.Expect(device.ListUSBDevices()).To(matchers.SatisfyPredicate(
		"EVE enumerates a hub at every prefix of the drive's port path",
		hasUSBDevicesAt(drive.Bus, hubPaths, evetest.USBHubVendorID, evetest.USBHubProductID)))
	evetest.Checkpoint("hub-chain-attached")

	// Phase 3: five apps claim the drive, by every prefix of its port path and
	// by the path itself; each new claim outranks the one before and takes the
	// drive away from the previous holder. An app is labelled by its claim.
	claims := make([]string, 0, hubChainLength+1)
	for _, hubPath := range hubPaths {
		claims = append(claims, hubPath+".*")
	}
	claims = append(claims, drivePath)
	apps := newUSBFlashApps(t, device, devConfig)
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	holders := make([]*usbFlashApp, 0, len(claims))
	for i, claim := range claims {
		app := apps.start(usbClaimLabelPrefix+claim, fmt.Sprintf("%d:%s", drive.Bus, claim))
		t.Eventually(app.usbDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
			matchers.SatisfyPredicate("the app claiming "+claim+" enumerates the drive",
				hasUSBDevice(chainedDriveID)))
		if i > 0 {
			t.Eventually(holders[i-1].usbDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
				matchers.SatisfyPredicate("the app claiming "+claims[i-1]+" lost the drive",
					lacksUSBDevice(chainedDriveID)))
		}
		holders = append(holders, app)
	}
	t.Eventually(devUpdates, devInfoTimeout).Should(Receive(matchers.SatisfyPredicate(
		"every entry is reported as used by its app", adaptersUsedBy(holders))))
	evetest.Checkpoint("flash-drive-with-exact-claim")

	// Phase 4: stopping the holder hands the drive to the next lower claim.
	for i := len(holders) - 1; i >= 0; i-- {
		holders[i].stop()
		if i > 0 {
			t.Eventually(holders[i-1].usbDevices, usbEnumerationTimeout, usbEnumerationInterval).Should(
				matchers.SatisfyPredicate("the app claiming "+claims[i-1]+" got the drive",
					hasUSBDevice(chainedDriveID)))
		}
	}
	evetest.Checkpoint("flash-drive-handed-down")

	// Leave the device as found: the drive and then the hubs, innermost first,
	// since a hub cannot go while something is plugged into it.
	device.DetachUSBStorage(chainedDriveID)
	for i := len(hubIDs) - 1; i >= 0; i-- {
		device.DetachUSBHub(hubIDs[i])
	}
}
