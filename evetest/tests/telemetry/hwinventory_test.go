// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the hardware inventory (ZInfoHardware) that EVE reports to the controller.

package telemetry_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/google/go-cmp/cmp"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/matchers"
	"google.golang.org/protobuf/testing/protocmp"
)

const (
	devInfoTimeout = 5 * time.Minute

	// EVE publishes ZInfoHardware once per boot, at zedagent startup - i.e. long
	// before this test starts - so the pre-reboot message is fetched from the
	// controller's store rather than awaited on a watch. Polling Adam reloads
	// every stored info message, hence the deliberately slow interval.
	hwInfoTimeout      = 2 * time.Minute
	hwInfoPollInterval = 5 * time.Second

	// RequestReboot(true) returns only once the device is back and has reported a
	// fresh LastRebootTime, so this covers just the gap between that device info
	// message and the hardware info message - zedagent triggers both during
	// startup, seconds apart.
	postRebootHwInfoTimeout = 2 * time.Minute
)

// TestHardwareInventory verifies the hardware inventory EVE reports in
// ZInfoHardware: that EVE advertises the capability, that the inventory
// describes the device it actually runs on, and - the point of the test - that
// it is a *stable* description of that hardware, unchanged by a reboot.
//
// zedagent collects the inventory once per boot, from ghw, before any controller
// config is applied (hardware.GetInventoryInfo) - which is what makes a
// difference across a reboot meaningful: it can only be a non-deterministic
// collector or runtime state leaking into a pure hardware description.
//
// Two traps in the field assertions:
//   - CpuInfo lists one entry per *physical core* while ZInfoDevice.Ncpu counts
//     *logical* CPUs. Both are asserted against the vCPU count the harness gave
//     the VM rather than against each other, so that EVE is not its own
//     reference; the inventory side holds only while threads-per-core is 1, as
//     it is for every provider the broker drives. Ids are not asserted unique:
//     the id is a core id, unique only within a socket.
//   - Several assertions are floor checks catching collection that failed
//     outright, not cross-checks: HwInventorySupport is hardcoded true in
//     getOptionalCapabilities, so it guards the API shape rather than a runtime
//     capability; ghw falls TotalPhysicalBytes back to MemTotal; and
//     TotalStorageBytes contains ZInfoDevice.Storage (the /persist partition) by
//     construction. ghw also enumerates /sys/class/net irrespective of the
//     applied config, so the entry for the configured port proves nothing about
//     that config; it is asserted because a physical NIC is the one device whose
//     properties the test knows in advance.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the inventory is not about networking, so a
//     single port need only give the device controller connectivity; it also
//     gives the NetworkDevice assertion an unambiguous interface to look for.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), nothing else: the inventory is
//     collected before any config is applied, so the configuration exists only
//     to get the device reporting to the controller.
//
// Phases / assertions
// -------------------
//
//  1. setup-done -> config-applied.
//
//  2. inventory-support-reported: wait for a ZInfoDevice with Ncpu and Storage
//     populated - they reach zedagent from other microservices via pubsub - then
//     assert HwInventorySupport, rather than waiting for it, so that an EVE
//     without the field fails immediately instead of timing out.
//
//  3. inventory-reported: the ZInfoHardware message EVE published at boot carries
//     an inventory. Fetched with GetHardwareInfo rather than a watch, because it
//     was published once during zedagent startup, so the controller's stored copy
//     is by now the only one there is.
//
//  4. inventory-fields-checked: the field assertions.
//
//  5. device-rebooted -> inventory-stable-after-reboot: reboot via
//     RequestReboot(true), then compare the two inventories. Here a watch is the
//     right tool, opened *before* the reboot: it streams only messages arriving
//     after subscribing, so what it delivers can only be the publish from the
//     rebooted device's own startup, not the record the controller already held.
//     The whole HardwareInventory is compared; the enclosing ZInfoHardware is
//     not, since its Disks field carries S.M.A.R.T. attributes that legitimately
//     change. The comment at the diff names the likely sources of a spurious one.
//
// Test params
// -----------
//   - TPM. Drives both whether the device VM gets an emulated TPM and the
//     expected value of Inventory.Tpm.Present.
//   - HYPERVISOR. Not asserted on; declared so that every test in the suite
//     states the same device requirements and the framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite, among the subtests that reboot the device.
func TestHardwareInventory(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupTelemetryTestDevice(hypervisor, useTPM)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration.
	devConfig := singleMgmtPortConfig()
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 2: EVE advertises hardware inventory support and reports the summary
	// quantities the inventory is checked alongside.
	var devInfo *eveinfo.ZInfoDevice
	t.Eventually(devUpdates, devInfoTimeout).Should(Receive(matchers.SatisfyPredicate(
		"Device reports its CPU count and storage size",
		func(info *eveinfo.ZInfoDevice) bool {
			devInfo = info
			return info.GetNcpu() > 0 && info.GetStorage() > 0
		})))
	t.Expect(devInfo.GetOptionalCapabilities()).ToNot(BeNil(),
		"device info reports no optional capabilities")
	t.Expect(devInfo.GetOptionalCapabilities().GetHwInventorySupport()).To(BeTrue(),
		"device does not advertise hardware inventory support")
	evetest.Checkpoint("inventory-support-reported")

	// Phase 3: the hardware info message published at boot is on the controller
	// and carries an inventory.
	var hwInfo *eveinfo.ZInfoHardware
	t.Eventually(func(g Gomega) {
		hwInfo = device.GetHardwareInfo()
		g.Expect(hwInfo).ToNot(BeNil(), "no ZInfoHardware message received")
		g.Expect(hwInfo.GetInventory()).ToNot(BeNil(),
			"ZInfoHardware message carries no hardware inventory")
	}, hwInfoTimeout, hwInfoPollInterval).Should(Succeed())
	inventory := hwInfo.GetInventory()
	evetest.Logger().Infof("Hardware inventory reported by %s: %v", devName, inventory)
	evetest.Checkpoint("inventory-reported")

	// Phase 4: the inventory describes the device EVE actually runs on. Both CPU
	// counts are compared against the vCPUs the harness provisioned, not against
	// each other.
	cpus := inventory.GetCpuInfo().GetCpus()
	t.Expect(len(cpus)).To(Equal(constants.DefaultEVEDeviceCPUs),
		"inventory reports %d CPU(s) for a %d-vCPU device",
		len(cpus), constants.DefaultEVEDeviceCPUs)
	t.Expect(devInfo.GetNcpu()).To(BeEquivalentTo(constants.DefaultEVEDeviceCPUs),
		"device info reports %d CPU(s) for a %d-vCPU device",
		devInfo.GetNcpu(), constants.DefaultEVEDeviceCPUs)
	for i, cpu := range cpus {
		t.Expect(cpu.GetVendor() != "" || cpu.GetModel() != "").To(BeTrue(),
			"CPU %d is identified by neither vendor nor model", i)
	}

	t.Expect(inventory.GetTotalMemoryBytes()).To(BeNumerically(">", 0),
		"inventory reports no system memory")
	// Both sides in MiB; ZInfoDevice.Storage covers the /persist partition only.
	t.Expect(inventory.GetTotalStorageBytes()>>20).To(
		BeNumerically(">=", devInfo.GetStorage()),
		"inventory reports less total storage than the /persist partition size "+
			"reported in the device info")

	var portDev *eveinfo.NetworkDevice
	for _, netDev := range inventory.GetNetworkDevices() {
		if netDev.GetIfname() == portIfName {
			portDev = netDev
			break
		}
	}
	t.Expect(portDev).ToNot(BeNil(), "inventory has no network device %q", portIfName)
	t.Expect(portDev.GetMacAddress()).ToNot(BeEmpty(),
		"network device %q has no MAC address", portIfName)
	t.Expect(portDev.GetType()).To(
		Equal(eveinfo.NetworkDeviceType_NETWORK_DEVICE_TYPE_ETHERNET),
		"network device %q is not classified as Ethernet", portIfName)

	t.Expect(inventory.GetPciDevices()).ToNot(BeEmpty(),
		"inventory reports no PCI devices")
	for _, pciDev := range inventory.GetPciDevices() {
		t.Expect(pciDev.GetAddress()).ToNot(BeNil(),
			"PCI device %04x:%04x has no bus address",
			pciDev.GetVendorId(), pciDev.GetDeviceId())
	}

	t.Expect(inventory.GetTpm()).ToNot(BeNil(), "inventory reports no TPM information")
	t.Expect(inventory.GetTpm().GetPresent()).To(Equal(useTPM),
		"inventory disagrees with the TPM the device was created with")
	evetest.Checkpoint("inventory-fields-checked")

	// Phase 5: the inventory survives a reboot unchanged. The watch is opened
	// before the reboot, so the only message it can deliver is the one the
	// rebooted device publishes during startup.
	hwUpdates, stopHwWatch := device.WatchHardwareInfo()
	defer stopHwWatch()
	device.RequestReboot(true)
	evetest.Checkpoint("device-rebooted")

	var rebootedHwInfo *eveinfo.ZInfoHardware
	t.Eventually(hwUpdates, postRebootHwInfoTimeout).Should(Receive(&rebootedHwInfo),
		"the rebooted device did not report its hardware inventory")

	// Should this ever produce a spurious diff, start with the fields whose value
	// depends on when during the boot ghw sampled - the two boots are not
	// symmetric, a cold first boot against a warm reboot:
	//   - PciDevices[].Driver: driver binding is asynchronous, so a module
	//     binding later on one boot leaves the driver symlink, and this, unset.
	//   - NetworkDevices: ghw skips only lo and bonding_masters, so every netdev
	//     alive at sample time counts (sit0, tunl0, app or NI leftovers).
	//   - NetworkDevices[].SpeedMbps: raw /sys/class/net/<dev>/speed, which is
	//     EINVAL while the carrier is down; constant on virtio, not on real NICs.
	//   - TotalStorageBytes: sums every /sys/block entry unfiltered, so loop*,
	//     dm-* and zram* count too.
	diff := cmp.Diff(inventory, rebootedHwInfo.GetInventory(),
		protocmp.Transform(), protocmp.SortRepeated(cpuLess))
	t.Expect(diff).To(BeEmpty(),
		"hardware inventory changed across a reboot (-before +after)")
	evetest.Checkpoint("inventory-stable-after-reboot")
}

// cpuLess orders CPUs by their observable content so that CpuInfo.Cpus can be
// compared as a multiset: ghw derives the list by ranging over a map keyed by
// socket, so its order is stable only while the VM has a single socket.
func cpuLess(a, b *eveinfo.CPU) bool {
	switch {
	case a.GetId() != b.GetId():
		return a.GetId() < b.GetId()
	case a.GetVendor() != b.GetVendor():
		return a.GetVendor() < b.GetVendor()
	case a.GetModel() != b.GetModel():
		return a.GetModel() < b.GetModel()
	default:
		return a.GetFreq() < b.GetFreq()
	}
}
