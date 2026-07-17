// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import "testing"

// TestNetworkAdapterPassthrough verifies that a physical network adapter
// directly assigned to an application (PCI passthrough) is removed from
// EVE's host networking and exposed to the guest VM. Replicates the eden test:
//
//	github.com/lf-edge/eden/tests/hardware_reboot/testdata/hardware_eth_reboot.txt
//
// (eden passes a virtio NIC through to the guest VM and the guest sees a
// new ethX interface; the same trick works here once the evetest broker
// is updated -- see the prerequisite below.)
//
// SKIPPED for now -- requires a small evetest broker change. The eden
// QEMU launcher (pkg/eden/qemu.go) adds the flags
//
//	disable-legacy=on,disable-modern=off,iommu_platform=on
//
// to every virtio-net-pci device. With those flags + KVM acceleration +
// IOMMU enabled on the machine type, EVE running inside the outer VM can
// use VFIO to pass the virtio NIC through to its own guest application
// VM. evetest's broker (evetest/broker/provider/qemu.go around the
// "-> networking (virtio-net-pci)" loop, and the analogous spot in
// libvirt.go that sets -global virtio-net-pci.* properties) currently
// builds the device with just `mac=...,speed=1000,duplex=full` -- no
// iommu_platform. Adding the same three flags there (and ensuring the
// EVE machine type has IOMMU enabled, q35 + intel-iommu=on if not
// already) is the only framework prerequisite.
//
// Network model
// -------------
//   - Two physical ports defined in the netmodel (one for mgmt, one to be
//     passed through). Mgmt port (eth0) attaches to a normal SDN bridge
//     with DHCP and controller reachability.
//   - The passthrough port (eth1) is attached to its own SDN bridge with
//     a DHCP server so the guest can DHCP an IP once it sees the NIC, and
//     reach an SDN HTTP server. The SDN side still drives traffic for the
//     adapter -- only EVE's host networking is bypassed.
//
// Device configuration
// --------------------
//   - PhysicalIO entry for eth0 with Usage=PhyIoUsageMgmtAndApps and a
//     SystemAdapter on it (DHCP). Used to onboard and reach the controller.
//   - PhysicalIO entry for eth1 with Usage=PhyIoUsageDedicated and NO
//     SystemAdapter. This marks the port for passthrough; EVE must not
//     attach the host network stack to it. (The eden test does the same
//     via a custom devmodel.json that flips eth1 to PhyIoUsageNone.)
//   - One application with a DirectlyAssignedNetworkAdapter referencing
//     eth1 by logical label. The application can be either a true VM (the
//     eden test uses an Ubuntu focal cloud image) OR a container -- EVE
//     wraps containers in a shim VM for isolation (see APP-CONNECTIVITY.md
//     "Virtual network interfaces" and "Container App VIF MTU"), so the
//     shim VM is the passthrough target and the container inside it sees
//     the NIC directly. The existing lfedge/evetest-ubuntu-ctr
//     image used by TestLocalNI / TestSwitchNI is therefore suitable
//     here too; using it avoids pulling a separate cloud image.
//   - Optionally a Local NI on eth0 and a virtual VIF for the app, so the
//     test framework can SSH into the app via a port-forwarding ACL. The
//     eden test follows the same pattern (port 2223 -> 22) to drive the
//     in-VM checks.
//
// Assertions
// ----------
//   - Before app deploys: WatchDeviceInfo confirms eth1 is listed under
//     assignableAdapters (ZInfoDevice.assignableAdapters) with state
//     "available", and there is no SystemAdapter for eth1 in
//     SystemAdapterInfo.
//   - After WaitUntilAppIsRunning:
//   - The assignableAdapters entry for eth1 transitions to "assigned to
//     app <uuid>".
//   - WatchAppInfo: the app reports one VIF (the mgmt-NI one) and one
//     directly-assigned adapter for eth1.
//   - From inside the guest VM (RunShellScriptInsideApp via the SSH
//     port-fwd):
//     a) `ip link` lists a fresh ethX interface for the passed-through
//     NIC (the eden test parameterizes this as `enp4s0`; here we
//     accept any name and instead match by MAC or by the order in
//     which it appears after the mgmt interface).
//     b) Acquire an IP from the SDN-side DHCP server for the eth1
//     network. With the lfedge/evetest-ubuntu-ctr image the
//     shim VM's init script runs DHCP on every recognized interface
//     by default, so the address should be present as soon as the
//     link appears; in a VM cloud image variant, run `dhclient
//     <iface>` (or systemd-networkd) explicitly.
//     c) `curl http://http-server.test/helloworld` from inside the
//     guest, sourced via the passed-through interface, succeeds.
//     This confirms the guest fully owns the NIC and that EVE is not
//     in the data path.
//   - After app deletion: WatchDeviceInfo eventually reports
//     assignableAdapters[eth1] back to "available".
//
// Reboot variant
// --------------
// The eden test specifically exercises a guest reboot to catch
// regressions where the passthrough adapter is not re-attached cleanly
// on resume. Add a second phase:
//   - From inside the VM, `reboot`. Wait until the VM is back (SSH
//     succeeds again).
//   - Re-run the passthrough interface checks (steps a-c above).
//
// Test params
// -----------
//   - HYPERVISOR. The test must call evetest.SkipIfHypervisorKubevirt()
//     after reading the parameter -- Kubevirt is reserved for cluster tests.
//
// Future extensions
// -----------------
//   - SR-IOV VF passthrough (different code path from full-NIC passthrough;
//     see APP-CONNECTIVITY.md "SR-IOV VFs"). Requires either real hardware
//     or QEMU's emulated SR-IOV (e.g. igb), which the broker currently
//     does not expose.
//   - USB passthrough of a network adapter
func TestNetworkAdapterPassthrough(test *testing.T) {
	test.Skip("not yet implemented")
}
