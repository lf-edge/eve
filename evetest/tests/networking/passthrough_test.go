// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// TestNetworkAdapterPassthrough verifies that a physical network adapter
// directly assigned to an application (PCI passthrough) is removed from
// EVE's host networking and handed over to the guest, which must fully own
// the NIC: see it under the adapter's MAC address and obtain an address
// from the SDN-side DHCP server through it. Replicates the eden test
// tests/hardware_reboot/testdata/hardware_eth_reboot.txt.
//
// Network model
// -------------
// TwoMgmtPorts: eth0 is used for management (DHCP, controller
// reachability); eth1, the passthrough port, sits on its own SDN bridge
// with a DHCP server (172.20.21.0/24). The SDN side still drives traffic
// for the adapter -- only EVE's host networking is bypassed.
//
// Device configuration
// --------------------
//   - eth0: PhyIoUsageMgmtAndApps with a SystemAdapter (DHCP).
//   - eth1: PhyIoUsageDedicated without a SystemAdapter -- marked for
//     passthrough.
//   - One container app (EVE wraps it in a shim VM, which is the actual
//     passthrough target) with a virtual NIC on a Local NI for SSH access
//     (port forwarding) and eth1 directly assigned.
//
// Phases
// ------
//  1. Apply the port configuration; eth1 must be reported among
//     assignableAdapters as unused and with a MAC address.
//  2. Deploy the app; eth1's bundle must be reported as used by the app.
//  3. From inside the guest: an interface with eth1's MAC address must be
//     present and hold a DHCP address from eth1's SDN network, proving the
//     passthrough datapath works end-to-end.
//  4. "Reboot Test" subtest: reboot the guest from inside, prove a reboot
//     actually happened via a changed kernel boot ID, and re-run the check
//     of phase 3 -- the adapter must be re-attached cleanly.
//
// Parameters: HYPERVISOR (kubevirt is skipped -- reserved for cluster
// tests).
//
// Note: nested VFIO passthrough requires the EVE VM itself to run with a
// vIOMMU and with iommu_platform=on set on its virtio NICs. All evetest
// broker providers (qemu, libvirt, proxmox) set these up, mirroring eden's
// QEMU options. The test still probes the device for an IOMMU and skips
// itself when there is none (e.g. a broker predating this support). It
// also skips when EVE reports that the two NICs share a PCI controller
// (both in one IOMMU group), which makes passing through only one of them
// impossible -- the case on Proxmox, whose fixed q35 layout places all
// NICs behind a single conventional PCI bridge.
func TestNetworkAdapterPassthrough(test *testing.T) {
	evetestT := evetest.Init(test)
	log := evetest.Logger()
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.TwoMgmtPorts,
		})
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Nested VFIO passthrough only works when the broker exposes a vIOMMU
	// to the EVE VM (see the note above); skip when it does not.
	iommus, err := device.ListDirEntries("/sys/class/iommu")
	if err != nil {
		evetestT.Fatalf("Failed to check the device for a vIOMMU: %v", err)
	}
	if len(iommus) == 0 {
		test.Fatal("the broker provider does not expose a vIOMMU to the EVE VM, " +
			"which nested VFIO NIC passthrough requires")
	}

	const (
		timeout    = 5 * time.Minute
		sshTimeout = 20 * time.Second
		polling    = 3 * time.Second
	)

	// eth0 is the management port; eth1 is reserved for passthrough
	// (dedicated usage, hence no network and no SystemAdapter).
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		// Shared label referenced by the "newni" NI of the Dynamic
		// Adapters subtest to select this adapter as its uplink port.
		SharedLabels: []string{"newni0"},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)

	// Remember the adapter's MAC address to later find the NIC inside the
	// guest.
	var eth1MAC string
	var sharedControllerErr string
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"eth1 is reported as an unused assignable adapter with a MAC address",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			bundle := lookupAssignableAdapter(dinfo, "ethernet1")
			if bundle == nil || len(bundle.GetIoAddressList()) == 0 {
				return false
			}
			// When the NICs share a PCI controller (e.g. placed behind one
			// conventional PCI bridge, as in Proxmox's default q35 layout),
			// EVE merges them into a single assignment group and reports an
			// error on the bundle: passing through eth1 alone is impossible
			// in such a topology, so the test skips itself below.
			if err := bundle.GetErr(); err != nil {
				if strings.Contains(err.GetDescription(), "same PCI controller") {
					sharedControllerErr = err.GetDescription()
					return true
				}
				return false
			}
			if bundle.GetUsedByAppUUID() != "" {
				return false
			}
			eth1MAC = bundle.GetIoAddressList()[0].GetMacAddress()
			return eth1MAC != ""
		})))
	if sharedControllerErr != "" {
		test.Skipf("NIC passthrough is not possible on this host, the NICs "+
			"share a PCI controller: %s", sharedControllerErr)
	}
	evetest.Checkpoint("adapter-available")

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
	})
	appConfig := evetest.ApplicationInstanceConfig{
		DisplayName: "passthrough-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				MAC:                 evetest.MACAddress("02:16:3e:00:00:01"),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
			evetest.DirectlyAssignedNetworkAdapter{
				LogicalLabel: "ethernet1",
			},
		},
		EnforceNetIntfOrder: true,
	}
	appUUID := devConfig.AddApplication(appConfig)
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, timeout)

	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"eth1 is reported as assigned to the application",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			bundle := lookupAssignableAdapter(dinfo, "ethernet1")
			return bundle != nil && bundle.GetUsedByAppUUID() == appUUID.String()
		})))
	evetest.Checkpoint("adapter-assigned")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}

	t.Eventually(func(t Gomega) {
		stdout, _, err := device.RunShellScript(`lspci -k -d 1af4:*`, time.Minute, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(stdout).To(ContainSubstring("vfio-pci"))
	}, timeout, polling).Should(Succeed())

	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for the passed-through NIC to appear in the guest " +
			"with a DHCP address...")
		script := fmt.Sprintf("ip a | grep -i -A 3 '%s'", eth1MAC)
		stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			script, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(stdout).To(ContainSubstring("inet 172.20.21."))
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("guest-owns-nic")

	test.Run("Reboot Test", func(t *testing.T) {
		g := NewGomegaWithT(t)

		// The passed-through NIC must be re-initialized and functional
		// again after the guest reboots (mirrors the eden
		// hardware_eth_reboot scenario). The kernel boot ID proves that a
		// reboot actually took place -- the re-check cannot pass against
		// the pre-reboot boot. eden uses a marker file in /tmp for this,
		// but the container rootfs lives on the app volume and survives
		// reboots, while the boot ID works in both guest types.
		const bootIDCmd = "cat /proc/sys/kernel/random/boot_id"
		var bootID string
		g.Eventually(func(t Gomega) {
			stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				bootIDCmd, sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
			bootID = strings.TrimSpace(stdout)
			t.Expect(bootID).ToNot(BeEmpty())
		}, timeout, polling).Should(Succeed())

		// Trigger the reboot from inside the guest, detached and delayed
		// so the SSH session closes cleanly first (like eden's
		// "shutdown -r +1 &"), with a sysrq fallback in case the image
		// has no working reboot binary.
		log.Infof("Rebooting the guest from inside...")
		rebootCmd := "nohup sh -c 'sleep 2; reboot -f || " +
			"{ echo 1 > /proc/sys/kernel/sysrq; echo b > /proc/sysrq-trigger; }' " +
			">/dev/null 2>&1 &"
		_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, rebootCmd,
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())

		g.Eventually(func(t Gomega) {
			log.Infof("Waiting for the guest to come back with a new boot ID...")
			stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				bootIDCmd, sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
			newBootID := strings.TrimSpace(stdout)
			t.Expect(newBootID).ToNot(BeEmpty())
			t.Expect(newBootID).ToNot(Equal(bootID))
		}, timeout, polling).Should(Succeed())

		// Re-check: the passed-through NIC is present again and has
		// re-acquired a DHCP address from eth1's SDN network.
		g.Eventually(func(t Gomega) {
			log.Infof("Waiting for the passed-through NIC to be back in the " +
				"guest with a DHCP address after reboot...")
			script := fmt.Sprintf("ip a | grep -i -A 3 '%s'", eth1MAC)
			stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				script, sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
			t.Expect(stdout).To(ContainSubstring("inet 172.20.21."))
		}, timeout, polling).Should(Succeed())
		evetest.Checkpoint("guest-owns-nic-after-reboot")
	})

	test.Run("Dynamic Adapters", func(t *testing.T) {
		g := NewGomegaWithT(t)

		// The NI's Port must resolve to an existing device adapter (by
		// logical or shared label): "newni0" is a shared label carried by
		// ethernet0, so this NI shares the mgmt port as its uplink --
		// ethernet1 is dedicated to the app and cannot back an NI.
		nuuid := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
			DisplayName: "newni",
			Port:        "newni0",
			Subnet:      evetest.IPSubnet("10.11.13.0/24"),
			DHCPRange: types.IPRange{
				Start: evetest.IPAddress("10.11.13.2"),
				End:   evetest.IPAddress("10.11.13.254"),
			},
		})

		g.Eventually(func(t Gomega) {
			stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				"ip a", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
			t.Expect(stdout).ToNot(ContainSubstring("00:09:5b:45:af:d1"))
			t.Expect(stdout).ToNot(ContainSubstring("00:09:5b:45:af:d2"))
			t.Expect(stdout).ToNot(ContainSubstring("00:09:5b:45:af:d3"))
		}, timeout, polling).Should(Succeed())

		// No port forwarding on newvif1 -- SSH keeps going through vif0.
		orderNewVif1 := uint32(1)
		appConfig.NetworkAdapters = append(appConfig.NetworkAdapters, evetest.VirtualNetworkAdapter{
			LogicalLabel:        "newvif1",
			NetworkInstanceUUID: nuuid,
			MAC:                 evetest.MACAddress("00:09:5b:45:af:d1"),
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
			InterfaceOrder: &orderNewVif1,
		})

		orderNewVif3 := uint32(3)
		appConfig.NetworkAdapters = append(appConfig.NetworkAdapters, evetest.VirtualNetworkAdapter{
			LogicalLabel:        "newvif3",
			NetworkInstanceUUID: nuuid,
			MAC:                 evetest.MACAddress("00:09:5b:45:af:d3"),
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
			InterfaceOrder: &orderNewVif3,
		})

		devConfig.UpdateApplication(appUUID, appConfig)
		device.ApplyConfig(devConfig, true, true)
		device.WaitUntilAppIsRunning(appUUID, timeout)

		g.Eventually(func(t Gomega) {
			stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				"ip a", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
			t.Expect(stdout).To(ContainSubstring("00:09:5b:45:af:d1"))
			t.Expect(stdout).To(ContainSubstring("00:09:5b:45:af:d3"))
		}, timeout, polling).Should(Succeed())

		orderNewVif2 := uint32(2) // add this device into the middle
		appConfig.NetworkAdapters = append(appConfig.NetworkAdapters, evetest.VirtualNetworkAdapter{
			LogicalLabel:        "newvif2",
			NetworkInstanceUUID: nuuid,
			MAC:                 evetest.MACAddress("00:09:5b:45:af:d2"),
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
			InterfaceOrder: &orderNewVif2,
		})

		devConfig.UpdateApplication(appUUID, appConfig)
		device.ApplyConfig(devConfig, true, true)
		device.WaitUntilAppIsRunning(appUUID, timeout)

		g.Eventually(func(t Gomega) {
			stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				"ip a", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
			t.Expect(stdout).To(ContainSubstring("00:09:5b:45:af:d1"))
			t.Expect(stdout).To(ContainSubstring("00:09:5b:45:af:d2"))
			t.Expect(stdout).To(ContainSubstring("00:09:5b:45:af:d3"))
		}, timeout, polling).Should(Succeed())

		ensureNetworkOrder(g, device, appUUID, []string{"vif0", "newvif1", "newvif2", "newvif3"})
	})
}

// lookupAssignableAdapter returns the ZioBundle with the given name from the
// device info, or nil if not (yet) reported.
func lookupAssignableAdapter(dinfo *eveinfo.ZInfoDevice, name string) *eveinfo.ZioBundle {
	for _, bundle := range dinfo.GetAssignableAdapters() {
		if bundle.GetName() == name {
			return bundle
		}
	}
	return nil
}
