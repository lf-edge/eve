// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"strings"
	"testing"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

// TestSRIOVInterfaceOrder verifies that SR-IOV virtual functions (VFs)
// directly assigned to an application are presented to the guest at the
// position that their interface order gives them among the application's
// network interfaces (EnforceNetIntfOrder), like directly assigned physical
// NICs are. EVE used to place VFs after all other network interfaces,
// whatever their interface order.
//
// Network model
// -------------
// TwoMgmtPorts with eth1 turned into an SR-IOV capable NIC: eth0 is used for
// management (DHCP, controller reachability) and eth1 is the physical
// function (PF) on which EVE creates the VFs. No traffic is sent over eth1.
//
// Device configuration
// --------------------
//   - eth0: PhyIoUsageMgmtAndApps with a SystemAdapter (DHCP).
//   - eth1: a PF (PhyIoNetEthPF) with two VFs, which EVE makes assignable as
//     ethernet1vf0 and ethernet1vf1.
//   - Two Local NIs, one for each virtual NIC of the application; the first
//     forwards a port for SSH access.
//   - One container app (EVE wraps it in a shim VM, which is the actual
//     passthrough target) with both VFs placed between its two virtual NICs
//     and in reverse order of their index: vif0, ethernet1vf1, ethernet1vf0,
//     vif1.
//
// Phases
// ------
//  1. Apply the port configuration; both VFs must be reported among
//     assignableAdapters as unused.
//  2. Deploy the app; both VFs must be reported as used by the app.
//  3. From inside the guest: listed in the order of their PCI addresses,
//     which is the order a guest enumerates its NICs in, the Ethernet devices
//     must be vif0, the two VFs and vif1. The virtual NICs are recognized by
//     their MAC address; a VF is whatever is not a virtual NIC, so the two
//     VFs are not told apart here.
//
// Parameters: HYPERVISOR (anything but kvm is skipped -- EVE enforces the
// interface order only there).
func TestSRIOVInterfaceOrder(test *testing.T) {
	evetestT := evetest.Init(test)
	log := evetest.Logger()
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor != evetest.HypervisorKVM {
		test.Skipf("EVE enforces the network interface order only with kvm, not with %s",
			hypervisor)
	}

	// The network model is shared with other tests, so the SR-IOV capable
	// port is set on a copy.
	netModel := proto.CloneOf(netmodels.TwoMgmtPorts)
	netModel.Ports[1].EveSriov = &api.SRIOVNic{}

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netModel,
		})
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	const (
		timeout    = 5 * time.Minute
		sshTimeout = 20 * time.Second
		polling    = 3 * time.Second

		vf0     = "ethernet1vf0"
		vf1     = "ethernet1vf1"
		vif0MAC = "02:16:3e:00:00:01"
		vif1MAC = "02:16:3e:00:00:02"
	)

	// eth0 is the management port; eth1 is the PF, which stays in the host
	// while its VFs are assigned to the application.
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
	})
	devConfig.AddPhysicalIO(evetest.PhysicalIOConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		Type:          evecommon.PhyIoType_PhyIoNetEthPF,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
		VFCount:       2,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)

	// vfsReported tells whether both VFs are reported as assignable adapters
	// without an error and as used by the given application ("" for unused).
	vfsReported := func(dinfo *eveinfo.ZInfoDevice, usedByApp string) bool {
		for _, vf := range []string{vf0, vf1} {
			bundle := lookupAssignableAdapter(dinfo, vf)
			if bundle == nil || bundle.GetErr() != nil ||
				bundle.GetType() != evecommon.PhyIoType_PhyIoNetEthVF ||
				bundle.GetUsedByAppUUID() != usedByApp {
				return false
			}
		}
		return true
	}
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"both VFs are reported as unused assignable adapters",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return vfsReported(dinfo, "")
		})))
	evetest.Checkpoint("vfs-available")

	ni0UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni0",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
	})
	ni1UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni1",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.13.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.13.2"),
			End:   evetest.IPAddress("10.11.13.254"),
		},
	})

	// The interface order puts the VFs between the two virtual NICs. Without
	// it EVE presents the virtual NICs first, in the order they are listed
	// here, and the directly assigned ones after them.
	orderVif0, orderVF1, orderVF0, orderVif1 := uint32(1), uint32(2), uint32(3), uint32(4)
	allowAll := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolAny,
			RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
		},
	}
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "sriov-app",
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
				NetworkInstanceUUID: ni0UUID,
				MAC:                 evetest.MACAddress(vif0MAC),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules:  allowAll,
				InterfaceOrder: &orderVif0,
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: ni1UUID,
				MAC:                 evetest.MACAddress(vif1MAC),
				ACLAllowRules:       allowAll,
				InterfaceOrder:      &orderVif1,
			},
			evetest.DirectlyAssignedNetworkAdapter{
				LogicalLabel:   vf0,
				Type:           evecommon.PhyIoType_PhyIoNetEthVF,
				InterfaceOrder: &orderVF0,
			},
			evetest.DirectlyAssignedNetworkAdapter{
				LogicalLabel:   vf1,
				Type:           evecommon.PhyIoType_PhyIoNetEthVF,
				InterfaceOrder: &orderVF1,
			},
		},
		EnforceNetIntfOrder: true,
	})
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, timeout)

	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"both VFs are reported as assigned to the application",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			return vfsReported(dinfo, appUUID.String())
		})))
	evetest.Checkpoint("vfs-assigned")

	// One line per Ethernet-class PCI function of the guest, in the order of
	// the PCI addresses: the address, followed by the MAC address of the
	// function's network interface if the guest has a driver for it.
	const listNICsScript = `for d in /sys/bus/pci/devices/*; do
	case "$(cat "$d/class")" in 0x0200*) ;; *) continue ;; esac
	echo "${d##*/} $(cat "$d"/net/*/address "$d"/virtio*/net/*/address 2>/dev/null)"
done`
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for the guest to list its NICs...")
		stdout, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			listNICsScript, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		log.Infof("Ethernet devices of the guest by PCI address:\n%s", stdout)
		var nics []string
		for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
			_, mac, _ := strings.Cut(strings.TrimSpace(line), " ")
			switch mac {
			case vif0MAC:
				nics = append(nics, "vif0")
			case vif1MAC:
				nics = append(nics, "vif1")
			default:
				nics = append(nics, "VF")
			}
		}
		t.Expect(nics).To(Equal([]string{"vif0", "VF", "VF", "vif1"}))
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("guest-nic-order-verified")
}
