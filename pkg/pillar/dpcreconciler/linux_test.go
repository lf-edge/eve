// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcreconciler_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/lf-edge/eve/api/go/evecommon"
	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	dpcrec "github.com/lf-edge/eve/pkg/pillar/dpcreconciler"
	generic "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	dpcReconciler  *dpcrec.LinuxDpcReconciler
	networkMonitor *netmonitor.MockNetworkMonitor
)

func initTest(test *testing.T) *GomegaWithT {
	t := NewGomegaWithT(test)
	t.SetDefaultEventuallyTimeout(5 * time.Second)
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	networkMonitor = &netmonitor.MockNetworkMonitor{
		Log:    log,
		MainRT: syscall.RT_TABLE_MAIN,
	}
	dpcReconciler = &dpcrec.LinuxDpcReconciler{
		Log:            log,
		AgentName:      "test",
		NetworkMonitor: networkMonitor,
	}
	return t
}

func printCurrentState() {
	currentState := dpcReconciler.GetCurrentState()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.Export(currentState)
	fmt.Println(dot)
}

func printIntendedState() {
	intendedState := dpcReconciler.GetIntendedState()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.Export(intendedState)
	fmt.Println(dot)
}

func printCombinedState() {
	currentState := dpcReconciler.GetCurrentState()
	intendedState := dpcReconciler.GetIntendedState()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.ExportTransition(currentState, intendedState)
	fmt.Println(dot)
}

func itemIsCreated(itemRef dg.ItemRef) bool {
	_, state, _, found := dpcReconciler.GetCurrentState().Item(itemRef)
	return found && state.IsCreated()
}

func itemIsCreatedWithLabel(label string) bool {
	currentState := dpcReconciler.GetCurrentState()
	iter := currentState.Items(true)
	for iter.Next() {
		item, state := iter.Item()
		if item.Label() == label {
			return state.IsCreated()
		}
	}
	return false
}

func itemDescription(itemRef dg.ItemRef) string {
	item, _, _, found := dpcReconciler.GetCurrentState().Item(itemRef)
	if !found {
		return ""
	}
	return item.String()
}

func macAddress(macAddr string) net.HardwareAddr {
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		log.Fatal(err)
	}
	return mac
}

func ipAddress(ipAddr string) *net.IPNet {
	ip, subnet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		log.Fatal(err)
	}
	subnet.IP = ip
	return subnet
}

func ipSubnet(ipAddr string) *net.IPNet {
	_, subnet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		log.Fatal(err)
	}
	return subnet
}

func itemCountWithType(itemType string) (count int) {
	currentState := dpcReconciler.GetCurrentState()
	iter := currentState.Items(true)
	for iter.Next() {
		item, _ := iter.Item()
		if item.Type() == itemType {
			count++
		}
	}
	return count
}

func TestReconcileWithEmptyArgs(test *testing.T) {
	t := initTest(test)
	ctx := reconciler.MockRun(context.Background())
	status := dpcReconciler.Reconcile(ctx, dpcrec.Args{})
	t.Expect(status.Error).To(BeNil())
	t.Expect(status.AsyncInProgress).To(BeFalse())
	t.Expect(status.FailingItems).To(BeEmpty())
	t.Expect(status.RS.Imposed).To(BeFalse())
	t.Expect(status.RS.ConfigError).To(BeEmpty())
	t.Expect(status.DNS.Error).To(BeNil())
	t.Expect(status.DNS.Servers).To(BeEmpty())
	t.Expect(itemCountWithType(linux.LocalIPRuleTypename)).To(Equal(1))
	t.Expect(itemCountWithType(iptables.ChainV4Typename)).To(Equal(11))
	t.Expect(itemCountWithType(iptables.ChainV6Typename)).To(Equal(11))
	t.Expect(itemCountWithType(iptables.RuleV4Typename)).To(Equal(28))
	t.Expect(itemCountWithType(iptables.RuleV6Typename)).To(Equal(27)) // without markDhcp
	t.Expect(itemIsCreatedWithLabel("Block SSH")).To(BeTrue())

	// Enable SSH access
	gcp := types.DefaultConfigItemValueMap()
	gcp.SetGlobalValueString(types.SSHAuthorizedKeys, "mock-authorized-key")
	ctx = reconciler.MockRun(context.Background())
	status = dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp})
	t.Expect(status.Error).To(BeNil())
	t.Expect(itemIsCreatedWithLabel("Block SSH")).To(BeFalse())

	// Nothing changed - nothing to reconcile.
	ctx = reconciler.MockRun(context.Background())
	status = dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp})
	t.Expect(status.Error).To(BeNil())
}

func TestSingleEthInterface(test *testing.T) {
	t := initTest(test)
	eth0Mac := "02:00:00:00:00:01"
	eth0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "eth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress(eth0Mac),
	}
	networkMonitor.AddOrUpdateInterface(eth0)
	gcp := types.DefaultConfigItemValueMap()
	gcp.SetGlobalValueString(types.SSHAuthorizedKeys, "mock-authorized-key")
	dpc := types.DevicePortConfig{
		Version:      types.DPCIsMgmt,
		Key:          "zedagent",
		TimePriority: time.Now(),
		Ports: []types.NetworkPortConfig{
			{
				IfName:       "eth0",
				Phylabel:     "eth0",
				Logicallabel: "mock-eth0",
				IsMgmt:       true,
				IsL3Port:     true,
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DT_CLIENT,
					Type: types.NT_IPV4,
				},
			},
		},
	}
	aa := types.AssignableAdapters{
		Initialized: true,
		IoBundleList: []types.IoBundle{
			{
				Type:         types.IoNetEth,
				Phylabel:     "eth0",
				Logicallabel: "mock-eth0",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Cost:         0,
				Ifname:       "eth0",
				MacAddr:      eth0Mac,
				IsPCIBack:    false,
				IsPort:       true,
			},
		},
	}

	ctx := reconciler.MockRun(context.Background())
	status := dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())
	t.Expect(status.AsyncInProgress).To(BeFalse())
	t.Expect(status.FailingItems).To(BeEmpty())
	t.Expect(status.RS.Imposed).To(BeFalse())
	t.Expect(status.RS.ConfigError).To(BeEmpty())
	t.Expect(status.DNS.Error).To(BeNil())
	t.Expect(status.DNS.Servers).To(HaveKey("eth0"))
	t.Expect(status.DNS.Servers["eth0"]).To(BeEmpty())

	ioHandle := dg.Reference(generic.IOHandle{PhysIfName: "eth0"})
	t.Expect(itemIsCreated(ioHandle)).To(BeTrue())
	adapter := dg.Reference(linux.Adapter{IfName: "eth0"})
	t.Expect(itemIsCreated(adapter)).To(BeTrue())
	adapterAddrs := dg.Reference(generic.AdapterAddrs{AdapterIfName: "eth0"})
	t.Expect(itemDescription(adapterAddrs)).To(Equal("Adapter mock-eth0 IP addresses: []"))
	t.Expect(itemIsCreatedWithLabel("dhcpcd for mock-eth0")).To(BeTrue())
	sshAuthKeys := dg.Reference(generic.SSHAuthKeys{})
	t.Expect(itemIsCreated(sshAuthKeys)).To(BeTrue())
	t.Expect(itemDescription(sshAuthKeys)).To(Equal("/run/authorized_keys with keys: mock-authorized-key"))
	resolvConf := dg.Reference(generic.ResolvConf{})
	t.Expect(itemIsCreated(resolvConf)).To(BeTrue())
	t.Expect(itemDescription(resolvConf)).To(ContainSubstring("eth0: []"))

	// Simulate IP address being allocated by DHCP server
	eth0IP := ipAddress("192.168.10.5/24")
	eth0.IPAddrs = append(eth0.IPAddrs, eth0IP)
	eth0.DHCP = netmonitor.DHCPInfo{
		Subnet:     ipSubnet("192.168.10.0/24"),
		NtpServers: []net.IP{net.ParseIP("132.163.96.5")},
	}
	eth0.DNS = netmonitor.DNSInfo{
		ResolvConfPath: "/etc/eth0-resolv.conf",
		Domains:        []string{"test-domain"},
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
	}
	networkMonitor.AddOrUpdateInterface(eth0)
	routes := []netmonitor.Route{
		{
			IfIndex: 1,
			Dst:     nil,
			Gw:      net.ParseIP("192.168.10.1"),
			Table:   syscall.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 1,
				Dst:       nil,
				Gw:        net.ParseIP("192.168.10.1"),
				Table:     syscall.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
			},
		},
	}
	networkMonitor.UpdateRoutes(routes)
	t.Eventually(status.ResumeReconcile).Should(Receive())

	ctx = reconciler.MockRun(context.Background())
	status = dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())
	t.Expect(status.AsyncInProgress).To(BeFalse())
	t.Expect(status.FailingItems).To(BeEmpty())
	t.Expect(status.RS.Imposed).To(BeFalse())
	t.Expect(status.RS.ConfigError).To(BeEmpty())
	t.Expect(status.DNS.Error).To(BeNil())
	t.Expect(status.DNS.Servers).To(HaveKey("eth0"))
	t.Expect(status.DNS.Servers["eth0"]).To(HaveLen(1))
	t.Expect(status.DNS.Servers["eth0"][0].String()).To(Equal("8.8.8.8"))
	t.Expect(itemDescription(adapterAddrs)).To(Equal("Adapter mock-eth0 IP addresses: [192.168.10.5/24]"))
	t.Expect(itemIsCreatedWithLabel("IP rule for mock-eth0/192.168.10.5")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("IPv4 route table 501 dst <default> dev mock-eth0 via 192.168.10.1")).To(BeTrue())
	t.Expect(itemIsCreated(resolvConf)).To(BeTrue())
	t.Expect(itemDescription(resolvConf)).To(ContainSubstring("eth0: [8.8.8.8]"))

	// Simulate event of interface losing the IP address.
	eth0.IPAddrs = nil
	eth0.DHCP = netmonitor.DHCPInfo{}
	eth0.DNS = netmonitor.DNSInfo{}
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.UpdateRoutes(nil)
	t.Eventually(status.ResumeReconcile).Should(Receive())

	ctx = reconciler.MockRun(context.Background())
	status = dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())
	t.Expect(status.AsyncInProgress).To(BeFalse())
	t.Expect(status.FailingItems).To(BeEmpty())
	t.Expect(status.RS.Imposed).To(BeFalse())
	t.Expect(status.RS.ConfigError).To(BeEmpty())
	t.Expect(status.DNS.Error).To(BeNil())
	t.Expect(status.DNS.Servers).To(HaveKey("eth0"))
	t.Expect(status.DNS.Servers["eth0"]).To(BeEmpty())
	t.Expect(itemDescription(adapterAddrs)).To(Equal("Adapter mock-eth0 IP addresses: []"))
	t.Expect(itemIsCreatedWithLabel("IP rule for mock-eth0/192.168.10.5")).ToNot(BeTrue())
	t.Expect(itemCountWithType(generic.IPv4RouteTypename)).To(Equal(0))
	t.Expect(itemIsCreated(resolvConf)).To(BeTrue())
	t.Expect(itemDescription(resolvConf)).To(ContainSubstring("eth0: []"))

	// Change eth0 to directly assigned to an app.
	networkMonitor.DelInterface("eth0")
	dpc.Ports = nil
	aa = types.AssignableAdapters{
		Initialized: true,
		IoBundleList: []types.IoBundle{
			{
				Type:         types.IoNetEth,
				Phylabel:     "eth0",
				Logicallabel: "mock-eth0",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageDedicated,
				Cost:         0,
				Ifname:       "eth0",
				MacAddr:      eth0Mac,
				IsPCIBack:    true,
				IsPort:       true,
			},
		},
	}
	t.Eventually(status.ResumeReconcile).Should(Receive())

	ctx = reconciler.MockRun(context.Background())
	status = dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())
	t.Expect(status.AsyncInProgress).To(BeFalse())
	t.Expect(status.FailingItems).To(BeEmpty())
	t.Expect(status.RS.Imposed).To(BeFalse())
	t.Expect(status.RS.ConfigError).To(BeEmpty())
	t.Expect(itemCountWithType(generic.AdapterTypename)).To(Equal(0))
	t.Expect(itemCountWithType(generic.AdapterAddrsTypename)).To(Equal(0))
	t.Expect(itemCountWithType(generic.DhcpcdTypename)).To(Equal(0))
}

func TestMultipleEthsSameSubnet(test *testing.T) {
	t := initTest(test)
	eth0Mac := "02:00:00:00:00:01"
	eth0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "eth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress(eth0Mac),
	}
	eth1Mac := "02:00:00:00:00:02"
	eth1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       2,
			IfName:        "eth1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress(eth1Mac),
	}
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	gcp := types.DefaultConfigItemValueMap()
	gcp.SetGlobalValueString(types.SSHAuthorizedKeys, "mock-authorized-key")
	dpc := types.DevicePortConfig{
		Version:      types.DPCIsMgmt,
		Key:          "zedagent",
		TimePriority: time.Now(),
		Ports: []types.NetworkPortConfig{
			{
				IfName:       "eth0",
				Phylabel:     "eth0",
				Logicallabel: "mock-eth0",
				IsMgmt:       true,
				IsL3Port:     true,
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DT_CLIENT,
					Type: types.NT_IPV4,
				},
			},
			{
				IfName:       "eth1",
				Phylabel:     "eth1",
				Logicallabel: "mock-eth1",
				IsMgmt:       true,
				IsL3Port:     true,
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DT_CLIENT,
					Type: types.NT_IPV4,
				},
			},
		},
	}
	aa := types.AssignableAdapters{
		Initialized: true,
		IoBundleList: []types.IoBundle{
			{
				Type:         types.IoNetEth,
				Phylabel:     "eth0",
				Logicallabel: "mock-eth0",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Cost:         0,
				Ifname:       "eth0",
				MacAddr:      eth0Mac,
				IsPCIBack:    false,
				IsPort:       true,
			},
			{
				Type:         types.IoNetEth,
				Phylabel:     "eth1",
				Logicallabel: "mock-eth1",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Cost:         0,
				Ifname:       "eth1",
				MacAddr:      eth1Mac,
				IsPCIBack:    false,
				IsPort:       true,
			},
		},
	}

	ctx := reconciler.MockRun(context.Background())
	status := dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())
	t.Expect(itemCountWithType(generic.IOHandleTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.AdapterTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.AdapterAddrsTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.DhcpcdTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.IPv4RouteTypename)).To(Equal(0))
	t.Expect(itemCountWithType(generic.ArpTypename)).To(Equal(0))

	// Simulate IP addresses being allocated by DHCP server.
	// Both interfaces will be in the same subnet.
	subnet := ipSubnet("192.168.10.0/24")
	ntpServers := []net.IP{net.ParseIP("132.163.96.5")}
	eth0IP := ipAddress("192.168.10.5/24")
	eth0.IPAddrs = append(eth0.IPAddrs, eth0IP)
	eth0.DHCP = netmonitor.DHCPInfo{
		Subnet:     subnet,
		NtpServers: ntpServers,
	}
	eth0.DNS = netmonitor.DNSInfo{
		ResolvConfPath: "/etc/eth0-resolv.conf",
		Domains:        []string{"test-domain"},
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
	}
	networkMonitor.AddOrUpdateInterface(eth0)
	eth1IP := ipAddress("192.168.10.6/24")
	eth1.IPAddrs = append(eth1.IPAddrs, eth1IP)
	eth1.DHCP = netmonitor.DHCPInfo{
		Subnet:     subnet,
		NtpServers: ntpServers,
	}
	eth1.DNS = netmonitor.DNSInfo{
		ResolvConfPath: "/etc/eth1-resolv.conf",
		Domains:        []string{"test-domain"},
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
	}
	networkMonitor.AddOrUpdateInterface(eth1)
	gw := net.ParseIP("192.168.10.1")
	routes := []netmonitor.Route{
		{
			IfIndex: 1,
			Dst:     nil,
			Gw:      gw,
			Table:   syscall.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 1,
				Dst:       nil,
				Gw:        gw,
				Table:     syscall.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
			},
		},
		{
			IfIndex: 2,
			Dst:     nil,
			Gw:      gw,
			Table:   syscall.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 1,
				Dst:       nil,
				Gw:        gw,
				Table:     syscall.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
			},
		},
	}
	networkMonitor.UpdateRoutes(routes)
	t.Eventually(status.ResumeReconcile).Should(Receive())

	ctx = reconciler.MockRun(context.Background())
	status = dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())
	eth0AdapterAddrs := dg.Reference(generic.AdapterAddrs{AdapterIfName: "eth0"})
	t.Expect(itemDescription(eth0AdapterAddrs)).To(Equal("Adapter mock-eth0 IP addresses: [192.168.10.5/24]"))
	eth1AdapterAddrs := dg.Reference(generic.AdapterAddrs{AdapterIfName: "eth1"})
	t.Expect(itemDescription(eth1AdapterAddrs)).To(Equal("Adapter mock-eth1 IP addresses: [192.168.10.6/24]"))
	t.Expect(itemIsCreatedWithLabel("IP rule for mock-eth0/192.168.10.5")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("IP rule for mock-eth1/192.168.10.6")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("IPv4 route table 501 dst <default> dev mock-eth0 via 192.168.10.1")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("IPv4 route table 502 dst <default> dev mock-eth1 via 192.168.10.1")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("ARP entry 192.168.10.6 / 02:00:00:00:00:02 for mock-eth0")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("ARP entry 192.168.10.5 / 02:00:00:00:00:01 for mock-eth1")).To(BeTrue())
	t.Expect(itemCountWithType(generic.IPv4RouteTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.ArpTypename)).To(Equal(2))
}

func TestWireless(test *testing.T) {
	t := initTest(test)
	wlan0Mac := "02:00:00:00:00:01"
	wlan0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "wlan0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress(wlan0Mac),
	}
	wwan0Mac := "02:00:00:00:00:02"
	wwan0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       2,
			IfName:        "wwan0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress(wwan0Mac),
	}
	networkMonitor.AddOrUpdateInterface(wlan0)
	networkMonitor.AddOrUpdateInterface(wwan0)
	gcp := types.DefaultConfigItemValueMap()
	dpc := types.DevicePortConfig{
		Version:      types.DPCIsMgmt,
		Key:          "zedagent",
		TimePriority: time.Now(),
		Ports: []types.NetworkPortConfig{
			{
				IfName:       "wlan0",
				Phylabel:     "wlan0",
				Logicallabel: "mock-wlan0",
				IsMgmt:       true,
				IsL3Port:     true,
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DT_CLIENT,
					Type: types.NT_IPV4,
				},
				WirelessCfg: types.WirelessConfig{
					WType: types.WirelessTypeWifi,
					Wifi: []types.WifiConfig{
						{
							KeyScheme: types.KeySchemeWpaPsk,
							Identity:  "my-user",
							Password:  "my-password",
							SSID:      "my-ssid",
						},
					},
				},
			},
			{
				IfName:       "wwan0",
				Phylabel:     "wwan0",
				Logicallabel: "mock-wwan0",
				IsMgmt:       true,
				IsL3Port:     true,
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DT_CLIENT,
					Type: types.NT_IPV4,
				},
				WirelessCfg: types.WirelessConfig{
					WType: types.WirelessTypeCellular,
					Cellular: []types.CellConfig{
						{
							APN: "my-apn",
						},
					},
				},
			},
		},
	}
	aa := types.AssignableAdapters{
		Initialized: true,
		IoBundleList: []types.IoBundle{
			{
				Type:         types.IoNetWLAN,
				Phylabel:     "wlan0",
				Logicallabel: "mock-wlan0",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Cost:         0,
				Ifname:       "wlan0",
				MacAddr:      wlan0Mac,
				IsPCIBack:    false,
				IsPort:       true,
			},
			{
				Type:         types.IoNetWWAN,
				Phylabel:     "wwan0",
				Logicallabel: "mock-wwan0",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Cost:         0,
				Ifname:       "wwan0",
				MacAddr:      wwan0Mac,
				IsPCIBack:    false,
				IsPort:       true,
			},
		},
	}

	ctx := reconciler.MockRun(context.Background())
	status := dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())

	t.Expect(itemIsCreatedWithLabel("dhcpcd for mock-wlan0")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("dhcpcd for mock-wwan0")).To(BeFalse())
	wlan := dg.Reference(linux.Wlan{})
	t.Expect(itemDescription(wlan)).To(ContainSubstring("SSID: my-ssid"))
	t.Expect(itemDescription(wlan)).To(ContainSubstring("KeyScheme: 1"))
	t.Expect(itemDescription(wlan)).To(ContainSubstring("Identity: my-user"))
	t.Expect(itemDescription(wlan)).To(ContainSubstring("Priority: 0"))
	t.Expect(itemDescription(wlan)).ToNot(ContainSubstring("my-password"))
	t.Expect(itemDescription(wlan)).To(ContainSubstring("enable RF: true"))
	wwan := dg.Reference(generic.Wwan{})
	t.Expect(itemDescription(wwan)).To(ContainSubstring("Apns:[my-apn]"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("Interface:wwan0"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("LogicalLabel:mock-wwan0"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RadioSilence:false"))
	t.Expect(itemCountWithType(generic.IOHandleTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.AdapterTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.AdapterAddrsTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.DhcpcdTypename)).To(Equal(1))
	t.Expect(itemCountWithType(generic.IPv4RouteTypename)).To(Equal(0))
	t.Expect(itemCountWithType(generic.ArpTypename)).To(Equal(0))

	// Impose radio silence
	rsTimestamp := time.Now()
	rs := types.RadioSilence{
		Imposed:           true,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsTimestamp,
	}
	ctx = reconciler.MockRun(context.Background())
	status = dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa, RS: rs})
	t.Expect(status.Error).To(BeNil())
	t.Expect(status.RS.Imposed).To(BeTrue())
	t.Expect(status.RS.ChangeRequestedAt.Equal(rsTimestamp)).To(BeTrue())
	t.Expect(status.RS.ConfigError).To(BeEmpty())
	t.Expect(itemDescription(wlan)).To(ContainSubstring("enable RF: false"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RadioSilence:true"))
	t.Expect(itemCountWithType(generic.IOHandleTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.AdapterTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.AdapterAddrsTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.DhcpcdTypename)).To(Equal(1))
	t.Expect(itemCountWithType(generic.IPv4RouteTypename)).To(Equal(0))
	t.Expect(itemCountWithType(generic.ArpTypename)).To(Equal(0))
}

func TestVlansAndBonds(test *testing.T) {
	t := initTest(test)
	eth0Mac := "02:00:00:00:00:01"
	eth0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "eth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress(eth0Mac),
	}
	eth1Mac := "02:00:00:00:00:02"
	eth1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       2,
			IfName:        "eth1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress(eth1Mac),
	}
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	gcp := types.DefaultConfigItemValueMap()
	dpc := types.DevicePortConfig{
		Version:      types.DPCIsMgmt,
		Key:          "zedagent",
		TimePriority: time.Now(),
		Ports: []types.NetworkPortConfig{
			{
				IfName:       "eth0",
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor0",
			},
			{
				IfName:       "eth1",
				Phylabel:     "ethernet1",
				Logicallabel: "shopfloor1",
			},
			{
				IfName:       "bond0",
				Logicallabel: "bond-shopfloor",
				L2LinkConfig: types.L2LinkConfig{
					L2Type: types.L2LinkTypeBond,
					Bond: types.BondConfig{
						AggregatedPorts: []string{"shopfloor0", "shopfloor1"},
						Mode:            types.BondModeActiveBackup,
						MIIMonitor: types.BondMIIMonitor{
							Enabled:   true,
							Interval:  400,
							UpDelay:   800,
							DownDelay: 1200,
						},
					},
				},
			},
			{
				IfName:       "shopfloor.100",
				Logicallabel: "shopfloor-vlan100",
				IsL3Port:     true,
				IsMgmt:       true,
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DT_CLIENT,
					Type: types.NT_IPV4,
				},
				L2LinkConfig: types.L2LinkConfig{
					L2Type: types.L2LinkTypeVLAN,
					VLAN: types.VLANConfig{
						ParentPort: "bond-shopfloor",
						ID:         100,
					},
				},
			},
			{
				IfName:       "shopfloor.200",
				Logicallabel: "shopfloor-vlan200",
				IsL3Port:     true,
				IsMgmt:       true,
				DhcpConfig: types.DhcpConfig{
					Dhcp: types.DT_CLIENT,
					Type: types.NT_IPV4,
				},
				L2LinkConfig: types.L2LinkConfig{
					L2Type: types.L2LinkTypeVLAN,
					VLAN: types.VLANConfig{
						ParentPort: "bond-shopfloor",
						ID:         200,
					},
				},
			},
		},
	}
	aa := types.AssignableAdapters{
		Initialized: true,
		IoBundleList: []types.IoBundle{
			{
				Type:         types.IoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "shopfloor0",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Cost:         0,
				Ifname:       "eth0",
				MacAddr:      eth0Mac,
				IsPCIBack:    false,
				IsPort:       true,
			},
			{
				Type:         types.IoNetEth,
				Phylabel:     "ethernet1",
				Logicallabel: "shopfloor1",
				Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
				Cost:         0,
				Ifname:       "eth1",
				MacAddr:      eth1Mac,
				IsPCIBack:    false,
				IsPort:       true,
			},
		},
	}

	ctx := reconciler.MockRun(context.Background())
	status := dpcReconciler.Reconcile(ctx, dpcrec.Args{GCP: *gcp, DPC: dpc, AA: aa})
	t.Expect(status.Error).To(BeNil())

	t.Expect(itemCountWithType(generic.IOHandleTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.BondTypename)).To(Equal(1))
	t.Expect(itemCountWithType(generic.VlanTypename)).To(Equal(2))
	t.Expect(itemCountWithType(generic.AdapterTypename)).To(Equal(2))

	t.Expect(itemIsCreatedWithLabel("dhcpcd for shopfloor-vlan100")).To(BeTrue())
	t.Expect(itemIsCreatedWithLabel("dhcpcd for shopfloor-vlan200")).To(BeTrue())

	bondRef := dg.Reference(linux.Bond{IfName: "bond0"})
	item, _, _, found := dpcReconciler.GetCurrentState().Item(bondRef)
	t.Expect(found).To(BeTrue())
	bond := item.(linux.Bond)
	t.Expect(bond.IfName).To(Equal("bond0"))
	t.Expect(bond.AggregatedPorts).To(Equal([]string{"shopfloor0", "shopfloor1"}))
	t.Expect(bond.AggregatedIfNames).To(Equal([]string{"eth0", "eth1"}))
	t.Expect(bond.ARPMonitor.Enabled).To(BeFalse())
	t.Expect(bond.MIIMonitor.Enabled).To(BeTrue())
	t.Expect(bond.MIIMonitor.Interval).To(BeEquivalentTo(400))
	t.Expect(bond.MIIMonitor.UpDelay).To(BeEquivalentTo(800))
	t.Expect(bond.MIIMonitor.DownDelay).To(BeEquivalentTo(1200))

	vlan100Ref := dg.Reference(linux.Vlan{IfName: "shopfloor.100"})
	item, _, _, found = dpcReconciler.GetCurrentState().Item(vlan100Ref)
	t.Expect(found).To(BeTrue())
	vlan100 := item.(linux.Vlan)
	t.Expect(vlan100.IfName).To(Equal("shopfloor.100"))
	t.Expect(vlan100.ID).To(BeEquivalentTo(100))
	t.Expect(vlan100.ParentLL).To(BeEquivalentTo("bond-shopfloor"))
	t.Expect(vlan100.ParentIfName).To(BeEquivalentTo("bond0"))

	vlan200Ref := dg.Reference(linux.Vlan{IfName: "shopfloor.200"})
	item, _, _, found = dpcReconciler.GetCurrentState().Item(vlan200Ref)
	t.Expect(found).To(BeTrue())
	vlan200 := item.(linux.Vlan)
	t.Expect(vlan200.IfName).To(Equal("shopfloor.200"))
	t.Expect(vlan200.ID).To(BeEquivalentTo(200))
	t.Expect(vlan200.ParentLL).To(BeEquivalentTo("bond-shopfloor"))
	t.Expect(vlan200.ParentIfName).To(BeEquivalentTo("bond0"))
}
