// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nireconciler_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/kube/cnirpc"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	nirec "github.com/lf-edge/eve/pkg/pillar/nireconciler"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	niReconciler   *nirec.LinuxNIReconciler
	networkMonitor *netmonitor.MockNetworkMonitor
)

func initTest(test *testing.T, withKube bool) *GomegaWithT {
	t := NewGomegaWithT(test)
	t.SetDefaultEventuallyTimeout(5 * time.Second)
	t.SetDefaultConsistentlyDuration(5 * time.Second)
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 1234)
	networkMonitor = &netmonitor.MockNetworkMonitor{
		Log:    log,
		MainRT: unix.RT_TABLE_MAIN,
	}
	niReconciler = nirec.NewLinuxNIReconciler(log, logger, networkMonitor, nil,
		false, false, withKube)
	return t
}

func printCurrentState() {
	currentState := niReconciler.GetCurrentState()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.Export(currentState)
	fmt.Println(dot)
}

func printIntendedState() {
	intendedState := niReconciler.GetIntendedState()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.Export(intendedState)
	fmt.Println(dot)
}

func printCombinedState() {
	currentState := niReconciler.GetCurrentState()
	intendedState := niReconciler.GetIntendedState()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.ExportTransition(currentState, intendedState)
	fmt.Println(dot)
}

func itemIsCreated(itemRef dg.ItemRef) bool {
	_, state, _, found := niReconciler.GetCurrentState().Item(itemRef)
	return found && state.IsCreated()
}

func itemDescription(itemRef dg.ItemRef) string {
	item, _, _, found := niReconciler.GetCurrentState().Item(itemRef)
	if !found {
		return ""
	}
	return item.String()
}

func itemCount(match func(item dg.Item) bool) (count int) {
	currentState := niReconciler.GetCurrentState()
	iter := currentState.Items(true)
	for iter.Next() {
		item, _ := iter.Item()
		if match(item) {
			count++
		}
	}
	return count
}

func itemCountWithType(itemType string) (count int) {
	currentState := niReconciler.GetCurrentState()
	iter := currentState.Items(true)
	for iter.Next() {
		item, _ := iter.Item()
		if item.Type() == itemType {
			count++
		}
	}
	return count
}

func macAddress(macAddr string) net.HardwareAddr {
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		log.Fatal(err)
	}
	return mac
}

func ipAddress(ipAddr string) net.IP {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		log.Fatal(fmt.Sprintf("bad IP: %s", ipAddr))
	}
	return ip
}

func ipAddressWithPrefix(ipAddr string) *net.IPNet {
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

func deref[T any](p *T) T {
	return *p
}

func makeUUID(id string) types.UUIDandVersion {
	uuid, _ := uuid.FromString(id)
	return types.UUIDandVersion{UUID: uuid}
}

// Test hostIpsetBasename function.
func TestHostIpsetBasename(t *testing.T) {
	tests := []struct {
		testname         string
		hostname         string
		expIPSetBasename string
	}{
		{
			testname:         "short hostname",
			hostname:         "google.com",
			expIPSetBasename: "google.com",
		},
		{
			testname:         "short hostname ending with '.'",
			hostname:         "google.com.",
			expIPSetBasename: "google.com.",
		},
		{
			testname:         "short TLD",
			hostname:         "com",
			expIPSetBasename: "com",
		},
		{
			testname:         "short TLD ending with '.'",
			hostname:         "com.",
			expIPSetBasename: "com.",
		},
		{
			testname:         "hostname just at the length limit",
			hostname:         "this.host.fits.the.limit.x",
			expIPSetBasename: "this.host.fits.the.limit.x",
		},
		{
			testname:         "very long hostname",
			hostname:         "theofficialabsolutelongestdomainnameregisteredontheworldwideweb.international",
			expIPSetBasename: "unFy00boc2ME#international",
		},
		{
			testname:         "very long hostname ending with '.'",
			hostname:         "theofficialabsolutelongestdomainnameregisteredontheworldwideweb.international.",
			expIPSetBasename: "josqV3v361A#international.",
		},
		{
			testname:         "very long TLD",
			hostname:         "shop.verylongcompanynamewhichmakesnosense",
			expIPSetBasename: "jbfc_EF2sup6los19u4HLC4BN#",
		},
		{
			testname:         "very long TLD ending with '.'",
			hostname:         "shop.verylongcompanynamewhichmakesnosense.",
			expIPSetBasename: "3dNidrrnlGggYozJoicbPPi_y#",
		},
		{
			testname:         "hostname one character above the length limit",
			hostname:         "this.host.is.over.the.limit",
			expIPSetBasename: "rQRoWR0T#is.over.the.limit",
		},
		{
			testname:         "empty hostname",
			hostname:         "",
			expIPSetBasename: "",
		},
	}
	for _, test := range tests {
		t.Run(test.testname, func(t *testing.T) {
			if len(test.expIPSetBasename)+len("ipvX.") > nirec.IPSetNameLenLimit {
				t.Errorf("expected ipset basename '%s' is unexpectedly long"+
					" - mistake in the test?", test.expIPSetBasename)
			}
			ipsetBasename := nirec.HostIPSetBasename(test.hostname)
			if ipsetBasename != test.expIPSetBasename {
				t.Errorf("failed for: hostname=%s\n"+
					"expected ipset basename:\n\t%q\ngot ipset basename:\n\t%q",
					test.hostname, test.expIPSetBasename, ipsetBasename)
			}
		})
	}
}

/*
  Config for testing:

  +------+       +--------------+       +--------+
  | app1 |------>| NI1 (local)  |------>|  eth0  |
  +------+   --->|    (IPv4)    |       | (mgmt) |
             |   +--------------+       +--------+
  +------+   |
  |      |----   +--------------+       +--------------+
  | app2 |------>| NI2 (switch) |------>|     eth1     |
  |      |------>|    (IPv4)    |       | (app-shared) |
  |      |----   +--------------+       +--------------+
  +------+   |                                 ^
             |   +------------------+          |
             --->|   NI5 (local)    |-----------
                 |      (IPv4)      |
                 | (multiple ports) |     +--------------+
                 |                  |---->|     eth3     |
                 |                  |     | (app-shared) |
                 +------------------+     +--------------+

  +------+       +--------------+       +--------+
  | app3 |------>| NI3 (local)  |------>|  eth2  |
  |      |----   |    (IPv6)    |   --->| (mgmt) |
  +------+   |   +--------------+   |   +--------+
             |                      |
             |   +--------------+   |
             --->| NI4 (switch) |----
                 |    (IPv6)    |
                 +--------------+
*/

var (
	// Device network port "eth0"
	keth0 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "keth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 2,
		},
		HwAddr: macAddress("02:00:00:00:00:01"),
	}
	eth0 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       2,
			IfName:        "eth0",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("192.168.10.5/24")},
		DHCP: netmonitor.DHCPInfo{
			Subnet:     ipSubnet("192.168.10.0/24"),
			NtpServers: []net.IP{ipAddress("132.163.96.5")},
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/eth0-resolv.conf",
			Domains:        []string{"eth0-test-domain"},
			DNSServers:     []net.IP{ipAddress("8.8.8.8")},
		},
		HwAddr: macAddress("02:00:00:00:01:01"),
	}
	eth0Routes = []netmonitor.Route{
		{
			IfIndex: 2,
			Dst:     ipAddressWithPrefix("0.0.0.0/0"),
			Gw:      ipAddress("192.168.10.1"),
			Table:   unix.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 2,
				Dst:       nil,
				Gw:        ipAddress("192.168.10.1"),
				Table:     unix.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
				Protocol:  unix.RTPROT_DHCP,
			},
		},
	}

	// Device network port "eth1"
	keth1 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       3,
			IfName:        "keth1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 4,
		},
		HwAddr: macAddress("02:00:00:00:00:02"),
	}
	eth1 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       4,
			IfName:        "eth1",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("172.20.0.40/16")},
		DHCP: netmonitor.DHCPInfo{
			Subnet: ipSubnet("172.20.0.0/16"),
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/eth1-resolv.conf",
			Domains:        []string{"eth1-test-domain"},
			DNSServers:     []net.IP{ipAddress("8.8.8.8"), ipAddress("1.1.1.1")},
		},
		HwAddr: macAddress("02:00:00:00:01:02"),
	}
	eth1Routes = []netmonitor.Route{
		{
			IfIndex: 4,
			Dst:     ipAddressWithPrefix("0.0.0.0/0"),
			Gw:      ipAddress("172.20.0.1"),
			Table:   unix.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 4,
				Dst:       nil,
				Gw:        ipAddress("172.20.0.1"),
				Table:     unix.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
				Protocol:  unix.RTPROT_DHCP,
			},
		},
	}

	// Device network port "eth2" (IPv6 connectivity)
	keth2 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       5,
			IfName:        "keth2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 6,
		},
		HwAddr: macAddress("02:00:00:00:00:03"),
	}
	eth2 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       6,
			IfName:        "eth2",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("2001::20/64")},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/eth1-resolv.conf",
			Domains:        []string{"eth1-test-domain"},
			DNSServers:     []net.IP{ipAddress("2001:4860:4860::8888")},
		},
		HwAddr: macAddress("02:00:00:00:01:03"),
	}
	eth2Routes = []netmonitor.Route{
		{
			IfIndex: 6,
			Dst:     ipAddressWithPrefix("::/0"),
			Gw:      ipAddress("2001::1"),
			Table:   unix.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 6,
				Dst:       ipAddressWithPrefix("::/0"),
				Gw:        ipAddress("2001::1"),
				Table:     unix.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
				Protocol:  unix.RTPROT_DHCP,
			},
		},
	}

	// Device network port "eth3"
	keth3 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       7,
			IfName:        "keth3",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 8,
		},
		HwAddr: macAddress("02:00:00:00:00:04"),
	}
	eth3 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       8,
			IfName:        "eth3",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("172.30.30.40/24")},
		DHCP: netmonitor.DHCPInfo{
			Subnet: ipSubnet("172.30.30.0/24"),
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/eth3-resolv.conf",
			Domains:        []string{"eth3-test-domain"},
			DNSServers:     []net.IP{ipAddress("172.30.30.57")},
		},
		HwAddr: macAddress("02:00:00:00:01:04"),
	}
	eth3Routes = []netmonitor.Route{
		{
			IfIndex: 8,
			Dst:     ipAddressWithPrefix("0.0.0.0/0"),
			Gw:      ipAddress("172.30.30.1"),
			Table:   unix.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 8,
				Dst:       nil,
				Gw:        ipAddress("172.30.30.1"),
				Table:     unix.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
				Protocol:  unix.RTPROT_DHCP,
			},
		},
	}

	// Local IPv4 network instance "ni1"
	ni1UUID   = makeUUID("0d6a128b-b36f-4bd0-a71c-087ba2d71ebc")
	ni1Config = types.NetworkInstanceConfig{
		UUIDandVersion: ni1UUID,
		DisplayName:    "ni1",
		PortLabel:      "ethernet0",
		Type:           types.NetworkInstanceTypeLocal,
		IpType:         types.AddressTypeIPV4,
		Subnet:         deref(ipAddressWithPrefix("10.10.10.0/24")),
	}
	ni1Bridge = nirec.NIBridge{
		NI:         ni1UUID.UUID,
		BrNum:      1,
		MACAddress: macAddress("02:00:00:00:02:01"),
		IPAddress:  ipAddressWithPrefix("10.10.10.1/24"),
		Ports: []nirec.Port{
			{
				LogicalLabel: "ethernet0",
				IfName:       "eth0",
				IsMgmt:       true,
				DhcpType:     types.DhcpTypeClient,
				DNSServers:   []net.IP{ipAddress("8.8.8.8")},
				NTPServers:   []net.IP{ipAddress("132.163.96.5")},
			},
		},
	}
	ni1BridgeIf = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       9,
			IfName:        "bn1",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("10.10.10.1/24")},
		HwAddr:  macAddress("02:00:00:00:02:01"),
	}

	// Switch network instance "ni2" (IPv4)
	ni2UUID   = makeUUID("68a6e10a-78e9-4fc8-ba22-8fcccbbad690")
	ni2Config = types.NetworkInstanceConfig{
		UUIDandVersion: ni2UUID,
		DisplayName:    "ni2",
		PortLabel:      "ethernet1",
		Type:           types.NetworkInstanceTypeSwitch,
		IpType:         types.AddressTypeNone,
	}
	ni2Bridge = nirec.NIBridge{
		NI:         ni2UUID.UUID,
		BrNum:      2,
		MACAddress: macAddress("02:00:00:00:01:02"), // eth1
		Ports: []nirec.Port{
			{
				LogicalLabel: "ethernet1",
				IfName:       "eth1",
				IsMgmt:       false,
				DhcpType:     types.DhcpTypeClient,
				DNSServers:   []net.IP{ipAddress("8.8.8.8")},
				NTPServers:   []net.IP{ipAddress("132.163.96.5")},
			},
		},
	}

	// Local IPv6 network instance "ni3"
	ni3UUID   = makeUUID("6dde0993-b095-44c2-b0bb-f657c5f08a6f")
	ni3Config = types.NetworkInstanceConfig{
		UUIDandVersion: ni3UUID,
		DisplayName:    "ni3",
		PortLabel:      "ethernet2",
		Type:           types.NetworkInstanceTypeLocal,
		IpType:         types.AddressTypeIPV6,
		Subnet:         deref(ipAddressWithPrefix("2001::1111:0000/112")),
		DnsServers:     []net.IP{ipAddress("2001:4860:4860::8888")},
		DnsNameToIPList: []types.DNSNameToIP{
			{
				HostName: "test-hostname",
				IPs:      []net.IP{ipAddress("2001:db8::1")},
			},
		},
	}
	ni3Bridge = nirec.NIBridge{
		NI:         ni3UUID.UUID,
		BrNum:      3,
		MACAddress: macAddress("02:00:00:00:02:03"),
		IPAddress:  ipAddressWithPrefix("2001::1111:1/112"),
		Ports: []nirec.Port{
			{
				LogicalLabel: "ethernet2",
				IfName:       "eth2",
				IsMgmt:       true,
				DhcpType:     types.DhcpTypeClient,
				DNSServers:   []net.IP{ipAddress("2001:4860:4860::8888")},
				NTPServers:   []net.IP{ipAddress("2610:20:6f15:15::27")},
			},
		},
	}
	ni3BridgeIf = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       10,
			IfName:        "bn3",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("2001::1111:1/112")},
		HwAddr:  macAddress("02:00:00:00:02:03"),
	}

	// (IPv6) Switch network instance "ni4"
	ni4UUID   = makeUUID("73cecbd5-102f-41a2-998b-33d42b57cbad")
	ni4Config = types.NetworkInstanceConfig{
		UUIDandVersion: ni4UUID,
		DisplayName:    "ni4",
		PortLabel:      "ethernet2",
		Type:           types.NetworkInstanceTypeSwitch,
		IpType:         types.AddressTypeNone,
	}
	ni4Bridge = nirec.NIBridge{
		NI:         ni4UUID.UUID,
		BrNum:      4,
		MACAddress: macAddress("02:00:00:00:01:03"), // eth2
		Ports: []nirec.Port{
			{
				LogicalLabel: "ethernet2",
				IfName:       "eth2",
				IsMgmt:       true,
				DhcpType:     types.DhcpTypeClient,
				DNSServers:   []net.IP{ipAddress("2001:4860:4860::8888")},
				NTPServers:   []net.IP{ipAddress("2610:0020:6f15:0015::0027")},
			},
		},
	}

	// Local IPv4 network instance "ni5" with multiple ports.
	ni5UUID   = makeUUID("1664a775-9107-4663-976e-c6e3c37bf0e9")
	ni5Config = types.NetworkInstanceConfig{
		UUIDandVersion: ni5UUID,
		DisplayName:    "ni5",
		PortLabel:      "shopfloor",
		Type:           types.NetworkInstanceTypeLocal,
		IpType:         types.AddressTypeIPV4,
		Subnet:         deref(ipAddressWithPrefix("10.10.20.0/24")),
	}
	ni5Bridge = nirec.NIBridge{
		NI:         ni5UUID.UUID,
		BrNum:      5,
		MACAddress: macAddress("02:00:00:00:02:05"),
		IPAddress:  ipAddressWithPrefix("10.10.20.1/24"),
		Ports: []nirec.Port{
			{
				LogicalLabel: "ethernet1",
				IfName:       "eth1",
				IsMgmt:       false,
				DhcpType:     types.DhcpTypeClient,
				SharedLabels: []string{"shopfloor", "portfwd"},
				DNSServers:   []net.IP{ipAddress("8.8.8.8"), ipAddress("1.1.1.1")},
				NTPServers:   []net.IP{ipAddress("132.163.96.5")},
			},
			{
				LogicalLabel: "ethernet3",
				IfName:       "eth3",
				IsMgmt:       false,
				DhcpType:     types.DhcpTypeStatic,
				SharedLabels: []string{"shopfloor"},
				DNSServers:   []net.IP{ipAddress("172.30.30.57")},
				NTPServers:   []net.IP{ipAddress("128.138.140.211")},
			},
		},
	}
	ni5BridgeIf = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       11,
			IfName:        "bn5",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("10.10.20.1/24")},
		HwAddr:  macAddress("02:00:00:00:02:05"),
	}

	// Application "app1"
	app1UUID      = makeUUID("f9a3acd0-85ae-4c1f-8fb2-0ac22b5dd312")
	app1Num       = 1
	app1NetConfig = types.AppNetworkConfig{
		UUIDandVersion: app1UUID,
		DisplayName:    "app1",
		Activate:       true,
		AppNetAdapterList: []types.AppNetAdapterConfig{
			{
				Name:      "adapter1",
				IntfOrder: 0,
				Network:   ni1UUID.UUID,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type: "eidset",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "host",
								Value: "ieee.org",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 2,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "50.50.50.50",
							},
						},
						Actions: []types.ACEAction{
							{
								Limit:      true,
								LimitUnit:  "s",
								LimitRate:  10,
								LimitBurst: 30,
							},
						},
						RuleID: 3,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "protocol",
								Value: "tcp",
							},
							{
								Type:  "lport",
								Value: "2222",
							},
						},
						Actions: []types.ACEAction{
							{
								PortMap:    true,
								TargetPort: 22,
							},
						},
						RuleID: 4,
					},
				},
			},
		},
	}
	app1VIFs = []nirec.AppVIF{
		{
			App:            app1UUID.UUID,
			NI:             ni1UUID.UUID,
			NetAdapterName: "adapter1",
			VIFNum:         1,
			GuestIfMAC:     macAddress("02:00:00:00:04:01"),
			GuestIP:        ipAddress("10.10.10.2"),
		},
	}
	app1VIF1 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       12,
			IfName:        "nbu1x1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 9,
		},
		HwAddr: macAddress("02:00:00:00:03:01"), // host-side
	}

	// Application "app2"
	app2UUID      = makeUUID("fd6147dc-7232-40df-90f3-dbe963d76d4b")
	app2Num       = 2
	app2NetConfig = types.AppNetworkConfig{
		UUIDandVersion: app2UUID,
		DisplayName:    "app2",
		Activate:       true,
		AppNetAdapterList: []types.AppNetAdapterConfig{
			{
				Name:      "adapter1",
				IntfOrder: 0,
				Network:   ni1UUID.UUID,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type:  "protocol",
								Value: "tcp",
							},
							{
								Type:  "lport",
								Value: "2223",
							},
						},
						Actions: []types.ACEAction{
							{
								PortMap:    true,
								TargetPort: 22,
							},
						},
						RuleID: 1,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "0.0.0.0/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 2,
					},
				},
			},
			// Put two VIFs into the same switch NI (just to cover this scenario).
			{
				Name:      "adapter2",
				IntfOrder: 1,
				Network:   ni2UUID.UUID,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "0.0.0.0/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
				},
				AccessVlanID: 10,
			},
			{
				Name:      "adapter3",
				IntfOrder: 2,
				Network:   ni2UUID.UUID,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "0.0.0.0/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
				},
				AccessVlanID: 20,
			},
			{
				Name:      "adapter4",
				IntfOrder: 3,
				Network:   ni5UUID.UUID,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "0.0.0.0/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "protocol",
								Value: "tcp",
							},
							{
								Type:  "lport",
								Value: "2223",
							},
							{
								Type:  "adapter",
								Value: "portfwd",
							},
						},
						Actions: []types.ACEAction{
							{
								PortMap:    true,
								TargetPort: 22,
							},
						},
						RuleID: 2,
					},
				},
			},
		},
	}
	app2VIFs = []nirec.AppVIF{
		{
			App:            app2UUID.UUID,
			NI:             ni1UUID.UUID,
			NetAdapterName: "adapter1",
			VIFNum:         1,
			GuestIfMAC:     macAddress("02:00:00:00:04:02"),
			GuestIP:        ipAddress("10.10.10.3"),
		},
		{
			App:            app2UUID.UUID,
			NI:             ni2UUID.UUID,
			NetAdapterName: "adapter2",
			VIFNum:         2,
			GuestIfMAC:     macAddress("02:00:00:00:04:03"),
		},
		{
			App:            app2UUID.UUID,
			NI:             ni2UUID.UUID,
			NetAdapterName: "adapter3",
			VIFNum:         3,
			GuestIfMAC:     macAddress("02:00:00:00:04:04"),
		},
		{
			App:            app2UUID.UUID,
			NI:             ni5UUID.UUID,
			NetAdapterName: "adapter4",
			VIFNum:         4,
			GuestIfMAC:     macAddress("02:00:00:00:04:07"),
			GuestIP:        ipAddress("10.10.20.2"),
		},
	}
	app2VIF1 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       13,
			IfName:        "nbu1x2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 9,
		},
		HwAddr: macAddress("02:00:00:00:03:02"), // host-side
	}
	app2VIF2 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       14,
			IfName:        "nbu2x2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 4,
		},
		HwAddr: macAddress("02:00:00:00:03:03"), // host-side
	}
	app2VIF3 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       15,
			IfName:        "nbu3x2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 4,
		},
		HwAddr: macAddress("02:00:00:00:03:04"), // host-side
	}
	app2VIF4 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       18,
			IfName:        "nbu4x2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 11,
		},
		HwAddr: macAddress("02:00:00:00:03:07"), // host-side
	}

	// Application "app3"
	app3UUID      = makeUUID("c009c3c0-8342-4a7a-9ec3-672882e9060f")
	app3Num       = 3
	app3NetConfig = types.AppNetworkConfig{
		UUIDandVersion: app3UUID,
		DisplayName:    "app3",
		Activate:       true,
		AppNetAdapterList: []types.AppNetAdapterConfig{
			{
				Name:      "adapter1",
				IntfOrder: 0,
				Network:   ni3UUID.UUID,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type: "eidset",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "host",
								Value: "ieee.org",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 2,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "2610:20:6f96:96::4",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 3,
					},
					// This rule will be skipped on the IPv6 NI.
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "50.50.50.50",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 4,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "protocol",
								Value: "tcp",
							},
							{
								Type:  "lport",
								Value: "2222",
							},
						},
						Actions: []types.ACEAction{
							{
								PortMap:    true,
								TargetPort: 22,
							},
						},
						RuleID: 5,
					},
				},
			},
			{
				Name:      "adapter2",
				IntfOrder: 1,
				Network:   ni4UUID.UUID,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "::/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "0.0.0.0/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 2,
					},
				},
				AccessVlanID: 10,
			},
		},
	}
	app3VIFs = []nirec.AppVIF{
		{
			App:            app3UUID.UUID,
			NI:             ni3UUID.UUID,
			NetAdapterName: "adapter1",
			VIFNum:         1,
			GuestIfMAC:     macAddress("02:00:00:00:04:05"),
			GuestIP:        ipAddress("2001::1111:2"),
		},
		{
			App:            app3UUID.UUID,
			NI:             ni4UUID.UUID,
			NetAdapterName: "adapter2",
			VIFNum:         2,
			GuestIfMAC:     macAddress("02:00:00:00:04:06"),
		},
	}
	app3VIF1 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       16,
			IfName:        "nbu1x3",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 10,
		},
		HwAddr: macAddress("02:00:00:00:03:05"),
	}
	app3VIF2 = netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       17,
			IfName:        "nbu2x3",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 6,
		},
		HwAddr: macAddress("02:00:00:00:03:06"),
	}
)

func TestSingleLocalNI(test *testing.T) {
	t := initTest(test, false)
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.UpdateRoutes(eth0Routes)

	// Test initial reconciliation.
	updatesCh := niReconciler.WatchReconcilerUpdates()
	ctx := reconciler.MockRun(context.Background())
	niReconciler.RunInitialReconcile(ctx)
	var recUpdate nirec.ReconcilerUpdate
	t.Consistently(updatesCh).ShouldNot(Receive(&recUpdate))

	// Create local network instance.
	niStatus, err := niReconciler.AddNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("bn1"))
	t.Expect(niStatus.BrIfIndex).To(Equal(-1)) // not yet known
	t.Expect(niStatus.FailedItems).To(BeEmpty())
	t.Expect(niStatus.Routes).To(HaveLen(1))
	t.Expect(niStatus.Routes[0].IsDefaultRoute()).To(BeTrue())
	t.Expect(netutils.EqualIPs(niStatus.Routes[0].Gateway, eth0Routes[0].Gw)).To(BeTrue())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	networkMonitor.AddOrUpdateInterface(ni1BridgeIf)

	// Check some of the configured items.
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.Bridge{IfName: "bn1"}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANBridge{BridgeIfName: "bn1"}))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "bn1"}, Port: 80},
	))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.Dnsmasq{ListenIf: genericitems.NetworkIf{IfName: "bn1"}}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.Radvd{ListenIf: genericitems.NetworkIf{IfName: "bn1"}}))).To(BeFalse())
	netlinkDefRoute := netlink.Route{
		LinkIndex: 1,
		Dst:       nil,
		Table:     801,
		Gw:        ipAddress("192.168.10.1"),
		Family:    netlink.FAMILY_V4,
		Protocol:  unix.RTPROT_STATIC,
	}
	netmonitorDefRoute := netmonitor.Route{
		IfIndex: 1,
		Dst:     nil,
		Table:   801,
		Gw:      ipAddress("192.168.10.1"),
		Data:    netlinkDefRoute,
	}
	intendedDefRoute := linuxitems.Route{
		Route: netlinkDefRoute,
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth0",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth0"}),
		}}
	t.Expect(itemIsCreated(dg.Reference(intendedDefRoute))).To(BeTrue())
	netlinkUnreachV4Route := netlink.Route{
		Dst:      ipSubnet("0.0.0.0/0"),
		Table:    801,
		Priority: int(^uint32(0)),
		Type:     unix.RTN_UNREACHABLE,
		Family:   netlink.FAMILY_V4,
		Protocol: unix.RTPROT_STATIC,
	}
	netmonitorUnreachV4Route := netmonitor.Route{
		Dst:   ipSubnet("0.0.0.0/0"),
		Table: 801,
		Data:  netlinkUnreachV4Route,
	}
	intendedUnreachV4Route := linuxitems.Route{Route: netlinkUnreachV4Route}
	t.Expect(itemIsCreated(dg.Reference(intendedUnreachV4Route))).To(BeTrue())
	netlinkUnreachV6Route := netlink.Route{
		Dst:      ipSubnet("::/0"),
		Table:    801,
		Priority: int(^uint32(0)),
		Type:     unix.RTN_UNREACHABLE,
		Family:   netlink.FAMILY_V4,
		Protocol: unix.RTPROT_STATIC,
	}
	netmonitorUnreachV6Route := netmonitor.Route{
		Dst:   ipSubnet("::/0"),
		Table: 801,
		Data:  netlinkUnreachV6Route,
	}
	intendedUnreachV6Route := linuxitems.Route{Route: netlinkUnreachV6Route}
	t.Expect(itemIsCreated(dg.Reference(intendedUnreachV6Route))).To(BeTrue())
	networkMonitor.UpdateRoutes(append([]netmonitor.Route{
		netmonitorDefRoute,
		netmonitorUnreachV4Route,
		netmonitorUnreachV6Route,
	}, eth0Routes...))

	// Connect application into the network instance.
	appStatus, err := niReconciler.AddAppConn(ctx, app1NetConfig, app1Num, cnirpc.AppPod{}, app1VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app1UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(1))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x1"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.BrIfIndex).To(Equal(9))

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	intendedPortMapRule1 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 4 for port eth0 IP 192.168.10.5 from inside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x1",
	}
	intendedPortMapRule2 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 4 for port eth0 IP 192.168.10.5 from outside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x1",
	}
	t.Expect(itemIsCreated(dg.Reference(intendedPortMapRule1))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(intendedPortMapRule2))).To(BeTrue())

	// Simulate domainmgr creating the VIF.
	networkMonitor.AddOrUpdateInterface(app1VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.VIFs[0].InProgress).To(BeFalse())
	t.Expect(recUpdate.AppConnStatus.VIFs[0].FailedItems).To(BeEmpty())

	graphs := []dg.GraphR{niReconciler.GetIntendedState(), niReconciler.GetCurrentState()}
	for _, graph := range graphs {
		niSG := graph.SubGraph(nirec.NIToSGName(ni1UUID.UUID))
		t.Expect(niSG).ToNot(BeNil())
		appSG := niSG.SubGraph(nirec.AppConnSGName(app1UUID.UUID, app1VIFs[0].NetAdapterName))
		t.Expect(appSG).ToNot(BeNil())
	}

	// Simulate port losing IP address.
	ips := eth0.IPAddrs
	eth0.IPAddrs = nil
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.UpdateRoutes([]netmonitor.Route{
		netmonitorDefRoute,
		netmonitorUnreachV4Route,
		netmonitorUnreachV6Route,
	})
	// Should receive CurrentStateChanged twice - for route and addr update.
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	// Route not configured anymore.
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Routes).To(BeEmpty())

	t.Consistently(updatesCh).ShouldNot(Receive())
	t.Expect(itemIsCreated(dg.Reference(intendedPortMapRule1))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(intendedPortMapRule2))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(intendedDefRoute))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(intendedUnreachV4Route))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(intendedUnreachV6Route))).To(BeTrue())
	networkMonitor.UpdateRoutes([]netmonitor.Route{
		netmonitorUnreachV4Route,
		netmonitorUnreachV6Route,
	})

	// Simulate port regaining IP address.
	eth0.IPAddrs = ips
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.UpdateRoutes(append([]netmonitor.Route{
		netmonitorUnreachV4Route,
		netmonitorUnreachV6Route,
	}, eth0Routes...))
	// Should receive CurrentStateChanged twice - for route and addr update.
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	// Route configured again.
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Routes).To(HaveLen(1))
	t.Expect(recUpdate.NIStatus.Routes[0].IsDefaultRoute()).To(BeTrue())
	t.Expect(netutils.EqualIPs(recUpdate.NIStatus.Routes[0].Gateway, eth0Routes[0].Gw)).To(BeTrue())

	t.Expect(itemIsCreated(dg.Reference(intendedPortMapRule1))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(intendedPortMapRule2))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(intendedDefRoute))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(intendedUnreachV4Route))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(intendedUnreachV6Route))).To(BeTrue())

	// Disconnect the application.
	appStatus, err = niReconciler.DelAppConn(ctx, app1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app1UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeTrue())
	t.Expect(appStatus.VIFs).To(HaveLen(1))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeFalse())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x1"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	networkMonitor.DelInterface(app1VIF1.Attrs.IfName)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	graphs = []dg.GraphR{niReconciler.GetIntendedState(), niReconciler.GetCurrentState()}
	for _, graph := range graphs {
		niSG := graph.SubGraph(nirec.NIToSGName(ni1UUID.UUID))
		t.Expect(niSG).ToNot(BeNil())
		appSG := niSG.SubGraph(nirec.AppConnSGName(app1UUID.UUID, app1VIFs[0].NetAdapterName))
		t.Expect(appSG).To(BeNil())
	}

	// Delete network instance
	niStatus, err = niReconciler.DelNI(ctx, ni1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("bn1"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())
	networkMonitor.DelInterface(ni1BridgeIf.Attrs.IfName)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	graphs = []dg.GraphR{niReconciler.GetIntendedState(), niReconciler.GetCurrentState()}
	for _, graph := range graphs {
		niSG := graph.SubGraph(nirec.NIToSGName(ni1UUID.UUID))
		t.Expect(niSG).To(BeNil())
	}
}

func TestIPv4LocalAndSwitchNIs(test *testing.T) {
	t := initTest(test, false)
	// Start with eth1 not having yet received IP address from an external DHCP server.
	eth1IPs := eth1.IPAddrs
	eth1.IPAddrs = nil
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(keth1)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.AddOrUpdateInterface(keth1)
	networkMonitor.AddOrUpdateInterface(eth3)
	networkMonitor.AddOrUpdateInterface(keth3)
	var routes []netmonitor.Route
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth3Routes...)
	networkMonitor.UpdateRoutes(routes)
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create 2 local network instances.
	networkMonitor.AddOrUpdateInterface(ni1BridgeIf) // avoid separate notif for bridge if index
	niStatus, err := niReconciler.AddNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("bn1"))
	// Traffic mirroring for Local NI is not implemented.
	t.Expect(niStatus.MirrorIfName).To(BeEmpty())
	t.Expect(niStatus.FailedItems).To(BeEmpty())
	t.Expect(niStatus.Routes).To(HaveLen(1))
	t.Expect(niStatus.Routes[0].IsDefaultRoute()).To(BeTrue())
	t.Expect(netutils.EqualIPs(niStatus.Routes[0].Gateway, eth0Routes[0].Gw)).To(BeTrue())

	var recUpdate nirec.ReconcilerUpdate
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	networkMonitor.AddOrUpdateInterface(ni5BridgeIf)
	niStatus, err = niReconciler.AddNI(ctx, ni5Config, ni5Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.Routes).To(HaveLen(1)) // route for eth3 only, eth1 is without IP
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	// Flow logging is disabled - blocked traffic is immediately dropped by iptables,
	// blackhole is not used.
	dummyIf := linuxitems.DummyIf{
		IfName: "blackhole",
	}
	t.Expect(itemIsCreated(dg.Reference(dummyIf))).To(BeFalse())

	snatRuleNI1 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 0d6a128b-b36f-4bd0-a71c-087ba2d71ebc leaving via port eth0",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemDescription(dg.Reference(snatRuleNI1))).To(ContainSubstring(
		"-o eth0 -s 10.10.10.0/24 -j MASQUERADE"))
	snatRuleNI2 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 1664a775-9107-4663-976e-c6e3c37bf0e9 leaving via port eth1",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemDescription(dg.Reference(snatRuleNI2))).To(ContainSubstring(
		"-o eth1 -s 10.10.20.0/24 -j MASQUERADE"))
	snatRuleNI3 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 1664a775-9107-4663-976e-c6e3c37bf0e9 leaving via port eth3",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemDescription(dg.Reference(snatRuleNI3))).To(ContainSubstring(
		"-o eth3 -s 10.10.20.0/24 -j MASQUERADE"))
	eth0Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    801,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth0",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth0"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(eth0Route))).To(BeTrue())
	eth1Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    805,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth1",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth1"}),
		},
	}
	// eth1 does not yet have IP address assigned
	t.Expect(itemIsCreated(dg.Reference(eth1Route))).To(BeFalse())
	eth3Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    805,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth3",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth3"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(eth3Route))).To(BeTrue())

	// Create switch network instance.
	niStatus, err = niReconciler.AddNI(ctx, ni2Config, ni2Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni2UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("eth1"))
	t.Expect(niStatus.MirrorIfName).To(Equal("eth1-m"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANBridge{BridgeIfName: "eth1"}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "eth1"}, Port: 80,
		}))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.DummyIf{IfName: "eth1-m"}))).To(BeTrue())
	t.Expect(itemCountWithType(linuxitems.TCIngressTypename)).To(Equal(1))
	t.Expect(itemCountWithType(linuxitems.TCMirrorTypename)).To(Equal(4))

	// Simulate eth1 getting an IP address.
	eth1.IPAddrs = eth1IPs
	networkMonitor.AddOrUpdateInterface(eth1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth1Routes...)
	routes = append(routes, eth3Routes...)
	networkMonitor.UpdateRoutes(routes)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.NI).To(Equal(ni5UUID.UUID))
	t.Expect(recUpdate.NIStatus.Routes).To(HaveLen(2)) // Now has routes for both eth1 and eth3

	t.Expect(itemIsCreated(dg.Reference(eth1Route))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "eth1"}, Port: 80,
		}))).To(BeTrue())

	// Connect application into network instances.
	// VIFs on the switch NI will receive IPs later.
	appStatus, err := niReconciler.AddAppConn(ctx, app2NetConfig, app2Num, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x2"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[1].NetAdapterName).To(Equal("adapter2"))
	t.Expect(appStatus.VIFs[1].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[1].HostIfName).To(Equal("nbu2x2"))
	t.Expect(appStatus.VIFs[1].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[2].NetAdapterName).To(Equal("adapter3"))
	t.Expect(appStatus.VIFs[2].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[2].HostIfName).To(Equal("nbu3x2"))
	t.Expect(appStatus.VIFs[2].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[3].NetAdapterName).To(Equal("adapter4"))
	t.Expect(appStatus.VIFs[3].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[3].HostIfName).To(Equal("nbu4x2"))
	t.Expect(appStatus.VIFs[3].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	t.Expect(itemCountWithType(linuxitems.TCIngressTypename)).To(Equal(1))
	t.Expect(itemCountWithType(linuxitems.TCMirrorTypename)).To(Equal(4))

	// Simulate domainmgr creating all VIFs.
	networkMonitor.AddOrUpdateInterface(app2VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF2)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF3)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF4)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	for i := 0; i < 4; i++ {
		t.Expect(recUpdate.AppConnStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(recUpdate.AppConnStatus.VIFs[i].FailedItems).To(BeEmpty())
	}

	// 2 VIFs and one device port are connected to switch NI.
	t.Expect(itemCountWithType(linuxitems.TCIngressTypename)).To(Equal(1 * 3))
	t.Expect(itemCountWithType(linuxitems.TCMirrorTypename)).To(Equal(4 * 3))

	ni1PortMapRule1 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 1 for port eth0 IP 192.168.10.5 from inside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x2",
	}
	ni1PortMapRule2 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 1 for port eth0 IP 192.168.10.5 from outside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x2",
	}
	t.Expect(itemIsCreated(dg.Reference(ni1PortMapRule1))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(ni1PortMapRule2))).To(BeTrue())

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANPort{
			BridgeIfName: "bn1",
			PortIfName:   "nbu1x2",
		}))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANPort{
			BridgeIfName: "eth1",
			PortIfName:   "nbu2x2",
		}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANPort{
			BridgeIfName: "eth1",
			PortIfName:   "nbu3x2",
		}))).To(BeTrue())

	vif2Eidset := itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu2x2"}))
	t.Expect(vif2Eidset).To(ContainSubstring("entries: []"))
	vif3Eidset := itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu3x2"}))
	t.Expect(vif3Eidset).To(ContainSubstring("entries: []"))

	// Simulate VIF2 and VIF3 getting IP addresses from an external DHCP server.
	app2VIFs[1].GuestIP = ipAddress("172.20.0.101")
	app2VIFs[2].GuestIP = ipAddress("172.20.0.102")
	appStatus, err = niReconciler.UpdateAppConn(ctx, app2NetConfig, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(appStatus.VIFs[i].FailedItems).To(BeEmpty())
	}

	vif2Eidset = itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu2x2"}))
	t.Expect(vif2Eidset).To(ContainSubstring("entries: [172.20.0.101]"))
	vif3Eidset = itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu3x2"}))
	t.Expect(vif3Eidset).To(ContainSubstring("entries: [172.20.0.102]"))

	// Disconnect the application.
	_, err = niReconciler.DelAppConn(ctx, app1UUID.UUID) // wrong UUID
	t.Expect(err).To(HaveOccurred())
	appStatus, err = niReconciler.DelAppConn(ctx, app2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeTrue())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
	}

	// Delete network instances
	niStatus, err = niReconciler.DelNI(ctx, ni1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni2UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni5UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni5UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())

	// Revert back to VIF2 and VIF3 not having IP addresses.
	app2VIFs[1].GuestIP = nil
	app2VIFs[2].GuestIP = nil
}

func TestIPv4LocalAndSwitchNIsWithFlowlogging(test *testing.T) {
	t := initTest(test, false)

	ni1Config.EnableFlowlog = true
	ni2Config.EnableFlowlog = true
	ni5Config.EnableFlowlog = true

	// Start with eth1 not having yet received IP address from an external DHCP server.
	eth1IPs := eth1.IPAddrs
	eth1.IPAddrs = nil
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(keth1)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.AddOrUpdateInterface(keth1)
	networkMonitor.AddOrUpdateInterface(eth3)
	networkMonitor.AddOrUpdateInterface(keth3)
	var routes []netmonitor.Route
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth3Routes...)
	networkMonitor.UpdateRoutes(routes)
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create 2 local network instances.
	networkMonitor.AddOrUpdateInterface(ni1BridgeIf) // avoid separate notif for bridge if index
	niStatus, err := niReconciler.AddNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("bn1"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())

	var recUpdate nirec.ReconcilerUpdate
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	networkMonitor.AddOrUpdateInterface(ni5BridgeIf)
	niStatus, err = niReconciler.AddNI(ctx, ni5Config, ni5Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	fmt.Println(recUpdate.NIStatus)
	fmt.Println(niStatus)
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	// Check Blackhole configuration.
	dummyIf := linuxitems.DummyIf{
		IfName: "blackhole",
	}
	t.Expect(itemIsCreated(dg.Reference(dummyIf))).To(BeTrue())
	mask := uint32(0x800000)
	iprule := linuxitems.IPRule{
		Priority: 1000,
		Table:    400,
		Mark:     0x800000,
		Mask:     &mask,
	}
	t.Expect(itemIsCreated(dg.Reference(iprule))).To(BeTrue())
	netlinkUnreachV4Route := netlink.Route{
		Table:    400,
		Type:     unix.RTN_UNREACHABLE,
		Family:   netlink.FAMILY_V4,
		Protocol: unix.RTPROT_STATIC,
	}
	intendedUnreachV4Route := linuxitems.Route{
		Route: netlinkUnreachV4Route,
		OutputIf: genericitems.NetworkIf{
			IfName:  "blackhole",
			ItemRef: dg.Reference(genericitems.Port{IfName: "blackhole"}),
		},
	}
	fmt.Println(dg.Reference(intendedUnreachV4Route))
	t.Expect(itemIsCreated(dg.Reference(intendedUnreachV4Route))).To(BeTrue())

	snatRuleNI1 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 0d6a128b-b36f-4bd0-a71c-087ba2d71ebc leaving via port eth0",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemDescription(dg.Reference(snatRuleNI1))).To(ContainSubstring(
		"-o eth0 -s 10.10.10.0/24 -j MASQUERADE"))
	snatRuleNI2 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 1664a775-9107-4663-976e-c6e3c37bf0e9 leaving via port eth1",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemDescription(dg.Reference(snatRuleNI2))).To(ContainSubstring(
		"-o eth1 -s 10.10.20.0/24 -j MASQUERADE"))
	snatRuleNI3 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 1664a775-9107-4663-976e-c6e3c37bf0e9 leaving via port eth3",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemDescription(dg.Reference(snatRuleNI3))).To(ContainSubstring(
		"-o eth3 -s 10.10.20.0/24 -j MASQUERADE"))
	eth0Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    801,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth0",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth0"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(eth0Route))).To(BeTrue())
	eth1Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    805,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth1",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth1"}),
		},
	}
	// eth1 does not yet have IP address assigned
	t.Expect(itemIsCreated(dg.Reference(eth1Route))).To(BeFalse())
	eth3Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    805,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth3",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth3"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(eth3Route))).To(BeTrue())

	// Create switch network instance.
	niStatus, err = niReconciler.AddNI(ctx, ni2Config, ni2Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni2UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("eth1"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANBridge{BridgeIfName: "eth1"}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "eth1"}, Port: 80,
		}))).To(BeFalse())

	// Simulate eth1 getting an IP address.
	eth1.IPAddrs = eth1IPs
	networkMonitor.AddOrUpdateInterface(eth1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth1Routes...)
	routes = append(routes, eth3Routes...)
	networkMonitor.UpdateRoutes(routes)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.NI).To(Equal(ni5UUID.UUID))
	t.Expect(recUpdate.NIStatus.Routes).To(HaveLen(2)) // Now has routes for both eth1 and eth3

	t.Expect(itemIsCreated(dg.Reference(eth1Route))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "eth1"}, Port: 80,
		}))).To(BeTrue())

	// Connect application into network instances.
	// VIFs on the switch NI will receive IPs later.
	appStatus, err := niReconciler.AddAppConn(ctx, app2NetConfig, app2Num, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x2"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[1].NetAdapterName).To(Equal("adapter2"))
	t.Expect(appStatus.VIFs[1].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[1].HostIfName).To(Equal("nbu2x2"))
	t.Expect(appStatus.VIFs[1].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[2].NetAdapterName).To(Equal("adapter3"))
	t.Expect(appStatus.VIFs[2].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[2].HostIfName).To(Equal("nbu3x2"))
	t.Expect(appStatus.VIFs[2].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[3].NetAdapterName).To(Equal("adapter4"))
	t.Expect(appStatus.VIFs[3].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[3].HostIfName).To(Equal("nbu4x2"))
	t.Expect(appStatus.VIFs[3].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	// Simulate domainmgr creating all VIFs.
	networkMonitor.AddOrUpdateInterface(app2VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF2)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF3)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF4)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	for i := 0; i < 4; i++ {
		t.Expect(recUpdate.AppConnStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(recUpdate.AppConnStatus.VIFs[i].FailedItems).To(BeEmpty())
	}

	ni1PortMapRule1 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 1 for port eth0 IP 192.168.10.5 from inside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x2",
	}
	ni1PortMapRule2 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 1 for port eth0 IP 192.168.10.5 from outside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x2",
	}
	t.Expect(itemIsCreated(dg.Reference(ni1PortMapRule1))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(ni1PortMapRule2))).To(BeTrue())

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANPort{
			BridgeIfName: "bn1",
			PortIfName:   "nbu1x2",
		}))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANPort{
			BridgeIfName: "eth1",
			PortIfName:   "nbu2x2",
		}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANPort{
			BridgeIfName: "eth1",
			PortIfName:   "nbu3x2",
		}))).To(BeTrue())

	vif2Eidset := itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu2x2"}))
	t.Expect(vif2Eidset).To(ContainSubstring("entries: []"))
	vif3Eidset := itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu3x2"}))
	t.Expect(vif3Eidset).To(ContainSubstring("entries: []"))

	// Simulate VIF2 and VIF3 getting IP addresses from an external DHCP server.
	app2VIFs[1].GuestIP = ipAddress("172.20.0.101")
	app2VIFs[2].GuestIP = ipAddress("172.20.0.102")
	appStatus, err = niReconciler.UpdateAppConn(ctx, app2NetConfig, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(appStatus.VIFs[i].FailedItems).To(BeEmpty())
	}

	vif2Eidset = itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu2x2"}))
	t.Expect(vif2Eidset).To(ContainSubstring("entries: [172.20.0.101]"))
	vif3Eidset = itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu3x2"}))
	t.Expect(vif3Eidset).To(ContainSubstring("entries: [172.20.0.102]"))

	// Check rules used to mark traffic for flow-logging purposes.
	vif1IPRule := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 1 for port eth0 IP 192.168.10.5 from outside",
		Table:     "mangle",
		ChainName: "PREROUTING-nbu1x2-IN",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif1IPRule))).To(ContainSubstring(
		"-i eth0 -d 192.168.10.5 -p tcp --dport 2223 -j bn1-nbu1x2-1"))

	vif2IPRuleIngress := iptables.Rule{
		RuleLabel: "User-configured ALLOW ACL rule 1 for ingress port eth1",
		Table:     "mangle",
		ChainName: "PREROUTING-nbu2x2-IN",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif2IPRuleIngress))).To(ContainSubstring(
		"-i eth1 -s 0.0.0.0/0 -j eth1-nbu2x2-1"))
	vif2IPRuleEgress := iptables.Rule{
		RuleLabel: "User-configured ALLOW ACL rule 1",
		Table:     "mangle",
		ChainName: "PREROUTING-nbu2x2-OUT",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif2IPRuleEgress))).To(ContainSubstring(
		"-d 0.0.0.0/0 -j eth1-nbu2x2-1"))

	vif3IPRuleIngress := iptables.Rule{
		RuleLabel: "User-configured ALLOW ACL rule 1 for ingress port eth1",
		Table:     "mangle",
		ChainName: "PREROUTING-nbu3x2-IN",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif3IPRuleIngress))).To(ContainSubstring(
		"-i eth1 -s 0.0.0.0/0 -j eth1-nbu3x2-1"))
	vif3IPRuleEgress := iptables.Rule{
		RuleLabel: "User-configured ALLOW ACL rule 1",
		Table:     "mangle",
		ChainName: "PREROUTING-nbu3x2-OUT",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif3IPRuleEgress))).To(ContainSubstring(
		"-d 0.0.0.0/0 -j eth1-nbu3x2-1"))

	vif4IPRule1 := iptables.Rule{
		RuleLabel: "User-configured ALLOW ACL rule 1",
		Table:     "mangle",
		ChainName: "PREROUTING-nbu4x2-OUT",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif4IPRule1))).To(ContainSubstring(
		"-d 0.0.0.0/0 -j bn5-nbu4x2-1"))
	vif4IPRule2 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 2 for port eth1 IP 172.20.0.40 from outside",
		Table:     "mangle",
		ChainName: "PREROUTING-nbu4x2-IN",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif4IPRule2))).To(ContainSubstring(
		"-i eth1 -d 172.20.0.40 -p tcp --dport 2223 -j bn5-nbu4x2-2"))

	// Disconnect the application.
	_, err = niReconciler.DelAppConn(ctx, app1UUID.UUID) // wrong UUID
	t.Expect(err).To(HaveOccurred())
	appStatus, err = niReconciler.DelAppConn(ctx, app2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeTrue())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
	}

	// Delete network instances
	niStatus, err = niReconciler.DelNI(ctx, ni1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni2UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni5UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni5UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())

	// Revert back to VIF2 and VIF3 not having IP addresses.
	app2VIFs[1].GuestIP = nil
	app2VIFs[2].GuestIP = nil

	// Revert back to flow logging being disabled.
	ni1Config.EnableFlowlog = false
	ni2Config.EnableFlowlog = false
	ni5Config.EnableFlowlog = false
}

func TestIPv6LocalAndSwitchNIs(test *testing.T) {
	t := initTest(test, false)
	networkMonitor.AddOrUpdateInterface(keth2)
	networkMonitor.AddOrUpdateInterface(eth2)
	networkMonitor.UpdateRoutes(eth2Routes)
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create local network instance.
	networkMonitor.AddOrUpdateInterface(ni3BridgeIf)
	niStatus, err := niReconciler.AddNI(ctx, ni3Config, ni3Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni3UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("bn3"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())

	var recUpdate nirec.ReconcilerUpdate
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	// Create switch network instance.
	niStatus, err = niReconciler.AddNI(ctx, ni4Config, ni4Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni4UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("eth2"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "bn3"}, Port: 80,
		}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "eth2"}, Port: 80,
		}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANBridge{BridgeIfName: "eth2"}))).To(BeTrue())

	// Connect application into network instances.
	// VIF on the switch NI will receive IPv6 address later.
	appStatus, err := niReconciler.AddAppConn(ctx, app3NetConfig, app3Num, cnirpc.AppPod{}, app3VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app3UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(2))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x3"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[1].NetAdapterName).To(Equal("adapter2"))
	t.Expect(appStatus.VIFs[1].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[1].HostIfName).To(Equal("nbu2x3"))
	t.Expect(appStatus.VIFs[1].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	// Simulate domainmgr creating both VIFs.
	networkMonitor.AddOrUpdateInterface(app3VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app3VIF2)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.VIFs[0].InProgress).To(BeFalse())
	t.Expect(recUpdate.AppConnStatus.VIFs[1].InProgress).To(BeFalse())

	vif2VLAN := linuxitems.VLANPort{
		BridgeIfName: "eth2",
		PortIfName:   "nbu2x3",
	}
	t.Expect(itemIsCreated(dg.Reference(vif2VLAN))).To(BeTrue())
	t.Expect(itemDescription(dg.Reference(vif2VLAN))).To(ContainSubstring(
		"accessPort: {vid: 10}"))

	// Simulate VIF2 obtaining an IPv6 address.
	app3VIFs[1].GuestIP = ipAddress("2001::101")
	_, err = niReconciler.UpdateAppConn(ctx, app3NetConfig, cnirpc.AppPod{}, app3VIFs)
	t.Expect(err).ToNot(HaveOccurred())

	// Check items created in the scope of NI3.
	ni3NetlinkDefRoute := netlink.Route{
		LinkIndex: 6,
		Dst:       ipAddressWithPrefix("::/0"),
		Table:     803,
		Gw:        ipAddress("2001::1"),
		Family:    netlink.FAMILY_V4,
		Protocol:  unix.RTPROT_STATIC,
	}
	ni3DefRoute := linuxitems.Route{
		Route: ni3NetlinkDefRoute,
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth2",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth2"}),
		}}
	t.Expect(itemIsCreated(dg.Reference(ni3DefRoute))).To(BeTrue())
	radvd := genericitems.Radvd{ListenIf: genericitems.NetworkIf{IfName: "bn3"}}
	t.Expect(itemIsCreated(dg.Reference(radvd))).To(BeTrue())
	dnsmasq := genericitems.Dnsmasq{ListenIf: genericitems.NetworkIf{IfName: "bn3"}}
	t.Expect(itemDescription(dg.Reference(dnsmasq))).To(ContainSubstring(
		"subnet: 2001::1111:0/112"))
	t.Expect(itemDescription(dg.Reference(dnsmasq))).To(ContainSubstring(
		"gatewayIP: 2001::1111:1"))
	t.Expect(itemDescription(dg.Reference(dnsmasq))).To(ContainSubstring(
		"withDefaultRoute: true"))
	t.Expect(itemDescription(dg.Reference(dnsmasq))).To(ContainSubstring(
		"dnsServers: [2001:4860:4860::8888]"))
	t.Expect(itemDescription(dg.Reference(dnsmasq))).To(ContainSubstring(
		"ntpServers: [2610:20:6f15:15::27]"))
	t.Expect(itemDescription(dg.Reference(dnsmasq))).To(ContainSubstring(
		"staticEntries: [{test-hostname [2001:db8::1]} {router [2001::1111:1]} {app3 [2001::1111:2]}]"))
	httpSrvN3 := genericitems.HTTPServer{
		ListenIf: genericitems.NetworkIf{IfName: "bn3"}, Port: 80}
	t.Expect(itemDescription(dg.Reference(httpSrvN3))).To(ContainSubstring(
		"listenIP: 2001::1111:1"))
	vif1Eidset := linuxitems.IPSet{SetName: "ipv6.eids.nbu1x3"}
	t.Expect(itemDescription(dg.Reference(vif1Eidset))).To(ContainSubstring(
		"entries: [2001:db8::1 2001::1111:2]"))
	vif1IPRuleIngress := iptables.Rule{
		RuleLabel: "User configured ALLOW ACL rule 3",
		Table:     "filter",
		ChainName: "FORWARD-nbu1x3",
		ForIPv6:   true,
	}
	t.Expect(itemDescription(dg.Reference(vif1IPRuleIngress))).To(ContainSubstring(
		"-s 2610:20:6f96:96::4/128 -j ACCEPT"))
	vif1IPRuleEgress := iptables.Rule{
		RuleLabel: "User configured ALLOW ACL rule 3",
		Table:     "raw",
		ChainName: "PREROUTING-nbu1x3",
		ForIPv6:   true,
	}
	t.Expect(itemDescription(dg.Reference(vif1IPRuleIngress))).To(ContainSubstring(
		"-s 2610:20:6f96:96::4/128 -j ACCEPT"))
	t.Expect(itemDescription(dg.Reference(vif1IPRuleEgress))).To(ContainSubstring(
		"-d 2610:20:6f96:96::4/128 -j ACCEPT"))
	ni3PortMapRuleIn := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 5 for port eth2 IP 2001::20 from inside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x3",
		ForIPv6:   true,
	}
	ni3PortMapRuleOut := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 5 for port eth2 IP 2001::20 from outside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu1x3",
		ForIPv6:   true,
	}
	t.Expect(itemIsCreated(dg.Reference(ni3PortMapRuleIn))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(ni3PortMapRuleOut))).To(BeTrue())

	// Check items created in the scope of NI4.
	httpSrvN4 := genericitems.HTTPServer{
		ListenIf: genericitems.NetworkIf{IfName: "eth2"}, Port: 80}
	t.Expect(itemDescription(dg.Reference(httpSrvN4))).To(ContainSubstring(
		"listenIP: 2001::20"))
	vif2Eidset := linuxitems.IPSet{SetName: "ipv6.eids.nbu2x3"}
	t.Expect(itemDescription(dg.Reference(vif2Eidset))).To(ContainSubstring(
		"entries: [2001::101]"))
	vif2IPv6RuleIngress := iptables.Rule{
		RuleLabel: "User configured ALLOW ACL rule 1",
		Table:     "filter",
		ChainName: "FORWARD-nbu2x3",
		ForIPv6:   true,
	}
	t.Expect(itemDescription(dg.Reference(vif2IPv6RuleIngress))).To(ContainSubstring(
		"-s ::/0 -j ACCEPT"))
	vif2IPv6RuleEgress := iptables.Rule{
		RuleLabel: "User configured ALLOW ACL rule 1",
		Table:     "raw",
		ChainName: "PREROUTING-nbu2x3",
		ForIPv6:   true,
	}
	t.Expect(itemDescription(dg.Reference(vif2IPv6RuleEgress))).To(ContainSubstring(
		"-d ::/0 -j ACCEPT"))
	vif2IPv4RuleIngress := iptables.Rule{
		RuleLabel: "User configured ALLOW ACL rule 2",
		Table:     "filter",
		ChainName: "FORWARD-nbu2x3",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif2IPv4RuleIngress))).To(ContainSubstring(
		"-s 0.0.0.0/0 -j ACCEPT"))
	vif2IPv4RuleEgress := iptables.Rule{
		RuleLabel: "User configured ALLOW ACL rule 2",
		Table:     "raw",
		ChainName: "PREROUTING-nbu2x3",
		ForIPv6:   false,
	}
	t.Expect(itemDescription(dg.Reference(vif2IPv4RuleEgress))).To(ContainSubstring(
		"-d 0.0.0.0/0 -j ACCEPT"))

	// Do not run dnsmasq and radvd for the switch network instance.
	t.Expect(itemCountWithType(genericitems.DnsmasqTypename)).To(Equal(1))
	t.Expect(itemCountWithType(genericitems.RadvdTypename)).To(Equal(1))

	// Disconnect the application.
	_, err = niReconciler.DelAppConn(ctx, app3UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())

	// Delete network instances
	_, err = niReconciler.DelNI(ctx, ni3UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	_, err = niReconciler.DelNI(ctx, ni4UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())

	// Revert back to VIF2 not having IP address.
	app3VIFs[1].GuestIP = nil
}

func TestAirGappedLocalAndSwitchNIs(test *testing.T) {
	t := initTest(test, false)
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create 2 local network instances but make them both air-gapped.
	ni1Ports := ni1Bridge.Ports
	ni1Bridge.Ports = []nirec.Port{}
	networkMonitor.AddOrUpdateInterface(ni1BridgeIf)
	niStatus, err := niReconciler.AddNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("bn1"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())

	var recUpdate nirec.ReconcilerUpdate
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	ni5Ports := ni5Bridge.Ports
	ni5Bridge.Ports = []nirec.Port{}
	networkMonitor.AddOrUpdateInterface(ni5BridgeIf)
	niStatus, err = niReconciler.AddNI(ctx, ni5Config, ni5Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	// There should not be MASQUERADE iptables rule or the default gateway route.
	snatRuleNI1 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 0d6a128b-b36f-4bd0-a71c-087ba2d71ebc",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemIsCreated(dg.Reference(snatRuleNI1))).To(BeFalse())
	snatRuleNI5 := iptables.Rule{
		RuleLabel: "SNAT traffic from NI 1664a775-9107-4663-976e-c6e3c37bf0e9",
		Table:     "nat",
		ChainName: "POSTROUTING-apps",
	}
	t.Expect(itemIsCreated(dg.Reference(snatRuleNI5))).To(BeFalse())
	eth0Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    801,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth0",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth0"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(eth0Route))).To(BeFalse())
	eth1Route := linuxitems.Route{
		Route: netlink.Route{
			Table:    805,
			Dst:      &net.IPNet{IP: net.IP{0x0, 0x0, 0x0, 0x0}, Mask: net.IPMask{0x0, 0x0, 0x0, 0x0}},
			Family:   netlink.FAMILY_V4,
			Protocol: unix.RTPROT_STATIC,
		},
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth1",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth1"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(eth1Route))).To(BeFalse())

	// Metadata server is run even in the air-gapped mode, however.
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "bn1"}, Port: 80,
		}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "bn5"}, Port: 80,
		}))).To(BeTrue())

	// Create switch network instance but make it air-gapped.
	ni2AirGappedBridgeIf := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       99,
			IfName:        "bn2",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:02:02"),
	}
	networkMonitor.AddOrUpdateInterface(ni2AirGappedBridgeIf)
	ni2Ports := ni2Bridge.Ports
	ni2Bridge.Ports = []nirec.Port{}
	niStatus, err = niReconciler.AddNI(ctx, ni2Config, ni2Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni2UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeFalse())
	t.Expect(niStatus.InProgress).To(BeFalse())
	t.Expect(niStatus.BrIfName).To(Equal("bn2"))
	t.Expect(niStatus.FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANBridge{BridgeIfName: "bn2"}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		genericitems.HTTPServer{
			ListenIf: genericitems.NetworkIf{IfName: "bn2"}, Port: 80,
		}))).To(BeFalse())

	// Connect application into network instances.
	appStatus, err := niReconciler.AddAppConn(ctx, app2NetConfig, app2Num, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x2"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[1].NetAdapterName).To(Equal("adapter2"))
	t.Expect(appStatus.VIFs[1].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[1].HostIfName).To(Equal("nbu2x2"))
	t.Expect(appStatus.VIFs[1].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[2].NetAdapterName).To(Equal("adapter3"))
	t.Expect(appStatus.VIFs[2].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[2].HostIfName).To(Equal("nbu3x2"))
	t.Expect(appStatus.VIFs[2].FailedItems).To(BeEmpty())
	t.Expect(appStatus.VIFs[3].NetAdapterName).To(Equal("adapter4"))
	t.Expect(appStatus.VIFs[3].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[3].HostIfName).To(Equal("nbu4x2"))
	t.Expect(appStatus.VIFs[3].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	// Simulate domainmgr creating all VIFs.
	app2VIF2.Attrs.MasterIfIndex = 99 // using air-gapped bridge instead of eth1
	app2VIF3.Attrs.MasterIfIndex = 99 // using air-gapped bridge instead of eth1
	networkMonitor.AddOrUpdateInterface(app2VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF2)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF3)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF4)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	for i := 0; i < 4; i++ {
		t.Expect(recUpdate.AppConnStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(recUpdate.AppConnStatus.VIFs[i].FailedItems).To(BeEmpty())
	}

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANPort{
			BridgeIfName: "bn1",
			PortIfName:   "nbu1x2",
		}))).To(BeFalse())
	vif2VLANPort := linuxitems.VLANPort{
		BridgeIfName: "bn2",
		PortIfName:   "nbu2x2",
	}
	vif3VLANPort := linuxitems.VLANPort{
		BridgeIfName: "bn2",
		PortIfName:   "nbu3x2",
	}
	t.Expect(itemDescription(dg.Reference(vif2VLANPort))).To(ContainSubstring(
		"accessPort: {vid: 10}"))
	t.Expect(itemDescription(dg.Reference(vif3VLANPort))).To(ContainSubstring(
		"accessPort: {vid: 20}"))

	vif1Eidset := itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu1x2"}))
	t.Expect(vif1Eidset).To(ContainSubstring("entries: [10.10.10.3]"))
	vif2Eidset := itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu2x2"}))
	t.Expect(vif2Eidset).To(ContainSubstring("entries: []"))
	vif3Eidset := itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu3x2"}))
	t.Expect(vif3Eidset).To(ContainSubstring("entries: []"))

	// Simulate that app2 is running DHCP server and gave VIF2 and VIF3 IP addresses.
	app2VIFs[1].GuestIP = ipAddress("192.168.1.1")
	app2VIFs[2].GuestIP = ipAddress("192.168.1.2")
	appStatus, err = niReconciler.UpdateAppConn(ctx, app2NetConfig, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(appStatus.VIFs[i].FailedItems).To(BeEmpty())
	}

	vif2Eidset = itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu2x2"}))
	t.Expect(vif2Eidset).To(ContainSubstring("entries: [192.168.1.1]"))
	vif3Eidset = itemDescription(dg.Reference(linuxitems.IPSet{SetName: "ipv4.eids.nbu3x2"}))
	t.Expect(vif3Eidset).To(ContainSubstring("entries: [192.168.1.2]"))

	// Disconnect the application.
	appStatus, err = niReconciler.DelAppConn(ctx, app2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeTrue())
	t.Expect(appStatus.VIFs).To(HaveLen(4))
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
	}

	// Delete network instances
	niStatus, err = niReconciler.DelNI(ctx, ni1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni2UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni5UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni5UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())

	// Revert back to NI1, NI2 and NI5 having external connectivity.
	ni1Bridge.Ports = ni1Ports
	ni2Bridge.Ports = ni2Ports
	ni5Bridge.Ports = ni5Ports
	app2VIF2.Attrs.MasterIfIndex = 4
	app2VIF3.Attrs.MasterIfIndex = 4
}

func TestStaticAndConnectedRoutes(test *testing.T) {
	t := initTest(test, false)
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.AddOrUpdateInterface(eth3)
	var routes []netmonitor.Route
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth1Routes...)
	routes = append(routes, eth3Routes...)
	networkMonitor.UpdateRoutes(routes)
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create network instances used by app2.
	networkMonitor.AddOrUpdateInterface(ni1BridgeIf)
	_, err := niReconciler.AddNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	var recUpdate nirec.ReconcilerUpdate
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	_, err = niReconciler.AddNI(ctx, ni2Config, ni2Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	// NI5 will propagate user-configured DNS server to apps.
	ni5Config.DnsServers = []net.IP{ipAddress("1.1.1.1")}
	networkMonitor.AddOrUpdateInterface(ni5BridgeIf)
	_, err = niReconciler.AddNI(ctx, ni5Config, ni5Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))

	// Connect application into network instances.
	// VIFs on the switch NI will receive IPs later.
	appStatus, err := niReconciler.AddAppConn(ctx, app2NetConfig, app2Num, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	// Simulate domainmgr creating all VIFs.
	networkMonitor.AddOrUpdateInterface(app2VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF2)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF3)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	networkMonitor.AddOrUpdateInterface(app2VIF4)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	for i := 0; i < 4; i++ {
		t.Expect(recUpdate.AppConnStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(recUpdate.AppConnStatus.VIFs[i].FailedItems).To(BeEmpty())
	}

	// Simulate VIF2 and VIF3 getting IP addresses from an external DHCP server.
	app2VIFs[1].GuestIP = ipAddress("172.20.0.101")
	app2VIFs[2].GuestIP = ipAddress("172.20.0.102")
	appStatus, err = niReconciler.UpdateAppConn(ctx, app2NetConfig, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
		t.Expect(appStatus.VIFs[i].FailedItems).To(BeEmpty())
	}
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))

	// Check that port forwarding in NI5 is enabled only for eth1 (and not for eth3).
	ni5PortMapRule1 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 2 for port eth1 IP 172.20.0.40 from inside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu4x2",
	}
	ni5PortMapRule2 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 2 for port eth1 IP 172.20.0.40 from outside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu4x2",
	}
	t.Expect(itemIsCreated(dg.Reference(ni5PortMapRule1))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(ni5PortMapRule2))).To(BeTrue())
	ni5PortMapRule3 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 2 for port eth3 IP 172.30.30.40 from inside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu4x2",
	}
	ni5PortMapRule4 := iptables.Rule{
		RuleLabel: "User-configured PORTMAP ACL rule 2 for port eth3 IP 172.30.30.40 from outside",
		Table:     "nat",
		ChainName: "PREROUTING-nbu4x2",
	}
	t.Expect(itemIsCreated(dg.Reference(ni5PortMapRule3))).ToNot(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(ni5PortMapRule4))).ToNot(BeTrue())

	// Both N1 and N5 should publish default route.
	// Even though N5 uses app-shared ports eth1 & eth3, these port both have default routes.
	dnsmasqNI1 := genericitems.Dnsmasq{ListenIf: genericitems.NetworkIf{IfName: "bn1"}}
	dnsmasqNI5 := genericitems.Dnsmasq{ListenIf: genericitems.NetworkIf{IfName: "bn5"}}
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"gatewayIP: 10.10.10.1"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"withDefaultRoute: true"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"gatewayIP: 10.10.20.1"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"withDefaultRoute: true"))

	// When eth1 & eth3 both loose the default route, N5 should stop propagating it.
	networkMonitor.UpdateRoutes(eth0Routes)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"gatewayIP: 10.10.10.1"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"withDefaultRoute: true"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"gatewayIP: 10.10.20.1"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"withDefaultRoute: false"))

	// Once at least one of eth1 or eth3 obtains default route, NI5 should start
	// propagating it again.
	routes = nil
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth1Routes...) // eth1 has default route again
	networkMonitor.UpdateRoutes(routes)
	t.Eventually(func() string {
		niReconciler.ResumeReconcile(ctx)
		return itemDescription(dg.Reference(dnsmasqNI5))
	}).Should(ContainSubstring("withDefaultRoute: true"))

	// Connected routes (of local NIs) should not be propagated to applications.
	// Only host routes for DNS and NTP servers should be.
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.10.1}]"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.20.1} {128.138.140.211/32 10.10.20.1} {1.1.1.1/32 10.10.20.1}]"))

	// Enable propagation of connected routes for NI1 (only).
	ni1Config.PropagateConnRoutes = true
	_, err = niReconciler.UpdateNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.10.1} {192.168.10.0/24 10.10.10.1}]"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.20.1} {128.138.140.211/32 10.10.20.1} {1.1.1.1/32 10.10.20.1}]"))

	// Enable propagation of connected routes for NI5 as well.
	ni5Config.PropagateConnRoutes = true
	_, err = niReconciler.UpdateNI(ctx, ni5Config, ni5Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.10.1} {192.168.10.0/24 10.10.10.1}]"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.20.1} {128.138.140.211/32 10.10.20.1} " +
			"{1.1.1.1/32 10.10.20.1} {172.20.0.0/16 10.10.20.1} {172.30.30.0/24 10.10.20.1}]"))

	// Make N1 air-gapped.
	ni1Ports := ni1Bridge.Ports
	ni1Bridge.Ports = []nirec.Port{}
	_, err = niReconciler.UpdateNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"propagateRoutes: []"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.20.1} {128.138.140.211/32 10.10.20.1} " +
			"{1.1.1.1/32 10.10.20.1} {172.20.0.0/16 10.10.20.1} {172.30.30.0/24 10.10.20.1}]"))

	// Add some static routes.
	ni1Bridge.StaticRoutes = []nirec.IPRoute{
		// GW is inside the NI subnet (app gateway).
		{DstNetwork: ipAddressWithPrefix("10.50.1.0/24"), Gateway: ipAddress("10.10.10.100")},
	}
	_, err = niReconciler.UpdateNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())

	ni5Bridge.StaticRoutes = []nirec.IPRoute{
		{DstNetwork: ipAddressWithPrefix("10.50.1.0/24"), Gateway: ipAddress("172.20.1.1")},
		{DstNetwork: ipAddressWithPrefix("10.50.14.0/26"), Gateway: ipAddress("172.30.30.15")},
		// This one uses app2 as GW:
		{DstNetwork: ipAddressWithPrefix("10.50.19.0/30"), Gateway: ipAddress("10.10.20.2")},
		// This one also uses app2 as GW:
		{DstNetwork: ipAddressWithPrefix("10.50.5.0/30"), Gateway: ipAddress("10.10.20.2")},
		// This one has GW outside eth1 and eth3 subnets and will be skipped:
		{DstNetwork: ipAddressWithPrefix("10.50.2.0/24"), Gateway: ipAddress("172.21.1.1")},
		// Override default route:
		{DstNetwork: ipAddressWithPrefix("0.0.0.0/0"), OutputPort: "ethernet1"},
	}
	recStatus, err := niReconciler.UpdateNI(ctx, ni5Config, ni5Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	// The list does not include routes with application as a gateway. In those cases,
	// the traffic is simply forwarded by the bridge, not routed.
	t.Expect(recStatus.Routes).To(HaveLen(3))
	t.Expect(recStatus.Routes[0].Equal(types.IPRouteInfo{
		IPVersion:  types.AddressTypeIPV4,
		DstNetwork: ipAddressWithPrefix("0.0.0.0/0"),
		Gateway:    ipAddress("172.20.0.1"),
		OutputPort: "ethernet1",
	})).To(BeTrue())
	t.Expect(recStatus.Routes[1].Equal(types.IPRouteInfo{
		IPVersion:  types.AddressTypeIPV4,
		DstNetwork: ipAddressWithPrefix("10.50.14.0/26"),
		Gateway:    ipAddress("172.30.30.15"),
		OutputPort: "ethernet3",
	})).To(BeTrue())
	t.Expect(recStatus.Routes[2].Equal(types.IPRouteInfo{
		IPVersion:  types.AddressTypeIPV4,
		DstNetwork: ipAddressWithPrefix("10.50.1.0/24"),
		Gateway:    ipAddress("172.20.1.1"),
		OutputPort: "ethernet1",
	})).To(BeTrue())

	t.Expect(itemDescription(dg.Reference(dnsmasqNI1))).To(ContainSubstring(
		"propagateRoutes: [{10.50.1.0/24 10.10.10.100}]"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"withDefaultRoute: true"))
	t.Expect(itemDescription(dg.Reference(dnsmasqNI5))).To(ContainSubstring(
		"propagateRoutes: [{132.163.96.5/32 10.10.20.1} {128.138.140.211/32 10.10.20.1} " +
			"{1.1.1.1/32 10.10.20.1} {10.50.1.0/24 10.10.20.1} {10.50.14.0/26 10.10.20.1} " +
			"{10.50.19.0/30 10.10.20.2} {10.50.5.0/30 10.10.20.2} {172.20.0.0/16 10.10.20.1} " +
			"{172.30.30.0/24 10.10.20.1}]"))

	// Check routing tables
	netlinkStaticRoute1 := netlink.Route{
		LinkIndex: 4,
		Dst:       ipAddressWithPrefix("10.50.1.0/24"),
		Table:     805,
		Gw:        ipAddress("172.20.1.1"),
		Family:    netlink.FAMILY_V4,
		Protocol:  unix.RTPROT_STATIC,
	}
	staticRoute1 := linuxitems.Route{
		Route: netlinkStaticRoute1,
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth1",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth1"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(staticRoute1))).To(BeTrue())
	netlinkStaticRoute3 := netlink.Route{
		LinkIndex: 4,
		Dst:       nil,
		Table:     805,
		Gw:        ipAddress("172.20.1.1"),
		Family:    netlink.FAMILY_V4,
		Protocol:  unix.RTPROT_STATIC,
	}
	staticRoute3 := linuxitems.Route{
		Route: netlinkStaticRoute3,
		OutputIf: genericitems.NetworkIf{
			IfName:  "eth1",
			ItemRef: dg.Reference(genericitems.Port{IfName: "eth1"}),
		},
	}
	t.Expect(itemIsCreated(dg.Reference(staticRoute3))).To(BeTrue())
	t.Expect(itemCount(func(item dg.Item) bool {
		route, isRoute := item.(linuxitems.Route)
		if !isRoute {
			return false
		}
		return route.Table == 801
	})).To(Equal(2)) // only IPv4 + IPv6 unreachable routes (N1 is air-gapped)
	t.Expect(itemCount(func(item dg.Item) bool {
		route, isRoute := item.(linuxitems.Route)
		if !isRoute {
			return false
		}
		return route.Table == 805
	})).To(Equal(2 + 3)) // unreachable IPv4/IPv6 routes + static routes

	// Disconnect the application.
	appStatus, err = niReconciler.DelAppConn(ctx, app2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	for i := 0; i < 4; i++ {
		t.Expect(appStatus.VIFs[i].InProgress).To(BeFalse())
	}

	// Delete network instances
	niStatus, err := niReconciler.DelNI(ctx, ni1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni1UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni2UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
	niStatus, err = niReconciler.DelNI(ctx, ni5UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(ni5UUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())

	// Revert back config changes.
	ni1Bridge.StaticRoutes = nil
	ni5Bridge.StaticRoutes = nil
	ni5Config.DnsServers = nil
	ni1Bridge.Ports = ni1Ports
	ni1Config.PropagateConnRoutes = false
	ni5Config.PropagateConnRoutes = false
}

func TestCNI(test *testing.T) {
	t := initTest(test, true)
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	var routes []netmonitor.Route
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth1Routes...)
	networkMonitor.UpdateRoutes(routes)
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create local network instance.
	networkMonitor.AddOrUpdateInterface(ni1BridgeIf)
	_, err := niReconciler.AddNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	var recUpdate nirec.ReconcilerUpdate
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))

	// Connect K3s Pod into the network instance.
	// L2-only connection for now.
	pod := cnirpc.AppPod{
		Name:      "app-pod-12345",
		NetNsPath: "/var/run/netns/app-netns-12345",
	}
	vif := app1VIFs[0]
	vif.PodVIF = types.PodVIF{
		GuestIfName: "net0",
		IPAM:        cnirpc.PodIPAMConfig{},
	}
	_, err = niReconciler.AddAppConn(ctx, app1NetConfig, app1Num, pod, []nirec.AppVIF{vif})
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))

	vifRef := dg.Reference(linuxitems.VIF{HostIfName: "nbu1x1"})
	t.Expect(itemDescription(vifRef)).To(ContainSubstring("appIfName: net0"))
	t.Expect(itemDescription(vifRef)).To(ContainSubstring("appIPs: []"))

	sysctlRef := dg.Reference(linuxitems.Sysctl{
		ForApp: linuxitems.ContainerApp{ID: app1UUID.UUID},
		NetIf:  genericitems.NetworkIf{IfName: "net0"},
	})
	t.Expect(itemDescription(sysctlRef)).To(
		ContainSubstring("enableDAD: false, enableARPNotify: true"))

	// Elevate the connection to L3.
	vif.PodVIF.IPAM = cnirpc.PodIPAMConfig{
		IPs: []cnirpc.PodIPAddress{
			{
				Address: ipAddressWithPrefix("10.10.10.2/24"),
				Gateway: ipAddress("10.10.10.1"),
			},
		},
		Routes: []cnirpc.PodRoute{
			{
				Dst: ipSubnet("10.10.10.0/24"),
				GW:  ipAddress("10.10.10.1"),
			},
		},
	}
	_, err = niReconciler.UpdateAppConn(ctx, app1NetConfig, pod, []nirec.AppVIF{vif})
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))

	t.Expect(itemDescription(vifRef)).To(ContainSubstring("appIPs: [10.10.10.2/24]"))
	routeRef := dg.Reference(linuxitems.Route{
		Route:    netlink.Route{Dst: ipSubnet("10.10.10.0/24"), Family: netlink.FAMILY_V4},
		OutputIf: genericitems.NetworkIf{IfName: "net0"},
		ForApp:   linuxitems.ContainerApp{ID: app1UUID.UUID},
	})
	t.Expect(itemIsCreated(routeRef)).To(BeTrue())

	// Disconnect the K3s Pod.
	_, err = niReconciler.DelAppConn(ctx, app1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())

	t.Expect(itemIsCreated(vifRef)).To(BeFalse())
	t.Expect(itemIsCreated(routeRef)).To(BeFalse())

	// Delete network instance
	_, err = niReconciler.DelNI(ctx, ni1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
}

func TestHostSysctl(test *testing.T) {
	t := initTest(test, false)
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(keth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.AddOrUpdateInterface(keth1)
	networkMonitor.AddOrUpdateInterface(eth3)
	networkMonitor.AddOrUpdateInterface(keth3)
	var routes []netmonitor.Route
	routes = append(routes, eth0Routes...)
	routes = append(routes, eth1Routes...)
	routes = append(routes, eth3Routes...)
	networkMonitor.UpdateRoutes(routes)
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create 2 local and 1 switch network instance.
	var recUpdate nirec.ReconcilerUpdate
	networkMonitor.AddOrUpdateInterface(ni1BridgeIf)
	niStatus, err := niReconciler.AddNI(ctx, ni1Config, ni1Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	niStatus, err = niReconciler.AddNI(ctx, ni2Config, ni2Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	networkMonitor.AddOrUpdateInterface(ni5BridgeIf)
	niStatus, err = niReconciler.AddNI(ctx, ni5Config, ni5Bridge)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))
	t.Expect(recUpdate.NIStatus.Equal(niStatus)).To(BeTrue())

	// Flow logging is disabled in all network instances and there are
	// no apps deployed hence bridges do not need iptables.
	hostSysctlRef := dg.Reference(linuxitems.Sysctl{})
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIptables: false"))
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIp6tables: false"))

	// Connection application with allow-all for IPv4 + portmap rules.
	// This does not require to trigger iptables from bridge, but ip6tables
	// should be triggered (still we get performance improvement at least for IPv4).
	appStatus, err := niReconciler.AddAppConn(ctx, app2NetConfig, app2Num, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIptables: false"))
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIp6tables: true"))

	// Connect application with a LIMIT rule.
	appStatus, err = niReconciler.AddAppConn(ctx, app1NetConfig, app1Num, cnirpc.AppPod{}, app1VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	// With LIMIT rule present, iptables should be called from the bridge.
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIptables: true"))
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIp6tables: true"))

	// Remove app with the LIMIT rule. For IPv4 bridge should not call iptables anymore.
	appStatus, err = niReconciler.DelAppConn(ctx, app1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIptables: false"))
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIp6tables: true"))

	// Enable flow logging in one of the network instances.
	// This enforces the use of iptables from bridge for both IPv4 and IPv6.
	ni2Config.EnableFlowlog = true
	_, err = niReconciler.UpdateNI(ctx, ni2Config, ni2Bridge)
	t.Expect(err).ToNot(HaveOccurred())

	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIptables: true"))
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIp6tables: true"))

	// Delete everything.
	_, err = niReconciler.DelAppConn(ctx, app2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	_, err = niReconciler.DelNI(ctx, ni1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	_, err = niReconciler.DelNI(ctx, ni2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	_, err = niReconciler.DelNI(ctx, ni5UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())

	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIptables: false"))
	t.Expect(itemDescription(hostSysctlRef)).To(
		ContainSubstring("bridgeCallIp6tables: false"))

	// Revert back to flow logging being disabled.
	ni2Config.EnableFlowlog = false
}

// This test uses it own network config, not the config globally defined.
/*
                                                  +-------------------+
                                                  |  eth0 (EVE mgmt)  |
                                                  |      (DHCP)       |
                                                  +-------------------+
                       +-----------+
                       |           |
                       |           |              +-------------------+
                       |           |---<trunk>----| eth1 (app-shared) |
                       |           |              | (No IP, L2-only)  |
                       | Switch NI |              +-------------------+
                       |           |
 +------+              |           |              +-------------------+
 | app1 |--<VLAN 100>--|           |--<VLAN 100>--| eth2 (app-shared) |
 +------+              |           |              | (No IP, L2-only)  |
                       |           |              +-------------------+
 +------+              |           |
 | app2 |--<VLAN 200>--|           |              +-------------------+
 +------+              |           |--<VLAN 200>--| eth3 (app-shared) |
                       |           |              | (No IP, L2-only)  |
                       +-----------+              +-------------------+
*/
func TestSwitchNIWithMultiplePorts(test *testing.T) {
	t := initTest(test, false)

	// Prepare mock network interfaces (which are normally managed by NIM).
	keth0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "keth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 2,
		},
		HwAddr: macAddress("02:00:00:00:00:01"),
	}
	eth0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       2,
			IfName:        "eth0",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddressWithPrefix("192.168.10.5/24")},
		DHCP: netmonitor.DHCPInfo{
			Subnet:     ipSubnet("192.168.10.0/24"),
			NtpServers: []net.IP{ipAddress("132.163.96.5")},
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/eth0-resolv.conf",
			Domains:        []string{"eth0-test-domain"},
			DNSServers:     []net.IP{ipAddress("8.8.8.8")},
		},
		HwAddr: macAddress("02:00:00:00:01:01"),
	}
	eth1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       3,
			IfName:        "eth1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:02"),
	}
	eth2 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       4,
			IfName:        "eth2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:03"),
	}
	eth3 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       5,
			IfName:        "eth3",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:04"),
	}
	networkMonitor.AddOrUpdateInterface(keth0)
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.AddOrUpdateInterface(eth2)
	networkMonitor.AddOrUpdateInterface(eth3)

	// Run initial reconciliation.
	ctx := reconciler.MockRun(context.Background())
	updatesCh := niReconciler.WatchReconcilerUpdates()
	niReconciler.RunInitialReconcile(ctx)

	// Create switch network instance with multiple ports.
	niUUID := makeUUID("d17a2818-e5b2-4778-9d61-d5af17feec69")
	niConfig := types.NetworkInstanceConfig{
		UUIDandVersion: niUUID,
		DisplayName:    "multiport-switch",
		PortLabel:      "switch-port",
		Type:           types.NetworkInstanceTypeSwitch,
		IpType:         types.AddressTypeNone,
		STPConfig: types.STPConfig{
			PortsWithBpduGuard: "end-devices",
		},
		VlanAccessPorts: []types.VlanAccessPort{
			{
				VlanID:    100,
				PortLabel: "ethernet2",
			},
			{
				VlanID:    200,
				PortLabel: "ethernet3",
			},
		},
	}
	niBridge := nirec.NIBridge{
		NI:         niUUID.UUID,
		BrNum:      1,
		MACAddress: macAddress("02:00:00:00:02:01"),
		Ports: []nirec.Port{
			{
				LogicalLabel: "ethernet1",
				SharedLabels: []string{"switch-port"},
				IfName:       "eth1",
				IsMgmt:       true,
				DhcpType:     types.DhcpTypeNone,
			},
			{
				LogicalLabel: "ethernet2",
				SharedLabels: []string{"switch-port", "end-devices"},
				IfName:       "eth2",
				IsMgmt:       true,
				DhcpType:     types.DhcpTypeNone,
			},
			{
				LogicalLabel: "ethernet3",
				SharedLabels: []string{"switch-port", "end-devices"},
				IfName:       "eth3",
				IsMgmt:       true,
				DhcpType:     types.DhcpTypeNone,
			},
		},
	}
	niBridgeIf := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       6,
			IfName:        "bn1",
			IfType:        "bridge",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:02:01"),
	}
	networkMonitor.AddOrUpdateInterface(niBridgeIf)
	_, err := niReconciler.AddNI(ctx, niConfig, niBridge)
	t.Expect(err).ToNot(HaveOccurred())
	var recUpdate nirec.ReconcilerUpdate
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.NIReconcileStatusChanged))

	// Check some of the configured items.
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.Bridge{IfName: "bn1"}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.VLANBridge{BridgeIfName: "bn1"}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BridgePort{Variant: linuxitems.BridgePortVariant{PortIfName: "eth1"}}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BridgePort{Variant: linuxitems.BridgePortVariant{PortIfName: "eth2"}}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BridgePort{Variant: linuxitems.BridgePortVariant{PortIfName: "eth3"}}))).To(BeTrue())
	t.Expect(itemDescription(dg.Reference(linuxitems.VLANPort{PortIfName: "eth1"}))).
		To(ContainSubstring("trunkPort: {allVIDs: false, vids:[100 200]}}"))
	t.Expect(itemDescription(dg.Reference(linuxitems.VLANPort{PortIfName: "eth2"}))).
		To(ContainSubstring("accessPort: {vid: 100}"))
	t.Expect(itemDescription(dg.Reference(linuxitems.VLANPort{PortIfName: "eth3"}))).
		To(ContainSubstring("accessPort: {vid: 200}"))
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BPDUGuard{PortIfName: "eth1"}))).To(BeFalse())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BPDUGuard{PortIfName: "eth3"}))).To(BeTrue())
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BPDUGuard{PortIfName: "eth3"}))).To(BeTrue())

	// Connect "app1"
	app1UUID := makeUUID("f9a3acd0-85ae-4c1f-8fb2-0ac22b5dd312")
	app1Num := 1
	app1NetConfig := types.AppNetworkConfig{
		UUIDandVersion: app1UUID,
		DisplayName:    "app1",
		Activate:       true,
		AppNetAdapterList: []types.AppNetAdapterConfig{
			{
				Name:         "adapter1",
				IntfOrder:    0,
				Network:      niUUID.UUID,
				AccessVlanID: 100,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "0.0.0.0/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
				},
			},
		},
	}
	app1VIFs := []nirec.AppVIF{
		{
			App:            app1UUID.UUID,
			NI:             niUUID.UUID,
			NetAdapterName: "adapter1",
			VIFNum:         1,
			GuestIfMAC:     macAddress("02:00:00:00:04:01"),
			GuestIP:        ipAddress("10.10.100.2"),
		},
	}
	app1VIF1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       7,
			IfName:        "nbu1x1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 6,
		},
		HwAddr: macAddress("02:00:00:00:03:01"), // host-side
	}
	appStatus, err := niReconciler.AddAppConn(ctx, app1NetConfig, app1Num, cnirpc.AppPod{}, app1VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app1UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(1))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x1"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	// domainmgr has not yet created the VIF.
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BridgePort{Variant: linuxitems.BridgePortVariant{VIFIfName: "nbu1x1"}}))).To(BeFalse())

	// Simulate domainmgr creating the VIF.
	networkMonitor.AddOrUpdateInterface(app1VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.VIFs[0].InProgress).To(BeFalse())
	t.Expect(recUpdate.AppConnStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BridgePort{Variant: linuxitems.BridgePortVariant{VIFIfName: "nbu1x1"}}))).To(BeTrue())
	t.Expect(itemDescription(dg.Reference(linuxitems.VLANPort{PortIfName: "nbu1x1"}))).
		To(ContainSubstring("accessPort: {vid: 100}"))
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BPDUGuard{PortIfName: "nbu1x1"}))).To(BeTrue())

	// Connect "app2"
	app2UUID := makeUUID("d7152df0-fc94-4da7-af8a-e73cb8dc2760")
	app2Num := 2
	app2NetConfig := types.AppNetworkConfig{
		UUIDandVersion: app2UUID,
		DisplayName:    "app2",
		Activate:       true,
		AppNetAdapterList: []types.AppNetAdapterConfig{
			{
				Name:         "adapter1",
				IntfOrder:    0,
				Network:      niUUID.UUID,
				AccessVlanID: 200,
				ACLs: []types.ACE{
					{
						Matches: []types.ACEMatch{
							{
								Type:  "ip",
								Value: "0.0.0.0/0",
							},
						},
						Actions: []types.ACEAction{
							{
								Drop: false,
							},
						},
						RuleID: 1,
					},
				},
			},
		},
	}
	app2VIFs := []nirec.AppVIF{
		{
			App:            app2UUID.UUID,
			NI:             niUUID.UUID,
			NetAdapterName: "adapter1",
			VIFNum:         1,
			GuestIfMAC:     macAddress("02:00:00:00:04:02"),
			GuestIP:        ipAddress("10.10.200.2"),
		},
	}
	app2VIF1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       8,
			IfName:        "nbu1x2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
			Enslaved:      true,
			MasterIfIndex: 6,
		},
		HwAddr: macAddress("02:00:00:00:03:02"), // host-side
	}

	appStatus, err = niReconciler.AddAppConn(ctx, app2NetConfig, app2Num, cnirpc.AppPod{}, app2VIFs)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeFalse())
	t.Expect(appStatus.VIFs).To(HaveLen(1))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeTrue())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x2"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	// domainmgr has not yet created the VIF.
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BridgePort{Variant: linuxitems.BridgePortVariant{VIFIfName: "nbu1x2"}}))).To(BeFalse())

	// Simulate domainmgr creating the VIF.
	networkMonitor.AddOrUpdateInterface(app2VIF1)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.VIFs[0].InProgress).To(BeFalse())
	t.Expect(recUpdate.AppConnStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BridgePort{Variant: linuxitems.BridgePortVariant{VIFIfName: "nbu1x2"}}))).To(BeTrue())
	t.Expect(itemDescription(dg.Reference(linuxitems.VLANPort{PortIfName: "nbu1x2"}))).
		To(ContainSubstring("accessPort: {vid: 200}"))
	t.Expect(itemIsCreated(dg.Reference(
		linuxitems.BPDUGuard{PortIfName: "nbu1x2"}))).To(BeTrue())

	// Disconnect the applications.
	appStatus, err = niReconciler.DelAppConn(ctx, app1UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app1UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeTrue())
	t.Expect(appStatus.VIFs).To(HaveLen(1))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeFalse())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x1"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	networkMonitor.DelInterface(app1VIF1.Attrs.IfName)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	appStatus, err = niReconciler.DelAppConn(ctx, app2UUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(appStatus.App).To(Equal(app2UUID.UUID))
	t.Expect(appStatus.Deleted).To(BeTrue())
	t.Expect(appStatus.VIFs).To(HaveLen(1))
	t.Expect(appStatus.VIFs[0].NetAdapterName).To(Equal("adapter1"))
	t.Expect(appStatus.VIFs[0].InProgress).To(BeFalse())
	t.Expect(appStatus.VIFs[0].HostIfName).To(Equal("nbu1x2"))
	t.Expect(appStatus.VIFs[0].FailedItems).To(BeEmpty())

	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.AppConnReconcileStatusChanged))
	t.Expect(recUpdate.AppConnStatus.Equal(appStatus)).To(BeTrue())

	networkMonitor.DelInterface(app2VIF1.Attrs.IfName)
	t.Eventually(updatesCh).Should(Receive(&recUpdate))
	t.Expect(recUpdate.UpdateType).To(Equal(nirec.CurrentStateChanged))
	niReconciler.ResumeReconcile(ctx)

	// Delete network instance
	niStatus, err := niReconciler.DelNI(ctx, niUUID.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(niStatus.NI).To(Equal(niUUID.UUID))
	t.Expect(niStatus.Deleted).To(BeTrue())
}
