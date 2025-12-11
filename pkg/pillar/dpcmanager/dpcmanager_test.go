// Copyright (c) 2022,2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/eriknordmark/ipinfo"
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/lf-edge/eve-api/go/evecommon"
	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/conntester"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	dpcmngr "github.com/lf-edge/eve/pkg/pillar/dpcmanager"
	dpcrec "github.com/lf-edge/eve/pkg/pillar/dpcreconciler"
	generic "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

var (
	logObj         *base.LogObject
	networkMonitor *netmonitor.MockNetworkMonitor
	geoService     *MockGeoService
	dpcReconciler  *dpcrec.LinuxDpcReconciler
	dpcManager     *dpcmngr.DpcManager
	connTester     *conntester.MockConnectivityTester
	pubDummyDPC    pubsub.Publication // for logging
	pubDPCList     pubsub.Publication
	pubDNS         pubsub.Publication
)

func initTest(test *testing.T, expectBootstrapDPCsOpt ...bool) *GomegaWithT {
	t := NewGomegaWithT(test)
	t.SetDefaultEventuallyTimeout(20 * time.Second)
	t.SetDefaultEventuallyPollingInterval(250 * time.Millisecond)
	t.SetDefaultConsistentlyDuration(5 * time.Second) // > NetworkTestInterval
	t.SetDefaultConsistentlyPollingInterval(250 * time.Millisecond)
	logger := logrus.StandardLogger()
	logObj = base.NewSourceLogObject(logger, "test", 1234)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, logObj)
	var err error
	pubDummyDPC, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  "test",
			AgentScope: "dummy",
			TopicType:  types.DevicePortConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubDPCList, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  "test",
			Persistent: true,
			TopicType:  types.DevicePortConfigList{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubDNS, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: "test",
			TopicType: types.DeviceNetworkStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	networkMonitor = &netmonitor.MockNetworkMonitor{
		Log:    logObj,
		MainRT: syscall.RT_TABLE_MAIN,
	}
	dpcReconciler = &dpcrec.LinuxDpcReconciler{
		Log:            logObj,
		AgentName:      "test",
		NetworkMonitor: networkMonitor,
	}
	geoService = &MockGeoService{}
	connTester = &conntester.MockConnectivityTester{
		TestDuration:   2 * time.Second,
		NetworkMonitor: networkMonitor,
	}
	dpcManager = &dpcmngr.DpcManager{
		Log:                      logObj,
		Watchdog:                 &MockWatchdog{},
		AgentName:                "test",
		GeoService:               geoService,
		DpcMinTimeSinceFailure:   3 * time.Second,
		DpcAvailTimeLimit:        3 * time.Second,
		NetworkMonitor:           networkMonitor,
		DpcReconciler:            dpcReconciler,
		ConnTester:               connTester,
		PubDummyDevicePortConfig: pubDummyDPC,
		PubDevicePortConfigList:  pubDPCList,
		PubDeviceNetworkStatus:   pubDNS,
		AgentMetrics:             controllerconn.NewAgentMetrics(),
	}
	ctx := reconciler.MockRun(context.Background())
	if err := dpcManager.Init(ctx); err != nil {
		log.Fatal(err)
	}
	expectBootstrapDPCs := false
	if len(expectBootstrapDPCsOpt) > 0 {
		expectBootstrapDPCs = expectBootstrapDPCsOpt[0]
	}
	if err := dpcManager.Run(ctx, expectBootstrapDPCs); err != nil {
		log.Fatal(err)
	}
	return t
}

func printCurrentState() {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.Export(currentState)
	fmt.Println(dot)
}

func printIntendedState() {
	intendedState, release := dpcReconciler.GetIntendedState()
	defer release()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.Export(intendedState)
	fmt.Println(dot)
}

func itemDescription(itemRef dg.ItemRef) string {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	item, _, _, found := currentState.Item(itemRef)
	if !found {
		return ""
	}
	return item.String()
}

func itemIsCreated(itemRef dg.ItemRef) bool {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	_, state, _, found := currentState.Item(itemRef)
	return found && state.IsCreated()
}

func itemIsCreatedCb(itemRef dg.ItemRef) func() bool {
	return func() bool {
		return itemIsCreated(itemRef)
	}
}

func itemIsCreatedWithLabel(label string) bool {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	iter := currentState.Items(true)
	for iter.Next() {
		item, state := iter.Item()
		if item.Label() == label {
			return state.IsCreated()
		}
	}
	return false
}

func itemIsCreatedWithLabelCb(label string) func() bool {
	return func() bool {
		return itemIsCreatedWithLabel(label)
	}
}

func dhcpcdArgs(ifName string) string {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	itemRef := dg.Reference(generic.Dhcpcd{AdapterIfName: ifName})
	item, _, _, found := currentState.Item(itemRef)
	if !found {
		return ""
	}
	dhcpcd, ok := item.(generic.Dhcpcd)
	if !ok {
		return ""
	}
	configurator := generic.DhcpcdConfigurator{Log: logObj}
	op, args := configurator.DhcpcdArgs(
		dhcpcd.DhcpConfig, dhcpcd.IgnoreDhcpGateways, dhcpcd.RouteMetric)
	return fmt.Sprintf("%s %s", op, strings.Join(args, " "))
}

func adapterStaticIPs(ifName string) []*net.IPNet {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	itemRef := dg.Reference(linux.Adapter{IfName: ifName})
	item, _, _, found := currentState.Item(itemRef)
	if !found {
		return nil
	}
	adapter, ok := item.(linux.Adapter)
	if !ok {
		return nil
	}
	return adapter.StaticIPs
}

func ipRoutes(table int, ipv6 bool) (routes []linux.Route) {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	iter := currentState.Items(true)
	routeType := generic.IPv4RouteTypename
	if ipv6 {
		routeType = generic.IPv6RouteTypename
	}
	for iter.Next() {
		item, state := iter.Item()
		if state.IsCreated() && item.Type() == routeType {
			route := item.(linux.Route)
			if route.Table == table {
				routes = append(routes, route)
			}
		}
	}
	return routes
}

func ipRoutesCb(table int, ipv6 bool) func() []linux.Route {
	return func() []linux.Route {
		return ipRoutes(table, ipv6)
	}
}

func dnsServers(ifName string) []net.IP {
	currentState, release := dpcReconciler.GetCurrentState()
	defer release()
	itemRef := dg.Reference(generic.ResolvConf{})
	item, _, _, found := currentState.Item(itemRef)
	if !found {
		return nil
	}
	resolvConf, ok := item.(generic.ResolvConf)
	if !ok {
		return nil
	}
	if resolvConf.DNSServers == nil {
		return nil
	}
	return resolvConf.DNSServers[ifName]
}

func dnsServersCb(ifName string) func() []net.IP {
	return func() []net.IP {
		return dnsServers(ifName)
	}
}

func equalPortAddresses(a, b types.AddrInfo) bool {
	return netutils.EqualIPs(a.Addr, b.Addr)
}

func dnsKeyCb() func() string {
	return func() string {
		return getDNS().DPCKey
	}
}

func testingInProgressCb() func() bool {
	return func() bool {
		return getDNS().Testing
	}
}

func dpcIdxCb() func() int {
	return func() int {
		idx, _ := getDPCList()
		return idx
	}
}

func dpcListLenCb() func() int {
	return func() int {
		_, dpcList := getDPCList()
		return len(dpcList)
	}
}

func dpcKeyCb(idx int) func() string {
	return func() string {
		dpc := getDPC(idx)
		return dpc.Key
	}
}

func dpcTimePrioCb(idx int, expected time.Time) func() bool {
	return func() bool {
		dpc := getDPC(idx)
		return dpc.TimePriority.Equal(expected)
	}
}

func dpcStateCb(idx int) func() types.DPCState {
	return func() types.DPCState {
		dpc := getDPC(idx)
		return dpc.State
	}
}

func getDNS() types.DeviceNetworkStatus {
	dnsObj, err := pubDNS.Get("global")
	if err != nil {
		return types.DeviceNetworkStatus{}
	}
	return dnsObj.(types.DeviceNetworkStatus)
}

func portHasIP(portLL string, ip net.IP) bool {
	dns := getDNS()
	portStatus := dns.LookupPortByLogicallabel(portLL)
	if portStatus == nil {
		return false
	}
	if len(portStatus.AddrInfoList) != 1 {
		return false
	}
	return portStatus.AddrInfoList[0].Addr.Equal(ip)
}

func portHasConfigSource(portLL string, source types.PortConfigSource) bool {
	dns := getDNS()
	portStatus := dns.LookupPortByLogicallabel(portLL)
	if portStatus == nil {
		return false
	}
	return portStatus.ConfigSource.Equal(source)
}

func getPortLpsConfigErr(portLL string) string {
	dns := getDNS()
	portStatus := dns.LookupPortByLogicallabel(portLL)
	if portStatus == nil {
		return ""
	}
	return portStatus.LpsConfigError
}

func getDPC(idx int) types.DevicePortConfig {
	_, dpcList := getDPCList()
	if idx < 0 || idx >= len(dpcList) {
		return types.DevicePortConfig{}
	}
	return dpcList[idx]
}

func getDPCList() (currentIndex int, list []types.DevicePortConfig) {
	obj, err := pubDPCList.Get("global")
	if err != nil {
		return -1, nil
	}
	dpcl := obj.(types.DevicePortConfigList)
	return dpcl.CurrentIndex, dpcl.PortConfigList
}

func wirelessStatusFromDNS(wType types.WirelessType) types.WirelessStatus {
	for _, port := range getDNS().Ports {
		if port.WirelessStatus.WType == wType {
			return port.WirelessStatus
		}
	}
	return types.WirelessStatus{}
}

func wwanOpModeCb(expMode types.WwanOpMode) func() bool {
	return func() bool {
		wwanDNS := wirelessStatusFromDNS(types.WirelessTypeCellular)
		return wwanDNS.Cellular.Module.OpMode == expMode
	}
}

func rsChangeInProgressCb() func() bool {
	return func() bool {
		return getDNS().RadioSilence.ChangeInProgress
	}
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

func globalConfig() types.ConfigItemValueMap {
	gcp := types.DefaultConfigItemValueMap()
	gcp.SetGlobalValueString(types.SSHAuthorizedKeys, "mock-authorized-key")
	gcp.SetGlobalValueInt(types.NetworkTestInterval, 2)
	gcp.SetGlobalValueInt(types.NetworkTestBetterInterval, 3)
	gcp.SetGlobalValueInt(types.NetworkTestDuration, 1)
	gcp.SetGlobalValueInt(types.NetworkGeoRetryTime, 1)
	gcp.SetGlobalValueInt(types.NetworkGeoRedoTime, 3)
	gcp.SetGlobalValueInt(types.LocationCloudInterval, 10)
	gcp.SetGlobalValueInt(types.LocationAppInterval, 2)
	gcp.SetGlobalValueInt(types.NTPSourcesInterval, 5)
	gcp.SetGlobalValueBool(types.NetDumpEnable, false)
	return *gcp
}

func globalConfigWithLastresort() types.ConfigItemValueMap {
	gcp := globalConfig()
	gcp.SetGlobalValueTriState(types.NetworkFallbackAnyEth, types.TS_ENABLED)
	return gcp
}

func mockEth0() netmonitor.MockInterface {
	eth0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "eth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddress("192.168.10.5/24")},
		DHCP: netmonitor.DHCPInfo{
			IPv4Subnet:     ipSubnet("192.168.10.0/24"),
			IPv4NtpServers: netutils.NewHostnameOrIPs("132.163.96.5"),
		},
		DNS: []netmonitor.DNSInfo{
			{
				ResolvConfPath: "/etc/eth0-resolv.conf",
				Domains:        []string{"eth-test-domain"},
				DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
			},
		},
		HwAddr: macAddress("02:00:00:00:00:01"),
	}
	return eth0
}

func mockEth0Routes() []netmonitor.Route {
	gwIP := net.ParseIP("192.168.10.1")
	return []netmonitor.Route{
		{
			IfIndex: 1,
			Dst:     nil,
			Gw:      gwIP,
			Table:   syscall.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 1,
				Dst:       nil,
				Gw:        gwIP,
				Table:     syscall.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
			},
		},
	}
}

func mockEth0Geo() *ipinfo.IPInfo {
	return &ipinfo.IPInfo{
		IP:       "123.123.123.123",
		Hostname: "hostname",
		City:     "Berlin",
		Country:  "Germany",
		Loc:      "52.51631, 13.37786",
		Org:      "fake ISP provider",
		Postal:   "999 99",
	}
}

func mockEth1() netmonitor.MockInterface {
	eth1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       2,
			IfName:        "eth1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddress("172.20.1.2/24")},
		DHCP: netmonitor.DHCPInfo{
			IPv4Subnet:     ipSubnet("172.20.1.0/24"),
			IPv4NtpServers: netutils.NewHostnameOrIPs("132.163.96.6"),
		},
		DNS: []netmonitor.DNSInfo{
			{
				ResolvConfPath: "/etc/eth1-resolv.conf",
				Domains:        []string{"eth-test-domain"},
				DNSServers:     []net.IP{net.ParseIP("1.1.1.1")},
			},
		},
		HwAddr: macAddress("02:00:00:00:00:02"),
	}
	return eth1
}

func mockEth1Routes() []netmonitor.Route {
	gwIP := net.ParseIP("172.20.1.1")
	return []netmonitor.Route{
		{
			IfIndex: 2,
			Dst:     nil,
			Gw:      gwIP,
			Table:   syscall.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 2,
				Dst:       nil,
				Gw:        gwIP,
				Table:     syscall.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V4,
			},
		},
	}
}

func mockEth2() netmonitor.MockInterface {
	eth2 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       3,
			IfName:        "eth2",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{
			ipAddress("2001:1111::1/64"),
		},
		DHCP: netmonitor.DHCPInfo{
			IPv6Subnets:    []*net.IPNet{ipSubnet("2001:1111::/64")},
			IPv6NtpServers: netutils.NewHostnameOrIPs("2001:db8:3c4d:15::1"),
		},
		DNS: []netmonitor.DNSInfo{
			{
				ResolvConfPath: "/run/dhcpcd/resolv.conf/eth2.ra",
				Domains:        []string{"eth2-ipv6-test-domain"},
				DNSServers: []net.IP{
					net.ParseIP("2001:4860:4860::8888"),
					net.ParseIP("2001:4860:4860::8844"),
				},
			},
		},
		HwAddr: macAddress("02:00:00:00:00:03"),
	}
	return eth2
}

func mockEth2Routes() []netmonitor.Route {
	gwIP := net.ParseIP("fe80::c225:2fff:fea2:dc73")
	return []netmonitor.Route{
		{
			IfIndex: 3,
			Dst:     nil,
			Gw:      gwIP,
			Table:   syscall.RT_TABLE_MAIN,
			Data: netlink.Route{
				LinkIndex: 3,
				Dst:       nil,
				Gw:        gwIP,
				Table:     syscall.RT_TABLE_MAIN,
				Family:    netlink.FAMILY_V6,
			},
		},
	}
}

func mockWlan0() netmonitor.MockInterface {
	wlan0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       4,
			IfName:        "wlan0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddress("192.168.77.2/24")},
		DHCP: netmonitor.DHCPInfo{
			IPv4Subnet:     ipSubnet("192.168.77.0/24"),
			IPv4NtpServers: netutils.NewHostnameOrIPs("129.6.15.32"),
		},
		DNS: []netmonitor.DNSInfo{
			{
				ResolvConfPath: "/etc/wlan0-resolv.conf",
				Domains:        []string{"wlan-test-domain"},
				DNSServers:     []net.IP{net.ParseIP("192.168.77.13")},
			},
		},
		HwAddr: macAddress("02:00:00:00:00:04"),
	}
	return wlan0
}

func mockWwan0() netmonitor.MockInterface {
	wlan0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       5,
			IfName:        "wwan0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddress("15.123.87.20/28")},
		DHCP: netmonitor.DHCPInfo{
			IPv4Subnet:     ipSubnet("15.123.87.16/28"),
			IPv4NtpServers: netutils.NewHostnameOrIPs("128.138.141.177"),
		},
		DNS: []netmonitor.DNSInfo{
			{
				ResolvConfPath: "/etc/wlan0-resolv.conf",
				Domains:        []string{"wwan-test-domain"},
				DNSServers:     []net.IP{net.ParseIP("208.67.222.222")},
			},
		},
		HwAddr: macAddress("02:00:00:00:00:05"),
	}
	return wlan0
}

func mockWwan0Status(dpc types.DevicePortConfig, rs types.RadioSilence) types.WwanStatus {
	return types.WwanStatus{
		DPCKey:            dpc.Key,
		DPCTimestamp:      dpc.TimePriority,
		RSConfigTimestamp: rs.ChangeRequestedAt,
		Networks: []types.WwanNetworkStatus{
			{
				LogicalLabel: "mock-wwan0",
				PhysAddrs: types.WwanPhysAddrs{
					Interface: "wwan0",
					USB:       "1:3.3",
					PCI:       "0000:f4:00.0",
				},
				Module: types.WwanCellModule{
					IMEI:            "353533101772021",
					Model:           "EM7565",
					Revision:        "SWI9X50C_01.08.04.00",
					ControlProtocol: types.WwanCtrlProtQMI,
					OpMode:          types.WwanOpModeConnected,
				},
				SimCards: []types.WwanSimCard{
					{
						ICCID: "89012703578345957137",
						IMSI:  "310180933695713",
						Type:  types.SimTypePhysical,
					},
				},
				CurrentProvider: types.WwanProvider{
					PLMN:           "310-410",
					Description:    "AT&T",
					CurrentServing: true,
				},
				VisibleProviders: []types.WwanProvider{
					{
						PLMN:           "310-410",
						Description:    "AT&T",
						CurrentServing: true,
					},
					{
						PLMN:           "231-02",
						Description:    "Telekom",
						CurrentServing: false,
					},
				},
			},
		},
	}
}

func mockWwan0Metrics() types.WwanMetrics {
	return types.WwanMetrics{
		Networks: []types.WwanNetworkMetrics{
			{
				LogicalLabel: "mock-wwan0",
				PhysAddrs: types.WwanPhysAddrs{
					Interface: "wwan0",
					USB:       "1:3.3",
					PCI:       "0000:f4:00.0",
				},
				PacketStats: types.WwanPacketStats{
					RxBytes:   12345,
					RxPackets: 56,
					TxBytes:   1256,
					TxPackets: 12,
				},
				SignalInfo: types.WwanSignalInfo{
					RSSI: -67,
					RSRQ: -11,
					RSRP: -97,
					SNR:  92,
				},
			},
		},
	}
}

func mockWwan0LocationInfo() types.WwanLocationInfo {
	return types.WwanLocationInfo{
		Latitude:              37.333964,
		Longitude:             -121.893975,
		Altitude:              93.170685,
		HorizontalUncertainty: 16.123,
		HorizontalReliability: types.LocReliabilityMedium,
		VerticalUncertainty:   12.42,
		VerticalReliability:   types.LocReliabilityLow,
		UTCTimestamp:          1648629022000,
	}
}

type selectedIntfs struct {
	eth0  bool
	eth1  bool
	eth2  bool
	wlan0 bool
	wwan0 bool
}

func makeDPC(key string, timePrio time.Time, intfs selectedIntfs) types.DevicePortConfig {
	dpc := types.DevicePortConfig{
		Version:      types.DPCIsMgmt,
		Key:          key,
		TimePriority: timePrio,
	}
	cfgSrc := types.PortConfigSource{
		Origin:      types.NetworkConfigOriginController,
		SubmittedAt: timePrio,
	}
	if key == "lps" {
		cfgSrc = types.PortConfigSource{
			Origin: types.NetworkConfigOriginLPS,
		}
	}
	if intfs.eth0 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
			IfName:       "eth0",
			Phylabel:     "eth0",
			Logicallabel: "mock-eth0",
			IsMgmt:       true,
			IsL3Port:     true,
			Cost:         10,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIPv4,
			},
			ConfigSource: cfgSrc,
		})
	}
	if intfs.eth1 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
			IfName:       "eth1",
			Phylabel:     "eth1",
			Logicallabel: "mock-eth1",
			IsMgmt:       true,
			IsL3Port:     true,
			Cost:         0,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIPv4,
			},
			ConfigSource: cfgSrc,
		})
	}
	if intfs.eth2 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
			IfName:       "eth2",
			Phylabel:     "eth2",
			Logicallabel: "mock-eth2",
			IsMgmt:       true,
			IsL3Port:     true,
			Cost:         5,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIpv6Only,
			},
			ConfigSource: cfgSrc,
		})
	}
	if intfs.wlan0 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
			IfName:       "wlan0",
			Phylabel:     "wlan0",
			Logicallabel: "mock-wlan0",
			IsMgmt:       true,
			IsL3Port:     true,
			Cost:         20,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIPv4,
			},
			WirelessCfg: types.WirelessConfig{
				WType: types.WirelessTypeWifi,
				Wifi: []types.WifiConfig{
					{
						KeyScheme: types.KeySchemeWpaPsk,
						Identity:  "user",
						Password:  "password",
						SSID:      "ssid",
					},
				},
			},
			ConfigSource: cfgSrc,
		})
	}
	if intfs.wwan0 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
			IfName:       "wwan0",
			Phylabel:     "wwan0",
			Logicallabel: "mock-wwan0",
			IsMgmt:       true,
			IsL3Port:     true,
			Cost:         50,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DhcpTypeClient,
				Type: types.NetworkTypeIPv4,
			},
			WirelessCfg: types.WirelessConfig{
				WType: types.WirelessTypeCellular,
				CellularV2: types.CellNetPortConfig{
					AccessPoints: []types.CellularAccessPoint{
						{
							APN:       "apn",
							Activated: true,
						},
					},
					LocationTracking: true,
				},
			},
			ConfigSource: cfgSrc,
		})
	}
	return dpc
}

func makeAA(intfs selectedIntfs) types.AssignableAdapters {
	aa := types.AssignableAdapters{
		Initialized: true,
	}
	if intfs.eth0 {
		aa.IoBundleList = append(aa.IoBundleList, types.IoBundle{
			Type:         types.IoNetEth,
			Phylabel:     "eth0",
			Logicallabel: "mock-eth0",
			Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			Cost:         0,
			Ifname:       "eth0",
			MacAddr:      mockEth0().HwAddr.String(),
			IsPCIBack:    false,
			IsPort:       true,
		})
	}
	if intfs.eth1 {
		aa.IoBundleList = append(aa.IoBundleList, types.IoBundle{
			Type:         types.IoNetEth,
			Phylabel:     "eth1",
			Logicallabel: "mock-eth1",
			Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			Cost:         0,
			Ifname:       "eth1",
			MacAddr:      mockEth1().HwAddr.String(),
			IsPCIBack:    false,
			IsPort:       true,
		})
	}
	if intfs.eth2 {
		aa.IoBundleList = append(aa.IoBundleList, types.IoBundle{
			Type:         types.IoNetEth,
			Phylabel:     "eth2",
			Logicallabel: "mock-eth2",
			Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			Cost:         0,
			Ifname:       "eth2",
			MacAddr:      mockEth2().HwAddr.String(),
			IsPCIBack:    false,
			IsPort:       true,
		})
	}
	if intfs.wlan0 {
		aa.IoBundleList = append(aa.IoBundleList, types.IoBundle{
			Type:         types.IoNetEth,
			Phylabel:     "wlan0",
			Logicallabel: "mock-wlan0",
			Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
			Cost:         0,
			Ifname:       "wlan0",
			MacAddr:      mockWlan0().HwAddr.String(),
			IsPCIBack:    false,
			IsPort:       true,
		})
	}
	if intfs.wwan0 {
		aa.IoBundleList = append(aa.IoBundleList, types.IoBundle{
			Type:         types.IoNetEth,
			Phylabel:     "wwan0",
			Logicallabel: "mock-wwan0",
			Usage:        evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
			Cost:         0,
			Ifname:       "wwan0",
			MacAddr:      mockWwan0().HwAddr.String(),
			IsPCIBack:    false,
			IsPort:       true,
		})
	}
	return aa
}

func TestSingleDPC(test *testing.T) {
	t := initTest(test)
	t.Expect(dpcManager.GetDNS().DPCKey).To(BeEmpty())

	// Prepare simulated network stack.
	eth0 := mockEth0()
	networkMonitor.AddOrUpdateInterface(eth0)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply DPC with single ethernet port.
	aa := makeAA(selectedIntfs{eth0: true})
	timePrio1 := time.Now()
	dpc := makeDPC("zedagent", timePrio1, selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)
	dpcManager.AddDPC(dpc)

	// Verification should succeed.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	dns := getDNS()
	t.Expect(dns.CurrentIndex).To(Equal(0))
	t.Expect(dns.State).To(Equal(types.DPCStateSuccess))

	// Simulate interface losing IP addresses.
	// Eventually DPC will be re-tested and the verification should fail.
	// (but there is nothing else to fallback to)
	eth0.IPAddrs = nil
	networkMonitor.AddOrUpdateInterface(eth0)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateIPDNSWait))
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateFail))
	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio1)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateFail))
	t.Expect(dpcList[0].LastFailed.After(dpcList[0].LastSucceeded)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(Equal("not enough working ports (0); failed with: " +
		"[interface eth0: no suitable IP address available]"))

	// Simulate the interface obtaining the IP address back after a while.
	time.Sleep(5 * time.Second)
	eth0 = mockEth0() // with IP
	networkMonitor.AddOrUpdateInterface(eth0)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio1)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())

	//printCurrentState()
}

func TestDPCFallback(test *testing.T) {
	t := initTest(test)
	t.Expect(dpcManager.GetDNS().DPCKey).To(BeEmpty())

	// Prepare simulated network stack.
	eth0 := mockEth0()
	networkMonitor.AddOrUpdateInterface(eth0)

	// Apply global config first.
	// "lastresort" DPC will be created by DPCManager.
	dpcManager.UpdateGCP(globalConfigWithLastresort())
	lastResortTimePrio := time.Unix(0, 0)

	// Publish AssignableAdapters.
	aa := makeAA(selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)

	// Lastresort verification should succeed.
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// Change DPC - change from eth0 to non-existent eth1.
	// Verification should fail and the manager should revert back to the first DPC.
	timePrio2 := time.Now()
	dpc := makeDPC("zedagent", timePrio2, selectedIntfs{eth1: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateFail))
	t.Eventually(dpcIdxCb()).Should(Equal(1))
	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(1)) // not the highest priority
	t.Expect(dpcList).To(HaveLen(2))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio2)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateFail))
	t.Expect(dpcList[0].LastFailed.After(dpcList[0].LastSucceeded)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(
		Equal("not enough working ports (0); failed with: [interface eth1 is missing]"))
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())

	// Put a new working DPC.
	// The previous failing DPC will be compressed out, but lastresort should be preserved.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcListLenCb()).Should(Equal(2)) // compressed
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(0)) // the highest priority
	t.Expect(dpcList).To(HaveLen(2))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio3)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())

	// Simulate Remote Temporary failure.
	// This should not trigger fallback to lastresort.
	connTester.SetConnectivityError("zedagent", "eth0",
		&conntester.RemoteTemporaryFailure{
			Endpoint:   "fake-url",
			WrappedErr: errors.New("controller error"),
		})
	t.Consistently(testingInProgressCb()).Should(BeFalse())

	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(0)) // still the highest priority
	t.Expect(dpcList).To(HaveLen(2))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio3)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())

	// Simulate a loss of connectivity with "zedagent" DPC.
	// Manager should fallback to lastresort.
	connTester.SetConnectivityError("zedagent", "eth0",
		fmt.Errorf("failed to connect"))
	time.Sleep(time.Second)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateFailWithIPAndDNS))
	t.Eventually(dpcIdxCb()).Should(Equal(1))

	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(1)) // not the highest priority
	t.Expect(dpcList).To(HaveLen(2))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio3)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateFailWithIPAndDNS))
	t.Expect(dpcList[0].LastFailed.After(dpcList[0].LastSucceeded)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(Equal("not enough working ports (0); failed with: [failed to connect]"))
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())

	//printCurrentState()
}

func TestDPCWithMultipleEths(test *testing.T) {
	t := initTest(test)
	t.Expect(dpcManager.GetDNS().DPCKey).To(BeEmpty())

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	// lastresort will work through one interface
	connTester.SetConnectivityError("lastresort", "eth1",
		errors.New("failed to connect over eth1"))
	// DPC "zedagent" will not work at all
	connTester.SetConnectivityError("zedagent", "eth0",
		errors.New("failed to connect over eth0"))
	connTester.SetConnectivityError("zedagent", "eth1",
		errors.New("failed to connect over eth1"))

	// Apply global config with enabled lastresort.
	dpcManager.UpdateGCP(globalConfigWithLastresort())
	lastResortTimePrio := time.Unix(0, 0)

	// Publish AssignableAdapters.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Verification should succeed even if connectivity over eth1 is failing.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("lastresort"))
	t.Expect(dpcList[0].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	eth0Port := dpcList[0].Ports[0]
	t.Expect(eth0Port.IfName).To(Equal("eth0"))
	t.Expect(eth0Port.LastSucceeded.After(eth0Port.LastFailed)).To(BeTrue())
	t.Expect(eth0Port.IfName).To(Equal("eth0"))
	t.Expect(eth0Port.LastError).To(BeEmpty())
	eth1Port := dpcList[0].Ports[1]
	t.Expect(eth1Port.IfName).To(Equal("eth1"))
	t.Expect(eth1Port.LastFailed.After(eth1Port.LastSucceeded)).To(BeTrue())
	t.Expect(eth1Port.IfName).To(Equal("eth1"))
	t.Expect(eth1Port.LastError).To(Equal("failed to connect over eth1"))

	// Put a new DPC.
	// This one will fail for both ports and thus manager should fallback to lastresort.
	timePrio2 := time.Now()
	dpc := makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateFailWithIPAndDNS))
	t.Eventually(dpcIdxCb()).Should(Equal(1))
	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(1)) // not the highest priority
	t.Expect(dpcList).To(HaveLen(2))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio2)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateFailWithIPAndDNS))
	t.Expect(dpcList[0].LastFailed.After(dpcList[0].LastSucceeded)).To(BeTrue())
	fmt.Println(dpcList[0].LastError)
	t.Expect(dpcList[0].LastError).To(
		Equal("not enough working ports (0); failed with: " +
			"[failed to connect over eth1 failed to connect over eth0]"))
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())
}

func TestDNS(test *testing.T) {
	t := initTest(test)
	t.Expect(dpcManager.GetDNS().DPCKey).To(BeEmpty())

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), mockEth1Routes()...))
	geoSetAt := time.Now()
	geoService.SetGeolocationInfo(eth0.IPAddrs[0].IP, mockEth0Geo())
	// lastresort will work through one interface
	connTester.SetConnectivityError("lastresort", "eth1",
		errors.New("failed to connect over eth1"))

	// Apply global config with enabled lastresort.
	dpcManager.UpdateGCP(globalConfigWithLastresort())

	// Publish AssignableAdapters.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Verification should succeed even if connectivity over eth1 is failing.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
	// Wait for geolocation information.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 && ports[0].AddrInfoList[0].Geo.IP == mockEth0Geo().IP &&
			ports[0].AddrInfoList[0].LastGeoTimestamp.After(geoSetAt)
	}).Should(BeTrue())

	// Check DNS content.
	dnsObj, _ := pubDNS.Get("global")
	dns := dnsObj.(types.DeviceNetworkStatus)
	t.Expect(dns.Version).To(Equal(types.DPCIsMgmt))
	t.Expect(dns.State).To(Equal(types.DPCStateSuccess))
	t.Expect(dns.Testing).To(BeFalse())
	t.Expect(dns.DPCKey).To(Equal("lastresort"))
	t.Expect(dns.CurrentIndex).To(Equal(0))
	t.Expect(dns.RadioSilence.Imposed).To(BeFalse())
	t.Expect(dns.Ports).To(HaveLen(2))
	eth0State := dns.Ports[0]
	t.Expect(eth0State.IfName).To(Equal("eth0"))
	t.Expect(eth0State.LastSucceeded.After(eth0State.LastFailed)).To(BeTrue())
	t.Expect(eth0State.IfName).To(Equal("eth0"))
	t.Expect(eth0State.Phylabel).To(Equal("eth0"))
	t.Expect(eth0State.Logicallabel).To(Equal("eth0"))
	t.Expect(eth0State.LastError).To(BeEmpty())
	t.Expect(eth0State.AddrInfoList).To(HaveLen(1))
	t.Expect(eth0State.AddrInfoList[0].Addr.String()).To(Equal("192.168.10.5"))
	t.Expect(eth0State.AddrInfoList[0].LastGeoTimestamp.After(geoSetAt)).To(BeTrue())
	t.Expect(eth0State.AddrInfoList[0].Geo.IP).To(Equal("123.123.123.123"))
	t.Expect(eth0State.AddrInfoList[0].Geo.Hostname).To(Equal("hostname"))
	t.Expect(eth0State.AddrInfoList[0].Geo.City).To(Equal("Berlin"))
	t.Expect(eth0State.AddrInfoList[0].Geo.Country).To(Equal("Germany"))
	t.Expect(eth0State.AddrInfoList[0].Geo.Loc).To(Equal("52.51631, 13.37786"))
	t.Expect(eth0State.AddrInfoList[0].Geo.Org).To(Equal("fake ISP provider"))
	t.Expect(eth0State.AddrInfoList[0].Geo.Postal).To(Equal("999 99"))
	t.Expect(eth0State.IsMgmt).To(BeTrue())
	t.Expect(eth0State.IsL3Port).To(BeTrue())
	t.Expect(eth0State.DomainName).To(Equal("eth-test-domain"))
	t.Expect(eth0State.DNSServers).To(HaveLen(1))
	t.Expect(eth0State.DNSServers[0].String()).To(Equal("8.8.8.8"))
	t.Expect(eth0State.NtpServers).To(HaveLen(1))
	t.Expect(eth0State.NtpServers[0].String()).To(Equal("132.163.96.5"))
	t.Expect(eth0State.IPv4Subnet.String()).To(Equal("192.168.10.0/24"))
	t.Expect(eth0State.MacAddr.String()).To(Equal("02:00:00:00:00:01"))
	t.Expect(eth0State.Up).To(BeTrue())
	t.Expect(eth0State.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	t.Expect(eth0State.Dhcp).To(BeEquivalentTo(types.DhcpTypeClient))
	t.Expect(eth0State.DefaultRouters).To(HaveLen(1))
	t.Expect(eth0State.DefaultRouters[0].String()).To(Equal("192.168.10.1"))
	eth1State := dns.Ports[1]
	t.Expect(eth1State.IfName).To(Equal("eth1"))
	t.Expect(eth1State.LastFailed.After(eth1State.LastSucceeded)).To(BeTrue())
	t.Expect(eth1State.IfName).To(Equal("eth1"))
	t.Expect(eth1State.Phylabel).To(Equal("eth1"))
	t.Expect(eth1State.Logicallabel).To(Equal("eth1"))
	t.Expect(eth1State.LastError).To(Equal("failed to connect over eth1"))
	t.Expect(eth1State.AddrInfoList).To(HaveLen(1))
	t.Expect(eth1State.AddrInfoList[0].Addr.String()).To(Equal("172.20.1.2"))
	t.Expect(eth1State.IsMgmt).To(BeTrue())
	t.Expect(eth1State.IsL3Port).To(BeTrue())
	t.Expect(eth1State.DomainName).To(Equal("eth-test-domain"))
	t.Expect(eth1State.DNSServers).To(HaveLen(1))
	t.Expect(eth1State.DNSServers[0].String()).To(Equal("1.1.1.1"))
	t.Expect(eth1State.NtpServers).To(HaveLen(1))
	t.Expect(eth1State.NtpServers[0].String()).To(Equal("132.163.96.6"))
	t.Expect(eth1State.IPv4Subnet.String()).To(Equal("172.20.1.0/24"))
	t.Expect(eth1State.MacAddr.String()).To(Equal("02:00:00:00:00:02"))
	t.Expect(eth1State.Up).To(BeTrue())
	t.Expect(eth1State.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	t.Expect(eth1State.Dhcp).To(BeEquivalentTo(types.DhcpTypeClient))
	t.Expect(eth1State.DefaultRouters).To(HaveLen(1))
	t.Expect(eth1State.DefaultRouters[0].String()).To(Equal("172.20.1.1"))
}

func TestWireless(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	wlan0 := mockWlan0()
	wlan0.IPAddrs = nil
	wwan0 := mockWwan0()
	wwan0.IPAddrs = nil
	networkMonitor.AddOrUpdateInterface(wlan0)
	networkMonitor.AddOrUpdateInterface(wwan0)

	// Apply global config first.
	dpcManager.UpdateGCP(globalConfig())

	// Apply DPC with wireless connectivity only.
	aa := makeAA(selectedIntfs{wlan0: true, wwan0: true})
	timePrio1 := time.Now()
	dpc := makeDPC("zedagent", timePrio1, selectedIntfs{wlan0: true, wwan0: true})
	dpcManager.UpdateAA(aa)
	dpcManager.AddDPC(dpc)

	// Verification will wait for wwan config to be applied.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateWwanWait))

	// Simulate working wwan connectivity.
	rs := types.RadioSilence{}
	wwan0Status := mockWwan0Status(dpc, rs)
	dpcManager.ProcessWwanStatus(wwan0Status)
	wwan0 = mockWwan0() // with IP
	networkMonitor.AddOrUpdateInterface(wwan0)
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
	t.Eventually(func() bool {
		ports := getDNS().Ports
		return len(ports) == 2 && len(ports[1].AddrInfoList) == 1 &&
			ports[1].AddrInfoList[0].Addr.String() == "15.123.87.20"
	}).Should(BeTrue())

	// Check DNS content, it should include wwan state data.
	t.Eventually(wwanOpModeCb(types.WwanOpModeConnected)).Should(BeTrue())
	wwanDNS := wirelessStatusFromDNS(types.WirelessTypeCellular)
	t.Expect(wwanDNS.Cellular.Module.Name).To(Equal("353533101772021")) // IMEI put by DoSanitize()
	t.Expect(wwanDNS.Cellular.Module.OpMode).To(BeEquivalentTo(types.WwanOpModeConnected))
	t.Expect(wwanDNS.Cellular.Module.ControlProtocol).To(BeEquivalentTo(types.WwanCtrlProtQMI))
	t.Expect(wwanDNS.Cellular.Module.Revision).To(Equal("SWI9X50C_01.08.04.00"))
	t.Expect(wwanDNS.Cellular.ConfigError).To(BeEmpty())
	t.Expect(wwanDNS.Cellular.ProbeError).To(BeEmpty())
	t.Expect(wwanDNS.Cellular.CurrentProvider.Description).To(Equal("AT&T"))
	t.Expect(wwanDNS.Cellular.CurrentProvider.CurrentServing).To(BeTrue())
	t.Expect(wwanDNS.Cellular.CurrentProvider.PLMN).To(Equal("310-410"))
	t.Expect(wwanDNS.Cellular.VisibleProviders).To(HaveLen(2))
	t.Expect(wwanDNS.Cellular.VisibleProviders[0].Description).To(Equal("AT&T"))
	t.Expect(wwanDNS.Cellular.VisibleProviders[0].CurrentServing).To(BeTrue())
	t.Expect(wwanDNS.Cellular.VisibleProviders[0].PLMN).To(Equal("310-410"))
	t.Expect(wwanDNS.Cellular.VisibleProviders[1].Description).To(Equal("Telekom"))
	t.Expect(wwanDNS.Cellular.VisibleProviders[1].CurrentServing).To(BeFalse())
	t.Expect(wwanDNS.Cellular.VisibleProviders[1].PLMN).To(Equal("231-02"))
	t.Expect(wwanDNS.Cellular.SimCards).To(HaveLen(1))
	t.Expect(wwanDNS.Cellular.SimCards[0].Name).To(Equal("89012703578345957137")) // ICCID put by DoSanitize()
	t.Expect(wwanDNS.Cellular.SimCards[0].ICCID).To(Equal("89012703578345957137"))
	t.Expect(wwanDNS.Cellular.SimCards[0].IMSI).To(Equal("310180933695713"))
	t.Expect(wwanDNS.Cellular.SimCards[0].Type).To(Equal(types.SimTypePhysical))
	t.Expect(wwanDNS.Cellular.PhysAddrs.Interface).To(Equal("wwan0"))
	t.Expect(wwanDNS.Cellular.PhysAddrs.USB).To(Equal("1:3.3"))
	t.Expect(wwanDNS.Cellular.PhysAddrs.PCI).To(Equal("0000:f4:00.0"))

	// Simulate working wlan connectivity.
	wlan0 = mockWlan0() // with IP
	networkMonitor.AddOrUpdateInterface(wlan0)
	t.Eventually(func() bool {
		ports := getDNS().Ports
		return len(ports) == 2 && len(ports[0].AddrInfoList) == 1 &&
			ports[0].AddrInfoList[0].Addr.String() == "192.168.77.2"
	}).Should(BeTrue())

	// Impose radio silence.
	// But actually there is a config error coming from upper layers,
	// so there should be no change in the wwan config.
	rsImposedAt := time.Now()
	rs = types.RadioSilence{
		Imposed:           true,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsImposedAt,
		ConfigError:       "Error from upper layers",
	}
	dpcManager.UpdateRadioSilence(rs)
	t.Eventually(func() bool {
		rs := getDNS().RadioSilence
		return rs.ConfigError == "Error from upper layers"
	}).Should(BeTrue())
	rs = getDNS().RadioSilence
	t.Expect(rs.ChangeRequestedAt.Equal(rsImposedAt)).To(BeTrue())
	t.Expect(rs.ConfigError).To(Equal("Error from upper layers"))
	t.Expect(rs.Imposed).To(BeFalse())
	t.Expect(rs.ChangeInProgress).To(BeFalse())
	wwan := dg.Reference(generic.Wwan{})
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RadioSilence:false"))

	// Second attempt should be successful.
	rsImposedAt = time.Now()
	rs = types.RadioSilence{
		Imposed:           true,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsImposedAt,
	}
	dpcManager.UpdateRadioSilence(rs)
	t.Eventually(rsChangeInProgressCb()).Should(BeTrue())
	wwan0Status = mockWwan0Status(dpc, rs)
	wwan0Status.Networks[0].Module.OpMode = types.WwanOpModeRadioOff
	wwan0Status.Networks[0].ConfigError = ""
	dpcManager.ProcessWwanStatus(wwan0Status)
	t.Eventually(wwanOpModeCb(types.WwanOpModeRadioOff)).Should(BeTrue())
	t.Eventually(rsChangeInProgressCb()).Should(BeFalse())
	rs = getDNS().RadioSilence
	t.Expect(rs.ChangeRequestedAt.Equal(rsImposedAt)).To(BeTrue())
	t.Expect(rs.ConfigError).To(BeEmpty())
	t.Expect(rs.Imposed).To(BeTrue())
	t.Expect(rs.ChangeInProgress).To(BeFalse())
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RadioSilence:true"))

	// Disable radio silence.
	rsLiftedAt := time.Now()
	rs = types.RadioSilence{
		Imposed:           false,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsLiftedAt,
	}
	dpcManager.UpdateRadioSilence(rs)
	t.Eventually(rsChangeInProgressCb()).Should(BeTrue())
	wwan0Status = mockWwan0Status(dpc, rs)
	wwan0Status.Networks[0].Module.OpMode = types.WwanOpModeConnected
	wwan0Status.Networks[0].ConfigError = ""
	dpcManager.ProcessWwanStatus(wwan0Status)
	t.Eventually(wwanOpModeCb(types.WwanOpModeConnected)).Should(BeTrue())
	t.Eventually(rsChangeInProgressCb()).Should(BeFalse())
	rs = getDNS().RadioSilence
	t.Expect(rs.ChangeRequestedAt.Equal(rsLiftedAt)).To(BeTrue())
	t.Expect(rs.ConfigError).To(BeEmpty())
	t.Expect(rs.Imposed).To(BeFalse())
	t.Expect(rs.ChangeInProgress).To(BeFalse())
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RadioSilence:false"))

	// Next simulate that wwan microservice failed to impose RS.
	rsImposedAt = time.Now()
	rs = types.RadioSilence{
		Imposed:           true,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsImposedAt,
	}
	dpcManager.UpdateRadioSilence(rs)
	t.Eventually(rsChangeInProgressCb()).Should(BeTrue())
	wwan0Status = mockWwan0Status(dpc, rs)
	wwan0Status.Networks[0].Module.OpMode = types.WwanOpModeOnline
	wwan0Status.Networks[0].ConfigError = "failed to impose RS"
	dpcManager.ProcessWwanStatus(wwan0Status)
	t.Eventually(wwanOpModeCb(types.WwanOpModeOnline)).Should(BeTrue())
	t.Eventually(rsChangeInProgressCb()).Should(BeFalse())
	rs = getDNS().RadioSilence
	t.Expect(rs.ChangeRequestedAt.Equal(rsImposedAt)).To(BeTrue())
	t.Expect(rs.ConfigError).To(Equal("mock-wwan0: failed to impose RS"))
	t.Expect(rs.Imposed).To(BeFalse())
	t.Expect(rs.ChangeInProgress).To(BeFalse())
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RadioSilence:true"))
}

func TestAddDPCDuringVerify(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth0.IPAddrs = nil // No connectivity via eth0.
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)

	// Two ethernet interface available for mgmt.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Apply global config first.
	dpcManager.UpdateGCP(globalConfig())

	// Apply "zedagent" DPC with eth0.
	timePrio1 := time.Now()
	dpc := makeDPC("zedagent", timePrio1, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)

	// Verification should start.
	t.Eventually(testingInProgressCb()).Should(BeTrue())

	// Add DPC while verification is still ongoing.
	time.Sleep(time.Second)
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth1: true})
	dpcManager.AddDPC(dpc)

	// Eventually the latest DPC will be chosen and the previous one
	// will be compressed out (it didn't get a chance to succeed).
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio2)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
}

func TestDPCWithAssignedInterface(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth0.IPAddrs = nil // eth0 does not provide working connectivity
	networkMonitor.AddOrUpdateInterface(eth0)

	// Two ethernet interface configured for mgmt.
	// However, eth1 is assigned to an application.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	appUUID, err := uuid.FromString("ccf4c2f8-1d0f-4b44-b55a-220f7a138f6d")
	t.Expect(err).To(BeNil())
	aa.IoBundleList[1].IsPCIBack = true
	aa.IoBundleList[1].UsedByUUID = appUUID
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply "zedagent" DPC with eth0 and eth1.
	timePrio1 := time.Now()
	dpc := makeDPC("zedagent", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)

	// Verification should fail.
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateFail))
	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio1)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateFail))
	t.Expect(dpcList[0].LastFailed.After(dpcList[0].LastSucceeded)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(Equal("port eth1 in PCIBack is used by ccf4c2f8-1d0f-4b44-b55a-220f7a138f6d"))

	// eth1 was released from the application but it is still in PCIBack.
	aa.IoBundleList[1].UsedByUUID = uuid.UUID{}
	dpcManager.UpdateAA(aa)
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStatePCIWait))

	// Finally the eth1 is released from PCIBack.
	aa.IoBundleList[1].IsPCIBack = false
	dpcManager.UpdateAA(aa)
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth1)
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
}

func TestDeleteDPC(test *testing.T) {
	t := initTest(test)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	networkMonitor.AddOrUpdateInterface(eth0)

	// Single interface configured for mgmt.
	aa := makeAA(selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)

	// Apply global config with lastresort enabled.
	dpcManager.UpdateGCP(globalConfigWithLastresort())
	lastResortTimePrio := time.Unix(0, 0)

	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("lastresort"))
	t.Eventually(dpcTimePrioCb(0, lastResortTimePrio)).Should(BeTrue())

	// Apply "zedagent" DPC.
	timePrio2 := time.Now()
	dpc := makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())

	// Remove "zedagent" DPC, the manager should apply lastresort again.
	dpcManager.DelDPC(dpc)
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("lastresort"))
	t.Eventually(dpcTimePrioCb(0, lastResortTimePrio)).Should(BeTrue())
}

func TestDPCWithReleasedAndRenamedInterface(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Two ethernet interface configured for mgmt.
	// However, both interfaces are assigned to PCIBack.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	aa.IoBundleList[0].IsPCIBack = true
	aa.IoBundleList[1].IsPCIBack = true
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply "zedagent" DPC with eth0 and eth1.
	timePrio1 := time.Now()
	dpc := makeDPC("zedagent", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStatePCIWait))

	// eth1 is released, but first it comes as "eth0" (first available name).
	// Domainmgr will rename it to eth1 but it will take some time.
	// (see the use of types.IfRename in updatePortAndPciBackIoMember() of domainmgr)
	eth1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1, // without assignments this would be the index of eth0
			IfName:        "eth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
	}
	networkMonitor.AddOrUpdateInterface(eth1)

	// Until AA is updated, DpcManager should ignore the interface
	// and not configure anything for it.
	eth0Dhcpcd := dg.Reference(generic.Dhcpcd{AdapterIfName: "eth0"})
	eth1Dhcpcd := dg.Reference(generic.Dhcpcd{AdapterIfName: "eth1"})
	t.Consistently(itemIsCreatedCb(eth0Dhcpcd)).Should(BeFalse())
	t.Consistently(itemIsCreatedCb(eth1Dhcpcd)).Should(BeFalse())
	dns := getDNS()
	t.Expect(dns.Ports).To(HaveLen(2))
	t.Expect(dns.Ports[0].Up).To(BeFalse())
	t.Expect(dns.Ports[1].Up).To(BeFalse())

	// Domainmgr performs the interface renaming.
	eth1.Attrs.IfName = "eth1"
	networkMonitor.DelInterface("eth0")
	networkMonitor.AddOrUpdateInterface(eth1)
	aa = makeAA(selectedIntfs{eth0: true, eth1: true})
	aa.IoBundleList[0].IsPCIBack = true
	aa.IoBundleList[1].IsPCIBack = false
	dpcManager.UpdateAA(aa)
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateIPDNSWait))
	t.Eventually(itemIsCreatedCb(eth1Dhcpcd)).Should(BeTrue())

	// Simulate event of eth1 receiving IP addresses.
	eth1 = mockEth1()                             // with IPs
	eth1.Attrs.IfIndex = mockEth0().Attrs.IfIndex // index was not changed by domainmgr
	networkMonitor.AddOrUpdateInterface(eth1)
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
}

func TestVlansAndBonds(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	// Initially there are only physical network interfaces.
	eth0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       1,
			IfName:        "eth0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:01"),
	}
	eth1 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       2,
			IfName:        "eth1",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:02"),
	}
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)

	// Apply global config first.
	dpcManager.UpdateGCP(globalConfig())

	// Apply DPC with bond and VLAN sub-interfaces.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	timePrio1 := time.Now()
	dpc := types.DevicePortConfig{
		Version:      types.DPCIsMgmt,
		Key:          "zedagent",
		TimePriority: timePrio1,
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
					Dhcp: types.DhcpTypeClient,
					Type: types.NetworkTypeIPv4,
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
					Dhcp: types.DhcpTypeClient,
					Type: types.NetworkTypeIPv4,
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
	dpcManager.UpdateAA(aa)
	dpcManager.AddDPC(dpc)

	// Update simulated network stack.
	// Simulate that logical interfaces were created.
	bond0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       3,
			IfName:        "bond0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:03"),
	}
	shopfloor100 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       4,
			IfName:        "shopfloor.100",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:04"),
	}
	shopfloor200 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       5,
			IfName:        "shopfloor.200",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		HwAddr: macAddress("02:00:00:00:00:05"),
	}
	networkMonitor.AddOrUpdateInterface(bond0)
	networkMonitor.AddOrUpdateInterface(shopfloor100)
	networkMonitor.AddOrUpdateInterface(shopfloor200)

	// Verification will wait for IP addresses.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateIPDNSWait))

	// Simulate events of VLAN sub-interfaces receiving IP addresses from DHCP servers.
	shopfloor100.IPAddrs = []*net.IPNet{ipAddress("192.168.10.5/24")}
	shopfloor100.DHCP = netmonitor.DHCPInfo{
		IPv4Subnet:     ipSubnet("192.168.10.0/24"),
		IPv4NtpServers: netutils.NewHostnameOrIPs("132.163.96.5"),
	}
	shopfloor100.DNS = []netmonitor.DNSInfo{
		{
			ResolvConfPath: "/etc/shopfloor.100-resolv.conf",
			Domains:        []string{"vlan100-test-domain"},
			DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
		},
	}
	shopfloor200.IPAddrs = []*net.IPNet{ipAddress("172.20.1.2/24")}
	shopfloor200.DHCP = netmonitor.DHCPInfo{
		IPv4Subnet:     ipSubnet("172.20.1.0/24"),
		IPv4NtpServers: netutils.NewHostnameOrIPs("132.163.96.6"),
	}
	shopfloor200.DNS = []netmonitor.DNSInfo{
		{
			ResolvConfPath: "/etc/shopfloor.200-resolv.conf",
			Domains:        []string{"vlan200-test-domain"},
			DNSServers:     []net.IP{net.ParseIP("1.1.1.1")},
		},
	}
	networkMonitor.AddOrUpdateInterface(shopfloor100)
	networkMonitor.AddOrUpdateInterface(shopfloor200)
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
	// Eventually both VLAN sub-interfaces are reported as functional.
	t.Eventually(func() bool {
		dns := getDNS()
		return len(dns.Ports) == 5 &&
			dns.Ports[3].LastError == "" &&
			dns.Ports[4].LastError == ""
	}).Should(BeTrue())

	vlan100Ref := dg.Reference(linux.Vlan{IfName: "shopfloor.100"})
	t.Expect(itemIsCreated(vlan100Ref)).To(BeTrue())
	vlan200Ref := dg.Reference(linux.Vlan{IfName: "shopfloor.200"})
	t.Expect(itemIsCreated(vlan200Ref)).To(BeTrue())
	bondRef := dg.Reference(linux.Bond{IfName: "bond0"})
	t.Expect(itemIsCreated(bondRef)).To(BeTrue())

	// Check DNS content.
	dnsObj, _ := pubDNS.Get("global")
	dns := dnsObj.(types.DeviceNetworkStatus)
	t.Expect(dns.Version).To(Equal(types.DPCIsMgmt))
	t.Expect(dns.State).To(Equal(types.DPCStateSuccess))
	t.Expect(dns.Testing).To(BeFalse())
	t.Expect(dns.DPCKey).To(Equal("zedagent"))
	t.Expect(dns.CurrentIndex).To(Equal(0))
	t.Expect(dns.RadioSilence.Imposed).To(BeFalse())
	t.Expect(dns.Ports).To(HaveLen(5))
	eth0State := dns.Ports[0]
	t.Expect(eth0State.IfName).To(Equal("eth0"))
	t.Expect(eth0State.Phylabel).To(Equal("ethernet0"))
	t.Expect(eth0State.Logicallabel).To(Equal("shopfloor0"))
	t.Expect(eth0State.LastError).To(BeEmpty())
	t.Expect(eth0State.AddrInfoList).To(BeEmpty())
	t.Expect(eth0State.IsMgmt).To(BeFalse())
	t.Expect(eth0State.IsL3Port).To(BeFalse())
	t.Expect(eth0State.DomainName).To(BeEmpty())
	t.Expect(eth0State.DNSServers).To(BeEmpty())
	t.Expect(eth0State.NtpServers).To(BeEmpty())
	t.Expect(eth0State.IPv4Subnet).To(BeNil())
	t.Expect(eth0State.MacAddr.String()).To(Equal("02:00:00:00:00:01"))
	t.Expect(eth0State.Up).To(BeTrue())
	t.Expect(eth0State.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	t.Expect(eth0State.Dhcp).To(BeEquivalentTo(types.DhcpTypeNOOP))
	t.Expect(eth0State.DefaultRouters).To(BeEmpty())
	eth1State := dns.Ports[1]
	t.Expect(eth1State.IfName).To(Equal("eth1"))
	t.Expect(eth1State.Phylabel).To(Equal("ethernet1"))
	t.Expect(eth1State.Logicallabel).To(Equal("shopfloor1"))
	t.Expect(eth1State.LastError).To(BeEmpty())
	t.Expect(eth1State.AddrInfoList).To(BeEmpty())
	t.Expect(eth1State.IsMgmt).To(BeFalse())
	t.Expect(eth1State.IsL3Port).To(BeFalse())
	t.Expect(eth1State.DomainName).To(BeEmpty())
	t.Expect(eth1State.DNSServers).To(BeEmpty())
	t.Expect(eth1State.NtpServers).To(BeEmpty())
	t.Expect(eth1State.IPv4Subnet).To(BeNil())
	t.Expect(eth1State.MacAddr.String()).To(Equal("02:00:00:00:00:02"))
	t.Expect(eth1State.Up).To(BeTrue())
	t.Expect(eth1State.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	t.Expect(eth1State.Dhcp).To(BeEquivalentTo(types.DhcpTypeNOOP))
	t.Expect(eth1State.DefaultRouters).To(BeEmpty())
	bond0State := dns.Ports[2]
	t.Expect(bond0State.IfName).To(Equal("bond0"))
	t.Expect(bond0State.Logicallabel).To(Equal("bond-shopfloor"))
	t.Expect(bond0State.LastError).To(BeEmpty())
	t.Expect(bond0State.AddrInfoList).To(BeEmpty())
	t.Expect(bond0State.IsMgmt).To(BeFalse())
	t.Expect(bond0State.IsL3Port).To(BeFalse())
	t.Expect(bond0State.DomainName).To(BeEmpty())
	t.Expect(bond0State.DNSServers).To(BeEmpty())
	t.Expect(bond0State.NtpServers).To(BeEmpty())
	t.Expect(bond0State.IPv4Subnet).To(BeNil())
	t.Expect(bond0State.MacAddr.String()).To(Equal("02:00:00:00:00:03"))
	t.Expect(bond0State.Up).To(BeTrue())
	t.Expect(bond0State.Type).To(BeEquivalentTo(types.NetworkTypeNOOP))
	t.Expect(bond0State.Dhcp).To(BeEquivalentTo(types.DhcpTypeNOOP))
	t.Expect(bond0State.DefaultRouters).To(BeEmpty())
	vlan100State := dns.Ports[3]
	t.Expect(vlan100State.IfName).To(Equal("shopfloor.100"))
	t.Expect(vlan100State.Logicallabel).To(Equal("shopfloor-vlan100"))
	t.Expect(vlan100State.LastError).To(BeEmpty())
	t.Expect(vlan100State.AddrInfoList).To(HaveLen(1))
	t.Expect(vlan100State.AddrInfoList[0].Addr.String()).To(Equal("192.168.10.5"))
	t.Expect(vlan100State.IsMgmt).To(BeTrue())
	t.Expect(vlan100State.IsL3Port).To(BeTrue())
	t.Expect(vlan100State.DomainName).To(Equal("vlan100-test-domain"))
	t.Expect(vlan100State.DNSServers).To(HaveLen(1))
	t.Expect(vlan100State.DNSServers[0].String()).To(Equal("8.8.8.8"))
	t.Expect(vlan100State.NtpServers).To(HaveLen(1))
	t.Expect(vlan100State.NtpServers[0].String()).To(Equal("132.163.96.5"))
	t.Expect(vlan100State.IPv4Subnet.String()).To(Equal("192.168.10.0/24"))
	t.Expect(vlan100State.MacAddr.String()).To(Equal("02:00:00:00:00:04"))
	t.Expect(vlan100State.Up).To(BeTrue())
	t.Expect(vlan100State.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	t.Expect(vlan100State.Dhcp).To(BeEquivalentTo(types.DhcpTypeClient))
	t.Expect(vlan100State.DefaultRouters).To(BeEmpty())
	t.Expect(vlan100State.LastSucceeded.After(vlan100State.LastFailed)).To(BeTrue())
	vlan200State := dns.Ports[4]
	t.Expect(vlan200State.IfName).To(Equal("shopfloor.200"))
	t.Expect(vlan200State.Logicallabel).To(Equal("shopfloor-vlan200"))
	t.Expect(vlan200State.LastError).To(BeEmpty())
	t.Expect(vlan200State.AddrInfoList).To(HaveLen(1))
	t.Expect(vlan200State.AddrInfoList[0].Addr.String()).To(Equal("172.20.1.2"))
	t.Expect(vlan200State.IsMgmt).To(BeTrue())
	t.Expect(vlan200State.IsL3Port).To(BeTrue())
	t.Expect(vlan200State.DomainName).To(Equal("vlan200-test-domain"))
	t.Expect(vlan200State.DNSServers).To(HaveLen(1))
	t.Expect(vlan200State.DNSServers[0].String()).To(Equal("1.1.1.1"))
	t.Expect(vlan200State.NtpServers).To(HaveLen(1))
	t.Expect(vlan200State.NtpServers[0].String()).To(Equal("132.163.96.6"))
	t.Expect(vlan200State.IPv4Subnet.String()).To(Equal("172.20.1.0/24"))
	t.Expect(vlan200State.MacAddr.String()).To(Equal("02:00:00:00:00:05"))
	t.Expect(vlan200State.Up).To(BeTrue())
	t.Expect(vlan200State.Type).To(BeEquivalentTo(types.NetworkTypeIPv4))
	t.Expect(vlan200State.Dhcp).To(BeEquivalentTo(types.DhcpTypeClient))
	t.Expect(vlan200State.DefaultRouters).To(BeEmpty())
	t.Expect(vlan200State.LastSucceeded.After(vlan200State.LastFailed)).To(BeTrue())
}

func TestTransientDNSError(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth0.IPAddrs = nil // eth0 does not yet provide working connectivity
	eth0.DNS = []netmonitor.DNSInfo{}
	networkMonitor.AddOrUpdateInterface(eth0)

	// Apply global config first.
	gcp := globalConfig()
	gcp.SetGlobalValueInt(types.NetworkTestInterval, 30)
	gcp.SetGlobalValueInt(types.NetworkTestDuration, 3)
	dpcManager.UpdateGCP(gcp)

	// Apply "zedagent" DPC with single ethernet port.
	aa := makeAA(selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)
	timePrio1 := time.Now()
	dpc := makeDPC("zedagent", timePrio1, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)

	// Verification should wait for IP addresses and DNS servers.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateIPDNSWait))

	// Simulate an event of interface receiving IP and DNS config from DHCP.
	// However, let's pretend that the DNS resolver of the connection tester
	// has not reloaded DNS config yet.
	connTester.SetConnectivityError("zedagent", "eth0",
		&types.DNSNotAvailError{
			IfName: eth0.Attrs.IfName,
		})
	eth0 = mockEth0() // With IPAddrs and DNS.
	networkMonitor.AddOrUpdateInterface(eth0)
	// Do not mark DPC as failed yet - missing DNS could be a transient error.
	t.Consistently(testingInProgressCb(), 8*time.Second).Should(BeTrue())
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateIPDNSWait))
	dpc = getDPC(0)
	dpcEth0 := dpc.LookupPortByIfName("eth0")
	t.Expect(dpcEth0).ToNot(BeNil())
	t.Expect(dpcEth0.HasError()).To(BeTrue())
	t.Expect(dpcEth0.LastError).To(Equal("interface eth0: no DNS server available"))
	dns := getDNS()
	dnsEth0 := dns.LookupPortByIfName("eth0")
	t.Expect(dnsEth0).ToNot(BeNil())
	t.Expect(dnsEth0.HasError()).To(BeTrue())
	t.Expect(dnsEth0.LastError).To(Equal("interface eth0: no DNS server available"))

	// Eventually the DNS resolver reloads DNS config.
	connTester.SetConnectivityError("zedagent", "eth0", nil)
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
	dpc = getDPC(0)
	dpcEth0 = dpc.LookupPortByIfName("eth0")
	t.Expect(dpcEth0).ToNot(BeNil())
	t.Expect(dpcEth0.HasError()).To(BeFalse())
	t.Expect(dpcEth0.LastError).To(BeEmpty())
	dns = getDNS()
	dnsEth0 = dns.LookupPortByIfName("eth0")
	t.Expect(dnsEth0).ToNot(BeNil())
	t.Expect(dnsEth0.HasError()).To(BeFalse())
	t.Expect(dnsEth0.LastError).To(BeEmpty())
}

// Test DPC from before 7.3.0 which does not have IsL3Port flag.
func TestOldDPC(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	networkMonitor.AddOrUpdateInterface(eth0)

	// Single interface configured for mgmt.
	aa := makeAA(selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply "zedagent" DPC persisted by an older version of EVE,
	// which is missing IsL3Port flag.
	timePrio1 := time.Time{}
	dpc := makeDPC("zedagent", timePrio1, selectedIntfs{eth0: true})
	dpc.Ports[0].IsL3Port = false

	// This is run by nim for any input DPC to make sure that it is compliant
	// with the latest EVE version.
	dpc.DoSanitize(logObj, types.DPCSanitizeArgs{
		SanitizeTimePriority: true,
		SanitizeKey:          false,
		SanitizeName:         true,
		SanitizeL3Port:       true,
		SanitizeSharedLabels: true,
	})

	dpcManager.AddDPC(dpc)

	// Verification should succeed even with the old DPC.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// DPC manager should have applied L3 config for eth0 even if it was
	// not marked as L3 port in the old DPC.
	eth0Dhcpcd := dg.Reference(generic.Dhcpcd{AdapterIfName: "eth0"})
	t.Expect(itemIsCreated(eth0Dhcpcd)).To(BeTrue())
}

func TestRemoteTemporaryFailure(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	networkMonitor.AddOrUpdateInterface(eth0)

	// Single interface configured for mgmt.
	aa := makeAA(selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply initial "bootstrap" DPC with single ethernet port.
	timePrio1 := time.Now()
	dpc := makeDPC("bootstrap", timePrio1, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// Apply "zedagent" DPC with single ethernet port.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true})

	// Simulate certificate error, which is reported from ConnectivityTester to DpcManager
	// as a RemoteTemporaryFailure.
	connTester.SetConnectivityError("zedagent", "eth0",
		&conntester.RemoteTemporaryFailure{
			Endpoint:   "simulated-controller",
			WrappedErr: errors.New("certificate error"),
		})

	// Even though we are getting error from the simulated controller,
	// the connectivity is working and DPC should be marked as working
	// and replace the "bootstrap" DPC.
	// Previously, we had a bug that would result in DPCManager being
	// stuck in a loop inside runVerify, re-running verification
	// for the same DPC and constantly getting RemoteTemporaryFailure.
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcListLenCb()).Should(Equal(1)) // "bootstrap" compressed out
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateRemoteWait))
	dpc = getDPC(0)
	t.Expect(dpc.HasError()).To(BeFalse())
	t.Expect(dpc.HasWarning()).To(BeTrue())
	t.Expect(dpc.LastWarning).To(Equal(
		"Remote temporary failure (endpoint: simulated-controller): certificate error"))
}

// Test that a non-working, non-latest DPC is removed from the DPCL by compressDPCL
// if a newer DPC exists, regardless of whether the newer DPC provides working
// connectivity. This prevents the DPCL from growing beyond the pubsub size limit.
func TestRemovalOfOldNonWorkingDPCs(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)

	// Two interfaces available for mgmt.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	// Effectively disable test-better timer to avoid interference with the unit test.
	gcp := globalConfig()
	gcp.SetGlobalValueInt(types.NetworkTestBetterInterval, math.MaxUint32)
	dpcManager.UpdateGCP(gcp)

	// Apply initial "bootstrap" DPC using both ports
	timePrio1 := time.Now()
	dpc := makeDPC("bootstrap", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// Apply "zedagent" DPC which configures only eth0 and with config
	// that breaks connectivity.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true})
	dpc.Ports[0].Dhcp = types.DhcpTypeStatic
	dpc.Ports[0].AddrSubnet = "192.168.1.44/24"
	connTester.SetConnectivityError("zedagent", "eth0",
		errors.New("failed to connect over eth0"))
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())

	// Latest DPC from zedagent is not working, DPCManager therefore falls back to
	// the "bootstrap" DPC.
	t.Eventually(dpcIdxCb()).Should(Equal(1))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcListLenCb()).Should(Equal(2))

	// Apply "zedagent" DPC which configures only eth1 and with config
	// that also breaks connectivity.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth1: true})
	dpc.Ports[0].Dhcp = types.DhcpTypeStatic
	dpc.Ports[0].AddrSubnet = "10.10.5.22/24"
	connTester.SetConnectivityError("zedagent", "eth1",
		errors.New("failed to connect over eth1"))
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())

	// DPCManager should stay on "bootstrap" and the old "zedagent" DPC
	// should be compressed out.
	t.Eventually(dpcIdxCb()).Should(Equal(1))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcListLenCb()).Should(Equal(2))
	latestDPC := getDPC(0)
	t.Expect(latestDPC.Key).To(Equal("zedagent"))
	t.Expect(latestDPC.TimePriority.Equal(timePrio3)).To(BeTrue())
	t.Expect(latestDPC.State).To(Equal(types.DPCStateFailWithIPAndDNS))
}

// Test that DPCManager will temporarily use lastresort when there is no DPC
// available for bootstrapping, even if lastresort is not enabled by config.
func TestNoDPCForBootstrap(test *testing.T) {
	expectBootstrapDPC := false
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	networkMonitor.AddOrUpdateInterface(eth0)

	// Single interface configured for mgmt.
	aa := makeAA(selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)

	// Apply global config, lastresort is not enabled.
	dpcManager.UpdateGCP(globalConfig())

	// Even though lastresort is disabled, DPCManager will use it because
	// there is no DPC available to bootstrap controller connectivity.
	lastResortTimePrio := time.Unix(0, 0)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("lastresort"))
	t.Expect(dpcList[0].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())

	// Apply "zedagent" DPC but with failing connectivity -- lastresort should be retained.
	timePrio2 := time.Now()
	dpc := makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true})
	connTester.SetConnectivityError("zedagent", "eth0",
		errors.New("failed to connect over eth0"))
	dpcManager.AddDPC(dpc)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateFailWithIPAndDNS))
	t.Eventually(dpcIdxCb()).Should(Equal(1))
	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(1)) // not the highest priority
	t.Expect(dpcList).To(HaveLen(2))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio2)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateFailWithIPAndDNS))
	t.Expect(dpcList[0].LastFailed.After(dpcList[0].LastSucceeded)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(
		Equal("not enough working ports (0); failed with: " +
			"[failed to connect over eth0]"))
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())

	// Now put a working zedagent DPC. Lastresort should be eventually removed because
	// it is not enabled by config to always stay around.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth0: true})
	connTester.SetConnectivityError("zedagent", "eth0", nil)
	dpcManager.AddDPC(dpc)

	t.Eventually(dpcListLenCb()).Should(Equal(1))
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio3)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
}

// Test that if there is no DPC available within DpcAvailTimeLimit (in the unit test
// only 3 seconds, in reality 1 minute), DPCManager will use lastresort
// (even if it is disabled by config).
func TestDpcAvailTimeLimit(test *testing.T) {
	// Let's trick DPCManager to wait for a DPC, but nothing will be actually submitted
	// and the timer should fire.
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	networkMonitor.AddOrUpdateInterface(eth0)

	// Single interface configured for mgmt.
	aa := makeAA(selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)

	// Apply global config, lastresort is not enabled.
	dpcManager.UpdateGCP(globalConfig())

	// Even though lastresort is disabled, DPCManager will use it because
	// it receives no DPC within DpcAvailTimeLimit.
	lastResortTimePrio := time.Unix(0, 0)
	t.Eventually(dpcListLenCb()).Should(Equal(1))
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("lastresort"))
	t.Expect(dpcList[0].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())

	// Now put a working zedagent DPC. Lastresort should be eventually removed because
	// it is not enabled by config to always stay around.
	timePrio2 := time.Now()
	dpc := makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true})
	connTester.SetConnectivityError("zedagent", "eth0", nil)
	dpcManager.AddDPC(dpc)

	t.Eventually(dpcListLenCb()).Should(Equal(1))
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
}

// When the set of ethernet ports available for management changes,
// Lastresort DPC should be updated.
func TestLastresortUpdate(test *testing.T) {
	t := initTest(test)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)

	// Two ethernet interface configured for mgmt.
	// However, eth1 is assigned to an application initially.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	appUUID, err := uuid.FromString("ccf4c2f8-1d0f-4b44-b55a-220f7a138f6d")
	t.Expect(err).To(BeNil())
	aa.IoBundleList[1].IsPCIBack = true
	aa.IoBundleList[1].UsedByUUID = appUUID
	dpcManager.UpdateAA(aa)

	// Apply global config first.
	// "lastresort" DPC will be created by DPCManager.
	dpcManager.UpdateGCP(globalConfigWithLastresort())
	lastResortTimePrio := time.Unix(0, 0)

	// Lastresort verification should succeed.
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// Only eth0 is used in lastresort DPC.
	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("lastresort"))
	t.Expect(dpcList[0].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	t.Expect(dpcList[0].Ports).To(HaveLen(1))
	t.Expect(dpcList[0].Ports[0].IfName).To(Equal("eth0"))

	// Now simulate that eth1 was unassigned from an application and is therefore available
	// for management and should be added into lastresort.
	aa = makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return !dns.Testing && len(ports) == 2
	}).Should(BeTrue())
	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("lastresort"))
	t.Expect(dpcList[0].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	t.Expect(dpcList[0].Ports).To(HaveLen(2))
	t.Expect(dpcList[0].Ports[0].IfName).To(Equal("eth0"))
	t.Expect(dpcList[0].Ports[1].IfName).To(Equal("eth1"))
}

func TestDPCWithIPv6(test *testing.T) {
	t := initTest(test)
	t.Expect(dpcManager.GetDNS().DPCKey).To(BeEmpty())

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth2 := mockEth2() // has IPv6 address
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth2)
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), mockEth2Routes()...))
	// lastresort will work through one interface (the one with IPv6 address)
	connTester.SetConnectivityError("lastresort", "eth0",
		errors.New("failed to connect over eth0"))
	// DPC "zedagent" will not work at all
	connTester.SetConnectivityError("zedagent", "eth0",
		errors.New("failed to connect over eth0"))
	connTester.SetConnectivityError("zedagent", "eth2",
		errors.New("failed to connect over eth2"))

	// Apply global config with enabled lastresort.
	dpcManager.UpdateGCP(globalConfigWithLastresort())
	lastResortTimePrio := time.Unix(0, 0)

	// Publish AssignableAdapters.
	aa := makeAA(selectedIntfs{eth0: true, eth2: true})
	dpcManager.UpdateAA(aa)

	// Verification should succeed even if connectivity over eth0 is failing.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	idx, dpcList := getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(1))
	t.Expect(dpcList[0].Key).To(Equal("lastresort"))
	t.Expect(dpcList[0].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	t.Expect(dpcList[0].Ports).To(HaveLen(2))
	// Check the working port.
	eth2Port := dpcList[0].Ports[1]
	t.Expect(eth2Port.IfName).To(Equal("eth2"))
	t.Expect(eth2Port.LastSucceeded.After(eth2Port.LastFailed)).To(BeTrue())
	t.Expect(eth2Port.IfName).To(Equal("eth2"))
	t.Expect(eth2Port.LastError).To(BeEmpty())

	// Put a new DPC.
	// This one will fail for both ports and thus manager should fallback to lastresort.
	timePrio2 := time.Now()
	dpc := makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true, eth2: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateFailWithIPAndDNS))
	t.Eventually(dpcIdxCb()).Should(Equal(1))
	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(1)) // not the highest priority
	t.Expect(dpcList).To(HaveLen(2))
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio2)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateFailWithIPAndDNS))
	t.Expect(dpcList[0].LastFailed.After(dpcList[0].LastSucceeded)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(
		Equal("not enough working ports (0); failed with: " +
			"[failed to connect over eth2 failed to connect over eth0]"))
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(lastResortTimePrio)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())

	// Put a new good DPC, configuring only eth2.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth2: true})
	connTester.SetConnectivityError("zedagent", "eth2", nil)
	dpcManager.AddDPC(dpc)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	idx, dpcList = getDPCList()
	t.Expect(idx).To(Equal(0))
	t.Expect(dpcList).To(HaveLen(2)) // last-resort is enabled and therefore not compressed out
	t.Expect(dpcList[0].Key).To(Equal("zedagent"))
	t.Expect(dpcList[0].TimePriority.Equal(timePrio3)).To(BeTrue())
	t.Expect(dpcList[0].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[0].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[0].LastError).To(BeEmpty())
	t.Expect(dpcList[0].Ports).To(HaveLen(1))
	eth2Port = dpcList[0].Ports[0]
	t.Expect(eth2Port.IfName).To(Equal("eth2"))
	t.Expect(eth2Port.LastSucceeded.After(eth2Port.LastFailed)).To(BeTrue())
	t.Expect(eth2Port.IfName).To(Equal("eth2"))
	t.Expect(eth2Port.LastError).To(BeEmpty())

	// Check DNS.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return dns.DPCKey == "zedagent" && !dns.Testing && len(ports) == 1
	}).Should(BeTrue())

	// Check DNS content.
	dnsObj, _ := pubDNS.Get("global")
	dns := dnsObj.(types.DeviceNetworkStatus)
	t.Expect(dns.Version).To(Equal(types.DPCIsMgmt))
	t.Expect(dns.State).To(Equal(types.DPCStateSuccess))
	t.Expect(dns.Testing).To(BeFalse())
	t.Expect(dns.DPCKey).To(Equal("zedagent"))
	t.Expect(dns.CurrentIndex).To(Equal(0))
	t.Expect(dns.RadioSilence.Imposed).To(BeFalse())
	t.Expect(dns.Ports).To(HaveLen(1))
	eth2State := dns.Ports[0]
	t.Expect(eth2State.IfName).To(Equal("eth2"))
	t.Expect(eth2State.LastSucceeded.After(eth2State.LastFailed)).To(BeTrue())
	t.Expect(eth2State.IfName).To(Equal("eth2"))
	t.Expect(eth2State.Phylabel).To(Equal("eth2"))
	t.Expect(eth2State.Logicallabel).To(Equal("mock-eth2"))
	t.Expect(eth2State.LastError).To(BeEmpty())
	t.Expect(eth2State.AddrInfoList).To(HaveLen(1))
	t.Expect(eth2State.AddrInfoList[0].Addr.String()).To(Equal("2001:1111::1"))
	t.Expect(eth2State.IsMgmt).To(BeTrue())
	t.Expect(eth2State.IsL3Port).To(BeTrue())
	t.Expect(eth2State.DomainName).To(Equal("eth2-ipv6-test-domain"))
	t.Expect(eth2State.DNSServers).To(HaveLen(2))
	t.Expect(eth2State.DNSServers[0].String()).To(Equal("2001:4860:4860::8888"))
	t.Expect(eth2State.DNSServers[1].String()).To(Equal("2001:4860:4860::8844"))
	t.Expect(eth2State.NtpServers).To(HaveLen(1))
	t.Expect(eth2State.NtpServers[0].String()).To(Equal("2001:db8:3c4d:15::1"))
	t.Expect(eth2State.IPv4Subnet).To(BeNil())
	t.Expect(eth2State.IPv6Subnets).To(HaveLen(1))
	t.Expect(eth2State.IPv6Subnets[0].String()).To(Equal("2001:1111::/64"))
	t.Expect(eth2State.MacAddr.String()).To(Equal("02:00:00:00:00:03"))
	t.Expect(eth2State.Up).To(BeTrue())
	t.Expect(eth2State.Type).To(BeEquivalentTo(types.NetworkTypeIpv6Only))
	t.Expect(eth2State.Dhcp).To(BeEquivalentTo(types.DhcpTypeClient))
	t.Expect(eth2State.DefaultRouters).To(HaveLen(1))
	t.Expect(eth2State.DefaultRouters[0].String()).To(Equal("fe80::c225:2fff:fea2:dc73"))
}

func TestOverrideDhcpGateway(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), mockEth1Routes()...))

	// Two interfaces available for mgmt.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply initial "bootstrap" DPC using both ports.
	timePrio1 := time.Now()
	dpc := makeDPC("bootstrap", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.1")).Should(BeTrue())
	t.Expect(dhcpcdArgs("eth1")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 5000"))

	// Apply "zedagent" DPC which enables DHCP but overwrites gateway for eth1.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true, eth1: true})
	eth1StaticGw := net.ParseIP("172.20.1.100")
	dpc.Ports[1].Gateway = eth1StaticGw
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	newEth1DefRoute := netmonitor.Route{
		IfIndex: 2,
		Dst:     nil,
		Gw:      eth1StaticGw,
		Table:   syscall.RT_TABLE_MAIN,
		Data: netlink.Route{
			LinkIndex: 2,
			Dst:       nil,
			Gw:        eth1StaticGw,
			Table:     syscall.RT_TABLE_MAIN,
			Family:    netlink.FAMILY_V4,
		},
	}
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), newEth1DefRoute))
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check routing table for default route update.
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.100")).Should(BeTrue())
	t.Expect(dhcpcdArgs("eth1")).To(ContainSubstring("--static routers=172.20.1.100"))
	t.Expect(itemIsCreatedWithLabel("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.1")).To(BeFalse())

	// Check device network state.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 && len(ports[1].DefaultRouters) == 1 &&
			netutils.EqualIPs(ports[1].DefaultRouters[0], eth1StaticGw)
	}).Should(BeTrue())

	// Apply new "zedagent" DPC, which removes the static gateway previously set
	// for eth1, allowing it to fall back to the gateway provided via DHCP.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), mockEth1Routes()...))
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio3)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.1")).Should(BeTrue())
	t.Expect(dhcpcdArgs("eth1")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 5000"))

	// Check device network state.
	eth1DhcpGw := net.ParseIP("172.20.1.1")
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 && len(ports[1].DefaultRouters) == 1 &&
			netutils.EqualIPs(ports[1].DefaultRouters[0], eth1DhcpGw)
	}).Should(BeTrue())

	// Apply new "zedagent" DPC, which enabled IgnoreDhcpGateways while leaving the static
	// gateway unset. This should have the effect of configuring the interface without
	// default route.
	timePrio4 := time.Now()
	dpc = makeDPC("zedagent", timePrio4, selectedIntfs{eth0: true, eth1: true})
	dpc.Ports[1].IgnoreDhcpGateways = true
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	networkMonitor.UpdateRoutes(mockEth0Routes())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio4)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.1")).Should(Not(BeTrue()))
	t.Expect(dhcpcdArgs("eth1")).To(ContainSubstring("--nogateway"))

	// Check device network state.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 && len(ports[1].DefaultRouters) == 0
	}).Should(BeTrue())
}

func TestOverrideDhcpIPs(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	eth1DhcpGw := net.ParseIP("172.20.1.1")
	eth1DhcpSubnet := ipSubnet("172.20.1.0/24")
	eth1DefaultRoute := netmonitor.Route{
		IfIndex: 2,
		Dst:     nil,
		Gw:      eth1DhcpGw,
		Table:   syscall.RT_TABLE_MAIN,
		Data: netlink.Route{
			LinkIndex: 2,
			Dst:       nil,
			Gw:        eth1DhcpGw,
			Table:     syscall.RT_TABLE_MAIN,
			Family:    netlink.FAMILY_V4,
			Scope:     netlink.SCOPE_UNIVERSE,
		},
	}
	eth1LinkRoute := netmonitor.Route{
		IfIndex: 2,
		Dst:     eth1DhcpSubnet,
		Table:   syscall.RT_TABLE_MAIN,
		Data: netlink.Route{
			LinkIndex: 2,
			Dst:       eth1DhcpSubnet,
			Table:     syscall.RT_TABLE_MAIN,
			Family:    netlink.FAMILY_V4,
			Scope:     netlink.SCOPE_LINK,
			Protocol:  unix.RTPROT_DHCP,
		},
	}
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), eth1DefaultRoute, eth1LinkRoute))

	// Two interfaces available for mgmt.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply initial "bootstrap" DPC using both ports.
	timePrio1 := time.Now()
	dpc := makeDPC("bootstrap", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.1")).Should(BeTrue())
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst 172.20.1.0/24 dev mock-eth1 via <nil>")).Should(BeTrue())
	t.Expect(adapterStaticIPs("eth1")).To(BeEmpty())

	// Check device network state.
	eth1DhcpIP := ipAddress("172.20.1.2/24")
	expectedAddrs := []types.AddrInfo{
		{Addr: eth1DhcpIP.IP},
	}
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].AddrInfoList, expectedAddrs, equalPortAddresses)
	}).Should(BeTrue())

	// Apply "zedagent" DPC which enables DHCP but additionally adds another IP for eth1.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true, eth1: true})
	eth1StaticIP := ipAddress("172.20.1.200/24")
	dpc.Ports[1].AddrSubnet = eth1StaticIP.String()
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	eth1.IPAddrs = []*net.IPNet{eth1DhcpIP, eth1StaticIP}
	networkMonitor.AddOrUpdateInterface(eth1)
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check routing table and the adapter for IP update.
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.1")).Should(BeTrue())
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst 172.20.1.0/24 dev mock-eth1 via <nil>")).Should(BeTrue())
	t.Expect(generics.EqualSetsFn(adapterStaticIPs("eth1"), []*net.IPNet{eth1StaticIP}, netutils.EqualIPNets)).To(BeTrue())

	// Check device network state.
	expectedAddrs = []types.AddrInfo{
		{Addr: eth1DhcpIP.IP}, {Addr: eth1StaticIP.IP},
	}
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].AddrInfoList, expectedAddrs, equalPortAddresses)
	}).Should(BeTrue())

	// Apply new "zedagent" DPC which overwrites DHCP IP with a static address.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth0: true, eth1: true})
	eth1StaticIP = ipAddress("172.20.10.10/16")
	dpc.Ports[1].AddrSubnet = eth1StaticIP.String()
	dpc.Ports[1].IgnoreDhcpIPAddresses = true
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	eth1.IPAddrs = []*net.IPNet{eth1DhcpIP, eth1StaticIP} // dhcpcd still assigns the DHCP-received IP, EVE just ignores it
	networkMonitor.AddOrUpdateInterface(eth1)
	eth1StaticSubnet := ipSubnet("172.20.0.0/16")
	eth1LinkRoute2 := netmonitor.Route{
		IfIndex: 2,
		Dst:     eth1StaticSubnet,
		Table:   syscall.RT_TABLE_MAIN,
		Data: netlink.Route{
			LinkIndex: 2,
			Dst:       eth1StaticSubnet,
			Table:     syscall.RT_TABLE_MAIN,
			Family:    netlink.FAMILY_V4,
			Scope:     netlink.SCOPE_LINK,
			Protocol:  unix.RTPROT_DHCP,
		},
	}
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), eth1DefaultRoute, eth1LinkRoute, eth1LinkRoute2))
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio3)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check routing table and the adapter for IP update.
	// Note that the DHCP-received gateway was not statically changed.
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst <default> dev mock-eth1 via 172.20.1.1")).Should(BeTrue())
	t.Eventually(itemIsCreatedWithLabelCb("IPv4 route table 502 dst 172.20.0.0/16 dev mock-eth1 via <nil>")).Should(BeTrue())
	t.Expect(generics.EqualSetsFn(adapterStaticIPs("eth1"), []*net.IPNet{eth1StaticIP}, netutils.EqualIPNets)).To(BeTrue())

	// Check device network state.
	expectedAddrs = []types.AddrInfo{
		{Addr: eth1StaticIP.IP},
	}
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].AddrInfoList, expectedAddrs, equalPortAddresses)
	}).Should(BeTrue())

	// The final "zedagent" DPC clears the static IP and at the same time enabled the flag
	// to ignore DHCP-received IP addresses, meaning that no IP address should be configured
	// on the interface.
	timePrio4 := time.Now()
	dpc = makeDPC("zedagent", timePrio4, selectedIntfs{eth0: true, eth1: true})
	dpc.Ports[1].AddrSubnet = ""
	dpc.Ports[1].IgnoreDhcpIPAddresses = true
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	eth1.IPAddrs = []*net.IPNet{eth1DhcpIP} // dhcpcd still assigns the DHCP-received IP, EVE just ignores it
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), eth1DefaultRoute, eth1LinkRoute))
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio4)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check routing table and the adapter for IP update.
	t.Eventually(ipRoutesCb(502, false)).Should(BeEmpty())
	t.Expect(adapterStaticIPs("eth1")).To(BeEmpty())

	// Check device network state.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 && len(ports[1].AddrInfoList) == 0
	}).Should(BeTrue())
}

func TestOverrideDhcpDNS(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), mockEth1Routes()...))

	// Two interfaces available for mgmt.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply initial "bootstrap" DPC using both ports.
	timePrio1 := time.Now()
	dpc := makeDPC("bootstrap", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
	eth1DhcpDNS := net.ParseIP("1.1.1.1")
	expDNSServers := []net.IP{eth1DhcpDNS}
	t.Expect(generics.EqualSetsFn(dnsServers("eth1"), expDNSServers, netutils.EqualIPs)).To(BeTrue())

	// Check device network state.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].DNSServers, expDNSServers, netutils.EqualIPs) &&
			ports[1].DomainName == "eth-test-domain"
	}).Should(BeTrue())

	// Apply "zedagent" DPC which enables DHCP but additionally adds some DNS servers for eth1.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true, eth1: true})
	eth1StaticDNS1 := net.ParseIP("8.8.8.8")
	eth1StaticDNS2 := net.ParseIP("192.168.50.40")
	dpc.Ports[1].DNSServers = []net.IP{eth1StaticDNS1, eth1StaticDNS2}
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check resolv.conf after the DNS config update.
	expDNSServers = []net.IP{eth1DhcpDNS, eth1StaticDNS1, eth1StaticDNS2}
	t.Expect(generics.EqualSetsFn(dnsServers("eth1"), expDNSServers, netutils.EqualIPs)).To(BeTrue())

	// Check device network state.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].DNSServers, expDNSServers, netutils.EqualIPs) &&
			ports[1].DomainName == "eth-test-domain"
	}).Should(BeTrue())

	// Apply new "zedagent" DPC which replaces DHCP-received DNS servers with statically configured ones.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth0: true, eth1: true})
	dpc.Ports[1].DNSServers = []net.IP{eth1StaticDNS1, eth1StaticDNS2}
	dpc.Ports[1].IgnoreDhcpDNSConfig = true
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio3)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check resolv.conf after the DNS config update.
	expDNSServers = []net.IP{eth1StaticDNS1, eth1StaticDNS2}
	t.Expect(generics.EqualSetsFn(dnsServers("eth1"), expDNSServers, netutils.EqualIPs)).To(BeTrue())

	// Check device network state.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].DNSServers, expDNSServers, netutils.EqualIPs) &&
			ports[1].DomainName == "" // cleared by static config
	}).Should(BeTrue())

	// Apply new "zedagent" DPC which configures no static DNS servers and at the same
	// time enables the flag to ignore DHCP-received DNS servers, thus no DNS servers
	// should be configured.
	// We set some DomainName just to test this as well.
	timePrio4 := time.Now()
	dpc = makeDPC("zedagent", timePrio4, selectedIntfs{eth0: true, eth1: true})
	dpc.Ports[1].DNSServers = nil
	dpc.Ports[1].DomainName = "test-domain"
	dpc.Ports[1].IgnoreDhcpDNSConfig = true
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio4)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check resolv.conf after the DNS config update.
	expDNSServers = []net.IP{}
	t.Expect(generics.EqualSetsFn(dnsServers("eth1"), expDNSServers, netutils.EqualIPs)).To(BeTrue())

	// Check device network state.
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].DNSServers, expDNSServers, netutils.EqualIPs) &&
			ports[1].DomainName == "test-domain"
	}).Should(BeTrue())
}

func TestOverrideDhcpNTP(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.UpdateRoutes(append(mockEth0Routes(), mockEth1Routes()...))

	// Two interfaces available for mgmt.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply initial "bootstrap" DPC using both ports.
	timePrio1 := time.Now()
	dpc := makeDPC("bootstrap", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// Check device network state.
	eth1DhcpNTP := netutils.NewHostnameOrIP("132.163.96.6")
	expNTPServers := []netutils.HostnameOrIP{eth1DhcpNTP}
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].NtpServers, expNTPServers, netutils.EqualHostnameOrIPs)
	}).Should(BeTrue())

	// Apply "zedagent" DPC which enables DHCP but additionally adds some NTP servers for eth1.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true, eth1: true})
	eth1StaticNTP1 := netutils.NewHostnameOrIP("129.6.15.28")
	eth1StaticNTP2 := netutils.NewHostnameOrIP("time.google.com")
	dpc.Ports[1].NTPServers = []netutils.HostnameOrIP{eth1StaticNTP1, eth1StaticNTP2}
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check device network state.
	expNTPServers = []netutils.HostnameOrIP{eth1DhcpNTP, eth1StaticNTP1, eth1StaticNTP2}
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].NtpServers, expNTPServers, netutils.EqualHostnameOrIPs)
	}).Should(BeTrue())

	// Apply new "zedagent" DPC which replaces DHCP-received NTP servers with statically configured ones.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth0: true, eth1: true})
	dpc.Ports[1].NTPServers = []netutils.HostnameOrIP{eth1StaticNTP1, eth1StaticNTP2}
	dpc.Ports[1].IgnoreDhcpNtpServers = true
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio3)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check device network state.
	expNTPServers = []netutils.HostnameOrIP{eth1StaticNTP1, eth1StaticNTP2}
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].NtpServers, expNTPServers, netutils.EqualHostnameOrIPs)
	}).Should(BeTrue())

	// Apply new "zedagent" DPC which configures no static NTP servers and at the same
	// time enables the flag to ignore DHCP-received NTP servers, thus no NTP servers
	// should be configured.
	timePrio4 := time.Now()
	dpc = makeDPC("zedagent", timePrio4, selectedIntfs{eth0: true, eth1: true})
	dpc.Ports[1].NTPServers = nil
	dpc.Ports[1].IgnoreDhcpNtpServers = true
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio4)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check device network state.
	expNTPServers = nil
	t.Eventually(func() bool {
		dnsObj, _ := pubDNS.Get("global")
		dns := dnsObj.(types.DeviceNetworkStatus)
		ports := dns.Ports
		return len(ports) == 2 &&
			generics.EqualSetsFn(ports[1].NtpServers, expNTPServers, netutils.EqualHostnameOrIPs)
	}).Should(BeTrue())
}

func TestLPSConfig(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	wlan0 := mockWlan0()
	wlan0.IPAddrs = nil
	wwan0 := mockWwan0()
	wwan0.IPAddrs = nil
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.AddOrUpdateInterface(wlan0)
	networkMonitor.AddOrUpdateInterface(wwan0)

	// Apply global config first.
	dpcManager.UpdateGCP(globalConfig())

	// Apply "zedagent" DPC, allowing local changes for wireless adapters and eth1,
	// but not for eth0.
	intfs := selectedIntfs{eth0: true, eth1: true, wlan0: true, wwan0: true}
	aa := makeAA(intfs)
	timePrio1 := time.Now()
	dpc := makeDPC("zedagent", timePrio1, intfs)
	dpc.Ports[0].AllowLocalModifications = false // eth0
	dpc.Ports[1].AllowLocalModifications = true  // eth1
	dpc.Ports[2].AllowLocalModifications = true  // wlan0
	dpc.Ports[3].AllowLocalModifications = true  // wwan0
	dpcManager.UpdateAA(aa)
	dpcManager.AddDPC(dpc)

	// Simulate working wlan connectivity.
	wlan0 = mockWlan0() // with IP
	networkMonitor.AddOrUpdateInterface(wlan0)

	// Simulate working wwan connectivity.
	rs := types.RadioSilence{}
	wwan0Status := mockWwan0Status(dpc, rs)
	dpcManager.ProcessWwanStatus(wwan0Status)
	wwan0 = mockWwan0() // with IP
	networkMonitor.AddOrUpdateInterface(wwan0)

	// Verification should succeed and eventually all interfaces are reported
	// with IP addresses.
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
	t.Eventually(func() bool {
		return portHasIP("mock-eth0", net.ParseIP("192.168.10.5")) &&
			portHasIP("mock-eth1", net.ParseIP("172.20.1.2")) &&
			portHasIP("mock-wlan0", net.ParseIP("192.168.77.2")) &&
			portHasIP("mock-wwan0", net.ParseIP("15.123.87.20"))
	}).Should(BeTrue())

	// Change eth1 and wwan0 config locally.
	eth1StaticDNS1 := net.ParseIP("8.8.8.8")
	eth1StaticDNS2 := net.ParseIP("192.168.50.40")
	eth1StaticNTP1 := netutils.NewHostnameOrIP("132.163.96.6")
	dpc = makeDPC("lps", time.Time{}, selectedIntfs{eth1: true, wwan0: true})
	eth1ChangedDhcpConfig := types.DhcpConfig{
		Dhcp:       types.DhcpTypeStatic,
		AddrSubnet: "172.20.1.50/24",
		Gateway:    net.ParseIP("10.10.1.1"),
		NTPServers: []netutils.HostnameOrIP{eth1StaticNTP1},
		DNSServers: []net.IP{eth1StaticDNS1, eth1StaticDNS2},
		Type:       types.NetworkTypeIpv4Only,
	}
	dpc.Ports[0].DhcpConfig = eth1ChangedDhcpConfig
	dpc.Ports[1].WirelessCfg.CellularV2.AccessPoints[0].APN = "changed-apn"
	dpcManager.AddDPC(dpc)

	// Simulate that eth1 got the statically configured IP.
	eth1 = mockEth1()
	eth1.IPAddrs = []*net.IPNet{ipAddress("172.20.1.50/24")}
	eth1.DHCP.IPv4NtpServers = []netutils.HostnameOrIP{eth1StaticNTP1}
	eth1.DNS[0].DNSServers = []net.IP{eth1StaticDNS1, eth1StaticDNS2}
	networkMonitor.AddOrUpdateInterface(eth1)

	// Still using the same underlying DPC, but with local changes overriding
	// eth1 and wwan0 configuration.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Wait until DNS reports the LPS config being used.
	zedagentSrc := types.PortConfigSource{
		Origin:      types.NetworkConfigOriginController,
		SubmittedAt: timePrio1,
	}
	lpsSrc := types.PortConfigSource{
		Origin: types.NetworkConfigOriginLPS,
	}
	t.Eventually(func() bool {
		return portHasConfigSource("mock-eth0", zedagentSrc) &&
			portHasConfigSource("mock-eth1", lpsSrc) &&
			portHasConfigSource("mock-wlan0", zedagentSrc) &&
			portHasConfigSource("mock-wwan0", lpsSrc) &&
			portHasIP("mock-eth1", net.ParseIP("172.20.1.50"))
	}).Should(BeTrue())

	// Check that local configuration is applied.
	t.Expect(getPortLpsConfigErr("mock-eth1")).To(BeEmpty())
	t.Expect(getPortLpsConfigErr("mock-wwan0")).To(BeEmpty())
	t.Expect(dhcpcdArgs("eth1")).To(ContainSubstring("--static ip_address=172.20.1.50/24"))
	wwan := dg.Reference(generic.Wwan{})
	t.Expect(itemDescription(wwan)).To(ContainSubstring("APN:changed-apn"))

	// Remove wwan APN change from the LPS config and also try to change
	// eth0 config, which should be forbidden.
	dpc = makeDPC("lps", time.Time{}, selectedIntfs{eth0: true, eth1: true})
	dpc.Ports[0].MTU = 9000
	dpc.Ports[1].DhcpConfig = eth1ChangedDhcpConfig
	dpcManager.AddDPC(dpc)

	// Still using the same underlying DPC, but with local changes overriding
	// eth1 configuration.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Wait until DNS reports the LPS config being used.
	t.Eventually(func() bool {
		return portHasConfigSource("mock-eth0", zedagentSrc) &&
			portHasConfigSource("mock-eth1", lpsSrc) &&
			portHasConfigSource("mock-wlan0", zedagentSrc) &&
			portHasConfigSource("mock-wwan0", zedagentSrc) &&
			portHasIP("mock-eth1", net.ParseIP("172.20.1.50"))
	}).Should(BeTrue())

	// Verify that:
	// - wwan0 has reverted to the controller-provided configuration,
	// - eth1 continues to use the LPS configuration,
	// - changing the MTU for eth0 via LPS was not permitted.
	t.Expect(getPortLpsConfigErr("mock-eth0")).To(Equal(
		"local modifications not permitted for port \"mock-eth0\""))
	t.Expect(getPortLpsConfigErr("mock-eth1")).To(BeEmpty())
	t.Expect(dhcpcdArgs("eth1")).To(ContainSubstring("--static ip_address=172.20.1.50/24"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("APN:apn"))

	// Simulate the controller submitting a new network configuration that
	// now permits local changes for eth0.
	//   - eth0 switches to the LPS configuration (previously denied),
	//   - wlan0 and wwan0 switch to the new controller configuration,
	//   - eth1 continues using the LPS-provided configuration.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, intfs)
	dpc.Ports[0].AllowLocalModifications = true // eth0
	dpc.Ports[1].AllowLocalModifications = true // eth1
	dpc.Ports[2].AllowLocalModifications = true // wlan0
	dpc.Ports[2].WirelessCfg.Wifi[0].SSID = "ssid2"
	dpc.Ports[3].AllowLocalModifications = true // wwan0
	dpc.Ports[3].WirelessCfg.CellularV2.AccessPoints[0].APN = "apn2"
	dpcManager.AddDPC(dpc)

	// Underlying DPC should change.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Wait until DNS reports:
	//  - eth0 using the LPS provided config
	//  - updated config timestamp for wlan0 and wwan0.
	zedagentSrcNew := types.PortConfigSource{
		Origin:      types.NetworkConfigOriginController,
		SubmittedAt: timePrio2,
	}
	t.Eventually(func() bool {
		return portHasConfigSource("mock-eth0", lpsSrc) &&
			portHasConfigSource("mock-eth1", lpsSrc) &&
			portHasConfigSource("mock-wlan0", zedagentSrcNew) &&
			portHasConfigSource("mock-wwan0", zedagentSrcNew) &&
			portHasIP("mock-eth1", net.ParseIP("172.20.1.50"))
	}).Should(BeTrue())

	// Verify that:
	// - eth0 is using LPS configuration with increased MTU
	// - eth1 continues to use the LPS configuration
	// - wlan0 and wwan0 use the new controller configuration.
	t.Expect(getPortLpsConfigErr("mock-eth0")).To(BeEmpty())
	t.Expect(getPortLpsConfigErr("mock-eth1")).To(BeEmpty())
	eth0PhysIf := dg.Reference(linux.PhysIf{PhysIfName: "eth0"})
	t.Expect(itemDescription(eth0PhysIf)).To(ContainSubstring("MTU:0x2328"))
	t.Expect(dhcpcdArgs("eth1")).To(ContainSubstring("--static ip_address=172.20.1.50/24"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("APN:apn2"))
	wlan := dg.Reference(linux.Wlan{})
	t.Expect(itemDescription(wlan)).To(ContainSubstring("SSID: ssid2"))

	// Now completely revert LPS configuration.
	// We do this by publishing LPS DPC with an empty set of ports.
	dpc = makeDPC("lps", time.Time{}, selectedIntfs{})
	dpcManager.AddDPC(dpc)

	// Underlying DPC remains the same.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Simulate that eth1 got back the original IP from DHCP.
	eth1 = mockEth1()
	networkMonitor.AddOrUpdateInterface(eth1)

	// Wait until DNS reports that all ports are using controller config.
	t.Eventually(func() bool {
		return portHasConfigSource("mock-eth0", zedagentSrcNew) &&
			portHasConfigSource("mock-eth1", zedagentSrcNew) &&
			portHasConfigSource("mock-wlan0", zedagentSrcNew) &&
			portHasConfigSource("mock-wwan0", zedagentSrcNew) &&
			portHasIP("mock-eth1", net.ParseIP("172.20.1.2"))
	}).Should(BeTrue())

	// Verify that all ports are using controller config.
	t.Expect(itemDescription(eth0PhysIf)).To(ContainSubstring("MTU:0x5dc"))
	t.Expect(dhcpcdArgs("eth1")).To(ContainSubstring("--request"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("APN:apn2"))
	t.Expect(itemDescription(wlan)).To(ContainSubstring("SSID: ssid2"))
}

func TestRouteMetrics(test *testing.T) {
	expectBootstrapDPC := true
	t := initTest(test, expectBootstrapDPC)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth1 := mockEth1()
	eth2 := mockEth2()
	wlan0 := mockWlan0()
	wwan0 := mockWwan0()
	networkMonitor.AddOrUpdateInterface(eth0)
	networkMonitor.AddOrUpdateInterface(eth1)
	networkMonitor.AddOrUpdateInterface(eth2)
	networkMonitor.AddOrUpdateInterface(wlan0)
	networkMonitor.AddOrUpdateInterface(wwan0)

	// 5 interfaces, all with management usage initially.
	aa := makeAA(selectedIntfs{
		eth0: true, eth1: true, eth2: true, wlan0: true, wwan0: true})
	dpcManager.UpdateAA(aa)

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply initial "bootstrap" DPC using all the ports for management.
	timePrio1 := time.Now()
	dpc := makeDPC("bootstrap", timePrio1, selectedIntfs{
		eth0: true, eth1: true, eth2: true, wlan0: true, wwan0: true})
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("bootstrap"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// Check route metrics assigned to ports.
	t.Expect(dhcpcdArgs("eth0")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 5002"))
	t.Expect(dhcpcdArgs("eth1")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 5000"))
	t.Expect(dhcpcdArgs("eth2")).To(Equal("--request -f /etc/dhcpcd.conf --ipv6only -b -t 0 --metric 5001"))
	t.Expect(dhcpcdArgs("wlan0")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 5003"))
	wwan := dg.Reference(generic.Wwan{})
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RouteMetric:5004"))

	// Apply "zedagent" DPC which changes eth1 and wlan0 usage to app-shared.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{
		eth0: true, eth1: true, eth2: true, wlan0: true, wwan0: true})
	dpc.Ports[1].IsMgmt = false
	dpc.Ports[3].IsMgmt = false
	dpcManager.AddDPC(dpc)
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Check route metrics assigned to ports after the change.
	t.Expect(dhcpcdArgs("eth0")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 5001"))
	t.Expect(dhcpcdArgs("eth1")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 10000"))
	t.Expect(dhcpcdArgs("eth2")).To(Equal("--request -f /etc/dhcpcd.conf --ipv6only -b -t 0 --metric 5000"))
	t.Expect(dhcpcdArgs("wlan0")).To(Equal("--request -f /etc/dhcpcd.conf --noipv4ll -b -t 0 --metric 10001"))
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RouteMetric:5002"))
}
