// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/eriknordmark/ipinfo"
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/lf-edge/eve/api/go/evecommon"
	dg "github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/conntester"
	dpcmngr "github.com/lf-edge/eve/pkg/pillar/dpcmanager"
	dpcrec "github.com/lf-edge/eve/pkg/pillar/dpcreconciler"
	generic "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/dpcreconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

var (
	logObj          *base.LogObject
	networkMonitor  *netmonitor.MockNetworkMonitor
	wwanWatcher     *MockWwanWatcher
	geoService      *MockGeoService
	dpcReconciler   *dpcrec.LinuxDpcReconciler
	dpcManager      *dpcmngr.DpcManager
	connTester      *conntester.MockConnectivityTester
	pubDummyDPC     pubsub.Publication // for logging
	pubDPCList      pubsub.Publication
	pubDNS          pubsub.Publication
	pubWwwanStatus  pubsub.Publication
	pubWwwanMetrics pubsub.Publication
	pubWwanLocInfo  pubsub.Publication
)

func initTest(test *testing.T) *GomegaWithT {
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
	pubWwwanStatus, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: "test",
			TopicType: types.WwanStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubWwwanMetrics, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: "test",
			TopicType: types.WwanMetrics{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubWwanLocInfo, err = ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: "test",
			TopicType: types.WwanLocationInfo{},
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
	wwanWatcher = &MockWwanWatcher{}
	geoService = &MockGeoService{}
	connTester = &conntester.MockConnectivityTester{
		TestDuration: 2 * time.Second,
	}
	dpcManager = &dpcmngr.DpcManager{
		Log:                      logObj,
		Watchdog:                 &MockWatchdog{},
		AgentName:                "test",
		WwanWatcher:              wwanWatcher,
		GeoService:               geoService,
		DpcMinTimeSinceFailure:   3 * time.Second,
		NetworkMonitor:           networkMonitor,
		DpcReconciler:            dpcReconciler,
		ConnTester:               connTester,
		PubDummyDevicePortConfig: pubDummyDPC,
		PubDevicePortConfigList:  pubDPCList,
		PubDeviceNetworkStatus:   pubDNS,
		PubWwanStatus:            pubWwwanStatus,
		PubWwanMetrics:           pubWwwanMetrics,
		PubWwanLocationInfo:      pubWwanLocInfo,
		ZedcloudMetrics:          zedcloud.NewAgentMetrics(),
	}
	ctx := reconciler.MockRun(context.Background())
	if err := dpcManager.Init(ctx); err != nil {
		log.Fatal(err)
	}
	if err := dpcManager.Run(ctx); err != nil {
		log.Fatal(err)
	}
	return t
}

func printCurrentState() {
	currentState := dpcReconciler.GetCurrentState()
	dotExporter := &dg.DotExporter{CheckDeps: true}
	dot, _ := dotExporter.Export(currentState)
	fmt.Println(dot)
}

func itemDescription(itemRef dg.ItemRef) string {
	item, _, _, found := dpcReconciler.GetCurrentState().Item(itemRef)
	if !found {
		return ""
	}
	return item.String()
}

func itemIsCreated(itemRef dg.ItemRef) bool {
	_, state, _, found := dpcReconciler.GetCurrentState().Item(itemRef)
	return found && state.IsCreated()
}

func itemIsCreatedCb(itemRef dg.ItemRef) func() bool {
	return func() bool {
		return itemIsCreated(itemRef)
	}
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
	return *gcp
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
			Subnet:     ipSubnet("192.168.10.0/24"),
			NtpServers: []net.IP{net.ParseIP("132.163.96.5")},
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/eth0-resolv.conf",
			Domains:        []string{"eth-test-domain"},
			DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
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
			Subnet:     ipSubnet("172.20.1.0/24"),
			NtpServers: []net.IP{net.ParseIP("132.163.96.6")},
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/eth1-resolv.conf",
			Domains:        []string{"eth-test-domain"},
			DNSServers:     []net.IP{net.ParseIP("1.1.1.1")},
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
				LinkIndex: 1,
				Dst:       nil,
				Gw:        gwIP,
				Table:     syscall.RT_TABLE_MAIN,
			},
		},
	}
}

func mockWlan0() netmonitor.MockInterface {
	wlan0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       3,
			IfName:        "wlan0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddress("192.168.77.2/24")},
		DHCP: netmonitor.DHCPInfo{
			Subnet:     ipSubnet("192.168.77.0/24"),
			NtpServers: []net.IP{net.ParseIP("129.6.15.32")},
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/wlan0-resolv.conf",
			Domains:        []string{"wlan-test-domain"},
			DNSServers:     []net.IP{net.ParseIP("192.168.77.13")},
		},
		HwAddr: macAddress("02:00:00:00:00:03"),
	}
	return wlan0
}

func mockWwan0() netmonitor.MockInterface {
	wlan0 := netmonitor.MockInterface{
		Attrs: netmonitor.IfAttrs{
			IfIndex:       4,
			IfName:        "wwan0",
			IfType:        "device",
			WithBroadcast: true,
			AdminUp:       true,
			LowerUp:       true,
		},
		IPAddrs: []*net.IPNet{ipAddress("15.123.87.20/28")},
		DHCP: netmonitor.DHCPInfo{
			Subnet:     ipSubnet("15.123.87.16/28"),
			NtpServers: []net.IP{net.ParseIP("128.138.141.177")},
		},
		DNS: netmonitor.DNSInfo{
			ResolvConfPath: "/etc/wlan0-resolv.conf",
			Domains:        []string{"wwan-test-domain"},
			DNSServers:     []net.IP{net.ParseIP("208.67.222.222")},
		},
		HwAddr: macAddress("02:00:00:00:00:04"),
	}
	return wlan0
}

func mockWwan0Status() types.WwanStatus {
	return types.WwanStatus{
		Networks: []types.WwanNetworkStatus{
			{
				LogicalLabel: "mock-wwan0",
				PhysAddrs: types.WwanPhysAddrs{
					Interface: "wwan0",
					USB:       "1:3.3",
					PCI:       "0000:04:00.0",
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
					},
				},
				Providers: []types.WwanProvider{
					{
						PLMN:           "310-410",
						Description:    "AT&T",
						CurrentServing: true,
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
					PCI:       "0000:04:00.0",
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
	wlan0 bool
	wwan0 bool
}

func makeDPC(key string, timePrio time.Time, intfs selectedIntfs) types.DevicePortConfig {
	dpc := types.DevicePortConfig{
		Version:      types.DPCIsMgmt,
		Key:          key,
		TimePriority: timePrio,
	}
	if intfs.eth0 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
			IfName:       "eth0",
			Phylabel:     "eth0",
			Logicallabel: "mock-eth0",
			IsMgmt:       true,
			IsL3Port:     true,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DT_CLIENT,
				Type: types.NT_IPV4,
			},
		})
	}
	if intfs.eth1 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
			IfName:       "eth1",
			Phylabel:     "eth1",
			Logicallabel: "mock-eth1",
			IsMgmt:       true,
			IsL3Port:     true,
			DhcpConfig: types.DhcpConfig{
				Dhcp: types.DT_CLIENT,
				Type: types.NT_IPV4,
			},
		})
	}
	if intfs.wlan0 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
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
						Identity:  "user",
						Password:  "password",
						SSID:      "ssid",
					},
				},
			},
		})
	}
	if intfs.wwan0 {
		dpc.Ports = append(dpc.Ports, types.NetworkPortConfig{
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
						APN:              "apn",
						LocationTracking: true,
					},
				},
			},
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
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
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
	dpcManager.UpdateGCP(globalConfig())

	// Apply "lastresort" DPC with single ethernet port.
	aa := makeAA(selectedIntfs{eth0: true})
	timePrio1 := time.Time{} // zero timestamp for lastresort
	dpc := makeDPC("lastresort", timePrio1, selectedIntfs{eth0: true})
	dpcManager.UpdateAA(aa)
	dpcManager.AddDPC(dpc)

	// Verification should succeed.
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dnsKeyCb()).Should(Equal("lastresort"))
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))

	// Change DPC - change from eth0 to non-existent eth1.
	// Verification should fail and the manager should revert back to the first DPC.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth1: true})
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
	t.Expect(dpcList[1].TimePriority.Equal(timePrio1)).To(BeTrue())
	t.Expect(dpcList[1].State).To(Equal(types.DPCStateSuccess))
	t.Expect(dpcList[1].LastSucceeded.After(dpcList[0].LastFailed)).To(BeTrue())
	t.Expect(dpcList[1].LastError).To(BeEmpty())

	// Put a new working DPC.
	// The previous failing DPC will be compressed out, but lastresort should be preserved.
	timePrio3 := time.Now()
	dpc = makeDPC("zedagent", timePrio3, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(dpcListLenCb()).Should(Equal(3))
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
	t.Expect(dpcList[1].TimePriority.Equal(timePrio1)).To(BeTrue())
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
	t.Expect(dpcList[1].TimePriority.Equal(timePrio1)).To(BeTrue())
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
	t.Expect(dpcList[1].TimePriority.Equal(timePrio1)).To(BeTrue())
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

	// Apply global config first.
	dpcManager.UpdateGCP(globalConfig())

	// Apply last-resort DPC with two ethernet ports.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	timePrio1 := time.Time{} // zero timestamp for lastresort
	dpc := makeDPC("lastresort", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)
	dpcManager.AddDPC(dpc)

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
	t.Expect(dpcList[0].TimePriority.Equal(timePrio1)).To(BeTrue())
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
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true, eth1: true})
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
			"[failed to connect over eth0 failed to connect over eth1]"))
	t.Expect(dpcList[1].Key).To(Equal("lastresort"))
	t.Expect(dpcList[1].TimePriority.Equal(timePrio1)).To(BeTrue())
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

	// Apply global config first.
	dpcManager.UpdateGCP(globalConfig())

	// Apply last-resort DPC with two ethernet ports.
	aa := makeAA(selectedIntfs{eth0: true, eth1: true})
	timePrio1 := time.Time{} // zero timestamp for lastresort
	dpc := makeDPC("lastresort", timePrio1, selectedIntfs{eth0: true, eth1: true})
	dpcManager.UpdateAA(aa)
	dpcManager.AddDPC(dpc)

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
	t.Expect(eth0State.Logicallabel).To(Equal("mock-eth0"))
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
	t.Expect(eth0State.Subnet.String()).To(Equal("192.168.10.0/24"))
	t.Expect(eth0State.MacAddr).To(Equal("02:00:00:00:00:01"))
	t.Expect(eth0State.Up).To(BeTrue())
	t.Expect(eth0State.Type).To(BeEquivalentTo(types.NT_IPV4))
	t.Expect(eth0State.Dhcp).To(BeEquivalentTo(types.DT_CLIENT))
	t.Expect(eth0State.DefaultRouters).To(HaveLen(1))
	t.Expect(eth0State.DefaultRouters[0].String()).To(Equal("192.168.10.1"))
	eth1State := dns.Ports[1]
	t.Expect(eth1State.IfName).To(Equal("eth1"))
	t.Expect(eth1State.LastFailed.After(eth1State.LastSucceeded)).To(BeTrue())
	t.Expect(eth1State.IfName).To(Equal("eth1"))
	t.Expect(eth1State.Phylabel).To(Equal("eth1"))
	t.Expect(eth1State.Logicallabel).To(Equal("mock-eth1"))
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
	t.Expect(eth1State.Subnet.String()).To(Equal("172.20.1.0/24"))
	t.Expect(eth1State.MacAddr).To(Equal("02:00:00:00:00:02"))
	t.Expect(eth1State.Up).To(BeTrue())
	t.Expect(eth1State.Type).To(BeEquivalentTo(types.NT_IPV4))
	t.Expect(eth1State.Dhcp).To(BeEquivalentTo(types.DT_CLIENT))
	t.Expect(eth1State.DefaultRouters).To(HaveLen(1))
	t.Expect(eth1State.DefaultRouters[0].String()).To(Equal("172.20.1.1"))
}

func TestWireless(test *testing.T) {
	t := initTest(test)

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

	// Verification will wait for IP addresses.
	t.Eventually(testingInProgressCb()).Should(BeTrue())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
	t.Eventually(dnsKeyCb()).Should(Equal("zedagent"))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateIPDNSWait))

	// Simulate working wlan connectivity.
	wlan0 = mockWlan0() // with IP
	networkMonitor.AddOrUpdateInterface(wlan0)
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))

	// Simulate working wwan connectivity.
	wwan0 = mockWwan0() // with IP
	networkMonitor.AddOrUpdateInterface(wwan0)
	t.Eventually(func() bool {
		ports := getDNS().Ports
		return len(ports) == 2 && len(ports[1].AddrInfoList) == 1 &&
			ports[1].AddrInfoList[0].Addr.String() == "15.123.87.20"
	}).Should(BeTrue())

	// Simulate some output from wwan microservice.
	expectedWwanConfig := types.WwanConfig{
		RadioSilence: false,
		Networks: []types.WwanNetworkConfig{
			{
				LogicalLabel: "mock-wwan0",
				PhysAddrs: types.WwanPhysAddrs{
					Interface: "wwan0",
				},
				Apns:             []string{"apn"},
				LocationTracking: true,
			},
		},
	}
	_, wwanCfgHash, err := generic.MarshalWwanConfig(expectedWwanConfig)
	t.Expect(err).To(BeNil())
	wwan0Status := mockWwan0Status()
	wwan0Status.ConfigChecksum = wwanCfgHash
	wwanWatcher.UpdateStatus(wwan0Status)
	wwan0Metrics := mockWwan0Metrics()
	wwanWatcher.UpdateMetrics(wwan0Metrics)
	wwan0LocInfo := mockWwan0LocationInfo()
	wwanWatcher.UpdateLocationInfo(wwan0LocInfo)

	// Check DNS content, it should include wwan state data.
	t.Eventually(wwanOpModeCb(types.WwanOpModeConnected)).Should(BeTrue())
	wwanDNS := wirelessStatusFromDNS(types.WirelessTypeCellular)
	t.Expect(wwanDNS.Cellular.Module.Name).To(Equal("353533101772021")) // IMEI put by DoSanitize()
	t.Expect(wwanDNS.Cellular.Module.OpMode).To(BeEquivalentTo(types.WwanOpModeConnected))
	t.Expect(wwanDNS.Cellular.Module.ControlProtocol).To(BeEquivalentTo(types.WwanCtrlProtQMI))
	t.Expect(wwanDNS.Cellular.Module.Revision).To(Equal("SWI9X50C_01.08.04.00"))
	t.Expect(wwanDNS.Cellular.ConfigError).To(BeEmpty())
	t.Expect(wwanDNS.Cellular.ProbeError).To(BeEmpty())
	t.Expect(wwanDNS.Cellular.Providers).To(HaveLen(1))
	t.Expect(wwanDNS.Cellular.Providers[0].Description).To(Equal("AT&T"))
	t.Expect(wwanDNS.Cellular.Providers[0].CurrentServing).To(BeTrue())
	t.Expect(wwanDNS.Cellular.Providers[0].PLMN).To(Equal("310-410"))
	t.Expect(wwanDNS.Cellular.SimCards).To(HaveLen(1))
	t.Expect(wwanDNS.Cellular.SimCards[0].Name).To(Equal("89012703578345957137")) // ICCID put by DoSanitize()
	t.Expect(wwanDNS.Cellular.SimCards[0].ICCID).To(Equal("89012703578345957137"))
	t.Expect(wwanDNS.Cellular.SimCards[0].IMSI).To(Equal("310180933695713"))
	t.Expect(wwanDNS.Cellular.PhysAddrs.Interface).To(Equal("wwan0"))
	t.Expect(wwanDNS.Cellular.PhysAddrs.USB).To(Equal("1:3.3"))
	t.Expect(wwanDNS.Cellular.PhysAddrs.PCI).To(Equal("0000:04:00.0"))

	// Check published wwan status
	t.Eventually(func() bool {
		obj, err := pubWwwanStatus.Get("global")
		return err == nil && obj != nil
	}).Should(BeTrue())
	obj, err := pubWwwanStatus.Get("global")
	status := obj.(types.WwanStatus)
	t.Expect(status).To(BeEquivalentTo(wwan0Status))

	// Check published wwan metrics
	t.Eventually(func() bool {
		obj, err := pubWwwanMetrics.Get("global")
		return err == nil && obj != nil
	}).Should(BeTrue())
	obj, err = pubWwwanMetrics.Get("global")
	metrics := obj.(types.WwanMetrics)
	t.Expect(metrics.Networks).To(HaveLen(1))
	t.Expect(metrics.Networks[0].LogicalLabel).To(Equal("mock-wwan0"))
	t.Expect(metrics.Networks[0].PhysAddrs.PCI).To(Equal("0000:04:00.0"))
	t.Expect(metrics.Networks[0].PhysAddrs.USB).To(Equal("1:3.3"))
	t.Expect(metrics.Networks[0].PhysAddrs.Interface).To(Equal("wwan0"))
	t.Expect(metrics.Networks[0].PacketStats.RxBytes).To(BeEquivalentTo(12345))
	t.Expect(metrics.Networks[0].PacketStats.RxPackets).To(BeEquivalentTo(56))
	t.Expect(metrics.Networks[0].PacketStats.TxBytes).To(BeEquivalentTo(1256))
	t.Expect(metrics.Networks[0].PacketStats.TxPackets).To(BeEquivalentTo(12))
	t.Expect(metrics.Networks[0].SignalInfo.RSSI).To(BeEquivalentTo(-67))
	t.Expect(metrics.Networks[0].SignalInfo.RSRQ).To(BeEquivalentTo(-11))
	t.Expect(metrics.Networks[0].SignalInfo.RSRP).To(BeEquivalentTo(-97))
	t.Expect(metrics.Networks[0].SignalInfo.SNR).To(BeEquivalentTo(92))

	// Check published wwan location info.
	t.Eventually(func() bool {
		obj, err := pubWwanLocInfo.Get("global")
		return err == nil && obj != nil
	}).Should(BeTrue())
	obj, err = pubWwanLocInfo.Get("global")
	locInfo := obj.(types.WwanLocationInfo)
	t.Expect(locInfo.Latitude).To(BeNumerically("~", 37.333964, 0.1))
	t.Expect(locInfo.Longitude).To(BeNumerically("~", -121.893975, 0.1))
	t.Expect(locInfo.Altitude).To(BeNumerically("~", 93.170685, 0.1))
	t.Expect(locInfo.HorizontalUncertainty).To(BeNumerically("~", 16.123, 0.1))
	t.Expect(locInfo.HorizontalReliability).To(Equal(types.LocReliabilityMedium))
	t.Expect(locInfo.VerticalUncertainty).To(BeNumerically("~", 12.42, 0.1))
	t.Expect(locInfo.VerticalReliability).To(Equal(types.LocReliabilityLow))
	t.Expect(locInfo.UTCTimestamp).To(BeEquivalentTo(1648629022000))

	// Impose radio silence.
	// But actually there is a config error coming from upper layers,
	// so there should be no change in the wwan config.
	rsImposedAt := time.Now()
	dpcManager.UpdateRadioSilence(types.RadioSilence{
		Imposed:           true,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsImposedAt,
		ConfigError:       "Error from upper layers",
	})
	t.Eventually(func() bool {
		rs := getDNS().RadioSilence
		return rs.ConfigError == "Error from upper layers"
	}).Should(BeTrue())
	rs := getDNS().RadioSilence
	t.Expect(rs.ChangeRequestedAt.Equal(rsImposedAt)).To(BeTrue())
	t.Expect(rs.ConfigError).To(Equal("Error from upper layers"))
	t.Expect(rs.Imposed).To(BeFalse())
	t.Expect(rs.ChangeInProgress).To(BeFalse())
	wwan := dg.Reference(generic.Wwan{})
	t.Expect(itemDescription(wwan)).To(ContainSubstring("RadioSilence:false"))

	// Second attempt should be successful.
	rsImposedAt = time.Now()
	dpcManager.UpdateRadioSilence(types.RadioSilence{
		Imposed:           true,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsImposedAt,
	})
	t.Eventually(rsChangeInProgressCb()).Should(BeTrue())
	expectedWwanConfig.RadioSilence = true
	_, wwanCfgHash, err = generic.MarshalWwanConfig(expectedWwanConfig)
	t.Expect(err).To(BeNil())
	wwan0Status = mockWwan0Status()
	wwan0Status.ConfigChecksum = wwanCfgHash
	wwan0Status.Networks[0].Module.OpMode = types.WwanOpModeRadioOff
	wwan0Status.Networks[0].ConfigError = ""
	wwanWatcher.UpdateStatus(wwan0Status)
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
	dpcManager.UpdateRadioSilence(types.RadioSilence{
		Imposed:           false,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsLiftedAt,
	})
	t.Eventually(rsChangeInProgressCb()).Should(BeTrue())
	expectedWwanConfig.RadioSilence = false
	_, wwanCfgHash, err = generic.MarshalWwanConfig(expectedWwanConfig)
	t.Expect(err).To(BeNil())
	wwan0Status = mockWwan0Status()
	wwan0Status.ConfigChecksum = wwanCfgHash
	wwan0Status.Networks[0].Module.OpMode = types.WwanOpModeConnected
	wwan0Status.Networks[0].ConfigError = ""
	wwanWatcher.UpdateStatus(wwan0Status)
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
	dpcManager.UpdateRadioSilence(types.RadioSilence{
		Imposed:           true,
		ChangeInProgress:  true,
		ChangeRequestedAt: rsImposedAt,
	})
	t.Eventually(rsChangeInProgressCb()).Should(BeTrue())
	expectedWwanConfig.RadioSilence = true
	_, wwanCfgHash, err = generic.MarshalWwanConfig(expectedWwanConfig)
	t.Expect(err).To(BeNil())
	wwan0Status = mockWwan0Status()
	wwan0Status.ConfigChecksum = wwanCfgHash
	wwan0Status.Networks[0].Module.OpMode = types.WwanOpModeOnline
	wwan0Status.Networks[0].ConfigError = "failed to impose RS"
	wwanWatcher.UpdateStatus(wwan0Status)
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
	t := initTest(test)

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
	t := initTest(test)

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

	// Apply global config.
	dpcManager.UpdateGCP(globalConfig())

	// Apply "lastresort" DPC.
	timePrio1 := time.Time{}
	dpc := makeDPC("lastresort", timePrio1, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("lastresort"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())

	// Apply "zedagent" DPC.
	timePrio2 := time.Now()
	dpc = makeDPC("zedagent", timePrio2, selectedIntfs{eth0: true})
	dpcManager.AddDPC(dpc)

	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("zedagent"))
	t.Eventually(dpcTimePrioCb(0, timePrio2)).Should(BeTrue())

	// Remove "zedagent" DPC, the manager should apply lastresort again.
	dpcManager.DelDPC(dpc)
	t.Eventually(dpcIdxCb()).Should(Equal(0))
	t.Eventually(dpcKeyCb(0)).Should(Equal("lastresort"))
	t.Eventually(dpcTimePrioCb(0, timePrio1)).Should(BeTrue())
}

func TestDPCWithReleasedAndRenamedInterface(test *testing.T) {
	t := initTest(test)

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
	aa.IoBundleList[1].IsPCIBack = false
	dpcManager.UpdateAA(aa)
	t.Eventually(itemIsCreatedCb(eth1Dhcpcd)).Should(BeTrue())

	// Simulate event of eth1 receiving IP addresses.
	eth1 = mockEth1()                             // with IPs
	eth1.Attrs.IfIndex = mockEth0().Attrs.IfIndex // index was not changed by domainmgr
	networkMonitor.AddOrUpdateInterface(eth1)
	t.Eventually(dpcStateCb(0)).Should(Equal(types.DPCStateSuccess))
}

func TestVlansAndBonds(test *testing.T) {
	t := initTest(test)

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
		Subnet:     ipSubnet("192.168.10.0/24"),
		NtpServers: []net.IP{net.ParseIP("132.163.96.5")},
	}
	shopfloor100.DNS = netmonitor.DNSInfo{
		ResolvConfPath: "/etc/shopfloor.100-resolv.conf",
		Domains:        []string{"vlan100-test-domain"},
		DNSServers:     []net.IP{net.ParseIP("8.8.8.8")},
	}
	shopfloor200.IPAddrs = []*net.IPNet{ipAddress("172.20.1.2/24")}
	shopfloor200.DHCP = netmonitor.DHCPInfo{
		Subnet:     ipSubnet("172.20.1.0/24"),
		NtpServers: []net.IP{net.ParseIP("132.163.96.6")},
	}
	shopfloor200.DNS = netmonitor.DNSInfo{
		ResolvConfPath: "/etc/shopfloor.200-resolv.conf",
		Domains:        []string{"vlan200-test-domain"},
		DNSServers:     []net.IP{net.ParseIP("1.1.1.1")},
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
	t.Expect(eth0State.Subnet.IP).To(BeNil())
	t.Expect(eth0State.MacAddr).To(Equal("02:00:00:00:00:01"))
	t.Expect(eth0State.Up).To(BeTrue())
	t.Expect(eth0State.Type).To(BeEquivalentTo(types.NT_NOOP))
	t.Expect(eth0State.Dhcp).To(BeEquivalentTo(types.DT_NOOP))
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
	t.Expect(eth1State.Subnet.IP).To(BeNil())
	t.Expect(eth1State.MacAddr).To(Equal("02:00:00:00:00:02"))
	t.Expect(eth1State.Up).To(BeTrue())
	t.Expect(eth1State.Type).To(BeEquivalentTo(types.NT_NOOP))
	t.Expect(eth1State.Dhcp).To(BeEquivalentTo(types.DT_NOOP))
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
	t.Expect(bond0State.Subnet.IP).To(BeNil())
	t.Expect(bond0State.MacAddr).To(Equal("02:00:00:00:00:03"))
	t.Expect(bond0State.Up).To(BeTrue())
	t.Expect(bond0State.Type).To(BeEquivalentTo(types.NT_NOOP))
	t.Expect(bond0State.Dhcp).To(BeEquivalentTo(types.DT_NOOP))
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
	t.Expect(vlan100State.Subnet.String()).To(Equal("192.168.10.0/24"))
	t.Expect(vlan100State.MacAddr).To(Equal("02:00:00:00:00:04"))
	t.Expect(vlan100State.Up).To(BeTrue())
	t.Expect(vlan100State.Type).To(BeEquivalentTo(types.NT_IPV4))
	t.Expect(vlan100State.Dhcp).To(BeEquivalentTo(types.DT_CLIENT))
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
	t.Expect(vlan200State.Subnet.String()).To(Equal("172.20.1.0/24"))
	t.Expect(vlan200State.MacAddr).To(Equal("02:00:00:00:00:05"))
	t.Expect(vlan200State.Up).To(BeTrue())
	t.Expect(vlan200State.Type).To(BeEquivalentTo(types.NT_IPV4))
	t.Expect(vlan200State.Dhcp).To(BeEquivalentTo(types.DT_CLIENT))
	t.Expect(vlan200State.DefaultRouters).To(BeEmpty())
	t.Expect(vlan200State.LastSucceeded.After(vlan200State.LastFailed)).To(BeTrue())
}

func TestTransientDNSError(test *testing.T) {
	t := initTest(test)

	// Prepare simulated network stack.
	eth0 := mockEth0()
	eth0.IPAddrs = nil // eth0 does not yet provide working connectivity
	eth0.DNS = netmonitor.DNSInfo{}
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
		&types.DNSNotAvail{
			IfName: eth0.Attrs.IfName,
		})
	eth0 = mockEth0() // With IPAddrs and DNS.
	networkMonitor.AddOrUpdateInterface(eth0)
	// Do not mark DPC as failed yet - missing DNS could be a transient error.
	t.Consistently(testingInProgressCb(), 8*time.Second).Should(BeTrue())
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateIPDNSWait))
	dpc = getDPC(0)
	dpcEth0 := dpc.GetPortByIfName("eth0")
	t.Expect(dpcEth0).ToNot(BeNil())
	t.Expect(dpcEth0.HasError()).To(BeTrue())
	t.Expect(dpcEth0.LastError).To(Equal("interface eth0: no DNS server available"))
	dns := getDNS()
	dnsEth0 := dns.GetPortByIfName("eth0")
	t.Expect(dnsEth0).ToNot(BeNil())
	t.Expect(dnsEth0.HasError()).To(BeTrue())
	t.Expect(dnsEth0.LastError).To(Equal("interface eth0: no DNS server available"))

	// Eventually the DNS resolver reloads DNS config.
	connTester.SetConnectivityError("zedagent", "eth0", nil)
	t.Eventually(testingInProgressCb()).Should(BeFalse())
	t.Expect(getDPC(0).State).To(Equal(types.DPCStateSuccess))
	dpc = getDPC(0)
	dpcEth0 = dpc.GetPortByIfName("eth0")
	t.Expect(dpcEth0).ToNot(BeNil())
	t.Expect(dpcEth0.HasError()).To(BeFalse())
	t.Expect(dpcEth0.LastError).To(BeEmpty())
	dns = getDNS()
	dnsEth0 = dns.GetPortByIfName("eth0")
	t.Expect(dnsEth0).ToNot(BeNil())
	t.Expect(dnsEth0.HasError()).To(BeFalse())
	t.Expect(dnsEth0.LastError).To(BeEmpty())
}

// Test DPC from before 7.3.0 which does not have IsL3Port flag.
func TestOldDPC(test *testing.T) {
	t := initTest(test)

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
	dpc.DoSanitize(logObj, true, false, "", true, true)

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
