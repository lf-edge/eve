// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package portprober_test

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/portprober"
	"github.com/lf-edge/eve/pkg/pillar/types"
	gomegatypes "github.com/onsi/gomega/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func configForTest() portprober.Config {
	return portprober.Config{
		MaxContFailCnt:      3,
		MaxContSuccessCnt:   2,
		MinContPrevStateCnt: 5,
		NextHopProbeTimeout: 500 * time.Millisecond, // 0.5 second
		UserProbeTimeout:    time.Second,
		NHToUserProbeRatio:  5, // once per second
		NHProbeInterval:     200 * time.Millisecond,
	}
}

func prepareGomega(test *testing.T) *GomegaWithT {
	t := NewGomegaWithT(test)
	t.SetDefaultEventuallyTimeout(10 * time.Second)
	t.SetDefaultEventuallyPollingInterval(50 * time.Millisecond)
	t.SetDefaultConsistentlyDuration(5 * time.Second)
	t.SetDefaultConsistentlyPollingInterval(50 * time.Millisecond)
	return t
}

var (
	prober          *portprober.PortProber
	reachProberICMP *portprober.MockReachProber
	reachProberTCP  *portprober.MockReachProber
)

var (
	latestStatusLock sync.Mutex
	latestStatus     map[string]portprober.ProbeStatus // key: routeKey(NI, dst)
)

func routeKey(ni uuid.UUID, dstNet *net.IPNet) string {
	return fmt.Sprintf("%s-%s", ni, dstNet.String())
}

func initportprober(t *GomegaWithT, intfs selectedIntfs) {
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.TraceLevel)
	/*
		formatter := logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		}
		logger.SetFormatter(&formatter)
	*/
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	reachProberICMP = portprober.NewMockReachProber()
	setDefaultReachState(intfs)
	reachProberTCP = portprober.NewMockReachProber()
	prober = portprober.NewPortProber(logObj, configForTest(),
		reachProberICMP, reachProberTCP)
	t.Expect(prober).ToNot(BeNil())
	updatesCh := prober.WatchProbeUpdates()
	t.Expect(updatesCh).ToNot(BeNil())
	latestStatus = make(map[string]portprober.ProbeStatus)
	go runWatcher(updatesCh)
}

func clearLatestStatus() {
	latestStatusLock.Lock()
	defer latestStatusLock.Unlock()
	latestStatus = make(map[string]portprober.ProbeStatus)
}

func runWatcher(updateCh <-chan []portprober.ProbeStatus) {
	for {
		select {
		case updates := <-updateCh:
			latestStatusLock.Lock()
			for _, update := range updates {
				key := routeKey(update.NetworkInstance, update.MPRoute.DstNetwork)
				latestStatus[key] = update
			}
			latestStatusLock.Unlock()
		}
	}
}

func getRouteProbeStatus(niUUID uuid.UUID, dstNet *net.IPNet) portprober.ProbeStatus {
	latestStatusLock.Lock()
	defer latestStatusLock.Unlock()
	key := routeKey(niUUID, dstNet)
	status, exists := latestStatus[key]
	if !exists {
		status, _ = prober.GetProbeStatus(niUUID, dstNet)
	}
	return status
}

const (
	eth0LL  = "mgmt-ethernet"
	eth1LL  = "appshared-ethernet"
	wlanLL  = "wifi"
	wwan0LL = "lte1"
	wwan1LL = "lte2"
)

func portIfName(portLL string) string {
	switch portLL {
	case eth0LL:
		return "eth0"
	case eth1LL:
		return "eth1"
	case wlanLL:
		return "wlan0"
	case wwan0LL:
		return "wwan0"
	case wwan1LL:
		return "wwan1"
	}
	return ""
}

func ipAddress(ipAddr string) net.IP {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		log.Fatal(fmt.Sprintf("bad IP: %s", ipAddr))
	}
	return ip
}

func ipSubnet(ipAddr string) *net.IPNet {
	_, subnet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		log.Fatal(err)
	}
	return subnet
}

func mockEth0Status() types.NetworkPortStatus {
	localOnlyIP := ipAddress("169.254.50.50")
	ip, subnet, _ := net.ParseCIDR("192.168.1.1/24")
	return types.NetworkPortStatus{
		IfName:         portIfName(eth0LL),
		Phylabel:       portIfName(eth0LL),
		Logicallabel:   eth0LL,
		SharedLabels:   []string{"all", "uplink", "freeuplink", "internet", "ethernet"},
		IsMgmt:         true,
		IsL3Port:       true,
		Cost:           0,
		Subnet:         *subnet,
		AddrInfoList:   []types.AddrInfo{{Addr: ip}, {Addr: localOnlyIP}},
		DefaultRouters: []net.IP{ipAddress("192.168.1.2")},
	}
}

func mockEth1Status() types.NetworkPortStatus {
	ip, subnet, _ := net.ParseCIDR("10.10.0.1/16")
	return types.NetworkPortStatus{
		IfName:         portIfName(eth1LL),
		Phylabel:       portIfName(eth1LL),
		Logicallabel:   eth1LL,
		SharedLabels:   []string{"all", "localnet", "ethernet"},
		IsMgmt:         false,
		IsL3Port:       true,
		Cost:           0,
		Subnet:         *subnet,
		AddrInfoList:   []types.AddrInfo{{Addr: ip}},
		DefaultRouters: []net.IP{ipAddress("10.10.0.250")},
	}
}

func mockWlanStatus() types.NetworkPortStatus {
	ip, subnet, _ := net.ParseCIDR("172.30.1.1/24")
	return types.NetworkPortStatus{
		IfName:         portIfName(wlanLL),
		Phylabel:       portIfName(wlanLL),
		Logicallabel:   wlanLL,
		SharedLabels:   []string{"all", "wireless", "localnet"},
		IsMgmt:         false,
		IsL3Port:       true,
		Cost:           2,
		Subnet:         *subnet,
		AddrInfoList:   []types.AddrInfo{{Addr: ip}},
		DefaultRouters: []net.IP{ipAddress("172.30.1.10")},
		WirelessCfg:    types.WirelessConfig{WType: types.WirelessTypeWifi},
	}
}

func mockWwan0Status() types.NetworkPortStatus {
	ip, subnet, _ := net.ParseCIDR("172.18.40.199/24")
	return types.NetworkPortStatus{
		IfName:         portIfName(wwan0LL),
		Phylabel:       portIfName(wwan0LL),
		Logicallabel:   wwan0LL,
		SharedLabels:   []string{"all", "uplink", "wireless", "internet"},
		IsMgmt:         true,
		IsL3Port:       true,
		Cost:           10,
		Subnet:         *subnet,
		AddrInfoList:   []types.AddrInfo{{Addr: ip}},
		DefaultRouters: []net.IP{ipAddress("172.18.40.200")},
		WirelessCfg:    types.WirelessConfig{WType: types.WirelessTypeCellular},
	}
}

func mockWwan1Status() types.NetworkPortStatus {
	ip, subnet, _ := net.ParseCIDR("172.95.6.12/24")
	return types.NetworkPortStatus{
		IfName:         portIfName(wwan1LL),
		Phylabel:       portIfName(wwan1LL),
		Logicallabel:   wwan1LL,
		SharedLabels:   []string{"all", "uplink", "wireless", "internet"},
		IsMgmt:         true,
		IsL3Port:       true,
		Cost:           10,
		Subnet:         *subnet,
		AddrInfoList:   []types.AddrInfo{{Addr: ip}},
		DefaultRouters: []net.IP{ipAddress("172.95.6.11")},
		WirelessCfg:    types.WirelessConfig{WType: types.WirelessTypeCellular},
	}
}

var (
	eth0NHAddr  = &net.IPAddr{IP: mockEth0Status().DefaultRouters[0]}
	eth1NHAddr  = &net.IPAddr{IP: mockEth1Status().DefaultRouters[0]}
	wlan0NHAddr = &net.IPAddr{IP: mockWlanStatus().DefaultRouters[0]}
	wwan0NHAddr = &net.IPAddr{IP: mockWwan0Status().DefaultRouters[0]}
	wwan1NHAddr = &net.IPAddr{IP: mockWwan1Status().DefaultRouters[0]}
)

type selectedIntfs struct {
	eth0  bool
	eth1  bool
	wlan0 bool
	wwan0 bool
	wwan1 bool
}

func makeDNS(intfs selectedIntfs) types.DeviceNetworkStatus {
	dns := types.DeviceNetworkStatus{
		DPCKey:  "test",
		Version: types.DPCIsMgmt,
		Testing: false,
		State:   types.DPCStateSuccess,
	}
	if intfs.eth0 {
		dns.Ports = append(dns.Ports, mockEth0Status())
	}
	if intfs.eth1 {
		dns.Ports = append(dns.Ports, mockEth1Status())
	}
	if intfs.wlan0 {
		dns.Ports = append(dns.Ports, mockWlanStatus())
	}
	if intfs.wwan0 {
		dns.Ports = append(dns.Ports, mockWwan0Status())
	}
	if intfs.wwan1 {
		dns.Ports = append(dns.Ports, mockWwan1Status())
	}
	return dns
}

func makeWwanMetrics(intfs selectedIntfs) types.WwanMetrics {
	metrics := types.WwanMetrics{}
	if intfs.wwan0 {
		metrics.Networks = append(metrics.Networks, types.WwanNetworkMetrics{
			LogicalLabel: wwan0LL,
			PhysAddrs: types.WwanPhysAddrs{
				Interface: portIfName(wwan0LL),
				USB:       "1:3",
				PCI:       "0000:a2:00.0",
			},
			SignalInfo: types.WwanSignalInfo{
				RSSI: -67,
			},
		})
	}
	if intfs.wwan1 {
		metrics.Networks = append(metrics.Networks, types.WwanNetworkMetrics{
			LogicalLabel: wwan1LL,
			PhysAddrs: types.WwanPhysAddrs{
				Interface: portIfName(wwan1LL),
				USB:       "1:4",
				PCI:       "0000:f4:00.0",
			},
			SignalInfo: types.WwanSignalInfo{
				RSSI: -82,
			},
		})
	}
	return metrics
}

func copyDNS(dns types.DeviceNetworkStatus) types.DeviceNetworkStatus {
	dnsCopy := dns
	dnsCopy.Ports = make([]types.NetworkPortStatus, len(dns.Ports))
	for i := range dns.Ports {
		dnsCopy.Ports[i] = dns.Ports[i]
	}
	return dnsCopy
}

func copyWwanMetrics(metrics types.WwanMetrics) types.WwanMetrics {
	metricsCopy := metrics
	metricsCopy.Networks = make([]types.WwanNetworkMetrics, len(metrics.Networks))
	for i := range metrics.Networks {
		metricsCopy.Networks[i] = metrics.Networks[i]
	}
	return metricsCopy
}

func setDefaultReachState(intfs selectedIntfs) {
	if intfs.eth0 {
		reachProberICMP.SetReachabilityState(portIfName(eth0LL), eth0NHAddr, nil, 50*time.Millisecond)
	}
	if intfs.eth1 {
		reachProberICMP.SetReachabilityState(portIfName(eth1LL), eth1NHAddr, nil, 50*time.Millisecond)
	}
	if intfs.wlan0 {
		reachProberICMP.SetReachabilityState(portIfName(wlanLL), wlan0NHAddr, nil, 100*time.Millisecond)
	}
	if intfs.wwan0 {
		reachProberICMP.SetReachabilityState(portIfName(wwan0LL), wwan0NHAddr, nil, 200*time.Millisecond)
	}
	if intfs.wwan1 {
		reachProberICMP.SetReachabilityState(portIfName(wwan1LL), wwan1NHAddr, nil, 300*time.Millisecond)
	}
}

var (
	ni1, _ = uuid.FromString("0d6a128b-b36f-4bd0-a71c-087ba2d71ebc")
	ni2, _ = uuid.FromString("f9a3acd0-85ae-4c1f-8fb2-0ac22b5dd312")
)

const (
	ni1PortLabel = eth0LL
	ni2PortLabel = "all"
)

func eventuallyProbe(t *GomegaWithT, portLL string, dstAddr net.Addr) {
	startTime := time.Now()
	probeDone := func() bool {
		probeTimeICMP := reachProberICMP.LastProbe(portIfName(portLL), dstAddr)
		probeTimeTCP := reachProberTCP.LastProbe(portIfName(portLL), dstAddr)
		return probeTimeICMP.After(startTime) || probeTimeTCP.After(startTime)
	}
	t.Eventually(probeDone).Should(BeTrue())
}

func neverProbe(t *GomegaWithT, portLL string, dstAddr net.Addr) {
	startTime := time.Now()
	probeDone := func() bool {
		probeTimeICMP := reachProberICMP.LastProbe(portIfName(portLL), dstAddr)
		probeTimeTCP := reachProberTCP.LastProbe(portIfName(portLL), dstAddr)
		return probeTimeICMP.After(startTime) || probeTimeTCP.After(startTime)
	}
	t.Consistently(probeDone).Should(BeFalse())
}

func eventuallySelectedPort(t *GomegaWithT,
	niUUID uuid.UUID, dstNet *net.IPNet, portLLs ...string) (selectedAt time.Time) {
	selectedPort := func() string {
		status := getRouteProbeStatus(niUUID, dstNet)
		return status.SelectedPortLL
	}
	var conds []gomegatypes.GomegaMatcher
	for _, portLL := range portLLs {
		conds = append(conds, BeEquivalentTo(portLL))
	}
	t.Eventually(selectedPort).Should(Or(conds...))
	return getRouteProbeStatus(niUUID, dstNet).SelectedAt
}

func neverChangedPort(t *GomegaWithT, niUUID uuid.UUID, dstNet *net.IPNet) {
	lastSelectedAt := getRouteProbeStatus(niUUID, dstNet).SelectedAt
	changedPort := func() bool {
		status := getRouteProbeStatus(niUUID, dstNet)
		return status.SelectedAt.After(lastSelectedAt)
	}
	t.Consistently(changedPort()).Should(BeFalse())
}

func isGatewayUP(portLL string) bool {
	var niMetrics []types.ProbeMetrics
	var err error
	for _, niUUID := range []uuid.UUID{ni1, ni2} {
		niMetrics, err = prober.GetProbeMetrics(niUUID)
		if err != nil {
			panic(err)
		}
		for _, routeMetrics := range niMetrics {
			for _, intfMetrics := range routeMetrics.IntfProbeStats {
				if intfMetrics.IntfName == portIfName(portLL) {
					return intfMetrics.NexthopUP
				}
			}
		}
	}
	panic("unknown/unused port interface")
}

func isUserEpUP(portLL string, userProbeAddrStr string) bool {
	var niMetrics []types.ProbeMetrics
	var err error
	for _, niUUID := range []uuid.UUID{ni1, ni2} {
		niMetrics, err = prober.GetProbeMetrics(niUUID)
		if err != nil {
			panic(err)
		}
		for _, routeMetrics := range niMetrics {
			if len(routeMetrics.RemoteEndpoints) != 1 ||
				routeMetrics.RemoteEndpoints[0] != userProbeAddrStr {
				continue
			}
			for _, intfMetrics := range routeMetrics.IntfProbeStats {
				if intfMetrics.IntfName == portIfName(portLL) {
					return intfMetrics.RemoteUP
				}
			}
		}
	}
	panic("unknown/unused port interface")
}

func TestProbingSingleRoute(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, eth1: true, wlan0: true, wwan0: true, wwan1: true}
	initportprober(t, intfs)
	wwanMetrics := makeWwanMetrics(intfs)
	prober.ApplyWwanMetricsUpdate(wwanMetrics)

	routeDst := ipSubnet("100.100.100.0/24")
	mpRoute := types.IPRouteConfig{
		DstNetwork:      routeDst,
		OutputPortLabel: "internet",
		PortProbe: types.NIPortProbe{
			EnabledGwPing: true,
			GwPingMaxCost: 0, // next-hop ping disabled for wwan ports
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodTCP,
				ProbeHost: "100.100.100.50",
				ProbePort: 80,
			},
		},
		PreferLowerCost:          true,
		PreferStrongerWwanSignal: true,
	}
	userProbeAddr := &net.TCPAddr{IP: ipAddress("100.100.100.50"), Port: 80}
	userProbeAddrStr := "tcp://100.100.100.50:80"
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, nil, 250*time.Millisecond)

	// portprober does not have DNS yet,
	// i.e. the list of ports to probe is still unknown.
	_, err := prober.GetProbeStatus(ni1, routeDst)
	t.Expect(err).To(HaveOccurred())
	status, err := prober.StartPortProbing(ni1, ni1PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni1.String()))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedPortLL).To(BeZero())
	t.Expect(status.SelectedAt.IsZero()).To(BeTrue())

	// Apply DNS with eth0, eth1, wwan0 and wwan1 (all with working connectivity).
	dnsAppliedAt := time.Now()
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	// Route should only be using eth0 (the only interface used by NI1).
	eventuallyProbe(t, eth0LL, eth0NHAddr)
	eventuallyProbe(t, eth0LL, userProbeAddr)
	neverProbe(t, eth1LL, userProbeAddr)
	neverProbe(t, wwan0LL, userProbeAddr)
	neverProbe(t, wwan1LL, userProbeAddr)

	selectedAt := eventuallySelectedPort(t, ni1, routeDst, eth0LL)
	t.Expect(selectedAt.After(dnsAppliedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni1, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(dnsAppliedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni1.String()))

	metrics, err := prober.GetProbeMetrics(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(metrics).To(HaveLen(1))
	t.Expect(metrics[0].DstNetwork).To(Equal(routeDst.String()))
	t.Expect(metrics[0].PortCount).To(BeEquivalentTo(1)) // eth0 only selected for NI1
	t.Expect(metrics[0].SelectedPortIfName).To(Equal(portIfName(eth0LL)))
	t.Expect(metrics[0].RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics[0].LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics[0].RemoteEndpoints).To(BeEquivalentTo([]string{userProbeAddrStr}))
	t.Expect(metrics[0].IntfProbeStats).To(HaveLen(1))
	intfStats := metrics[0].IntfProbeStats[0]
	t.Expect(intfStats.IntfName).To(Equal(portIfName(eth0LL)))
	t.Expect(intfStats.NexthopUP).To(BeTrue())
	t.Expect(intfStats.NexthopDownCnt).To(BeZero())
	t.Expect(intfStats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(intfStats.NexthopIPs).To(HaveLen(1))
	t.Expect(intfStats.NexthopIPs[0].Equal(eth0NHAddr.IP)).To(BeTrue())
	t.Expect(intfStats.RemoteUP).To(BeTrue())
	t.Expect(intfStats.RemoteDownCnt).To(BeZero())
	t.Expect(intfStats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(intfStats.LatencyToRemote >= 200).To(BeTrue()) // should be around 250ms
	t.Expect(intfStats.LatencyToRemote <= 300).To(BeTrue())

	neverChangedPort(t, ni1, routeDst)

	err = prober.StopPortProbing(ni1, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	status, err = prober.GetProbeStatus(ni1, routeDst)
	t.Expect(err).To(HaveOccurred())
	metrics, err = prober.GetProbeMetrics(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(metrics).To(HaveLen(0))

	neverProbe(t, eth0LL, eth0NHAddr)
	neverProbe(t, eth0LL, userProbeAddr)

	// Now try the same route but with NI2 which uses all ports.
	// Route narrows down the port selection to eth0, wwan0 and wwan1.
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, nil, 250*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wwan0LL), userProbeAddr, nil, 400*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wwan1LL), userProbeAddr, nil, 500*time.Millisecond)

	// eth0 should be already selected (lowest cost).
	probingStartedAt := time.Now()
	status, err = prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())

	neverChangedPort(t, ni2, routeDst)

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Next-hop for eth0 stops being reachable.
	reachProberICMP.SetReachabilityState(portIfName(eth0LL), eth0NHAddr,
		errors.New("unreachable"), 50*time.Millisecond)
	// Probing interval is 200 ms, MaxContFailCnt is 3 => it will take 800 ms
	// at least for the state to change (+ probing durations ~ 200ms).
	// All well inside the eventual timeout.
	t.Eventually(func() bool { return isGatewayUP(eth0LL) }).Should(BeFalse())

	// However, eth0 is still the best pick, even if nexthop is down.
	neverChangedPort(t, ni2, routeDst)

	// Check metrics
	metrics, err = prober.GetProbeMetrics(ni2)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(metrics).To(HaveLen(1))
	t.Expect(metrics[0].DstNetwork).To(Equal(routeDst.String()))
	t.Expect(metrics[0].PortCount).To(BeEquivalentTo(3)) // eth0, wwan0, wwan1
	t.Expect(metrics[0].SelectedPortIfName).To(Equal(portIfName(eth0LL)))
	t.Expect(metrics[0].RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics[0].LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics[0].RemoteEndpoints).To(BeEquivalentTo([]string{userProbeAddrStr}))
	t.Expect(metrics[0].IntfProbeStats).To(HaveLen(3))
	eth0Stats := metrics[0].IntfProbeStats[0]
	t.Expect(eth0Stats.IntfName).To(Equal(portIfName(eth0LL)))
	t.Expect(eth0Stats.NexthopUP).To(BeFalse())
	t.Expect(eth0Stats.NexthopDownCnt).ToNot(BeZero())
	t.Expect(eth0Stats.NexthopUPCnt).To(BeZero())
	t.Expect(eth0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(eth0Stats.NexthopIPs[0].Equal(eth0NHAddr.IP)).To(BeTrue())
	t.Expect(eth0Stats.RemoteUP).To(BeTrue())
	t.Expect(eth0Stats.RemoteDownCnt).To(BeZero())
	t.Expect(eth0Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(eth0Stats.LatencyToRemote >= 200).To(BeTrue()) // should be around 250ms
	t.Expect(eth0Stats.LatencyToRemote <= 300).To(BeTrue())
	wwan0Stats := metrics[0].IntfProbeStats[1]
	t.Expect(wwan0Stats.IntfName).To(Equal(portIfName(wwan0LL)))
	t.Expect(wwan0Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan0Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan0Stats.NexthopIPs[0].Equal(wwan0NHAddr.IP)).To(BeTrue())
	t.Expect(wwan0Stats.RemoteUP).To(BeTrue())
	t.Expect(wwan0Stats.RemoteDownCnt).To(BeZero())
	t.Expect(wwan0Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wwan0Stats.LatencyToRemote >= 350).To(BeTrue()) // should be around 400ms
	t.Expect(wwan0Stats.LatencyToRemote <= 450).To(BeTrue())
	wwan1Stats := metrics[0].IntfProbeStats[2]
	t.Expect(wwan1Stats.IntfName).To(Equal(portIfName(wwan1LL)))
	t.Expect(wwan1Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan1Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan1Stats.NexthopIPs[0].Equal(wwan1NHAddr.IP)).To(BeTrue())
	t.Expect(wwan1Stats.RemoteUP).To(BeTrue())
	t.Expect(wwan1Stats.RemoteDownCnt).To(BeZero())
	t.Expect(wwan1Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wwan1Stats.LatencyToRemote >= 450).To(BeTrue()) // should be around 500ms
	t.Expect(wwan1Stats.LatencyToRemote <= 550).To(BeTrue())

	// When user-defined endpoint reachability for eth0 goes down, wwan0 becomes better pick
	// (it has better RSSI than wwan1).
	// User-defined endpoint stops responding within the (1sec) probing timeout.
	userProbeChange := time.Now()
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr,
		nil, time.Minute)
	// Probing interval is 1 sec, MaxContFailCnt is 3, probe duration 1 sec (after timeout
	// is triggered) => it will take 8 seconds at least for the state to change.
	// Still within the eventual timeout.
	t.Eventually(func() bool { return isUserEpUP(eth0LL, userProbeAddrStr) }).Should(BeFalse())

	selectedAt = eventuallySelectedPort(t, ni2, routeDst, wwan0LL)
	t.Expect(selectedAt.After(userProbeChange)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(wwan0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(userProbeChange)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// When all ports lose connectivity, portprober prefers to not change
	// the currently selected port.
	reachProberTCP.SetReachabilityState(portIfName(wwan0LL), userProbeAddr,
		errors.New("unreachable"), 50*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wwan1LL), userProbeAddr,
		errors.New("unreachable"), 50*time.Millisecond)
	t.Eventually(func() bool { return isUserEpUP(wwan0LL, userProbeAddrStr) }).Should(BeFalse())
	t.Eventually(func() bool { return isUserEpUP(wwan1LL, userProbeAddrStr) }).Should(BeFalse())
	neverChangedPort(t, ni2, routeDst)

	// Re-check metrics with the connectivity being DOWN.
	metrics, err = prober.GetProbeMetrics(ni2)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(metrics).To(HaveLen(1))
	t.Expect(metrics[0].DstNetwork).To(Equal(routeDst.String()))
	t.Expect(metrics[0].PortCount).To(BeEquivalentTo(3)) // eth0, wwan0, wwan1
	t.Expect(metrics[0].SelectedPortIfName).To(Equal(portIfName(wwan0LL)))
	t.Expect(metrics[0].RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics[0].LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics[0].RemoteEndpoints).To(BeEquivalentTo([]string{userProbeAddrStr}))
	t.Expect(metrics[0].IntfProbeStats).To(HaveLen(3))
	eth0Stats = metrics[0].IntfProbeStats[0]
	t.Expect(eth0Stats.IntfName).To(Equal(portIfName(eth0LL)))
	t.Expect(eth0Stats.NexthopUP).To(BeFalse())
	t.Expect(eth0Stats.NexthopDownCnt).ToNot(BeZero())
	t.Expect(eth0Stats.NexthopUPCnt).To(BeZero())
	t.Expect(eth0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(eth0Stats.NexthopIPs[0].Equal(eth0NHAddr.IP)).To(BeTrue())
	t.Expect(eth0Stats.RemoteUP).To(BeFalse())
	t.Expect(eth0Stats.RemoteDownCnt).ToNot(BeZero())
	t.Expect(eth0Stats.RemoteUPCnt).To(BeZero())
	wwan0Stats = metrics[0].IntfProbeStats[1]
	t.Expect(wwan0Stats.IntfName).To(Equal(portIfName(wwan0LL)))
	t.Expect(wwan0Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan0Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan0Stats.NexthopIPs[0].Equal(wwan0NHAddr.IP)).To(BeTrue())
	t.Expect(wwan0Stats.RemoteUP).To(BeFalse())
	t.Expect(wwan0Stats.RemoteDownCnt).ToNot(BeZero())
	t.Expect(wwan0Stats.RemoteUPCnt).To(BeZero())
	wwan1Stats = metrics[0].IntfProbeStats[2]
	t.Expect(wwan1Stats.IntfName).To(Equal(portIfName(wwan1LL)))
	t.Expect(wwan1Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan1Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan1Stats.NexthopIPs[0].Equal(wwan1NHAddr.IP)).To(BeTrue())
	t.Expect(wwan1Stats.RemoteUP).To(BeFalse())
	t.Expect(wwan1Stats.RemoteDownCnt).ToNot(BeZero())
	t.Expect(wwan1Stats.RemoteUPCnt).To(BeZero())

	// Restore eth0 connectivity - at least next hop..
	nhChange := time.Now()
	reachProberICMP.SetReachabilityState(portIfName(eth0LL), eth0NHAddr, nil, 50*time.Millisecond)
	selectedAt = eventuallySelectedPort(t, ni2, routeDst, eth0LL)
	t.Expect(selectedAt.After(nhChange)).To(BeTrue())

	err = prober.StopPortProbing(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	_, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).To(HaveOccurred())
}

func TestProbingMultipleRoutes(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, eth1: true, wlan0: true, wwan0: true, wwan1: true}
	initportprober(t, intfs)

	// Apply DNS and wwan metrics with all ports having working connectivity.
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)
	wwanMetrics := makeWwanMetrics(intfs)
	prober.ApplyWwanMetricsUpdate(wwanMetrics)

	route1Dst := ipSubnet("200.50.0.0/16")
	mpRoute1 := types.IPRouteConfig{
		DstNetwork:      route1Dst,
		OutputPortLabel: "internet", // eth0, wwan0 and wwan1
		PortProbe: types.NIPortProbe{
			EnabledGwPing: true,
			GwPingMaxCost: 0, // next-hop ping disabled for wwan ports
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodICMP,
				ProbeHost: "remote-hostname-for-probing.com",
			},
		},
		PreferLowerCost:          true,
		PreferStrongerWwanSignal: true,
	}
	userProbe1Addr := &portprober.HostnameAddr{Hostname: "remote-hostname-for-probing.com"}
	userProbe1AddrStr := "icmp://remote-hostname-for-probing.com"
	reachProberICMP.SetReachabilityState(portIfName(eth0LL), userProbe1Addr, nil, 250*time.Millisecond)
	reachProberICMP.SetReachabilityState(portIfName(wwan0LL), userProbe1Addr, nil, 400*time.Millisecond)
	reachProberICMP.SetReachabilityState(portIfName(wwan1LL), userProbe1Addr, nil, 400*time.Millisecond)

	probing1StartedAt := time.Now()
	_, err := prober.StartPortProbing(ni2, ni2PortLabel, mpRoute1)
	t.Expect(err).ToNot(HaveOccurred())

	route2Dst := ipSubnet("192.168.5.0/24")
	mpRoute2 := types.IPRouteConfig{
		DstNetwork:      route2Dst,
		OutputPortLabel: "localnet", // eth1 & wlan
		PortProbe: types.NIPortProbe{
			EnabledGwPing: true,
			GwPingMaxCost: 2, // next-hop ping enabled for wlan
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodTCP,
				ProbeHost: "192.168.5.5",
				ProbePort: 443,
			},
		},
		PreferLowerCost: false, // We do not care about the cost
	}
	userProbe2Addr := &net.TCPAddr{IP: ipAddress("192.168.5.5"), Port: 443}
	userProbe2AddrStr := "tcp://192.168.5.5:443"
	reachProberTCP.SetReachabilityState(portIfName(eth1LL), userProbe2Addr, nil, 250*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wlanLL), userProbe2Addr, nil, 350*time.Millisecond)

	probing2StartedAt := time.Now()
	_, err = prober.StartPortProbing(ni2, ni2PortLabel, mpRoute2)
	t.Expect(err).ToNot(HaveOccurred())

	route3Dst := ipSubnet("210.100.100.0/24")
	mpRoute3 := types.IPRouteConfig{
		DstNetwork:      route3Dst,
		OutputPortLabel: "all",
		// Same probe as for route2:
		PortProbe: types.NIPortProbe{
			EnabledGwPing: true,
			GwPingMaxCost: 2, // next-hop ping enabled for wlan, but not for wwan
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodTCP,
				ProbeHost: "192.168.5.5",
				ProbePort: 443,
			},
		},
		PreferLowerCost:          true,
		PreferStrongerWwanSignal: true,
	}
	// Reachability of userProbe2Addr is already set for eth1 and wlan.
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbe2Addr, nil, 250*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wwan0LL), userProbe2Addr, nil, 400*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wwan1LL), userProbe2Addr, nil, 400*time.Millisecond)

	probing3StartedAt := time.Now()
	_, err = prober.StartPortProbing(ni2, ni2PortLabel, mpRoute3)
	t.Expect(err).ToNot(HaveOccurred())

	// For route1, eth0 should be selected (lowest cost).
	selectedAt := eventuallySelectedPort(t, ni2, route1Dst, eth0LL)
	t.Expect(selectedAt.After(probing1StartedAt)).To(BeTrue())

	status, err := prober.GetProbeStatus(ni2, route1Dst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
	t.Expect(status.MPRoute).To(Equal(mpRoute1))
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.SelectedAt.After(probing1StartedAt)).To(BeTrue())

	// For route2, eth1 and wlan have equal preference at this moment
	selectedAt = eventuallySelectedPort(t, ni2, route2Dst, eth1LL, wlanLL)
	t.Expect(selectedAt.After(probing1StartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, route2Dst)
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
	t.Expect(status.MPRoute).To(Equal(mpRoute2))
	t.Expect(status.SelectedPortLL).To(Or(Equal(eth1LL), Equal(wlanLL)))
	t.Expect(status.SelectedAt.After(probing2StartedAt)).To(BeTrue())

	// For route3, eth0 or eth1 should be selected (lowest cost).
	selectedAt = eventuallySelectedPort(t, ni2, route3Dst, eth0LL, eth1LL)
	t.Expect(selectedAt.After(probing3StartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, route3Dst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
	t.Expect(status.MPRoute).To(Equal(mpRoute3))
	t.Expect(status.SelectedPortLL).To(Or(Equal(eth0LL), Equal(eth1LL)))
	t.Expect(status.SelectedAt.After(probing3StartedAt)).To(BeTrue())

	// Selections remain stable.
	neverChangedPort(t, ni2, route1Dst)
	neverChangedPort(t, ni2, route2Dst)
	neverChangedPort(t, ni2, route3Dst)

	// Check metrics
	metrics, err := prober.GetProbeMetrics(ni2)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(metrics).To(HaveLen(3))
	// Route2 comes first (ordered by dst network address)
	t.Expect(metrics[0].DstNetwork).To(Equal(route2Dst.String()))
	t.Expect(metrics[0].PortCount).To(BeEquivalentTo(2)) // eth0, wwan0, wwan1
	t.Expect(metrics[0].SelectedPortIfName).To(Or(Equal(portIfName(eth1LL)), Equal(portIfName(wlanLL))))
	t.Expect(metrics[0].RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics[0].LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics[0].RemoteEndpoints).To(BeEquivalentTo([]string{userProbe2AddrStr}))
	t.Expect(metrics[0].IntfProbeStats).To(HaveLen(2))
	eth1Stats := metrics[0].IntfProbeStats[0]
	t.Expect(eth1Stats.IntfName).To(Equal(portIfName(eth1LL)))
	t.Expect(eth1Stats.NexthopUP).To(BeTrue())
	t.Expect(eth1Stats.NexthopDownCnt).To(BeZero())
	t.Expect(eth1Stats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(eth1Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(eth1Stats.NexthopIPs[0].Equal(eth1NHAddr.IP)).To(BeTrue())
	t.Expect(eth1Stats.RemoteUP).To(BeTrue())
	t.Expect(eth1Stats.RemoteDownCnt).To(BeZero())
	t.Expect(eth1Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(eth1Stats.LatencyToRemote >= 200).To(BeTrue()) // should be around 250ms
	t.Expect(eth1Stats.LatencyToRemote <= 300).To(BeTrue())
	wlanStats := metrics[0].IntfProbeStats[1]
	t.Expect(wlanStats.IntfName).To(Equal(portIfName(wlanLL)))
	t.Expect(wlanStats.NexthopUP).To(BeTrue()) // next-hop ping is enabled for wlan
	t.Expect(wlanStats.NexthopDownCnt).To(BeZero())
	t.Expect(wlanStats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(wlanStats.NexthopIPs).To(HaveLen(1))
	t.Expect(wlanStats.NexthopIPs[0].Equal(wlan0NHAddr.IP)).To(BeTrue())
	t.Expect(wlanStats.RemoteUP).To(BeTrue())
	t.Expect(wlanStats.RemoteDownCnt).To(BeZero())
	t.Expect(wlanStats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wlanStats.LatencyToRemote >= 300).To(BeTrue()) // should be around 350ms
	t.Expect(wlanStats.LatencyToRemote <= 400).To(BeTrue())
	// Route1
	t.Expect(metrics[1].DstNetwork).To(Equal(route1Dst.String()))
	t.Expect(metrics[1].PortCount).To(BeEquivalentTo(3)) // eth0, wwan0, wwan1
	t.Expect(metrics[1].SelectedPortIfName).To(Equal(portIfName(eth0LL)))
	t.Expect(metrics[1].RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics[1].LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics[1].RemoteEndpoints).To(BeEquivalentTo([]string{userProbe1AddrStr}))
	t.Expect(metrics[1].IntfProbeStats).To(HaveLen(3))
	eth0Stats := metrics[1].IntfProbeStats[0]
	t.Expect(eth0Stats.IntfName).To(Equal(portIfName(eth0LL)))
	t.Expect(eth0Stats.NexthopUP).To(BeTrue())
	t.Expect(eth0Stats.NexthopDownCnt).To(BeZero())
	t.Expect(eth0Stats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(eth0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(eth0Stats.NexthopIPs[0].Equal(eth0NHAddr.IP)).To(BeTrue())
	t.Expect(eth0Stats.RemoteUP).To(BeTrue())
	t.Expect(eth0Stats.RemoteDownCnt).To(BeZero())
	t.Expect(eth0Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(eth0Stats.LatencyToRemote >= 200).To(BeTrue()) // should be around 250ms
	t.Expect(eth0Stats.LatencyToRemote <= 300).To(BeTrue())
	wwan0Stats := metrics[1].IntfProbeStats[1]
	t.Expect(wwan0Stats.IntfName).To(Equal(portIfName(wwan0LL)))
	t.Expect(wwan0Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan0Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan0Stats.NexthopIPs[0].Equal(wwan0NHAddr.IP)).To(BeTrue())
	t.Expect(wwan0Stats.RemoteUP).To(BeTrue())
	t.Expect(wwan0Stats.RemoteDownCnt).To(BeZero())
	t.Expect(wwan0Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wwan0Stats.LatencyToRemote >= 350).To(BeTrue()) // should be around 400ms
	t.Expect(wwan0Stats.LatencyToRemote <= 450).To(BeTrue())
	wwan1Stats := metrics[1].IntfProbeStats[2]
	t.Expect(wwan1Stats.IntfName).To(Equal(portIfName(wwan1LL)))
	t.Expect(wwan1Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan1Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan1Stats.NexthopIPs[0].Equal(wwan1NHAddr.IP)).To(BeTrue())
	t.Expect(wwan1Stats.RemoteUP).To(BeTrue())
	t.Expect(wwan1Stats.RemoteDownCnt).To(BeZero())
	t.Expect(wwan1Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wwan1Stats.LatencyToRemote >= 350).To(BeTrue()) // should be around 400ms
	t.Expect(wwan1Stats.LatencyToRemote <= 450).To(BeTrue())
	// Route3
	t.Expect(metrics[2].DstNetwork).To(Equal(route3Dst.String()))
	t.Expect(metrics[2].PortCount).To(BeEquivalentTo(5))
	t.Expect(metrics[2].SelectedPortIfName).To(Or(Equal(portIfName(eth0LL)), Equal(portIfName(eth1LL))))
	t.Expect(metrics[2].RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics[2].LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics[2].RemoteEndpoints).To(BeEquivalentTo([]string{userProbe2AddrStr}))
	t.Expect(metrics[2].IntfProbeStats).To(HaveLen(5))
	eth0Stats = metrics[2].IntfProbeStats[0]
	t.Expect(eth0Stats.IntfName).To(Equal(portIfName(eth0LL)))
	t.Expect(eth0Stats.NexthopUP).To(BeTrue())
	t.Expect(eth0Stats.NexthopDownCnt).To(BeZero())
	t.Expect(eth0Stats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(eth0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(eth0Stats.NexthopIPs[0].Equal(eth0NHAddr.IP)).To(BeTrue())
	t.Expect(eth0Stats.RemoteUP).To(BeTrue())
	t.Expect(eth0Stats.RemoteDownCnt).To(BeZero())
	t.Expect(eth0Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(eth0Stats.LatencyToRemote >= 200).To(BeTrue()) // should be around 250ms
	t.Expect(eth0Stats.LatencyToRemote <= 300).To(BeTrue())
	eth1Stats = metrics[2].IntfProbeStats[1]
	t.Expect(eth1Stats.IntfName).To(Equal(portIfName(eth1LL)))
	t.Expect(eth1Stats.NexthopUP).To(BeTrue())
	t.Expect(eth1Stats.NexthopDownCnt).To(BeZero())
	t.Expect(eth1Stats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(eth1Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(eth1Stats.NexthopIPs[0].Equal(eth1NHAddr.IP)).To(BeTrue())
	t.Expect(eth1Stats.RemoteUP).To(BeTrue())
	t.Expect(eth1Stats.RemoteDownCnt).To(BeZero())
	t.Expect(eth1Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(eth1Stats.LatencyToRemote >= 200).To(BeTrue()) // should be around 250ms
	t.Expect(eth1Stats.LatencyToRemote <= 300).To(BeTrue())
	wlanStats = metrics[2].IntfProbeStats[2]
	t.Expect(wlanStats.IntfName).To(Equal(portIfName(wlanLL)))
	t.Expect(wlanStats.NexthopUP).To(BeTrue()) // next-hop ping is enabled for wlan
	t.Expect(wlanStats.NexthopDownCnt).To(BeZero())
	t.Expect(wlanStats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(wlanStats.NexthopIPs).To(HaveLen(1))
	t.Expect(wlanStats.NexthopIPs[0].Equal(wlan0NHAddr.IP)).To(BeTrue())
	t.Expect(wlanStats.RemoteUP).To(BeTrue())
	t.Expect(wlanStats.RemoteDownCnt).To(BeZero())
	t.Expect(wlanStats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wlanStats.LatencyToRemote >= 300).To(BeTrue()) // should be around 350ms
	t.Expect(wlanStats.LatencyToRemote <= 400).To(BeTrue())
	wwan0Stats = metrics[2].IntfProbeStats[3]
	t.Expect(wwan0Stats.IntfName).To(Equal(portIfName(wwan0LL)))
	t.Expect(wwan0Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan0Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan0Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan0Stats.NexthopIPs[0].Equal(wwan0NHAddr.IP)).To(BeTrue())
	t.Expect(wwan0Stats.RemoteUP).To(BeTrue())
	t.Expect(wwan0Stats.RemoteDownCnt).To(BeZero())
	t.Expect(wwan0Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wwan0Stats.LatencyToRemote >= 350).To(BeTrue()) // should be around 400ms
	t.Expect(wwan0Stats.LatencyToRemote <= 450).To(BeTrue())
	wwan1Stats = metrics[2].IntfProbeStats[4]
	t.Expect(wwan1Stats.IntfName).To(Equal(portIfName(wwan1LL)))
	t.Expect(wwan1Stats.NexthopUP).To(BeFalse()) // next-hop ping is disabled for wwan ports
	t.Expect(wwan1Stats.NexthopDownCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopUPCnt).To(BeZero())
	t.Expect(wwan1Stats.NexthopIPs).To(HaveLen(1))
	t.Expect(wwan1Stats.NexthopIPs[0].Equal(wwan1NHAddr.IP)).To(BeTrue())
	t.Expect(wwan1Stats.RemoteUP).To(BeTrue())
	t.Expect(wwan1Stats.RemoteDownCnt).To(BeZero())
	t.Expect(wwan1Stats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(wwan1Stats.LatencyToRemote >= 350).To(BeTrue()) // should be around 400ms
	t.Expect(wwan1Stats.LatencyToRemote <= 450).To(BeTrue())

	// Next-hop for eth1 stops being reachable.
	reachProberICMP.SetReachabilityState(portIfName(eth1LL), eth1NHAddr, errors.New("unreachable"), 50*time.Millisecond)
	t.Eventually(func() bool { return isGatewayUP(eth1LL) }).Should(BeFalse())

	// eth1 NH being down should have no effect on route1.
	neverChangedPort(t, ni2, route1Dst)

	// Since cost preference is disabled, Route2 will now pick wlan
	// (if it was not done in the first probing).
	_ = eventuallySelectedPort(t, ni2, route2Dst, wlanLL)

	status, err = prober.GetProbeStatus(ni2, route2Dst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(wlanLL))
	t.Expect(status.MPRoute).To(Equal(mpRoute2))
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Route3 should now switch to eth0 if it is using eth1.
	_ = eventuallySelectedPort(t, ni2, route3Dst, eth0LL)

	status, err = prober.GetProbeStatus(ni2, route3Dst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute3))
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	err = prober.StopPortProbing(ni2, route1Dst)
	t.Expect(err).ToNot(HaveOccurred())
	err = prober.StopPortProbing(ni2, route2Dst)
	t.Expect(err).ToNot(HaveOccurred())
	err = prober.StopPortProbing(ni2, route3Dst)
	t.Expect(err).ToNot(HaveOccurred())

	neverProbe(t, eth0LL, eth0NHAddr)
	neverProbe(t, eth0LL, userProbe1Addr)
	neverProbe(t, eth0LL, userProbe2Addr)
	neverProbe(t, eth1LL, eth1NHAddr)
	neverProbe(t, eth1LL, userProbe2Addr)
}

func TestProbingNoConnectivity(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true, wwan0: true}
	initportprober(t, intfs)

	// Apply DNS with eth0, wlan0 and wwan0.
	// However, none of them has working connectivity.
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	routeDst := ipSubnet("192.168.100.0/24")
	mpRoute := types.IPRouteConfig{
		DstNetwork:      routeDst,
		OutputPortLabel: "all",
		PortProbe: types.NIPortProbe{
			EnabledGwPing: true,
			GwPingMaxCost: 2, // enable NH probing for wlan
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodTCP,
				ProbeHost: "webserver",
				ProbePort: 80,
			},
		},
		PreferLowerCost: true,
	}
	userProbeAddr := &portprober.HostnameAddr{Hostname: "webserver", Port: 80}
	unresponsive := errors.New("unresponsive")
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, unresponsive, 50*time.Millisecond)
	reachProberICMP.SetReachabilityState(portIfName(eth0LL), eth0NHAddr, unresponsive, 50*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wlanLL), userProbeAddr, unresponsive, 100*time.Millisecond)
	reachProberICMP.SetReachabilityState(portIfName(wlanLL), wlan0NHAddr, unresponsive, 100*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wwan0LL), userProbeAddr, unresponsive, 200*time.Millisecond)
	reachProberICMP.SetReachabilityState(portIfName(wwan0LL), wwan0NHAddr, unresponsive, 200*time.Millisecond)

	probingStartedAt := time.Now()
	status, err := prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())

	eventuallyProbe(t, eth0LL, eth0NHAddr)
	eventuallyProbe(t, eth0LL, userProbeAddr)
	eventuallyProbe(t, wlanLL, wlan0NHAddr)
	eventuallyProbe(t, wlanLL, userProbeAddr)
	eventuallyProbe(t, wwan0LL, userProbeAddr)

	// Pick eth0 based on having the lowest cost.
	selectedAt := eventuallySelectedPort(t, ni2, routeDst, eth0LL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Remove IP addresses from eth0
	dns = copyDNS(dns)
	dns.Ports[0].AddrInfoList = nil
	prober.ApplyDNSUpdate(dns)

	// Without connectivity, portprober will prefer already selected port over
	// switching to another.
	neverChangedPort(t, ni2, routeDst)

	// Restart probing to get a new selection.
	err = prober.StopPortProbing(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	clearLatestStatus()
	probingStartedAt = time.Now()
	status, err = prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())

	// Now portprober will select wlan1 because it has the lowest cost among
	// ports with IP address.
	selectedAt = eventuallySelectedPort(t, ni2, routeDst, wlanLL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(wlanLL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Remove IP address from all interfaces but give wwan only a local-only IP.
	dns = copyDNS(dns)
	dns.Ports[1].AddrInfoList = nil
	dns.Ports[2].AddrInfoList = []types.AddrInfo{
		{
			Addr: ipAddress("169.254.50.50"),
		},
	}
	prober.ApplyDNSUpdate(dns)

	// Without connectivity, portprober will prefer already selected port over
	// switching to another.
	neverChangedPort(t, ni2, routeDst)

	// Restart probing to get a new selection.
	err = prober.StopPortProbing(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	clearLatestStatus()
	probingStartedAt = time.Now()
	status, err = prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())

	// Now portprober will select wwan because it has at least a local IP address.
	selectedAt = eventuallySelectedPort(t, ni2, routeDst, wwan0LL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(wwan0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Remove all IP addresses from all interfaces.
	dns = copyDNS(dns)
	dns.Ports[2].AddrInfoList = nil
	prober.ApplyDNSUpdate(dns)

	// Without connectivity, portprober will prefer already selected port over
	// switching to another.
	neverChangedPort(t, ni2, routeDst)

	// Restart probing to get a new selection.
	err = prober.StopPortProbing(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	clearLatestStatus()
	probingStartedAt = time.Now()
	status, err = prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())

	// Now portprober cannot use connectivity status or IP address presence to distinguish
	// between ports.
	// It will simply pick eth0 as port with the lowest cost.
	selectedAt = eventuallySelectedPort(t, ni2, routeDst, eth0LL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
}

func TestPortCostChange(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true}
	initportprober(t, intfs)

	// Apply DNS with eth0 and wlan (all with working connectivity).
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	routeDst := ipSubnet("192.168.100.0/24")
	mpRoute := types.IPRouteConfig{
		DstNetwork:      routeDst,
		OutputPortLabel: "all",
		PortProbe: types.NIPortProbe{
			EnabledGwPing: true,
			GwPingMaxCost: 2, // enable NH probing for wlan
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodTCP,
				ProbeHost: "webserver",
				ProbePort: 80,
			},
		},
		PreferLowerCost: true,
	}
	userProbeAddr := &portprober.HostnameAddr{Hostname: "webserver", Port: 80}
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, nil, 50*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wlanLL), userProbeAddr, nil, 100*time.Millisecond)

	probingStartedAt := time.Now()
	status, err := prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())

	eventuallyProbe(t, eth0LL, eth0NHAddr)
	eventuallyProbe(t, eth0LL, userProbeAddr)
	eventuallyProbe(t, wlanLL, wlan0NHAddr)
	eventuallyProbe(t, wlanLL, userProbeAddr)

	// Pick eth0 based on already executed probes and having lower cost.
	selectedAt := eventuallySelectedPort(t, ni2, routeDst, eth0LL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	neverChangedPort(t, ni2, routeDst)

	// Increase eth0 cost.
	eth0CostIncreasedAt := time.Now()
	dns = copyDNS(dns)
	dns.Ports[0].Cost = 100
	prober.ApplyDNSUpdate(dns)

	// portprober switches the route to now cheaper wlan interface.
	selectedAt = eventuallySelectedPort(t, ni2, routeDst, wlanLL)
	t.Expect(selectedAt.After(eth0CostIncreasedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(wlanLL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(eth0CostIncreasedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Decrease eth0 cost back to 0.
	eth0CostDecreasedAt := time.Now()
	dns = copyDNS(dns)
	dns.Ports[0].Cost = 0
	prober.ApplyDNSUpdate(dns)

	// portprober switches the route back to eth0.
	selectedAt = eventuallySelectedPort(t, ni2, routeDst, eth0LL)
	t.Expect(selectedAt.After(eth0CostDecreasedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(eth0CostDecreasedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
}

func TestAvoidStateFlapping(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true}
	initportprober(t, intfs)

	// Apply DNS with eth0 and wlan (all with working connectivity).
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	routeDst := ipSubnet("192.168.100.0/24")
	mpRoute := types.IPRouteConfig{
		DstNetwork:      routeDst,
		OutputPortLabel: "all",
		PortProbe: types.NIPortProbe{
			EnabledGwPing: true,
			GwPingMaxCost: 2, // enable NH probing for wlan
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodTCP,
				ProbeHost: "webserver",
				ProbePort: 80,
			},
		},
		PreferLowerCost: true,
	}
	userProbeAddr := &portprober.HostnameAddr{Hostname: "webserver", Port: 80}
	// Avoid large probing times for this test.
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, nil, time.Millisecond)
	reachProberICMP.SetReachabilityState(portIfName(eth0LL), eth0NHAddr, nil, time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wlanLL), userProbeAddr, nil, time.Millisecond)
	reachProberICMP.SetReachabilityState(portIfName(wlanLL), wlan0NHAddr, nil, time.Millisecond)

	probingStartedAt := time.Now()
	status, err := prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())

	eventuallyProbe(t, eth0LL, eth0NHAddr)
	eventuallyProbe(t, eth0LL, userProbeAddr)
	eventuallyProbe(t, wlanLL, wlan0NHAddr)
	eventuallyProbe(t, wlanLL, userProbeAddr)

	// Pick eth0 based on already executed probes and having lower cost.
	selectedAt := eventuallySelectedPort(t, ni2, routeDst, eth0LL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Simulate connectivity flapping..
	flappingFrom := time.Now()
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			// eth0 looses connectivity.
			unresponsive := errors.New("unresponsive")
			reachProberICMP.SetReachabilityState(portIfName(eth0LL), eth0NHAddr, unresponsive, 50*time.Millisecond)
			reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, unresponsive, 250*time.Millisecond)
		} else {
			// eth0 regains connectivity.
			reachProberICMP.SetReachabilityState(portIfName(eth0LL), eth0NHAddr, nil, time.Millisecond)
			reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, nil, time.Millisecond)
		}
		// New state remains only for two probes at most. Too short to be taken into effect.
		time.Sleep(300 * time.Millisecond)
	}

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.SelectedAt.Before(flappingFrom)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
	neverChangedPort(t, ni2, routeDst)
}

func TestDisappearedPort(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true}
	initportprober(t, intfs)

	// Apply DNS with eth0 and wlan (all with working connectivity).
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	routeDst := ipSubnet("192.168.100.0/24")
	mpRoute := types.IPRouteConfig{
		DstNetwork:      routeDst,
		OutputPortLabel: "all",
		PortProbe: types.NIPortProbe{
			EnabledGwPing: false, // probe only user-defined endpoint
			UserDefinedProbe: types.ConnectivityProbe{
				Method:    types.ConnectivityProbeMethodTCP,
				ProbeHost: "webserver",
				ProbePort: 80,
			},
		},
		PreferLowerCost: true,
	}
	userProbeAddr := &portprober.HostnameAddr{Hostname: "webserver", Port: 80}
	reachProberTCP.SetReachabilityState(portIfName(eth0LL), userProbeAddr, nil, 250*time.Millisecond)
	reachProberTCP.SetReachabilityState(portIfName(wlanLL), userProbeAddr, nil, 250*time.Millisecond)

	probingStartedAt := time.Now()
	status, err := prober.StartPortProbing(ni2, ni2PortLabel, mpRoute)
	t.Expect(err).ToNot(HaveOccurred())

	neverProbe(t, eth0LL, eth0NHAddr)
	eventuallyProbe(t, eth0LL, userProbeAddr)
	neverProbe(t, wlanLL, wlan0NHAddr)
	eventuallyProbe(t, wlanLL, userProbeAddr)

	// Pick eth0 based on already executed probes and having lower cost.
	selectedAt := eventuallySelectedPort(t, ni2, routeDst, eth0LL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(eth0LL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(probingStartedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))

	// Simulate that eth0 disappeared (e.g. assigned to pciback).
	eth0DisappearedAt := time.Now()
	dns = copyDNS(dns)
	dns.Ports = dns.Ports[1:]
	prober.ApplyDNSUpdate(dns)
	eventuallyProbe(t, wlanLL, userProbeAddr)

	// portprober selects the remaining wlan interface.
	selectedAt = eventuallySelectedPort(t, ni2, routeDst, wlanLL)
	t.Expect(selectedAt.After(probingStartedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni2, routeDst)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedPortLL).To(Equal(wlanLL))
	t.Expect(status.MPRoute).To(Equal(mpRoute))
	t.Expect(status.SelectedAt.After(eth0DisappearedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.String()))
}
