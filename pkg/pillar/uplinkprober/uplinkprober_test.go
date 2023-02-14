// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package uplinkprober_test

import (
	"errors"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/uplinkprober"
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

func configForTest() uplinkprober.Config {
	return uplinkprober.Config{
		MaxContFailCnt:       3,
		MaxContSuccessCnt:    2,
		MinContPrevStateCnt:  5,
		NextHopProbeTimeout:  500 * time.Millisecond, // 0.5 second
		RemoteProbeTimeout:   time.Second,
		NHToRemoteProbeRatio: 5, // once per second
		NHProbeInterval:      200 * time.Millisecond,
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
	prober      *uplinkprober.UplinkProber
	reachProber *uplinkprober.MockReachProber
)

var (
	latestStatusLock sync.Mutex
	latestStatus     map[string]uplinkprober.NIProbeStatus // key: NI UUID
)

func initUplinkProber(t *GomegaWithT, intfs selectedIntfs) {
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.TraceLevel)
	/*
		formatter := logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
		}
		logger.SetFormatter(&formatter)
	*/
	logObj := base.NewSourceLogObject(logger, "test", 1234)
	reachProber = uplinkprober.NewMockReachProber()
	setDefaultReachState(intfs)
	prober = uplinkprober.NewUplinkProber(logObj, configForTest(), reachProber)
	t.Expect(prober).ToNot(BeNil())
	updatesCh := prober.WatchProbeUpdates()
	t.Expect(updatesCh).ToNot(BeNil())
	latestStatus = make(map[string]uplinkprober.NIProbeStatus)
	go runWatcher(updatesCh)
}

func runWatcher(updateCh <-chan []uplinkprober.NIProbeStatus) {
	for {
		select {
		case updates := <-updateCh:
			latestStatusLock.Lock()
			for _, update := range updates {
				latestStatus[update.NetworkInstance.String()] = update
			}
			latestStatusLock.Unlock()
		}
	}
}

func getNIProbeStatus(niUUID uuid.UUID) uplinkprober.NIProbeStatus {
	latestStatusLock.Lock()
	defer latestStatusLock.Unlock()
	status, exists := latestStatus[niUUID.String()]
	if !exists {
		status, _ = prober.GetProbeStatus(niUUID)
	}
	return status
}

const (
	controllerAddr = "http://mycontroller.mydomain.com:443"
	eth0LL         = "mgmt-ethernet"
	eth1LL         = "appshared-ethernet"
	wlanLL         = "wifi"
	wwanLL         = "lte"
)

func mockRemoteEps() []url.URL {
	controllerURL, err := url.Parse(controllerAddr)
	if err != nil {
		panic(err)
	}
	return []url.URL{*controllerURL}
}

func mockEth0Status() types.NetworkPortStatus {
	localIP := net.ParseIP("169.254.50.50")
	ip, subnet, _ := net.ParseCIDR("192.168.1.1/24")
	return types.NetworkPortStatus{
		IfName:       "eth0",
		Phylabel:     "eth0",
		Logicallabel: eth0LL,
		IsMgmt:       true,
		IsL3Port:     true,
		Cost:         0,
		Subnet:       *subnet,
		AddrInfoList: []types.AddrInfo{{Addr: ip}, {Addr: localIP}},
	}
}

func mockEth0NHs() []net.IP {
	return []net.IP{net.ParseIP("192.168.1.2")}
}

func mockEth1Status() types.NetworkPortStatus {
	ip, subnet, _ := net.ParseCIDR("10.10.0.1/16")
	return types.NetworkPortStatus{
		IfName:       "eth1",
		Phylabel:     "eth1",
		Logicallabel: eth1LL,
		IsMgmt:       false,
		IsL3Port:     true,
		Cost:         0,
		Subnet:       *subnet,
		AddrInfoList: []types.AddrInfo{{Addr: ip}},
	}
}

func mockEth1NHs() []net.IP {
	return []net.IP{net.ParseIP("10.10.0.250")}
}

func mockWlanStatus() types.NetworkPortStatus {
	ip, subnet, _ := net.ParseCIDR("172.30.1.1/24")
	return types.NetworkPortStatus{
		IfName:       "wlan0",
		Phylabel:     "wlan0",
		Logicallabel: wlanLL,
		IsMgmt:       true,
		IsL3Port:     true,
		Cost:         0, // same as ethernet
		Subnet:       *subnet,
		AddrInfoList: []types.AddrInfo{{Addr: ip}},
	}
}

func mockWlanNHs() []net.IP {
	return []net.IP{net.ParseIP("172.30.1.10")}
}

func mockWwanStatus() types.NetworkPortStatus {
	ip, subnet, _ := net.ParseCIDR("172.18.40.1/24")
	return types.NetworkPortStatus{
		IfName:       "wwan0",
		Phylabel:     "wwan0",
		Logicallabel: wwanLL,
		IsMgmt:       true,
		IsL3Port:     true,
		Cost:         10,
		Subnet:       *subnet,
		AddrInfoList: []types.AddrInfo{{Addr: ip}},
	}
}

func mockWwanNHs() []net.IP {
	return []net.IP{net.ParseIP("172.18.40.200")}
}

type selectedIntfs struct {
	eth0  bool
	eth1  bool
	wlan0 bool
	wwan0 bool
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
		dns.Ports = append(dns.Ports, mockWwanStatus())
	}
	return dns
}

func setDefaultReachState(intfs selectedIntfs) {
	if intfs.eth0 {
		reachProber.SetNextHopState(eth0LL, mockEth0NHs(), nil, 50*time.Millisecond)
		reachProber.SetRemoteState(eth0LL, mockRemoteEps(), nil, 250*time.Millisecond)
	}
	// eth1 is not for management
	if intfs.wlan0 {
		reachProber.SetNextHopState(wlanLL, mockWlanNHs(), nil, 100*time.Millisecond)
		reachProber.SetRemoteState(wlanLL, mockRemoteEps(), nil, 300*time.Millisecond)
	}
	if intfs.wwan0 {
		reachProber.SetNextHopState(wwanLL, mockWwanNHs(), nil, 200*time.Millisecond)
		reachProber.SetRemoteState(wwanLL, mockRemoteEps(), nil, 500*time.Millisecond)
	}
}

func testUUIDs() []types.UUIDandVersion {
	uuid1, _ := uuid.FromString("0d6a128b-b36f-4bd0-a71c-087ba2d71ebc")
	uuid2, _ := uuid.FromString("f9a3acd0-85ae-4c1f-8fb2-0ac22b5dd312")
	uuid3, _ := uuid.FromString("90539cb0-4c31-4d96-931f-1d59183d61a4")
	return []types.UUIDandVersion{{UUID: uuid1}, {UUID: uuid2}, {UUID: uuid3}}
}

func mockNI(index int, local, onlyFreeUplinks bool) types.NetworkInstanceConfig {
	niType := types.NetworkInstanceTypeSwitch
	if local {
		niType = types.NetworkInstanceTypeLocal
	}
	uplinkLabel := types.UplinkLabel
	if onlyFreeUplinks {
		uplinkLabel = types.FreeUplinkLabel
	}
	return types.NetworkInstanceConfig{
		UUIDandVersion: testUUIDs()[index-1],
		Type:           niType,
		Logicallabel:   uplinkLabel,
	}
}

func eventuallyNHProbe(t *GomegaWithT, uplinkLL string) {
	startTime := time.Now()
	probeDone := func() bool {
		probeTime := reachProber.LastNHProbe(uplinkLL)
		return probeTime.After(startTime)
	}
	t.Eventually(probeDone).Should(BeTrue())
}

func neverNHProbe(t *GomegaWithT, uplinkLL string) {
	startTime := time.Now()
	probeDone := func() bool {
		probeTime := reachProber.LastNHProbe(uplinkLL)
		return probeTime.After(startTime)
	}
	t.Consistently(probeDone).Should(BeFalse())
}

func eventuallyRemoteProbe(t *GomegaWithT, uplinkLL string) {
	startTime := time.Now()
	probeDone := func() bool {
		probeTime := reachProber.LastRemoteProbe(uplinkLL)
		return probeTime.After(startTime)
	}
	t.Eventually(probeDone).Should(BeTrue())
}

func neverRemoteProbe(t *GomegaWithT, uplinkLL string) {
	startTime := time.Now()
	probeDone := func() bool {
		probeTime := reachProber.LastRemoteProbe(uplinkLL)
		return probeTime.After(startTime)
	}
	t.Consistently(probeDone).Should(BeFalse())
}

func eventuallySelectedUplink(t *GomegaWithT,
	niUUID uuid.UUID, uplinkLL string) (selectedAt time.Time) {
	selectedUplink := func() string {
		status := getNIProbeStatus(niUUID)
		return status.SelectedUplinkLL
	}
	t.Eventually(selectedUplink).Should(BeEquivalentTo(uplinkLL))
	return getNIProbeStatus(niUUID).SelectedAt
}

func neverChangedUplink(t *GomegaWithT, niUUID uuid.UUID) {
	lastSelectedAt := getNIProbeStatus(niUUID).SelectedAt
	changedUplink := func() bool {
		status := getNIProbeStatus(niUUID)
		return status.SelectedAt.After(lastSelectedAt)
	}
	t.Consistently(changedUplink()).Should(BeFalse())
}

func isGatewayUP(uplinkIntf string) bool {
	var metrics types.ProbeMetrics
	var err error
	for _, niUUID := range testUUIDs() {
		metrics, err = prober.GetProbeMetrics(niUUID.UUID)
		if err == nil {
			break
		}
	}
	for _, intfStats := range metrics.IntfProbeStats {
		if intfStats.IntfName == uplinkIntf {
			return intfStats.NexthopUP
		}
	}
	panic("unknown uplink interface")
}

func isRemoteUP(uplinkIntf string) bool {
	var metrics types.ProbeMetrics
	var err error
	for _, niUUID := range testUUIDs() {
		metrics, err = prober.GetProbeMetrics(niUUID.UUID)
		if err == nil {
			break
		}
	}
	for _, intfStats := range metrics.IntfProbeStats {
		if intfStats.IntfName == uplinkIntf {
			return intfStats.RemoteUP
		}
	}
	panic("unknown uplink interface")
}

func TestProbingSingleNI(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, eth1: true, wwan0: true}
	initUplinkProber(t, intfs)

	// UplinkProber does not have DNS yet,
	// i.e. the list of uplinks to probe is still unknown.
	ni1 := mockNI(1, true, false)
	_, err := prober.GetProbeStatus(ni1.UUID)
	t.Expect(err).To(HaveOccurred())
	status, err := prober.StartNIProbing(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(BeZero())
	t.Expect(status.SelectedAt.IsZero()).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni1.UUID.String()))

	// Apply DNS with eth0, eth1 and wwan0 (all with working connectivity).
	dnsAppliedAt := time.Now()
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	eventuallyNHProbe(t, eth0LL)
	neverNHProbe(t, eth1LL) // not for mgmt
	neverNHProbe(t, wwanLL) // cost > 0

	eventuallyRemoteProbe(t, eth0LL)
	neverRemoteProbe(t, eth1LL) // not for mgmt
	eventuallyRemoteProbe(t, wwanLL)

	selectedAt := eventuallySelectedUplink(t, ni1.UUID, eth0LL)
	t.Expect(selectedAt.After(dnsAppliedAt)).To(BeTrue())

	status, err = prober.GetProbeStatus(ni1.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(eth0LL))
	t.Expect(status.SelectedAt.After(dnsAppliedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni1.UUID.String()))

	metrics, err := prober.GetProbeMetrics(ni1.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(metrics.UplinkCount).To(BeEquivalentTo(2)) // without eth1
	t.Expect(metrics.SelectedUplinkIntf).To(Equal("eth0"))
	t.Expect(metrics.RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics.LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics.RemoteEndpoints).To(BeEquivalentTo([]string{controllerAddr}))
	t.Expect(metrics.IntfProbeStats).To(HaveLen(2))
	intfStats := metrics.IntfProbeStats[0]
	t.Expect(intfStats.IntfName).To(Equal("eth0"))
	t.Expect(intfStats.NexthopUP).To(BeTrue())
	t.Expect(intfStats.NexthopDownCnt).To(BeZero())
	t.Expect(intfStats.NexthopUPCnt).ToNot(BeZero())
	t.Expect(intfStats.NexthopIPs).To(HaveLen(1))
	t.Expect(intfStats.NexthopIPs[0].Equal(mockEth0NHs()[0])).To(BeTrue())
	t.Expect(intfStats.RemoteUP).To(BeTrue())
	t.Expect(intfStats.RemoteDownCnt).To(BeZero())
	t.Expect(intfStats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(intfStats.LatencyToRemote >= 200).To(BeTrue()) // should be around 250ms
	t.Expect(intfStats.LatencyToRemote <= 300).To(BeTrue())
	intfStats = metrics.IntfProbeStats[1]
	t.Expect(intfStats.IntfName).To(Equal("wwan0"))
	t.Expect(intfStats.NexthopUP).To(BeTrue()) // copied from RemoteUP, next-hop probing not done for cost > 0
	t.Expect(intfStats.NexthopDownCnt).To(BeZero())
	t.Expect(intfStats.NexthopUPCnt).To(BeZero())
	t.Expect(intfStats.NexthopIPs).To(HaveLen(0)) // next-hop probing not done for cost > 0
	t.Expect(intfStats.RemoteUP).To(BeTrue())
	t.Expect(intfStats.RemoteDownCnt).To(BeZero())
	t.Expect(intfStats.RemoteUPCnt).ToNot(BeZero())
	t.Expect(intfStats.LatencyToRemote >= 400).To(BeTrue()) // should be around 500ms
	t.Expect(intfStats.LatencyToRemote <= 600).To(BeTrue())

	neverChangedUplink(t, ni1.UUID)

	// Next-hop for eth0 stops being reachable.
	reachProber.SetNextHopState(eth0LL, mockEth0NHs(), errors.New("unreachable"), 50*time.Millisecond)
	// Probing interval is 200 ms, MaxContFailCnt is 3 => it will take 800 ms
	// at least for the state to change (+ probing durations ~ 200ms).
	// All well inside the eventual timeout.
	t.Eventually(func() bool { return isGatewayUP("eth0") }).Should(BeFalse())

	// However, eth0 is still the best pick, even if nexthop is down.
	neverChangedUplink(t, ni1.UUID)

	// When remote reachability goes down, wwan0 becomes better pick.
	// Remote endpoint stops responding within the (1sec) probing timeout.
	remoteChange := time.Now()
	reachProber.SetRemoteState(eth0LL, mockRemoteEps(), nil, time.Minute)
	// Probing interval is 1 sec, MaxContFailCnt is 3, probe duration 1 sec (after timeout
	// is triggered) => it will take 8 seconds at least for the state to change.
	// Still within the eventual timeout.
	t.Eventually(func() bool { return isRemoteUP("eth0") }).Should(BeFalse())

	selectedAt = eventuallySelectedUplink(t, ni1.UUID, wwanLL)
	t.Expect(selectedAt.After(remoteChange)).To(BeTrue())

	// When all uplinks lose connectivity, UplinkProber prefers to not change
	// the currently selected uplink.
	reachProber.SetNextHopState(wwanLL, mockWwanNHs(), errors.New("unreachable"), 200*time.Millisecond)
	reachProber.SetRemoteState(wwanLL, mockRemoteEps(), errors.New("unreachable"), 500*time.Millisecond)
	t.Eventually(func() bool { return isGatewayUP("wwan0") }).Should(BeFalse())
	t.Eventually(func() bool { return isRemoteUP("wwan0") }).Should(BeFalse())
	neverChangedUplink(t, ni1.UUID)

	// Re-check metrics with the connectivity being DOWN.
	metrics, err = prober.GetProbeMetrics(ni1.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(metrics.UplinkCount).To(BeEquivalentTo(2)) // without eth1
	t.Expect(metrics.SelectedUplinkIntf).To(Equal("wwan0"))
	t.Expect(metrics.RemotePingIntvl).To(BeEquivalentTo(1))
	t.Expect(metrics.LocalPingIntvl).To(BeEquivalentTo(0)) // less than 1 sec in UTs
	t.Expect(metrics.RemoteEndpoints).To(BeEquivalentTo([]string{controllerAddr}))
	t.Expect(metrics.IntfProbeStats).To(HaveLen(2))
	intfStats = metrics.IntfProbeStats[0]
	t.Expect(intfStats.IntfName).To(Equal("eth0"))
	t.Expect(intfStats.NexthopUP).To(BeFalse())
	t.Expect(intfStats.NexthopDownCnt).ToNot(BeZero())
	t.Expect(intfStats.NexthopUPCnt).To(BeZero())
	t.Expect(intfStats.NexthopIPs).To(HaveLen(1))
	t.Expect(intfStats.NexthopIPs[0].Equal(mockEth0NHs()[0])).To(BeTrue())
	t.Expect(intfStats.RemoteUP).To(BeFalse())
	t.Expect(intfStats.RemoteDownCnt).ToNot(BeZero())
	t.Expect(intfStats.RemoteUPCnt).To(BeZero())
	t.Expect(intfStats.LatencyToRemote).To(BeZero()) // without remote connectivity
	intfStats = metrics.IntfProbeStats[1]
	t.Expect(intfStats.IntfName).To(Equal("wwan0"))
	t.Expect(intfStats.NexthopUP).To(BeFalse()) // copied from RemoteUP, next-hop probing not done for cost > 0
	t.Expect(intfStats.NexthopDownCnt).To(BeZero())
	t.Expect(intfStats.NexthopUPCnt).To(BeZero())
	t.Expect(intfStats.NexthopIPs).To(HaveLen(0))
	t.Expect(intfStats.RemoteUP).To(BeFalse())
	t.Expect(intfStats.RemoteDownCnt).ToNot(BeZero())
	t.Expect(intfStats.RemoteUPCnt).To(BeZero())
	t.Expect(intfStats.LatencyToRemote).To(BeZero()) // without remote connectivity

	// Restore eth0 connectivity - at least next hop..
	nhChange := time.Now()
	reachProber.SetNextHopState(eth0LL, mockEth0NHs(), nil, 50*time.Millisecond)
	selectedAt = eventuallySelectedUplink(t, ni1.UUID, eth0LL)
	t.Expect(selectedAt.After(nhChange)).To(BeTrue())

	err = prober.StopNIProbing(ni1.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	_, err = prober.GetProbeStatus(ni1.UUID)
	t.Expect(err).To(HaveOccurred())
}

func TestProbingMultipleNIs(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, eth1: true, wlan0: true}
	initUplinkProber(t, intfs)

	// Apply DNS with eth0, eth1 and wlan0 (all with working connectivity).
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	eventuallyNHProbe(t, eth0LL)
	neverNHProbe(t, eth1LL) // not for mgmt
	eventuallyNHProbe(t, wlanLL)

	eventuallyRemoteProbe(t, eth0LL)
	neverRemoteProbe(t, eth1LL) // not for mgmt
	eventuallyRemoteProbe(t, wlanLL)

	// Pick eth0 based on already execute probes.
	niAddedAt := time.Now()
	ni1 := mockNI(1, true, false)
	status, err := prober.StartNIProbing(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(eth0LL))
	t.Expect(status.SelectedAt.After(niAddedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni1.UUID.String()))

	// Spread the load and instead of eth0 pick wlan0 with the same cost and UP count.
	niAddedAt = time.Now()
	ni2 := mockNI(2, true, true)
	status, err = prober.StartNIProbing(ni2)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(wlanLL))
	t.Expect(status.SelectedAt.After(niAddedAt)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni2.UUID.String()))

	neverChangedUplink(t, ni1.UUID)
	neverChangedUplink(t, ni2.UUID)
}

func TestProbingNoConnectivity(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true}
	initUplinkProber(t, intfs)

	// Apply DNS with eth0 and wlan0, however neither with working
	// connectivity or with assigned IP addresses.
	dns := makeDNS(intfs)
	for i := range dns.Ports {
		dns.Ports[i].AddrInfoList = nil
	}
	unresponsive := errors.New("unresponsive")
	reachProber.SetNextHopState(eth0LL, mockEth0NHs(), unresponsive, 50*time.Millisecond)
	reachProber.SetRemoteState(eth0LL, mockRemoteEps(), unresponsive, 250*time.Millisecond)
	reachProber.SetNextHopState(wlanLL, mockWlanNHs(), unresponsive, 100*time.Millisecond)
	reachProber.SetRemoteState(wlanLL, mockRemoteEps(), unresponsive, 300*time.Millisecond)
	prober.ApplyDNSUpdate(dns)

	eventuallyNHProbe(t, eth0LL)
	eventuallyNHProbe(t, wlanLL)
	eventuallyRemoteProbe(t, eth0LL)
	eventuallyRemoteProbe(t, wlanLL)

	// Without connectivity and assigned IP addresses, UplinkProber will pick
	// any uplink randomly.
	ni1 := mockNI(1, true, false)
	status, err := prober.StartNIProbing(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Or(Equal(eth0LL), Equal(wlanLL)))

	// Give wlan0 interface at least a local IP addr...
	localIP := net.ParseIP("169.254.50.50")
	dns.Ports[1].AddrInfoList = []types.AddrInfo{{Addr: localIP}}
	prober.ApplyDNSUpdate(dns)
	eventuallyNHProbe(t, eth0LL)

	// UplinkProber will now prefer wlan0 over eth0.
	// However, without working connectivity, the existing assignments
	// remain unchanged.
	ni2 := mockNI(2, true, false)
	status, err = prober.StartNIProbing(ni2)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(wlanLL))

	neverChangedUplink(t, ni1.UUID)

	// Give eth0 a unicast IP.
	ip := net.ParseIP("192.168.1.1")
	dns.Ports[0].AddrInfoList = []types.AddrInfo{{Addr: ip}}
	prober.ApplyDNSUpdate(dns)
	eventuallyNHProbe(t, eth0LL)

	// UplinkProber will now prefer eth0 over wlan0.
	// However, without working connectivity, the existing assignments
	// remain unchanged.
	ni3 := mockNI(3, true, false)
	status, err = prober.StartNIProbing(ni3)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(eth0LL))

	neverChangedUplink(t, ni1.UUID)
	neverChangedUplink(t, ni2.UUID)

	// Once eth0 has connectivity, all NIs start using it.
	eth0ConnectedAt := time.Now()
	reachProber.SetNextHopState(eth0LL, mockEth0NHs(), nil, 50*time.Millisecond)
	reachProber.SetRemoteState(eth0LL, mockRemoteEps(), nil, 250*time.Millisecond)

	eventuallySelectedUplink(t, ni1.UUID, eth0LL)
	selectedAt := eventuallySelectedUplink(t, ni2.UUID, eth0LL)
	t.Expect(selectedAt.After(eth0ConnectedAt)).To(BeTrue())
	neverChangedUplink(t, ni3.UUID)
}

func TestPauseAndResumeProbing(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true}
	initUplinkProber(t, intfs)

	// Apply DNS with eth0 and wlan0 (all with working connectivity).
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	eventuallyNHProbe(t, eth0LL)
	eventuallyNHProbe(t, wlanLL)
	eventuallyRemoteProbe(t, eth0LL)
	eventuallyRemoteProbe(t, wlanLL)

	// Pick eth0 based on already execute probes.
	ni1 := mockNI(1, true, false)
	status, err := prober.StartNIProbing(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(eth0LL))

	// Pause any probing activities.
	prober.PauseProbing()
	neverNHProbe(t, eth0LL)
	neverNHProbe(t, wlanLL)

	// eth0 looses connectivity.
	unresponsive := errors.New("unresponsive")
	reachProber.SetNextHopState(eth0LL, mockEth0NHs(), unresponsive, 50*time.Millisecond)
	reachProber.SetRemoteState(eth0LL, mockRemoteEps(), unresponsive, 250*time.Millisecond)

	// Probing is paused and therefore uplink selection will not change.
	neverChangedUplink(t, ni1.UUID)

	// Resume probing activities.
	resumedProbing := time.Now()
	prober.ResumeProbing()
	t.Eventually(func() bool { return isGatewayUP("eth0") }).Should(BeFalse())
	t.Eventually(func() bool { return isRemoteUP("eth0") }).Should(BeFalse())

	eventuallySelectedUplink(t, ni1.UUID, wlanLL)
	selectedAt := eventuallySelectedUplink(t, ni1.UUID, wlanLL)
	t.Expect(selectedAt.After(resumedProbing)).To(BeTrue())
}

func TestAvoidStateFlapping(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true}
	initUplinkProber(t, intfs)

	// Avoid large probing times for this test.
	reachProber.SetNextHopState(eth0LL, mockEth0NHs(), nil, time.Millisecond)
	reachProber.SetRemoteState(eth0LL, mockRemoteEps(), nil, time.Millisecond)
	reachProber.SetNextHopState(wlanLL, mockWlanNHs(), nil, time.Millisecond)
	reachProber.SetRemoteState(wlanLL, mockRemoteEps(), nil, time.Millisecond)

	// Apply DNS with eth0 and wlan0 (all with working connectivity).
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)
	eventuallyNHProbe(t, eth0LL)

	// Pick eth0 based on already execute probes.
	ni1 := mockNI(1, true, false)
	status, err := prober.StartNIProbing(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(eth0LL))

	// Simulate connectivity flapping..
	flappingFrom := time.Now()
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			// eth0 looses connectivity.
			unresponsive := errors.New("unresponsive")
			reachProber.SetNextHopState(eth0LL, mockEth0NHs(), unresponsive, 50*time.Millisecond)
			reachProber.SetRemoteState(eth0LL, mockRemoteEps(), unresponsive, 250*time.Millisecond)
		} else {
			// eth0 regains connectivity.
			reachProber.SetNextHopState(eth0LL, mockEth0NHs(), nil, time.Millisecond)
			reachProber.SetRemoteState(eth0LL, mockRemoteEps(), nil, time.Millisecond)
		}
		// New state remains only for two probes at most. Too short to be taken into effect.
		time.Sleep(300 * time.Millisecond)
	}

	status, err = prober.GetProbeStatus(ni1.UUID)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(eth0LL))
	t.Expect(status.SelectedAt.Before(flappingFrom)).To(BeTrue())
	t.Expect(status.NetworkInstance.String()).To(Equal(ni1.UUID.String()))
	neverChangedUplink(t, ni1.UUID)
}

func TestDisappearedUplink(test *testing.T) {
	t := prepareGomega(test)
	intfs := selectedIntfs{eth0: true, wlan0: true}
	initUplinkProber(t, intfs)

	// Apply DNS with eth0 and wlan0 (all with working connectivity).
	dns := makeDNS(intfs)
	prober.ApplyDNSUpdate(dns)

	eventuallyNHProbe(t, eth0LL)
	eventuallyNHProbe(t, wlanLL)
	eventuallyRemoteProbe(t, eth0LL)
	eventuallyRemoteProbe(t, wlanLL)

	// Pick eth0 based on already execute probes.
	ni1 := mockNI(1, true, false)
	status, err := prober.StartNIProbing(ni1)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(status.SelectedUplinkLL).To(Equal(eth0LL))

	// Simulate that eth0 disappeared (e.g. assigned to pciback).
	eth0DisappearedAt := time.Now()
	dns.Ports = dns.Ports[1:]
	prober.ApplyDNSUpdate(dns)
	eventuallyNHProbe(t, wlanLL)

	// UplinkProber selects the remaining wlan interface.
	eventuallySelectedUplink(t, ni1.UUID, wlanLL)
	selectedAt := eventuallySelectedUplink(t, ni1.UUID, wlanLL)
	t.Expect(selectedAt.After(eth0DisappearedAt)).To(BeTrue())
}
