// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package portprober is used by zedrouter to determine the connectivity status
// of device ports and to decide which port should be used by a given multipath
// route configured for a network instance (with a shared port label) at a given moment.
package portprober

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
)

// PortProber is used by zedrouter to test the connectivity status of device ports
// used by network instances with multipath routes.
// For every multipath route, PortProber picks one of the ports to use at the given
// time, based on probe results, ports costs, etc. (criteria to consider are configured
// separately for every route).
// Whenever the selected port changes, zedrouter is notified by the prober.
// It is up to the zedrouter to perform update of the route from one port to another
// inside the network stack.
type PortProber struct {
	sync.Mutex
	log             *base.LogObject
	config          Config
	reachProberICMP ReachabilityProber
	reachProberTCP  ReachabilityProber

	dns         types.DeviceNetworkStatus
	pendingDNS  *types.DeviceNetworkStatus
	wwanMetrics types.WwanMetrics

	watcherChs []chan []ProbeStatus

	probeTicker *time.Ticker
	forcedTick  bool

	routes map[string]*multipathRoute // key: routeKey(ni,dstNet)
	ports  map[string]*portStatus     // key: port logical label

	probeIteration int
	pickIteration  int
}

const (
	minNHToUserProbeRatio uint8 = 5
	maxCost               uint8 = 255
	minRSSI               int32 = math.MinInt32
)

// Config : configuration for port prober.
// Currently, this is not configurable via controller.
type Config struct {
	// MaxContFailCnt : maximum number of continuous failures that is allowed to happen
	// before the next hop or user-defined endpoint reachability is declared as DOWN.
	MaxContFailCnt uint8
	// MaxContSuccessCnt : maximum number of continuous successes that is allowed to happen
	// before the next hop or user-defined endpoint reachability is declared as UP.
	MaxContSuccessCnt uint8
	// MinContPrevStateCnt : how many continuous confirmations of the previous UP/DOWN state
	// are needed for a sudden change to be applied immediately. This avoids frequent
	// port selection changes with a flapping connectivity, but also ensures that
	// an occasional change is reflected as soon as possible.
	// Currently only applied for Next Hop probing, not for user-defined endpoint probing.
	MinContPrevStateCnt uint8
	// NextHopProbeTimeout : timeout for a single next hop probe.
	NextHopProbeTimeout time.Duration
	// UserProbeTimeout : timeout for a single user probe.
	UserProbeTimeout time.Duration
	// NHToUserProbeRatio : How many NH probes must be run first before a single user
	// probe is executed.
	// Minimum allowed value is 5.
	NHToUserProbeRatio uint8
	// NHProbeInterval : how often to execute NH probe.
	// User probe interval is NHProbeInterval * NHToUserProbeRatio
	NHProbeInterval time.Duration
}

// DefaultConfig : default configuration for PortProber.
// Since these options are currently not configurable via controller,
// non-default config is used only in unit tests.
func DefaultConfig() Config {
	return Config{
		MaxContFailCnt:      4,
		MaxContSuccessCnt:   3,
		MinContPrevStateCnt: 40, // 40 * 15sec = 10 minutes
		NextHopProbeTimeout: 100 * time.Millisecond,
		UserProbeTimeout:    3 * time.Second,
		NHToUserProbeRatio:  10,
		NHProbeInterval:     15 * time.Second,
	}
}

// ReachabilityProber is used by PortProber to test the reachability of device port's
// next hop(s) (the closest router(s)) or remote networks (Internet, cloud VPC, etc.).
// PortProber expects one ReachabilityProber for every probing method (ICMP, TCP, ...).
// There might be a different set of probers implemented for every supported network
// stack (currently only Linux networking is supported by EVE).
// A mock implementation is also provided for unit testing purposes.
type ReachabilityProber interface {
	// Probe reachability of <dstAddr> via the given port.
	// If <dstAddr> is IP address and not hostname, <dnsServers> can be nil.
	Probe(ctx context.Context, portIfName string, srcIP net.IP, dstAddr net.Addr,
		dnsServers []net.IP) error
}

// ProbeStatus is published whenever the selected port for a given multipath route
// changes.
type ProbeStatus struct {
	NetworkInstance uuid.UUID
	MPRoute         types.IPRouteConfig
	SelectedPortLL  string
	SelectedAt      time.Time
}

// multipathRoute is used only internally to store configs of multipath routes and
// labels of their currently selected output ports.
type multipathRoute struct {
	ProbeStatus
	NIPortLabel string
}

// portStatus - used only internally to track the probing state of every probed port.
type portStatus struct {
	logicallabel string
	sharedlabels []string
	ifName       string
	cost         uint8
	isWwan       bool
	localAddrs   []net.IP
	nextHops     []net.IP
	dnsServers   []net.IP
	newlyAdded   bool
	nhProbe      probeStatus
	userProbes   map[types.ConnectivityProbe]*probeStatus
}

func (ps portStatus) matchesLabels(labels ...string) bool {
	for _, label := range labels {
		if ps.logicallabel != label && !generics.ContainsItem(ps.sharedlabels, label) {
			return false
		}
	}
	return true
}

func (ps portStatus) upCount(probeCfg types.NIPortProbe) int {
	var upCount int
	if probeCfg.EnabledGwPing && ps.cost <= probeCfg.GwPingMaxCost {
		if ps.nhProbe.connIsUP {
			upCount++
		}
	}
	userProbe := ps.userProbes[probeCfg.UserDefinedProbe]
	if userProbe != nil {
		if userProbe.connIsUP {
			upCount++
		}
	}
	return upCount
}

type probeStatus struct {
	refCount   int
	connIsUP   bool
	failedCnt  uint32 // continuous fail count, reset on success
	successCnt uint32 // continuous success count, reset on fail
	avgLatency time.Duration
}

// NewPortProber is a constructor for PortProber.
func NewPortProber(log *base.LogObject, config Config,
	reachProberICMP, reachProberTCP ReachabilityProber) *PortProber {
	if config.NHToUserProbeRatio < minNHToUserProbeRatio {
		config.NHToUserProbeRatio = minNHToUserProbeRatio
	}
	prober := &PortProber{
		log:             log,
		config:          config,
		reachProberICMP: reachProberICMP,
		reachProberTCP:  reachProberTCP,
		routes:          make(map[string]*multipathRoute),
		ports:           make(map[string]*portStatus),
	}
	prober.probeTicker = time.NewTicker(config.NHProbeInterval)
	go prober.runProbing()
	return prober
}

// StartPortProbing tells PortProber to start periodic probing of network ports
// for this multipath route.
// It is called by zedrouter whenever a new multipath route is configured for an existing
// or a new network instance.
// If probing config options change for an existing route, zedrouter first stops an ongoing
// probing activity, then starts a new one.
func (p *PortProber) StartPortProbing(ni uuid.UUID, niPortLabel string,
	mpRoute types.IPRouteConfig) (
	initialStatus ProbeStatus, err error) {
	p.Lock()
	defer p.Unlock()
	key := p.routeKey(ni, mpRoute.DstNetwork)
	p.routes[key] = &multipathRoute{
		ProbeStatus: ProbeStatus{
			NetworkInstance: ni,
			MPRoute:         mpRoute},
		NIPortLabel: niPortLabel,
	}
	probeCfg := mpRoute.PortProbe
	for _, port := range p.getPortsMatchingLabels(niPortLabel, mpRoute.OutputPortLabel) {
		if probeCfg.EnabledGwPing && port.cost <= probeCfg.GwPingMaxCost {
			port.nhProbe.refCount++
		}
		if probeCfg.UserDefinedProbe.Method != types.ConnectivityProbeMethodNone {
			userProbe := port.userProbes[probeCfg.UserDefinedProbe]
			if userProbe != nil {
				userProbe.refCount++
			} else {
				port.userProbes[probeCfg.UserDefinedProbe] = &probeStatus{refCount: 1}
			}
		}
	}
	// Initial pick is made based on the last probing results.
	p.log.Noticef("PortProber: Started port probing for route dst=%v NI=%v",
		mpRoute.DstNetwork, ni)
	p.pickPortForRoute(key)
	p.forceProbing()
	return p.routes[key].ProbeStatus, nil
}

// StopPortProbing tells PortProber to stop periodic probing of network ports
// for this multipath route.
// It is called by zedrouter whenever multipath route is removed or the probing config
// options have changed (in that case zedrouter will restart probing with the new config).
func (p *PortProber) StopPortProbing(ni uuid.UUID, mpRouteDst *net.IPNet) error {
	p.Lock()
	defer p.Unlock()
	key := p.routeKey(ni, mpRouteDst)
	mpRoute, exists := p.routes[key]
	if !exists {
		return fmt.Errorf("route dst=%v NI=%v is without probing", mpRouteDst, ni)
	}
	delete(p.routes, key)
	probeCfg := mpRoute.MPRoute.PortProbe
	matchingPorts := p.getPortsMatchingLabels(mpRoute.NIPortLabel,
		mpRoute.MPRoute.OutputPortLabel)
	for _, port := range matchingPorts {
		if probeCfg.EnabledGwPing && port.cost <= probeCfg.GwPingMaxCost {
			port.nhProbe.refCount--
			if port.nhProbe.refCount == 0 {
				// Zero out all values.
				port.nhProbe = probeStatus{}
			}
		}
		userProbe := port.userProbes[probeCfg.UserDefinedProbe]
		if userProbe != nil {
			userProbe.refCount--
			if userProbe.refCount == 0 {
				delete(port.userProbes, probeCfg.UserDefinedProbe)
			}
		}
	}
	p.log.Noticef("PortProber: Stopped port probing for route dst=%v NI=%v",
		mpRouteDst, ni)
	return nil
}

// ApplyDNSUpdate : update the state of probing based on a newly received
// Device Network Status from NIM.
func (p *PortProber) ApplyDNSUpdate(dns types.DeviceNetworkStatus) {
	p.Lock()
	defer p.Unlock()
	p.pendingDNS = &dns
	p.forceProbing()
}

// ApplyWwanMetricsUpdate : update the state of probing based on a newly received
// wwan metrics from the mmagent.
// This is needed to implement the PreferStrongerWwanSignal config option.
func (p *PortProber) ApplyWwanMetricsUpdate(wwanMetrics types.WwanMetrics) {
	p.Lock()
	defer p.Unlock()
	p.wwanMetrics = wwanMetrics
	// Do not force probing, we get wwan metrics updates quite often...
}

// WatchProbeUpdates returns channel where PortProber will be publishing updates
// about ports to use for multipath routes.
// Channel type is a slice of probe statuses - this is used to publish multiple updates
// in a bulk for efficiency.
func (p *PortProber) WatchProbeUpdates() <-chan []ProbeStatus {
	p.Lock()
	defer p.Unlock()
	watcherCh := make(chan []ProbeStatus)
	p.watcherChs = append(p.watcherChs, watcherCh)
	return watcherCh
}

// GetProbeStatus : get the current probing status for a given multipath route.
func (p *PortProber) GetProbeStatus(ni uuid.UUID, mpRouteDst *net.IPNet) (
	ProbeStatus, error) {
	p.Lock()
	defer p.Unlock()
	key := p.routeKey(ni, mpRouteDst)
	mpRoute, exists := p.routes[key]
	if !exists {
		return ProbeStatus{}, fmt.Errorf("route dst=%v NI=%v is without probing",
			mpRouteDst, ni)
	}
	return mpRoute.ProbeStatus, nil
}

// GetProbeMetrics : get probing metrics for all multipath routes configured
// for a given network instance.
func (p *PortProber) GetProbeMetrics(
	ni uuid.UUID) (allMetrics []types.ProbeMetrics, err error) {
	p.Lock()
	defer p.Unlock()
	nhProbeInterval := uint32(p.config.NHProbeInterval / time.Second)
	userProbeInterval := uint32((time.Duration(p.config.NHToUserProbeRatio) *
		p.config.NHProbeInterval) / time.Second)
	for _, mpRoute := range p.routes {
		if mpRoute.NetworkInstance != ni {
			continue
		}
		probeCfg := mpRoute.MPRoute.PortProbe
		selectedPort := mpRoute.SelectedPortLL
		metrics := types.ProbeMetrics{
			DstNetwork:      mpRoute.MPRoute.DstNetwork.String(),
			SelectedPort:    selectedPort,
			LocalPingIntvl:  nhProbeInterval,
			RemotePingIntvl: userProbeInterval,
			IntfProbeStats:  nil,
		}
		if probeCfg.UserDefinedProbe.Method != types.ConnectivityProbeMethodNone {
			metrics.RemoteEndpoints = append(metrics.RemoteEndpoints,
				probeCfg.UserDefinedProbe.String())
		}
		matchingPorts := p.getPortsMatchingLabels(mpRoute.NIPortLabel,
			mpRoute.MPRoute.OutputPortLabel)
		for _, port := range matchingPorts {
			if port.logicallabel == selectedPort {
				metrics.SelectedPortIfName = port.ifName
			}
			metrics.PortCount++
			intfMetrics := types.ProbeIntfMetrics{
				IntfName:       port.ifName,
				NexthopIPs:     port.nextHops,
				NexthopUP:      port.nhProbe.connIsUP,
				NexthopUPCnt:   port.nhProbe.successCnt,
				NexthopDownCnt: port.nhProbe.failedCnt,
			}
			userProbe := port.userProbes[probeCfg.UserDefinedProbe]
			if userProbe != nil {
				intfMetrics.RemoteUP = userProbe.connIsUP
				intfMetrics.RemoteUPCnt = userProbe.successCnt
				intfMetrics.RemoteDownCnt = userProbe.failedCnt
				latency := uint32(userProbe.avgLatency / time.Millisecond)
				intfMetrics.LatencyToRemote = latency
			}
			metrics.IntfProbeStats = append(metrics.IntfProbeStats, intfMetrics)
			// Keep the interface order from DNS.
			comparePortIndex := func(i, j int) bool {
				intfI := metrics.IntfProbeStats[i].IntfName
				intfJ := metrics.IntfProbeStats[j].IntfName
				return p.getIntfOrderInDNS(intfI, false) < p.getIntfOrderInDNS(intfJ, false)
			}
			sort.Slice(metrics.IntfProbeStats, comparePortIndex)
		}
		allMetrics = append(allMetrics, metrics)
	}
	// Make the order of probe metrics deterministic.
	// This is solely to simplify unit testing.
	compareRouteDst := func(i, j int) bool {
		return allMetrics[i].DstNetwork < allMetrics[j].DstNetwork
	}
	sort.Slice(allMetrics, compareRouteDst)
	return allMetrics, nil
}

// Run periodic port probing from a separate Go routine.
func (p *PortProber) runProbing() {
	for {
		select {
		case <-p.probeTicker.C:
			p.Lock()
			var updates []ProbeStatus
			updates = p.probePorts()
			if p.forcedTick {
				// Reset back to the regular interval.
				p.probeTicker.Reset(p.config.NHProbeInterval)
			}
			p.forcedTick = false
			watchers := p.watcherChs
			p.Unlock()
			for _, watcherCh := range watchers {
				watcherCh <- updates
			}
		}
	}
}

// Trigger probing sooner that it would be otherwise.
func (p *PortProber) forceProbing() {
	p.probeTicker.Reset(time.Second)
	p.forcedTick = true
}

// Main method performing probing of all ports used by at least one
// multipath route. Next it iterates over all multipath routes with enabled probing
// and decides if selected port should change.
func (p *PortProber) probePorts() (updates []ProbeStatus) {
	defer func() { p.probeIteration++ }()
	// 1. Apply pending DNS update if there is any
	p.applyPendingDNS()
	// 2. probe every used port
	for _, port := range p.ports {
		if port.nhProbe.refCount > 0 {
			// Perform next-hop probing if it is enabled at least for one route
			// matching this port.
			p.probePortNH(port)
		}
		// 2.2. Maybe probe also user endpoints.
		if port.newlyAdded ||
			p.probeIteration%int(p.config.NHToUserProbeRatio) == 0 {
			for userProbeConfig := range port.userProbes {
				p.probePortUserEp(port, userProbeConfig)
			}
		}
		port.newlyAdded = false
	}
	// 3. update port selections for routes
	for routeKey := range p.routes {
		if changed := p.pickPortForRoute(routeKey); changed {
			updates = append(updates, p.routes[routeKey].ProbeStatus)
		}
	}
	return updates
}

// Take the latest received DNS update into effect.
func (p *PortProber) applyPendingDNS() {
	if p.pendingDNS == nil {
		return
	}
	defer func() {
		p.dns = *p.pendingDNS
	}()
	// Remove ports from portProbeStatus that do not exist anymore or have invalid config.
	// or are no longer configured for management.
	for portLL := range p.ports {
		port := p.pendingDNS.LookupPortByLogicallabel(portLL)
		if port == nil || port.InvalidConfig {
			p.log.Noticef("PortProber: Removed %s from the list of probed ports",
				portLL)
			delete(p.ports, portLL)
			continue
		}
	}
	// Add ports that have just appeared and update existing.
	for _, dnsPort := range p.pendingDNS.Ports {
		if dnsPort.InvalidConfig {
			continue
		}
		portLL := dnsPort.Logicallabel
		port, havePort := p.ports[portLL]
		if !havePort {
			// Newly appeared port.
			p.addPort(dnsPort)
			p.log.Noticef("PortProber: Added %s to list of probed ports", portLL)
		} else {
			// Update existing.
			isWwan := dnsPort.WirelessCfg.WType == types.WirelessTypeCellular
			labelsChanged := !generics.EqualSets(port.sharedlabels, dnsPort.SharedLabels)
			if port.ifName != dnsPort.IfName || port.cost != dnsPort.Cost ||
				port.isWwan != isWwan || labelsChanged {
				// Port config changed. It is easier to re-add the port.
				delete(p.ports, portLL)
				p.addPort(dnsPort)
				p.log.Noticef("PortProber: Updated config of the probed port %s", portLL)
			} else {
				// Just update IP status.
				port.localAddrs = getLocalIPs(dnsPort)
				port.nextHops = getNextHops(dnsPort)
				port.dnsServers = dnsPort.DNSServers
			}
		}
	}
}

func (p *PortProber) addPort(dnsPort types.NetworkPortStatus) {
	port := &portStatus{
		logicallabel: dnsPort.Logicallabel,
		sharedlabels: dnsPort.SharedLabels,
		ifName:       dnsPort.IfName,
		cost:         dnsPort.Cost,
		isWwan:       dnsPort.WirelessCfg.WType == types.WirelessTypeCellular,
		localAddrs:   getLocalIPs(dnsPort),
		nextHops:     getNextHops(dnsPort),
		dnsServers:   dnsPort.DNSServers,
		// Mark as new so that the following probing will run fully
		// and decide the UP/DOWN states.
		newlyAdded: true,
		nhProbe:    probeStatus{},
		userProbes: make(map[types.ConnectivityProbe]*probeStatus),
	}
	for _, route := range p.routes {
		if !port.matchesLabels(route.NIPortLabel, route.MPRoute.OutputPortLabel) {
			continue
		}
		probeCfg := route.MPRoute.PortProbe
		if probeCfg.EnabledGwPing && port.cost <= probeCfg.GwPingMaxCost {
			port.nhProbe.refCount++
		}
		if probeCfg.UserDefinedProbe.Method != types.ConnectivityProbeMethodNone {
			userProbe := port.userProbes[probeCfg.UserDefinedProbe]
			if userProbe != nil {
				userProbe.refCount++
			} else {
				port.userProbes[probeCfg.UserDefinedProbe] = &probeStatus{refCount: 1}
			}
		}
	}
	p.ports[dnsPort.Logicallabel] = port
}

// Probe next-hops of the given port.
func (p *PortProber) probePortNH(port *portStatus) {
	portLL := port.logicallabel
	err := errors.New("missing next-hop or local IP")
	for _, nhIP := range port.nextHops {
		nhAddr := &net.IPAddr{IP: nhIP}
		for _, localIP := range port.localAddrs {
			if !localIP.IsGlobalUnicast() {
				continue
			}
			ctx := context.Background()
			ctx, cancel := context.WithTimeout(ctx, p.config.NextHopProbeTimeout)
			err = p.reachProberICMP.Probe(ctx, port.ifName, localIP, nhAddr, nil)
			cancel()
			if err == nil {
				break
			}
		}
		if err == nil {
			break
		}
	}
	if err == nil {
		// (At least one) next hop is reachable.
		if port.newlyAdded {
			port.nhProbe.connIsUP = true
		} else {
			if !port.nhProbe.connIsUP &&
				port.nhProbe.successCnt == 0 &&
				port.nhProbe.failedCnt >= uint32(p.config.MinContPrevStateCnt) {
				port.nhProbe.connIsUP = true
				p.log.Noticef("PortProber: Setting NH to UP for port %s "+
					"(sudden change)", portLL)
			}
			port.nhProbe.successCnt++
			port.nhProbe.failedCnt = 0
			if !port.nhProbe.connIsUP &&
				port.nhProbe.successCnt > uint32(p.config.MaxContSuccessCnt) {
				port.nhProbe.connIsUP = true
				p.log.Noticef(
					"PortProber: Setting NH to UP for port %s "+
						"(continuously UP)", portLL)
			}
		}
	} else {
		// Next hop is NOT reachable.
		if port.newlyAdded {
			port.nhProbe.connIsUP = false
		} else {
			if port.nhProbe.connIsUP &&
				port.nhProbe.failedCnt == 0 &&
				port.nhProbe.successCnt >= uint32(p.config.MinContPrevStateCnt) {
				port.nhProbe.connIsUP = false
				p.log.Noticef("PortProber: Setting NH to DOWN for port %s "+
					"(sudden change; probe err: %v)", portLL, err)
			}
			port.nhProbe.failedCnt++
			port.nhProbe.successCnt = 0
			if port.nhProbe.connIsUP &&
				port.nhProbe.failedCnt > uint32(p.config.MaxContFailCnt) {
				port.nhProbe.connIsUP = false
				p.log.Noticef(
					"PortProber: Setting NH to DOWN for port %s "+
						"(continuously DOWN; probe err: %v)", portLL, err)
			}
		}
	}
	if port.newlyAdded {
		p.log.Noticef("PortProber: Initial NH status for port %s: %t (probe err: %v)",
			portLL, port.nhProbe.connIsUP, err)
	}
}

// Probe user-defined endpoint through the given port.
func (p *PortProber) probePortUserEp(port *portStatus, probe types.ConnectivityProbe) {
	portLL := port.logicallabel
	var (
		duration time.Duration
		dstAddr  net.Addr
		prober   ReachabilityProber
	)
	switch probe.Method {
	case types.ConnectivityProbeMethodICMP:
		if hostIP := net.ParseIP(probe.ProbeHost); hostIP != nil {
			dstAddr = &net.IPAddr{IP: hostIP}
		} else {
			dstAddr = &HostnameAddr{Hostname: probe.ProbeHost}
		}
		prober = p.reachProberICMP
	case types.ConnectivityProbeMethodTCP:
		if hostIP := net.ParseIP(probe.ProbeHost); hostIP != nil {
			dstAddr = &net.TCPAddr{
				IP:   hostIP,
				Port: int(probe.ProbePort),
			}
		} else {
			dstAddr = &HostnameAddr{
				Hostname: probe.ProbeHost,
				Port:     probe.ProbePort,
			}
		}
		prober = p.reachProberTCP
	}
	err := errors.New("missing local IP")
	for _, localIP := range port.localAddrs {
		if !localIP.IsGlobalUnicast() {
			continue
		}
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, p.config.UserProbeTimeout)
		startTime := time.Now()
		err = prober.Probe(ctx, port.ifName, localIP, dstAddr, port.dnsServers)
		duration = time.Since(startTime)
		cancel()
		if err == nil {
			break
		}
	}
	userProbe := port.userProbes[probe]
	if err == nil {
		// User-defined endpoint is reachable.
		totalDuration := userProbe.avgLatency *
			time.Duration(userProbe.successCnt)
		userProbe.successCnt++
		userProbe.avgLatency = (totalDuration + duration) /
			time.Duration(userProbe.successCnt)
		userProbe.failedCnt = 0
		if port.newlyAdded {
			userProbe.connIsUP = true
		} else if !userProbe.connIsUP &&
			userProbe.successCnt > uint32(p.config.MaxContSuccessCnt) {
			userProbe.connIsUP = true
			p.log.Noticef(
				"PortProber: Setting User-probe %s status to UP for port %s "+
					"(continuously UP)", probe, portLL)
		}
	} else {
		// User-defined endpoint is NOT reachable.
		userProbe.failedCnt++
		userProbe.successCnt = 0
		userProbe.avgLatency = 0
		if port.newlyAdded {
			userProbe.connIsUP = false
		} else if userProbe.connIsUP &&
			userProbe.failedCnt > uint32(p.config.MaxContFailCnt) {
			userProbe.connIsUP = false
			p.log.Noticef(
				"PortProber: Setting User-probe %s status to DOWN for port %s "+
					"(continuously DOWN; probe err: %v)", probe, portLL, err)
		}
	}
	if port.newlyAdded {
		p.log.Noticef("PortProber: Initial User-probe %s status for port %s: %t "+
			"(probe err: %v)", probe, portLL, userProbe.connIsUP, err)
	}
}

func (p *PortProber) getPortsMatchingLabels(labels ...string) (ports []*portStatus) {
	for _, port := range p.ports {
		if !port.matchesLabels(labels...) {
			continue
		}
		ports = append(ports, port)
	}
	return ports
}

// Pick the best port for the given multipath route.
// PortProber optimizes first by cost, then by the number of UP states and finally
// by the presence or lack of a local IP address, wwan signal strength, etc.
func (p *PortProber) pickPortForRoute(routeKey string) (changed bool) {
	route := p.routes[routeKey]
	probeCfg := route.MPRoute.PortProbe
	defer func() {
		if changed {
			route.SelectedAt = time.Now()
		}
	}()
	// 1. Check if the selected port is still available.
	if route.SelectedPortLL != "" {
		if _, exists := p.ports[route.SelectedPortLL]; !exists {
			p.log.Noticef(
				"PortProber: Previously selected port %s for route dst=%v NI=%v "+
					"is no longer available", route.SelectedPortLL,
				route.MPRoute.DstNetwork, route.NetworkInstance)
			route.SelectedPortLL = ""
		}
	}
	// 2. Find best ports with working connectivity (best = lowest cost, most UP states)
	// 2.1. Find the lowest cost for which there is at least one port available
	//      with at least one UP state.
	lowestCost := maxCost
	anyUPState := false
	matchingPorts := p.getPortsMatchingLabels(route.NIPortLabel,
		route.MPRoute.OutputPortLabel)
	for _, port := range matchingPorts {
		if port.newlyAdded {
			// Not yet probed, skip.
			continue
		}
		if port.upCount(probeCfg) > 0 {
			anyUPState = true
			if port.cost < lowestCost {
				lowestCost = port.cost
			}
		}
	}
	if anyUPState {
		// 2.2. Find the highest UP count at this cost.
		var highestUPCnt int
		for _, port := range matchingPorts {
			if port.newlyAdded ||
				(route.MPRoute.PreferLowerCost && port.cost != lowestCost) {
				continue
			}
			if port.upCount(probeCfg) > highestUPCnt {
				highestUPCnt = port.upCount(probeCfg)
			}
		}
		// 2.3. Find the best cellular signal at this cost and UP count
		bestRSSI := minRSSI
		for _, port := range matchingPorts {
			if port.newlyAdded ||
				(route.MPRoute.PreferLowerCost && port.cost != lowestCost) {
				continue
			}
			if port.upCount(probeCfg) != highestUPCnt {
				continue
			}
			if !port.isWwan {
				continue
			}
			portRSSI := p.getWwanRSSI(port.logicallabel)
			if portRSSI > bestRSSI {
				bestRSSI = portRSSI
			}
		}
		// 2.3. Collect labels of ports with lowestCost + highestUPCnt + bestRSSI
		//      If NI is already using one of them, then return without any change.
		var bestPorts []string
		for _, port := range matchingPorts {
			if port.newlyAdded ||
				(route.MPRoute.PreferLowerCost && port.cost != lowestCost) {
				continue
			}
			if port.upCount(probeCfg) != highestUPCnt {
				continue
			}
			if route.MPRoute.PreferStrongerWwanSignal && port.isWwan {
				if p.getWwanRSSI(port.logicallabel) != bestRSSI {
					continue
				}
			}
			if route.SelectedPortLL == port.logicallabel {
				return false
			}
			bestPorts = append(bestPorts, port.logicallabel)
		}
		// 2.4. Try to share load between these ports using round-robin approach.
		selectedPort := p.roundRobinPick(bestPorts)
		if route.SelectedPortLL == "" {
			p.log.Noticef(
				"PortProber: Selecting port %s for route dst=%v NI=%v "+
					"(UP count = %d)", selectedPort, route.MPRoute.DstNetwork,
				route.NetworkInstance, highestUPCnt)
		} else {
			p.log.Noticef("PortProber: Changing port from %s to %s for route dst=%v NI=%v "+
				"(UP count = %d)", route.SelectedPortLL, selectedPort,
				route.MPRoute.DstNetwork, route.NetworkInstance, highestUPCnt)
		}
		route.SelectedPortLL = selectedPort
		return true
	}

	// If we got here, then there is no port with working connectivity...
	// Keep the existing if NI already has one.
	if route.SelectedPortLL != "" {
		return false
	}
	// 3. Find lowest-cost port matching the label that has unicast IP address.
	var suitablePorts []string
	for _, port := range matchingPorts {
		for _, ip := range port.localAddrs {
			if ip.IsGlobalUnicast() {
				suitablePorts = append(suitablePorts, port.logicallabel)
			}
		}
	}
	if len(suitablePorts) > 0 {
		if route.MPRoute.PreferLowerCost {
			suitablePorts = p.lowestCostPorts(suitablePorts)
		}
		route.SelectedPortLL = p.roundRobinPick(suitablePorts)
		p.log.Noticef(
			"PortProber: Selecting port %s for route dst=%v NI=%v "+
				"(has at least unicast IP)", route.SelectedPortLL, route.MPRoute.DstNetwork,
			route.NetworkInstance)
		return true
	}
	// 4. Find lowest-cost port matching the label that at least has a local IP address.
	suitablePorts = nil
	for _, port := range matchingPorts {
		if len(port.localAddrs) > 0 {
			suitablePorts = append(suitablePorts, port.logicallabel)
		}
	}
	if len(suitablePorts) > 0 {
		if route.MPRoute.PreferLowerCost {
			suitablePorts = p.lowestCostPorts(suitablePorts)
		}
		route.SelectedPortLL = p.roundRobinPick(suitablePorts)
		p.log.Noticef(
			"PortProber: Selecting port %s for route dst=%v NI=%v "+
				"(has at least local IP)", route.SelectedPortLL, route.MPRoute.DstNetwork,
			route.NetworkInstance)
		return true
	}
	// 5. If none of the ports have valid unicast/local IP address just pick
	//    the lowest-cost port that matches the label
	suitablePorts = nil
	for _, port := range matchingPorts {
		suitablePorts = append(suitablePorts, port.logicallabel)
	}
	if len(suitablePorts) > 0 {
		if route.MPRoute.PreferLowerCost {
			suitablePorts = p.lowestCostPorts(suitablePorts)
		}
		route.SelectedPortLL = p.roundRobinPick(suitablePorts)
		p.log.Noticef(
			"PortProber: Selecting port %s for route dst=%v NI=%v "+
				"(last resort)", route.SelectedPortLL, route.MPRoute.DstNetwork,
			route.NetworkInstance)
		return true
	}
	// 6. If nothing found, just leave the empty port label for this NI.
	return false
}

func (p *PortProber) roundRobinPick(ports []string) string {
	// The list must be sorted otherwise we could get random order which breaks
	// round-robin selection.
	comparePortIndex := func(i, j int) bool {
		iIdx := p.getIntfOrderInDNS(ports[i], true)
		jIdx := p.getIntfOrderInDNS(ports[j], true)
		return iIdx < jIdx
	}
	sort.Slice(ports, comparePortIndex)
	p.pickIteration++
	return ports[p.pickIteration%len(ports)]
}

func (p *PortProber) lowestCostPorts(ports []string) []string {
	lowestCost := maxCost
	for _, port := range ports {
		cost := p.getPortCost(port)
		if cost < lowestCost {
			lowestCost = cost
		}
	}
	var lowestCostPorts []string
	for _, port := range ports {
		cost := p.getPortCost(port)
		if cost == lowestCost {
			lowestCostPorts = append(lowestCostPorts, port)
		}
	}
	return lowestCostPorts
}

func (p *PortProber) routeKey(ni uuid.UUID, dstNet *net.IPNet) string {
	return fmt.Sprintf("%s-%s", ni, dstNet.String())
}

func (p *PortProber) getIntfOrderInDNS(ifNameOrLabel string, isLabel bool) int {
	for i := range p.dns.Ports {
		if isLabel && p.dns.Ports[i].Logicallabel == ifNameOrLabel {
			return i
		}
		if !isLabel && p.dns.Ports[i].IfName == ifNameOrLabel {
			return i
		}
	}
	return -1
}

func (p *PortProber) getPortCost(portLabel string) (cost uint8) {
	for _, port := range p.dns.Ports {
		if port.Logicallabel == portLabel {
			return port.Cost
		}
	}
	return maxCost // unavailable cost is worse than any actual cost
}

func (p *PortProber) getWwanRSSI(portLabel string) (rssi int32) {
	for _, wwanNet := range p.wwanMetrics.Networks {
		if wwanNet.LogicalLabel == portLabel {
			return wwanNet.SignalInfo.RSSI
		}
	}
	return minRSSI // unavailable RSSI is worse than any actual RSSI
}

func getLocalIPs(port types.NetworkPortStatus) (ips []net.IP) {
	for _, addr := range port.AddrInfoList {
		if !addr.Addr.IsUnspecified() {
			ips = append(ips, addr.Addr)
		}
	}
	return ips
}

func getNextHops(port types.NetworkPortStatus) (ips []net.IP) {
	for _, dr := range port.DefaultRouters {
		if !dr.IsUnspecified() {
			ips = append(ips, dr)
		}
	}
	return ips
}
