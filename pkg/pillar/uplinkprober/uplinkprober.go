// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package uplinkprober is used by zedrouter to determine the connectivity status
// of uplink interfaces and to decide which interface should be used by each network
// instance (with a dynamic uplink assignment) at a given moment.
package uplinkprober

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// UplinkProber is used by zedrouter to test the connectivity status of uplink interfaces
// (aka ports) used by (non-switch) network instances. The prober picks the lowest-cost
// working port for every network instance that is configured with the "uplink" label
// instead of being attached to a specific port. Whenever the selected uplink changes,
// zedrouter is notified by the prober. It is up to the zedrouter to perform the re-routing
// from one port to another.
type UplinkProber struct {
	sync.Mutex
	log         *base.LogObject
	config      Config
	reachProber ReachabilityProber
	dns         types.DeviceNetworkStatus
	pendingDNS  *types.DeviceNetworkStatus

	pauseCh    chan bool
	watcherChs []chan []NIProbeStatus

	probeTicker *time.Ticker
	forcedTick  bool

	niConfig          map[string]types.NetworkInstanceConfig // key: UUID
	niProbeStatus     map[string]*NIProbeStatus              // key: UUID
	uplinkProbeStatus map[string]*uplinkProbeStatus          // key: uplink logical label

	probeIteration int
	pickIteration  int
}

const minNHToRemoteProbeRatio uint8 = 5

// Config : configuration for uplink prober.
// Currently, this is not configurable via controller.
type Config struct {
	// MaxContFailCnt : maximum number of continuous failures that is allowed to happen
	// before the next hop or remote network reachability is declared as DOWN.
	MaxContFailCnt uint8
	// MaxContSuccessCnt : maximum number of continuous successes that is allowed to happen
	// before the next hop or remote network reachability is declared as UP.
	MaxContSuccessCnt uint8
	// MinContPrevStateCnt : how many continuous confirmations of the previous UP/DOWN state
	// are needed for a sudden change to be applied immediately. This avoids frequent
	// uplink selection changes with a flapping connectivity, but also ensures that
	// an occasional change is reflected as soon as possible.
	// Currently only applied for Next Hop probing, not for remote probing.
	MinContPrevStateCnt uint8
	// NextHopProbeTimeout : timeout for a single next hop probe.
	NextHopProbeTimeout time.Duration
	// RemoteProbeTimeout : timeout for a single remote probe.
	RemoteProbeTimeout time.Duration
	// NHToRemoteProbeRatio : How many NH probes must be run first before a single remote
	// probe is executed.
	// Minimum allowed value is 5.
	NHToRemoteProbeRatio uint8
	// NHProbeInterval : how often to execute NH probe.
	// Remote probe interval is NHProbeInterval * NHToRemoteProbeRatio
	NHProbeInterval time.Duration
}

// DefaultConfig : default configuration for UplinkProber.
// Since these options are currently not configurable via controller,
// non-default config is used only in unit tests.
func DefaultConfig() Config {
	return Config{
		MaxContFailCnt:       4,
		MaxContSuccessCnt:    3,
		MinContPrevStateCnt:  40, // 40 * 15sec = 10 minutes
		NextHopProbeTimeout:  100 * time.Millisecond,
		RemoteProbeTimeout:   3 * time.Second,
		NHToRemoteProbeRatio: 10,
		NHProbeInterval:      15 * time.Second,
	}
}

// ReachabilityProber is used by UplinkProber to test the reachability of the uplink's
// next hop(s) (the closest router(s)) and remote networks (Internet, cloud VPC, etc.).
// How the reachability is determined (i.e. what protocols/techniques are used, which
// remote endpoints are communicated with, etc.) is up to the prober implementation.
// The default implementation uses ICMP ping for NH probing and HTTP GET towards
// the controller to evaluate remote reachability.
// A mock implementation is also provided for unit testing purposes.
type ReachabilityProber interface {
	// ProbeNextHopReach : test reachability of the uplink's closest router(s).
	// Return non-nil error if the next hop is not reachable.
	// Additionally, return a list of all next hops that were used for probing.
	// It is preferred for the method to be fast as it will be called quite often.
	ProbeNextHopReach(ctx context.Context, uplinkLL string, dns *types.DeviceNetworkStatus) (
		probedNHs []net.IP, err error)
	// ProbeRemoteReach : test reachability of remote network(s), such as the Internet
	// (or whatever remote networks are expected to be reachable via this uplink).
	// Return non-nil error if remote networks are not reachable.
	// Additionally, return a list of all remote endpoints that were used for probing.
	// This method is not called as often as ProbeNextHopReach and can therefore
	// take a little longer to execute if needed.
	ProbeRemoteReach(ctx context.Context, uplinkLL string, dns *types.DeviceNetworkStatus) (
		probedEps []url.URL, err error)
}

// NIProbeStatus is published whenever the selected uplink interface for a network
// instance changes.
type NIProbeStatus struct {
	NetworkInstance uuid.UUID
	// SelectedUplinkLL is a logical label of the uplink interface selected as having
	// the best working connectivity at the moment.
	SelectedUplinkLL string
	SelectedAt       time.Time
}

// uplinkProbeStatus - used only internally to track the probing state of every
// uplink interface.
type uplinkProbeStatus struct {
	logicallabel string
	ifName       string
	cost         uint8
	localAddrs   []net.IP
	newlyAdded   bool

	remoteEps []url.URL
	nextHops  []net.IP

	nhUP     bool
	remoteUP bool

	nhFailedCnt      uint32 // continuous fail count, reset on success
	nhSuccessCnt     uint32 // contiguous success count, reset on fail
	remoteFailedCnt  uint32 // continuous fail count, reset on success
	remoteSuccessCnt uint32 // continuous success count, reset on fail

	remoteAvgLatency time.Duration
}

// How many probing states are UP.
func (s uplinkProbeStatus) upCount() int {
	var upCnt int
	if s.nhUP {
		upCnt++
	}
	if s.remoteUP {
		upCnt++
	}
	return upCnt
}

// NewUplinkProber is a constructor for UplinkProber.
func NewUplinkProber(log *base.LogObject, config Config,
	reachProber ReachabilityProber) *UplinkProber {
	if config.NHToRemoteProbeRatio < minNHToRemoteProbeRatio {
		config.NHToRemoteProbeRatio = minNHToRemoteProbeRatio
	}
	prober := &UplinkProber{
		log:               log,
		config:            config,
		reachProber:       reachProber,
		pauseCh:           make(chan bool),
		niConfig:          make(map[string]types.NetworkInstanceConfig),
		niProbeStatus:     make(map[string]*NIProbeStatus),
		uplinkProbeStatus: make(map[string]*uplinkProbeStatus),
	}
	prober.probeTicker = time.NewTicker(config.NHProbeInterval)
	go prober.runProbing()
	return prober
}

// StartNIProbing tells UplinkProber to start periodic probing of uplink
// interfaces for this network instance.
// It is called by zedrouter whenever a new network instance with "uplink" label
// is created or when the config related to probing has changed (in that case
// the probing is first stopped, then restarted with the new config).
func (p *UplinkProber) StartNIProbing(niConfig types.NetworkInstanceConfig) (
	initialStatus NIProbeStatus, err error) {
	p.Lock()
	defer p.Unlock()
	if !types.IsSharedPortLabel(niConfig.Logicallabel) {
		return initialStatus, fmt.Errorf("cannot probe NI (%s) with non-shared label (%s)",
			niConfig.UUID, niConfig.Logicallabel)
	}
	if niConfig.Type != types.NetworkInstanceTypeLocal {
		return initialStatus, fmt.Errorf("unsupported NI (%s) type (%v) for probing",
			niConfig.UUID, niConfig.Type)
	}
	p.niConfig[niConfig.UUID.String()] = niConfig
	p.niProbeStatus[niConfig.UUID.String()] = &NIProbeStatus{
		NetworkInstance: niConfig.UUID,
	}
	// Initial pick is made based on the last probing results.
	p.log.Noticef("UplinkProber: Started uplink probing for NI %s", niConfig.UUID)
	p.pickUplinkForNI(niConfig.UUID)
	p.forceProbing()
	return *p.niProbeStatus[niConfig.UUID.String()], nil
}

// StopNIProbing tells UplinkProber to stop periodic probing of uplink
// interfaces for this network instance.
// It is called by zedrouter whenever a network instance with "uplink" label is about
// to be deleted (i.e. the method is called before removal) or when the config related
// to probing has changed (in that case the probing is first stopped, then restarted
// with the new config).
func (p *UplinkProber) StopNIProbing(ni uuid.UUID) error {
	p.Lock()
	defer p.Unlock()
	if _, ok := p.niConfig[ni.String()]; ok {
		delete(p.niConfig, ni.String())
		delete(p.niProbeStatus, ni.String())
		p.log.Noticef("UplinkProber: Stopped uplink probing for NI %s", ni)
		return nil
	}
	return fmt.Errorf("network instance %s is without probing", ni)
}

// PauseProbing : pause all probing activities for all network instances.
// The method is blocking and when it returns it is guaranteed that no probing
// is in progress.
// It is used by zedrouter whenever network stack is being reconfigured, which could
// interfere with the probing and produce false results.
func (p *UplinkProber) PauseProbing() {
	p.pauseCh <- true
	p.log.Tracef("UplinkProber: Paused probing")
}

// ResumeProbing : resume all probing activities after a pause.
func (p *UplinkProber) ResumeProbing() {
	p.pauseCh <- false
	p.log.Tracef("UplinkProber: Resumed probing")
}

// ApplyDNSUpdate : update the state of probing based on a newly received
// Device Network Status from NIM.
func (p *UplinkProber) ApplyDNSUpdate(dns types.DeviceNetworkStatus) {
	p.Lock()
	defer p.Unlock()
	p.pendingDNS = &dns
	p.forceProbing()
}

// WatchProbeUpdates returns channel where UplinkProber will for every probed network
// instance publish an update of which uplink interface should be used.
// Channel type is a slice of probe statuses - this is used to publish multiple updates
// in a bulk for efficiency.
func (p *UplinkProber) WatchProbeUpdates() <-chan []NIProbeStatus {
	p.Lock()
	defer p.Unlock()
	watcherCh := make(chan []NIProbeStatus)
	p.watcherChs = append(p.watcherChs, watcherCh)
	return watcherCh
}

// GetProbeStatus : get the current probing status for a given network instance.
func (p *UplinkProber) GetProbeStatus(ni uuid.UUID) (NIProbeStatus, error) {
	p.Lock()
	defer p.Unlock()
	status, ok := p.niProbeStatus[ni.String()]
	if !ok {
		return NIProbeStatus{}, fmt.Errorf("network instance %s is without probing", ni)
	}
	return *status, nil
}

// GetProbeMetrics : get probing metrics for a given network instance.
func (p *UplinkProber) GetProbeMetrics(
	ni uuid.UUID) (metrics types.ProbeMetrics, err error) {
	p.Lock()
	defer p.Unlock()
	status, ok := p.niProbeStatus[ni.String()]
	if !ok {
		return metrics, fmt.Errorf("network instance %s is without probing", ni)
	}
	uplink := status.SelectedUplinkLL
	if uplink != "" {
		ports := p.dns.GetPortsByLogicallabel(status.SelectedUplinkLL)
		if len(ports) == 1 {
			metrics.SelectedUplinkIntf = ports[0].IfName
		}
		if uplinkStatus, exists := p.uplinkProbeStatus[uplink]; exists {
			var remoteEps []string
			for _, remoteURL := range uplinkStatus.remoteEps {
				remoteEps = append(remoteEps, remoteURL.String())
			}
			metrics.RemoteEndpoints = remoteEps
		}
	}
	metrics.LocalPingIntvl = uint32(p.config.NHProbeInterval / time.Second)
	remoteIntvl := time.Duration(p.config.NHToRemoteProbeRatio) * p.config.NHProbeInterval
	metrics.RemotePingIntvl = uint32(remoteIntvl / time.Second)
	config := p.niConfig[ni.String()]
	for _, uplinkStatus := range p.uplinkProbeStatus {
		if config.Logicallabel == types.FreeUplinkLabel && uplinkStatus.cost > 0 {
			continue
		}
		metrics.UplinkCount++
		intfMetrics := types.ProbeIntfMetrics{
			IntfName:        uplinkStatus.ifName,
			NexthopIPs:      uplinkStatus.nextHops,
			NexthopUP:       uplinkStatus.nhUP,
			RemoteUP:        uplinkStatus.remoteUP,
			NexthopUPCnt:    uplinkStatus.nhSuccessCnt,
			NexthopDownCnt:  uplinkStatus.nhFailedCnt,
			RemoteUPCnt:     uplinkStatus.remoteSuccessCnt,
			RemoteDownCnt:   uplinkStatus.remoteFailedCnt,
			LatencyToRemote: uint32(uplinkStatus.remoteAvgLatency / time.Millisecond),
		}
		metrics.IntfProbeStats = append(metrics.IntfProbeStats, intfMetrics)
	}
	// Keep the interface order from DNS.
	less := func(i, j int) bool {
		intfI := metrics.IntfProbeStats[i].IntfName
		intfJ := metrics.IntfProbeStats[j].IntfName
		return p.getIntfOrderInDNS(intfI, false) < p.getIntfOrderInDNS(intfJ, false)
	}
	sort.Slice(metrics.IntfProbeStats, less)
	return metrics, nil
}

// Run periodic uplink probing from a separate Go routine.
func (p *UplinkProber) runProbing() {
	var paused bool
	for {
		select {
		case paused = <-p.pauseCh:
			p.Lock()
			if paused {
				p.probeTicker.Stop()
			} else {
				p.forceProbing()
			}
			p.Unlock()

		case <-p.probeTicker.C:
			p.Lock()
			if paused {
				// Caller forcefully requested probing while prober was in a paused state.
				p.probeTicker.Stop()
				p.forcedTick = false
				p.Unlock()
				continue
			}
			var updates []NIProbeStatus
			updates, paused = p.probeUplinks()
			if !paused && p.forcedTick {
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
func (p *UplinkProber) forceProbing() {
	p.probeTicker.Reset(time.Second)
	p.forcedTick = true
}

// Main method performing probing of all uplinks used by at least one
// network instance with a shared label. Next it iterates over all network
// instances with enabled probing and decides if selected uplink should change.
func (p *UplinkProber) probeUplinks() (updates []NIProbeStatus, paused bool) {
	defer func() { p.probeIteration++ }()
	// 1. Apply pending DNS update if there is any
	if p.pendingDNS != nil {
		p.applyPendingDNS(*p.pendingDNS)
		p.dns = *p.pendingDNS
	}
	// 2. probe every used uplink
	for _, uplinkStatus := range p.uplinkProbeStatus {
		// 2.1. if uplink has zero cost, probe the next hop
		if uplinkStatus.cost == 0 {
			p.probeUplinkNH(uplinkStatus)
		} else {
			// Assume that the states of NH and remote connectivity are the same.
			uplinkStatus.nhUP = uplinkStatus.remoteUP
			uplinkStatus.nextHops = nil
			uplinkStatus.nhSuccessCnt = 0
			uplinkStatus.nhFailedCnt = 0
		}
		if p.checkIfPaused() {
			return nil, true
		}
		// 2.2. Maybe probe also remote endpoints.
		if uplinkStatus.newlyAdded ||
			p.probeIteration%int(p.config.NHToRemoteProbeRatio) == 0 {
			p.probeUplinkRemoteEps(uplinkStatus)
			if uplinkStatus.cost > 0 {
				// For non-free uplink next hop probing is not performed,
				// instead we just duplicate the UP/DOWN state from the remote probe.
				uplinkStatus.nhUP = uplinkStatus.remoteUP
			}
		}
		uplinkStatus.newlyAdded = false
		if p.checkIfPaused() {
			return nil, true
		}
	}
	// 3. update uplink selections for NIs
	for _, ni := range p.niConfig {
		if changed := p.pickUplinkForNI(ni.UUID); changed {
			updates = append(updates, *p.niProbeStatus[ni.UUID.String()])
		}
	}
	return updates, false
}

// Take the latest received DNS update into effect.
func (p *UplinkProber) applyPendingDNS(pendingDNS types.DeviceNetworkStatus) {
	// Remove ports from uplinkProbeStatus that do not exist anymore
	// or are no longer configured for management.
	for uplinkLL := range p.uplinkProbeStatus {
		ports := p.pendingDNS.GetPortsByLogicallabel(uplinkLL)
		if len(ports) == 0 {
			p.log.Noticef("UplinkProber: Removed %s from the list of probed uplinks",
				uplinkLL)
			delete(p.uplinkProbeStatus, uplinkLL)
			continue
		}
		port := ports[0]
		if !port.IsMgmt {
			p.log.Noticef("UplinkProber: Removed %s from the list of probed uplinks",
				uplinkLL)
			delete(p.uplinkProbeStatus, uplinkLL)
		}
	}
	// Add ports that have just appeared and update existing.
	for _, port := range p.pendingDNS.Ports {
		if !port.IsMgmt {
			continue
		}
		uplinkStatus, haveStatus := p.uplinkProbeStatus[port.Logicallabel]
		if !haveStatus {
			// Newly appeared port.
			uplinkLL := port.Logicallabel
			p.uplinkProbeStatus[uplinkLL] = &uplinkProbeStatus{
				logicallabel: port.Logicallabel,
				ifName:       port.IfName,
				cost:         port.Cost,
				// Mark as new so that the following probing will run fully
				// and decide the UP/DOWN state.
				newlyAdded: true,
				localAddrs: getLocalIPs(port),
			}
			p.log.Noticef("UplinkProber: Added %s to list of probed uplinks", uplinkLL)
		} else {
			// Update existing.
			uplinkStatus.ifName = port.IfName
			uplinkStatus.cost = port.Cost
			uplinkStatus.localAddrs = getLocalIPs(port)
		}
	}
}

// Probe next-hops of the given uplink.
func (p *UplinkProber) probeUplinkNH(uplinkStatus *uplinkProbeStatus) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, p.config.NextHopProbeTimeout)
	uplinkLL := uplinkStatus.logicallabel
	probedNHs, err := p.reachProber.ProbeNextHopReach(ctx, uplinkLL, &p.dns)
	cancel()
	uplinkStatus.nextHops = probedNHs
	if err == nil {
		// Next hop is reachable.
		if uplinkStatus.newlyAdded {
			uplinkStatus.nhUP = true
		} else {
			if !uplinkStatus.nhUP &&
				uplinkStatus.nhSuccessCnt == 0 &&
				uplinkStatus.nhFailedCnt >= uint32(p.config.MinContPrevStateCnt) {
				uplinkStatus.nhUP = true
				p.log.Noticef("UplinkProber: Setting NH to UP for uplink %s "+
					"(sudden change)", uplinkLL)

			}
			uplinkStatus.nhSuccessCnt++
			uplinkStatus.nhFailedCnt = 0
			if !uplinkStatus.nhUP &&
				uplinkStatus.nhSuccessCnt > uint32(p.config.MaxContSuccessCnt) {
				uplinkStatus.nhUP = true
				p.log.Noticef(
					"UplinkProber: Setting NH to UP for uplink %s "+
						"(continuously UP)", uplinkLL)
			}
		}
	} else {
		// Next hop is NOT reachable.
		if uplinkStatus.newlyAdded {
			uplinkStatus.nhUP = false
		} else {
			if uplinkStatus.nhUP &&
				uplinkStatus.nhFailedCnt == 0 &&
				uplinkStatus.nhSuccessCnt >= uint32(p.config.MinContPrevStateCnt) {
				uplinkStatus.nhUP = false
				p.log.Noticef("UplinkProber: Setting NH to DOWN for uplink %s "+
					"(sudden change; probe err: %v)", uplinkLL, err)
			}
			uplinkStatus.nhFailedCnt++
			uplinkStatus.nhSuccessCnt = 0
			if uplinkStatus.nhUP &&
				uplinkStatus.nhFailedCnt > uint32(p.config.MaxContFailCnt) {
				uplinkStatus.nhUP = false
				p.log.Noticef(
					"UplinkProber: Setting NH to DOWN for uplink %s "+
						"(continuously DOWN; probe err: %v)", uplinkLL, err)
			}
		}
	}
	if uplinkStatus.newlyAdded {
		p.log.Noticef("UplinkProber: Initial NH status for uplink %s: %t (probe err: %v)",
			uplinkLL, uplinkStatus.nhUP, err)
	}
}

// Probe remote endpoints through the given uplink.
func (p *UplinkProber) probeUplinkRemoteEps(uplinkStatus *uplinkProbeStatus) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, p.config.RemoteProbeTimeout)
	startTime := time.Now()
	uplinkLL := uplinkStatus.logicallabel
	probedEps, err := p.reachProber.ProbeRemoteReach(ctx, uplinkLL, &p.dns)
	duration := time.Since(startTime)
	cancel()
	uplinkStatus.remoteEps = probedEps
	if err == nil {
		// Remote networks are reachable.
		totalDuration := uplinkStatus.remoteAvgLatency *
			time.Duration(uplinkStatus.remoteSuccessCnt)
		uplinkStatus.remoteSuccessCnt++
		uplinkStatus.remoteAvgLatency = (totalDuration + duration) /
			time.Duration(uplinkStatus.remoteSuccessCnt)
		uplinkStatus.remoteFailedCnt = 0
		if uplinkStatus.newlyAdded {
			uplinkStatus.remoteUP = true
		} else if !uplinkStatus.remoteUP &&
			uplinkStatus.remoteSuccessCnt > uint32(p.config.MaxContSuccessCnt) {
			uplinkStatus.remoteUP = true
			p.log.Noticef(
				"UplinkProber: Setting Remote status to UP for uplink %s "+
					"(continuously UP)", uplinkLL)
		}
	} else {
		// Remote networks are NOT reachable.
		uplinkStatus.remoteFailedCnt++
		uplinkStatus.remoteSuccessCnt = 0
		uplinkStatus.remoteAvgLatency = 0
		if uplinkStatus.newlyAdded {
			uplinkStatus.remoteUP = false
		} else if uplinkStatus.remoteUP &&
			uplinkStatus.remoteFailedCnt > uint32(p.config.MaxContFailCnt) {
			uplinkStatus.remoteUP = false
			p.log.Noticef(
				"UplinkProber: Setting Remote status to DOWN for uplink %s "+
					"(continuously DOWN; probe err: %v)", uplinkLL, err)
		}
	}
	if uplinkStatus.newlyAdded {
		p.log.Noticef("UplinkProber: Initial Remote status for uplink %s: %t (probe err: %v)",
			uplinkLL, uplinkStatus.remoteUP, err)
	}
}

// Entering this function the prober is in the non-paused state and will check
// if an ongoing probing should stop.
func (p *UplinkProber) checkIfPaused() (paused bool) {
	select {
	case paused = <-p.pauseCh:
	default:
	}
	if paused {
		p.probeTicker.Stop()
	}
	return paused
}

// Pick the best uplink for the given network instance.
// UplinkProber optimizes first by cost, then by the number of UP states and finally
// by the presence or lack of a local IP address.
func (p *UplinkProber) pickUplinkForNI(ni uuid.UUID) (changed bool) {
	status := p.niProbeStatus[ni.String()]
	defer func() {
		if changed {
			status.SelectedAt = time.Now()
		}
	}()
	// 1. Check if the selected uplink is still available.
	if status.SelectedUplinkLL != "" {
		if _, exists := p.uplinkProbeStatus[status.SelectedUplinkLL]; !exists {
			p.log.Noticef(
				"UplinkProber: Previously selected uplink %s for NI %s is no longer available",
				status.SelectedUplinkLL, ni)
			status.SelectedUplinkLL = ""
		}
	}
	config := p.niConfig[ni.String()]
	// 2. Find best uplinks with working connectivity (best = lowest cost, most UP states)
	// 2.1. Find the lowest cost for which there is at least one uplink interface available
	//      with at least one UP state.
	lowestCost := uint8(255)
	anyUPState := false
	for _, uplinkStatus := range p.uplinkProbeStatus {
		if uplinkStatus.newlyAdded {
			// Not yet probed, skip.
			continue
		}
		if config.Logicallabel == types.FreeUplinkLabel && uplinkStatus.cost > 0 {
			continue
		}
		if uplinkStatus.upCount() == 0 {
			continue
		}
		anyUPState = true
		if uplinkStatus.cost < lowestCost {
			lowestCost = uplinkStatus.cost
		}
	}
	highestUPCnt := 0
	if anyUPState {
		// 2.2. Find the highest UP count at this cost.
		for _, uplinkStatus := range p.uplinkProbeStatus {
			if uplinkStatus.newlyAdded || uplinkStatus.cost != lowestCost {
				continue
			}
			if uplinkStatus.upCount() > highestUPCnt {
				highestUPCnt = uplinkStatus.upCount()
			}
		}
		// 2.3. Collect labels of uplinks with lowestCost + highestUPCnt
		//      If NI is already using one of them, then return without any change.
		var uplinks []string
		for uplinkLL, uplinkStatus := range p.uplinkProbeStatus {
			if uplinkStatus.newlyAdded || uplinkStatus.cost != lowestCost ||
				uplinkStatus.upCount() != highestUPCnt {
				continue
			}
			if status.SelectedUplinkLL == uplinkLL {
				return false
			}
			uplinks = append(uplinks, uplinkLL)
		}
		// 2.4. Try to share load between these uplinks using round-robin approach.
		//      The list must be sorted otherwise we would get random order which
		//      breaks round-robin selection.
		less := func(i, j int) bool {
			iIdx := p.getIntfOrderInDNS(uplinks[i], true)
			jIdx := p.getIntfOrderInDNS(uplinks[j], true)
			return iIdx < jIdx
		}
		sort.Slice(uplinks, less)
		selectedUplink := uplinks[p.pickIteration%len(uplinks)]
		p.pickIteration++
		if status.SelectedUplinkLL == "" {
			p.log.Noticef(
				"UplinkProber: Selecting uplink %s for NI %s (cost = %d, UP count = %d)",
				selectedUplink, ni, lowestCost, highestUPCnt)
		} else {
			p.log.Noticef("UplinkProber: Changing uplink from %s to %s for NI %s "+
				"(cost = %d, UP count = %d)", status.SelectedUplinkLL, selectedUplink,
				ni, lowestCost, highestUPCnt)
		}
		status.SelectedUplinkLL = selectedUplink
		return true
	}
	// If we got here, then there is no uplink with working connectivity...
	// Keep the existing if NI already has one.
	if status.SelectedUplinkLL != "" {
		return false
	}
	// 3. Find any uplink matching the label that has unicast IP address.
	for uplinkLL, uplinkStatus := range p.uplinkProbeStatus {
		if config.Logicallabel == types.FreeUplinkLabel && uplinkStatus.cost > 0 {
			continue
		}
		for _, ip := range uplinkStatus.localAddrs {
			if ip.IsGlobalUnicast() {
				p.log.Noticef(
					"UplinkProber: Selecting uplink %s for NI %s (has at least unicast IP)",
					uplinkLL, ni)
				status.SelectedUplinkLL = uplinkLL
				return true
			}
		}
	}
	// 4. Find any uplink matching the label that at least has a local IP address.
	for uplinkLL, uplinkStatus := range p.uplinkProbeStatus {
		if config.Logicallabel == types.FreeUplinkLabel && uplinkStatus.cost > 0 {
			continue
		}
		if len(uplinkStatus.localAddrs) > 0 {
			p.log.Noticef(
				"UplinkProber: Selecting uplink %s for NI %s (has at least local IP)",
				uplinkLL, ni)
			status.SelectedUplinkLL = uplinkLL
			return true
		}
	}
	// 5. If none of the uplinks have valid unicast/local IP address just pick
	//    the first that matches the label
	for uplinkLL, uplinkStatus := range p.uplinkProbeStatus {
		if config.Logicallabel == types.FreeUplinkLabel && uplinkStatus.cost > 0 {
			continue
		}
		p.log.Noticef(
			"UplinkProber: Selecting uplink %s for NI %s (last resort)",
			uplinkLL, ni)
		status.SelectedUplinkLL = uplinkLL
		return true
	}
	// 6. If nothing found, just leave the empty uplink label for this NI.
	return false
}

func (p *UplinkProber) getIntfOrderInDNS(ifNameOrLabel string, isLabel bool) int {
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

func getLocalIPs(status types.NetworkPortStatus) (ips []net.IP) {
	for _, addr := range status.AddrInfoList {
		ips = append(ips, addr.Addr)
	}
	return ips
}
