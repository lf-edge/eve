// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package uplinkprober

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// MockReachProber is a mock ReachabilityProber used only for unit testing.
type MockReachProber struct {
	sync.Mutex

	// Mocked reachability state
	nhState     map[string]nextHopReachState // key: uplink logical label
	remoteState map[string]remoteReachState  // key: uplink logical label

	// Executed probes
	lastNhProbe     map[string]time.Time // key: uplink logical label
	lastRemoteProbe map[string]time.Time // key: uplink logical label
}

// Next-hop mocked reachability state
type nextHopReachState struct {
	nhs        []net.IP
	nhReachErr error
	nhProbeRTT time.Duration
}

// Remote network mocked reachability state
type remoteReachState struct {
	remoteEps      []url.URL
	remoteReachErr error
	remoteProbeRTT time.Duration
}

// NewMockReachProber is constructor for NewMockReachProber.
func NewMockReachProber() *MockReachProber {
	return &MockReachProber{
		nhState:         make(map[string]nextHopReachState),
		remoteState:     make(map[string]remoteReachState),
		lastNhProbe:     make(map[string]time.Time),
		lastRemoteProbe: make(map[string]time.Time),
	}
}

// SetNextHopState is used to simulate the state of next hop reachability
// for a given uplink port.
// Provide the list of next hops, non-nil error if they are not reachable
// and the time it takes to execute one probe.
func (p *MockReachProber) SetNextHopState(uplinkLL string,
	nhs []net.IP, reachErr error, probeRTT time.Duration) {
	p.Lock()
	defer p.Unlock()
	p.nhState[uplinkLL] = nextHopReachState{
		nhs:        nhs,
		nhReachErr: reachErr,
		nhProbeRTT: probeRTT,
	}
}

// ProbeNextHopReach returns fake probing results prepared using SetNextHopState.
func (p *MockReachProber) ProbeNextHopReach(ctx context.Context,
	uplinkLL string, dns *types.DeviceNetworkStatus) (probedNHs []net.IP, err error) {
	p.Lock()
	defer p.Unlock()
	p.lastNhProbe[uplinkLL] = time.Now()
	reachState := p.nhState[uplinkLL]
	select {
	case <-time.After(reachState.nhProbeRTT):
		// continue below the select
	case <-ctx.Done():
		return reachState.nhs, errors.New("timeout")
	}
	return reachState.nhs, reachState.nhReachErr
}

// LastNHProbe returns the timestamp of the last NH probing executed
// for the given uplink.
func (p *MockReachProber) LastNHProbe(uplinkLL string) time.Time {
	p.Lock()
	defer p.Unlock()
	return p.lastNhProbe[uplinkLL]
}

// SetRemoteState is used to simulate the state of remote networks reachability
// for a given uplink port.
// Provide the list of probed remote endpoints, non-nil error if they are not reachable
// and the time it takes to execute one probe.
func (p *MockReachProber) SetRemoteState(uplinkLL string,
	remoteEps []url.URL, reachErr error, probeRTT time.Duration) {
	p.Lock()
	defer p.Unlock()
	p.remoteState[uplinkLL] = remoteReachState{
		remoteEps:      remoteEps,
		remoteReachErr: reachErr,
		remoteProbeRTT: probeRTT,
	}
}

// ProbeRemoteReach return fake probing results prepared using SetRemoteState.
func (p *MockReachProber) ProbeRemoteReach(ctx context.Context,
	uplinkLL string, dns *types.DeviceNetworkStatus) (probedEps []url.URL, err error) {
	p.Lock()
	defer p.Unlock()
	p.lastRemoteProbe[uplinkLL] = time.Now()
	reachState := p.remoteState[uplinkLL]
	select {
	case <-time.After(reachState.remoteProbeRTT):
		// continue below the select
	case <-ctx.Done():
		return reachState.remoteEps, errors.New("timeout")
	}
	return reachState.remoteEps, reachState.remoteReachErr
}

// LastRemoteProbe returns the timestamp of the last Remote probing executed
// for the given uplink.
func (p *MockReachProber) LastRemoteProbe(uplinkLL string) time.Time {
	p.Lock()
	defer p.Unlock()
	return p.lastRemoteProbe[uplinkLL]
}
