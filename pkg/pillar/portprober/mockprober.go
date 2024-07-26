// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package portprober

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// MockReachProber is a mock ReachabilityProber used only for unit testing.
// Can be used as a mock implementation for every probing method.
type MockReachProber struct {
	sync.Mutex
	reachState map[string]reachState
	lastProbe  map[string]time.Time
}

// mocked reachability state
type reachState struct {
	reachErr error
	probeRTT time.Duration
}

// NewMockReachProber is constructor for NewMockReachProber.
func NewMockReachProber() *MockReachProber {
	return &MockReachProber{
		reachState: make(map[string]reachState),
		lastProbe:  make(map[string]time.Time),
	}
}

// SetReachabilityState is used to simulate the state of a remote endpoint reachability
// for a given output port.
// Provide non-nil error if the endpoint is not reachable and the time it takes to execute
// one probe.
func (p *MockReachProber) SetReachabilityState(portIfName string,
	dstAddr net.Addr, reachErr error, probeRTT time.Duration) {
	p.Lock()
	defer p.Unlock()
	p.reachState[p.probeKey(portIfName, dstAddr)] = reachState{
		reachErr: reachErr,
		probeRTT: probeRTT,
	}
}

// Probe return fake probing results prepared using SetReachabilityState.
func (p *MockReachProber) Probe(ctx context.Context, portIfName string,
	srcIP net.IP, dstAddr net.Addr, dnsServers []net.IP) error {
	p.Lock()
	defer p.Unlock()
	key := p.probeKey(portIfName, dstAddr)
	p.lastProbe[key] = time.Now()
	reachState, hasReachState := p.reachState[key]
	if !hasReachState {
		return errors.New("unreachable")
	}
	select {
	case <-time.After(reachState.probeRTT):
		// continue below the select
	case <-ctx.Done():
		return errors.New("timeout")
	}
	return reachState.reachErr
}

// LastProbe returns the timestamp of the last probing executed
// for the given destination and the output port.
func (p *MockReachProber) LastProbe(portIfName string, dstAddr net.Addr) time.Time {
	p.Lock()
	defer p.Unlock()
	return p.lastProbe[p.probeKey(portIfName, dstAddr)]
}

func (p *MockReachProber) probeKey(portIfName string, dstAddr net.Addr) string {
	return fmt.Sprintf("%s-%s", portIfName, dstAddr.String())
}
