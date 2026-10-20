// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package mgmtproxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// dialError carries failures from individual port attempts; the proxy handler
// translates these into HTTP 502/504 responses.
type dialError struct {
	msg      string
	attempts []attemptResult
}

type attemptResult struct {
	IfName string
	SrcIP  net.IP
	Cost   uint8
	Err    error
}

func (e *dialError) Error() string {
	if len(e.attempts) == 0 {
		return e.msg
	}
	out := e.msg
	for _, a := range e.attempts {
		out += fmt.Sprintf("; %s/%v(cost=%d): %v", a.IfName, a.SrcIP, a.Cost, a.Err)
	}
	return out
}

// Attempts returns the per-port failure list for callers that want to record
// stats or include them in a structured log line.
func (e *dialError) Attempts() []attemptResult {
	return e.attempts
}

// dialResult carries the metadata of a successful dial so the caller can log
// which port + cost won.
type dialResult struct {
	Conn     net.Conn
	IfName   string
	SrcIP    net.IP
	Cost     uint8
	Attempts []attemptResult // failed attempts that preceded this success (may be empty)
}

// mgmtSource is one (port, source IP) pair that outbound traffic can be bound
// to so it follows that port's routing table.
type mgmtSource struct {
	IfName string
	SrcIP  net.IP
	Cost   uint8
}

// mgmtSources lists the usable (port, non-link-local source IP) pairs in
// ascending port cost order, skipping ports above maxCost and ports flagged
// failed by NIM. Shared by dialing and by hostname resolution so both pick
// the same ports in the same order.
func mgmtSources(dns types.DeviceNetworkStatus, maxCost uint8, rotation int) []mgmtSource {
	intfs := types.GetMgmtPortsSortedCostWithoutFailed(dns, rotation)
	if len(intfs) == 0 {
		// Mirror SendOnAllIntf's fallback: during onboarding NIM may not
		// have set LastFailed/LastSucceeded yet, so try unfiltered.
		intfs = types.GetMgmtPortsSortedCost(dns, rotation)
	}
	var out []mgmtSource
	for _, intf := range intfs {
		port := dns.LookupPortByIfName(intf)
		if port == nil || port.Cost > maxCost {
			continue
		}
		// An error only means the port has no usable address right now.
		addrs, _ := types.GetLocalAddrList(dns, intf)
		for _, addr := range addrs {
			out = append(out, mgmtSource{IfName: intf, SrcIP: addr, Cost: port.Cost})
		}
	}
	return out
}

// dialCostAware iterates management ports in ascending cost order (skipping
// ports above maxCost and ports flagged failed by NIM) and tries each port's
// non-link-local source IPs in turn. The first successful TCP connect wins.
// The rotation argument round-robins selection within each cost tier so load
// is shared across same-cost ports, matching controllerconn's behavior.
//
// This mirrors the shape of pillar's controllerconn.Client.SendOnAllIntf /
// SendOnIntf — same primitives, no controller-specific HTTP/cert logic.
//
// Source-IP binding is what makes the cost-aware routing work: NIM installs
// `from <srcIP> lookup <port-table>` IP rules, so packets bound to a port's
// source IP go through that port's per-port routing table and out its own
// gateway, regardless of what `table main`'s default route currently points
// at.
func dialCostAware(parent context.Context, log *base.LogObject,
	dns types.DeviceNetworkStatus, maxCost uint8, target string,
	timeout time.Duration, rotation int) (*dialResult, error) {

	sources := mgmtSources(dns, maxCost, rotation)
	if len(sources) == 0 {
		return nil, &dialError{msg: fmt.Sprintf("mgmtproxy: no management interfaces available for %s", target)}
	}

	var attempts []attemptResult
	for _, src := range sources {
		conn, err := dialFromSource(parent, log, src.IfName, src.SrcIP, target, timeout)
		if err == nil {
			return &dialResult{
				Conn:     conn,
				IfName:   src.IfName,
				SrcIP:    src.SrcIP,
				Cost:     src.Cost,
				Attempts: attempts,
			}, nil
		}
		attempts = append(attempts, attemptResult{
			IfName: src.IfName, SrcIP: src.SrcIP, Cost: src.Cost, Err: err,
		})
		if log != nil {
			log.Tracef("mgmtproxy: dial %s via %s src %v cost %d failed: %v",
				target, src.IfName, src.SrcIP, src.Cost, err)
		}
	}
	return nil, &dialError{
		msg:      fmt.Sprintf("mgmtproxy: all attempts to %s failed", target),
		attempts: attempts,
	}
}

// dialFromSource binds the outbound socket to srcIP and uses a per-port DNS
// resolver so the DNS query for the target hostname also flows through the
// per-port routing table.
func dialFromSource(parent context.Context, log *base.LogObject,
	ifName string, srcIP net.IP, target string, timeout time.Duration) (net.Conn, error) {

	resolver := controllerconn.NewResolverWithLocalIP(log, ifName, srcIP).NetResolver()

	dialer := &net.Dialer{
		Resolver:  resolver,
		LocalAddr: &net.TCPAddr{IP: srcIP},
		Timeout:   timeout,
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return dialer.DialContext(ctx, "tcp", target)
}
