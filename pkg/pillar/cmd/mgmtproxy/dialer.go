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

	intfs := types.GetMgmtPortsSortedCostWithoutFailed(dns, rotation)
	if len(intfs) == 0 {
		// Mirror SendOnAllIntf's fallback: during onboarding NIM may not
		// have set LastFailed/LastSucceeded yet, so try unfiltered.
		intfs = types.GetMgmtPortsSortedCost(dns, rotation)
	}
	if len(intfs) == 0 {
		return nil, &dialError{msg: fmt.Sprintf("mgmtproxy: no management interfaces available for %s", target)}
	}

	var attempts []attemptResult
	for _, intf := range intfs {
		port := dns.LookupPortByIfName(intf)
		if port == nil {
			continue
		}
		if port.Cost > maxCost {
			continue
		}
		for _, addr := range port.AddrInfoList {
			srcIP := addr.Addr
			if srcIP == nil || srcIP.IsLinkLocalUnicast() {
				continue
			}
			conn, err := dialFromSource(parent, log, intf, srcIP, target, timeout)
			if err == nil {
				return &dialResult{
					Conn:     conn,
					IfName:   intf,
					SrcIP:    srcIP,
					Cost:     port.Cost,
					Attempts: attempts,
				}, nil
			}
			attempts = append(attempts, attemptResult{
				IfName: intf, SrcIP: srcIP, Cost: port.Cost, Err: err,
			})
			if log != nil {
				log.Tracef("mgmtproxy: dial %s via %s src %v cost %d failed: %v",
					target, intf, srcIP, port.Cost, err)
			}
		}
	}
	return nil, &dialError{
		msg:      fmt.Sprintf("mgmtproxy: all attempts to %s failed", target),
		attempts: attempts,
	}
}

// dialFromSource binds the outbound socket to srcIP so packets follow the
// per-port routing table installed by NIM. DNS goes through resolv.conf →
// mgmt dnsmasq (127.0.0.1), which forwards to the upstream servers of all
// management ports; no per-port DNS binding is needed.
func dialFromSource(parent context.Context, log *base.LogObject,
	ifName string, srcIP net.IP, target string, timeout time.Duration) (net.Conn, error) {

	dialer := &controllerconn.DialerWithSrcIP{
		Log:     log,
		IfName:  ifName,
		LocalIP: srcIP,
		Timeout: timeout,
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return dialer.DialContext(ctx, "tcp", target)
}
