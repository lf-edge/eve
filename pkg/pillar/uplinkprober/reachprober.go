// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package uplinkprober

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/tatsushid/go-fastping"
)

// ControllerReachProber is the default reachability prober that uses ICMP
// ping to test next hop reachability and HTTP GET against the controller
// to evaluate remote reachability.
type ControllerReachProber struct {
	log           *base.LogObject
	agentName     string
	metrics       *zedcloud.AgentMetrics
	controllerURL *url.URL
}

// NewControllerReachProber is a constructor for ControllerReachProber.
func NewControllerReachProber(log *base.LogObject, agentName string,
	metrics *zedcloud.AgentMetrics) *ControllerReachProber {
	return &ControllerReachProber{
		log:       log,
		agentName: agentName,
		metrics:   metrics,
	}
}

// ProbeNextHopReach uses tatsushid/go-fastping package to efficiently
// execute ICMP ping against the uplink's next hop.
func (p *ControllerReachProber) ProbeNextHopReach(ctx context.Context,
	uplinkLL string, dns *types.DeviceNetworkStatus) (probedNHs []net.IP, err error) {
	// Determine timeout for the ping based on the context.
	var pingTimeout time.Duration
	const minPingTimeout = 50 * time.Millisecond // minimum accepted timeout
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		pingTimeout = deadline.Sub(time.Now())
		if pingTimeout < minPingTimeout {
			pingTimeout = minPingTimeout
		}
	}
	// Determine source and destination IP addresses for the ping.
	var dstAddr, srcAddr net.IPAddr
	ports := dns.GetPortsByLogicallabel(uplinkLL)
	if len(ports) == 0 {
		return nil, fmt.Errorf("missing status for uplink interface %s", uplinkLL)
	}
	if len(ports) > 1 {
		return nil, fmt.Errorf("multiple uplink interfaces match label %s", uplinkLL)
	}
	port := ports[0]
	nextHopIP := p.getPortNextHop(port)
	if nextHopIP == nil || nextHopIP.IsUnspecified() {
		return nil, fmt.Errorf("uplink %s has no suitable next hop IP address", uplinkLL)
	}
	dstAddr.IP = nextHopIP
	probedNHs = append(probedNHs, nextHopIP)
	localIP := p.getPortLocalIP(port)
	if localIP == nil || localIP.IsUnspecified() {
		return probedNHs, fmt.Errorf("uplink %s has no suitable local IP address", uplinkLL)
	}
	srcAddr.IP = localIP
	// Run ICMP ping against the uplink's next hop.
	var pingSuccess bool
	pinger := fastping.NewPinger()
	pinger.AddIPAddr(&dstAddr)
	_, err = pinger.Source(srcAddr.String())
	if err != nil {
		return probedNHs, err
	}
	if pingTimeout != 0 {
		pinger.MaxRTT = pingTimeout
	}
	pinger.OnRecv = func(ip *net.IPAddr, d time.Duration) {
		if ip != nil && ip.IP.Equal(dstAddr.IP) {
			pingSuccess = true
		}
	}
	err = pinger.Run()
	if err != nil {
		return probedNHs, err
	}
	if !pingSuccess {
		err = fmt.Errorf("no ping response received from %v", dstAddr)
		return probedNHs, err
	}
	return probedNHs, nil
}

// ProbeRemoteReach runs HTTP GET against the controller address to determine
// if remote networks are reachable.
func (p *ControllerReachProber) ProbeRemoteReach(ctx context.Context,
	uplinkLL string, dns *types.DeviceNetworkStatus) (probedEps []url.URL, err error) {
	const (
		allowProxy     = true
		useOnboard     = false
		withNetTracing = false
	)
	if p.controllerURL == nil {
		content, err := os.ReadFile(types.ServerFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %v",
				types.ServerFileName, err)
		}
		server := strings.TrimSpace(string(content))
		p.controllerURL, err = url.Parse("http://" + server)
		if err != nil {
			return nil, fmt.Errorf("failed to parse controller address %s: %v",
				server, err)
		}
	}
	probedEps = append(probedEps, *p.controllerURL)
	// No verification of AuthContainer or server TLS certificate in this reachability probe.
	zcloudCtx := zedcloud.NewContext(p.log, zedcloud.ContextOptions{
		TLSConfig:        &tls.Config{InsecureSkipVerify: true},
		AgentMetrics:     p.metrics,
		AgentName:        p.agentName,
		DevNetworkStatus: dns,
	})
	ports := dns.GetPortsByLogicallabel(uplinkLL)
	if len(ports) == 0 {
		return probedEps, fmt.Errorf("missing status for uplink interface %s", uplinkLL)
	}
	if len(ports) > 1 {
		return probedEps, fmt.Errorf("multiple uplink interfaces match label %s", uplinkLL)
	}
	port := ports[0]
	rv, err := zedcloud.SendOnIntf(
		ctx, &zcloudCtx, p.controllerURL.String(), port.IfName,
		0, nil, allowProxy, useOnboard, withNetTracing, false)
	if rv.HTTPResp != nil {
		// Any HTTP response received is good enough to claim the controller
		// as being reachable.
		return probedEps, nil
	}
	if err != nil {
		return probedEps, err
	}
	return probedEps, fmt.Errorf("no HTTP response received from %s",
		p.controllerURL.String())
}

func (p *ControllerReachProber) getPortLocalIP(port *types.NetworkPortStatus) net.IP {
	for _, addrInfo := range port.AddrInfoList {
		if port.Subnet.Contains(addrInfo.Addr) {
			return addrInfo.Addr
		}
	}
	return nil
}

// Pick the first default router with a valid IP address.
// XXX Later we could test all available default routers and evaluate next hop as reachable
// if any of them responds to ping.
// For now keeping the next hop probing behaviour as it was historically done in zedrouter.
func (p *ControllerReachProber) getPortNextHop(port *types.NetworkPortStatus) net.IP {
	for _, dr := range port.DefaultRouters {
		if !dr.IsUnspecified() {
			return dr
		}
	}
	return nil
}
