// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package portprober

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/tatsushid/go-fastping"
)

// HostnameAddr is an implementation of net.Addr that can be used to store hostname
// and optionally also port.
// Other implementations provided by Golang can only store already resolved IP address.
type HostnameAddr struct {
	Hostname string
	Port     uint16
}

// Network returns the address's network type.
func (h *HostnameAddr) Network() string {
	if h.Port == 0 {
		return "ip"
	}
	// We do not provide UDP-based probing method for now.
	return "tcp"
}

// String returns the address in the form "hostname:port".
func (h *HostnameAddr) String() string {
	if h.Port == 0 {
		return h.Hostname
	}
	return fmt.Sprintf("%s:%d", h.Hostname, h.Port)
}

// LinuxReachabilityProberICMP is an implementation of ReachabilityProber
// for the ICMP-based probing method and the Linux TCP/IP network stack.
type LinuxReachabilityProberICMP struct{}

// Probe reachability of <dstAddr> using ICMP ping sent via the given port.
func (p *LinuxReachabilityProberICMP) Probe(ctx context.Context, portIfName string,
	srcIP net.IP, dstAddr net.Addr, dnsServers []net.IP) error {
	// Do not use DNS servers other than those that belong to the probed
	// network port.
	customResolver := &dnsResolver{
		dnsServers: dnsServers,
		srcIP:      srcIP,
		ifName:     portIfName,
	}
	resolver := customResolver.getNetResolver()
	var dstIPs []*net.IPAddr
	switch addr := dstAddr.(type) {
	case *net.IPAddr:
		// Resolver is not needed, dstAddr is already an IP address.
		dstIPs = append(dstIPs, addr)
	case *HostnameAddr:
		// Try to resolve destination hostname.
		ips, err := resolver.LookupIP(ctx, "ip", addr.Hostname)
		if err != nil {
			return fmt.Errorf("failed to resolve %s: %w", dstAddr, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("resolver returned no IPs for %s", dstAddr)
		}
		for _, ip := range ips {
			dstIPs = append(dstIPs, &net.IPAddr{IP: ip})
		}
	default:
		return fmt.Errorf("unexpected dstAddr type for ICMP probe: %T", dstAddr)
	}
	for i, dstIP := range dstIPs {
		// Determine timeout for the ping based on the context.
		var pingTimeout time.Duration
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			pingTimeout = deadline.Sub(time.Now())
			if pingTimeout <= 0 {
				return fmt.Errorf("ping timeout expired")
			}
			// Leave some time to try remaining IPs.
			pingTimeout = pingTimeout / time.Duration(len(dstIPs)-i)
		}
		var pingSuccess bool
		pinger := fastping.NewPinger()
		pinger.AddIPAddr(dstIP)
		_, err := pinger.Source(srcIP.String())
		if err != nil {
			// Should be unreachable, source IP is valid.
			return err
		}
		if pingTimeout != 0 {
			pinger.MaxRTT = pingTimeout
		}
		pinger.OnRecv = func(ip *net.IPAddr, d time.Duration) {
			if ip != nil && ip.IP.Equal(dstIP.IP) {
				pingSuccess = true
			}
		}
		err = pinger.Run()
		if err != nil {
			// Check remaining time and try the next IP.
			continue
		}
		if pingSuccess {
			return nil
		}
	}
	return fmt.Errorf("no ping response received from %v", dstAddr)
}

// LinuxReachabilityProberTCP is an implementation of ReachabilityProber
// for the TCP-based probing method and the Linux TCP/IP network stack.
type LinuxReachabilityProberTCP struct{}

// Probe reachability of <dstAddr> using TCP handshake initiated via the given port.
func (p *LinuxReachabilityProberTCP) Probe(ctx context.Context, portIfName string,
	srcIP net.IP, dstAddr net.Addr, dnsServers []net.IP) error {
	// Do not use DNS servers other than those that belong to the probed
	// network port.
	customResolver := &dnsResolver{
		dnsServers: dnsServers,
		srcIP:      srcIP,
		ifName:     portIfName,
	}
	resolver := customResolver.getNetResolver()
	switch dstAddr.(type) {
	case *net.TCPAddr:
		// Resolver is not needed, dstAddr is already an IP address.
		resolver = nil
	case *HostnameAddr:
		// Continue...
	default:
		return fmt.Errorf("unexpected dstAddr type for TCP probe: %T", dstAddr)
	}
	tcpDialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: srcIP},
		Resolver:  resolver,
	}
	conn, err := tcpDialer.DialContext(ctx, "tcp", dstAddr.String())
	if err != nil {
		return fmt.Errorf("TCP connect request to %v failed: %w", dstAddr, err)
	}
	// TCP handshake succeeded.
	_ = conn.Close()
	return nil
}

// dnsResolver makes sure that only defined <dnsServers> are tried to resolve
// the given hostname.
type dnsResolver struct {
	srcIP      net.IP
	dnsServers []net.IP
	ifName     string
}

func (r *dnsResolver) getNetResolver() *net.Resolver {
	return &net.Resolver{Dial: r.resolverDial, PreferGo: true, StrictErrors: false}
}

func (r *dnsResolver) resolverDial(
	ctx context.Context, network, address string) (net.Conn, error) {
	dnsHost, _, err := net.SplitHostPort(address)
	if err != nil {
		// No port in the address.
		dnsHost = address
	}
	dnsIP := net.ParseIP(dnsHost)
	if dnsIP == nil {
		return nil, fmt.Errorf("failed to parse DNS server IP address '%s'", dnsHost)
	}
	if dnsIP.IsLoopback() {
		// 127.0.0.1:53 is tried by Golang resolver when resolv.conf does not contain
		// any nameservers (see defaultNS in net/dnsconfig_unix.go).
		// There is no point in looking for DNS server on the loopback interface on EVE.
		return nil, &types.DNSNotAvailError{IfName: r.ifName}
	}
	var acceptedServer bool
	for _, dnsServer := range r.dnsServers {
		if netutils.EqualIPs(dnsServer, dnsIP) {
			acceptedServer = true
			break
		}
	}
	if !acceptedServer {
		return nil, fmt.Errorf("DNS server %s is not valid for port %s", dnsIP, r.ifName)
	}
	switch network {
	case "udp", "udp4", "udp6":
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: r.srcIP}}
		return d.DialContext(ctx, network, address)
	case "tcp", "tcp4", "tcp6":
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: r.srcIP}}
		return d.DialContext(ctx, network, address)
	default:
		return nil, fmt.Errorf("unsupported address type: %v", network)
	}
}
