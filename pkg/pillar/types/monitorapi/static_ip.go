// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package monitorapi defines the stable, wire-facing contract types exchanged
// between EVE (Go) and the monitor TUI (Rust) over the local IPC socket.
//
// These types are intentionally decoupled from the rest of pkg/pillar/types:
//   - scalars use net/netip so JSON encoding is canonical and strictly
//     parseable on both ends (no legacy net.IP marshalling quirks);
//   - the shape is designed for what the TUI shows/edits, not EVE internals;
//   - all translation from legacy representations happens in From* mappers,
//     which are the single place that touches the messy internal types.
//
// The Rust side of this contract is generated from these types; see
// internal/gen. Do not change the wire shape without regenerating.
package monitorapi

import (
	"fmt"
	"net"
	"net/netip"
)

// StaticIPConfig is the contract type for a manually configured (static) IP on
// a network port. It is the slice of the contract that the TUI both displays
// and edits, then sends back to EVE to apply — so it must round-trip losslessly
// and validate identically on both sides.
type StaticIPConfig struct {
	// IP is the host address assigned to the port, e.g. "192.0.2.10".
	IP netip.Addr `json:"ip"`
	// Subnet is the (masked) network the address belongs to, e.g. "192.0.2.0/24".
	Subnet netip.Prefix `json:"subnet"`
	// Gateway is the default router for this port; optional.
	Gateway *netip.Addr `json:"gateway,omitempty"`
	// DNSServers configured for this port; optional.
	DNSServers []netip.Addr `json:"dnsServers,omitempty"`
}

// Validate enforces the semantic invariants the TUI relies on. The same checks
// run on the Rust side before sending and here on the Go side before applying
// (defense in depth — neither end trusts the wire blindly).
func (c StaticIPConfig) Validate() error {
	if !c.IP.IsValid() {
		return fmt.Errorf("ip address is not set")
	}
	if !c.Subnet.IsValid() {
		return fmt.Errorf("subnet is not set")
	}
	if !c.Subnet.Contains(c.IP) {
		return fmt.Errorf("ip %s is not within subnet %s", c.IP, c.Subnet)
	}
	if c.Gateway != nil && !c.Subnet.Contains(*c.Gateway) {
		return fmt.Errorf("gateway %s is not within subnet %s", *c.Gateway, c.Subnet)
	}
	return nil
}

// FromLegacy builds a StaticIPConfig from the stdlib net types that pervade
// pkg/pillar/types (net.IP, *net.IPNet). It is the single place legacy
// representations are translated into the contract.
//
// TODO(monitorapi): replace with a mapper that consumes the real
// types.NetworkPortStatus once message migration begins.
func FromLegacy(ip net.IP, subnet *net.IPNet, gw net.IP, dns []net.IP) (StaticIPConfig, error) {
	addr, ok := addrFromIP(ip)
	if !ok {
		return StaticIPConfig{}, fmt.Errorf("invalid ip %v", ip)
	}
	prefix, err := prefixFromIPNet(subnet)
	if err != nil {
		return StaticIPConfig{}, err
	}
	cfg := StaticIPConfig{IP: addr, Subnet: prefix}
	if len(gw) > 0 {
		gwAddr, ok := addrFromIP(gw)
		if !ok {
			return StaticIPConfig{}, fmt.Errorf("invalid gateway %v", gw)
		}
		cfg.Gateway = &gwAddr
	}
	for _, d := range dns {
		dAddr, ok := addrFromIP(d)
		if !ok {
			return StaticIPConfig{}, fmt.Errorf("invalid dns server %v", d)
		}
		cfg.DNSServers = append(cfg.DNSServers, dAddr)
	}
	return cfg, nil
}

// addrFromIP converts a legacy net.IP to netip.Addr, normalizing IPv4-in-IPv6.
func addrFromIP(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFromSlice(v4)
	}
	return netip.AddrFromSlice(ip)
}

// prefixFromIPNet converts a legacy *net.IPNet to a canonical, masked netip.Prefix.
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, error) {
	if n == nil {
		return netip.Prefix{}, fmt.Errorf("subnet is nil")
	}
	addr, ok := addrFromIP(n.IP)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid subnet address %v", n.IP)
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr, ones).Masked(), nil
}
