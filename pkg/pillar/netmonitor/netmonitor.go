// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package netmonitor

import (
	"context"
	"net"
)

// NetworkMonitor should allow to:
// - list (and possibly cache) network interfaces
// - obtain (and possibly cache) interface index
// - obtain (and possibly cache) interface attributes, addresses, DNS info, etc.
// - allow to watch for interface/address/route changes
// There should be one implementation for every supported network stack.
// NetworkMonitor should be thread-safe.
type NetworkMonitor interface {
	// ListInterfaces returns all available network interfaces.
	ListInterfaces() (ifNames []string, err error)
	// GetInterfaceIndex : get interface index. Both name and index are unique
	// interface identifiers, but while name is usually used in user-facing
	// contexts, index is preferred in APIs (may vary between different network stacks).
	// At least within NetworkMonitor, index is the preferred identifier and can be used
	// with the methods below to obtain interface attributes, assigned addresses, etc.
	// Do not keep the index for too long however, the mapping between the name and
	// the index may change as interfaces are added/deleted.
	GetInterfaceIndex(ifName string) (ifIndex int, exists bool, err error)
	// GetInterfaceAttrs : get interface attributes (not including assigned addresses).
	GetInterfaceAttrs(ifIndex int) (IfAttrs, error)
	// GetInterfaceAddrs : get MAC address and a list of IP addresses assigned
	// to the given interface.
	GetInterfaceAddrs(ifIndex int) ([]*net.IPNet, net.HardwareAddr, error)
	// GetInterfaceDNSInfo : get DNS information associated with the given interface.
	GetInterfaceDNSInfo(ifIndex int) (DNSInfo, error)
	// GetInterfaceDHCPInfo : get DHCP information associated with the given interface.
	// This information should be retrieved from the DHCP client.
	GetInterfaceDHCPInfo(ifIndex int) (DHCPInfo, error)
	// GetInterfaceDefaultGWs : return a list of IP addresses of default gateways
	// used by the given interface. Includes both statically configured GWs as well as
	// those assigned by DHCP.
	GetInterfaceDefaultGWs(ifIndex int) ([]net.IP, error)
	// ListRoutes returns routes currently present in the routing tables.
	// The set of routes to list can be filtered.
	ListRoutes(filters RouteFilters) ([]Route, error)
	// ClearCache : clear cached mappings between interface names, interface indexes,
	// attributes, assigned addresses, DNS info, DHCP info and default GWs.
	// It is reasonable to do this once in a while because the monitor can miss some
	// notification from the network stack and therefore the cache can get out-of-date
	// over time.
	ClearCache()
	// WatchEvents : subscribe to watch for changes happening inside the network stack
	// related to interfaces, routes, DNS, etc.
	// The returned channel should be reasonably buffered.
	WatchEvents(ctx context.Context, subName string) <-chan Event
}

// Event received from the network stack.
type Event interface {
	isNetworkEvent()
}

// Route : IP route.
type Route struct {
	IfIndex int
	Dst     *net.IPNet
	Gw      net.IP
	Table   int
	// Network-stack specific data.
	Data interface{}
}

// IsDefaultRoute returns true if this is a default route, i.e. matches all destinations.
func (r Route) IsDefaultRoute() bool {
	if r.Dst == nil {
		return true
	}
	ones, _ := r.Dst.Mask.Size()
	return r.Dst.IP.IsUnspecified() && ones == 0
}

// RouteChange : a route was added or removed.
type RouteChange struct {
	Route
	Added   bool
	Deleted bool
}

// RouteFilters : used by ListRoutes() to limit the set of routes to list.
type RouteFilters struct {
	// Enable to retrieve routes only from the given table.
	FilterByTable bool
	Table         int

	// Enable to retrieve only those routes which are associated
	// with the given interface.
	FilterByIf bool
	IfIndex    int
}

func (e RouteChange) isNetworkEvent() {}

// AddrChange : IP address was (un)assigned from/to interface.
type AddrChange struct {
	IfIndex   int
	IfAddress *net.IPNet
	Deleted   bool
}

func (e AddrChange) isNetworkEvent() {}

// IfChange : interface (dis)appeared or attributes changed.
type IfChange struct {
	Attrs IfAttrs
	// True if this is a newly added interface.
	Added bool
	// True if interface was removed.
	Deleted bool
}

func (e IfChange) isNetworkEvent() {}

// Equal allows to compare two IfChange events for equality.
func (e IfChange) Equal(e2 IfChange) bool {
	return e.Added == e2.Added &&
		e.Deleted == e2.Deleted &&
		e.Attrs.Equal(e2.Attrs)
}

// DNSInfoChange : DNS information for interface has changed.
type DNSInfoChange struct {
	IfIndex int
	Info    DNSInfo
}

func (e DNSInfoChange) isNetworkEvent() {}

// IfAttrs : interface attributes.
type IfAttrs struct {
	// Index of the interface
	IfIndex int
	// Name of the interface.
	IfName string
	// IfType should be one of the link types as defined in ip-link(8).
	IfType string
	// True if interface is a loopback interface.
	IsLoopback bool
	// True if interface supports broadcast access capability.
	WithBroadcast bool
	// True if interface is administratively enabled.
	AdminUp bool
	// True if interface is ready to transmit data at the L1 layer.
	LowerUp bool
	// True if interface is a slave of another interface (e.g. a sub-interface).
	Enslaved bool
	// If interface is enslaved, this should contain index of the master interface.
	MasterIfIndex int
	// Maximum Transmission Unit configured on the interface.
	MTU uint16
}

// Equal allows to compare two sets of interface attributes for equality.
func (a IfAttrs) Equal(a2 IfAttrs) bool {
	return a.IfIndex == a2.IfIndex &&
		a.IfName == a2.IfName &&
		a.IfType == a2.IfType &&
		a.IsLoopback == a2.IsLoopback &&
		a.WithBroadcast == a2.WithBroadcast &&
		a.AdminUp == a2.AdminUp &&
		a.LowerUp == a2.LowerUp &&
		a.Enslaved == a2.Enslaved &&
		a.MasterIfIndex == a2.MasterIfIndex &&
		a.MTU == a2.MTU
}

// DNSInfo : DNS information associated with an interface.
type DNSInfo struct {
	ResolvConfPath string
	Domains        []string
	DNSServers     []net.IP
}

// DHCPInfo : DHCP information associated with an interface.
type DHCPInfo struct {
	Subnet     *net.IPNet
	NtpServers []net.IP
}
