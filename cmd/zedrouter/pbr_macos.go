// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// macos version of pbr.go
//	Stub file, to allow compilation of go-provision to go thru.
// We don't need the actual functionality to work
// +build darwin

package zedrouter

import (
	"net"

	"github.com/eriknordmark/netlink"
	"github.com/zededa/go-provision/types"
)

type addrChangeFnType func(ifname string)

var FreeTable = 500 // Need a FreeMgmtPort policy for NAT+underlay

// Returns the channels for route, addr, link updates
func PbrInit(ctx *zedrouterContext, addrChange addrChangeFnType,
	addrChangeNon addrChangeFnType) (chan netlink.RouteUpdate,
	chan netlink.AddrUpdate, chan netlink.LinkUpdate) {

	routechan := make(chan netlink.RouteUpdate)
	linkchan := make(chan netlink.LinkUpdate)
	addrchan := make(chan netlink.AddrUpdate)

	return routechan, addrchan, linkchan
}

// Add a default route for the bridgeName table to the specific port
func PbrRouteAddDefault(bridgeName string, port string) error {
	return nil
}

// Delete the default route for the bridgeName table to the specific port
func PbrRouteDeleteDefault(bridgeName string, port string) error {
	return nil
}

// XXX The PbrNAT functions are no-ops for now.
// The prefix for the NAT linux bridge interface is in its own pbr table
// XXX put the default route(s) for the selected Adapter for the service
// into the table for the bridge to avoid using other ports.
func PbrNATAdd(prefix string) error {
	return nil
}

// XXX The PbrNAT functions are no-ops for now.
func PbrNATDel(prefix string) error {
	return nil
}

// Handle a route change
func PbrRouteChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.RouteUpdate) {
}

// Handle an IP address change
func PbrAddrChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.AddrUpdate) {
}

// Handle a link being added or deleted
func PbrLinkChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.LinkUpdate) {
}

func setFreeMgmtPorts(freeMgmtPorts []string) {
}

// ===== map from ifindex to ifname

func IfindexToNameInit() {
}

// Returns true if added
func IfindexToNameAdd(index int, linkName string, linkType string) bool {
	return true
}

// Returns true if deleted
func IfindexToNameDel(index int, linkName string) bool {
	return true
}

// Returns linkName, linkType
func IfindexToName(index int) (string, string, error) {
	return "", "", nil
}

func IfnameToIndex(ifname string) (int, error) {
	return 0, nil
}

// ===== map from ifindex to list of IP addresses

func IfindexToAddrsInit() {
}

// Returns true if added
func IfindexToAddrsAdd(index int, addr net.IPNet) bool {
	return true
}

// Returns true if deleted
func IfindexToAddrsDel(index int, addr net.IPNet) bool {
	return true
}

func IfindexToAddrs(index int) ([]net.IPNet, error) {
	var addrs []net.IPNet
	return addrs, nil
}

// ==== manage the ip rules

// Flush the rules we create. If ifindex is non-zero we also compare it
// Otherwise we flush the FreeTable
func flushRules(ifindex int) {
}

func AddOverlayRuleAndRoute(bridgeName string, iifIndex int,
	oifIndex int, ipnet *net.IPNet) error {
	return nil
}
