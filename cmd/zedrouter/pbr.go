// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Create ip rules and ip routing tables for each ifindex and also a free
// one for the collection of free uplinks.

package main

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"syscall"
)

var FreeTable = 500 // Need a FreeUplink policy for NAT+underlay

type addrChangeFnType func(ifname string)

var addrChangeFunc addrChangeFnType

// Returns the channels for route, addr, link updates
func PbrInit(uplinks []string, freeUplinks []string, addrChangeFn addrChangeFnType) (chan netlink.RouteUpdate,
	chan netlink.AddrUpdate, chan netlink.LinkUpdate) {
	fmt.Printf("PbrInit(%v, %v)\n", uplinks, freeUplinks)

	setUplinks(uplinks)
	setFreeUplinks(freeUplinks)
	addrChangeFunc = addrChangeFn

	IfindexToNameInit()
	IfindexToAddrsInit()

	flushRoutesTable(FreeTable, 0)

	// flush any old rules using RuleList
	flushRules(0)

	// Create rule for FreeTable; src NAT range
	// XXX for IPv6 underlay we also need rules.
	// Can we use iif match for all the bo* interfaces?
	// If so, use bu* matches for this rule
	freeRule := netlink.NewRule()
	_, prefix, err := net.ParseCIDR("172.27.0.0/16")
	if err != nil {
		log.Fatal(err)
	}
	freeRule.Src = prefix
	freeRule.Table = FreeTable
	freeRule.Family = syscall.AF_INET
	err = netlink.RuleAdd(freeRule)
	if err != nil {
		log.Fatal(err)
	}

	// Need links to get name to ifindex? Or lookup each time?
	linkchan := make(chan netlink.LinkUpdate)
	linkopt := netlink.LinkSubscribeOptions{List: true}
	if err := netlink.LinkSubscribeWithOptions(linkchan, nil,
		linkopt); err != nil {
		log.Fatal(err)
	}

	addrchan := make(chan netlink.AddrUpdate)
	addropt := netlink.AddrSubscribeOptions{List: true}
	if err := netlink.AddrSubscribeWithOptions(addrchan, nil,
		addropt); err != nil {
		log.Fatal(err)
	}
	routechan := make(chan netlink.RouteUpdate)
	rtopt := netlink.RouteSubscribeOptions{List: true}
	if err := netlink.RouteSubscribeWithOptions(routechan, nil,
		rtopt); err != nil {
		log.Fatal(err)
	}
	return routechan, addrchan, linkchan
}

// Handle a route change
func PbrRouteChange(change netlink.RouteUpdate) {
	rt := change.Route
	if rt.Table != syscall.RT_TABLE_MAIN {
		// Ignore since we will not add to other table
		return
	}
	// Add for all ifindices
	MyTable := FreeTable + rt.LinkIndex

	doFreeTable := false
	ifname, err := IfindexToName(rt.LinkIndex)
	if err != nil {
		// We'll check on ifname when we see a linkchange
		fmt.Printf("PbrRouteChange IfindexToName failed for %d: %s\n",
			rt.LinkIndex, err)
	} else if isFreeUplink(ifname) {
		fmt.Printf("Applying to FreeTable: %v\n", rt)
		doFreeTable = true
	}
	srt := rt
	srt.Table = FreeTable
	// Multiple IPv6 link-locals can't be added to the same
	// table unless the Priority differs. Different
	// LinkIndex, Src, Scope doesn't matter.
	if rt.Dst != nil && rt.Dst.IP.IsLinkLocalUnicast() {
		fmt.Printf("Forcing Priority to %v\n", rt.LinkIndex)
		// Hack to make the kernel routes not appear identical
		srt.Priority = rt.LinkIndex
	}

	// Add to ifindex specific table
	myrt := rt
	myrt.Table = MyTable
	// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
	if rt.Flags != 0 {
		srt.Flags = 0
		myrt.Flags = 0
	}
	if change.Type == syscall.RTM_DELROUTE {
		fmt.Printf("Received route del %v\n", rt)
		if doFreeTable {
			if err := netlink.RouteDel(&srt); err != nil {
				fmt.Printf("Failed to remove %v from %d: %s\n",
					srt, srt.Table, err)
			}
		}
		if err := netlink.RouteDel(&myrt); err != nil {
			fmt.Printf("Failed to remove %v from %d: %s\n",
				myrt, myrt.Table, err)
		}
	} else if change.Type == syscall.RTM_NEWROUTE {
		fmt.Printf("Received route add %v\n", rt)
		if doFreeTable {
			if err := netlink.RouteAdd(&srt); err != nil {
				fmt.Printf("Failed to add %v to %d: %s\n",
					srt, srt.Table, err)
			}
		}
		if err := netlink.RouteAdd(&myrt); err != nil {
			fmt.Printf("Failed to add %v to %d: %s\n",
				myrt, myrt.Table, err)
		}
	}
}

// Handle an IP address change
// XXX use to update global status
// XXX lisp should react to global status change to
// detect if different RLOCs on uplinks
func PbrAddrChange(change netlink.AddrUpdate) {
	if change.NewAddr {
		added := IfindexToAddrsAdd(change.LinkIndex, change.LinkAddress)
		if added {
			addSourceRule(change.LinkIndex, change.LinkAddress)
		}
	} else {
		removed := IfindexToAddrsDel(change.LinkIndex,
			change.LinkAddress)
		if removed {
			delSourceRule(change.LinkIndex, change.LinkAddress)
		}
	}
	ifname, err := IfindexToName(change.LinkIndex)
	if err != nil {
		// XXX when? Need callback when uplink addresses change
		// also called in PbrLinkChange
		fmt.Printf("PbrAddrChange IfindexToName failed for %d: %s\n",
			change.LinkIndex, err)
	} else if isUplink(ifname) {
		fmt.Printf("Address change for uplink: %v\n", change)
		addrChangeFunc(ifname)
		// XXX also call from PbrLinkChange for uplink/freeuplink
	}
}

// Handle a link being added or deleted
func PbrLinkChange(change netlink.LinkUpdate) {
	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		new := IfindexToNameAdd(ifindex, ifname)
		if new {
			// XXX any ordering issues?
			// Could we flush things we just added?
			flushRoutesTable(FreeTable, ifindex)
			MyTable := FreeTable + ifindex
			flushRoutesTable(MyTable, 0)
			flushRules(ifindex)

			if isFreeUplink(ifname) {
				fmt.Printf("PbrLinkChange moving to FreeTable %s\n",
					ifname)
				moveRoutesTable(0, ifindex, FreeTable)
			}
			if isUplink(ifname) {
				fmt.Printf("Link change for uplink: %\n", ifname)
				addrChangeFunc(ifname)
			}
		}
	case syscall.RTM_DELLINK:
		gone := IfindexToNameDel(ifindex, ifname)
		if gone {
			if isFreeUplink(ifname) {
				flushRoutesTable(FreeTable, ifindex)
			}
			MyTable := FreeTable + ifindex
			flushRoutesTable(MyTable, 0)
			flushRules(ifindex)
			if isUplink(ifname) {
				fmt.Printf("Link change for uplink: %\n", ifname)
				addrChangeFunc(ifname)
			}
		}
	case syscall.RTM_SETLINK:
		fmt.Printf("Link set index %d name %s\n",
			change.Attrs().Index,
			change.Attrs().Name)
	}
}

var uplinkList []string     // All uplinks
var freeUplinkList []string // The subset we add to FreeTable

// Can be called to update the list. However, need to detect the changes
// and move when updating XXX
func setFreeUplinks(freeUplinks []string) {
	freeUplinkList = freeUplinks
}

func isFreeUplink(ifname string) bool {
	for _, fu := range freeUplinkList {
		if fu == ifname {
			return true
		}
	}
	return false
}

// Can be called to update the list. However, need to detect the changes
// and move when updating XXX
func setUplinks(uplinks []string) {
	uplinkList = uplinks
}

func isUplink(ifname string) bool {
	for _, u := range uplinkList {
		if u == ifname {
			return true
		}
	}
	return false
}

// ===== map from ifindex to ifname

var ifindexToName map[int]string

func IfindexToNameInit() {
	ifindexToName = make(map[int]string)
}

// Returns true if new
func IfindexToNameAdd(index int, name string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		// Note that we get RTM_NEWLINK even for link changes
		fmt.Printf("Link add index %d name %s\n", index, name)
		ifindexToName[index] = name
		// fmt.Printf("ifindexToName post add %v\n", ifindexToName)
		return true
	} else if m != name {
		fmt.Printf("IfindexToNameAdd name mismatch %s vs %s for %d\n",
			m, name, index)
		ifindexToName[index] = name
		// fmt.Printf("ifindexToName post add %v\n", ifindexToName)
		return false // Rename
	} else {
		return false
	}
}

// Returns true if deleted
func IfindexToNameDel(index int, name string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		fmt.Printf("IfindexToNameDel unknown index %d\n", index)
		return false
	} else if m != name {
		fmt.Printf("IfindexToNameDel name mismatch %s vs %s for %d\n",
			m, name, index)
		delete(ifindexToName, index)
		// fmt.Printf("ifindexToName post delete %v\n", ifindexToName)
		return true
	} else {
		fmt.Printf("Link del index %d name %s\n", index, name)
		delete(ifindexToName, index)
		// fmt.Printf("ifindexToName post delete %v\n", ifindexToName)
		return true
	}
}

func IfindexToName(index int) (string, error) {
	n, ok := ifindexToName[index]
	if !ok {
		return "", errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	return n, nil
}

// ===== map from ifindex to list of IP addresses

var ifindexToAddrs map[int][]net.IPNet

func IfindexToAddrsInit() {
	ifindexToAddrs = make(map[int][]net.IPNet)
}

// Returns true if added
func IfindexToAddrsAdd(index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		fmt.Printf("Link add index %d addr %s\n", index, addr)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// fmt.Printf("ifindexToAddrs post add %v\n", ifindexToAddrs)
		return true
	}
	found := false
	for _, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			found = true
			break
		}
	}
	if !found {
		fmt.Printf("IfindexToAddrsAdd add %v for %d\n",
			addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// fmt.Printf("ifindexToAddrs post add %v\n", ifindexToAddrs)
	}
	return !found
}

// Returns true if deleted
func IfindexToAddrsDel(index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		fmt.Printf("IfindexToAddrsDel unknown index %d\n", index)
		// XXX error?
		return false
	}
	for i, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			fmt.Printf("IfindexToAddrsDel del %v for %d\n",
				addr, index)
			ifindexToAddrs[index] = append(ifindexToAddrs[index][:i],
				ifindexToAddrs[index][i+1:]...)
			// fmt.Printf("ifindexToAddrs post remove %v\n", ifindexToAddrs)
			// XXX should we check for zero and remove ifindex?
			return true
		}
	}
	fmt.Printf("IfindexToAddrsDel address not found for %d in\n",
		index, addrs)
	return false
}

func IfindexToAddrs(index int) ([]net.IPNet, error) {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	return addrs, nil
}

// =====

// If ifindex is non-zero we also compare it
func flushRoutesTable(table int, ifindex int) {
	filter := netlink.Route{Table: table, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	if ifindex != 0 {
		fflags |= netlink.RT_FILTER_OIF
	}
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Fatal("RouteList failed: %v\n", err)
	}
	fmt.Printf("flushRoutesTable(%d, %d) - got %d\n", table, ifindex,
		len(routes))
	for _, rt := range routes {
		fmt.Printf("flushRoutesTable: table %d index %d\n",
			rt.Table, rt.LinkIndex)
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		fmt.Printf("flushRoutesTable(%d, %d) deleting %v\n",
			table, ifindex, rt)
		if err := netlink.RouteDel(&rt); err != nil {
			log.Fatal("flushRoutesTable - RouteDel %v failed %s\n",
				rt, err)
		}
	}
}

// Used when FreeUplinks get a link added
// If ifindex is non-zero we also compare it
func moveRoutesTable(srcTable int, ifindex int, dstTable int) {
	if srcTable == 0 {
		srcTable = syscall.RT_TABLE_MAIN
	}
	filter := netlink.Route{Table: srcTable, LinkIndex: ifindex}
	fflags := netlink.RT_FILTER_TABLE
	if ifindex != 0 {
		fflags |= netlink.RT_FILTER_OIF
	}
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Fatal("RouteList failed: %v\n", err)
	}
	fmt.Printf("moveRoutesTable(%d, %d, %d) - got %d\n", srcTable, ifindex,
		dstTable, len(routes))
	for _, rt := range routes {
		fmt.Printf("moveRoutesTable: table %d index %d\n",
			rt.Table, rt.LinkIndex)
		if rt.Table != srcTable {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		art := rt
		art.Table = dstTable
		// Multiple IPv6 link-locals can't be added to the same
		// table unless the Priority differs. Different
		// LinkIndex, Src, Scope doesn't matter.
		if rt.Dst != nil && rt.Dst.IP.IsLinkLocalUnicast() {
			fmt.Printf("Forcing Priority to %v\n",
				rt.LinkIndex)
			// Hack to make the kernel routes not appear identical
			art.Priority = rt.LinkIndex
		}
		// Clear any RTNH_F_LINKDOWN etc flags since add doesn't
		// like them
		if rt.Flags != 0 {
			fmt.Printf("flags %v\n", rt.Flags)
			art.Flags = 0
		}
		fmt.Printf("moveRoutesTable(%d, %d, %d) adding %v\n",
			srcTable, ifindex, dstTable, art)
		if err := netlink.RouteAdd(&art); err != nil {
			log.Printf("moveRoutesTable failed to add %v to %d: %s\n",
				art, art.Table, err)
		}
	}
}

// ==== manage the ip rules

// Flush the rules we create. If ifindex is non-zero we also compare it
func flushRules(ifindex int) {
	rules, err := netlink.RuleList(syscall.AF_UNSPEC)
	if err != nil {
		log.Fatal("RuleList failed: %v\n", err)
	}
	fmt.Printf("flushRules(%d) - got %d\n", ifindex, len(rules))
	for _, r := range rules {
		if ifindex == 0 && r.Table != FreeTable {
			continue
		}
		if ifindex != 0 && r.Table != FreeTable+ifindex {
			continue
		}
		fmt.Printf("flushRules(%d): table %d src %v\n",
			ifindex, r.Table, r.Src)
		if err := netlink.RuleDel(&r); err != nil {
			log.Fatal("flushRules - RuleDel %v failed %s\n",
				r, err)
		}
	}
}

var (
	v4HostMask = net.CIDRMask(32, 32)
	v6HostMask = net.CIDRMask(128, 128)
)

func addSourceRule(ifindex int, p net.IPNet) {
	r := netlink.NewRule()
	r.Table = FreeTable + ifindex
	// Add rule for /32 or /128
	if p.IP.To4() != nil {
		r.Family = syscall.AF_INET
		r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(32, 32)}
	} else {
		r.Family = syscall.AF_INET6
		r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(128, 128)}
	}
	fmt.Printf("addSourceRule: RuleAdd %v\n", r)
	if err := netlink.RuleAdd(r); err != nil {
		fmt.Printf("RuleAdd %v failed with %s\n", r, err)
		return
	}
}

func delSourceRule(ifindex int, p net.IPNet) {
	r := netlink.NewRule()
	r.Table = FreeTable + ifindex
	// Add rule for /32 or /128
	if p.IP.To4() != nil {
		r.Family = syscall.AF_INET
		r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(32, 32)}
	} else {
		r.Family = syscall.AF_INET6
		r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(128, 128)}
	}
	fmt.Printf("delSourceRule: RuleDel %v\n", r)
	if err := netlink.RuleDel(r); err != nil {
		fmt.Printf("RuleDel %v failed with %s\n", r, err)
		return
	}
}
