// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Create ip rules and ip routing tables for each ifindex and also a free
// one for the collection of free uplinks.

package zedrouter

import (
	"errors"
	"fmt"
	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"net"
	"syscall"
)

var FreeTable = 500 // Need a FreeUplink policy for NAT+underlay

type addrChangeFnType func(ifname string)

// XXX should really be in a context returned by Init
var addrChangeFuncUplink addrChangeFnType
var addrChangeFuncNonUplink addrChangeFnType

// Returns the channels for route, addr, link updates
func PbrInit(ctx *zedrouterContext, addrChange addrChangeFnType,
	addrChangeNon addrChangeFnType) (chan netlink.RouteUpdate,
	chan netlink.AddrUpdate, chan netlink.LinkUpdate) {

	log.Debugf("PbrInit()\n")
	setFreeUplinks(types.GetUplinksFree(*ctx.deviceNetworkStatus, 0))
	addrChangeFuncUplink = addrChange
	addrChangeFuncNonUplink = addrChangeNon

	IfindexToNameInit()
	IfindexToAddrsInit()

	flushRoutesTable(FreeTable, 0)

	// flush any old rules using RuleList
	flushRules(0)

	// Need links to get name to ifindex? Or lookup each time?
	linkchan := make(chan netlink.LinkUpdate)
	linkErrFunc := func(err error) {
		log.Errorf("LinkSubscribe failed %s\n", err)
	}
	linkopt := netlink.LinkSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: linkErrFunc,
	}
	if err := netlink.LinkSubscribeWithOptions(linkchan, nil,
		linkopt); err != nil {
		log.Fatal(err)
	}

	addrchan := make(chan netlink.AddrUpdate)
	addrErrFunc := func(err error) {
		log.Errorf("AddrSubscribe failed %s\n", err)
	}
	addropt := netlink.AddrSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: addrErrFunc,
	}
	if err := netlink.AddrSubscribeWithOptions(addrchan, nil,
		addropt); err != nil {
		log.Fatal(err)
	}
	routechan := make(chan netlink.RouteUpdate)
	routeErrFunc := func(err error) {
		log.Errorf("RouteSubscribe failed %s\n", err)
	}
	rtopt := netlink.RouteSubscribeOptions{
		ListExisting:  true,
		ErrorCallback: routeErrFunc,
	}
	if err := netlink.RouteSubscribeWithOptions(routechan, nil,
		rtopt); err != nil {
		log.Fatal(err)
	}
	return routechan, addrchan, linkchan
}

// Add a default route for the bridgeName table to the specific uplink
func PbrRouteAddDefault(bridgeName string, uplink string) error {
	log.Infof("PbrRouteAddDefault(%s, %s)\n", bridgeName, uplink)

	ifindex, err := IfnameToIndex(uplink)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			uplink, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	rt := getDefaultIPv4Route(ifindex)
	if rt == nil {
		log.Warnf("PbrRouteAddDefault(%s, %s) no default route\n",
			bridgeName, uplink)
		return nil
	}
	// Add to ifindex specific table
	ifindex, err = IfnameToIndex(bridgeName)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			bridgeName, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	MyTable := FreeTable + ifindex
	myrt := *rt
	myrt.Table = MyTable
	// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
	if rt.Flags != 0 {
		myrt.Flags = 0
	}
	log.Infof("PbrRouteAddDefault(%s, %s) adding %v\n",
		bridgeName, uplink, myrt)
	if err := netlink.RouteAdd(&myrt); err != nil {
		errStr := fmt.Sprintf("Failed to add %v to %d: %s",
			myrt, myrt.Table, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	return nil
}

// Delete the default route for the bridgeName table to the specific uplink
func PbrRouteDeleteDefault(bridgeName string, uplink string) error {
	log.Infof("PbrRouteAddDefault(%s, %s)\n", bridgeName, uplink)

	ifindex, err := IfnameToIndex(uplink)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			uplink, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	rt := getDefaultIPv4Route(ifindex)
	if rt == nil {
		log.Warnf("PbrRouteDeleteDefault(%s, %s) no default route\n",
			bridgeName, uplink)
		return nil
	}
	// Remove from ifindex specific table
	ifindex, err = IfnameToIndex(bridgeName)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			bridgeName, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	MyTable := FreeTable + ifindex
	myrt := *rt
	myrt.Table = MyTable
	// Clear any RTNH_F_LINKDOWN etc flags since del might not like them
	if rt.Flags != 0 {
		myrt.Flags = 0
	}
	log.Infof("PbrRouteDeleteDefault(%s, %s) deleting %v\n",
		bridgeName, uplink, myrt)
	if err := netlink.RouteDel(&myrt); err != nil {
		errStr := fmt.Sprintf("Failed to delete %v from %d: %s",
			myrt, myrt.Table, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	return nil
}

// Return the first default route for one interface. XXX or return all?
func getDefaultIPv4Route(ifindex int) *netlink.Route {
	table := syscall.RT_TABLE_MAIN
	// Default route is nil Dst.
	filter := netlink.Route{Table: table, LinkIndex: ifindex, Dst: nil}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	fflags |= netlink.RT_FILTER_DST
	log.Infof("getDefaultIPv4Route(%d) filter %v\n", ifindex, filter)
	routes, err := netlink.RouteListFiltered(syscall.AF_INET,
		&filter, fflags)
	if err != nil {
		log.Fatal("RouteList failed: %v\n", err)
	}
	log.Debugf("getDefaultIPv4Route(%d) - got %d matches\n",
		ifindex, len(routes))
	for _, rt := range routes {
		if rt.LinkIndex != ifindex {
			continue
		}
		log.Debugf("getDefaultIPv4Route(%d) returning %v\n",
			ifindex, rt)
		return &rt
	}
	return nil
}

// XXX The PbrNAT functions are no-ops for now.
// The prefix for the NAT linux bridge interface is in its own pbr table
// XXX put the default route(s) for the selected Adapter for the service
// into the table for the bridge to avoid using other uplinks.
func PbrNATAdd(prefix string) error {

	log.Debugf("PbrNATAdd(%s)\n", prefix)
	return nil

	freeRule, err := pbrGetFreeRule(prefix)
	if err != nil {
		return err
	}
	// Avoid duplicate rules
	_ = netlink.RuleDel(freeRule)
	err = netlink.RuleAdd(freeRule)
	if err != nil {
		return err
	}
	return nil
}

// XXX The PbrNAT functions are no-ops for now.
func PbrNATDel(prefix string) error {

	log.Debugf("PbrNATDel(%s)\n", prefix)
	return nil

	freeRule, err := pbrGetFreeRule(prefix)
	if err != nil {
		return err
	}
	// Avoid duplicate rules
	err = netlink.RuleDel(freeRule)
	if err != nil {
		return err
	}
	return nil
}

func pbrGetFreeRule(prefixStr string) (*netlink.Rule, error) {

	// Create rule for FreeTable; src NAT range
	// XXX for IPv6 underlay we also need rules.
	// Can we use iif match for all the bo* interfaces?
	// If so, use bu* matches for this rule
	freeRule := netlink.NewRule()
	_, prefix, err := net.ParseCIDR(prefixStr)
	if err != nil {
		return nil, err
	}
	freeRule.Src = prefix
	freeRule.Table = FreeTable
	freeRule.Family = syscall.AF_INET
	return freeRule, nil
}

// Handle a route change
func PbrRouteChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.RouteUpdate) {

	rt := change.Route
	if rt.Table != syscall.RT_TABLE_MAIN {
		// Ignore since we will not add to other table
		return
	}
	doFreeTable := false
	ifname, _, err := IfindexToName(rt.LinkIndex)
	if err != nil {
		// We'll check on ifname when we see a linkchange
		log.Errorf("PbrRouteChange IfindexToName failed for %d: %s\n",
			rt.LinkIndex, err)
	} else {
		if types.IsFreeUplink(*deviceNetworkStatus, ifname) {
			log.Debugf("Applying to FreeTable: %v\n", rt)
			doFreeTable = true
		}
	}
	srt := rt
	srt.Table = FreeTable
	// Multiple IPv6 link-locals can't be added to the same
	// table unless the Priority differs. Different
	// LinkIndex, Src, Scope doesn't matter.
	if rt.Dst != nil && rt.Dst.IP.IsLinkLocalUnicast() {
		log.Debugf("Forcing IPv6 priority to %v\n", rt.LinkIndex)
		// Hack to make the kernel routes not appear identical
		srt.Priority = rt.LinkIndex
	}

	// Add for all ifindices
	MyTable := FreeTable + rt.LinkIndex

	// Add to ifindex specific table
	myrt := rt
	myrt.Table = MyTable
	// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
	if rt.Flags != 0 {
		srt.Flags = 0
		myrt.Flags = 0
	}
	if change.Type == syscall.RTM_DELROUTE {
		log.Debugf("Received route del %v\n", rt)
		if doFreeTable {
			if err := netlink.RouteDel(&srt); err != nil {
				log.Errorf("Failed to remove %v from %d: %s\n",
					srt, srt.Table, err)
			}
		}
		if err := netlink.RouteDel(&myrt); err != nil {
			log.Errorf("Failed to remove %v from %d: %s\n",
				myrt, myrt.Table, err)
		}
	} else if change.Type == syscall.RTM_NEWROUTE {
		log.Debugf("Received route add %v\n", rt)
		if doFreeTable {
			if err := netlink.RouteAdd(&srt); err != nil {
				log.Errorf("Failed to add %v to %d: %s\n",
					srt, srt.Table, err)
			}
		}
		if err := netlink.RouteAdd(&myrt); err != nil {
			log.Errorf("Failed to add %v to %d: %s\n",
				myrt, myrt.Table, err)
		}
	}
}

// Handle an IP address change
func PbrAddrChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.AddrUpdate) {

	changed := false
	if change.NewAddr {
		changed = IfindexToAddrsAdd(change.LinkIndex,
			change.LinkAddress)
		if changed {
			_, linkType, err := IfindexToName(change.LinkIndex)
			if err != nil {
				log.Errorf("XXX NewAddr IfindexToName(%d) failed %s\n",
					change.LinkIndex, err)
			}
			// XXX only call for uplinks and bridges?
			addSourceRule(change.LinkIndex, change.LinkAddress,
				linkType == "bridge")
		}
	} else {
		changed = IfindexToAddrsDel(change.LinkIndex,
			change.LinkAddress)
		if changed {
			_, linkType, err := IfindexToName(change.LinkIndex)
			if err != nil {
				log.Errorf("XXX DelAddr IfindexToName(%d) failed %s\n",
					change.LinkIndex, err)
			}
			// XXX only call for uplinks and bridges?
			delSourceRule(change.LinkIndex, change.LinkAddress,
				linkType == "bridge")
		}
	}
	if changed {
		ifname, _, err := IfindexToName(change.LinkIndex)
		if err != nil {
			log.Errorf("PbrAddrChange IfindexToName failed for %d: %s\n",
				change.LinkIndex, err)
		} else if types.IsUplink(*deviceNetworkStatus, ifname) {
			log.Debugf("Address change for uplink: %v\n", change)
			if addrChangeFuncUplink != nil {
				addrChangeFuncUplink(ifname)
			}
		} else {
			log.Debugf("Address change for non-uplink: %v\n",
				change)
			if addrChangeFuncNonUplink != nil {
				addrChangeFuncNonUplink(ifname)
			}
		}
	}
}

// Handle a link being added or deleted
func PbrLinkChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.LinkUpdate) {

	ifindex := change.Attrs().Index
	ifname := change.Attrs().Name
	linkType := change.Link.Type()
	log.Infof("PbrLinkChange: index %d name %s type %s\n", ifindex, ifname,
		linkType)
	switch change.Header.Type {
	case syscall.RTM_NEWLINK:
		added := IfindexToNameAdd(ifindex, ifname, linkType)
		if added {
			if types.IsFreeUplink(*deviceNetworkStatus,
				ifname) {

				log.Debugf("PbrLinkChange moving to FreeTable %s\n",
					ifname)
				moveRoutesTable(0, ifindex, FreeTable)
			}
			if types.IsUplink(*deviceNetworkStatus, ifname) {
				log.Debugf("Link change for uplink: %s\n",
					ifname)
				if addrChangeFuncUplink != nil {
					addrChangeFuncUplink(ifname)
				}
			} else {
				log.Debugf("Link change for non-uplink: %s\n",
					ifname)
				if addrChangeFuncNonUplink != nil {
					addrChangeFuncNonUplink(ifname)
				}
			}

		}
	case syscall.RTM_DELLINK:
		gone := IfindexToNameDel(ifindex, ifname)
		if gone {
			if types.IsFreeUplink(*deviceNetworkStatus,
				ifname) {

				flushRoutesTable(FreeTable, ifindex)
			}
			MyTable := FreeTable + ifindex
			flushRoutesTable(MyTable, 0)
			flushRules(ifindex)
			if types.IsUplink(*deviceNetworkStatus, ifname) {
				log.Debugf("Link change for uplink: %s\n",
					ifname)
				if addrChangeFuncUplink != nil {
					addrChangeFuncUplink(ifname)
				}
			} else {
				log.Debugf("Link change for non-uplink: %s\n",
					ifname)
				if addrChangeFuncNonUplink != nil {
					addrChangeFuncNonUplink(ifname)
				}
			}

		}
	}
}

// We track the freeuplink list to be able to detect changes and
// update the free table with the routes from all the free uplinks.
// XXX TBD: do we need a separate table for all the uplinks?

var freeUplinkList []string // The subset we add to FreeTable

// Can be called to update the list.
func setFreeUplinks(freeUplinks []string) {

	log.Debugf("setFreeUplinks(%v)\n", freeUplinks)
	// Determine which ones were added; moveRoutesTable to add to free table
	for _, u := range freeUplinks {
		found := false
		for _, old := range freeUplinkList {
			if old == u {
				found = true
				break
			}
		}
		if !found {
			if ifindex, err := IfnameToIndex(u); err == nil {
				moveRoutesTable(0, ifindex, FreeTable)
			}
		}
	}
	// Determine which ones were deleted; flushRoutesTable to remove from
	// free table
	for _, old := range freeUplinkList {
		found := false
		for _, u := range freeUplinks {
			if old == u {
				found = true
				break
			}
		}
		if !found {
			if ifindex, err := IfnameToIndex(old); err == nil {
				flushRoutesTable(FreeTable, ifindex)
			}
		}
	}
	freeUplinkList = freeUplinks
}

// ===== map from ifindex to ifname

type linkNameType struct {
	linkName string
	linkType string
}

var ifindexToName map[int]linkNameType

func IfindexToNameInit() {
	ifindexToName = make(map[int]linkNameType)
}

// Returns true if added
func IfindexToNameAdd(index int, linkName string, linkType string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		// Note that we get RTM_NEWLINK even for link changes
		// hence we don't print unless the entry is new
		log.Infof("IfindexToNameAdd index %d name %s type %s\n",
			index, linkName, linkType)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
		}
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return true
	} else if m.linkName != linkName {
		// We get this when the vifs are created with "vif*" names
		// and then changed to "bu*" etc.
		log.Infof("IfindexToNameAdd name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		ifindexToName[index] = linkNameType{
			linkName: linkName,
			linkType: linkType,
		}
		// log.Debugf("ifindexToName post add %v\n", ifindexToName)
		return false
	} else {
		return false
	}
}

// Returns true if deleted
func IfindexToNameDel(index int, linkName string) bool {
	m, ok := ifindexToName[index]
	if !ok {
		log.Errorf("IfindexToNameDel unknown index %d\n", index)
		return false
	} else if m.linkName != linkName {
		log.Errorf("IfindexToNameDel name mismatch %s vs %s for %d\n",
			m.linkName, linkName, index)
		delete(ifindexToName, index)
		// log.Debugf("ifindexToName post delete %v\n", ifindexToName)
		return true
	} else {
		log.Debugf("IfindexToNameDel index %d name %s\n",
			index, linkName)
		delete(ifindexToName, index)
		// log.Debugf("ifindexToName post delete %v\n", ifindexToName)
		return true
	}
}

// Returns linkName, linkType
func IfindexToName(index int) (string, string, error) {
	n, ok := ifindexToName[index]
	if ok {
		return n.linkName, n.linkType, nil
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return "", "", errors.New(fmt.Sprintf("Unknown ifindex %d", index))
	}
	linkName := link.Attrs().Name
	linkType := link.Type()
	log.Warnf("IfindexToName(%d) fallback lookup done: %s, %s\n",
		index, linkName, linkType)
	return linkName, linkType, nil
}

func IfnameToIndex(ifname string) (int, error) {
	for i, lnt := range ifindexToName {
		if lnt.linkName == ifname {
			return i, nil
		}
	}
	// Try a lookup to handle race
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return -1, errors.New(fmt.Sprintf("Unknown ifname %s", ifname))
	}
	index := link.Attrs().Index
	log.Warnf("IfnameToIndex(%s) fallback lookup done: %d, %s\n",
		ifname, index, link.Type())
	return index, nil
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
		log.Debugf("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Debugf("ifindexToAddrs post add %v\n", ifindexToAddrs)
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
		log.Debugf("IfindexToAddrsAdd add %v for %d\n", addr, index)
		ifindexToAddrs[index] = append(ifindexToAddrs[index], addr)
		// log.Debugf("ifindexToAddrs post add %v\n", ifindexToAddrs)
	}
	return !found
}

// Returns true if deleted
func IfindexToAddrsDel(index int, addr net.IPNet) bool {
	addrs, ok := ifindexToAddrs[index]
	if !ok {
		log.Warnf("IfindexToAddrsDel unknown index %d\n", index)
		return false
	}
	for i, a := range addrs {
		// Equal if containment in both directions?
		if a.IP.Equal(addr.IP) &&
			a.Contains(addr.IP) && addr.Contains(a.IP) {
			log.Debugf("IfindexToAddrsDel del %v for %d\n",
				addr, index)
			ifindexToAddrs[index] = append(ifindexToAddrs[index][:i],
				ifindexToAddrs[index][i+1:]...)
			// log.Debugf("ifindexToAddrs post remove %v\n", ifindexToAddrs)
			// XXX should we check for zero and remove ifindex?
			return true
		}
	}
	log.Warnf("IfindexToAddrsDel address not found for %d in\n",
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
	log.Debugf("flushRoutesTable(%d, %d) - got %d\n",
		table, ifindex, len(routes))
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		log.Debugf("flushRoutesTable(%d, %d) deleting %v\n",
			table, ifindex, rt)
		if err := netlink.RouteDel(&rt); err != nil {
			// XXX was Fatalf
			log.Errorf("flushRoutesTable - RouteDel %v failed %s\n",
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
	log.Debugf("moveRoutesTable(%d, %d, %d) - got %d\n",
		srcTable, ifindex, dstTable, len(routes))
	for _, rt := range routes {
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
			log.Debugf("Forcing IPv6 priority to %v\n",
				rt.LinkIndex)
			// Hack to make the kernel routes not appear identical
			art.Priority = rt.LinkIndex
		}
		// Clear any RTNH_F_LINKDOWN etc flags since add doesn't
		// like them
		if rt.Flags != 0 {
			art.Flags = 0
		}
		log.Debugf("moveRoutesTable(%d, %d, %d) adding %v\n",
			srcTable, ifindex, dstTable, art)
		if err := netlink.RouteAdd(&art); err != nil {
			log.Errorf("moveRoutesTable failed to add %v to %d: %s\n",
				art, art.Table, err)
		}
	}
}

// ==== manage the ip rules

// Flush the rules we create. If ifindex is non-zero we also compare it
// Otherwise we flush the FreeTable
func flushRules(ifindex int) {
	rules, err := netlink.RuleList(syscall.AF_UNSPEC)
	if err != nil {
		log.Fatal("RuleList failed: %v\n", err)
	}
	log.Debugf("flushRules(%d) - got %d\n", ifindex, len(rules))
	for _, r := range rules {
		if ifindex == 0 && r.Table != FreeTable {
			continue
		}
		if ifindex != 0 && r.Table != FreeTable+ifindex {
			continue
		}
		log.Debugf("flushRules: RuleDel %v\n", r)
		if err := netlink.RuleDel(&r); err != nil {
			log.Fatal("flushRules - RuleDel %v failed %s\n",
				r, err)
		}
	}
}

// If it is a bridge interface we add a rule for the subnet. Otherwise
// just for the host.
func addSourceRule(ifindex int, p net.IPNet, bridge bool) {

	log.Debugf("addSourceRule(%d, %v, %v)\n", ifindex, p.String(), bridge)
	r := netlink.NewRule()
	r.Table = FreeTable + ifindex
	// Add rule for /32 or /128
	if p.IP.To4() != nil {
		r.Family = syscall.AF_INET
		if bridge {
			r.Src = &p
		} else {
			r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(32, 32)}
		}
	} else {
		r.Family = syscall.AF_INET6
		if bridge {
			r.Src = &p
		} else {
			r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(128, 128)}
		}
	}
	log.Debugf("addSourceRule: RuleAdd %v\n", r)
	// Avoid duplicate rules
	_ = netlink.RuleDel(r)
	if err := netlink.RuleAdd(r); err != nil {
		log.Errorf("RuleAdd %v failed with %s\n", r, err)
		return
	}
}

// If it is a bridge interface we add a rule for the subnet. Otherwise
// just for the host.
func delSourceRule(ifindex int, p net.IPNet, bridge bool) {

	log.Debugf("delSourceRule(%d, %v, %v)\n", ifindex, p.String(), bridge)
	r := netlink.NewRule()
	r.Table = FreeTable + ifindex
	// Add rule for /32 or /128
	if p.IP.To4() != nil {
		r.Family = syscall.AF_INET
		if bridge {
			r.Src = &p
		} else {
			r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(32, 32)}
		}
	} else {
		r.Family = syscall.AF_INET6
		if bridge {
			r.Src = &p
		} else {
			r.Src = &net.IPNet{IP: p.IP, Mask: net.CIDRMask(128, 128)}
		}
	}
	log.Debugf("delSourceRule: RuleDel %v\n", r)
	if err := netlink.RuleDel(r); err != nil {
		log.Errorf("RuleDel %v failed with %s\n", r, err)
		return
	}
}

func AddOverlayRuleAndRoute(bridgeName string, iifIndex int,
	oifIndex int, ipnet *net.IPNet) error {
	log.Debugf("AddOverlayRuleAndRoute: IIF index %d, Prefix %s, OIF index %d",
		iifIndex, ipnet.String(), oifIndex)

	r := netlink.NewRule()
	myTable := FreeTable + iifIndex
	r.Table = myTable
	r.IifName = bridgeName
	if ipnet.IP.To4() != nil {
		r.Family = syscall.AF_INET
	} else {
		r.Family = syscall.AF_INET6
	}

	// Avoid duplicate rules
	_ = netlink.RuleDel(r)

	// Add rule
	if err := netlink.RuleAdd(r); err != nil {
		errStr := fmt.Sprintf("AddOverlayRuleAndRoute: RuleAdd %v failed with %s", r, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}

	// Add a the required route to new table that we created above.

	// Setup a route for the current network's subnet to point out of the given oifIndex
	rt := netlink.Route{Dst: ipnet, LinkIndex: oifIndex, Table: myTable, Flags: 0}
	if err := netlink.RouteAdd(&rt); err != nil {
		errStr := fmt.Sprintf("AddOverlayRuleAndRoute: RouteAdd %s failed: %s",
			ipnet.String(), err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	return nil
}
