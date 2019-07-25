// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Create ip rules and ip routing tables for each ifindex and also a free
// one for the collection of free management ports.

package zedrouter

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

var FreeTable = 500 // Need a FreeMgmtPort policy for NAT+underlay

// Call before setting up routeChanges, addrChanges, and linkChanges
func PbrInit(ctx *zedrouterContext) {

	log.Debugf("PbrInit()\n")

	setFreeMgmtPorts(types.GetMgmtPortsFree(*ctx.deviceNetworkStatus, 0))

	flushRoutesTable(FreeTable, 0)

	// flush any old rules using RuleList
	flushRules(0)
}

// PbrRouteAddAll adds all the routes for the bridgeName table to the specific port
// Separately we handle changes in PbrRouteChange
func PbrRouteAddAll(bridgeName string, port string) error {
	log.Infof("PbrRouteAddAll(%s, %s)\n", bridgeName, port)

	ifindex, err := devicenetwork.IfnameToIndex(port)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			port, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	routes := getAllIPv4Routes(ifindex)
	if routes == nil {
		log.Warnf("PbrRouteAddAll(%s, %s) no routes",
			bridgeName, port)
		return nil
	}
	// Add to ifindex specific table
	ifindex, err = devicenetwork.IfnameToIndex(bridgeName)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			bridgeName, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	// XXX do they differ? Yes
	link, err := netlink.LinkByName(bridgeName)
	if err != nil {
		errStr := fmt.Sprintf("LinkByName(%s) failed: %s",
			bridgeName, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	index := link.Attrs().Index
	if index != ifindex {
		log.Warnf("XXX Different ifindex vs index %d vs %x",
			ifindex, index)
		ifindex = index
	}
	MyTable := FreeTable + ifindex
	for _, rt := range routes {
		myrt := rt
		myrt.Table = MyTable
		// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
		if rt.Flags != 0 {
			myrt.Flags = 0
		}
		log.Infof("PbrRouteAddAll(%s, %s) adding %v\n",
			bridgeName, port, myrt)
		if err := netlink.RouteAdd(&myrt); err != nil {
			errStr := fmt.Sprintf("Failed to add %v to %d: %s",
				myrt, myrt.Table, err)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
	}
	return nil
}

// PbrRouteDeleteAll deletes all the routes for the bridgeName table to the specific port
// Separately we handle changes in PbrRouteChange
func PbrRouteDeleteAll(bridgeName string, port string) error {
	log.Infof("PbrRouteDeleteAll(%s, %s)\n", bridgeName, port)

	ifindex, err := devicenetwork.IfnameToIndex(port)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			port, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	routes := getAllIPv4Routes(ifindex)
	if routes == nil {
		log.Warnf("PbrRouteDeleteAll(%s, %s) no routes",
			bridgeName, port)
		return nil
	}
	// Remove from ifindex specific table
	ifindex, err = devicenetwork.IfnameToIndex(bridgeName)
	if err != nil {
		errStr := fmt.Sprintf("IfnameToIndex(%s) failed: %s",
			bridgeName, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	MyTable := FreeTable + ifindex
	for _, rt := range routes {
		myrt := rt
		myrt.Table = MyTable
		// Clear any RTNH_F_LINKDOWN etc flags since del might not like them
		if rt.Flags != 0 {
			myrt.Flags = 0
		}
		log.Infof("PbrRouteDeleteAll(%s, %s) deleting %v\n",
			bridgeName, port, myrt)
		if err := netlink.RouteDel(&myrt); err != nil {
			errStr := fmt.Sprintf("Failed to delete %v from %d: %s",
				myrt, myrt.Table, err)
			log.Errorln(errStr)
			// We continue to try to delete all
		}
	}
	return nil
}

// XXX The PbrNAT functions are no-ops for now.
// The prefix for the NAT linux bridge interface is in its own pbr table
// XXX put the default route(s) for the selected Adapter for the service
// into the table for the bridge to avoid using other ports.
func PbrNATAdd(prefix string) error {

	log.Debugf("PbrNATAdd(%s)\n", prefix)
	return nil
}

// XXX The PbrNAT functions are no-ops for now.
func PbrNATDel(prefix string) error {

	log.Debugf("PbrNATDel(%s)\n", prefix)
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
	freeRule.Priority = 10000
	return freeRule, nil
}

// Handle a route change
func PbrRouteChange(ctx *zedrouterContext,
	deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.RouteUpdate) {

	rt := change.Route
	if rt.Table != getDefaultRouteTable() {
		// Ignore since we will not add to other table
		return
	}
	doFreeTable := false
	ifname, _, err := devicenetwork.IfindexToName(rt.LinkIndex)
	if err != nil {
		// We'll check on ifname when we see a linkchange
		log.Errorf("PbrRouteChange IfindexToName failed for %d: %s\n",
			rt.LinkIndex, err)
	} else {
		if types.IsFreeMgmtPort(*deviceNetworkStatus, ifname) {
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
	if change.Type == getRouteUpdateTypeDELROUTE() {
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
		// find all bridges for network instances and del for them
		indicies := getAllNIindices(ctx, ifname)
		log.Infof("XXX Apply route del %v to %v", rt, indicies)
		for _, ifindex := range indicies {
			myrt.Table = FreeTable + ifindex
			if err := netlink.RouteDel(&myrt); err != nil {
				log.Errorf("Failed to remove %v from %d: %s\n",
					myrt, myrt.Table, err)
			}
		}
	} else if change.Type == getRouteUpdateTypeNEWROUTE() {
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
		// find all bridges for network instances and add for them
		indicies := getAllNIindices(ctx, ifname)
		log.Infof("XXX Apply route add %v to %v", rt, indicies)
		for _, ifindex := range indicies {
			myrt.Table = FreeTable + ifindex
			if err := netlink.RouteAdd(&myrt); err != nil {
				log.Errorf("Failed to add %v from %d: %s\n",
					myrt, myrt.Table, err)
			}
		}
	}
}

// Handle an IP address change
// Returns the ifname if there was a change
func PbrAddrChange(deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.AddrUpdate) string {

	changed := false
	if change.NewAddr {
		changed = devicenetwork.IfindexToAddrsAdd(change.LinkIndex,
			change.LinkAddress)
		if changed {
			_, linkType, err := devicenetwork.IfindexToName(change.LinkIndex)
			if err != nil {
				log.Errorf("XXX NewAddr IfindexToName(%d) failed %s\n",
					change.LinkIndex, err)
			}
			// XXX only call for ports and bridges?
			addSourceRule(change.LinkIndex, change.LinkAddress,
				linkType == "bridge")
		}
	} else {
		changed = devicenetwork.IfindexToAddrsDel(change.LinkIndex,
			change.LinkAddress)
		if changed {
			_, linkType, err := devicenetwork.IfindexToName(change.LinkIndex)
			if err != nil {
				log.Errorf("XXX DelAddr IfindexToName(%d) failed %s\n",
					change.LinkIndex, err)
			}
			// XXX only call for ports and bridges?
			delSourceRule(change.LinkIndex, change.LinkAddress,
				linkType == "bridge")
		}
	}
	if changed {
		ifname, _, err := devicenetwork.IfindexToName(change.LinkIndex)
		if err != nil {
			log.Errorf("PbrAddrChange IfindexToName failed for %d: %s\n",
				change.LinkIndex, err)
			return ""
		}
		return ifname
	}
	return ""
}

// We track the freeMgmtPort list to be able to detect changes and
// update the free table with the routes from all the free management ports.
// XXX TBD: do we need a separate table for all the management ports?

var freeMgmtPortList []string // The subset we add to FreeTable

// Can be called to update the list.
func setFreeMgmtPorts(freeMgmtPorts []string) {

	log.Debugf("setFreeMgmtPorts(%v)\n", freeMgmtPorts)
	// Determine which ones were added; moveRoutesTable to add to free table
	for _, u := range freeMgmtPorts {
		found := false
		for _, old := range freeMgmtPortList {
			if old == u {
				found = true
				break
			}
		}
		if !found {
			ifindex, err := devicenetwork.IfnameToIndex(u)
			if err == nil {
				moveRoutesTable(0, ifindex, FreeTable)
			}
		}
	}
	// Determine which ones were deleted; flushRoutesTable to remove from
	// free table
	for _, old := range freeMgmtPortList {
		found := false
		for _, u := range freeMgmtPorts {
			if old == u {
				found = true
				break
			}
		}
		if !found {
			ifindex, err := devicenetwork.IfnameToIndex(old)
			if err == nil {
				flushRoutesTable(FreeTable, ifindex)
			}
		}
	}
	freeMgmtPortList = freeMgmtPorts
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
		log.Fatalf("RouteList failed: %v\n", err)
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

// ==== manage the ip rules

// Flush the rules we create. If ifindex is non-zero we also compare it
// Otherwise we flush the FreeTable
func flushRules(ifindex int) {
	rules, err := netlink.RuleList(syscall.AF_UNSPEC)
	if err != nil {
		log.Fatalf("RuleList failed: %v\n", err)
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
			log.Fatalf("flushRules - RuleDel %v failed %s\n",
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
	r.Priority = 10000
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
	r.Priority = 10000
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
	r.Priority = 10000
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

// AddFwMarkRuleToDummy : Create a ip rule that sends packets marked with given mark
// out of interface with given index.
func AddFwMarkRuleToDummy(fwmark uint32, iifIndex int) error {

	r := netlink.NewRule()
	myTable := FreeTable + iifIndex
	r.Table = myTable
	r.Mark = int(fwmark)
	// XXX Explain this magic number
	// This rule gets added during the starting steps of service.
	// Other ip rules corresponding to network instances get added after this
	// and take higher priority. We want this ip rule to match before anything else.
	// Hence we make the priority of this 1000 and the other rules to have 10000.
	r.Priority = 1000

	// Avoid duplicate rules
	_ = netlink.RuleDel(r)

	// Add rule
	if err := netlink.RuleAdd(r); err != nil {
		errStr := fmt.Sprintf("AddFwMarkRuleToDummy: RuleAdd %v failed with %s", r, err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}

	// Add default route that points to dummy interface.
	_, ipnet, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		errStr := fmt.Sprintf("AddFwMarkRuleToDummy: ParseCIDR of %s failed",
			"0.0.0.0/0")
		return errors.New(errStr)
	}

	// Setup a route for the current network's subnet to point out of the given oifIndex
	rt := netlink.Route{Dst: ipnet, LinkIndex: iifIndex, Table: myTable, Flags: 0}
	if err := netlink.RouteAdd(&rt); err != nil {
		errStr := fmt.Sprintf("AddFwMarkRuleToDummy: RouteAdd %s failed: %s",
			ipnet.String(), err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	return nil
}
