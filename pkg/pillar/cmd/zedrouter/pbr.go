// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Create ip rules and ip routing tables for each ifindex for the bridges used
// for network instances.

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

var baseTableIndex = 500 // Number tables from here + ifindex

// Call before setting up routeChanges, addrChanges, and linkChanges
func PbrInit(ctx *zedrouterContext) {

	log.Debugf("PbrInit()\n")
}

// PbrRouteAddAll adds all the routes for the bridgeName table to the specific port
// Separately we handle changes in PbrRouteChange
// XXX used by networkinstance only
// XXX Can't we use MoveRoutesTable?
func PbrRouteAddAll(bridgeName string, port string) error {
	log.Infof("PbrRouteAddAll(%s, %s)\n", bridgeName, port)

	// for airgap internal switch case
	if port == "" {
		log.Infof("PbrRouteAddAll: for internal switch, skip for ACL and Route installation\n")
		return nil
	}

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
	MyTable := baseTableIndex + ifindex
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
// XXX used by networkinstance only
// XXX can't we flush the table?
func PbrRouteDeleteAll(bridgeName string, port string) error {
	log.Infof("PbrRouteDeleteAll(%s, %s)\n", bridgeName, port)

	// for airgap internal switch case
	if port == "" {
		log.Infof("PbrRouteDeleteAll: for internal switch, skip for ACL and Route deletion\n")
		return nil
	}

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
	MyTable := baseTableIndex + ifindex
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

// Handle a route change
func PbrRouteChange(ctx *zedrouterContext,
	deviceNetworkStatus *types.DeviceNetworkStatus,
	change netlink.RouteUpdate) {

	rt := change.Route
	if rt.Table != getDefaultRouteTable() {
		// Ignore since we will not add to other table
		return
	}
	op := "NONE"
	if change.Type == getRouteUpdateTypeDELROUTE() {
		op = "DELROUTE"
	} else if change.Type == getRouteUpdateTypeNEWROUTE() {
		op = "NEWROUTE"
	}
	ifname, linkType, err := devicenetwork.IfindexToName(rt.LinkIndex)
	if err != nil {
		log.Errorf("PbrRouteChange IfindexToName failed for %d: %s\n",
			rt.LinkIndex, err)
		return
	}
	if linkType != "bridge" {
		// Ignore
		return
	}
	log.Infof("RouteChange(%d/%s) %s %+v", rt.LinkIndex, ifname, op, rt)

	// XXX introduce common devicenetwork.AddRouteToTable(rt, baseTableIndex + rt.LinkIndex)

	// Apply to any bridges used by network instances
	myrt := rt
	// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
	if myrt.Flags != 0 {
		myrt.Flags = 0
	}
	if change.Type == getRouteUpdateTypeDELROUTE() {
		log.Infof("Received route del %v\n", rt)
		// find all bridges for network instances and del for them
		indicies := getAllNIindices(ctx, ifname)
		log.Infof("XXX Apply route del %v to %v", rt, indicies)
		for _, ifindex := range indicies {
			myrt.Table = baseTableIndex + ifindex
			if err := netlink.RouteDel(&myrt); err != nil {
				log.Errorf("Failed to remove %v from %d: %s\n",
					myrt, myrt.Table, err)
			}
		}
	} else if change.Type == getRouteUpdateTypeNEWROUTE() {
		log.Infof("Received route add %v\n", rt)
		// find all bridges for network instances and add for them
		indicies := getAllNIindices(ctx, ifname)
		log.Infof("XXX Apply route add %v to %v", rt, indicies)
		for _, ifindex := range indicies {
			myrt.Table = baseTableIndex + ifindex
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
			change.LinkAddress.IP)
		if changed {
			_, linkType, err := devicenetwork.IfindexToName(change.LinkIndex)
			if err != nil {
				log.Errorf("XXX NewAddr IfindexToName(%d) failed %s\n",
					change.LinkIndex, err)
			}
			if linkType == "bridge" {
				devicenetwork.AddSourceRule(change.LinkIndex, change.LinkAddress,
					linkType == "bridge")
			}
		}
	} else {
		changed = devicenetwork.IfindexToAddrsDel(change.LinkIndex,
			change.LinkAddress.IP)
		if changed {
			_, linkType, err := devicenetwork.IfindexToName(change.LinkIndex)
			if err != nil {
				log.Errorf("XXX DelAddr IfindexToName(%d) failed %s\n",
					change.LinkIndex, err)
			}
			if linkType == "bridge" {
				devicenetwork.DelSourceRule(change.LinkIndex, change.LinkAddress,
					linkType == "bridge")
			}
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

func AddOverlayRuleAndRoute(bridgeName string, iifIndex int,
	oifIndex int, ipnet *net.IPNet) error {
	log.Debugf("AddOverlayRuleAndRoute: IIF index %d, Prefix %s, OIF index %d",
		iifIndex, ipnet.String(), oifIndex)

	r := netlink.NewRule()
	myTable := baseTableIndex + iifIndex
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
	myTable := baseTableIndex + iifIndex
	r.Table = myTable
	r.Mark = int(fwmark)
	r.Mask = 0x00ffffff
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
