// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Create ip rules and ip routing tables for each ifindex for the bridges used
// for network instances.

package zedrouter

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

var baseTableIndex = 500 // Number tables from here + ifindex

// PbrRouteAddAll adds all the routes for the bridgeName table to the specific port
// Separately we handle changes in PbrRouteChange
// XXX used by networkinstance only
func PbrRouteAddAll(ctx *zedrouterContext, bridgeName string, port string) error {
	log.Functionf("PbrRouteAddAll(%s, %s)\n", bridgeName, port)

	// for airgap internal switch case
	if port == "" {
		log.Functionf("PbrRouteAddAll: for internal switch, skip for ACL and Route installation\n")
		return nil
	}
	portIndex, exists, err := ctx.networkMonitor.GetInterfaceIndex(port)
	if err != nil {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: %w", port, err)
		log.Error(err)
		return err
	}
	if !exists {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: port does not exist", port)
		log.Error(err)
		return err
	}
	routes, err := ctx.networkMonitor.ListRoutes(netmonitor.RouteFilters{
		FilterByTable: true,
		Table:         getDefaultRouteTable(),
		FilterByIf:    true,
		IfIndex:       portIndex,
	})
	if err != nil {
		err = fmt.Errorf("ListRoutes(%s) failed: %w", port, err)
		log.Error(err)
		return err
	}
	brIndex, exists, err := ctx.networkMonitor.GetInterfaceIndex(bridgeName)
	if err != nil {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: %w", bridgeName, err)
		log.Error(err)
		return err
	}
	if !exists {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: bridge does not exist", bridgeName)
		log.Error(err)
		return err
	}
	// Add the lowest-prio default-drop route.
	// The route is used to drop all packets otherwise not matched by any route
	// and prevent them from escaping the NI-specific routing table.
	err = AddDefaultDropRoute(ctx, brIndex, true)
	if err != nil {
		errStr := fmt.Sprintf("Failed to add default-drop route: %s", err)
		log.Errorln(errStr)
	}
	brTable := baseTableIndex + brIndex
	for _, rt := range routes {
		// TODO: accessing Linux specific route definition.
		// This will have to go to Linux-specific zedrouter section
		// (will be done later in refactoring).
		copiedRt := rt.Data.(netlink.Route)
		copiedRt.Table = brTable
		// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
		copiedRt.Flags = 0
		log.Functionf("PbrRouteAddAll(%s, %s) adding %v\n",
			bridgeName, port, copiedRt)
		if err := netlink.RouteAdd(&copiedRt); err != nil {
			errStr := fmt.Sprintf("Failed to add %v to %d: %s",
				copiedRt, copiedRt.Table, err)
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
func PbrRouteDeleteAll(ctx *zedrouterContext, bridgeName string, port string) error {
	log.Functionf("PbrRouteDeleteAll(%s, %s)\n", bridgeName, port)

	// for airgap internal switch case
	if port == "" {
		log.Functionf("PbrRouteDeleteAll: for internal switch, skip for ACL and Route deletion\n")
		return nil
	}
	portIndex, exists, err := ctx.networkMonitor.GetInterfaceIndex(port)
	if err != nil {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: %w", port, err)
		log.Error(err)
		return err
	}
	if !exists {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: port does not exist", port)
		log.Error(err)
		return err
	}
	routes, err := ctx.networkMonitor.ListRoutes(netmonitor.RouteFilters{
		FilterByTable: true,
		Table:         getDefaultRouteTable(),
		FilterByIf:    true,
		IfIndex:       portIndex,
	})
	if err != nil {
		err = fmt.Errorf("ListRoutes(%s) failed: %w", port, err)
		log.Error(err)
		return err
	}
	// Remove from bridge specific table
	brIndex, exists, err := ctx.networkMonitor.GetInterfaceIndex(bridgeName)
	if err != nil {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: %w", bridgeName, err)
		log.Error(err)
		return err
	}
	if !exists {
		err = fmt.Errorf("GetInterfaceIndex(%s) failed: bridge does not exist", bridgeName)
		log.Error(err)
		return err
	}
	brTable := baseTableIndex + brIndex
	for _, rt := range routes {
		// TODO: accessing Linux specific route definition.
		// This will have to go to Linux-specific zedrouter section
		// (will be done later in refactoring).
		copiedRt := rt.Data.(netlink.Route)
		copiedRt.Table = brTable
		// Clear any RTNH_F_LINKDOWN etc flags since del might not like them
		copiedRt.Flags = 0
		log.Functionf("PbrRouteDeleteAll(%s, %s) deleting %v\n",
			bridgeName, port, copiedRt)
		if err := netlink.RouteDel(&copiedRt); err != nil {
			errStr := fmt.Sprintf("Failed to delete %v from %d: %s",
				copiedRt, copiedRt.Table, err)
			log.Errorln(errStr)
			// We continue to try to delete all
		}
	}
	// Delete the lowest-prio default-drop route.
	err = DelDefaultDropRoute(ctx, brIndex, true)
	if err != nil {
		errStr := fmt.Sprintf("Failed to delete default-drop route: %s", err)
		log.Errorln(errStr)
	}
	return nil
}

// Handle a route change
func PbrRouteChange(ctx *zedrouterContext,
	deviceNetworkStatus *types.DeviceNetworkStatus,
	change netmonitor.RouteChange) {

	// TODO: accessing Linux specific route definition.
	// This will have to go to Linux-specific zedrouter section
	// (will be done later in refactoring).
	rt := change.Route.Data.(netlink.Route)
	if rt.Table != getDefaultRouteTable() {
		// Ignore since we will not add to other table
		return
	}
	op := "NONE"
	if change.Deleted {
		op = "DELROUTE"
	} else if change.Added {
		op = "NEWROUTE"
	}
	// We are interested in routes created/deleted for a port or a network
	// instance bridge.
	ifIndex := change.IfIndex
	attrs, err := ctx.networkMonitor.GetInterfaceAttrs(ifIndex)
	if err != nil {
		log.Errorf("GetInterfaceAttrs failed for %d: %s: route %v\n",
			ifIndex, err, rt)
		return
	}
	ifName := attrs.IfName
	if !isNIBridge(ctx, ifName) && !types.IsL3Port(*deviceNetworkStatus, ifName) {
		// Ignore
		log.Functionf("PbrRouteChange ignore %s: "+
			"neither network instance bridge nor port. route %v\n",
			attrs.IfName, rt)
		return
	}
	log.Tracef("RouteChange(%d/%s) %s %+v", ifIndex, ifName, op, rt)

	// Add to any network instance specific table associated with this interface.
	// Do not touch port-specific table, however - that one is under NIM management!
	copiedRt := rt
	// Clear any RTNH_F_LINKDOWN etc flags since add doesn't like them
	copiedRt.Flags = 0
	if change.Deleted {
		log.Functionf("Received route del %v\n", rt)
		if isNIBridge(ctx, ifName) {
			log.Functionf("Apply route del for NI bridge %s", ifName)
			copiedRt.Table = baseTableIndex + ifIndex
			if err := netlink.RouteDel(&copiedRt); err != nil {
				log.Errorf("Failed to remove %v from %d: %s\n",
					copiedRt, copiedRt.Table, err)
			}
		} else { // L3 port
			// Find all network instances using this port.
			indexes := getAllNIindices(ctx, ifName)
			if len(indexes) != 0 {
				log.Functionf("Apply route del to %v", indexes)
			}
			for _, brIndex := range indexes {
				copiedRt.Table = baseTableIndex + brIndex
				if err := netlink.RouteDel(&copiedRt); err != nil {
					log.Errorf("Failed to remove %v from %d: %s\n",
						copiedRt, copiedRt.Table, err)
				}
			}
		}
	} else if change.Added {
		log.Functionf("Received route add %v\n", rt)
		if isNIBridge(ctx, ifName) {
			log.Functionf("Apply route add to NI bridge %s", ifName)
			copiedRt.Table = baseTableIndex + ifIndex
			if err := netlink.RouteAdd(&copiedRt); err != nil {
				// XXX ditto for ENXIO?? for del?
				if isErrno(err, syscall.EEXIST) {
					log.Functionf("Failed to add %v to %d: %s\n",
						copiedRt, copiedRt.Table, err)
				} else {
					log.Errorf("Failed to add %v to %d: %s\n",
						copiedRt, copiedRt.Table, err)
				}
			}
		} else { // L3 port
			// Find all network instances using this port.
			indexes := getAllNIindices(ctx, ifName)
			if len(indexes) != 0 {
				log.Functionf("Apply route add to %v", indexes)
			}
			for _, brIndex := range indexes {
				copiedRt.Table = baseTableIndex + brIndex
				if err := netlink.RouteAdd(&copiedRt); err != nil {
					log.Errorf("Failed to add %v to %d: %s\n",
						copiedRt, copiedRt.Table, err)
				}
			}
		}
	}
}

func isErrno(err error, errno syscall.Errno) bool {
	e1, ok := err.(syscall.Errno)
	if !ok {
		log.Warnf("XXX not Errno: %T", err)
		return false
	}
	return e1 == errno
}

// AddFwMarkRuleToDummy : Create an ip rule that sends packets marked by a Drop ACE
// out of interface with given index.
func AddFwMarkRuleToDummy(ctx *zedrouterContext, ifIndex int) error {

	r := netlink.NewRule()
	myTable := baseTableIndex + ifIndex
	r.Table = myTable
	r.Mark = iptables.AceDropAction
	r.Mask = iptables.AceActionMask
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
	err := AddDefaultDropRoute(ctx, ifIndex, false)
	if err != nil {
		errStr := fmt.Sprintf("AddFwMarkRuleToDummy: AddDefaultDropRoute failed: %s", err)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	return nil
}

// AddDefaultDropRoute : Add default route dropping packets either by sending them
// into the dummy interface or by using an unreachable destination.
func AddDefaultDropRoute(ctx *zedrouterContext, ifIndex int, unreachable bool) error {
	route, err := makeDefaultDropRoute(ctx, ifIndex, unreachable)
	if err != nil {
		return err
	}
	return netlink.RouteAdd(route)
}

// DelDefaultDropRoute : Delete previously added default route dropping packets.
func DelDefaultDropRoute(ctx *zedrouterContext, ifIndex int, unreachable bool) error {
	route, err := makeDefaultDropRoute(ctx, ifIndex, unreachable)
	if err != nil {
		return err
	}
	return netlink.RouteDel(route)
}

func makeDefaultDropRoute(
	ctx *zedrouterContext, ifIndex int, unreachable bool) (*netlink.Route, error) {
	var (
		routeType    int
		outLinkIndex int
	)
	if unreachable {
		routeType = unix.RTN_UNREACHABLE
	} else {
		var err error
		var exists bool
		outLinkIndex, exists, err = ctx.networkMonitor.GetInterfaceIndex(dummyIntfName)
		if !exists {
			return nil, errors.New("dummy interface does not exist")
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get dummy interface: %w", err)
		}
	}

	_, dst, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return nil, fmt.Errorf("failed to parse dst for default route: %w", err)
	}

	var prio int
	if unreachable {
		// Do not override any actual default route.
		prio = int(^uint32(0))
	}
	return &netlink.Route{
		LinkIndex: outLinkIndex,
		Dst:       dst,
		Priority:  prio,
		Table:     baseTableIndex + ifIndex,
		Type:      routeType,
	}, nil
}

// TODO: make this part of the interface between the generic and the network stack
// specific part of zedrouter.
func getDefaultRouteTable() int {
	return syscall.RT_TABLE_MAIN
}
