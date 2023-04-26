// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/vishvananda/netlink"
)

var (
	_, ipv4Any, _ = net.ParseCIDR("0.0.0.0/0")
	_, ipv6Any, _ = net.ParseCIDR("::/0")
)

// Route : Network route.
type Route struct {
	netlink.Route
	// AdapterIfName : name of the interface associated with the route.
	// Should match with Route.LinkIndex.
	AdapterIfName string
	// AdapterLL : logical label of the associated interface.
	AdapterLL string
}

// Name combines the interface name, route table ID and the destination
// address to construct a unique route identifier.
func (r Route) Name() string {
	var dst string
	if r.hasDefaultDst() {
		dst = "default"
	} else {
		dst = r.Route.Dst.String()
	}
	return fmt.Sprintf("%d/%s/%s",
		r.Table, r.AdapterIfName, dst)
}

// Label is more human-readable than name.
func (r Route) Label() string {
	var dst string
	if r.Route.Dst == nil {
		dst = "<default>"
	} else {
		dst = r.Route.Dst.String()
	}
	return fmt.Sprintf("%s route table %d dst %s dev %v via %v",
		r.ipVersionStr(), r.Table, dst, r.AdapterLL, r.Gw)
}

func (r Route) ipVersionStr() string {
	switch r.Family {
	case netlink.FAMILY_V4:
		return "IPv4"
	case netlink.FAMILY_V6:
		return "IPv6"
	default:
		return fmt.Sprintf("Unsupported (family %d)", r.Family)
	}
}

func (r Route) hasDefaultDst() bool {
	if r.Route.Dst == nil {
		return true
	}
	ones, _ := r.Route.Dst.Mask.Size()
	return ones == 0 && r.Route.Dst.IP.IsUnspecified()
}

// Any destination IP and nil destination IP are treated as the same.
// However, netlink RouteAdd and RouteDel require a non-nil destination IP.
func (r Route) normalizedNetlinkRoute() netlink.Route {
	route := r.Route
	if route.Dst == nil {
		if route.Family == netlink.FAMILY_V4 {
			route.Dst = ipv4Any
		} else {
			route.Dst = ipv6Any
		}
	}
	// Also clear flags like RTNH_F_LINKDOWN - in the scope of *config* reconciliation
	// we do not care about them.
	route.Flags = 0
	return route
}

// Type of the item.
func (r Route) Type() string {
	switch r.Family {
	case netlink.FAMILY_V4:
		return genericitems.IPv4RouteTypename
	case netlink.FAMILY_V6:
		return genericitems.IPv6RouteTypename
	default:
		return genericitems.UnsupportedRouteTypename
	}
}

// Equal is a comparison method for two equally-named route instances.
func (r Route) Equal(other depgraph.Item) bool {
	r2, isRoute := other.(Route)
	if !isRoute {
		return false
	}
	return r.normalizedNetlinkRoute().Equal(r2.normalizedNetlinkRoute())
}

// External returns false.
func (r Route) External() bool {
	return false
}

// String describes the network route.
func (r Route) String() string {
	return fmt.Sprintf("Network route for adapter '%s' with priority %d: %s",
		r.AdapterLL, r.Route.Priority, r.Route.String())
}

// Dependencies of a network route are:
//   - the "via" adapter must exist and be UP
//   - the "via" adapter must have an IP address assigned from the subnet
//     of the route gateway.
func (r Route) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.AdapterTypename,
				ItemName: r.AdapterIfName,
			},
			Description: "The associated adapter must exist (and be UP)",
		},
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.AdapterAddrsTypename,
				ItemName: r.AdapterIfName,
			},
			MustSatisfy: func(item depgraph.Item) bool {
				addrs := item.(genericitems.AdapterAddrs)
				if len(addrs.IPAddrs) == 0 {
					return false
				}
				if len(r.Gw) > 0 {
					for _, addr := range addrs.IPAddrs {
						if addr.Contains(r.Gw) {
							return true
						}
					}
					return false
				}
				return true
			},
			Attributes: depgraph.DependencyAttributes{
				// Linux automatically removes route when the interface
				// looses the corresponding IP address.
				AutoDeletedByExternal: true,
			},
			Description: "The associated adapter must have matching IP address assigned",
		},
	}
}

// RouteConfigurator implements Configurator interface (libs/reconciler) for network routes.
type RouteConfigurator struct {
	Log *base.LogObject
}

// Create adds network route.
func (c *RouteConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	route := item.(Route)
	netlinkRoute := route.normalizedNetlinkRoute()
	err := netlink.RouteAdd(&netlinkRoute)
	if err != nil && errors.Is(err, syscall.EEXIST) {
		// Ignore duplicate route.
		return nil
	}
	return err
}

// Modify is not implemented.
func (c *RouteConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes network route.
func (c *RouteConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	route := item.(Route)
	netlinkRoute := route.normalizedNetlinkRoute()
	err := netlink.RouteDel(&netlinkRoute)
	if err != nil && errors.Is(err, syscall.ESRCH) {
		// Ignore error if route is already removed by kernel.
		return nil
	}
	return err
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *RouteConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
