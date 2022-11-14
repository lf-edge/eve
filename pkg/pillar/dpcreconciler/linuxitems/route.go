// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"github.com/lf-edge/eve/libs/depgraph"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/vishvananda/netlink"
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
	if r.Route.Dst == nil {
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
	return fmt.Sprintf("IP route table %d dst %s dev %v via %v",
		r.Table, dst, r.AdapterLL, r.Gw)
}

// Type of the item.
func (r Route) Type() string {
	return genericitems.RouteTypename
}

// Equal is a comparison method for two equally-named route instances.
func (r Route) Equal(other depgraph.Item) bool {
	r2 := other.(Route)
	return r.Route.Equal(r2.Route)
}

// External returns false.
func (r Route) External() bool {
	return false
}

// String describes the network route.
func (r Route) String() string {
	return fmt.Sprintf("Network route for adapter %s: %+v",
		r.AdapterLL, r.Route)
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
	err := netlink.RouteAdd(&route.Route)
	if err != nil && err.Error() == "file exists" {
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
	return netlink.RouteDel(&route.Route)
}

// NeedsRecreate returns true - Modify is not implemented.
func (c *RouteConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
