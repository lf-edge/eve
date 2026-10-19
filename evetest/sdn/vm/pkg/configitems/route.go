// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Route : single route entry.
type Route struct {
	// NetNamespace : network namespace where the route should be created.
	NetNamespace string
	// DstNet : destination network that the route matches.
	// Mandatory argument (should not be nil).
	DstNet *net.IPNet
	// OutputIf : output interface for the routed traffic.
	// Leave undefined if the destination is unreachable.
	OutputIf RouteOutIf
	// Gw : IP address of the gateway to route the traffic via.
	// Leave undefined for unreachable or link-local destination.
	GwIP net.IP
	// Table : routing table to put the entry into.
	Table int
	// Metric : route metric (basically the "cost").
	// The higher the value, the lower the priority is.
	// Highest priority is 0, lowest is ^uint32(0).
	Metric uint32
}

// RouteOutIf : output interface for the route -- one of: VETH, physical interface, TUN.
type RouteOutIf struct {
	// VethName : logical name of the veth pair used as the output device for the route.
	// Define either PhysIf or VethName + VethPeerIfName.
	VethName string
	// VethPeerIfName : interface name of that side of the veth pair which the routed
	// traffic is entering.
	VethPeerIfName string
	// PhysIf : physical interface to use as the output device.
	// Define either PhysIf or VethName + VethPeerIfName.
	PhysIf PhysIf
	// TunIfName : TUN interface to use as the output device.
	TunIfName string
}

// Name returns the name of the route item.
func (r Route) Name() string {
	if r.outputIfRef() == "" {
		return fmt.Sprintf("%s/%d/%v",
			normNetNsName(r.NetNamespace), r.Table, r.DstNet)
	}
	return fmt.Sprintf("%s/%d/%v/%s",
		normNetNsName(r.NetNamespace), r.Table, r.DstNet, r.outputIfRef())
}

// Label returns the label of the route item.
func (r Route) Label() string {
	if r.outputIfRef() == "" {
		return fmt.Sprintf("IP route ns %s table %d dst %v is unreachable",
			normNetNsName(r.NetNamespace), r.Table, r.DstNet)
	}
	return fmt.Sprintf("IP route ns %s table %d dst %v dev %s via %v",
		normNetNsName(r.NetNamespace), r.Table, r.DstNet, r.outputIfRef(), r.GwIP)
}

func (r Route) outputIfRef() string {
	if r.OutputIf.VethName != "" {
		return r.OutputIf.VethName
	}
	if len(r.OutputIf.PhysIf.MAC) > 0 {
		return r.OutputIf.PhysIf.MAC.String()
	}
	if r.OutputIf.TunIfName != "" {
		return r.OutputIf.TunIfName
	}
	return ""
}

// Type returns the typename of the route item.
func (r Route) Type() string {
	return RouteTypename
}

// Equal is a comparison method for two equally-named Route instances.
func (r Route) Equal(other depgraph.Item) bool {
	r2 := other.(Route)
	// Every other attribute is part of the name.
	return r.GwIP.Equal(r2.GwIP) && r.Metric == r2.Metric
}

// External returns false.
func (r Route) External() bool {
	return false
}

// String describes Route.
func (r Route) String() string {
	return fmt.Sprintf("Route: %#+v", r)
}

// Dependencies lists the namespace and the output interface as dependencies.
// Note that we do not check if IP address(es) assigned to the output interface
// match with the route gateway (it would be a programming error in sdnagent/config.go
// if it didn't).
func (r Route) Dependencies() (deps []depgraph.Dependency) {
	deps = append(deps, depgraph.Dependency{
		RequiredItem: depgraph.ItemRef{
			ItemType: NetNamespaceTypename,
			ItemName: normNetNsName(r.NetNamespace),
		},
		Description: "Network namespace must exist",
	})
	switch {
	case r.OutputIf.VethName != "":
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: VethTypename,
				ItemName: r.OutputIf.VethName,
			},
			Description: "VETH interface must exist",
		})
	case len(r.OutputIf.PhysIf.MAC) > 0:
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: IfHandleTypename,
				ItemName: r.OutputIf.PhysIf.MAC.String(),
			},
			MustSatisfy: func(item depgraph.Item) bool {
				ifHandle := item.(IfHandle)
				return ifHandle.Usage == IfUsageL3
			},
			Description: "Physical network interface must exist and be used in the L3 mode",
		})
	case r.OutputIf.TunIfName != "":
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: TunTypename,
				ItemName: r.OutputIf.TunIfName,
			},
			Description: "TUN interface must exist",
		})
	}
	return deps
}

// RouteConfigurator implements Configurator interface for Route.
type RouteConfigurator struct {
	MacLookup *maclookup.MacLookup
}

// Create adds new route.
func (c *RouteConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	routeCfg := item.(Route)
	ns := normNetNsName(routeCfg.NetNamespace)
	if ns != MainNsName {
		// Move into the namespace with the route (leave on defer).
		revertNs, err := switchToNamespace(ns)
		if err != nil {
			return fmt.Errorf("failed to switch to net namespace %s: %w", ns, err)
		}
		defer revertNs()
	}
	netlinkRoute, err := c.buildNetlinkRoute(routeCfg)
	if err != nil {
		log.Error(err)
		return err
	}
	err = netlink.RouteAdd(netlinkRoute)
	if err != nil {
		if err.Error() == "file exists" {
			// Ignore duplicate route.
			return nil
		}
		err = fmt.Errorf("failed to add route %+v: %w", netlinkRoute, err)
		log.Error(err)
		return err
	}
	return nil
}

func (c *RouteConfigurator) buildNetlinkRoute(route Route) (*netlink.Route, error) {
	var (
		routeType    int
		outLinkIndex int
	)
	switch {
	case route.OutputIf.VethPeerIfName != "":
		ifName := route.OutputIf.VethPeerIfName
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return nil, fmt.Errorf("failed to get link for veth peer %q: %w", ifName, err)
		}
		outLinkIndex = link.Attrs().Index
	case len(route.OutputIf.PhysIf.MAC) > 0:
		mac := route.OutputIf.PhysIf.MAC
		netIf, found := c.MacLookup.GetInterfaceByMAC(mac, false)
		if !found {
			return nil, fmt.Errorf("failed to get physical interface with MAC %v", mac)
		}
		outLinkIndex = netIf.IfIndex
	case route.OutputIf.TunIfName != "":
		ifName := route.OutputIf.TunIfName
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return nil, fmt.Errorf("failed to get link for TUN %q: %w", ifName, err)
		}
		outLinkIndex = link.Attrs().Index
	default:
		routeType = unix.RTN_UNREACHABLE
	}
	return &netlink.Route{
		Table:     route.Table,
		Dst:       route.DstNet,
		LinkIndex: outLinkIndex,
		Gw:        route.GwIP,
		Type:      routeType,
		Priority:  int(route.Metric),
	}, nil
}

// Modify is not implemented (route is recreated on change).
func (c *RouteConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete removes route.
func (c *RouteConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	routeCfg := item.(Route)
	ns := normNetNsName(routeCfg.NetNamespace)
	if ns != MainNsName {
		// Move into the namespace with the route (leave on defer).
		revertNs, err := switchToNamespace(ns)
		if err != nil {
			return fmt.Errorf("failed to switch to net namespace %s: %w", ns, err)
		}
		defer revertNs()
	}
	netlinkRoute, err := c.buildNetlinkRoute(routeCfg)
	if err != nil {
		log.Error(err)
		return err
	}
	err = netlink.RouteDel(netlinkRoute)
	if err != nil {
		err = fmt.Errorf("failed to remove route %+v: %w", netlinkRoute, err)
		log.Error(err)
		return err
	}
	return nil
}

// NeedsRecreate returns true. Modify is not implemented.
func (c *RouteConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
