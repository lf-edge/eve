// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nireconciler

import (
	"fmt"
	"net"

	dg "github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/netmonitor"
	generic "github.com/lf-edge/eve/pkg/pillar/nireconciler/genericitems"
	linux "github.com/lf-edge/eve/pkg/pillar/nireconciler/linuxitems"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
	"github.com/vishvananda/netlink"
)

// Refresh the state of external items inside the Global subgraph of the current
// state depgraph.
func (r *LinuxNIReconciler) updateCurrentGlobalState(onlyPortsChanged bool) (changed bool) {
	var globalSG dg.Graph
	if readHandle := r.currentState.SubGraph(GlobalSG); readHandle != nil {
		globalSG = r.currentState.EditSubGraph(readHandle)
	} else {
		globalSG = dg.New(dg.InitArgs{Name: GlobalSG})
		r.currentState.PutSubGraph(globalSG)
	}
	// Refresh the current state of device ports.
	currentPorts := dg.New(dg.InitArgs{Name: PortsSG})
	for _, ni := range r.nis {
		if ni.deleted {
			continue
		}
		for _, port := range ni.bridge.Ports {
			var portIfName string
			switch ni.config.Type {
			case types.NetworkInstanceTypeSwitch:
				// If the port is used with an IP address, bridge.PortIfName should refer
				// to a bridge created by NIM for the port (wired, ethernet) interface.
				// NIM-created bridge will be used by the network instance directly
				// and Port config item will be used to refer to the bridged
				// physical interface.
				// L2-only ports are bridged by zedrouter (ports keep their original
				// interface names).
				portIfName = portPhysIfName(port)
			case types.NetworkInstanceTypeLocal:
				// bridge.PortIfName refers to a bridge created by NIM for the port
				// (wired, ethernet) interface or directly to a wireless physical interface.
				// However, it does not matter which case it is, Local NI will have its own
				// bridge and even if port refers to a bridge it will be used just as if it
				// was a physical interface.
				portIfName = port.IfName
			}
			ifIndex, found, err := r.netMonitor.GetInterfaceIndex(portIfName)
			if err != nil {
				r.log.Errorf("%s: updateCurrentGlobalState: failed to get ifIndex for %s: %v",
					LogAndErrPrefix, portIfName, err)
				continue
			}
			if !found {
				continue
			}
			ifAttrs, err := r.netMonitor.GetInterfaceAttrs(ifIndex)
			if err != nil {
				r.log.Errorf(
					"%s: updateCurrentGlobalState: failed to get interface %s attrs: %v",
					LogAndErrPrefix, portIfName, err)
				continue
			}
			var masterIfName string
			if ifAttrs.Enslaved {
				masterIfAttrs, err := r.netMonitor.GetInterfaceAttrs(ifAttrs.MasterIfIndex)
				if err != nil {
					r.log.Errorf("%s: updateCurrentGlobalState: failed to get attrs "+
						"for interface %s master (ifIndex: %d): %v",
						LogAndErrPrefix, portIfName, ifAttrs.MasterIfIndex, err)
					// Continue as if this port interface didn't have master...
				} else {
					masterIfName = masterIfAttrs.IfName
				}
			}
			ips, _, err := r.netMonitor.GetInterfaceAddrs(ifIndex)
			if err != nil {
				r.log.Errorf(
					"%s: updateCurrentGlobalState: failed to get interface %s addresses: %v",
					LogAndErrPrefix, portIfName, err)
				// Continue as if this port interface didn't have any IP addresses...
			}
			currentPorts.PutItem(generic.Port{
				IfName:       portIfName,
				LogicalLabel: port.LogicalLabel,
				MasterIfName: masterIfName,
				AdminUp:      ifAttrs.AdminUp,
				IPAddresses:  ips,
			}, &reconciler.ItemStateData{
				State:         reconciler.ItemStateCreated,
				LastOperation: reconciler.OperationCreate,
			})
		}
	}
	prevPorts := globalSG.SubGraph(PortsSG)
	if prevPorts == nil || len(prevPorts.DiffItems(currentPorts)) > 0 {
		globalSG.PutSubGraph(currentPorts)
		changed = true
	}
	if !onlyPortsChanged || globalSG.SubGraph(ACLRootChainsSG) == nil {
		// Refresh the current state of external iptables chains.
		// XXX For now assume that all application chains were created by NIM
		// successfully. Later we could improve this and actually check for their
		// presence using iptables CLI. But then we also need to make the iptables
		// chain retrieval replaceable with a mock for unit testing purposes.
		currentACLRoot := dg.New(dg.InitArgs{Name: ACLRootChainsSG})
		ipv4Chains := dg.New(dg.InitArgs{Name: IPv4ChainsSG})
		currentACLRoot.PutSubGraph(ipv4Chains)
		ipv6Chains := dg.New(dg.InitArgs{Name: IPv6ChainsSG})
		currentACLRoot.PutSubGraph(ipv6Chains)
		for table, chains := range usedIptablesChains {
			for _, forIPv6 := range []bool{false, true} {
				sg := ipv4Chains
				if forIPv6 {
					sg = ipv6Chains
				}
				for _, chain := range chains {
					sg.PutItem(iptables.Chain{
						ChainName:  appChain(chain),
						Table:      table,
						ForIPv6:    forIPv6,
						PreCreated: true,
					}, &reconciler.ItemStateData{
						State:         reconciler.ItemStateCreated,
						LastOperation: reconciler.OperationCreate,
					})
				}
			}
		}
		prevACLRoot := globalSG.SubGraph(ACLRootChainsSG)
		if prevACLRoot == nil || len(prevACLRoot.DiffItems(currentACLRoot)) > 0 {
			globalSG.PutSubGraph(currentACLRoot)
			changed = true
		}
	}
	return changed
}

func (r *LinuxNIReconciler) updateCurrentNIState(niID uuid.UUID) (changed bool) {
	changed = r.updateCurrentNIBridge(niID)
	changed = r.updateCurrentNIRoutes(niID) || changed
	changed = r.updateCurrentVIFs(niID) || changed
	return changed
}

// Update the external bridge inside the depgraph for the current state of the given NI
// to reflect the set of external (configured by NIM) bridges actually present
// inside the network stack at the current moment.
func (r *LinuxNIReconciler) updateCurrentNIBridge(niID uuid.UUID) (changed bool) {
	ni := r.nis[niID]
	niSG := r.getOrAddNISubgraph(niID)
	var l2SG dg.Graph
	if readHandle := niSG.SubGraph(L2SG); readHandle != nil {
		l2SG = niSG.EditSubGraph(readHandle)
	} else {
		l2SG = dg.New(dg.InitArgs{Name: L2SG})
		niSG.PutSubGraph(l2SG)
	}
	var prevExtBridge dg.Item
	iter := l2SG.Items(false)
	for iter.Next() {
		item, _ := iter.Item()
		if item.Type() == linux.BridgeTypename && item.External() {
			prevExtBridge = item
			// There should be only one external bridge...
			break
		}
	}
	if !r.niBridgeIsCreatedByNIM(ni.config, ni.bridge) {
		return r.updateSingleItem(prevExtBridge, nil, l2SG)
	}
	ips, _, mac, found, err := r.getBridgeAddrs(niID)
	if err != nil {
		r.log.Errorf("%s: updateCurrentNIBridge: getBridgeAddrs(%s) failed: %v",
			LogAndErrPrefix, niID, err)
		return r.updateSingleItem(prevExtBridge, nil, l2SG)
	}
	if !found {
		return r.updateSingleItem(prevExtBridge, nil, l2SG)
	}
	mtu, err := r.getBridgeMTU(niID)
	if err != nil {
		r.log.Errorf("%s: updateCurrentNIBridge: getBridgeMTU(%s) failed: %v",
			LogAndErrPrefix, niID, err)
		return r.updateSingleItem(prevExtBridge, nil, l2SG)
	}
	bridge := linux.Bridge{
		IfName:       ni.brIfName,
		CreatedByNIM: true,
		MACAddress:   mac,
		IPAddresses:  ips,
		MTU:          mtu,
		WithSTP:      false,
	}
	return r.updateSingleItem(prevExtBridge, bridge, l2SG)
}

// Update the set of routes inside the depgraph for the current state of the given NI
// to reflect the set of routes actually configured inside the network stack
// at the present moment.
func (r *LinuxNIReconciler) updateCurrentNIRoutes(niID uuid.UUID) (changed bool) {
	ni := r.nis[niID]
	niSG := r.getOrAddNISubgraph(niID)
	var l3SG dg.Graph
	if readHandle := niSG.SubGraph(L3SG); readHandle != nil {
		l3SG = niSG.EditSubGraph(readHandle)
	} else {
		l3SG = dg.New(dg.InitArgs{Name: L3SG})
		niSG.PutSubGraph(l3SG)
	}
	prevRoutes := make(map[dg.ItemRef]dg.Item)
	iter := l3SG.Items(false)
	for iter.Next() {
		item, _ := iter.Item()
		if item.Type() == generic.IPv4RouteTypename ||
			item.Type() == generic.IPv6RouteTypename {
			prevRoutes[dg.Reference(item)] = item
		}
	}
	defer func() {
		// Remove obsolete route(s) at the end.
		for itemRef := range prevRoutes {
			l3SG.DelItem(itemRef)
			changed = true
		}
		if changed {
			r.log.Noticef("%s: Current state of IP routes of NI %s has been updated",
				LogAndErrPrefix, niID)
		}
	}()
	// Switch NI does not use routes.
	if ni.config.Type == types.NetworkInstanceTypeSwitch {
		return changed
	}
	table := types.NIBaseRTIndex + ni.bridge.BrNum
	routes, err := r.netMonitor.ListRoutes(netmonitor.RouteFilters{
		FilterByTable: true,
		Table:         table,
	})
	if err != nil {
		r.log.Errorf("%s: updateCurrentNIRoutes: ListRoutes failed for table %d: %v",
			LogAndErrPrefix, table, err)
	}
	for _, rt := range routes {
		var rtOutIf generic.NetworkIf
		if rt.IfIndex > 0 {
			ifAttrs, err := r.netMonitor.GetInterfaceAttrs(rt.IfIndex)
			if err != nil {
				r.log.Errorf("%s: updateCurrentNIRoutes: failed to get attributes "+
					"for interface with index %d: %v", LogAndErrPrefix, rt.IfIndex, err)
				continue
			}
			if ifAttrs.IfName == ni.brIfName {
				// Output interface for this route is bridge.
				rtOutIf = generic.NetworkIf{
					IfName:  ni.brIfName,
					ItemRef: dg.Reference(linux.Bridge{IfName: ni.brIfName}),
				}
			} else {
				// Output interface for this route is a physical network port.
				rtOutIf = generic.NetworkIf{
					IfName:  ifAttrs.IfName,
					ItemRef: dg.Reference(generic.Port{IfName: ifAttrs.IfName}),
				}
			}
		}
		route := linux.Route{
			Route:          rt.Data.(netlink.Route),
			OutputIf:       rtOutIf,
			GwViaLinkRoute: gwViaLinkRoute(rt, routes),
		}
		prevRoute := prevRoutes[dg.Reference(route)]
		if prevRoute == nil || !prevRoute.Equal(route) {
			l3SG.PutItem(route, &reconciler.ItemStateData{
				State:         reconciler.ItemStateCreated,
				LastOperation: reconciler.OperationCreate,
			})
			changed = true
		}
		// Remove from the list of no-longer-existing routes,
		// which are deleted from the graph by defer function (see above).
		delete(prevRoutes, dg.Reference(route))
	}
	return changed
}

// Update the set of VIFs inside the depgraph for the current state of the given NI
// to reflect the set of VIFs actually present inside the network stack
// at the current moment.
func (r *LinuxNIReconciler) updateCurrentVIFs(niID uuid.UUID) (changed bool) {
	if r.withKubernetesNetworking {
		// With Kubernetes networking, VIFs are not external, but configured by zedrouter.
		return false
	}
	niSG := r.getOrAddNISubgraph(niID)
	prevVIFs := make(map[dg.ItemRef]dg.Item)
	iter := niSG.Items(true)
	for iter.Next() {
		item, _ := iter.Item()
		if item.Type() == linux.VIFTypename {
			prevVIFs[dg.Reference(item)] = item
		}
	}
	defer func() {
		// Remove obsolete VIFs at the end.
		// These are VIFs that we no longer care about - app connection un-configured
		// while domain is yet to be removed by domainmgr.
		for itemRef := range prevVIFs {
			_, _, path, _ := niSG.Item(itemRef)
			changed = dg.DelItemFrom(niSG, itemRef, path) || changed
		}
	}()
	for _, app := range r.apps {
		if app.deleted {
			continue
		}
		for _, vif := range app.vifs {
			if vif.NI != niID {
				continue
			}
			delete(prevVIFs, dg.Reference(linux.VIF{HostIfName: vif.hostIfName}))
			sgName := AppConnSGName(app.config.UUIDandVersion.UUID, vif.NetAdapterName)
			var appConnSG dg.Graph
			if readHandle := niSG.SubGraph(sgName); readHandle != nil {
				appConnSG = niSG.EditSubGraph(readHandle)
			} else {
				appConnSG = dg.New(dg.InitArgs{Name: sgName})
				niSG.PutSubGraph(appConnSG)
			}
			var prevVIF dg.Item
			iter := appConnSG.Items(false)
			for iter.Next() {
				item, _ := iter.Item()
				if item.Type() == linux.VIFTypename {
					prevVIF = item
					// There should be only one VIF...
					break
				}
			}
			_, found, err := r.netMonitor.GetInterfaceIndex(vif.hostIfName)
			if err != nil {
				r.log.Errorf("%s: updateCurrentVIFs: failed to get ifIndex "+
					"for (VIF) %s: %v", LogAndErrPrefix, vif.hostIfName, err)
				changed = r.updateSingleItem(prevVIF, nil, appConnSG) || changed
				continue
			}
			if !found {
				changed = r.updateSingleItem(prevVIF, nil, appConnSG) || changed
				continue
			}
			newVIF := linux.VIF{
				HostIfName:     vif.hostIfName,
				NetAdapterName: vif.NetAdapterName,
				Variant:        linux.VIFVariant{External: true},
			}
			changed = r.updateSingleItem(prevVIF, newVIF, appConnSG) || changed
		}
	}
	return changed
}

func (r *LinuxNIReconciler) getBridgeAddrs(niID uuid.UUID) (ipsWithSubnet,
	ipsWithHostSubnet []*net.IPNet, mac net.HardwareAddr, found bool, err error) {
	ni := r.nis[niID]
	switch ni.config.Type {
	case types.NetworkInstanceTypeSwitch:
		if r.niBridgeIsCreatedByNIM(ni.config, ni.bridge) {
			var ifIndex int
			ifIndex, found, err = r.netMonitor.GetInterfaceIndex(ni.brIfName)
			if err != nil || !found {
				return
			}
			var ips []*net.IPNet
			ips, mac, err = r.netMonitor.GetInterfaceAddrs(ifIndex)
			if err != nil {
				return
			}
			// Take global unicast IPs.
			for _, ip := range ips {
				if ip.IP.IsGlobalUnicast() {
					ipsWithSubnet = append(ipsWithSubnet, ip)
					ipsWithHostSubnet = append(ipsWithHostSubnet,
						netutils.HostSubnet(ip.IP))
				}
			}
			return
		}
		fallthrough // bridge created by zedrouter
	case types.NetworkInstanceTypeLocal:
		if ni.bridge.IPAddress != nil {
			ipsWithSubnet = append(ipsWithSubnet, ni.bridge.IPAddress)
			ipsWithHostSubnet = append(ipsWithHostSubnet,
				netutils.HostSubnet(ni.bridge.IPAddress.IP))
		}
		mac = ni.bridge.MACAddress
		found = true
		return
	}
	// unreachable
	err = fmt.Errorf("unsupported NI type: %v", ni.config.Type)
	return
}

func (r *LinuxNIReconciler) getBridgeMTU(niID uuid.UUID) (mtu uint16, err error) {
	ni := r.nis[niID]
	switch ni.config.Type {
	case types.NetworkInstanceTypeSwitch:
		if r.niBridgeIsCreatedByNIM(ni.config, ni.bridge) {
			ifIndex, found, err := r.netMonitor.GetInterfaceIndex(ni.brIfName)
			if !found {
				err = fmt.Errorf("bridge %s does not exist", ni.brIfName)
			}
			if err != nil {
				return 0, err
			}
			ifAttrs, err := r.netMonitor.GetInterfaceAttrs(ifIndex)
			if err != nil {
				return 0, err
			}
			return ifAttrs.MTU, nil
		}
		fallthrough // bridge created by zedrouter
	case types.NetworkInstanceTypeLocal:
		return ni.bridge.MTU, nil
	}
	// unreachable
	return 0, fmt.Errorf("unsupported NI type: %v", ni.config.Type)
}

func (r *LinuxNIReconciler) updateSingleItem(
	prev, new dg.Item, graph dg.Graph) (changed bool) {
	if prev == nil && new == nil {
		return false
	}
	if new == nil {
		graph.DelItem(dg.Reference(prev))
		return true
	}
	state := &reconciler.ItemStateData{
		State:         reconciler.ItemStateCreated,
		LastOperation: reconciler.OperationCreate,
	}
	if prev == nil {
		graph.PutItem(new, state)
		return true
	}
	sameRef := dg.Reference(prev) == dg.Reference(new)
	if !sameRef || !prev.Equal(new) {
		graph.PutItem(new, state)
		changed = true
	}
	if !sameRef {
		graph.DelItem(dg.Reference(prev))
		changed = true
	}
	return changed
}

func (r *LinuxNIReconciler) getOrAddNISubgraph(niID uuid.UUID) dg.Graph {
	sgName := NIToSGName(niID)
	var niSG dg.Graph
	if readHandle := r.currentState.SubGraph(sgName); readHandle != nil {
		niSG = r.currentState.EditSubGraph(readHandle)
	} else {
		niSG = dg.New(dg.InitArgs{Name: sgName})
		r.currentState.PutSubGraph(niSG)
	}
	return niSG
}
