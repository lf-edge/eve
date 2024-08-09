// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"fmt"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/nireconciler"
	"github.com/lf-edge/eve/pkg/pillar/nistate"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
)

// Return arguments describing network instance config as required by NIStateCollector
// for collecting of state information (IP assignments, flows, metrics).
func (z *zedrouter) getArgsForNIStateCollecting(niID uuid.UUID) (
	br nistate.NIBridge, vifs []nistate.AppVIF, err error) {
	niStatus := z.lookupNetworkInstanceStatus(niID.String())
	if niStatus == nil {
		return br, vifs, fmt.Errorf("failed to get status for network instance %v", niID)
	}
	br.NI = niID
	br.BrNum = niStatus.BridgeNum
	br.BrIfName = niStatus.BridgeName
	br.BrIfMAC = niStatus.BridgeMac
	// Find all app instances that (actively) use this network.
	apps := z.pubAppNetworkStatus.GetAll()
	for _, app := range apps {
		appNetStatus := app.(types.AppNetworkStatus)
		if !appNetStatus.Activated {
			continue
		}
		appNetConfig := z.lookupAppNetworkConfig(appNetStatus.Key())
		if appNetConfig == nil || !appNetConfig.Activate {
			continue
		}
		for _, adapterStatus := range appNetStatus.GetAdaptersStatusForNI(niID) {
			vifs = append(vifs, nistate.AppVIF{
				App:            appNetStatus.UUIDandVersion.UUID,
				NI:             niID,
				AppNum:         appNetStatus.AppNum,
				NetAdapterName: adapterStatus.Name,
				HostIfName:     adapterStatus.Vif,
				GuestIfMAC:     adapterStatus.Mac,
			})
		}
	}
	return br, vifs, nil
}

// Return arguments describing network instance bridge config as required by NIReconciler.
func (z *zedrouter) getNIBridgeConfig(
	status *types.NetworkInstanceStatus) nireconciler.NIBridge {
	var ipAddr *net.IPNet
	if status.BridgeIPAddr != nil {
		ipAddr = &net.IPNet{
			IP:   status.BridgeIPAddr,
			Mask: status.Subnet.Mask,
		}
	}
	var staticRoutes []nireconciler.IPRoute
	for _, route := range status.IntendedRoutes {
		if route.RunningPortProbing && route.SelectedPort == "" {
			continue
		}
		if route.Gateway == nil && route.SelectedPort == "" {
			continue
		}
		staticRoutes = append(staticRoutes, nireconciler.IPRoute{
			DstNetwork: route.DstNetwork,
			Gateway:    route.Gateway,
			OutputPort: route.SelectedPort,
		})
	}
	return nireconciler.NIBridge{
		NI:           status.UUID,
		BrNum:        status.BridgeNum,
		MACAddress:   status.BridgeMac,
		IPAddress:    ipAddr,
		Ports:        z.getNIPortConfig(status),
		StaticRoutes: staticRoutes,
		IPConflict:   status.IPConflictErr.HasError(),
		MTU:          status.MTU,
	}
}

func (z *zedrouter) getNIPortConfig(
	status *types.NetworkInstanceStatus) (portConfigs []nireconciler.Port) {
	if len(status.Ports) == 0 {
		// Air-gapped
		return nil
	}
	for _, portLL := range status.Ports {
		port := z.deviceNetworkStatus.LookupPortByLogicallabel(portLL)
		if port == nil {
			continue
		}
		portConfigs = append(portConfigs, nireconciler.Port{
			LogicalLabel: port.Logicallabel,
			SharedLabels: port.SharedLabels,
			IfName:       port.IfName,
			IsMgmt:       port.IsMgmt,
			MTU:          port.MTU,
			DNSServers:   types.GetDNSServers(*z.deviceNetworkStatus, port.IfName),
			NTPServers:   types.GetNTPServers(*z.deviceNetworkStatus, port.IfName),
		})
	}
	return portConfigs
}

// Update the selection of device ports matching the port label.
func (z *zedrouter) updateNIPorts(status *types.NetworkInstanceStatus) (
	changed bool, err error) {
	var (
		newPorts             []*types.NetworkPortStatus
		newPortLogicalLabels []string
		newNTPServers        []net.IP
	)
	if status.NtpServer != nil {
		// The NTP server explicitly configured for the NI.
		newNTPServers = append(newNTPServers, status.NtpServer)
	}
	if status.PortLabel != "" {
		newPorts = z.deviceNetworkStatus.LookupPortsByLabel(status.PortLabel)
		for _, port := range newPorts {
			newPortLogicalLabels = append(newPortLogicalLabels, port.Logicallabel)
			if port.NtpServer != nil {
				// The NTP server explicitly configured for the port.
				newNTPServers = append(newNTPServers, port.NtpServer)
			}
			// NTP servers received via DHCP.
			newNTPServers = append(newNTPServers, port.NtpServers...)
		}
	}
	newNTPServers = generics.FilterDuplicatesFn(newNTPServers, netutils.EqualIPs)
	changed = changed || !generics.EqualSets(status.Ports, newPortLogicalLabels)
	status.Ports = newPortLogicalLabels
	changed = changed || !generics.EqualSetsFn(status.NTPServers, newNTPServers,
		netutils.EqualIPs)
	status.NTPServers = newNTPServers
	if status.PortLabel != "" && len(status.Ports) == 0 {
		// This is potentially a transient state, wait for DNS update.
		return changed, fmt.Errorf("no port is matching label '%s'", status.PortLabel)
	}
	for _, port := range newPorts {
		if port.InvalidConfig {
			return changed, fmt.Errorf("port %s has invalid config: %s",
				port.Logicallabel, port.LastError)
		}
	}
	// Update BridgeMac for switch NI port created by NIM.
	if status.IsUsingPortBridge() && len(newPorts) == 1 {
		// Note that for switch NI we do not support multiple ports yet.
		ifName := newPorts[0].IfName
		if ifIndex, exists, _ := z.networkMonitor.GetInterfaceIndex(ifName); exists {
			_, ifMAC, _ := z.networkMonitor.GetInterfaceAddrs(ifIndex)
			changed = changed || !bytes.Equal(ifMAC, status.BridgeMac)
			status.BridgeMac = ifMAC
		}
	}
	return changed, nil
}

func (z *zedrouter) updateNIRoutes(status *types.NetworkInstanceStatus,
	forceRecreate bool) (changed bool) {
	if status.Type != types.NetworkInstanceTypeLocal {
		return false
	}
	var hasDefaultRoute bool
	var newRoutes []types.IPRouteConfig
	for _, route := range status.StaticRoutes {
		if route.IsDefaultRoute() {
			hasDefaultRoute = true
		}
		newRoutes = append(newRoutes, route)
	}
	if !hasDefaultRoute {
		var anyDst *net.IPNet
		if status.Subnet.IP.To4() != nil {
			_, anyDst, _ = net.ParseCIDR("0.0.0.0/0")
		} else {
			_, anyDst, _ = net.ParseCIDR("::/0")
		}
		switch status.PortLabel {
		case types.UplinkLabel, types.FreeUplinkLabel:
			// Backward-compatible default route configuration.
			newRoutes = append(newRoutes, types.IPRouteConfig{
				DstNetwork:      anyDst,
				OutputPortLabel: status.PortLabel,
				PortProbe: types.NIPortProbe{
					EnabledGwPing: true,
					GwPingMaxCost: 0,
					UserDefinedProbe: types.ConnectivityProbe{
						Method:    types.ConnectivityProbeMethodTCP,
						ProbeHost: z.controllerHostname,
						ProbePort: z.controllerPort,
					},
				},
				PreferLowerCost:          true,
				PreferStrongerWwanSignal: false,
			})
		default:
			// XXX We could improve this condition and check if there are multiple
			// ports which actually have gateway IP assigned.
			if len(status.Ports) > 1 {
				newRoutes = append(newRoutes, types.IPRouteConfig{
					DstNetwork:      anyDst,
					OutputPortLabel: status.PortLabel,
					PortProbe: types.NIPortProbe{
						EnabledGwPing: true,
						GwPingMaxCost: 0,
					},
					PreferLowerCost:          true,
					PreferStrongerWwanSignal: false,
				})
			}
		}
	}
	// Remove or update existing routes.
	var newIntended []types.IPRouteStatus
	for _, routeStatus := range status.IntendedRoutes {
		var (
			newConfig *types.IPRouteConfig
			newStatus *types.IPRouteStatus
		)
		for i := range newRoutes {
			if netutils.EqualIPNets(routeStatus.DstNetwork, newRoutes[i].DstNetwork) {
				newConfig = &newRoutes[i]
				break
			}
		}
		newStatus, changed = z.reconcileNIRouteProbing(
			status, &routeStatus, newConfig, forceRecreate)
		if newStatus != nil {
			newIntended = append(newIntended, *newStatus)
		}
	}
	// Next add new routes.
	for _, newRoute := range newRoutes {
		var routeStatus *types.IPRouteStatus
		for _, route := range status.IntendedRoutes {
			if netutils.EqualIPNets(newRoute.DstNetwork, route.DstNetwork) {
				routeStatus = &route
			}
		}
		if routeStatus == nil {
			routeStatus, changed = z.reconcileNIRouteProbing(
				status, nil, &newRoute, forceRecreate)
			newIntended = append(newIntended, *routeStatus)
		}
	}
	status.IntendedRoutes = newIntended
	return changed
}

func (z *zedrouter) reconcileNIRouteProbing(niStatus *types.NetworkInstanceStatus,
	routeStatus *types.IPRouteStatus, newConfig *types.IPRouteConfig,
	forceRecreate bool) (newStatus *types.IPRouteStatus, changed bool) {
	configChanged := routeStatus != nil && newConfig != nil &&
		!routeStatus.IPRouteConfig.Equal(*newConfig)
	stopProbing := routeStatus != nil && routeStatus.RunningPortProbing &&
		(newConfig == nil || configChanged || forceRecreate)
	if stopProbing {
		changed = true
		routeStatus.ClearError()
		err := z.portProber.StopPortProbing(niStatus.UUID, routeStatus.DstNetwork)
		if err != nil {
			err = fmt.Errorf(
				"failed to stop port probing for route: dst=%v, ni=%v",
				routeStatus.DstNetwork, niStatus.UUID)
			z.log.Error(err)
			routeStatus.SetErrorNow(err.Error())
		}
		routeStatus.RunningPortProbing = false
		routeStatus.SelectedPort = ""
	}
	startProbing := newConfig != nil && newConfig.OutputPortLabel != "" &&
		(routeStatus == nil || configChanged || forceRecreate)
	if routeStatus == nil {
		routeStatus = &types.IPRouteStatus{
			IPRouteConfig: *newConfig,
		}
	}
	if startProbing {
		changed = true
		routeStatus.ClearError()
		port := z.deviceNetworkStatus.LookupPortByLogicallabel(
			newConfig.OutputPortLabel)
		if port != nil {
			// Uses single port referenced by a logical label.
			// Not need to probe.
			routeStatus.SelectedPort = port.Logicallabel
		} else {
			// Most likely a shared label for the output port.
			probeStatus, err := z.portProber.StartPortProbing(
				niStatus.UUID, niStatus.PortLabel, *newConfig)
			if err != nil {
				err = fmt.Errorf(
					"failed to start port probing for route: dst=%v, ni=%v",
					newConfig.DstNetwork, niStatus.UUID)
				z.log.Error(err)
				routeStatus.SetErrorNow(err.Error())
			} else {
				routeStatus.SelectedPort = probeStatus.SelectedPortLL
				routeStatus.RunningPortProbing = true
				if routeStatus.SelectedPort == "" {
					err = fmt.Errorf("%v is not matching any port", newConfig)
					z.log.Error(err)
					routeStatus.SetErrorNow(err.Error())
				}
			}
		}
	}
	if newConfig == nil {
		// Route should be removed from the Intended route list.
		routeStatus = nil
	} else if configChanged {
		// Update config
		routeStatus.IPRouteConfig = *newConfig
	}
	return routeStatus, changed
}

// This function is called when PortProber changes port selected for a given
// (multipath) route.
func (z *zedrouter) updateNIRoutePort(route types.IPRouteConfig, port string,
	status *types.NetworkInstanceStatus, config types.NetworkInstanceConfig) {
	var routeStatus *types.IPRouteStatus
	for i := range status.IntendedRoutes {
		if netutils.EqualIPNets(status.IntendedRoutes[i].DstNetwork, route.DstNetwork) {
			routeStatus = &status.IntendedRoutes[i]
		}
	}
	if routeStatus == nil {
		z.log.Warnf("Received port update for unknown route (ni: %s, route: %+v, port: %s)",
			status.UUID, route, port)
		return
	}
	if routeStatus.SelectedPort == port {
		// No actual change.
		return
	}
	routeStatus.SelectedPort = port
	if routeStatus.SelectedPort == "" {
		err := fmt.Errorf("%v is not matching any port", routeStatus.IPRouteConfig)
		if routeStatus.Error != err.Error() {
			z.log.Error(err)
			routeStatus.SetErrorNow(err.Error())
		}
	} else {
		routeStatus.ClearError()
	}
	if status.Activated {
		z.doUpdateActivatedNetworkInstance(config, status)
	}
	z.publishNetworkInstanceStatus(status)
}

func (z *zedrouter) doActivateNetworkInstance(config types.NetworkInstanceConfig,
	status *types.NetworkInstanceStatus) {
	// Create network instance inside the network stack.
	niRecStatus, err := z.niReconciler.AddNI(
		z.runCtx, config, z.getNIBridgeConfig(status))
	if err != nil {
		z.log.Errorf("Failed to activate network instance %s: %v", status.UUID, err)
		status.ReconcileErr.SetErrorNow(err.Error())
		z.publishNetworkInstanceStatus(status)
		return
	}
	z.log.Functionf("Activated network instance %s (%s)", status.UUID,
		status.DisplayName)
	z.processNIReconcileStatus(niRecStatus, status)
	status.Activated = true
	z.publishNetworkInstanceStatus(status)
	// Start collecting state data and metrics for this network instance.
	br, vifs, err := z.getArgsForNIStateCollecting(config.UUID)
	if err == nil {
		err = z.niStateCollector.StartCollectingForNI(
			config, br, vifs, z.enableArpSnooping)
	}
	if err != nil {
		z.log.Error(err)
	}
}

func (z *zedrouter) doInactivateNetworkInstance(status *types.NetworkInstanceStatus) {
	err := z.niStateCollector.StopCollectingForNI(status.UUID)
	if err != nil {
		z.log.Error(err)
	}
	niRecStatus, err := z.niReconciler.DelNI(z.runCtx, status.UUID)
	if err != nil {
		z.log.Errorf("Failed to deactivate network instance %s: %v", status.UUID, err)
		status.ReconcileErr.SetErrorNow(err.Error())
		z.publishNetworkInstanceStatus(status)
		return
	}
	z.log.Functionf("Deactivated network instance %s (%s)", status.UUID,
		status.DisplayName)
	z.processNIReconcileStatus(niRecStatus, status)
	status.Activated = false
	z.publishNetworkInstanceStatus(status)
}

func (z *zedrouter) doUpdateActivatedNetworkInstance(config types.NetworkInstanceConfig,
	status *types.NetworkInstanceStatus) {
	niRecStatus, err := z.niReconciler.UpdateNI(
		z.runCtx, config, z.getNIBridgeConfig(status))
	if err != nil {
		z.log.Errorf("Failed to update activated network instance %s: %v",
			status.UUID, err)
		status.ReconcileErr.SetErrorNow(err.Error())
		z.publishNetworkInstanceStatus(status)
		return
	}
	z.log.Functionf("Updated activated network instance %s (%s)", status.UUID,
		status.DisplayName)
	z.processNIReconcileStatus(niRecStatus, status)
	_, vifs, err := z.getArgsForNIStateCollecting(config.UUID)
	if err == nil {
		err = z.niStateCollector.UpdateCollectingForNI(config, vifs)
	}
	if err != nil {
		z.log.Error(err)
	}
	z.publishNetworkInstanceStatus(status)
}

// maybeDelOrInactivateNetworkInstance checks if the VIFs are gone and if so deletes
// or at least inactivates NI.
func (z *zedrouter) maybeDelOrInactivateNetworkInstance(
	status *types.NetworkInstanceStatus) bool {
	// Any remaining numbers allocated to application interfaces on this network instance?
	allocator := z.getOrAddAppIntfAllocator(status.UUID)
	count, _ := allocator.AllocatedCount()
	z.log.Noticef("maybeDelOrInactivateNetworkInstance(%s): refcount=%d VIFs=%+v",
		status.Key(), count, status.Vifs)
	if count != 0 {
		return false
	}

	config := z.lookupNetworkInstanceConfig(status.Key())
	if config != nil && config.Activate {
		z.log.Noticef(
			"maybeDelOrInactivateNetworkInstance(%s): NI should remain activated",
			status.Key())
		return false
	}

	if config != nil {
		// Should be only inactivated, not yet deleted.
		if status.Activated {
			z.doInactivateNetworkInstance(status)
		}
		return true
	}

	z.delNetworkInstance(status)
	z.log.Noticef("maybeDelOrInactivateNetworkInstance(%s) done", status.Key())
	return true
}

func (z *zedrouter) delNetworkInstance(status *types.NetworkInstanceStatus) {
	if status.Activated {
		z.doInactivateNetworkInstance(status)
		// Status will be unpublished when async operations of NI inactivation complete.
	} else {
		z.unpublishNetworkInstanceStatus(status)
	}
	for _, route := range status.IntendedRoutes {
		if route.RunningPortProbing {
			err := z.portProber.StopPortProbing(status.UUID, route.DstNetwork)
			if err != nil {
				z.log.Error(err)
			}
		}
	}
	if status.BridgeNum != 0 {
		bridgeNumKey := types.UuidToNumKey{UUID: status.UUID}
		err := z.bridgeNumAllocator.Free(bridgeNumKey, false)
		if err != nil {
			z.log.Errorf(
				"failed to free number allocated for network instance bridge %s: %v",
				status.UUID, err)
		}
	}
	err := z.delAppIntfAllocator(status.UUID)
	if err != nil {
		// Should be unreachable.
		z.log.Fatal(err)
	}

	z.deleteNetworkInstanceMetrics(status.Key())
}

// Called when a NetworkInstance is deleted or modified, or when a device port IP is
// added or removed, to check if there are new IP conflicts or if some existing
// have been resolved.
func (z *zedrouter) checkAllNetworkInstanceIPConflicts() {
	for _, item := range z.pubNetworkInstanceStatus.GetAll() {
		niStatus := item.(types.NetworkInstanceStatus)
		niConfig := z.lookupNetworkInstanceConfig(niStatus.Key())
		if niConfig == nil {
			continue
		}
		conflictErr := z.checkNetworkInstanceIPConflicts(niConfig)
		if conflictErr == nil && niStatus.IPConflictErr.HasError() {
			// IP conflict was resolved.
			niStatus.IPConflictErr.ClearError()
			if niStatus.Activated {
				// Local NI was initially activated prior to the IP conflict.
				// Subsequently, when the IP conflict arose, it was almost completely
				// un-configured (only preserving app VIFs) to keep device connectivity
				// unaffected. Now, it can be restored to full functionality.
				z.log.Noticef("Updating NI %s (%s) now that IP conflict "+
					"is not present anymore", niConfig.UUID, niConfig.DisplayName)
				// This also publishes the new status.
				z.doUpdateActivatedNetworkInstance(*niConfig, &niStatus)
			} else {
				// NI is not in an active state (nothing configured in the network stack).
				// We can simply re-create the network instance now that the IP conflict
				// is gone.
				z.log.Noticef("Recreating NI %s (%s) now that IP conflict "+
					"is not present anymore", niConfig.UUID, niConfig.DisplayName)
				// First release whatever has been already allocated for this NI.
				z.delNetworkInstance(&niStatus)
				z.handleNetworkInstanceCreate(nil, niConfig.Key(), *niConfig)
			}
		}
		if conflictErr != nil && !niStatus.IPConflictErr.HasError() {
			// New IP conflict arose.
			z.log.Error(conflictErr)
			niStatus.IPConflictErr.SetErrorNow(conflictErr.Error())
			z.publishNetworkInstanceStatus(&niStatus)
			if niStatus.Activated {
				// Local NI is already activated. Instead of removing it and halting
				// all connected applications (which can lead to loss of data), we
				// un-configure everything but app VIFs, which will be set DOWN
				// on the host side. User has a chance to fix the configuration.
				// When IP conflict is removed, NI will be automatically fully restored.
				z.log.Noticef("Updating NI %s (%s) after detecting an IP conflict (%s)",
					niConfig.UUID, niConfig.DisplayName, conflictErr)
				z.doUpdateActivatedNetworkInstance(*niConfig, &niStatus)
			}
		}
	}
}
