// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
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
	br.MirrorIfName = niStatus.MirrorIfName
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

func (z *zedrouter) attachNTPServersToPortConfigs(portConfigs []nireconciler.Port) {
	for i := range portConfigs {
		pc := &portConfigs[i]
		ntpServerIPs, ntpServerDomainsOrIPs := types.GetNTPServers(*z.deviceNetworkStatus, pc.IfName)

		ntpServers := make([]net.IP, 0, len(ntpServerDomainsOrIPs))
		for _, ntpServer := range ntpServerDomainsOrIPs {
			ip := net.ParseIP(ntpServer)
			if ip != nil {
				ntpServers = append(ntpServers, ip)
				continue
			}
			z.pubSub.StillRunning(agentName, warningTime, errorTime)
			dnsResponses, err := controllerconn.ResolveWithPortsLambda(
				ntpServer,
				*z.deviceNetworkStatus,
				controllerconn.ResolveCacheWrap(controllerconn.ResolveWithSrcIP),
			)
			if err != nil {
				z.log.Warnf("could not resolve '%s': %v", ntpServer, err)
			}

			for _, dnsResponse := range dnsResponses {
				ntpServers = append(ntpServers, dnsResponse.IP)
			}
		}

		ntpServers = append(ntpServers, ntpServerIPs...)
		generics.FilterDuplicatesFn(ntpServers, netutils.EqualIPs)

		pc.NTPServers = ntpServers
	}
}

// NTP servers are set separately with z.attachNTPServersToPortConfigs
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
			DhcpType:     port.Dhcp,
			DNSServers:   types.GetDNSServers(*z.deviceNetworkStatus, port.IfName),
		})
	}
	return portConfigs
}

// Update the selection of device ports matching the port label.
func (z *zedrouter) updateNIPorts(niConfig types.NetworkInstanceConfig,
	niStatus *types.NetworkInstanceStatus) (
	changed bool, err error) {
	var (
		newPorts         []*types.NetworkPortStatus
		validatedPortLLs []string
		newNTPServers    []string
		errorMsgs        []string
	)
	if niStatus.NtpServers != nil {
		// The NTP server explicitly configured for the NI.
		newNTPServers = append(newNTPServers, niStatus.NtpServers...)
	}
	if niStatus.PortLabel != "" {
		newPorts = z.deviceNetworkStatus.LookupPortsByLabel(niStatus.PortLabel)
	}
	for _, port := range newPorts {
		// Check if port is valid for the network instance.
		if port.InvalidConfig {
			errorMsgs = append(errorMsgs,
				fmt.Sprintf("port %s has invalid config: %s",
					port.Logicallabel, port.LastError))
			continue
		}
		if port.IfName == "" {
			errorMsgs = append(errorMsgs,
				fmt.Sprintf("missing interface name for port %s", port.Logicallabel))
			continue
		}
		var checkOnlySwitchOverlap, checkOnlyMultiportOverlap bool
		switch niStatus.Type {
		case types.NetworkInstanceTypeLocal:
			if port.Dhcp != types.DhcpTypeStatic && port.Dhcp != types.DhcpTypeClient {
				errorMsgs = append(errorMsgs,
					fmt.Sprintf(
						"L2-only port %s cannot be used in Local Network Instance",
						port.Logicallabel))
				continue
			}
			// The same port can be used by multiple Local NIs.
			// Also, Local NI(s) can share port with a single-port Switch NI.
			checkOnlySwitchOverlap = true
			checkOnlyMultiportOverlap = true
		case types.NetworkInstanceTypeSwitch:
			if port.WirelessCfg.WType != types.WirelessTypeNone {
				errorMsgs = append(errorMsgs,
					fmt.Sprintf("wireless port %s cannot be used in Switch Network Instance",
						port.Logicallabel))
				continue
			}
			if z.deviceNetworkStatus.IsPortUsedAsVlanParent(port.Logicallabel) {
				// It is not supported/valid to bridge port which has VLAN
				// sub-interfaces configured.
				errorMsgs = append(errorMsgs,
					fmt.Sprintf("port %s with VLAN sub-interfaces cannot be used "+
						"in Switch Network Instance", port.Logicallabel))
				continue
			}
			if len(newPorts) > 1 && port.Dhcp != types.DhcpTypeNone {
				errorMsgs = append(errorMsgs,
					fmt.Sprintf(
						"L3 port %s cannot be used in multi-port Switch Network Instance",
						port.Logicallabel))
				continue
			}
			if len(newPorts) > 1 {
				// Port used by multi-port Switch NI cannot be used by any other NI.
				checkOnlySwitchOverlap = false
				checkOnlyMultiportOverlap = false
			} else {
				// Single-port Switch NI can share port with Local NIs.
				// Multiple Switch NIs trying to use the same port is not valid, however.
				checkOnlySwitchOverlap = true
				checkOnlyMultiportOverlap = false
			}
		}
		anotherNI := z.checkIfPortUsedByAnotherNI(niConfig.UUID, port.Logicallabel,
			checkOnlySwitchOverlap, checkOnlyMultiportOverlap)
		if anotherNI != emptyUUID {
			errorMsgs = append(errorMsgs,
				fmt.Sprintf(
					"port %s is already used by Network Instance %s",
					port.Logicallabel, anotherNI))
			continue
		}
		// Port is valid for this network instance.
		validatedPortLLs = append(validatedPortLLs, port.Logicallabel)
		if port.ConfiguredNtpServers != nil {
			// The NTP server explicitly configured for the port.
			newNTPServers = append(newNTPServers, port.ConfiguredNtpServers...)
		}
		// NTP servers received via DHCP.
		if !port.IgnoreDhcpNtpServers {
			for _, dhcpNtpserver := range port.DhcpNtpServers {
				newNTPServers = append(newNTPServers, dhcpNtpserver.String())
			}
		}
	}
	if niStatus.PortLabel != "" && len(newPorts) == 0 {
		// This is potentially a transient state, wait for DNS update.
		errorMsgs = append(errorMsgs,
			fmt.Sprintf("no port is matching label '%s'", niStatus.PortLabel))
	}
	newNTPServers = generics.FilterDuplicates(newNTPServers)
	changed = changed || !generics.EqualSets(niStatus.Ports, validatedPortLLs)
	niStatus.Ports = validatedPortLLs
	changed = changed || !generics.EqualSets(niStatus.NTPServers, newNTPServers)
	niStatus.NTPServers = newNTPServers
	// Update BridgeMac for Switch NI bridge created by NIM.
	if z.niBridgeIsCreatedByNIM(niConfig) {
		// Only switch NI with single port may have the bridge created by NIM.
		ifName := newPorts[0].IfName
		if ifIndex, exists, _ := z.networkMonitor.GetInterfaceIndex(ifName); exists {
			_, ifMAC, _ := z.networkMonitor.GetInterfaceAddrs(ifIndex)
			changed = changed || !bytes.Equal(ifMAC, niStatus.BridgeMac)
			niStatus.BridgeMac = ifMAC
		}
	}
	if len(errorMsgs) > 0 {
		err = errors.New(strings.Join(errorMsgs, "\n"))
	}
	return changed, err
}

// Update port selection for all network instances.
// Also handle (dis)appearance of device ports.
// Note that even if port disappears, we do not revert activated NI.
func (z *zedrouter) updatePortsForAllNIs() {
	items := z.pubNetworkInstanceStatus.GetAll()
	for key, st := range items {
		niStatus := st.(types.NetworkInstanceStatus)
		niConfig := z.lookupNetworkInstanceConfig(key)
		if niConfig == nil {
			z.log.Errorf("updatePortsForAllNIs: failed to get config for NI %s",
				niStatus.UUID)
			continue
		}
		niStatus.PortErr.ClearError()
		changedPorts, portErr := z.updateNIPorts(*niConfig, &niStatus)
		if portErr != nil {
			portErr = fmt.Errorf(
				"failed to update selection of ports for network instance %s: %v",
				niStatus.UUID, portErr)
			z.log.Error(portErr)
			niStatus.PortErr.SetErrorNow(portErr.Error())
		}

		if changedPorts {
			// Changing the number of ports may affect if a multi-path default route
			// is needed or not.
			_ = z.updateNIRoutes(&niStatus, false)
		}

		// Re-check MTUs between the NI and the selected ports.
		mtuToUse, mtuErr := z.checkNetworkInstanceMTUConflicts(*niConfig, &niStatus)
		niStatus.MTU = mtuToUse
		if mtuErr == nil && niStatus.MTUConflictErr.HasError() {
			// MTU conflict was resolved.
			niStatus.MTUConflictErr.ClearError()
		}
		if mtuErr != nil &&
			mtuErr.Error() != niStatus.MTUConflictErr.Error {
			// New MTU conflict arose or the error has changed.
			z.log.Error(mtuErr)
			niStatus.MTUConflictErr.SetErrorNow(mtuErr.Error())
		}

		// Apply port/MTU changes in the network stack.
		if niStatus.Activated {
			z.doUpdateActivatedNetworkInstance(*niConfig, &niStatus)
		}
		if niConfig.Activate && !niStatus.Activated && niStatus.EligibleForActivate() {
			z.doActivateNetworkInstance(*niConfig, &niStatus)
			z.checkAndRecreateAppNetworks(niStatus.UUID)
		}
		z.publishNetworkInstanceStatus(&niStatus)
	}
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
	bridgeConfig := z.getNIBridgeConfig(status)
	z.attachNTPServersToPortConfigs(bridgeConfig.Ports)
	niRecStatus, err := z.niReconciler.AddNI(
		z.runCtx, config, bridgeConfig)
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
	bridgeConfig := z.getNIBridgeConfig(status)
	z.attachNTPServersToPortConfigs(bridgeConfig.Ports)
	niRecStatus, err := z.niReconciler.UpdateNI(
		z.runCtx, config, bridgeConfig)
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
		err = z.niStateCollector.UpdateCollectingForNI(config, vifs, z.enableArpSnooping)
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

// If Switch NI has single port which is also used for EVE mgmt or for Local NI,
// then the associated bridge is managed by NIM.
func (z *zedrouter) niBridgeIsCreatedByNIM(niConfig types.NetworkInstanceConfig) bool {
	if niConfig.Type != types.NetworkInstanceTypeSwitch {
		// Zedrouter creates bridge for Local NI.
		return false
	}
	if niConfig.PortLabel == "" {
		// Zedrouter creates bridge for air-gapped switch NI.
		return false
	}
	singlePort := z.deviceNetworkStatus.LookupPortByLogicallabel(niConfig.PortLabel)
	if singlePort == nil {
		// niConfig.PortLabel is likely a shared label.
		// Zedrouter creates bridge for switch NI with multiple ports.
		return false
	}
	// If the (single) port is also used for mgmt or Local NI, NIM is responsible
	// for bridging the port.
	return singlePort.Dhcp == types.DhcpTypeStatic || singlePort.Dhcp == types.DhcpTypeClient
}
