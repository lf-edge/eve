package zedrouter

import (
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func (z *zedrouter) handleRestart(ctxArg interface{}, restartCounter int) {
	z.log.Tracef("handleRestart(%d)", restartCounter)
	if restartCounter != 0 {
		// Since all work is done inline we can immediately say that
		// we have restarted.
		z.pubAppNetworkStatus.SignalRestarted()
	}
}

func (z *zedrouter) handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	z.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (z *zedrouter) handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	z.handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func (z *zedrouter) handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {
	if key != "global" {
		z.log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	z.log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(z.log, z.subGlobalConfig, agentName,
		z.CLIParams().DebugOverride, z.logger)
	if gcp != nil {
		z.gcInitialized = true
		z.appContainerStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)
		metricInterval := gcp.GlobalValueInt(types.MetricInterval)
		if metricInterval != 0 && z.metricInterval != metricInterval {
			if z.publishTicker != nil {
				interval := time.Duration(metricInterval) * time.Second
				max := float64(interval) / publishTickerDivider
				min := max * 0.3
				z.publishTicker.UpdateRangeTicker(time.Duration(min), time.Duration(max))
			}
			z.metricInterval = metricInterval
		}
		enableArpSnooping := gcp.GlobalValueBool(types.EnableARPSnoop)
		if z.enableArpSnooping != enableArpSnooping {
			z.enableArpSnooping = enableArpSnooping
			// Start/Stop ARP snooping in every activated Switch NI.
			for _, item := range z.pubNetworkInstanceStatus.GetAll() {
				niStatus := item.(types.NetworkInstanceStatus)
				if !niStatus.Activated {
					continue
				}
				if niStatus.Type != types.NetworkInstanceTypeSwitch {
					// ARP snooping is only used in Switch NIs.
					continue
				}
				niConfig := z.lookupNetworkInstanceConfig(niStatus.Key())
				if niConfig == nil {
					continue
				}
				_, vifs, err := z.getArgsForNIStateCollecting(niConfig.UUID)
				if err == nil {
					err = z.niStateCollector.UpdateCollectingForNI(
						*niConfig, vifs, z.enableArpSnooping)
				}
				if err != nil {
					z.log.Error(err)
				}
			}
		}
		z.localLegacyMACAddr = gcp.GlobalValueBool(types.NetworkLocalLegacyMACAddress)
		z.niReconciler.ApplyUpdatedGCP(z.runCtx, *gcp)
	}
	z.log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func (z *zedrouter) handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	if key != "global" {
		z.log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	z.log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(z.log, z.subGlobalConfig, agentName,
		z.CLIParams().DebugOverride, z.logger)
	gcp := *types.DefaultConfigItemValueMap()
	z.appContainerStatsInterval = gcp.GlobalValueInt(types.AppContainerStatsInterval)
	z.niReconciler.ApplyUpdatedGCP(z.runCtx, gcp)
	z.log.Functionf("handleGlobalConfigDelete done for %s", key)
}

func (z *zedrouter) handleDNSCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	z.handleDNSImpl(ctxArg, key, statusArg)
}

func (z *zedrouter) handleDNSModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	z.handleDNSImpl(ctxArg, key, statusArg)
}

func (z *zedrouter) handleDNSImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.DeviceNetworkStatus)
	if key != "global" {
		z.log.Functionf("handleDNSImpl: ignoring %s", key)
		return
	}
	z.log.Functionf("handleDNSImpl for %s", key)

	// Ignore test status and timestamps
	// Interface (dis)appearance will trigger change of multiple attributes (e.g. "Up").
	if z.deviceNetworkStatus.MostlyEqual(status) {
		z.log.Functionf("handleDNSImpl no change")
		return
	}
	z.log.Functionf("handleDNSImpl: changed %v",
		cmp.Diff(z.deviceNetworkStatus, status))
	z.deviceNetworkStatus = &status

	if !z.initReconcileDone {
		z.niReconciler.RunInitialReconcile(z.runCtx)
		z.initReconcileDone = true
	}

	// A new IP address may have been assigned to a device port, or a previously existing
	// one may have been removed, potentially creating or resolving an IP conflict.
	z.checkAllNetworkInstanceIPConflicts()
	// Handle (dis)appeared port, change in shared labels and change in port MTU.
	z.updatePortsForAllNIs()

	z.portProber.ApplyDNSUpdate(status)
	z.log.Functionf("handleDNSImpl done for %s", key)
}

// This should be unreachable.
func (z *zedrouter) handleDNSDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	z.log.Functionf("handleDNSDelete for %s", key)
	ctx := ctxArg.(*zedrouter)

	if key != "global" {
		z.log.Functionf("handleDNSDelete: ignoring %s", key)
		return
	}
	*ctx.deviceNetworkStatus = types.DeviceNetworkStatus{}
	z.log.Functionf("handleDNSDelete done for %s", key)
}

func (z *zedrouter) handleWwanMetricsCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	z.handleWwanMetricsImpl(ctxArg, key, statusArg)
}

func (z *zedrouter) handleWwanMetricsModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	z.handleWwanMetricsImpl(ctxArg, key, statusArg)
}

func (z *zedrouter) handleWwanMetricsImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	metrics := statusArg.(types.WwanMetrics)
	if key != "global" {
		z.log.Functionf("handleWwanMetricsImpl: ignoring %s", key)
		return
	}
	z.log.Functionf("handleWwanMetricsImpl for %s", key)
	z.portProber.ApplyWwanMetricsUpdate(metrics)
}

func (z *zedrouter) handleNetworkInstanceCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	config := configArg.(types.NetworkInstanceConfig)
	z.log.Functionf("handleNetworkInstanceCreate: (UUID: %s, name:%s)",
		key, config.DisplayName)
	defer z.log.Functionf("handleNetworkInstanceCreate(%s) done", key)

	if !z.initReconcileDone {
		z.niReconciler.RunInitialReconcile(z.runCtx)
		z.initReconcileDone = true
	}

	status := types.NetworkInstanceStatus{
		NetworkInstanceConfig: config,
		NetworkInstanceInfo: types.NetworkInstanceInfo{
			IPAssignments: make(map[string]types.AssignedAddrs),
			VlanMap:       make(map[uint32]uint32),
		},
	}
	z.getOrAddAppIntfAllocator(status.UUID)
	status.ChangeInProgress = types.ChangeInProgressTypeCreate
	z.publishNetworkInstanceStatus(&status)

	// Any error from parser?
	if config.HasError() {
		z.log.Errorf("handleNetworkInstanceCreate(%s) returning parse error %s",
			key, config.Error)
		status.ValidationErr = config.ErrorAndTime
		// Do not continue with invalid config.
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
		return
	}

	if err := z.doNetworkInstanceSanityCheck(&config); err != nil {
		z.log.Error(err)
		status.ValidationErr.SetErrorNow(err.Error())
		// Do not continue with invalid config.
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
		return
	}

	if err := z.checkNetworkInstanceIPConflicts(&config); err != nil {
		z.log.Error(err)
		status.IPConflictErr.SetErrorNow(err.Error())
	}

	// Allocate unique number for the bridge.
	bridgeNumKey := types.UuidToNumKey{UUID: status.UUID}
	bridgeNum, err := z.bridgeNumAllocator.GetOrAllocate(bridgeNumKey)
	if err != nil {
		err := fmt.Errorf("failed to allocate number for network instance bridge %s: %v",
			status.UUID, err)
		z.log.Error(err)
		status.AllocationErr.SetErrorNow(err.Error())
		// Do not continue if allocation failed.
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
		return
	}
	status.BridgeNum = bridgeNum

	// Generate MAC address for the bridge.
	if !z.niBridgeIsCreatedByNIM(config) {
		status.BridgeMac = z.generateBridgeMAC(bridgeNum)
	}

	// Set bridge IP address.
	if status.Gateway != nil {
		addrs := types.AssignedAddrs{
			IPv4Addrs: []types.AssignedAddr{
				{
					Address:    status.Gateway,
					AssignedBy: types.AddressSourceEVEInternal,
				}},
		}
		status.IPAssignments[status.BridgeMac.String()] = addrs
		status.BridgeIPAddr = status.Gateway
	}

	// Lookup ports matching the port label.
	_, err = z.updateNIPorts(config, &status)
	if err != nil {
		err = fmt.Errorf("failed to select ports for network instance %s: %v",
			status.UUID, err)
		z.log.Error(err)
		status.PortErr.SetErrorNow(err.Error())
	}

	// Build a set of intended IP routes.
	_ = z.updateNIRoutes(&status, true)

	mtuToUse, err := z.checkNetworkInstanceMTUConflicts(config, &status)
	status.MTU = mtuToUse
	if err != nil {
		z.log.Error(err)
		status.MTUConflictErr.SetErrorNow(err.Error())
	}

	if config.Activate && status.EligibleForActivate() {
		z.doActivateNetworkInstance(config, &status)
		// Update AppNetwork-s that depend on this network instance.
		z.checkAndRecreateAppNetworks(config.UUID)
	} else {
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
	}
}

func (z *zedrouter) handleNetworkInstanceModify(ctxArg interface{}, key string,
	configArg interface{},
	oldConfigArg interface{}) {

	config := configArg.(types.NetworkInstanceConfig)
	status := z.lookupNetworkInstanceStatus(key)
	if status == nil {
		z.log.Fatalf("handleNetworkInstanceModify(%s) no status", key)
	}
	z.log.Functionf("handleNetworkInstanceModify(%s)", key)
	defer z.log.Functionf("handleNetworkInstanceModify(%s) done", key)
	status.ChangeInProgress = types.ChangeInProgressTypeModify
	z.publishNetworkInstanceStatus(status)

	// Any error from parser?
	if config.HasError() {
		z.log.Errorf("handleNetworkInstanceModify(%s) returning parse error %s",
			key, config.Error)
		status.ValidationErr.SetError(config.Error, config.ErrorTime)
		// Do not continue with invalid config.
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(status)
		return
	}

	// We do not allow Type to change.
	if config.Type != status.Type {
		err := fmt.Errorf("changing Type of NetworkInstance from %d to %d is not supported",
			status.Type, config.Type)
		z.log.Errorf("handleNetworkInstanceModify(%s) %v", key, err)
		status.ValidationErr.SetErrorNow(err.Error())
		// Do not continue with invalid config.
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(status)
		return
	}

	prevPortLabel := status.PortLabel
	status.NetworkInstanceConfig = config
	if err := z.doNetworkInstanceSanityCheck(&config); err != nil {
		z.log.Error(err)
		status.ValidationErr.SetErrorNow(err.Error())
		// Do not continue with invalid config.
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(status)
		return
	}
	// NI config is proven to be valid beyond this point.
	status.ValidationErr.ClearError()

	// Get or (less likely) allocate a bridge number.
	bridgeNumKey := types.UuidToNumKey{UUID: status.UUID}
	bridgeNum, err := z.bridgeNumAllocator.GetOrAllocate(bridgeNumKey)
	if err != nil {
		err = fmt.Errorf("failed to allocate number for network instance bridge %s: %v",
			status.UUID, err)
		z.log.Error(err)
		status.AllocationErr.SetErrorNow(err.Error())
		// Do not continue if allocation failed.
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(status)
		return
	}
	status.AllocationErr.ClearError()
	status.BridgeNum = bridgeNum

	// Generate MAC address for the bridge.
	// If already done during NI Create, this returns the same value.
	if !z.niBridgeIsCreatedByNIM(config) {
		status.BridgeMac = z.generateBridgeMAC(bridgeNum)
	}

	// Reset bridge IP address (in case it changed).
	status.BridgeIPAddr = nil
	if status.BridgeMac != nil {
		delete(status.IPAssignments, status.BridgeMac.String())
	}
	if status.Gateway != nil && status.BridgeMac != nil {
		addrs := types.AssignedAddrs{
			IPv4Addrs: []types.AssignedAddr{
				{
					Address:    status.Gateway,
					AssignedBy: types.AddressSourceEVEInternal,
				}},
		}
		status.IPAssignments[status.BridgeMac.String()] = addrs
		status.BridgeIPAddr = status.Gateway
	}

	if err := z.checkNetworkInstanceIPConflicts(&config); err != nil {
		z.log.Error(err)
		status.IPConflictErr.SetErrorNow(err.Error())
	} else {
		status.IPConflictErr.ClearError()
	}

	// Handle change of the configured port label.
	status.PortErr.ClearError()
	_, err = z.updateNIPorts(config, status)
	if err != nil {
		err = fmt.Errorf("failed to update selection of ports for network instance %s: %v",
			status.UUID, err)
		z.log.Error(err)
		status.PortErr.SetErrorNow(err.Error())
	}

	// Update the set of intended IP routes.
	forceRecreate := status.PortLabel != prevPortLabel
	_ = z.updateNIRoutes(status, forceRecreate)

	mtuToUse, err := z.checkNetworkInstanceMTUConflicts(config, status)
	status.MTU = mtuToUse
	if err != nil {
		z.log.Error(err)
		status.MTUConflictErr.SetErrorNow(err.Error())
	} else {
		status.MTUConflictErr.ClearError()
	}

	// Handle changed activation status.
	z.publishNetworkInstanceStatus(status)
	if config.Activate && !status.Activated && status.EligibleForActivate() {
		z.doActivateNetworkInstance(config, status)
		z.checkAndRecreateAppNetworks(config.UUID)
	} else if !config.Activate && status.Activated {
		z.maybeDelOrInactivateNetworkInstance(status)
	} else if status.Activated {
		z.doUpdateActivatedNetworkInstance(config, status)
	}

	// Check if some IP conflicts were resolved by this modification.
	z.checkAllNetworkInstanceIPConflicts()
	if status.PortLabel != prevPortLabel {
		// Check if some port-overlap is avoided now that the port selection
		// for this NI changed.
		z.updatePortsForAllNIs()
	}
}

func (z *zedrouter) handleNetworkInstanceDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	z.log.Functionf("handleNetworkInstanceDelete(%s)", key)
	status := z.lookupNetworkInstanceStatus(key)
	if status == nil {
		z.log.Functionf("handleNetworkInstanceDelete: unknown %s", key)
		return
	}
	status.ChangeInProgress = types.ChangeInProgressTypeDelete
	z.publishNetworkInstanceStatus(status)

	done := z.maybeDelOrInactivateNetworkInstance(status)
	// Check if some IP conflicts were resolved by this NI deletion.
	z.checkAllNetworkInstanceIPConflicts()
	// Check if some port-overlap or MTU conflict is avoided now that this NI was deleted.
	z.updatePortsForAllNIs()
	z.log.Functionf("handleNetworkInstanceDelete(%s) done %t", key, done)
}

func (z *zedrouter) handleAppNetworkCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	config := configArg.(types.AppNetworkConfig)
	z.log.Functionf("handleAppNetworkCreate(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	if !z.initReconcileDone {
		z.niReconciler.RunInitialReconcile(z.runCtx)
		z.initReconcileDone = true
	}

	// If this is the first time, update the timer for GC of allocated
	// app and bridge numbers.
	if z.receivedConfigTime.IsZero() {
		z.log.Functionf("triggerNumGC")
		z.receivedConfigTime = time.Now()
		z.triggerNumGC = true
	}

	// Start by marking with PendingAdd
	status := types.AppNetworkStatus{
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
	}
	z.doCopyAppNetworkConfigToStatus(config, &status)
	status.PendingAdd = true
	z.publishAppNetworkStatus(&status)
	defer func() {
		status.PendingAdd = false
		z.publishAppNetworkStatus(&status)
	}()

	if err := z.validateAppNetworkConfig(config); err != nil {
		z.log.Errorf("handleAppNetworkCreate(%v): validation failed: %v",
			config.UUIDandVersion.UUID, err)
		z.addAppNetworkError(&status, "handleAppNetworkCreate", err)
		return
	}

	// Pick a local number to identify the application instance
	// Used to generate VIF MAC addresses, interface names, etc.
	appNumKey := types.UuidToNumKey{UUID: config.UUIDandVersion.UUID}
	appNum, err := z.appNumAllocator.GetOrAllocate(appNumKey)
	if err != nil {
		err = fmt.Errorf("failed to allocate appNum for %s/%s: %v",
			config.UUIDandVersion.UUID, config.DisplayName, err)
		z.log.Errorf("handleAppNetworkCreate(%v): %v", config.UUIDandVersion.UUID, err)
		z.addAppNetworkError(&status, "handleAppNetworkCreate", err)
		return
	}
	status.AppNum = appNum

	err = z.selectMACGeneratorForApp(&status)
	if err != nil {
		z.log.Errorf("handleAppNetworkCreate(%v): %v", config.UUIDandVersion.UUID, err)
		z.addAppNetworkError(&status, "handleAppNetworkCreate", err)
		return
	}
	z.publishAppNetworkStatus(&status)

	// Allocate application numbers on network instances.
	// Used to allocate VIF IP address.
	err = z.allocateAppIntfNums(config.UUIDandVersion.UUID, config.AppNetAdapterList)
	if err != nil {
		err = fmt.Errorf("failed to allocate numbers for VIFs of the app %s/%s: %v",
			config.UUIDandVersion.UUID, config.DisplayName, err)
		z.log.Errorf("handleAppNetworkCreate(%v): %v", config.UUIDandVersion.UUID, err)
		z.addAppNetworkError(&status, "handleAppNetworkCreate", err)
		return
	}

	// Check that Network exists for all AppNetAdapters.
	// We look for apps with raised AwaitNetworkInstance when a NetworkInstance is added.
	netInErrState, err := z.checkNetworkReferencesFromApp(config)
	if err != nil {
		z.log.Errorf("handleAppNetworkCreate(%v): %v", config.UUIDandVersion.UUID, err)
		status.AwaitNetworkInstance = true
		if netInErrState {
			z.addAppNetworkError(&status, "handleAppNetworkCreate", err)
		}
		return
	}

	if config.Activate {
		z.doActivateAppNetwork(config, &status)
	}

	z.maybeScheduleRetry()
	z.log.Functionf("handleAppNetworkCreate(%s) done for %s", key, config.DisplayName)
}

// handleAppNetworkModify cannot handle any change.
// For example, the number of AppNetAdapters can not be changed.
func (z *zedrouter) handleAppNetworkModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	newConfig := configArg.(types.AppNetworkConfig)
	oldConfig := oldConfigArg.(types.AppNetworkConfig)

	// re-activate network instances of edge apps in order to resolve NTP servers again
	for _, appNetConfig := range newConfig.AppNetAdapterList {
		appNetStatus := z.lookupNetworkInstanceStatus(appNetConfig.Network.String())
		if appNetStatus == nil {
			continue
		}
		if appNetStatus.Activated {
			appNetConfig := z.lookupNetworkInstanceConfig(appNetStatus.Key())
			z.doUpdateActivatedNetworkInstance(*appNetConfig, appNetStatus)
		}
	}

	status := z.lookupAppNetworkStatus(key)
	z.log.Functionf("handleAppNetworkModify(%v) for %s",
		newConfig.UUIDandVersion, newConfig.DisplayName)

	// Reset error status and mark pending modify as true.
	status.ClearError()
	status.PendingModify = true
	z.publishAppNetworkStatus(status)
	defer func() {
		status.PendingModify = false
		z.publishAppNetworkStatus(status)
	}()

	// Check for unsupported/invalid changes.
	if err := z.validateAppNetworkConfigForModify(newConfig, oldConfig); err != nil {
		z.log.Errorf("handleAppNetworkModify(%v): validation failed: %v",
			newConfig.UUIDandVersion.UUID, err)
		z.addAppNetworkError(status, "handleAppNetworkModify", err)
		return
	}

	// Get or (less likely) allocate number to identify the application instance.
	appNumKey := types.UuidToNumKey{UUID: newConfig.UUIDandVersion.UUID}
	appNum, err := z.appNumAllocator.GetOrAllocate(appNumKey)
	if err != nil {
		err = fmt.Errorf("failed to allocate appNum for %s/%s: %v",
			newConfig.UUIDandVersion.UUID, newConfig.DisplayName, err)
		z.log.Errorf("handleAppNetworkModify(%v): %v", newConfig.UUIDandVersion.UUID, err)
		z.addAppNetworkError(status, "handleAppNetworkModify", err)
		return
	}
	status.AppNum = appNum

	err = z.selectMACGeneratorForApp(status)
	if err != nil {
		z.log.Errorf("handleAppNetworkModify(%v): %v", newConfig.UUIDandVersion.UUID, err)
		z.addAppNetworkError(status, "handleAppNetworkModify", err)
		return
	}
	z.publishAppNetworkStatus(status)

	// Update numbers allocated for application interfaces.
	z.checkAppNetworkModifyAppIntfNums(newConfig, status)

	// Check that Network exists for all new AppNetAdapters.
	// We look for apps with raised AwaitNetworkInstance when a NetworkInstance is added.
	netInErrState, err := z.checkNetworkReferencesFromApp(newConfig)
	if err != nil {
		z.log.Errorf("handleAppNetworkModify(%v): %v", newConfig.UUIDandVersion.UUID, err)
		status.AwaitNetworkInstance = true
		if netInErrState {
			z.addAppNetworkError(status, "handleAppNetworkModify", err)
		}
		return
	}

	if !newConfig.Activate && status.Activated {
		z.doInactivateAppNetwork(newConfig, status)
		z.doCopyAppNetworkConfigToStatus(newConfig, status)
	} else if newConfig.Activate && !status.Activated {
		z.doCopyAppNetworkConfigToStatus(newConfig, status)
		z.doActivateAppNetwork(newConfig, status)
	} else if !status.Activated {
		// Just copy in newConfig
		z.doCopyAppNetworkConfigToStatus(newConfig, status)
	} else { // Config change while application network is active.
		z.doUpdateActivatedAppNetwork(oldConfig, newConfig, status)
	}

	// On resource release, another AppNetworkConfig which is currently in a failed state
	// may be able to proceed now.
	z.maybeScheduleRetry()
	z.log.Functionf("handleAppNetworkModify(%s) done for %s",
		key, newConfig.DisplayName)
}

func (z *zedrouter) handleAppNetworkDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	config := configArg.(types.AppNetworkConfig)
	z.log.Functionf("handleAppNetworkDelete(%v) for %s",
		config.UUIDandVersion, config.DisplayName)

	status := z.lookupAppNetworkStatus(key)
	if status == nil {
		z.log.Functionf("handleAppNetworkDelete: unknown key %s", key)
		return
	}

	// Deactivate app network if it is currently activated.
	if status.Activated {
		// No need to clear PendingDelete later. Instead, we un-publish
		// the status completely few lines below.
		status.PendingDelete = true
		z.publishAppNetworkStatus(status)
		z.doInactivateAppNetwork(config, status)
	}

	// Write out what we modified to AppNetworkStatus aka delete
	z.unpublishAppNetworkStatus(status)

	// Unpublish AppContainerStats
	if config.GetStatsIPAddr != nil {
		z.pubAppContainerStats.Unpublish(status.Key())
	}

	// Free all numbers allocated for this app network.
	appNumKey := types.UuidToNumKey{UUID: status.UUIDandVersion.UUID}
	err := z.appNumAllocator.Free(appNumKey, false)
	if err != nil {
		z.log.Errorf("failed to free number allocated to app %s/%s: %v",
			status.UUIDandVersion.UUID, status.DisplayName, err)
		// Continue anyway...
	}
	err = z.appMACGeneratorMap.Delete(appNumKey, false)
	if err != nil {
		z.log.Errorf("failed to delete persisted MAC generator ID for app %s/%s: %v",
			status.UUIDandVersion.UUID, status.DisplayName, err)
		// Continue anyway...
	}
	z.freeAppIntfNums(status)

	// Did this free up any last references against any deleted Network Instance?
	for i := range status.AppNetAdapterList {
		adapterStatus := &status.AppNetAdapterList[i]
		netstatus := z.lookupNetworkInstanceStatus(adapterStatus.Network.String())
		if netstatus != nil {
			if z.maybeDelOrInactivateNetworkInstance(netstatus) {
				z.log.Functionf(
					"Deleted/Inactivated NI %s as a result of deleting app network %s (%s)",
					netstatus.Key(), status.UUIDandVersion, status.DisplayName)
			}
		}
	}

	// On resource release, another AppNetworkConfig which is currently in a failed state
	// may be able to proceed now.
	z.maybeScheduleRetry()
	z.log.Functionf("handleAppNetworkDelete(%s) done for %s",
		key, config.DisplayName)
}
