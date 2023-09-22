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
		z.enableArpSnooping = gcp.GlobalValueBool(types.EnableARPSnoop)
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

	// Update uplink config for network instances.
	// Also handle (dis)appearance of uplink interfaces.
	// Note that even if uplink interface disappears, we do not revert activated NI.
	items := z.pubNetworkInstanceStatus.GetAll()
	for key, st := range items {
		niStatus := st.(types.NetworkInstanceStatus)
		niConfig := z.lookupNetworkInstanceConfig(key)
		if niConfig == nil {
			z.log.Errorf("handleDNSImpl: failed to get config for NI %s", niStatus.UUID)
			continue
		}
		z.doUpdateNIUplink(niStatus.SelectedUplinkLogicalLabel, &niStatus, *niConfig)
	}

	if z.uplinkProber != nil {
		z.uplinkProber.ApplyDNSUpdate(status)
	}
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

func (z *zedrouter) handleNetworkInstanceCreate(ctxArg interface{}, key string,
	configArg interface{}) {

	config := configArg.(types.NetworkInstanceConfig)
	z.log.Functionf("handleNetworkInstanceCreate: (UUID: %s, name:%s)",
		key, config.DisplayName)

	if !z.initReconcileDone {
		z.niReconciler.RunInitialReconcile(z.runCtx)
		z.initReconcileDone = true
	}

	status := types.NetworkInstanceStatus{
		NetworkInstanceConfig: config,
		NetworkInstanceInfo: types.NetworkInstanceInfo{
			IPAssignments: make(map[string]types.AssignedAddrs),
			VifMetricMap:  make(map[string]types.NetworkMetric),
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
		status.SetError(config.Error, config.ErrorTime)
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
		z.log.Functionf("handleNetworkInstanceCreate(%s) done", key)
		return
	}

	if niConflict, err := z.doNetworkInstanceSanityCheck(&config); err != nil {
		z.log.Error(err)
		status.SetErrorNow(err.Error())
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		status.NIConflict = niConflict
		z.publishNetworkInstanceStatus(&status)
		return
	}

	// Allocate unique number for the bridge.
	bridgeNumKey := types.UuidToNumKey{UUID: status.UUID}
	bridgeNum, err := z.bridgeNumAllocator.GetOrAllocate(bridgeNumKey)
	if err != nil {
		err := fmt.Errorf("failed to allocate number for network instance bridge %s: %v",
			status.UUID, err)
		z.log.Error(err)
		status.SetErrorNow(err.Error())
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
		return
	}
	status.BridgeNum = bridgeNum

	// Generate MAC address for the bridge.
	if !status.IsUsingUplinkBridge() {
		status.BridgeMac = z.generateBridgeMAC(bridgeNum)
	}

	// Set bridge IP address.
	if status.Gateway != nil {
		addrs := types.AssignedAddrs{IPv4Addr: status.Gateway}
		status.IPAssignments[status.BridgeMac.String()] = addrs
		status.BridgeIPAddr = status.Gateway
	}

	// Find suitable uplink port.
	var selectedUplinkLL string
	if config.WithUplinkProbing() {
		probeStatus, err := z.uplinkProber.StartNIProbing(config)
		if err != nil {
			err := fmt.Errorf("failed to start uplink probing for network instance %s: %v",
				status.UUID, err)
			z.log.Error(err)
			status.SetErrorNow(err.Error())
			status.ChangeInProgress = types.ChangeInProgressTypeNone
			z.publishNetworkInstanceStatus(&status)
			return
		}
		selectedUplinkLL = probeStatus.SelectedUplinkLL
		status.RunningUplinkProbing = true
	} else {
		selectedUplinkLL = config.PortLogicalLabel
	}

	// Set selected uplink port.
	waitForUplink, err := z.setSelectedUplink(selectedUplinkLL, &status)
	if err != nil {
		err := fmt.Errorf("failed to set selected uplink for network instance %s: %v",
			status.UUID, err)
		z.log.Error(err)
		status.SetErrorNow(err.Error())
		status.WaitingForUplink = waitForUplink
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
		return
	}

	if !config.Activate {
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(&status)
		return
	}

	z.doActivateNetworkInstance(config, &status)

	// Update AppNetwork-s that depend on this network instance.
	z.checkAndRecreateAppNetworks(config.UUID)
	z.log.Functionf("handleNetworkInstanceCreate(%s) done", key)
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
	status.ChangeInProgress = types.ChangeInProgressTypeModify
	z.publishNetworkInstanceStatus(status)

	// Any error from parser?
	if config.HasError() {
		z.log.Errorf("handleNetworkInstanceModify(%s) returning parse error %s",
			key, config.Error)
		status.SetError(config.Error, config.ErrorTime)
		status.WaitingForUplink = false
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(status)
		z.log.Functionf("handleNetworkInstanceModify(%s) done", key)
		return
	}

	// We do not allow Type to change.
	if config.Type != status.Type {
		err := fmt.Errorf("changing Type of NetworkInstance from %d to %d is not supported",
			status.Type, config.Type)
		z.log.Errorf("handleNetworkInstanceModify(%s) %v", key, err)
		status.SetErrorNow(err.Error())
		status.WaitingForUplink = false
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(status)
		z.log.Functionf("handleNetworkInstanceModify(%s) done", key)
		return
	}

	prevPortLL := status.PortLogicalLabel
	status.NetworkInstanceConfig = config
	if niConflict, err := z.doNetworkInstanceSanityCheck(&config); err != nil {
		z.log.Error(err)
		status.SetErrorNow(err.Error())
		status.WaitingForUplink = false
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		status.NIConflict = niConflict
		z.publishNetworkInstanceStatus(status)
		return
	}

	// Get or (less likely) allocate a bridge number.
	bridgeNumKey := types.UuidToNumKey{UUID: status.UUID}
	bridgeNum, err := z.bridgeNumAllocator.GetOrAllocate(bridgeNumKey)
	if err != nil {
		err := fmt.Errorf("failed to allocate number for network instance bridge %s: %v",
			status.UUID, err)
		z.log.Error(err)
		status.SetErrorNow(err.Error())
		status.WaitingForUplink = false
		status.ChangeInProgress = types.ChangeInProgressTypeNone
		z.publishNetworkInstanceStatus(status)
		return
	}
	status.BridgeNum = bridgeNum

	// Generate MAC address for the bridge.
	// If already done during NI Create, this returns the same value.
	if !status.IsUsingUplinkBridge() {
		status.BridgeMac = z.generateBridgeMAC(bridgeNum)
	}

	// Reset bridge IP address (in case it changed).
	status.BridgeIPAddr = nil
	if status.BridgeMac != nil {
		delete(status.IPAssignments, status.BridgeMac.String())
	}
	if status.Gateway != nil {
		addrs := types.AssignedAddrs{IPv4Addr: status.Gateway}
		status.IPAssignments[status.BridgeMac.String()] = addrs
		status.BridgeIPAddr = status.Gateway
	}

	// Handle change of the configured port logical label.
	if config.PortLogicalLabel != prevPortLL {
		if status.RunningUplinkProbing {
			err = z.uplinkProber.StopNIProbing(status.UUID)
			if err != nil {
				z.log.Errorf("failed to stop uplink probing for network instance %s: %v",
					status.UUID, err)
				// Try to continue...
			}
			status.RunningUplinkProbing = false
		}
		var selectedUplinkLL string
		if config.WithUplinkProbing() {
			probeStatus, err := z.uplinkProber.StartNIProbing(config)
			if err != nil {
				err := fmt.Errorf(
					"failed to start uplink probing for network instance %s: %v",
					status.UUID, err)
				z.log.Error(err)
				status.SetErrorNow(err.Error())
				status.WaitingForUplink = false
				status.ChangeInProgress = types.ChangeInProgressTypeNone
				z.publishNetworkInstanceStatus(status)
				return
			}
			selectedUplinkLL = probeStatus.SelectedUplinkLL
			status.RunningUplinkProbing = true
		} else {
			selectedUplinkLL = config.PortLogicalLabel
		}
		// Set selected uplink port.
		waitForUplink, err := z.setSelectedUplink(selectedUplinkLL, status)
		if err != nil {
			err := fmt.Errorf("failed to set selected uplink for network instance %s: %v",
				status.UUID, err)
			z.log.Error(err)
			status.SetErrorNow(err.Error())
			status.WaitingForUplink = waitForUplink
			status.ChangeInProgress = types.ChangeInProgressTypeNone
			z.publishNetworkInstanceStatus(status)
			return
		}
	}

	// Handle changed activation status.
	z.publishNetworkInstanceStatus(status)
	if config.Activate && !status.Activated {
		status.WaitingForUplink = false
		z.doActivateNetworkInstance(config, status)
		z.checkAndRecreateAppNetworks(config.UUID)
	} else if !config.Activate && status.Activated {
		z.maybeDelOrInactivateNetworkInstance(status)
	} else if status.Activated {
		z.doUpdateActivatedNetworkInstance(config, status)
	}

	// Check if some inter-NI conflicts were resolved by this modification.
	z.checkConflictingNetworkInstances()
	z.log.Functionf("handleNetworkInstanceModify(%s) done", key)
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
	// Check if some inter-NI conflicts were resolved by this delete.
	z.checkConflictingNetworkInstances()
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
	z.publishAppNetworkStatus(&status)

	// Allocate application numbers on underlay network.
	// Used to allocate VIF IP address.
	err = z.allocateAppIntfNums(config.UUIDandVersion.UUID, config.UnderlayNetworkList)
	if err != nil {
		err = fmt.Errorf("failed to allocate numbers for VIFs of the app %s/%s: %v",
			config.UUIDandVersion.UUID, config.DisplayName, err)
		z.log.Errorf("handleAppNetworkCreate(%v): %v", config.UUIDandVersion.UUID, err)
		z.addAppNetworkError(&status, "handleAppNetworkCreate", err)
		return
	}

	// Check that Network exists for all underlays.
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
// For example, the number of underlay networks can not be changed.
func (z *zedrouter) handleAppNetworkModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	newConfig := configArg.(types.AppNetworkConfig)
	oldConfig := oldConfigArg.(types.AppNetworkConfig)
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

	// Update numbers allocated for application interfaces.
	z.checkAppNetworkModifyAppIntfNums(newConfig, status)

	// Check that Network exists for all new underlays.
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

	// Free all numbers allocated for this app network.
	appNumKey := types.UuidToNumKey{UUID: status.UUIDandVersion.UUID}
	err := z.appNumAllocator.Free(appNumKey, false)
	if err != nil {
		z.log.Errorf("failed to free number allocated to app %s/%s: %v",
			status.UUIDandVersion.UUID, status.DisplayName, err)
		// Continue anyway...
	}
	z.freeAppIntfNums(status)

	// Did this free up any last references against any deleted Network Instance?
	for i := range status.UnderlayNetworkList {
		ulStatus := &status.UnderlayNetworkList[i]
		netstatus := z.lookupNetworkInstanceStatus(ulStatus.Network.String())
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

func (z *zedrouter) handleAppInstDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	z.log.Functionf("handleAppInstDelete(%s)", key)
	appInstMetadata := z.lookupAppInstMetadata(key)
	if appInstMetadata == nil {
		z.log.Functionf("handleAppInstDelete: unknown %s", key)
		return
	}
	// Clean up appInst Metadata
	z.unpublishAppInstMetadata(appInstMetadata)
	z.log.Functionf("handleAppInstDelete(%s) done", key)
}

func (z *zedrouter) handlePatchEnvelopeCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	peInfo := ctxArg.([]types.PatchEnvelopeInfo)
	z.log.Functionf("handlePatchEnvelopeCreate: (UUID: %s)", key)

	z.patchEnvelopes.Wg.Add(1)
	z.patchEnvelopes.PatchEnvelopeInfoCh <- peInfo

	z.log.Functionf("handleVolumeStatusCreate(%s) done", key)
}

func (z *zedrouter) handlePatchEnvelopeModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	peInfo := ctxArg.([]types.PatchEnvelopeInfo)
	z.log.Functionf("handlePatchEnvelopeModify: (UUID: %s)", key)

	z.patchEnvelopes.Wg.Add(1)
	z.patchEnvelopes.PatchEnvelopeInfoCh <- peInfo

	z.log.Functionf("handlePatchEnvelopeModify(%s) done", key)
}

func (z *zedrouter) handleVolumeStatusCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	volume := ctxArg.(types.VolumeStatus)
	z.log.Functionf("handleVolumeStatusCreate: (UUID: %s, name:%s)",
		key, volume.DisplayName)

	z.patchEnvelopes.Wg.Add(1)
	z.patchEnvelopes.VolumeStatusCh <- types.PatchEnvelopesVsCh{
		Vs:     volume,
		Action: types.PatchEnvelopesVsChActionPut,
	}

	z.log.Functionf("handleVolumeStatusCreate(%s) done", key)
}

func (z *zedrouter) handleVolumeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	volume := ctxArg.(types.VolumeStatus)
	z.log.Functionf("handleVolumeStatusModify: (UUID: %s, name:%s)",
		key, volume.DisplayName)

	z.patchEnvelopes.Wg.Add(1)
	z.patchEnvelopes.VolumeStatusCh <- types.PatchEnvelopesVsCh{
		Vs:     volume,
		Action: types.PatchEnvelopesVsChActionPut,
	}

	z.log.Functionf("handleVolumeStatusModify(%s) done", key)
}

func (z *zedrouter) handleVolumeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	volume := ctxArg.(types.VolumeStatus)
	z.log.Functionf("handleVolumeStatusDelete: (UUID: %s, name:%s)",
		key, volume.DisplayName)

	z.patchEnvelopes.Wg.Add(1)
	z.patchEnvelopes.VolumeStatusCh <- types.PatchEnvelopesVsCh{
		Vs:     volume,
		Action: types.PatchEnvelopesVsChActionDelete,
	}

	z.log.Functionf("handleVolumeStatusDelete(%s) done", key)
}
