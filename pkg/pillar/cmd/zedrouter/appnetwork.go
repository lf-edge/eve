// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/nireconciler"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
)

// Scan through existing AppNetworkStatus list to bring up any AppNetwork
// stuck in error state while contending for resources.
func (z *zedrouter) retryFailedAppNetworks() {
	z.log.Functionf("retryFailedAppNetworks()")
	pub := z.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.AppNetworkStatus)
		config := z.lookupAppNetworkConfig(status.Key())
		if config == nil || !config.Activate || !status.HasError() {
			continue
		}
		z.log.Functionf("retryFailedAppNetworks: retry AppNetworkConfigCreate(%s)",
			status.Key())
		if !status.Activated {
			// We wouldn't have even copied AppNetAdapter networks into status.
			// This is as good as starting from scratch all over.
			// App num that would have been allocated will be used this time also,
			// since the app UUID does not change.
			z.handleAppNetworkCreate(nil, status.Key(), *config)
		} else {
			// Retry by running modify without any actual config change.
			z.handleAppNetworkModify(nil, status.Key(), *config, *config)
		}
	}
}

// This function is called when AppNetworkConfig changes.
// In such case it can be necessary to update VIF description provided to NIStateCollector
// for all network instances that this app is or was connected to.
func (z *zedrouter) updateVIFsForStateCollecting(
	prevAppConf, newAppConfig *types.AppNetworkConfig) {
	// Determine the set of affected network instances.
	var networks []uuid.UUID
	if prevAppConf != nil {
		for _, adapter := range prevAppConf.AppNetAdapterList {
			networks = append(networks, adapter.Network)
		}
	}
	if newAppConfig != nil {
		for _, adapter := range newAppConfig.AppNetAdapterList {
			networks = append(networks, adapter.Network)
		}
	}
	networks = generics.FilterDuplicates(networks)
	// Update state collecting for NIs that the app is or was connected to.
	for _, network := range networks {
		netConfig := z.lookupNetworkInstanceConfig(network.String())
		if netConfig == nil {
			z.log.Errorf("failed to get config for network instance %v "+
				"(needed to update VIF arguments for state collecting)", network)
			continue
		}
		_, vifs, err := z.getArgsForNIStateCollecting(network)
		if err == nil {
			err = z.niStateCollector.UpdateCollectingForNI(*netConfig, vifs,
				z.enableArpSnooping)
		}
		if err != nil {
			z.log.Error(err)
		}
	}
}

func (z *zedrouter) prepareConfigForVIFs(config types.AppNetworkConfig,
	status *types.AppNetworkStatus) (vifs []nireconciler.AppVIF, err error) {
	for i := range status.AppNetAdapterList {
		adapterNum := i + 1
		adapterStatus := &status.AppNetAdapterList[i]
		netInstStatus := z.lookupNetworkInstanceStatus(adapterStatus.Network.String())
		if netInstStatus == nil {
			// Should be unreachable.
			err := fmt.Errorf("missing network instance status for %s",
				adapterStatus.Network.String())
			z.log.Errorf("doActivateAppNetwork(%v/%v): %v",
				config.UUIDandVersion.UUID, config.DisplayName, err)
			z.addAppNetworkError(status, "doActivateAppNetwork", err)
			return nil, err
		}
		adapterStatus.Bridge = netInstStatus.BridgeName
		adapterStatus.BridgeMac = netInstStatus.BridgeMac
		adapterStatus.BridgeIPAddr = netInstStatus.BridgeIPAddr
		if adapterStatus.AppMacAddr != nil {
			// User-configured static MAC address.
			adapterStatus.Mac = adapterStatus.AppMacAddr
		} else {
			adapterStatus.Mac = z.generateAppMac(adapterNum, status, netInstStatus)
		}
		adapterStatus.HostName = config.Key()
		adapterStatus.MTU = netInstStatus.MTU
		guestIP, err := z.lookupOrAllocateIPv4ForVIF(
			netInstStatus, *adapterStatus, status.UUIDandVersion.UUID)
		if err != nil {
			z.log.Errorf("doActivateAppNetwork(%v/%v): %v",
				config.UUIDandVersion.UUID, config.DisplayName, err)
			z.addAppNetworkError(status, "doActivateAppNetwork", err)
			return nil, err
		}
		vifs = append(vifs, nireconciler.AppVIF{
			App:            status.UUIDandVersion.UUID,
			NI:             adapterStatus.Network,
			NetAdapterName: adapterStatus.Name,
			VIFNum:         adapterNum,
			GuestIfMAC:     adapterStatus.Mac,
			GuestIP:        guestIP,
			PodVIF:         adapterStatus.PodVif,
		})
	}
	return vifs, nil
}

func (z *zedrouter) doActivateAppNetwork(config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {
	vifs, err := z.prepareConfigForVIFs(config, status)
	if err != nil {
		// Error already logged and added to status.
		return
	}

	// Use NIReconciler to configure connection between the app and the network instance(s)
	// inside the network stack.
	appConnRecStatus, err := z.niReconciler.AddAppConn(
		z.runCtx, config, status.AppNum, status.AppPod, vifs)
	if err != nil {
		err = fmt.Errorf("failed to activate application network: %v", err)
		z.log.Errorf("doActivateAppNetwork(%v/%v): %v",
			config.UUIDandVersion.UUID, config.DisplayName, err)
		z.addAppNetworkError(status, "doActivateAppNetwork", err)
		return
	}
	z.log.Functionf("Activated application network %s (%s)", status.UUIDandVersion.UUID,
		status.DisplayName)
	z.processAppConnReconcileStatus(appConnRecStatus, status)

	// Update AppNetwork and NetworkInstance status.
	status.Activated = true
	z.publishAppNetworkStatus(status)
	z.updateNIStatusAfterAppNetworkActivate(status)

	// Update state data collecting to include this application.
	z.checkAppContainerStatsCollecting(&config, status)
	z.updateVIFsForStateCollecting(nil, &config)
}

func (z *zedrouter) updateNIStatusAfterAppNetworkActivate(status *types.AppNetworkStatus) {
	for _, adapterStatus := range status.AppNetAdapterList {
		netInstStatus := z.lookupNetworkInstanceStatus(adapterStatus.Network.String())
		if netInstStatus == nil {
			err := fmt.Errorf("missing network instance status for %s",
				adapterStatus.Network.String())
			z.log.Error(err)
			continue
		}
		if netInstStatus.Type == types.NetworkInstanceTypeSwitch {
			if adapterStatus.AccessVlanID <= 1 {
				netInstStatus.NumTrunkPorts++
			} else {
				netInstStatus.VlanMap[adapterStatus.AccessVlanID]++
			}
		}
		netInstStatus.AddVif(z.log, adapterStatus.Vif, adapterStatus.Mac,
			status.UUIDandVersion.UUID)
		netInstStatus.IPAssignments[adapterStatus.Mac.String()] =
			adapterStatus.AssignedAddresses
		z.publishNetworkInstanceStatus(netInstStatus)
	}
}

func (z *zedrouter) updateNIStatusAfterAppNetworkInactivate(
	status *types.AppNetworkStatus) {
	for _, adapterStatus := range status.AppNetAdapterList {
		netInstStatus := z.lookupNetworkInstanceStatus(adapterStatus.Network.String())
		if netInstStatus == nil {
			err := fmt.Errorf("missing network instance status for %s",
				adapterStatus.Network.String())
			z.log.Error(err)
			continue
		}
		if netInstStatus.Type == types.NetworkInstanceTypeSwitch {
			if adapterStatus.AccessVlanID <= 1 {
				netInstStatus.NumTrunkPorts--
			} else {
				netInstStatus.VlanMap[adapterStatus.AccessVlanID]--
			}
		}
		netInstStatus.RemoveVif(z.log, adapterStatus.Vif)
		delete(netInstStatus.IPAssignments, adapterStatus.Mac.String())
		z.publishNetworkInstanceStatus(netInstStatus)
	}
}

func (z *zedrouter) doCopyAppNetworkConfigToStatus(
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	ulcount := len(config.AppNetAdapterList)
	prevNetStatus := status.AppNetAdapterList
	status.AppNetAdapterList = make([]types.AppNetAdapterStatus, ulcount)
	for i, netConfig := range config.AppNetAdapterList {
		// Preserve previous VIF status unless it was moved to another network.
		// Note that adding or removing VIF is not currently supported
		// (such change would be rejected by config validation methods,
		// see zedrouter/validation.go).
		if i < len(prevNetStatus) && prevNetStatus[i].Network == netConfig.Network {
			status.AppNetAdapterList[i] = prevNetStatus[i]
		}
		status.AppNetAdapterList[i].AppNetAdapterConfig = netConfig
	}
}

// Called when a NetworkInstance is added or when an error is cleared
// Walk all AppNetworkStatus looking for AwaitNetworkInstance, then check
// if network UUID is there.
// Also check if error on network instance and propagate to app network.
func (z *zedrouter) checkAndRecreateAppNetworks(niID uuid.UUID) {
	z.log.Functionf("checkAndRecreateAppNetworks(%v)", niID)
	niStatus := z.lookupNetworkInstanceStatus(niID.String())
	if niStatus == nil {
		z.log.Warnf("checkAndRecreateAppNetworks(%v): status not available",
			niID)
		return
	}
	pub := z.pubAppNetworkStatus
	items := pub.GetAll()
	for _, st := range items {
		appNetStatus := st.(types.AppNetworkStatus)
		appNetConfig := z.lookupAppNetworkConfig(appNetStatus.Key())
		if appNetConfig == nil {
			z.log.Warnf("checkAndRecreateAppNetworks(%v): no config for %s",
				niID, appNetStatus.DisplayName)
			continue
		}
		if !appNetConfig.IsNetworkUsed(niStatus.UUID) {
			continue
		}
		var awaitNetworkInstance bool
		netInErrState, err := z.checkNetworkReferencesFromApp(*appNetConfig)
		if err != nil {
			awaitNetworkInstance = true
		}
		var changedErr bool
		if netInErrState {
			changedErr = z.addAppNetworkError(
				&appNetStatus, "checkAndRecreateAppNetworks", err)
		} else if appNetStatus.AwaitNetworkInstance && appNetStatus.HasError() {
			appNetStatus.ClearError()
			changedErr = true
		}
		if changedErr || appNetStatus.AwaitNetworkInstance != awaitNetworkInstance {
			appNetStatus.AwaitNetworkInstance = awaitNetworkInstance
			z.publishAppNetworkStatus(&appNetStatus)
		}
		if !appNetStatus.HasError() && !appNetStatus.AwaitNetworkInstance &&
			appNetConfig.Activate && !appNetStatus.Activated {
			z.doActivateAppNetwork(*appNetConfig, &appNetStatus)
		}
		z.log.Functionf("checkAndRecreateAppNetworks(%v) done for %s",
			niID, appNetConfig.DisplayName)
	}
}

func (z *zedrouter) doUpdateActivatedAppNetwork(oldConfig, newConfig types.AppNetworkConfig,
	status *types.AppNetworkStatus) {
	// To update status of connected network instances we can pretend
	// that application network was deactivated and then re-activated.
	// This approach simplifies the implementation quite a bit.
	z.updateNIStatusAfterAppNetworkInactivate(status)
	// Reloaded below, see reloadStatusOfAssignedIPs.
	z.removeAssignedIPsFromAppNetStatus(status)

	// Re-build config for application VIFs.
	z.doCopyAppNetworkConfigToStatus(newConfig, status)
	vifs, err := z.prepareConfigForVIFs(newConfig, status)
	if err != nil {
		// Error already logged and added to status.
		return
	}

	// Update configuration inside the network stack.
	appConnRecStatus, err := z.niReconciler.UpdateAppConn(
		z.runCtx, newConfig, status.AppPod, vifs)
	if err != nil {
		err = fmt.Errorf("failed to update activated app network: %v", err)
		z.log.Errorf("doUpdateActivatedAppNetwork(%v/%v): %v",
			newConfig.UUIDandVersion.UUID, newConfig.DisplayName, err)
		z.addAppNetworkError(status, "doUpdateActivatedAppNetwork", err)
		return
	}
	z.log.Functionf("Updated activated application network %s (%s)",
		newConfig.UUIDandVersion.UUID, newConfig.DisplayName)

	// Update state data collecting parameters.
	z.checkAppContainerStatsCollecting(&newConfig, status)
	z.updateVIFsForStateCollecting(&oldConfig, &newConfig)

	// Update app network status as well as status of connected network instances.
	z.processAppConnReconcileStatus(appConnRecStatus, status)
	z.reloadStatusOfAssignedIPs(status)
	z.publishAppNetworkStatus(status)
	z.updateNIStatusAfterAppNetworkActivate(status)
}

func (z *zedrouter) doInactivateAppNetwork(config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {
	// Stop state data collecting for this application.
	z.updateVIFsForStateCollecting(&config, nil)
	z.checkAppContainerStatsCollecting(nil, status) // nil config to represent delete

	// Use NIReconciler to un-configure connection between the app and the network instance(s)
	// inside the network stack.
	appConnRecStatus, err := z.niReconciler.DelAppConn(z.runCtx, config.UUIDandVersion.UUID)
	if err != nil {
		err = fmt.Errorf("failed to deactivate application network: %v", err)
		z.log.Errorf("doInactivateAppNetwork(%v/%v): %v",
			config.UUIDandVersion.UUID, config.DisplayName, err)
		z.addAppNetworkError(status, "doInactivateAppNetwork", err)
		return

	}
	z.log.Functionf("Deactivated application network %s (%s)", status.UUIDandVersion.UUID,
		status.DisplayName)
	z.processAppConnReconcileStatus(appConnRecStatus, status)

	// Update AppNetwork and NetworkInstance status.
	status.Activated = false
	z.updateNIStatusAfterAppNetworkInactivate(status)
	z.removeAssignedIPsFromAppNetStatus(status)
	z.publishAppNetworkStatus(status)
}

// Check if any references to network instances have changed and potentially update
// allocated application interface numbers.
// Adds errors to status if there is a failure.
func (z *zedrouter) checkAppNetworkModifyAppIntfNums(config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	// Check if any AppNetAdapter have changes to the Networks they use
	for i := range config.AppNetAdapterList {
		adapterConfig := &config.AppNetAdapterList[i]
		adapterStatus := &status.AppNetAdapterList[i]
		if adapterConfig.Network == adapterStatus.Network {
			continue
		}
		z.log.Functionf(
			"checkAppNetworkModifyAppIntfNums(%v) for %s: change from %s to %s",
			config.UUIDandVersion, config.DisplayName,
			adapterStatus.Network, adapterConfig.Network)
		// update the reference to the network instance
		err := z.doAppNetworkModifyAppIntfNum(
			status.UUIDandVersion.UUID, adapterConfig, adapterStatus)
		if err != nil {
			err = fmt.Errorf("failed to modify appIntfNum: %v", err)
			z.log.Errorf(
				"checkAppNetworkModifyAppIntfNums(%v/%v): %v",
				config.UUIDandVersion.UUID, config.DisplayName, err)
			z.addAppNetworkError(status, "checkAppNetworkModifyAppIntfNums", err)
			// Continue anyway...
		}
	}
}

// handle a change to the network UUID for one AppNetAdapterConfig.
// Assumes the caller has checked that such a change is present.
// Release the current appIntfNum and acquire appIntfNum on the new network instance.
func (z *zedrouter) doAppNetworkModifyAppIntfNum(appID uuid.UUID,
	adapterConfig *types.AppNetAdapterConfig,
	adapterStatus *types.AppNetAdapterStatus) error {

	newNetworkID := adapterConfig.Network
	oldNetworkID := adapterStatus.Network
	newIfIdx := adapterConfig.IfIdx
	oldIfIdx := adapterStatus.IfIdx

	// Try to release the app number on the old network.
	err := z.freeAppIntfNum(oldNetworkID, appID, oldIfIdx)
	if err != nil {
		z.log.Error(err)
		// Continue anyway...
	}

	// Allocate an app number on the new network.
	withStaticIP := adapterConfig.AppIPAddr != nil
	err = z.allocateAppIntfNum(newNetworkID, appID, newIfIdx, withStaticIP)
	if err != nil {
		z.log.Error(err)
		return err
	}

	// Did the freeAppIntfNum release any last reference from app to NI?
	netstatus := z.lookupNetworkInstanceStatus(oldNetworkID.String())
	if netstatus != nil {
		if z.maybeDelOrInactivateNetworkInstance(netstatus) {
			z.log.Functionf("Deleted/Inactivated NI %s as a result of moving app %s "+
				"to another network %s", oldNetworkID, appID, newNetworkID)
		}
	}
	return nil
}

// For app already deployed (before node reboot), keep using the same MAC address
// generator. Changing MAC addresses could break network config inside the app.
func (z *zedrouter) selectMACGeneratorForApp(status *types.AppNetworkStatus) error {
	appKey := types.UuidToNumKey{UUID: status.UUIDandVersion.UUID}
	macGenerator, _, err := z.appMACGeneratorMap.Get(appKey)
	if err != nil || macGenerator == types.MACGeneratorUnspecified {
		// New app or an existing app but without MAC generator ID persisted.
		if z.withKubeNetworking {
			macGenerator = types.MACGeneratorClusterDeterministic
		} else if z.localLegacyMACAddr {
			// Use older node-scoped MAC address generator.
			macGenerator = types.MACGeneratorNodeScoped
		} else {
			// Use newer (and preferred) globally-scoped MAC address generator.
			macGenerator = types.MACGeneratorGloballyScoped
		}
		// Remember which MAC generator is being used for this app.
		err = z.appMACGeneratorMap.Assign(appKey, macGenerator, false)
		if err != nil {
			err = fmt.Errorf("failed to persist MAC generator ID for app %s/%s: %v",
				status.UUIDandVersion.UUID, status.DisplayName, err)
			return err
		}
	}
	status.MACGenerator = macGenerator
	return nil
}
