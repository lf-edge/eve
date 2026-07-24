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
		// Propagate IntfOrder from adapter down to VifConfig, which zedmanager then passes
		// to domainmgr.
		adapterStatus.VifConfig.VifOrder = adapterStatus.IntfOrder
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
		// Adding or removing a VIF is supported; the new/removed adapters
		// simply have no matching previous status to preserve here.
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
			// Re-execute the entire pubsub handler to repeat the full validation process.
			// The conditions might have changed while the application was waiting for the
			// network instance to appear or get fixed. For instance, another application
			// with conflicting port forwarding rules could have been deployed during this
			// time, which would necessitate preventing the activation of this app's network.
			z.handleAppNetworkCreate(nil, appNetConfig.Key(), *appNetConfig)
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

	// Update app network status as well as status of connected network instances.
	z.processAppConnReconcileStatus(appConnRecStatus, status)
	z.reloadStatusOfAssignedIPs(status)
	z.publishAppNetworkStatus(status)
	z.updateNIStatusAfterAppNetworkActivate(status)

	// Update state data collecting parameters. This must come after
	// publishAppNetworkStatus: getArgsForNIStateCollecting builds the
	// collector's VIF list from the *published* AppNetworkStatus, so
	// registering earlier re-registers the collectors with the pre-modify
	// adapter list -- an added NIC never gets its IP attributed and a
	// removed one is watched forever. Same order as doActivateAppNetwork.
	z.checkAppContainerStatsCollecting(&newConfig, status)
	z.updateVIFsForStateCollecting(&oldConfig, &newConfig)
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
		// Still mark as deactivated to keep status in sync with the
		// reconciler.  Previously we returned here, leaving
		// status.Activated = true while the reconciler considered the
		// app removed (or partially removed).  That mismatch caused
		// the next activation attempt to call AddAppConn (because
		// !status.Activated was false) which then failed with
		// "already connected" if the reconciler still had a stale entry.
	} else {
		z.log.Functionf("Deactivated application network %s (%s)", status.UUIDandVersion.UUID,
			status.DisplayName)
		z.processAppConnReconcileStatus(appConnRecStatus, status)
	}

	// Update AppNetwork and NetworkInstance status.
	status.Activated = false
	z.updateNIStatusAfterAppNetworkInactivate(status)
	z.removeAssignedIPsFromAppNetStatus(status)
	z.publishAppNetworkStatus(status)
}

// Reconcile the per-interface numbers allocated for the application's VIFs with
// the (possibly changed) set of AppNetAdapters in the new config. An interface is
// identified by the network instance it connects to together with the per-network
// interface index (IfIdx). Numbers are freed for adapters that were removed (or
// moved to a different network/index) and allocated for newly added adapters;
// adapters present in both the old and new set keep their already-allocated number.
// Adds errors to status if an allocation fails.
func (z *zedrouter) checkAppNetworkModifyAppIntfNums(config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {
	appID := config.UUIDandVersion.UUID

	type intfRef struct {
		network uuid.UUID
		ifIdx   uint32
	}

	// Interfaces required by the new config.
	newRefs := make(map[intfRef]types.AppNetAdapterConfig)
	for i := range config.AppNetAdapterList {
		adapterConfig := config.AppNetAdapterList[i]
		newRefs[intfRef{adapterConfig.Network, adapterConfig.IfIdx}] = adapterConfig
	}
	// Interfaces for which a number is currently allocated (based on status).
	oldRefs := make(map[intfRef]struct{})
	for i := range status.AppNetAdapterList {
		adapterStatus := status.AppNetAdapterList[i]
		oldRefs[intfRef{adapterStatus.Network, adapterStatus.IfIdx}] = struct{}{}
	}

	// Free numbers for interfaces that are no longer present.
	affectedNIs := make(map[uuid.UUID]struct{})
	for ref := range oldRefs {
		if _, stillUsed := newRefs[ref]; stillUsed {
			continue
		}
		if err := z.freeAppIntfNum(ref.network, appID, ref.ifIdx); err != nil {
			z.log.Error(err)
			// Continue anyway, try to (de)allocate as many as possible.
		}
		affectedNIs[ref.network] = struct{}{}
	}

	// Allocate numbers for newly added interfaces.
	for ref, adapterConfig := range newRefs {
		if _, alreadyAllocated := oldRefs[ref]; alreadyAllocated {
			continue
		}
		withStaticIP := adapterConfig.AppIPAddr != nil
		if err := z.allocateAppIntfNum(
			ref.network, appID, ref.ifIdx, withStaticIP); err != nil {
			err = fmt.Errorf("failed to allocate appIntfNum: %v", err)
			z.log.Errorf("checkAppNetworkModifyAppIntfNums(%v/%v): %v",
				config.UUIDandVersion.UUID, config.DisplayName, err)
			z.addAppNetworkError(status, "checkAppNetworkModifyAppIntfNums", err)
			// Continue anyway...
		}
	}

	// Freeing a number may have removed the last reference from the app to a
	// network instance, which then may be deleted or inactivated.
	for niID := range affectedNIs {
		netstatus := z.lookupNetworkInstanceStatus(niID.String())
		if netstatus == nil {
			continue
		}
		if z.maybeDelOrInactivateNetworkInstance(netstatus) {
			z.log.Functionf("Deleted/Inactivated NI %s as a result of "+
				"removing interface(s) of app %s", niID, appID)
		}
	}
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
