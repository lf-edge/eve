// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/nireconciler"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
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
		// We wouldn't have even copied underlay networks into status.
		// This is as good as starting from scratch all over.
		// App num that would have been allocated will be used this time also,
		// since the app UUID does not change.
		z.handleAppNetworkCreate(nil, status.Key(), *config)
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
		for _, ul := range prevAppConf.UnderlayNetworkList {
			networks = append(networks, ul.Network)
		}
	}
	if newAppConfig != nil {
		for _, ul := range newAppConfig.UnderlayNetworkList {
			networks = append(networks, ul.Network)
		}
	}
	networks = utils.FilterDuplicates(networks)
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
			err = z.niStateCollector.UpdateCollectingForNI(*netConfig, vifs)
		}
		if err != nil {
			z.log.Error(err)
		}
	}
}

func (z *zedrouter) prepareConfigForVIFs(config types.AppNetworkConfig,
	status *types.AppNetworkStatus) (vifs []nireconciler.AppVIF, err error) {
	for i := range status.UnderlayNetworkList {
		ulNum := i + 1
		ulStatus := &status.UnderlayNetworkList[i]
		netInstStatus := z.lookupNetworkInstanceStatus(ulStatus.Network.String())
		if netInstStatus == nil {
			// Should be unreachable.
			err := fmt.Errorf("missing network instance status for %s",
				ulStatus.Network.String())
			z.log.Errorf("doActivateAppNetwork(%v/%v): %v",
				config.UUIDandVersion.UUID, config.DisplayName, err)
			z.addAppNetworkError(status, "doActivateAppNetwork", err)
			return nil, err
		}
		ulStatus.Bridge = netInstStatus.BridgeName
		ulStatus.BridgeMac = netInstStatus.BridgeMac
		ulStatus.BridgeIPAddr = netInstStatus.BridgeIPAddr
		if ulStatus.AppMacAddr != nil {
			// User-configured static MAC address.
			ulStatus.Mac = ulStatus.AppMacAddr
		} else {
			ulStatus.Mac = z.generateAppMac(config.UUIDandVersion.UUID, ulNum,
				status.AppNum, netInstStatus)
		}
		ulStatus.HostName = config.Key()
		guestIP, err := z.lookupOrAllocateIPv4ForVIF(
			netInstStatus, *ulStatus, status.UUIDandVersion.UUID)
		if err != nil {
			z.log.Errorf("doActivateAppNetwork(%v/%v): %v",
				config.UUIDandVersion.UUID, config.DisplayName, err)
			z.addAppNetworkError(status, "doActivateAppNetwork", err)
			return nil, err
		}
		vifs = append(vifs, nireconciler.AppVIF{
			App:            status.UUIDandVersion.UUID,
			NI:             ulStatus.Network,
			NetAdapterName: ulStatus.Name,
			VIFNum:         ulNum,
			GuestIfMAC:     ulStatus.Mac,
			GuestIP:        guestIP,
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
	appConnRecStatus, err := z.niReconciler.ConnectApp(
		z.runCtx, config, status.AppNum, vifs)
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
	for _, ulStatus := range status.UnderlayNetworkList {
		netInstStatus := z.lookupNetworkInstanceStatus(ulStatus.Network.String())
		if netInstStatus == nil {
			err := fmt.Errorf("missing network instance status for %s",
				ulStatus.Network.String())
			z.log.Error(err)
			continue
		}
		if netInstStatus.Type == types.NetworkInstanceTypeSwitch {
			if ulStatus.AccessVlanID <= 1 {
				netInstStatus.NumTrunkPorts++
			} else {
				netInstStatus.VlanMap[ulStatus.AccessVlanID]++
			}
		}
		netInstStatus.AddVif(z.log, ulStatus.Vif, ulStatus.Mac,
			status.UUIDandVersion.UUID)
		netInstStatus.IPAssignments[ulStatus.Mac.String()] =
			types.AssignedAddrs{
				IPv4Addr:  ulStatus.AllocatedIPv4Addr,
				IPv6Addrs: ulStatus.AllocatedIPv6List,
			}
		z.publishNetworkInstanceStatus(netInstStatus)
	}
}

func (z *zedrouter) updateNIStatusAfterAppNetworkInactivate(
	status *types.AppNetworkStatus) {
	for _, ulStatus := range status.UnderlayNetworkList {
		netInstStatus := z.lookupNetworkInstanceStatus(ulStatus.Network.String())
		if netInstStatus == nil {
			err := fmt.Errorf("missing network instance status for %s",
				ulStatus.Network.String())
			z.log.Error(err)
			continue
		}
		if netInstStatus.Type == types.NetworkInstanceTypeSwitch {
			if ulStatus.AccessVlanID <= 1 {
				netInstStatus.NumTrunkPorts--
			} else {
				netInstStatus.VlanMap[ulStatus.AccessVlanID]--
			}
		}
		netInstStatus.RemoveVif(z.log, ulStatus.Vif)
		delete(netInstStatus.IPAssignments, ulStatus.Mac.String())
		z.publishNetworkInstanceStatus(netInstStatus)
	}
}

func (z *zedrouter) doCopyAppNetworkConfigToStatus(
	config types.AppNetworkConfig,
	status *types.AppNetworkStatus) {

	ulcount := len(config.UnderlayNetworkList)
	prevNetStatus := status.UnderlayNetworkList
	status.UnderlayNetworkList = make([]types.UnderlayNetworkStatus, ulcount)
	for i, netConfig := range config.UnderlayNetworkList {
		// Preserve previous VIF status unless it was moved to another network.
		// Note that adding or removing VIF is not currently supported
		// (such change would be rejected by config validation methods,
		// see zedrouter/validation.go).
		if i < len(prevNetStatus) && prevNetStatus[i].Network == netConfig.Network {
			status.UnderlayNetworkList[i] = prevNetStatus[i]
		}
		status.UnderlayNetworkList[i].UnderlayNetworkConfig = netConfig
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
	appConnRecStatus, err := z.niReconciler.ReconnectApp(
		z.runCtx, newConfig, vifs)
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
	appConnRecStatus, err := z.niReconciler.DisconnectApp(z.runCtx, config.UUIDandVersion.UUID)
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

	// Check if any underlays have changes to the Networks
	for i := range config.UnderlayNetworkList {
		ulConfig := &config.UnderlayNetworkList[i]
		ulStatus := &status.UnderlayNetworkList[i]
		if ulConfig.Network == ulStatus.Network {
			continue
		}
		z.log.Functionf(
			"checkAppNetworkModifyAppIntfNums(%v) for %s: change from %s to %s",
			config.UUIDandVersion, config.DisplayName,
			ulStatus.Network, ulConfig.Network)
		// update the reference to the network instance
		err := z.doAppNetworkModifyAppIntfNum(
			status.UUIDandVersion.UUID, ulConfig, ulStatus)
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

// handle a change to the network UUID for one UnderlayNetworkConfig.
// Assumes the caller has checked that such a change is present.
// Release the current appIntfNum and acquire appIntfNum on the new network instance.
func (z *zedrouter) doAppNetworkModifyAppIntfNum(appID uuid.UUID,
	ulConfig *types.UnderlayNetworkConfig,
	ulStatus *types.UnderlayNetworkStatus) error {

	newNetworkID := ulConfig.Network
	oldNetworkID := ulStatus.Network
	newIfIdx := ulConfig.IfIdx
	oldIfIdx := ulStatus.IfIdx

	// Try to release the app number on the old network.
	err := z.freeAppIntfNum(oldNetworkID, appID, oldIfIdx)
	if err != nil {
		z.log.Error(err)
		// Continue anyway...
	}

	// Allocate an app number on the new network.
	withStaticIP := ulConfig.AppIPAddr != nil
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
