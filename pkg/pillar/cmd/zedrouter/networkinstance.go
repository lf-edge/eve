// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"fmt"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/nireconciler"
	"github.com/lf-edge/eve/pkg/pillar/nistate"
	"github.com/lf-edge/eve/pkg/pillar/types"
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
		for _, ulStatus := range appNetStatus.GetULStatusForNI(niID) {
			vifs = append(vifs, nistate.AppVIF{
				App:            appNetStatus.UUIDandVersion.UUID,
				NI:             niID,
				AppNum:         appNetStatus.AppNum,
				NetAdapterName: ulStatus.Name,
				HostIfName:     ulStatus.Vif,
				GuestIfMAC:     ulStatus.Mac,
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
	return nireconciler.NIBridge{
		NI:         status.UUID,
		BrNum:      status.BridgeNum,
		MACAddress: status.BridgeMac,
		IPAddress:  ipAddr,
		Uplink:     z.getNIUplinkConfig(status),
	}
}

func (z *zedrouter) getNIUplinkConfig(
	status *types.NetworkInstanceStatus) nireconciler.Uplink {
	if status.PortLogicalLabel == "" {
		// Air-gapped
		return nireconciler.Uplink{}
	}
	ifName := status.SelectedUplinkIntfName
	if ifName == "" {
		return nireconciler.Uplink{}
	}
	port := z.deviceNetworkStatus.GetPortByIfName(ifName)
	if port == nil {
		return nireconciler.Uplink{}
	}
	return nireconciler.Uplink{
		LogicalLabel: port.Logicallabel,
		IfName:       ifName,
		DNSServers:   types.GetDNSServers(*z.deviceNetworkStatus, ifName),
		NTPServers:   types.GetNTPServers(*z.deviceNetworkStatus, ifName),
	}
}

// Update NI status and set interface name of the selected uplink
// referenced by a logical label.
func (z *zedrouter) setSelectedUplink(uplinkLogicalLabel string,
	status *types.NetworkInstanceStatus) (waitForUplink bool, err error) {
	if status.PortLogicalLabel == "" {
		// Air-gapped
		status.SelectedUplinkLogicalLabel = ""
		status.SelectedUplinkIntfName = ""
		return false, nil
	}
	status.SelectedUplinkLogicalLabel = uplinkLogicalLabel
	if uplinkLogicalLabel == "" {
		status.SelectedUplinkIntfName = ""
		// This is potentially a transient state, wait for DPC update
		// and uplink probing eventually finding a suitable uplink port.
		return true, fmt.Errorf("no selected uplink port")
	}
	ports := z.deviceNetworkStatus.GetPortsByLogicallabel(uplinkLogicalLabel)
	switch len(ports) {
	case 0:
		err = fmt.Errorf("label of selected uplink (%s) does not match any port (%v)",
			uplinkLogicalLabel, ports)
		// Wait for DPC update
		return true, err
	case 1:
		// OK
	default:
		err = fmt.Errorf("label of selected uplink matches multiple ports (%v)", ports)
		return false, err
	}
	ifName := ports[0].IfName
	status.SelectedUplinkIntfName = ifName
	ifIndex, exists, _ := z.networkMonitor.GetInterfaceIndex(ifName)
	if !exists {
		// Wait for uplink interface to appear in the network stack.
		return true, fmt.Errorf("missing uplink interface '%s'", ifName)
	}
	if status.IsUsingUplinkBridge() {
		_, ifMAC, _ := z.networkMonitor.GetInterfaceAddrs(ifIndex)
		status.BridgeMac = ifMAC
	}
	return false, nil
}

// This function is called on DPC update or when UplinkProber changes uplink port
// selected for network instance.
func (z *zedrouter) doUpdateNIUplink(uplinkLogicalLabel string,
	status *types.NetworkInstanceStatus, config types.NetworkInstanceConfig) {
	waitForUplink, err := z.setSelectedUplink(uplinkLogicalLabel, status)
	if err != nil {
		z.log.Errorf("doUpdateNIUplink(%s) for %s failed: %v", uplinkLogicalLabel,
			status.UUID, err)
		status.SetErrorNow(err.Error())
		z.publishNetworkInstanceStatus(status)
		return
	}
	if status.Activated {
		z.doUpdateActivatedNetworkInstance(config, status)
	}
	if status.WaitingForUplink && !waitForUplink {
		status.WaitingForUplink = false
		status.ClearError()
		if config.Activate && !status.Activated {
			z.doActivateNetworkInstance(config, status)
			z.checkAndRecreateAppNetworks(status.UUID)
		}
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
		status.SetErrorNow(err.Error())
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
		status.SetErrorNow(err.Error())
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
		status.SetErrorNow(err.Error())
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
	if status.RunningUplinkProbing {
		err := z.uplinkProber.StopNIProbing(status.UUID)
		if err != nil {
			z.log.Error(err)
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

// Called when a NetworkInstance is deleted or modified to check if there are other
// NIs that previously could not be configured due to inter-NI config conflicts.
func (z *zedrouter) checkConflictingNetworkInstances() {
	for _, item := range z.pubNetworkInstanceStatus.GetAll() {
		niStatus := item.(types.NetworkInstanceStatus)
		if !niStatus.NIConflict {
			continue
		}
		niConfig := z.lookupNetworkInstanceConfig(niStatus.Key())
		if niConfig == nil {
			continue
		}
		niConflict, err := z.doNetworkInstanceSanityCheck(niConfig)
		if err == nil && niConflict == false {
			// Try to re-create the network instance now that the conflict is gone.
			z.log.Noticef("Recreating NI %s (%s) now that inter-NI conflict "+
				"is not present anymore", niConfig.UUID, niConfig.DisplayName)
			// First release whatever has been already allocated for this NI.
			z.delNetworkInstance(&niStatus)
			z.handleNetworkInstanceCreate(nil, niConfig.Key(), *niConfig)
		}
	}
}
