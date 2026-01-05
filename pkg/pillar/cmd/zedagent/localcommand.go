// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"fmt"
	"time"

	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// bootOrderEvalResult holds the result of evaluating boot order from all sources.
type bootOrderEvalResult struct {
	BootOrder zcommon.BootOrder
	Source    profile.BootOrderSource
}

// evaluateAppBootOrder determines the effective boot order for an app by checking
// all configuration sources in precedence order:
//  1. LPS (Local Profile Server) - highest priority
//  2. Controller API (controllerBootOrder parameter)
//  3. Device configuration property (app.boot.order)
//  4. Default (BOOT_ORDER_UNSPECIFIED)
//
// Parameters:
//   - appUUID: the app to evaluate
//   - controllerBootOrder: the boot order from controller config (may be UNSPECIFIED)
//   - getconfigCtx: context to access LPS cache and global config
func evaluateAppBootOrder(
	appUUID uuid.UUID,
	controllerBootOrder zcommon.BootOrder,
	getconfigCtx *getconfigContext,
) bootOrderEvalResult {
	result := bootOrderEvalResult{
		BootOrder: zcommon.BootOrder_BOOT_ORDER_UNSPECIFIED,
		Source:    profile.BootOrderSource_BOOT_ORDER_SOURCE_UNSPECIFIED,
	}

	// Start with device property as the lowest-priority source.
	devicePropBootOrder := getconfigCtx.zedagentCtx.globalConfig.GlobalValueString(types.AppBootOrder)
	if devicePropBootOrder != "" {
		switch devicePropBootOrder {
		case "usb":
			result.BootOrder = zcommon.BootOrder_BOOT_ORDER_USB
			result.Source = profile.BootOrderSource_BOOT_ORDER_SOURCE_DEVICE_PROPERTY
		case "nousb":
			result.BootOrder = zcommon.BootOrder_BOOT_ORDER_NOUSB
			result.Source = profile.BootOrderSource_BOOT_ORDER_SOURCE_DEVICE_PROPERTY
		}
	}

	// Controller API takes precedence over device property.
	if controllerBootOrder != zcommon.BootOrder_BOOT_ORDER_UNSPECIFIED {
		result.BootOrder = controllerBootOrder
		result.Source = profile.BootOrderSource_BOOT_ORDER_SOURCE_CONTROLLER
	}

	// LPS takes highest precedence.
	lpsConfig := getconfigCtx.localCmdAgent.GetAppBootConfig(appUUID)
	if lpsConfig != nil && lpsConfig.BootOrder != zcommon.BootOrder_BOOT_ORDER_UNSPECIFIED {
		result.BootOrder = lpsConfig.BootOrder
		result.Source = profile.BootOrderSource_BOOT_ORDER_SOURCE_LPS
	}

	return result
}

// ApplyRadioSilence applies radio silence configuration.
func (zedagentCtx *zedagentContext) ApplyRadioSilence(types.RadioSilence) {
	// publishZedAgentStatus fetches and publishes the latest radio silence
	// configuration to NIM.
	publishZedAgentStatus(zedagentCtx.getconfigCtx)
}

// ApplyProfile applies a given profile, which then decides the subset of applications
// to activate.
func (zedagentCtx *zedagentContext) ApplyProfile(profile string) {
	// publishZedAgentStatus fetches and publishes the current profile to zedmanager.
	publishZedAgentStatus(zedagentCtx.getconfigCtx)
}

// ApplyLocalDeviceCommand applies a device command and reports if any changes
// were actually triggered.
func (zedagentCtx *zedagentContext) ApplyLocalDeviceCommand(
	devCmd types.DevCommand, timestamp uint64) (triggeredChanges bool) {
	getconfigCtx := zedagentCtx.getconfigCtx
	if devCmd == types.DevCommandCollectInfo {
		for key := range getconfigCtx.pubCollectInfoCmd.GetAll() {
			getconfigCtx.pubCollectInfoCmd.Unpublish(key)
		}
		key := time.Now().String()
		err := getconfigCtx.pubCollectInfoCmd.Publish(key, types.CollectInfoCmd{
			Time: time.Unix(0, int64(timestamp)),
		})
		if err != nil {
			log.Warnf("could not publish collect info cmd: %v", err)
		}
		return true
	}

	if getconfigCtx.updateInprogress {
		switch devCmd {
		case types.DevCommandUnspecified:
			// Do nothing
		case types.DevCommandShutdown:
			log.Noticef("Received shutdown from local profile server " +
				"during updateInProgress")
			zedagentCtx.shutdownCmdDeferred = true
		case types.DevCommandShutdownPoweroff:
			log.Noticef("Received shutdown_poweroff from local profile server " +
				"during updateInProgress")
			zedagentCtx.poweroffCmdDeferred = true
		case types.DevCommandGracefulReboot:
			log.Noticef("Received graceful-reboot from local profile server " +
				"during updateInProgress")
			zedagentCtx.rebootCmdDeferred = true
		}
		return false
	}

	// If HV=k and clustered, we may need to drain a replica first.
	// If so defer/block the node outage.
	if getconfigCtx.waitDrainInProgress {
		switch devCmd {
		case types.DevCommandUnspecified:
			// Do nothing
		case types.DevCommandShutdown:
			log.Noticef("Received shutdown from local profile server " +
				"during waitDrainInProgress")
			zedagentCtx.shutdownCmdDeferred = true
		case types.DevCommandShutdownPoweroff:
			log.Noticef("Received shutdown_poweroff from local profile server " +
				"during waitDrainInProgress")
			zedagentCtx.poweroffCmdDeferred = true
		case types.DevCommandGracefulReboot:
			log.Noticef("Received graceful-reboot from local profile server " +
				"during waitDrainInProgress")
			zedagentCtx.rebootCmdDeferred = true
		}
		return false
	}

	switch devCmd {
	case types.DevCommandUnspecified:
		// Do nothing
		return false
	case types.DevCommandShutdown:
		log.Noticef("Received shutdown from local profile server")
		if zedagentCtx.shutdownCmd || zedagentCtx.deviceShutdown {
			log.Warnf("Shutdown already in progress")
			return false
		}
		zedagentCtx.shutdownCmd = true
	case types.DevCommandShutdownPoweroff:
		log.Noticef("Received shutdown_poweroff from local profile server")
		if zedagentCtx.poweroffCmd || zedagentCtx.devicePoweroff {
			log.Warnf("Poweroff already in progress")
			return false
		}
		zedagentCtx.poweroffCmd = true
		infoStr := fmt.Sprintf("NORMAL: local profile server power off")
		zedagentCtx.requestedRebootReason = infoStr
		zedagentCtx.requestedBootReason = types.BootReasonPoweroffCmd
	case types.DevCommandGracefulReboot:
		log.Noticef("Received graceful+reboot from local profile server")
		if zedagentCtx.rebootCmd || zedagentCtx.deviceReboot {
			log.Warnf("Reboot already in progress")
			return false
		}
		zedagentCtx.rebootCmd = true
		infoStr := fmt.Sprintf("NORMAL: local profile graceful reboot")
		zedagentCtx.requestedRebootReason = infoStr
		zedagentCtx.requestedBootReason = types.BootReasonRebootCmd
	}

	// shutdown the application instances
	shutdownAppsGlobal(zedagentCtx)
	zedagentCtx.devState = getDeviceState(zedagentCtx)
	publishZedAgentStatus(getconfigCtx)

	// Ensure Controller, LOC and LPS receive the PREPARING_POWEROFF / POWERING_OFF
	// state update before the device/LPS shuts down.
	triggerPublishDevInfoToDest(zedagentCtx, AllDest)
	return true
}

// ApplyLocalAppRestartCmd applies a locally requested restart command for an app.
func (zedagentCtx *zedagentContext) ApplyLocalAppRestartCmd(
	appUUID uuid.UUID, localCmd types.AppInstanceOpsCmd) {
	pubAppInstanceConfig := zedagentCtx.getconfigCtx.pubAppInstanceConfig
	appObj, err := pubAppInstanceConfig.Get(appUUID.String())
	if err != nil {
		log.Errorf("ApplyLocalAppRestartCmd: failed to find configuration for app %v",
			appUUID)
		return
	}
	appConfig := appObj.(types.AppInstanceConfig)
	appConfig.LocalRestartCmd = localCmd
	checkAndPublishAppInstanceConfig(pubAppInstanceConfig, appConfig)
}

// ApplyLocalAppPurgeCmd applies a locally requested purge command for an app.
func (zedagentCtx *zedagentContext) ApplyLocalAppPurgeCmd(
	appUUID uuid.UUID, localCmd types.AppInstanceOpsCmd,
	localVolumeGenCounters map[string]int64) {
	pubAppInstanceConfig := zedagentCtx.getconfigCtx.pubAppInstanceConfig
	appObj, err := pubAppInstanceConfig.Get(appUUID.String())
	if err != nil {
		log.Errorf("ApplyLocalAppPurgeCmd: failed to find configuration for app %v",
			appUUID)
		return
	}
	appConfig := appObj.(types.AppInstanceConfig)
	appConfig.LocalPurgeCmd = localCmd

	// Trigger purge of all volumes used by the application.
	var changedVolumes bool
	for i := range appConfig.VolumeRefConfigList {
		vr := &appConfig.VolumeRefConfigList[i]
		uuid := vr.VolumeID.String()
		remoteGenCounter := vr.GenerationCounter
		prevLocalGenCounter := vr.LocalGenerationCounter
		newLocalGenCounter := localVolumeGenCounters[uuid]
		if prevLocalGenCounter == newLocalGenCounter {
			continue
		}
		// Un-publish volume with the current counters.
		volKey := volumeKey(uuid, remoteGenCounter, prevLocalGenCounter)
		pubVolumeConfig := zedagentCtx.getconfigCtx.pubVolumeConfig
		volObj, _ := pubVolumeConfig.Get(volKey)
		if volObj == nil {
			log.Warnf("Failed to find volume %s referenced by app instance "+
				"with UUID=%s - not purging this volume", volKey, appUUID)
			continue
		}
		volume := volObj.(types.VolumeConfig)
		unpublishVolumeConfig(pubVolumeConfig, volKey)
		// Publish volume with the new generation counter.
		vr.LocalGenerationCounter = newLocalGenCounter
		volume.LocalGenerationCounter = newLocalGenCounter
		publishVolumeConfig(pubVolumeConfig, volume)
		changedVolumes = true
	}
	checkAndPublishAppInstanceConfig(pubAppInstanceConfig, appConfig)
	if changedVolumes {
		signalVolumeConfigChange(zedagentCtx.getconfigCtx)
	}
}

// ApplyLocalNetworkConfig applies a network port configuration received from LPS,
// overriding the active configuration for the set of locally changed ports.
func (zedagentCtx *zedagentContext) ApplyLocalNetworkConfig(dpc types.DevicePortConfig) {
	// Publish to NIM under the key "lps" to distinguish it from controller/LOC
	// configuration (which is published under "zedagent").
	zedagentCtx.getconfigCtx.pubDevicePortConfig.Publish(types.LpsDPCKey, dpc)
}

// ApplyAppBootConfig applies boot configuration for an app received from LPS.
// This re-evaluates the effective boot order using the stored ControllerBootOrder
// and current device property, respecting the precedence: LPS > Controller > DeviceProperty.
func (zedagentCtx *zedagentContext) ApplyAppBootConfig(appUUID uuid.UUID) {

	// Lock to protect the read-modify-write cycle
	zedagentCtx.getconfigCtx.bootOrderUpdateMx.Lock()
	defer zedagentCtx.getconfigCtx.bootOrderUpdateMx.Unlock()

	pubAppInstanceConfig := zedagentCtx.getconfigCtx.pubAppInstanceConfig
	appObj, err := pubAppInstanceConfig.Get(appUUID.String())
	if err != nil {
		// App not found - might not be deployed yet or already deleted
		log.Warnf("ApplyAppBootConfig: AppInstanceConfig not found for %s: %v",
			appUUID.String(), err)
		return
	}

	appConfig := appObj.(types.AppInstanceConfig)

	// Re-evaluate boot order using the helper function.
	// This properly considers all sources: LPS (new value), Controller (stored), DeviceProperty.
	result := evaluateAppBootOrder(appUUID, appConfig.ControllerBootOrder, zedagentCtx.getconfigCtx)

	// Update boot order if changed
	if appConfig.FixedResources.BootOrder != result.BootOrder ||
		appConfig.BootOrderSource != result.Source {
		log.Noticef("ApplyAppBootConfig: Updating %s (%s) BootOrder: %s -> %s (source: %s)",
			appUUID.String(), appConfig.DisplayName,
			appConfig.FixedResources.BootOrder, result.BootOrder, result.Source)

		appConfig.FixedResources.BootOrder = result.BootOrder
		appConfig.BootOrderSource = result.Source
		checkAndPublishAppInstanceConfig(pubAppInstanceConfig, appConfig)

		// Trigger immediate POST of boot order info to LPS
		zedagentCtx.getconfigCtx.localCmdAgent.TriggerAppBootInfoPOST()
	} else {
		log.Functionf("ApplyAppBootConfig: No change needed for %s (already %s from %s)",
			appUUID.String(), result.BootOrder, result.Source)
	}
}

// ApplyDevicePropertyBootOrder is called when app.boot.order device property changes.
// This re-evaluates the effective boot order for all apps using the stored
// ControllerBootOrder, current LPS config, and the new device property value.
// Returns true if any app was actually updated.
func (zedagentCtx *zedagentContext) ApplyDevicePropertyBootOrder() (changed bool) {

	// Lock to protect the entire batch of read-modify-write operations
	zedagentCtx.getconfigCtx.bootOrderUpdateMx.Lock()
	defer zedagentCtx.getconfigCtx.bootOrderUpdateMx.Unlock()

	pubAppInstanceConfig := zedagentCtx.getconfigCtx.pubAppInstanceConfig

	// Iterate over all apps and re-evaluate boot order with proper precedence
	for _, appObj := range pubAppInstanceConfig.GetAll() {
		appConfig := appObj.(types.AppInstanceConfig)
		appUUID := appConfig.UUIDandVersion.UUID

		// Re-evaluate boot order using the helper function.
		// This properly considers all sources: LPS, Controller (stored), DeviceProperty (new).
		result := evaluateAppBootOrder(appUUID, appConfig.ControllerBootOrder, zedagentCtx.getconfigCtx)

		// Update if changed
		if appConfig.FixedResources.BootOrder != result.BootOrder ||
			appConfig.BootOrderSource != result.Source {
			log.Noticef("ApplyDevicePropertyBootOrder: Updating %s (%s) BootOrder: %s -> %s (source: %s)",
				appUUID.String(), appConfig.DisplayName,
				appConfig.FixedResources.BootOrder, result.BootOrder, result.Source)

			appConfig.FixedResources.BootOrder = result.BootOrder
			appConfig.BootOrderSource = result.Source
			checkAndPublishAppInstanceConfig(pubAppInstanceConfig, appConfig)
			changed = true
		}
	}
	return changed
}
