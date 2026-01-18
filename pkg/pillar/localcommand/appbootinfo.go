// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

const (
	// appBootInfoURLPath is the API endpoint on the Local Profile Server (LPS)
	// used to POST application boot information and receive boot configuration.
	appBootInfoURLPath = "/api/v1/appbootinfo"
	// savedAppBootConfigFile is the filename used to persist the last received app boot config.
	savedAppBootConfigFile = "lastappbootconfig"
	// appBootInfoPOSTInterval is the normal interval between app boot info POSTs.
	appBootInfoPOSTInterval = time.Minute
	// appBootInfoPOSTThrottledInterval is the backoff interval used when LPS
	// signals throttling by returning HTTP 404.
	appBootInfoPOSTThrottledInterval = time.Hour
)

// initializeAppBootInfo sets up the ticker for periodic app boot info POSTs
// and loads persisted boot configuration from disk.
func (lc *LocalCmdAgent) initializeAppBootInfo() {
	// sync.Map doesn't need initialization
	lc.appBootInfoTicker = newTaskTicker(appBootInfoPOSTInterval)
	if !lc.loadSavedAppBootConfig() {
		// Invalid or missing configuration - start with empty.
		lc.saveAppBootConfig(&profile.AppBootConfigList{AppConfigs: nil})
	}
}

// runAppBootInfoTask runs a long-lived loop that periodically POSTs application
// boot order information to the LPS and processes any boot configuration received
// in response. This follows the standard LPS pattern where EVE posts status and
// receives config in response.
func (lc *LocalCmdAgent) runAppBootInfoTask() {

	wdName := watchdogPrefix + "appbootinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	lc.Watchdog.RegisterFileWatchdog(wdName)

	// task posts app boot info and processes any config received in response.
	// It uses taskControl to coordinate with pause/resume operations:
	//   - startTask() checks if tasks are paused; if so, it skips this iteration
	//     and returns true. This allows Pause() callers to safely modify shared state.
	//   - endTask() signals that this task iteration is complete, allowing
	//     pending Pause() calls to proceed.
	// The postAppBootInfo() call may be interrupted by a pause request; if so,
	// it returns discarded=true and the response is ignored to avoid applying
	// stale configuration after state changes.
	task := func() {
		if paused := lc.tc.startTask(); paused {
			return
		}
		defer lc.tc.endTask()
		start := time.Now()
		config, discarded := lc.postAppBootInfo()
		if discarded {
			return
		}
		lc.processReceivedAppBootConfig(config)
		lc.Watchdog.CheckMaxTimeTopic(wdName, "appBootInfoTask", start,
			warningTime, errorTime)
	}

	//
	// On first run, currentAppBootConfigs already contains configs loaded from disk
	// during initialization. These are applied here before fetching from LPS.
	// This ensures boot order is set even if LPS is unreachable.
	//
	// When LPS responds, processReceivedAppBootConfig() compares against the cache
	// and only applies changes, so there's no conflict between saved and new configs.
	//
	// Collect saved configs first, then apply them.
	// sync.Map.Range is safe to call concurrently.
	var savedConfigs []types.AppBootConfig
	lc.currentAppBootConfigs.Range(func(key, value interface{}) bool {
		config := value.(types.AppBootConfig)
		savedConfigs = append(savedConfigs, config)
		return true
	})

	if len(savedConfigs) > 0 {
		lc.Log.Noticef("%s: Applying %d saved app boot configs", logPrefix, len(savedConfigs))
		for _, config := range savedConfigs {
			lc.Log.Noticef("%s: Applying saved AppBootConfig: UUID=%s, BootOrder=%s",
				logPrefix, config.AppUUID.String(), config.BootOrder)
			lc.ConfigAgent.ApplyAppBootConfig(config.AppUUID)
		}
	}

	// Run immediately on startup - all dependencies (RunArgs, lpsAddresses, etc.)
	// are already set before this goroutine is started by RunTasks().
	task()

	for {
		select {
		case <-lc.appBootInfoTicker.tickerChan():
			task()
		case <-stillRunning.C:
		}
		lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

// TriggerAppBootInfoPOST forces an immediate tick of the appBootInfoTicker.
func (lc *LocalCmdAgent) TriggerAppBootInfoPOST() {
	lc.appBootInfoTicker.tickNow()
}

// updateAppBootInfoTicker adjusts the appBootInfoTicker's interval.
// If throttling is enabled, the interval is stretched to the throttled interval
// (1 hour); otherwise, it returns to the normal 1-minute cadence.
func (lc *LocalCmdAgent) updateAppBootInfoTicker(throttle bool) {
	interval := appBootInfoPOSTInterval
	if throttle {
		interval = appBootInfoPOSTThrottledInterval
	}
	lc.appBootInfoTicker.update(throttle, interval)
}

// postAppBootInfo sends the effective boot order and source information for all
// application instances to the LPS, and receives boot configuration in response.
//
// This follows the standard LPS pattern (like /api/v1/appinfo, /api/v1/radio):
// EVE POSTs status, LPS responds with configuration.
//
// Return values:
//   - config: The received AppBootConfigList, or nil if no new config is available
//   - discarded: true if the request was cancelled due to a pause; the caller should
//     not process the response and should retry soon
//
// HTTP status code handling:
//   - 200/201 (OK/Created): Config received successfully, returns the config
//   - 204 (No Content): No changes needed, returns nil (cache preserved)
//   - 404 (Not Found): LPS has no config for this device, returns empty config
//     to clear all LPS-set boot orders. Enables throttled posting (1 hour).
//   - Other codes: Logged as error, tries next LPS address
func (lc *LocalCmdAgent) postAppBootInfo() (config *profile.AppBootConfigList, discarded bool) {
	if lc.lpsURL == nil {
		// LPS is not configured.
		return nil, false
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf("%s: postAppBootInfo: cannot find any configured apps "+
			"for LPS URL: %s", logPrefix, lc.lpsURL)
		return nil, false
	}

	bootInfoList := lc.prepareAppBootInfo()
	// Note: We still POST even if there are no apps to report, so LPS can
	// respond with configuration (e.g., clearing cache on 404).

	var (
		err     error
		resp    *http.Response
		errList []string
	)
	for intf, srvAddrs := range lc.lpsAddresses.addrsByIface {
		for _, srvAddr := range srvAddrs {
			fullURL := srvAddr.destURL.String() + appBootInfoURLPath
			config = &profile.AppBootConfigList{}
			wasPaused := lc.tc.runInterruptible(func() {
				// POST boot info, receive boot config in response
				resp, err = lc.CtrlClient.SendLocalProto(
					fullURL, intf, srvAddr.sourceIP, bootInfoList, config)
			})
			if wasPaused {
				lc.Log.Functionf("%s: postAppBootInfo: LPS response discarded "+
					"due to task pause", logPrefix)
				// Retry ASAP to minimize delay in publishing boot info.
				lc.TriggerAppBootInfoPOST()
				return nil, true
			}
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				// 404 means LPS has no config for this device - clear all LPS-set boot orders.
				// This is different from network errors which preserve the cache.
				// Throttle posting to reduce load on LPS.
				lc.updateAppBootInfoTicker(true)
				lc.Log.Noticef("%s: LPS returned 404 - clearing all app boot configs", logPrefix)
				return &profile.AppBootConfigList{AppConfigs: nil}, false
			case http.StatusOK, http.StatusCreated:
				// Validate token for all 200/201 responses
				if config.GetServerToken() != lc.lpsConfig.LpsToken {
					errList = append(errList, "invalid token submitted by LPS")
					continue
				}
				if len(config.GetAppConfigs()) > 0 {
					lc.Log.Noticef("%s: Received app boot config for %d apps",
						logPrefix, len(config.GetAppConfigs()))
					for _, appCfg := range config.GetAppConfigs() {
						lc.Log.Noticef("%s: App %s (%s) BootOrder: %s",
							logPrefix, appCfg.GetId(), appCfg.GetDisplayname(), appCfg.GetUsbBoot())
					}
				} else {
					// Empty config with 200/201 means "reset all apps to default".
					// This is different from 204 (no changes) - empty list explicitly
					// indicates no apps should have LPS-set boot order.
					lc.Log.Noticef("%s: Received empty app boot config - resetting all apps to default",
						logPrefix)
				}
				lc.updateAppBootInfoTicker(false)
				return config, false
			case http.StatusNoContent:
				lc.Log.Tracef("%s: postAppBootInfo: successfully posted boot info for %d apps, no config changes",
					logPrefix, len(bootInfoList.AppsBootInfo))
				lc.updateAppBootInfoTicker(false)
				return nil, false
			default:
				errList = append(errList, fmt.Sprintf(
					"wrong response status code: %d", resp.StatusCode))
				continue
			}
		}
	}
	lc.Log.Errorf("%s: postAppBootInfo: all attempts failed: %s",
		logPrefix, strings.Join(errList, ";"))
	return nil, false
}

// prepareAppBootInfo builds the AppBootInfoList message from current app configs.
func (lc *LocalCmdAgent) prepareAppBootInfo() *profile.AppBootInfoList {
	msg := &profile.AppBootInfoList{}

	// Read app instance configs to get the effective boot order and source.
	for _, value := range lc.AppInstanceConfig.GetAll() {
		appConfig, ok := value.(types.AppInstanceConfig)
		if !ok {
			continue
		}
		bootInfo := &profile.AppBootInfo{
			Id:          appConfig.UUIDandVersion.UUID.String(),
			Displayname: appConfig.DisplayName,
			BootOrder:   appConfig.FixedResources.BootOrder,
			Source:      appConfig.BootOrderSource,
		}
		msg.AppsBootInfo = append(msg.AppsBootInfo, bootInfo)
	}
	return msg
}

// processReceivedAppBootConfig processes app boot configuration received from LPS.
//
// Processing flow for each app in the config:
//  1. Resolves the app by UUID or displayname (at least one must be provided)
//  2. Compares with cached config to detect changes
//  3. Applies changed configs via ConfigAgent.ApplyAppBootConfig()
//  4. Updates local cache with new values
//
// Special cases:
//   - nil config: No action (normal when LPS not configured or returns 204)
//   - App removed from config: Resets that app to default (this includes empty config
//     which resets ALL apps since all are considered "removed")
//   - App with usb_boot="": Explicitly sets that app to default (empty string)
//   - Same config received: No action taken (optimizes 200 with unchanged content to behave like 204)
//
// How to reset boot order to default:
//   - To reset a specific app: Either remove it from config OR set usb_boot=""
//   - To reset all apps: Send empty config {"app_configs":[]}
//
// Persistence:
// Config is saved to disk only if something actually changed, avoiding unnecessary I/O.
func (lc *LocalCmdAgent) processReceivedAppBootConfig(config *profile.AppBootConfigList) {
	// nil config means no new data (LPS not configured, returned 204, etc.)
	if config == nil {
		return
	}

	// Track changes for applying and persistence
	type bootOrderChange struct {
		appUUID   uuid.UUID
		bootOrder zcommon.BootOrder
	}
	var changesToApply []bootOrderChange
	var configChanged bool

	// Track which apps are in this config (used to detect removed apps)
	seenApps := make(map[uuid.UUID]bool)

	// Process each app in the received config
	for _, protoConfig := range config.AppConfigs {
		var err error
		appUUID := uuid.Nil
		displayName := protoConfig.GetDisplayname()

		// Parse UUID if provided
		if protoConfig.GetId() != "" {
			appUUID, err = uuid.FromString(protoConfig.GetId())
			if err != nil {
				lc.Log.Warnf("%s: Failed to parse UUID from app boot config: %v",
					logPrefix, err)
				continue
			}
		}

		// Validate: at least one identifier required
		if appUUID == uuid.Nil && displayName == "" {
			lc.Log.Warnf("%s: App boot config is missing both UUID and display name",
				logPrefix)
			continue
		}

		// Resolve app instance by UUID or displayname
		appInst := lc.findAppInstance(appUUID, displayName)
		if appInst == nil {
			lc.Log.Warnf("%s: Failed to find app instance with UUID=%s, displayName=%s",
				logPrefix, appUUID, displayName)
			continue
		}

		// Use the resolved app's actual UUID
		appUUID = appInst.UUIDandVersion.UUID
		bootOrder := protoConfig.GetUsbBoot()
		seenApps[appUUID] = true

		// Skip if unchanged - makes 200 with same content behave like 204.
		if existingValue, exists := lc.currentAppBootConfigs.Load(appUUID); exists {
			existingConfig := existingValue.(types.AppBootConfig)
			if existingConfig.BootOrder == bootOrder {
				lc.Log.Tracef("%s: AppBootConfig unchanged for %s, skipping apply",
					logPrefix, appUUID.String())
				continue
			}
		}

		// Update cache. sync.Map handles concurrency internally.
		if bootOrder == zcommon.BootOrder_BOOT_ORDER_UNSPECIFIED {
			// LPS is explicitly clearing the override - remove from cache
			lc.currentAppBootConfigs.Delete(appUUID)
		} else {
			// LPS is setting a new value - update cache
			lc.currentAppBootConfigs.Store(appUUID, types.AppBootConfig{
				AppUUID:     appUUID,
				DisplayName: appInst.DisplayName,
				BootOrder:   bootOrder,
			})
		}

		lc.Log.Noticef("%s: Applying AppBootConfig: UUID=%s, Name=%s, BootOrder=%s",
			logPrefix, appUUID.String(), appInst.DisplayName, bootOrder)
		changesToApply = append(changesToApply, bootOrderChange{appUUID, bootOrder})
		configChanged = true
	}

	// Reset boot order for apps that were removed from LPS config.
	lc.currentAppBootConfigs.Range(func(key, value interface{}) bool {
		appUUID := key.(uuid.UUID)
		if !seenApps[appUUID] {
			lc.Log.Noticef("%s: Resetting BootOrder for app no longer in LPS config: %s",
				logPrefix, appUUID.String())
			lc.currentAppBootConfigs.Delete(appUUID)
			changesToApply = append(changesToApply, bootOrderChange{appUUID, zcommon.BootOrder_BOOT_ORDER_UNSPECIFIED})
			configChanged = true
		}
		return true
	})

	// Apply changes via ConfigAgent
	for _, change := range changesToApply {
		lc.ConfigAgent.ApplyAppBootConfig(change.appUUID)
	}

	// Persist only if something changed (avoid unnecessary disk I/O)
	if configChanged {
		lc.saveAppBootConfig(config)
		lc.Log.Noticef("%s: Applied app boot config changes for %d apps", logPrefix, len(changesToApply))
	} else {
		lc.Log.Tracef("%s: App boot config unchanged, no action taken", logPrefix)
	}
}

// GetAppBootConfig returns the LPS-set app boot configuration for
// the given app, or nil if no config exists for this app.
// This is safe to call from any goroutine - sync.Map handles concurrency.
func (lc *LocalCmdAgent) GetAppBootConfig(appUUID uuid.UUID) *types.AppBootConfig {
	if value, exists := lc.currentAppBootConfigs.Load(appUUID); exists {
		bootConfig := value.(types.AppBootConfig)
		return &bootConfig
	}
	return nil
}

// loadSavedAppBootConfig loads the last saved app boot configuration from disk
// and populates the currentAppBootConfigs cache. The actual application of configs
// (calling ApplyAppBootConfig) is deferred to runAppBootInfoTask() because
// AppInstanceConfig subscription is not available during initialization.
// Returns true if successfully loaded, false otherwise.
func (lc *LocalCmdAgent) loadSavedAppBootConfig() bool {
	configBytes, ts, err := persist.ReadSavedConfig(lc.Log, savedAppBootConfigFile)
	if err != nil {
		lc.Log.Warnf("%s: Failed to load saved app boot config: %v", logPrefix, err)
		return false
	}

	if configBytes == nil {
		lc.Log.Warnf("%s: No saved app boot config found", logPrefix)
		return false
	}

	config := &profile.AppBootConfigList{}
	if err := proto.Unmarshal(configBytes, config); err != nil {
		lc.Log.Errorf("%s: Unmarshalling app boot config failed: %v", logPrefix, err)
		return false
	}

	// Populate the cache with saved configs (will be applied on first task run)
	var count int
	for _, protoConfig := range config.GetAppConfigs() {
		appUUID, err := uuid.FromString(protoConfig.GetId())
		if err != nil {
			lc.Log.Warnf("%s: Invalid UUID in saved config: %s", logPrefix, protoConfig.GetId())
			continue
		}
		lc.currentAppBootConfigs.Store(appUUID, types.AppBootConfig{
			AppUUID:     appUUID,
			DisplayName: protoConfig.GetDisplayname(),
			BootOrder:   protoConfig.GetUsbBoot(),
		})
		count++
	}

	lc.Log.Noticef("%s: Loaded saved app boot config dated %s with %d entries (will apply when ready)",
		logPrefix, ts.Format(time.RFC3339Nano), count)
	return true
}

// saveAppBootConfig saves app boot configuration to disk for persistence.
func (lc *LocalCmdAgent) saveAppBootConfig(config *profile.AppBootConfigList) {
	contents, err := proto.Marshal(config)
	if err != nil {
		lc.Log.Errorf("%s: Marshalling app boot config failed: %v", logPrefix, err)
		return
	}
	persist.SaveConfig(lc.Log, savedAppBootConfigFile, contents)
	lc.Log.Tracef("%s: Saved app boot config to disk", logPrefix)
}
