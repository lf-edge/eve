// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"fmt"
	"net/http"
	"time"

	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

const (
	// appBootConfigURLPath is the REST API path used to fetch app boot configuration from LPS.
	appBootConfigURLPath = "/api/v1/app-boot-config"
	// savedAppBootConfigFile is the filename used to persist the last received app boot config.
	savedAppBootConfigFile = "lastappbootconfig"
	// appBootConfigInterval defines the normal interval for periodic GET requests.
	appBootConfigInterval = 10 * time.Second
	// appBootConfigThrottledInterval is the backoff interval used when LPS
	// signals throttling by returning HTTP 404.
	appBootConfigThrottledInterval = 5 * time.Minute
)

// initializeAppBootConfig initializes the app boot configuration and sets up the periodic ticker.
// Loads persisted configuration if available, otherwise starts with empty config.
func (lc *LocalCmdAgent) initializeAppBootConfig() {
	lc.currentAppBootConfigs = make(map[uuid.UUID]types.AppBootConfig)
	lc.appBootConfigTicker = newTaskTicker(appBootConfigInterval)
	if !lc.loadSavedAppBootConfig() {
		// Invalid or missing configuration - start with empty.
		lc.saveAppBootConfig(&profile.AppBootConfigList{AppConfigs: nil})
	}
}

// runAppBootConfigTask continuously fetches app boot configuration from LPS at periodic intervals.
func (lc *LocalCmdAgent) runAppBootConfigTask() {
	wdName := watchdogPrefix + "appbootconfig"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	lc.Watchdog.RegisterFileWatchdog(wdName)

	// task fetches app boot configuration from LPS and applies it.
	// It uses taskControl to coordinate with pause/resume operations:
	//   - startTask() checks if tasks are paused; if so, it skips this iteration
	//     and returns true. This allows Pause() callers to safely modify shared state.
	//   - endTask() signals that this task iteration is complete, allowing
	//     pending Pause() calls to proceed.
	// The getAppBootConfig() call may be interrupted by a pause request; if so,
	// it returns discarded=true and the response is ignored to avoid applying
	// stale configuration after state changes.
	task := func() {
		if paused := lc.tc.startTask(); paused {
			return
		}
		defer lc.tc.endTask()
		start := time.Now()
		config, discarded := lc.getAppBootConfig()
		if discarded {
			return
		}
		lc.processReceivedAppBootConfig(config)
		lc.Watchdog.CheckMaxTimeTopic(wdName, "appBootConfigTask", start,
			warningTime, errorTime)
	}

	//
	// On first run, currentAppBootConfigs already contains configs loaded from disk
	// during initialization. These are applied here before fetching from LPS.
	// This ensures boot order is set even if LPS is unreachable.
	//
	// When LPS responds, processReceivedAppBootConfig() compares against the cache
	// and only applies changes, so there's no conflict between saved and new configs.
	if len(lc.currentAppBootConfigs) > 0 {
		lc.Log.Noticef("%s: Applying %d saved app boot configs", logPrefix, len(lc.currentAppBootConfigs))
		for appUUID, config := range lc.currentAppBootConfigs {
			lc.Log.Noticef("%s: Applying saved AppBootConfig: UUID=%s, BootOrder=%s",
				logPrefix, appUUID.String(), config.BootOrder)
			lc.ConfigAgent.ApplyAppBootConfig(appUUID, config.BootOrder)
		}
	}

	// Run immediately on startup - all dependencies (RunArgs, lpsAddresses, etc.)
	// are already set before this goroutine is started by RunTasks().
	task()

	for {
		select {
		case <-lc.appBootConfigTicker.tickerChan():
			task()
		case <-stillRunning.C:
		}
		lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

// TriggerAppBootConfigGET manually triggers the app boot config GET ticker.
func (lc *LocalCmdAgent) TriggerAppBootConfigGET() {
	lc.appBootConfigTicker.tickNow()
}

// updateAppBootConfigTicker adjusts the appBootConfigTicker's interval.
// If throttling is enabled, the interval is stretched to the throttled interval
// (5 minutes); otherwise, it returns to the normal 10 seconds cadence.
func (lc *LocalCmdAgent) updateAppBootConfigTicker(throttle bool) {
	interval := appBootConfigInterval
	if throttle {
		interval = appBootConfigThrottledInterval
	}
	lc.appBootConfigTicker.update(throttle, interval)
}

// getAppBootConfig queries LPS for the desired app boot configuration.
//
// The function iterates over all known LPS addresses and attempts to fetch the config.
// It returns on the first successful response or after all addresses have been tried.
//
// Cancellation:
// The HTTP request is wrapped in runInterruptible(), which allows the request to be
// cancelled if a pause is requested (e.g., when UpdateLpsConfig() changes the LPS address).
// If cancelled, the function returns discarded=true, signaling to the caller that the
// response should be ignored because the LPS configuration may have changed during the request.
// This prevents applying stale configuration from an old LPS instance.
//
// Return values:
//   - config: The received AppBootConfigList, or nil if no new config is available
//   - discarded: true if the request was cancelled due to a pause; the caller should
//     not process the response and should retry soon
//
// HTTP status code handling:
//   - 200/201 (OK/Created): Config received successfully, returns the config
//   - 204 (No Content): No changes since last fetch, returns nil (not an error)
//   - 404 (Not Found): LPS has no config for this device, enables throttled polling
//     (5 minutes instead of 10 seconds) to reduce load
//   - Other codes: Logged as error, tries next LPS address
//
// Note: The HTTP response body is already closed by SendLocalProto/SendLocal before
// returning, so there is no resource leak even when discarded=true or on early return.
func (lc *LocalCmdAgent) getAppBootConfig() (config *profile.AppBootConfigList, discarded bool) {
	if lc.lpsURL == nil {
		// LPS is not configured, nothing to do.
		return nil, false
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf(
			"%s: getAppBootConfig: cannot find any configured apps for LPS URL: %s",
			logPrefix, lc.lpsURL)
		return nil, false
	}

	var (
		err     error
		resp    *http.Response
		errList []string
	)
	for intf, srvAddrs := range lc.lpsAddresses.addrsByIface {
		for _, srvAddr := range srvAddrs {
			fullURL := srvAddr.destURL.String() + appBootConfigURLPath
			config = &profile.AppBootConfigList{}
			wasPaused := lc.tc.runInterruptible(func() {
				// Send empty request body, just requesting the config from LPS
				resp, err = lc.CtrlClient.SendLocalProto(
					fullURL, intf, srvAddr.sourceIP, nil, config)
			})
			if wasPaused {
				lc.Log.Functionf("%s: getAppBootConfig: LPS response discarded "+
					"due to task pause", logPrefix)
				// Retry ASAP to minimize delay in fetching the latest app boot config.
				lc.TriggerAppBootConfigGET()
				return nil, true
			}
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				// Throttle sending to be about once per 5 minutes.
				lc.updateAppBootConfigTicker(true)
				return nil, false
			case http.StatusOK, http.StatusCreated:
				if config.GetServerToken() != lc.lpsConfig.LpsToken {
					errList = append(errList, "invalid token submitted by LPS")
					continue
				}
				lc.Log.Noticef("%s: Received app boot config for %d apps",
					logPrefix, len(config.GetAppConfigs()))
				for _, appCfg := range config.GetAppConfigs() {
					lc.Log.Noticef("%s: App %s (%s) BootOrder: %s",
						logPrefix, appCfg.GetId(), appCfg.GetDisplayname(), appCfg.GetUsbBoot())
				}
				lc.updateAppBootConfigTicker(false)
				return config, false
			case http.StatusNoContent:
				lc.Log.Tracef("%s: LPS %s does not require change in app boot config",
					logPrefix, lc.lpsURL)
				lc.updateAppBootConfigTicker(false)
				return nil, false
			default:
				errList = append(errList, fmt.Sprintf(
					"wrong response status code: %d", resp.StatusCode))
			}
		}
	}
	lc.Log.Warnf("%s: getAppBootConfig failed: %v", logPrefix, errList)
	return nil, false
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

	lc.appBootConfigMx.Lock()
	defer lc.appBootConfigMx.Unlock()

	// Track which apps are in this config (used to detect removed apps)
	seenApps := make(map[uuid.UUID]bool)
	// Track if any changes occurred (to avoid unnecessary disk writes)
	configChanged := false

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
		// Note: usb_boot="" is a valid value (explicit default), different from missing field.
		if existingConfig, exists := lc.currentAppBootConfigs[appUUID]; exists {
			if existingConfig.BootOrder == bootOrder {
				lc.Log.Tracef("%s: AppBootConfig unchanged for %s, skipping apply",
					logPrefix, appUUID.String())
				continue
			}
		}

		// Apply the change via ConfigAgent (this triggers republish to domainmgr)
		lc.Log.Noticef("%s: Applying AppBootConfig: UUID=%s, Name=%s, BootOrder=%s",
			logPrefix, appUUID.String(), appInst.DisplayName, bootOrder)

		lc.ConfigAgent.ApplyAppBootConfig(appUUID, bootOrder)
		configChanged = true

		// Update local cache
		lc.currentAppBootConfigs[appUUID] = types.AppBootConfig{
			AppUUID:     appUUID,
			DisplayName: appInst.DisplayName,
			BootOrder:   bootOrder,
		}
	}

	// Reset boot order for apps that were removed from LPS config.
	// This is how LPS clears a previously set boot order for specific apps.
	for appUUID := range lc.currentAppBootConfigs {
		if !seenApps[appUUID] {
			lc.Log.Noticef("%s: Resetting BootOrder for app no longer in LPS config: %s",
				logPrefix, appUUID.String())
			lc.ConfigAgent.ApplyAppBootConfig(appUUID, "")
			delete(lc.currentAppBootConfigs, appUUID)
			configChanged = true
		}
	}

	// Persist only if something changed (avoid unnecessary disk I/O)
	if configChanged {
		lc.saveAppBootConfig(config)
		lc.Log.Noticef("%s: Applied app boot config changes for %d apps", logPrefix, len(seenApps))
	} else {
		lc.Log.Tracef("%s: App boot config unchanged, no action taken", logPrefix)
	}
}

// GetAppBootConfig returns the LPS-set app boot configuration for
// the given app, or nil if no config exists for this app.
func (lc *LocalCmdAgent) GetAppBootConfig(appUUID uuid.UUID) *types.AppBootConfig {
	lc.appBootConfigMx.RLock()
	defer lc.appBootConfigMx.RUnlock()
	if bootConfig, exists := lc.currentAppBootConfigs[appUUID]; exists {
		return &bootConfig
	}
	return nil
}

// loadSavedAppBootConfig loads the last saved app boot configuration from disk
// and populates the currentAppBootConfigs cache. The actual application of configs
// (calling ApplyAppBootConfig) is deferred to runAppBootConfigTask() because
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
	for _, protoConfig := range config.GetAppConfigs() {
		appUUID, err := uuid.FromString(protoConfig.GetId())
		if err != nil {
			lc.Log.Warnf("%s: Invalid UUID in saved config: %s", logPrefix, protoConfig.GetId())
			continue
		}
		lc.currentAppBootConfigs[appUUID] = types.AppBootConfig{
			AppUUID:     appUUID,
			DisplayName: protoConfig.GetDisplayname(),
			BootOrder:   protoConfig.GetUsbBoot(),
		}
	}

	lc.Log.Noticef("%s: Loaded saved app boot config dated %s with %d entries (will apply when ready)",
		logPrefix, ts.Format(time.RFC3339Nano), len(lc.currentAppBootConfigs))
	return true
}

// saveAppBootConfig saves app boot configuration to disk for persistence.
func (lc *LocalCmdAgent) saveAppBootConfig(config *profile.AppBootConfigList) {
	contents, err := proto.Marshal(config)
	if err != nil {
		lc.Log.Fatalf("%s: Marshalling app boot config failed: %v", logPrefix, err)
	}
	persist.SaveConfig(lc.Log, savedAppBootConfigFile, contents)
	lc.Log.Tracef("%s: Saved app boot config to disk", logPrefix)
}
