// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	uuid "github.com/satori/go.uuid"
)

const (
	// appInfoURLPath is the API endpoint on the Local Profile Server (LPS)
	// used to POST application instance information and optionally receive
	// application commands (restart/purge).
	appInfoURLPath = "/api/v1/appinfo"
	// appInfoPOSTInterval is the normal interval between application info POSTs.
	appInfoPOSTInterval = time.Minute
	// appInfoPOSTThrottledInterval is the backoff interval used when LPS
	// signals throttling by returning HTTP 404.
	appInfoPOSTThrottledInterval = time.Hour
	// savedAppCommandsFile is the name of the file inside persist that stores
	// all currently known application command state (commands + counters).
	savedAppCommandsFile = "appCommands"
)

// emptyAppCmd is a zero-value AppInstanceOpsCmd used as a default
// return value when no local command exists for an app instance.
var emptyAppCmd types.AppInstanceOpsCmd // used as a constant

// initializeAppCommands sets up the ticker for periodic application info POSTs
// and restores saved application command state (counters + commands) from
// persistent storage. If no persisted state exists, it writes an initial empty
// structure to disk.
func (lc *LocalCmdAgent) initializeAppCommands() {
	lc.appCommands.VolumeGenCounters = make(map[string]int64)
	lc.appInfoTicker = newTaskTicker(appInfoPOSTInterval)
	if !lc.loadSavedAppCommands() {
		// Write the initial empty content.
		lc.persistAppCommands()
	}
}

// runAppInfoTask runs a long-lived loop that periodically POSTs application
// state to the LPS and, if present in the response, executes application
// commands (restart/purge). The task:
//   - Waits for an initial trigger from zedagent.
//   - Periodically POSTs app info, respecting throttling signals from LPS.
//   - Executes received commands by updating local counters and republishing
//     application configurations.
//   - Continuously updates a watchdog to confirm liveness.
func (lc *LocalCmdAgent) runAppInfoTask() {
	lc.Log.Functionf("%s: appInfoTask: waiting for the first trigger", logPrefix)
	// wait for the first trigger
	<-lc.appInfoTicker.tickerChan()
	lc.Log.Functionf("%s: appInfoTask: received the first trigger", logPrefix)
	// trigger again to pass into the loop
	lc.TriggerAppInfoPOST()

	wdName := watchdogPrefix + "appinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	lc.Watchdog.RegisterFileWatchdog(wdName)

	task := func() {
		if paused := lc.tc.startTask(); paused {
			return
		}
		defer lc.tc.endTask()
		start := time.Now()
		appCmds, discarded := lc.postAppInfo()
		if discarded {
			return
		}
		lc.processReceivedAppCommands(appCmds)
		lc.Watchdog.CheckMaxTimeTopic(wdName, "appInfoPOSTTask", start,
			warningTime, errorTime)
	}

	for {
		select {
		case <-lc.appInfoTicker.tickerChan():
			task()
		case <-stillRunning.C:
		}
		lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

// TriggerAppInfoPOST forces an immediate tick of the appInfoTicker.
func (lc *LocalCmdAgent) TriggerAppInfoPOST() {
	lc.appInfoTicker.tickNow()
}

// ProcessAppCommandStatus checks the status of an application instance and,
// if a locally requested command (restart/purge) has completed, marks it as
// finished and persists the updated state. Prevents reissuing commands that
// were already executed.
func (lc *LocalCmdAgent) ProcessAppCommandStatus(
	appStatus types.AppInstanceStatus) {
	lc.appCommandsMx.Lock()
	defer lc.appCommandsMx.Unlock()
	uuid := appStatus.UUIDandVersion.UUID.String()
	appCmd, hasAppCmd := lc.appCommands.AppCommands[uuid]
	if !hasAppCmd {
		// This app received no local command requests.
		return
	}
	if appCmd.Completed {
		// Nothing to update.
		return
	}
	if appStatus.PurgeInprogress != types.NotInprogress ||
		appStatus.RestartInprogress != types.NotInprogress {
		// A command is still ongoing.
		return
	}
	var updated bool
	switch appCmd.Command {
	case types.AppCommandRestart:
		if appStatus.RestartStartedAt.After(appCmd.DeviceTimestamp) {
			appCmd.Completed = true
			appCmd.LastCompletedTimestamp = appCmd.LocalServerTimestamp
			updated = true
			lc.Log.Noticef("%s: local restart completed: %+v", logPrefix, appCmd)
		}
	case types.AppCommandPurge:
		if appStatus.PurgeStartedAt.After(appCmd.DeviceTimestamp) {
			appCmd.Completed = true
			appCmd.LastCompletedTimestamp = appCmd.LocalServerTimestamp
			updated = true
			lc.Log.Noticef("%s: local purge completed: %+v", logPrefix, appCmd)
		}
	}
	if updated {
		lc.persistAppCommands()
	}
}

// GetLocalAppRestartCmd returns the most recent locally issued restart
// command for the given app, or an empty command if none exists.
func (lc *LocalCmdAgent) GetLocalAppRestartCmd(appUUID uuid.UUID) types.AppInstanceOpsCmd {
	lc.appCommandsMx.RLock()
	defer lc.appCommandsMx.RUnlock()
	appCounters, hasCounters := lc.appCommands.AppCounters[appUUID.String()]
	if hasCounters {
		return appCounters.RestartCmd
	}
	return emptyAppCmd
}

// GetLocalAppPurgeCmd returns the most recent locally issued purge
// command for the given app, or an empty command if none exists.
func (lc *LocalCmdAgent) GetLocalAppPurgeCmd(appUUID uuid.UUID) types.AppInstanceOpsCmd {
	lc.appCommandsMx.RLock()
	defer lc.appCommandsMx.RUnlock()
	appCounters, hasCounters := lc.appCommands.AppCounters[appUUID.String()]
	if hasCounters {
		return appCounters.PurgeCmd
	}
	return emptyAppCmd
}

// DelLocalAppCmds clears all local state (commands and counters) for the
// specified application and persists the updated appCommands.
func (lc *LocalCmdAgent) DelLocalAppCmds(appUUIDStr string) {
	lc.appCommandsMx.Lock()
	defer lc.appCommandsMx.Unlock()
	delete(lc.appCommands.AppCommands, appUUIDStr)
	delete(lc.appCommands.AppCounters, appUUIDStr)
	lc.persistAppCommands()
}

// GetLocalVolumeGenCounter returns the local generation counter for the
// specified volume, used to trigger application purges.
func (lc *LocalCmdAgent) GetLocalVolumeGenCounter(volumeUUID uuid.UUID) int64 {
	lc.appCommandsMx.RLock()
	defer lc.appCommandsMx.RUnlock()
	return lc.appCommands.VolumeGenCounters[volumeUUID.String()]
}

// DelLocalVolumeGenCounter removes the local generation counter entry for the
// specified volume and persists the updated appCommands state.
func (lc *LocalCmdAgent) DelLocalVolumeGenCounter(volumeUUID uuid.UUID) {
	lc.appCommandsMx.Lock()
	defer lc.appCommandsMx.Unlock()
	delete(lc.appCommands.VolumeGenCounters, volumeUUID.String())
	lc.persistAppCommands()
}

// updateAppInfoTicker adjusts the appInfoTicker’s interval.
// If throttling is enabled, the interval is stretched to the throttled interval
// (1 hour); otherwise, it returns to the normal 1-minute cadence.
func (lc *LocalCmdAgent) updateAppInfoTicker(throttle bool) {
	interval := appInfoPOSTInterval
	if throttle {
		interval = appInfoPOSTThrottledInterval
	}
	lc.appInfoTicker.update(throttle, interval)
}

// postAppInfo sends the current state of application instances to the LPS.
// If the response contains valid application commands, they are returned
// for execution. Behavior:
//   - If LPS is not configured or no addresses are available, returns nil.
//   - On 404: switch to throttled posting interval.
//   - On 200/201 with commands: return command list if token matches.
//   - On 204: no commands to execute.
//   - On error or unexpected status: log and retry with other addresses.
func (lc *LocalCmdAgent) postAppInfo() (appCmds *profile.LocalAppCmdList, discarded bool) {
	if lc.lpsURL == nil {
		// LPS is not configured.
		return nil, false
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf("%s: postAppInfo: cannot find any configured apps "+
			"for LPS URL: %s", logPrefix, lc.lpsURL)
		return nil, false
	}

	appInfo := lc.prepareAppInfo()
	var (
		err     error
		resp    *http.Response
		errList []string
	)
	for intf, srvAddrs := range lc.lpsAddresses.addrsByIface {
		for _, srvAddr := range srvAddrs {
			fullURL := srvAddr.destURL.String() + appInfoURLPath
			appCmds = &profile.LocalAppCmdList{}
			wasPaused := lc.tc.runInterruptible(func() {
				resp, err = lc.CtrlClient.SendLocalProto(
					fullURL, intf, srvAddr.sourceIP, appInfo, appCmds)
			})
			if wasPaused {
				lc.Log.Functionf("%s: postAppInfo: LPS response discarded "+
					"due to task pause", logPrefix)
				// Retry ASAP to minimize delay in publishing application info
				// and retrieving the latest application commands to execute.
				lc.TriggerAppInfoPOST()
				return nil, true
			}
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				// Throttle sending to be about once per hour.
				lc.updateAppInfoTicker(true)
				return nil, false
			case http.StatusOK, http.StatusCreated:
				if len(appCmds.AppCommands) != 0 {
					if appCmds.GetServerToken() != lc.lpsConfig.LpsToken {
						errList = append(errList, "invalid token submitted by LPS")
						continue
					}
					lc.updateAppInfoTicker(false)
					return appCmds, false
				}
				// No content in the response.
				fallthrough
			case http.StatusNoContent:
				lc.Log.Tracef("%s: LPS %s does not require additional app commands "+
					"to execute", logPrefix, lc.lpsURL)
				lc.updateAppInfoTicker(false)
				return nil, false
			default:
				errList = append(errList, fmt.Sprintf(
					"wrong response status code: %d", resp.StatusCode))
				continue
			}
		}
	}
	lc.Log.Errorf("%s: sendAppInfo: all attempts failed: %s",
		logPrefix, strings.Join(errList, ";"))
	return nil, false
}

// processReceivedAppCommands processes application commands received from LPS.
// Ensures:
//   - Each app receives at most one new command per POST cycle.
//   - Already accepted commands (same type + timestamp) are ignored.
//   - Restart command: increments restart counter and republishes config.
//   - Purge command: increments purge counter, increments generation counters
//     for all referenced volumes, and republishes app + volume configs.
//   - State (commands and counters) is persisted after processing to survive
//     restarts.
func (lc *LocalCmdAgent) processReceivedAppCommands(cmdList *profile.LocalAppCmdList) {
	lc.appCommandsMx.Lock()
	defer lc.appCommandsMx.Unlock()
	if cmdList == nil {
		// Nothing requested by LPS, just refresh the persisted config.
		if !lc.appCommands.Empty() {
			lc.touchAppCommands()
		}
		return
	}

	var cmdChanges bool
	processedApps := make(map[string]struct{})
	for _, appCmdReq := range cmdList.AppCommands {
		var err error
		appUUID := nilUUID
		if appCmdReq.Id != "" {
			appUUID, err = uuid.FromString(appCmdReq.Id)
			if err != nil {
				lc.Log.Warnf("%s: Failed to parse UUID from app command request: %v",
					logPrefix, err)
				continue
			}
		}
		displayName := appCmdReq.Displayname
		if appUUID == nilUUID && displayName == "" {
			lc.Log.Warnf("%s: App command request is missing both UUID and display name: %+v",
				logPrefix, appCmdReq)
			continue
		}
		// Try to find the application instance.
		appInst := lc.findAppInstance(appUUID, displayName)
		if appInst == nil {
			lc.Log.Warnf("%s: Failed to find app instance with UUID=%s, displayName=%s",
				logPrefix, appUUID, displayName)
			continue
		}
		appUUID = appInst.UUIDandVersion.UUID
		if _, duplicate := processedApps[appUUID.String()]; duplicate {
			lc.Log.Warnf("%s: Multiple commands requested for app instance with UUID=%s",
				logPrefix, appUUID)
			continue
		}
		processedApps[appUUID.String()] = struct{}{}

		// Accept (or skip already accepted) application command.
		command := types.AppCommand(appCmdReq.Command)
		appCmd, hasAppCmd := lc.appCommands.AppCommands[appUUID.String()]
		if !hasAppCmd {
			appCmd = &types.LocalAppCommand{}
			if lc.appCommands.AppCommands == nil {
				lc.appCommands.AppCommands =
					make(map[string]*types.LocalAppCommand)
			}
			lc.appCommands.AppCommands[appUUID.String()] = appCmd
		}
		if appCmd.Command == command &&
			appCmd.LocalServerTimestamp == appCmdReq.Timestamp {
			// already accepted
			continue
		}
		appCmd.Command = command
		appCmd.LocalServerTimestamp = appCmdReq.Timestamp
		appCmd.DeviceTimestamp = time.Now()
		appCmd.Completed = false
		cmdChanges = true

		// Get current local counters of the application.
		appCounters, hasCounters := lc.appCommands.AppCounters[appUUID.String()]
		if !hasCounters {
			appCounters = &types.LocalAppCounters{}
			if lc.appCommands.AppCounters == nil {
				lc.appCommands.AppCounters =
					make(map[string]*types.LocalAppCounters)
			}
			lc.appCommands.AppCounters[appUUID.String()] = appCounters
		}

		// Update configuration to trigger the operation.
		switch appCmd.Command {
		case types.AppCommandRestart:
			// To trigger application restart we take the previously published
			// app instance config, increase the local-restart command counter by 1
			// and re-publish the updated configuration.
			restartCmd := appCounters.RestartCmd
			restartCmd.Counter++
			restartCmd.ApplyTime = appCmd.DeviceTimestamp.String()
			appCounters.RestartCmd = restartCmd
			lc.Log.Noticef("%s: Triggering restart of application %q",
				logPrefix, appInst.DisplayName)
			// Unlock when calling the ConfigAgent (to avoid deadlocks in case
			// the ConfigAgent uses Get methods from inside the callback).
			lc.appCommandsMx.Unlock()
			lc.ConfigAgent.ApplyLocalAppRestartCmd(appUUID, restartCmd)
			lc.appCommandsMx.Lock()

		case types.AppCommandPurge:
			// To trigger application purge we take the previously published
			// app instance config, increase the local-purge command counter by 1,
			// next we add increment of 1 to local-generation counters of ALL volumes
			// used by the application (inside both volume config and volume-reference
			// config), and re-publish the updated configuration of the application
			// and all the volumes.
			purgeCmd := appCounters.PurgeCmd
			purgeCmd.Counter++
			purgeCmd.ApplyTime = appCmd.DeviceTimestamp.String()
			appCounters.PurgeCmd = purgeCmd
			volumeGenCounters := make(map[string]int64)
			for _, vr := range appInst.VolumeRefConfigList {
				volumeUUID := vr.VolumeID.String()
				localGenCounter := lc.appCommands.VolumeGenCounters[volumeUUID]
				localGenCounter++
				lc.appCommands.VolumeGenCounters[volumeUUID] = localGenCounter
				volumeGenCounters[volumeUUID] = localGenCounter
			}
			lc.Log.Noticef("%s: Triggering purge of application %q",
				logPrefix, appInst.DisplayName)
			// Unlock when calling the ConfigAgent (to avoid deadlocks in case
			// the ConfigAgent uses Get methods from inside the callback).
			lc.appCommandsMx.Unlock()
			lc.ConfigAgent.ApplyLocalAppPurgeCmd(appUUID, purgeCmd, volumeGenCounters)
			lc.appCommandsMx.Lock()
		}

	}

	// Persist accepted application commands and counters.
	if cmdChanges {
		lc.persistAppCommands()
	} else {
		// No actual configuration change to apply, just refresh the persisted config.
		lc.touchAppCommands()
	}
}

// findAppInstance searches for an AppInstanceConfig either by UUID or by
// display name (or both). If both UUID and displayName are provided, both
// must match. Returns a pointer to the matching AppInstanceConfig if found,
// or nil if no match exists.
func (lc *LocalCmdAgent) findAppInstance(
	appUUID uuid.UUID, displayName string) (appInst *types.AppInstanceConfig) {
	for _, value := range lc.AppInstanceConfig.GetAll() {
		ais := value.(types.AppInstanceConfig)
		if (appUUID == nilUUID || appUUID == ais.UUIDandVersion.UUID) &&
			(displayName == "" || displayName == ais.DisplayName) {
			return &ais
		}
	}
	return nil
}

// prepareAppInfo builds and returns a LocalAppInfoList message representing
// the current state of all locally running application instances.
// Includes information such as ID, version, display name, error state,
// runtime state, and last executed command timestamp.
// This message is later sent to LPS in a periodic POST request.
func (lc *LocalCmdAgent) prepareAppInfo() *profile.LocalAppInfoList {
	lc.appCommandsMx.RLock()
	defer lc.appCommandsMx.RUnlock()
	msg := profile.LocalAppInfoList{}
	for _, value := range lc.AppInstanceStatus.GetAll() {
		ais := value.(types.AppInstanceStatus)
		zinfoAppInst := new(profile.LocalAppInfo)
		zinfoAppInst.Id = ais.UUIDandVersion.UUID.String()
		zinfoAppInst.Version = ais.UUIDandVersion.Version
		zinfoAppInst.Name = ais.DisplayName
		zinfoAppInst.Err = ais.ErrorAndTimeWithSource.ErrorDescription.ToProto()
		zinfoAppInst.State = ais.State.ZSwState()
		if appCmd, hasEntry :=
			lc.appCommands.AppCommands[zinfoAppInst.Id]; hasEntry {
			zinfoAppInst.LastCmdTimestamp = appCmd.LastCompletedTimestamp
		}
		msg.AppsInfo = append(msg.AppsInfo, zinfoAppInst)
	}
	return &msg
}

// readSavedAppCommands loads persisted local app commands from disk
// (if any exist) and unmarshals them into a LocalCommands structure.
// Also returns the timestamp when the commands were last modified.
// If no file exists, returns an empty LocalCommands structure without error.
func (lc *LocalCmdAgent) readSavedAppCommands() (types.LocalCommands, error) {
	var commands types.LocalCommands
	contents, ts, err := persist.ReadSavedConfig(lc.Log, savedAppCommandsFile)
	if err != nil {
		return commands, err
	}
	if contents != nil {
		err := json.Unmarshal(contents, &commands)
		if err != nil {
			return commands, err
		}
		lc.Log.Noticef("%s: Using saved app commands dated %s",
			logPrefix, ts.Format(time.RFC3339Nano))
		return commands, nil
	}
	return commands, nil
}

// readSavedAppCommands loads persisted local app commands from disk
// (if any exist) and unmarshals them into a LocalCommands structure.
// Also returns the timestamp when the commands were last modified.
// If no file exists, returns an empty LocalCommands structure without error.
func (lc *LocalCmdAgent) loadSavedAppCommands() bool {
	commands, err := lc.readSavedAppCommands()
	if err != nil {
		lc.Log.Errorf("%s: loadSavedAppCommands failed: %v", logPrefix, err)
		return false
	}
	for _, appCmd := range commands.AppCommands {
		lc.Log.Noticef("%s: Loaded persisted app command: %+v", logPrefix, appCmd)
	}
	lc.appCommands = commands
	return true
}

// persistAppCommands marshals the current in-memory appCommands into JSON
// and saves them persistently on disk. Fatal-logs if marshalling fails.
func (lc *LocalCmdAgent) persistAppCommands() {
	contents, err := json.Marshal(lc.appCommands)
	if err != nil {
		lc.Log.Fatalf("%s: persistAppCommands: Marshalling failed: %v", logPrefix, err)
	}
	persist.SaveConfig(lc.Log, savedAppCommandsFile, contents)
	return
}

// touchAppCommands updates the modification timestamp of the persisted
// appCommands file without changing its contents.
func (lc *LocalCmdAgent) touchAppCommands() {
	persist.TouchSavedConfig(lc.Log, savedAppCommandsFile)
}
