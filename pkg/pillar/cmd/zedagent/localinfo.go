// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
)

const (
	localAppInfoURLPath               = "/api/v1/appinfo"
	localAppInfoPOSTInterval          = time.Minute
	localAppInfoPOSTThrottledInterval = time.Hour
	savedLocalCommandsFile            = "localcommands"
	localDevInfoURLPath               = "/api/v1/devinfo"
	localDevInfoPOSTInterval          = time.Minute
	localDevInfoPOSTThrottledInterval = time.Hour
)

var (
	throttledLocalAppInfo bool
	throttledLocalDevInfo bool
)

// updateLocalAppInfoTicker sets ticker options to the initial value
// if throttle set, will use localAppInfoPOSTThrottledInterval as interval
func updateLocalAppInfoTicker(ctx *getconfigContext, throttle bool) {
	interval := float64(localAppInfoPOSTInterval)
	if throttle {
		interval = float64(localAppInfoPOSTThrottledInterval)
	}
	max := 1.1 * interval
	min := 0.8 * max
	throttledLocalAppInfo = throttle
	ctx.sideController.localAppInfoPOSTTicker.UpdateRangeTicker(
		time.Duration(min), time.Duration(max))
}

func initializeLocalAppInfo(ctx *getconfigContext) {
	max := 1.1 * float64(localAppInfoPOSTInterval)
	min := 0.8 * max
	ctx.sideController.localAppInfoPOSTTicker =
		flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
}

func initializeLocalCommands(ctx *getconfigContext) {
	if !loadSavedLocalCommands(ctx) {
		// Write the initial empty content.
		ctx.sideController.localCommands = &types.LocalCommands{}
		persistLocalCommands(ctx.sideController.localCommands)
	}
}

func triggerLocalAppInfoPOST(ctx *getconfigContext) {
	log.Functionf("Triggering POST for %s to local server", localAppInfoURLPath)
	if throttledLocalAppInfo {
		log.Functionln("throttledLocalAppInfo flag set")
		return
	}
	ctx.sideController.localAppInfoPOSTTicker.TickNow()
}

// Run a periodic POST request to send information message about apps to local server
// and optionally receive app commands to run in the response.
func localAppInfoPOSTTask(ctx *getconfigContext) {

	log.Functionf("localAppInfoPOSTTask: waiting for localAppInfoPOSTTicker")
	// wait for the first trigger
	<-ctx.sideController.localAppInfoPOSTTicker.C
	log.Functionln("localAppInfoPOSTTask: waiting for localAppInfoPOSTTicker done")
	// trigger again to pass into the loop
	triggerLocalAppInfoPOST(ctx)

	wdName := agentName + "-localappinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.zedagentCtx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-ctx.sideController.localAppInfoPOSTTicker.C:
			start := time.Now()
			appCmds := postLocalAppInfo(ctx)
			processReceivedAppCommands(ctx, appCmds)
			ctx.zedagentCtx.ps.CheckMaxTimeTopic(wdName, "localAppInfoPOSTTask", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// Post the current state of locally running application instances to the local server
// and optionally receive a set of app commands to run in the response.
func postLocalAppInfo(ctx *getconfigContext) *profile.LocalAppCmdList {
	localProfileServer := ctx.sideController.localProfileServer
	if localProfileServer == "" {
		return nil
	}
	localServerURL, err := makeLocalServerBaseURL(localProfileServer)
	if err != nil {
		log.Errorf("sendLocalAppInfo: makeLocalServerBaseURL: %v", err)
		return nil
	}
	if !ctx.sideController.localServerMap.upToDate {
		err := updateLocalServerMap(ctx, localServerURL)
		if err != nil {
			log.Errorf("sendLocalAppInfo: updateLocalServerMap: %v", err)
			return nil
		}
		// Make sure HasLocalServer is set correctly for the AppInstanceConfig
		updateHasLocalServer(ctx)
	}
	srvMap := ctx.sideController.localServerMap.servers
	if len(srvMap) == 0 {
		log.Functionf("sendLocalAppInfo: cannot find any configured apps for localServerURL: %s",
			localServerURL)
		return nil
	}

	localInfo := prepareLocalAppInfo(ctx)
	var errList []string
	for bridgeName, servers := range srvMap {
		for _, srv := range servers {
			fullURL := srv.localServerAddr + localAppInfoURLPath
			appCmds := &profile.LocalAppCmdList{}
			resp, err := zedcloud.SendLocalProto(
				zedcloudCtx, fullURL, bridgeName, srv.bridgeIP, localInfo, appCmds)
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				// Throttle sending to be about once per hour.
				updateLocalAppInfoTicker(ctx, true)
				return nil
			case http.StatusOK, http.StatusCreated:
				if len(appCmds.AppCommands) != 0 {
					if appCmds.GetServerToken() != ctx.sideController.profileServerToken {
						errList = append(errList,
							fmt.Sprintf("invalid token submitted by local server (%s)", appCmds.GetServerToken()))
						continue
					}
					updateLocalAppInfoTicker(ctx, false)
					return appCmds
				}
				// No content in the response.
				fallthrough
			case http.StatusNoContent:
				log.Functionf("Local server %s does not require additional app commands to execute",
					localServerURL)
				updateLocalAppInfoTicker(ctx, false)
				return nil
			default:
				errList = append(errList, fmt.Sprintf("SendLocal: wrong response status code: %d",
					resp.StatusCode))
				continue
			}
		}
	}
	log.Errorf("sendLocalAppInfo: all attempts failed: %s", strings.Join(errList, ";"))
	return nil
}

func processReceivedAppCommands(ctx *getconfigContext, cmdList *profile.LocalAppCmdList) {
	ctx.sideController.Lock()
	defer ctx.sideController.Unlock()
	if cmdList == nil {
		// Nothing requested by local server, just refresh the persisted config.
		if !ctx.sideController.localCommands.Empty() {
			touchLocalCommands()
		}
		return
	}

	var cmdChanges, volChanges bool
	processedApps := make(map[string]struct{})
	for _, appCmdReq := range cmdList.AppCommands {
		var err error
		appUUID := nilUUID
		if appCmdReq.Id != "" {
			appUUID, err = uuid.FromString(appCmdReq.Id)
			if err != nil {
				log.Warnf("Failed to parse UUID from app command request: %v", err)
				continue
			}
		}
		displayName := appCmdReq.Displayname
		if appUUID == nilUUID && displayName == "" {
			log.Warnf("App command request is missing both UUID and display name: %+v",
				appCmdReq)
			continue
		}
		// Try to find the application instance.
		appInst := findAppInstance(ctx, appUUID, displayName)
		if appInst == nil {
			log.Warnf("Failed to find app instance with UUID=%s, displayName=%s",
				appUUID, displayName)
			continue
		}
		appUUID = appInst.UUIDandVersion.UUID
		if _, duplicate := processedApps[appUUID.String()]; duplicate {
			log.Warnf("Multiple commands requested for app instance with UUID=%s",
				appUUID)
			continue
		}
		processedApps[appUUID.String()] = struct{}{}

		// Accept (or skip already accepted) application command.
		command := types.AppCommand(appCmdReq.Command)
		appCmd, hasLocalCmd := ctx.sideController.localCommands.AppCommands[appUUID.String()]
		if !hasLocalCmd {
			appCmd = &types.LocalAppCommand{}
			if ctx.sideController.localCommands.AppCommands == nil {
				ctx.sideController.localCommands.AppCommands =
					make(map[string]*types.LocalAppCommand)
			}
			ctx.sideController.localCommands.AppCommands[appUUID.String()] = appCmd
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

		// Update and re-publish configuration to trigger the operation.
		timestamp := appCmd.DeviceTimestamp.String()
		changedVolumes := triggerLocalCommand(ctx, command, appInst, timestamp)
		if changedVolumes {
			volChanges = true
		}
	}

	// Persist accepted application commands and counters.
	if cmdChanges {
		persistLocalCommands(ctx.sideController.localCommands)
	} else {
		// No actual configuration change to apply, just refresh the persisted config.
		touchLocalCommands()
	}

	// Signal changes in the configuration of volumes.
	if volChanges {
		signalVolumeConfigRestarted(ctx)
	}
}

// Trigger application command (restart, purge, ...) requested via Local profile server.
// TODO: move this logic to zedmanager
func triggerLocalCommand(ctx *getconfigContext, cmd types.AppCommand,
	app *types.AppInstanceConfig, timestamp string) (changedVolumes bool) {
	// Get current local counters of the application.
	appUUID := app.UUIDandVersion.UUID
	appCounters, hasCounters := ctx.sideController.localCommands.AppCounters[appUUID.String()]
	if !hasCounters {
		appCounters = &types.LocalAppCounters{}
		if ctx.sideController.localCommands.AppCounters == nil {
			ctx.sideController.localCommands.AppCounters =
				make(map[string]*types.LocalAppCounters)
		}
		ctx.sideController.localCommands.AppCounters[appUUID.String()] = appCounters
	}

	// Update configuration to trigger the operation.
	switch cmd {
	case types.AppCommandRestart:
		// To trigger application restart we take the previously published
		// app instance config, increase the local-restart command counter by 1
		// and re-publish the updated configuration.
		appCounters.RestartCmd.Counter++
		appCounters.RestartCmd.ApplyTime = timestamp
		app.LocalRestartCmd = appCounters.RestartCmd
		checkAndPublishAppInstanceConfig(ctx, *app)

	case types.AppCommandPurge:
		// To trigger application purge we take the previously published
		// app instance config, increase the local-purge command counter by 1,
		// next we add increment of 1 to local-generation counters of ALL volumes
		// used by the application (inside both volume config and volume-reference
		// config), and re-publish the updated configuration of the application
		// and all the volumes.
		appCounters.PurgeCmd.Counter++
		appCounters.PurgeCmd.ApplyTime = timestamp
		app.LocalPurgeCmd = appCounters.PurgeCmd
		// Trigger purge of all volumes used by the application.
		// XXX Currently the assumption is that every volume instance is used
		//     by at most one application.
		if ctx.sideController.localCommands.VolumeGenCounters == nil {
			ctx.sideController.localCommands.VolumeGenCounters =
				make(map[string]int64)
		}
		for i := range app.VolumeRefConfigList {
			vr := &app.VolumeRefConfigList[i]
			uuid := vr.VolumeID.String()
			remoteGenCounter := vr.GenerationCounter
			localGenCounter := ctx.sideController.localCommands.VolumeGenCounters[uuid]
			// Un-publish volume with the current counters.
			volKey := volumeKey(uuid, remoteGenCounter, localGenCounter)
			volObj, _ := ctx.pubVolumeConfig.Get(volKey)
			if volObj == nil {
				log.Warnf("Failed to find volume %s referenced by app instance "+
					"with UUID=%s - not purging this volume", volKey, appUUID)
				continue
			}
			volume := volObj.(types.VolumeConfig)
			unpublishVolumeConfig(ctx, volKey)
			// Publish volume with an increased local generation counter.
			localGenCounter++
			ctx.sideController.localCommands.VolumeGenCounters[uuid] = localGenCounter
			vr.LocalGenerationCounter = localGenCounter
			volume.LocalGenerationCounter = localGenCounter
			publishVolumeConfig(ctx, volume)
			changedVolumes = true
		}
		checkAndPublishAppInstanceConfig(ctx, *app)
	}
	return changedVolumes
}

func processAppCommandStatus(
	ctx *getconfigContext, appStatus types.AppInstanceStatus) {
	ctx.sideController.Lock()
	defer ctx.sideController.Unlock()
	uuid := appStatus.UUIDandVersion.UUID.String()
	appCmd, hasLocalCmd := ctx.sideController.localCommands.AppCommands[uuid]
	if !hasLocalCmd {
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
			log.Noticef("Local restart completed: %+v", appCmd)
		}
	case types.AppCommandPurge:
		if appStatus.PurgeStartedAt.After(appCmd.DeviceTimestamp) {
			appCmd.Completed = true
			appCmd.LastCompletedTimestamp = appCmd.LocalServerTimestamp
			updated = true
			log.Noticef("Local purge completed: %+v", appCmd)
		}
	}
	if updated {
		persistLocalCommands(ctx.sideController.localCommands)
	}
}

// Add config submitted for the application via local profile server.
// ctx.sideController should be locked!
func addLocalAppConfig(ctx *getconfigContext, appInstance *types.AppInstanceConfig) {
	uuid := appInstance.UUIDandVersion.UUID.String()
	appCounters, hasCounters := ctx.sideController.localCommands.AppCounters[uuid]
	if hasCounters {
		appInstance.LocalRestartCmd = appCounters.RestartCmd
		appInstance.LocalPurgeCmd = appCounters.PurgeCmd
	}
	for i := range appInstance.VolumeRefConfigList {
		vr := &appInstance.VolumeRefConfigList[i]
		uuid = vr.VolumeID.String()
		vr.LocalGenerationCounter =
			ctx.sideController.localCommands.VolumeGenCounters[uuid]
	}
}

// Delete all local config for this application.
// ctx.sideController should be locked!
func delLocalAppConfig(ctx *getconfigContext, appUUID string) {
	delete(ctx.sideController.localCommands.AppCommands, appUUID)
	delete(ctx.sideController.localCommands.AppCounters, appUUID)
	persistLocalCommands(ctx.sideController.localCommands)
}

// Add config submitted for the volume via local profile server.
// ctx.sideController should be locked!
func addLocalVolumeConfig(ctx *getconfigContext, volumeConfig *types.VolumeConfig) {
	uuid := volumeConfig.VolumeID.String()
	volumeConfig.LocalGenerationCounter =
		ctx.sideController.localCommands.VolumeGenCounters[uuid]
}

// Delete all local config for this volume.
// ctx.localCommands should be locked!
func delLocalVolumeConfig(ctx *getconfigContext, volumeUUID string) {
	delete(ctx.sideController.localCommands.VolumeGenCounters, volumeUUID)
	persistLocalCommands(ctx.sideController.localCommands)
}

func prepareLocalAppInfo(ctx *getconfigContext) *profile.LocalAppInfoList {
	msg := profile.LocalAppInfoList{}
	ctx.sideController.Lock()
	defer ctx.sideController.Unlock()
	addAppInstanceFunc := func(key string, value interface{}) bool {
		ais := value.(types.AppInstanceStatus)
		zinfoAppInst := new(profile.LocalAppInfo)
		zinfoAppInst.Id = ais.UUIDandVersion.UUID.String()
		zinfoAppInst.Version = ais.UUIDandVersion.Version
		zinfoAppInst.Name = ais.DisplayName
		zinfoAppInst.Err = encodeErrorInfo(ais.ErrorAndTimeWithSource.ErrorDescription)
		zinfoAppInst.State = ais.State.ZSwState()
		if appCmd, hasEntry :=
			ctx.sideController.localCommands.AppCommands[zinfoAppInst.Id]; hasEntry {
			zinfoAppInst.LastCmdTimestamp = appCmd.LastCompletedTimestamp
		}
		msg.AppsInfo = append(msg.AppsInfo, zinfoAppInst)
		return true
	}
	ctx.subAppInstanceStatus.Iterate(addAppInstanceFunc)
	return &msg
}

func findAppInstance(
	ctx *getconfigContext, appUUID uuid.UUID, displayName string) (appInst *types.AppInstanceConfig) {
	matchApp := func(_ string, value interface{}) bool {
		ais := value.(types.AppInstanceConfig)
		if (appUUID == nilUUID || appUUID == ais.UUIDandVersion.UUID) &&
			(displayName == "" || displayName == ais.DisplayName) {
			appInst = &ais
			// stop iteration
			return false
		}
		return true
	}
	ctx.pubAppInstanceConfig.Iterate(matchApp)
	return appInst
}

func readSavedLocalCommands(ctx *getconfigContext) (*types.LocalCommands, error) {
	commands := &types.LocalCommands{}
	contents, ts, err := readSavedConfig(
		filepath.Join(checkpointDirname, savedLocalCommandsFile))
	if err != nil {
		return commands, err
	}
	if contents != nil {
		err := json.Unmarshal(contents, &commands)
		if err != nil {
			return commands, err
		}
		log.Noticef("Using saved local commands dated %s",
			ts.Format(time.RFC3339Nano))
		return commands, nil
	}
	return commands, nil
}

// loadSavedLocalCommands reads saved locally-issued commands and sets them.
func loadSavedLocalCommands(ctx *getconfigContext) bool {
	commands, err := readSavedLocalCommands(ctx)
	if err != nil {
		log.Errorf("loadSavedLocalCommands failed: %v", err)
		return false
	}
	for _, appCmd := range commands.AppCommands {
		log.Noticef("Loaded persisted local app command: %+v", appCmd)
	}
	ctx.sideController.localCommands = commands
	return true
}

func persistLocalCommands(localCommands *types.LocalCommands) {
	contents, err := json.Marshal(localCommands)
	if err != nil {
		log.Fatalf("persistLocalCommands: Marshalling failed: %v", err)
	}
	saveConfig(savedLocalCommandsFile, contents)
	return
}

// touchLocalCommands is used to update the modification time of the persisted
// local commands.
func touchLocalCommands() {
	touchSavedConfig(savedLocalCommandsFile)
}

// updateLocalDevInfoTicker sets ticker options to the initial value
// if throttle set, will use localDevInfoPOSTThrottledInterval as interval
func updateLocalDevInfoTicker(ctx *getconfigContext, throttle bool) {
	interval := float64(localDevInfoPOSTInterval)
	if throttle {
		interval = float64(localDevInfoPOSTThrottledInterval)
	}
	max := 1.1 * interval
	min := 0.8 * max
	throttledLocalDevInfo = throttle
	ctx.sideController.localDevInfoPOSTTicker.UpdateRangeTicker(
		time.Duration(min), time.Duration(max))
}

func initializeLocalDevInfo(ctx *getconfigContext) {
	max := 1.1 * float64(localDevInfoPOSTInterval)
	min := 0.8 * max
	ctx.sideController.localDevInfoPOSTTicker =
		flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
}

const maxReadSize = 1024 // Sufficient for a uin64

func initializeLocalDevCmdTimestamp(ctx *getconfigContext) {
	if _, err := os.Stat(lastDevCmdTimestampFile); err != nil && os.IsNotExist(err) {
		ctx.sideController.lastDevCmdTimestamp = 0
		return
	}
	b, err := fileutils.ReadWithMaxSize(log, lastDevCmdTimestampFile,
		maxReadSize)
	if err != nil {
		log.Errorf("initializeLocalDevCmdTimestamp read: %s", err)
		ctx.sideController.lastDevCmdTimestamp = 0
		return
	}
	u, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		log.Errorf("initializeLocalDevCmdTimestamp: %s", err)
		ctx.sideController.lastDevCmdTimestamp = 0
	} else {
		ctx.sideController.lastDevCmdTimestamp = u
		log.Noticef("initializeLocalDevCmdTimestamp: read %d",
			ctx.sideController.lastDevCmdTimestamp)
	}
}

func saveLocalDevCmdTimestamp(ctx *getconfigContext) {
	b := []byte(fmt.Sprintf("%v", ctx.sideController.lastDevCmdTimestamp))
	err := fileutils.WriteRename(lastDevCmdTimestampFile, b)
	if err != nil {
		log.Errorf("saveLocalDevCmdTimestamp write: %s", err)
	}
}

func triggerLocalDevInfoPOST(ctx *getconfigContext) {
	log.Functionf("Triggering POST for %s to local server", localDevInfoURLPath)
	if throttledLocalDevInfo {
		log.Functionln("throttledLocalDevInfo flag set")
		return
	}
	ctx.sideController.localDevInfoPOSTTicker.TickNow()
}

// Run a periodic POST request to send information message about devs to local server
// and optionally receive dev commands to run in the response.
func localDevInfoPOSTTask(ctx *getconfigContext) {

	log.Functionf("localDevInfoPOSTTask: waiting for localDevInfoPOSTTicker")
	// wait for the first trigger
	<-ctx.sideController.localDevInfoPOSTTicker.C
	log.Functionln("localDevInfoPOSTTask: waiting for localDevInfoPOSTTicker done")
	// trigger again to pass into the loop
	triggerLocalDevInfoPOST(ctx)

	wdName := agentName + "-localdevinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.zedagentCtx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-ctx.sideController.localDevInfoPOSTTicker.C:
			start := time.Now()
			devCmd := postLocalDevInfo(ctx)
			if devCmd != nil {
				processReceivedDevCommands(ctx, devCmd)
			}
			ctx.zedagentCtx.ps.CheckMaxTimeTopic(wdName, "localDevInfoPOSTTask", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// Post the current state of locally running devlication instances to the local server
// and optionally receive a set of dev commands to run in the response.
func postLocalDevInfo(ctx *getconfigContext) *profile.LocalDevCmd {
	localProfileServer := ctx.sideController.localProfileServer
	if localProfileServer == "" {
		return nil
	}
	localServerURL, err := makeLocalServerBaseURL(localProfileServer)
	if err != nil {
		log.Errorf("sendLocalDevInfo: makeLocalServerBaseURL: %v", err)
		return nil
	}
	if !ctx.sideController.localServerMap.upToDate {
		err := updateLocalServerMap(ctx, localServerURL)
		if err != nil {
			log.Errorf("sendLocalDevInfo: updateLocalServerMap: %v", err)
			return nil
		}
		// Make sure HasLocalServer is set correctly for the AppInstanceConfig
		updateHasLocalServer(ctx)
	}
	srvMap := ctx.sideController.localServerMap.servers
	if len(srvMap) == 0 {
		log.Functionf("sendLocalDevInfo: cannot find any configured devs for localServerURL: %s",
			localServerURL)
		return nil
	}

	localInfo := prepareLocalDevInfo(ctx.zedagentCtx)
	var errList []string
	for bridgeName, servers := range srvMap {
		for _, srv := range servers {
			fullURL := srv.localServerAddr + localDevInfoURLPath
			devCmd := &profile.LocalDevCmd{}
			resp, err := zedcloud.SendLocalProto(
				zedcloudCtx, fullURL, bridgeName, srv.bridgeIP,
				localInfo, devCmd)
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				// Throttle sending to be about once per hour.
				updateLocalDevInfoTicker(ctx, true)
				return nil
			case http.StatusOK, http.StatusCreated:
				if devCmd.GetServerToken() != ctx.sideController.profileServerToken {
					errList = append(errList,
						fmt.Sprintf("invalid token submitted by local server (%s)",
							devCmd.GetServerToken()))
					continue
				}
				updateLocalDevInfoTicker(ctx, false)
				return devCmd
			case http.StatusNoContent:
				log.Functionf("Local server %s does not require additional dev commands to execute",
					localServerURL)
				updateLocalDevInfoTicker(ctx, false)
				return nil
			default:
				errList = append(errList, fmt.Sprintf("sendLocalDevInfo: wrong response status code: %d",
					resp.StatusCode))
				continue
			}
		}
	}
	log.Errorf("sendLocalDevInfo: all attempts failed: %s", strings.Join(errList, ";"))
	return nil
}

func prepareLocalDevInfo(ctx *zedagentContext) *profile.LocalDevInfo {
	msg := profile.LocalDevInfo{}
	msg.DeviceUuid = devUUID.String()
	msg.State = info.ZDeviceState(getDeviceState(ctx))
	msg.MaintenanceModeReasons = append(msg.MaintenanceModeReasons,
		info.MaintenanceModeReason(ctx.maintModeReason))
	hinfo, err := host.Info()
	if err != nil {
		log.Errorf("host.Info(): %s", err)
	} else {
		bootTime, _ := ptypes.TimestampProto(
			time.Unix(int64(hinfo.BootTime), 0).UTC())
		msg.BootTime = bootTime
	}
	msg.LastBootReason = info.BootReason(ctx.bootReason)
	msg.LastCmdTimestamp = ctx.getconfigCtx.sideController.lastDevCmdTimestamp
	return &msg
}

func processReceivedDevCommands(getconfigCtx *getconfigContext, cmd *profile.LocalDevCmd) {
	if cmd == nil {
		return
	}
	ctx := getconfigCtx.zedagentCtx
	getconfigCtx.sideController.Lock()
	defer getconfigCtx.sideController.Unlock()

	if cmd.Timestamp == getconfigCtx.sideController.lastDevCmdTimestamp {
		log.Functionf("unchanged timestamp %v",
			getconfigCtx.sideController.lastDevCmdTimestamp)
		return
	}
	command := types.DevCommand(cmd.Command)
	if getconfigCtx.updateInprogress {
		switch command {
		case types.DevCommandUnspecified:
			// Do nothing
		case types.DevCommandShutdown:
			log.Noticef("Received shutdown from local profile server during updateInProgress")
			ctx.shutdownCmdDeferred = true
		case types.DevCommandShutdownPoweroff:
			log.Noticef("Received shutdown_poweroff from local profile server during updateInProgress")
			ctx.poweroffCmdDeferred = true
		}
		return
	}
	switch command {
	case types.DevCommandUnspecified:
		// Do nothing
		return
	case types.DevCommandShutdown:
		log.Noticef("Received shutdown from local profile server")
		if ctx.shutdownCmd || ctx.deviceShutdown {
			log.Warnf("Shutdown already in progress")
			return
		}
		ctx.shutdownCmd = true
	case types.DevCommandShutdownPoweroff:
		log.Noticef("Received shutdown_poweroff from local profile server")
		if ctx.poweroffCmd || ctx.devicePoweroff {
			log.Warnf("Poweroff already in progress")
		}
		ctx.poweroffCmd = true
		infoStr := fmt.Sprintf("NORMAL: local profile server power off")
		ctx.requestedRebootReason = infoStr
		ctx.requestedBootReason = types.BootReasonPoweroffCmd
	}

	// shutdown the application instances
	shutdownAppsGlobal(ctx)

	publishZedAgentStatus(getconfigCtx)

	// Persist timestamp here even though the operation is not complete.
	// The only reason it would not complete is if we crash or reboot due to
	// a power failure, and in that case we'd shutdown all the app instances
	// implicitly.
	// However, if it was a shutdown_poweroff command and we crash to get a
	// power failure, then we will not poweroff. It seems impossible to do that
	// without introducing a race condition where we might poweroff without
	// a power cycle from a UPS to power on again.
	getconfigCtx.sideController.lastDevCmdTimestamp = cmd.Timestamp
	saveLocalDevCmdTimestamp(getconfigCtx)
}
