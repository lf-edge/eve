// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
)

const (
	localAppInfoURLPath               = "/api/v1/appinfo"
	localAppInfoPOSTInterval          = time.Minute
	localAppInfoPOSTThrottledInterval = time.Hour
	savedAppCommandsFile              = "appcommands"
)

var (
	throttledLocalAppInfo bool
)

//updateLocalAppInfoTicker sets ticker options to the initial value
//if throttle set, will use localAppInfoPOSTThrottledInterval as interval
func updateLocalAppInfoTicker(ctx *getconfigContext, throttle bool) {
	interval := float64(localAppInfoPOSTInterval)
	if throttle {
		interval = float64(localAppInfoPOSTThrottledInterval)
	}
	max := 1.1 * interval
	min := 0.8 * max
	throttledLocalAppInfo = throttle
	ctx.localAppInfoPOSTTicker.UpdateRangeTicker(time.Duration(min), time.Duration(max))
}

func initializeLocalAppInfo(ctx *getconfigContext) {
	max := 1.1 * float64(localAppInfoPOSTInterval)
	min := 0.8 * max
	ctx.localAppInfoPOSTTicker = flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
	if loadSavedAppCommands(ctx) {
		publishZedAgentStatus(ctx)
	} else {
		// Write the initial empty content.
		persistAppCommands(ctx.localAppCommands)
	}
}

func triggerLocalAppInfoPOST(ctx *getconfigContext) {
	log.Functionf("Triggering POST for %s to local server", localAppInfoURLPath)
	if throttledLocalAppInfo {
		log.Functionln("throttledLocalAppInfo flag set")
		return
	}
	ctx.localAppInfoPOSTTicker.TickNow()
}

// Run a periodic POST request to send information message about apps to local server
// and optionally receive app commands to run in the response.
func localAppInfoPOSTTask(ctx *getconfigContext) {

	log.Functionf("localAppInfoPOSTTask: waiting for localAppInfoPOSTTicker")
	// wait for the first trigger
	<-ctx.localAppInfoPOSTTicker.C
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
		case <-ctx.localAppInfoPOSTTicker.C:
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
	localProfileServer := ctx.localProfileServer
	if localProfileServer == "" {
		return nil
	}
	localServerURL, err := makeLocalServerBaseURL(localProfileServer)
	if err != nil {
		log.Errorf("sendLocalAppInfo: makeLocalServerBaseURL: %v", err)
		return nil
	}
	if !ctx.localServerMap.upToDate {
		err := updateLocalServerMap(ctx, localServerURL)
		if err != nil {
			log.Errorf("sendLocalAppInfo: updateLocalServerMap: %v", err)
			return nil
		}
	}
	srvMap := ctx.localServerMap.servers
	if len(srvMap) == 0 {
		log.Functionf("sendLocalAppInfo: cannot find any configured apps for localServerURL: %s",
			localServerURL)
		return nil
	}

	localInfo := prepareLocalInfo(ctx)
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
			case http.StatusOK:
				if len(appCmds.AppCommands) != 0 {
					if appCmds.GetServerToken() != ctx.profileServerToken {
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
	ctx.localAppCommandsLock.Lock()
	defer ctx.localAppCommandsLock.Unlock()
	if cmdList == nil {
		// Nothing requested by local server, just refresh the persisted config.
		touchAppCommands()
		return
	}
	var cmdChanges bool
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
		ais := findAppInstance(ctx, appUUID, displayName)
		if ais == nil {
			log.Warnf("Failed to find app instance with UUID=%s, displayName=%s",
				appUUID, displayName)
			continue
		}
		appUUID = ais.UUIDandVersion.UUID
		command := types.AppCommand(appCmdReq.Command)
		appCmd := ctx.localAppCommands.LookupByAppUUID(appUUID)
		if appCmd != nil {
			// Entry for this app already exists.
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
			continue
		}
		// Add new entry.
		ctx.localAppCommands.Cmds = append(ctx.localAppCommands.Cmds,
			types.LocalAppCommand{
				AppUUID:              appUUID,
				Command:              command,
				LocalServerTimestamp: appCmdReq.Timestamp,
				DeviceTimestamp:      time.Now(),
				Completed:            false,
			})
		cmdChanges = true
	}
	if cmdChanges {
		publishZedAgentStatus(ctx)
		persistAppCommands(ctx.localAppCommands)
	} else {
		// No actual configuration change to apply, just refresh the persisted config.
		touchAppCommands()
	}
}

func processAppCommandStatus(ctx *getconfigContext, appStatus types.AppInstanceStatus) {
	ctx.localAppCommandsLock.Lock()
	defer ctx.localAppCommandsLock.Unlock()
	appCmdStatus := appStatus.LocalCommand
	if appCmdStatus.Command == types.AppCommandUnspecified {
		return
	}
	if !appCmdStatus.Completed {
		// Command has not yet completed, nothing to update.
		return
	}
	appCmd := ctx.localAppCommands.LookupByAppUUID(appStatus.UUIDandVersion.UUID)
	if appCmd == nil {
		log.Warnf("Missing entry for app command: %+v", appStatus.LocalCommand)
		return
	}
	var updated bool
	if appCmd.LastCompletedTimestamp != appCmdStatus.LocalServerTimestamp {
		appCmd.LastCompletedTimestamp = appCmdStatus.LocalServerTimestamp
		updated = true
	}
	if !appCmd.Completed && appCmd.SameCommand(appCmdStatus) {
		appCmd.Completed = true
		updated = true
	}
	if updated {
		persistAppCommands(ctx.localAppCommands)
	}
}

func prepareLocalInfo(ctx *getconfigContext) *profile.LocalAppInfoList {
	msg := profile.LocalAppInfoList{}
	addAppInstanceFunc := func(key string, value interface{}) bool {
		ais := value.(types.AppInstanceStatus)
		zinfoAppInst := new(profile.LocalAppInfo)
		zinfoAppInst.Id = ais.UUIDandVersion.UUID.String()
		zinfoAppInst.Version = ais.UUIDandVersion.Version
		zinfoAppInst.Name = ais.DisplayName
		zinfoAppInst.Err = encodeErrorInfo(ais.ErrorAndTimeWithSource.ErrorDescription)
		zinfoAppInst.State = ais.State.ZSwState()
		ctx.localAppCommandsLock.Lock()
		for _, appCmd := range ctx.localAppCommands.Cmds {
			if appCmd.AppUUID == ais.UUIDandVersion.UUID {
				zinfoAppInst.LastCmdTimestamp = appCmd.LastCompletedTimestamp
				break
			}
		}
		ctx.localAppCommandsLock.Unlock()
		msg.AppsInfo = append(msg.AppsInfo, zinfoAppInst)
		return true
	}
	ctx.subAppInstanceStatus.Iterate(addAppInstanceFunc)
	return &msg
}

func findAppInstance(
	ctx *getconfigContext, appUUID uuid.UUID, displayName string) (appInst *types.AppInstanceStatus) {
	matchApp := func(_ string, value interface{}) bool {
		ais := value.(types.AppInstanceStatus)
		if (appUUID == nilUUID || appUUID == ais.UUIDandVersion.UUID) &&
			(displayName == "" || displayName == ais.DisplayName) {
			appInst = &ais
			// stop iteration
			return false
		}
		return true
	}
	ctx.subAppInstanceStatus.Iterate(matchApp)
	return appInst
}

func readSavedAppCommands(ctx *getconfigContext) (types.LocalAppCommands, error) {
	appCommands := types.LocalAppCommands{}
	contents, ts, err := readSavedConfig(
		ctx.zedagentCtx.globalConfig.GlobalValueInt(types.StaleConfigTime),
		filepath.Join(checkpointDirname, savedAppCommandsFile), false)
	if err != nil {
		return appCommands, err
	}
	if contents != nil {
		err := json.Unmarshal(contents, &appCommands)
		if err != nil {
			return appCommands, err
		}
		log.Noticef("Using saved app commands dated %s",
			ts.Format(time.RFC3339Nano))
		return appCommands, nil
	}
	return appCommands, nil
}

// loadSavedAppCommands reads saved application commands and sets it.
func loadSavedAppCommands(ctx *getconfigContext) bool {
	appCommands, err := readSavedAppCommands(ctx)
	if err != nil {
		log.Errorf("readSavedAppCommands failed: %v", err)
		return false
	}
	log.Noticef("Starting with app commands: %+v", appCommands)
	ctx.localAppCommands = appCommands
	return true
}

func persistAppCommands(cmds types.LocalAppCommands) {
	contents, err := json.Marshal(cmds)
	if err != nil {
		log.Fatalf("persistAppCommands: Marshalling failed: %v", err)
	}
	saveConfig(savedAppCommandsFile, contents)
	return
}

// touchAppCommands is used to update the modification time of the persisted
// application commands.
func touchAppCommands() {
	touchSavedConfig(savedAppCommandsFile)
}
