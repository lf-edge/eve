// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
)

const (
	radioURLPath         = "/api/v1/radio"
	savedRadioConfigFile = "lastradioconfig"
	radioPOSTInterval    = 5 * time.Second
)

func initializeRadioConfig(ctx *getconfigContext) {
	ctx.triggerRadioPOST = make(chan Notify, 1)
	if !loadSavedRadioConfig(ctx) {
		// invalid or missing configuration - overwrite with the default
		writeRadioConfig(&profile.RadioConfig{RadioSilence: false})
	}
	ctx.radioSilence.ChangeRequestedAt = time.Now()
	ctx.radioSilence.ChangeInProgress = true
	// apply requested RF status immediately
	publishZedAgentStatus(ctx)
}

func triggerRadioPOST(ctx *getconfigContext) {
	log.Functionf("Triggering POST for %s to local server", radioURLPath)
	select {
	case ctx.triggerRadioPOST <- struct{}{}:
		// Do nothing more
	default:
		log.Warnln("Failed to trigger Radio fetch operation")
	}
}

// Run a periodic POST request to fetch the intended state of radio devices from local server.
func radioPOSTTask(ctx *getconfigContext) {
	max := float64(radioPOSTInterval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	log.Functionf("radioPOSTTask: waiting for triggerRadioPOST")
	// wait for the first trigger
	<-ctx.triggerRadioPOST
	log.Functionln("radioPOSTTask: waiting for triggerRadioPOST done")
	// trigger again to pass into the loop
	triggerRadioPOST(ctx)

	wdName := agentName + "-radio"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.zedagentCtx.ps.RegisterFileWatchdog(wdName)

	task := func() {
		start := time.Now()
		status := getRadioStatus(ctx)
		if status == nil {
			log.Noticeln("Radio status is not yet available")
			return
		}
		config := getRadioConfig(ctx, status)
		if config != nil {
			if config.RadioSilence != ctx.radioSilence.Imposed {
				ctx.radioSilence.Imposed = config.RadioSilence
				ctx.radioSilence.ChangeInProgress = true
				ctx.radioSilence.ChangeRequestedAt = time.Now()
				log.Noticef("Triggering radio-silence state change to: %s",
					ctx.radioSilence)
				publishZedAgentStatus(ctx)
			}
		}
		ctx.zedagentCtx.ps.CheckMaxTimeTopic(wdName, "radioPOSTTask", start,
			warningTime, errorTime)
	}
	for {
		select {
		case <-ctx.triggerRadioPOST:
			task()
		case <-ticker.C:
			task()
		case <-stillRunning.C:
		}
		ctx.zedagentCtx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func getRadioStatus(ctx *getconfigContext) *profile.RadioStatus {
	obj, err := ctx.zedagentCtx.subDeviceNetworkStatus.Get("global")
	if err != nil {
		log.Error(err)
		return nil
	}
	dns := obj.(types.DeviceNetworkStatus)
	if !dns.RadioSilence.ChangeRequestedAt.Equal(ctx.radioSilence.ChangeRequestedAt) {
		log.Noticeln("Up-to-date radio-silence status is not available")
		return nil
	}
	if dns.RadioSilence.ChangeInProgress {
		log.Noticeln("Skipping radio POST request - radio state changing operation is still in progress")
		return nil
	}
	if ctx.radioSilence.ChangeInProgress {
		// radio-silence state changing operation has finalized
		log.Noticeln("Radio-silence state changing operation has finalized (as seen by zedagent)")
		ctx.radioSilence.ChangeInProgress = false
	}

	var cellularStatus []*profile.CellularStatus
	for _, port := range dns.Ports {
		if port.WirelessStatus.WType != types.WirelessTypeCellular {
			continue
		}
		wwanStatus := port.WirelessStatus.Cellular
		cellularStatus = append(cellularStatus,
			&profile.CellularStatus{
				Logicallabel: port.Logicallabel,
				Module:       encodeCellModuleInfo(wwanStatus.Module),
				SimCards:     encodeSimCards(wwanStatus.Module.Name, wwanStatus.SimCards),
				Providers:    encodeCellProviders(wwanStatus.Providers),
				ConfigError:  wwanStatus.ConfigError,
				ProbeError:   wwanStatus.ProbeError,
			})
	}
	return &profile.RadioStatus{
		RadioSilence:   dns.RadioSilence.Imposed,
		ConfigError:    dns.RadioSilence.ConfigError,
		CellularStatus: cellularStatus,
	}
}

func getRadioConfig(ctx *getconfigContext, radioStatus *profile.RadioStatus) *profile.RadioConfig {
	localProfileServer := ctx.localProfileServer
	if localProfileServer == "" {
		// default configuration
		return &profile.RadioConfig{
			RadioSilence: false, // disabled by default
		}
	}
	localServerURL, err := makeLocalServerBaseURL(localProfileServer)
	if err != nil {
		log.Errorf("getRadioConfig: makeLocalServerBaseURL: %v", err)
		return nil
	}
	if !ctx.localServerMap.upToDate {
		err := updateLocalServerMap(ctx, localServerURL)
		if err != nil {
			log.Errorf("getRadioConfig: updateLocalServerMap: %v", err)
			return nil
		}
	}
	srvMap := ctx.localServerMap.servers
	if len(srvMap) == 0 {
		log.Functionf("getRadioConfig: cannot find any configured apps for localServerURL: %s",
			localServerURL)
		return nil
	}

	var errList []string
	for bridgeName, servers := range srvMap {
		for _, srv := range servers {
			fullURL := srv.localServerAddr + radioURLPath
			radioConfig := &profile.RadioConfig{}
			resp, err := zedcloud.SendLocalProto(
				zedcloudCtx, fullURL, bridgeName, srv.bridgeIP, radioStatus, radioConfig)
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
				errList = append(errList, fmt.Sprintf("SendLocal: wrong response status code: %d",
					resp.StatusCode))
				continue
			}
			if resp.StatusCode == http.StatusNoContent {
				log.Functionf("Local server %s does not require change in the radio state", localServerURL)
				touchRadioConfig()
				return nil
			}
			if radioConfig.GetServerToken() != ctx.profileServerToken {
				errList = append(errList,
					fmt.Sprintf("invalid token submitted by local server (%s)", radioConfig.GetServerToken()))
				continue
			}
			if ctx.radioSilence.Imposed == radioConfig.RadioSilence {
				// no actual configuration change to apply, just refresh the persisted config
				touchRadioConfig()
			} else {
				writeRadioConfig(radioConfig)
			}
			return radioConfig
		}
	}
	log.Errorf("getRadioConfig: all attempts failed: %s", strings.Join(errList, ";"))
	return nil
}

// read saved radio config in case of a reboot
func readSavedRadioConfig(ctx *getconfigContext) (*profile.RadioConfig, error) {
	radioConfigBytes, ts, err := readSavedProtoMessage(
		ctx.zedagentCtx.globalConfig.GlobalValueInt(types.StaleConfigTime),
		filepath.Join(checkpointDirname, savedRadioConfigFile), false)
	if err != nil {
		return nil, fmt.Errorf("readSavedRadioConfig: %v", err)
	}
	if radioConfigBytes != nil {
		radioConfig := &profile.RadioConfig{}
		err := proto.Unmarshal(radioConfigBytes, radioConfig)
		if err != nil {
			return nil, fmt.Errorf("radio config unmarshalling failed: %v", err)
		}
		log.Noticef("Using saved radio config dated %s",
			ts.Format(time.RFC3339Nano))
		return radioConfig, nil
	}
	return nil, nil
}

// loadSavedRadioConfig reads saved radio config and sets it.
func loadSavedRadioConfig(ctx *getconfigContext) bool {
	radioConfig, err := readSavedRadioConfig(ctx)
	if err != nil {
		log.Errorf("readSavedRadioConfig failed: %v", err)
		return false
	}
	if radioConfig == nil {
		log.Warnf("Loaded empty radio config: %+v", radioConfig)
		return false
	}
	log.Noticef("Starting with radio config: %+v", radioConfig)
	ctx.radioSilence.Imposed = radioConfig.RadioSilence
	return true
}

// writeRadioConfig saves received RadioConfig into the persisted partition.
func writeRadioConfig(radioConfig *profile.RadioConfig) {
	contents, err := proto.Marshal(radioConfig)
	if err != nil {
		log.Fatalf("writeRadioConfig: Marshalling failed: %v", err)
	}
	writeProtoMessage(savedRadioConfigFile, contents)
	return
}

// touchRadioConfig is used to update the modification time of the persisted radio config.
func touchRadioConfig() {
	touchProtoMessage(savedRadioConfigFile)
}
