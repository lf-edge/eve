// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"google.golang.org/protobuf/proto"
)

const (
	// radioURLPath is the REST API path used to fetch radio configuration from LPS.
	radioURLPath = "/api/v1/radio"
	// savedRadioConfigFile is the filename used to persist the last received radio config.
	savedRadioConfigFile = "lastradioconfig"
	// radioPOSTInterval defines the normal interval for periodic POST requests to
	// publish the radio state and optionally fetch any radio silence configuration.
	radioPOSTInterval = 5 * time.Second
	// radioPOSTThrottledInterval is the backoff interval used when LPS
	// signals throttling by returning HTTP 404.
	radioPOSTThrottledInterval = 5 * time.Minute
)

// initializeRadioConfig initializes the radio configuration and sets up the periodic ticker.
// Loads persisted configuration if available, otherwise sets the default (radio enabled).
func (lc *LocalCmdAgent) initializeRadioConfig() {
	lc.radioTicker = newTaskTicker(radioPOSTInterval)
	if !lc.loadSavedRadioConfig() {
		// Invalid or missing configuration - overwrite with the default.
		lc.saveRadioConfig(&profile.RadioConfig{RadioSilence: false})
	}
	lc.radioSilence.ChangeRequestedAt = time.Now()
	lc.radioSilence.ChangeInProgress = true
}

// runRadioTask continuously publishes radio status and potentially fetches radio
// silence configuration from LPS at periodic intervals.
func (lc *LocalCmdAgent) runRadioTask() {
	lc.Log.Functionf("%s: radioTask: waiting for the first trigger", logPrefix)
	// Wait for the first trigger.
	<-lc.radioTicker.tickerChan()
	lc.Log.Functionf("%s: radioTask: received the first trigger", logPrefix)
	// Trigger again to pass into the loop.
	lc.TriggerRadioPOST()

	wdName := watchdogPrefix + "radio"

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
		status := lc.getRadioStatus()
		if status == nil {
			lc.Log.Noticef("%s: Radio status is not yet available", logPrefix)
			return
		}
		config, discarded := lc.getRadioConfig(status)
		if discarded {
			return
		}
		lc.processReceivedRadioConfig(config)
		lc.Watchdog.CheckMaxTimeTopic(wdName, "radioTask", start,
			warningTime, errorTime)
	}

	for {
		select {
		case <-lc.radioTicker.tickerChan():
			task()
		case <-stillRunning.C:
		}
		lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

// TriggerRadioPOST manually triggers the radio POST ticker to immediately publish
// radio state and fetch radio silence config.
func (lc *LocalCmdAgent) TriggerRadioPOST() {
	lc.radioTicker.tickNow()
}

// GetRadioSilenceConfig returns the current radio silence configuration.
func (lc *LocalCmdAgent) GetRadioSilenceConfig() types.RadioSilence {
	lc.radioSilenceMx.RLock()
	defer lc.radioSilenceMx.RUnlock()
	return lc.radioSilence
}

// updateRadioTicker adjusts the radioTicker’s interval.
// If throttling is enabled, the interval is stretched to the throttled interval
// (5 minutes); otherwise, it returns to the normal 5 seconds cadence.
func (lc *LocalCmdAgent) updateRadioTicker(throttle bool) {
	interval := radioPOSTInterval
	if throttle {
		interval = radioPOSTThrottledInterval
	}
	lc.radioTicker.update(throttle, interval)
}

// getRadioStatus fetches the current device radio status, including cellular info.
// Returns nil if the status is not available or if a radio state change is in progress.
func (lc *LocalCmdAgent) getRadioStatus() *profile.RadioStatus {
	lc.radioSilenceMx.Lock()
	defer lc.radioSilenceMx.Unlock()
	obj, err := lc.DeviceNetworkStatus.Get("global")
	if err != nil {
		lc.Log.Errorf("%s: failed to get DeviceNetworkStatus: %v", logPrefix, err)
		return nil
	}
	dns := obj.(types.DeviceNetworkStatus)
	if !dns.RadioSilence.ChangeRequestedAt.Equal(lc.radioSilence.ChangeRequestedAt) {
		lc.Log.Noticef("%s: Up-to-date radio-silence status is not available", logPrefix)
		return nil
	}
	if dns.RadioSilence.ChangeInProgress {
		lc.Log.Noticef("%s: Skipping radio POST request - radio state changing operation "+
			"is still in progress", logPrefix)
		return nil
	}
	if lc.radioSilence.ChangeInProgress {
		lc.Log.Noticef("%s: Radio-silence state changing operation has finalized "+
			"(as seen by zedagent)", logPrefix)
		lc.radioSilence.ChangeInProgress = false
		// Radio-silence state change has completed.
		// Notify zedagent so it can update RadioSilence.ChangeInProgress
		// in ZedAgentStatus.
		// The mutex is temporarily released to avoid deadlocks in case
		// ConfigAgent invokes Get methods from within the callback.
		lc.radioSilenceMx.Unlock()
		lc.ConfigAgent.ApplyRadioSilence(lc.radioSilence)
		lc.radioSilenceMx.Lock()
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
				Module:       wwanStatus.Module.ToProto(lc.Log),
				SimCards:     wwanStatus.SimCardsToProto(),
				Providers:    wwanStatus.CellProvidersToProto(),
				ConfigError:  wwanStatus.ConfigError,
				ProbeError:   wwanStatus.ProbeError,
			})
	}
	return &profile.RadioStatus{
		RadioSilence:    dns.RadioSilence.Imposed,
		ConfigError:     dns.RadioSilence.ConfigError,
		CellularStatus:  cellularStatus,
		CellularMetrics: lc.getCellularMetrics(),
	}
}

// getCellularMetrics retrieves cellular metrics.
func (lc *LocalCmdAgent) getCellularMetrics() []*metrics.CellularMetric {
	m, err := lc.WwanMetrics.Get("global")
	if err != nil {
		lc.Log.Errorf("%s: getCellularMetrics: failed to get wwan metrics: %v",
			logPrefix, err)
		return nil
	}
	wwanMetrics := m.(types.WwanMetrics)
	return wwanMetrics.ToProto(lc.Log)
}

// getRadioConfig publish radio status and queries LPS for the desired radio configuration.
// Returns nil if no (new) configuration is available.
func (lc *LocalCmdAgent) getRadioConfig(
	radioStatus *profile.RadioStatus) (radioConfig *profile.RadioConfig, discarded bool) {
	if lc.lpsURL == nil && lc.locConfig.LocURL == "" {
		// In case neither LPS nor LOC is configured, we apply the default configuration
		// of disabled radio silence (i.e. wireless devices are enabled).
		return &profile.RadioConfig{
			RadioSilence: false,
		}, false
	}
	if lc.lpsURL == nil {
		// LPS is not configured, but LOC is, which means that LocalCmdAgent will receive
		// radio configuration via ProcessLocalCommandsFromLoc.
		return nil, false
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf(
			"%s: getRadioConfig: cannot find any configured apps for LPS URL: %s",
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
			fullURL := srvAddr.destURL.String() + radioURLPath
			radioConfig = &profile.RadioConfig{}
			wasPaused := lc.tc.runInterruptible(func() {
				resp, err = lc.CtrlClient.SendLocalProto(
					fullURL, intf, srvAddr.sourceIP, radioStatus, radioConfig)
			})
			if wasPaused {
				lc.Log.Functionf("%s: getRadioConfig: LPS response discarded "+
					"due to task pause", logPrefix)
				// No need to immediately trigger the radio ticker, we retry again just
				// 5 seconds later.
				return nil, true
			}
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				// Throttle sending to be about once per 5 minutes.
				lc.updateRadioTicker(true)
				return nil, false
			case http.StatusOK, http.StatusCreated:
				if radioConfig.GetServerToken() != lc.lpsConfig.LpsToken {
					errList = append(errList, "invalid token submitted by LPS")
					continue
				}
				lc.updateRadioTicker(false)
				return radioConfig, false
			case http.StatusNoContent:
				lc.Log.Tracef("%s: LPS %s does not require change in the radio state",
					logPrefix, lc.lpsURL)
				lc.updateRadioTicker(false)
				return nil, false
			default:
				errList = append(errList, fmt.Sprintf(
					"wrong response status code: %d", resp.StatusCode))
				continue
			}
		}
	}
	lc.Log.Errorf("%s: getRadioConfig: all attempts failed: %s", logPrefix,
		strings.Join(errList, ";"))
	return nil, false
}

// processReceivedRadioConfig applies the received radio configuration and triggers
// state change if necessary. Also persists configuration to disk.
func (lc *LocalCmdAgent) processReceivedRadioConfig(config *profile.RadioConfig) {
	lc.radioSilenceMx.Lock()
	if config == nil || (lc.radioSilence.Imposed == config.RadioSilence) {
		// No actual configuration change to apply, just refresh the persisted config.
		lc.touchRadioConfig()
		lc.radioSilenceMx.Unlock()
		return
	}
	var changed bool
	if lc.radioSilence.Imposed != config.RadioSilence {
		// Configuration for radio silence has changed.
		lc.radioSilence.ChangeRequestedAt = time.Now()
		lc.radioSilence.Imposed = config.RadioSilence
		lc.radioSilence.ChangeInProgress = true
		lc.saveRadioConfig(config)
		lc.Log.Noticef("%s: Triggering radio-silence state change to: %s",
			logPrefix, lc.radioSilence)
		changed = true
	}
	// Unlock before calling the ConfigAgent (to avoid deadlocks in case
	// the ConfigAgent uses Get methods from inside the callback).
	lc.radioSilenceMx.Unlock()
	if changed {
		lc.ConfigAgent.ApplyRadioSilence(lc.radioSilence)
	}
}

// loadSavedRadioConfig reads the saved radio configuration from disk.
// Returns true if a valid configuration was loaded and applied, false otherwise.
func (lc *LocalCmdAgent) loadSavedRadioConfig() bool {
	radioConfigBytes, ts, err := persist.ReadSavedConfig(lc.Log, savedRadioConfigFile)
	if err != nil {
		lc.Log.Errorf("%s: loadSavedRadioConfig: failed to read saved config: %v",
			logPrefix, err)
		return false
	}

	if radioConfigBytes == nil {
		lc.Log.Warnf("%s: No saved radio config found", logPrefix)
		return false
	}

	radioConfig := &profile.RadioConfig{}
	if err := proto.Unmarshal(radioConfigBytes, radioConfig); err != nil {
		lc.Log.Errorf("%s: loadSavedRadioConfig: unmarshalling failed: %v",
			logPrefix, err)
		return false
	}

	lc.Log.Noticef("%s: Loaded saved radio config dated %s: %+v",
		logPrefix, ts.Format(time.RFC3339Nano), radioConfig)

	// Apply the saved radio silence setting
	lc.radioSilence.Imposed = radioConfig.RadioSilence
	return true
}

// saveRadioConfig saves received RadioConfig into the persist partition.
func (lc *LocalCmdAgent) saveRadioConfig(radioConfig *profile.RadioConfig) {
	contents, err := proto.Marshal(radioConfig)
	if err != nil {
		lc.Log.Fatalf("%s: saveRadioConfig: Marshalling failed: %v", logPrefix, err)
	}
	persist.SaveConfig(lc.Log, savedRadioConfigFile, contents)
	return
}

// touchRadioConfig is used to update the modification time of the persisted radio config.
func (lc *LocalCmdAgent) touchRadioConfig() {
	persist.TouchSavedConfig(lc.Log, savedRadioConfigFile)
}
