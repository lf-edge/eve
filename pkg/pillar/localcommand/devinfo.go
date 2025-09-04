// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/shirou/gopsutil/host"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// devInfoURLPath is the API endpoint on the Local Profile Server (LPS)
	// used to POST device information and optionally receive commands.
	devInfoURLPath = "/api/v1/devinfo"
	// devInfoPOSTInterval is the normal interval between device info POSTs.
	devInfoPOSTInterval = time.Minute
	// devInfoPOSTThrottledInterval is the backoff interval used when LPS
	// signals throttling by returning HTTP 404.
	devInfoPOSTThrottledInterval = time.Hour
	// lastDevCmdTimestampFile persists the timestamp of the last successfully
	// applied device command, so that EVE does not re-apply the same command
	// after a restart.
	lastDevCmdTimestampFile = types.PersistStatusDir + "/lastdevcmdtimestamp"
	// maxReadSize limits how many bytes we attempt to read when loading
	// lastDevCmdTimestamp from disk. 1KB is more than sufficient for a uint64.
	maxReadSize = 1024
)

// initializeDevCommands sets up the ticker for periodic device info POSTs
// and restores the last known device command timestamp from persistent storage.
// This ensures commands are not replayed after a restart.
func (lc *LocalCmdAgent) initializeDevCommands() {
	lc.devInfoTicker = newTaskTicker(devInfoPOSTInterval)
	if _, err := os.Stat(lastDevCmdTimestampFile); err != nil && os.IsNotExist(err) {
		lc.lastDevCmdTimestamp = 0
		return
	}
	b, err := fileutils.ReadWithMaxSize(lc.Log, lastDevCmdTimestampFile,
		maxReadSize)
	if err != nil {
		lc.Log.Errorf("%s: initializeDevCmdTimestamp read: %s", logPrefix, err)
		lc.lastDevCmdTimestamp = 0
		return
	}
	u, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		lc.Log.Errorf("%s: initializeDevCmdTimestamp: %s", logPrefix, err)
		lc.lastDevCmdTimestamp = 0
	} else {
		lc.lastDevCmdTimestamp = u
		lc.Log.Noticef("%s: initializeDevCmdTimestamp: read %d", logPrefix,
			lc.lastDevCmdTimestamp)
	}
}

// runDevInfoTask runs a long-lived loop that periodically POSTs device info
// to the LPS and, if present in the response, executes device commands.
func (lc *LocalCmdAgent) runDevInfoTask() {
	lc.Log.Functionf("%s: devInfoTask: waiting for the first trigger", logPrefix)
	// wait for the first trigger
	<-lc.devInfoTicker.tickerChan()
	lc.Log.Functionf("%s: devInfoTask: received the first trigger", logPrefix)
	// trigger again to pass into the loop
	lc.TriggerDevInfoPOST()

	wdName := watchdogPrefix + "devinfo"

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
		devCmd, discarded := lc.postDevInfo()
		if discarded {
			return
		}
		lc.processReceivedDevCommand(devCmd)
		lc.Watchdog.CheckMaxTimeTopic(wdName, "devInfoTask", start,
			warningTime, errorTime)
	}

	for {
		select {
		case <-lc.devInfoTicker.tickerChan():
			task()
		case <-stillRunning.C:
		}
		lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

// TriggerDevInfoPOST forces an immediate tick of the devInfoTicker.
func (lc *LocalCmdAgent) TriggerDevInfoPOST() {
	lc.devInfoTicker.tickNow()
}

// updateDevInfoTicker adjusts the devInfoTicker’s interval.
// If throttling is enabled, the interval is stretched to the throttled interval
// (1 hour); otherwise, it returns to the normal 1-minute cadence.
func (lc *LocalCmdAgent) updateDevInfoTicker(throttle bool) {
	interval := devInfoPOSTInterval
	if throttle {
		interval = devInfoPOSTThrottledInterval
	}
	lc.devInfoTicker.update(throttle, interval)
}

// saveDevCmdTimestamp persists the timestamp of the last applied device command.
// This prevents re-application of the same command after restart.
func (lc *LocalCmdAgent) saveDevCmdTimestamp() {
	b := []byte(fmt.Sprintf("%v", lc.lastDevCmdTimestamp))
	err := fileutils.WriteRename(lastDevCmdTimestampFile, b)
	if err != nil {
		lc.Log.Errorf("%s: saveDevCmdTimestamp write: %s", logPrefix, err)
	}
}

// postDevInfo sends the current device state to the LPS.
// If the response contains a valid device command, it is returned for execution.
// Behavior:
//   - If LPS is not configured or no addresses are available, returns nil.
//   - On 404: switch to throttled posting interval.
//   - On 200/201: return a device command if the LPS token is valid.
//   - On 204: no commands to execute.
//   - On error or unexpected status: log and retry with other LPS addresses.
func (lc *LocalCmdAgent) postDevInfo() (devCmd *profile.LocalDevCmd, discarded bool) {
	if lc.lpsURL == nil {
		// LPS is not configured.
		return nil, false
	}
	if lc.lpsAddresses.empty() {
		lc.Log.Functionf("%s: postDevInfo: cannot find any configured apps for LPS URL: %s",
			logPrefix, lc.lpsURL)
		return nil, false
	}

	devInfo := lc.collectDevInfo()
	var (
		err     error
		resp    *http.Response
		errList []string
	)
	for intf, srvAddrs := range lc.lpsAddresses.addrsByIface {
		for _, srvAddr := range srvAddrs {
			fullURL := srvAddr.destURL.String() + devInfoURLPath
			devCmd = &profile.LocalDevCmd{}
			wasPaused := lc.tc.runInterruptible(func() {
				resp, err = lc.CtrlClient.SendLocalProto(
					fullURL, intf, srvAddr.sourceIP, devInfo, devCmd)
			})
			if wasPaused {
				lc.Log.Functionf("%s: postDevInfo: LPS response discarded "+
					"due to task pause", logPrefix)
				// Retry ASAP to minimize delay in publishing device info
				// and retrieving the latest device commands to execute.
				lc.TriggerDevInfoPOST()
				return nil, true
			}
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocalProto: %v", err))
				continue
			}
			switch resp.StatusCode {
			case http.StatusNotFound:
				// Throttle sending to be about once per hour.
				lc.updateDevInfoTicker(true)
				return nil, false
			case http.StatusOK, http.StatusCreated:
				if devCmd.GetServerToken() != lc.lpsConfig.LpsToken {
					errList = append(errList, "invalid token submitted by LPS")
					continue
				}
				lc.updateDevInfoTicker(false)
				return devCmd, false
			case http.StatusNoContent:
				lc.Log.Tracef("%s: LPS %s does not require additional dev commands "+
					"to execute", logPrefix, lc.lpsURL)
				lc.updateDevInfoTicker(false)
				return nil, false
			default:
				errList = append(errList, fmt.Sprintf(
					"wrong response status code: %d", resp.StatusCode))
				continue
			}
		}
	}
	lc.Log.Errorf("%s: postDevInfo: all attempts failed: %s",
		logPrefix, strings.Join(errList, ";"))
	return nil, false
}

// collectDevInfo collects the current device state from various pubsub topics
// (onboarding, zedagent, nodeagent) and returns a LocalDevInfo message for sending
// to the LPS.
func (lc *LocalCmdAgent) collectDevInfo() *profile.LocalDevInfo {
	msg := profile.LocalDevInfo{}
	obj, err := lc.OnboardingStatus.Get("global")
	if err != nil {
		lc.Log.Errorf("%s: collectDevInfo: failed to get onboarding status: %v",
			logPrefix, err)
	} else {
		onboardingStatus := obj.(types.OnboardingStatus)
		msg.DeviceUuid = onboardingStatus.DeviceUUID.String()
	}
	obj, err = lc.ZedagentStatus.Get("zedagent")
	if err != nil {
		lc.Log.Errorf("%s: collectDevInfo: failed to get zedagent status: %v",
			logPrefix, err)
	} else {
		zedagentStatus := obj.(types.ZedAgentStatus)
		msg.State = info.ZDeviceState(zedagentStatus.DeviceState)
		msg.MaintenanceModeReasons = zedagentStatus.MaintenanceModeReasons.ToProto()
	}
	hinfo, err := host.Info()
	if err != nil {
		lc.Log.Errorf("%s: host.Info(): %s", logPrefix, err)
	} else {
		msg.BootTime = timestamppb.New(
			time.Unix(int64(hinfo.BootTime), 0).UTC())
	}
	obj, err = lc.NodeAgentStatus.Get("nodeagent")
	if err != nil {
		lc.Log.Errorf("%s: collectDevInfo: failed to get nodeagent status: %v",
			logPrefix, err)
	} else {
		nodeAgentStatus := obj.(types.NodeAgentStatus)
		msg.LastBootReason = info.BootReason(nodeAgentStatus.BootReason)
	}
	msg.LastCmdTimestamp = lc.lastDevCmdTimestamp
	return &msg
}

// processReceivedDevCommand executes a device command received from LPS.
// It ensures:
//   - Commands with the same timestamp are not re-applied.
//   - Only commands that trigger changes are persisted.
//   - The lastDevCmdTimestamp is saved early to avoid replay on restart,
//     even if EVE crashes before command execution completes.
//   - Some race conditions (e.g. crash during poweroff command) are tolerated
//     but not perfectly resolvable.
func (lc *LocalCmdAgent) processReceivedDevCommand(devCmd *profile.LocalDevCmd) {
	if devCmd == nil {
		return
	}
	if devCmd.Timestamp == lc.lastDevCmdTimestamp {
		lc.Log.Functionf("%s: unchanged timestamp %v", logPrefix, lc.lastDevCmdTimestamp)
		return
	}
	command := types.DevCommand(devCmd.Command)
	lc.Log.Noticef("%s: Triggering device command: %s", logPrefix, command.String())
	triggeredChanges := lc.ConfigAgent.ApplyLocalDeviceCommand(command, devCmd.Timestamp)
	if triggeredChanges {
		// Persist timestamp here even though the operation is not complete.
		// The only reason it would not complete is if we crash or reboot
		// due to a power failure, and in that case we'd shutdown all the app
		// instances implicitly.
		// However, if it was a shutdown_poweroff command and we crash to
		// get a power failure, then we will not poweroff. It seems impossible
		// to do that without introducing a race condition where we might
		// poweroff without a power cycle from a UPS to power on again.
		lc.lastDevCmdTimestamp = devCmd.Timestamp
		lc.saveDevCmdTimestamp()
	}
}
