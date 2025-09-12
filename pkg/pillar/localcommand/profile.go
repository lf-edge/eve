// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package localcommand

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"google.golang.org/protobuf/proto"
)

const (
	// profileURLPath is the REST endpoint path used to fetch the local profile
	// from the Local Profile Server (LPS).
	profileURLPath = "/api/v1/local_profile"
	// savedLocalProfileFile is the filename under persistent storage where
	// the last successfully applied local profile is stored. This allows
	// LocalCmdAgent to restore the previous state after a reboot.
	savedLocalProfileFile = "lastlocalprofile"
)

// initializeProfile initializes the ticker for fetching local profiles
// from LPS and loads any saved profile from persistent storage to restore
// the last known state after a reboot.
func (lc *LocalCmdAgent) initializeProfile() {
	// GlobalConfig is not yet available, use default config for now.
	// It will be later updated through UpdateGlobalConfig.
	defaultConfig := types.DefaultConfigItemValueMap()
	configInterval := defaultConfig.GlobalValueInt(types.ConfigInterval)
	interval := time.Duration(configInterval) * time.Second
	lc.profileTicker = newTaskTicker(interval)
	lc.processSavedProfile()
}

// runProfileTask periodically fetches the local profile from LPS.
// It starts after an initial trigger from zedagent, then runs at regular
// intervals defined by profileTicker. Any change in the active profile
// is applied to the system through ConfigAgent.
func (lc *LocalCmdAgent) runProfileTask() {
	lc.Log.Functionf("%s: profileTask: waiting for the first trigger", logPrefix)
	// Wait for the first trigger to come from zedagent.
	<-lc.profileTicker.tickerChan()
	lc.Log.Functionf("%s: profileTask: received the first trigger", logPrefix)
	// Trigger again to pass into loop.
	lc.triggerProfileGET()

	wdName := watchdogPrefix + "profile"

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
		changed := lc.updateActiveProfile(false)
		if changed {
			lc.ConfigAgent.ApplyProfile(lc.currentProfile)
		}
		lc.Watchdog.CheckMaxTimeTopic(wdName, "profileGETTask", start,
			warningTime, errorTime)
	}

	for {
		select {
		case <-lc.profileTicker.tickerChan():
			task()
		case <-stillRunning.C:
		}
		lc.Watchdog.StillRunning(wdName, warningTime, errorTime)
	}
}

// GetCurrentProfile returns the currently active profile.
func (lc *LocalCmdAgent) GetCurrentProfile() string {
	lc.profileMx.RLock()
	defer lc.profileMx.RUnlock()
	return lc.currentProfile
}

// GetGlobalProfile returns the global profile as reported by LPS.
func (lc *LocalCmdAgent) GetGlobalProfile() string {
	lc.profileMx.RLock()
	defer lc.profileMx.RUnlock()
	return lc.globalProfile
}

// updateProfileTicker updates the interval used by profileTicker
// based on the latest global configuration.
func (lc *LocalCmdAgent) updateProfileTicker() {
	if lc.globalConfig == nil {
		return
	}
	configInterval := lc.globalConfig.GlobalValueInt(types.ConfigInterval)
	interval := time.Duration(configInterval) * time.Second
	lc.profileTicker.update(false, interval)
}

// parseLocalProfile decodes a LocalProfile protobuf message from bytes.
// Returns the parsed LocalProfile or an error if unmarshalling fails.
func (lc *LocalCmdAgent) parseLocalProfile(
	localProfileBytes []byte) (*profile.LocalProfile, error) {
	var localProfile = &profile.LocalProfile{}
	err := proto.Unmarshal(localProfileBytes, localProfile)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling failed: %v", err)
	}
	return localProfile, nil
}

// readSavedLocalProfile loads the last successfully applied local profile
// from persistent storage (if present). This is used after a reboot to
// restore the previously active profile without waiting for LPS.
// Returns the parsed profile or nil if no profile was saved.
func (lc *LocalCmdAgent) readSavedLocalProfile() (*profile.LocalProfile, error) {
	localProfileMessage, ts, err := persist.ReadSavedConfig(lc.Log, savedLocalProfileFile)
	if err != nil {
		return nil, fmt.Errorf("readSavedLocalProfile: %v", err)
	}
	if localProfileMessage != nil {
		lc.Log.Noticef("%s: Using saved local profile dated %s",
			logPrefix, ts.Format(time.RFC3339Nano))
		return lc.parseLocalProfile(localProfileMessage)
	}
	return nil, nil
}

// getLocalProfileConfig connects to LPS to fetch the local profile.
func (lc *LocalCmdAgent) getLocalProfileConfig() (
	localProfile *profile.LocalProfile, discarded bool) {
	if lc.lpsURL == nil {
		// LPS is not configured.
		return nil, false
	}

	if lc.lpsAddresses.empty() {
		lc.Log.Functionf(
			"%s: getLocalProfileConfig: cannot find any configured apps for LPS URL: %s",
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
			fullURL := srvAddr.destURL.String() + profileURLPath
			localProfile = &profile.LocalProfile{}
			wasPaused := lc.tc.runInterruptible(func() {
				resp, err = lc.CtrlClient.SendLocalProto(
					fullURL, intf, srvAddr.sourceIP, nil, localProfile)
			})
			if wasPaused {
				lc.Log.Functionf("%s: getLocalProfileConfig: LPS response discarded "+
					"due to task pause", logPrefix)
				// Retry ASAP to minimize delay in fetching the latest profile.
				lc.triggerProfileGET()
				return nil, true
			}
			if err != nil {
				errList = append(errList, fmt.Sprintf("SendLocal: %s", err))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				errList = append(errList, fmt.Sprintf(
					"SendLocalProto: wrong response status code: %d",
					resp.StatusCode))
				continue
			}
			if localProfile.GetServerToken() != lc.lpsConfig.LpsToken {
				errList = append(errList, "invalid token submitted by LPS")
				continue
			}
			return localProfile, false
		}
	}
	lc.Log.Errorf("%s: getLocalProfileConfig: all attempts failed: %s",
		logPrefix, strings.Join(errList, ";"))
	return nil, false
}

// saveOrTouchReceivedLocalProfile either:
//   - Updates the modification time of the saved LocalProfile if it matches the
//     currently received profile and token, and the checkpoint file already exists.
//   - Otherwise, saves the new LocalProfile to the checkpoint file.
func (lc *LocalCmdAgent) saveOrTouchReceivedLocalProfile(
	localProfile *profile.LocalProfile) {
	if lc.localProfile == localProfile.GetLocalProfile() &&
		lc.lpsConfig.LpsToken == localProfile.GetServerToken() &&
		persist.ExistsSavedConfig(lc.Log, savedLocalProfileFile) {
		persist.TouchSavedConfig(lc.Log, savedLocalProfileFile)
		return
	}
	contents, err := proto.Marshal(localProfile)
	if err != nil {
		lc.Log.Errorf("%s: saveOrTouchReceivedLocalProfile Marshalling failed: %s",
			logPrefix, err)
		return
	}
	persist.SaveConfig(lc.Log, savedLocalProfileFile, contents)
	return
}

// triggerProfileGET notifies task to reload local profile from LPS.
func (lc *LocalCmdAgent) triggerProfileGET() {
	lc.profileTicker.tickNow()
}

// updateActiveProfile determines the effective profile, where a local profile
// (if available) takes precedence over the global profile.
// - If skipFetch is true, the cached local profile is reused instead of fetching a new one.
// - If a globalProfile argument is provided, it is used to update the global profile state.
// The function updates the agent’s active profile accordingly and returns true if it changed.
func (lc *LocalCmdAgent) updateActiveProfile(skipFetch bool, globalProfile ...string) (changed bool) {
	var profileConfig *profile.LocalProfile
	if !skipFetch {
		var discarded bool
		profileConfig, discarded = lc.getLocalProfileConfig()
		if discarded {
			return false
		}
	}

	lc.profileMx.Lock()
	defer lc.profileMx.Unlock()

	if len(globalProfile) == 1 {
		if lc.globalProfile != globalProfile[0] {
			lc.Log.Noticef("%s: UpdateLpsConfig: GlobalProfile changed from %q to %q",
				logPrefix, lc.globalProfile, globalProfile[0])
			lc.globalProfile = globalProfile[0]
		}
	}

	if lc.lpsURL == nil && lc.localProfile != "" {
		lc.Log.Noticef("%s: clearing localProfile checkpoint since no LPS is configured",
			logPrefix)
		persist.CleanSavedConfig(lc.Log, savedLocalProfileFile)
		lc.localProfile = ""
	}

	if profileConfig != nil {
		lc.saveOrTouchReceivedLocalProfile(profileConfig)
		if lc.localProfile != profileConfig.GetLocalProfile() {
			lc.Log.Noticef("%s: local profile changed from %s to %s",
				logPrefix, lc.localProfile, profileConfig.GetLocalProfile())
			lc.localProfile = profileConfig.GetLocalProfile()
		}
	}

	var newProfile string
	if lc.localProfile == "" {
		newProfile = lc.globalProfile
	} else {
		newProfile = lc.localProfile
	}

	if lc.currentProfile != newProfile {
		lc.Log.Noticef("%s: current profile changed from %s to %s",
			logPrefix, lc.currentProfile, newProfile)
		lc.currentProfile = newProfile
		return true
	}
	return false
}

// processSavedProfile attempts to restore the most recently saved local profile
// from persistent storage. If successful, the profile is set as the starting
// point after a reboot. If no profile is found or an error occurs, the agent
// continues without a preset profile.
func (lc *LocalCmdAgent) processSavedProfile() {
	localProfile, err := lc.readSavedLocalProfile()
	if err != nil {
		lc.Log.Functionf("%s: processSavedProfile: readSavedLocalProfile %s",
			logPrefix, err)
		return
	}
	if localProfile != nil {
		lc.Log.Noticef("%s: starting with localProfile %s", logPrefix,
			localProfile.LocalProfile)
		lc.localProfile = localProfile.LocalProfile
	}
}
