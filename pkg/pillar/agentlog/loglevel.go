// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handle logLevel and remoteLogLevel for agents.

package agentlog

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func GetGlobalConfig(sub pubsub.Subscription) *types.ConfigItemValueMap {

	m, err := sub.Get("global")
	if err != nil {
		log.Infof("GlobalConfig failed %s\n", err)
		return nil
	}
	gc := m.(types.ConfigItemValueMap)
	return &gc
}

// Returns (value, ok)
func GetLogLevel(sub pubsub.Subscription, agentName string) (string, bool) {
	return getLogLevelImpl(sub, agentName, true)
}

func GetLogLevelNoDefault(sub pubsub.Subscription, agentName string) (string, bool) {
	return getLogLevelImpl(sub, agentName, false)
}

func getLogLevelImpl(sub pubsub.Subscription, agentName string,
	allowDefault bool) (string, bool) {

	m, err := sub.Get("global")
	if err != nil {
		log.Infof("GetLogLevel failed %s\n", err)
		return "", false
	}
	gc := m.(types.ConfigItemValueMap)
	// Do we have an entry for this agent?
	loglevel := gc.AgentSettingStringValue(agentName, types.LogLevel)
	defaultLogLevel := types.DefaultConfigItemValueMap().GlobalValueString(types.DefaultLogLevel)
	if loglevel != "" {
		return loglevel, true
	}
	// Do we have a default value?
	if allowDefault && defaultLogLevel != "" {
		return defaultLogLevel, true
	}
	return "", false
}

// Returns (value, ok)
func GetRemoteLogLevel(sub pubsub.Subscription, agentName string) (string, bool) {
	return getRemoteLogLevelImpl(sub, agentName, true)
}

func GetRemoteLogLevelNoDefault(sub pubsub.Subscription, agentName string) (string, bool) {
	return getRemoteLogLevelImpl(sub, agentName, false)
}

func getRemoteLogLevelImpl(sub pubsub.Subscription, agentName string,
	allowDefault bool) (string, bool) {

	m, err := sub.Get("global")
	if err != nil {
		log.Infof("GetRemoteLogLevel failed %s\n", err)
		return "", false
	}
	gc := m.(types.ConfigItemValueMap)
	// Do we have an entry for this agent?
	loglevel := gc.AgentSettingStringValue(agentName, types.RemoteLogLevel)
	defaultLogLevel := types.DefaultConfigItemValueMap().GlobalValueString(types.DefaultRemoteLogLevel)
	if loglevel != "" {
		return loglevel, true
	}
	// Do we have a default value?
	if allowDefault && defaultLogLevel != "" {
		return defaultLogLevel, true
	}
	return "", false
}

func LogLevel(gc *types.ConfigItemValueMap, agentName string) string {

	loglevel := gc.AgentSettingStringValue(agentName, types.LogLevel)
	if loglevel != "" {
		return loglevel
	}
	return ""
}

// Update LogLevel setting based on GlobalConfig and debugOverride
// Return debug bool
func HandleGlobalConfig(sub pubsub.Subscription, agentName string,
	debugOverride bool) (bool, *types.ConfigItemValueMap) {

	log.Infof("HandleGlobalConfig(%s, %v)\n", agentName, debugOverride)
	return handleGlobalConfigImpl(sub, agentName, debugOverride, true)
}

func HandleGlobalConfigNoDefault(sub pubsub.Subscription, agentName string,
	debugOverride bool) (bool, *types.ConfigItemValueMap) {

	log.Infof("HandleGlobalConfig(%s, %v)\n", agentName, debugOverride)
	return handleGlobalConfigImpl(sub, agentName, debugOverride, false)
}

func handleGlobalConfigImpl(sub pubsub.Subscription, agentName string,
	debugOverride bool, allowDefault bool) (bool, *types.ConfigItemValueMap) {

	level := log.InfoLevel
	debug := false
	gcp := GetGlobalConfig(sub)
	log.Infof("HandleGlobalConfig: gcp %+v\n", gcp)
	if debugOverride {
		debug = true
		level = log.DebugLevel
	} else if loglevel, ok := getLogLevelImpl(sub, agentName, allowDefault); ok {
		l, err := log.ParseLevel(loglevel)
		if err != nil {
			log.Errorf("ParseLevel %s failed: %s\n", loglevel, err)
		} else if !debugOverride {
			level = l
			log.Infof("handleGlobalConfigModify: level %v\n",
				level)
		}
		if level == log.DebugLevel {
			debug = true
		}
	}
	log.SetLevel(level)
	return debug, gcp
}
