// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle logLevel and remoteLogLevel for agents.

package agentlog

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
)

// Returns (value, ok)
func GetLogLevel(sub *pubsub.Subscription, agentName string) (string, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Infof("GetLogLevel failed %s\n", err)
		return "", false
	}
	gc := cast.CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.AgentSettings[agentName]
	if ok {
		return as.LogLevel, true
	}
	// Do we have a default entry?
	as, ok = gc.AgentSettings["default"]
	if ok {
		return as.LogLevel, true
	}
	return "", false
}

// Returns (value, ok)
func GetRemoteLogLevel(sub *pubsub.Subscription, agentName string) (string, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Infof("GetRemoteLogLevel failed %s\n", err)
		return "", false
	}
	gc := cast.CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.AgentSettings[agentName]
	if ok {
		return as.RemoteLogLevel, true
	}
	// Do we have a default entry?
	as, ok = gc.AgentSettings["default"]
	if ok {
		return as.RemoteLogLevel, true
	}
	return "", false
}

// Update LogLevel setting based on GlobalConfig and debugOverride
// Return debug bool
func HandleGlobalConfig(sub *pubsub.Subscription, agentName string,
	debugOverride bool) bool {

	log.Infof("HandleGlobalConfig(%s, %v)\n", agentName, debugOverride)
	level := log.InfoLevel
	debug := false
	if debugOverride {
		debug = true
		level = log.DebugLevel
	} else if loglevel, ok := GetLogLevel(sub, agentName); ok {
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
	return debug
}
