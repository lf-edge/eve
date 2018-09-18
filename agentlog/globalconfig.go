// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Code to dynamically be able to change settings such as debug flags and
// log levels in running agents
// Intention is to also use this for state we need to save across reboots

package agentlog

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/pubsub"
)

type perAgentSettings struct {
	Debug          bool
	LogLevel       string // What we log to files
	RemoteLogLevel string // What we log to zedcloud
}

// Agents subscribe to this info
type GlobalConfig struct {
	// "global" or agentName is the index to the map
	AgentSettings map[string]perAgentSettings

	// Any future globals such as timers we want to save across reboot
}

// Returns (value, ok)
func GetDebug(sub *pubsub.Subscription, agentName string) (bool, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Printf("GetDebug failed %s\n", err)
		return false, false
	}
	gc := CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.AgentSettings[agentName]
	if ok {
		return as.Debug, true
	}
	// Do we have a global entry?
	as, ok = gc.AgentSettings["global"]
	if ok {
		return as.Debug, true
	}
	return false, false
}

// Returns (value, ok)
func GetLogLevel(sub *pubsub.Subscription, agentName string) (string, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Printf("GetLogLevel failed %s\n", err)
		return "", false
	}
	gc := CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.AgentSettings[agentName]
	if ok {
		return as.LogLevel, true
	}
	// Do we have a global entry?
	as, ok = gc.AgentSettings["global"]
	if ok {
		return as.LogLevel, true
	}
	return "", false
}

// Returns (value, ok)
func GetRemoteLogLevel(sub *pubsub.Subscription, agentName string) (string, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Printf("GetRemoteLogLevel failed %s\n", err)
		return "", false
	}
	gc := CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.AgentSettings[agentName]
	if ok {
		return as.RemoteLogLevel, true
	}
	// Do we have a global entry?
	as, ok = gc.AgentSettings["global"]
	if ok {
		return as.RemoteLogLevel, true
	}
	return "", false
}

// Update LogLevel setting based on GlobalConfig and debugOverride
// Return debug bool
func HandleGlobalConfig(sub *pubsub.Subscription, agentName string,
	debugOverride bool) bool {

	log.Printf("HandleGlobalConfig(%s, %v)\n", agentName, debugOverride)
	level := log.InfoLevel
	debug := false
	if val, ok := GetDebug(sub, agentName); ok {
		debug = val || debugOverride
		if debugOverride {
			level = log.DebugLevel
		}
		log.Printf("handleGlobalConfigModify: debug %v\n", debug)
	}
	if loglevel, ok := GetLogLevel(sub, agentName); ok {
		l, err := log.ParseLevel(loglevel)
		if err != nil {
			log.Printf("ParseLevel failed: %s\n", err)
		} else if !debugOverride {
			level = l
			log.Printf("handleGlobalConfigModify: level %v\n",
				level)
		}
	}
	log.SetLevel(level)
	return debug
}

func CastGlobalConfig(in interface{}) GlobalConfig {
	b, err := json.Marshal(in)
	if err != nil {
		log.Fatal(err, "json Marshal in CastGlobalConfig")
	}
	var output GlobalConfig
	if err := json.Unmarshal(b, &output); err != nil {
		log.Fatal(err, "json Unmarshal in CastGlobalConfig")
	}
	return output
}
