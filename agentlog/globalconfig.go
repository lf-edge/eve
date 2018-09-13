// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Code to dynamically be able to change settings such as debug flags and
// log levels in running agents
// Intention is to also use this for state we need to save across reboots

package agentlog

import (
	"encoding/json"
	"github.com/zededa/go-provision/pubsub"
	"log"
)

type perAgentSettings struct {
	debug          bool
	localLogLevel  int // What we log to files
	remoteLogLevel int // What we log to zedcloud
}

// Agents subscribe to this info
type GlobalConfig struct {
	// "global" or agentName is the index to the map
	agentSettings map[string]perAgentSettings

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
	as, ok := gc.agentSettings[agentName]
	if ok {
		return as.debug, true
	}
	// Do we have a global entry?
	as, ok = gc.agentSettings["global"]
	if ok {
		return as.debug, true
	}
	return false, false
}

// Returns (value, ok)
func GetLocalLogLevel(sub *pubsub.Subscription, agentName string) (int, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Printf("GetLocalLogLevel failed %s\n", err)
		return 0, false
	}
	gc := CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.agentSettings[agentName]
	if ok {
		return as.localLogLevel, true
	}
	// Do we have a global entry?
	as, ok = gc.agentSettings["global"]
	if ok {
		return as.localLogLevel, true
	}
	return 0, false
}

// Returns (value, ok)
func GetRemoteLogLevel(sub *pubsub.Subscription, agentName string) (int, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Printf("GetRemoteLogLevel failed %s\n", err)
		return 0, false
	}
	gc := CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.agentSettings[agentName]
	if ok {
		return as.remoteLogLevel, true
	}
	// Do we have a global entry?
	as, ok = gc.agentSettings["global"]
	if ok {
		return as.remoteLogLevel, true
	}
	return 0, false
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
