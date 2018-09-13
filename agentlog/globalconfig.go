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
	Debug          bool
	LocalLogLevel  int // What we log to files
	RemoteLogLevel int // What we log to zedcloud
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
func GetLocalLogLevel(sub *pubsub.Subscription, agentName string) (int, bool) {
	m, err := sub.Get("global")
	if err != nil {
		log.Printf("GetLocalLogLevel failed %s\n", err)
		return 0, false
	}
	gc := CastGlobalConfig(m)
	// Do we have an entry for this agent?
	as, ok := gc.AgentSettings[agentName]
	if ok {
		return as.LocalLogLevel, true
	}
	// Do we have a global entry?
	as, ok = gc.AgentSettings["global"]
	if ok {
		return as.LocalLogLevel, true
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
	as, ok := gc.AgentSettings[agentName]
	if ok {
		return as.RemoteLogLevel, true
	}
	// Do we have a global entry?
	as, ok = gc.AgentSettings["global"]
	if ok {
		return as.RemoteLogLevel, true
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

// To print a struct in json
// XXX remove?
func PrintGlobalConfig() {
	gc := GlobalConfig{}
	gc.AgentSettings = make(map[string]perAgentSettings)
	gc.AgentSettings["global"] = perAgentSettings{Debug: true}
	gc.AgentSettings["zedagent"] = perAgentSettings{Debug: true}
	log.Printf("GlobalConfig: %+v\n", gc)
	b, err := json.Marshal(gc)
	if err != nil {
		log.Fatal(err, "json Marshal in PrintGlobalConfig")
	}
	log.Printf("%s\n", b)
}
