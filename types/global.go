// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package types

// GlobalConfig is used for log levels and timer values which are preserved
// across reboots and baseimage-updates.

type perAgentSettings struct {
	LogLevel       string // What we log to files
	RemoteLogLevel string // What we log to zedcloud
}

// Agents subscribe to this info
type GlobalConfig struct {
	// "default" or agentName is the index to the map
	AgentSettings map[string]perAgentSettings

	// Any future globals such as timers we want to save across reboot
}
