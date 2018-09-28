// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package types

// GlobalConfig is used for log levels and timer values which are preserved
// across reboots and baseimage-updates.

// Agents subscribe to this info to get at least the log levels
// A value of zero means we should use the default
// All times are in seconds.
type GlobalConfig struct {
	ConfigInterval          uint32 // Try get of device config
	MetricInterval          uint32 // push metrics to cloud
	ResetIfCloudGoneTime    uint32 // reboot if no cloud connectivity
	FallbackIfCloudGoneTime uint32 // ... and shorter during update
	MintimeUpdateSuccess    uint32 // time before zedagent declares success
	NoUsbAccess             bool   // domU has all PCI including USB controllers
	NoSshAccess             bool
	StaleConfigTime         uint32 // On reboot use saved config if not stale
	DefaultLogLevel         string
	DefaultRemoteLogLevel   string
	// XXX add max space for downloads?
	// XXX add LTE uplink usage policy?

	// Per agent settings of log levels; if set for an agent it
	// overrides the Default*Level above
	AgentSettings map[string]perAgentSettings
}

type perAgentSettings struct {
	LogLevel       string // What we log to files
	RemoteLogLevel string // What we log to zedcloud
}
