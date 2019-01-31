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
	StaleConfigTime         uint32 // On reboot use saved config if not stale
	DownloadGCTime          uint32 // Garbage collect if no use
	VdiskGCTime             uint32 // Garbage collect RW disk if no use

	DownloadRetryTime   uint32 // Retry failed download after N sec
	DomainBootRetryTime uint32 // Retry failed boot after N sec

	// Control NIM testing behavior:
	NetworkTestDuration       uint32 // Time we wait for DHCP to complete
	NetworkTestInterval       uint32 // Re-test DevicePortConfig
	NetworkTestBetterInterval uint32 // Look for better DevicePortConfig

	// NoUsbAccess
	// Determines if Dom0 can use USB devices.
	// If true:
	//		USB devices can only be passed through to the applications
	//		( pciBack=true). The devices are in pci-assignable-list
	// If false:
	// 			dom0 can use these devices as well.
	//			By default, all USB devices will be assigned to dom0. pciBack=false.
	//			But these devices are still available in pci-assignable-list.
	NoUsbAccess           bool
	NoSshAccess           bool
	AllowAppVnc           bool
	DefaultLogLevel       string
	DefaultRemoteLogLevel string
	// XXX add max space for downloads?
	// XXX add LTE management port usage policy?

	XXXTest bool
	// Per agent settings of log levels; if set for an agent it
	// overrides the Default*Level above
	AgentSettings map[string]perAgentSettings
}

type perAgentSettings struct {
	LogLevel       string // What we log to files
	RemoteLogLevel string // What we log to zedcloud
}
