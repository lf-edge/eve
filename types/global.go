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

	// Control NIM testing behavior: In seconds
	NetworkGeoRedoTime        uint32 // Periodic IP geolocation
	NetworkGeoRetryTime       uint32 // Redo IP geolocation failure
	NetworkTestDuration       uint32 // Time we wait for DHCP to complete
	NetworkTestInterval       uint32 // Re-test DevicePortConfig
	NetworkTestBetterInterval uint32 // Look for better DevicePortConfig

	// UsbAccess
	// Determines if Dom0 can use USB devices.
	// If false:
	//		USB devices can only be passed through to the applications
	//		( pciBack=true). The devices are in pci-assignable-list
	// If true:
	// 		dom0 can use these devices as well.
	//		All USB devices will be assigned to dom0. pciBack=false.
	//		But these devices are still available in pci-assignable-list.
	UsbAccess             bool
	SshAccess             bool
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

// Default values until/unless we receive them from the cloud
// We do a GET of config every 60 seconds,
// PUT of metrics every 60 seconds,
// If we don't hear anything from the cloud in a week, then we reboot,
// and during a post-update boot that time is reduced to 10 minutes.
// On reboot if we can't get a config, then we use a saved one if the saved is
// not older than 10 minutes.
// A downloaded image which isn't used is garbage collected after 10 minutes.
// If a instance has been removed its read/write vdisks are deleted after
// one hour.
var GlobalConfigDefaults = GlobalConfig{
	ConfigInterval:          60,
	MetricInterval:          60,
	ResetIfCloudGoneTime:    7 * 24 * 3600,
	FallbackIfCloudGoneTime: 600,
	MintimeUpdateSuccess:    300,

	NetworkGeoRedoTime:        3600, // 1 hour
	NetworkGeoRetryTime:       600,  // 10 minutes
	NetworkTestDuration:       30,
	NetworkTestInterval:       300,  // 5 minutes
	NetworkTestBetterInterval: 1800, // 30 minutes

	UsbAccess:             true,   // Contoller likely to default to false
	SshAccess:             true,   // Contoller likely to default to false
	StaleConfigTime:       600,    // Use stale config for up to 10 minutes
	DownloadGCTime:        600,    // 10 minutes
	VdiskGCTime:           3600,   // 1 hour
	DownloadRetryTime:     600,    // 10 minutes
	DomainBootRetryTime:   600,    // 10 minutes
	DefaultLogLevel:       "info", // XXX change default to warning?
	DefaultRemoteLogLevel: "warning",
}
