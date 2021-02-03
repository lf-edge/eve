// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// IMP - XXX TODO - This file should be removed when all 4.X and 5.0
// versions of EVE become unsupported - when Eve 5.1.x is the oldest
// image supported. DO NOT add any new features into this. THIS is OBSOLETE.

package types

import (
	"github.com/sirupsen/logrus"
)

// OldGlobalConfig - Legacy version of global config. Kept for upgradeconverter
type OldGlobalConfig struct {
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
	NetworkGeoRedoTime        uint32   // Periodic IP geolocation
	NetworkGeoRetryTime       uint32   // Redo IP geolocation failure
	NetworkTestDuration       uint32   // Time we wait for DHCP to complete
	NetworkTestInterval       uint32   // Re-test DevicePortConfig
	NetworkTestBetterInterval uint32   // Look for better DevicePortConfig
	NetworkFallbackAnyEth     TriState // When no connectivity try any Ethernet, wlan, and wwan
	NetworkTestTimeout        uint32   // Timeout for each test http/send

	// zedagent, etc
	NetworkSendTimeout uint32 // Timeout for each http/send

	// UsbAccess
	// Determines if Dom0 can use USB devices.
	// If false:
	//		USB devices can only be passed through to the applications
	//		( pciBack=true). The devices are in pci-assignable-list
	// If true:
	// 		dom0 can use these devices as well.
	//		All USB devices will be assigned to dom0. pciBack=false.
	//		But these devices are still available in pci-assignable-list.
	UsbAccess bool

	// Normal operation is to SshAuthorizedKeys from EVE build or using
	// the configItem. SshAccess is used to enable/disable the filter.
	SshAccess         bool
	SshAuthorizedKeys string

	AllowAppVnc bool

	// These settings control how the EVE microservices
	// will use free and non-free (e.g., WWAN) ports for image downloads.
	AllowNonFreeAppImages  TriState // For app images
	AllowNonFreeBaseImages TriState // For baseos images

	// Dom0MinDiskUsagePercent - Percentage of available storage reserved for
	// dom0. The rest is available for Apps.
	Dom0MinDiskUsagePercent  uint32
	IgnoreMemoryCheckForApps bool
	IgnoreDiskCheckForApps   bool

	// XXX add max space for downloads?
	// XXX add max space for running images?

	DefaultLogLevel       string
	DefaultRemoteLogLevel string

	// Per agent settings of log levels; if set for an agent it
	// overrides the Default*Level above
	AgentSettings map[string]PerAgentSettings
}

type PerAgentSettings struct {
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
var globalConfigDefaults = OldGlobalConfig{
	ConfigInterval:          60,
	MetricInterval:          60,
	ResetIfCloudGoneTime:    7 * 24 * 3600,
	FallbackIfCloudGoneTime: 300,
	MintimeUpdateSuccess:    600,

	NetworkGeoRedoTime:        3600, // 1 hour
	NetworkGeoRetryTime:       600,  // 10 minutes
	NetworkTestDuration:       30,
	NetworkTestInterval:       300, // 5 minutes
	NetworkTestBetterInterval: 0,   // Disabled
	NetworkFallbackAnyEth:     TS_ENABLED,
	NetworkTestTimeout:        15,

	NetworkSendTimeout: 120,

	UsbAccess:           true, // Contoller likely to default to false
	SshAccess:           true, // Contoller likely to default to false
	SshAuthorizedKeys:   "",
	StaleConfigTime:     600,  // Use stale config for up to 10 minutes
	DownloadGCTime:      600,  // 10 minutes
	VdiskGCTime:         3600, // 1 hour
	DownloadRetryTime:   600,  // 10 minutes
	DomainBootRetryTime: 600,  // 10 minutes

	AllowNonFreeAppImages:  TS_ENABLED,
	AllowNonFreeBaseImages: TS_ENABLED,

	DefaultLogLevel:       "info", // XXX Should we change to warning?
	DefaultRemoteLogLevel: "info", // XXX Should we change to warning?

	Dom0MinDiskUsagePercent:  20,
	IgnoreMemoryCheckForApps: false,
	IgnoreDiskCheckForApps:   false,
}

// Check which values are set and which should come from defaults
// Zero integers means to use default

// ApplyDefaults - applies defaults to an old global config
func ApplyDefaults(newgc OldGlobalConfig) OldGlobalConfig {

	if newgc.ConfigInterval == 0 {
		newgc.ConfigInterval = globalConfigDefaults.ConfigInterval
	}
	if newgc.MetricInterval == 0 {
		newgc.MetricInterval = globalConfigDefaults.MetricInterval
	}
	if newgc.ResetIfCloudGoneTime == 0 {
		newgc.ResetIfCloudGoneTime = globalConfigDefaults.ResetIfCloudGoneTime
	}
	if newgc.FallbackIfCloudGoneTime == 0 {
		newgc.FallbackIfCloudGoneTime = globalConfigDefaults.FallbackIfCloudGoneTime
	}
	if newgc.MintimeUpdateSuccess == 0 {
		newgc.MintimeUpdateSuccess = globalConfigDefaults.MintimeUpdateSuccess
	}
	if newgc.NetworkGeoRedoTime == 0 {
		newgc.NetworkGeoRedoTime = globalConfigDefaults.NetworkGeoRedoTime
	}
	if newgc.NetworkGeoRetryTime == 0 {
		newgc.NetworkGeoRetryTime = globalConfigDefaults.NetworkGeoRetryTime
	}
	if newgc.NetworkTestDuration == 0 {
		newgc.NetworkTestDuration = globalConfigDefaults.NetworkTestDuration
	}
	if newgc.NetworkTestInterval == 0 {
		newgc.NetworkTestInterval = globalConfigDefaults.NetworkTestInterval
	}
	// We allow newgc.NetworkTestBetterInterval to be zero meaning disabled

	if newgc.NetworkFallbackAnyEth == TS_NONE {
		newgc.NetworkFallbackAnyEth = globalConfigDefaults.NetworkFallbackAnyEth
	}
	if newgc.NetworkTestTimeout == 0 {
		newgc.NetworkTestTimeout = globalConfigDefaults.NetworkTestTimeout
	}
	if newgc.NetworkSendTimeout == 0 {
		newgc.NetworkSendTimeout = globalConfigDefaults.NetworkSendTimeout
	}
	if newgc.StaleConfigTime == 0 {
		newgc.StaleConfigTime = globalConfigDefaults.StaleConfigTime
	}
	if newgc.DownloadGCTime == 0 {
		newgc.DownloadGCTime = globalConfigDefaults.DownloadGCTime
	}
	if newgc.VdiskGCTime == 0 {
		newgc.VdiskGCTime = globalConfigDefaults.VdiskGCTime
	}
	if newgc.DownloadRetryTime == 0 {
		newgc.DownloadRetryTime = globalConfigDefaults.DownloadRetryTime
	}
	if newgc.DomainBootRetryTime == 0 {
		newgc.DomainBootRetryTime = globalConfigDefaults.DomainBootRetryTime
	}
	if newgc.DefaultLogLevel == "" {
		newgc.DefaultLogLevel = globalConfigDefaults.DefaultLogLevel
	}
	if newgc.DefaultRemoteLogLevel == "" {
		newgc.DefaultRemoteLogLevel = globalConfigDefaults.DefaultRemoteLogLevel
	}
	if newgc.AllowNonFreeAppImages == TS_NONE {
		newgc.AllowNonFreeAppImages = globalConfigDefaults.AllowNonFreeAppImages
	}
	if newgc.AllowNonFreeBaseImages == TS_NONE {
		newgc.AllowNonFreeBaseImages = globalConfigDefaults.AllowNonFreeBaseImages
	}

	if newgc.Dom0MinDiskUsagePercent == 0 {
		newgc.Dom0MinDiskUsagePercent =
			globalConfigDefaults.Dom0MinDiskUsagePercent
	}

	// Reset Agent Settings
	newgc.AgentSettings = make(map[string]PerAgentSettings)
	return newgc
}

// We enforce that timers are not below these values
var GlobalConfigMinimums = OldGlobalConfig{
	ConfigInterval:          5,
	MetricInterval:          5,
	ResetIfCloudGoneTime:    120,
	FallbackIfCloudGoneTime: 60,
	MintimeUpdateSuccess:    30,

	NetworkGeoRedoTime:        60,
	NetworkGeoRetryTime:       5,
	NetworkTestDuration:       10,  // Wait for DHCP client
	NetworkTestInterval:       300, // 5 minutes
	NetworkTestBetterInterval: 0,   // Disabled

	StaleConfigTime:         0, // Don't use stale config
	DownloadGCTime:          60,
	VdiskGCTime:             60,
	DownloadRetryTime:       60,
	DomainBootRetryTime:     10,
	Dom0MinDiskUsagePercent: 20,
}

func EnforceGlobalConfigMinimums(newgc OldGlobalConfig) OldGlobalConfig {

	if newgc.ConfigInterval < GlobalConfigMinimums.ConfigInterval {
		logrus.Warnf("Enforce minimum ConfigInterval received %d; using %d",
			newgc.ConfigInterval, GlobalConfigMinimums.ConfigInterval)
		newgc.ConfigInterval = GlobalConfigMinimums.ConfigInterval
	}
	if newgc.MetricInterval < GlobalConfigMinimums.MetricInterval {
		logrus.Warnf("Enforce minimum MetricInterval received %d; using %d",
			newgc.MetricInterval, GlobalConfigMinimums.MetricInterval)
		newgc.MetricInterval = GlobalConfigMinimums.MetricInterval
	}
	if newgc.ResetIfCloudGoneTime < GlobalConfigMinimums.ResetIfCloudGoneTime {
		logrus.Warnf("Enforce minimum XXX received %d; using %d",
			newgc.ResetIfCloudGoneTime, GlobalConfigMinimums.ResetIfCloudGoneTime)
		newgc.ResetIfCloudGoneTime = GlobalConfigMinimums.ResetIfCloudGoneTime
	}
	if newgc.FallbackIfCloudGoneTime < GlobalConfigMinimums.FallbackIfCloudGoneTime {
		logrus.Warnf("Enforce minimum FallbackIfCloudGoneTime received %d; using %d",
			newgc.FallbackIfCloudGoneTime, GlobalConfigMinimums.FallbackIfCloudGoneTime)
		newgc.FallbackIfCloudGoneTime = GlobalConfigMinimums.FallbackIfCloudGoneTime
	}
	if newgc.MintimeUpdateSuccess < GlobalConfigMinimums.MintimeUpdateSuccess {
		logrus.Warnf("Enforce minimum MintimeUpdateSuccess received %d; using %d",
			newgc.MintimeUpdateSuccess, GlobalConfigMinimums.MintimeUpdateSuccess)
		newgc.MintimeUpdateSuccess = GlobalConfigMinimums.MintimeUpdateSuccess
	}
	if newgc.NetworkGeoRedoTime < GlobalConfigMinimums.NetworkGeoRedoTime {
		logrus.Warnf("Enforce minimum NetworkGeoRedoTime received %d; using %d",
			newgc.NetworkGeoRedoTime, GlobalConfigMinimums.NetworkGeoRedoTime)
		newgc.NetworkGeoRedoTime = GlobalConfigMinimums.NetworkGeoRedoTime
	}
	if newgc.NetworkGeoRetryTime < GlobalConfigMinimums.NetworkGeoRetryTime {
		logrus.Warnf("Enforce minimum NetworkGeoRetryTime received %d; using %d",
			newgc.NetworkGeoRetryTime, GlobalConfigMinimums.NetworkGeoRetryTime)
		newgc.NetworkGeoRetryTime = GlobalConfigMinimums.NetworkGeoRetryTime
	}
	if newgc.NetworkTestDuration < GlobalConfigMinimums.NetworkTestDuration {
		logrus.Warnf("Enforce minimum NetworkTestDuration received %d; using %d",
			newgc.NetworkTestDuration, GlobalConfigMinimums.NetworkTestDuration)
		newgc.NetworkTestDuration = GlobalConfigMinimums.NetworkTestDuration
	}
	if newgc.NetworkTestInterval < GlobalConfigMinimums.NetworkTestInterval {
		newgc.NetworkTestInterval = GlobalConfigMinimums.NetworkTestInterval
	}
	if newgc.NetworkTestBetterInterval < GlobalConfigMinimums.NetworkTestBetterInterval {
		logrus.Warnf("Enforce minimum NetworkTestInterval received %d; using %d",
			newgc.NetworkTestBetterInterval, GlobalConfigMinimums.NetworkTestBetterInterval)
		newgc.NetworkTestBetterInterval = GlobalConfigMinimums.NetworkTestBetterInterval
	}

	if newgc.StaleConfigTime < GlobalConfigMinimums.StaleConfigTime {
		logrus.Warnf("Enforce minimum StaleConfigTime received %d; using %d",
			newgc.StaleConfigTime, GlobalConfigMinimums.StaleConfigTime)
		newgc.StaleConfigTime = GlobalConfigMinimums.StaleConfigTime
	}
	if newgc.DownloadGCTime < GlobalConfigMinimums.DownloadGCTime {
		logrus.Warnf("Enforce minimum DownloadGCTime received %d; using %d",
			newgc.DownloadGCTime, GlobalConfigMinimums.DownloadGCTime)
		newgc.DownloadGCTime = GlobalConfigMinimums.DownloadGCTime
	}
	if newgc.VdiskGCTime < GlobalConfigMinimums.VdiskGCTime {
		logrus.Warnf("Enforce minimum VdiskGCTime received %d; using %d",
			newgc.VdiskGCTime, GlobalConfigMinimums.VdiskGCTime)
		newgc.VdiskGCTime = GlobalConfigMinimums.VdiskGCTime
	}
	if newgc.DownloadRetryTime < GlobalConfigMinimums.DownloadRetryTime {
		logrus.Warnf("Enforce minimum DownloadRetryTime received %d; using %d",
			newgc.DownloadRetryTime, GlobalConfigMinimums.DownloadRetryTime)
		newgc.DownloadRetryTime = GlobalConfigMinimums.DownloadRetryTime
	}
	if newgc.DomainBootRetryTime < GlobalConfigMinimums.DomainBootRetryTime {
		logrus.Warnf("Enforce minimum DomainBootRetryTime received %d; using %d",
			newgc.DomainBootRetryTime, GlobalConfigMinimums.DomainBootRetryTime)
		newgc.DomainBootRetryTime = GlobalConfigMinimums.DomainBootRetryTime
	}
	if newgc.Dom0MinDiskUsagePercent < GlobalConfigMinimums.Dom0MinDiskUsagePercent {
		logrus.Warnf("Enforce minimum Dom0MinDiskUsagePercent received %d; using %d",
			newgc.Dom0MinDiskUsagePercent, GlobalConfigMinimums.Dom0MinDiskUsagePercent)
		newgc.Dom0MinDiskUsagePercent = GlobalConfigMinimums.Dom0MinDiskUsagePercent
	}
	return newgc
}

// MoveBetweenConfigs - converts old config to new config
func (config OldGlobalConfig) MoveBetweenConfigs() *ConfigItemValueMap {
	newConfig := DefaultConfigItemValueMap()
	newConfig.SetGlobalValueInt(ConfigInterval, config.ConfigInterval)
	newConfig.SetGlobalValueInt(MetricInterval, config.MetricInterval)
	newConfig.SetGlobalValueInt(ResetIfCloudGoneTime, config.ResetIfCloudGoneTime)
	newConfig.SetGlobalValueInt(FallbackIfCloudGoneTime, config.FallbackIfCloudGoneTime)
	newConfig.SetGlobalValueInt(MintimeUpdateSuccess, config.MintimeUpdateSuccess)
	newConfig.SetGlobalValueInt(StaleConfigTime, config.StaleConfigTime)
	newConfig.SetGlobalValueInt(VdiskGCTime, config.VdiskGCTime)
	newConfig.SetGlobalValueInt(DownloadRetryTime, config.DownloadRetryTime)
	newConfig.SetGlobalValueInt(DomainBootRetryTime, config.DomainBootRetryTime)
	newConfig.SetGlobalValueInt(NetworkGeoRedoTime, config.NetworkGeoRedoTime)
	newConfig.SetGlobalValueInt(NetworkGeoRetryTime, config.NetworkGeoRetryTime)
	newConfig.SetGlobalValueInt(NetworkTestDuration, config.NetworkTestDuration)
	newConfig.SetGlobalValueInt(NetworkTestInterval, config.NetworkTestInterval)
	newConfig.SetGlobalValueInt(NetworkTestBetterInterval, config.NetworkTestBetterInterval)
	newConfig.SetGlobalValueInt(NetworkTestTimeout, config.NetworkTestTimeout)
	newConfig.SetGlobalValueInt(Dom0MinDiskUsagePercent, config.Dom0MinDiskUsagePercent)
	newConfig.SetGlobalValueInt(NetworkSendTimeout, config.NetworkSendTimeout)

	newConfig.SetGlobalValueTriState(NetworkFallbackAnyEth, config.NetworkFallbackAnyEth)
	newConfig.SetGlobalValueTriState(AllowNonFreeAppImages, config.AllowNonFreeAppImages)
	newConfig.SetGlobalValueTriState(AllowNonFreeBaseImages, config.AllowNonFreeBaseImages)

	newConfig.SetGlobalValueBool(AllowAppVnc, config.AllowAppVnc)
	newConfig.SetGlobalValueBool(UsbAccess, config.UsbAccess)
	newConfig.SetGlobalValueBool(IgnoreMemoryCheckForApps, config.IgnoreMemoryCheckForApps)
	newConfig.SetGlobalValueBool(IgnoreDiskCheckForApps, config.IgnoreDiskCheckForApps)

	newConfig.SetGlobalValueString(SSHAuthorizedKeys, config.SshAuthorizedKeys)
	newConfig.SetGlobalValueString(DefaultLogLevel, config.DefaultLogLevel)
	newConfig.SetGlobalValueString(DefaultRemoteLogLevel, config.DefaultRemoteLogLevel)

	for agentName, agentSettings := range config.AgentSettings {
		newConfig.SetAgentSettingStringValue(agentName, LogLevel,
			agentSettings.LogLevel)
		newConfig.SetAgentSettingStringValue(agentName, RemoteLogLevel,
			agentSettings.RemoteLogLevel)
	}

	return newConfig
}
