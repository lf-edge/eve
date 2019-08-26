// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	log "github.com/sirupsen/logrus"
)

const (
	globalConfigDir  = "/persist/config/GlobalConfig"
	globalConfigFile = globalConfigDir + "/global.json"
	symlinkDir       = "/var/tmp/zededa/GlobalConfig"
)

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
	NetworkGeoRedoTime        uint32   // Periodic IP geolocation
	NetworkGeoRetryTime       uint32   // Redo IP geolocation failure
	NetworkTestDuration       uint32   // Time we wait for DHCP to complete
	NetworkTestInterval       uint32   // Re-test DevicePortConfig
	NetworkTestBetterInterval uint32   // Look for better DevicePortConfig
	NetworkFallbackAnyEth     TriState // When no connectivity try any Ethernet, wlan, and wwan
	NetworkTestTimeout        uint32   // Timeout for each test http/send

	// zedagent, logmanager, etc
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

	// Normally the EVE microservices as well as baseos images will download
	// using free and non-free (e.g., WWAN) ports, while app images will
	// only download using the free ports. These can change that behavior
	AllowNonFreeAppImages  TriState // For app images
	AllowNonFreeBaseImages TriState // For baseos images
	AllowNonFreeCerts      TriState // For cert objects

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
var GlobalConfigDefaults = GlobalConfig{
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

	AllowNonFreeAppImages:  TS_DISABLED,
	AllowNonFreeBaseImages: TS_ENABLED,
	AllowNonFreeCerts:      TS_ENABLED,

	DefaultLogLevel:       "info", // XXX Should we change to warning?
	DefaultRemoteLogLevel: "info", // XXX Should we change to warning?
}

// Check which values are set and which should come from defaults
// Zero integers means to use default
func ApplyGlobalConfig(newgc GlobalConfig) GlobalConfig {

	if newgc.ConfigInterval == 0 {
		newgc.ConfigInterval = GlobalConfigDefaults.ConfigInterval
	}
	if newgc.MetricInterval == 0 {
		newgc.MetricInterval = GlobalConfigDefaults.MetricInterval
	}
	if newgc.ResetIfCloudGoneTime == 0 {
		newgc.ResetIfCloudGoneTime = GlobalConfigDefaults.ResetIfCloudGoneTime
	}
	if newgc.FallbackIfCloudGoneTime == 0 {
		newgc.FallbackIfCloudGoneTime = GlobalConfigDefaults.FallbackIfCloudGoneTime
	}
	if newgc.MintimeUpdateSuccess == 0 {
		newgc.MintimeUpdateSuccess = GlobalConfigDefaults.MintimeUpdateSuccess
	}
	if newgc.NetworkGeoRedoTime == 0 {
		newgc.NetworkGeoRedoTime = GlobalConfigDefaults.NetworkGeoRedoTime
	}
	if newgc.NetworkGeoRetryTime == 0 {
		newgc.NetworkGeoRetryTime = GlobalConfigDefaults.NetworkGeoRetryTime
	}
	if newgc.NetworkTestDuration == 0 {
		newgc.NetworkTestDuration = GlobalConfigDefaults.NetworkTestDuration
	}
	if newgc.NetworkTestInterval == 0 {
		newgc.NetworkTestInterval = GlobalConfigDefaults.NetworkTestInterval
	}
	// We allow newgc.NetworkTestBetterInterval to be zero meaning disabled

	if newgc.NetworkFallbackAnyEth == TS_NONE {
		newgc.NetworkFallbackAnyEth = GlobalConfigDefaults.NetworkFallbackAnyEth
	}
	if newgc.NetworkTestTimeout == 0 {
		newgc.NetworkTestTimeout = GlobalConfigDefaults.NetworkTestTimeout
	}
	if newgc.NetworkSendTimeout == 0 {
		newgc.NetworkSendTimeout = GlobalConfigDefaults.NetworkSendTimeout
	}
	if newgc.StaleConfigTime == 0 {
		newgc.StaleConfigTime = GlobalConfigDefaults.StaleConfigTime
	}
	if newgc.DownloadGCTime == 0 {
		newgc.DownloadGCTime = GlobalConfigDefaults.DownloadGCTime
	}
	if newgc.VdiskGCTime == 0 {
		newgc.VdiskGCTime = GlobalConfigDefaults.VdiskGCTime
	}
	if newgc.DownloadRetryTime == 0 {
		newgc.DownloadRetryTime = GlobalConfigDefaults.DownloadRetryTime
	}
	if newgc.DomainBootRetryTime == 0 {
		newgc.DomainBootRetryTime = GlobalConfigDefaults.DomainBootRetryTime
	}
	if newgc.DefaultLogLevel == "" {
		newgc.DefaultLogLevel = GlobalConfigDefaults.DefaultLogLevel
	}
	if newgc.DefaultRemoteLogLevel == "" {
		newgc.DefaultRemoteLogLevel = GlobalConfigDefaults.DefaultRemoteLogLevel
	}
	if newgc.AllowNonFreeAppImages == TS_NONE {
		newgc.AllowNonFreeAppImages = GlobalConfigDefaults.AllowNonFreeAppImages
	}
	if newgc.AllowNonFreeBaseImages == TS_NONE {
		newgc.AllowNonFreeBaseImages = GlobalConfigDefaults.AllowNonFreeBaseImages
	}
	if newgc.AllowNonFreeCerts == TS_NONE {
		newgc.AllowNonFreeCerts = GlobalConfigDefaults.AllowNonFreeCerts
	}
	return newgc
}

// We enforce that timers are not below these values
var GlobalConfigMinimums = GlobalConfig{
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

	StaleConfigTime:     0, // Don't use stale config
	DownloadGCTime:      60,
	VdiskGCTime:         60,
	DownloadRetryTime:   60,
	DomainBootRetryTime: 10,
}

func EnforceGlobalConfigMinimums(newgc GlobalConfig) GlobalConfig {

	if newgc.ConfigInterval < GlobalConfigMinimums.ConfigInterval {
		log.Warnf("Enforce minimum ConfigInterval received %d; using %d",
			newgc.ConfigInterval, GlobalConfigMinimums.ConfigInterval)
		newgc.ConfigInterval = GlobalConfigMinimums.ConfigInterval
	}
	if newgc.MetricInterval < GlobalConfigMinimums.MetricInterval {
		log.Warnf("Enforce minimum MetricInterval received %d; using %d",
			newgc.MetricInterval, GlobalConfigMinimums.MetricInterval)
		newgc.MetricInterval = GlobalConfigMinimums.MetricInterval
	}
	if newgc.ResetIfCloudGoneTime < GlobalConfigMinimums.ResetIfCloudGoneTime {
		log.Warnf("Enforce minimum XXX received %d; using %d",
			newgc.ResetIfCloudGoneTime, GlobalConfigMinimums.ResetIfCloudGoneTime)
		newgc.ResetIfCloudGoneTime = GlobalConfigMinimums.ResetIfCloudGoneTime
	}
	if newgc.FallbackIfCloudGoneTime < GlobalConfigMinimums.FallbackIfCloudGoneTime {
		log.Warnf("Enforce minimum FallbackIfCloudGoneTime received %d; using %d",
			newgc.FallbackIfCloudGoneTime, GlobalConfigMinimums.FallbackIfCloudGoneTime)
		newgc.FallbackIfCloudGoneTime = GlobalConfigMinimums.FallbackIfCloudGoneTime
	}
	if newgc.MintimeUpdateSuccess < GlobalConfigMinimums.MintimeUpdateSuccess {
		log.Warnf("Enforce minimum MintimeUpdateSuccess received %d; using %d",
			newgc.MintimeUpdateSuccess, GlobalConfigMinimums.MintimeUpdateSuccess)
		newgc.MintimeUpdateSuccess = GlobalConfigMinimums.MintimeUpdateSuccess
	}
	if newgc.NetworkGeoRedoTime < GlobalConfigMinimums.NetworkGeoRedoTime {
		log.Warnf("Enforce minimum NetworkGeoRedoTime received %d; using %d",
			newgc.NetworkGeoRedoTime, GlobalConfigMinimums.NetworkGeoRedoTime)
		newgc.NetworkGeoRedoTime = GlobalConfigMinimums.NetworkGeoRedoTime
	}
	if newgc.NetworkGeoRetryTime < GlobalConfigMinimums.NetworkGeoRetryTime {
		log.Warnf("Enforce minimum NetworkGeoRetryTime received %d; using %d",
			newgc.NetworkGeoRetryTime, GlobalConfigMinimums.NetworkGeoRetryTime)
		newgc.NetworkGeoRetryTime = GlobalConfigMinimums.NetworkGeoRetryTime
	}
	if newgc.NetworkTestDuration < GlobalConfigMinimums.NetworkTestDuration {
		log.Warnf("Enforce minimum NetworkTestDuration received %d; using %d",
			newgc.NetworkTestDuration, GlobalConfigMinimums.NetworkTestDuration)
		newgc.NetworkTestDuration = GlobalConfigMinimums.NetworkTestDuration
	}
	if newgc.NetworkTestInterval < GlobalConfigMinimums.NetworkTestInterval {
		newgc.NetworkTestInterval = GlobalConfigMinimums.NetworkTestInterval
	}
	if newgc.NetworkTestBetterInterval < GlobalConfigMinimums.NetworkTestBetterInterval {
		log.Warnf("Enforce minimum NetworkTestInterval received %d; using %d",
			newgc.NetworkTestBetterInterval, GlobalConfigMinimums.NetworkTestBetterInterval)
		newgc.NetworkTestBetterInterval = GlobalConfigMinimums.NetworkTestBetterInterval
	}

	if newgc.StaleConfigTime < GlobalConfigMinimums.StaleConfigTime {
		log.Warnf("Enforce minimum StaleConfigTime received %d; using %d",
			newgc.StaleConfigTime, GlobalConfigMinimums.StaleConfigTime)
		newgc.StaleConfigTime = GlobalConfigMinimums.StaleConfigTime
	}
	if newgc.DownloadGCTime < GlobalConfigMinimums.DownloadGCTime {
		log.Warnf("Enforce minimum DownloadGCTime received %d; using %d",
			newgc.DownloadGCTime, GlobalConfigMinimums.DownloadGCTime)
		newgc.DownloadGCTime = GlobalConfigMinimums.DownloadGCTime
	}
	if newgc.VdiskGCTime < GlobalConfigMinimums.VdiskGCTime {
		log.Warnf("Enforce minimum VdiskGCTime received %d; using %d",
			newgc.VdiskGCTime, GlobalConfigMinimums.VdiskGCTime)
		newgc.VdiskGCTime = GlobalConfigMinimums.VdiskGCTime
	}
	if newgc.DownloadRetryTime < GlobalConfigMinimums.DownloadRetryTime {
		log.Warnf("Enforce minimum DownloadRetryTime received %d; using %d",
			newgc.DownloadRetryTime, GlobalConfigMinimums.DownloadRetryTime)
		newgc.DownloadRetryTime = GlobalConfigMinimums.DownloadRetryTime
	}
	if newgc.DomainBootRetryTime < GlobalConfigMinimums.DomainBootRetryTime {
		log.Warnf("Enforce minimum DomainBootRetryTime received %d; using %d",
			newgc.DomainBootRetryTime, GlobalConfigMinimums.DomainBootRetryTime)
		newgc.DomainBootRetryTime = GlobalConfigMinimums.DomainBootRetryTime
	}
	return newgc
}

// Agents which wait for GlobalConfig initialized should call this
// on startup to make sure we have a GlobalConfig file.
func EnsureGCFile() {
	if _, err := os.Stat(globalConfigDir); err != nil {
		log.Infof("Create %s\n", globalConfigDir)
		if err := os.MkdirAll(globalConfigDir, 0700); err != nil {
			log.Fatal(err)
		}
	}
	// If it exists but doesn't parse we pretend it doesn't exist
	if _, err := os.Stat(globalConfigFile); err == nil {
		ok := false
		sb, err := ioutil.ReadFile(globalConfigFile)
		if err != nil {
			log.Errorf("%s for %s", err, globalConfigFile)
		} else {
			gc := GlobalConfig{}
			if err := json.Unmarshal(sb, &gc); err != nil {
				log.Errorf("%s file: %s", err, globalConfigFile)
			} else {
				ok = true
			}
			// Any new fields which need defaults/mins applied?
			changed := false
			updated := ApplyGlobalConfig(gc)
			if !cmp.Equal(gc, updated) {
				log.Infof("EnsureGCFile: updated with defaults %v",
					cmp.Diff(gc, updated))
				changed = true
			}
			sane := EnforceGlobalConfigMinimums(updated)
			if !cmp.Equal(updated, sane) {
				log.Infof("EnsureGCFile: enforced minimums %v",
					cmp.Diff(updated, sane))
				changed = true
			}
			gc = sane
			if changed {
				err := pubsub.PublishToDir("/persist/config/",
					"global", gc)
				if err != nil {
					log.Errorf("PublishToDir for globalConfig failed: %s",
						err)
				}
			}
		}
		if !ok {
			log.Warnf("Removing bad %s", globalConfigFile)
			if err := os.RemoveAll(globalConfigFile); err != nil {
				log.Fatal(err)
			}
		}
	}
	if _, err := os.Stat(globalConfigFile); err != nil {
		err := pubsub.PublishToDir("/persist/config/", "global",
			GlobalConfigDefaults)
		if err != nil {
			log.Errorf("PublishToDir for globalConfig failed %s\n",
				err)
		}
	}

	info, err := os.Lstat(symlinkDir)
	if err == nil {
		if (info.Mode() & os.ModeSymlink) != 0 {
			return
		}
		log.Warnf("Removing old %s", symlinkDir)
		if err := os.RemoveAll(symlinkDir); err != nil {
			log.Fatal(err)
		}
	}
	if err := os.Symlink(globalConfigDir, symlinkDir); err != nil {
		log.Fatal(err)
	}
}
