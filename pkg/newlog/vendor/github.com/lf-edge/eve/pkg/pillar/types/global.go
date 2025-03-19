// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus" // OK for logrus.Fatal
)

// SenderStatus - Enum to further clarify the reason for failed SendOnAllIntf/SendOnIntf
type SenderStatus uint8

// Enum of http extra status for 'rtf'
const (
	SenderStatusNone                      SenderStatus = iota
	SenderStatusRefused                                // ECNNREFUSED
	SenderStatusUpgrade                                // 503 indicating controller upgrade in progress
	SenderStatusCertInvalid                            // Server cert expired or NotBefore; device might have wrong time
	SenderStatusCertMiss                               // remote signed senderCertHash we don't have
	SenderStatusSignVerifyFail                         // envelope signature verify failed
	SenderStatusAlgoFail                               // hash algorithm we don't support
	SenderStatusHashSizeError                          // senderCertHash length error
	SenderStatusCertUnknownAuthority                   // device may miss proxy certificate for MiTM
	SenderStatusCertUnknownAuthorityProxy              // device configured proxy, may miss proxy certificate for MiTM
	SenderStatusNotFound                               // 404 indicating device might have been deleted in controller
	SenderStatusForbidden                              // 403 indicating integrity token might invalidated
	SenderStatusFailed                                 // Other failure
	SenderStatusDebug                                  // Not a failure
)

// String prints ASCII
func (status SenderStatus) String() string {
	switch status {
	case SenderStatusNone:
		return "SenderStatusNone"
	case SenderStatusRefused:
		return "SenderStatusRefused"
	case SenderStatusUpgrade:
		return "SenderStatusUpgrade"
	case SenderStatusCertInvalid:
		return "SenderStatusCertInvalid"
	case SenderStatusCertMiss:
		return "SenderStatusCertMiss"
	case SenderStatusSignVerifyFail:
		return "SenderStatusSignVerifyFail"
	case SenderStatusAlgoFail:
		return "SenderStatusAlgoFail"
	case SenderStatusHashSizeError:
		return "SenderStatusHashSizeError"
	case SenderStatusCertUnknownAuthority:
		return "SenderStatusCertUnknownAuthority"
	case SenderStatusCertUnknownAuthorityProxy:
		return "SenderStatusCertUnknownAuthorityProxy"
	case SenderStatusNotFound:
		return "SenderStatusNotFound"
	case SenderStatusForbidden:
		return "SenderStatusForbidden"
	case SenderStatusFailed:
		return "SenderStatusFailed"
	case SenderStatusDebug:
		return "SenderStatusDebug"
	default:
		return fmt.Sprintf("Unknown status %d", status)
	}
}

const (
	// MinuteInSec is number of seconds in a minute
	MinuteInSec = 60
	// HourInSec is number of seconds in a minute
	HourInSec = 60 * MinuteInSec
)

// ConfigItemStatus - Status of Config Items
type ConfigItemStatus struct {
	// Value - Current value of the item
	Value string
	// Err - Error from last config. nil if no error.
	Err error
}

// GlobalStatus - Status of Global Config Items.
type GlobalStatus struct {
	ConfigItems        map[string]ConfigItemStatus
	UnknownConfigItems map[string]ConfigItemStatus
}

// NewGlobalStatus - Creates a new global status
func NewGlobalStatus() *GlobalStatus {
	newGlobalStatus := GlobalStatus{}
	newGlobalStatus.ConfigItems = make(map[string]ConfigItemStatus)
	newGlobalStatus.UnknownConfigItems = make(map[string]ConfigItemStatus)
	return &newGlobalStatus
}

// setItemValue - Sets value for the key. Expects a valid key. asserts if
//
//	the key is not found.
func (gs *GlobalStatus) setItemValue(key, value string) {
	item := gs.ConfigItems[key]
	item.Value = value
	gs.ConfigItems[key] = item
}

func (gs *GlobalStatus) setItemValueInt(key string, intVal uint32) {
	value := strconv.FormatUint(uint64(intVal), 10)
	gs.setItemValue(key, value)
}

func (gs *GlobalStatus) setItemValueTriState(key string, state TriState) {
	value := FormatTriState(state)
	gs.setItemValue(key, value)
}

func (gs *GlobalStatus) setItemValueBool(key string, boolVal bool) {
	value := strconv.FormatBool(boolVal)
	gs.setItemValue(key, value)
}

// UpdateItemValuesFromGlobalConfig - Update values of ConfigItems from
// globalConfig
func (gs *GlobalStatus) UpdateItemValuesFromGlobalConfig(gc ConfigItemValueMap) {
	for key, val := range gc.GlobalSettings {
		gs.setItemValue(string(key), val.StringValue())
	}

	for agentName, agentSettingMap := range gc.AgentSettings {
		for setting, value := range agentSettingMap {
			key := "agent." + agentName + "." + string(setting)
			gs.setItemValue(key, value.StringValue())
		}
	}
}

// GlobalConfig is used for log levels and timer values which are preserved
// across reboots and baseimage-updates.

// Agents subscribe to this info to get at least the log levels
// A value of zero means we should use the default
// All times are in seconds.

// GlobalSettingKey - Constants of all global setting keys
type GlobalSettingKey string

// Try to keep the GlobalSettingKey consts in the same order as in
// NewConfigItemSpecMap
const (

	// Int Items
	// ConfigInterval global setting key
	ConfigInterval GlobalSettingKey = "timer.config.interval"
	// CertInterval global setting key; check for controller cert update
	CertInterval GlobalSettingKey = "timer.cert.interval"
	// MetricInterval global setting key
	MetricInterval GlobalSettingKey = "timer.metric.interval"
	// DiskScanMetricInterval global setting key
	DiskScanMetricInterval GlobalSettingKey = "timer.metric.diskscan.interval"
	// ResetIfCloudGoneTime global setting key
	ResetIfCloudGoneTime GlobalSettingKey = "timer.reboot.no.network"
	// FallbackIfCloudGoneTime global setting key
	FallbackIfCloudGoneTime GlobalSettingKey = "timer.update.fallback.no.network"
	// MintimeUpdateSuccess global setting key
	MintimeUpdateSuccess GlobalSettingKey = "timer.test.baseimage.update"
	// VdiskGCTime global setting key
	VdiskGCTime GlobalSettingKey = "timer.gc.vdisk"
	// DeferContentDelete global setting key
	DeferContentDelete GlobalSettingKey = "timer.defer.content.delete"
	// DownloadRetryTime global setting key
	DownloadRetryTime GlobalSettingKey = "timer.download.retry"
	// DownloadStalledTime global setting key
	DownloadStalledTime GlobalSettingKey = "timer.download.stalled"
	// DomainBootRetryTime global setting key
	DomainBootRetryTime GlobalSettingKey = "timer.boot.retry"
	// NetworkGeoRedoTime global setting key
	NetworkGeoRedoTime GlobalSettingKey = "timer.port.georedo"
	// NetworkGeoRetryTime global setting key
	NetworkGeoRetryTime GlobalSettingKey = "timer.port.georetry"
	// NetworkTestDuration global setting key
	NetworkTestDuration GlobalSettingKey = "timer.port.testduration"
	// NetworkTestInterval global setting key
	NetworkTestInterval GlobalSettingKey = "timer.port.testinterval"
	// NetworkTestBetterInterval global setting key
	NetworkTestBetterInterval GlobalSettingKey = "timer.port.testbetterinterval"
	// NetworkTestTimeout global setting key
	NetworkTestTimeout GlobalSettingKey = "timer.port.timeout"
	// NetworkSendTimeout global setting key
	NetworkSendTimeout GlobalSettingKey = "timer.send.timeout"
	// NetworkDialTimeout global setting key
	NetworkDialTimeout GlobalSettingKey = "timer.dial.timeout"
	// LocationCloudInterval global setting key
	LocationCloudInterval GlobalSettingKey = "timer.location.cloud.interval"
	// LocationAppInterval global setting key
	LocationAppInterval GlobalSettingKey = "timer.location.app.interval"
	// NTPSourcesInterval global setting key
	NTPSourcesInterval GlobalSettingKey = "timer.ntpsources.interval"
	// Dom0MinDiskUsagePercent global setting key
	Dom0MinDiskUsagePercent GlobalSettingKey = "storage.dom0.disk.minusage.percent"
	// Dom0DiskUsageMaxBytes - Max disk usage for Dom0. Dom0 can use
	//  Dom0MinDiskUsagePercent up to a max of  Dom0DiskUsageMaxBytes
	Dom0DiskUsageMaxBytes GlobalSettingKey = "storage.dom0.disk.maxusagebytes"
	// StorageZfsReserved is the percentage reserved in a ZFS pool
	StorageZfsReserved GlobalSettingKey = "storage.zfs.reserved.percent"
	// AppContainerStatsInterval - App Container Stats Collection
	AppContainerStatsInterval GlobalSettingKey = "timer.appcontainer.stats.interval"
	// VaultReadyCutOffTime global setting key
	VaultReadyCutOffTime GlobalSettingKey = "timer.vault.ready.cutoff"
	// LogRemainToSendMBytes Max gzip log files remain on device to be sent in Mbytes
	LogRemainToSendMBytes GlobalSettingKey = "newlog.gzipfiles.ondisk.maxmegabytes"

	// ForceFallbackCounter global setting key
	ForceFallbackCounter = "force.fallback.counter"

	// DownloadMaxPortCost global setting key controls
	// how the EVE microservices will use free and non-free (e.g., WWAN)
	// ports for image downloads.
	DownloadMaxPortCost GlobalSettingKey = "network.download.max.cost"

	// BlobDownloadMaxRetries global setting key
	// how many times EVE will retry to download a blob if its checksum is not verified
	BlobDownloadMaxRetries GlobalSettingKey = "blob.download.max.retries"

	// Bool Items
	// UsbAccess global setting key
	UsbAccess GlobalSettingKey = "debug.enable.usb"
	// VgaAccess global setting to enable host VGA console if it is not assigned to an application
	VgaAccess GlobalSettingKey = "debug.enable.vga"
	// AllowAppVnc global setting key
	AllowAppVnc GlobalSettingKey = "app.allow.vnc"
	// EveMemoryLimitInMiB global setting key, memory limit for EVE in MiB
	EveMemoryLimitInMiB GlobalSettingKey = "memory.eve.limit.MiB"
	// EveMemoryLimitInBytes global setting key, memory limit for EVE in bytes
	// Deprecated: Use EveMemoryLimitInMiB. This config is limited to 4GB
	// as it is stored as uint32. Nevertheles, for backward compatibility,
	// this config is still supported and has higher priority than EveMemoryLimitInMiB.
	EveMemoryLimitInBytes GlobalSettingKey = "memory.eve.limit.bytes"
	// How much memory overhead is allowed for VMM needs
	VmmMemoryLimitInMiB GlobalSettingKey = "memory.vmm.limit.MiB"
	// GOGCMemoryLimitInBytes global setting key
	GOGCMemoryLimitInBytes GlobalSettingKey = "gogc.memory.limit.bytes"
	// GOGCPercent global setting key
	GOGCPercent GlobalSettingKey = "gogc.percent"
	// GOGCForcedIntervalInSec global setting key
	GOGCForcedIntervalInSec GlobalSettingKey = "gogc.forced.interval.seconds"
	// GOGCForcedGrowthMemInMiB global setting key
	GOGCForcedGrowthMemInMiB GlobalSettingKey = "gogc.forced.growth.memory.MiB"
	// GOGCForcedGrowthMemPerc global setting key
	GOGCForcedGrowthMemPerc GlobalSettingKey = "gogc.forced.growth.memory.percent"
	// IgnoreMemoryCheckForApps global setting key
	IgnoreMemoryCheckForApps GlobalSettingKey = "memory.apps.ignore.check"
	// IgnoreDiskCheckForApps global setting key
	IgnoreDiskCheckForApps GlobalSettingKey = "storage.apps.ignore.disk.check"
	// AllowLogFastupload global setting key
	AllowLogFastupload GlobalSettingKey = "newlog.allow.fastupload"
	// EnableARPSnoopOnNI global setting key
	EnableARPSnoop GlobalSettingKey = "network.switch.enable.arpsnoop"
	// WwanQueryVisibleProviders : periodically query visible cellular service providers
	WwanQueryVisibleProviders GlobalSettingKey = "wwan.query.visible.providers"

	// GoroutineLeakDetectionThreshold amount of goroutines, reaching which will trigger leak detection
	// regardless of growth rate.
	GoroutineLeakDetectionThreshold GlobalSettingKey = "goroutine.leak.detection.threshold"
	// GoroutineLeakDetectionCheckIntervalMinutes interval in minutes between the measurements of the
	// goroutine count.
	GoroutineLeakDetectionCheckIntervalMinutes GlobalSettingKey = "goroutine.leak.detection.check.interval.minutes"
	// GoroutineLeakDetectionCheckWindowMinutes interval in minutes for which the leak analysis is performed.
	// It should contain at least 10 measurements, so no less than 10 * GoroutineLeakDetectionCheckIntervalMinutes.
	GoroutineLeakDetectionCheckWindowMinutes GlobalSettingKey = "goroutine.leak.detection.check.window.minutes"
	// GoroutineLeakDetectionKeepStatsHours amount of hours to keep the stats for the leak detection. We keep more
	// stats than the check window to be able to react to settings a bigger check window via configuration.
	GoroutineLeakDetectionKeepStatsHours GlobalSettingKey = "goroutine.leak.detection.keep.stats.hours"
	// GoroutineLeakDetectionCooldownMinutes cooldown period in minutes after the leak detection is triggered. During
	// this period no stack traces are collected, only warning messages are logged.
	GoroutineLeakDetectionCooldownMinutes GlobalSettingKey = "goroutine.leak.detection.cooldown.minutes"

	// TriState Items
	// NetworkFallbackAnyEth global setting key
	NetworkFallbackAnyEth GlobalSettingKey = "network.fallback.any.eth"

	// MaintenanceMode global setting key
	MaintenanceMode GlobalSettingKey = "maintenance.mode"

	// String Items
	// SSHAuthorizedKeys global setting key
	SSHAuthorizedKeys GlobalSettingKey = "debug.enable.ssh"
	// ConsoleAccess global setting key
	ConsoleAccess GlobalSettingKey = "debug.enable.console"
	// Shim VM VNC access global setting key
	VncShimVMAccess GlobalSettingKey = "debug.enable.vnc.shim.vm"
	// DefaultLogLevel default level of logs produced by EVE microservices
	DefaultLogLevel GlobalSettingKey = "debug.default.loglevel"
	// DefaultRemoteLogLevel default level of logs sent by EVE microservices to the controller
	DefaultRemoteLogLevel GlobalSettingKey = "debug.default.remote.loglevel"
	// SyslogLogLevel level of the produced syslog messages
	SyslogLogLevel GlobalSettingKey = "debug.syslog.loglevel"
	// SyslogRemoteLogLevel level of the syslog messages sent to the controller
	SyslogRemoteLogLevel GlobalSettingKey = "debug.syslog.remote.loglevel"
	// KernelLogLevel level of the produced kernel messages
	KernelLogLevel GlobalSettingKey = "debug.kernel.loglevel"
	// KernelRemoteLogLevel level of the kernel messages sent to the controller
	KernelRemoteLogLevel GlobalSettingKey = "debug.kernel.remote.loglevel"
	// FmlCustomResolution global setting key
	FmlCustomResolution GlobalSettingKey = "app.fml.resolution"

	// DisableDHCPAllOnesNetMask option is deprecated and has no effect.
	// Zedrouter no longer uses the all-ones netmask as it adds unnecessary complexity,
	// causes confusion for some applications, and is no longer required for any EVE
	// functionality (previously it was supposedly needed for ACLs and flow logging).
	// We keep the option defined to avoid reporting errors in ZInfoDevice.ConfigItemStatus
	// for older deployments where this option is still configured.
	DisableDHCPAllOnesNetMask GlobalSettingKey = "debug.disable.dhcp.all-ones.netmask"

	// ProcessCloudInitMultiPart to help VMs which do not handle mime multi-part themselves
	ProcessCloudInitMultiPart GlobalSettingKey = "process.cloud-init.multipart"

	// NetDumpEnable : enable publishing of network diagnostics (as tgz archives to /persist/netdump).
	NetDumpEnable GlobalSettingKey = "netdump.enable"
	// NetDumpTopicPreOnboardInterval : how frequently (in seconds) can be netdumps
	// of the same topic published.
	// This interval applies *only until* device is onboarded.
	NetDumpTopicPreOnboardInterval GlobalSettingKey = "netdump.topic.preonboard.interval"
	// NetDumpTopicPostOnboardInterval : how frequently (in seconds) can be netdumps
	// of the same topic published.
	// This interval applies *after* device is onboarded.
	NetDumpTopicPostOnboardInterval GlobalSettingKey = "netdump.topic.postonboard.interval"
	// NetDumpTopicMaxCount : maximum number of netdumps that can be published (persisted)
	// for each topic. The oldest netdump is unpublished should a new netdump exceed the limit.
	NetDumpTopicMaxCount GlobalSettingKey = "netdump.topic.maxcount"
	// NetDumpDownloaderPCAP : Enable to include packet captures inside netdumps for
	// download requests. However, even if enabled, TCP segments carrying non-empty payload
	// (i.e. content which is being downloaded) are excluded.
	NetDumpDownloaderPCAP GlobalSettingKey = "netdump.downloader.with.pcap"
	// NetDumpDownloaderHTTPWithFieldValue : Enable to include HTTP header field values in captured
	// network traces for download requests.
	// Beware: may contain secrets, such as datastore credentials.
	NetDumpDownloaderHTTPWithFieldValue GlobalSettingKey = "netdump.downloader.http.with.fieldvalue"
	// NetworkLocalLegacyMACAddress : Enables legacy MAC address generation for
	// local network instances. The legacy generation is not "that" random and
	// probability of repeating MAC addresses across nodes is high. Later the
	// algorithm was changed and more randomness was introduced, but some
	// applications may be already configured with already allocated MAC
	// address, and MAC address change on EVE node upgrade (switch from old
	// generation logic to new one) can cause problems with the guest network.
	NetworkLocalLegacyMACAddress GlobalSettingKey = "network.local.legacy.mac.address"
	// KubevirtDrainTimeout : how long in hours is allowed for a node drain before a failure is returned
	KubevirtDrainTimeout GlobalSettingKey = "kubevirt.drain.timeout"
	// KubevirtDrainSkipK8sApiTimeout : specifies the time duration in seconds which the drain request handler
	// will continue retrying the k8s api before declaring the node is unavailable and continuing
	// device operations (reboot/shutdown/upgrade)
	// This covers the following k8s.io/apimachinery/pkg/api/errors
	// IsInternalError
	// IsServerTimeout
	// IsServiceUnavailable
	// IsTimeout
	// IsTooManyRequests
	KubevirtDrainSkipK8sAPINotReachableTimeout GlobalSettingKey = "kubevirt.drain.skip.k8sapinotreachable.timeout"

	// MemoryMonitorEnabled : Enable memory monitor
	MemoryMonitorEnabled GlobalSettingKey = "memory-monitor.enabled"
)

// AgentSettingKey - keys for per-agent settings
type AgentSettingKey string

const (
	// LogLevel agent setting key
	LogLevel AgentSettingKey = "debug.loglevel"
	// RemoteLogLevel agent setting key
	RemoteLogLevel AgentSettingKey = "debug.remote.loglevel"
)

const (
	agentSettingKeyPattern       = `^agent\.([0-9A-Za-z_]+)\.([0-9A-Za-z_.]+)$`
	legacyAgentSettingKeyPattern = `^debug\.([0-9A-Za-z_]+)\.([0-9A-Za-z_.]+)$`
)

// ConfigItemType - Defines what type of item we are storing
type ConfigItemType uint8

const (
	// ConfigItemTypeInvalid - Invalid type. Never use it for a valid entry
	ConfigItemTypeInvalid ConfigItemType = iota
	// ConfigItemTypeInt - for config item's who's value is an integer
	ConfigItemTypeInt
	// ConfigItemTypeBool - for config item's who's value is a boolean
	ConfigItemTypeBool
	// ConfigItemTypeString - for config item's who's value is a string
	ConfigItemTypeString
	// ConfigItemTypeTriState - for config item's who's value is a tristate
	ConfigItemTypeTriState
)

var (
	// SyslogKernelLogLevelStr is a string representation of syslog/kernel
	// loglevels.
	SyslogKernelLogLevelStr = [8]string{
		"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
	}
	// SyslogKernelLogLevelNum is a number representation of syslog/kernel
	// loglevels.
	SyslogKernelLogLevelNum = map[string]uint32{
		"none":     0,
		"emerg":    1,
		"alert":    2,
		"crit":     3,
		"critical": 3,
		"err":      4,
		"error":    4,
		"warning":  5,
		"warn":     5,
		"notice":   6,
		"info":     7,
		"debug":    8,
		"all":      99,
	}
	// SyslogKernelDefaultLogLevel is a default loglevel for syslog and kernel.
	SyslogKernelDefaultLogLevel = "info"
)

var (
	// FmlResolutionUnset is a string to indicate that custom resolution is not set
	FmlResolutionUnset = ""
	// FmlResolution800x600 is a string to indicate 800x600 resolution
	FmlResolution800x600 = "800x600"
	// FmlResolution1024x768 is a string to indicate 1024x768 resolution
	FmlResolution1024x768 = "1024x768"
	// FmlResolution1280x800 is a string to indicate 1280x720 resolution
	FmlResolution1280x800 = "1280x800"
	// FmlResolution1920x1080 is a string to indicate 1280x720 resolution
	FmlResolution1920x1080 = "1920x1080"
)

// ConfigItemSpec - Defines what a specification for a configuration should be
type ConfigItemSpec struct {
	Key      string
	ItemType ConfigItemType

	IntMin     uint32
	IntMax     uint32
	IntDefault uint32

	StringValidator Validator
	StringDefault   string
	BoolDefault     bool
	TriStateDefault TriState
}

// DefaultValue - Creates default value from a spec
func (configSpec ConfigItemSpec) DefaultValue() ConfigItemValue {
	var item ConfigItemValue
	item.Key = configSpec.Key
	item.ItemType = configSpec.ItemType
	switch configSpec.ItemType {
	case ConfigItemTypeBool:
		item.BoolValue = configSpec.BoolDefault
	case ConfigItemTypeInt:
		item.IntValue = configSpec.IntDefault
	case ConfigItemTypeString:
		item.StrValue = configSpec.StringDefault
	case ConfigItemTypeTriState:
		item.TriStateValue = configSpec.TriStateDefault
	}
	return item
}

// Validator - pass in function to validate a string
type Validator func(string) error

// ConfigItemSpecMap - Map of all specifications
type ConfigItemSpecMap struct {
	// GlobalSettings - Map Key: GlobalSettingKey, ConfigItemValue.Key: GlobalSettingKey
	GlobalSettings map[GlobalSettingKey]ConfigItemSpec
	// AgentSettingKey - Map Key: AgentSettingKey, ConfigItemValue.Key: AgentSettingKey
	AgentSettings map[AgentSettingKey]ConfigItemSpec
}

// AddIntItem - Adds integer item to specMap
func (specMap *ConfigItemSpecMap) AddIntItem(key GlobalSettingKey,
	defaultInt uint32, min uint32, max uint32) {
	if defaultInt < min || defaultInt > max {
		logrus.Fatalf("Adding int item %s failed. Value does not meet given min/max criteria", key)
	}
	configItem := ConfigItemSpec{
		ItemType:   ConfigItemTypeInt,
		Key:        string(key),
		IntDefault: defaultInt,
		IntMin:     min,
		IntMax:     max,
	}
	specMap.GlobalSettings[key] = configItem
}

// AddBoolItem - Adds boolean item to specMap
func (specMap *ConfigItemSpecMap) AddBoolItem(key GlobalSettingKey, defaultBool bool) {
	configItem := ConfigItemSpec{
		ItemType:    ConfigItemTypeBool,
		Key:         string(key),
		BoolDefault: defaultBool,
	}
	specMap.GlobalSettings[key] = configItem
}

// AddStringItem - Adds string item to specMap
func (specMap *ConfigItemSpecMap) AddStringItem(key GlobalSettingKey, defaultString string, validator Validator) {
	err := validator(defaultString)
	if err != nil {
		defaultString = "failed validation"
		logrus.Fatalf("AddStringItem: key %s, default (%s) Failed "+
			"validator. err: %s", key, defaultString, err)
	}
	configItem := ConfigItemSpec{
		ItemType:        ConfigItemTypeString,
		Key:             string(key),
		StringDefault:   defaultString,
		StringValidator: validator,
	}
	specMap.GlobalSettings[key] = configItem
}

// AddTriStateItem - Adds tristate item to specMap
func (specMap *ConfigItemSpecMap) AddTriStateItem(key GlobalSettingKey, defaultTriState TriState) {
	configItem := ConfigItemSpec{
		Key:             string(key),
		ItemType:        ConfigItemTypeTriState,
		TriStateDefault: defaultTriState,
	}
	specMap.GlobalSettings[key] = configItem
}

// AddAgentSettingStringItem - Adds string item for a per-agent setting
func (specMap *ConfigItemSpecMap) AddAgentSettingStringItem(key AgentSettingKey,
	defaultString string, validator Validator) {
	err := validator(defaultString)
	if err != nil {
		defaultString = "failed validation"
		logrus.Fatalf("AddAgentSettingStringItem: key %s, default (%s) Failed "+
			"validator. err: %s", key, defaultString, err)
	}
	configItem := ConfigItemSpec{
		ItemType:        ConfigItemTypeString,
		Key:             string(key),
		StringDefault:   defaultString,
		StringValidator: validator,
	}
	specMap.AgentSettings[key] = configItem
}

// parseAgentSettingKey
//
//	Returns AgentName, AgentSettingKey, error ( nil if success )
func parseAgentSettingKey(key string) (string, AgentSettingKey, error) {
	// Check new Agent Key Setting
	re := regexp.MustCompile(agentSettingKeyPattern)
	if re.MatchString(key) {
		parsedStrings := re.FindStringSubmatch(key)
		return parsedStrings[1], AgentSettingKey(parsedStrings[2]), nil
	}
	// Check if Legacy Agent Setting
	re = regexp.MustCompile(legacyAgentSettingKeyPattern)
	if re.MatchString(key) {
		parsedStrings := re.FindStringSubmatch(key)
		return parsedStrings[1], AgentSettingKey("debug." + parsedStrings[2]), nil
	}
	// Neither New or Legacy.. Return Error
	err := fmt.Errorf("parseAgentSettingKey: Key %s Doesn't match agent "+
		"Setting Key Pattern", key)
	return "", "", err
}

func (specMap *ConfigItemSpecMap) parseAgentItem(
	newConfigMap *ConfigItemValueMap, oldConfigMap *ConfigItemValueMap,
	key string, value string) (ConfigItemValue, error) {
	agentName, asKey, err := parseAgentSettingKey(key)
	if err != nil {
		return ConfigItemValue{}, err
	}
	itemSpec, ok := specMap.AgentSettings[asKey]
	if !ok {
		err := fmt.Errorf("Cannot find key (%s) in AgentSettings. asKey: %s",
			key, asKey)
		return ConfigItemValue{}, err
	}
	val, err := itemSpec.parseValue(value)
	if err == nil {
		newConfigMap.setAgentSettingValue(agentName, asKey, val)
		return val, nil
	}
	// Parse Error. Get the Value from old config
	val, asErr := oldConfigMap.agentConfigItemValue(agentName, asKey)
	if asErr == nil {
		newConfigMap.setAgentSettingValue(agentName, asKey, val)
		err := fmt.Errorf("ParseItem: Invalid Value for agent Setting - "+
			"agentName: %s, Key: %s. Err: %s. Using Existing Value: %+v",
			agentName, key, err, val)
		return val, err
	}
	// No Existing Value for Agent. It will use the default value.
	val = itemSpec.DefaultValue()
	return val, err
}

// ParseItem - Parses the Key/Value pair into a ConfigItem and updates
//
//	newConfigMap. If there is a Parse error, it copies the corresponding value
//	from oldConfigMap
func (specMap *ConfigItemSpecMap) ParseItem(newConfigMap *ConfigItemValueMap,
	oldConfigMap *ConfigItemValueMap,
	key string, value string) (ConfigItemValue, error) {

	// First check if this is a Global Setting
	gsKey := GlobalSettingKey(key)
	itemSpec, ok := specMap.GlobalSettings[gsKey]
	if !ok {
		// Not a Global Setting. Check if this is a per-agent setting
		return specMap.parseAgentItem(newConfigMap, oldConfigMap, key, value)
	}
	// Global Setting
	val, err := itemSpec.parseValue(value)
	if err == nil {
		newConfigMap.GlobalSettings[gsKey] = val
		return val, nil
	}
	// Parse Error. Get the Value from old config
	val, ok = oldConfigMap.GlobalSettings[gsKey]
	if ok {
		err = fmt.Errorf("***ParseItem: Error in parsing Item. Replacing it "+
			"with existing Value. key: %s, value: %s, Existing Value: %+v. "+
			"Err: %s", key, value, val, err)
	} else {
		val = itemSpec.DefaultValue()
		err = fmt.Errorf("***ParseItem: Error in parsing Item. No Existing "+
			"Value Found. Using Default Value. key: %s, value: %s, "+
			"Default Value: %+v. Err: %s", key, value, val, err)
	}
	newConfigMap.GlobalSettings[gsKey] = val
	return val, err
}

// ConfigItemValue - Stores the value of a setting
type ConfigItemValue struct {
	Key      string
	ItemType ConfigItemType

	IntValue      uint32
	StrValue      string
	BoolValue     bool
	TriStateValue TriState
}

// StringValue - Returns the value in String Format
func (val ConfigItemValue) StringValue() string {
	switch val.ItemType {
	case ConfigItemTypeBool:
		return fmt.Sprintf("%t", val.BoolValue)
	case ConfigItemTypeInt:
		return fmt.Sprintf("%d", val.IntValue)
	case ConfigItemTypeString:
		return val.StrValue
	case ConfigItemTypeTriState:
		return FormatTriState(val.TriStateValue)
	default:
		return fmt.Sprintf("UnknownType(%d)", val.ItemType)
	}
}

// ConfigItemValueMap - Maps both agent and global settings
type ConfigItemValueMap struct {
	// GlobalSettings - Map Key: GlobalSettingKey, ConfigItemValue.Key: GlobalSettingKey
	GlobalSettings map[GlobalSettingKey]ConfigItemValue
	// AgentSettings - Map Outer Key: agentName, Map Inner Key: AgentSettingKey ConfigItemValue.Key: AgentSettingKey
	AgentSettings map[string]map[AgentSettingKey]ConfigItemValue
}

func (configPtr *ConfigItemValueMap) globalConfigItemValue(
	key GlobalSettingKey) ConfigItemValue {
	val, okVal := configPtr.GlobalSettings[key]
	if okVal {
		return val
	}
	// Return Default Value
	specMap := NewConfigItemSpecMap()
	spec, ok := specMap.GlobalSettings[key]
	if ok {
		return spec.DefaultValue()
	}
	logrus.Fatalf("globalConfigItemValue - Invalid key: %s", key)
	return spec.DefaultValue()
}

func (configPtr *ConfigItemValueMap) agentConfigItemValue(agentName string,
	key AgentSettingKey) (ConfigItemValue, error) {
	agent, ok := configPtr.AgentSettings[agentName]
	var blankValue = ConfigItemValue{}
	if ok {
		val, ok := agent[key]
		if ok {
			return val, nil
		}
		return blankValue, fmt.Errorf("Failed to find %s settings for %s", string(key), agentName)
	}
	return blankValue, fmt.Errorf("Failed to find any per-agent settings for agent %s", agentName)
}

// AgentSettingStringValue - Gets the value of a per-agent setting for a certain agentname and per-agent key
func (configPtr *ConfigItemValueMap) AgentSettingStringValue(agentName string, agentSettingKey AgentSettingKey) string {
	val, err := configPtr.agentConfigItemValue(agentName, agentSettingKey)
	if err != nil {
		return ""
	}
	if val.ItemType != ConfigItemTypeString {
		logrus.Fatalf("Agent setting is not of type string. agent-name %s, agentSettingKey %s",
			agentName, string(agentSettingKey))
	}
	return val.StrValue
}

// GlobalValueInt - Gets a int global setting value
func (configPtr *ConfigItemValueMap) GlobalValueInt(key GlobalSettingKey) uint32 {
	val := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeInt {
		return val.IntValue
	} else {
		logrus.Fatalf("***Key(%s) is of Type(%d) NOT Int", key, val.ItemType)
		return 0
	}
}

// GlobalValueString - Gets a string global setting value
func (configPtr *ConfigItemValueMap) GlobalValueString(key GlobalSettingKey) string {
	val := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeString {
		return val.StrValue
	} else {
		logrus.Fatalf("***Key(%s) is of Type(%d) NOT String", key, val.ItemType)
		return ""
	}
}

// GlobalValueTriState - Gets a tristate global setting value
func (configPtr *ConfigItemValueMap) GlobalValueTriState(key GlobalSettingKey) TriState {
	val := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeTriState {
		return val.TriStateValue
	} else {
		logrus.Fatalf("***Key(%s) is of Type(%d) NOT TriState", key, val.ItemType)
		return TS_NONE
	}
}

// GlobalValueBool - Gets a boolean global setting value
func (configPtr *ConfigItemValueMap) GlobalValueBool(key GlobalSettingKey) bool {
	val := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeBool {
		return val.BoolValue
	} else {
		logrus.Fatalf("***Key(%s) is of Type(%d) NOT Bool", key, val.ItemType)
		return false
	}
}

// setAgentSettingValue - Sets an agent value for a certain key and agent name
func (configPtr *ConfigItemValueMap) setAgentSettingValue(
	agentName string, key AgentSettingKey, value ConfigItemValue) {
	_, ok := configPtr.AgentSettings[agentName]
	if !ok {
		// Agent Map not yet set. Create the map
		configPtr.AgentSettings[agentName] =
			make(map[AgentSettingKey]ConfigItemValue)
	}
	configPtr.AgentSettings[agentName][key] = value
}

// SetAgentSettingStringValue - Sets an agent value for a certain key and agent name
func (configPtr *ConfigItemValueMap) SetAgentSettingStringValue(
	agentName string, key AgentSettingKey, newValue string) {
	configItemValue := ConfigItemValue{
		Key:      string(key),
		ItemType: ConfigItemTypeString,
		StrValue: newValue,
	}
	configPtr.setAgentSettingValue(agentName, key, configItemValue)
}

// DelAgentValue - Deletes agent settings for an agent name and agent setting key
func (configPtr *ConfigItemValueMap) DelAgentValue(key AgentSettingKey, agentName string) {
	settingMap, ok := configPtr.AgentSettings[agentName]
	if !ok {
		return
	}
	delete(settingMap, key)
	if len(settingMap) > 0 {
		configPtr.AgentSettings[agentName] = settingMap
	} else {
		// No more settings for Agent.. So delete it from AgentSettings
		delete(configPtr.AgentSettings, agentName)
	}
}

// SetGlobalValueInt - sets a int value for a key
func (configPtr *ConfigItemValueMap) SetGlobalValueInt(key GlobalSettingKey, value uint32) {
	if configPtr.GlobalSettings == nil {
		configPtr.GlobalSettings = make(map[GlobalSettingKey]ConfigItemValue)
	}
	configPtr.GlobalSettings[key] = ConfigItemValue{
		Key:      string(key),
		ItemType: ConfigItemTypeInt,
		IntValue: value,
	}
}

// SetGlobalValueBool - sets a bool value for a key
func (configPtr *ConfigItemValueMap) SetGlobalValueBool(key GlobalSettingKey, value bool) {
	if configPtr.GlobalSettings == nil {
		configPtr.GlobalSettings = make(map[GlobalSettingKey]ConfigItemValue)
	}
	configPtr.GlobalSettings[key] = ConfigItemValue{
		Key:       string(key),
		ItemType:  ConfigItemTypeBool,
		BoolValue: value,
	}
}

// SetGlobalValueTriState - sets a tristate value for a key
func (configPtr *ConfigItemValueMap) SetGlobalValueTriState(key GlobalSettingKey, value TriState) {
	if configPtr.GlobalSettings == nil {
		configPtr.GlobalSettings = make(map[GlobalSettingKey]ConfigItemValue)
	}
	configPtr.GlobalSettings[key] = ConfigItemValue{
		Key:           string(key),
		ItemType:      ConfigItemTypeTriState,
		TriStateValue: value,
	}
}

// SetGlobalValueString - sets a string value for a key
func (configPtr *ConfigItemValueMap) SetGlobalValueString(key GlobalSettingKey, value string) {
	if configPtr.GlobalSettings == nil {
		configPtr.GlobalSettings = make(map[GlobalSettingKey]ConfigItemValue)
	}
	configPtr.GlobalSettings[key] = ConfigItemValue{
		Key:      string(key),
		ItemType: ConfigItemTypeString,
		StrValue: value,
	}
}

// ResetGlobalValue - resets global value to default
func (configPtr *ConfigItemValueMap) ResetGlobalValue(key GlobalSettingKey) {
	specMap := NewConfigItemSpecMap()
	configPtr.GlobalSettings[key] = specMap.GlobalSettings[key].DefaultValue()
}

func (configSpec ConfigItemSpec) parseValue(itemValue string) (ConfigItemValue, error) {
	value := configSpec.DefaultValue()
	var retErr error
	if configSpec.ItemType == ConfigItemTypeInt {
		i64, err := strconv.ParseUint(itemValue, 10, 32)
		if err == nil {
			val := uint32(i64)
			if val > configSpec.IntMax || val < configSpec.IntMin {
				retErr = fmt.Errorf("value out of bounds. Parsed value: %d, Max: %d, Min: %d",
					val, configSpec.IntMax, configSpec.IntMin)
			} else {
				value.IntValue = val
			}
		} else {
			value.IntValue = configSpec.IntDefault
			retErr = err
		}
	} else if configSpec.ItemType == ConfigItemTypeTriState {
		newTs, err := ParseTriState(itemValue)
		if err == nil {
			value.TriStateValue = newTs
		} else {
			value.TriStateValue = configSpec.TriStateDefault
			retErr = err
		}
	} else if configSpec.ItemType == ConfigItemTypeBool {
		newBool, err := strconv.ParseBool(itemValue)
		if err == nil {
			value.BoolValue = newBool
		} else {
			value.BoolValue = configSpec.BoolDefault
			retErr = err
		}
	} else if configSpec.ItemType == ConfigItemTypeString {
		err := configSpec.StringValidator(itemValue)
		if err == nil {
			value.StrValue = itemValue
		} else {
			return value, err
		}
	}
	return value, retErr
}

// NewConfigItemSpecMap - Creates a specmap based on default values
func NewConfigItemSpecMap() ConfigItemSpecMap {
	eveMemoryLimitInBytes, err := GetEveMemoryLimitInBytes()
	if err != nil {
		logrus.Errorf("getEveMemoryLimitInBytes failed: %v", err)
	}
	// Round up to the nearest MiB
	eveMemoryLimitInMiB := uint32((eveMemoryLimitInBytes + 1024*1024 - 1) / (1024 * 1024))
	var configItemSpecMap ConfigItemSpecMap
	configItemSpecMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	configItemSpecMap.AgentSettings = make(map[AgentSettingKey]ConfigItemSpec)

	// timer.config.interval(seconds)
	// MaxValue needs to be limited. If configured too high, the device will wait
	// too long to get next config and is practically unreachable for any config
	// changes or reboot through cloud.
	configItemSpecMap.AddIntItem(ConfigInterval, 60, 5, HourInSec)
	// Additional safety to periodically fetch the controller certificate
	// Useful for odd cases when the triggered updates do not work.
	configItemSpecMap.AddIntItem(CertInterval, 24*HourInSec, 60, 0xFFFFFFFF)
	// timer.metric.diskscan.interval (seconds)
	// Shorter interval can lead to device scanning the disk frequently which is a costly operation.
	configItemSpecMap.AddIntItem(DiskScanMetricInterval, 300, 5, HourInSec)
	// timer.metric.diskscan.interval (seconds)
	// Need to be careful about max value. Controller may use metric message to
	// update status of device (online / suspect etc ).
	configItemSpecMap.AddIntItem(MetricInterval, 60, 5, HourInSec)
	// timer.reboot.no.network (seconds) - reboot after no cloud connectivity
	// Max designed to allow the option of never rebooting even if device
	//  can't connect to the cloud
	configItemSpecMap.AddIntItem(ResetIfCloudGoneTime, 7*24*3600, 120, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(FallbackIfCloudGoneTime, 300, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(MintimeUpdateSuccess, 600, 30, HourInSec)
	configItemSpecMap.AddIntItem(VdiskGCTime, 3600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(DeferContentDelete, 0, 0, 24*3600)
	configItemSpecMap.AddIntItem(DownloadRetryTime, 600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(DownloadStalledTime, 600, 20, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(DomainBootRetryTime, 600, 10, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkGeoRedoTime, 3600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkGeoRetryTime, 600, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestDuration, 30, 10, 3600)
	configItemSpecMap.AddIntItem(NetworkTestInterval, 300, 300, 3600)
	configItemSpecMap.AddIntItem(NetworkTestBetterInterval, 600, 0, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestTimeout, 15, 0, 3600)
	configItemSpecMap.AddIntItem(NetworkSendTimeout, 120, 0, 3600)
	configItemSpecMap.AddIntItem(NetworkDialTimeout, 10, 0, 3600)
	configItemSpecMap.AddIntItem(LocationCloudInterval, HourInSec, 5*MinuteInSec, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(LocationAppInterval, 20, 5, HourInSec)
	configItemSpecMap.AddIntItem(NTPSourcesInterval, 10*MinuteInSec, MinuteInSec, 30*MinuteInSec)
	configItemSpecMap.AddIntItem(Dom0MinDiskUsagePercent, 20, 20, 80)
	configItemSpecMap.AddIntItem(AppContainerStatsInterval, 300, 1, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(VaultReadyCutOffTime, 300, 60, 0xFFFFFFFF)
	// Dom0DiskUsageMaxBytes - Default is 2GB, min is 100MB
	configItemSpecMap.AddIntItem(Dom0DiskUsageMaxBytes, 2*1024*1024*1024,
		100*1024*1024, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(StorageZfsReserved, 20, 1, 99)
	configItemSpecMap.AddIntItem(ForceFallbackCounter, 0, 0, 0xFFFFFFFF)
	//
	// Go garbage collector configuration section
	//
	// Default GOGC memory limit is 0
	configItemSpecMap.AddIntItem(GOGCMemoryLimitInBytes, 0, 0, 0xFFFFFFFF)
	// Default GOGC target percentage is 100, 0 means disable GC
	configItemSpecMap.AddIntItem(GOGCPercent, 100, 0, 500)
	// Default forced GOGC interval in seconds, 0 means disable forced GC
	configItemSpecMap.AddIntItem(GOGCForcedIntervalInSec, 10, 0, 1000)
	// Default forced GOGC growth memory in MiB
	configItemSpecMap.AddIntItem(GOGCForcedGrowthMemInMiB, 50, 10, 1024)
	// Default forced GOGC growth memory percent
	configItemSpecMap.AddIntItem(GOGCForcedGrowthMemPerc, 20, 5, 300)
	//
	configItemSpecMap.AddIntItem(EveMemoryLimitInBytes, uint32(eveMemoryLimitInBytes),
		uint32(eveMemoryLimitInBytes), 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(EveMemoryLimitInMiB, eveMemoryLimitInMiB,
		eveMemoryLimitInMiB, 0xFFFFFFFF)
	// Limit manual vmm overhead override to 1 PiB
	configItemSpecMap.AddIntItem(VmmMemoryLimitInMiB, 0, 0, uint32(1024*1024*1024))
	// LogRemainToSendMBytes - Default is 2 Gbytes, minimum is 10 Mbytes
	configItemSpecMap.AddIntItem(LogRemainToSendMBytes, 2048, 10, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(DownloadMaxPortCost, 0, 0, 255)
	configItemSpecMap.AddIntItem(BlobDownloadMaxRetries, 5, 1, 10)

	// Goroutine Leak Detection section
	configItemSpecMap.AddIntItem(GoroutineLeakDetectionThreshold, 5000, 1, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(GoroutineLeakDetectionCheckIntervalMinutes, 1, 1, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(GoroutineLeakDetectionCheckWindowMinutes, 10, 10, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(GoroutineLeakDetectionKeepStatsHours, 24, 1, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(GoroutineLeakDetectionCooldownMinutes, 5, 1, 0xFFFFFFFF)

	// Kubevirt Drain Section
	configItemSpecMap.AddIntItem(KubevirtDrainTimeout, 24, 1, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(KubevirtDrainSkipK8sAPINotReachableTimeout, 300, 1, 0xFFFFFFFF)

	// Add Bool Items
	configItemSpecMap.AddBoolItem(UsbAccess, true) // Controller likely default to false
	configItemSpecMap.AddBoolItem(VgaAccess, true) // Controller likely default to false
	configItemSpecMap.AddBoolItem(AllowAppVnc, false)
	configItemSpecMap.AddBoolItem(IgnoreMemoryCheckForApps, false)
	configItemSpecMap.AddBoolItem(IgnoreDiskCheckForApps, false)
	configItemSpecMap.AddBoolItem(AllowLogFastupload, false)
	configItemSpecMap.AddBoolItem(DisableDHCPAllOnesNetMask, false)
	configItemSpecMap.AddBoolItem(ProcessCloudInitMultiPart, false)
	configItemSpecMap.AddBoolItem(ConsoleAccess, true) // Controller likely default to false
	configItemSpecMap.AddBoolItem(VncShimVMAccess, false)
	configItemSpecMap.AddBoolItem(EnableARPSnoop, true)
	configItemSpecMap.AddBoolItem(WwanQueryVisibleProviders, false)
	configItemSpecMap.AddBoolItem(NetworkLocalLegacyMACAddress, false)
	configItemSpecMap.AddBoolItem(MemoryMonitorEnabled, false)

	// Add TriState Items
	configItemSpecMap.AddTriStateItem(NetworkFallbackAnyEth, TS_DISABLED)
	configItemSpecMap.AddTriStateItem(MaintenanceMode, TS_NONE)

	// Add String Items
	configItemSpecMap.AddStringItem(SSHAuthorizedKeys, "", blankValidator)
	configItemSpecMap.AddStringItem(DefaultLogLevel, "info", validateLogLevel)
	configItemSpecMap.AddStringItem(DefaultRemoteLogLevel, "info", validateLogLevel)
	configItemSpecMap.AddStringItem(SyslogLogLevel, "info", validateSyslogKernelLevel)
	configItemSpecMap.AddStringItem(KernelLogLevel, "info", validateSyslogKernelLevel)
	configItemSpecMap.AddStringItem(SyslogRemoteLogLevel, "info", validateSyslogKernelLevel)
	configItemSpecMap.AddStringItem(KernelRemoteLogLevel, "info", validateSyslogKernelLevel)
	configItemSpecMap.AddStringItem(FmlCustomResolution, FmlResolutionUnset, blankValidator)

	// Add Agent Settings
	configItemSpecMap.AddAgentSettingStringItem(LogLevel, "info", validateLogLevel)
	configItemSpecMap.AddAgentSettingStringItem(RemoteLogLevel, "info", validateLogLevel)

	// Add NetDump settings
	configItemSpecMap.AddBoolItem(NetDumpEnable, true)
	configItemSpecMap.AddIntItem(NetDumpTopicPreOnboardInterval, HourInSec, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetDumpTopicPostOnboardInterval, 24*HourInSec, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetDumpTopicMaxCount, 10, 1, 0xFFFFFFFF)
	configItemSpecMap.AddBoolItem(NetDumpDownloaderPCAP, false)
	configItemSpecMap.AddBoolItem(NetDumpDownloaderHTTPWithFieldValue, false)

	return configItemSpecMap
}

// validateLogLevel - make sure the log level has one of the supported values
func validateLogLevel(level string) error {
	switch level {
	case "none", "all":
		return nil
	default:
		_, err := logrus.ParseLevel(level)
		return err
	}
}

// validateSyslogKernelLevel - Wrapper for validating syslog and kernel
// loglevels.
func validateSyslogKernelLevel(level string) error {
	_, ok := SyslogKernelLogLevelNum[level]
	if !ok {
		return fmt.Errorf("validateSyslogKernelLevel: unknown loglevel '%v'", level)
	}
	return nil
}

// blankValidator - A validator that accepts any string
func blankValidator(s string) error {
	return nil
}

// NewConfigItemValueMap - Create new instance of ConfigItemValueMap
func NewConfigItemValueMap() *ConfigItemValueMap {
	var valueMap ConfigItemValueMap
	valueMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemValue)
	valueMap.AgentSettings = make(map[string]map[AgentSettingKey]ConfigItemValue)
	return &valueMap
}

// DefaultConfigItemValueMap - converts default specmap into value map
func DefaultConfigItemValueMap() *ConfigItemValueMap {
	configMap := NewConfigItemSpecMap()
	valueMapPtr := NewConfigItemValueMap()

	for key, configItemSpec := range configMap.GlobalSettings {
		valueMapPtr.GlobalSettings[key] = configItemSpec.DefaultValue()
	}
	// By default there are no per-agent settings.
	return valueMapPtr
}

// UpdateItemValues brings in any of the source items into the ConfigItemValueMap
func (configPtr *ConfigItemValueMap) UpdateItemValues(source *ConfigItemValueMap) {

	for key, val := range source.GlobalSettings {
		configPtr.GlobalSettings[key] = val
	}

	for agentName, agentSettingMap := range source.AgentSettings {
		if _, ok := configPtr.AgentSettings[agentName]; !ok {
			configPtr.AgentSettings[agentName] = make(map[AgentSettingKey]ConfigItemValue)
		}
		for setting, value := range agentSettingMap {
			configPtr.AgentSettings[agentName][setting] = value
		}
	}
}

func agentSettingKeyFromLegacyKey(key string) string {
	components := strings.Split(key, ".")
	if len(components) < 3 {
		return ""
	}
	agentKey := components[0] + "." + strings.Join(components[2:], ".")
	return agentKey
}
