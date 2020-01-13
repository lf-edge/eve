// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
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
//  the key is not found.
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
	// Set Int Values
	gs.setItemValueInt("timer.config.interval", gc.GlobalValueInt(ConfigInterval))
	gs.setItemValueInt("timer.metric.interval", gc.GlobalValueInt(MetricInterval))
	gs.setItemValueInt("timer.send.timeout", gc.GlobalValueInt(NetworkSendTimeout))
	gs.setItemValueInt("timer.reboot.no.network", gc.GlobalValueInt(ResetIfCloudGoneTime))
	gs.setItemValueInt("timer.update.fallback.no.network", gc.GlobalValueInt(FallbackIfCloudGoneTime))
	gs.setItemValueInt("timer.test.baseimage.update", gc.GlobalValueInt(MintimeUpdateSuccess))
	gs.setItemValueInt("timer.port.georedo", gc.GlobalValueInt(NetworkGeoRedoTime))
	gs.setItemValueInt("timer.port.georetry", gc.GlobalValueInt(NetworkGeoRetryTime))
	gs.setItemValueInt("timer.port.testduration", gc.GlobalValueInt(NetworkTestDuration))
	gs.setItemValueInt("timer.port.testinterval", gc.GlobalValueInt(NetworkTestInterval))
	gs.setItemValueInt("timer.port.timeout", gc.GlobalValueInt(NetworkTestTimeout))
	gs.setItemValueInt("timer.port.testbetterinterval", gc.GlobalValueInt(NetworkTestBetterInterval))
	gs.setItemValueInt("timer.use.config.checkpoint", gc.GlobalValueInt(StaleConfigTime))
	gs.setItemValueInt("timer.gc.download", gc.GlobalValueInt(DownloadGCTime))
	gs.setItemValueInt("timer.gc.vdisk", gc.GlobalValueInt(VdiskGCTime))
	gs.setItemValueInt("timer.gc.rkt.graceperiod", gc.GlobalValueInt(RktGCGracePeriod))
	gs.setItemValueInt("timer.download.retry", gc.GlobalValueInt(DownloadRetryTime))
	gs.setItemValueInt("timer.boot.retry", gc.GlobalValueInt(DomainBootRetryTime))
	gs.setItemValueInt("storage.dom0.disk.minusage.percent", gc.GlobalValueInt(Dom0MinDiskUsagePercent))

	// Set TriState Values
	gs.setItemValueTriState("network.fallback.any.eth", gc.GlobalValueTriState(NetworkFallbackAnyEth))
	gs.setItemValueTriState("network.allow.wwan.app.download", gc.GlobalValueTriState(AllowNonFreeAppImages))
	gs.setItemValueTriState("network.allow.wwan.baseos.download", gc.GlobalValueTriState(AllowNonFreeBaseImages))

	// Set Bool
	gs.setItemValueBool("debug.enable.usb", gc.GlobalValueBool(UsbAccess))
	gs.setItemValueBool("debug.enable.ssh", gc.GlobalValueBool(SSHAccess))
	gs.setItemValueBool("app.allow.vnc", gc.GlobalValueBool(AllowAppVnc))

	// Set String Values
	gs.setItemValue("debug.default.loglevel", gc.GlobalValueString(DefaultLogLevel))
	gs.setItemValue("debug.default.remote.loglevel", gc.GlobalValueString(DefaultRemoteLogLevel))

	for agentName := range gc.AgentSettings {
		gs.setItemValue("debug."+agentName+".loglevel", gc.AgentSettingStringValue(agentName, LogLevel))
		gs.setItemValue("debug."+agentName+".remote.loglevel", gc.AgentSettingStringValue(agentName, RemoteLogLevel))
	}
}

// GlobalConfig is used for log levels and timer values which are preserved
// across reboots and baseimage-updates.

// Agents subscribe to this info to get at least the log levels
// A value of zero means we should use the default
// All times are in seconds.

// GlobalSettingKey - Constants of all global setting keys
type GlobalSettingKey string

const (
	// Constants for all
	// global config global setting items
	ConfigInterval            GlobalSettingKey = "timer.config.interval"
	MetricInterval            GlobalSettingKey = "timer.metric.interval"
	ResetIfCloudGoneTime      GlobalSettingKey = "timer.reboot.no.network"
	FallbackIfCloudGoneTime   GlobalSettingKey = "timer.update.fallback.no.network"
	MintimeUpdateSuccess      GlobalSettingKey = "timer.test.baseimage.update"
	StaleConfigTime           GlobalSettingKey = "timer.use.config.checkpoint"
	DownloadGCTime            GlobalSettingKey = "timer.gc.download"
	VdiskGCTime               GlobalSettingKey = "timer.gc.vdisk"
	RktGCGracePeriod          GlobalSettingKey = "timer.gc.rkt.graceperiod"
	DownloadRetryTime         GlobalSettingKey = "timer.download.retry"
	DomainBootRetryTime       GlobalSettingKey = "timer.boot.retry"
	NetworkGeoRedoTime        GlobalSettingKey = "timer.port.georedo"
	NetworkGeoRetryTime       GlobalSettingKey = "timer.port.georetry"
	NetworkTestDuration       GlobalSettingKey = "timer.port.testduration"
	NetworkTestInterval       GlobalSettingKey = "timer.port.testinterval"
	NetworkTestBetterInterval GlobalSettingKey = "timer.port.testbetterinterval"
	NetworkTestTimeout        GlobalSettingKey = "timer.port.timeout"
	NetworkSendTimeout        GlobalSettingKey = "timer.send.timeout"
	UsbAccess                 GlobalSettingKey = "debug.enable.usb"
	NetworkFallbackAnyEth     GlobalSettingKey = "network.fallback.any.eth"
	SSHAccess                 GlobalSettingKey = "debug.enable.ssh"
	SSHAuthorizedKeys         GlobalSettingKey = "debug.enable.ssh"
	AllowAppVnc               GlobalSettingKey = "app.allow.vnc"
	AllowNonFreeAppImages     GlobalSettingKey = "network.allow.wwan.app.download"
	AllowNonFreeBaseImages    GlobalSettingKey = "network.allow.wwan.baseos.download"
	Dom0MinDiskUsagePercent   GlobalSettingKey = "storage.dom0.disk.minusage.percent"
	IgnoreDiskCheckForApps    GlobalSettingKey = "storage.apps.ignore.disk.check"
	DefaultLogLevel           GlobalSettingKey = "debug.default.loglevel"
	DefaultRemoteLogLevel     GlobalSettingKey = "debug.default.remote.loglevel"
)

// AgentSettingKey - keys for per-agent settings
type AgentSettingKey string

const (
	// Define all
	// per-agent settings
	LogLevel       AgentSettingKey = "debug.loglevel"
	RemoteLogLevel AgentSettingKey = "debug.remote.loglevel"
)

// ConfigItemType - Defines what type of item we are storing
type ConfigItemType uint8

const (
	// Define all
	// item types
	ConfigItemTypeInt ConfigItemType = iota + 1
	ConfigItemTypeBool
	ConfigItemTypeString
	ConfigItemTypeTriState
)

// ConfigItemSpec - Defines what a specification for a configuration should be
type ConfigItemSpec struct {
	Key      string
	ItemType ConfigItemType

	IntMin     uint32
	IntMax     uint32
	IntDefault uint32

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
		item.boolValue = configSpec.BoolDefault
	case ConfigItemTypeInt:
		item.intValue = configSpec.IntDefault
	case ConfigItemTypeString:
		item.stringValue = configSpec.StringDefault
	case ConfigItemTypeTriState:
		item.triStateValue = configSpec.TriStateDefault
	}
	return item
}

// ConfigItemSpecMap - Map of all specifications
type ConfigItemSpecMap struct {
	// GlobalSettings - Map Key: GlobalSettingKey, ConfigItemValue.Key: GlobalSettingKey
	GlobalSettings map[GlobalSettingKey]ConfigItemSpec
	// AgentSettingKey - Map Key: AgentSettingKey, ConfigItemValue.Key: AgentSettingKey
	AgentSettings map[AgentSettingKey]ConfigItemSpec
}

// AddIntItem - Adds integer item to specMap
func (specMap *ConfigItemSpecMap) AddIntItem(key GlobalSettingKey, defaultInt uint32, min uint32, max uint32) {
	if defaultInt < min || defaultInt > max {
		log.Fatalf("Adding int item %s failed. Value does not meet given min/max criteria", key)
	}
	configItem := ConfigItemSpec{
		ItemType:   ConfigItemTypeInt,
		Key:        string(key),
		IntDefault: defaultInt,
		IntMin:     min,
		IntMax:     max,
	}
	specMap.GlobalSettings[key] = configItem
	log.Debugf("Added int item %s", key)
}

// AddBoolItem - Adds boolean item to specMap
func (specMap *ConfigItemSpecMap) AddBoolItem(key GlobalSettingKey, defaultBool bool) {
	configItem := ConfigItemSpec{
		ItemType:    ConfigItemTypeBool,
		Key:         string(key),
		BoolDefault: defaultBool,
	}
	specMap.GlobalSettings[key] = configItem
	log.Debugf("Added bool item %s", key)
}

// AddStringItem - Adds string item to specMap
func (specMap *ConfigItemSpecMap) AddStringItem(key GlobalSettingKey, defaultString string) {
	configItem := ConfigItemSpec{
		ItemType:      ConfigItemTypeString,
		Key:           string(key),
		StringDefault: defaultString,
	}
	specMap.GlobalSettings[key] = configItem
	log.Debugf("Added string item %s", key)
}

func (specMap *ConfigItemSpecMap) AddTriStateItem(key GlobalSettingKey, defaultTriState TriState) {
	configItem := ConfigItemSpec{
		Key:             string(key),
		ItemType:        ConfigItemTypeTriState,
		TriStateDefault: defaultTriState,
	}
	specMap.GlobalSettings[key] = configItem
	log.Debugf("Added tristate item %s", key)
}

// AddAgentSettingStringItem - Adds string item for a per-agent setting
func (specMap *ConfigItemSpecMap) AddAgentSettingStringItem(key AgentSettingKey, defaultString string) {
	configItem := ConfigItemSpec{
		ItemType:      ConfigItemTypeString,
		Key:           string(key),
		StringDefault: defaultString,
	}
	specMap.AgentSettings[key] = configItem
	log.Debugf("Added string item %s", key)
}

// ParseItem - Uses a ConfigItem to create a globalconfig
func (specMap *ConfigItemSpecMap) ParseItem(configMap *ConfigItemValueMap, value string, key string) error {
	// legacy per-agent setting key debug.<agentname>.xxx
	// new per-agent setting key agent.<agentname>.debug.xxx
	var itemSpec ConfigItemSpec
	agentSetting := false
	globalSetting := false
	var agentName string
	components := strings.Split(key, ".")
	if strings.HasPrefix(key, "agent") || specMap.isLegacyAgent(key) {
		agentName = components[1]
		if strings.HasPrefix(key, "agent") && len(components) > 2 {
			components = components[2:]
		} else if strings.HasPrefix(key, "debug") && len(components) > 2 {
			components[1] = ""
		} else {
			return fmt.Errorf("Unable to find agent name for per-agent setting. Key: %s", key)
		}
		key = strings.Join(components, ".")
		agentSetting = true
	} else if _, ok := specMap.GlobalSettings[GlobalSettingKey(key)]; ok {
		globalSetting = true
	} else {
		return fmt.Errorf("Item is neither a global nor a per-agent setting. Key: %s", key)
	}
	if agentSetting {
		itemSpec = specMap.AgentSettings[AgentSettingKey(key)]
		val, err := itemSpec.parseValue(value)
		if err == nil {
			agentMap, ok := configMap.AgentSettings[agentName]
			if !ok {
				agentMap = make(map[AgentSettingKey]ConfigItemValue)
			}
			agentMap[AgentSettingKey(key)] = val
			configMap.AgentSettings[agentName] = agentMap
		} else {
			return err
		}
	} else if globalSetting {
		itemSpec = specMap.GlobalSettings[GlobalSettingKey(key)]
		val, err := itemSpec.parseValue(value)
		if err == nil {
			configMap.GlobalSettings[GlobalSettingKey(key)] = val
		} else {
			return err
		}
	}
	return nil
}

// ConfigItemValue - Stores the value of a setting
type ConfigItemValue struct {
	Key      string
	ItemType ConfigItemType

	intValue      uint32
	stringValue   string
	boolValue     bool
	triStateValue TriState
}

// ConfigItemValueMap - Maps both agent and global settings
type ConfigItemValueMap struct {
	// GlobalSettings - Map Key: GlobalSettingKey, ConfigItemValue.Key: GlobalSettingKey
	GlobalSettings map[GlobalSettingKey]ConfigItemValue
	// AgentSettings - Map Outer Key: agentName, Map Inner Key: AgentSettingKey ConfigItemValue.Key: AgentSettingKey
	AgentSettings map[string]map[AgentSettingKey]ConfigItemValue
}

func (configPtr *ConfigItemValueMap) globalConfigItemValue(key GlobalSettingKey) (ConfigItemValue, error) {
	specMapPtr := NewConfigItemSpecMap()
	val, okVal := configPtr.GlobalSettings[key]
	spec, _ := specMapPtr.GlobalSettings[key]
	if okVal {
		return val, nil
	} else {
		return spec.DefaultValue(), fmt.Errorf("Global setting not found. Default value was returned. Key %s", key)
	}
}

func (configPtr *ConfigItemValueMap) agentConfigItemValue(agentName string, key AgentSettingKey) (ConfigItemValue, error) {
	agent, ok := configPtr.AgentSettings[agentName]
	var blankValue = ConfigItemValue{}
	if ok {
		val, ok := agent[key]
		if ok {
			return val, nil
		} else {
			return blankValue, fmt.Errorf("Failed to find %s settings for %s", string(key), agentName)
		}
	} else {
		return blankValue, fmt.Errorf("Failed to find any per-agent settings for agent %s", agentName)
	}
}

// AgentSettingStringValue - Gets the value of a per-agent setting for a certain agentname and per-agent key
func (configPtr *ConfigItemValueMap) AgentSettingStringValue(agentName string, agentSettingKey AgentSettingKey) string {
	val, err := configPtr.agentConfigItemValue(agentName, agentSettingKey)
	if err != nil {
		return ""
	}
	if val.ItemType != ConfigItemTypeString {
		log.Fatalf("Agent setting is not of type string. agent-name %s, agentSettingKey %s",
			agentName, string(agentSettingKey))
	}
	return val.stringValue
}

// GlobalValueInt - Gets a int global setting value
func (configPtr *ConfigItemValueMap) GlobalValueInt(key GlobalSettingKey) uint32 {
	val, err := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeInt {
		return val.intValue
	} else {
		log.Fatalf("Failed to find bool value for key %s, err %s", key, err)
		return 0
	}
}

// GlobalValueInt - Gets a string global setting value
func (configPtr *ConfigItemValueMap) GlobalValueString(key GlobalSettingKey) string {
	val, err := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeString {
		return val.stringValue
	} else {
		log.Fatalf("Failed to find string value for key %s, err %s", key, err)
		return ""
	}
}

// GlobalValueInt - Gets a tristate global setting value
func (configPtr *ConfigItemValueMap) GlobalValueTriState(key GlobalSettingKey) TriState {
	val, err := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeTriState {
		return val.triStateValue
	} else {
		log.Fatalf("Failed to find tristate value for key %s, err %s", key, err)
		return TS_NONE
	}
}

// GlobalValueInt - Gets a boolean global setting value
func (configPtr *ConfigItemValueMap) GlobalValueBool(key GlobalSettingKey) bool {
	val, err := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeBool {
		return val.boolValue
	} else {
		log.Fatalf("Failed to find bool value for key %s, err %s", key, err)
		return false
	}
}

// SetAgentSettingStringValue - Sets an agent value for a certain key and agent name
func (configPtr *ConfigItemValueMap) SetAgentSettingStringValue(key AgentSettingKey, agentName string, newValue string) error {
	configItemValue := ConfigItemValue{
		Key:         string(key),
		ItemType:    ConfigItemTypeString,
		stringValue: newValue,
	}
	settingMap, ok := configPtr.AgentSettings[agentName]
	if !ok {
		// Agent Map not yet set. Create the map
		settingMap := make(map[AgentSettingKey]ConfigItemValue)
		configPtr.AgentSettings[agentName] = settingMap
	}
	settingMap[key] = configItemValue
	return nil
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
				value.intValue = val
			}
		} else {
			value.intValue = configSpec.IntDefault
			retErr = err
		}
	} else if configSpec.ItemType == ConfigItemTypeTriState {
		newTs, err := ParseTriState(itemValue)
		if err == nil {
			value.triStateValue = newTs
		} else {
			value.triStateValue = configSpec.TriStateDefault
			retErr = err
		}
	} else if configSpec.ItemType == ConfigItemTypeBool {
		newBool, err := strconv.ParseBool(itemValue)
		if err == nil {
			value.boolValue = newBool
		} else {
			value.boolValue = configSpec.BoolDefault
			retErr = err
		}
	} else if configSpec.ItemType == ConfigItemTypeString {
		value.stringValue = itemValue
	}
	return value, retErr
}

// NewConfigItemSpecMap - Creates a specmap based on default values
func NewConfigItemSpecMap() ConfigItemSpecMap {
	var configItemSpecMap ConfigItemSpecMap
	configItemSpecMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	configItemSpecMap.AgentSettings = make(map[AgentSettingKey]ConfigItemSpec)
	configItemSpecMap.AddIntItem(ConfigInterval, 60, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(MetricInterval, 60, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkSendTimeout, 0, 0, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(ResetIfCloudGoneTime, 7*24*3600, 120, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(FallbackIfCloudGoneTime, 300, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(MintimeUpdateSuccess, 60, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkGeoRedoTime, 3600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkGeoRetryTime, 600, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestDuration, 30, 10, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestInterval, 300, 300, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestTimeout, 15, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestBetterInterval, 0, 0, 0xFFFFFFFF)
	configItemSpecMap.AddTriStateItem("network.fallback.any.eth", TS_ENABLED)
	configItemSpecMap.AddTriStateItem("network.allow.wwan.app.download", TS_ENABLED)
	configItemSpecMap.AddTriStateItem("network.allow.wwan.baseos.download", TS_ENABLED)
	configItemSpecMap.AddBoolItem("debug.enable.usb", true)
	configItemSpecMap.AddBoolItem("debug.enable.usb", true)
	configItemSpecMap.AddBoolItem("app.allow.vnc", false)
	configItemSpecMap.AddIntItem("app.allow.vnc", 60, 5, 0xFFFFFFFF)               //UNSURE OF VALUES
	configItemSpecMap.AddIntItem("timer.use.config.checkpoint", 60, 5, 0xFFFFFFFF) //UNSURE OF VALUES
	configItemSpecMap.AddIntItem("timer.gc.download", 600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem("timer.gc.vdisk", 3600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem("timer.gc.rkt.graceperiod", 3600, 600, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem("timer.download.retry", 600, 0, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem("timer.boot.retry", 600, 10, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem("network.allow.wwan.app.download", 0, 0, 0xFFFFFFFF)    //UNSURE OF VALUES
	configItemSpecMap.AddIntItem("network.allow.wwan.baseos.download", 0, 0, 0xFFFFFFFF) //UNSURE OF VALUES
	configItemSpecMap.AddStringItem(DefaultLogLevel, "info")
	configItemSpecMap.AddStringItem(DefaultRemoteLogLevel, "info")
	configItemSpecMap.AddIntItem("storage.dom0.disk.minusage.percent", 20, 20, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem("storage.apps.ignore.disk.check", 0, 5, 80)
	return configItemSpecMap
}

// DefaultConfigItemValueMap - converts default specmap into value map
func DefaultConfigItemValueMap() *ConfigItemValueMap {
	configMap := NewConfigItemSpecMap()
	var valueMap ConfigItemValueMap
	for key, configItemSpec := range configMap.GlobalSettings {
		valueMap.GlobalSettings[key] = configItemSpec.DefaultValue()
	}
	// By default there are no per-agent settings.
	return &valueMap
}

func (specMap ConfigItemSpecMap) isLegacyAgent(key string) bool {
	if !strings.HasPrefix(key, "debug") {
		return false
	}
	components := strings.Split(key, ".")
	if len(components) < 3 {
		return false
	}
	agentKey := components[0] + strings.Join(components[2:], "")
	_, ok := specMap.AgentSettings[AgentSettingKey(agentKey)]
	return ok
}
