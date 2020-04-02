// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// SenderResult - Enum name for return extra sender results from SendOnAllIntf
type SenderResult uint8

// Enum of http extra status for 'rtf'
const (
	SenderStatusNone                      SenderResult = iota
	SenderStatusRemTempFail                            // http remote temporarilly failure
	SenderStatusCertMiss                               // remote signed senderCertHash we don't have
	SenderStatusSignVerifyFail                         // envelope signature verify failed
	SenderStatusAlgoFail                               // hash algorithm we don't support
	SenderStatusHashSizeError                          // senderCertHash length error
	SenderStatusCertUnknownAuthority                   // device may miss proxy certificate for MiTM
	SenderStatusCertUnknownAuthorityProxy              // device configed proxy, may miss proxy certificate for MiTM
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
	// MetricInterval global setting key
	MetricInterval GlobalSettingKey = "timer.metric.interval"
	// ResetIfCloudGoneTime global setting key
	ResetIfCloudGoneTime GlobalSettingKey = "timer.reboot.no.network"
	// FallbackIfCloudGoneTime global setting key
	FallbackIfCloudGoneTime GlobalSettingKey = "timer.update.fallback.no.network"
	// MintimeUpdateSuccess global setting key
	MintimeUpdateSuccess GlobalSettingKey = "timer.test.baseimage.update"
	// StaleConfigTime global setting key
	StaleConfigTime GlobalSettingKey = "timer.use.config.checkpoint"
	// DownloadGCTime global setting key
	DownloadGCTime GlobalSettingKey = "timer.gc.download"
	// VdiskGCTime global setting key
	VdiskGCTime GlobalSettingKey = "timer.gc.vdisk"
	// DownloadRetryTime global setting key
	DownloadRetryTime GlobalSettingKey = "timer.download.retry"
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
	// Dom0MinDiskUsagePercent global setting key
	Dom0MinDiskUsagePercent GlobalSettingKey = "storage.dom0.disk.minusage.percent"

	// Bool Items
	// UsbAccess global setting key
	UsbAccess GlobalSettingKey = "debug.enable.usb"
	// AllowAppVnc global setting key
	AllowAppVnc GlobalSettingKey = "app.allow.vnc"
	// IgnoreDiskCheckForApps global setting key
	IgnoreDiskCheckForApps GlobalSettingKey = "storage.apps.ignore.disk.check"

	// TriState Items
	// NetworkFallbackAnyEth global setting key
	NetworkFallbackAnyEth GlobalSettingKey = "network.fallback.any.eth"
	// AllowNonFreeAppImages global setting key
	AllowNonFreeAppImages GlobalSettingKey = "network.allow.wwan.app.download"
	// AllowNonFreeBaseImages global setting key
	AllowNonFreeBaseImages GlobalSettingKey = "network.allow.wwan.baseos.download"

	// String Items
	// SSHAuthorizedKeys global setting key
	SSHAuthorizedKeys GlobalSettingKey = "debug.enable.ssh"
	// DefaultLogLevel global setting key
	DefaultLogLevel GlobalSettingKey = "debug.default.loglevel"
	// DefaultRemoteLogLevel global setting key
	DefaultRemoteLogLevel GlobalSettingKey = "debug.default.remote.loglevel"
)

// AgentSettingKey - keys for per-agent settings
type AgentSettingKey string

const (
	// LogLevel agent setting key
	LogLevel AgentSettingKey = "debug.loglevel"
	// RemoteLogLevel agent setting key
	RemoteLogLevel AgentSettingKey = "debug.remote.loglevel"
)

// ConfigItemType - Defines what type of item we are storing
type ConfigItemType uint8

const (
	// ConfigItemTypeInt - for config item's who's value is an integer
	ConfigItemTypeInt ConfigItemType = iota + 1
	// ConfigItemTypeBool - for config item's who's value is a boolean
	ConfigItemTypeBool
	// ConfigItemTypeString - for config item's who's value is a string
	ConfigItemTypeString
	// ConfigItemTypeTriState - for config item's who's value is a tristate
	ConfigItemTypeTriState
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
	log.Debugf("Added int item. Key: %s, Val: %+v", key, configItem)
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
func (specMap *ConfigItemSpecMap) AddStringItem(key GlobalSettingKey, defaultString string, validator Validator) {
	err := validator(defaultString)
	if err != nil {
		defaultString = "failed validation"
		log.Fatalf("AddStringItem: key %s, default (%s) Failed "+
			"validator. err: %s", key, defaultString, err)
	}
	configItem := ConfigItemSpec{
		ItemType:        ConfigItemTypeString,
		Key:             string(key),
		StringDefault:   defaultString,
		StringValidator: validator,
	}
	specMap.GlobalSettings[key] = configItem
	log.Debugf("Added string item %s", key)
}

// AddTriStateItem - Adds tristate item to specMap
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
func (specMap *ConfigItemSpecMap) AddAgentSettingStringItem(key AgentSettingKey,
	defaultString string, validator Validator) {
	err := validator(defaultString)
	if err != nil {
		defaultString = "failed validation"
		log.Fatalf("AddAgentSettingStringItem: key %s, default (%s) Failed "+
			"validator. err: %s", key, defaultString, err)
	}
	configItem := ConfigItemSpec{
		ItemType:        ConfigItemTypeString,
		Key:             string(key),
		StringDefault:   defaultString,
		StringValidator: validator,
	}
	specMap.AgentSettings[key] = configItem
	log.Debugf("Added string item %s", key)
}

func (specMap *ConfigItemSpecMap) parseAgentItem(
	newConfigMap *ConfigItemValueMap, oldConfigMap *ConfigItemValueMap,
	key string, value string) (ConfigItemValue, error) {
	// legacy per-agent setting key debug.<agentname>.xxx
	// new per-agent setting key agent.<agentname>.debug.xxx
	log.Debugf("ParseItem: Agent or Lagecy Agent Item. key: %s, Value: %s",
		key, value)
	keyStr := key

	// Get Key and AgentName
	components := strings.Split(key, ".")
	agentName := components[1]
	if strings.HasPrefix(key, "agent") && len(components) > 2 {
		components = components[2:]
		key = strings.Join(components, ".")
	} else if strings.HasPrefix(key, "debug") && len(components) > 3 {
		key = components[0] + "." + strings.Join(components[2:], ".")
	} else {
		err := fmt.Errorf("Unable to find agent name for per-agent setting. "+
			"Key: %s", key)
		log.Errorf("***parseAgentItem: ERROR: %s", err)
		return ConfigItemValue{}, err
	}

	asKey := AgentSettingKey(key)
	itemSpec, ok := specMap.AgentSettings[asKey]
	if !ok {
		err := fmt.Errorf("Cannot find key (%s) in AgentSettings. KeyStr: %s",
			key, keyStr)
		log.Errorf("***parseAgentItem: ERROR: %s", err)
		return ConfigItemValue{}, err
	}
	val, err := itemSpec.parseValue(value)
	if err == nil {
		newConfigMap.setAgentSettingValue(agentName, asKey, val)
		log.Debugf("parseAgentItem: Successfully parsed Agent Setting. "+
			"Agent: %s, key: %s, Value: %s", agentName, key, value)
		return val, nil
	}
	// Parse Error. Get the Value from old config
	existingValue, asErr := oldConfigMap.agentConfigItemValue(agentName, asKey)
	if asErr == nil {
		newConfigMap.setAgentSettingValue(agentName, asKey, val)
		log.Errorf("***ParseItem: Can't find existing value for agent "+
			"Setting - agentName: %s, Key: %s. Using Existing Value: %+v",
			agentName, key, existingValue)
		return val, err
	}
	// No Existing Value for Agent. It will use the default value.
	log.Errorf("***ParseItem: Can't find existing value for agent "+
		"Setting - agentName: %s, Key: %s. No Existing Value Either."+
		" Use Default", agentName, key)
	return ConfigItemValue{}, err
}

// ParseItem - Parses the Key/Value pair into a ConfigItem and updates
//  newConfigMap. If there is a Parse error, it copies the corresponding value
//  from oldConfigMap
func (specMap *ConfigItemSpecMap) ParseItem(newConfigMap *ConfigItemValueMap,
	oldConfigMap *ConfigItemValueMap,
	key string, value string) (ConfigItemValue, error) {
	// legacy per-agent setting key debug.<agentname>.xxx
	// new per-agent setting key agent.<agentname>.debug.xxx
	if strings.HasPrefix(key, "agent") || specMap.isLegacyAgent(key) {
		return specMap.parseAgentItem(newConfigMap, oldConfigMap, key, value)
	}
	gsKey := GlobalSettingKey(key)
	itemSpec, ok := specMap.GlobalSettings[gsKey]
	if !ok {
		err := fmt.Errorf("ParseItem: Item is neither a global nor a "+
			"per-agent setting. Key: %s, Value: %s", key, value)
		log.Errorf("ParseItem: ERROR: %s", err)
		return ConfigItemValue{}, err
	}
	// Global Setting
	log.Debugf("ParseItem: Global Setting. key: %s, Value: %s", key, value)
	val, err := itemSpec.parseValue(value)
	if err == nil {
		newConfigMap.GlobalSettings[gsKey] = val
		log.Debugf("ParseItem: Successfully parsed Global Setting. "+
			"key: %s, Value: %s", key, value)
		return val, nil
	}
	// Parse Error. Get the Value from old config
	existingValue, ok := oldConfigMap.GlobalSettings[gsKey]
	if !ok {
		existingValue = itemSpec.DefaultValue()
		log.Errorf("**ParseItem: Can't find existing value for Key: %s"+
			". Using default value ( %+v)", key, existingValue)
	}
	newConfigMap.GlobalSettings[gsKey] = val
	log.Error("ParseItem: Error in parsing Item. Replacing it with "+
		"existing Value. key: %s, value: %s, Existing Value: %+v. "+
		"Err: %s", key, value, existingValue, err)
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
	log.Fatalf("globalConfigItemValue - Invalid key: %s", key)
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
		log.Fatalf("Agent setting is not of type string. agent-name %s, agentSettingKey %s",
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
		log.Fatalf("***Key(%s) is of Type(%d) NOT Int", key, val.ItemType)
		return 0
	}
}

// GlobalValueString - Gets a string global setting value
func (configPtr *ConfigItemValueMap) GlobalValueString(key GlobalSettingKey) string {
	val := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeString {
		return val.StrValue
	} else {
		log.Fatalf("***Key(%s) is of Type(%d) NOT String", key, val.ItemType)
		return ""
	}
}

// GlobalValueTriState - Gets a tristate global setting value
func (configPtr *ConfigItemValueMap) GlobalValueTriState(key GlobalSettingKey) TriState {
	val := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeTriState {
		return val.TriStateValue
	} else {
		log.Fatalf("***Key(%s) is of Type(%d) NOT TriState", key, val.ItemType)
		return TS_NONE
	}
}

// GlobalValueBool - Gets a boolean global setting value
func (configPtr *ConfigItemValueMap) GlobalValueBool(key GlobalSettingKey) bool {
	val := configPtr.globalConfigItemValue(key)
	if val.ItemType == ConfigItemTypeBool {
		return val.BoolValue
	} else {
		log.Fatalf("***Key(%s) is of Type(%d) NOT Bool", key, val.ItemType)
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
	var configItemSpecMap ConfigItemSpecMap
	configItemSpecMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	configItemSpecMap.AgentSettings = make(map[AgentSettingKey]ConfigItemSpec)

	configItemSpecMap.AddIntItem(ConfigInterval, 60, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(MetricInterval, 60, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(ResetIfCloudGoneTime, 7*24*3600, 120, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(FallbackIfCloudGoneTime, 300, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(MintimeUpdateSuccess, 600, 30, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(StaleConfigTime, 600, 0, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(DownloadGCTime, 600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(VdiskGCTime, 3600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(DownloadRetryTime, 600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(DomainBootRetryTime, 600, 10, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkGeoRedoTime, 3600, 60, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkGeoRetryTime, 600, 5, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestDuration, 30, 10, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestInterval, 300, 300, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestBetterInterval, 0, 0, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkTestTimeout, 15, 0, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(NetworkSendTimeout, 120, 0, 0xFFFFFFFF)
	configItemSpecMap.AddIntItem(Dom0MinDiskUsagePercent, 20, 20, 0xFFFFFFFF)

	// Add Bool Items
	configItemSpecMap.AddBoolItem(UsbAccess, true)
	configItemSpecMap.AddBoolItem(AllowAppVnc, false)
	configItemSpecMap.AddBoolItem(IgnoreDiskCheckForApps, false)

	// Add TriState Items
	configItemSpecMap.AddTriStateItem(NetworkFallbackAnyEth, TS_ENABLED)
	configItemSpecMap.AddTriStateItem(AllowNonFreeAppImages, TS_ENABLED)
	configItemSpecMap.AddTriStateItem(AllowNonFreeBaseImages, TS_ENABLED)

	// Add String Items
	configItemSpecMap.AddStringItem(SSHAuthorizedKeys, "", blankValidator)
	configItemSpecMap.AddStringItem(DefaultLogLevel, "info", parseLevel)
	configItemSpecMap.AddStringItem(DefaultRemoteLogLevel, "info", parseLevel)

	configItemSpecMap.AddAgentSettingStringItem(LogLevel, "info", parseLevel)
	configItemSpecMap.AddAgentSettingStringItem(RemoteLogLevel, "info", parseLevel)

	return configItemSpecMap
}

// parseLevel - Wrapper that ignores the 'Level' output of the log.ParseLevel function
func parseLevel(level string) error {
	_, err := log.ParseLevel(level)
	return err
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

func agentSettingKeyFromLegacyKey(key string) string {
	components := strings.Split(key, ".")
	if len(components) < 3 {
		return ""
	}
	agentKey := components[0] + "." + strings.Join(components[2:], ".")
	return agentKey
}

func (specMap ConfigItemSpecMap) isLegacyAgent(key string) bool {
	if !strings.HasPrefix(key, "debug") {
		return false
	}
	agentKey := agentSettingKeyFromLegacyKey(key)
	log.Debugf("isLegacyAgent: agentKey %s", agentKey)
	_, ok := specMap.AgentSettings[AgentSettingKey(agentKey)]

	if !ok {
		log.Debugf("isLegacyAgent: Key (%s) Not Found. specMap.AgentSettings: %+v",
			agentKey, specMap.AgentSettings)
	}
	return ok
}

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

	// These settings control how the EVE microservices
	// will use free and non-free (e.g., WWAN) ports for image downloads.
	AllowNonFreeAppImages  TriState // For app images
	AllowNonFreeBaseImages TriState // For baseos images

	// Dom0MinDiskUsagePercent - Percentage of available storage reserved for
	// dom0. The rest is available for Apps.
	Dom0MinDiskUsagePercent uint32
	IgnoreDiskCheckForApps  bool

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

	Dom0MinDiskUsagePercent: 20,
	IgnoreDiskCheckForApps:  false,
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
	if newgc.Dom0MinDiskUsagePercent < GlobalConfigMinimums.Dom0MinDiskUsagePercent {
		log.Warnf("Enforce minimum Dom0MinDiskUsagePercent received %d; using %d",
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
	newConfig.SetGlobalValueInt(DownloadGCTime, config.DownloadGCTime)
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
