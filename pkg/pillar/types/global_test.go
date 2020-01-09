package types

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/lf-edge/eve/api/go/config"
	"github.com/stretchr/testify/assert"
)

func TestDefaultValue(t *testing.T) {
	specMap := NewConfigItemSpecMap()
	for _, item := range specMap.GlobalSettings {
		t.Logf("Testing if defualt value and spec matches for %s", item.Key)
		defaultValue := item.DefaultValue()
		if item.ItemType == ConfigItemTypeInt {
			assert.Equal(t, item.IntDefault, defaultValue.IntValue)
		} else if item.ItemType == ConfigItemTypeBool {
			assert.Equal(t, item.BoolDefault, defaultValue.BoolValue)
		} else if item.ItemType == ConfigItemTypeTriState {
			assert.Equal(t, item.TriStateDefault, defaultValue.TriStateValue)
		} else if item.ItemType == ConfigItemTypeString {
			assert.Equal(t, item.StringDefault, defaultValue.StrValue)
		}
	}

}

func TestAddIntItem(t *testing.T) {
	specMap := ConfigItemSpecMap{}
	specMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	testMatrix := map[string]struct {
		key         GlobalSettingKey
		defaultInt  uint32
		min         uint32
		max         uint32
		expectedVal uint32
	}{
		"Within Constraints": {
			key:         MintimeUpdateSuccess,
			defaultInt:  90,
			min:         0,
			max:         150,
			expectedVal: 90,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		(&specMap).AddIntItem(test.key, test.defaultInt, test.min, test.max)
		assert.Equal(t, test.expectedVal, specMap.GlobalSettings[test.key].IntDefault)
	}
}
func TestAddBoolItem(t *testing.T) {
	specMap := ConfigItemSpecMap{}
	specMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	testMatrix := map[string]struct {
		key         GlobalSettingKey
		defaultBool bool
		expectedVal bool
	}{
		"Test True": {
			key:         MintimeUpdateSuccess,
			defaultBool: true,
			expectedVal: true,
		},
		"Test False": {
			key:         MetricInterval,
			defaultBool: false,
			expectedVal: false,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		(&specMap).AddBoolItem(test.key, test.defaultBool)
		assert.Equal(t, test.expectedVal, specMap.GlobalSettings[test.key].BoolDefault)
	}
}
func TestAddTriStateItem(t *testing.T) {
	specMap := ConfigItemSpecMap{}
	specMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	testMatrix := map[string]struct {
		key             GlobalSettingKey
		defaultTristate TriState
		expectedVal     TriState
	}{
		"Test None": {
			key:             ConfigInterval,
			defaultTristate: TS_NONE,
			expectedVal:     TS_NONE,
		},
		"Test Enabled": {
			key:             MetricInterval,
			defaultTristate: TS_ENABLED,
			expectedVal:     TS_ENABLED,
		},
		"Test Disabled": {
			key:             MintimeUpdateSuccess,
			defaultTristate: TS_DISABLED,
			expectedVal:     TS_DISABLED,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		(&specMap).AddTriStateItem(test.key, test.defaultTristate)
		assert.Equal(t, test.expectedVal, specMap.GlobalSettings[test.key].TriStateDefault)
	}
}
func TestAddStringItem(t *testing.T) {
	specMap := ConfigItemSpecMap{}
	specMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	testMatrix := map[string]struct {
		key           GlobalSettingKey
		defaultString string
		expectedVal   string
	}{
		"Test None": {
			key:           ConfigInterval,
			defaultString: "info",
			expectedVal:   "info",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		(&specMap).AddStringItem(test.key, test.defaultString, parseLevel)
		assert.Equal(t, test.expectedVal, specMap.GlobalSettings[test.key].StringDefault)
	}
}
func TestParseGlobalItem(t *testing.T) {
	// log.SetLevel(log.DebugLevel)
	specMap := NewConfigItemSpecMap()
	oldGlobalConfig := DefaultConfigItemValueMap()
	newGlobalConfig := DefaultConfigItemValueMap()
	testMatrix := map[string]struct {
		item                config.ConfigItem
		itemType            ConfigItemType
		expectError         bool
		expectedStringValue string
		expectedIntValue    string
	}{
		"Global String Setting": {
			item: config.ConfigItem{
				Key:   string(DefaultLogLevel),
				Value: "warn",
			},
			itemType: ConfigItemTypeString,
		},
		"Global Int Setting": {
			item: config.ConfigItem{
				Key:   string(ConfigInterval),
				Value: "10",
			},
			itemType: ConfigItemTypeInt,
		},
		"Global Bool Setting": {
			item: config.ConfigItem{
				Key:   string(UsbAccess),
				Value: "false",
			},
			itemType: ConfigItemTypeBool,
		},
		"Global Tristate Setting": {
			item: config.ConfigItem{
				Key:   string(NetworkFallbackAnyEth),
				Value: "none",
			},
			itemType: ConfigItemTypeTriState,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s, test: %+v", testname, test)
		_, err := specMap.ParseItem(newGlobalConfig, oldGlobalConfig,
			test.item.Key, test.item.Value)
		gsKey := GlobalSettingKey(test.item.Key)
		if test.expectError {
			failureStr := fmt.Sprintf("Expecting Error, Didn't get one. "+
				"testname: %s, test: %+v", testname, test)
			assert.NotEqual(t, err, nil, failureStr)
		} else {
			failureStr := fmt.Sprintf("Unexpected Error. testname: %s, test: %+v",
				testname, test)
			assert.Equal(t, err, nil, failureStr)
		}
		if test.itemType == ConfigItemTypeString && err == nil {
			assert.Equal(t, test.item.Value, newGlobalConfig.GlobalValueString(gsKey))
		} else if test.itemType == ConfigItemTypeInt && err == nil {
			intVal, _ := strconv.Atoi(test.item.Value)
			assert.Equal(t, uint32(intVal), newGlobalConfig.GlobalValueInt(gsKey))
		} else if test.itemType == ConfigItemTypeBool && err == nil {
			boolVal, _ := strconv.ParseBool(test.item.Value)
			assert.Equal(t, boolVal, newGlobalConfig.GlobalValueBool(gsKey))
		} else if test.itemType == ConfigItemTypeTriState && err == nil {
			tsVal, _ := ParseTriState(test.item.Value)
			assert.Equal(t, tsVal, newGlobalConfig.GlobalValueTriState(gsKey))
		}
	}
}
func TestParseAgentItem(t *testing.T) {
	// log.SetLevel(log.DebugLevel)
	specMap := ConfigItemSpecMap{}
	specMap.AgentSettings = make(map[AgentSettingKey]ConfigItemSpec)
	specMap.AgentSettings[LogLevel] = ConfigItemSpec{
		ItemType:        ConfigItemTypeString,
		StringValidator: parseLevel,
	}
	specMap.AgentSettings[RemoteLogLevel] = ConfigItemSpec{
		ItemType:        ConfigItemTypeString,
		StringValidator: parseLevel,
	}
	globalConfig := ConfigItemValueMap{}
	globalConfig.AgentSettings = make(map[string]map[AgentSettingKey]ConfigItemValue)
	testMatrix := map[string]struct {
		item     config.ConfigItem
		logLevel AgentSettingKey
	}{
		"Agent Setting": {
			logLevel: LogLevel,
			item: config.ConfigItem{
				Key:   "agent.zedagent.debug.loglevel",
				Value: "info",
			},
		},
		"Agent Legacy Setting": {
			logLevel: LogLevel,
			item: config.ConfigItem{
				Key:   "debug.zedagent.loglevel",
				Value: "info",
			},
		},
		"Agent Setting Remote": {
			logLevel: RemoteLogLevel,
			item: config.ConfigItem{
				Key:   "agent.zedagent.debug.remote.loglevel",
				Value: "info",
			},
		},
		"Agent Legacy Remote Setting": {
			logLevel: RemoteLogLevel,
			item: config.ConfigItem{
				Key:   "debug.zedagent.remote.loglevel",
				Value: "info",
			},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s - key:%s, Value: %s",
			testname, test.item.Key, test.item.Value)
		newGlobalConfig := DefaultConfigItemValueMap()
		_, err := specMap.ParseItem(newGlobalConfig, &globalConfig,
			test.item.Key, test.item.Value)
		if err == nil {
			assert.Equal(t, "info", newGlobalConfig.AgentSettingStringValue(
				"zedagent", test.logLevel))
		}
	}
}
func TestAgentSettingStringValue(t *testing.T) {
	valueMap := DefaultConfigItemValueMap()
	valueMap.SetAgentSettingStringValue("zedagent", LogLevel, "info")
	valueMap.SetAgentSettingStringValue("zedagent", RemoteLogLevel, "info")
	assert.Equal(t, "info", valueMap.AgentSettingStringValue("zedagent", LogLevel))
	assert.Equal(t, "info", valueMap.AgentSettingStringValue(
		"zedagent", RemoteLogLevel))

}
func TestGlobalValue(t *testing.T) {
	valueMap := DefaultConfigItemValueMap()
	for key, val := range valueMap.GlobalSettings {
		if val.ItemType == ConfigItemTypeInt {
			assert.Equal(t, valueMap.GlobalSettings[key].IntValue, valueMap.GlobalValueInt(key))
		} else if val.ItemType == ConfigItemTypeBool {
			assert.Equal(t, valueMap.GlobalSettings[key].BoolValue, valueMap.GlobalValueBool(key))
		} else if val.ItemType == ConfigItemTypeTriState {
			assert.Equal(t, valueMap.GlobalSettings[key].TriStateValue, valueMap.GlobalValueTriState(key))
		} else if val.ItemType == ConfigItemTypeString {
			assert.Equal(t, valueMap.GlobalSettings[key].StrValue, valueMap.GlobalValueString(key))
		}
	}
}

func TestDelAgentValue(t *testing.T) {
	valueMap := DefaultConfigItemValueMap()
	valueMap.SetAgentSettingStringValue("zedagent", LogLevel, "info")
	valueMap.SetAgentSettingStringValue("zedagent", RemoteLogLevel, "info")
	valueMap.DelAgentValue(LogLevel, "zedagent")
	valueMap.DelAgentValue(RemoteLogLevel, "zedagent")
	assert.Equal(t, "", valueMap.AgentSettingStringValue("zedagent", LogLevel))
	assert.Equal(t, "", valueMap.AgentSettingStringValue("zedagent", RemoteLogLevel))
}
func TestSetGlobalValue(t *testing.T) {
	valueMap := DefaultConfigItemValueMap()
	valueMap.SetGlobalValueInt(ConfigInterval, uint32(10))
	valueMap.SetGlobalValueBool(UsbAccess, true)
	valueMap.SetGlobalValueTriState(FallbackIfCloudGoneTime, TS_DISABLED)
	valueMap.SetGlobalValueString(SSHAuthorizedKeys, "hola amigo")
	assert.Equal(t, uint32(10), valueMap.GlobalValueInt(ConfigInterval))
	assert.Equal(t, true, valueMap.GlobalValueBool(UsbAccess))
	assert.Equal(t, TS_DISABLED, valueMap.GlobalValueTriState(FallbackIfCloudGoneTime))
	assert.Equal(t, "hola amigo", valueMap.GlobalValueString(SSHAuthorizedKeys))
}
