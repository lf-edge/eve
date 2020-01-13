package types

import (
	"github.com/lf-edge/eve/api/go/config"
	"github.com/stretchr/testify/assert"

	//"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseGlobalItem(t *testing.T) {
	specMap := ConfigItemSpecMap{}
	specMap.GlobalSettings = make(map[GlobalSettingKey]ConfigItemSpec)
	specMap.GlobalSettings[ConfigInterval] = ConfigItemSpec{
		ItemType: ConfigItemTypeString,
	}
	specMap.GlobalSettings[MetricInterval] = ConfigItemSpec{
		ItemType: ConfigItemTypeInt,
	}
	specMap.GlobalSettings[MintimeUpdateSuccess] = ConfigItemSpec{
		ItemType: ConfigItemTypeBool,
	}
	specMap.GlobalSettings[DefaultLogLevel] = ConfigItemSpec{
		ItemType: ConfigItemTypeTriState,
	}
	globalConfig := ConfigItemValueMap{}
	globalConfig.GlobalSettings = make(map[GlobalSettingKey]ConfigItemValue)
	testMatrix := map[string]struct {
		item     config.ConfigItem
		itemType ConfigItemType
	}{
		"Global String Setting": {
			item: config.ConfigItem{
				Key:   string(ConfigInterval),
				Value: "testValue",
			},
			itemType: ConfigItemTypeString,
		},
		"Global Int Setting": {
			item: config.ConfigItem{
				Key:   string(MetricInterval),
				Value: "10",
			},
			itemType: ConfigItemTypeInt,
		},
		"Global Bool Setting": {
			item: config.ConfigItem{
				Key:   string(MintimeUpdateSuccess),
				Value: "false",
			},
			itemType: ConfigItemTypeBool,
		},
		"Global Tristate Setting": {
			item: config.ConfigItem{
				Key:   string(DefaultLogLevel),
				Value: "TS_NONE",
			},
			itemType: ConfigItemTypeTriState,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		err := specMap.ParseItem(&globalConfig, test.item.Value, test.item.Value)
		if test.itemType == ConfigItemTypeString && err == nil {
			assert.Equal(t, "testValue", (globalConfig).GlobalSettings[GlobalSettingKey(test.item.Key)].stringValue)
		}
		if test.itemType == ConfigItemTypeInt && err == nil {
			assert.Equal(t, 10, (globalConfig).GlobalSettings[GlobalSettingKey(test.item.Key)].intValue)
		}
		if test.itemType == ConfigItemTypeBool && err == nil {
			assert.Equal(t, false, (globalConfig).GlobalSettings[GlobalSettingKey(test.item.Key)].boolValue)
		}
		if test.itemType == ConfigItemTypeTriState && err == nil {
			assert.Equal(t, TS_NONE, (globalConfig).GlobalSettings[GlobalSettingKey(test.item.Key)].triStateValue)
		}
	}
}
func TestParseAgentItem(t *testing.T) {
	specMap := ConfigItemSpecMap{}
	specMap.AgentSettings = make(map[AgentSettingKey]ConfigItemSpec)
	specMap.AgentSettings[LogLevel] = ConfigItemSpec{
		ItemType: ConfigItemTypeString,
	}
	specMap.AgentSettings[RemoteLogLevel] = ConfigItemSpec{
		ItemType: ConfigItemTypeString,
	}
	globalConfig := ConfigItemValueMap{}
	globalConfig.AgentSettings = make(map[string]map[AgentSettingKey]ConfigItemValue)
	testMatrix := map[string]struct {
		item     config.ConfigItem
		itemType ConfigItemType
	}{
		"Agent Setting": {
			item: config.ConfigItem{
				Key:   "agent.zedagent.debug.loglevel",
				Value: "info",
			},
		},
		"Agent Legacy Setting": {
			item: config.ConfigItem{
				Key:   "debug.zedagent.loglevel",
				Value: "info",
			},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		err := specMap.ParseItem(&globalConfig, test.item.Value, test.item.Key)
		if err == nil {
			assert.Equal(t, "info", globalConfig.AgentSettings["zedagent"][LogLevel].stringValue)
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
			defaultString: "Hi",
			expectedVal:   "Hi",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		(&specMap).AddStringItem(test.key, test.defaultString)
		assert.Equal(t, test.expectedVal, specMap.GlobalSettings[test.key].StringDefault)
	}
}
