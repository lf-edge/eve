package types

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDefaultValue(t *testing.T) {
	specMap := NewConfigItemSpecMap()
	for _, item := range specMap.GlobalSettings {
		t.Logf("Testing if default value and spec matches for %s", item.Key)
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

func TestNewConfigItemSpecMap(t *testing.T) {
	// logrus.SetLevel(logrus.TraceLevel)
	specMap := NewConfigItemSpecMap()

	// Verify none of the Global key have agent as prefix
	for key, itemSpec := range specMap.GlobalSettings {
		if strings.HasPrefix(string(key), "agent") {
			t.Errorf("TestNewConfigItemSpecMap FAILED. Global setting keys "+
				"cannot have prefix 'agent'. Keys starting with 'agent' are "+
				"agent specific settings. Wrong Key: %s, ItemSpec: %+v",
				key, itemSpec)
		}
	}

	// Check all expected keys present in SpecMap
	gsKeys := []GlobalSettingKey{
		// Int Items
		ConfigInterval,
		CertInterval,
		MetricInterval,
		LocationCloudInterval,
		LocationAppInterval,
		DiskScanMetricInterval,
		ResetIfCloudGoneTime,
		FallbackIfCloudGoneTime,
		MintimeUpdateSuccess,
		StaleConfigTime,
		VdiskGCTime,
		DeferContentDelete,
		DownloadRetryTime,
		DownloadStalledTime,
		DomainBootRetryTime,
		NetworkGeoRedoTime,
		NetworkGeoRetryTime,
		NetworkTestDuration,
		NetworkTestInterval,
		NetworkTestBetterInterval,
		NetworkTestTimeout,
		NetworkSendTimeout,
		NetworkDialTimeout,
		Dom0MinDiskUsagePercent,
		AppContainerStatsInterval,
		VaultReadyCutOffTime,
		Dom0DiskUsageMaxBytes,
		ForceFallbackCounter,
		LogRemainToSendMBytes,
		DownloadMaxPortCost,
		// Bool Items
		UsbAccess,
		VgaAccess,
		AllowAppVnc,
		EveMemoryLimitInBytes,
		IgnoreMemoryCheckForApps,
		IgnoreDiskCheckForApps,
		AllowLogFastupload,
		// TriState Items
		NetworkFallbackAnyEth,
		MaintenanceMode,
		// String Items
		SSHAuthorizedKeys,
		DefaultLogLevel,
		DefaultRemoteLogLevel,
		DisableDHCPAllOnesNetMask,
		ProcessCloudInitMultiPart,
		EdgeViewToken,
	}
	if len(specMap.GlobalSettings) != len(gsKeys) {
		t.Errorf("GlobalSettings has more (%d) than expected keys (%d)",
			len(specMap.GlobalSettings), len(gsKeys))
	}
	for _, key := range gsKeys {
		_, ok := specMap.GlobalSettings[key]
		if !ok {
			t.Errorf("Key %s not present in SpecMap.GlobalSettings", key)
		}
	}

	// Check all expected AgentSettingKeys present in SpecMap
	asKeys := []AgentSettingKey{
		LogLevel,
		RemoteLogLevel,
	}
	if len(specMap.AgentSettings) != len(asKeys) {
		t.Errorf("AgentSettings has more (%d) than expected keys (%d)",
			len(specMap.AgentSettings), len(asKeys))
	}
	for _, key := range asKeys {
		_, ok := specMap.AgentSettings[key]
		if !ok {
			t.Errorf("Key %s not present in SpecMap.GlobalSettings", key)
		}
	}

}

type configItemStruct struct {
	key   string
	value string
}

type parseItemTestEntry struct {
	item          configItemStruct
	itemType      ConfigItemType
	expectError   bool
	expectedValue string
	oldValue      string
}

func (testPtr *parseItemTestEntry) configItemValue(
	oldVal bool) ConfigItemValue {
	if !oldVal {
		if testPtr.expectError && testPtr.expectedValue == "" {
			// Not expecting a Value. Return Empty Val
			return ConfigItemValue{}
		}
	}
	val := ConfigItemValue{
		Key:      testPtr.item.key,
		ItemType: testPtr.itemType,
	}

	var valueStr string
	if oldVal {
		valueStr = testPtr.oldValue
	} else if testPtr.expectedValue == "" {
		// Expected Value not specified. Use Configured Value
		valueStr = testPtr.item.value
	} else {
		valueStr = testPtr.expectedValue
	}

	switch testPtr.itemType {
	case ConfigItemTypeBool:
		val.BoolValue, _ = strconv.ParseBool(valueStr)
	case ConfigItemTypeInt:
		intVal, _ := strconv.ParseUint(valueStr, 10, 32)
		val.IntValue = uint32(intVal)
	case ConfigItemTypeString:
		val.StrValue = valueStr
	case ConfigItemTypeTriState:
		val.TriStateValue, _ = ParseTriState(valueStr)
	default:
		logrus.Fatalf("Invalid inteType %d in testPtr %+v",
			testPtr.itemType, *testPtr)
	}
	return val
}

// Verify Expected value is same as Actual value - both returned
//  value as well as one in newGlobalConfig
func (testPtr *parseItemTestEntry) verifyEntry(t *testing.T, testname string,
	newGlobalConfig *ConfigItemValueMap, val ConfigItemValue) {
	// Verify Expected value is same as Actual value - both returned
	//  value as well as one in newGlobalConfig
	gsKey := GlobalSettingKey(testPtr.item.key)
	expectedItemVal := testPtr.configItemValue(false)
	msg := fmt.Sprintf("ExpectedValue (%+v) != Actual Value (%+v)",
		expectedItemVal, val)
	assert.Equal(t, expectedItemVal, val, msg)
	if expectedItemVal.ItemType != ConfigItemTypeInvalid {
		val = newGlobalConfig.globalConfigItemValue(gsKey)
		msg = fmt.Sprintf("ExpectedValue (%+v) != Actual Value (%+v)",
			expectedItemVal, val)
		assert.Equal(t, expectedItemVal, val, msg)
	}
}

func TestParseGlobalItem(t *testing.T) {
	// logrus.SetLevel(logrus.TraceLevel)
	specMap := NewConfigItemSpecMap()
	testMatrix := map[string]parseItemTestEntry{
		"Global String Setting": {
			item: configItemStruct{
				key:   string(DefaultLogLevel),
				value: "warn",
			},
			itemType: ConfigItemTypeString,
		},
		"Global Int Setting": {
			item: configItemStruct{
				key:   string(ConfigInterval),
				value: "10",
			},
			itemType: ConfigItemTypeInt,
		},
		"Global Bool Setting": {
			item: configItemStruct{
				key:   string(UsbAccess),
				value: "false",
			},
			itemType: ConfigItemTypeBool,
		},
		"Global Tristate Setting": {
			item: configItemStruct{
				key:   string(NetworkFallbackAnyEth),
				value: "none",
			},
			itemType: ConfigItemTypeTriState,
		},
		"Global Setting - Unknown Key": {
			item: configItemStruct{
				key:   "UnknownKey",
				value: "10",
			},
			expectError: true,
		},
		"Global Setting - Invalid int Value - Retain Old Value": {
			item: configItemStruct{
				key:   string(ConfigInterval),
				value: "0",
			},
			itemType:      ConfigItemTypeInt,
			expectError:   true,
			expectedValue: "10",
			oldValue:      "10",
		},
		"Global Setting - Invalid int Value Parse Error - Retain Old Value": {
			item: configItemStruct{
				key:   string(ConfigInterval),
				value: "0abc",
			},
			itemType:      ConfigItemTypeInt,
			expectError:   true,
			expectedValue: "20",
			oldValue:      "20",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s, test: %+v", testname, test)
		newGlobalConfig := DefaultConfigItemValueMap()
		oldGlobalConfig := DefaultConfigItemValueMap()
		if test.oldValue != "" {
			// Set old value in globalConfig
			oldGlobalConfig.GlobalSettings[GlobalSettingKey(test.item.key)] =
				test.configItemValue(true)
		}
		val, err := specMap.ParseItem(newGlobalConfig, oldGlobalConfig,
			test.item.key, test.item.value)
		if test.expectError {
			msg := fmt.Sprintf("Expecting Error, Didn't get one. "+
				"testname: %s, test: %+v", testname, test)
			assert.NotEqual(t, err, nil, msg)

			test.verifyEntry(t, testname, newGlobalConfig, val)
		} else {
			msg := fmt.Sprintf("Unexpected Error. testname: %s, test: %+v, "+
				"err: %s", testname, test, err)
			assert.Equal(t, err, nil, msg)
			test.verifyEntry(t, testname, newGlobalConfig, val)
		}
	}
}

// Test ParseItem for Agent Settings
//  Verify both new and Legacy settings are parsed correctly
//  Verify Unknown settings ( New and Legacy ) are rejected
//  Verify Invalid Values for known settings are rejected and old value retained
func TestParseAgentItem(t *testing.T) {
	// logrus.SetLevel(logrus.TraceLevel)
	specMap := NewConfigItemSpecMap()

	testMatrix := map[string]parseItemTestEntry{
		"Agent Setting LogLevel New": {
			item: configItemStruct{
				key:   "agent.zedagent.debug.loglevel",
				value: "fatal",
			},
		},
		"Agent Setting Legacy LogLevel": {
			item: configItemStruct{
				key:   "debug.zedrouter.loglevel",
				value: "panic",
			},
		},
		"Agent Setting Remote Loglevel": {
			item: configItemStruct{
				key:   "agent.nim.debug.remote.loglevel",
				value: "error",
			},
		},
		"Agent Setting Legacy Remote LogLevel": {
			item: configItemStruct{
				key:   "debug.domainmgr.remote.loglevel",
				value: "warn",
			},
		},
		// Error Cases for Agent Settings
		"Agent Setting Legacy - UnknownOldSetting": {
			item: configItemStruct{
				key:   "debug.nodeagent.UnknownOldSetting",
				value: "none",
			},
			expectError: true,
		},
		"Agent Setting - UnknownSetting": {
			item: configItemStruct{
				key:   "agent.ledmanager.UnknownOldSetting",
				value: "none",
			},
			expectError: true,
		},
		"Agent Setting - Invalid Value - Old Value should be retained": {
			item: configItemStruct{
				key:   "agent.downloader.debug.loglevel",
				value: "BadValue",
			},
			expectError:   true,
			expectedValue: "panic",
			oldValue:      "panic",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s - key:%s, value: %s",
			testname, test.item.key, test.item.value)
		// oldGlobalConfig is used as the Current Setting. In case of
		// invalid values, values from this ar retained.
		oldGlobalConfig := DefaultConfigItemValueMap()
		if test.oldValue != "" {
			agentName, asKey, err := parseAgentSettingKey(test.item.key)
			if err != nil {
				logrus.Fatalf("Invalid Agent Key. Key: %s, err: %s",
					test.item.key, err)
			}
			// Set old value in globalConfig
			itemVal := ConfigItemValue{
				Key:      test.item.key,
				ItemType: ConfigItemTypeString,
				StrValue: test.oldValue,
			}
			oldGlobalConfig.setAgentSettingValue(agentName, asKey, itemVal)
		}
		agentName, asKey, err := parseAgentSettingKey(test.item.key)
		if err != nil {
			logrus.Fatalf("Unexpected Error in parsing key(%s). err: %s",
				test.item.key, err)
		}
		newGlobalConfig := DefaultConfigItemValueMap()
		itemVal, err := specMap.ParseItem(newGlobalConfig, oldGlobalConfig,
			test.item.key, test.item.value)
		if test.expectError {
			// Verify Error Cases
			if err == nil {
				t.Fatalf("TEST FAILED: %s - Expected Error. But did not get one",
					testname)
			} else {
				logrus.Debugf("Test %s - received Error as expected: %s",
					testname, err)
				if test.oldValue != "" {
					// Value Error. Verify the Old value has been retained
					// Verify Returned value is the expected Value
					assert.Equal(t, test.expectedValue, itemVal.StringValue())
					// Verify the value has been set in newGlobalConfig
					assert.Equal(t, test.expectedValue,
						newGlobalConfig.AgentSettingStringValue(agentName,
							asKey))
				}
			}
		} else {
			if err == nil {
				// Verify Returned value is the expected Value
				expectedVal := test.expectedValue
				if expectedVal == "" {
					expectedVal = test.item.value
				}
				assert.Equal(t, expectedVal, itemVal.StringValue())
				// Verify the value has been set in newGlobalConfig
				assert.Equal(t, expectedVal,
					newGlobalConfig.AgentSettingStringValue(agentName, asKey))
			} else {
				t.Fatalf("TEST FAILED: %s - Unexpected Error from parseItem. "+
					"Key: %s, value: %s, Err: %s",
					testname, test.item.key, test.item.value, err)

			}
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
