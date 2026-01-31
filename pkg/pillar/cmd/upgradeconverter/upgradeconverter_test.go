// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type testEntry struct {
	oldVersionExists bool
	newVersionExists bool
	oldVersionOlder  bool
	// newConfigPtr - If nil, verifies no NewCfgDir. If not, expect contents
	//  to match.
	newConfigPtr *types.ConfigItemValueMap
	// expectNoOldCfgDir - Verified oldConfigDir to be deleted.
	expectNoOldCfgDir bool
}

func oldGlobalConfig() types.OldGlobalConfig {
	config := types.OldGlobalConfig{}
	config = types.ApplyDefaults(config)
	// Set Some values
	config.ConfigInterval = 300
	config.AllowAppVnc = true
	config.DefaultLogLevel = "debug"
	config.AgentSettings["zedagent"] = types.PerAgentSettings{
		LogLevel: "info", RemoteLogLevel: "fatal"}
	return config
}

func newConfigItemValueMap() types.ConfigItemValueMap {
	config := types.DefaultConfigItemValueMap()
	config.SetGlobalValueInt(types.ConfigInterval, 400)
	config.SetGlobalValueBool(types.AllowAppVnc, false)
	config.SetGlobalValueString(types.DefaultLogLevel, "warn")
	config.SetGlobalValueInt(types.DownloadMaxPortCost, 1)
	config.SetAgentSettingStringValue("zedagent", types.LogLevel, "debug")

	config.SetAgentSettingStringValue("zedagent", types.RemoteLogLevel, "crit")
	return *config
}

func createJSONFile(config interface{}, file string) {

	parentDir := filepath.Dir(file)
	if !fileutils.DirExists(log, parentDir) {
		err := os.MkdirAll(parentDir, 0700)
		if err != nil {
			log.Fatalf("Failed to create Dir: %s", parentDir)
		}
		log.Tracef("Created Dir: %s", parentDir)
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		log.Fatalf("createJSONFile: failed to marshall. err %s\n config: %+v",
			err, config)
	}
	err = os.WriteFile(file, configJSON, 0644)
	if err != nil {
		log.Fatalf("createJSONFile: failed to write file err %s", err)
	}
	return
}

func configItemValueMapFromFile(file string) *types.ConfigItemValueMap {
	var newConfig types.ConfigItemValueMap
	cfgJSON, err := os.ReadFile(file)
	if err != nil {
		log.Errorf("***configItemValueMapFromFile - Failed to read from %s. "+
			"Err: %s", file, err)
		return nil
	}
	err = json.Unmarshal(cfgJSON, &newConfig)
	if err == nil {
		return &newConfig
	}
	log.Errorf("***configItemValueMapFromFile - Failed to unmarshall data: %+v",
		cfgJSON)
	return nil
}

func checkNoDir(t *testing.T, dir string) {
	if fileutils.DirExists(log, dir) {
		t.Fatalf("***Dir %s Still Present. Expected it to be deleted.", dir)
	}
}

func ucContextForTest() *ucContext {
	//log.SetLevel(log.TraceLevel)
	var err error
	ctxPtr := &ucContext{}
	ctxPtr.persistDir, err = os.MkdirTemp("", "PersistDir")
	if err != nil {
		log.Fatalf("Failed to create persistDir. err: %s", err)
	}
	ctxPtr.persistConfigDir, err = os.MkdirTemp("", "PersistConfigDir")
	if err != nil {
		log.Fatalf("Failed to create persistConfigDir. err: %s", err)
	}
	ctxPtr.persistStatusDir, err = os.MkdirTemp("", "PersistStatusDir")
	if err != nil {
		log.Fatalf("Failed to create persistStatusDir. err: %s", err)
	}
	logger = logrus.StandardLogger()
	ctxPtr.ps = pubsub.New(
		&socketdriver.SocketDriver{
			Logger:  logger,
			Log:     log,
			RootDir: ctxPtr.persistStatusDir,
		},
		logger, log)
	return ctxPtr
}

func ucContextCleanupDirs(ctxPtr *ucContext) {
	os.RemoveAll(ctxPtr.persistDir)
	ctxPtr.persistDir = ""
	os.RemoveAll(ctxPtr.persistConfigDir)
	ctxPtr.persistConfigDir = ""
	os.RemoveAll(ctxPtr.persistStatusDir)
	ctxPtr.persistStatusDir = ""
}

// Test_ConvertUUIDPairToNum verifies conversion from UUIDPairToNum to AppInterfaceToNum
// (previously called UUIDPairAndIfIdxToNum)
func Test_ConvertUUIDPairToNum(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	ctxPtr := ucContextForTest()
	pubUUIDPairToNum, err := ctxPtr.ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		Persistent: true,
		TopicType:  UUIDPairToNum{},
	})
	if err != nil {
		t.Fatal(err)
	}
	pubAppInterfaceToNum, err := ctxPtr.ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		Persistent: true,
		TopicType:  types.AppInterfaceToNum{},
	})
	if err != nil {
		t.Fatal(err)
	}
	appID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	baseID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	numType := "num-type1"
	//it should be converted
	uptn := UUIDPairToNum{
		BaseID:      baseID,
		AppID:       appID,
		Number:      0,
		NumType:     numType,
		CreateTime:  time.Now(),
		LastUseTime: time.Now(),
		InUse:       false,
	}
	err = pubUUIDPairToNum.Publish(uptn.Key(), uptn)
	if err != nil {
		t.Fatal(err)
	}
	// it should be removed
	appifnum := types.AppInterfaceToNum{
		AppInterfaceKey: types.AppInterfaceKey{
			NetInstID: uuid.UUID{},
			AppID:     uuid.UUID{},
			IfIdx:     0,
		},
		Number:      0,
		NumType:     "",
		CreateTime:  time.Now().Add(time.Hour),
		LastUseTime: time.Now().Add(time.Hour),
		InUse:       false,
	}
	err = pubAppInterfaceToNum.Publish(appifnum.Key(), appifnum)
	if err != nil {
		t.Fatal(err)
	}
	// we are done with persist publishing, close publisher
	err = pubUUIDPairToNum.Close()
	if err != nil {
		t.Fatal(err)
	}
	// we are done with persist publishing, close publisher
	err = pubAppInterfaceToNum.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = convertUUIDPairToNum(ctxPtr)
	if err != nil {
		t.Fatal(err)
	}
	// Verify that a second publish gets the data
	// filled in.
	pubUUIDPairToNum, err = ctxPtr.ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		Persistent: true,
		TopicType:  UUIDPairToNum{},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Verify that a second publish gets the data
	// filled in.
	pubAppInterfaceToNum, err = ctxPtr.ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  "zedrouter",
		Persistent: true,
		TopicType:  types.AppInterfaceToNum{},
	})
	if err != nil {
		t.Fatal(err)
	}
	oldMappings := pubUUIDPairToNum.GetAll()
	if len(oldMappings) > 0 {
		t.Fatalf("unexpected UUIDPairToNum count (expected 0): %d", len(oldMappings))
	}
	newMappings := pubAppInterfaceToNum.GetAll()
	if len(newMappings) != 1 {
		t.Fatalf("unexpected AppInterfaceToNum count (expected 1): %d", len(newMappings))
	}
	for _, v := range newMappings {
		val, ok := v.(types.AppInterfaceToNum)
		if !ok {
			t.Fatal("cannot cast interface to AppInterfaceToNum")
		}
		assert.Equal(t, val.AppID, appID)
		assert.Equal(t, val.NetInstID, baseID)
		assert.Equal(t, val.IfIdx, uint32(0))
		assert.Equal(t, val.NumType, numType)
		if !val.CreateTime.Equal(uptn.CreateTime) {
			t.Fatalf("CreateTime mismatch: %s vs %s", val.CreateTime, uptn.CreateTime)
		}
	}
	ucContextCleanupDirs(ctxPtr)
}
