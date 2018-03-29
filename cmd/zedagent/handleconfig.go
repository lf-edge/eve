// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zboot"
	"github.com/zededa/go-provision/zedcloud"
	"io/ioutil"
	"log"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	MaxReaderSmall      = 1 << 16 // 64k
	MaxReaderMaxDefault = MaxReaderSmall
	MaxReaderMedium     = 1 << 19 // 512k
	MaxReaderHuge       = 1 << 21 // two megabytes
)

var configApi string = "api/v1/edgedevice/config"
var statusApi string = "api/v1/edgedevice/info"
var metricsApi string = "api/v1/edgedevice/metrics"

// This is set once at init time and not changed
var serverName string

const (
	identityDirname = "/config"
	serverFilename  = identityDirname + "/server"
	uuidFileName    = identityDirname + "/uuid"
)

// A value of zero means we should use the default
// All times are in seconds.
type configItems struct {
	configInterval          uint32 // Try get of device config
	metricInterval          uint32 // push metrics to cloud
	resetIfCloudGoneTime    uint32 // reboot if no cloud connectivity
	fallbackIfCloudGoneTime uint32 // ... and shorter during upgrade
	// XXX add max space for downloads?
	// XXX add LTE uplink usage policy?
}

// Really a constant
// We do a GET of config every 60 seconds,
// PUT of metrics every 60 seconds,
// if we don't hear anything from the cloud in a week, then we reboot,
// and during a post-upgrade boot that time is reduced to 10 minutes.
var configItemDefaults = configItems{configInterval: 60, metricInterval: 60,
	resetIfCloudGoneTime: 7 * 24 * 3600, fallbackIfCloudGoneTime: 600}

// XXX	resetIfCloudGoneTime: 300, fallbackIfCloudGoneTime: 60}

var configItemCurrent = configItemDefaults

type getconfigContext struct {
	ledManagerCount             int // Current count
	lastReceivedConfigFromCloud time.Time
	configTickerHandle          interface{}
	metricsTickerHandle         interface{}
}

// tlsConfig is initialized once i.e. effectively a constant
var zedcloudCtx zedcloud.ZedCloudContext

// devUUID is set in handleConfigInit and never changed
var devUUID uuid.UUID

// XXX need to support recreating devices. Remove when zedcloud preserves state
var zcdevUUID uuid.UUID

// Really a constant
var nilUUID uuid.UUID

func handleConfigInit() {

	// get the server name
	bytes, err := ioutil.ReadFile(serverFilename)
	if err != nil {
		log.Fatal(err)
	}
	strTrim := strings.TrimSpace(string(bytes))
	serverName = strings.Split(strTrim, ":")[0]

	tlsConfig, err := zedcloud.GetTlsConfig(serverName, nil)
	if err != nil {
		log.Fatal(err)
	}
	zedcloudCtx.DeviceNetworkStatus = &deviceNetworkStatus
	zedcloudCtx.TlsConfig = tlsConfig
	zedcloudCtx.Debug = debug
	zedcloudCtx.FailureFunc = zedcloud.ZedCloudFailure
	zedcloudCtx.SuccessFunc = zedcloud.ZedCloudSuccess

	b, err := ioutil.ReadFile(uuidFileName)
	if err != nil {
		log.Fatal("ReadFile", err, uuidFileName)
	}
	uuidStr := strings.TrimSpace(string(b))
	devUUID, err = uuid.FromString(uuidStr)
	if err != nil {
		log.Fatal("uuid.FromString", err, string(b))
	}
	log.Printf("Read UUID %s\n", devUUID)
	zcdevUUID = devUUID
}

// Run a periodic fetch of the config
func configTimerTask(handleChannel chan interface{},
	getconfigCtx *getconfigContext) {
	configUrl := serverName + "/" + configApi
	getconfigCtx.lastReceivedConfigFromCloud = time.Now()
	iteration := 0
	upgradeInprogress := zboot.IsAvailable() && zboot.IsCurrentPartitionStateInProgress()
	rebootFlag := getLatestConfig(configUrl, iteration,
		&upgradeInprogress, getconfigCtx)

	interval := time.Duration(configItemCurrent.configInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker
	for range ticker.C {
		iteration += 1
		// reboot flag is not set, go fetch new config
		if rebootFlag == false {
			rebootFlag = getLatestConfig(configUrl, iteration,
				&upgradeInprogress, getconfigCtx)
		} else {
			log.Printf("rebootFlag set; not getting config\n")
		}
	}
}

func triggerGetConfig(tickerHandle interface{}) {
	log.Printf("triggerGetConfig()\n")
	flextimer.TickNow(tickerHandle)
}

// Called when configItemCurrent changes
// Assumes the caller has verifier that the interval has changed
func updateConfigTimer(tickerHandle interface{}) {
	interval := time.Duration(configItemCurrent.configInterval) * time.Second
	log.Printf("updateConfigTimer() change to %v\n", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(tickerHandle,
		time.Duration(min), time.Duration(max))
	// Force an immediate timout since timer could have decreased
	flextimer.TickNow(tickerHandle)
}

// Start by trying the all the free uplinks and then all the non-free
// until one succeeds in communicating with the cloud.
// We use the iteration argument to start at a different point each time.
// Returns a rebootFlag
func getLatestConfig(url string, iteration int, upgradeInprogress *bool,
	getconfigCtx *getconfigContext) bool {

	// Did we exceed the time limits?
	timePassed := time.Since(getconfigCtx.lastReceivedConfigFromCloud)

	resetLimit := time.Second * time.Duration(configItemCurrent.resetIfCloudGoneTime)
	if timePassed > resetLimit {
		log.Printf("Exceeded outage for cloud connectivity by %d seconds- rebooting\n",
			(timePassed-resetLimit)/time.Second)
		execReboot(true)
		return true
	}
	if *upgradeInprogress {
		fallbackLimit := time.Second * time.Duration(configItemCurrent.fallbackIfCloudGoneTime)
		if timePassed > fallbackLimit {
			log.Printf("Exceeded fallback outage for cloud connectivity by %d seconds- rebooting\n",
				(timePassed-fallbackLimit)/time.Second)
			execReboot(true)
			return true
		}
	}

	resp, contents, err := zedcloud.SendOnAllIntf(zedcloudCtx, url, 0, nil, iteration)
	if err != nil {
		log.Printf("getLatestConfig failed: %s\n", err)
		if getconfigCtx.ledManagerCount == 4 {
			// Inform ledmanager about loss of config from cloud
			types.UpdateLedManagerConfig(3)
			getconfigCtx.ledManagerCount = 3
		}
		return false
	} else {
		// now cloud connectivity is good, mark partition state as
		// active if it was inprogress
		// XXX down the road we want more diagnostics and validation
		// before we do this.
		if *upgradeInprogress && zboot.IsCurrentPartitionStateInProgress() {
			curPart := zboot.GetCurrentPartition()
			log.Printf("Config Fetch Task, curPart %s inprogress\n",
				curPart)
			if err := zboot.MarkOtherPartitionStateActive(); err != nil {
				log.Println(err)
			} else {
				*upgradeInprogress = false
			}
		}

		// Each time we hear back from the cloud we assume
		// the device and connectivity is ok so we advance the
		// watchdog timer.
		// We should only require this connectivity once every 24 hours
		// or so using a setable policy in the watchdog, but have
		// a short timeout during validation of a image post upgrade.
		zboot.WatchdogOK()

		if err := validateConfigMessage(url, resp); err != nil {
			log.Println("validateConfigMessage: ", err)
			// Inform ledmanager about cloud connectivity
			types.UpdateLedManagerConfig(3)
			getconfigCtx.ledManagerCount = 3
			return false
		}

		changed, config, err := readDeviceConfigProtoMessage(contents)
		if err != nil {
			log.Println("readDeviceConfigProtoMessage: ", err)
			// Inform ledmanager about cloud connectivity
			types.UpdateLedManagerConfig(3)
			getconfigCtx.ledManagerCount = 3
			return false
		}

		// Inform ledmanager about config received from cloud
		types.UpdateLedManagerConfig(4)
		getconfigCtx.ledManagerCount = 4

		getconfigCtx.lastReceivedConfigFromCloud = time.Now()
		if !changed {
			if debug {
				log.Printf("Configuration from zedcloud is unchanged\n")
			}
			return false
		}
		return inhaleDeviceConfig(config, getconfigCtx)
	}
}

func validateConfigMessage(url string, r *http.Response) error {

	var ctTypeStr = "Content-Type"
	var ctTypeProtoStr = "application/x-proto-binary"

	ct := r.Header.Get(ctTypeStr)
	if ct == "" {
		return fmt.Errorf("No content-type")
	}
	mimeType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("Get Content-type error")
	}
	switch mimeType {
	case ctTypeProtoStr:
		return nil
	default:
		return fmt.Errorf("Content-type %s not supported",
			mimeType)
	}
}

var prevConfigHash []byte

// Returns changed, config, error. The changed is based on a comparison of
// the hash of the protobuf message.
func readDeviceConfigProtoMessage(contents []byte) (bool, *zconfig.EdgeDevConfig, error) {

	var config = &zconfig.EdgeDevConfig{}

	// compute sha256 of the image and match it
	// with the one in config file...
	h := sha256.New()
	h.Write(contents)
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, prevConfigHash)
	prevConfigHash = configHash

	err := proto.Unmarshal(contents, config)
	if err != nil {
		log.Println("Unmarshalling failed: %v", err)
		return false, nil, err
	}
	return !same, config, nil
}

// Returns a rebootFlag
func inhaleDeviceConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext) bool {
	log.Printf("Inhaling config %v\n", config)

	// if they match return
	var devId = &zconfig.UUIDandVersion{}

	devId = config.GetId()
	if devId != nil {
		id, err := uuid.FromString(devId.Uuid)
		if err != nil {
			log.Printf("Invalid UUID %s from cloud: %s\n",
				devId.Uuid, err)
			return false
		}
		if id != devUUID {
			// XXX logic to handle re-registering a device private
			// key with zedcloud. We accept a new UUID from the
			// cloud and use that in our reports, but we do
			// not update the hostname nor LISP.
			// XXX remove once zedcloud preserves state.
			if id != zcdevUUID {
				log.Printf("XXX Device UUID changed from %s to %s\n",
					zcdevUUID.String(), id.String())
				zcdevUUID = id
			}

		}
	}
	handleLookupParam(config)

	// clean up old config entries
	if deleted := cleanupOldConfig(config); deleted {
		log.Printf("Old Config removed, take a delay\n")
		duration := time.Duration(immediate)
		newConfigTimer := time.NewTimer(time.Second * duration)
		<-newConfigTimer.C
	}

	// add new BaseOS/App instances; returns rebootFlag
	if parseConfig(config, getconfigCtx) {
		return true
	}

	return false
}

// clean up oldConfig, after newConfig
// to maintain the refcount for certs
func cleanupOldConfig(config *zconfig.EdgeDevConfig) bool {

	// delete old app configs, if any
	appDel := checkCurrentAppFiles(config)

	// delete old base os configs, if any
	baseDel := checkCurrentBaseOsFiles(config)
	return appDel || baseDel
}

func checkCurrentAppFiles(config *zconfig.EdgeDevConfig) bool {

	deleted := false
	// get the current set of App files
	curAppFilenames, err := ioutil.ReadDir(zedmanagerConfigDirname)
	if err != nil {
		log.Printf("%v for %s\n", err, zedmanagerConfigDirname)
		curAppFilenames = nil
	}

	Apps := config.GetApps()
	// delete any app instances which are not present in the new set
	for _, curApp := range curAppFilenames {
		curAppFilename := curApp.Name()

		// file type json
		if strings.HasSuffix(curAppFilename, ".json") {
			found := false
			for _, app := range Apps {
				appFilename := app.Uuidandversion.Uuid + ".json"
				if appFilename == curAppFilename {
					found = true
					break
				}
			}
			// app instance not found, delete app instance
			// config holder file
			if !found {
				log.Printf("Remove app config %s\n", curAppFilename)
				err := os.Remove(zedmanagerConfigDirname + "/" + curAppFilename)
				if err != nil {
					log.Println("Old config: ", err)
				}
				// also remove the certificates config holder file
				os.Remove(zedagentCertObjConfigDirname + "/" + curAppFilename)
				deleted = true
			}
		}
	}
	return deleted
}

func checkCurrentBaseOsFiles(config *zconfig.EdgeDevConfig) bool {

	deleted := false
	// get the current set of baseOs files
	curBaseOsFilenames, err := ioutil.ReadDir(zedagentBaseOsConfigDirname)
	if err != nil {
		log.Printf("%v for %s\n", err, zedagentBaseOsConfigDirname)
		curBaseOsFilenames = nil
	}

	baseOses := config.GetBase()
	// delete any baseOs config which is not present in the new set
	for _, curBaseOs := range curBaseOsFilenames {
		curBaseOsFilename := curBaseOs.Name()

		// file type json
		if strings.HasSuffix(curBaseOsFilename, ".json") {
			found := false
			for _, baseOs := range baseOses {
				baseOsFilename := baseOs.Uuidandversion.Uuid + ".json"
				if baseOsFilename == curBaseOsFilename {
					found = true
					break
				}
			}
			// baseOS instance not found, delete
			if !found {
				removeBaseOsEntry(curBaseOsFilename)
				deleted = true
			}
		}
	}
	return deleted
}

func removeBaseOsEntry(baseOsFilename string) {

	uuidStr := strings.Split(baseOsFilename, ".")[0]
	log.Printf("removeBaseOsEntry %s, remove baseOs entry\n", uuidStr)

	// remove base os holder config file
	os.Remove(zedagentBaseOsConfigDirname + "/" + baseOsFilename)

	// remove certificates holder config file
	os.Remove(zedagentCertObjConfigDirname + "/" + baseOsFilename)
}
