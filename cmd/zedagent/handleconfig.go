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
	configInterval          uint32
	metricInterval          uint32
	resetIfCloudGoneTime    uint32
	fallbackIfCloudGoneTime uint32
	// XXX max space for downloads?
	// XXX LTE uplink usage policy?
}

// XXX add code which sets timers from ConfigItems from cloud
var configItemDefaults = configItems{configInterval: 10, metricInterval: 60,
	resetIfCloudGoneTime: 168 * 3600, fallbackIfCloudGoneTime: 600}

type getconfigContext struct {
	ledManagerCount int // Current count
	// XXX add timer handles?
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
	zedcloudCtx.FailureFunc = zedCloudFailure
	zedcloudCtx.SuccessFunc = zedCloudSuccess

	b, err := ioutil.ReadFile(uuidFileName)
	if err != nil {
		log.Fatal("ReadFile", err, uuidFileName)
	}
	uuidStr := strings.TrimSpace(string(b))
	devUUID, err = uuid.FromString(uuidStr)
	if err != nil {
		log.Fatal("uuid.FromString", err, string(b))
	}
	fmt.Printf("Read UUID %s\n", devUUID)
	zcdevUUID = devUUID
}

// Run a periodic fetch of the config
// XXX have caller check for unchanged value?
var currentConfigInterval time.Duration

func configTimerTask(handleChannel chan interface{},
	getconfigCtx *getconfigContext) {
	configUrl := serverName + "/" + configApi
	iteration := 0
	checkConnectivity := isZbootAvailable() && isCurrentPartitionStateInProgress()
	rebootFlag := getLatestConfig(configUrl, iteration,
		&checkConnectivity, getconfigCtx)

	interval := time.Duration(configItemDefaults.configInterval) * time.Second
	currentConfigInterval = interval
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
				&checkConnectivity, getconfigCtx)
		}
	}
}

func triggerGetConfig(tickerHandle interface{}) {
	log.Printf("triggerGetConfig()\n")
	flextimer.TickNow(tickerHandle)
}

// Called when configItemDefaults changes
func updateConfigTimer(tickerHandle interface{}) {
	interval := time.Duration(configItemDefaults.configInterval) * time.Second
	if interval == currentConfigInterval {
		return
	}
	log.Printf("updateConfigTimer() change from %v to %v\n",
		currentConfigInterval, interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(tickerHandle,
		time.Duration(min), time.Duration(max))
	if interval < currentConfigInterval {
		// Force an immediate timout on decrease
		flextimer.TickNow(tickerHandle)
	}
	currentConfigInterval = interval
}

// Start by trying the all the free uplinks and then all the non-free
// until one succeeds in communicating with the cloud.
// We use the iteration argument to start at a different point each time.
// Returns a rebootFlag
func getLatestConfig(url string, iteration int, checkConnectivity *bool,
	getconfigCtx *getconfigContext) bool {
	resp, err := zedcloud.SendOnAllIntf(zedcloudCtx, url, nil, iteration)
	if err != nil {
		log.Printf("getLatestConfig failed: %s\n", err)
		if getconfigCtx.ledManagerCount == 4 {
			// Inform ledmanager about loss of config from cloud
			types.UpdateLedManagerConfig(3)
			getconfigCtx.ledManagerCount = 3
		}
		return false
	} else {
		defer resp.Body.Close()

		// now cloud connectivity is good, mark partition state as
		// active if it was inprogress
		// XXX down the road we want more diagnostics and validation
		// before we do this.
		if *checkConnectivity && isCurrentPartitionStateInProgress() {
			curPart := getCurrentPartition()
			log.Printf("Config Fetch Task, curPart %s inprogress\n",
				curPart)
			if err := markPartitionStateActive(); err != nil {
				log.Println(err)
			} else {
				*checkConnectivity = false
			}
		}

		// Each time we hear back from the cloud we assume
		// the device and connectivity is ok so we advance the
		// watchdog timer.
		// We should only require this connectivity once every 24 hours
		// or so using a setable policy in the watchdog, but have
		// a short timeout during validation of a image post upgrade.
		zbootWatchdogOK()

		if err := validateConfigMessage(url, resp); err != nil {
			log.Println("validateConfigMessage: ", err)
			// Inform ledmanager about cloud connectivity
			types.UpdateLedManagerConfig(3)
			getconfigCtx.ledManagerCount = 3
			return false
		}

		changed, config, err := readDeviceConfigProtoMessage(resp)
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
		if !changed {
			if debug {
				log.Printf("Configuration from zedcloud is unchanged\n")
			}
			return false
		}
		return inhaleDeviceConfig(config)
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
func readDeviceConfigProtoMessage(r *http.Response) (bool, *zconfig.EdgeDevConfig, error) {

	var config = &zconfig.EdgeDevConfig{}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		return false, nil, err
	}
	// compute sha256 of the image and match it
	// with the one in config file...
	h := sha256.New()
	h.Write(b)
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, prevConfigHash)
	prevConfigHash = configHash

	//log.Println(" proto bytes(config) received from cloud: ", fmt.Sprintf("%s",bytes))
	//log.Printf("parsing proto %d bytes\n", len(b))
	err = proto.Unmarshal(b, config)
	if err != nil {
		log.Println("Unmarshalling failed: %v", err)
		return false, nil, err
	}
	return !same, config, nil
}

// Returns a rebootFlag
func inhaleDeviceConfig(config *zconfig.EdgeDevConfig) bool {
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
	handleLookUpParam(config)

	// add new BaseOS/App instances
	if rebootSet := parseConfig(config); rebootSet == true {
		return rebootSet
	}

	// then, clean up old config entries
	duration := time.Duration(immediate)
	cleanUpTimer := time.NewTimer(time.Second * duration)
	cleanupOldConfig(config, cleanUpTimer)

	return false
}

// clean up oldConfig, after newConfig
// to maintain the refcount for certs
func cleanupOldConfig(config *zconfig.EdgeDevConfig,
		 cleanUpTimer *time.Timer) {

	<-cleanUpTimer.C

	// delete old app configs, if any
	checkCurrentAppFiles(config)

	// delete old base os configs, if any
	checkCurrentBaseOsFiles(config)
}

func checkCurrentAppFiles(config *zconfig.EdgeDevConfig) {

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
			// app instance not found, delete
			if !found {
				log.Printf("Remove app config %s\n", curAppFilename)
				err := os.Remove(zedmanagerConfigDirname + "/" + curAppFilename)
				if err != nil {
					log.Println("Old config: ", err)
				}
				// also remove the certifiates holder config
				os.Remove(zedagentCertObjConfigDirname + "/" + curAppFilename)
			}
		}
	}
}

func checkCurrentBaseOsFiles(config *zconfig.EdgeDevConfig) {

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
			}
		}
	}
}

func removeBaseOsEntry(baseOsFilename string) {

	uuidStr := strings.Split(baseOsFilename, ".")[0]
	log.Printf("removeBaseOsEntry %s, remove baseOs entry\n", uuidStr)

	// remove partition map entry
	resetPersistentPartitionInfo(uuidStr)

	// remove the certificates holder config
	os.Remove(zedagentCertObjConfigDirname + "/" + baseOsFilename)

	// remove Config File
	os.Remove(zedagentBaseOsConfigDirname + "/" + baseOsFilename)
}
