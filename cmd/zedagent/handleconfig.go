// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/pubsub"
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
	fallbackIfCloudGoneTime uint32 // ... and shorter during update
	mintimeUpdateSuccess    uint32 // time before zedagent declares success
	usbAccess               bool   // domU has all PCI including USB controllers
	sshAccess               bool
	staleConfigTime         uint32 // On reboot use saved config if not stale
	// XXX add max space for downloads?
	// XXX add LTE uplink usage policy?
}

// Really a constant
// We do a GET of config every 60 seconds,
// PUT of metrics every 60 seconds,
// if we don't hear anything from the cloud in a week, then we reboot,
// and during a post-update boot that time is reduced to 10 minutes.
// On reboot if we can't get a config, then we use a saved one if
// not older than 10 minutes.
var configItemDefaults = configItems{configInterval: 60, metricInterval: 60,
	resetIfCloudGoneTime: 7 * 24 * 3600, fallbackIfCloudGoneTime: 600,
	mintimeUpdateSuccess: 300, usbAccess: true, sshAccess: true,
	staleConfigTime: 600}

// XXX shorter counters for testing fallback:
// 	resetIfCloudGoneTime: 300, fallbackIfCloudGoneTime: 60,

var configItemCurrent = configItemDefaults

type getconfigContext struct {
	ledManagerCount             int // Current count
	startTime                   time.Time
	lastReceivedConfigFromCloud time.Time
	readSavedConfig		    bool
	configTickerHandle          interface{}
	metricsTickerHandle         interface{}
	pubNetworkObjectConfig      *pubsub.Publication
	pubNetworkServiceConfig     *pubsub.Publication
	subAppInstanceStatus        *pubsub.Subscription
	pubAppInstanceConfig        *pubsub.Publication
	pubAppNetworkConfig         *pubsub.Publication
	pubCertObjConfig            *pubsub.Publication
	pubBaseOsConfig             *pubsub.Publication
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
	getconfigCtx.startTime = time.Now()
	getconfigCtx.lastReceivedConfigFromCloud = getconfigCtx.startTime
	iteration := 0
	updateInprogress := zboot.IsCurrentPartitionStateInProgress()
	rebootFlag := getLatestConfig(configUrl, iteration,
		&updateInprogress, getconfigCtx)

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
				&updateInprogress, getconfigCtx)
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
func getLatestConfig(url string, iteration int, updateInprogress *bool,
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
	if *updateInprogress {
		fallbackLimit := time.Second * time.Duration(configItemCurrent.fallbackIfCloudGoneTime)
		if timePassed > fallbackLimit {
			log.Printf("Exceeded fallback outage for cloud connectivity by %d seconds- rebooting\n",
				(timePassed-fallbackLimit)/time.Second)
			execReboot(true)
			return true
		}
	}

	resp, contents, err := zedcloud.SendOnAllIntf(zedcloudCtx, url, 0, nil, iteration, false)
	if err != nil {
		log.Printf("getLatestConfig failed: %s\n", err)
		if getconfigCtx.ledManagerCount == 4 {
			// Inform ledmanager about loss of config from cloud
			types.UpdateLedManagerConfig(3)
			getconfigCtx.ledManagerCount = 3
		}
		// If we didn't yet get a config, then look for a file
		// XXX should we try a few times?
		// XXX different policy if updateInProgress? No fallback for now
		if !*updateInprogress &&
			!getconfigCtx.readSavedConfig &&
			getconfigCtx.lastReceivedConfigFromCloud == getconfigCtx.startTime {

			config, err := readSavedProtoMessage()
			if err != nil {
				log.Printf("getconfig: %v\n", err)
				return false
			}
			if config != nil {
				log.Printf("Using saved config %v\n", config)
				getconfigCtx.readSavedConfig = true
				return inhaleDeviceConfig(config, getconfigCtx)
			}
		}
		return false
	}
	// now cloud connectivity is good, consider marking partition state as
	// active if it was inprogress
	// XXX down the road we want more diagnostics and validation
	// before we do this.
	if *updateInprogress && zboot.IsCurrentPartitionStateInProgress() {
		// Wait for a bit to detect an agent crash. Should run for
		// at least N minutes to make sure we don't hit a watchdog.
		timePassed := time.Since(getconfigCtx.startTime)
		successLimit := time.Second *
			time.Duration(configItemCurrent.mintimeUpdateSuccess)
		curPart := zboot.GetCurrentPartition()
		if timePassed < successLimit {
			log.Printf("getLastestConfig, curPart %s inprogress waiting for %d seconds\n",
				curPart,
				(successLimit-timePassed)/time.Second)
		} else {
			log.Printf("getLastestConfig, curPart %s inprogress; marking active\n",
				curPart)
			if err := zboot.MarkOtherPartitionStateActive(); err != nil {
				log.Println(err)
			} else {
				*updateInprogress = false
				publishDeviceInfo = true
			}
		}
	}

	// Each time we hear back from the cloud we assume
	// the device and connectivity is ok so we advance the
	// watchdog timer.
	// We should only require this connectivity once every 24 hours
	// or so using a setable policy in the watchdog, but have
	// a short timeout during validation of a image post update.
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
	writeReceivedProtoMessage(contents)

	if !changed {
		if debug {
			log.Printf("Configuration from zedcloud is unchanged\n")
		}
		return false
	}
	return inhaleDeviceConfig(config, getconfigCtx)
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

func writeReceivedProtoMessage(contents []byte) {
	filename := checkpointDirname + "/lastconfig"
	err := ioutil.WriteFile(filename, contents, 0744)
	if err != nil {
		log.Fatal("writeReceiveProtoMessage", err)
		return
	}
}

// If the file exists then read the config
// Ignore if if older than staleConfigTime seconds
func readSavedProtoMessage() (*zconfig.EdgeDevConfig, error) {
	filename := checkpointDirname + "/lastconfig"
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		} else {
			return nil, err
		}
	}
	age := time.Since(info.ModTime())
	staleLimit := time.Second * time.Duration(configItemCurrent.staleConfigTime)
	if age > staleLimit {
		errStr := fmt.Sprintf("savedProto too old: age %v limit %d\n",
			age, staleLimit)
		log.Println(errStr)
		return nil, nil
	}
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println("readSavedProtoMessage", err)
		return nil, err
	}
	var config = &zconfig.EdgeDevConfig{}

	err = proto.Unmarshal(contents, config)
	if err != nil {
		log.Println("readSavedProtoMessage Unmarshalling failed: %v",
			err)
		return nil, err
	}
	return config, nil
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
	if debug {
		log.Printf("Inhaling config %v\n", config)
	}

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
	handleLookupParam(getconfigCtx, config)

	// XXX should check for different sha for baseOs and appInstances
	// before looking for old
	// clean up old config entries
	if deleted := cleanupOldConfig(getconfigCtx, config); deleted {
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
func cleanupOldConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) bool {

	// delete old app configs, if any
	appDel := checkCurrentAppInstances(getconfigCtx, config)

	// delete old base os configs, if any
	baseDel := checkCurrentBaseOs(getconfigCtx, config)
	return appDel || baseDel
}

// Delete any app instances which are not present in the new set
func checkCurrentAppInstances(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) bool {

	Apps := config.GetApps()
	deleted := false
	// get the current set of App instances
	pub := getconfigCtx.pubAppInstanceConfig
	items := pub.GetAll()
	for key, c := range items {
		config := cast.CastAppInstanceConfig(c)
		if config.Key() != key {
			log.Printf("checkCurrentAppInstances key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		key := config.Key()
		found := false
		for _, app := range Apps {
			if app.Uuidandversion.Uuid == key {
				found = true
				break
			}
		}
		if !found {
			log.Printf("Remove app config %s\n", key)
			pub.Unpublish(key)
			deleted = true

			unpublishCertObjConfig(getconfigCtx, key)
		}
	}
	return deleted
}

func checkCurrentBaseOs(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) bool {

	deleted := false
	// get the current set of baseOs configs
	pub := getconfigCtx.pubBaseOsConfig
	items := pub.GetAll()
	baseOses := config.GetBase()
	// delete any baseOs config which is not present in the new set
	for uuidStr, _ := range items {
		found := false
		for _, baseOs := range baseOses {
			if baseOs.Uuidandversion.Uuid == uuidStr {
				found = true
				break
			}
		}
		// baseOS instance not found, delete
		if !found {
			unpublishBaseOsConfig(getconfigCtx, uuidStr)
			// XXX what is the uuid for the cert objects?
			unpublishCertObjConfig(getconfigCtx, uuidStr)
			deleted = true
		}
	}
	return deleted
}
