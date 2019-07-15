// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

var configApi string = "api/v1/edgedevice/config"
var statusApi string = "api/v1/edgedevice/info"
var metricsApi string = "api/v1/edgedevice/metrics"

// This is set once at init time and not changed
var serverName string
var serverNameAndPort string

const (
	identityDirname = "/config"
	serverFilename  = identityDirname + "/server"
	uuidFileName    = identityDirname + "/uuid"
)

var globalConfig = types.GlobalConfigDefaults

type getconfigContext struct {
	zedagentCtx                 *zedagentContext // Cross link
	ledManagerCount             int              // Current count
	startTime                   time.Time
	lastReceivedConfigFromCloud time.Time
	readSavedConfig             bool
	configTickerHandle          interface{}
	metricsTickerHandle         interface{}
	pubDevicePortConfig         *pubsub.Publication
	devicePortConfig            types.DevicePortConfig
	pubNetworkXObjectConfig     *pubsub.Publication
	subAppInstanceStatus        *pubsub.Subscription
	pubAppInstanceConfig        *pubsub.Publication
	pubAppNetworkConfig         *pubsub.Publication
	pubCertObjConfig            *pubsub.Publication
	pubBaseOsConfig             *pubsub.Publication
	pubDatastoreConfig          *pubsub.Publication
	pubNetworkInstanceConfig    *pubsub.Publication
	rebootFlag                  bool
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
	serverNameAndPort = strings.TrimSpace(string(bytes))
	serverName = strings.Split(serverNameAndPort, ":")[0]

	tlsConfig, err := zedcloud.GetTlsConfig(serverName, nil)
	if err != nil {
		log.Fatal(err)
	}
	zedcloudCtx.DeviceNetworkStatus = deviceNetworkStatus
	zedcloudCtx.TlsConfig = tlsConfig
	zedcloudCtx.FailureFunc = zedcloud.ZedCloudFailure
	zedcloudCtx.SuccessFunc = zedcloud.ZedCloudSuccess
	zedcloudCtx.DevSerial = hardware.GetProductSerial()
	log.Infof("Configure Get Device Serial %s\n", zedcloudCtx.DevSerial)

	b, err := ioutil.ReadFile(uuidFileName)
	if err != nil {
		log.Fatal("ReadFile", err, uuidFileName)
	}
	uuidStr := strings.TrimSpace(string(b))
	devUUID, err = uuid.FromString(uuidStr)
	if err != nil {
		log.Fatal("uuid.FromString", err, string(b))
	}
	log.Infof("Read UUID %s\n", devUUID)
	zedcloudCtx.DevUUID = devUUID
	zcdevUUID = devUUID
}

// Run a periodic fetch of the config
func configTimerTask(handleChannel chan interface{},
	getconfigCtx *getconfigContext, updateInprogress bool) {

	configUrl := serverNameAndPort + "/" + configApi
	getconfigCtx.startTime = time.Now()
	getconfigCtx.lastReceivedConfigFromCloud = getconfigCtx.startTime
	iteration := 0
	ctx := getconfigCtx.zedagentCtx
	getconfigCtx.rebootFlag = getLatestConfig(configUrl, iteration,
		updateInprogress, getconfigCtx)

	interval := time.Duration(globalConfig.ConfigInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)

	for {
		select {
		case <-ticker.C:
			iteration += 1
			// check whether the device is still in progress state
			// once activated, it does not go back to the inprogress
			// state
			if updateInprogress {
				updateInprogress = isBaseOsCurrentPartitionStateInProgress(ctx)
			}
			rebootFlag := getLatestConfig(configUrl, iteration,
				updateInprogress, getconfigCtx)
			getconfigCtx.rebootFlag = getconfigCtx.rebootFlag || rebootFlag

		case <-stillRunning.C:
			agentlog.StillRunning(agentName + "config")
		}
	}
}

func triggerGetConfig(tickerHandle interface{}) {
	log.Infof("triggerGetConfig()\n")
	flextimer.TickNow(tickerHandle)
}

// Called when globalConfig changes
// Assumes the caller has verifier that the interval has changed
func updateConfigTimer(tickerHandle interface{}) {

	if tickerHandle == nil {
		// Happens if we have a GlobalConfig setting in /persist/
		log.Warnf("updateConfigTimer: no configTickerHandle yet")
		return
	}
	interval := time.Duration(globalConfig.ConfigInterval) * time.Second
	log.Infof("updateConfigTimer() change to %v\n", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(tickerHandle,
		time.Duration(min), time.Duration(max))
	// Force an immediate timout since timer could have decreased
	flextimer.TickNow(tickerHandle)
}

// Start by trying the all the free management ports and then all the non-free
// until one succeeds in communicating with the cloud.
// We use the iteration argument to start at a different point each time.
// Returns a rebootFlag
func getLatestConfig(url string, iteration int, updateInprogress bool,
	getconfigCtx *getconfigContext) bool {

	log.Debugf("getLatestConfig(%s, %d, %v)\n", url, iteration,
		updateInprogress)

	// Did we exceed the time limits?
	timePassed := time.Since(getconfigCtx.lastReceivedConfigFromCloud)

	resetLimit := time.Second * time.Duration(globalConfig.ResetIfCloudGoneTime)
	if timePassed > resetLimit {
		errStr := fmt.Sprintf("Exceeded outage for cloud connectivity %d by %d seconds; rebooting\n",
			resetLimit/time.Second,
			(timePassed-resetLimit)/time.Second)
		log.Errorf(errStr)
		agentlog.RebootReason(errStr)
		shutdownAppsGlobal(getconfigCtx.zedagentCtx)
		execReboot(true)
		return true
	}
	if updateInprogress {
		fallbackLimit := time.Second * time.Duration(globalConfig.FallbackIfCloudGoneTime)
		if timePassed > fallbackLimit {
			errStr := fmt.Sprintf("Exceeded fallback outage for cloud connectivity %d by %d seconds; rebooting\n",
				fallbackLimit/time.Second,
				(timePassed-fallbackLimit)/time.Second)
			log.Errorf(errStr)
			agentlog.RebootReason(errStr)
			shutdownAppsGlobal(getconfigCtx.zedagentCtx)
			execReboot(true)
			return true
		}
	}

	const return400 = false
	resp, contents, cf, err := zedcloud.SendOnAllIntf(zedcloudCtx, url, 0, nil, iteration, return400)
	if err != nil {
		log.Errorf("getLatestConfig failed: %s\n", err)
		if cf {
			log.Errorf("getLatestConfig certificate failure")
		}
		if getconfigCtx.ledManagerCount == 4 {
			// Inform ledmanager about loss of config from cloud
			types.UpdateLedManagerConfig(2)
			getconfigCtx.ledManagerCount = 2
		}
		// If we didn't yet get a config, then look for a file
		// XXX should we try a few times?
		// XXX different policy if updateInProgress? No fallback for now
		if !updateInprogress &&
			!getconfigCtx.readSavedConfig &&
			getconfigCtx.lastReceivedConfigFromCloud == getconfigCtx.startTime {

			config, err := readSavedProtoMessage(checkpointDirname+"/lastconfig", false)
			if err != nil {
				log.Errorf("getconfig: %v\n", err)
				return false
			}
			if config != nil {
				log.Errorf("Using saved config %v\n", config)
				getconfigCtx.readSavedConfig = true
				return inhaleDeviceConfig(config, getconfigCtx,
					true)
			}
		}
		return false
	}
	// now cloud connectivity is good, consider marking partition state as
	// active if it was inprogress
	// XXX down the road we want more diagnostics and validation
	// before we do this.
	if updateInprogress {
		// Wait for a bit to detect an agent crash. Should run for
		// at least N minutes to make sure we don't hit a watchdog.
		timePassed := time.Since(getconfigCtx.startTime)
		successLimit := time.Second *
			time.Duration(globalConfig.MintimeUpdateSuccess)
		ctx := getconfigCtx.zedagentCtx
		curPart := getZbootCurrentPartition(ctx)
		if timePassed < successLimit {
			log.Infof("getLatestConfig, curPart %s inprogress waiting for %d seconds\n", curPart, (successLimit-timePassed)/time.Second)
			ctx.remainingTestTime = successLimit - timePassed
		} else {
			initiateBaseOsZedCloudTestComplete(ctx)
			ctx.remainingTestTime = 0
		}
		// Send updated remainingTestTime to zedcloud
		ctx.TriggerDeviceInfo = true
	}

	if err := validateConfigMessage(url, resp); err != nil {
		log.Errorln("validateConfigMessage: ", err)
		// Inform ledmanager about cloud connectivity
		types.UpdateLedManagerConfig(3)
		getconfigCtx.ledManagerCount = 3
		return false
	}

	changed, config, err := readDeviceConfigProtoMessage(contents)
	if err != nil {
		log.Errorln("readDeviceConfigProtoMessage: ", err)
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
		log.Debugf("Configuration from zedcloud is unchanged\n")
		return false
	}
	return inhaleDeviceConfig(config, getconfigCtx, false)
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
	writeProtoMessage("lastconfig", contents)
}

// XXX for debug we track these
func writeSentMetricsProtoMessage(contents []byte) {
	writeProtoMessage("lastmetrics", contents)
}

// XXX for debug we track these
func writeSentDeviceInfoProtoMessage(contents []byte) {
	writeProtoMessage("lastdeviceinfo", contents)
}

// XXX for debug we track these
func writeSentAppInfoProtoMessage(contents []byte) {
	writeProtoMessage("lastappinfo", contents)
}

func writeProtoMessage(filename string, contents []byte) {
	filename = checkpointDirname + "/" + filename
	err := ioutil.WriteFile(filename, contents, 0744)
	if err != nil {
		log.Fatal("writeReceiveProtoMessage", err)
		return
	}
}

// If the file exists then read the config
// Ignore if if older than StaleConfigTime seconds
func readSavedProtoMessage(filename string, force bool) (*zconfig.EdgeDevConfig, error) {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) && !force {
			return nil, nil
		} else {
			return nil, err
		}
	}
	age := time.Since(info.ModTime())
	staleLimit := time.Second * time.Duration(globalConfig.StaleConfigTime)
	if !force && age > staleLimit {
		errStr := fmt.Sprintf("savedProto too old: age %v limit %d\n",
			age, staleLimit)
		log.Errorln(errStr)
		return nil, nil
	}
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Errorln("readSavedProtoMessage", err)
		return nil, err
	}
	var config = &zconfig.EdgeDevConfig{}

	err = proto.Unmarshal(contents, config)
	if err != nil {
		log.Errorf("readSavedProtoMessage Unmarshalling failed: %v",
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
	log.Debugf("readDeviceConfigProtoMessage: same %v config sha % x vs. % x\n",
		same, prevConfigHash, configHash)
	err := proto.Unmarshal(contents, config)
	if err != nil {
		log.Errorf("Unmarshalling failed: %v", err)
		return false, nil, err
	}
	return !same, config, nil
}

// Returns a rebootFlag
func inhaleDeviceConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext, usingSaved bool) bool {
	log.Debugf("Inhaling config %v\n", config)

	// if they match return
	var devId = &zconfig.UUIDandVersion{}

	devId = config.GetId()
	if devId != nil {
		id, err := uuid.FromString(devId.Uuid)
		if err != nil {
			log.Errorf("Invalid UUID %s from cloud: %s\n",
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
				log.Infof("XXX Device UUID changed from %s to %s\n",
					zcdevUUID.String(), id.String())
				zcdevUUID = id
				ctx := getconfigCtx.zedagentCtx
				ctx.TriggerDeviceInfo = true
			}

		}
	}
	handleLookupParam(getconfigCtx, config)

	// add new BaseOS/App instances; returns rebootFlag
	return parseConfig(config, getconfigCtx, usingSaved)
}
