// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/satori/go.uuid"
)

// This is set once at init time and not changed
var serverName string
var serverNameAndPort string

// Notify simple struct to pass notification messages
type Notify struct{}

type getconfigContext struct {
	zedagentCtx              *zedagentContext    // Cross link
	ledBlinkCount            types.LedBlinkCount // Current count
	configReceived           bool
	configGetStatus          types.ConfigGetStatus
	updateInprogress         bool
	readSavedConfig          bool // Did we already read it?
	configTickerHandle       interface{}
	metricsTickerHandle      interface{}
	localProfileTickerHandle interface{}
	pubDevicePortConfig      pubsub.Publication
	pubPhysicalIOAdapters    pubsub.Publication
	devicePortConfig         types.DevicePortConfig
	pubNetworkXObjectConfig  pubsub.Publication
	subAppInstanceStatus     pubsub.Subscription
	subDomainMetric          pubsub.Subscription
	subProcessMetric         pubsub.Subscription
	subHostMemory            pubsub.Subscription
	subNodeAgentStatus       pubsub.Subscription
	pubZedAgentStatus        pubsub.Publication
	pubAppInstanceConfig     pubsub.Publication
	pubAppNetworkConfig      pubsub.Publication
	subAppNetworkStatus      pubsub.Subscription
	pubBaseOsConfig          pubsub.Publication
	pubBaseOs                pubsub.Publication
	pubDatastoreConfig       pubsub.Publication
	pubNetworkInstanceConfig pubsub.Publication
	pubControllerCert        pubsub.Publication
	pubCipherContext         pubsub.Publication
	subContentTreeStatus     pubsub.Subscription
	pubContentTreeConfig     pubsub.Publication
	subVolumeStatus          pubsub.Subscription
	pubVolumeConfig          pubsub.Publication
	rebootFlag               bool
	lastReceivedConfig       time.Time
	lastProcessedConfig      time.Time
	localProfileServer       string
	profileServerToken       string
	currentProfile           string
	globalProfile            string
	localProfile             string
	localProfileTrigger      chan Notify

	callProcessLocalProfileServerChange bool //did we already call processLocalProfileServerChange

	configRetryUpdateCounter uint32 // received from config
}

// devUUID is set in Run and never changed
var devUUID uuid.UUID

// XXX need to support recreating devices. Remove when zedcloud preserves state
var zcdevUUID uuid.UUID

// Really a constant
var nilUUID uuid.UUID

// current epoch received from controller
var controllerEpoch int64

func handleConfigInit(networkSendTimeout uint32) *zedcloud.ZedCloudContext {

	// get the server name
	bytes, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	serverNameAndPort = strings.TrimSpace(string(bytes))
	serverName = strings.Split(serverNameAndPort, ":")[0]

	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus: deviceNetworkStatus,
		Timeout:          networkSendTimeout,
		NeedStatsFunc:    true,
		Serial:           hardware.GetProductSerial(log),
		SoftSerial:       hardware.GetSoftSerial(log),
		AgentName:        agentName,
	})

	log.Functionf("Configure Get Device Serial %s, Soft Serial %s, Use V2 API %v", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial, zedcloud.UseV2API())

	// XXX need to redo this since the root certificates can change
	err = zedcloud.UpdateTLSConfig(&zedcloudCtx, serverName, nil)
	if err != nil {
		log.Fatal(err)
	}

	zedcloudCtx.DevUUID = devUUID
	zcdevUUID = devUUID
	return &zedcloudCtx
}

// Run a periodic fetch of the config
func configTimerTask(handleChannel chan interface{},
	getconfigCtx *getconfigContext) {

	ctx := getconfigCtx.zedagentCtx
	configUrl := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, devUUID, "config")
	iteration := 0
	rebootFlag := getLatestConfig(configUrl, iteration,
		getconfigCtx)
	if rebootFlag != getconfigCtx.rebootFlag {
		getconfigCtx.rebootFlag = rebootFlag
		triggerPublishDevInfo(ctx)
	}
	publishZedAgentStatus(getconfigCtx)

	configInterval := ctx.globalConfig.GlobalValueInt(types.ConfigInterval)
	interval := time.Duration(configInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	wdName := agentName + "config"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			iteration += 1
			rebootFlag := getLatestConfig(configUrl, iteration, getconfigCtx)
			if rebootFlag != getconfigCtx.rebootFlag {
				getconfigCtx.rebootFlag = rebootFlag
				triggerPublishDevInfo(ctx)
			}
			ctx.ps.CheckMaxTimeTopic(wdName, "getLastestConfig", start,
				warningTime, errorTime)
			publishZedAgentStatus(getconfigCtx)

		case <-stillRunning.C:
			if getconfigCtx.rebootFlag {
				log.Noticef("reboot flag set")
			}
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func triggerGetConfig(tickerHandle interface{}) {
	log.Functionf("triggerGetConfig()")
	flextimer.TickNow(tickerHandle)
}

// Called when globalConfig changes
// Assumes the caller has verifier that the interval has changed
func updateConfigTimer(configInterval uint32, tickerHandle interface{}) {

	if tickerHandle == nil {
		// Happens if we have a GlobalConfig setting in /persist/
		log.Warnf("updateConfigTimer: no configTickerHandle yet")
		return
	}
	interval := time.Duration(configInterval) * time.Second
	log.Functionf("updateConfigTimer() change to %v", interval)
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
func getLatestConfig(url string, iteration int,
	getconfigCtx *getconfigContext) bool {

	log.Tracef("getLatestConfig(%s, %d)", url, iteration)
	ctx := getconfigCtx.zedagentCtx
	const bailOnHTTPErr = false // For 4xx and 5xx HTTP errors we try other interfaces
	// except http.StatusForbidden(which returns error
	// irrespective of bailOnHTTPErr)
	getconfigCtx.configGetStatus = types.ConfigGetFail
	b, cr, err := generateConfigRequest(getconfigCtx)
	if err != nil {
		// XXX	fatal?
		return false
	}
	buf := bytes.NewBuffer(b)
	size := int64(proto.Size(cr))
	resp, contents, rtf, err := zedcloud.SendOnAllIntf(zedcloudCtx, url, size, buf, iteration, bailOnHTTPErr)
	if err != nil {
		newCount := types.LedBlinkConnectingToController
		switch rtf {
		case types.SenderStatusUpgrade:
			log.Functionf("getLatestConfig : Controller upgrade in progress")
		case types.SenderStatusRefused:
			log.Functionf("getLatestConfig : Controller returned ECONNREFUSED")
		case types.SenderStatusCertInvalid:
			log.Warnf("getLatestConfig : Controller certificate invalid time")
		case types.SenderStatusCertMiss:
			log.Functionf("getLatestConfig : Controller certificate miss")
		default:
			log.Errorf("getLatestConfig  failed: %s", err)
		}
		switch rtf {
		case types.SenderStatusUpgrade, types.SenderStatusRefused, types.SenderStatusCertInvalid:
			newCount = types.LedBlinkConnectedToController // Almost connected to controller!
			// Don't treat as upgrade failure
			if getconfigCtx.updateInprogress {
				log.Warnf("remoteTemporaryFailure don't fail update")
				getconfigCtx.configGetStatus = types.ConfigGetTemporaryFail
			}
		case types.SenderStatusCertMiss:
			// trigger to acquire new controller certs from cloud
			triggerControllerCertEvent(ctx)
		}
		if getconfigCtx.ledBlinkCount == types.LedBlinkOnboarded {
			// Inform ledmanager about loss of config from cloud
			utils.UpdateLedManagerConfig(log, newCount)
			getconfigCtx.ledBlinkCount = newCount
		}
		// If we didn't yet get a config, then look for a file
		// XXX should we try a few times?
		// If we crashed we wait until we connect to zedcloud so that
		// keyboard can be enabled and things can be debugged and not
		// have e.g., an OOM reboot loop
		if !ctx.bootReason.StartWithSavedConfig() {
			log.Warnf("Ignore any saved config due to boot reason %s",
				ctx.bootReason)
		} else if !getconfigCtx.readSavedConfig && !getconfigCtx.configReceived {

			config, ts, err := readSavedProtoMessageConfig(
				ctx.globalConfig.GlobalValueInt(types.StaleConfigTime),
				checkpointDirname+"/lastconfig", false)
			if err != nil {
				log.Errorf("getconfig: %v", err)
				return false
			}
			if config != nil {
				log.Noticef("Using saved config dated %s",
					ts.Format(time.RFC3339Nano))
				getconfigCtx.readSavedConfig = true
				getconfigCtx.configGetStatus = types.ConfigGetReadSaved
				return inhaleDeviceConfig(config, getconfigCtx,
					true)
			}
		}
		publishZedAgentStatus(getconfigCtx)
		return false
	}

	if resp.StatusCode == http.StatusForbidden {
		log.Errorf("Config request is forbidden, triggering attestation again")
		restartAttestation(ctx)
		if getconfigCtx.updateInprogress {
			log.Warnf("updateInprogress=true,resp.StatusCode=Forbidden, so marking ConfigGetTemporaryFail")
			getconfigCtx.configGetStatus = types.ConfigGetTemporaryFail
		}
		return false
	}
	if resp.StatusCode == http.StatusNotModified {
		log.Tracef("StatusNotModified len %d", len(contents))
		// Inform ledmanager about config received from cloud
		utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		getconfigCtx.ledBlinkCount = types.LedBlinkOnboarded

		if !getconfigCtx.configReceived {
			getconfigCtx.configReceived = true
		}
		getconfigCtx.configGetStatus = types.ConfigGetSuccess
		publishZedAgentStatus(getconfigCtx)

		log.Tracef("Configuration from zedcloud is unchanged")
		// Update modification time since checked by readSavedProtoMessage
		touchReceivedProtoMessage()
		return false
	}

	if err := validateProtoMessage(url, resp); err != nil {
		log.Errorln("validateProtoMessage: ", err)
		// Inform ledmanager about cloud connectivity
		utils.UpdateLedManagerConfig(log, types.LedBlinkConnectedToController)
		getconfigCtx.ledBlinkCount = types.LedBlinkConnectedToController
		publishZedAgentStatus(getconfigCtx)
		return false
	}

	changed, config, err := readConfigResponseProtoMessage(resp, contents)
	if err != nil {
		log.Errorln("readConfigResponseProtoMessage: ", err)
		// Inform ledmanager about cloud connectivity
		utils.UpdateLedManagerConfig(log, types.LedBlinkConnectedToController)
		getconfigCtx.ledBlinkCount = types.LedBlinkConnectedToController
		publishZedAgentStatus(getconfigCtx)
		return false
	}

	// Inform ledmanager about config received from cloud
	utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
	getconfigCtx.ledBlinkCount = types.LedBlinkOnboarded

	if !getconfigCtx.configReceived {
		getconfigCtx.configReceived = true
	}
	getconfigCtx.configGetStatus = types.ConfigGetSuccess
	publishZedAgentStatus(getconfigCtx)

	if !changed {
		log.Tracef("Configuration from zedcloud is unchanged")
		// Update modification time since checked by readSavedProtoMessage
		touchReceivedProtoMessage()
		return false
	}
	writeReceivedProtoMessage(contents)

	return inhaleDeviceConfig(config, getconfigCtx, false)
}

func validateProtoMessage(url string, r *http.Response) error {
	// No check Content-Type for empty response
	if r.ContentLength == 0 {
		return nil
	}
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

// Update timestamp - no content changes
func touchReceivedProtoMessage() {
	touchProtoMessage("lastconfig")
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
	err := fileutils.WriteRename(filename, contents)
	if err != nil {
		// Can occur if no space in filesystem
		log.Errorf("writeProtoMessage failed: %s", err)
		return
	}
}

// remove saved proto file if exists
func cleanSavedProtoMessage(filename string) {
	filename = checkpointDirname + "/" + filename
	if err := os.Remove(filename); err != nil {
		log.Functionf("cleanSavedProtoMessage failed: %s", err)
	}
}

// Update modification time
func touchProtoMessage(filename string) {
	filename = checkpointDirname + "/" + filename
	_, err := os.Stat(filename)
	if err != nil {
		log.Warnf("touchProtoMessage stat failed: %s", err)
		return
	}
	currentTime := time.Now()
	err = os.Chtimes(filename, currentTime, currentTime)
	if err != nil {
		// Can occur if no space in filesystem?
		log.Errorf("touchProtoMessage failed: %s", err)
	}
}

// If the file exists then read the config, and return is modify time
// Ignore if if older than StaleConfigTime seconds
func readSavedProtoMessageConfig(staleConfigTime uint32,
	filename string, force bool) (*zconfig.EdgeDevConfig, time.Time, error) {
	contents, ts, err := readSavedProtoMessage(staleConfigTime, filename, force)
	if err != nil {
		log.Errorln("readSavedProtoMessageConfig", err)
		return nil, ts, err
	}
	var configResponse = &zconfig.ConfigResponse{}
	err = proto.Unmarshal(contents, configResponse)
	if err != nil {
		log.Errorf("readSavedProtoMessageConfig Unmarshalling failed: %v",
			err)
		return nil, ts, err
	}
	config := configResponse.GetConfig()
	return config, ts, nil
}

// If the file exists then read the proto message from it, and return its modify time
// Ignore if if older than staleTime seconds
func readSavedProtoMessage(staleTime uint32,
	filename string, force bool) ([]byte, time.Time, error) {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) && !force {
			return nil, time.Time{}, nil
		} else {
			return nil, time.Time{}, err
		}
	}
	age := time.Since(info.ModTime())
	staleLimit := time.Second * time.Duration(staleTime)
	if !force && age > staleLimit {
		errStr := fmt.Sprintf("savedProto too old: age %v limit %d\n",
			age, staleLimit)
		log.Errorln(errStr)
		return nil, info.ModTime(), nil
	}
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Errorln("readSavedProtoMessage", err)
		return nil, info.ModTime(), err
	}
	return contents, info.ModTime(), nil
}

// The most recent config hash we received. Starts empty
var prevConfigHash string

func generateConfigRequest(getconfigCtx *getconfigContext) ([]byte, *zconfig.ConfigRequest, error) {
	log.Tracef("generateConfigRequest() sending hash %s", prevConfigHash)
	configRequest := &zconfig.ConfigRequest{
		ConfigHash: prevConfigHash,
	}
	//Populate integrity token if there is one available
	iToken, err := readIntegrityToken()
	if err == nil {
		configRequest.IntegrityToken = iToken
	}
	b, err := proto.Marshal(configRequest)
	if err != nil {
		log.Errorln(err)
		return nil, nil, err
	}
	return b, configRequest, nil
}

// Returns changed, config, error. The changed is based the ConfigRequest vs
// the ConfigResponse hash
func readConfigResponseProtoMessage(resp *http.Response, contents []byte) (bool, *zconfig.EdgeDevConfig, error) {

	var configResponse = &zconfig.ConfigResponse{}
	err := proto.Unmarshal(contents, configResponse)
	if err != nil {
		log.Errorf("Unmarshalling failed: %v", err)
		return false, nil, err
	}
	hash := configResponse.GetConfigHash()
	if hash == prevConfigHash {
		log.Tracef("Same ConfigHash %s len %d", hash, len(contents))
		return false, nil, nil
	}
	log.Tracef("Change in ConfigHash from %s to %s", prevConfigHash, hash)
	prevConfigHash = hash
	config := configResponse.GetConfig()
	return true, config, nil
}

// Returns a rebootFlag
func inhaleDeviceConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext, usingSaved bool) bool {
	log.Tracef("Inhaling config")

	// if they match return
	var devId = &zconfig.UUIDandVersion{}

	devId = config.GetId()
	if devId != nil {
		id, err := uuid.FromString(devId.Uuid)
		if err != nil {
			log.Errorf("Invalid UUID %s from cloud: %s",
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
				log.Functionf("XXX Device UUID changed from %s to %s",
					zcdevUUID.String(), id.String())
				zcdevUUID = id
				ctx := getconfigCtx.zedagentCtx
				triggerPublishDevInfo(ctx)
			}
		}
		newControllerEpoch := config.GetControllerEpoch()
		if controllerEpoch != newControllerEpoch {
			log.Noticef("Controller epoch changed from %d to %d", controllerEpoch, newControllerEpoch)
			controllerEpoch = newControllerEpoch
			triggerPublishAllInfo(getconfigCtx.zedagentCtx)
		}
	}

	// add new BaseOS/App instances; returns rebootFlag
	return parseConfig(config, getconfigCtx, usingSaved)
}

func publishZedAgentStatus(getconfigCtx *getconfigContext) {
	ctx := getconfigCtx.zedagentCtx
	status := types.ZedAgentStatus{
		Name:                 agentName,
		ConfigGetStatus:      getconfigCtx.configGetStatus,
		RebootCmd:            ctx.rebootCmd,
		RebootReason:         ctx.currentRebootReason,
		BootReason:           ctx.currentBootReason,
		MaintenanceMode:      ctx.maintenanceMode,
		ForceFallbackCounter: ctx.forceFallbackCounter,
		CurrentProfile:       getconfigCtx.currentProfile,
	}
	pub := getconfigCtx.pubZedAgentStatus
	pub.Publish(agentName, status)
}
