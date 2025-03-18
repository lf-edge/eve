// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	zauth "github.com/lf-edge/eve-api/go/auth"
	zconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-libs/nettrace"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/pidfile"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

const (
	// Topic for zedagent netdumps of successful config retrievals.
	netDumpConfigOKTopic = agentName + "-config-ok"
	// Topic for zedagent netdumps of failed config retrievals.
	netDumpConfigFailTopic = agentName + "-config-fail"
)

// This is set once at init time and not changed
var serverName string
var serverNameAndPort string

// Notify simple struct to pass notification messages
type Notify struct{}

// localServerAddr contains a source IP and a destination URL (without path)
// to use to connect to a particular local server.
type localServerAddr struct {
	bridgeIP        net.IP
	localServerAddr string
	appUUID         uuid.UUID
}

// localServerMap is a map of all local (profile, radio, ...) servers
type localServerMap struct {
	servers  map[string][]localServerAddr // key = bridge name, value = local servers
	upToDate bool
}

// L2Adapter is used to represent L2 Adapter (VLAN, bond) during configuration parsing.
type L2Adapter struct {
	config         *types.NetworkPortConfig
	lowerL2Ports   []*L2Adapter
	lowerPhysPorts []*types.PhysicalIOAdapter
}

type getconfigContext struct {
	zedagentCtx                *zedagentContext    // Cross link
	ledBlinkCount              types.LedBlinkCount // Current count
	configReceived             bool
	configGetStatus            types.ConfigGetStatus
	updateInprogress           bool
	readSavedConfig            bool // Did we already read it?
	waitDrainInProgress        bool
	configTickerHandle         interface{}
	certTickerHandle           interface{}
	metricsTickerHandle        interface{}
	hardwareHealthTickerHandle interface{}
	locationCloudTickerHandle  interface{}
	locationAppTickerHandle    interface{}
	localProfileTickerHandle   interface{}
	ntpSourcesTickerHandle     interface{}
	pubDevicePortConfig        pubsub.Publication
	pubPhysicalIOAdapters      pubsub.Publication
	devicePortConfig           types.DevicePortConfig
	pubNetworkXObjectConfig    pubsub.Publication
	subAppInstanceStatus       pubsub.Subscription
	subDomainMetric            pubsub.Subscription
	subProcessMetric           pubsub.Subscription
	subHostMemory              pubsub.Subscription
	subNodeAgentStatus         pubsub.Subscription
	pubZedAgentStatus          pubsub.Publication
	pubAppInstanceConfig       pubsub.Publication
	pubAppNetworkConfig        pubsub.Publication
	subAppNetworkStatus        pubsub.Subscription
	pubBaseOsConfig            pubsub.Publication
	pubDatastoreConfig         pubsub.Publication
	pubNetworkInstanceConfig   pubsub.Publication
	pubControllerCert          pubsub.Publication
	pubCipherContext           pubsub.Publication
	subContentTreeStatus       pubsub.Subscription
	pubContentTreeConfig       pubsub.Publication
	subVolumeStatus            pubsub.Subscription
	pubVolumeConfig            pubsub.Publication
	pubDisksConfig             pubsub.Publication
	pubEdgeNodeInfo            pubsub.Publication
	pubPatchEnvelopeInfo       pubsub.Publication
	subPatchEnvelopeStatus     pubsub.Subscription
	subCachedResolvedIPs       pubsub.Subscription
	NodeAgentStatus            *types.NodeAgentStatus
	configProcessingRV         configProcessingRetval
	lastReceivedConfig         time.Time // controller or local clocks
	lastProcessedConfig        time.Time // controller or local clocks
	lastConfigTimestamp        time.Time // controller clocks (zero if not available)
	lastConfigSource           configSource

	// parsed L2 adapters
	vlans []L2Adapter
	bonds []L2Adapter

	// radio-silence
	radioSilence     types.RadioSilence // the intended state of radio devices
	triggerRadioPOST chan Notify

	// Combines both LPS (local profile server) and LOC (local operator console)
	// configurations and structures
	sideController struct {
		sync.Mutex
		localProfileServer        string
		profileServerToken        string
		currentProfile            string
		globalProfile             string
		localProfile              string
		localProfileTrigger       chan Notify
		localServerMap            *localServerMap
		lastDevCmdTimestamp       uint64 // From lastDevCmdTimestampFile
		compoundConfLastTimestamp uint64 // used for compound config acknowledgement
		locConfig                 *types.LOCConfig

		localAppInfoPOSTTicker flextimer.FlexTickerHandle
		localDevInfoPOSTTicker flextimer.FlexTickerHandle

		// When enabled, device location reports are being published to the Local profile server
		// at a significantly decreased rate.
		lpsThrottledLocation     bool
		lpsLastPublishedLocation time.Time

		// localCommands : list of commands requested from a local server.
		// This information is persisted under /persist/checkpoint/localcommands
		localCommands *types.LocalCommands
	}

	configRetryUpdateCounter uint32 // received from config

	// Frequency in seconds at which metrics is published to the controller.
	// This value can be different from 'timer.metric.interval' in the case of
	// timer.metric.interval > currentMetricInterval, until the value of
	// 'timer.metric.interval' has been successfully notified to the controller.
	currentMetricInterval uint32

	configEdgeview *types.EdgeviewConfig // edge-view config save
}

func (ctx *getconfigContext) getCachedResolvedIPs(hostname string) []types.CachedIP {
	if ctx.subCachedResolvedIPs == nil {
		return nil
	}
	if item, err := ctx.subCachedResolvedIPs.Get(hostname); err == nil {
		return item.(types.CachedResolvedIPs).CachedIPs
	}
	return nil
}

// current devUUID from OnboardingStatus
var devUUID uuid.UUID

// Really a constant
var nilUUID uuid.UUID

// current epoch received from controller
var controllerEpoch int64

type configSource int

const (
	fromController configSource = iota
	savedConfig
	fromBootstrap
)

func (s configSource) String() string {
	switch s {
	case fromController:
		return "from-controller"
	case fromBootstrap:
		return "from-bootstrap"
	case savedConfig:
		return "saved-config"
	}
	return "<invalid>"
}

// return value used by getLatestConfig, inhaleDeviceConfig and parseConfig
type configProcessingRetval int

const (
	configOK         configProcessingRetval = iota
	configReqFailed                         // failed to request latest config
	obsoleteConfig                          // newer config is already applied
	invalidConfig                           // config is not valid (cannot be parsed, UUID mismatch, bad signature, etc.)
	skipConfigReboot                        // reboot or shutdown flag is set
	skipConfigUpdate                        // update flag is set
	deferConfig                             // not ready to process config yet
)

func (r configProcessingRetval) isSkip() bool {
	return r == skipConfigReboot || r == skipConfigUpdate
}

func (r configProcessingRetval) String() string {
	switch r {
	case configOK:
		return "configOK"
	case configReqFailed:
		return "configReqFailed"
	case obsoleteConfig:
		return "obsoleteConfig"
	case invalidConfig:
		return "invalidConfig"
	case skipConfigReboot:
		return "skipConfigReboot"
	case skipConfigUpdate:
		return "skipConfigUpdate"
	case deferConfig:
		return "deferConfig"
	}
	return "<invalid>"
}

// Load bootstrap config provided that:
//   - it exists
//   - has not been loaded before (incl. previous device boots)
//   - has valid controller signature
//
// The function will only load and publish global config items (publishes default values
// if empty set is configured) and items related to networking (system adapters, networks,
// vlans, bonds, etc.).
func maybeLoadBootstrapConfig(getconfigCtx *getconfigContext) {
	//  Check if bootstrap config has been already loaded.
	if !fileutils.FileExists(log, types.BootstrapConfFileName) {
		// No bootstrap config to read
		return
	}
	changed, configSha, err := fileutils.CompareSha(
		types.BootstrapConfFileName, types.BootstrapShaFileName)
	if err != nil {
		log.Errorf("CompareSha failed for bootstrap config: %s", err)
		// We will not record SHA for applied bootstrap config
		// and as a result load it again with the next boot.
		// However, with config timestamp preventing accidental revert
		// to an older configuration, this should not be a problem.
		configSha = nil
	} else if !changed {
		// This bootstrap config was already applied.
		return
	}

	// Load file content.
	contents, err := os.ReadFile(types.BootstrapConfFileName)
	if err != nil {
		log.Errorf("Failed to read bootstrap config: %v", err)
		indicateInvalidBootstrapConfig(getconfigCtx)
		return
	}

	// Mark bootstrap config as processed by storing SHA hash of its content
	// under /persist/ingested/ directory.
	// We do this even even if the unmarshalling (or anything else) below fails.
	// This is to avoid repeated failing attempts to load invalid config on each boot.
	defer func() {
		if configSha != nil {
			err := fileutils.SaveShaInFile(types.BootstrapShaFileName, configSha)
			if err != nil {
				log.Errorf("Failed to save SHA of bootstrap config: %v", err)
			}
		}
	}()

	// Unmarshal BootstrapConfig.
	bootstrap := zconfig.BootstrapConfig{}
	err = proto.Unmarshal(contents, &bootstrap)
	if err != nil {
		log.Errorf("Failed to unmarshal bootstrap config: %v", err)
		indicateInvalidBootstrapConfig(getconfigCtx)
		return
	}

	// Verify controller certificate chain.
	sigCertBytes, err := zedcloud.VerifySigningCertChain(log, bootstrap.ControllerCerts)
	if err != nil {
		log.Errorf("Controller cert chain verification failed for bootstrap config: %v", err)
		indicateInvalidBootstrapConfig(getconfigCtx)
		return
	}

	// Verify payload signature
	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{})
	if err = zedcloud.LoadServerSigningCert(&zedcloudCtx, sigCertBytes); err != nil {
		log.Errorf("Failed to load signing server cert from bootstrap config: %v", err)
		indicateInvalidBootstrapConfig(getconfigCtx)
		return
	}
	_, err = zedcloud.VerifyAuthContainer(&zedcloudCtx, bootstrap.SignedConfig)
	if err != nil {
		log.Errorf("Signature verification failed for bootstrap config: %v", err)
		indicateInvalidBootstrapConfig(getconfigCtx)
		return
	}

	// Unmarshal EdgeDevConfig from the payload of AuthContainer.
	devConfig := zconfig.EdgeDevConfig{}
	payload := bootstrap.SignedConfig.GetProtectedPayload().GetPayload()
	if payload == nil {
		log.Error("Bootstrap config payload is nil")
		indicateInvalidBootstrapConfig(getconfigCtx)
		return
	}
	err = proto.Unmarshal(payload, &devConfig)
	if err != nil {
		log.Errorf("Failed to unmarshal bootstrap config payload: %v", err)
		return
	}

	// Apply bootstrap config.
	retVal := inhaleDeviceConfig(getconfigCtx, &devConfig, fromBootstrap)
	switch retVal {
	case configOK:
		log.Notice("Bootstrap config was applied")
	case invalidConfig:
		log.Error("Bootstrap config is invalid")
	case obsoleteConfig:
		log.Error("Bootstrap config is obsolete")
	}
}

func indicateInvalidBootstrapConfig(getconfigCtx *getconfigContext) {
	utils.UpdateLedManagerConfig(log, types.LedBlinkInvalidBootstrapConfig)
	getconfigCtx.ledBlinkCount = types.LedBlinkInvalidBootstrapConfig
}

func initZedcloudContext(getconfigCtx *getconfigContext,
	networkSendTimeout, networkDialTimeout uint32,
	agentMetrics *zedcloud.AgentMetrics) *zedcloud.ZedCloudContext {

	// get the server name
	var bytes []byte
	var err error
	for len(bytes) == 0 {
		bytes, err = os.ReadFile(types.ServerFileName)
		if err != nil {
			log.Error(err)
			time.Sleep(10 * time.Second)
		} else if len(bytes) == 0 {
			log.Warnf("Empty %s file - waiting for it",
				types.ServerFileName)
			time.Sleep(10 * time.Second)
		}
	}
	serverNameAndPort = strings.TrimSpace(string(bytes))

	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus:  deviceNetworkStatus,
		SendTimeout:       networkSendTimeout,
		DialTimeout:       networkDialTimeout,
		AgentMetrics:      agentMetrics,
		Serial:            hardware.GetProductSerial(log),
		SoftSerial:        hardware.GetSoftSerial(log),
		AgentName:         agentName,
		ResolverCacheFunc: getconfigCtx.getCachedResolvedIPs,
		// Enable all net traces but packet capture, which is already covered
		// by NIM (for the ping request).
		NetTraceOpts: []nettrace.TraceOpt{
			&nettrace.WithLogging{
				CustomLogger: &base.LogrusWrapper{Log: log},
			},
			&nettrace.WithConntrack{},
			&nettrace.WithSockTrace{},
			&nettrace.WithDNSQueryTrace{},
			&nettrace.WithHTTPReqTrace{
				// Hide secrets stored inside values of header fields.
				HeaderFields: nettrace.HdrFieldsOptValueLenOnly,
			},
		},
	})

	log.Functionf("Configure Get Device Serial %s, Soft Serial %s, Use V2 API %v", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial, zedcloud.UseV2API())

	// XXX need to redo this since the root certificates can change
	err = zedcloud.UpdateTLSConfig(&zedcloudCtx, nil)
	if err != nil {
		log.Fatal(err)
	}

	zedcloudCtx.DevUUID = devUUID
	return &zedcloudCtx
}

// Run a periodic fetch of the config
func configTimerTask(getconfigCtx *getconfigContext, handleChannel chan interface{}) {
	ctx := getconfigCtx.zedagentCtx
	iteration := 0
	withNetTracing := traceNextConfigReq(ctx)
	retVal, tracedReqs := getLatestConfig(getconfigCtx, iteration, withNetTracing)
	if getconfigCtx.configProcessingRV != retVal {
		getconfigCtx.configProcessingRV = retVal
		triggerPublishDevInfo(ctx)
	}
	getconfigCtx.sideController.localServerMap.upToDate = false
	publishZedAgentStatus(getconfigCtx)
	if withNetTracing {
		publishConfigNetdump(ctx, retVal, tracedReqs)
	}

	configInterval := ctx.globalConfig.GlobalValueInt(types.ConfigInterval)
	interval := time.Duration(configInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	// ticker for periodical info publish around 10 min when no real change
	interval2 := time.Duration(600) * time.Second
	max2 := float64(interval2) * 1.2
	min2 := float64(interval2) * 0.8
	tickerInfo := flextimer.NewRangeTicker(time.Duration(min2),
		time.Duration(max2))

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
			withNetTracing = traceNextConfigReq(ctx)
			retVal, tracedReqs = getLatestConfig(
				getconfigCtx, iteration, withNetTracing)
			if getconfigCtx.configProcessingRV != retVal {
				getconfigCtx.configProcessingRV = retVal
				triggerPublishDevInfo(ctx)
			}
			getconfigCtx.sideController.localServerMap.upToDate = false
			ctx.ps.CheckMaxTimeTopic(wdName, "getLastestConfig", start,
				warningTime, errorTime)
			publishZedAgentStatus(getconfigCtx)
			if withNetTracing {
				publishConfigNetdump(ctx, retVal, tracedReqs)
			}

		case <-tickerInfo.C:
			start := time.Now()
			triggerPublishDevInfo(ctx)
			ctx.ps.CheckMaxTimeTopic(wdName, "publishInfoTimer", start,
				warningTime, errorTime)

		case <-stillRunning.C:
			if getconfigCtx.configProcessingRV != configOK {
				log.Noticef("config processing flag is not OK: %s", getconfigCtx.configProcessingRV)
			}
			if ctx.publishedEdgeNodeCerts && !ctx.publishedAttestEscrow {
				log.Warning("Not yet published AttestEscrow")
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
	// Force an immediate timeout since timer could have decreased
	flextimer.TickNow(tickerHandle)
}

// Called when globalConfig changes
// Assumes the caller has verified that the interval has changed
func updateCertTimer(configInterval uint32, tickerHandle interface{}) {

	if tickerHandle == nil {
		// Happens if we have a GlobalConfig setting in /persist/
		log.Warnf("updateConfigTimer: no certTickerHandle yet")
		return
	}
	interval := time.Duration(configInterval) * time.Second
	log.Functionf("updateCertTimer() change to %v", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(tickerHandle,
		time.Duration(min), time.Duration(max))
	// Force an immediate timeout since timer could have decreased
	flextimer.TickNow(tickerHandle)
}

func decryptAuthContainer(getconfigCtx *getconfigContext, sendRV *zedcloud.SendRetval) error {
	decryptCtx := &cipher.DecryptCipherContext{
		Log:                  log,
		AgentName:            agentName,
		PubSubControllerCert: getconfigCtx.pubControllerCert,
		PubSubEdgeNodeCert:   getconfigCtx.zedagentCtx.subEdgeNodeCert,
	}
	sm := &zauth.AuthContainer{}
	err := proto.Unmarshal(sendRV.RespContents, sm)
	if err != nil {
		return err
	}
	cipherBlock := sm.GetCipherData()
	if cipherBlock == nil {
		// Nothing encrypted, nothing to do
		return nil
	}
	// Verify auth container header and propagate the certificate
	// errors to the caller by updating the retval status. That is
	// utterly important that a caller schedules certs update in
	// that case.
	status, err := zedcloud.VerifyAuthContainerHeader(zedcloudCtx, sm)
	if err != nil {
		sendRV.Status = status
		return err
	}
	cipherContext := sm.GetCipherContext()
	if cipherContext == nil {
		err := errors.New("cipher context is undefined\n")
		return err
	}
	if len(cipherBlock.CipherData) == 0 ||
		len(cipherBlock.CipherContextId) == 0 {
		err := errors.New("cipher block data or context id are incorrect\n")
		return err
	}
	if cipherContext.ContextId != cipherBlock.CipherContextId {
		err := errors.New("cipher context ids do not match\n")
		return err
	}
	cipherCtx := &types.CipherContext{
		ContextID:          cipherContext.GetContextId(),
		HashScheme:         cipherContext.GetHashScheme(),
		KeyExchangeScheme:  cipherContext.GetKeyExchangeScheme(),
		EncryptionScheme:   cipherContext.GetEncryptionScheme(),
		DeviceCertHash:     cipherContext.GetDeviceCertHash(),
		ControllerCertHash: cipherContext.GetControllerCertHash(),
	}
	cipherBlockSt := types.CipherBlockStatus{
		// No unique key is needed here, because this status is never published
		CipherBlockID:   "cipher-block",
		CipherContextID: cipherBlock.GetCipherContextId(),
		InitialValue:    cipherBlock.GetInitialValue(),
		CipherData:      cipherBlock.GetCipherData(),
		ClearTextHash:   cipherBlock.GetClearTextSha256(),
		CipherContext:   cipherCtx,
		IsCipher:        true,
	}
	clearBytes, err := cipher.DecryptCipherBlock(decryptCtx, cipherBlockSt)
	if err != nil {
		return err
	}

	// Restore payload with decrypted bytes
	sm.ProtectedPayload = &zauth.AuthBody{
		Payload: clearBytes,
	}
	sm.CipherContext = nil
	sm.CipherData = nil

	bytes, err := proto.Marshal(sm)
	if err != nil {
		return err
	}

	// Restore contents
	sendRV.RespContents = bytes

	return nil
}

// Start by trying the all the free management ports and then all the non-free
// until one succeeds in communicating with the cloud.
// We use the iteration argument to start at a different point each time.
// Returns the configProcessingRetval and the traced requests if any.
func requestConfigByURL(getconfigCtx *getconfigContext, url string,
	isCompoundConfig bool, iteration int, withNetTracing bool) (
	configProcessingRetval, []netdump.TracedNetRequest) {

	log.Tracef("getLatestConfig(%s, %d)", url, iteration)
	ctx := getconfigCtx.zedagentCtx
	const bailOnHTTPErr = false // For 4xx and 5xx HTTP errors we try other interfaces
	// except http.StatusForbidden(which returns error
	// irrespective of bailOnHTTPErr)
	getconfigCtx.configGetStatus = types.ConfigGetFail
	b, err := generateConfigRequest(getconfigCtx, isCompoundConfig)
	if err != nil {
		log.Fatal(err)
	}
	buf := bytes.NewBuffer(b)
	size := int64(buf.Len())
	ctxWork, cancel := zedcloud.GetContextForAllIntfFunctions(zedcloudCtx)
	defer cancel()
	rv, err := zedcloud.SendOnAllIntf(
		ctxWork, zedcloudCtx, url, size, buf, iteration, bailOnHTTPErr, withNetTracing)
	if err != nil {
		newCount := types.LedBlinkConnectingToController
		switch rv.Status {
		case types.SenderStatusUpgrade:
			log.Functionf("getLatestConfig : Controller upgrade in progress")
		case types.SenderStatusRefused:
			log.Functionf("getLatestConfig : Controller returned ECONNREFUSED")
		case types.SenderStatusCertInvalid:
			log.Warnf("getLatestConfig : Controller certificate invalid time")
		case types.SenderStatusCertMiss:
			log.Warnf("getLatestConfig : Controller certificate miss")
		case types.SenderStatusNotFound:
			log.Noticef("getLatestConfig : Device deleted in controller?")
		case types.SenderStatusForbidden:
			log.Warnf("getLatestConfig : Device integrity token mismatch")
		default:
			log.Errorf("getLatestConfig  failed: %s", err)
		}
		switch rv.Status {
		case types.SenderStatusCertInvalid:
			// trigger to acquire new controller certs from cloud
			log.Noticef("%s trigger", rv.Status.String())
			triggerControllerCertEvent(ctx)
			fallthrough
		case types.SenderStatusUpgrade, types.SenderStatusRefused, types.SenderStatusNotFound:
			newCount = types.LedBlinkConnectedToController // Almost connected to controller!
			// Don't treat as upgrade failure
			if getconfigCtx.updateInprogress {
				log.Warnf("remoteTemporaryFailure don't fail update")
				getconfigCtx.configGetStatus = types.ConfigGetTemporaryFail
			}
		case types.SenderStatusCertMiss:
			// trigger to acquire new controller certs from cloud
			log.Noticef("%s trigger", rv.Status.String())
			triggerControllerCertEvent(ctx)
		}
		if getconfigCtx.ledBlinkCount == types.LedBlinkOnboarded {
			// Inform ledmanager about loss of config from cloud
			utils.UpdateLedManagerConfig(log, newCount)
			getconfigCtx.ledBlinkCount = newCount
		}
		if rv.Status == types.SenderStatusNotFound {
			potentialUUIDUpdate(getconfigCtx)
		}
		if rv.Status == types.SenderStatusForbidden &&
			ctx.attestationTryCount > 0 {
			log.Errorf("Config request is forbidden, triggering attestation again")
			_ = restartAttestation(ctx)
			if getconfigCtx.updateInprogress {
				log.Warnf("updateInprogress=true,resp.StatusCode=Forbidden, so marking ConfigGetTemporaryFail")
				getconfigCtx.configGetStatus = types.ConfigGetTemporaryFail
			}
		}

		if !getconfigCtx.readSavedConfig && !getconfigCtx.configReceived {
			// If we didn't yet get a config, then look for a file
			// XXX should we try a few times?
			// If we crashed we wait until we connect to zedcloud so that
			// keyboard can be enabled and things can be debugged and not
			// have e.g., an OOM reboot loop
			if !ctx.bootReason.StartWithSavedConfig() {
				log.Warnf("Ignore any saved config due to boot reason %s",
					ctx.bootReason)
			} else {
				config, ts, err := readSavedProtoMessageConfig(
					zedcloudCtx, url, checkpointDirname+"/lastconfig")
				if err != nil {
					log.Errorf("getconfig: %v", err)
					return invalidConfig, rv.TracedReqs
				}
				if config != nil {
					log.Noticef("Using saved config dated %s",
						ts.Format(time.RFC3339Nano))

					cfgRetval := inhaleDeviceConfig(getconfigCtx, config, savedConfig)
					if cfgRetval != configOK {
						log.Errorf("inhaleDeviceConfig failed: %d", cfgRetval)
						return cfgRetval, rv.TracedReqs
					}

					getconfigCtx.readSavedConfig = true
					getconfigCtx.configGetStatus = types.ConfigGetReadSaved

					return configOK, rv.TracedReqs
				}
			}
		}
		publishZedAgentStatus(getconfigCtx)
		return configReqFailed, rv.TracedReqs
	}

	if rv.HTTPResp.StatusCode == http.StatusNotModified {
		log.Tracef("StatusNotModified len %d", len(rv.RespContents))
		// Inform ledmanager about config received from cloud
		utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
		getconfigCtx.ledBlinkCount = types.LedBlinkOnboarded

		if !getconfigCtx.configReceived {
			getconfigCtx.configReceived = true
		}
		getconfigCtx.configGetStatus = types.ConfigGetSuccess
		publishZedAgentStatus(getconfigCtx)

		log.Tracef("Configuration from zedcloud is unchanged")
		// Update modification time since checked by readSavedConfig
		touchReceivedProtoMessage()
		return configOK, rv.TracedReqs
	}

	if err := zedcloud.ValidateProtoContentType(url, rv.HTTPResp); err != nil {
		log.Errorln("validateProtoMessage: ", err)
		// Inform ledmanager about cloud connectivity
		utils.UpdateLedManagerConfig(log, types.LedBlinkConnectedToController)
		getconfigCtx.ledBlinkCount = types.LedBlinkConnectedToController
		publishZedAgentStatus(getconfigCtx)
		return invalidConfig, rv.TracedReqs
	}

	var compoundConfig zconfig.CompoundEdgeDevConfig
	if isCompoundConfig {
		// Parse compound config and update the rv.RespContents with
		// auth container stream for further processing
		err = parseCompoundDeviceConfig(getconfigCtx, &rv, &compoundConfig)
		if err != nil {
			log.Errorln("parseCompoundDeviceConfig: ", err)
			// Inform ledmanager about cloud connectivity
			utils.UpdateLedManagerConfig(log, types.LedBlinkConnectedToController)
			getconfigCtx.ledBlinkCount = types.LedBlinkConnectedToController
			publishZedAgentStatus(getconfigCtx)
			return invalidConfig, rv.TracedReqs
		}
		// Decrypts auth container envelope if it is encrypted
		err = decryptAuthContainer(getconfigCtx, &rv)
		if err != nil {
			log.Errorf("decryptAuthContainer: %s", err)
		}
	}

	// Copy of retval with auth container stream
	var authWrappedRV zedcloud.SendRetval

	if err == nil {
		// Success path for both cases: generic config or compound decrypted
		// config. Store auth container stream for further saving it into the
		// file.
		authWrappedRV = rv
		err = zedcloud.RemoveAndVerifyAuthContainer(zedcloudCtx, &rv, false)
		if err != nil {
			log.Errorf("RemoveAndVerifyAuthContainer: %s", err)
		}
	}
	if err != nil {
		// Handles decrypt or verification error
		switch rv.Status {
		case types.SenderStatusCertMiss, types.SenderStatusCertInvalid:
			// trigger to acquire new controller certs from cloud
			log.Noticef("%s trigger", rv.Status.String())
			triggerControllerCertEvent(ctx)
		}
		// Inform ledmanager about problem
		utils.UpdateLedManagerConfig(log, types.LedBlinkInvalidAuthContainer)
		getconfigCtx.ledBlinkCount = types.LedBlinkInvalidAuthContainer
		publishZedAgentStatus(getconfigCtx)
		return invalidConfig, rv.TracedReqs
	}

	changed, config, err := readConfigResponseProtoMessage(rv.HTTPResp, rv.RespContents)
	if err != nil {
		log.Errorln("readConfigResponseProtoMessage: ", err)
		// Inform ledmanager about cloud connectivity
		utils.UpdateLedManagerConfig(log, types.LedBlinkConnectedToController)
		getconfigCtx.ledBlinkCount = types.LedBlinkConnectedToController
		publishZedAgentStatus(getconfigCtx)
		return invalidConfig, rv.TracedReqs
	}

	cfgRetval := configOK
	if !changed {
		log.Tracef("Configuration from zedcloud is unchanged")
		// Update modification time since checked by readSavedConfig
		touchReceivedProtoMessage()
		goto cfgReceived
	}

	cfgRetval = inhaleDeviceConfig(getconfigCtx, config, fromController)
	if cfgRetval != configOK {
		log.Errorf("inhaleDeviceConfig failed: %d", cfgRetval)
		return cfgRetval, rv.TracedReqs
	}

	// Inform ledmanager about config received from cloud
	utils.UpdateLedManagerConfig(log, types.LedBlinkOnboarded)
	getconfigCtx.ledBlinkCount = types.LedBlinkOnboarded

	getconfigCtx.configGetStatus = types.ConfigGetSuccess
	publishZedAgentStatus(getconfigCtx)

	// Save configuration wrapped in AuthContainer.
	saveReceivedProtoMessage(authWrappedRV.RespContents)

cfgReceived:
	getconfigCtx.configReceived = true

	if isCompoundConfig {
		// No errors are propagated up to the caller, the main
		// config was applied successfully, all possible errors
		// from the auxiliary members from the compound config
		// are ignored.
		inhaleCompoundDeviceConfig(getconfigCtx, &compoundConfig)
	}

	return configOK, rv.TracedReqs
}

// Returns true if attempt to get a configuration has failed, but initial
// configuration was received (either from the controller, either successfully
// read from the file)
func needRequestLocConfig(getconfigCtx *getconfigContext,
	rv configProcessingRetval) bool {

	return (rv != configOK && getconfigCtx.sideController.locConfig != nil)
}

func getLatestConfig(getconfigCtx *getconfigContext, iteration int,
	withNetTracing bool) (configProcessingRetval, []netdump.TracedNetRequest) {

	url := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "config")

	rv, tracedReqs := requestConfigByURL(getconfigCtx, url, false,
		iteration, withNetTracing)

	// Request configuration from the LOC
	if needRequestLocConfig(getconfigCtx, rv) {
		locURL := getconfigCtx.sideController.locConfig.LocURL
		url = zedcloud.URLPathString(locURL, zedcloudCtx.V2API,
			devUUID, "compound-config")

		// Request compound config, if LOC configuration is outdated, then we
		// get @obsoleteConfig return value (see parseConfig() for details)
		// and we repeat on the next fetch attempt
		rv, tracedReqs = requestConfigByURL(getconfigCtx, url, true,
			iteration, withNetTracing)
	}

	return rv, tracedReqs
}

func saveReceivedProtoMessage(contents []byte) {
	saveConfig("lastconfig", contents)
}

// Update timestamp - no content changes
func touchReceivedProtoMessage() {
	touchSavedConfig("lastconfig")
}

// XXX for debug we track these
func saveSentMetricsProtoMessage(contents []byte) {
	saveConfig("lastmetrics", contents)
}

// XXX for debug we track these
func saveSentHardwareHealthProtoMessage(contents []byte) {
	saveConfig("lasthardwarehealth", contents)
}

// XXX for debug we track these
func saveSentDeviceInfoProtoMessage(contents []byte) {
	saveConfig("lastdeviceinfo", contents)
}

// XXX for debug we track these
func saveSentAppInfoProtoMessage(contents []byte) {
	saveConfig("lastappinfo", contents)
}

func saveConfig(filename string, contents []byte) {
	filename = checkpointDirname + "/" + filename
	err := fileutils.WriteRename(filename, contents)
	if err != nil {
		// Can occur if no space in filesystem
		log.Errorf("saveConfig failed: %s", err)
		return
	}
}

// Remove saved config file if it exists.
func cleanSavedConfig(filename string) {
	filename = checkpointDirname + "/" + filename
	if err := os.Remove(filename); err != nil {
		log.Functionf("cleanSavedConfig failed: %s", err)
	}
}

// Update modification time
func touchSavedConfig(filename string) {
	filename = checkpointDirname + "/" + filename
	_, err := os.Stat(filename)
	if err != nil {
		log.Warnf("touchSavedConfig stat failed: %s", err)
	}
	currentTime := time.Now()
	err = os.Chtimes(filename, currentTime, currentTime)
	if err != nil {
		// Can occur if no space in filesystem?
		log.Errorf("touchSavedConfig failed: %s", err)
	}
}

// Check if SavedConfig exists
func existsSavedConfig(filename string) bool {
	filename = filepath.Join(checkpointDirname, filename)
	_, err := os.Stat(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("existsSavedConfig: cannot stat %s: %s", filename, err)
		}
		return false
	}
	return true
}

// If the file exists then read the config, and return is modify time
// Ignore if older than StaleConfigTime seconds
func readSavedProtoMessageConfig(zedcloudCtx *zedcloud.ZedCloudContext, URL string,
	filename string) (*zconfig.EdgeDevConfig, time.Time, error) {
	contents, ts, err := readSavedConfig(filename)
	if err != nil {
		log.Errorln("readSavedProtoMessageConfig", err)
		return nil, ts, err
	}
	restoredSendRV := zedcloud.SendRetval{
		ReqURL:       URL,
		RespContents: contents,
		// Other fields are not needed to restore for RemoveAndVerifyAuthContainer().
	}
	err = zedcloud.RemoveAndVerifyAuthContainer(
		zedcloudCtx, &restoredSendRV, false)
	if err != nil {
		log.Errorf("RemoveAndVerifyAuthContainer failed: %s", err)
		return nil, ts, err
	}
	var configResponse = &zconfig.ConfigResponse{}
	err = proto.Unmarshal(restoredSendRV.RespContents, configResponse)
	if err != nil {
		log.Errorf("readSavedProtoMessageConfig Unmarshalling failed: %v",
			err)
		return nil, ts, err
	}
	config := configResponse.GetConfig()
	return config, ts, nil
}

// If the file exists then read the config content from it, and return its modify time.
func readSavedConfig(filename string) ([]byte, time.Time, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, time.Time{}, err
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		log.Errorln("readSavedConfig", err)
		return nil, info.ModTime(), err
	}
	return contents, info.ModTime(), nil
}

// The most recent config hash we received. Starts empty
var prevConfigHash string

func generateConfigRequest(getconfigCtx *getconfigContext, isCompoundConfig bool) (
	[]byte, error) {
	log.Tracef("generateConfigRequest() sending hash %s", prevConfigHash)
	configRequest := &zconfig.ConfigRequest{
		ConfigHash: prevConfigHash,
	}
	//Populate integrity token if there is one available
	iToken, err := readIntegrityToken()
	if err == nil {
		configRequest.IntegrityToken = iToken
	}
	var b []byte
	if isCompoundConfig {
		compoundRequest := &zconfig.CompoundEdgeDevConfigRequest{
			LastCmdTimestamp: getconfigCtx.sideController.compoundConfLastTimestamp,
			CfgReq:           configRequest,
		}
		b, err = proto.Marshal(compoundRequest)
	} else {
		b, err = proto.Marshal(configRequest)
	}
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	return b, nil
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

func inhaleDeviceConfig(getconfigCtx *getconfigContext, config *zconfig.EdgeDevConfig,
	source configSource) configProcessingRetval {
	log.Tracef("Inhaling config")

	// if they match return
	var devId = &zconfig.UUIDandVersion{}

	devId = config.GetId()
	if devId != nil {
		id, err := uuid.FromString(devId.Uuid)
		if err != nil {
			log.Errorf("Invalid UUID %s from cloud: %s",
				devId.Uuid, err)
			return invalidConfig
		}
		initialBootstrap := source == fromBootstrap && devUUID == nilUUID
		if !initialBootstrap && id != devUUID {
			log.Warnf("Device UUID changed from %s to %s",
				devUUID.String(), id.String())
			potentialUUIDUpdate(getconfigCtx)
			return invalidConfig
		}
		newControllerEpoch := config.GetControllerEpoch()
		if controllerEpoch != newControllerEpoch {
			log.Noticef("Controller epoch changed from %d to %d", controllerEpoch, newControllerEpoch)
			controllerEpoch = newControllerEpoch
			triggerPublishAllInfo(getconfigCtx.zedagentCtx, AllDest)
		}
	}

	// add new BaseOS/App instances; returns configProcessingSkipFlagReboot
	return parseConfig(getconfigCtx, config, source)
}

func parseCompoundDeviceConfig(getconfigCtx *getconfigContext,
	rv *zedcloud.SendRetval,
	compoundConfig *zconfig.CompoundEdgeDevConfig) error {

	err := proto.Unmarshal(rv.RespContents, compoundConfig)
	if err != nil {
		return err
	}
	authContainer := compoundConfig.GetProtectedConfig()
	if authContainer == nil {
		return fmt.Errorf("Incorrect compound config received: protected config is not defined!")
	}
	// Restore stream of contents by marshalling and assigning the auth
	// container. This is needed, because all internal processing functions
	// expect auth container.
	bytes, err := proto.Marshal(authContainer)
	if err != nil {
		return err
	}
	rv.RespContents = bytes

	return nil
}

func inhaleCompoundDeviceConfig(getconfigCtx *getconfigContext,
	compoundConfig *zconfig.CompoundEdgeDevConfig) {

	appCmdList := compoundConfig.GetAppCmdList()
	if appCmdList != nil {
		processReceivedAppCommands(getconfigCtx, appCmdList)
	}
	devCmd := compoundConfig.GetDevCmd()
	if devCmd != nil {
		processReceivedDevCommands(getconfigCtx, devCmd)
	}

	// Acknowledge the config has been processed
	getconfigCtx.sideController.compoundConfLastTimestamp =
		compoundConfig.Timestamp
}

var (
	lastDevUUIDChange       = time.Now()
	potentialUUIDUpdateLock sync.Mutex
)

// When we think (due to 404) or know that the controller has changed our UUID,
// ask client to get it so OnboardingStatus can be updated and notified to all agents
// The controller might do this due to a delete and re-onboard with the same device
// certificate.
// We ask client at most every 10 minutes.
// We check that another zedclient instance is not running
func potentialUUIDUpdate(_ *getconfigContext) {
	potentialUUIDUpdateLock.Lock()
	if time.Since(lastDevUUIDChange) < 10*time.Minute {
		log.Warnf("Device UUID last changed %v ago",
			time.Since(lastDevUUIDChange))
		potentialUUIDUpdateLock.Unlock()
		return
	}
	if exists, description := pidfile.CheckProcessExists(log, "zedclient"); exists {
		log.Warnf("another process is still running: %s", description)
		potentialUUIDUpdateLock.Unlock()
		return
	}
	lastDevUUIDChange = time.Now()
	// after time updated we can unlock mutex to go into time check from other routine
	potentialUUIDUpdateLock.Unlock()
	cmd := "/opt/zededa/bin/client"
	cmdArgs := []string{"getUuid"}
	log.Noticef("Calling command %s %v", cmd, cmdArgs)
	out, err := base.Exec(log, cmd, cmdArgs...).CombinedOutput()
	if err != nil {
		log.Errorf("client command %s failed %s output %s",
			cmdArgs, err, out)
	}
}

func publishZedAgentStatus(getconfigCtx *getconfigContext) {
	ctx := getconfigCtx.zedagentCtx
	status := types.ZedAgentStatus{
		Name:                  agentName,
		ConfigGetStatus:       getconfigCtx.configGetStatus,
		RebootCmd:             ctx.rebootCmd,
		ShutdownCmd:           ctx.shutdownCmd,
		PoweroffCmd:           ctx.poweroffCmd,
		RequestedRebootReason: ctx.requestedRebootReason,
		RequestedBootReason:   ctx.requestedBootReason,
		MaintenanceMode:       ctx.maintenanceMode,
		ForceFallbackCounter:  ctx.forceFallbackCounter,
		CurrentProfile:        getconfigCtx.sideController.currentProfile,
		RadioSilence:          getconfigCtx.radioSilence,
		DeviceState:           ctx.devState,
		AttestState:           ctx.attestState,
		AttestError:           ctx.attestError,
		VaultStatus:           ctx.vaultStatus,
		PCRStatus:             ctx.pcrStatus,
		VaultErr:              ctx.vaultErr,
	}
	pub := getconfigCtx.pubZedAgentStatus
	pub.Publish(agentName, status)
}

// updateLocalServerMap processes configuration of network instances to locate all local servers matching
// the given localServerURL.
// Returns the source IP and a normalized URL for one or more network instances on which the local server
// was found to be hosted.
func updateLocalServerMap(getconfigCtx *getconfigContext, localServerURL string) error {
	url, err := url.Parse(localServerURL)
	if err != nil {
		return fmt.Errorf("updateLocalServerMap: url.Parse: %v", err)
	}

	srvMap := &localServerMap{servers: make(map[string][]localServerAddr), upToDate: true}
	appNetworkStatuses := getconfigCtx.subAppNetworkStatus.GetAll()
	networkInstanceConfigs := getconfigCtx.pubNetworkInstanceConfig.GetAll()
	localServerHostname := url.Hostname()
	localServerIP := net.ParseIP(localServerHostname)

	for _, entry := range appNetworkStatuses {
		appNetworkStatus := entry.(types.AppNetworkStatus)
		for _, adapterStatus := range appNetworkStatus.AppNetAdapterList {
			if len(adapterStatus.BridgeIPAddr) == 0 {
				continue
			}
			if localServerIP != nil {
				// Check if the defined IP of localServer equals one of the IPs
				// allocated to the app.
				var matchesApp bool
				for _, ip := range adapterStatus.AssignedAddresses.IPv4Addrs {
					if ip.Address.Equal(localServerIP) {
						matchesApp = true
						break
					}
				}
				for _, ip := range adapterStatus.AssignedAddresses.IPv6Addrs {
					if ip.Address.Equal(localServerIP) {
						matchesApp = true
						break
					}
				}
				if matchesApp {
					srvAddr := localServerAddr{
						localServerAddr: localServerURL,
						bridgeIP:        adapterStatus.BridgeIPAddr,
						appUUID:         appNetworkStatus.UUIDandVersion.UUID,
					}
					srvMap.servers[adapterStatus.Bridge] = append(srvMap.servers[adapterStatus.Bridge], srvAddr)
				}
				continue
			}
			// check if defined hostname of localServer is in DNS records
			for _, ni := range networkInstanceConfigs {
				networkInstanceConfig := ni.(types.NetworkInstanceConfig)
				for _, dnsNameToIPList := range networkInstanceConfig.DnsNameToIPList {
					if dnsNameToIPList.HostName != localServerHostname {
						continue
					}
					for _, ip := range dnsNameToIPList.IPs {
						localServerURLReplaced := strings.Replace(
							localServerURL, localServerHostname, ip.String(), 1)
						log.Functionf(
							"updateLocalServerMap: will use %s for bridge %s",
							localServerURLReplaced, adapterStatus.Bridge)
						srvAddr := localServerAddr{
							localServerAddr: localServerURLReplaced,
							bridgeIP:        adapterStatus.BridgeIPAddr,
							appUUID:         appNetworkStatus.UUIDandVersion.UUID,
						}
						srvMap.servers[adapterStatus.Bridge] = append(srvMap.servers[adapterStatus.Bridge], srvAddr)
					}
				}
			}
		}
	}
	// To handle concurrent access to localServerMap (from localProfileTimerTask, radioPOSTTask and potentially from
	// some more future tasks), we replace the map pointer at the very end of this function once the map is fully
	// constructed.
	getconfigCtx.sideController.localServerMap = srvMap
	return nil
}

// updateHasLocalServer sets HasLocalServer on the app instances
// Note that if there are changes to the AppInstanceConfig or the allocated IP
// addresses the HasLocalServer will not immediately reflect that since we need
// the IP address from AppNetworkStatus.
func updateHasLocalServer(ctx *getconfigContext) {
	srvMap := ctx.sideController.localServerMap.servers
	items := ctx.pubAppInstanceConfig.GetAll()
	for _, item := range items {
		aic := item.(types.AppInstanceConfig)
		hasLocalServer := false
		for _, servers := range srvMap {
			for _, srv := range servers {
				if srv.appUUID == aic.UUIDandVersion.UUID {
					hasLocalServer = true
					break
				}
			}
		}
		if hasLocalServer != aic.HasLocalServer {
			aic.HasLocalServer = hasLocalServer
			log.Noticef("HasLocalServer(%s) for %s change to %t",
				aic.Key(), aic.DisplayName, hasLocalServer)
			// Verify that it fits and if not publish with error
			checkAndPublishAppInstanceConfig(ctx, aic)
		}
	}
}

// Is network tracing enabled (for any request)?
func isNettraceEnabled(ctx *zedagentContext) bool {
	if ctx.netDumper == nil || ctx.netdumpInterval == 0 {
		return false
	}
	// Trace only if the highest priority DPC is currently being applied
	// and is reported by nim as working. Otherwise, we have netdumps from nim
	// available for connectivity troubleshooting.
	if deviceNetworkStatus == nil ||
		deviceNetworkStatus.Testing ||
		deviceNetworkStatus.CurrentIndex != 0 ||
		deviceNetworkStatus.State != types.DPCStateSuccess {
		return false
	}
	return true
}

// Function decides if the next HTTP request should be traced and netdump published.
func traceNextReq(ctx *zedagentContext, lastNetdump time.Time) bool {
	if !isNettraceEnabled(ctx) {
		return false
	}
	if lastNetdump.IsZero() {
		// No netdump published yet.
		return true
	}
	uptime := time.Since(ctx.startTime)
	lastNetdumpAge := time.Since(lastNetdump)
	// Ensure we get at least one netdump for the currently tested EVE upgrade.
	if zboot.IsCurrentPartitionStateInProgress() && lastNetdumpAge > uptime {
		return true
	}
	return lastNetdumpAge >= ctx.netdumpInterval
}

// Function decides if the next call to SendOnAllIntf for /config request should be traced
// and netdump published at the end (see libs/nettrace and pkg/pillar/netdump).
func traceNextConfigReq(ctx *zedagentContext) bool {
	return traceNextReq(ctx, ctx.lastConfigNetdumpPub)
}

// Publish netdump containing traces of executed config requests.
func publishConfigNetdump(ctx *zedagentContext,
	configRV configProcessingRetval, tracedConfigReqs []netdump.TracedNetRequest) {
	netDumper := ctx.netDumper
	if netDumper == nil {
		return
	}
	var topic string
	switch configRV {
	case configOK:
		topic = netDumpConfigOKTopic
	case deferConfig:
		// There was no actual /config request so there is nothing interesting to publish.
		return
	default:
		topic = netDumpConfigFailTopic
	}
	filename, err := netDumper.Publish(topic, tracedConfigReqs...)
	if err != nil {
		log.Warnf("Failed to publish netdump for topic %s: %v", topic, err)
	} else {
		log.Noticef("Published netdump for topic %s: %s", topic, filename)
	}
	ctx.lastConfigNetdumpPub = time.Now()
}
