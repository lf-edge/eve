// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// certs API specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/lf-edge/eve/api/go/attest"
	zcert "github.com/lf-edge/eve/api/go/certs"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"google.golang.org/protobuf/proto"
)

// Cipher Information Context
type cipherContext struct {
	zedagentCtx *zedagentContext // Cross link

	// post and get certs triggers
	triggerEdgeNodeCerts   chan struct{}
	triggerControllerCerts chan struct{}

	cfgControllerCertHash string // Last controllercert_confighash received from controller
	iteration             int
}

var controllerCertHash []byte

// parse and update controller certs
func parseControllerCerts(ctx *zedagentContext, contents []byte) (changed bool, err error) {
	log.Functionf("Started parsing controller certs")
	cfgConfig := &zcert.ZControllerCert{}
	err = proto.Unmarshal(contents, cfgConfig)
	if err != nil {
		err = fmt.Errorf("parseControllerCerts(): Unmarshal error %w", err)
		log.Error(err)
		return false, err
	}

	cfgCerts := cfgConfig.GetCerts()
	h := sha256.New()
	for _, cfgCert := range cfgCerts {
		computeConfigElementSha(h, cfgCert)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, controllerCertHash) {
		return false, nil
	}
	log.Functionf("parseControllerCerts: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgCert: %d",
		controllerCertHash, newHash, len(cfgCerts))

	controllerCertHash = newHash

	// First look for deleted ones
	items := ctx.getconfigCtx.pubControllerCert.GetAll()
	for _, item := range items {
		config := item.(types.ControllerCert)
		configHash := config.CertHash
		found := false
		for _, cfgConfig := range cfgCerts {
			cfgConfigHash := cfgConfig.GetCertHash()
			if bytes.Equal(configHash, cfgConfigHash) {
				found = true
				break
			}
		}
		if !found {
			log.Functionf("parseControllerCerts: deleting %s", config.Key())
			unpublishControllerCert(ctx.getconfigCtx, config.Key())
			changed = true
		}
	}

	for _, cfgConfig := range cfgCerts {
		certKey := hex.EncodeToString(cfgConfig.GetCertHash())
		cert := lookupControllerCert(ctx.getconfigCtx, certKey)
		if cert == nil {
			log.Functionf("parseControllerCerts: not found %s", certKey)
			cert = &types.ControllerCert{
				HashAlgo: cfgConfig.GetHashAlgo(),
				Type:     cfgConfig.GetType(),
				Cert:     cfgConfig.GetCert(),
				CertHash: cfgConfig.GetCertHash(),
			}
			publishControllerCert(ctx.getconfigCtx, *cert)
			changed = true
		}
	}
	log.Functionf("parsing controller certs done")
	return changed, nil
}

// look up controller cert
func lookupControllerCert(ctx *getconfigContext,
	key string) *types.ControllerCert {
	log.Functionf("lookupControllerCert(%s)", key)
	pub := ctx.pubControllerCert
	item, err := pub.Get(key)
	if err != nil {
		log.Errorf("lookupControllerCert(%s) not found", key)
		return nil
	}
	status := item.(types.ControllerCert)
	log.Functionf("lookupControllerCert(%s) Done", key)
	return &status
}

// pubsub functions
// for controller cert
func publishControllerCert(ctx *getconfigContext,
	config types.ControllerCert) {
	key := config.Key()
	log.Tracef("publishControllerCert %s", key)
	pub := ctx.pubControllerCert
	pub.Publish(key, config)
	log.Tracef("publishControllerCert %s Done", key)
}

func unpublishControllerCert(ctx *getconfigContext, key string) {
	log.Tracef("unpublishControllerCert %s", key)
	pub := ctx.pubControllerCert
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishControllerCert(%s) not found", key)
		return
	}
	log.Tracef("unpublishControllerCert %s Done", key)
	pub.Unpublish(key)
}

func handleEdgeNodeCertCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleEdgeNodeCertImpl(ctxArg, key, configArg)
}

func handleEdgeNodeCertModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleEdgeNodeCertImpl(ctxArg, key, configArg)
}

func handleEdgeNodeCertImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := configArg.(types.EdgeNodeCert)
	log.Functionf("handleEdgeNodeCertImpl for %s", status.Key())
	triggerEdgeNodeCertEvent(ctx)
}

func handleEdgeNodeCertDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := configArg.(types.EdgeNodeCert)
	log.Functionf("handleEdgeNodeCertDelete for %s", status.Key())
	triggerEdgeNodeCertEvent(ctx)
}

// Run a task certificate post task, on change trigger
func controllerCertsTask(ctx *zedagentContext, triggerCerts <-chan struct{}) {

	log.Functionln("starting controller certificate fetch task")
	retry := !getCertsFromController(ctx, "initial")

	wdName := agentName + "ccerts"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	// Run a timer for extra safety to handle controller certificates updates
	// If we failed with the initial we have a short timer, otherwise
	// the configurable one.
	const shortTime = 120 // Two minutes
	certInterval := ctx.globalConfig.GlobalValueInt(types.CertInterval)
	if retry {
		log.Noticef("Initial getCertsFromController failed; switching to short timer")
		certInterval = shortTime
	}
	interval := time.Duration(certInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	periodicTicker := flextimer.NewRangeTicker(time.Duration(min),
		time.Duration(max))
	ctx.getconfigCtx.certTickerHandle = periodicTicker

	for {
		success := true
		select {
		case <-triggerCerts:
			start := time.Now()
			success = getCertsFromController(ctx, "triggered")
			ctx.ps.CheckMaxTimeTopic(wdName, "publishCerts", start,
				warningTime, errorTime)

		case <-periodicTicker.C:
			start := time.Now()
			success = getCertsFromController(ctx, "periodic")
			ctx.ps.CheckMaxTimeTopic(wdName, "publishCerts", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
		if retry && success {
			log.Noticef("getCertsFromController succeeded; switching to long timer %d seconds",
				ctx.globalConfig.GlobalValueInt(types.CertInterval))
			updateCertTimer(ctx.globalConfig.GlobalValueInt(types.CertInterval),
				ctx.getconfigCtx.certTickerHandle)
			retry = false
		} else if !retry && !success {
			log.Noticef("getCertsFromController failed; switching to short timer")
			updateCertTimer(shortTime,
				ctx.getconfigCtx.certTickerHandle)
			retry = true
		}
	}
}

// Fetch and verify the controller certificates. Returns true if certificates have
// not changed or the update was successfully applied.
// False is returned if the function failed to fetch/verify/unmarshal certs.
func getCertsFromController(ctx *zedagentContext, desc string) (success bool) {
	log.Functionf("getCertsFromController started for %s", desc)
	certURL := zedcloud.URLPathString(serverNameAndPort,
		zedcloudCtx.V2API, nilUUID, "certs")

	// not V2API
	if !zedcloud.UseV2API() {
		log.Noticef("getCertsFromController not V2API!")
		return false
	}

	ctxWork, cancel := zedcloud.GetContextForAllIntfFunctions(zedcloudCtx)
	defer cancel()

	const bailOnHTTPErr = false
	const withNetTracing = false
	rv, err := zedcloud.SendOnAllIntf(ctxWork, zedcloudCtx, certURL, 0, nil, 0,
		bailOnHTTPErr, withNetTracing)
	if err != nil {
		switch rv.Status {
		case types.SenderStatusUpgrade:
			log.Noticef("getCertsFromController: Controller upgrade in progress")
		case types.SenderStatusRefused:
			log.Noticef("getCertsFromController: Controller returned ECONNREFUSED")
		case types.SenderStatusCertInvalid:
			log.Warnf("getCertsFromController: Controller certificate invalid time")
			log.Noticef("%s trigger", rv.Status.String())
			triggerControllerCertEvent(ctx)
		case types.SenderStatusCertMiss:
			log.Noticef("getCertsFromController: Controller certificate miss")
			log.Noticef("%s trigger", rv.Status.String())
			triggerControllerCertEvent(ctx)
		default:
			log.Errorf("getCertsFromController failed: %s", err)
		}
		return false
	}

	switch rv.HTTPResp.StatusCode {
	case http.StatusOK:
		log.Functionf("getCertsFromController: status %d", rv.Status)
	default:
		log.Errorf("getCertsFromController: failed, statuscode %d %s",
			rv.HTTPResp.StatusCode, http.StatusText(rv.HTTPResp.StatusCode))
		switch rv.Status {
		case types.SenderStatusCertMiss, types.SenderStatusCertInvalid:
			// trigger to acquire new controller certs from cloud
			log.Noticef("%s trigger", rv.Status.String())
			triggerControllerCertEvent(ctx)
		}
		return false
	}

	if err := zedcloud.ValidateProtoContentType(certURL, rv.HTTPResp); err != nil {
		log.Errorf("getCertsFromController: resp header error")
		return false
	}
	if len(rv.RespContents) > 0 {
		err = zedcloud.RemoveAndVerifyAuthContainer(zedcloudCtx, &rv, true)
		if err != nil {
			log.Errorf("RemoveAndVerifyAuthContainer failed: %s", err)
			return false
		}
	}

	// validate the certificate message payload
	signingCertBytes, ret := zedcloud.VerifyProtoSigningCertChain(log, rv.RespContents)
	if ret != nil {
		log.Errorf("getCertsFromController: verify err %v", ret)
		switch rv.Status {
		case types.SenderStatusCertMiss, types.SenderStatusCertInvalid:
			// trigger to acquire new controller certs from cloud
			log.Noticef("%s trigger", rv.Status.String())
			triggerControllerCertEvent(ctx)
		}
		return false
	}

	// manage the certificates through pubsub
	changed, err := parseControllerCerts(ctx, rv.RespContents)
	if err != nil {
		// Note that err is already logged.
		return false
	}
	if !changed {
		return true
	}

	// write the signing cert to file
	if err := zedcloud.SaveServerSigningCert(zedcloudCtx, signingCertBytes); err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorf("getCertsFromController: " + errStr)
		return false
	}

	log.Noticef("getCertsFromController: success for %s", desc)
	return true
}

// edge node certificate post task, on change trigger
func edgeNodeCertsTask(ctx *zedagentContext, triggerEdgeNodeCerts chan struct{}) {
	log.Functionln("starting edge node certificates publish task")

	publishEdgeNodeCertsToController(ctx)

	wdName := agentName + "ecerts"

	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-triggerEdgeNodeCerts:
			start := time.Now()
			publishEdgeNodeCertsToController(ctx)
			ctx.ps.CheckMaxTimeTopic(wdName,
				"publishEdgeNodeCertsToController", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// prepare the edge node certs list proto message
func publishEdgeNodeCertsToController(ctx *zedagentContext) {
	var attestReq = &attest.ZAttestReq{}

	// not V2API
	if !zedcloud.UseV2API() {
		ctx.publishedEdgeNodeCerts = true
		return
	}

	attestReq = new(attest.ZAttestReq)
	startPubTime := time.Now()
	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_CERT
	// no quotes

	sub := ctx.subEdgeNodeCert
	items := sub.GetAll()
	if len(items) == 0 {
		//Nothing to be sent
		return
	}

	ecdhCertExists := false

	for _, item := range items {
		config := item.(types.EdgeNodeCert)
		certMsg := zcert.ZCert{
			HashAlgo: convertLocalToApiHashAlgo(config.HashAlgo),
			Type:     convertLocalToApiCertType(config.CertType),
			Cert:     config.Cert,
			CertHash: config.CertID,
		}
		for _, metaData := range config.MetaDataItems {
			certMetaData := new(zcert.ZCertMetaData)
			certMetaData.Type = convertLocalToAPICertMetaDataType(metaData.Type)
			certMetaData.MetaData = metaData.Data
			certMsg.MetaDataItems = append(certMsg.MetaDataItems, certMetaData)
		}
		attestReq.Certs = append(attestReq.Certs, &certMsg)
		if certMsg.Type == zcert.ZCertType_CERT_TYPE_DEVICE_ECDH_EXCHANGE {
			ecdhCertExists = true
		}
	}

	if !ecdhCertExists {
		//we expect it to be published first
		log.Warn("publishEdgeNodeCertsToController: no ecdh")
	}

	log.Tracef("publishEdgeNodeCertsToController, sending %s", attestReq)
	sendAttestReqProtobuf(attestReq, ctx.cipherCtx.iteration)
	log.Tracef("publishEdgeNodeCertsToController: after send, total elapse sec %v",
		time.Since(startPubTime).Seconds())
	ctx.cipherCtx.iteration++
	// XXX remove log?
	log.Noticef("Maybe sent EdgeNodeCerts")
	// The getDeferredSentHandlerFunction will set ctx.publishedEdgeNodeCerts
	// when the message has been sent.
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different port for load spreading.
// For each port we try all its local IP addresses until we get a success.
func sendAttestReqProtobuf(attestReq *attest.ZAttestReq, iteration int) {
	data, err := proto.Marshal(attestReq)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	deferKey := "attest:" + devUUID.String()

	attestURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "attest")
	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}
	size := int64(proto.Size(attestReq))

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	// Since attest messages can fail if there is a certificate mismatch
	// we set ignoreErr to allow other messages to be sent as well.
	zedcloudCtx.DeferredEventCtx.SetDeferred(deferKey, buf, size, attestURL,
		false, false, true, attestReq.ReqType)
	zedcloudCtx.DeferredEventCtx.HandleDeferred(time.Now(), 0, true)
}

// initialize cipher pubsub trigger handlers and channels
func cipherModuleInitialize(ctx *zedagentContext) {

	// create the trigger channels
	ctx.cipherCtx.triggerEdgeNodeCerts = make(chan struct{}, 1)
	ctx.cipherCtx.triggerControllerCerts = make(chan struct{}, 1)
}

// start the task threads
func cipherModuleStart(ctx *zedagentContext) {
	if !zedcloud.UseV2API() {
		log.Functionf("V2 APIs are still not enabled")
		// we will run the tasks for watchdog
	}
	// start the edge node certificate push task
	log.Functionf("Creating %s at %s", "edgeNodeCertsTask", agentlog.GetMyStack())
	go edgeNodeCertsTask(ctx, ctx.cipherCtx.triggerEdgeNodeCerts)

	// start the controller certificate fetch task
	log.Functionf("Creating %s at %s", "controllerCertsTask", agentlog.GetMyStack())
	go controllerCertsTask(ctx, ctx.cipherCtx.triggerControllerCerts)
}

// Controller certificate, check whether there is a Sha mismatch
// to trigger the post request
func handleControllerCertsSha(ctx *zedagentContext,
	config *zconfig.EdgeDevConfig) {

	certHash := config.GetControllercertConfighash()
	if certHash != ctx.cipherCtx.cfgControllerCertHash {
		log.Noticef("handleControllerCertsSha trigger due to controller %v vs current %v",
			certHash, ctx.cipherCtx.cfgControllerCertHash)
		ctx.cipherCtx.cfgControllerCertHash = certHash
		triggerControllerCertEvent(ctx)
	}
}

// controller certificate pull trigger function
func triggerControllerCertEvent(ctxPtr *zedagentContext) {

	log.Noticef("Trigger for Controller Certs")
	select {
	case ctxPtr.cipherCtx.triggerControllerCerts <- struct{}{}:
		// Do nothing more
	default:
		log.Warnf("triggerControllerCertEvent(): already triggered, still not processed")
	}
}

// edge node certificate post trigger function
func triggerEdgeNodeCertEvent(ctxPtr *zedagentContext) {

	log.Function("Trigger Edge Node Certs publish")
	select {
	case ctxPtr.cipherCtx.triggerEdgeNodeCerts <- struct{}{}:
		// Do nothing more
	default:
		log.Warnf("triggerEdgeNodeCertEvent(): already triggered, still not processed")
	}
}

func convertLocalToApiHashAlgo(algo types.CertHashType) evecommon.HashAlgorithm {
	switch algo {
	case types.CertHashTypeSha256First16:
		return evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES
	default:
		errStr := fmt.Sprintf("convertLocalToApiHashAlgo(): unknown hash algorithm: %v", algo)
		log.Fatal(errStr)
		return evecommon.HashAlgorithm_HASH_ALGORITHM_INVALID
	}
}

func convertLocalToApiCertType(certType types.CertType) zcert.ZCertType {
	switch certType {
	case types.CertTypeOnboarding:
		return zcert.ZCertType_CERT_TYPE_DEVICE_ONBOARDING
	case types.CertTypeRestrictSigning:
		return zcert.ZCertType_CERT_TYPE_DEVICE_RESTRICTED_SIGNING
	case types.CertTypeEk:
		return zcert.ZCertType_CERT_TYPE_DEVICE_ENDORSEMENT_RSA
	case types.CertTypeEcdhXchange:
		return zcert.ZCertType_CERT_TYPE_DEVICE_ECDH_EXCHANGE
	default:
		errStr := fmt.Sprintf("convertLocalToApiCertType(): unknown certificate type: %v", certType)
		log.Fatal(errStr)
		return zcert.ZCertType_CERT_TYPE_CONTROLLER_NONE
	}
}

func convertLocalToAPICertMetaDataType(metaDataType types.CertMetaDataType) zcert.ZCertMetaDataType {
	switch metaDataType {
	case types.CertMetaDataTypeTpm2Public:
		return zcert.ZCertMetaDataType_Z_CERT_META_DATA_TYPE_TPM2_PUBLIC
	default:
		log.Errorf("convertLocalToAPICertMetaDataType: unknown type %v", metaDataType)
		return zcert.ZCertMetaDataType_Z_CERT_META_DATA_TYPE_INVALID
	}
}
