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

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/attest"
	zcert "github.com/lf-edge/eve/api/go/certs"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
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
func parseControllerCerts(ctx *zedagentContext, contents []byte) {
	log.Functionf("Started parsing controller certs")
	cfgConfig := &zcert.ZControllerCert{}
	err := proto.Unmarshal(contents, cfgConfig)
	if err != nil {
		log.Errorf("parseControllerCerts(): Unmarshal error %v", err)
		return
	}

	cfgCerts := cfgConfig.GetCerts()
	h := sha256.New()
	for _, cfgCert := range cfgCerts {
		computeConfigElementSha(h, cfgCert)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, controllerCertHash) {
		return
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
		}
	}
	log.Functionf("parsing controller certs done")
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
	getCertsFromController(ctx)

	wdName := agentName + "ccerts"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctx.ps.StillRunning(wdName, warningTime, errorTime)
	ctx.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-triggerCerts:
			start := time.Now()
			getCertsFromController(ctx)
			ctx.ps.CheckMaxTimeTopic(wdName, "publishCerts", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		ctx.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// prepare the certs list proto message
func getCertsFromController(ctx *zedagentContext) bool {
	certURL := zedcloud.URLPathString(serverNameAndPort,
		zedcloudCtx.V2API, nilUUID, "certs")

	// not V2API
	if !zedcloud.UseV2API() {
		return false
	}

	resp, contents, rtf, err := zedcloud.SendOnAllIntf(zedcloudCtx,
		certURL, 0, nil, 0, false)
	if err != nil {
		switch rtf {
		case types.SenderStatusUpgrade:
			log.Functionf("getCertsFromController: Controller upgrade in progress")
		case types.SenderStatusRefused:
			log.Functionf("getCertsFromController: Controller returned ECONNREFUSED")
		case types.SenderStatusCertInvalid:
			log.Warnf("getCertsFromController: Controller certificate invalid time")
		case types.SenderStatusCertMiss:
			log.Functionf("getCertsFromController: Controller certificate miss")
		default:
			log.Errorf("getCertsFromController failed: %s", err)
		}
		return false
	}

	switch resp.StatusCode {
	case http.StatusOK:
		log.Functionf("getCertsFromController: status %s", resp.Status)
	default:
		log.Errorf("getCertsFromController: failed, statuscode %d %s",
			resp.StatusCode, http.StatusText(resp.StatusCode))
		return false
	}

	if err := zedcloud.ValidateProtoContentType(certURL, resp); err != nil {
		log.Errorf("getCertsFromController: resp header error")
		return false
	}

	// validate the certificate message payload
	certBytes, ret := zedcloud.VerifySigningCertChain(zedcloudCtx, contents)
	if ret != nil {
		log.Errorf("getCertsFromController: verify err %v", ret)
		return false
	}

	// write the signing cert to file
	if err := zedcloud.UpdateServerCert(zedcloudCtx, certBytes); err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorf("getCertsFromController: " + errStr)
		return false
	}

	// manage the certificates through pubsub
	parseControllerCerts(ctx, contents)

	log.Functionf("getCertsFromController: success")
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
	}

	log.Tracef("publishEdgeNodeCertsToController, sending %s", attestReq)
	sendAttestReqProtobuf(attestReq, ctx.cipherCtx.iteration)
	log.Tracef("publishEdgeNodeCertsToController: after send, total elapse sec %v",
		time.Since(startPubTime).Seconds())
	ctx.cipherCtx.iteration++
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
	zedcloud.SetDeferred(zedcloudCtx, deferKey, buf, size, attestURL,
		false, attestReq.ReqType)
	zedcloud.HandleDeferred(zedcloudCtx, time.Now(), 0, true)
}

// initialize cipher pubsub trigger handlers and channels
func cipherModuleInitialize(ctx *zedagentContext, ps *pubsub.PubSub) {

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
		log.Functionf("handleControllerCertsSha trigger due to controller %v vs current %v",
			certHash, ctx.cipherCtx.cfgControllerCertHash)
		ctx.cipherCtx.cfgControllerCertHash = certHash
		triggerControllerCertEvent(ctx)
	}
}

//  controller certificate pull trigger function
func triggerControllerCertEvent(ctxPtr *zedagentContext) {

	log.Function("Trigger for Controller Certs")
	select {
	case ctxPtr.cipherCtx.triggerControllerCerts <- struct{}{}:
		// Do nothing more
	default:
		log.Warnf("triggerControllerCertEvent(): already triggered, still not processed")
	}
}

//  edge node certificate post trigger function
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
