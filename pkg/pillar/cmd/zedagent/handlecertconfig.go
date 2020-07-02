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
	log "github.com/sirupsen/logrus"
)

// Cipher Information Context
type cipherContext struct {
	zedagentCtx *zedagentContext // Cross link

	// post and get certs triggers
	triggerEdgeNodeCerts   chan struct{}
	triggerControllerCerts chan struct{}

	cfgControllerCertHash []byte
	iteration             int
}

// parse and update controller certs
func parseControllerCerts(ctx *zedagentContext, contents []byte) {
	log.Infof("Started parsing controller certs")
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
	if bytes.Equal(newHash, ctx.cipherCtx.cfgControllerCertHash) {
		return
	}
	log.Infof("parseControllerCerts: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgCert: %d",
		ctx.cipherCtx.cfgControllerCertHash, newHash, len(cfgCerts))

	ctx.cipherCtx.cfgControllerCertHash = newHash

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
			log.Infof("parseControllerCerts: deleting %s", config.Key())
			unpublishControllerCert(ctx.getconfigCtx, config.Key())
		}
	}

	for _, cfgConfig := range cfgCerts {
		certKey := hex.EncodeToString(cfgConfig.GetCertHash())
		cert := lookupControllerCert(ctx.getconfigCtx, certKey)
		if cert == nil {
			log.Infof("parseControllerCerts: not found %s", certKey)
			cert = &types.ControllerCert{
				HashAlgo: cfgConfig.GetHashAlgo(),
				Type:     cfgConfig.GetType(),
				Cert:     cfgConfig.GetCert(),
				CertHash: cfgConfig.GetCertHash(),
			}
			publishControllerCert(ctx.getconfigCtx, *cert)
		}
	}
	log.Infof("parsing controller certs done")
}

// look up controller cert
func lookupControllerCert(ctx *getconfigContext,
	key string) *types.ControllerCert {
	log.Infof("lookupControllerCert(%s)", key)
	pub := ctx.pubControllerCert
	item, err := pub.Get(key)
	if err != nil {
		log.Errorf("lookupControllerCert(%s) not found", key)
		return nil
	}
	status := item.(types.ControllerCert)
	log.Infof("lookupControllerCert(%s) Done", key)
	return &status
}

// pubsub functions
// for controller cert
func publishControllerCert(ctx *getconfigContext,
	config types.ControllerCert) {
	key := config.Key()
	log.Debugf("publishControllerCert %s", key)
	pub := ctx.pubControllerCert
	pub.Publish(key, config)
	log.Debugf("publishControllerCert %s Done", key)
}

func unpublishControllerCert(ctx *getconfigContext, key string) {
	log.Debugf("unpublishControllerCert %s", key)
	pub := ctx.pubControllerCert
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishControllerCert(%s) not found", key)
		return
	}
	log.Debugf("unpublishControllerCert %s Done", key)
	pub.Unpublish(key)
}

func handleEdgeNodeCertModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := configArg.(types.EdgeNodeCert)
	log.Infof("handleEdgeNodeCertModify for %s", status.Key())
	triggerEdgeNodeCertEvent(ctx)
	return
}

func handleEdgeNodeCertDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := configArg.(types.EdgeNodeCert)
	log.Infof("handleEdgeNodeCertDelete for %s", status.Key())
	triggerEdgeNodeCertEvent(ctx)
	return
}

// Run a task certificate post task, on change trigger
func controllerCertsTask(ctx *zedagentContext, triggerCerts <-chan struct{}) {

	log.Infoln("starting controller certificate fetch task")
	getCertsFromController(ctx)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"ccerts", warningTime, errorTime)

	for {
		select {
		case <-triggerCerts:
			start := time.Now()
			getCertsFromController(ctx)
			pubsub.CheckMaxTimeTopic(agentName+"ccerts", "publishCerts", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"ccerts", warningTime, errorTime)
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

	resp, contents, rtf, err := zedcloud.SendOnAllIntf(&zedcloudCtx,
		certURL, 0, nil, 0, false)
	if err != nil {
		if rtf == types.SenderStatusRemTempFail {
			log.Infof("getCertsFromController remoteTemporaryFailure: %s", err)
		} else {
			log.Errorf("getCertsFromController failed: %s", err)
		}
		return false
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNotModified:
		log.Infof("getCertsFromController: status %s", resp.Status)
	default:
		log.Errorf("getCertsFromController: failed, statuscode %d %s",
			resp.StatusCode, http.StatusText(resp.StatusCode))
		return false
	}

	if err := validateProtoMessage(certURL, resp); err != nil {
		log.Errorf("getCertsFromController: resp header error")
		return false
	}

	// validate the certificate message payload
	certBytes, ret := zedcloud.VerifySigningCertChain(&zedcloudCtx, contents)
	if ret != nil {
		log.Errorf("getCertsFromController: verify err %v", ret)
		return false
	}

	// write the signing cert to file
	if err := zedcloud.UpdateServerCert(&zedcloudCtx, certBytes); err != nil {
		errStr := fmt.Sprintf("%v", err)
		log.Errorf("getCertsFromController: " + errStr)
		return false
	}

	// manage the certificates through pubsub
	parseControllerCerts(ctx, contents)

	log.Infof("getCertsFromController: success")
	return true
}

// edge node certificate post task, on change trigger
func edgeNodeCertsTask(ctx *zedagentContext, triggerEdgeNodeCerts chan struct{}) {
	log.Infoln("starting edge node certificates publish task")

	publishEdgeNodeCertsToController(ctx)

	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"attest", warningTime, errorTime)

	for {
		select {
		case <-triggerEdgeNodeCerts:
			start := time.Now()
			publishEdgeNodeCertsToController(ctx)
			pubsub.CheckMaxTimeTopic(agentName+"attest",
				"publishEdgeNodeCertsToController", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"attest", warningTime, errorTime)
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
	for _, item := range items {
		config := item.(types.EdgeNodeCert)
		certMsg := zcert.ZCert{
			HashAlgo: convertLocalToApiHashAlgo(config.HashAlgo),
			Type:     convertLocalToApiCertType(config.CertType),
			Cert:     config.Cert,
			CertHash: config.CertID,
		}
		attestReq.Certs = append(attestReq.Certs, &certMsg)
	}

	log.Debugf("publishEdgeNodeCertsToController, sending %s", attestReq)
	sendAttestReqProtobuf(attestReq, ctx.cipherCtx.iteration)
	log.Debugf("publishEdgeNodeCertsToController: after send, total elapse sec %v",
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

	deferKey := "attest:" + zcdevUUID.String()
	zedcloud.RemoveDeferred(deferKey)

	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(attestReq))
	attestURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "attest")
	const bailOnHTTPErr = false
	_, _, rtf, err := zedcloud.SendOnAllIntf(&zedcloudCtx, attestURL,
		size, buf, iteration, bailOnHTTPErr)
	if err != nil {
		// Hopefully next timeout will be more successful
		if rtf == types.SenderStatusRemTempFail {
			log.Errorf("sendAttestReqProtobuf remoteTemporaryFailure: %s",
				err)
		} else {
			log.Errorf("sendAttestReqProtobuf failed: %s", err)
		}
		zedcloud.SetDeferred(deferKey, buf, size, attestURL,
			zedcloudCtx, true)
	}
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
		log.Infof("V2 APIs are still not enabled")
		// we will run the tasks for watchdog
	}
	// start the edge node certificate push task
	go edgeNodeCertsTask(ctx, ctx.cipherCtx.triggerEdgeNodeCerts)

	// start the controller certificate fetch task
	go controllerCertsTask(ctx, ctx.cipherCtx.triggerControllerCerts)
}

// Controller certificate, check whether there is a Sha mismatch
// to trigger the post request
func handleControllerCertsSha(ctx *zedagentContext,
	config *zconfig.EdgeDevConfig) {

	certHash := config.GetControllercertConfighash()
	// In case sha is not getting populated by the controller
	if len(certHash) == 0 {
		log.Infof("handleControllerCertsSha not set by controller")
		return
	}
	sumHash := hex.EncodeToString(ctx.cipherCtx.cfgControllerCertHash)
	if sumHash != certHash {
		log.Infof("handleControllerCertsSha trigger due to controller %v vs current %v",
			certHash, sumHash)
		triggerControllerCertEvent(ctx)
	}
}

//  controller certificate pull trigger function
func triggerControllerCertEvent(ctxPtr *zedagentContext) {

	log.Info("Trigger for Controller Certs")
	select {
	case ctxPtr.cipherCtx.triggerControllerCerts <- struct{}{}:
		// Do nothing more
	default:
		log.Warnf("triggerControllerCertEvent(): already triggered, still not processed")
	}
}

//  edge node certificate post trigger function
func triggerEdgeNodeCertEvent(ctxPtr *zedagentContext) {

	log.Info("Trigger Edge Node Certs publish")
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
