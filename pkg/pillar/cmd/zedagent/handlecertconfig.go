// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// certs API specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
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
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
)

// Cipher Information Context
type cipherContext struct {
	zedagentCtx *zedagentContext // Cross link

	// post and get certs triggers
	triggerEveNodeCerts    chan struct{}
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
			if cfgConfig.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE {
				cfgConfigHash := cfgConfig.GetCertHash()
				if bytes.Equal(configHash, cfgConfigHash) {
					found = true
					break
				}
			}
		}
		if !found {
			log.Infof("parseControllerCerts: deleting %s", config.Key())
			unpublishControllerCert(ctx.getconfigCtx, config.Key())
		}
	}

	// get itermediate certificates
	interim := x509.NewCertPool()
	for _, cfgConfig := range cfgCerts {
		if cfgConfig.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_INTERMEDIATE {
			ok := interim.AppendCertsFromPEM(cfgConfig.GetCert())
			if !ok {
				errStr := fmt.Sprintf("intermediate cert append fail")
				log.Errorf("parseControllerCerts: " + errStr)
				return
			}
		}
	}

	// verify and update ECDH certificates
	for _, cfgConfig := range cfgCerts {
		if cfgConfig.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE {
			cert := &types.ControllerCert{
				HashAlgo: cfgConfig.GetHashAlgo(),
				Type:     cfgConfig.GetType(),
				Cert:     cfgConfig.GetCert(),
				CertHash: cfgConfig.GetCertHash(),
			}
			interim0 := interim
			if err := zedcloud.VerifySignature(cert.Cert, interim0); err != nil {
				errStr := fmt.Sprintf("%v", err)
				log.Errorf("parseControllerCerts: " + errStr)
				cert.ErrorAndTime.SetError(errStr, time.Now())
			}
			publishControllerCert(ctx.getconfigCtx, *cert)
		}
	}

	// verify and update signing certificate
	signingCertCount := 0
	for _, cfgConfig := range cfgCerts {
		if cfgConfig.Type == zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING {
			signingCertCount++
			if signingCertCount > 1 {
				errStr := fmt.Sprintf("more than one signing certificate")
				log.Errorf("parseControllerCerts: " + errStr)
				return
			}
			interim0 := interim
			if err := zedcloud.VerifySignature(cfgConfig.GetCert(), interim0); err != nil {
				errStr := fmt.Sprintf("%v", err)
				log.Errorf("parseControllerCerts: " + errStr)
				return
			}
			if err := zedcloud.UpdateServerCert(&zedcloudCtx, cfgConfig.GetCert()); err != nil {
				errStr := fmt.Sprintf("%v", err)
				log.Errorf("parseControllerCerts: " + errStr)
				return
			}
			fileutils.WriteRename(types.ServerSigningCertFileName, cfgConfig.GetCert())
		}
	}
	if signingCertCount == 0 {
		errStr := fmt.Sprintf("no signing certificate")
		log.Errorf("parseControllerCerts: " + errStr)
		return
	}
	log.Infof("parseControllerCerts(%d): done", len(cfgCerts))
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

func handleEveNodeCertModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := configArg.(types.EveNodeCert)
	log.Infof("handleEveNodeCertModify for %s", status.Key())
	triggerEveNodeCertEvent(ctx)
	return
}

func handleEveNodeCertDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	status := configArg.(types.EveNodeCert)
	log.Infof("handleEveNodeCertDelete for %s", status.Key())
	triggerEveNodeCertEvent(ctx)
	return
}

// Run a task certificate post task, on change trigger
func controllerCertsTask(ctx *zedagentContext, triggerCerts <-chan struct{}) {

	log.Infoln("starting controller fetch task")
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

	err = validateProtoMessage(certURL, resp)
	if err != nil {
		log.Errorf("getCertsFromController: resp header error")
		return false
	}

	// parse and update the controller certificates
	parseControllerCerts(ctx, contents)

	log.Infof("getCertsFromController: success")
	return true
}

// eve node certificate post task, on change trigger
func eveNodeCertsTask(ctx *zedagentContext, triggerEveNodeCerts chan struct{}) {
	log.Infoln("starting eve node certificates publish task")

	publishEveNodeCertsToController(ctx)

	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"attest", warningTime, errorTime)

	for {
		select {
		case <-triggerEveNodeCerts:
			start := time.Now()
			publishEveNodeCertsToController(ctx)
			pubsub.CheckMaxTimeTopic(agentName+"attest",
				"publishEveNodeCertsToController", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"attest", warningTime, errorTime)
	}
}

// prepare the eve node certs list proto message
func publishEveNodeCertsToController(ctx *zedagentContext) {
	var attestReq = &attest.ZAttestReq{}

	// not V2API
	if !zedcloud.UseV2API() {
		return
	}

	attestReq = new(attest.ZAttestReq)
	startPubTime := time.Now()
	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_CERT
	// no quotes

	sub := ctx.subEveNodeCert
	items := sub.GetAll()
	for _, item := range items {
		config := item.(types.EveNodeCert)
		certMsg := zcert.ZCert{
			HashAlgo: convertLocalToApiHashAlgo(config.HashAlgo),
			Type:     convertLocalToApiCertType(config.CertType),
			Cert:     config.Cert,
			CertHash: config.CertID,
		}
		attestReq.Certs = append(attestReq.Certs, &certMsg)
	}

	log.Debugf("publishEveNodeCertsToController, sending %s", attestReq)
	sendEveNodeCertsProtobuf(attestReq, ctx.cipherCtx.iteration)
	log.Debugf("publishEveNodeCertsToController: after send, total elapse sec %v",
		time.Since(startPubTime).Seconds())
	ctx.cipherCtx.iteration++
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different port for load spreading.
// For each port we try all its local IP addresses until we get a success.
func sendEveNodeCertsProtobuf(attestReq *attest.ZAttestReq, iteration int) {
	data, err := proto.Marshal(attestReq)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	deferKey := "attest:%s" + zcdevUUID.String()
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
			log.Errorf("sendEveNodeCertsProtobuf remoteTemporaryFailure: %s",
				err)
		} else {
			log.Errorf("sendEveNodeCertsProtobuf failed: %s", err)
		}
		zedcloud.SetDeferred(deferKey, buf, size, attestURL,
			zedcloudCtx, true)
	}
}

// initialize cipher pubsub trigger handlers and channels
func cipherModuleInitialize(ctx *zedagentContext, ps *pubsub.PubSub) {

	// create the trigger channels
	ctx.cipherCtx.triggerEveNodeCerts = make(chan struct{}, 1)
	ctx.cipherCtx.triggerControllerCerts = make(chan struct{}, 1)
}

// start the task threads
func cipherModuleStart(ctx *zedagentContext) {
	if !zedcloud.UseV2API() {
		log.Infof("V2 APIs are still not enabled")
		// we will run the tasks for watchdog
	}
	// start the eve node certificate push task
	go eveNodeCertsTask(ctx, ctx.cipherCtx.triggerEveNodeCerts)

	// start the controller certificate fetch task
	go controllerCertsTask(ctx, ctx.cipherCtx.triggerControllerCerts)
}

// Controller certificate, check whether there is a Sha mismatch
// to trigger the post request
func handleControllerCertsSha(ctx *zedagentContext,
	config *zconfig.EdgeDevConfig) {
	// still sha is not getting populated in the configuration
	if len(ctx.cipherCtx.cfgControllerCertHash) == 0 {
		return
	}
	sumHash := hex.EncodeToString(ctx.cipherCtx.cfgControllerCertHash)
	certHash := config.GetControllercertConfighash()
	if sumHash != certHash {
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

//  eve node certificate post trigger function
func triggerEveNodeCertEvent(ctxPtr *zedagentContext) {

	log.Info("Trigger Eve Node Certs publish")
	select {
	case ctxPtr.cipherCtx.triggerEveNodeCerts <- struct{}{}:
		// Do nothing more
	default:
		log.Warnf("triggerEveNodeCertEvent(): already triggered, still not processed")
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
