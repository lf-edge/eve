// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// certs API specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/attest"
	zcert "github.com/lf-edge/eve/api/go/certs"
	zconfig "github.com/lf-edge/eve/api/go/config"
	evecommon "github.com/lf-edge/eve/api/go/evecommon"
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

	// eve node certificates
	subEveNodeCertConfig pubsub.Subscription

	// zedagent uses these to handle received configuration
	pubControllerCertConfig pubsub.Publication
	pubCipherContextConfig  pubsub.Publication

	// parsing, cerrtificate signing status
	pubControllerCertStatus pubsub.Publication
	pubCipherContextStatus  pubsub.Publication
	pubEveNodeCertStatus    pubsub.Publication
}

// initialize cipher pubsub trigger handlers and channels`
func cipherModuleInitialize(ctx *zedagentContext, ps *pubsub.PubSub) {

	// create the channels
	if zedcloud.UseV2API() {
		ctx.cipherCtx.triggerEveNodeCerts = make(chan struct{}, 1)
		ctx.cipherCtx.triggerControllerCerts = make(chan struct{}, 1)
	}

	// ControllerCertConfig
	pubControllerCertConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: false,
			TopicType:  types.ZCertConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubControllerCertConfig.ClearRestarted()
	ctx.cipherCtx.pubControllerCertConfig = pubControllerCertConfig

	// CipherContextConfig
	pubCipherContextConfig, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: false,
			TopicType:  types.CipherContextConfig{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubCipherContextConfig.ClearRestarted()
	ctx.cipherCtx.pubCipherContextConfig = pubCipherContextConfig

	// EveNodeCertStatus
	pubEveNodeCertStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: false,
			TopicType:  types.ZCertStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubEveNodeCertStatus.ClearRestarted()
	ctx.cipherCtx.pubEveNodeCertStatus = pubEveNodeCertStatus

	// ControllerCertStatus
	pubControllerCertStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: false,
			TopicType:  types.ZCertStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubControllerCertStatus.ClearRestarted()
	ctx.cipherCtx.pubControllerCertConfig = pubControllerCertConfig

	// CipherContextStatus publish
	pubCipherContextStatus, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName:  agentName,
			Persistent: true,
			TopicType:  types.CipherContextStatus{},
		})
	if err != nil {
		log.Fatal(err)
	}
	pubCipherContextStatus.ClearRestarted()
	ctx.cipherCtx.pubCipherContextStatus = pubCipherContextStatus

	// EveNodeCertConfig
	subEveNodeCertConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "tpmmgr",
		TopicImpl:     types.ZCertConfig{},
		Activate:      false,
		Ctx:           ctx,
		CreateHandler: handleEveNodeCertConfigModify,
		ModifyHandler: handleEveNodeCertConfigModify,
		DeleteHandler: handleEveNodeCertConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	subEveNodeCertConfig.Activate()
	ctx.cipherCtx.subEveNodeCertConfig = subEveNodeCertConfig
}

// start the task threads
func cipherModuleStart(ctx *zedagentContext) {
	if !zedcloud.UseV2API() {
		return
	}
	// start the eve node certificate push task
	go eveNodeCertsTask(ctx, ctx.cipherCtx.triggerEveNodeCerts)

	// start the controller certificate fetch task
	go controllerCertsTask(ctx, ctx.cipherCtx.triggerControllerCerts)
}

// controller certificte fetch task, on trigger
func controllerCertsTask(ctx *zedagentContext, triggerControllerCerts chan struct{}) {
	log.Infoln("starting controller certificate fetch task")

	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"ccerts", warningTime, errorTime)
	getCertsFromController(ctx)

	for {
		select {
		case <-triggerControllerCerts:
			start := time.Now()
			getCertsFromController(ctx)
			pubsub.CheckMaxTimeTopic(agentName+"ccerts",
				"getCertsFromController", start, warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"ccerts", warningTime, errorTime)
	}
}

// eve node certificate post task, on change trigger
func eveNodeCertsTask(ctx *zedagentContext, triggerEveNodeCerts chan struct{}) {
	log.Infoln("starting eve node certificates publish task")

	iteration := 0
	publishEveNodeCertsToController(ctx, iteration)

	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"certs", warningTime, errorTime)

	for {
		select {
		case <-triggerEveNodeCerts:
			start := time.Now()
			publishEveNodeCertsToController(ctx, iteration)
			pubsub.CheckMaxTimeTopic(agentName+"certs",
				"publishEveNodeCertsToController", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"certs", warningTime, errorTime)
	}
}

// initiate fetch for controller certs
func getCertsFromController(ctx *zedagentContext) bool {
	certURL := zedcloud.URLPathString(serverNameAndPort,
		zedcloudCtx.V2API, nilUUID, "certs")

	reqID := zcdevUUID.String()
	zedcloud.RemoveDeferred("certs:" + reqID)

	resp, contents, rtf, err := zedcloud.SendOnAllIntf(&zedcloudCtx,
		certURL, 0, nil, 0, false)
	if err != nil {
		if rtf == types.SenderStatusRemTempFail {
			log.Infof("getCertsFromController remoteTemporaryFailure: %s", err)
		} else {
			log.Errorf("getCertsFromController failed: %s", err)
		}
		zedcloud.SetDeferred("certs:"+reqID, nil, 0, certURL,
			zedcloudCtx, true)
		return false
	}

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusNotModified:
		log.Infof("getCloudCertChain: status %s", resp.Status)
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusNotImplemented, http.StatusBadRequest:
		log.Infof("getCertsFromController: server %s does not support V2 API", serverName)
		return false
	default:
		log.Errorf("getCertsFromController: statuscode %d %s",
			resp.StatusCode, http.StatusText(resp.StatusCode))
		return false
	}

	err = validateProtoMessage(certURL, resp)
	if err != nil {
		log.Errorf("getCertsFromController: resp header error")
		return false
	}

	// for cipher object handling
	parseControllerCerts(ctx, contents)

	// TBD:XXX needed for MITM, accordingly refactor
	certBytes, err := zedcloud.VerifySigningCertChain(&zedcloudCtx, contents)
	if err != nil {
		log.Errorf("getCertsFromController: verify err %v", err)
		return false
	}
	err = fileutils.WriteRename(types.ServerSigningCertFileName, certBytes)
	if err != nil {
		log.Errorf("getCertsFromController: file save err %v", err)
		return false
	}

	log.Infof("getCertsFromController: success")
	return true
}

var cfgCertConfigHash []byte

// parse and update controller certs
func parseControllerCerts(ctx *zedagentContext, contents []byte) {
	log.Infof("controller certs parsing start")
	cfgCertConfigList := &zcert.ZControllerCert{}
	err := proto.Unmarshal(contents, cfgCertConfigList)
	if err != nil {
		log.Errorf("parseControllerCerts(): Unmarshal error %v", err)
		return
	}

	cfgCertConfigs := cfgCertConfigList.GetCerts()
	h := sha256.New()
	for _, cfgCertConfig := range cfgCertConfigs {
		certType := cfgCertConfig.GetType()
		if certType == zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE {
			computeConfigElementSha(h, cfgCertConfig)
		}
	}
	hash := h.Sum(nil)
	if bytes.Equal(hash, cfgCertConfigHash) {
		return
	}
	log.Infof("parseControllerCerts: Applying updated config "+
		"Last Sha: % x, New  Sha: % x, Num of cfgCert: %d",
		cfgCertConfigHash, hash, len(cfgCertConfigs))

	cfgCertConfigHash = hash

	// Look for deleted ones
	pub := ctx.cipherCtx.pubControllerCertConfig
	items := pub.GetAll()
	for _, item := range items {
		certConfig := item.(types.ZCertConfig)
		found := false
		for _, cfgCertConfig := range cfgCertConfigs {
			hash := cfgCertConfig.GetCertHash()
			certType := cfgCertConfig.GetType()
			if certType != zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE {
				continue
			}
			if bytes.Equal(certConfig.Hash, hash) {
				found = true
				break
			}
		}
		if !found {
			log.Infof("parseControllerCerts: deleting %s", certConfig.Key())
			handleControllerCertConfigDelete(ctx, certConfig.Key())
			unpublishControllerCertConfig(ctx.cipherCtx, certConfig.Key())
		}
	}

	// add the new ones
	for _, cfgCertConfig := range cfgCertConfigs {
		certType := cfgCertConfig.GetType()
		if certType != zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE {
			continue
		}
		certKey := hex.EncodeToString(cfgCertConfig.GetCertHash())
		if cert := lookupControllerCertConfig(ctx.cipherCtx, certKey); cert != nil {
			continue
		}
		log.Infof("parseControllerCerts: not found %s", certKey)
		certConfig := &types.ZCertConfig{
			HashAlgo: cfgCertConfig.GetHashAlgo(),
			Origin:   types.CERT_ORIGIN_CONTROLLER,
			Type:     evecommon.ZCertType(certType),
			Cert:     cfgCertConfig.GetCert(),
			Hash:     cfgCertConfig.GetCertHash(),
		}
		publishControllerCertConfig(ctx.cipherCtx, *certConfig)
		handleControllerCertConfigModify(ctx, *certConfig)
	}
	log.Infof("controller certs parsing done")
}

var eveNodeCertsHash []byte

// prepare the eve node certs list proto message
func publishEveNodeCertsToController(ctx *zedagentContext, iteration int) {
	var attestReq = &attest.ZAttestReq{}

	attestReq = new(attest.ZAttestReq)
	startPubTime := time.Now()
	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_CERT
	// no quotes

	h := sha256.New()
	sub := ctx.cipherCtx.subEveNodeCertConfig
	items := sub.GetAll()
	for _, item := range items {
		config := item.(types.ZCertConfig)
		if config.Type != evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE {
			continue
		}
		computeConfigElementSha(h, item)
		certMsg := new(evecommon.ZCert)
		certMsg.HashAlgo = config.HashAlgo
		certMsg.Type = config.Type
		certMsg.Cert = config.Cert
		certMsg.Hash = config.Hash
		attestReq.Certs = append(attestReq.Certs, certMsg)
	}
	eveNodeCertsHash = h.Sum(nil)

	log.Debugf("publishEveNodeCertsToController, sending %s", attestReq)
	sendEveNodeCertsProtobuf(attestReq, iteration)
	log.Debugf("publishEveNodeCertsToController: after send, total elapse sec %v",
		time.Since(startPubTime).Seconds())
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different port for load spreading.
// For each port we try all its local IP addresses until we get a success.
func sendEveNodeCertsProtobuf(attestReq *attest.ZAttestReq, iteration int) {
	data, err := proto.Marshal(attestReq)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	reqID := zcdevUUID.String()
	zedcloud.RemoveDeferred("attest:" + reqID)
	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(attestReq))
	attestURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "attest")
	const return400 = false
	_, _, rtf, err := zedcloud.SendOnAllIntf(&zedcloudCtx, attestURL,
		size, buf, iteration, return400)
	if err != nil {
		// Hopefully next timeout will be more successful
		if rtf == types.SenderStatusRemTempFail {
			log.Errorf("sendEveNodeCertsProtobuf remoteTemporaryFailure: %s",
				err)
		} else {
			log.Errorf("sendEveNodeCertsProtobuf failed: %s", err)
		}
		zedcloud.SetDeferred("attest:"+reqID, buf, size, attestURL,
			zedcloudCtx, true)
	}
}

// look up controller certificate config
func lookupControllerCertConfig(ctx *cipherContext,
	key string) *types.ZCertConfig {
	log.Infof("lookupControllerCertConfig(%s)", key)
	pub := ctx.pubControllerCertConfig
	item, err := pub.Get(key)
	if err != nil {
		log.Errorf("lookupControllerCertConfig(%s) not found", key)
		return nil
	}
	config := item.(types.ZCertConfig)
	log.Infof("lookupControllerCertConfig(%s) Done", key)
	return &config
}

// look up controller certificate status
func lookupControllerCertStatus(ctx *cipherContext,
	key string) *types.ZCertStatus {
	log.Infof("lookupControllerCertStatus(%s)", key)
	pub := ctx.pubControllerCertStatus
	item, err := pub.Get(key)
	if err != nil {
		log.Errorf("lookupControllerCertStatus(%s) not found", key)
		return nil
	}
	status := item.(types.ZCertStatus)
	log.Infof("lookupControllerCertStatus(%s) Done", key)
	return &status
}

// look up eve node certificate status
func lookupEveNodeCertStatus(ctx *cipherContext,
	key string) *types.ZCertStatus {
	log.Infof("lookupEveNodeCertStatus(%s)", key)
	pub := ctx.pubEveNodeCertStatus
	item, err := pub.Get(key)
	if err != nil {
		log.Errorf("lookupEveNodeCertStatus(%s) not found", key)
		return nil
	}
	status := item.(types.ZCertStatus)
	log.Infof("lookupEveNodeCertStatus(%s) Done", key)
	return &status
}

// Controller certificate, check whether there is a Sha mismatch
// to trigger the post request
func handleControllerCertsSha(ctx *zedagentContext,
	config *zconfig.EdgeDevConfig) {
	sumHash := hex.EncodeToString(cfgCertConfigHash)
	certHash := config.GetControllercertConfighash()
	if sumHash != certHash {
		triggerControllerCertsEvent(ctx)
	}
}

//  controller certificate pull trigger function
func triggerControllerCertsEvent(ctxPtr *zedagentContext) {

	if !zedcloud.UseV2API() {
		return
	}
	log.Info("Trigger for Controller Certs")
	select {
	case ctxPtr.cipherCtx.triggerControllerCerts <- struct{}{}:
		// Do nothing more
	default:
		log.Warnf("Failed to send on triggerControllerCerts")
	}
}

// Eve node certificate, check whether there is a Sha mismatch
// to trigger the post request
func handleEveNodeCertsSha(ctx *zedagentContext,
	config *zconfig.EdgeDevConfig) {
	sumHash := hex.EncodeToString(eveNodeCertsHash)
	certHash := config.GetNodecertConfighash()
	if sumHash != certHash {
		triggerEveNodeCertsEvent(ctx)
	}
}

//  eve node certificate post trigger function
func triggerEveNodeCertsEvent(ctxPtr *zedagentContext) {

	if !zedcloud.UseV2API() {
		return
	}
	log.Info("Triggered Eve Node Certs")
	select {
	case ctxPtr.cipherCtx.triggerEveNodeCerts <- struct{}{}:
		// Do nothing more
	default:
		log.Warnf("Failed to send on triggerEveNodeCerts")
	}
}

// pubsub functions
// controller certificate config
// config
func publishControllerCertConfig(ctx *cipherContext,
	config types.ZCertConfig) {
	key := config.Key()
	log.Debugf("publishControllerCertConfig %s", key)
	pub := ctx.pubControllerCertConfig
	pub.Publish(key, config)
	log.Debugf("publishControllerCertConfig %s Done", key)
}

func unpublishControllerCertConfig(ctx *cipherContext, key string) {
	log.Debugf("unpublishControllerCertConfig %s", key)
	pub := ctx.pubControllerCertConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishControllerCertConfig(%s) not found", key)
		return
	}
	log.Debugf("unpublishControllerCertConfig %s Done", key)
	pub.Unpublish(key)
}

// controller certificate status
// status
func publishControllerCertStatus(ctx *cipherContext,
	status types.ZCertStatus) {
	key := status.Key()
	log.Debugf("publishControllerCertStatus %s", key)
	pub := ctx.pubControllerCertStatus
	pub.Publish(key, status)
	log.Debugf("publishControllerCertStatus %s Done", key)
}

func unpublishControllerCertStatus(ctx *cipherContext, key string) {
	log.Debugf("unpublishControllerCertStatus %s", key)
	pub := ctx.pubControllerCertStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishControllerCertStatus(%s) not found", key)
		return
	}
	log.Debugf("unpublishControllerCertStatus %s Done", key)
	pub.Unpublish(key)
}

// cipher context config
// config
func publishCipherContextConfig(ctx *cipherContext,
	config types.CipherContextConfig) {
	key := config.Key()
	log.Debugf("publishCipherContextConfig(%s)", key)
	pub := ctx.pubCipherContextConfig
	pub.Publish(key, config)
	log.Debugf("publishCipherContextConfig(%s) done", key)
}

func unpublishCipherContextConfig(ctx *cipherContext, key string) {
	log.Debugf("unpublishCipherContextConfig(%s)", key)
	pub := ctx.pubCipherContextConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCipherContextConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishCipherContextConfig(%s) done", key)
}

// cipher context status
// status
func publishCipherContextStatus(ctx *cipherContext,
	status types.CipherContextStatus) {
	key := status.Key()
	log.Debugf("publishCipherContextStatus(%s)", key)
	pub := ctx.pubCipherContextStatus
	pub.Publish(key, status)
	log.Debugf("publishCipherContextStatus(%s) done", key)
}

func unpublishCipherContextStatus(ctx *cipherContext, key string) {
	log.Debugf("unpublishCipherContextStatus(%s)", key)
	pub := ctx.pubCipherContextStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCipherContextStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishCipherContextStatus(%s) done", key)
}

// eve node certificate status
// status
func publishEveNodeCertStatus(ctx *cipherContext,
	status types.ZCertStatus) {
	key := status.Key()
	log.Debugf("publishEveNodeCertStatus %s", key)
	pub := ctx.pubEveNodeCertStatus
	pub.Publish(key, status)
	log.Debugf("publishEveNodeCertStatus %s Done", key)
}

func unpublishEveNodeCertStatus(ctx *cipherContext, key string) {
	log.Debugf("unpublishEveNodeCertStatus %s", key)
	pub := ctx.pubEveNodeCertStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishEveNodeCertStatus(%s) not found", key)
		return
	}
	log.Debugf("unpublishEveNodeCertStatus %s Done", key)
	pub.Unpublish(key)
}
