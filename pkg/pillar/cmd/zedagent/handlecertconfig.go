// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// certs API specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/attest"
	zcert "github.com/lf-edge/eve/api/go/certs"
	"github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
)

var certHash []byte

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
	if bytes.Equal(newHash, certHash) {
		return
	}
	log.Infof("parseControllerCerts: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgCert: %d",
		certHash, newHash, len(cfgCerts))

	certHash = newHash

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
				HashAlgo: convertApiHashToLocal(cfgConfig.GetHashAlgo()),
				Type:     convertCertApiCertTypeToLocal(cfgConfig.GetType()),
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

func handleAttestCertModify(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX TBD
	status := configArg.(types.AttestCert)
	log.Infof("handleAttestCertModify for %s", status.Key())
	return
}

func handleAttestCertDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX TBD
	status := configArg.(types.AttestCert)
	log.Infof("handleAttestCertDelete for %s", status.Key())
	return
}

// Run a task certificate post task, on change trigger
func certsTask(ctx *zedagentContext, triggerCerts <-chan struct{}) {
	iteration := 0
	log.Infoln("starting certs publish task")
	publishCerts(ctx, iteration)

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"certs", warningTime, errorTime)

	for {
		select {
		case <-triggerCerts:
			start := time.Now()
			iteration++
			publishCerts(ctx, iteration)
			pubsub.CheckMaxTimeTopic(agentName+"certs", "publishCerts", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"certs", warningTime, errorTime)
	}
}

// prepare the certs list proto message
func publishCerts(ctx *zedagentContext, iteration int) {
	var attestReq = &attest.ZAttestReq{}

	attestReq.ReqType = attest.ZAttestReqType_ATTEST_REQ_CERT
	// no quotes

	// TBD:XXX, get the ECDH Certs here

	log.Debugf("publishCerts to ZedCloud, sending %s", attestReq)
	sendCertsProtobuf(attestReq, iteration)
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different port for load spreading.
// For each port we try all its local IP addresses until we get a success.
func sendCertsProtobuf(attestReq *attest.ZAttestReq, iteration int) {
	data, err := proto.Marshal(attestReq)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	deviceUUID := zcdevUUID.String()
	zedcloud.RemoveDeferred("attest:" + deviceUUID)
	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(attestReq))
	attestURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API,
		devUUID, "attest")
	const bailOnHTTPErr = false
	_, _, rtf, err := zedcloud.SendOnAllIntf(&zedcloudCtx, attestURL,
		size, buf, iteration, bailOnHTTPErr)
	if err != nil {
		if rtf == types.SenderStatusRemTempFail {
			log.Errorf("sendCertsProtobuf remoteTemporaryFailure: %s",
				err)
		} else {
			log.Errorf("sendCertsProtobuf failed: %s", err)
		}
		// Try sending later
		// The buf might have been consumed
		buf := bytes.NewBuffer(data)
		if buf == nil {
			log.Fatal("malloc error")
		}
		zedcloud.SetDeferred("attest:"+deviceUUID, buf, size, attestURL,
			zedcloudCtx, true)
	}
}

// conversion routines used while interfacing with controller
// convertApiHashToLocal :
func convertApiHashToLocal(hash evecommon.HashAlgorithm) types.ZHashAlgorithm {

	switch hash {
	case evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES:
		return types.HASH_ALGORITHM_SH256_16BYTES
	case evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES:
		return types.HASH_ALGORITHM_SH256_32BYTES
	default:
		return types.HASH_ALGORITHM_NONE
	}
}

// convertLocalToApiHash :
func convertLocalToApiHash(hash types.ZHashAlgorithm) evecommon.HashAlgorithm {

	switch hash {
	case types.HASH_ALGORITHM_SH256_16BYTES:
		return evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_16BYTES
	case types.HASH_ALGORITHM_SH256_32BYTES:
		return evecommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES
	default:
		return evecommon.HashAlgorithm_HASH_ALGORITHM_INVALID
	}
}

// convertCertApiCertTypeToLocal :
func convertCertApiCertTypeToLocal(certType zcert.ZCertType) types.ZCertType {

	switch certType {
	case zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING:
		return types.CERT_TYPE_CONTROLLER_SIGNING
	case zcert.ZCertType_CERT_TYPE_CONTROLLER_INTERMEDIATE:
		return types.CERT_TYPE_CONTROLLER_INTERMEDIATE
	case zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE:
		return types.CERT_TYPE_CONTROLLER_ECDH_EXCHANGE
	default:
		return types.CERT_TYPE_NONE
	}
}

// convertLocalToCertApiCertType :
func convertLocalToCertApiCertType(certType types.ZCertType) zcert.ZCertType {

	switch certType {
	case types.CERT_TYPE_CONTROLLER_SIGNING:
		return zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING
	case types.CERT_TYPE_CONTROLLER_INTERMEDIATE:
		return zcert.ZCertType_CERT_TYPE_CONTROLLER_INTERMEDIATE
	case types.CERT_TYPE_CONTROLLER_ECDH_EXCHANGE:
		return zcert.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE
	default:
		return zcert.ZCertType_CERT_TYPE_CONTROLLER_NONE
	}
}

// convertAttestApiCertTypeToLocal :
func convertAttestApiCertTypeToLocal(certType evecommon.ZCertType) types.ZCertType {

	switch certType {
	case evecommon.ZCertType_Z_CERT_TYPE_CONTROLLER_SIGNING:
		return types.CERT_TYPE_CONTROLLER_SIGNING
	case evecommon.ZCertType_Z_CERT_TYPE_CONTROLLER_INTERMEDIATE:
		return types.CERT_TYPE_CONTROLLER_INTERMEDIATE
	case evecommon.ZCertType_Z_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE:
		return types.CERT_TYPE_CONTROLLER_ECDH_EXCHANGE
	case evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ONBOARDING:
		return types.CERT_TYPE_DEVICE_ONBOARDING
	case evecommon.ZCertType_Z_CERT_TYPE_DEVICE_RESTRICTED_SIGNING:
		return types.CERT_TYPE_DEVICE_RESTRICTED_SIGNING
	case evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ENDORSEMENT_RSA:
		return types.CERT_TYPE_DEVICE_ENDORSEMENT_RSA
	case evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE:
		return types.CERT_TYPE_DEVICE_ECDH_EXCHANGE
	default:
		return types.CERT_TYPE_NONE
	}
}

//  convertLocalToAttestApiCertType :
func convertLocalToAttestApiCertType(certType types.ZCertType) evecommon.ZCertType {

	switch certType {
	case types.CERT_TYPE_CONTROLLER_SIGNING:
		return evecommon.ZCertType_Z_CERT_TYPE_CONTROLLER_SIGNING
	case types.CERT_TYPE_CONTROLLER_INTERMEDIATE:
		return evecommon.ZCertType_Z_CERT_TYPE_CONTROLLER_INTERMEDIATE
	case types.CERT_TYPE_CONTROLLER_ECDH_EXCHANGE:
		return evecommon.ZCertType_Z_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE
	case types.CERT_TYPE_DEVICE_ONBOARDING:
		return evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ONBOARDING
	case types.CERT_TYPE_DEVICE_RESTRICTED_SIGNING:
		return evecommon.ZCertType_Z_CERT_TYPE_DEVICE_RESTRICTED_SIGNING
	case types.CERT_TYPE_DEVICE_ENDORSEMENT_RSA:
		return evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ENDORSEMENT_RSA
	case types.CERT_TYPE_DEVICE_ECDH_EXCHANGE:
		return evecommon.ZCertType_Z_CERT_TYPE_DEVICE_ECDH_EXCHANGE
	default:
		return evecommon.ZCertType_Z_CERT_TYPE_INVALID
	}
}
