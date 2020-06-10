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
	const return400 = false
	_, _, rtf, err := zedcloud.SendOnAllIntf(&zedcloudCtx, attestURL,
		size, buf, iteration, return400)
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
