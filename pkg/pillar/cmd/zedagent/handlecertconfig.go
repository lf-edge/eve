// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// certs API specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/golang/protobuf/proto"
	zcert "github.com/lf-edge/eve/api/go/certs"
	"github.com/lf-edge/eve/pkg/pillar/types"
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
