// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// certs API specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	zcert "github.com/lf-edge/eve/api/go/certs"
	zconfig "github.com/lf-edge/eve/api/go/config"
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
		log.Errorf("parseControllerCerts(): Unmarshal error %v\n", err)
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
	log.Infof("parseControllerCerts: Applying updated config\n"+
		"Last Sha: % x\n"+
		"New  Sha: % x\n"+
		"Num of cfgCert: %d\n",
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
			log.Infof("parseControllerCerts: deleting %s\n", config.Key())
			unpublishControllerCert(ctx.getconfigCtx, config.Key())
		}
	}

	for _, cfgConfig := range cfgCerts {
		certKey := hex.EncodeToString(cfgConfig.GetCertHash())
		cert := lookupControllerCert(ctx.getconfigCtx, certKey)
		if cert == nil {
			log.Infof("parseControllerCerts: not found %s\n", certKey)
			cert = &types.ControllerCert{
				HashAlgo: cfgConfig.GetHashAlgo(),
				Type:     cfgConfig.GetType(),
				Cert:     cfgConfig.GetCert(),
				CertHash: cfgConfig.GetCertHash(),
			}
			publishControllerCert(ctx.getconfigCtx, *cert)
		}
	}
	log.Infof("parsing controller certs done\n")
}

// look up controller cert
func lookupControllerCert(ctx *getconfigContext,
	key string) *types.ControllerCert {
	log.Infof("lookupControllerCert(%s)\n", key)
	pub := ctx.pubControllerCert
	item, err := pub.Get(key)
	if err != nil {
		log.Errorf("lookupControllerCert(%s) not found\n", key)
		return nil
	}
	status := item.(types.ControllerCert)
	log.Infof("lookupControllerCert(%s) Done\n", key)
	return &status
}

// fetch controller cert
func getControllerCert(ctx *getconfigContext,
	suppliedHash []byte) ([]byte, error) {

	hexStr := hex.EncodeToString(suppliedHash)
	log.Infof("%v, get controller cert\n", hexStr)
	items := ctx.pubControllerCert.GetAll()
	for _, item := range items {
		status := item.(types.ControllerCert)
		if bytes.Equal(status.CertHash, suppliedHash) {
			if status.HasError() {
				log.Errorf("get controller cert failed because cert has following error: %v",
					status.Error)
				return status.Cert, errors.New(status.Error)
			}
			log.Infof("%v, controller certificate found\n", hexStr)
			return status.Cert, nil
		}
	}
	// TBD:XXX, schedule a cert API Get Call for
	// the suppliedHash
	errStr := fmt.Sprintf("%s, controller certificate not found", hexStr)
	return []byte{}, errors.New(errStr)
}

// for device cert
func getDeviceCert(hashScheme zconfig.CipherHashAlgorithm,
	suppliedHash []byte) ([]byte, error) {

	hexStr := hex.EncodeToString(suppliedHash)
	log.Infof("%v, get device cert\n", hexStr)

	// TBD:XXX as of now, only one
	certBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err != nil {
		errStr := fmt.Sprintf("get device cert failed while reading device certificate: %v",
			err)
		log.Errorf(errStr)
		return []byte{}, errors.New(errStr)
	}
	if computeAndMatchHash(certBytes, suppliedHash, hashScheme) {
		log.Infof("%v, device cert found", hexStr)
		return certBytes, nil
	}
	errStr := fmt.Sprintf("%s, device certificate not found", hexStr)
	return []byte{}, errors.New(errStr)
}

// hash function
func computeAndMatchHash(cert []byte, suppliedHash []byte,
	hashScheme zconfig.CipherHashAlgorithm) bool {

	switch hashScheme {
	case zconfig.CipherHashAlgorithm_HASH_NONE:
		return false

	case zconfig.CipherHashAlgorithm_HASH_SHA256_16bytes:
		h := sha256.New()
		h.Write(cert)
		computedHash := h.Sum(nil)
		return bytes.Equal(suppliedHash, computedHash[:16])

	case zconfig.CipherHashAlgorithm_HASH_SHA256_32bytes:
		h := sha256.New()
		h.Write(cert)
		computedHash := h.Sum(nil)
		return bytes.Equal(suppliedHash, computedHash)
	}
	return false
}

// pubsub functions
// for controller cert
func publishControllerCert(ctx *getconfigContext,
	config types.ControllerCert) {
	key := config.Key()
	log.Debugf("publishControllerCert %s\n", key)
	pub := ctx.pubControllerCert
	pub.Publish(key, config)
	log.Debugf("publishControllerCert %s Done\n", key)
}

func unpublishControllerCert(ctx *getconfigContext, key string) {
	log.Debugf("unpublishControllerCert %s\n", key)
	pub := ctx.pubControllerCert
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishControllerCert(%s) not found\n", key)
		return
	}
	log.Debugf("unpublishControllerCert %s Done\n", key)
	pub.Unpublish(key)
}

func handleAttestCertModify(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX TBD
	status := configArg.(types.AttestCert)
	log.Infof("handleAttestCertModify for %s\n", status.Key())
	return
}

func handleAttestCertDelete(ctxArg interface{}, key string,
	configArg interface{}) {

	// XXX TBD
	status := configArg.(types.AttestCert)
	log.Infof("handleAttestCertDelete for %s\n", status.Key())
	return
}
