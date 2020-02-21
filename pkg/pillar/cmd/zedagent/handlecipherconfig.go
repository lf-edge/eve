// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// cipher specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// XXX:TBD controller certificate change should trigger reprocessing
// of cipherContexts/cipherBlocks
func handleControllerCertModify(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleControllerCertModify(%s)\n", key)
	config := configArg.(types.ControllerCertificate)
	log.Infof("handleControllerCertModify(%s) done %v\n", key, config)
}

func handleControllerCertDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleControllerCertDelete(%s)\n", key)
}

// XXX:TBD cipherContext change should trigger reprocessing
// of cipherBlocks
func handleCipherContextModify(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleCipherContextModify(%s)\n", key)
	config := configArg.(types.CipherContext)
	log.Infof("handleCipherContextModify(%s) done %v\n", key, config)
}

func handleCipherContextDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleCipherContextDelete(%s)\n", key)
}

// parseCipherBlock : will collate all the relevant information
// ciphercontext will be used to get the certs and encryption schemes
func parseCipherBlock(ctx *getconfigContext,
	cfgCipherBlock *zconfig.CipherBlock) types.CipherBlock {
	cipherBlock := types.CipherBlock{}
	if cfgCipherBlock == nil {
		return cipherBlock
	}
	cipherBlock.ID = cfgCipherBlock.GetCipherContextId()
	cipherBlock.InitialValue = cfgCipherBlock.GetInitialValue()
	cipherBlock.CipherData = cfgCipherBlock.GetCipherData()
	cipherBlock.ClearTextHash = cfgCipherBlock.GetClearTextSha256()

	// should contain valid cipher data
	if len(cipherBlock.CipherData) == 0 || len(cipherBlock.ID) == 0 {
		log.Infof("%s, cipher block does not contain valid data\n", cipherBlock.ID)
		return cipherBlock
	}
	cipherBlock.IsCipher = true

	// get the cipher context
	cipherContext := getCipherContextConfig(ctx, cipherBlock.ID)
	if cipherContext == nil {
		return cipherBlock
	}

	// copy the relevant attributes, from cipher context to cipher block
	cipherBlock.KeyExchangeScheme = cipherContext.KeyExchangeScheme
	cipherBlock.EncryptionScheme = cipherContext.EncryptionScheme

	// get the relevant controller cert and device cert
	ccert, dcert, err := getCipherContextCerts(ctx, cipherContext)
	if err != nil {
		return cipherBlock
	}
	cipherBlock.ControllerCert = ccert
	cipherBlock.DeviceCert = dcert
	// finally, mark the cipher block as valid
	cipherBlock.IsValidCipher = true
	return cipherBlock
}

// cipher context config parsing and publish
var cipherContextConfigHash []byte

func parseCipherContextConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	cfgCipherContextList := config.GetCipherContexts()
	h := sha256.New()
	for _, cfgCipherContext := range cfgCipherContextList {
		computeConfigElementSha(h, cfgCipherContext)
	}
	newConfigHash := h.Sum(nil)
	same := bytes.Equal(newConfigHash, cipherContextConfigHash)
	if same {
		return
	}
	log.Infof("parseCipherContextConfig: Applying updated config\n"+
		"Last Sha: % x\n"+
		"New  Sha: % x\n"+
		"cfgCipherContextList: %v\n",
		cipherContextConfigHash, newConfigHash, cfgCipherContextList)

	cipherContextConfigHash = newConfigHash

	// First look for deleted ones
	items := getconfigCtx.pubCipherContextConfig.GetAll()
	for idStr := range items {
		found := false
		for _, cfgCipherContext := range cfgCipherContextList {
			if cfgCipherContext.GetContextId() == idStr {
				found = true
				break
			}
		}
		// cipherContext not found, delete
		if !found {
			log.Infof("parseCipherContextConfig: deleting %s\n", idStr)
			unpublishCipherContextConfig(getconfigCtx, idStr)
		}
	}

	for _, cfgCipherContext := range cfgCipherContextList {
		if cfgCipherContext.GetContextId() == "" {
			log.Debugf("parseCipherContextConfig ignoring empty\n")
			continue
		}
		cipherContext := new(types.CipherContext)
		cipherContext.ID = cfgCipherContext.GetContextId()
		cipherContext.HashScheme = cfgCipherContext.GetHashScheme()
		cipherContext.KeyExchangeScheme = cfgCipherContext.GetKeyExchangeScheme()
		cipherContext.EncryptionScheme = cfgCipherContext.GetEncryptionScheme()
		cipherContext.DeviceCertHash = cfgCipherContext.GetDeviceCertHash()
		cipherContext.ControllerCertHash = cfgCipherContext.GetControllerCertHash()
		log.Debugf("parseCipherContextConfig publishing %v\n", cipherContext)
		publishCipherContextConfig(getconfigCtx, cipherContext)
	}
}

func publishCipherContextConfig(getconfigCtx *getconfigContext,
	config *types.CipherContext) {

	key := config.Key()
	log.Debugf("publishCipherContext %s\n", key)
	pub := getconfigCtx.pubCipherContextConfig
	pub.Publish(key, *config)
}

func unpublishCipherContextConfig(getconfigCtx *getconfigContext, key string) {

	log.Debugf("unpublishCipherContextConfig(%s)\n", key)
	pub := getconfigCtx.pubCipherContextConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCipherContext(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func getCipherContextConfig(getconfigCtx *getconfigContext,
	key string) *types.CipherContext {
	log.Debugf("getCipherContextConfig(%s)\n", key)
	pub := getconfigCtx.pubCipherContextConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("CipherContextConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.CipherContext)
	return &config
}

func getCipherContextCerts(ctx *getconfigContext,
	cipherContext *types.CipherContext) ([]byte, []byte, error) {
	log.Debugf("getCipherContextCerts(%s)\n", cipherContext.Key())

	// get controller cert
	ccert := getCipherContextControllerCert(ctx, cipherContext.ControllerCertHash,
		cipherContext.HashScheme)
	if len(ccert) == 0 {
		errStr := fmt.Sprintf("%s, Failed to collect controller cert information",
			cipherContext.ID)
		log.Errorln(errStr)
		return ccert, []byte{}, errors.New(errStr)
	}
	// try to get device cert
	dcert := getCipherContextDeviceCert(ctx, cipherContext.DeviceCertHash,
		cipherContext.HashScheme)
	if len(dcert) == 0 {
		errStr := fmt.Sprintf("%s, Failed to collect device cert information",
			cipherContext.ID)
		log.Errorln(errStr)
		return ccert, dcert, errors.New(errStr)
	}
	return ccert, dcert, nil
}

func getCipherContextControllerCert(ctx *getconfigContext, suppliedHash []byte,
	hashScheme zconfig.CipherHashAlgorithm) []byte {
	items := ctx.pubControllerCertConfig.GetAll()
	for _, item := range items {
		certConfig := item.(types.ControllerCertificate)
		match := bytes.Equal(certConfig.CertHash, suppliedHash)
		if match {
			return certConfig.Cert
		}
	}
	return []byte{}
}

func getCipherContextDeviceCert(ctx *getconfigContext, suppliedHash []byte,
	hashScheme zconfig.CipherHashAlgorithm) []byte {
	// TBD:XXX as of now, only one
	certBytes, err := ioutil.ReadFile(types.DeviceCertName)
	if err == nil {
		match := computeAndMatchHash(certBytes, suppliedHash, hashScheme)
		if match {
			return certBytes
		}
	}
	return []byte{}
}

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
	}
	return false
}

// for controller certificates, publish utilities
func publishControllerCertConfig(getconfigCtx *getconfigContext,
	config *types.ControllerCertificate) {
	key := config.Key()
	log.Debugf("publishControllerCertificate %s\n", key)
	pub := getconfigCtx.pubControllerCertConfig
	pub.Publish(key, *config)
}

func unpublishControllerCertConfig(getconfigCtx *getconfigContext, key string) {
	log.Debugf("unpublishControllerCertConfig %s\n", key)
	pub := getconfigCtx.pubControllerCertConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCertObjConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}
