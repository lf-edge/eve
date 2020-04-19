// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// cipher specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

var cipherCtxHash []byte

// cipher context parsing routine
func parseCipherContext(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Infof("Started parsing cipher context")
	cfgCipherContextList := config.GetCipherContexts()
	h := sha256.New()
	for _, cfgCipherContext := range cfgCipherContextList {
		computeConfigElementSha(h, cfgCipherContext)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, cipherCtxHash) {
		return
	}
	log.Infof("parseCipherContext: Applying updated config\n"+
		"Last Sha: % x\n"+
		"New  Sha: % x\n"+
		"Num of cfgCipherContext: %d\n",
		cipherCtxHash, newHash, len(cfgCipherContextList))

	cipherCtxHash = newHash

	// First look for deleted ones
	items := ctx.pubCipherContext.GetAll()
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
			log.Infof("parseCipherContext: deleting %s\n", idStr)
			unpublishCipherContext(ctx, idStr)
		}
	}

	for _, cfgCipherContext := range cfgCipherContextList {
		if cfgCipherContext.GetContextId() == "" {
			log.Debugf("parseCipherContext ignoring empty\n")
			continue
		}
		context := types.CipherContext{
			ContextID:          cfgCipherContext.GetContextId(),
			HashScheme:         cfgCipherContext.GetHashScheme(),
			KeyExchangeScheme:  cfgCipherContext.GetKeyExchangeScheme(),
			EncryptionScheme:   cfgCipherContext.GetEncryptionScheme(),
			DeviceCertHash:     cfgCipherContext.GetDeviceCertHash(),
			ControllerCertHash: cfgCipherContext.GetControllerCertHash(),
		}
		publishCipherContext(ctx, context)
	}
	log.Infof("parsing cipher context done\n")
}

// parseCipherBlock : will collate all the relevant information
// ciphercontext will be used to get the certs and encryption schemes
func parseCipherBlock(ctx *getconfigContext, key string,
	cfgCipherBlock *zconfig.CipherBlock) types.CipherBlockStatus {

	log.Infof("parseCipherBlock(%s) started\n", key)
	if cfgCipherBlock == nil {
		log.Infof("parseCipherBlock(%s) nil cipher block", key)
		return types.CipherBlockStatus{CipherBlockID: key}
	}
	cipherBlock := types.CipherBlockStatus{
		CipherBlockID:   key,
		CipherContextID: cfgCipherBlock.GetCipherContextId(),
		InitialValue:    cfgCipherBlock.GetInitialValue(),
		CipherData:      cfgCipherBlock.GetCipherData(),
		ClearTextHash:   cfgCipherBlock.GetClearTextSha256(),
	}

	// should contain valid cipher data
	if len(cipherBlock.CipherData) == 0 ||
		len(cipherBlock.CipherContextID) == 0 {
		errStr := fmt.Sprintf("%s, block contains incomplete data", key)
		log.Errorf(errStr)
		cipherBlock.SetErrorNow(errStr)
		return cipherBlock
	}
	log.Infof("%s, marking cipher as true\n", key)
	cipherBlock.IsCipher = true

	log.Infof("parseCipherBlock(%s) done\n", key)
	return cipherBlock
}

func publishCipherContext(ctx *getconfigContext,
	status types.CipherContext) {
	key := status.Key()
	log.Debugf("publishCipherContext(%s)\n", key)
	pub := ctx.pubCipherContext
	pub.Publish(key, status)
	log.Debugf("publishCipherContext(%s) done\n", key)
}

func unpublishCipherContext(ctx *getconfigContext, key string) {
	log.Debugf("unpublishCipherContext(%s)\n", key)
	pub := ctx.pubCipherContext
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCipherContext(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
	log.Debugf("unpublishCipherContext(%s) done\n", key)
}
