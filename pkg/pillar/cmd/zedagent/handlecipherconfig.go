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
)

var cipherCtxHash []byte

// populateCipherContexts: fill in local map from persistent publication on boot
func populateCipherContexts(ctx *getconfigContext) {
	items := ctx.pubCipherContext.GetAll()
	for _, item := range items {
		context := item.(types.CipherContext)
		ctx.cipherContexts[context.Key()] = context
		log.Noticef("populateCipherContext found %s",
			context.Key())
	}
}

// lookupCipherContextByCCH: lookup by ControllerCertHash
// The Key is a UUID so need to walk map
func lookupCipherContextByCCH(ctx *getconfigContext, cch []byte) *types.CipherContext {
	for _, context := range ctx.cipherContexts {
		if bytes.Equal(context.ControllerCertHash, cch) {
			return &context
		}
	}
	return nil
}

// invalidateCipherContextDependenciesList function clear stored hashes for objects
// which have parseCipherBlock inside
// to re-run parse* functions on change of CipherContexts
func invalidateCipherContextDependenciesList() {
	appinstancePrevConfigHash = []byte{}
	networkConfigPrevConfigHash = []byte{}
	datastoreConfigPrevConfigHash = []byte{}
}

// cipher context parsing routine
func parseCipherContext(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	log.Functionf("Started parsing cipher context")
	cfgCipherContextList := config.GetCipherContexts()
	h := sha256.New()
	for _, cfgCipherContext := range cfgCipherContextList {
		computeConfigElementSha(h, cfgCipherContext)
	}
	newHash := h.Sum(nil)
	if bytes.Equal(newHash, cipherCtxHash) {
		return
	}
	log.Functionf("parseCipherContext: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgCipherContext: %d",
		cipherCtxHash, newHash, len(cfgCipherContextList))

	cipherCtxHash = newHash

	invalidateCipherContextDependenciesList()

	// First look for deleted ones
	for idStr := range ctx.cipherContexts {
		found := false
		for _, cfgCipherContext := range cfgCipherContextList {
			if cfgCipherContext.GetContextId() == idStr {
				found = true
				break
			}
		}
		// cipherContext not found, delete
		if !found {
			log.Functionf("parseCipherContext: deleting %s", idStr)
			delete(ctx.cipherContexts, idStr)
			unpublishCipherContext(ctx, idStr)
		}
	}

	for _, cfgCipherContext := range cfgCipherContextList {
		if cfgCipherContext.GetContextId() == "" {
			log.Tracef("parseCipherContext ignoring empty")
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
		ctx.cipherContexts[context.Key()] = context
		publishCipherContext(ctx, context)
	}
	log.Functionf("parsing cipher context done")
}

// parseCipherBlock : will collate all the relevant information
// ciphercontext will be used to get the certs and encryption schemes
// should be run after parseCipherContext
func parseCipherBlock(ctx *getconfigContext, key string, cfgCipherBlock *zconfig.CipherBlock) types.CipherBlockStatus {

	log.Functionf("parseCipherBlock(%s) started", key)
	if cfgCipherBlock == nil {
		log.Functionf("parseCipherBlock(%s) nil cipher block", key)
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
	log.Functionf("%s, marking cipher as true", key)
	cipherBlock.IsCipher = true

	// get CipherContext and embed it into CipherBlockStatus to avoid potential races
	for _, cfgCipherContext := range ctx.cipherContexts {
		if cfgCipherContext.ContextID == cipherBlock.CipherContextID {
			cipherBlock.CipherContext = &cfgCipherContext
			break
		}
	}

	if cipherBlock.CipherContext == nil {
		log.Warnf("parseCipherBlock(%s): config discrepancy: CipherContext %s not found",
			key, cipherBlock.CipherContextID)
	}

	log.Functionf("parseCipherBlock(%s) done", key)
	return cipherBlock
}

func publishCipherContext(ctx *getconfigContext,
	status types.CipherContext) {
	key := status.Key()
	log.Tracef("publishCipherContext(%s)", key)
	pub := ctx.pubCipherContext
	pub.Publish(key, status)
	log.Tracef("publishCipherContext(%s) done", key)
}

func unpublishCipherContext(ctx *getconfigContext, key string) {
	log.Tracef("unpublishCipherContext(%s)", key)
	pub := ctx.pubCipherContext
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCipherContext(%s) not found", key)
		return
	}
	pub.Unpublish(key)
	log.Tracef("unpublishCipherContext(%s) done", key)
}
