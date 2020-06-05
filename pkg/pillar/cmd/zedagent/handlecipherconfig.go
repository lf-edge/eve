// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

// cipher specific parser/utility routines

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	zconfig "github.com/lf-edge/eve/api/go/config"
	zinfo "github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

var cipherCtxHash []byte

// cipher context parsing routine
func parseCipherContext(ctx *zedagentContext,
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
	log.Infof("parseCipherContext: Applying updated config "+
		"Last Sha: % x, "+
		"New  Sha: % x, "+
		"Num of cfgCipherContext: %d",
		cipherCtxHash, newHash, len(cfgCipherContextList))

	cipherCtxHash = newHash

	// First look for deleted ones
	items := ctx.cipherCtx.pubCipherContextConfig.GetAll()
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
			log.Infof("parseCipherContextConfig: deleting %s", idStr)
			unpublishCipherContextStatus(ctx.cipherCtx, idStr)
			unpublishCipherContextConfig(ctx.cipherCtx, idStr)
		}
	}

	for _, cfgCipherContext := range cfgCipherContextList {
		if cfgCipherContext.GetContextId() == "" {
			log.Debugf("parseCipherContext ignoring empty")
			continue
		}
		context := types.CipherContextConfig{
			ContextID:          cfgCipherContext.GetContextId(),
			HashScheme:         cfgCipherContext.GetHashScheme(),
			KeyExchangeScheme:  cfgCipherContext.GetKeyExchangeScheme(),
			EncryptionScheme:   cfgCipherContext.GetEncryptionScheme(),
			DeviceCertHash:     cfgCipherContext.GetDeviceCertHash(),
			ControllerCertHash: cfgCipherContext.GetControllerCertHash(),
		}
		publishCipherContextConfig(ctx.cipherCtx, context)
		handleCipherContextConfigModify(ctx, context)
	}
	log.Infof("parsing cipher context done")
}

// parseCipherBlock : will collate all the relevant information
// ciphercontext will be used to get the certs and encryption schemes
func parseCipherBlock(ctx *getconfigContext, key string,
	cfgCipherBlock *zconfig.CipherBlock) types.CipherBlockStatus {

	log.Infof("parseCipherBlock(%s) started", key)
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
	log.Infof("%s, marking cipher as true", key)
	cipherBlock.IsCipher = true

	log.Infof("parseCipherBlock(%s) done", key)
	return cipherBlock
}

// orchestration routines
// on cipher context, controller certificate, eve node certificate change

func handleControllerCertConfigModify(ctx *zedagentContext,
	config types.ControllerCertConfig) {
	// generate controller certificate status
	status := types.ControllerCertStatus{
		HashAlgo: config.HashAlgo,
		Type:     config.Type,
		Cert:     config.Cert,
		Hash:     config.Hash,
	}
	// TBD:XXX generate signing verification status
	publishControllerCertStatus(ctx.cipherCtx, status)

	// update related cipher contexts
	pub := ctx.cipherCtx.pubCipherContextConfig
	items := pub.GetAll()
	for _, item := range items {
		context := item.(types.CipherContextConfig)
		if bytes.Equal(config.Hash, context.ControllerCertHash) {
			deviceKey := context.EveNodeCertKey()
			dcertstatus := lookupEveNodeCertStatus(ctx.cipherCtx, deviceKey)
			updateCipherContextStatus(ctx, context, &status, dcertstatus)
		}
	}
}

func handleControllerCertConfigDelete(ctx *zedagentContext, key string) {
	config := lookupControllerCertStatus(ctx.cipherCtx, key)
	// update related cipher contexts
	pub := ctx.cipherCtx.pubCipherContextConfig
	items := pub.GetAll()
	for _, item := range items {
		context := item.(types.CipherContextConfig)
		if bytes.Equal(config.Hash, context.ControllerCertHash) {
			deviceKey := context.EveNodeCertKey()
			dcertstatus := lookupEveNodeCertStatus(ctx.cipherCtx, deviceKey)
			updateCipherContextStatus(ctx, context, nil, dcertstatus)
		}
	}
	unpublishControllerCertStatus(ctx.cipherCtx, key)
}

func handleCipherContextConfigModify(ctx *zedagentContext,
	config types.CipherContextConfig) {
	deviceKey := config.EveNodeCertKey()
	controllerKey := config.ControllerCertKey()
	ccertstatus := lookupControllerCertStatus(ctx.cipherCtx, controllerKey)
	dcertstatus := lookupEveNodeCertStatus(ctx.cipherCtx, deviceKey)
	updateCipherContextStatus(ctx, config, ccertstatus, dcertstatus)
}

func updateCipherContextStatus(ctx *zedagentContext, config types.CipherContextConfig,
	ccert *types.ControllerCertStatus, dcert *types.EveNodeCertStatus) {
	var errStr, errStr0, errStr1 string

	// fill up the structure, with config values
	status := types.CipherContextStatus{
		ContextID:          config.ContextID,
		HashScheme:         config.HashScheme,
		KeyExchangeScheme:  config.KeyExchangeScheme,
		EncryptionScheme:   config.EncryptionScheme,
		ControllerCertHash: config.ControllerCertHash,
		DeviceCertHash:     config.DeviceCertHash,
	}

	// update the error string, if any
	if ccert != nil {
		status.ControllerCert = ccert.Cert
		if len(ccert.Error) != 0 {
			errStr0 = "controllerCert: " + ccert.Error
		}
	}

	if dcert != nil {
		status.DeviceCert = dcert.Cert
		if len(dcert.Error) != 0 {
			errStr1 = "deviceCert: " + dcert.Error
		}
	}

	if len(errStr0) != 0 || len(errStr1) != 0 {
		if len(errStr0) != 0 && len(errStr1) != 0 {
			errStr = errStr0 + "," + errStr1
		} else {
			if len(errStr0) != 0 {
				errStr = errStr0
			}
			if len(errStr1) != 0 {
				errStr = errStr1
			}
		}
		status.ErrorAndTime.SetErrorNow(errStr)
	}
	publishCipherContextStatus(ctx.cipherCtx, status)
}

// trigger handler routines
// eve node cert config change will trigger status and
// related cipher context status update
func handleEveNodeCertConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	config := configArg.(types.EveNodeCertConfig)
	// generate eve node certificate status
	status := types.EveNodeCertStatus{
		HashAlgo: config.HashAlgo,
		Type:     config.Type,
		Hash:     config.Hash,
		Cert:     config.Cert,
	}
	// TBD:XXX generate signing verification status
	publishEveNodeCertStatus(ctx.cipherCtx, status)

	// update related cipher contexts
	pub := ctx.cipherCtx.pubCipherContextConfig
	items := pub.GetAll()
	for _, item := range items {
		context := item.(types.CipherContextConfig)
		if bytes.Equal(config.Hash, context.DeviceCertHash) {
			cKey := context.ControllerCertKey()
			ccertstatus := lookupControllerCertStatus(ctx.cipherCtx, cKey)
			updateCipherContextStatus(ctx, context, ccertstatus, &status)
		}
	}
}

func handleEveNodeCertConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	config := configArg.(types.EveNodeCertConfig)
	// update related cipher contexts
	pub := ctx.cipherCtx.pubCipherContextConfig
	items := pub.GetAll()
	for _, item := range items {
		context := item.(types.CipherContextConfig)
		if bytes.Equal(config.Hash, context.DeviceCertHash) {
			cKey := context.ControllerCertKey()
			ccertstatus := lookupControllerCertStatus(ctx.cipherCtx, cKey)
			updateCipherContextStatus(ctx, context, ccertstatus, nil)
		}
	}
	unpublishEveNodeCertStatus(ctx.cipherCtx, key)
}

// controller bound triggers
func handleCipherContextStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.CipherContextStatus)
	errorStatus := zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS
	if len(status.Error) != 0 {
		errorStatus = zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_ERROR
	}
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_CONTEXT,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_MODIFY,
		errorStatus, status.Error)
}

func handleCipherContextStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_CONTEXT,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DELETE,
		zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS, "")
}

func handleControllerCertStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.ControllerCertStatus)
	errorStatus := zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS
	if len(status.Error) != 0 {
		errorStatus = zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_ERROR
	}
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_CONTROLLER_CERT,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_MODIFY,
		errorStatus, status.Error)
}

func handleControllerCertStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_CONTROLLER_CERT,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DELETE,
		zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS, "")
}

func handleEveNodeCertStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.EveNodeCertStatus)
	errorStatus := zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS
	if len(status.Error) != 0 {
		errorStatus = zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_ERROR
	}
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_NODE_CERT,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_MODIFY,
		errorStatus, status.Error)
}

func handleEveNodeCertStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_NODE_CERT,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DELETE,
		zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS, "")
}

func handleNimCipherBlockStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.CipherBlockStatus)
	errorStatus := zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS
	if len(status.Error) != 0 {
		errorStatus = zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_ERROR
	}
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_NIM_BLOCK,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DECRYPT,
		errorStatus, status.Error)
}

func handleNimCipherBlockStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_NIM_BLOCK,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DELETE,
		zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS, "")
}

func handleDomainMgrCipherBlockStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.CipherBlockStatus)
	errorStatus := zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS
	if len(status.Error) != 0 {
		errorStatus = zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_ERROR
	}
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_DOMAINMGR_BLOCK,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DECRYPT,
		errorStatus, status.Error)
}

func handleDomainMgrCipherBlockStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_DOMAINMGR_BLOCK,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DELETE,
		zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS, "")
}

func handleDownloaderCipherBlockStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.CipherBlockStatus)
	errorStatus := zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS
	if len(status.Error) != 0 {
		errorStatus = zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_ERROR
	}
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_DOWNLOADER_BLOCK,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DECRYPT,
		errorStatus, status.Error)
}

func handleDownloaderCipherBlockStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*zedagentContext)
	generateCipherEvent(ctx, key,
		zinfo.CipherObjectType_CIPHER_OBJECT_TYPE_DOWNLOADER_BLOCK,
		zinfo.CipherObjectEvent_CIPHER_OBJECT_EVENT_DELETE,
		zinfo.CipherObjectStatus_CIPHER_OBJECT_STATUS_SUCCESS, "")
}

// TBD:XXX fill up the details and trigger the device info message
func generateCipherEvent(ctx *zedagentContext, objKey string,
	objType zinfo.CipherObjectType, objEvent zinfo.CipherObjectEvent,
	objStatus zinfo.CipherObjectStatus, errorStr string) {
	// TBD:XXX fille up here
}
