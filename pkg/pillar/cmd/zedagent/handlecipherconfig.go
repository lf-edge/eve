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

var cipherCtxConfigHash []byte

// cipher context config parsing routine
func parseCipherContextConfig(ctx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	cfgCipherContextList := config.GetCipherContexts()
	h := sha256.New()
	for _, cfgCipherContext := range cfgCipherContextList {
		computeConfigElementSha(h, cfgCipherContext)
	}
	newConfigHash := h.Sum(nil)
	if bytes.Equal(newConfigHash, cipherCtxConfigHash) {
		return
	}
	log.Infof("parseCipherContextConfig: Applying updated config\n"+
		"Last Sha: % x\n"+
		"New  Sha: % x\n"+
		"cfgCipherContextList: %v\n",
		cipherCtxConfigHash, newConfigHash, cfgCipherContextList)

	cipherCtxConfigHash = newConfigHash

	// First look for deleted ones
	items := ctx.pubCipherContextConfig.GetAll()
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
			unpublishCipherContextConfig(ctx, idStr)
		}
	}

	for _, cfgCipherContext := range cfgCipherContextList {
		if cfgCipherContext.GetContextId() == "" {
			log.Debugf("parseCipherContextConfig ignoring empty\n")
			continue
		}
		config := types.CipherContextConfig{
			ContextID:          cfgCipherContext.GetContextId(),
			HashScheme:         cfgCipherContext.GetHashScheme(),
			KeyExchangeScheme:  cfgCipherContext.GetKeyExchangeScheme(),
			EncryptionScheme:   cfgCipherContext.GetEncryptionScheme(),
			DeviceCertHash:     cfgCipherContext.GetDeviceCertHash(),
			ControllerCertHash: cfgCipherContext.GetControllerCertHash(),
		}
		publishCipherContextConfig(ctx, config)
	}
}

// on create/modification, update the cipher context certs
func updateCipherContextCerts(ctx *getconfigContext,
	status *types.CipherContextStatus) error {
	// get controller cert
	ccert, err0 := getControllerCert(ctx.zedagentCtx,
		status.ControllerCertHash)
	if err0 != nil {
		return err0
	}
	status.ControllerCert = ccert

	// get device cert
	dcert, err1 := getDeviceCert(status.HashScheme,
		status.DeviceCertHash)
	if err1 != nil {
		return err1
	}
	status.DeviceCert = dcert
	return nil
}

// parseCipherBlock : will collate all the relevant information
// ciphercontext will be used to get the certs and encryption schemes
func parseCipherBlock(ctx *getconfigContext, key string,
	cfgCipherBlock *zconfig.CipherBlock) types.CipherBlockStatus {
	if cfgCipherBlock == nil {
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
		errStr := fmt.Sprintf("%s, block contains incomplete data, %s",
			cipherBlock.Key(), cipherBlock.CipherContextID)
		cipherBlock.SetErrorInfo(agentName, errStr)
		return cipherBlock
	}
	cipherBlock.IsCipher = true
	log.Infof("%s, marking cipher as true\n",
		cipherBlock.CipherContextID)

	// get the cipher context
	cipherCtx := getCipherContextStatus(ctx.zedagentCtx,
		cipherBlock.CipherContextID)
	if cipherCtx == nil {
		errStr := fmt.Sprintf("cipherContext not found %s\n",
			cipherBlock.CipherContextID)
		cipherBlock.SetErrorInfo(agentName, errStr)
	} else {
		log.Infof("cipherContext found %s\n", cipherBlock.CipherContextID)
		updateCipherBlock(*cipherCtx, &cipherBlock, key, false)
	}
	return cipherBlock
}

// for cipher context config
func handleCipherContextConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleCipherContextConfigModify(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	config := configArg.(types.CipherContextConfig)
	handleCipherContextConfigUpdate(ctx.getconfigCtx, config, false)
	log.Debugf("handleCipherContextConfigModify(%s) done %v\n", key, config)
}

func handleCipherContextConfigDelete(ctxArg interface{}, key string,
	configArg interface{}) {
	log.Infof("handleCipherContextConfigDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	config := configArg.(types.CipherContextConfig)
	handleCipherContextConfigUpdate(ctx.getconfigCtx, config, true)
	log.Debugf("handleCipherContextConfigDone(%s) done\n", key)
}

// for cipher context status
func handleCipherContextStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	log.Infof("handleCipherContextStatusModify(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.CipherContextStatus)
	handleCipherContextStatusUpdate(ctx.getconfigCtx, status, false)
	log.Debugf("handleCipherContexStatustModify(%s) done %v\n", key, status)
}

func handleCipherContextStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	log.Infof("handleCipherContextStatusDelete(%s)\n", key)
	ctx := ctxArg.(*zedagentContext)
	status := statusArg.(types.CipherContextStatus)
	//  clear matching cipher blocks
	handleCipherContextStatusUpdate(ctx.getconfigCtx, status, true)
	log.Debugf("handleCipherContextStatusDone(%s) done\n", key)
}

// on cipher context config update, update the cipher status
func handleCipherContextConfigUpdate(ctx *getconfigContext,
	config types.CipherContextConfig, reset bool) {

	log.Infof("%s, update cipher config, reset: %v\n",
		config.Key(), reset)
	if reset {
		unpublishCipherContextStatus(ctx, config.Key())
		return
	}
	status := getCipherContextStatus(ctx.zedagentCtx, config.Key())

	// nothing needs to be done
	if status == nil {
		if reset {
			return
		}
		status0 := types.CipherContextStatus{
			ContextID:          config.ContextID,
			HashScheme:         config.HashScheme,
			KeyExchangeScheme:  config.KeyExchangeScheme,
			EncryptionScheme:   config.EncryptionScheme,
			DeviceCertHash:     config.DeviceCertHash,
			ControllerCertHash: config.ControllerCertHash,
		}
		status = &status0
	}
	status.ClearErrorInfo()
	if err := updateCipherContextCerts(ctx, status); err != nil {
		errStr := fmt.Sprintf("%s, CipherContextUpdateCerts failed, %s",
			status.Key(), err)
		status.SetErrorInfo(agentName, errStr)
	}
	publishCipherContextStatus(ctx, *status)
}

// cipher context status update, triggers cipher block updates
func handleCipherContextStatusUpdate(ctx *getconfigContext,
	status types.CipherContextStatus, reset bool) {

	log.Infof("%s, update cipherblocks\n", status.Key())
	// app instances cloud init data
	appItems := ctx.pubAppInstanceConfig.GetAll()
	for _, item := range appItems {
		appCfg := item.(types.AppInstanceConfig)
		if updateCipherBlock(status, &appCfg.CipherBlockStatus,
			appCfg.Key(), reset) {
			log.Infof("%s, updating app instance cipherblock %s\n",
				status.Key(), appCfg.DisplayName)
			ctx.pubAppInstanceConfig.Publish(appCfg.Key(), appCfg)
		}
	}

	// data stores
	dsItems := ctx.pubDatastoreConfig.GetAll()
	for _, item := range dsItems {
		dsCfg := item.(types.DatastoreConfig)
		if updateCipherBlock(status, &dsCfg.CipherBlockStatus,
			dsCfg.Key(), reset) {
			log.Infof("%s, updating datastore cipherblock %s\n",
				status.Key(), dsCfg.Key())
			ctx.pubDatastoreConfig.Publish(dsCfg.Key(), dsCfg)
		}
	}

	// device networks
	netItems := ctx.pubNetworkXObjectConfig.GetAll()
	for _, item := range netItems {
		netCfg := item.(types.NetworkXObjectConfig)
		wifiCfgs := netCfg.WirelessCfg.Wifi
		change := false
		for _, wifiCfg := range wifiCfgs {
			if updateCipherBlock(status, &wifiCfg.CipherBlockStatus,
				netCfg.Key(), reset) {
				change = true
			}
		}
		if change {
			log.Infof("%s, updating network wifi cipherblock %s\n",
				status.Key(), netCfg.Key())
			ctx.pubNetworkXObjectConfig.Publish(netCfg.Key(), netCfg)
		}
	}
}

// cipherContext publish/get utilities
func updateCipherBlock(status types.CipherContextStatus,
	cipherBlock *types.CipherBlockStatus, key string, reset bool) bool {
	if !cipherBlock.IsCipher ||
		cipherBlock.CipherContextID != status.Key() {
		return false
	}
	log.Infof("%s, updating cipherblock\n", status.Key())

	// first mark the cipher block as not ready,
	// copy the relavant attributes, from cipher context to cipher block
	cipherBlock.ClearErrorInfo()
	cipherBlock.KeyExchangeScheme = status.KeyExchangeScheme
	cipherBlock.EncryptionScheme = status.EncryptionScheme

	ccert, dcert := getCipherContextCerts(status)
	if reset {
		ccert = []byte{}
		dcert = []byte{}
		errStr := fmt.Sprintf("CipherContext(%s) deleted for the cipherBlock",
			status.Key())
		cipherBlock.SetErrorInfo(agentName, errStr)
		return true
	}
	// when we have both the certificates,
	// mark the cipher block as valid
	if status.Error != "" {
		cipherBlock.SetErrorInfo(agentName, status.Error)
	} else {
		cipherBlock.ControllerCert = ccert
		cipherBlock.DeviceCert = dcert
		if len(ccert) != 0 && len(dcert) != 0 {
			log.Infof("cipherBlock is marked ready, %s\n",
				cipherBlock.CipherContextID)
		} else {
			errStr := fmt.Sprintf("%s, certs are not ready",
				cipherBlock.Key())
			cipherBlock.SetErrorInfo(agentName, errStr)
		}
	}
	return true
}

func getCipherContextCerts(status types.CipherContextStatus) ([]byte, []byte) {
	return status.ControllerCert, status.DeviceCert
}

// pub/sub utilities for cipher context config and status
func publishCipherContextConfig(ctx *getconfigContext,
	config types.CipherContextConfig) {
	key := config.Key()
	log.Debugf("publishCipherContext %s\n", key)
	pub := ctx.pubCipherContextConfig
	pub.Publish(key, config)
}

func unpublishCipherContextConfig(ctx *getconfigContext, key string) {
	log.Debugf("unpublishCipherContextConfig(%s)\n", key)
	pub := ctx.pubCipherContextConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCipherContext(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func getCipherContextStatus(ctx *zedagentContext,
	key string) *types.CipherContextStatus {
	pub := ctx.subCipherContextStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("getCipherContextStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.CipherContextStatus)
	return &status
}

func publishCipherContextStatus(ctx *getconfigContext,
	status types.CipherContextStatus) {
	key := status.Key()
	log.Debugf("publishCipherContextStatus %s\n", key)
	pub := ctx.pubCipherContextStatus
	pub.Publish(key, status)
}

func unpublishCipherContextStatus(ctx *getconfigContext, key string) {
	log.Debugf("unpublishCipherContextStatus(%s)\n", key)
	pub := ctx.pubCipherContextStatus
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCipherContextStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}
