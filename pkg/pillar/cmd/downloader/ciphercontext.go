// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"bytes"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleCipherContextCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleCipherContextImpl(ctxArg, key, configArg)
}

func handleCipherContextModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleCipherContextImpl(ctxArg, key, configArg)
}

func handleCipherContextImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	cipherContext := configArg.(types.CipherContext)
	log.Functionf("handleCipherContextImpl for %s", key)
	sub := ctx.subDatastoreConfig
	items := sub.GetAll()
	for _, el := range items {
		dsConfig := el.(types.DatastoreConfig)
		if dsConfig.CipherContextID == cipherContext.ContextID {
			checkAndUpdateDownloadableObjects(ctx, dsConfig.UUID)
			checkAndUpdateResolveConfig(ctx, dsConfig.UUID)
		}
	}
	log.Functionf("handleCipherContextImpl for %s, done", key)
}

func handleControllerCertCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleControllerCertImpl(ctxArg, key, configArg)
}

func handleControllerCertModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleControllerCertImpl(ctxArg, key, configArg)
}

func handleControllerCertImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	controllerCert := configArg.(types.ControllerCert)
	log.Functionf("handleControllerCertImpl for %s", key)
	sub := ctx.decryptCipherContext.SubCipherContext
	items := sub.GetAll()
	for _, el := range items {
		cc := el.(types.CipherContext)
		if bytes.Equal(cc.ControllerCertHash, controllerCert.CertHash) {
			handleCipherContextImpl(ctx, cc.Key(), cc)
		}
	}
	log.Functionf("handleControllerCertImpl for %s, done", key)
}

func handleEdgeNodeCertCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleEdgeNodeCertImpl(ctxArg, key, configArg)
}

func handleEdgeNodeCertModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleEdgeNodeCertImpl(ctxArg, key, configArg)
}

func handleEdgeNodeCertImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*downloaderContext)
	edgeNodeCert := configArg.(types.EdgeNodeCert)
	log.Functionf("handleEdgeNodeCertImpl for %s", key)
	sub := ctx.decryptCipherContext.SubCipherContext
	items := sub.GetAll()
	for _, el := range items {
		cc := el.(types.CipherContext)
		if bytes.Equal(cc.DeviceCertHash, edgeNodeCert.CertID) {
			handleCipherContextImpl(ctx, cc.Key(), cc)
		}
	}
	log.Functionf("handleEdgeNodeCertImpl for %s, done", key)
}
