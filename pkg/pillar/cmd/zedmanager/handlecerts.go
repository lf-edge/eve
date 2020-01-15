// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func handleCertObjStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.CertObjStatus)
	ctx := ctxArg.(*zedmanagerContext)
	uuidStr := status.Key()

	log.Infof("handlCertObjStatusModify for %s\n", uuidStr)
	updateAIStatusUUID(ctx, uuidStr)
	log.Infof("handleCertObjStatusModify done for %s\n", uuidStr)
}

func handleCertObjStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	log.Infof("handleCertObjtatusDelete for %s\n", key)
	updateAIStatusUUID(ctx, key)
	log.Infof("handleCertObjStatusDelete done for %s\n", key)
}

// Callers must be careful to publish any changes to CertObjStatus
func lookupCertObjStatus(ctx *zedmanagerContext, key string) *types.CertObjStatus {

	sub := ctx.subCertObjStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupCertObjStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.CertObjStatus)
	return &status
}
