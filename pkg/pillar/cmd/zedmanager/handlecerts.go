// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
)

func handleCertObjStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastCertObjStatus(statusArg)
	ctx := ctxArg.(*zedmanagerContext)
	uuidStr := status.Key()

	log.Infof("handlCertObjStatusModify for %s\n", uuidStr)
	if status.Key() != key {
		log.Errorf("handleCertObjStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
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

// Callers must be careful to publish any changes to NetworkObjectStatus
func lookupCertObjStatus(ctx *zedmanagerContext, key string) *types.CertObjStatus {

	sub := ctx.subCertObjStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupCertObjStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastCertObjStatus(st)
	if status.Key() != key {
		log.Errorf("lookupCertObjStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}
