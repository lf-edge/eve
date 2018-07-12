// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
)

func handleCertObjStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastCertObjStatus(statusArg)
	ctx := ctxArg.(*zedmanagerContext)
	uuidStr := status.Key()

	log.Printf("handlCertObjStatusModify for %s\n", uuidStr)
	if status.Key() != key {
		log.Printf("handleCertObjStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	updateAIStatusUUID(ctx, uuidStr)
	log.Printf("handleCertObjStatusModify done for %s\n", uuidStr)
}

func handleCertObjStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedmanagerContext)
	log.Printf("handleCertObjtatusDelete for %s\n", key)
	updateAIStatusUUID(ctx, key)
	log.Printf("handleCertObjStatusDelete done for %s\n", key)
}

// Callers must be careful to publish any changes to NetworkObjectStatus
func lookupCertObjStatus(ctx *zedmanagerContext, key string) *types.CertObjStatus {

	sub := ctx.subCertObjStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Printf("lookupCertObjStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastCertObjStatus(st)
	if status.Key() != key {
		log.Printf("lookupCertObjStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}
