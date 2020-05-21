// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handlers for PersistImageStatus

package verifier

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Callers must be careful to publish any changes to PersistImageStatus
func lookupPersistImageStatus(ctx *verifierContext, objType string,
	imageSha string) *types.PersistImageStatus {

	if imageSha == "" {
		return nil
	}
	sub := verifierPersistStatusSubscription(ctx, objType)
	s, _ := sub.Get(imageSha)
	if s == nil {
		log.Infof("lookupPersistImageStatus(%s) not found for %s", imageSha, objType)
		return nil
	}
	status := s.(types.PersistImageStatus)
	return &status
}

func publishPersistImageStatus(ctx *verifierContext,
	status *types.PersistImageStatus) {
	log.Debugf("publishPersistImageStatus(%s, %s)",
		status.ObjType, status.ImageSha256)

	pub := verifierPersistStatusPublication(ctx, status.ObjType)
	key := status.Key()
	pub.Publish(key, *status)
}

func handlePersistImageStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.PersistImageStatus)
	log.Infof("handlePersistImageStatusDelete for %s refcount %d expired %t",
		key, status.RefCount, status.Expired)
	// No more use for this image. Delete

	_, err := os.Stat(status.FileLocation)
	if err == nil {
		log.Infof("handlePersistImageStatusDelete removing %s", status.FileLocation)
		if err := os.RemoveAll(status.FileLocation); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Errorf("handlePersistImageStatusDelete: Unable to delete: %s. %s", status.FileLocation, err.Error())
	}
	log.Infof("handlePersistImageStatusDelete done %s", key)
}
