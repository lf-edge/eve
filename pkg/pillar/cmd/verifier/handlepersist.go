// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Handlers for PersistImageStatus

package verifier

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
	"os"
)

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

func handlePersistImageStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.PersistImageStatus)
	log.Infof("handlePersistImageStatusDelete for %s refcount %d expired %t",
		key, status.RefCount, status.Expired)

	_, err := os.Stat(status.FileLocation)
	if err == nil {
		log.Infof("handlePersistImageStatusDelete removing %s",
			status.FileLocation)
		if err := os.RemoveAll(status.FileLocation); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Errorf("handlePersistImageStatusDelete: Unable to delete %s:  %s",
			status.FileLocation, err)
	}
	log.Infof("handlePersistImageStatusDelete done %s", key)
}
