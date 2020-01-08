// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

func lookupImageStatusForApp(
	ctx *zedmanagerContext, appUUID uuid.UUID,
	imageSha string) *types.ImageStatus {

	imageStatusList := ctx.subImageStatus.GetAll()
	for _, item := range imageStatusList {
		status := item.(types.ImageStatus)
		if status.AppInstUUID == appUUID && status.ImageSha256 == imageSha {
			log.Debugf("lookupImageStatusForApp: IS found. appUUID: %s, "+
				"imageSha: %s", appUUID.String(), imageSha)
			return &status
		}
	}
	log.Debugf("lookupImageStatusForApp: Image Status NOT found. appUUID: %s, "+
		"imageSha: %s", appUUID.String(), imageSha)
	return nil
}
