// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

func lookupVerifyImageConfig(ctx *zedmanagerContext,
	imageID uuid.UUID) *types.VerifyImageConfig {

	pub := ctx.pubAppImgVerifierConfig
	c, _ := pub.Get(imageID.String())
	if c == nil {
		log.Infof("lookupVerifyImageConfig(%s) not found\n",
			imageID)
		return nil
	}
	config := c.(types.VerifyImageConfig)
	return &config
}

// If checkCerts is set this can return false. Otherwise not.
func MaybeAddVerifyImageConfig(ctx *zedmanagerContext, uuidStr string,
	ss types.StorageStatus, checkCerts bool) (bool, types.ErrorInfo) {

	imageID := ss.ImageID
	log.Infof("MaybeAddVerifyImageConfig for %s, checkCerts: %v, "+
		"isContainer: %v\n", imageID, checkCerts, ss.IsContainer)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts {
		certObjStatus := lookupCertObjStatus(ctx, uuidStr)
		displaystr := imageID.String()
		ret, err := ss.IsCertsAvailable(displaystr)
		if err != nil {
			log.Fatalf("%s, invalid certificate configuration", displaystr)
		}
		if ret {
			if ret, errInfo := ss.HandleCertStatus(displaystr, *certObjStatus); !ret {
				return false, errInfo
			}
		}
	}

	m := lookupVerifyImageConfig(ctx, imageID)
	if m != nil {
		m.RefCount += 1
		log.Infof("MaybeAddVerifyImageConfig: refcnt to %d for %s\n",
			m.RefCount, imageID)
		if m.IsContainer != ss.IsContainer {
			log.Infof("MaybeAddVerifyImageConfig: change IsContainer to %t for %s",
				ss.IsContainer, imageID)
		}
		m.IsContainer = ss.IsContainer
		if m.ImageSha256 != ss.ImageSha256 {
			log.Infof("MaybeAddVerifyImageConfig: change ImageSha256 to %s for %s",
				ss.ImageSha256, imageID)
		}
		m.ImageSha256 = ss.ImageSha256
		publishVerifyImageConfig(ctx, m)
	} else {
		log.Infof("MaybeAddVerifyImageConfig: add for %s, IsContainer: %t",
			imageID, ss.IsContainer)
		n := types.VerifyImageConfig{
			ImageID:          ss.ImageID,
			Name:             ss.Name,
			ImageSha256:      ss.ImageSha256,
			RefCount:         1,
			CertificateChain: ss.CertificateChain,
			ImageSignature:   ss.ImageSignature,
			SignatureKey:     ss.SignatureKey,
			IsContainer:      ss.IsContainer,
		}
		publishVerifyImageConfig(ctx, &n)
		log.Debugf("MaybeAddVerifyImageConfig - config: %+v\n", n)
	}
	log.Infof("MaybeAddVerifyImageConfig done for %s\n", imageID)
	return true, types.ErrorInfo{}
}

// MaybeRemoveVerifyImageConfig decreases the refcount and if it
// reaches zero it removes the VerifyImageConfig
func MaybeRemoveVerifyImageConfig(ctx *zedmanagerContext, imageID uuid.UUID) {

	log.Infof("MaybeRemoveVerifyImageConfig for %s\n", imageID)

	m := lookupVerifyImageConfig(ctx, imageID)
	if m == nil {
		log.Infof("MaybeRemoveVerifyImageConfig: config missing for %s\n",
			imageID)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveVerifyImageConfig: Attempting to reduce "+
			"0 RefCount. Image Details - Name: %s, ImageID: %s, "+
			"ImageSha256:%s, IsContainer: %t",
			m.Name, m.ImageID, m.ImageSha256, m.IsContainer)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveVerifyImageConfig: RefCount to %d for %s\n",
		m.RefCount, imageID)
	log.Infof("MaybeRemoveVerifyImageConfig done for %s\n", imageID)
	publishVerifyImageConfig(ctx, m)
}

func publishVerifyImageConfig(ctx *zedmanagerContext,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("publishVerifyImageConfig(%s)\n", key)
	pub := ctx.pubAppImgVerifierConfig
	pub.Publish(key, *config)
}

func unpublishVerifyImageConfig(ctx *zedmanagerContext,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("unpublishVerifyImageConfig(%s)\n", key)
	pub := ctx.pubAppImgVerifierConfig
	pub.Unpublish(key)
}

func handleVerifyImageStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VerifyImageStatus)
	ctx := ctxArg.(*zedmanagerContext)
	log.Infof("handleVerifyImageStatusModify for ImageID: %s, "+
		" RefCount %d\n", status.ImageID, status.RefCount)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Infof("handleVerifyImageStatusModify skipped due to Pending* for"+
			" ImageID: %s", status.ImageID)
		return
	}

	// We handle two special cases in the handshake here
	// 1. verifier added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. verifier set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupVerifyImageConfig(ctx, status.ImageID)
	if config == nil && status.RefCount == 0 {
		log.Infof("handleVerifyImageStatusModify adding RefCount=0 config %s\n",
			key)
		n := types.VerifyImageConfig{
			ImageID:     status.ImageID,
			Name:        status.Name,
			ImageSha256: status.ImageSha256,
			// IsContainer might not be known by verifier
			IsContainer: status.IsContainer,
			RefCount:    0,
		}
		publishVerifyImageConfig(ctx, &n)
		return
	}
	if config != nil && config.RefCount == 0 && status.Expired {
		log.Infof("handleVerifyImageStatusModify expired - deleting config %s\n",
			key)
		unpublishVerifyImageConfig(ctx, config)
		return
	}

	// Normal update work
	updateAIStatusWithStorageImageID(ctx, status.ImageID)
	log.Infof("handleVerifyImageStatusModify done for %s", status.ImageID)
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerifyImageStatus(ctx *zedmanagerContext,
	imageID uuid.UUID) *types.VerifyImageStatus {

	sub := ctx.subAppImgVerifierStatus
	c, _ := sub.Get(imageID.String())
	if c == nil {
		log.Infof("lookupVerifyImageStatus(%s) not found\n", imageID)
		return nil
	}
	status := c.(types.VerifyImageStatus)
	return &status
}

func handleVerifyImageStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VerifyImageStatus)
	log.Infof("handleVerifyImageStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusImageID(ctx, status.ImageID)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupVerifyImageConfig(ctx, status.ImageID)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleVerifyImageStatusDelete delete config for %s\n",
			key)
		unpublishVerifyImageConfig(ctx, config)
	}
	log.Infof("handleVerifyImageStatusDelete done for %s\n", key)
}
