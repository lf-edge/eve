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

func lookupPersistImageConfig(ctx *zedmanagerContext,
	sha string) *types.PersistImageConfig {

	pub := ctx.pubAppImgPersistConfig
	c, _ := pub.Get(sha)
	if c == nil {
		log.Infof("lookupPersistImageConfig(%s) not found\n",
			sha)
		return nil
	}
	config := c.(types.PersistImageConfig)
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
			ImageID: ss.ImageID,
			VerifyConfig: types.VerifyConfig{
				Name:             ss.Name,
				ImageSha256:      ss.ImageSha256,
				CertificateChain: ss.CertificateChain,
				ImageSignature:   ss.ImageSignature,
				SignatureKey:     ss.SignatureKey,
			},
			IsContainer: ss.IsContainer,
			RefCount:    1,
		}
		publishVerifyImageConfig(ctx, &n)
		log.Debugf("MaybeAddVerifyImageConfig - config: %+v\n", n)
	}
	log.Infof("MaybeAddVerifyImageConfig done for %s\n", imageID)
	return true, types.ErrorInfo{}
}

// MaybeRemoveVerifyImageConfig decreases the refcount and if it
// reaches zero the verifier might start a GC using the Expired exchange
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
	if m.RefCount == 0 {
		unpublishVerifyImageConfig(ctx, m.Key())
	} else {
		publishVerifyImageConfig(ctx, m)
	}
	log.Infof("MaybeRemoveVerifyImageConfig done for %s\n", imageID)
}

func publishVerifyImageConfig(ctx *zedmanagerContext,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("publishVerifyImageConfig(%s)\n", key)
	pub := ctx.pubAppImgVerifierConfig
	pub.Publish(key, *config)
}

func unpublishVerifyImageConfig(ctx *zedmanagerContext, key string) {

	log.Debugf("unpublishVerifyImageConfig(%s)\n", key)
	pub := ctx.pubAppImgVerifierConfig
	pub.Unpublish(key)
}

func publishPersistImageConfig(ctx *zedmanagerContext,
	config *types.PersistImageConfig) {

	key := config.Key()
	log.Debugf("publishPersistImageConfig(%s)\n", key)
	pub := ctx.pubAppImgPersistConfig
	pub.Publish(key, *config)
}

func unpublishPersistImageConfig(ctx *zedmanagerContext, key string) {

	log.Debugf("unpublishPersistImageConfig(%s)\n", key)
	pub := ctx.pubAppImgPersistConfig
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
	// Make sure the PersistImageConfig has the sum of the refcounts
	// for the sha
	if status.ImageSha256 != "" {
		updatePersistImageConfig(ctx, status.ImageSha256)
	}
	updateAIStatusWithStorageImageID(ctx, status.ImageID)
	log.Infof("handleVerifyImageStatusModify done for %s", status.ImageID)
}

// Make sure the PersistImageConfig has the sum of the refcounts
// for the sha
func updatePersistImageConfig(ctx *zedmanagerContext, imageSha string) {
	log.Infof("updatePersistImageConfig(%s)", imageSha)
	if imageSha == "" {
		return
	}
	var refcount uint
	sub := ctx.subAppImgVerifierStatus
	items := sub.GetAll()
	name := ""
	for _, s := range items {
		status := s.(types.VerifyImageStatus)
		if status.ImageSha256 == imageSha {
			log.Infof("Adding RefCount %d from %s to %s",
				status.RefCount, status.ImageID, imageSha)
			refcount += status.RefCount
			name = status.Name
		}
	}
	config := lookupPersistImageConfig(ctx, imageSha)
	if config == nil {
		log.Errorf("updatePersistImageConfig(%s): config not found",
			imageSha)
		if refcount == 0 {
			return
		}
		n := types.PersistImageConfig{
			VerifyConfig: types.VerifyConfig{
				Name:        name,
				ImageSha256: imageSha,
			},
			RefCount: 0,
		}
		config = &n
	} else if config.RefCount == refcount {
		log.Infof("updatePersistImageConfig(%s): no RefCount change %d",
			imageSha, refcount)
		return
	}
	log.Infof("updatePersistImageConfig(%s): RefCount change %d to %d",
		imageSha, config.RefCount, refcount)
	config.RefCount = refcount
	publishPersistImageConfig(ctx, config)
}

// Calculate sum of the refcounts for the config for a particular sha
func sumVerifyImageRefCount(ctx *zedmanagerContext, imageSha string) uint {
	log.Infof("sumVerifyImageRefCount(%s)", imageSha)
	if imageSha == "" {
		return 0
	}
	var refcount uint
	pub := ctx.pubAppImgVerifierConfig
	items := pub.GetAll()
	for _, c := range items {
		config := c.(types.VerifyImageConfig)
		if config.ImageSha256 == imageSha {
			log.Infof("Adding RefCount %d from %s to %s",
				config.RefCount, config.ImageID, imageSha)
			refcount += config.RefCount
		}
	}
	return refcount
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerifyImageStatus(ctx *zedmanagerContext,
	imageID uuid.UUID) *types.VerifyImageStatus {

	sub := ctx.subAppImgVerifierStatus
	s, _ := sub.Get(imageID.String())
	if s == nil {
		log.Infof("lookupVerifyImageStatus(%s) not found\n", imageID)
		return nil
	}
	status := s.(types.VerifyImageStatus)
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
		unpublishVerifyImageConfig(ctx, config.Key())
	}
	// Make sure the PersistImageConfig has the sum of the refcounts
	// for the sha
	if status.ImageSha256 != "" {
		updatePersistImageConfig(ctx, status.ImageSha256)
	}
	log.Infof("handleVerifyImageStatusDelete done for %s\n", key)
}

func lookupPersistImageStatus(ctx *zedmanagerContext,
	imageSha string) *types.PersistImageStatus {

	if imageSha == "" {
		return nil
	}
	sub := ctx.subAppImgPersistStatus
	s, _ := sub.Get(imageSha)
	if s == nil {
		log.Infof("lookupPersistImageStatus(%s) not found\n", imageSha)
		return nil
	}
	status := s.(types.PersistImageStatus)
	return &status
}

func handlePersistImageStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.PersistImageStatus)
	ctx := ctxArg.(*zedmanagerContext)

	log.Infof("handlePersistImageStatusModify for sha: %s, "+
		" RefCount %d Expired %t", status.ImageSha256, status.RefCount,
		status.Expired)

	// We handle two special cases in the handshake here
	// 1. verifier added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. verifier set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupPersistImageConfig(ctx, status.ImageSha256)
	if config == nil && status.RefCount == 0 {
		log.Infof("handlePersistImageStatusModify adding RefCount=0 config %s\n",
			key)
		n := types.PersistImageConfig{
			VerifyConfig: types.VerifyConfig{
				Name:        status.Name,
				ImageSha256: status.ImageSha256,
			},
			RefCount: 0,
		}
		publishPersistImageConfig(ctx, &n)
	} else if config != nil && config.RefCount == 0 && status.Expired &&
		sumVerifyImageRefCount(ctx, status.ImageSha256) == 0 {
		log.Infof("handlePersistImageStatusModify expired - deleting config %s\n",
			key)
		unpublishPersistImageConfig(ctx, config.Key())
	}
	log.Infof("handlePersistImageStatusModify done %s\n", key)
}

func handlePersistImageStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.PersistImageStatus)
	log.Infof("handlePersistImageStatusDelete for %s refcount %d expired %t\n",
		key, status.RefCount, status.Expired)
	ctx := ctxArg.(*zedmanagerContext)
	unpublishPersistImageConfig(ctx, key)
	log.Infof("handlePersistImageStatusDelete done %s\n", key)
}
