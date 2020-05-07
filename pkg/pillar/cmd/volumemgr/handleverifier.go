// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func lookupVerifyImageConfig(ctx *volumemgrContext, objType,
	key string) *types.VerifyImageConfig {

	pub := ctx.publication(types.VerifyImageConfig{}, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupVerifyImageConfig(%s) not found for %s",
			key, objType)
		return nil
	}
	config := c.(types.VerifyImageConfig)
	return &config
}

func publishVerifyImageConfig(ctx *volumemgrContext, objType string,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("publishVerifyImageConfig(%s/%s)", key, objType)
	pub := ctx.publication(*config, objType)
	pub.Publish(key, *config)
}

func unpublishVerifyImageConfig(ctx *volumemgrContext, objType string, key string) {

	log.Debugf("unpublishVerifyImageConfig(%s)", key)
	pub := ctx.publication(types.VerifyImageConfig{}, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVerifyImageConfig(%s) not found for %s", key, objType)
		return
	}
	pub.Unpublish(key)
}

// If checkCerts is set this can return false. Otherwise not.
func MaybeAddVerifyImageConfig(ctx *volumemgrContext,
	status types.VolumeStatus, checkCerts bool) (bool, types.ErrorAndTime) {

	log.Infof("MaybeAddVerifyImageConfig for %s, checkCerts: %v",
		status.BlobSha256, checkCerts)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts {
		certObjStatus := lookupCertObjStatus(ctx, status.AppInstID.String())
		displaystr := status.VolumeID.String()
		ret, err := status.IsCertsAvailable(displaystr)
		if err != nil {
			log.Fatalf("%s, invalid certificate configuration", displaystr)
		}
		if ret {
			if ret, errInfo := status.HandleCertStatus(displaystr, *certObjStatus); !ret {
				return false, errInfo
			}
		}
	}

	m := lookupVerifyImageConfig(ctx, status.ObjType, status.BlobSha256)
	if m != nil {
		m.RefCount++
		log.Infof("MaybeAddVerifyImageConfig: refcnt to %d for %s",
			m.RefCount, status.BlobSha256)
		publishVerifyImageConfig(ctx, status.ObjType, m)
	} else {
		log.Infof("MaybeAddVerifyImageConfig: add for %s, IsContainer: %t",
			status.BlobSha256, status.DownloadOrigin.IsContainer)
		n := types.VerifyImageConfig{
			ImageID: status.VolumeID,
			VerifyConfig: types.VerifyConfig{
				Name:             status.DisplayName,
				ImageSha256:      status.BlobSha256,
				CertificateChain: status.DownloadOrigin.CertificateChain,
				ImageSignature:   status.DownloadOrigin.ImageSignature,
				SignatureKey:     status.DownloadOrigin.SignatureKey,
				FileLocation:     status.FileLocation,
			},
			IsContainer: status.DownloadOrigin.IsContainer,
			RefCount:    1,
		}
		publishVerifyImageConfig(ctx, status.ObjType, &n)
		log.Debugf("MaybeAddVerifyImageConfig - config: %+v", n)
	}
	log.Infof("MaybeAddVerifyImageConfig done for %s", status.BlobSha256)
	return true, types.ErrorAndTime{}
}

// MaybeRemoveVerifyImageConfig decreases the refcount and if it
// reaches zero the verifier might start a GC using the Expired exchange
func MaybeRemoveVerifyImageConfig(ctx *volumemgrContext, objType, imageSha string) {

	log.Infof("MaybeRemoveVerifyImageConfig(%s) for %s", imageSha, objType)

	m := lookupVerifyImageConfig(ctx, objType, imageSha)
	if m == nil {
		log.Infof("MaybeRemoveVerifyImageConfig: config missing for %s",
			imageSha)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveVerifyImageConfig: Attempting to reduce "+
			"0 RefCount. Image Details - Name: %s, ImageID: %s, "+
			"ImageSha256:%s, IsContainer: %t",
			m.Name, m.ImageID, m.ImageSha256, m.IsContainer)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveVerifyImageConfig: RefCount to %d for %s",
		m.RefCount, imageSha)
	if m.RefCount == 0 {
		unpublishVerifyImageConfig(ctx, objType, m.Key())
	} else {
		publishVerifyImageConfig(ctx, objType, m)
	}
	log.Infof("MaybeRemoveVerifyImageConfig done for %s", imageSha)
}

func handleVerifyImageStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.VerifyImageStatus)
	ctx := ctxArg.(*volumemgrContext)
	log.Infof("handleVerifyImageStatusModify for ImageSha256: %s, "+
		" RefCount %d", status.ImageSha256, status.RefCount)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Infof("handleVerifyImageStatusModify skipped due to Pending* for"+
			" ImageSha256: %s", status.ImageSha256)
		return
	}
	updateVolumeStatus(ctx, status.ObjType, status.ImageSha256, status.ImageID)
	updateContentTreeStatus(ctx, status.ImageSha256, status.ImageID)
	log.Infof("handleVerifyImageStatusModify done for %s", status.ImageSha256)
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerifyImageStatus(ctx *volumemgrContext, objType,
	key string) *types.VerifyImageStatus {

	sub := ctx.subscription(types.VerifyImageStatus{}, objType)
	s, _ := sub.Get(key)
	if s == nil {
		log.Infof("lookupVerifyImageStatus(%s) not found for %s",
			key, objType)
		return nil
	}
	status := s.(types.VerifyImageStatus)
	return &status
}

func handleVerifyImageStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := statusArg.(types.VerifyImageStatus)
	log.Infof("handleVerifyImageStatusDelete for %s", key)
	ctx := ctxArg.(*volumemgrContext)
	updateVolumeStatus(ctx, status.ObjType, status.ImageSha256, status.ImageID)
	updateContentTreeStatus(ctx, status.ImageSha256, status.ImageID)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupVerifyImageConfig(ctx, status.ObjType, status.ImageSha256)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleVerifyImageStatusDelete delete config for %s",
			key)
		unpublishVerifyImageConfig(ctx, status.ObjType, config.Key())
	}
	log.Infof("handleVerifyImageStatusDelete done for %s", key)
}
