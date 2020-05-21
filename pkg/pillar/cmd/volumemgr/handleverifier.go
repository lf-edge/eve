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

// MaybeAddVerifyImageConfigBlob publishes the verifier config
func MaybeAddVerifyImageConfigBlob(ctx *volumemgrContext, objType string, blob types.BlobStatus, signature SignatureVerifier) (bool, types.ErrorAndTime) {

	log.Infof("MaybeAddVerifyImageConfigBlob for %s", blob.Sha256)

	var vic *types.VerifyImageConfig
	vic = lookupVerifyImageConfig(ctx, objType, blob.Sha256)
	if vic != nil {
		vic.RefCount++
		log.Infof("MaybeAddVerifyImageConfigBlob: refcnt to %d for %s",
			vic.RefCount, blob.Sha256)
	} else {
		log.Infof("MaybeAddVerifyImageConfigBlob: add for %s", blob.Sha256)
		vic = &types.VerifyImageConfig{
			VerifyConfig: types.VerifyConfig{
				FileLocation:     blob.Path,   // the source of the file to verify
				ImageSha256:      blob.Sha256, // the sha to verify
				Name:             blob.Sha256, // we are just going to use the sha for the verifier display
				CertificateChain: signature.CertificateChain,
				ImageSignature:   signature.Signature,
				SignatureKey:     signature.PublicKey,
			},
			RefCount: 1,
		}
		log.Debugf("MaybeAddVerifyImageConfigBlob - config: %+v", vic)
	}
	publishVerifyImageConfig(ctx, objType, vic)
	log.Infof("MaybeAddVerifyImageConfigBlob done for %s", blob.Sha256)
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

	// update the BlobStatus
	if blob := lookupBlobStatus(ctx, status.ImageSha256); blob != nil {
		log.Infof("handleVerifyImageStatusModify(%s): Update State %d to %d, Path %s to %s", blob.Sha256, blob.State, status.State, blob.Path, status.FileLocation)
		blob.State = status.State
		blob.Path = status.FileLocation
		if status.HasError() {
			log.Errorf("handleVerifyImageStatusModify(%s): Received error from verifier: %s", blob.Sha256, status.Error)
			blob.SetErrorWithSource(status.Error,
				types.VerifyImageStatus{}, status.ErrorTime)
		} else if blob.IsErrorSource(types.VerifyImageStatus{}) {
			log.Infof("handleVerifyImageStatusModify(%s): Clearing verifier error %s", blob.Sha256, blob.Error)
			blob.ClearErrorWithSource()
		}
		// also persist, if needed
		if blob.State == types.VERIFIED && !blob.HasPersistRef {
			log.Infof("handleVerifyImageStatusModify: Adding PersistImageStatus reference for blob: %s", blob.Sha256)
			AddOrRefCountPersistImageStatus(ctx, status.Name, status.ObjType, status.FileLocation, status.ImageSha256, status.Size)
			blob.HasPersistRef = true
		}

		publishBlobStatus(ctx, blob)
	}

	// update the status - do not change the sizes
	updateStatus(ctx, status.ObjType, status.ImageSha256)
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
	// update the status - do not change the sizes
	updateStatus(ctx, status.ObjType, status.ImageSha256)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupVerifyImageConfig(ctx, status.ObjType, status.ImageSha256)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleVerifyImageStatusDelete delete config for %s",
			key)
		unpublishVerifyImageConfig(ctx, status.ObjType, config.Key())
	}
	log.Infof("handleVerifyImageStatusDelete done for %s", key)
}
