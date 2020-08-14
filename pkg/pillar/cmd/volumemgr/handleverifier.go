// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Note that this function returns the entry even if Expired is set.
// Most callers should ignore such entries
func lookupVerifyImageConfig(ctx *volumemgrContext,
	key string) *types.VerifyImageConfig {

	pub := ctx.pubVerifyImageConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Debugf("lookupVerifyImageConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VerifyImageConfig)
	return &config
}

func publishVerifyImageConfig(ctx *volumemgrContext,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("publishVerifyImageConfig(%s)", key)
	pub := ctx.pubVerifyImageConfig
	pub.Publish(key, *config)
}

func unpublishVerifyImageConfig(ctx *volumemgrContext, key string) {

	log.Debugf("unpublishVerifyImageConfig(%s)", key)
	pub := ctx.pubVerifyImageConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVerifyImageConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

// MaybeAddVerifyImageConfigBlob publishes the verifier config
func MaybeAddVerifyImageConfigBlob(ctx *volumemgrContext, blob types.BlobStatus) (bool, types.ErrorAndTime) {

	log.Infof("MaybeAddVerifyImageConfigBlob for %s", blob.Sha256)

	var vic *types.VerifyImageConfig
	vic = lookupVerifyImageConfig(ctx, blob.Sha256)
	// If we have expired it we will create a new one and replace the old.
	// See delete handshake comment below.
	if vic != nil && !vic.Expired {
		vic.RefCount++
		log.Infof("MaybeAddVerifyImageConfigBlob: refcnt to %d for %s",
			vic.RefCount, blob.Sha256)
	} else {
		log.Infof("MaybeAddVerifyImageConfigBlob: add for %s", blob.Sha256)
		vic = &types.VerifyImageConfig{
			FileLocation: blob.Path,   // the source of the file to verify
			ImageSha256:  blob.Sha256, // the sha to verify
			Name:         blob.Sha256, // we are just going to use the sha for the verifier display
			RefCount:     1,
		}
		log.Debugf("MaybeAddVerifyImageConfigBlob - config: %+v", vic)
	}
	publishVerifyImageConfig(ctx, vic)
	log.Infof("MaybeAddVerifyImageConfigBlob done for %s", blob.Sha256)
	return true, types.ErrorAndTime{}
}

// MaybeRemoveVerifyImageConfig decreases the refcount
// The object is not deleted until MaybeDeleteVerifyImageConfig is called
// Thus MaybeAddVerifyImageConfig can be called to increment the refcount
func MaybeRemoveVerifyImageConfig(ctx *volumemgrContext, imageSha string) {

	log.Infof("MaybeRemoveVerifyImageConfig(%s)", imageSha)

	m := lookupVerifyImageConfig(ctx, imageSha)
	if m == nil {
		log.Infof("MaybeRemoveVerifyImageConfig: config missing for %s",
			imageSha)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveVerifyImageConfig: Attempting to reduce "+
			"0 RefCount. Image Details - Name: %s, "+
			"ImageSha256:%s", m.Name, m.ImageSha256)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveVerifyImageConfig: RefCount to %d for %s",
		m.RefCount, imageSha)
	publishVerifyImageConfig(ctx, m)

	if m.RefCount == 0 {
		log.Infof("MaybeRemoveVerifyImageConfig(%s): marking VerifyImageConfig as expired", imageSha)
		MaybeDeleteVerifyImageConfig(ctx, imageSha)
	}
	log.Infof("MaybeRemoveVerifyImageConfig done for %s", imageSha)
}

// MaybeDeleteVerifyImageConfig checks the refcount and if it is zero it
// initiates the delete handshake with the verifier. That handshake occurs
// after a MaybeRemoveVerifyImageConfig has dropped the refcount to zero
// thus after:
// 1. volumemgr publishes the VIC with RefCount=0
// 2. verifier publishes the VIS with RefCount=0
// At that point in time MaybeAddVerifyImageConfig can be called to increment
// the refcount, but if MaybeDeleteVerifyImageConfig is called we proceed with
// 3. volumemgr publishes the VIC with Expired=true (RefCount=0)
// 4. verifier publishes the VIS with Expired=true (RefCount=0) in response
// 5. handleVerifyImageStatusModify will check if a new VIC has been created
// in volumemgr post #4. If VIC has been recreated, it will do nothing.
// Otherwise it unpublishes the VIC. (A recreated VIC has Expired=false)
//
// Note that a VIC with Expired=true is effectively ignored; a replacement
// VIC is created should MaybeAddVerifyImage be called after #3.
// Also, any code doing a lookupVerifyImageStatus should ignore an Expired result
//
// 6. upon seeing the unpublish of the VIC the verifier deletes file and unpublishes the VIS
// at this point in time verifier might see a new VIC from volumemgr if it recreated it
// 7. handleVerifyImageStatusDelete will the unpublish the VIC if it has Expired set (if it was recreated it will not have Expired set)
func MaybeDeleteVerifyImageConfig(ctx *volumemgrContext, imageSha string) {

	log.Infof("MaybeDeleteVerifyImageConfig(%s)", imageSha)
	m := lookupVerifyImageConfig(ctx, imageSha)
	if m == nil {
		log.Infof("MaybeDeleteVerifyImageConfig: config missing for %s",
			imageSha)
		return
	}
	if m.Expired {
		log.Warnf("MaybeDeleteVerifyImageConfig: already Expired for %s",
			imageSha)
		return
	}
	if m.RefCount != 0 {
		log.Warnf("MaybeDeleteVerifyImageConfig: Attempting to delete but not zero "+
			"RefCount %d. Image Details - Name: %s, "+
			"ImageSha256:%s",
			m.RefCount, m.Name, m.ImageSha256)
		return
	}
	m.Expired = true
	publishVerifyImageConfig(ctx, m)
	log.Infof("MaybeDeleteVerifyImageConfig done for %s", imageSha)
}

func handleVerifyImageStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.VerifyImageStatus)
	ctx := ctxArg.(*volumemgrContext)
	log.Infof("handleVerifyImageStatusModify for ImageSha256: %s, "+
		" RefCount %d Expired %t", status.ImageSha256, status.RefCount,
		status.Expired)

	// We handle two special cases in the handshake here
	// 1. verifier added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. verifier set Expired in status in response to us setting Expired
	// in config. If we still have Expired and RefCount zero in the config
	// we delete the config, which will result in the file being deleted
	// in the verifier.

	config := lookupVerifyImageConfig(ctx, status.ImageSha256)
	if config == nil && status.RefCount == 0 {
		log.Infof("handleVerifyImageStatusModify adding RefCount=0 config %s",
			key)

		// Note: signature-related fields are filled in when
		// RefCount increases from zero in MaybeAddVerifyImageConfig
		n := types.VerifyImageConfig{
			Name:         status.Name,
			ImageSha256:  status.ImageSha256,
			Size:         status.Size,
			FileLocation: status.FileLocation,
			RefCount:     0,
		}
		publishVerifyImageConfig(ctx, &n)
		return
	}

	// If we still publish an Expired config with RefCount == 0 we unpublish it.
	// If config is not Expired it means it was recreated and we
	// ignore the Expired status
	if status.Expired && config != nil && config.RefCount == 0 && config.Expired {
		log.Infof("handleVerifyImageStatusModify delete config for %s",
			key)
		unpublishVerifyImageConfig(ctx, config.Key())
	} else if status.Expired {
		log.Infof("handleVerifyImageStatusModify ignore expired VerifyImageStatus; config not Expired for %s",
			key)
	}
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Infof("handleVerifyImageStatusModify skipped due to Pending* for"+
			" ImageSha256: %s", status.ImageSha256)
		return
	}
	updateStatusByBlob(ctx, status.ImageSha256)
	log.Infof("handleVerifyImageStatusModify done for %s", status.ImageSha256)
}

// Note that this function returns the entry even if Pending* or Expired is set.
// Most callers should ignore such entries
func lookupVerifyImageStatus(ctx *volumemgrContext,
	key string) *types.VerifyImageStatus {

	sub := ctx.subVerifyImageStatus
	s, _ := sub.Get(key)
	if s == nil {
		log.Debugf("lookupVerifyImageStatus(%s) not found", key)
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
	updateStatusByBlob(ctx, status.ImageSha256)
	log.Infof("handleVerifyImageStatusDelete done for %s", key)
}

//gcVerifyImageConfig marks all VerifyImageConfig with refCount = 0 as expired
func gcVerifyImageConfig(ctx *volumemgrContext) {
	verifyImageConfigMap := ctx.pubVerifyImageConfig.GetAll()

	for _, verifyImageConfigIntf := range verifyImageConfigMap {
		verifyImageConfig := verifyImageConfigIntf.(types.VerifyImageConfig)
		if verifyImageConfig.RefCount == 0 {
			log.Infof("gcVerifyImageConfig(%s): marking VerifyImageConfig as expired", verifyImageConfig.Key())
			MaybeDeleteVerifyImageConfig(ctx, verifyImageConfig.Key())
		}
	}
}
