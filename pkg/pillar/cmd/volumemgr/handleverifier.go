// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Note that this function returns the entry even if Expired is set.
// Most callers should ignore such entries
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

// MaybeAddVerifyImageConfig publishes the verifier config to the verifier
// If checkCerts is set this can return false. Otherwise not.
func MaybeAddVerifyImageConfig(ctx *volumemgrContext,
	status types.ContentTreeStatus, checkCerts bool) (bool, types.ErrorAndTime) {

	log.Infof("MaybeAddVerifyImageConfig for %s, checkCerts: %v",
		status.ContentSha256, checkCerts)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts {
		certObjStatus := lookupCertObjStatus(ctx, status.ContentID.String())
		displaystr := status.ContentID.String()
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

	m := lookupVerifyImageConfig(ctx, status.ObjType, status.ContentSha256)
	// If we have expired it we will create a new one and replace the old.
	// See delete handshake comment below.
	if m != nil && !m.Expired {
		if m.RefCount == 0 {
			// VerifyImageStatus + Config might have been
			// created from file. Fill in potentially missing
			// fields.
			m.CertificateChain = status.CertificateChain
			m.ImageSignature = status.ImageSignature
			m.SignatureKey = status.SignatureKey
		}
		m.RefCount++
		log.Infof("MaybeAddVerifyImageConfig: refcnt to %d for %s",
			m.RefCount, status.ContentSha256)

		publishVerifyImageConfig(ctx, status.ObjType, m)
	} else {
		log.Infof("MaybeAddVerifyImageConfig: add for %s, IsContainer: %t",
			status.ContentSha256, status.IsContainer())
		n := types.VerifyImageConfig{
			ImageID:          status.ContentID,
			Name:             status.DisplayName,
			ImageSha256:      status.ContentSha256,
			CertificateChain: status.CertificateChain,
			ImageSignature:   status.ImageSignature,
			SignatureKey:     status.SignatureKey,
			FileLocation:     status.FileLocation,
			IsContainer:      status.IsContainer(),
			RefCount:         1,
		}
		publishVerifyImageConfig(ctx, status.ObjType, &n)
		log.Debugf("MaybeAddVerifyImageConfig - config: %+v", n)
	}
	log.Infof("MaybeAddVerifyImageConfig done for %s", status.ContentSha256)
	return true, types.ErrorAndTime{}
}

// MaybeRemoveVerifyImageConfig decreases the refcount
// The object is not deleted until MaybeDeleteVerifyImageConfig is called
// Thus MaybeAddVerifyImageConfig can be called to increment the refcount
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
	publishVerifyImageConfig(ctx, objType, m)
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
// Also, any code doing a lookupVerifyImageStatus will ignore an Expired result
//
// 6. upon seeing the unpublish of the VIC the verifier deletes file and unpublishes the VIS
// at this point in time verifier might see a new VIC from volumemgr if it recreated it
// 7. handleVerifyImageStatusDelete will the unpublish the VIC if it has Expired set (if it was recreated it will not have Expired set)
func MaybeDeleteVerifyImageConfig(ctx *volumemgrContext, objType, imageSha string) {

	log.Infof("MaybeRemoveVerifyImageConfig(%s) for %s", imageSha, objType)

	m := lookupVerifyImageConfig(ctx, objType, imageSha)
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
			"RefCount %d. Image Details - Name: %s, ImageID: %s, "+
			"ImageSha256:%s, IsContainer: %t",
			m.RefCount, m.Name, m.ImageID, m.ImageSha256, m.IsContainer)
		return
	}
	m.Expired = true
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

	config := lookupVerifyImageConfig(ctx, status.ObjType, status.ImageSha256)
	if config == nil && status.RefCount == 0 {
		log.Infof("handleVerifyImageStatusModify adding RefCount=0 config %s",
			key)

		// Note: signature-related fields are filled in when
		// RefCount increases from zero in MaybeAddVerifyImageConfig
		n := types.VerifyImageConfig{
			ImageID:      status.ImageID, // XXX delete? empty
			Name:         status.Name,
			ImageSha256:  status.ImageSha256,
			Size:         status.Size,
			FileLocation: status.FileLocation,
			IsContainer:  status.IsContainer,
			RefCount:     0,
		}
		publishVerifyImageConfig(ctx, status.ObjType, &n)
		return
	}

	// If we still publish an Expired config with RefCount == 0 we unpublish it.
	// If config is not Expired it means it was recreated and we
	// ignore the Expired status
	if status.Expired && config != nil && config.RefCount == 0 && config.Expired {
		log.Infof("handleVerifyImageStatusModify delete config for %s",
			key)
		unpublishVerifyImageConfig(ctx, status.ObjType, config.Key())
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
	updateStatus(ctx, status.ObjType, status.ImageSha256, status.ImageID)
	log.Infof("handleVerifyImageStatusModify done for %s", status.ImageSha256)
}

// Note that this function returns the entry even if Pending* or Expired is set.
// Most callers should ignore such entries
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
	updateStatus(ctx, status.ObjType, status.ImageSha256, status.ImageID)
	log.Infof("handleVerifyImageStatusDelete done for %s", key)
}
