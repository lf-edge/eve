// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

func lookupVerifierConfig(ctx *baseOsMgrContext, objType string,
	imageID uuid.UUID) *types.VerifyImageConfig {

	pub := verifierPublication(ctx, objType)
	c, _ := pub.Get(imageID.String())
	if c == nil {
		log.Infof("lookupVerifierConfig(%s/%s) not found\n",
			objType, imageID)
		return nil
	}
	config := c.(types.VerifyImageConfig)
	return &config
}

func lookupPersistConfig(ctx *baseOsMgrContext, objType string,
	imageSha string) *types.PersistImageConfig {

	pub := persistPublication(ctx, objType)
	c, _ := pub.Get(imageSha)
	if c == nil {
		log.Infof("lookupPersistConfig(%s/%s) not found\n",
			objType, imageSha)
		return nil
	}
	config := c.(types.PersistImageConfig)
	return &config
}

// If checkCerts is set this can return an error. Otherwise not.
func createVerifierConfig(ctx *baseOsMgrContext, uuidStr string, objType string,
	imageID uuid.UUID, sc types.StorageConfig, ss types.StorageStatus, checkCerts bool) (bool, types.ErrorInfo) {

	log.Infof("createVerifierConfig(%s/%s)\n", objType, imageID)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts && objType == types.BaseOsObj {
		certObjStatus := lookupCertObjStatus(ctx, uuidStr)
		displaystr := imageID.String()
		ret, err := ss.IsCertsAvailable(displaystr)
		if err != nil {
			log.Fatalf("%s, invalid certificate configuration", displaystr)
		}
		if ret {
			if ret, errInfo := ss.HandleCertStatus(displaystr, *certObjStatus); !ret {
				return ret, errInfo
			}
		}
	}

	if m := lookupVerifierConfig(ctx, objType, imageID); m != nil {
		m.RefCount += 1
		publishVerifierConfig(ctx, objType, m)
	} else {
		log.Infof("createVerifierConfig(%s) add\n", imageID)
		n := types.VerifyImageConfig{
			ImageID: imageID,
			VerifyConfig: types.VerifyConfig{
				Name:             sc.Name,
				ImageSha256:      sc.ImageSha256,
				CertificateChain: sc.CertificateChain,
				ImageSignature:   sc.ImageSignature,
				SignatureKey:     sc.SignatureKey,
			},
			RefCount: 1,
		}
		publishVerifierConfig(ctx, objType, &n)
	}
	log.Infof("createVerifierConfig(%s) done\n", imageID)
	return true, types.ErrorInfo{}
}

func updateVerifierStatus(ctx *baseOsMgrContext,
	status *types.VerifyImageStatus) {

	key := status.Key()
	objType := status.ObjType
	log.Infof("updateVerifierStatus(%s/%s) to %v\n",
		objType, key, status.State)

	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Infof("updateVerifierStatus(%s) Skipping due to Pending*\n", key)
		return
	}

	if status.ObjType != types.BaseOsObj {
		log.Errorf("updateVerifierStatus for %s, unsupported objType %s\n",
			key, objType)
		return
	}
	baseOsHandleStatusUpdateImageID(ctx, status.ImageID)
	// Make sure the PersistImageConfig has the sum of the refcounts
	// for the sha
	if status.ImageSha256 != "" {
		updatePersistImageConfig(ctx, objType, status.ImageSha256)
	}
	log.Infof("updateVerifierStatus(%s) done\n", key)
}

func removeVerifierStatus(ctx *baseOsMgrContext,
	status *types.VerifyImageStatus) {

	key := status.Key()
	objType := status.ObjType
	log.Infof("removeVerifierStatus(%s/%s) refcount %d\n",
		objType, key, status.RefCount)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupVerifierConfig(ctx, objType, status.ImageID)
	if config != nil && config.RefCount == 0 {
		log.Infof("removeVerifierStatus delete config for %s\n",
			key)
		unpublishVerifierConfig(ctx, objType, config)
	}
	// Make sure the PersistImageConfig has the sum of the refcounts
	// for the sha
	if status.ImageSha256 != "" {
		updatePersistImageConfig(ctx, objType, status.ImageSha256)
	}
	log.Infof("removeVerifierStatus done for %s\n", key)
}

func updatePersistStatus(ctx *baseOsMgrContext,
	status *types.PersistImageStatus) {

	key := status.Key()
	objType := status.ObjType
	log.Infof("updatePersistStatus(%s/%s) to refcount %d expired %t\n",
		objType, key, status.RefCount, status.Expired)

	if status.ObjType != types.BaseOsObj {
		log.Errorf("updatePersistStatus for %s, unsupported objType %s\n",
			key, objType)
		return
	}
	// We handle two special cases in the handshake here
	// 1. verifier added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. verifier set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupPersistConfig(ctx, status.ObjType, status.ImageSha256)
	if config == nil && status.RefCount == 0 {
		log.Infof("updatePersistStatus adding RefCount=0 config %s\n",
			key)
		n := types.PersistImageConfig{
			VerifyConfig: types.VerifyConfig{
				Name:        status.Name,
				ImageSha256: status.ImageSha256,
			},
			RefCount: 0,
		}
		publishPersistConfig(ctx, status.ObjType, &n)
	} else if config != nil && config.RefCount == 0 && status.Expired &&
		sumVerifyImageRefCount(ctx, status.ImageSha256) == 0 {
		log.Infof("updatePersistStatus expired - deleting config %s\n",
			key)
		unpublishPersistConfig(ctx, status.ObjType, config)
	}
	log.Infof("updatePersistStatus(%s) done\n", key)
}

func removePersistStatus(ctx *baseOsMgrContext,
	status *types.PersistImageStatus) {

	key := status.Key()
	objType := status.ObjType
	log.Infof("removePersistStatus(%s/%s) refcount %d expired %t\n",
		objType, key, status.RefCount, status.Expired)
	config := lookupPersistConfig(ctx, status.ObjType, status.ImageSha256)
	if config == nil {
		log.Errorf("handlePersistStatusDelete no config for %s\n", key)
		return
	}
	unpublishPersistConfig(ctx, status.ObjType, config)
}

// Make sure the PersistImageConfig has the sum of the refcounts
// for the sha
func updatePersistImageConfig(ctx *baseOsMgrContext, objType string,
	imageSha string) {

	log.Infof("updatePersistImageConfig(%s/%s)", objType, imageSha)
	if imageSha == "" {
		return
	}
	var refcount uint
	sub := ctx.subBaseOsVerifierStatus
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
	config := lookupPersistConfig(ctx, objType, imageSha)
	if config == nil {
		log.Errorf("updatePersistImageConfig(%s/%s): config not found",
			objType, imageSha)
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
		log.Infof("updatePersistImageConfig(%s/%s): no RefCount change %d",
			objType, imageSha, refcount)
		return
	}
	log.Infof("updatePersistImageConfig(%s/%s): RefCount change %d to %d",
		objType, imageSha, config.RefCount, refcount)
	config.RefCount = refcount
	publishPersistConfig(ctx, objType, config)
}

// Calculate sum of the refcounts for the config for a particular sha
func sumVerifyImageRefCount(ctx *baseOsMgrContext, imageSha string) uint {
	log.Infof("sumVerifyImageRefCount(%s)", imageSha)
	if imageSha == "" {
		return 0
	}
	var refcount uint
	pub := ctx.pubBaseOsVerifierConfig
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

// MaybeRemoveVerifierConfig decreases the refcount and if it
// reaches zero it removes the VerifyImageConfig
func MaybeRemoveVerifierConfig(ctx *baseOsMgrContext, objType string,
	imageID uuid.UUID) {

	log.Infof("MaybeRemoveVerifierConfig(%s/%s)\n", objType, imageID)

	m := lookupVerifierConfig(ctx, objType, imageID)
	if m == nil {
		log.Errorf("MaybeRemoveVerifierConfig: not found %s\n",
			imageID)
		return
	}
	log.Infof("MaybeRemoveVerifierConfig found imageID %s\n",
		m.ImageID)

	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveVerifierConfig: RefCount for "+
			"objType: %s, imageID: %s already zero. Cannot decrement.",
			objType, imageID)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveVerifierConfig remaining RefCount %d for %s\n",
		m.RefCount, imageID)
	if m.RefCount == 0 {
		unpublishVerifierConfig(ctx, objType, m)
	} else {
		publishVerifierConfig(ctx, objType, m)
	}
	log.Infof("MaybeRemoveVerifierConfig done for %s\n", imageID)
}

// Note that this function returns the entry even if Pending* is set.
func lookupPersistStatus(ctx *baseOsMgrContext, objType string,
	imageSha256 string) *types.PersistImageStatus {

	sub := ctx.subBaseOsPersistStatus
	s, _ := sub.Get(imageSha256)
	if s == nil {
		log.Infof("lookupPersistStatus(%s/%s) not found\n",
			objType, imageSha256)
		return nil
	}
	status := s.(types.PersistImageStatus)
	return &status
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerificationStatus(ctx *baseOsMgrContext, objType string,
	imageID uuid.UUID) *types.VerifyImageStatus {

	sub := ctx.subBaseOsVerifierStatus
	items := sub.GetAll()
	for _, s := range items {
		status := s.(types.VerifyImageStatus)
		if status.ImageID == imageID {
			return &status
		}
	}
	log.Infof("lookupVerificationStatus(%s/%s) not found\n",
		objType, imageID)
	return nil
}

func checkStorageVerifierStatus(ctx *baseOsMgrContext, objType string, uuidStr string,
	config []types.StorageConfig, status []types.StorageStatus) *types.RetStatus {

	ret := &types.RetStatus{}

	log.Infof("checkStorageVerifierStatus(%s/%s)\n", objType, uuidStr)

	ret.AllErrors = ""
	ret.Changed = false
	ret.MinState = types.MAXSTATE

	for i, sc := range config {
		ss := &status[i]

		log.Infof("checkStorageVerifierStatus: url %s stat %v\n",
			sc.Name, ss.State)

		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			continue
		}

		vs := lookupVerificationStatus(ctx, objType, sc.ImageID)
		if vs == nil || vs.Pending() {
			log.Infof("checkStorageVerifierStatus: %s not found\n", sc.ImageID)
			// Keep at current state
			ret.MinState = types.DOWNLOADED
			continue
		}
		if ss.ImageSha256 != vs.ImageSha256 {
			log.Infof("updating imagesha from %s to %s",
				ss.ImageSha256, vs.ImageSha256)
			ss.ImageSha256 = vs.ImageSha256
			ret.Changed = true
		}
		if ret.MinState > vs.State {
			ret.MinState = vs.State
		}
		if vs.State != ss.State {
			log.Infof("checkStorageVerifierStatus(%s) set ss.State %d\n",
				sc.ImageID, vs.State)
			ss.State = vs.State
			ret.Changed = true
		}
		if vs.LastErr != "" {
			log.Errorf("checkStorageVerifierStatus(%s) verifier error for %s: %s\n",
				uuidStr, sc.ImageID, vs.LastErr)
			ss.Error = vs.LastErr
			ss.ErrorSource = pubsub.TypeToName(types.VerifyImageStatus{})
			ret.AllErrors = appendError(ret.AllErrors, "verifier",
				vs.LastErr)
			ss.ErrorTime = vs.LastErrTime
			ret.ErrorTime = vs.LastErrTime
			ret.Changed = true
			continue
		}
		switch vs.State {
		case types.INITIAL:
			// Nothing to do
		default:
			ss.ActiveFileLocation = vs.FileLocation
			log.Infof("checkStorageVerifierStatus(%s) Update SSL ActiveFileLocation to %s\n",
				uuidStr, ss.ActiveFileLocation)
			ret.Changed = true
		}
	}

	if ret.MinState == types.MAXSTATE {
		// Odd; no StorageConfig in list
		ret.MinState = types.DELIVERED
	}
	return ret
}

func publishVerifierConfig(ctx *baseOsMgrContext, objType string,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("publishVerifierConfig(%s/%s)\n", objType, config.Key())
	pub := verifierPublication(ctx, objType)
	pub.Publish(key, *config)
}

func unpublishVerifierConfig(ctx *baseOsMgrContext, objType string,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("unpublishVerifierConfig(%s/%s)\n", objType, key)
	pub := verifierPublication(ctx, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVerifierConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func publishPersistConfig(ctx *baseOsMgrContext, objType string,
	config *types.PersistImageConfig) {

	key := config.Key()
	log.Debugf("publishPersistConfig(%s/%s)\n", objType, config.Key())
	pub := persistPublication(ctx, objType)
	pub.Publish(key, *config)
}

func unpublishPersistConfig(ctx *baseOsMgrContext, objType string,
	config *types.PersistImageConfig) {

	key := config.Key()
	log.Debugf("unpublishPersistConfig(%s/%s)\n", objType, key)
	pub := persistPublication(ctx, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishPersistConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func verifierPublication(ctx *baseOsMgrContext, objType string) pubsub.Publication {
	var pub pubsub.Publication
	switch objType {
	case types.BaseOsObj:
		pub = ctx.pubBaseOsVerifierConfig
	default:
		log.Fatalf("verifierPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}

func persistPublication(ctx *baseOsMgrContext, objType string) pubsub.Publication {
	var pub pubsub.Publication
	switch objType {
	case types.BaseOsObj:
		pub = ctx.pubBaseOsPersistConfig
	default:
		log.Fatalf("persistPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}
