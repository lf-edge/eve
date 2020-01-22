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
			ImageID:          imageID,
			Name:             sc.Name,
			ImageSha256:      sc.ImageSha256,
			CertificateChain: sc.CertificateChain,
			ImageSignature:   sc.ImageSignature,
			SignatureKey:     sc.SignatureKey,
			RefCount:         1,
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
	// We handle two special cases in the handshake here
	// 1. verifier added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. verifier set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupVerifierConfig(ctx, status.ObjType, status.ImageID)
	if config == nil && status.RefCount == 0 {
		log.Infof("updateVerifierStatus adding RefCount=0 config %s\n",
			key)
		n := types.VerifyImageConfig{
			ImageID:     status.ImageID,
			Name:        status.Name,
			ImageSha256: status.ImageSha256,
			RefCount:    0,
		}
		publishVerifierConfig(ctx, status.ObjType, &n)
		return
	}
	if config != nil && config.RefCount == 0 && status.Expired {
		log.Infof("updateVerifierStatus expired - deleting config %s\n",
			key)
		unpublishVerifierConfig(ctx, status.ObjType, config)
		return
	}

	// Normal update work
	baseOsHandleStatusUpdateImageID(ctx, status.ImageID)
	log.Infof("updateVerifierStatus(%s) done\n", key)
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
	publishVerifierConfig(ctx, objType, m)
	log.Infof("MaybeRemoveVerifierConfig done for %s\n", imageID)
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerificationStatus(ctx *baseOsMgrContext, objType string,
	imageID uuid.UUID) *types.VerifyImageStatus {

	sub := ctx.subBaseOsVerifierStatus
	c, _ := sub.Get(imageID.String())
	if c == nil {
		log.Infof("lookupVerifierStatus(%s/%s) not found\n",
			objType, imageID)
		return nil
	}
	status := c.(types.VerifyImageStatus)
	return &status
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
