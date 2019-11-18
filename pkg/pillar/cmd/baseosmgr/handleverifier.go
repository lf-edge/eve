// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"errors"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func verifierConfigGetSha256(ctx *baseOsMgrContext, objType string,
	sha string) *types.VerifyImageConfig {

	log.Infof("verifierConfigGetSha256(%s/%s)\n", objType, sha)
	pub := verifierPublication(ctx, objType)
	items := pub.GetAll()
	for key, c := range items {
		config := cast.CastVerifyImageConfig(c)
		if config.ImageSha256 == sha {
			log.Infof("verifierConfigGetSha256(%s): found key %s safename %s, refcount %d\n",
				sha, key, config.Safename, config.RefCount)
			return &config
		}
	}
	log.Infof("verifierConfigGetSha256(%s): not found\n", sha)
	return nil
}

func lookupVerifierConfig(ctx *baseOsMgrContext, objType string,
	safename string) *types.VerifyImageConfig {

	pub := verifierPublication(ctx, objType)
	c, _ := pub.Get(safename)
	if c == nil {
		log.Infof("lookupVerifierConfig(%s/%s) not found\n",
			objType, safename)
		return nil
	}
	config := cast.CastVerifyImageConfig(c)
	if config.Key() != safename {
		log.Infof("lookupVerifierConfig(%s) got %s; ignored %+v\n",
			safename, config.Key(), config)
		return nil
	}
	return &config
}

// If checkCerts is set this can return an error. Otherwise not.
func createVerifierConfig(ctx *baseOsMgrContext, uuidStr string, objType string,
	safename string, sc *types.StorageConfig, ss *types.StorageStatus, checkCerts bool) error {

	log.Infof("createVerifierConfig(%s/%s)\n", objType, safename)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts {
		certObjStatus := lookupCertObjStatus(ctx, uuidStr)
		ret, err := ss.IsCertsAvailable(safename)
		if err != nil {
			log.Fatalf("%s, invalid certificate configuration", safename)
		}
		if ret {
			ret, errStr, errSrc, errTime := ss.GetCertStatus(safename, certObjStatus)
			if errStr != "" {
				ss.SetErrorInfo(errStr, errSrc, errTime)
				return errors.New(errStr)
			}
			if !ret {
				return nil
			}
		}
	}

	if m := lookupVerifierConfig(ctx, objType, safename); m != nil {
		m.RefCount += 1
		publishVerifierConfig(ctx, objType, m)
	} else {
		log.Infof("createVerifierConfig(%s) add\n", safename)
		n := types.VerifyImageConfig{
			Safename:         safename,
			Name:             sc.Name,
			ImageSha256:      sc.ImageSha256,
			CertificateChain: sc.CertificateChain,
			ImageSignature:   sc.ImageSignature,
			SignatureKey:     sc.SignatureKey,
			RefCount:         1,
		}
		publishVerifierConfig(ctx, objType, &n)
	}
	log.Infof("createVerifierConfig(%s) done\n", safename)
	return nil
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

	config := lookupVerifierConfig(ctx, status.ObjType, status.Key())
	if config == nil && status.RefCount == 0 {
		log.Infof("updateVerifierStatus adding RefCount=0 config %s\n",
			key)
		n := types.VerifyImageConfig{
			Safename:    status.Safename,
			Name:        status.Safename,
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
	baseOsHandleStatusUpdateSafename(ctx, status.Safename)
	log.Infof("updateVerifierStatus(%s) done\n", key)
}

func MaybeRemoveVerifierConfigSha256(ctx *baseOsMgrContext, objType string,
	sha256 string) {

	log.Infof("MaybeRemoveVerifierConfigSha256(%s/%s)\n", objType, sha256)

	m := verifierConfigGetSha256(ctx, objType, sha256)
	if m == nil {
		log.Errorf("MaybeRemoveVerifierConfigSha256: not found %s\n",
			sha256)
		return
	}
	log.Infof("MaybeRemoveVerifierConfigSha256 found safename %s\n",
		m.Safename)

	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveVerifyImageConfigSha256: RefCount for "+
			"objType: %s, sha256: %s already zero. Cannot decrement.",
			objType, sha256)
	}
	m.RefCount -= 1
	log.Infof("MaybeRemoveVerifierConfigSha256 remaining RefCount %d for %s\n",
		m.RefCount, sha256)
	publishVerifierConfig(ctx, objType, m)
	log.Infof("MaybeRemoveVerifierConfigSha256 done for %s\n", sha256)
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerificationStatusSha256(ctx *baseOsMgrContext, objType string,
	sha256 string) *types.VerifyImageStatus {

	sub := ctx.subBaseOsVerifierStatus
	items := sub.GetAll()
	for _, st := range items {
		status := cast.CastVerifyImageStatus(st)
		if status.ImageSha256 == sha256 {
			return &status
		}
	}
	return nil
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerificationStatus(ctx *baseOsMgrContext, objType string,
	safename string) *types.VerifyImageStatus {

	sub := ctx.subBaseOsVerifierStatus
	c, _ := sub.Get(safename)
	if c == nil {
		log.Infof("lookupVerifierStatus(%s/%s) not found\n",
			objType, safename)
		return nil
	}
	status := cast.CastVerifyImageStatus(c)
	if status.Key() != safename {
		log.Infof("lookupVerifierStatus(%s) got %s; ignored %+v\n",
			safename, status.Key(), status)
		return nil
	}
	return &status
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerificationStatusAny(ctx *baseOsMgrContext, objType string,
	safename string, sha256 string) *types.VerifyImageStatus {

	m := lookupVerificationStatus(ctx, objType, safename)
	if m != nil {
		return m
	}
	m = lookupVerificationStatusSha256(ctx, objType, sha256)
	if m != nil {
		log.Infof("lookupVerifyImageStatusAny: found based on sha %s\n", sha256)
		return m
	}
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

		safename := types.UrlToSafename(sc.Name, sc.ImageSha256)

		log.Infof("checkStorageVerifierStatus: url %s stat %v\n",
			sc.Name, ss.State)

		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			continue
		}

		vs := lookupVerificationStatusAny(ctx, objType, safename,
			sc.ImageSha256)
		if vs == nil || vs.Pending() {
			log.Infof("checkStorageVerifierStatus: %s not found\n", safename)
			// Keep at current state
			ret.MinState = types.DOWNLOADED
			continue
		}
		if ret.MinState > vs.State {
			ret.MinState = vs.State
		}
		if vs.State != ss.State {
			log.Infof("checkStorageVerifierStatus(%s) set ss.State %d\n",
				safename, vs.State)
			ss.State = vs.State
			ret.Changed = true
		}
		if vs.LastErr != "" {
			log.Errorf("checkStorageVerifierStatus(%s) verifier error for %s: %s\n",
				uuidStr, safename, vs.LastErr)
			ss.Error = vs.LastErr
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
			ss.ActiveFileLocation = types.DownloadDirname + "/" +
				objType + "/" + vs.Safename

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
	pub.Publish(key, config)
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

func verifierPublication(ctx *baseOsMgrContext, objType string) *pubsub.Publication {
	var pub *pubsub.Publication
	switch objType {
	case types.BaseOsObj:
		pub = ctx.pubBaseOsVerifierConfig
	default:
		log.Fatalf("verifierPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}
