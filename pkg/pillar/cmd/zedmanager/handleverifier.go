// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedmanager

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func lookupVerifyImageConfig(ctx *zedmanagerContext,
	safename string) *types.VerifyImageConfig {

	pub := ctx.pubAppImgVerifierConfig
	c, _ := pub.Get(safename)
	if c == nil {
		log.Infof("lookupVerifyImageConfig(%s) not found\n",
			safename)
		return nil
	}
	config := cast.CastVerifyImageConfig(c)
	if config.Key() != safename {
		log.Errorf("lookupVerifyImageConfig(%s) got %s; ignored %+v\n",
			safename, config.Key(), config)
		return nil
	}
	return &config
}

func lookupVerifyImageConfigSha256(ctx *zedmanagerContext,
	sha256 string) *types.VerifyImageConfig {

	pub := ctx.pubAppImgVerifierConfig
	items := pub.GetAll()
	for _, c := range items {
		config := cast.CastVerifyImageConfig(c)
		if config.ImageSha256 == sha256 {
			return &config
		}
	}
	return nil
}

// If checkCerts is set this can return false. Otherwise not.
func MaybeAddVerifyImageConfig(ctx *zedmanagerContext, safename string,
	ss *types.StorageStatus, checkCerts bool) bool {

	log.Infof("MaybeAddVerifyImageConfig for %s, checkCerts: %v, "+
		"isContainer: %v\n", safename, checkCerts, ss.IsContainer)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts && !checkCertsForObject(safename, ss) {
		log.Infof("MaybeAddVerifyImageConfig for %s, Certs are still not installed\n",
			safename)
		return false
	}

	m := lookupVerifyImageConfig(ctx, safename)
	if m != nil {
		m.RefCount += 1
		log.Infof("MaybeAddVerifyImageConfig: refcnt to %d for %s\n",
			m.RefCount, safename)
		publishVerifyImageConfig(ctx, m)
	} else {
		log.Infof("MaybeAddVerifyImageConfig: add for %s, IsContainer: %t"+
			"ContainerImageID: %s\n", safename, ss.IsContainer,
			ss.ContainerImageID)
		n := types.VerifyImageConfig{
			Safename:         safename,
			Name:             ss.Name,
			ImageSha256:      ss.ImageSha256,
			RefCount:         1,
			CertificateChain: ss.CertificateChain,
			ImageSignature:   ss.ImageSignature,
			SignatureKey:     ss.SignatureKey,
			IsContainer:      ss.IsContainer,
			ContainerImageID: ss.ContainerImageID,
		}
		publishVerifyImageConfig(ctx, &n)
		log.Debugf("MaybeAddVerifyImageConfig - config: %+v\n", n)
	}
	log.Infof("MaybeAddVerifyImageConfig done for %s\n", safename)
	return true
}

func MaybeRemoveVerifyImageConfigSha256(ctx *zedmanagerContext, sha256 string) {

	log.Infof("MaybeRemoveVerifyImageConfig for %s\n", sha256)

	m := lookupVerifyImageConfigSha256(ctx, sha256)
	if m == nil {
		log.Infof("MaybeRemoveVerifyImageConfigSha256: config missing for %s\n",
			sha256)
		return
	}
	m.RefCount -= 1
	if m.RefCount < 0 {
		log.Fatalf("MaybeRemoveVerifyImageConfigSha256: negative RefCount %d for %s\n",
			m.RefCount, sha256)
	}
	log.Infof("MaybeRemoveVerifyImageConfigSha256: RefCount to %d for %s\n",
		m.RefCount, sha256)
	log.Infof("MaybeRemoveVerifyImageConfigSha256 done for %s\n", sha256)
	publishVerifyImageConfig(ctx, m)
}

func publishVerifyImageConfig(ctx *zedmanagerContext,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Debugf("publishVerifyImageConfig(%s)\n", key)
	pub := ctx.pubAppImgVerifierConfig
	pub.Publish(key, config)
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

	status := cast.CastVerifyImageStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleVerifyImageStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedmanagerContext)
	log.Infof("handleVerifyImageStatusModify for %s RefCount %d\n",
		status.Safename, status.RefCount)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Infof("handleVerifyImageStatusModify skipped due to Pending* for %s\n",
			status.Safename)
		return
	}

	// We handle two special cases in the handshake here
	// 1. verifier added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. verifier set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupVerifyImageConfig(ctx, status.Key())
	if config == nil && status.RefCount == 0 {
		log.Infof("handleVerifyImageStatusModify adding RefCount=0 config %s\n",
			key)
		n := types.VerifyImageConfig{
			Safename:         status.Safename,
			Name:             status.Safename,
			ImageSha256:      status.ImageSha256,
			IsContainer:      status.IsContainer,
			ContainerImageID: status.ContainerImageID,
			RefCount:         0,
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
	updateAIStatusWithStorageSafename(ctx, key, false, "")
	updateAIStatusSha(ctx, config.ImageSha256)
	log.Infof("handleVerifyImageStatusModify done for %s\n",
		status.Safename)
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerifyImageStatus(ctx *zedmanagerContext,
	safename string) *types.VerifyImageStatus {

	sub := ctx.subAppImgVerifierStatus
	c, _ := sub.Get(safename)
	if c == nil {
		log.Infof("lookupVerifyImageStatus(%s) not found\n", safename)
		return nil
	}
	status := cast.CastVerifyImageStatus(c)
	if status.Key() != safename {
		log.Errorf("lookupVerifyImageStatus(%s) got %s; ignored %+v\n",
			safename, status.Key(), status)
		return nil
	}
	return &status
}

func lookupVerifyImageStatusSha256(ctx *zedmanagerContext,
	sha256 string) *types.VerifyImageStatus {

	if sha256 == "" {
		log.Debugf("lookupVerifyImageStatusSha256: sha256 is empty\n")
		return nil
	}
	sub := ctx.subAppImgVerifierStatus
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
func lookupVerifyImageStatusAny(ctx *zedmanagerContext, safename string,
	sha256 string) *types.VerifyImageStatus {

	m := lookupVerifyImageStatus(ctx, safename)
	if m != nil {
		return m
	}
	m = lookupVerifyImageStatusSha256(ctx, sha256)
	if m != nil {
		log.Debugf("lookupVerifyImageStatusAny: found based on sha %s\n",
			sha256)
		return m
	}
	return nil
}

func handleVerifyImageStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	log.Infof("handleVerifyImageStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusSafename(ctx, key)
	removeAIStatusSha(ctx, status.ImageSha256)
	// If we still publish a config with RefCount == 0 we delete it.
	config := lookupVerifyImageConfig(ctx, key)
	if config != nil && config.RefCount == 0 {
		log.Infof("handleVerifyImageStatusDelete delete config for %s\n",
			key)
		unpublishVerifyImageConfig(ctx, config)
	}
	log.Infof("handleVerifyImageStatusDelete done for %s\n", key)
}

// check whether the cert files are installed
func checkCertsForObject(safename string, ss *types.StorageStatus) bool {

	var cidx int = 0

	// count the number of cerificates in this object
	if ss.SignatureKey != "" {
		cidx++
	}
	for _, certUrl := range ss.CertificateChain {
		if certUrl != "" {
			cidx++
		}
	}
	// if no cerificates, return
	if cidx == 0 {
		log.Infof("checkCertsForObject() for %s, no certificates configured\n",
			safename)
		return true
	}

	if ss.SignatureKey != "" {
		safename := types.UrlToSafename(ss.SignatureKey, "")
		filename := certificateDirname + "/" +
			types.SafenameToFilename(safename)
		if _, err := os.Stat(filename); err != nil {
			log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}

	for _, certUrl := range ss.CertificateChain {
		if certUrl != "" {
			safename := types.UrlToSafename(certUrl, "")
			filename := certificateDirname + "/" +
				types.SafenameToFilename(safename)
			if _, err := os.Stat(filename); err != nil {
				log.Errorf("checkCertsForObject() for %s, %v\n", filename, err)
				return false
			}
			// XXX check for valid or non-zero length?
		}
	}
	return true
}
