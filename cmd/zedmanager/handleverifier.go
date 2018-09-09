// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
	"os"
)

func lookupVerifyImageConfig(ctx *zedmanagerContext,
	safename string) *types.VerifyImageConfig {

	pub := ctx.pubAppImgVerifierConfig
	c, _ := pub.Get(safename)
	if c == nil {
		log.Printf("lookupVerifyImageConfig(%s) not found\n",
			safename)
		return nil
	}
	config := cast.CastVerifyImageConfig(c)
	if config.Key() != safename {
		log.Printf("lookupVerifyImageConfig(%s) got %s; ignored %+v\n",
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
	sc *types.StorageConfig, checkCerts bool) bool {

	log.Printf("MaybeAddVerifyImageConfig for %s\n", safename)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts && !checkCertsForObject(safename, sc) {
		log.Printf("MaybeAddVerifyImageConfig for %s, Certs are still not installed\n",
			safename)
		return false
	}

	m := lookupVerifyImageConfig(ctx, safename)
	if m != nil {
		m.RefCount += 1
		log.Printf("MaybeAddVerifyImageConfig: refcnt %d for %s\n",
			m.RefCount, safename)
		publishVerifyImageConfig(ctx, m)
	} else {
		log.Printf("MaybeAddVerifyImageConfig: add for %s\n",
			safename)
		n := types.VerifyImageConfig{
			Safename:         safename,
			Name:             sc.Name,
			ImageSha256:      sc.ImageSha256,
			RefCount:         1,
			CertificateChain: sc.CertificateChain,
			ImageSignature:   sc.ImageSignature,
			SignatureKey:     sc.SignatureKey,
		}
		publishVerifyImageConfig(ctx, &n)
	}
	log.Printf("MaybeAddVerifyImageConfig done for %s\n", safename)
	return true
}

func MaybeRemoveVerifyImageConfigSha256(ctx *zedmanagerContext, sha256 string) {

	log.Printf("MaybeRemoveVerifyImageConfig for %s\n", sha256)

	m := lookupVerifyImageConfigSha256(ctx, sha256)
	if m == nil {
		log.Printf("MaybeRemoveVerifyImageConfigSha256: config missing for %s\n",
			sha256)
		return
	}
	m.RefCount -= 1
	if m.RefCount != 0 {
		log.Printf("MaybeRemoveVerifyImageConfigSha256: RefCount %d for %s\n",
			m.RefCount, sha256)
		publishVerifyImageConfig(ctx, m)
		return
	}
	log.Printf("MaybeRemoveVerifyImageConfigSha256: RefCount zero for %s\n",
		sha256)
	unpublishVerifyImageConfig(ctx, m)
	log.Printf("MaybeRemoveVerifyImageConfigSha256 done for %s\n", sha256)
}

func publishVerifyImageConfig(ctx *zedmanagerContext,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Printf("publishVerifyImageConfig(%s)\n", key)

	pub := ctx.pubAppImgVerifierConfig
	pub.Publish(key, config)
}

func unpublishVerifyImageConfig(ctx *zedmanagerContext,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Printf("removeVerifyImageConfig(%s)\n", key)

	pub := ctx.pubAppImgVerifierConfig
	pub.Unpublish(key)
}

func handleVerifyImageStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastVerifyImageStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleVerifyImageStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedmanagerContext)
	log.Printf("handleVerifyImageStatusModify for %s\n",
		status.Safename)
	// Ignore if any Pending* flag is set
	if status.Pending() {
		log.Printf("handleVerifyImageStatusModify skipped due to Pending* for %s\n",
			status.Safename)
		return
	}

	updateAIStatusSafename(ctx, key)
	log.Printf("handleVerifyImageStatusModify done for %s\n",
		status.Safename)
}

// Note that this function returns the entry even if Pending* is set.
func lookupVerifyImageStatus(ctx *zedmanagerContext,
	safename string) *types.VerifyImageStatus {

	sub := ctx.subAppImgVerifierStatus
	c, _ := sub.Get(safename)
	if c == nil {
		log.Printf("lookupVerifyImageStatus(%s) not found\n", safename)
		return nil
	}
	status := cast.CastVerifyImageStatus(c)
	if status.Key() != safename {
		log.Printf("lookupVerifyImageStatus(%s) got %s; ignored %+v\n",
			safename, status.Key(), status)
		return nil
	}
	return &status
}

func lookupVerifyImageStatusSha256(ctx *zedmanagerContext,
	sha256 string) *types.VerifyImageStatus {

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
		if debug {
			log.Printf("lookupVerifyImageStatusAny: found based on sha %s\n",
				sha256)
		}
		return m
	}
	return nil
}

func handleVerifyImageStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleVerifyImageStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)

	removeAIStatusSafename(ctx, key)
	log.Printf("handleVerifyImageStatusDelete done for %s\n", key)
}

// check whether the cert files are installed
func checkCertsForObject(safename string, sc *types.StorageConfig) bool {

	var cidx int = 0

	// count the number of cerificates in this object
	if sc.SignatureKey != "" {
		cidx++
	}
	for _, certUrl := range sc.CertificateChain {
		if certUrl != "" {
			cidx++
		}
	}
	// if no cerificates, return
	if cidx == 0 {
		log.Printf("checkCertsForObject() for %s, no certificates configured\n",
			safename)
		return true
	}

	if sc.SignatureKey != "" {
		safename := types.UrlToSafename(sc.SignatureKey, "")
		filename := certificateDirname + "/" +
			types.SafenameToFilename(safename)
		if _, err := os.Stat(filename); err != nil {
			log.Printf("checkCertsForObject() for %s, %v\n", filename, err)
			return false
		}
		// XXX check for valid or non-zero length?
	}

	for _, certUrl := range sc.CertificateChain {
		if certUrl != "" {
			safename := types.UrlToSafename(certUrl, "")
			filename := certificateDirname + "/" +
				types.SafenameToFilename(safename)
			if _, err := os.Stat(filename); err != nil {
				log.Printf("checkCertsForObject() for %s, %v\n", filename, err)
				return false
			}
			// XXX check for valid or non-zero length?
		}
	}
	return true
}
