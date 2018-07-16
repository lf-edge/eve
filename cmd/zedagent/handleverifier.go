// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedagent

import (
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"log"
	"os"
)

func verifierConfigGetSha256(ctx *zedagentContext, objType string,
	sha string) *types.VerifyImageConfig {

	log.Printf("verifierConfigGetSha256(%s/%s)\n", objType, sha)
	pub := verifierPublication(ctx, objType)
	items := pub.GetAll()
	for key, c := range items {
		config := cast.CastVerifyImageConfig(c)
		if config.ImageSha256 == sha {
			log.Printf("verifierConfigGetSha256(%s): found key %s safename %s, refcount %d\n",
				sha, key, config.Safename, config.RefCount)
			return &config
		}
	}
	log.Printf("verifierConfigGetSha256(%s): not found\n", sha)
	return nil
}

func lookupVerifierConfig(ctx *zedagentContext, objType string,
	safename string) *types.VerifyImageConfig {

	pub := verifierPublication(ctx, objType)
	c, _ := pub.Get(safename)
	if c == nil {
		log.Printf("lookupVerifierConfig(%s/%s) not found\n",
			objType, safename)
		return nil
	}
	config := cast.CastVerifyImageConfig(c)
	if config.Key() != safename {
		log.Printf("lookupVerifierConfig(%s) got %s; ignored %+v\n",
			safename, config.Key(), config)
		return nil
	}
	return &config
}

// If checkCerts is set this can return an error. Otherwise not.
func createVerifierConfig(ctx *zedagentContext, objType string, safename string,
	sc *types.StorageConfig, checkCerts bool) error {

	log.Printf("createVerifierConfig(%s/%s)\n", objType, safename)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts {
		if err := checkCertsForObject(safename, sc); err != nil {
			log.Printf("%v for %s\n", err, safename)
			return err
		}
	}

	if m := lookupVerifierConfig(ctx, objType, safename); m != nil {
		m.RefCount += 1
		publishVerifierConfig(ctx, objType, m)
	} else {
		log.Printf("createVerifierConfig(%s) add\n", safename)
		n := types.VerifyImageConfig{
			Safename:         safename,
			DownloadURL:      sc.DownloadURL,
			ImageSha256:      sc.ImageSha256,
			CertificateChain: sc.CertificateChain,
			ImageSignature:   sc.ImageSignature,
			SignatureKey:     sc.SignatureKey,
			RefCount:         1,
		}
		publishVerifierConfig(ctx, objType, &n)
	}
	log.Printf("createVerifierConfig(%s) done\n", safename)
	return nil
}

func updateVerifierStatus(ctx *zedagentContext,
	status *types.VerifyImageStatus) {

	key := status.Key()
	objType := status.ObjType
	log.Printf("updateVerifierStatus(%s/%s) to %v\n",
		objType, key, status.State)

	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("updateVerifierStatus(%s) Skipping due to Pending*\n", key)
		return
	}

	if objType == baseOsObj {
		baseOsHandleStatusUpdateSafename(ctx, status.Safename)
	}

	log.Printf("updateVerifierStatus(%s) done\n", key)
}

func MaybeRemoveVerifierConfigSha256(ctx *zedagentContext, objType string,
	sha256 string) {

	log.Printf("MaybeRemoveVerifierConfigSha256(%s/%s)\n", objType, sha256)

	m := verifierConfigGetSha256(ctx, objType, sha256)
	if m == nil {
		log.Printf("MaybeRemoveVerifierConfigSha256: not found %s\n",
			sha256)
		return
	}
	log.Printf("MaybeRemoveVerifierConfigSha256 found safename %s\n",
		m.Safename)

	m.RefCount -= 1
	if m.RefCount != 0 {
		log.Printf("MaybeRemoveVerifierConfigSha256 remaining RefCount %d for %s\n",
			m.RefCount, sha256)
		publishVerifierConfig(ctx, objType, m)
		return
	}
	unpublishVerifierConfig(ctx, objType, m)
	log.Printf("MaybeRemoveVerifierConfigSha256 done for %s\n", sha256)
}

func lookupVerificationStatusSha256(ctx *zedagentContext, objType string,
	sha256 string) *types.VerifyImageStatus {

	sub := verifierSubscription(ctx, objType)
	items := sub.GetAll()
	for _, st := range items {
		status := cast.CastVerifyImageStatus(st)
		if status.ImageSha256 == sha256 {
			return &status
		}
	}
	return nil
}

func lookupVerificationStatus(ctx *zedagentContext, objType string,
	safename string) *types.VerifyImageStatus {

	sub := verifierSubscription(ctx, objType)
	c, _ := sub.Get(safename)
	if c == nil {
		log.Printf("lookupVerifierStatus(%s/%s) not found\n",
			objType, safename)
		return nil
	}
	status := cast.CastVerifyImageStatus(c)
	if status.Key() != safename {
		log.Printf("lookupVerifierStatus(%s) got %s; ignored %+v\n",
			safename, status.Key(), status)
		return nil
	}
	return &status
}

func lookupVerificationStatusAny(ctx *zedagentContext, objType string,
	safename string, sha256 string) *types.VerifyImageStatus {

	m := lookupVerificationStatus(ctx, objType, safename)
	if m != nil {
		return m
	}
	m = lookupVerificationStatusSha256(ctx, objType, sha256)
	if m != nil {
		log.Printf("lookupVerifyImageStatusAny: found based on sha %s\n", sha256)
		return m
	}
	return nil
}

func checkStorageVerifierStatus(ctx *zedagentContext, objType string, uuidStr string,
	config []types.StorageConfig, status []types.StorageStatus) *types.RetStatus {

	ret := &types.RetStatus{}

	log.Printf("checkStorageVerifierStatus(%s/%s)\n", objType, uuidStr)

	ret.AllErrors = ""
	ret.Changed = false
	ret.MinState = types.MAXSTATE

	for i, sc := range config {
		ss := &status[i]

		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

		log.Printf("checkStorageVerifierStatus: url %s stat %v\n",
			sc.DownloadURL, ss.State)

		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			continue
		}

		vs := lookupVerificationStatusAny(ctx, objType, safename,
			sc.ImageSha256)
		if vs == nil {
			log.Printf("checkStorageVerifierStatus: %s not found\n", safename)
			ret.MinState = types.DOWNLOADED
			continue
		}
		if ret.MinState > vs.State {
			ret.MinState = vs.State
		}
		if vs.State != ss.State {
			log.Printf("checkStorageVerifierStatus(%s) set ss.State %d\n",
				safename, vs.State)
			ss.State = vs.State
			ret.Changed = true
		}
		switch vs.State {
		case types.INITIAL:
			log.Printf("checkStorageVerifierStatus(%s) verifier error for %s: %s\n",
				uuidStr, safename, vs.LastErr)
			ss.Error = vs.LastErr
			ret.AllErrors = appendError(ret.AllErrors, "verifier",
				vs.LastErr)
			ss.ErrorTime = vs.LastErrTime
			ret.ErrorTime = vs.LastErrTime
			ret.Changed = true
		default:
			ss.ActiveFileLocation = objectDownloadDirname + "/" + objType + "/" + vs.Safename

			log.Printf("checkStorageVerifierStatus(%s) Update SSL ActiveFileLocation to %s\n",
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

func publishVerifierConfig(ctx *zedagentContext, objType string,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Printf("publishVerifierConfig(%s/%s)\n", objType, config.Key())

	pub := verifierPublication(ctx, objType)
	pub.Publish(key, config)
}

func unpublishVerifierConfig(ctx *zedagentContext, objType string,
	config *types.VerifyImageConfig) {

	key := config.Key()
	log.Printf("removeVerifierConfig(%s/%s)\n", objType, key)

	pub := verifierPublication(ctx, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Printf("unpublishVerifierConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// check whether the cert files are installed
func checkCertsForObject(safename string, sc *types.StorageConfig) error {
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
		log.Printf("checkCertsForObject(%s), no configured certificates\n",
			safename)
		return nil
	}

	if sc.SignatureKey != "" {
		safename := types.UrlToSafename(sc.SignatureKey, "")
		filename := certificateDirname + "/" +
			types.SafenameToFilename(safename)
		if _, err := os.Stat(filename); err != nil {
			log.Printf("checkCertsForObject: %s failed %v\n",
				filename, err)
			return err
		}
	}

	for _, certUrl := range sc.CertificateChain {
		if certUrl != "" {
			safename := types.UrlToSafename(certUrl, "")
			filename := certificateDirname + "/" +
				types.SafenameToFilename(safename)
			if _, err := os.Stat(filename); err != nil {
				log.Printf("checkCertsForObject %s failed %v\n",
					filename, err)
				return err
			}
		}
	}
	return nil
}

func verifierPublication(ctx *zedagentContext, objType string) *pubsub.Publication {
	var pub *pubsub.Publication
	switch objType {
	case baseOsObj:
		pub = ctx.pubBaseOsVerifierConfig
	default:
		log.Fatalf("verifierPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}

func verifierSubscription(ctx *zedagentContext, objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case baseOsObj:
		sub = ctx.subBaseOsVerifierStatus
	case appImgObj:
		sub = ctx.subAppImgVerifierStatus
	default:
		log.Fatalf("verifierSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

func verifierGetAll(ctx *zedagentContext) map[string]interface{} {
	sub1 := verifierSubscription(ctx, baseOsObj)
	items1 := sub1.GetAll()
	sub2 := verifierSubscription(ctx, appImgObj)
	items2 := sub2.GetAll()

	items := make(map[string]interface{})
	for k, i := range items1 {
		items[k] = i
	}
	for k, i := range items2 {
		items[k] = i
	}
	return items
}
