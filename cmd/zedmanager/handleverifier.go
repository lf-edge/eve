// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"log"
	"os"
)

// Key is Safename string.
var verifyImageConfig map[string]types.VerifyImageConfig

// If checkCerts is set this can return false. Otherwise not.
func MaybeAddVerifyImageConfig(safename string, sc *types.StorageConfig,
	checkCerts bool) bool {

	log.Printf("MaybeAddVerifyImageConfig for %s\n", safename)

	// check the certificate files, if not present,
	// we can not start verification
	if checkCerts && !checkCertsForObject(safename, sc) {
		log.Printf("createVerifierConfig for %s, Certs are still not installed\n",
			safename)
		return false
	}

	if verifyImageConfig == nil {
		if debug {
			log.Printf("create verifier config map\n")
		}
		verifyImageConfig = make(map[string]types.VerifyImageConfig)
	}
	key := safename
	if m, ok := verifyImageConfig[key]; ok {
		m.RefCount += 1
		if debug {
			log.Printf("verifier config already exists refcnt %d for %s\n",
				m.RefCount, safename)
		}
		verifyImageConfig[key] = m
	} else {
		if debug {
			log.Printf("verifier config add for %s\n", safename)
		}
		n := types.VerifyImageConfig{
			Safename:         safename,
			DownloadURL:      sc.DownloadURL,
			ImageSha256:      sc.ImageSha256,
			RefCount:         1,
			CertificateChain: sc.CertificateChain,
			ImageSignature:   sc.ImageSignature,
			SignatureKey:     sc.SignatureKey,
		}
		verifyImageConfig[key] = n
	}
	configFilename := fmt.Sprintf("%s/%s.json",
		verifierAppImgObjConfigDirname, safename)
	writeVerifyImageConfig(verifyImageConfig[key], configFilename)
	log.Printf("MaybeAddVerifyImageConfig done for %s\n", safename)
	return true
}

func MaybeRemoveVerifyImageConfigSha256(sha256 string) {
	log.Printf("MaybeRemoveVerifyImageConfig for %s\n", sha256)

	// XXX Looking in status to remove config??? Assumes status made
	// it back from verifier before we want to delete it.
	m, err := lookupVerifyImageStatusSha256Impl(sha256)
	if err != nil {
		log.Printf("VerifyImage config missing for remove for %s\n",
			sha256)
		return
	}
	m.RefCount -= 1
	if m.RefCount != 0 {
		log.Printf("MaybeRemoveVerifyImageConfig remaining RefCount %d for %s\n",
			m.RefCount, sha256)
		return
	}
	if debug {
		log.Printf("MaybeRemoveVerifyImageConfig RefCount zero for %s\n",
			sha256)
	}
	key := m.Safename
	delete(verifyImageConfig, key)
	configFilename := fmt.Sprintf("%s/%s.json",
		verifierAppImgObjConfigDirname, key)
	if err := os.Remove(configFilename); err != nil {
		log.Println(err)
	}
	log.Printf("MaybeRemoveVerifyImageConfigSha256 done for %s\n", sha256)
}

func writeVerifyImageConfig(config types.VerifyImageConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageConfig")
	}
	err = pubsub.WriteRename(configFilename, b)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

// Key is Safename string.
var verifierStatus map[string]types.VerifyImageStatus

func dumpVerifierStatus() {
	for key, m := range verifierStatus {
		log.Printf("\tverifierStatus[%v]: sha256 %s safename %s\n",
			key, m.ImageSha256, m.Safename)
	}
}

func handleVerifyImageStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := cast.CastVerifyImageStatus(statusArg)
	// XXX change once key arg
	key := status.Key()
	if status.Key() != key {
		log.Printf("handleVerifyImageStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedmanagerContext)
	log.Printf("handleVerifyImageStatusModify for %s\n",
		status.Safename)
	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("handleVerifyImageStatusModify skipped due to Pending* for %s\n",
			status.Safename)
		return
	}

	if verifierStatus == nil {
		if debug {
			log.Printf("create verifier map\n")
		}
		verifierStatus = make(map[string]types.VerifyImageStatus)
	}
	key = status.Safename
	changed := false
	if m, ok := verifierStatus[key]; ok {
		if status.State != m.State {
			log.Printf("verifier map changed from %v to %v\n",
				m.State, status.State)
			changed = true
		}
	} else {
		if debug {
			log.Printf("verifier map add for %v\n", status.State)
		}
		changed = true
	}
	if changed {
		verifierStatus[key] = status
		if debug {
			log.Printf("Added verifierStatus key %v sha %s safename %s\n",
				key, status.ImageSha256, status.Safename)
			dumpVerifierStatus()
		}
		updateAIStatusSafename(ctx, key)
	}
	log.Printf("handleVerifyImageStatusModify done for %s\n",
		status.Safename)
}

func LookupVerifyImageStatus(safename string) (types.VerifyImageStatus, error) {
	if m, ok := verifierStatus[safename]; ok {
		if debug {
			log.Printf("LookupVerifyImageStatus: found based on safename %s\n",
				safename)
		}
		return m, nil
	} else {
		return types.VerifyImageStatus{}, errors.New("No VerifyImageStatus for safename")
	}
}

func lookupVerifyImageStatusSha256Impl(sha256 string) (*types.VerifyImageStatus,
	error) {
	for _, m := range verifierStatus {
		if m.ImageSha256 == sha256 {
			return &m, nil
		}
	}
	return nil, errors.New("No VerifyImageStatus for sha")
}

func LookupVerifyImageStatusSha256(sha256 string) (types.VerifyImageStatus,
	error) {
	m, err := lookupVerifyImageStatusSha256Impl(sha256)
	if err != nil {
		return types.VerifyImageStatus{}, err
	} else {
		log.Printf("LookupVerifyImageStatusSha256: found based on sha256 %s safename %s\n",
			sha256, m.Safename)
		return *m, nil
	}
}

func LookupVerifyImageStatusAny(safename string,
	sha256 string) (types.VerifyImageStatus, error) {
	m0, err := LookupVerifyImageStatus(safename)
	if err == nil {
		return m0, nil
	}
	m1, err := lookupVerifyImageStatusSha256Impl(sha256)
	if err == nil {
		if debug {
			log.Printf("LookupVerifyImageStatusAny: found based on sha %s\n",
				sha256)
		}
		return *m1, nil
	} else {
		return types.VerifyImageStatus{},
			errors.New("No VerifyImageStatus for safename nor sha")
	}
}

func handleVerifyImageStatusDelete(ctxArg interface{}, statusFilename string) {
// XXX	statusArg interface{}) {

	log.Printf("handleVerifyImageStatusDelete for %s\n", statusFilename)
	ctx := ctxArg.(*zedmanagerContext)
	// XXX use statusArg
	key := statusFilename // XXX different than safename? Whole path?
	if m, ok := verifierStatus[key]; !ok {
		log.Printf("handleVerifyImageStatusDelete for %s - not found\n",
			key)
	} else {
		if debug {
			log.Printf("verifier map delete for %v\n", m.State)
		}
		delete(verifierStatus, key)
		if debug {
			log.Printf("Deleted verifierStatus key %v\n", key)
			dumpVerifierStatus()
		}
		removeAIStatusSafename(ctx, key)
	}
	log.Printf("handleVerifyImageStatusDelete done for %s\n", statusFilename)
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
		}
	}
	return true
}
