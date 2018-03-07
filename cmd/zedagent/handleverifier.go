// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Pull AppInstanceConfig from ZedCloud, make it available for zedmanager
// publish AppInstanceStatus to ZedCloud.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"os"
)

// zedagent is the publishes for these config files
var verifierConfigMap map[string]types.VerifyImageConfig

// zedagent is the subscriber for these status files
var verifierStatusMap map[string]types.VerifyImageStatus

func initVerifierMaps() {

	if verifierConfigMap == nil {
		log.Printf("create verifierConfig map\n")
		verifierConfigMap = make(map[string]types.VerifyImageConfig)
	}

	if verifierStatusMap == nil {
		log.Printf("create verifierStatus map\n")
		verifierStatusMap = make(map[string]types.VerifyImageStatus)
	}
}

func createVerifierConfig(objType string, safename string,
	sc *types.StorageConfig) error {

	initVerifierMaps()

	// check the certificate files, if not present,
	// we can not start verification
	if err := checkCertsForObject(safename, sc); err != nil {
		log.Printf("%v for %s\n", err, safename)
		return err
	}

	key := formLookupKey(objType, safename)

	if m, ok := verifierConfigMap[key]; ok {
		log.Printf("verifier config exists for %s refcount %d\n",
			safename, m.RefCount)
		m.RefCount += 1
	} else {
		log.Printf(" dev config verifier config add for %s\n", safename)
		n := types.VerifyImageConfig{
			Safename:         safename,
			DownloadURL:      sc.DownloadURL,
			ImageSha256:      sc.ImageSha256,
			CertificateChain: sc.CertificateChain,
			ImageSignature:   sc.ImageSignature,
			SignatureKey:     sc.SignatureKey,
			RefCount:         1,
		}
		verifierConfigMap[key] = n
	}

	configFilename := fmt.Sprintf("%s/%s/config/%s.json",
		verifierBaseDirname, objType, safename)

	writeVerifierConfig(verifierConfigMap[key], configFilename)

	log.Printf("createVerifierConfig done for %s\n",
		safename)
	return nil
}

func updateVerifierStatus(objType string, status *types.VerifyImageStatus) {

	initVerifierMaps()

	key := formLookupKey(objType, status.Safename)
	log.Printf("updateVerifierStatus for %s\n", key)

	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("updateVerifierStatus for %s, Skipping due to Pending*\n", key)
		return
	}

	changed := false
	if m, ok := verifierStatusMap[key]; ok {
		if status.State != m.State {
			log.Printf("updateVerifierStatus for %s, Verifier map state changed from %v to %v\n",
				key, m.State, status.State)
			changed = true
		}
	} else {
		log.Printf("updateVerifierStatus for %s, Verifier map add for %v\n", key, status.State)
		changed = true

	}

	if changed {
		verifierStatusMap[key] = *status
		baseOsHandleStatusUpdateSafename(status.Safename)
	}

	log.Printf("updateVerifierStatus for %s, Done\n", key)
}

func removeVerifierConfig(objType string, safename string) {

	key := formLookupKey(objType, safename)
	log.Printf("removeVerifierConfig for %s, Done\n", key)

	if _, ok := verifierConfigMap[key]; !ok {
		log.Printf("removeVerifierConfig for %s - not found\n", key)
		return
	}
	log.Printf("removeVerifierConfig for %s, verifier config map delete\n", key)
	delete(verifierConfigMap, key)

	configFilename := fmt.Sprintf("%s/%s/config/%s.json",
		verifierBaseDirname, objType, safename)

	if err := os.Remove(configFilename); err != nil {
		log.Println(err)
	}

	log.Printf("removeVerifierConfig for %s, Done\n", key)
}

func removeVerifierStatus(objType string, safename string) {

	key := formLookupKey(objType, safename)

	if _, ok := verifierStatusMap[key]; !ok {
		log.Printf("removeVerifierStatus for %s, Verifier Status Map is absent\n", key)
		return
	}

	log.Printf("removeVerifierStatus for %s, verifier status map delete\n", key)
	delete(verifierStatusMap, key)

	log.Printf("removeVerifierStatus for %s, Done\n", key)
}

func lookupVerificationStatusSha256Internal(objType string, sha256 string) (*types.VerifyImageStatus, error) {

	for _, m := range verifierStatusMap {
		if m.ImageSha256 == sha256 {
			return &m, nil
		}
	}

	return nil, errors.New("No verificationStatusMap for sha")
}

func lookupVerificationStatus(objType string, safename string) (types.VerifyImageStatus, error) {

	key := formLookupKey(objType, safename)

	if m, ok := verifierStatusMap[key]; ok {

		log.Printf("lookupVerifyImageStatus: found based on safename %s\n",
			safename)
		return m, nil
	}
	return types.VerifyImageStatus{},
		errors.New("No verificationStatusMap for safename")
}

func lookupVerificationStatusSha256(objType string, sha256 string) (types.VerifyImageStatus, error) {

	m, err := lookupVerificationStatusSha256Internal(objType, sha256)
	if err != nil {
		return types.VerifyImageStatus{}, err
	}
	log.Printf("found status based on sha256 %s safename %s\n",
		sha256, m.Safename)
	return *m, nil
}

func lookupVerificationStatusAny(objType string, safename string, sha256 string) (types.VerifyImageStatus, error) {

	m0, err := lookupVerificationStatus(objType, safename)
	if err == nil {
		return m0, nil
	}
	m1, err := lookupVerificationStatusSha256Internal(objType, sha256)
	if err == nil {
		log.Printf("lookupVerifyImageStatusAny: found based on sha %s\n",
			sha256)
		return *m1, nil
	}
	return types.VerifyImageStatus{},
		errors.New("No verification status for safename nor sha")
}

func checkStorageVerifierStatus(objType string, uuidStr string,
	config []types.StorageConfig, status []types.StorageStatus) *types.RetStatus {

	ret := &types.RetStatus{}
	key := formLookupKey(objType, uuidStr)

	log.Printf("checkStorageVerifierStatus for %s\n", key)

	ret.AllErrors = ""
	ret.Changed = false
	ret.MinState = types.MAXSTATE

	for i, sc := range config {
		ss := &status[i]

		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

		log.Printf("checkStorageVerifierStatus for %s\n", sc.DownloadURL)

		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			continue
		}

		vs, err := lookupVerificationStatusAny(objType, safename, sc.ImageSha256)
		if err != nil {
			log.Printf("%s, %v\n", safename, err)
			ret.MinState = types.DOWNLOADED
			continue
		}
		if ret.MinState > vs.State {
			ret.MinState = vs.State
		}
		if vs.State != ss.State {
			ss.State = vs.State
			ret.Changed = true
		}
		switch vs.State {
		case types.INITIAL:
			log.Printf("%s, verifier error for %s: %s\n",
				key, safename, vs.LastErr)
			ss.Error = vs.LastErr
			ret.AllErrors = appendError(ret.AllErrors, "verifier",
				vs.LastErr)
			ss.ErrorTime = vs.LastErrTime
			ret.ErrorTime = vs.LastErrTime
			ret.Changed = true
		default:
			ss.ActiveFileLocation = objectDownloadDirname + "/" + objType + "/" + vs.Safename

			log.Printf("%s, Update SSL ActiveFileLocation for %s: %s\n",
				key, uuidStr, ss.ActiveFileLocation)
			ret.Changed = true
		}
	}

	if ret.MinState == types.MAXSTATE {
		// Odd; no StorageConfig in list
		ret.MinState = types.DELIVERED
	}
	return ret
}

func writeVerifierConfig(config types.VerifyImageConfig, configFilename string) {

	bytes, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageConfig")
	}

	err = ioutil.WriteFile(configFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
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
		log.Printf("checkCertsForObject() for %s, no certificates configured\n",
			safename)
		return nil
	}

	if sc.SignatureKey != "" {
		safename := types.UrlToSafename(sc.SignatureKey, "")
		filename := certificateDirname + "/" +
			types.SafenameToFilename(safename)
		if _, err := os.Stat(filename); err != nil {
			log.Printf("checkCertsForObject() for %s, %v\n", filename, err)
			return err
		}
	}

	for _, certUrl := range sc.CertificateChain {
		if certUrl != "" {
			safename := types.UrlToSafename(certUrl, "")
			filename := certificateDirname + "/" +
				types.SafenameToFilename(safename)
			if _, err := os.Stat(filename); err != nil {
				log.Printf("checkCertsForObject() for %s, %v\n", filename, err)
				return err
			}
		}
	}
	return nil
}
