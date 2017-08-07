// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
)

// Key is Safename string.
var verifierConfig map[string]types.VerifyImageConfig

func MaybeAddVerifyImageConfig(safename string, sc *types.StorageConfig) {
	log.Printf("MaybeAddVerifyImageConfig for %s\n",
		safename)

	if verifierConfig == nil {
		fmt.Printf("create verifier config map\n")
		verifierConfig = make(map[string]types.VerifyImageConfig)
	}
	key := safename
	if _, ok := verifierConfig[key]; ok {
		fmt.Printf("verifier config already exists for %s\n",
			safename)
	} else {
		fmt.Printf("verifier config add for %s\n", safename)
		n := types.VerifyImageConfig{
			Safename:	safename,
			DownloadURL:	sc.DownloadURL,
			ImageSha256:	sc.ImageSha256,
		}
		verifierConfig[key] = n
		configFilename := fmt.Sprintf("%s/%s.json",
			verifierConfigDirname, safename)
		writeVerifyImageConfig(verifierConfig[key], configFilename)
	}
	log.Printf("AddOrRefcountVerifyImageConfig done for %s\n",
		safename)
}

func writeVerifyImageConfig(config types.VerifyImageConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal VerifyImageConfig")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

// Key is Safename string.
var verifierStatus map[string]types.VerifyImageStatus

func handleVerifyImageStatusModify(statusFilename string,
     statusArg interface{}) {
	var status *types.VerifyImageStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle VerifyImageStatus")
	case *types.VerifyImageStatus:
		status = statusArg.(*types.VerifyImageStatus)
	}

	log.Printf("handleVerifyImageStatusModify for %s\n",
		status.Safename)
	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("handleVerifyImageStatusModify skipped due to Pending* for %s\n",
			status.Safename)
		return
	}

	if verifierStatus == nil {
		fmt.Printf("create verifier map\n")
		verifierStatus = make(map[string]types.VerifyImageStatus)
	}
	key := status.Safename
	changed := false
	if m, ok := verifierStatus[key]; ok {
		if status.State != m.State {
			fmt.Printf("verifier map changed from %v to %v\n",
				m.State, status.State)
			changed = true
		}
	} else {
		fmt.Printf("verifier map add for %v\n", status.State)
		changed = true
	}
	if changed {
		verifierStatus[key] = *status
		updateAIStatusSafename(key)
	}
	log.Printf("handleVerifyImageStatusModify done for %s\n",
		status.Safename)
}

func LookupVerifyImageStatus(safename string) (types.VerifyImageStatus, error) {
	if m, ok := verifierStatus[safename]; ok {
		log.Printf("LookupVerifyImageStatus: found based on safename %s\n",
				safename)
		return m, nil
	} else {
		return types.VerifyImageStatus{}, errors.New("No VerifyImageStatus")
	}
}

func LookupVerifyImageStatusSha256(sha256 string) (types.VerifyImageStatus,
     error) {
	for _, m := range verifierStatus {     
		if m.ImageSha256 == sha256 {
			log.Printf("LookupVerifyImageStatusSha256: found based on sha256 %s safename %s\n",
				sha256, m.Safename)
			return m, nil
		}
	}
	return types.VerifyImageStatus{}, errors.New("No VerifyImageStatus")
}

func handleVerifyImageStatusDelete(statusFilename string) {
	log.Printf("handleVerifyImageStatusDelete for %s\n",
		statusFilename)

	key := statusFilename
	if m, ok := verifierStatus[key]; !ok {
		log.Printf("handleVerifyImageStatusDelete for %s - not found\n",
			key)
	} else {
		fmt.Printf("verifier map delete for %v\n", m.State)
		delete(verifierStatus, key)
		updateAIStatusSafename(key)
	}
	log.Printf("handleVerifyImageStatusDelete done for %s\n",
		statusFilename)
}


