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
	"os"
)

// Key is UUID:IID
var EIDConfig map[string]types.EIDConfig

func MaybeAddEIDConfig(UUIDandVersion types.UUIDandVersion,
	displayName string, ec *types.EIDOverlayConfig) {
	key := fmt.Sprintf("%s:%d", UUIDandVersion.UUID.String(), ec.IID)

	log.Printf("MaybeAddEIDConfig for %s displayName %s\n", key,
		displayName)

	if EIDConfig == nil {
		fmt.Printf("create EID config map\n")
		EIDConfig = make(map[string]types.EIDConfig)
	}
	if _, ok := EIDConfig[key]; ok {
		fmt.Printf("EID config already exists for %s\n", key)
		// XXX check displayName and EIDConfigDetails didn't change?
	} else {
		fmt.Printf("EID config add for %s\n", key)

		EIDConfig[key] = types.EIDConfig{
			UUIDandVersion:   UUIDandVersion,
			DisplayName:      displayName,
			EIDConfigDetails: ec.EIDConfigDetails,
		}
		configFilename := fmt.Sprintf("%s/%s.json",
			identitymgrConfigDirname, key)
		writeEIDConfig(EIDConfig[key], configFilename)
	}
	log.Printf("MaybeAddEIDConfig done for %s\n", key)
}

func MaybeRemoveEIDConfig(UUIDandVersion types.UUIDandVersion,
	es *types.EIDStatusDetails) {
	key := fmt.Sprintf("%s:%d", UUIDandVersion.UUID.String(), es.IID)
	log.Printf("MaybeRemoveEIDConfig for %s\n", key)

	if EIDConfig == nil {
		fmt.Printf("create EID config map\n")
		EIDConfig = make(map[string]types.EIDConfig)
	}
	if _, ok := EIDConfig[key]; !ok {
		log.Printf("EID config missing for remove for %s\n", key)
		return
	}
	delete(EIDConfig, key)
	configFilename := fmt.Sprintf("%s/%s.json",
		identitymgrConfigDirname, key)
	if err := os.Remove(configFilename); err != nil {
		log.Println(err)
	}
	log.Printf("MaybeRemoveEIDConfig done for %s\n", key)
}

func writeEIDConfig(config types.EIDConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal EIDConfig")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

// Key is UUID:IID
var EIDStatus map[string]types.EIDStatus

func handleEIDStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.EIDStatus)
	key := fmt.Sprintf("%s:%d",
		status.UUIDandVersion.UUID.String(), status.IID)
	log.Printf("handleEIDStatusModify for %s\n", key)
	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("handleEIDStatusModify skipping due to Pending* for %s\n",
			key)
		return
	}

	if EIDStatus == nil {
		fmt.Printf("create EID map\n")
		EIDStatus = make(map[string]types.EIDStatus)
	}
	changed := false
	if _, ok := EIDStatus[key]; ok {
		fmt.Printf("Exists means no change for %v\n", status.EID)
	} else {
		fmt.Printf("EID map add for %v\n", status.EID)
		changed = true
	}
	if changed {
		EIDStatus[key] = *status
		updateAIStatusUUID(status.UUIDandVersion.UUID.String())
	}

	log.Printf("handleEIDStatusModify done for %s\n",
		key)
}

func LookupEIDStatus(UUIDandVersion types.UUIDandVersion, IID uint32) (types.EIDStatus, error) {
	key := fmt.Sprintf("%s:%d", UUIDandVersion.UUID.String(), IID)
	if m, ok := EIDStatus[key]; ok {
		return m, nil
	} else {
		return types.EIDStatus{}, errors.New("No EIDStatus")
	}
}

func handleEIDStatusDelete(ctxArg interface{}, statusFilename string) {
	log.Printf("handleEIDStatusDelete for %s\n",
		statusFilename)

	key := statusFilename
	if m, ok := EIDStatus[key]; !ok {
		log.Printf("handleEIDStatusDelete for %s - not found\n",
			key)
	} else {
		fmt.Printf("EID map delete for %v\n", m.EID)
		delete(EIDStatus, key)
		removeAIStatusUUID(m.UUIDandVersion.UUID.String())
	}
	log.Printf("handleEIDStatusDelete done for %s\n",
		statusFilename)
}
