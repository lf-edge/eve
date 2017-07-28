// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
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
			UUIDandVersion: UUIDandVersion,
			DisplayName: displayName,
			EIDConfigDetails: ec.EIDConfigDetails,
		}
		configFilename := fmt.Sprintf("%s/%s.json",
			identitymgrConfigDirname, key)
		writeEIDConfig(EIDConfig[key], configFilename)
	}	
	log.Printf("MaybeAddEIDConfig done for %s\n", key)
}

func writeEIDConfig(config types.EIDConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal EIDConfig")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	// XXX which permissions?
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

// Key is UUID:IID
var EIDStatus map[string]types.EIDStatus

func handleEIDStatusModify(statusFilename string,
     statusArg interface{}) {
	var status *types.EIDStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle EIDStatus")
	case *types.EIDStatus:
		status = statusArg.(*types.EIDStatus)
	}

	key := fmt.Sprintf("%s:%d",
		status.UUIDandVersion.UUID.String(), status.IID)
	log.Printf("handleEIDStatusModify for %s\n", key)

	if EIDStatus == nil {
		fmt.Printf("create EID map\n")
		EIDStatus = make(map[string]types.EIDStatus)
	}
	changed := false
	if m, ok := EIDStatus[key]; ok {
		// Did an EID get assigned?
		if !bytes.Equal(status.EID, m.EID) {
			fmt.Printf("EID map changed from %v to %v\n",
				m.EID, status.EID)
			changed = true
		}
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

func handleEIDStatusDelete(statusFilename string) {
	log.Printf("handleEIDStatusDelete for %s\n",
		statusFilename)

	key := statusFilename
	if m, ok := EIDStatus[key]; !ok {
		log.Printf("handleEIDStatusDelete for %s - not found\n",
			key)
	} else {
		fmt.Printf("EID map delete for %v\n", m.EID)
		delete(EIDStatus, key)
		updateAIStatusUUID(m.UUIDandVersion.UUID.String())
	}
	log.Printf("handleEIDStatusDelete done for %s\n",
		statusFilename)
}
