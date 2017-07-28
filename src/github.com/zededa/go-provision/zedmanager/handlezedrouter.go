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

// Key is UUID
// XXX change from string to UUID?
var appNetworkConfig map[string]types.AppNetworkConfig

func MaybeAddAppNetworkConfig(aiConfig types.AppInstanceConfig) {
	key := aiConfig.UUIDandVersion.UUID.String()
	displayName := aiConfig.DisplayName
	log.Printf("MaybeAddAppNetworkConfig for %s displayName %s\n", key,
		displayName)

	if appNetworkConfig == nil {
		fmt.Printf("create appNetwork config map\n")
		appNetworkConfig = make(map[string]types.AppNetworkConfig)
	}
	changed := false
	if _, ok := appNetworkConfig[key]; ok {
		fmt.Printf("appNetwork config already exists for %s\n", key)
		// XXX update ACLs etc; set changed
	} else {
		fmt.Printf("appNetwork config add for %s\n", key)
		changed = true
	}
	if changed {
		nc := types.AppNetworkConfig{
			UUIDandVersion: aiConfig.UUIDandVersion,
			DisplayName: aiConfig.DisplayName,
			IsZedmanager: false,
		}
		nc.OverlayNetworkList = make([]types.OverlayNetworkConfig,
			len(aiConfig.OverlayNetworkList))
		for i, olc := range aiConfig.OverlayNetworkList {
			ol := &nc.OverlayNetworkList[i]
			ol.IID = olc.IID
			ol.EID = olc.EID
			ol.LispSignature = olc.LispSignature
			ol.ACLs = olc.ACLs
			ol.NameToEidList = olc.NameToEidList
		}
		nc.UnderlayNetworkList = make([]types.UnderlayNetworkConfig,
			len(aiConfig.UnderlayNetworkList))
		for i, ulc := range aiConfig.UnderlayNetworkList {
			ul := &nc.UnderlayNetworkList[i]
			ul.ACLs = ulc.ACLs
		}
		appNetworkConfig[key] = nc
		configFilename := fmt.Sprintf("%s/%s.json",
			zedrouterConfigDirname, key)
		writeAppNetworkConfig(appNetworkConfig[key], configFilename)
	}	
	log.Printf("MaybeAddAppNetworkConfig done for %s\n", key)
}

func writeAppNetworkConfig(config types.AppNetworkConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal AppNetworkConfig")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	// XXX which permissions?
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

// Key is UUID
// XXX change from string to UUID?
var appNetworkStatus map[string]types.AppNetworkStatus

func handleAppNetworkStatusModify(statusFilename string,
     statusArg interface{}) {
	var status *types.AppNetworkStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle AppNetworkStatus")
	case *types.AppNetworkStatus:
		status = statusArg.(*types.AppNetworkStatus)
	}

	key := status.UUIDandVersion.UUID.String()
	log.Printf("handleAppNetworkStatusModify for %s\n", key)

	if appNetworkStatus == nil {
		fmt.Printf("create appNetwork status map\n")
		appNetworkStatus = make(map[string]types.AppNetworkStatus)
	}
	changed := false
	if _, ok := appNetworkStatus[key]; ok {
		// Is the add/change done?
		if !status.PendingAdd && !status.PendingModify {
			fmt.Printf("status is not pending\n");
			changed = true
		}
	} else {
		if !status.IsZedmanager {
			fmt.Printf("appNetwork status map add for %v\n", key)
			changed = true
		}
	}
	if changed {
		appNetworkStatus[key] = *status
		updateAIStatusUUID(status.UUIDandVersion.UUID.String())
	}
	
	log.Printf("handleAppNetworkStatusModify done for %s\n",
		key)
}

func LookupAppNetworkStatus(uuidStr string) (types.AppNetworkStatus, error) {
	if m, ok := appNetworkStatus[uuidStr]; ok {
		return m, nil
	} else {
		return types.AppNetworkStatus{}, errors.New("No AppNetworkStatus")
	}
}

func handleAppNetworkStatusDelete(statusFilename string) {
	log.Printf("handleAppNetworkStatusDelete for %s\n",
		statusFilename)

	key := statusFilename
	if m, ok := appNetworkStatus[key]; !ok {
		log.Printf("handleAppNetworkStatusDelete for %s - not found\n",
			key)
	} else {
		fmt.Printf("appNetwork Status map delete for %v\n", key)
		delete(appNetworkStatus, key)
		updateAIStatusUUID(m.UUIDandVersion.UUID.String())
	}
	log.Printf("handleAppNetworkStatusDelete done for %s\n",
		statusFilename)
}
