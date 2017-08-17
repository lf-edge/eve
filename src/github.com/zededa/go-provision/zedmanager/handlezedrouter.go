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
	"reflect"
)

// Key is UUID
// XXX change from string to UUID?
var appNetworkConfig map[string]types.AppNetworkConfig

func MaybeAddAppNetworkConfig(aiConfig types.AppInstanceConfig,
     aiStatus *types.AppInstanceStatus) {
	key := aiConfig.UUIDandVersion.UUID.String()
	displayName := aiConfig.DisplayName
	log.Printf("MaybeAddAppNetworkConfig for %s displayName %s\n", key,
		displayName)

	if appNetworkConfig == nil {
		fmt.Printf("create appNetwork config map\n")
		appNetworkConfig = make(map[string]types.AppNetworkConfig)
	}
	changed := false
	if m, ok := appNetworkConfig[key]; ok {
		fmt.Printf("appNetwork config already exists for %s\n", key)
		if len(aiConfig.OverlayNetworkList) != len(m.OverlayNetworkList) {
			log.Println("Unsupported: Changed number of overlays for ",
				aiConfig.UUIDandVersion)
			return
		}
		if len(aiConfig.UnderlayNetworkList) != len(m.UnderlayNetworkList) {
			log.Println("Unsupported: Changed number of underlays for ",
				aiConfig.UUIDandVersion)
			return
		}
		for i, new := range aiConfig.OverlayNetworkList {
			old := m.OverlayNetworkList[i]
			if !reflect.DeepEqual(new.ACLs, old.ACLs) {
				log.Printf("Over ACLs changed from %v to %v\n",
					old.ACLs, new.ACLs)
				changed = true
				break
			}
			if !reflect.DeepEqual(new.NameToEidList,
			   old.NameToEidList) {
				log.Printf("NameToEidList changed from %v to %v\n",
					old.NameToEidList, new.NameToEidList)
				changed = true
				break
			}
		}
		for i, new := range aiConfig.UnderlayNetworkList {
			old := m.UnderlayNetworkList[i]
			if !reflect.DeepEqual(new.ACLs, old.ACLs) {
				log.Printf("Under ACLs changed from %v to %v\n",
					old.ACLs, new.ACLs)
				changed = true
				break
			}
		}
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
			len(aiStatus.EIDList))
		for i, ols := range aiStatus.EIDList {
			olc := &aiConfig.OverlayNetworkList[i]
			ol := &nc.OverlayNetworkList[i]
			ol.IID = ols.IID
			ol.EID = ols.EID
			ol.LispSignature = ols.LispSignature
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

func MaybeRemoveAppNetworkConfig(uuidStr string) {
	log.Printf("MaybeRemoveAppNetworkConfig for %s\n", uuidStr)

	if appNetworkConfig == nil {
		fmt.Printf("create AppNetwork config map\n")
		appNetworkConfig = make(map[string]types.AppNetworkConfig)
	}
	if _, ok := appNetworkConfig[uuidStr]; !ok {
		log.Printf("AppNetwork config missing for remove for %s\n", uuidStr)
		return
	}
	delete(appNetworkConfig, uuidStr)
	configFilename := fmt.Sprintf("%s/%s.json",
		zedrouterConfigDirname, uuidStr)
	if err := os.Remove(configFilename); err != nil {
		log.Println("Failed to remove", configFilename, err)
	}
	log.Printf("MaybeRemoveAppNetworkConfig done for %s\n", uuidStr)
}

func writeAppNetworkConfig(config types.AppNetworkConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal AppNetworkConfig")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
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
	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("handleAppNetworkStatusModify skipped due to Pending* for %s\n",
			key)
		return
	}
	if status.IsZedmanager {
		fmt.Printf("Ignoring IsZedmanager appNetwork status for %v\n",
			key)
		return
	}
	if appNetworkStatus == nil {
		fmt.Printf("create appNetwork status map\n")
		appNetworkStatus = make(map[string]types.AppNetworkStatus)
	}
	appNetworkStatus[key] = *status
	updateAIStatusUUID(status.UUIDandVersion.UUID.String())
	
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
		removeAIStatusUUID(m.UUIDandVersion.UUID.String())
	}
	log.Printf("handleAppNetworkStatusDelete done for %s\n",
		statusFilename)
}
