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

// Key is UUID
// XXX change from string to UUID?
var domainConfig map[string]types.DomainConfig

func MaybeAddDomainConfig(aiConfig types.AppInstanceConfig,
	ns *types.AppNetworkStatus) {
	key := aiConfig.UUIDandVersion.UUID.String()
	displayName := aiConfig.DisplayName
	log.Printf("MaybeAddDomainConfig for %s displayName %s\n", key,
		displayName)

	if domainConfig == nil {
		fmt.Printf("create Domain config map\n")
		domainConfig = make(map[string]types.DomainConfig)
	}
	changed := false
	if m, ok := domainConfig[key]; ok {
		// XXX any other change? Compare nothing else changed?
		if m.Activate != aiConfig.Activate {
			fmt.Printf("Domain config: Activate changed %s\n", key)
			changed = true
		} else {
			fmt.Printf("Domain config already exists for %s\n", key)
		}
	} else {
		fmt.Printf("Domain config add for %s\n", key)
		changed = true
	}
	if changed {
		AppNum := 0
		if ns != nil {
			AppNum = ns.AppNum
		}
		dc := types.DomainConfig{
			UUIDandVersion: aiConfig.UUIDandVersion,
			DisplayName:    aiConfig.DisplayName,
			Activate:       aiConfig.Activate,
			AppNum:         AppNum,
			FixedResources: aiConfig.FixedResources,
		}
		dc.DiskConfigList = make([]types.DiskConfig,
			len(aiConfig.StorageConfigList))
		for i, sc := range aiConfig.StorageConfigList {
			disk := &dc.DiskConfigList[i]
			disk.ImageSha256 = sc.ImageSha256
			disk.ReadOnly = sc.ReadOnly
			disk.Preserve = sc.Preserve
			disk.Format = sc.Format
			disk.Devtype = sc.Devtype
		}
		if ns != nil {
			dc.VifList = make([]types.VifInfo, ns.OlNum+ns.UlNum)
			// Put UL before OL
			for i, ul := range ns.UnderlayNetworkList {
				dc.VifList[i] = ul.VifInfo
			}
			for i, ol := range ns.OverlayNetworkList {
				dc.VifList[i+ns.UlNum] = ol.VifInfo
			}
		}
		domainConfig[key] = dc
		configFilename := fmt.Sprintf("%s/%s.json",
			domainmgrConfigDirname, key)
		writeDomainConfig(domainConfig[key], configFilename)
	}
	log.Printf("MaybeAddDomainConfig done for %s\n", key)
}

func MaybeRemoveDomainConfig(uuidStr string) {
	log.Printf("MaybeRemoveDomainConfig for %s\n", uuidStr)

	if domainConfig == nil {
		fmt.Printf("create Domain config map\n")
		domainConfig = make(map[string]types.DomainConfig)
	}
	if _, ok := domainConfig[uuidStr]; !ok {
		log.Printf("Domain config missing for remove for %s\n", uuidStr)
		return
	}
	delete(domainConfig, uuidStr)
	configFilename := fmt.Sprintf("%s/%s.json",
		domainmgrConfigDirname, uuidStr)
	if err := os.Remove(configFilename); err != nil {
		log.Println(err)
	}
	log.Printf("MaybeRemoveDomainConfig done for %s\n", uuidStr)
}

func writeDomainConfig(config types.DomainConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal DomainConfig")
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
var domainStatus map[string]types.DomainStatus

func handleDomainStatusModify(statusFilename string,
	statusArg interface{}) {
	var status *types.DomainStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle DomainStatus")
	case *types.DomainStatus:
		status = statusArg.(*types.DomainStatus)
	}

	key := status.UUIDandVersion.UUID.String()
	log.Printf("handleDomainStatusModify for %s\n", key)
	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("handleDomainstatusModify skipped due to Pending* for %s\n",
			key)
		return
	}

	if domainStatus == nil {
		fmt.Printf("create Domain map\n")
		domainStatus = make(map[string]types.DomainStatus)
	}
	domainStatus[key] = *status
	updateAIStatusUUID(status.UUIDandVersion.UUID.String())

	log.Printf("handleDomainStatusModify done for %s\n",
		key)
}

func LookupDomainStatus(uuidStr string) (types.DomainStatus, error) {
	if m, ok := domainStatus[uuidStr]; ok {
		return m, nil
	} else {
		return types.DomainStatus{}, errors.New("No DomainStatus")
	}
}

func handleDomainStatusDelete(statusFilename string) {
	log.Printf("handleDomainStatusDelete for %s\n",
		statusFilename)

	key := statusFilename
	if m, ok := domainStatus[key]; !ok {
		log.Printf("handleDomainStatusDelete for %s - not found\n",
			key)
	} else {
		fmt.Printf("Domain map delete for %v\n", key)
		delete(domainStatus, key)
		removeAIStatusUUID(m.UUIDandVersion.UUID.String())
	}
	log.Printf("handleDomainStatusDelete done for %s\n",
		statusFilename)
}
