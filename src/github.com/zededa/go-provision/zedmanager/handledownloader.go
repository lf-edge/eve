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

// Key is Safename string.
var downloaderConfig map[string]types.DownloaderConfig

func AddOrRefcountDownloaderConfig(safename string, sc *types.StorageConfig) {
	log.Printf("AddOrRefcountDownloaderConfig for %s\n",
		safename)

	if downloaderConfig == nil {
		fmt.Printf("create downloader config map\n")
		downloaderConfig = make(map[string]types.DownloaderConfig)
	}
	key := safename
	if m, ok := downloaderConfig[key]; ok {
		fmt.Printf("downloader config exists for %s refcount %d\n",
			safename, m.RefCount)
		m.RefCount += 1
	} else {
		fmt.Printf("downloader config add for %s\n", safename)
		n := types.DownloaderConfig{
			Safename:	safename,
			DownloadURL:	sc.DownloadURL,
			MaxSize:	sc.MaxSize,
			ImageSha256:	sc.ImageSha256,
			RefCount:	1,
		}
		downloaderConfig[key] = n
	}
	configFilename := fmt.Sprintf("%s/%s.json",
		downloaderConfigDirname, safename)
	writeDownloaderConfig(downloaderConfig[key], configFilename)
	
	log.Printf("AddOrRefcountDownloaderConfig done for %s\n",
		safename)
}

func MaybeRemoveDownloaderConfig(safename string) {
	log.Printf("MaybeRemoveDownloaderConfig for %s\n", safename)

	if downloaderConfig == nil {
		fmt.Printf("create Downloader config map\n")
		downloaderConfig = make(map[string]types.DownloaderConfig)
	}
	if _, ok := downloaderConfig[safename]; !ok {
		log.Printf("Downloader config missing for remove for %s\n",
			safename)
		return
	}
	delete(downloaderConfig, safename)
	configFilename := fmt.Sprintf("%s/%s.json",
		downloaderConfigDirname, safename)
	if err := os.Remove(configFilename); err != nil {
		log.Println("Failed to remove", configFilename, err)
	}
	log.Printf("MaybeRemoveDownloaderConfig done for %s\n", safename)
}

func writeDownloaderConfig(config types.DownloaderConfig,
	configFilename string) {
	b, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal DownloaderConfig")
	}
	// We assume a /var/run path hence we don't need to worry about
	// partial writes/empty files due to a kernel crash.
	err = ioutil.WriteFile(configFilename, b, 0644)
	if err != nil {
		log.Fatal(err, configFilename)
	}
}

// Key is Safename string.
var downloaderStatus map[string]types.DownloaderStatus

func handleDownloaderStatusModify(statusFilename string,
     statusArg interface{}) {
	var status *types.DownloaderStatus

	switch statusArg.(type) {
	default:
		log.Fatal("Can only handle DownloaderStatus")
	case *types.DownloaderStatus:
		status = statusArg.(*types.DownloaderStatus)
	}

	log.Printf("handleDownloaderStatusModify for %s\n",
		status.Safename)

	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("handleDownloaderStatusModify skipping due to Pending* for %s\n",
			status.Safename)
		return
	}
	if downloaderStatus == nil {
		fmt.Printf("create downloader map\n")
		downloaderStatus = make(map[string]types.DownloaderStatus)
	}
	key := status.Safename
	changed := false
	if m, ok := downloaderStatus[key]; ok {
		if status.State != m.State {
			fmt.Printf("downloader map changed from %v to %v\n",
				m.State, status.State)
			changed = true
		}
	} else {
		fmt.Printf("downloader map add for %v\n", status.State)
		changed = true
	}
	if changed {
		downloaderStatus[key] = *status
		updateAIStatusSafename(key)
	}
	
	log.Printf("handleDownloaderStatusModify done for %s\n",
		status.Safename)
}

func LookupDownloaderStatus(safename string) (types.DownloaderStatus, error) {
	if m, ok := downloaderStatus[safename]; ok {
		return m, nil
	} else {
		return types.DownloaderStatus{}, errors.New("No DownloaderStatus")
	}
}

func handleDownloaderStatusDelete(statusFilename string) {
	log.Printf("handleDownloaderStatusDelete for %s\n",
		statusFilename)

	key := statusFilename
	if m, ok := downloaderStatus[key]; !ok {
		log.Printf("handleDownloaderStatusDelete for %s - not found\n",
			key)
	} else {
		fmt.Printf("downloader map delete for %v\n", m.State)
		delete(downloaderStatus, key)
		removeAIStatusSafename(key)
	}
	log.Printf("handleDownloaderStatusDelete done for %s\n",
		statusFilename)
}


