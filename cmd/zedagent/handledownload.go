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
	"time"
)

// zedagent publishes for these config files
var downloaderConfigMap map[string]types.DownloaderConfig

// zedagent is the subscriber for these status files
var downloaderStatusMap map[string]types.DownloaderStatus

func initDownloaderMaps() {

	if downloaderConfigMap == nil {
		log.Printf("create downloaderConfig map\n")
		downloaderConfigMap = make(map[string]types.DownloaderConfig)
	}

	if downloaderStatusMap == nil {
		log.Printf("create downloadetStatus map\n")
		downloaderStatusMap = make(map[string]types.DownloaderStatus)
	}
}

func createDownloaderConfig(objType string, safename string,
	sc *types.StorageConfig) {

	initDownloaderMaps()

	key := formLookupKey(objType, safename)
	log.Printf("createDownloaderConfig for %s\n", key)

	if m, ok := downloaderConfigMap[key]; ok {
		log.Printf("createDownloaderConfig for %s, exists, refcount %d\n",
			key, m.RefCount)
		m.RefCount += 1
	} else {
		n := types.DownloaderConfig{
			Safename:        safename,
			DownloadURL:     sc.DownloadURL,
			UseFreeUplinks:  false,
			MaxSize:         sc.MaxSize,
			TransportMethod: sc.TransportMethod,
			Dpath:           sc.Dpath,
			ApiKey:          sc.ApiKey,
			Password:        sc.Password,
			ImageSha256:     sc.ImageSha256,
			RefCount:        1,
		}
		downloaderConfigMap[key] = n
	}

	configFilename := fmt.Sprintf("%s/%s/config/%s.json",
		downloaderBaseDirname, objType, safename)
	writeDownloaderConfig(downloaderConfigMap[key], configFilename)
}

func updateDownloaderStatus(objType string, status *types.DownloaderStatus) {

	initDownloaderMaps()

	key := formLookupKey(objType, status.Safename)
	log.Printf("updateDownloaderStatus for %s, %v\n", key, status.State)

	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("updateDownloaderStatus for %s, Skipping due to Pending*\n", key)
		return
	}

	changed := false
	if m, ok := downloaderStatusMap[key]; ok {
		if status.State != m.State {
			log.Printf("Download state %s, state changed from %v to %v\n",
				key, m.State, status.State)
			changed = true
		}
	} else {
		log.Printf("Downloader status map %s add, state %v\n",
			key, status.State)
		changed = true
	}

	if changed {

		downloaderStatusMap[key] = *status

		switch objType {
		case baseOsObj:
			baseOsHandleStatusUpdateSafename(status.Safename)

		case certObj:
			certObjHandleStatusUpdateSafename(status.Safename)

		default:
			log.Fatal("%s, unsupported objType <%s>\n",
				status.Safename, objType)
			return
		}
	}

	log.Printf("updateDownloaderStatus for %s, Done\n", key)
}

func removeDownloaderConfig(objType string, safename string) {

	key := formLookupKey(objType, safename)

	log.Printf("removeDownloaderConfig for %s\n", key)

	m, ok := downloaderConfigMap[key];
	if !ok {
		log.Printf("removeDownloaderConfig for %s, Config absent\n", key)
		return
	}

	if m.RefCount > 1 {
		m.RefCount -= 1
		log.Printf("%s, decrementing refCount\n", key)
		return
	}

	log.Printf("%s, downloader config map entry delete\n", key)
	delete(downloaderConfigMap, key)

	configFilename := fmt.Sprintf("%s/%s/config/%s.json",
		downloaderBaseDirname, objType, safename)

	if err := os.Remove(configFilename); err != nil {
		log.Println(err)
	}
	log.Printf("removeDownloaderConfig for %s, Done\n", key)
}

func removeDownloaderStatus(objType string, statusFilename string) {

	key := formLookupKey(objType, statusFilename)

	log.Printf("%s, downloader status delete\n", key)

	if _, ok := downloaderStatusMap[key]; !ok {
		log.Printf("%s, downloader Status Map absent\n",
			key)
		return
	}
	log.Printf("removeDownloaderStatus for %s, Downloader status map entry delete\n", key)
	delete(downloaderStatusMap, key)

	log.Printf("%s, downloader status delete done\n", key)
}

func lookupDownloaderStatus(objType string, safename string) (types.DownloaderStatus, error) {

	key := formLookupKey(objType, safename)

	if m, ok := downloaderStatusMap[key]; ok {
		return m, nil
	}
	return types.DownloaderStatus{}, errors.New("No DownloaderStatus")
}

func checkStorageDownloadStatus(objType string, uuidStr string,
	config []types.StorageConfig, status []types.StorageStatus) *types.RetStatus {

	ret := &types.RetStatus{}
	key := formLookupKey(objType, uuidStr)
	log.Printf("checkStorageDownloadStatus for %s, %v\n", key, status)

	ret.Changed = false
	ret.AllErrors = ""
	ret.MinState = types.MAXSTATE

	for i, sc := range config {

		ss := &status[i]

		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

		log.Printf("checkStorageDownloadStatus for %s, %v\n", safename, ss.State)
		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			log.Printf("checkStorageDownloadStatus for %s is already installed\n", safename)
			continue
		}

		if sc.ImageSha256 != "" {
			// Shortcut if image is already verified
			vs, err := lookupVerificationStatusAny(objType,
				safename, sc.ImageSha256)

			if err == nil && vs.State == types.DELIVERED {
				log.Printf(" %s, exists verified with sha %s\n",
					safename, sc.ImageSha256)
				// If we don't already have a RefCount add one
				if !ss.HasVerifierRef {
					log.Printf("%s, !HasVerifierRef\n", safename)
					vs.RefCount += 1
					ss.HasVerifierRef = true
					ret.Changed = true
				}
				if ret.MinState > vs.State {
					ret.MinState = vs.State
				}
				if vs.State != ss.State {
					ss.State = vs.State
					ret.Changed = true
				}
				continue
			}
		}

		if !ss.HasDownloaderRef {
			log.Printf("%s, !HasDownloaderRef\n", safename)
			createDownloaderConfig(objType, safename, &sc)
			ss.HasDownloaderRef = true
			ret.Changed = true
		}
        
		ds, err := lookupDownloaderStatus(objType, safename)
		if err != nil {
			log.Printf("%s, %s \n", safename, err)
			ret.MinState = types.DOWNLOAD_STARTED
			continue
		}

		if ret.MinState > ds.State {
			ret.MinState = ds.State
		}
		if ds.State != ss.State {
			ss.State = ds.State
			ret.Changed = true
		}

		switch ss.State {
		case types.INITIAL:
			log.Printf("%s, Downloader status error, %s\n",
				key, ds.LastErr)
			ss.Error = ds.LastErr
			ret.AllErrors = appendError(ret.AllErrors, "downloader",
				ds.LastErr)
			ss.ErrorTime = ds.LastErrTime
			ret.ErrorTime = ss.ErrorTime
			ret.Changed = true
		case types.DOWNLOAD_STARTED:
			// Nothing to do
		case types.DOWNLOADED:

			log.Printf("%s, Downloaded\n", safename)
			// if verification is needed
			if sc.ImageSha256 != "" {
				// start verifier for this object
				if !ss.HasVerifierRef {
					err := createVerifierConfig(objType, safename, &sc)
					if err == nil {
						ss.HasVerifierRef = true
						ret.Changed = true
					} else {
						ret.AllErrors = appendError(ret.AllErrors, "downloader", err.Error())
					}
				}
			}
		}
	}

	if ret.MinState == types.MAXSTATE {
		ret.MinState = types.DOWNLOADED
	}

	return ret
}

func installDownloadedObjects(objType string, uuidStr string,
	config []types.StorageConfig, status []types.StorageStatus) bool {

	ret := true
	key := formLookupKey(objType, uuidStr)
	log.Printf("installDownloadedObjects for %s\n", key)

	for i, sc := range config {

		ss := &status[i]

		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

		installDownloadedObject(objType, safename, sc, ss)

		// if something is still not installed, mark accordingly
		if ss.State != types.INSTALLED {
			ret = false
		}
	}

	log.Printf("installDownloadedObjects for %s, Done %v\n", key, ret)
	return ret
}

// based on download/verification state, if
// the final installation directory is mentioned,
// move the object there
func installDownloadedObject(objType string, safename string,
	config types.StorageConfig, status *types.StorageStatus) error {

	var ret error
	var srcFilename string = objectDownloadDirname + "/" + objType

	key := formLookupKey(objType, safename)

	log.Printf("installDownloadedObject %s for %s, %v\n", objType, safename, status.State)

	// if the object is in downloaded state,
	// pick from pending directory
	// if ithe object is n delivered state,
	//  pick from verified directory
	switch status.State {

	case types.INSTALLED:
		log.Printf("%s, Already installed\n", key)
		return nil

	case types.DOWNLOADED:
		if config.ImageSha256 != "" {
			log.Printf("%s, Pending verification\n", key)
			return nil
		}
		srcFilename += "/pending/" + safename
		break

	case types.DELIVERED:
		srcFilename += "/verified/" + config.ImageSha256 + "/" +
			types.SafenameToFilename(safename)
		break

	default:
		log.Printf("%s, still not ready (%d)\n", key, status.State)
		return nil
	}

	// ensure the file is present
	if _, err := os.Stat(srcFilename); err != nil {
		log.Fatal(err)
	}

	// move to final installation point
	if config.FinalObjDir != "" {

		var dstFilename string = config.FinalObjDir

		switch objType {
		case certObj:
			ret = installCertObject(srcFilename, dstFilename, safename)

		case baseOsObj:
			ret = installBaseOsObject(srcFilename, dstFilename)

		default:
			log.Printf("%s, Unsupported Object Type %v\n", safename, objType)
		}
	} else {
		errStr := fmt.Sprintf("%s, final dir not set %v\n", safename, objType)
		log.Println(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		ret = errors.New(status.Error)
	}

	if ret == nil {
		status.State = types.INSTALLED
		log.Printf("installDownloadedObject for %s, installation done\n", key)
	}
	return ret
}

func writeDownloaderConfig(config types.DownloaderConfig, configFilename string) {

	bytes, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal DownloaderConfig")
	}

	err = ioutil.WriteFile(configFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
