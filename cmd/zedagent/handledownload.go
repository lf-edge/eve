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

func downloaderConfigGet(key string) *types.DownloaderConfig {
	if config, ok := downloaderConfigMap[key]; ok {
		log.Printf("%s, downloader config exists, refcount %d\n",
			key, config.RefCount)
		return &config
	}
	log.Printf("%s, downloader config is absent\n", key)
	return nil
}

func downloaderConfigSet(key string, config *types.DownloaderConfig) {
	downloaderConfigMap[key] = *config
}

func downloaderConfigDelete(key string, objType string, safename string) bool {

	config := downloaderConfigGet(key)
	if config == nil {
		return false
	}

	if config.RefCount > 1 {
		log.Printf("%s, decrementing refCount(%d)\n", key, config.RefCount)
		config.RefCount -= 1
		downloaderConfigSet(key, config)
		writeDownloaderConfig(objType, safename,
			downloaderConfigGet(key))
		return false
	}

	delete(downloaderConfigMap, key)
	log.Printf("%s, downloader config delete done\n", key)
	return true
}

func downloaderStatusGet(key string) *types.DownloaderStatus {
	if status, ok := downloaderStatusMap[key]; ok {
		return &status
	}
	return nil
}

func downloaderStatusSet(key string, status *types.DownloaderStatus) {
	downloaderStatusMap[key] = *status
}

func downloaderStatusDelete(key string) {
	log.Printf("%s, downloader status entry delete\n", key)
	if status := downloaderStatusGet(key); status != nil {
		delete(downloaderStatusMap, key)
	}
}

func createDownloaderConfig(objType string, safename string,
	sc *types.StorageConfig) {

	initDownloaderMaps()

	key := formLookupKey(objType, safename)
	log.Printf("createDownloaderConfig for %s\n", key)

	if m := downloaderConfigGet(key); m != nil {
		m.RefCount += 1
		downloaderConfigSet(key, m)
	} else {
		log.Printf("%s, downloader config add\n", safename)
		n := types.DownloaderConfig{
			Safename:        safename,
			DownloadURL:     sc.DownloadURL,
			UseFreeUplinks:  false,
			Size:            sc.Size,
			TransportMethod: sc.TransportMethod,
			Dpath:           sc.Dpath,
			ApiKey:          sc.ApiKey,
			Password:        sc.Password,
			ImageSha256:     sc.ImageSha256,
			RefCount:        1,
		}
		downloaderConfigSet(key, &n)
	}

	writeDownloaderConfig(objType, safename, downloaderConfigGet(key))

	log.Printf("%s, createDownloaderConfig done\n", safename)
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
	if m := downloaderStatusGet(key); m != nil {
		if status.State != m.State {
			log.Printf("%s, download state, state changed from %v to %v\n",
				key, m.State, status.State)
			changed = true
		} else {
			log.Printf("%s, download state, no change\n", key)
		}
	} else {
		log.Printf("%s downloader status add, state %v\n",
			key, status.State)
		changed = true
	}

	if changed {

		downloaderStatusSet(key, status)

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

	log.Printf("%s, updateDownloaderStatus done\n", key)
}

func removeDownloaderConfig(objType string, safename string) {

	key := formLookupKey(objType, safename)

	log.Printf("%s, removeDownloaderConfig\n", key)

	if ok := downloaderConfigDelete(key, objType, safename); ok {

		configFilename := fmt.Sprintf("%s/%s/config/%s.json",
			downloaderBaseDirname, objType, safename)

		if err := os.Remove(configFilename); err != nil {
			log.Println(err)
		}
		log.Printf("%s, removeDownloaderConfig done\n", key)
	} else {
		log.Printf("%s, removeDownloaderConfig no Config\n", key)
	}
}

func removeDownloaderStatus(objType string, statusFilename string) {
	key := formLookupKey(objType, statusFilename)
	downloaderStatusDelete(key)
}

func lookupDownloaderStatus(objType string, safename string) (*types.DownloaderStatus, error) {

	key := formLookupKey(objType, safename)

	if m := downloaderStatusGet(key); m != nil {
		return m, nil
	}
	return nil, errors.New("No DownloaderStatus")
}

func checkStorageDownloadStatus(objType string, uuidStr string,
	config []types.StorageConfig, status []types.StorageStatus) *types.RetStatus {

	ret := &types.RetStatus{}
	key := formLookupKey(objType, uuidStr)
	log.Printf("checkStorageDownloadStatus for %s\n", uuidStr)

	ret.Changed = false
	ret.AllErrors = ""
	ret.MinState = types.MAXSTATE

	for i, sc := range config {

		ss := &status[i]

		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

		log.Printf("%s, image status %v\n", safename, ss.State)
		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			log.Printf("%s,is already installed\n", safename)
			continue
		}

		if sc.ImageSha256 != "" {
			// Shortcut if image is already verified
			vs, err := lookupVerificationStatusAny(objType,
				safename, sc.ImageSha256)

			if err == nil && vs.State == types.DELIVERED {
				log.Printf(" %s, exists verified with sha %s\n",
					safename, sc.ImageSha256)
				if vs.Safename != safename {
					// If found based on sha256
					log.Printf("found diff safename %s\n",
						vs.Safename)
				}
				// If we don't already have a RefCount add one
				if !ss.HasVerifierRef {
					log.Printf("%s, !HasVerifierRef\n", vs.Safename)
					createVerifierConfig(objType, vs.Safename,
						&sc, false)
					ss.HasVerifierRef = true
					ret.Changed = true
				}
				if ret.MinState > vs.State {
					ret.MinState = vs.State
				}
				if vs.State != ss.State {
					log.Printf("checkStorageDownloadStatus(%s) from vs set ss.State %d\n",
						safename, vs.State)
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
			log.Printf("checkStorageDownloadStatus(%s) from ds set ss.State %d\n",
				safename, ds.State)
			ss.State = ds.State
			ret.Changed = true
		}

		switch ss.State {
		case types.INITIAL:
			log.Printf("%s, downloader error, %s\n",
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

			log.Printf("%s, is downloaded\n", safename)
			// if verification is needed
			if sc.ImageSha256 != "" {
				// start verifier for this object
				if !ss.HasVerifierRef {
					err := createVerifierConfig(objType, safename, &sc, true)
					if err == nil {
						ss.HasVerifierRef = true
						ret.Changed = true
					} else {
						// XXX or should we wait for
						// certs just like zedmanager?
						ret.AllErrors = appendError(ret.AllErrors, "downloader", err.Error())
						ret.ErrorTime = time.Now()
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
	log.Printf("%s, installDownloadedObjects\n", key)

	for i, sc := range config {

		ss := &status[i]

		safename := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

		installDownloadedObject(objType, safename, sc, ss)

		// if something is still not installed, mark accordingly
		if ss.State != types.INSTALLED {
			ret = false
		}
	}

	log.Printf("%s, installDownloadedObjects done %v\n", key, ret)
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

	log.Printf("%s, installDownloadedObject(%s, %v)\n", safename, objType, status.State)

	// if the object is in downloaded state,
	// pick from pending directory
	// if ithe object is n delivered state,
	//  pick from verified directory
	switch status.State {

	case types.INSTALLED:
		log.Printf("%s, already installed\n", key)
		return nil

	case types.DOWNLOADED:
		if config.ImageSha256 != "" {
			log.Printf("%s, verification pending\n", key)
			return nil
		}
		srcFilename += "/pending/" + safename
		break

	case types.DELIVERED:
		srcFilename += "/verified/" + config.ImageSha256 + "/" +
			types.SafenameToFilename(safename)
		break

		// XXX types.INITIAL for failures?
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
			// XXX if ok then decrease refcount?? Or done at uninstall time?
			// Done in Uninstall; just log here to make sure
			if ret == nil && status.HasDownloaderRef {
				log.Printf("installDownloadedObject: HasDownloaderRef for %s\n", safename)
				// XXX try decrementing
				removeBaseOsDownloaderConfig(safename)
				status.HasDownloaderRef = false
				// XXX write?
			}
		default:
			errStr := fmt.Sprintf("%s, Unsupported Object Type %v",
				safename, objType)
			log.Println(errStr)
			ret = errors.New(status.Error)
		}
	} else {
		errStr := fmt.Sprintf("%s, final dir not set %v\n", safename, objType)
		log.Println(errStr)
		ret = errors.New(errStr)
	}

	if ret == nil {
		status.State = types.INSTALLED
		log.Printf("%s, installation done\n", key)
	} else {
		status.State = types.INITIAL
		status.Error = fmt.Sprintf("%s", ret)
		status.ErrorTime = time.Now()
	}
	return ret
}

func writeDownloaderConfig(objType string, safename string,
	config *types.DownloaderConfig) {
	if config == nil {
		return
	}

	log.Printf("%s, writeDownloaderConfig: RefCount %d\n",
		safename, config.RefCount)
	configFilename := fmt.Sprintf("%s/%s/config/%s.json",
		downloaderBaseDirname, objType, safename)

	bytes, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal DownloaderConfig")
	}

	err = ioutil.WriteFile(configFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}
