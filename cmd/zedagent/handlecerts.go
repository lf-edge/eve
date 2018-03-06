// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// cert object event handlers
package main

import (
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/types"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"time"
)

// zedagent punlishes these config/status files
var certObjConfigMap map[string]types.CertObjConfig
var certObjStatusMap map[string]types.CertObjStatus

func initCertObjMaps() {

	if certObjConfigMap == nil {
		log.Printf("create certObjConfig map\n")
		certObjConfigMap = make(map[string]types.CertObjConfig)
	}

	if certObjStatusMap == nil {
		log.Printf("create certObjStatus map\n")
		certObjStatusMap = make(map[string]types.CertObjStatus)
	}
}

// handle Storage(download/verification) (Config/Status) events
func certObjHandleStatusUpdateSafename(safename string) {

	log.Printf("certObjHandleStatusUpdateSafename for %s\n", safename)

	for _, certObjConfig := range certObjConfigMap {

		for _, sc := range certObjConfig.StorageConfigList {

			safename1 := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)

			if safename == safename1 {

				uuidStr := certObjConfig.UUIDandVersion.UUID.String()
				log.Printf("certObjHandleStatusUpdateSafename for %s, Found certObj %s\n", safename, uuidStr)

				certObjHandleStatusUpdate(uuidStr)
			}
		}
	}
}

func addOrUpdateCertObjConfig(uuidStr string, config types.CertObjConfig) {

	added := false
	changed := false

	if m, ok := certObjConfigMap[uuidStr]; ok {
		// XXX or just compare version like elsewhere?
		if !reflect.DeepEqual(m, config) {
			log.Printf("addOrUpdateCertObjConfig for %s, Config change\n", uuidStr)
			changed = true
		}
	} else {
		log.Printf("addOrUpdateCertObjConfig for %s, Config add\n", uuidStr)
		added = true
		changed = true
	}
	if changed {
		certObjConfigMap[uuidStr] = config
	}

	if added {

		status := types.CertObjStatus{
			UUIDandVersion: config.UUIDandVersion,
			ConfigSha256:   config.ConfigSha256,
		}

		status.StorageStatusList = make([]types.StorageStatus,
			len(config.StorageConfigList))

		for i, sc := range config.StorageConfigList {
			ss := &status.StorageStatusList[i]
			ss.DownloadURL = sc.DownloadURL
			ss.ImageSha256 = sc.ImageSha256
		}

		certObjStatusMap[uuidStr] = status
		writeCertObjStatus(&status, uuidStr)
	}

	if changed {
		certObjHandleStatusUpdate(uuidStr)
	}
}

func certObjHandleStatusUpdate(uuidStr string) {

	log.Printf("certObjHandleStatusUpdate for %s\n", uuidStr)

	config, ok := certObjConfigMap[uuidStr]
	if !ok {
		log.Printf("certObjHandleStatusUpdate for %s, Config absent\n", uuidStr)
		return
	}

	status, ok := certObjStatusMap[uuidStr]
	if !ok {
		log.Printf("certObjHandleStatusUpdate for %s, Status absent\n",
			uuidStr)
		return
	}

	changed := doCertObjStatusUpdate(uuidStr, config, &status)

	if changed {
		log.Printf("certObjHandleStatusUpdate for %s, Status changed\n",
			uuidStr)
		certObjStatusMap[uuidStr] = status
		writeCertObjStatus(&status, uuidStr)
	}
}

func doCertObjStatusUpdate(uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) bool {

	log.Printf("doCertObjStatusUpdate for %s\n", uuidStr)

	changed, proceed := doCertObjInstall(uuidStr, config, status)
	if !proceed {
		return changed
	}

	log.Printf("doCertObjStatusUpdate for %s, Done\n", uuidStr)
	// call baseOs to pick up the certs
	baseOsHandleStatusUpdate(uuidStr)
	return changed
}

func doCertObjInstall(uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) (bool, bool) {

	log.Printf("doCertObjInstall for %s\n", uuidStr)
	changed := false

	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		errString := fmt.Sprintf("doCertObjInstall for %s, Storage length mismatch: %d vs %d\n", uuidStr,
			len(config.StorageConfigList),
			len(status.StorageStatusList))
		status.Error = errString
		status.ErrorTime = time.Now()
		return changed, false
	}

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]

		if ss.DownloadURL != sc.DownloadURL ||
			ss.ImageSha256 != sc.ImageSha256 {
			// Report to zedcloud
			errString := fmt.Sprintf("doCertObjInstall for %s, Storage config mismatch:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", uuidStr,
				sc.DownloadURL, ss.DownloadURL,
				sc.ImageSha256, ss.ImageSha256)
			log.Println(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, false
		}
	}

	downloadchange, downloaded :=
		checkCertObjStorageDownloadStatus(uuidStr, config, status)

	if downloaded == false {
		return changed || downloadchange, false
	}

	// install the certs now
	if ret := installDownloadedObjects(certObj, uuidStr, config.StorageConfigList,
		status.StorageStatusList); ret == true {
		// Automatically move from DOWNLOADED to INSTALLED
		status.State = types.INSTALLED
		changed = true
	}

	writeCertObjStatus(status, uuidStr)
	log.Printf("doCertObjInstall for %s, Done %v\n", uuidStr, changed)
	return changed, true
}

func checkCertObjStorageDownloadStatus(uuidStr string,
	config types.CertObjConfig,
	status *types.CertObjStatus) (bool, bool) {

	changed, minState, allErrors, errorTime := checkStorageDownloadStatus(certObj, uuidStr, config.StorageConfigList, status.StorageStatusList)

	status.State = minState
	status.Error = allErrors
	status.ErrorTime = errorTime

	log.Printf("checkCertObjDownloaStatus %s, %v\n", uuidStr, minState)

	if minState == types.INITIAL {
		log.Printf("checkCertObjDownloadStatus for %s, Download error\n", uuidStr)
		return changed, false
	}

	if minState < types.DOWNLOADED {
		log.Printf("checkCertObjDownloaStatus %s, Waiting for downloads\n", uuidStr)
		return changed, false
	}

	log.Printf("checkCertObjDownloadStatus for %s, Downloads done\n", uuidStr)
	return changed, true
}

func removeCertObjConfig(uuidStr string) {

	log.Printf("removeCertObjConfig for %s\n", uuidStr)

	if _, ok := certObjConfigMap[uuidStr]; !ok {
		log.Printf("removeCertObjConfig for %s, Config absent\n", uuidStr)
		return
	}

	delete(certObjConfigMap, uuidStr)

	removeCertObjStatus(uuidStr)

	log.Printf("removeCertObjConfig for %s, Done\n", uuidStr)
}

func removeCertObjStatus(uuidStr string) {

	status, ok := certObjStatusMap[uuidStr]
	if !ok {
		log.Printf("removeCertObjStatus for %s, Status absent\n", uuidStr)
		return
	}

	changed, del := doCertObjRemove(uuidStr, &status)
	if changed {
		log.Printf("removeCertObjStatus for %s, Status changed\n", uuidStr)
		certObjStatusMap[uuidStr] = status
		writeCertObjStatus(&status, uuidStr)
	}

	if del {

		// Write out what we modified to CertObj aka delete
		statusFilename := fmt.Sprintf("%s/%s.json",
			zedagentCertObjStatusDirname, uuidStr)
		if err := os.Remove(statusFilename); err != nil {
			log.Println(err)
		}

		delete(certObjStatusMap, uuidStr)
		log.Printf("removeCertObjStatus for %s: Done\n", uuidStr)
	}
}

func doCertObjRemove(uuidStr string, status *types.CertObjStatus) (bool, bool) {

	log.Printf("doCertObjRemove for %s\n", uuidStr)

	changed := false
	del := false

	changed, del = doCertObjUninstall(uuidStr, status)

	log.Printf("doCertObjRemove for %s, Done\n", uuidStr)
	return changed, del
}

func doCertObjUninstall(uuidStr string, status *types.CertObjStatus) (bool, bool) {

	del := false
	changed := false
	removedAll := true

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.DownloadURL, ss.ImageSha256)
		log.Printf("doCertObjUninstall for %s, Found StorageStatus safename %s\n", uuidStr, safename)
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			removeCertObjDownloaderConfig(safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		_, err := lookupCertObjDownloaderStatus(safename)
		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("doCertObjIninstall for %s, Download %s not yet gone\n",
				uuidStr, safename)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Printf("doCertObjUninstall for %s, Waiting for download purge\n", uuidStr)
		return changed, del
	}

	// XXX:FIXME, fill up the details
	if status.State == types.INITIAL {
		del = false
	}
	status.State = types.INITIAL

	return changed, del
}

func writeCertObjStatus(status *types.CertObjStatus, uuidStr string) {
	statusFilename := zedagentCertObjStatusDirname + "/" +  uuidStr + ".json"
	log.Printf("Writing CertObj Status %s\n", statusFilename)
	bytes, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal certObjStatus")
	}

	err = ioutil.WriteFile(statusFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func installCertObject(srcFilename string, dstDirname string, safename string) error {

	// create the destination directory
	if _, err := os.Stat(dstDirname); err != nil {
		if err := os.MkdirAll(dstDirname, 0700); err != nil {
			log.Fatal("installCertObject: ", err, dstDirname)
		}
	}

	dstFilename := dstDirname + "/" + types.SafenameToFilename(safename)

	if _, err := os.Stat(dstFilename); err != nil {

		log.Printf("installCertObject: writing %s to %s\n",
			srcFilename, dstFilename)

		// XXX:FIXME its copy, not move
		// need to refactor the certs placement properly
		// this should be on safename or, holder object uuid context
		_, err := copyFile(srcFilename, dstFilename)
		return err
	}
	return nil
}

func copyFile(srcFilename string, dstFilename string) (bool, error) {

	in, err := os.Open(srcFilename)
	if err != nil {
		return false, err
	}
	defer in.Close()

	out, err := os.Create(dstFilename)
	if err != nil {
		return false, err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return false, err
	}

	err = out.Sync()
	return true, err
}
