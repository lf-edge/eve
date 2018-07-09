// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// cert object event handlers
package zedagent

import (
	"encoding/json"
	"fmt"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"io"
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

func certObjConfigGet(uuidStr string) *types.CertObjConfig {
	if config, ok := certObjConfigMap[uuidStr]; ok {
		return &config
	}
	log.Printf("%s, certObj config is absent\n", uuidStr)
	return nil
}

func certObjConfigSet(uuidStr string, config *types.CertObjConfig) {
	certObjConfigMap[uuidStr] = *config
}

func certObjConfigDelete(uuidStr string) bool {
	log.Printf("%s, certObj config delete\n", uuidStr)
	if config := certObjConfigGet(uuidStr); config != nil {
		delete(certObjConfigMap, uuidStr)
		return true
	}
	return false
}

func certObjStatusGet(uuidStr string) *types.CertObjStatus {
	if status, ok := certObjStatusMap[uuidStr]; ok {
		return &status
	}
	log.Printf("%s, certObj status is absent\n", uuidStr)
	return nil
}

func certObjStatusSet(uuidStr string, status *types.CertObjStatus) {
	certObjStatusMap[uuidStr] = *status
}

func certObjStatusDelete(uuidStr string) bool {
	log.Printf("%s, certObj status delete\n", uuidStr)
	if status := certObjStatusGet(uuidStr); status != nil {
		delete(certObjStatusMap, uuidStr)
		return true
	}
	return false
}

// handle Storage(download/verification) (Config/Status) events
func certObjHandleStatusUpdateSafename(safename string) {

	log.Printf("certObjHandleStatusUpdateSafename for %s\n", safename)

	for _, certObjConfig := range certObjConfigMap {
		for _, sc := range certObjConfig.StorageConfigList {

			safename1 := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)
			if safename == safename1 {
				uuidStr := certObjConfig.Key()
				log.Printf("%s, found certObj %s\n", safename, uuidStr)
				certObjHandleStatusUpdate(uuidStr)
			}
		}
	}
}

func addOrUpdateCertObjConfig(uuidStr string, config types.CertObjConfig) {

	added := false
	changed := false

	if m := certObjConfigGet(uuidStr); m != nil {
		// XXX or just compare version like elsewhere?
		// XXX switch to Equal?
		if !reflect.DeepEqual(*m, config) {
			log.Printf("%s, certObj config change\n", uuidStr)
			changed = true
		} else {
			log.Printf("%s, certObj config no change\n", uuidStr)
		}
	} else {
		log.Printf("%s, certObj config add\n", uuidStr)
		added = true
		changed = true
	}

	if changed {
		certObjConfigSet(uuidStr, &config)
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

		certObjStatusSet(uuidStr, &status)
		writeCertObjStatus(&status, uuidStr)
	}

	if changed {
		certObjHandleStatusUpdate(uuidStr)
	}
}

func certObjHandleStatusUpdate(uuidStr string) {

	log.Printf("%s, certObjHandleStatusUpdate\n", uuidStr)

	config := certObjConfigGet(uuidStr)
	if config == nil {
		return
	}

	status := certObjStatusGet(uuidStr)
	if status == nil {
		return
	}

	changed := doCertObjStatusUpdate(uuidStr, *config, status)

	if changed {
		log.Printf("%s, certObj status changed\n",
			uuidStr)
		certObjStatusSet(uuidStr, status)
		writeCertObjStatus(status, uuidStr)
	}
}

func doCertObjStatusUpdate(uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) bool {

	log.Printf("%s, doCertObjStatusUpdate\n", uuidStr)

	changed, proceed := doCertObjInstall(uuidStr, config, status)
	if !proceed {
		return changed
	}

	// call baseOs to pick up the certs
	baseOsHandleStatusUpdate(uuidStr)
	log.Printf("%s, doCertObjStatusUdate done %v\n", uuidStr, changed)
	return changed
}

func doCertObjInstall(uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) (bool, bool) {

	log.Printf("%s, doCertObjInstall\n", uuidStr)
	changed := false

	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		errString := fmt.Sprintf("%s, Storage length mismatch: %d vs %d\n", uuidStr,
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
			errString := fmt.Sprintf("%s, Storage config mismatch:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", uuidStr,
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
	log.Printf("%s, doCertObjInstall done %v\n", uuidStr, changed)
	return changed, true
}

func checkCertObjStorageDownloadStatus(uuidStr string,
	config types.CertObjConfig, status *types.CertObjStatus) (bool, bool) {

	ret := checkStorageDownloadStatus(certObj, uuidStr,
		config.StorageConfigList, status.StorageStatusList)

	status.State = ret.MinState
	status.Error = ret.AllErrors
	status.ErrorTime = ret.ErrorTime

	log.Printf("checkCertObjDownloadStatus %s, %v\n", uuidStr, ret.MinState)

	if ret.MinState == types.INITIAL {
		log.Printf("checkCertObjDownloadStatus for %s, Download error\n", uuidStr)
		return ret.Changed, false
	}

	if ret.MinState < types.DOWNLOADED {
		log.Printf("checkCertObjDownloaStatus %s, Waiting for downloads\n", uuidStr)
		return ret.Changed, false
	}

	// XXX can this ever happen?
	if ret.WaitingForCerts {
		log.Printf("checkCertObjDownloadStatus %s, Waiting for certs\n",
			uuidStr)
		return ret.Changed, false
	}

	log.Printf("checkCertObjDownloadStatus for %s, Downloads done\n", uuidStr)
	return ret.Changed, true
}

func removeCertObjConfig(uuidStr string) {

	log.Printf("%s, removeCertObjConfig\n", uuidStr)
	certObjConfigDelete(uuidStr)
	removeCertObjStatus(uuidStr)
	log.Printf("%s, removeCertObjConfig done\n", uuidStr)
}

func removeCertObjStatus(uuidStr string) {

	status := certObjStatusGet(uuidStr)
	if status == nil {
		return
	}

	changed, del := doCertObjRemove(uuidStr, status)
	if changed {
		log.Printf("%s, removeCertObjStatus, status changed\n", uuidStr)
		certObjStatusSet(uuidStr, status)
		writeCertObjStatus(status, uuidStr)
	}

	if del {
		// Write out what we modified to CertObj aka delete
		// Delete the status file also
		if ok := certObjStatusDelete(uuidStr); ok {
			statusFilename := fmt.Sprintf("%s/%s.json",
				zedagentCertObjStatusDirname, uuidStr)
			if err := os.Remove(statusFilename); err != nil {
				log.Println(err)
			}
			log.Printf("%d, removeCertObjStatus done\n", uuidStr)
		}
	}
}

func doCertObjRemove(uuidStr string, status *types.CertObjStatus) (bool, bool) {

	log.Printf("%s, doCertObjRemove\n", uuidStr)
	changed, del := doCertObjUninstall(uuidStr, status)
	log.Printf("%s, doCertObjRemove done %v\n", uuidStr, del)
	return changed, del
}

func doCertObjUninstall(uuidStr string, status *types.CertObjStatus) (bool, bool) {

	var del, changed, removedAll bool

	removedAll = true
	log.Printf("%s, doCertObjUninstall\n", uuidStr)

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.DownloadURL, ss.ImageSha256)
		log.Printf("%s, certEntry safename %s\n", uuidStr, safename)
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			removeDownloaderConfig(certObj, safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		_, err := lookupDownloaderStatus(certObj, safename)
		// XXX if additional refs it will not go away
		if false && err == nil {
			log.Printf("%s, download %s not yet gone\n", uuidStr, safename)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Printf("%s, waiting for download purge\n", uuidStr)
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
	statusFilename := zedagentCertObjStatusDirname + "/" + uuidStr + ".json"
	bytes, err := json.Marshal(status)
	if err != nil {
		log.Fatal(err, "json Marshal certObjStatus")
	}

	err = pubsub.WriteRename(statusFilename, bytes)
	if err != nil {
		log.Fatal(err)
	}
}

func installCertObject(srcFilename string, dstDirname string, safename string) error {

	// create the destination directory
	if _, err := os.Stat(dstDirname); err != nil {
		log.Printf("Create %s\n", dstDirname)
		if err := os.MkdirAll(dstDirname, 0700); err != nil {
			log.Fatal("installCertObject: ", err, dstDirname)
		}
	}

	dstFilename := dstDirname + "/" + types.SafenameToFilename(safename)

	if _, err := os.Stat(dstFilename); err == nil {
		// Remove amd replace
		log.Printf("installCertObject: replacing %s\n",
			dstFilename)
		if err := os.Remove(dstFilename); err != nil {
			log.Fatalf("installCertObject failed %s\n", err)
		}
	}

	log.Printf("installCertObject: writing %s to %s\n",
		srcFilename, dstFilename)

	// XXX:FIXME its copy, not move
	// need to refactor the certs placement properly
	// this should be on safename or, holder object uuid context
	_, err := copyFile(srcFilename, dstFilename)
	return err
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
