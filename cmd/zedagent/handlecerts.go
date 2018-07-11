// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// cert object event handlers
package zedagent

import (
	"fmt"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"io"
	"log"
	"os"
	"reflect"
	"time"
)

// handle Storage(download/verification) (Config/Status) events
func certObjHandleStatusUpdateSafename(ctx *zedagentContext, safename string) {

	log.Printf("certObjHandleStatusUpdateSafename for %s\n", safename)

	sub := ctx.subCertObjConfig
	items := sub.GetAll()
	for _, c := range items {
		config := cast.CastCertObjConfig(c)
		for _, sc := range config.StorageConfigList {

			safename1 := types.UrlToSafename(sc.DownloadURL, sc.ImageSha256)
			if safename == safename1 {
				uuidStr := config.Key()
				log.Printf("%s, found certObj %s\n", safename, uuidStr)
				certObjHandleStatusUpdate(ctx, uuidStr)
			}
		}
	}
}

func addOrUpdateCertObjConfig(ctx *zedagentContext, uuidStr string, config types.CertObjConfig) {

	added := false
	changed := false

	// XXX change caller?
	uuidStr = config.Key()
	if m := lookupCertObjConfig(ctx, uuidStr); m != nil {
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

		updateCertObjStatus(ctx, &status)
	}

	if changed {
		certObjHandleStatusUpdate(ctx, uuidStr)
	}
}

// XXX do callers have config? Yes
func certObjHandleStatusUpdate(ctx *zedagentContext, uuidStr string) {

	log.Printf("%s, certObjHandleStatusUpdate\n", uuidStr)

	config := lookupCertObjConfig(ctx, uuidStr)
	if config == nil {
		return
	}

	status := lookupCertObjStatus(ctx, uuidStr)
	if status == nil {
		return
	}

	changed := doCertObjStatusUpdate(ctx, uuidStr, *config, status)

	if changed {
		log.Printf("%s, certObj status changed\n",
			uuidStr)
		updateCertObjStatus(ctx, status)
	}
}

func doCertObjStatusUpdate(ctx *zedagentContext, uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) bool {

	log.Printf("%s, doCertObjStatusUpdate\n", uuidStr)

	changed, proceed := doCertObjInstall(ctx, uuidStr, config, status)
	if !proceed {
		return changed
	}

	// call baseOs to pick up the certs
	baseOsHandleStatusUpdate(ctx, uuidStr)
	log.Printf("%s, doCertObjStatusUdate done %v\n", uuidStr, changed)
	return changed
}

func doCertObjInstall(ctx *zedagentContext, uuidStr string, config types.CertObjConfig,
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

	updateCertObjStatus(ctx, status)
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

func removeCertObjConfig(ctx *zedagentContext, uuidStr string) {

	log.Printf("%s, removeCertObjConfig\n", uuidStr)
	status := lookupCertObjStatus(ctx, uuidStr)
	if status == nil {
		log.Printf("%s, removeCertObjConfig, no status\n", uuidStr)
		return
	}

	changed, del := doCertObjUninstall(uuidStr, status)
	if changed {
		log.Printf("%s, removeCertObjConfig, status changed\n", uuidStr)
		updateCertObjStatus(ctx, status)
	}

	if del {
		// Write out what we modified to CertObj aka delete
		removeCertObjStatus(ctx, status.Key())
	}
	log.Printf("%s, removeCertObjConfig done\n", uuidStr)
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

func lookupCertObjConfig(ctx *zedagentContext, key string) *types.CertObjConfig {

	sub := ctx.subCertObjConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Printf("lookupCertObjConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastCertObjConfig(c)
	if config.Key() != key {
		log.Printf("lookupCertObjConfig(%s) got %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

func lookupCertObjStatus(ctx *zedagentContext, key string) *types.CertObjStatus {
	pub := ctx.pubCertObjStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("lookupCertObjStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastCertObjStatus(st)
	if status.Key() != key {
		log.Printf("lookupCertObjStatus(%s) got %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func updateCertObjStatus(ctx *zedagentContext, status *types.CertObjStatus) {

	key := status.Key()
	log.Printf("Updating CertObjStatus %s\n", key)
	pub := ctx.pubCertObjStatus
	pub.Publish(key, status)
}

func removeCertObjStatus(ctx *zedagentContext, key string) {

	log.Printf("Removing CertObjStatus %s\n", key)
	pub := ctx.pubCertObjStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("removeCertObjStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
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
