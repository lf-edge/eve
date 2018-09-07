// Copyright (c) 2017-2018 Zededa, Inc.
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
	"time"
)

func lookupCertObjSafename(ctx *zedagentContext, safename string) *types.CertObjConfig {

	sub := ctx.subCertObjConfig
	items := sub.GetAll()
	for key, c := range items {
		config := cast.CastCertObjConfig(c)
		if config.Key() != key {
			log.Printf("certObjHandleStatusUpdateSafename key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		for _, sc := range config.StorageConfigList {
			safename1 := types.UrlToSafename(sc.DownloadURL,
				sc.ImageSha256)
			if safename == safename1 {
				return &config
			}
		}
	}
	return nil
}

// XXX but there can be multiple CertObjConfig/Status with the same safename!
// This only looks for one.
func certObjHandleStatusUpdateSafename(ctx *zedagentContext, safename string) {

	log.Printf("certObjHandleStatusUpdateSafename(%s)\n", safename)
	config := lookupCertObjSafename(ctx, safename)
	if config == nil {
		log.Printf("certObjHandleStatusUpdateSafename(%s) not found\n",
			safename)
		return
	}
	uuidStr := config.Key()
	status := lookupCertObjStatus(ctx, uuidStr)
	if status == nil {
		log.Printf("certObjHandleStatusUpdateSafename(%s) no status\n",
			safename)
		return
	}
	log.Printf("certObjHandleStatusUpdateSafename(%s) found %s\n",
		safename, uuidStr)
	certObjHandleStatusUpdate(ctx, config, status)
}

func certObjHandleStatusUpdate(ctx *zedagentContext,
	config *types.CertObjConfig, status *types.CertObjStatus) {

	uuidStr := config.Key()
	log.Printf("certObjHandleStatusUpdate(%s)\n", uuidStr)

	changed := doCertObjStatusUpdate(ctx, uuidStr, *config, status)
	if changed {
		log.Printf("certObjHandleStatusUpdate(%s) changed\n",
			uuidStr)
		publishCertObjStatus(ctx, status)
	}
}

func doCertObjStatusUpdate(ctx *zedagentContext, uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) bool {

	log.Printf("doCertObjStatusUpdate(%s)\n", uuidStr)

	changed, proceed := doCertObjInstall(ctx, uuidStr, config, status)
	if !proceed {
		return changed
	}

	// call baseOs to pick up the certs
	baseOsConfig := lookupBaseOsConfig(ctx, uuidStr)
	if baseOsConfig == nil {
		log.Printf("doCertObjStatusUdate(%s) no baseOsConfig\n",
			uuidStr)
		return changed
	}

	baseOsStatus := lookupBaseOsStatus(ctx, uuidStr)
	if baseOsStatus == nil {
		log.Printf("doCertObjStatusUdate(%s) no baseOsStatus\n",
			uuidStr)
		return changed
	}
	baseOsHandleStatusUpdate(ctx, baseOsConfig, baseOsStatus)
	log.Printf("doCertObjStatusUdate(%s) done %v\n", uuidStr, changed)
	return changed
}

func doCertObjInstall(ctx *zedagentContext, uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) (bool, bool) {

	log.Printf("doCertObjInstall(%s)\n", uuidStr)
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
		checkCertObjStorageDownloadStatus(ctx, uuidStr, config, status)

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

	publishCertObjStatus(ctx, status)
	log.Printf("doCertObjInstall(%s) done %v\n", uuidStr, changed)
	return changed, true
}

func checkCertObjStorageDownloadStatus(ctx *zedagentContext, uuidStr string,
	config types.CertObjConfig, status *types.CertObjStatus) (bool, bool) {

	ret := checkStorageDownloadStatus(ctx, certObj, uuidStr,
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

	log.Printf("removeCertObjConfig(%s)\n", uuidStr)
	status := lookupCertObjStatus(ctx, uuidStr)
	if status == nil {
		log.Printf("removeCertObjConfig(%s), no status\n", uuidStr)
		return
	}

	changed, del := doCertObjUninstall(ctx, uuidStr, status)
	if changed {
		log.Printf("removeCertObjConfig(%s) status changed\n", uuidStr)
		publishCertObjStatus(ctx, status)
	}

	if del {
		// Write out what we modified to CertObj aka delete
		unpublishCertObjStatus(ctx, status.Key())
	}
	log.Printf("removeCertObjConfig(%s) done\n", uuidStr)
}

func doCertObjUninstall(ctx *zedagentContext, uuidStr string,
	status *types.CertObjStatus) (bool, bool) {

	var del, changed, removedAll bool

	removedAll = true
	log.Printf("doCertObjUninstall(%s)\n", uuidStr)

	for i, _ := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.DownloadURL, ss.ImageSha256)
		log.Printf("doCertObjUninstall(%s) safename %s\n",
			uuidStr, safename)
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			removeDownloaderConfig(ctx, certObj, safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		ds := lookupDownloaderStatus(ctx, certObj, safename)
		// XXX if additional refs it will not go away
		if false && ds != nil {
			log.Printf("doCertObjUninstall(%s) download %s not yet gone\n",
				uuidStr, safename)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Printf("doCertObjUninstall(%s) waiting for download purge\n",
			uuidStr)
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
		log.Printf("lookupCertObjConfig key/UUID mismatch %s vs %s; ignored %+v\n",
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
		log.Printf("lookupCertObjStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func publishCertObjStatus(ctx *zedagentContext, status *types.CertObjStatus) {

	key := status.Key()
	log.Printf("publishCertObjStatus(%s)\n", key)
	pub := ctx.pubCertObjStatus
	pub.Publish(key, status)
}

func unpublishCertObjStatus(ctx *zedagentContext, key string) {

	log.Printf("unpublishCertObjStatus(%s)\n", key)
	pub := ctx.pubCertObjStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Printf("unpublishCertObjStatus(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func installCertObject(srcFilename string, dstDirname string, safename string) error {

	st, err := os.Stat(srcFilename)
	if err != nil {
		log.Fatal("installCertObject: ", err, srcFilename)
	}
	srcCnt := st.Size()
	// create the destination directory
	if _, err := os.Stat(dstDirname); err != nil {
		log.Printf("Create %s\n", dstDirname)
		if err := os.MkdirAll(dstDirname, 0700); err != nil {
			log.Fatal("installCertObject: ", err, dstDirname)
		}
	}

	dstFilename := dstDirname + "/" + types.SafenameToFilename(safename)

	// XXX needed? Check for truncated file and replace??
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
	dstCnt, err := copyFile(srcFilename, dstFilename)
	if err != nil {
		log.Println("installCertObject: ", err, dstFilename)
	}
	if dstCnt != srcCnt {
		log.Printf("installCertObject: mismatched copy len %d vs %d, %s\n",
			dstCnt, srcCnt, dstFilename)
	}
	return err
}

// Returns the number of bytes copied
func copyFile(srcFilename string, dstFilename string) (int64, error) {

	in, err := os.Open(srcFilename)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.Create(dstFilename)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	cnt, err := io.Copy(out, in)
	if err != nil {
		return cnt, err
	}

	err = out.Sync()
	return cnt, err
}
