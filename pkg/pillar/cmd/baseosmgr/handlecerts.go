// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// cert object event handlers
package baseosmgr

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func lookupCertObjSafename(ctx *baseOsMgrContext, safename string) *types.CertObjConfig {

	sub := ctx.subCertObjConfig
	items := sub.GetAll()
	for _, c := range items {
		config := c.(types.CertObjConfig)
		for _, sc := range config.StorageConfigList {
			safename1 := types.UrlToSafename(sc.Name,
				sc.ImageSha256)
			if safename == safename1 {
				return &config
			}
		}
	}
	return nil
}

// check if the storage object config have changed
func certObjCheckConfigModify(ctx *baseOsMgrContext, uuidStr string,
	config *types.CertObjConfig, status *types.CertObjStatus) bool {

	// check, whether number of cert objects have changed
	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		log.Infof("certObjCheckConfigModify(%s), Storage length mismatch: %d vs %d\n", uuidStr,
			len(config.StorageConfigList), len(status.StorageStatusList))
		return true
	}

	// check, whether any cert object have changed
	for idx, sc := range config.StorageConfigList {
		ss := status.StorageStatusList[idx]
		if sc.Name != ss.Name {
			log.Infof("certObjCheckConfigModify(%s) CertObj changed %s, %s\n",
				uuidStr, ss.Name, sc.Name)
			return true
		}
	}
	log.Infof("certObjCheckConfigModify(%s): no change\n", uuidStr)
	return false
}

// XXX but there can be multiple CertObjConfig/Status with the same safename!
// This only looks for one.
func certObjHandleStatusUpdateSafename(ctx *baseOsMgrContext, safename string) {

	log.Infof("certObjHandleStatusUpdateSafename(%s)\n", safename)
	config := lookupCertObjSafename(ctx, safename)
	if config == nil {
		log.Infof("certObjHandleStatusUpdateSafename(%s) not found\n",
			safename)
		return
	}
	uuidStr := config.Key()
	status := lookupCertObjStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("certObjHandleStatusUpdateSafename(%s) no status\n",
			safename)
		return
	}
	log.Infof("certObjHandleStatusUpdateSafename(%s) found %s\n",
		safename, uuidStr)
	certObjHandleStatusUpdate(ctx, config, status)
}

func certObjHandleStatusUpdate(ctx *baseOsMgrContext,
	config *types.CertObjConfig, status *types.CertObjStatus) {

	uuidStr := config.Key()
	log.Infof("certObjHandleStatusUpdate(%s)\n", uuidStr)

	changed := doCertObjStatusUpdate(ctx, uuidStr, *config, status)
	if changed {
		log.Infof("certObjHandleStatusUpdate(%s) changed\n",
			uuidStr)
		publishCertObjStatus(ctx, status)
	}
}

func doCertObjStatusUpdate(ctx *baseOsMgrContext, uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) bool {

	log.Infof("doCertObjStatusUpdate(%s)\n", uuidStr)

	changed, proceed := doCertObjInstall(ctx, uuidStr, config, status)
	if !proceed {
		return changed
	}

	// call baseOs to pick up the certs
	baseOsConfig := lookupBaseOsConfig(ctx, uuidStr)
	if baseOsConfig == nil {
		log.Infof("doCertObjStatusUdate(%s) no baseOsConfig\n",
			uuidStr)
		return changed
	}

	baseOsStatus := lookupBaseOsStatus(ctx, uuidStr)
	if baseOsStatus == nil {
		log.Infof("doCertObjStatusUdate(%s) no baseOsStatus\n",
			uuidStr)
		return changed
	}
	baseOsHandleStatusUpdate(ctx, baseOsConfig, baseOsStatus)
	log.Infof("doCertObjStatusUdate(%s) done %v\n", uuidStr, changed)
	return changed
}

func doCertObjInstall(ctx *baseOsMgrContext, uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) (bool, bool) {

	log.Infof("doCertObjInstall(%s)\n", uuidStr)
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

		if ss.Name != sc.Name ||
			ss.ImageSha256 != sc.ImageSha256 {
			// Report to zedcloud
			errString := fmt.Sprintf("%s, Storage config mismatch:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", uuidStr,
				sc.Name, ss.Name,
				sc.ImageSha256, ss.ImageSha256)
			log.Errorln(errString)
			status.Error = errString
			status.ErrorTime = time.Now()
			changed = true
			return changed, false
		}
	}

	downloadchange, downloaded :=
		checkCertObjStorageDownloadStatus(ctx, uuidStr, config, status)

	if !downloaded {
		return changed || downloadchange, false
	}

	// install the certs now
	if installDownloadedObjects(types.CertObj, uuidStr, &status.StorageStatusList) {
		// Automatically move from DOWNLOADED to INSTALLED
		status.State = types.INSTALLED
		changed = true
	}

	publishCertObjStatus(ctx, status)
	log.Infof("doCertObjInstall(%s) done %v\n", uuidStr, changed)
	return changed, true
}

func checkCertObjStorageDownloadStatus(ctx *baseOsMgrContext, uuidStr string,
	config types.CertObjConfig, status *types.CertObjStatus) (bool, bool) {

	ret := checkStorageDownloadStatus(ctx, types.CertObj, uuidStr,
		config.StorageConfigList, status.StorageStatusList)

	status.State = ret.MinState
	status.Error = ret.AllErrors
	status.ErrorTime = ret.ErrorTime

	log.Infof("checkCertObjDownloadStatus %s, %v\n", uuidStr, ret.MinState)

	if ret.AllErrors != "" {
		log.Errorf("checkCertObjDownloadStatus for %s, Download error %s\n",
			uuidStr, ret.AllErrors)
		return ret.Changed, false
	}

	if ret.MinState < types.DOWNLOADED {
		log.Infof("checkCertObjDownloaStatus %s, Waiting for downloads\n",
			uuidStr)
		return ret.Changed, false
	}

	// XXX can this ever happen?
	if ret.WaitingForCerts {
		log.Infof("checkCertObjDownloadStatus %s, Waiting for certs\n",
			uuidStr)
		return ret.Changed, false
	}

	log.Infof("checkCertObjDownloadStatus for %s, Downloads done\n", uuidStr)
	return ret.Changed, true
}

func removeCertObjConfig(ctx *baseOsMgrContext, uuidStr string) {

	log.Infof("removeCertObjConfig(%s)\n", uuidStr)
	status := lookupCertObjStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("removeCertObjConfig(%s), no status\n", uuidStr)
		return
	}

	changed, del := doCertObjUninstall(ctx, uuidStr, status)
	if changed {
		log.Infof("removeCertObjConfig(%s) status changed\n", uuidStr)
		publishCertObjStatus(ctx, status)
	}

	if del {
		// Write out what we modified to CertObj aka delete
		unpublishCertObjStatus(ctx, status.Key())
	}
	log.Infof("removeCertObjConfig(%s) done\n", uuidStr)
}

func doCertObjUninstall(ctx *baseOsMgrContext, uuidStr string,
	status *types.CertObjStatus) (bool, bool) {

	var del, changed, removedAll bool

	removedAll = true
	log.Infof("doCertObjUninstall(%s)\n", uuidStr)

	for i := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		safename := types.UrlToSafename(ss.Name, ss.ImageSha256)
		log.Infof("doCertObjUninstall(%s) safename %s\n",
			uuidStr, safename)
		// Decrease refcount if we had increased it
		if ss.HasDownloaderRef {
			removeDownloaderConfig(ctx, types.CertObj, safename)
			ss.HasDownloaderRef = false
			changed = true
		}

		ds := lookupDownloaderStatus(ctx, types.CertObj, safename)
		// XXX if additional refs it will not go away
		if false && ds != nil {
			log.Infof("doCertObjUninstall(%s) download %s not yet gone\n",
				uuidStr, safename)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Infof("doCertObjUninstall(%s) waiting for download purge\n",
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

func lookupCertObjConfig(ctx *baseOsMgrContext, key string) *types.CertObjConfig {

	sub := ctx.subCertObjConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupCertObjConfig(%s) not found\n", key)
		return nil
	}
	config := c.(types.CertObjConfig)
	return &config
}

func lookupCertObjStatus(ctx *baseOsMgrContext, key string) *types.CertObjStatus {
	pub := ctx.pubCertObjStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupCertObjStatus(%s) not found\n", key)
		return nil
	}
	status := st.(types.CertObjStatus)
	return &status
}

func publishCertObjStatus(ctx *baseOsMgrContext, status *types.CertObjStatus) {

	key := status.Key()
	log.Debugf("publishCertObjStatus(%s)\n", key)
	pub := ctx.pubCertObjStatus
	pub.Publish(key, *status)
}

func unpublishCertObjStatus(ctx *baseOsMgrContext, key string) {

	log.Debugf("unpublishCertObjStatus(%s)\n", key)
	pub := ctx.pubCertObjStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishCertObjStatus(%s) not found\n", key)
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
		log.Debugf("Create %s\n", dstDirname)
		if err := os.MkdirAll(dstDirname, 0700); err != nil {
			log.Fatal("installCertObject: ", err, dstDirname)
		}
	}

	dstFilename := dstDirname + "/" + types.SafenameToFilename(safename)

	// XXX needed? Check for truncated file and replace??
	if _, err := os.Stat(dstFilename); err == nil {
		// Remove and replace
		log.Infof("installCertObject: replacing %s\n",
			dstFilename)
		if err := os.Remove(dstFilename); err != nil {
			log.Fatalf("installCertObject failed %s\n", err)
		}
	}

	log.Infof("installCertObject: writing %s to %s\n",
		srcFilename, dstFilename)

	// XXX:FIXME its copy, not move
	// need to refactor the certs placement properly
	// this should be on safename or, holder object uuid context
	dstCnt, err := copyFile(srcFilename, dstFilename)
	if err != nil {
		log.Errorln("installCertObject: ", err, dstFilename)
	}
	if dstCnt != srcCnt {
		log.Errorf("installCertObject: mismatched copy len %d vs %d, %s\n",
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
