// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"io"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Returns a list of all matching cert objects
func lookupCertObjImageID(ctx *volumemgrContext, imageID uuid.UUID) []*types.CertObjConfig {

	var result []*types.CertObjConfig
	sub := ctx.subCertObjConfig
	items := sub.GetAll()
	for _, c := range items {
		config := c.(types.CertObjConfig)
		for _, sc := range config.StorageConfigList {
			if uuid.Equal(imageID, sc.ImageID) {
				result = append(result, &config)
			}
		}
	}
	return result
}

// check if the storage object config have changed
func certObjCheckConfigModify(ctx *volumemgrContext, uuidStr string,
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
			log.Infof("certObjCheckConfigModify(%s) CertObj changed %s, %s",
				uuidStr, ss.Name, sc.Name)
			return true
		}
	}
	log.Infof("certObjCheckConfigModify(%s): no change", uuidStr)
	return false
}

func certObjHandleStatusUpdateImageID(ctx *volumemgrContext, imageID uuid.UUID) {

	log.Infof("certObjHandleStatusUpdateImageId(%s)", imageID)
	configPtrList := lookupCertObjImageID(ctx, imageID)
	if len(configPtrList) == 0 {
		log.Infof("certObjHandleStatusUpdateImageID(%s) not found",
			imageID)
		return
	}
	for _, configPtr := range configPtrList {
		uuidStr := configPtr.Key()
		statusPtr := lookupCertObjStatus(ctx, uuidStr)
		if statusPtr == nil {
			log.Infof("certObjHandleStatusUpdateImageID(%s) no status",
				imageID)
			continue
		}
		log.Infof("certObjHandleStatusUpdateImageID(%s) found %s",
			imageID, uuidStr)
		certObjHandleStatusUpdate(ctx, configPtr, statusPtr)
	}
}

// XXX who calls this?
func certObjHandleStatusUpdate(ctx *volumemgrContext,
	config *types.CertObjConfig, status *types.CertObjStatus) {

	uuidStr := config.Key()
	log.Infof("certObjHandleStatusUpdate(%s)", uuidStr)

	changed := doCertObjStatusUpdate(ctx, uuidStr, *config, status)
	if changed {
		log.Infof("certObjHandleStatusUpdate(%s) changed",
			uuidStr)
		publishCertObjStatus(ctx, status)
	}
}

func doCertObjStatusUpdate(ctx *volumemgrContext, uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) bool {

	log.Infof("doCertObjStatusUpdate(%s)", uuidStr)

	changed, proceed := doCertObjInstall(ctx, uuidStr, config, status)
	if !proceed {
		return changed
	}

	// Walk all which have WaitingForCerts set
	pubs := []pubsub.Publication{
		ctx.publication(types.VolumeStatus{}, types.AppImgObj),
		ctx.publication(types.VolumeStatus{}, types.BaseOsObj),
	}

	for _, pub := range pubs {
		items := pub.GetAll()
		for _, st := range items {
			vs := st.(types.VolumeStatus)
			if !vs.WaitingForCerts {
				continue
			}
			doUpdate(ctx, &vs)
		}
	}
	log.Infof("doCertObjStatusUdate(%s) done %v", uuidStr, changed)
	return changed
}

func doCertObjInstall(ctx *volumemgrContext, uuidStr string, config types.CertObjConfig,
	status *types.CertObjStatus) (bool, bool) {

	log.Infof("doCertObjInstall(%s)", uuidStr)
	changed := false

	if len(config.StorageConfigList) != len(status.StorageStatusList) {
		errString := fmt.Sprintf("%s, Storage length mismatch: %d vs %d\n", uuidStr,
			len(config.StorageConfigList),
			len(status.StorageStatusList))
		log.Error(errString)
		status.SetErrorNow(errString)
		return changed, false
	}

	for i, sc := range config.StorageConfigList {
		ss := &status.StorageStatusList[i]

		if ss.Name != sc.Name || !uuid.Equal(ss.ImageID, sc.ImageID) {
			// Report to zedcloud
			errString := fmt.Sprintf("%s, Storage config mismatch:\n\t%s\n\t%s\n\t%s\n\t%s\n\n", uuidStr,
				sc.Name, ss.Name,
				sc.ImageID, ss.ImageID)
			log.Error(errString)
			status.SetErrorNow(errString)
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
	// XXX
	//	if installDownloadedObjects(types.CertObj, uuidStr, &status.StorageStatusList) {
	//		// Automatically move from DOWNLOADED to INSTALLED
	//		status.State = types.INSTALLED
	//		changed = true
	//	}

	publishCertObjStatus(ctx, status)
	log.Infof("doCertObjInstall(%s) done %v", uuidStr, changed)
	return changed, true
}

func checkCertObjStorageDownloadStatus(ctx *volumemgrContext, uuidStr string,
	config types.CertObjConfig, status *types.CertObjStatus) (bool, bool) {

	// XXX	ret := checkStorageDownloadStatus(ctx, types.CertObj, uuidStr,
	//		config.StorageConfigList, status.StorageStatusList)
	var ret types.RetStatus
	status.State = ret.MinState
	status.SetError(ret.AllErrors, ret.ErrorTime)

	log.Infof("checkCertObjDownloadStatus %s, %v", uuidStr, ret.MinState)

	if ret.AllErrors != "" {
		log.Errorf("checkCertObjDownloadStatus for %s, Download error %s",
			uuidStr, ret.AllErrors)
		return ret.Changed, false
	}

	if ret.MinState < types.DOWNLOADED {
		log.Infof("checkCertObjDownloaStatus %s, Waiting for downloads",
			uuidStr)
		return ret.Changed, false
	}

	log.Infof("checkCertObjDownloadStatus for %s, Downloads done", uuidStr)
	return ret.Changed, true
}

func removeCertObjConfig(ctx *volumemgrContext, uuidStr string) {

	log.Infof("removeCertObjConfig(%s)", uuidStr)
	status := lookupCertObjStatus(ctx, uuidStr)
	if status == nil {
		log.Infof("removeCertObjConfig(%s), no status", uuidStr)
		return
	}

	changed, del := doCertObjUninstall(ctx, uuidStr, status)
	if changed {
		log.Infof("removeCertObjConfig(%s) status changed", uuidStr)
		publishCertObjStatus(ctx, status)
	}

	if del {
		// Write out what we modified to CertObj aka delete
		unpublishCertObjStatus(ctx, status.Key())
	}
	log.Infof("removeCertObjConfig(%s) done", uuidStr)
}

// XXX how many elements in StorageStatusList for a certobj?
// XXX zedagent creates a StorageConfigList with one entry per certificate
// and drive and associated that with the UUID of the BaseOsConfig or AppInstanceConfig.
// XXX just walk and ensure we have a refcount on urlsha=sha(URL=name)
// XXX no need to reduce refcounts if that is complex.
func doCertObjUninstall(ctx *volumemgrContext, uuidStr string,
	status *types.CertObjStatus) (bool, bool) {

	var del, changed, removedAll bool
	// XXX VolumeStatus for function
	vstatus := new(types.VolumeStatus)
	removedAll = true
	log.Infof("doCertObjUninstall(%s)", uuidStr)

	for i := range status.StorageStatusList {

		ss := &status.StorageStatusList[i]
		log.Infof("doCertObjUninstall(%s) imageID %s",
			uuidStr, ss.ImageID)
		// Decrease refcount if we had increased it
		if vstatus.DownloadOrigin.HasDownloaderRef {
			// XXX removeDownloaderConfig(ctx, types.CertObj, ss.ImageID)
			vstatus.DownloadOrigin.HasDownloaderRef = false
			changed = true
		}

		ds := lookupDownloaderStatus(ctx, types.CertObj, ss.ImageID.String())
		// XXX if additional refs it will not go away
		if false && ds != nil {
			log.Infof("doCertObjUninstall(%s) download %s not yet gone",
				uuidStr, ss.ImageID)
			removedAll = false
			continue
		}
	}

	if !removedAll {
		log.Infof("doCertObjUninstall(%s) waiting for download purge",
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

// key is UUIDandVersion string
func lookupCertObjConfig(ctx *volumemgrContext, key string) *types.CertObjConfig {

	sub := ctx.subCertObjConfig
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupCertObjConfig(%s) not found", key)
		return nil
	}
	config := c.(types.CertObjConfig)
	return &config
}

// key is UUIDandVersion string
func lookupCertObjStatus(ctx *volumemgrContext, key string) *types.CertObjStatus {
	pub := ctx.pubCertObjStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupCertObjStatus(%s) not found", key)
		return nil
	}
	status := st.(types.CertObjStatus)
	return &status
}

func publishCertObjStatus(ctx *volumemgrContext, status *types.CertObjStatus) {

	key := status.Key()
	log.Debugf("publishCertObjStatus(%s)", key)
	pub := ctx.pubCertObjStatus
	pub.Publish(key, *status)
}

func unpublishCertObjStatus(ctx *volumemgrContext, key string) {

	log.Debugf("unpublishCertObjStatus(%s)", key)
	pub := ctx.pubCertObjStatus
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishCertObjStatus(%s) not found", key)
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
		log.Debugf("Create %s", dstDirname)
		if err := os.MkdirAll(dstDirname, 0700); err != nil {
			log.Fatal("installCertObject: ", err, dstDirname)
		}
	}

	dstFilename := dstDirname + "/" + types.SafenameToFilename(safename)

	// XXX needed? Check for truncated file and replace??
	if _, err := os.Stat(dstFilename); err == nil {
		// Remove and replace
		log.Infof("installCertObject: replacing %s",
			dstFilename)
		if err := os.Remove(dstFilename); err != nil {
			log.Fatalf("installCertObject failed %s", err)
		}
	}

	log.Infof("installCertObject: writing %s to %s",
		srcFilename, dstFilename)

	// XXX:FIXME its copy, not move
	// need to refactor the certs placement properly
	// this should be on safename or, holder object uuid context
	dstCnt, err := copyFile(srcFilename, dstFilename)
	if err != nil {
		log.Errorln("installCertObject: ", err, dstFilename)
	}
	if dstCnt != srcCnt {
		log.Errorf("installCertObject: mismatched copy len %d vs %d, %s",
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
