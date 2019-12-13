// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Really a constant
var nilUUID uuid.UUID

func lookupDownloaderConfig(ctx *baseOsMgrContext, objType string,
	safename string) *types.DownloaderConfig {

	pub := downloaderPublication(ctx, objType)
	c, _ := pub.Get(safename)
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s/%s) not found\n",
			objType, safename)
		return nil
	}
	config := cast.CastDownloaderConfig(c)
	if config.Key() != safename {
		log.Errorf("lookupDownloaderConfig(%s) got %s; ignored %+v\n",
			safename, config.Key(), config)
		return nil
	}
	return &config
}

func createDownloaderConfig(ctx *baseOsMgrContext, objType string, safename string,
	sc *types.StorageConfig) {

	log.Infof("createDownloaderConfig(%s/%s)\n", objType, safename)

	if m := lookupDownloaderConfig(ctx, objType, safename); m != nil {
		m.RefCount += 1
		log.Infof("createDownloaderConfig(%s) refcount to %d\n",
			safename, m.RefCount)
		publishDownloaderConfig(ctx, objType, m)
	} else {
		log.Infof("createDownloaderConfig(%s) add\n", safename)
		n := types.DownloaderConfig{
			DatastoreID: sc.DatastoreID,
			Safename:    safename,
			Name:        sc.Name,
			NameIsURL:   sc.NameIsURL,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				objType),
			Size:        sc.Size,
			ImageSha256: sc.ImageSha256,
			RefCount:    1,
		}
		publishDownloaderConfig(ctx, objType, &n)
	}
	log.Infof("createDownloaderConfig(%s/%s) done\n", objType, safename)
}

func updateDownloaderStatus(ctx *baseOsMgrContext,
	status *types.DownloaderStatus) {

	key := status.Key()
	objType := status.ObjType
	log.Infof("updateDownloaderStatus(%s/%s) to %v\n",
		objType, key, status.State)

	// Update Progress counter even if Pending

	switch status.ObjType {
	case types.BaseOsObj, types.CertObj:
		// break
	default:
		log.Errorf("updateDownloaderStatus for %s, unsupported objType %s\n",
			key, objType)
		return
	}
	// We handle two special cases in the handshake here
	// 1. downloader added a status with RefCount=0 based on
	// an existing file. We echo that with a config with RefCount=0
	// 2. downloader set Expired in status when garbage collecting.
	// If we have no RefCount we delete the config.

	config := lookupDownloaderConfig(ctx, status.ObjType, status.Key())
	if config == nil && status.RefCount == 0 {
		log.Infof("updateDownloaderStatus adding RefCount=0 config %s\n",
			key)
		n := types.DownloaderConfig{
			DatastoreID: status.DatastoreID,
			Safename:    status.Safename,
			Name:        status.Name,
			NameIsURL:   status.NameIsURL,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				objType),
			Size:        status.Size,
			ImageSha256: status.ImageSha256,
			RefCount:    0,
		}
		publishDownloaderConfig(ctx, status.ObjType, &n)
		return
	}
	if config != nil && config.RefCount == 0 && status.Expired {
		log.Infof("updateDownloaderStatus expired - deleting config %s\n",
			key)
		unpublishDownloaderConfig(ctx, status.ObjType, config)
		return
	}

	// Normal update work
	switch objType {
	case types.BaseOsObj:
		baseOsHandleStatusUpdateSafename(ctx, status.Safename)

	case types.CertObj:
		certObjHandleStatusUpdateSafename(ctx, status.Safename)
	}
	log.Infof("updateDownloaderStatus(%s/%s) done\n",
		objType, key)
}

// Lookup published config;
func removeDownloaderConfig(ctx *baseOsMgrContext, objType string, safename string) {

	log.Infof("removeDownloaderConfig(%s/%s)\n", objType, safename)

	config := lookupDownloaderConfig(ctx, objType, safename)
	if config == nil {
		log.Infof("removeDownloaderConfig(%s/%s) no Config\n",
			objType, safename)
		return
	}
	if config.RefCount == 0 {
		log.Fatalf("removeDownloaderConfig(%s/%s): RefCount already 0. Cannot"+
			" decrement it.", objType, safename)
	}
	config.RefCount -= 1
	log.Infof("removeDownloaderConfig(%s/%s) decrementing refCount to %d\n",
		objType, safename, config.RefCount)
	publishDownloaderConfig(ctx, objType, config)
	log.Infof("removeDownloaderConfig(%s/%s) done\n", objType, safename)
}

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *baseOsMgrContext, objType string,
	safename string) *types.DownloaderStatus {

	sub := downloaderSubscription(ctx, objType)
	c, _ := sub.Get(safename)
	if c == nil {
		log.Infof("lookupDownloaderStatus(%s/%s) not found\n",
			objType, safename)
		return nil
	}
	status := cast.CastDownloaderStatus(c)
	if status.Key() != safename {
		log.Errorf("lookupDownloaderStatus(%s) got %s; ignored %+v\n",
			safename, status.Key(), status)
		return nil
	}
	return &status
}

func checkStorageDownloadStatus(ctx *baseOsMgrContext, objType string,
	uuidStr string, config []types.StorageConfig,
	status []types.StorageStatus) *types.RetStatus {

	ret := &types.RetStatus{}
	log.Infof("checkStorageDownloadStatus for %s\n", uuidStr)

	ret.Changed = false
	ret.AllErrors = ""
	ret.MinState = types.MAXSTATE
	ret.WaitingForCerts = false

	for i, sc := range config {

		ss := &status[i]

		safename := types.UrlToSafename(sc.Name, sc.ImageSha256)

		log.Infof("checkStorageDownloadStatus %s, image status %v\n",
			safename, ss.State)
		if ss.State == types.INSTALLED {
			ret.MinState = ss.State
			log.Infof("checkStorageDownloadStatus %s is already installed\n",
				safename)
			continue
		}

		// Check if cert already exists in FinalObjDir
		// Sanity check that length isn't zero
		// XXX other sanity checks?
		// Only meaningful for certObj
		if objType == types.CertObj && ss.FinalObjDir != "" {
			dstFilename := ss.FinalObjDir + "/" + types.SafenameToFilename(safename)
			st, err := os.Stat(dstFilename)
			if err == nil && st.Size() != 0 {
				ret.MinState = types.INSTALLED
				log.Infof("checkStorageDownloadStatus %s is in FinalObjDir %s\n",
					safename, dstFilename)
				continue
			}
		}
		if sc.ImageSha256 != "" {
			// Shortcut if image is already verified
			vs := lookupVerificationStatusAny(ctx, objType,
				safename, sc.ImageSha256)

			if vs != nil && !vs.Pending() &&
				vs.State == types.DELIVERED {

				log.Infof(" %s, exists verified with sha %s\n",
					safename, sc.ImageSha256)
				if vs.Safename != safename {
					// If found based on sha256
					log.Infof("found diff safename %s\n",
						vs.Safename)
				}
				// If we don't already have a RefCount add one
				if !ss.HasVerifierRef {
					log.Infof("checkStorageDownloadStatus %s, !HasVerifierRef\n", vs.Safename)
					createVerifierConfig(ctx, uuidStr, objType, vs.Safename, sc, *ss, false)
					ss.HasVerifierRef = true
					ret.Changed = true
				}
				if ret.MinState > vs.State {
					ret.MinState = vs.State
				}
				if vs.State != ss.State {
					log.Infof("checkStorageDownloadStatus(%s) from vs set ss.State %d\n",
						safename, vs.State)
					ss.State = vs.State
					ss.Progress = 100
					ret.Changed = true
				}
				continue
			}
		}

		if !ss.HasDownloaderRef {
			log.Infof("checkStorageDownloadStatus %s, !HasDownloaderRef\n", safename)
			createDownloaderConfig(ctx, objType, safename, &sc)
			ss.HasDownloaderRef = true
			ret.Changed = true
		}

		ds := lookupDownloaderStatus(ctx, objType, safename)
		if ds == nil {
			log.Infof("LookupDownloaderStatus %s not yet\n",
				safename)
			ret.MinState = types.DOWNLOAD_STARTED
			ss.State = types.DOWNLOAD_STARTED
			ret.Changed = true
			continue
		}

		if ret.MinState > ds.State {
			ret.MinState = ds.State
		}
		if ds.State != ss.State {
			log.Infof("checkStorageDownloadStatus(%s) from ds set ss.State %d\n",
				safename, ds.State)
			ss.State = ds.State
			ret.Changed = true
		}

		if ds.Progress != ss.Progress {
			ss.Progress = ds.Progress
			ret.Changed = true
		}
		if ds.Pending() {
			log.Infof("checkStorageDownloadStatus(%s) Pending\n",
				safename)
			continue
		}
		if ds.LastErr != "" {
			log.Errorf("checkStorageDownloadStatus %s, downloader error, %s\n",
				uuidStr, ds.LastErr)
			errInfo := types.ErrorInfo{
				Error:       ds.LastErr,
				ErrorTime:   ds.LastErrTime,
				ErrorSource: pubsub.TypeToName(types.VerifyImageStatus{}),
			}
			ss.SetErrorInfo(errInfo)
			ret.AllErrors = appendError(ret.AllErrors, "downloader", ds.LastErr)
			ret.ErrorTime = ss.ErrorTime
			ret.Changed = true
		}
		switch ss.State {
		case types.INITIAL:
			// Nothing to do
		case types.DOWNLOAD_STARTED:
			// Nothing to do
		case types.DOWNLOADED:

			log.Infof("checkStorageDownloadStatus %s, is downloaded\n", safename)
			// if verification is needed
			if sc.ImageSha256 != "" {
				// start verifier for this object
				if !ss.HasVerifierRef {
					val, errInfo := createVerifierConfig(ctx, uuidStr, objType,
						safename, sc, *ss, true)
					if val {
						ret.Changed = true
						ss.HasVerifierRef = true
					} else {
						if errInfo.Error != "" {
							ss.SetErrorInfo(errInfo)
							ret.AllErrors = appendError(ret.AllErrors, "baseosmgr", ss.Error)
							ret.ErrorTime = ss.ErrorTime
							ret.Changed = true
						} else {
							if !ret.WaitingForCerts {
								ret.Changed = true
								ret.WaitingForCerts = true
							}
						}
					}
				}
			}
		}
	}

	if ret.MinState == types.MAXSTATE {
		// No StorageStatus
		ret.MinState = types.DOWNLOADED
		ret.Changed = true
	}

	return ret
}

func installDownloadedObjects(objType string, uuidStr string,
	status *[]types.StorageStatus) bool {

	ret := true
	log.Infof("installDownloadedObjects(%s)\n", uuidStr)

	for i := range *status {
		ss := &(*status)[i]

		safename := types.UrlToSafename(ss.Name, ss.ImageSha256)

		installDownloadedObject(objType, safename, ss)

		// if something is still not installed, mark accordingly
		if ss.State != types.INSTALLED {
			ret = false
		}
	}

	log.Infof("installDownloadedObjects(%s) done %v\n", uuidStr, ret)
	return ret
}

// based on download/verification state, if
// the final installation directory is mentioned,
// move the object there
func installDownloadedObject(objType string, safename string,
	status *types.StorageStatus) error {

	var ret error
	var srcFilename string = types.DownloadDirname + "/" + objType

	log.Infof("installDownloadedObject(%s/%s, %v)\n",
		objType, safename, status.State)

	// if the object is in downloaded state,
	// pick from pending directory
	// if ithe object is n delivered state,
	//  pick from verified directory
	switch status.State {

	case types.INSTALLED:
		log.Infof("installDownloadedObject %s, already installed\n",
			safename)
		return nil

	case types.DOWNLOADED:
		// XXX should fix code elsewhere to advance to DELIVERED in
		// this case??
		if status.ImageSha256 != "" {
			log.Infof("installDownloadedObject %s, verification pending\n",
				safename)
			return nil
		}
		srcFilename += "/pending/" + safename

	case types.DELIVERED:
		srcFilename += "/verified/" + status.ImageSha256 + "/" +
			types.SafenameToFilename(safename)

	default:
		log.Infof("installDownloadedObject %s, still not ready (%d)\n",
			safename, status.State)
		return nil
	}

	// ensure the file is present
	if _, err := os.Stat(srcFilename); err != nil {
		log.Fatal(err)
	}

	// Move to final installation point
	if status.FinalObjDir != "" {

		var dstFilename string = status.FinalObjDir

		switch objType {
		case types.CertObj:
			ret = installCertObject(srcFilename, dstFilename, safename)

		case types.BaseOsObj:
			ret = installBaseOsObject(srcFilename, dstFilename)

		default:
			errStr := fmt.Sprintf("installDownloadedObject %s, Unsupported Object Type %v",
				safename, objType)
			log.Errorln(errStr)
			ret = errors.New(errStr)
		}
	} else {
		errStr := fmt.Sprintf("installDownloadedObject %s, final dir not set %v\n", safename, objType)
		log.Errorln(errStr)
		ret = errors.New(errStr)
	}

	if ret == nil {
		status.State = types.INSTALLED
		log.Infof("installDownloadedObject(%s) done\n", safename)
	} else {
		errInfo := types.ErrorInfo{
			Error:       fmt.Sprintf("%s", ret),
			ErrorTime:   time.Now(),
			ErrorSource: pubsub.TypeToName(types.VerifyImageStatus{}),
		}
		status.SetErrorInfo(errInfo)
	}
	return ret
}

func publishDownloaderConfig(ctx *baseOsMgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s/%s)\n", objType, config.Key())
	pub := downloaderPublication(ctx, objType)
	pub.Publish(key, config)
}

func unpublishDownloaderConfig(ctx *baseOsMgrContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("unpublishDownloaderConfig(%s/%s)\n", objType, key)
	pub := downloaderPublication(ctx, objType)
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishDownloaderConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func downloaderPublication(ctx *baseOsMgrContext, objType string) *pubsub.Publication {
	var pub *pubsub.Publication
	switch objType {
	case types.BaseOsObj:
		pub = ctx.pubBaseOsDownloadConfig
	case types.CertObj:
		pub = ctx.pubCertObjDownloadConfig
	default:
		log.Fatalf("downloaderPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}

func downloaderSubscription(ctx *baseOsMgrContext, objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case types.BaseOsObj:
		sub = ctx.subBaseOsDownloadStatus
	case types.CertObj:
		sub = ctx.subCertObjDownloadStatus
	default:
		log.Fatalf("downloaderSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}
