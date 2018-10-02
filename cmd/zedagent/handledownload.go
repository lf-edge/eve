// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedagent

import (
	"errors"
	"fmt"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"os"
	"strings"
	"time"
)

func lookupDownloaderConfig(ctx *zedagentContext, objType string,
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

func createDownloaderConfig(ctx *zedagentContext, objType string,
	safename string, sc *types.StorageConfig, ds *types.DatastoreConfig) {

	log.Infof("createDownloaderConfig(%s/%s)\n", objType, safename)

	if m := lookupDownloaderConfig(ctx, objType, safename); m != nil {
		m.RefCount += 1
		log.Infof("createDownloaderConfig(%s) refcount to %d\n",
			safename, m.RefCount)
		publishDownloaderConfig(ctx, objType, m)
	} else {
		log.Infof("createDownloaderConfig(%s) add\n", safename)
		// XXX We rewrite Dpath for certs. Can't zedcloud use
		// a separate datastore for the certs to remove this hack?
		// Note that the certs seem to come as complete URLs hence
		// this code might not be required?
		dpath := ds.Dpath
		if objType == certObj {
			// Replacing -images with -certs in dpath
			dpath = strings.Replace(dpath, "-images", "-certs", 1)
			log.Infof("createDownloaderConfig fqdn %s ts %s dpath %s to %s\n",
				ds.Fqdn, ds.DsType, ds.Dpath, dpath)
		}

		var downloadURL string
		if sc.NameIsURL {
			downloadURL = sc.Name
		} else {
			downloadURL = ds.Fqdn + "/" + dpath + "/" + sc.Name
		}
		n := types.DownloaderConfig{
			Safename:        safename,
			DownloadURL:     downloadURL,
			TransportMethod: ds.DsType,
			ApiKey:          ds.ApiKey,
			Password:        ds.Password,
			Dpath:           dpath,
			Region:          ds.Region,
			UseFreeUplinks:  false,
			Size:            sc.Size,
			ImageSha256:     sc.ImageSha256,
			RefCount:        1,
		}
		publishDownloaderConfig(ctx, objType, &n)
	}
	log.Infof("createDownloaderConfig(%s/%s) done\n", objType, safename)
}

func updateDownloaderStatus(ctx *zedagentContext,
	status *types.DownloaderStatus) {

	key := status.Key()
	objType := status.ObjType
	log.Infof("updateDownloaderStatus(%s/%s) to %v\n",
		objType, key, status.State)

	// Update Progress counter even if Pending

	switch objType {
	case baseOsObj:
		baseOsHandleStatusUpdateSafename(ctx, status.Safename)

	case certObj:
		certObjHandleStatusUpdateSafename(ctx, status.Safename)

	case appImgObj:
		// We subscribe to get metrics about disk usage
		log.Debugf("updateDownloaderStatus for %s, ignoring objType %s\n",
			key, objType)
		return

	default:
		log.Errorf("updateDownloaderStatus for %s, unsupported objType %s\n",
			key, objType)
		return
	}
	log.Infof("updateDownloaderStatus(%s/%s) done\n",
		objType, key)
}

// Lookup published config;
func removeDownloaderConfig(ctx *zedagentContext, objType string, safename string) {

	log.Infof("removeDownloaderConfig(%s/%s)\n", objType, safename)

	config := lookupDownloaderConfig(ctx, objType, safename)
	if config == nil {
		log.Infof("removeDownloaderConfig(%s/%s) no Config\n",
			objType, safename)
		return
	}

	if config.RefCount > 1 {
		config.RefCount -= 1
		log.Infof("removeDownloaderConfig(%s/%s) decrementing refCount to %d\n",
			objType, safename, config.RefCount)
		publishDownloaderConfig(ctx, objType, config)
		return
	}
	unpublishDownloaderConfig(ctx, objType, config)
	log.Infof("removeDownloaderConfig(%s/%s) done\n", objType, safename)
}

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *zedagentContext, objType string,
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

func checkStorageDownloadStatus(ctx *zedagentContext, objType string,
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
		if ss.FinalObjDir != "" {
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
					createVerifierConfig(ctx, objType,
						vs.Safename, &sc, false)
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
					ret.Changed = true
				}
				continue
			}
		}

		if !ss.HasDownloaderRef {
			log.Infof("checkStorageDownloadStatus %s, !HasDownloaderRef\n", safename)
			dst, err := lookupDatastoreConfig(ctx, sc.DatastoreId,
				sc.Name)
			if err != nil {
				ss.Error = fmt.Sprintf("%v", err)
				ret.AllErrors = appendError(ret.AllErrors, "datastore",
					ss.Error)
				ss.ErrorTime = time.Now()
				ret.ErrorTime = ss.ErrorTime
				ret.Changed = true
				continue
			}
			createDownloaderConfig(ctx, objType, safename, &sc, dst)
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
			ss.Error = ds.LastErr
			ret.AllErrors = appendError(ret.AllErrors, "downloader",
				ds.LastErr)
			ss.ErrorTime = ds.LastErrTime
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
					err := createVerifierConfig(ctx,
						objType, safename, &sc, true)
					if err == nil {
						ss.HasVerifierRef = true
						ret.Changed = true
					} else {
						ret.WaitingForCerts = true
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

// Check for nil UUID (an indication the drive was missing in parseconfig)
// and a missing datastore id.
func lookupDatastoreConfig(ctx *zedagentContext,
	datastoreId uuid.UUID, name string) (*types.DatastoreConfig, error) {

	if datastoreId == nilUUID {
		errStr := fmt.Sprintf("lookupDatastoreConfig(%s) for %s: No datastore ID",
			datastoreId.String(), name)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	cfg, err := ctx.subDatastoreConfig.Get(datastoreId.String())
	if err != nil {
		errStr := fmt.Sprintf("lookupDatastoreConfig(%s) for %s: %v",
			datastoreId.String(), name, err)
		log.Errorln(errStr)
		return nil, errors.New(errStr)
	}
	dst := cast.CastDatastoreConfig(cfg)
	return &dst, nil
}

func installDownloadedObjects(objType string, uuidStr string,
	status []types.StorageStatus) bool {

	ret := true
	log.Infof("installDownloadedObjects(%s)\n", uuidStr)

	for i, _ := range status {
		ss := &status[i]

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
	var srcFilename string = objectDownloadDirname + "/" + objType

	log.Infof("installDownloadedObject(%s/%s, %v)\n", objType, safename, status.State)

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
		case certObj:
			ret = installCertObject(srcFilename, dstFilename, safename)

		case baseOsObj:
			ret = installBaseOsObject(srcFilename, dstFilename)

		default:
			errStr := fmt.Sprintf("installDownloadedObject %s, Unsupported Object Type %v",
				safename, objType)
			log.Errorln(errStr)
			ret = errors.New(status.Error)
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
		status.Error = fmt.Sprintf("%s", ret)
		status.ErrorTime = time.Now()
	}
	return ret
}

func publishDownloaderConfig(ctx *zedagentContext, objType string,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s/%s)\n", objType, config.Key())
	pub := downloaderPublication(ctx, objType)
	pub.Publish(key, config)
}

func unpublishDownloaderConfig(ctx *zedagentContext, objType string,
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

func downloaderPublication(ctx *zedagentContext, objType string) *pubsub.Publication {
	var pub *pubsub.Publication
	switch objType {
	case baseOsObj:
		pub = ctx.pubBaseOsDownloadConfig
	case certObj:
		pub = ctx.pubCertObjDownloadConfig
	default:
		log.Fatalf("downloaderPublication: Unknown ObjType %s\n",
			objType)
	}
	return pub
}

func downloaderSubscription(ctx *zedagentContext, objType string) *pubsub.Subscription {
	var sub *pubsub.Subscription
	switch objType {
	case baseOsObj:
		sub = ctx.subBaseOsDownloadStatus
	case certObj:
		sub = ctx.subCertObjDownloadStatus
	case appImgObj:
		sub = ctx.subAppImgDownloadStatus
	default:
		log.Fatalf("downloaderSubscription: Unknown ObjType %s\n",
			objType)
	}
	return sub
}

func downloaderGetAll(ctx *zedagentContext) map[string]interface{} {
	sub1 := downloaderSubscription(ctx, baseOsObj)
	items1 := sub1.GetAll()
	sub2 := downloaderSubscription(ctx, certObj)
	items2 := sub2.GetAll()
	sub3 := downloaderSubscription(ctx, appImgObj)
	items3 := sub3.GetAll()

	items := make(map[string]interface{})
	for k, i := range items1 {
		items[k] = i
	}
	for k, i := range items2 {
		items[k] = i
	}
	for k, i := range items3 {
		items[k] = i
	}
	return items
}
