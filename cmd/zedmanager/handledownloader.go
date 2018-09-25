// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedmanager

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
)

func AddOrRefcountDownloaderConfig(ctx *zedmanagerContext, safename string,
	sc *types.StorageConfig, ds *types.DatastoreConfig) {

	log.Infof("AddOrRefcountDownloaderConfig for %s\n", safename)

	m := lookupDownloaderConfig(ctx, safename)
	if m != nil {
		m.RefCount += 1
		log.Infof("downloader config exists for %s to refcount %d\n",
			safename, m.RefCount)
		publishDownloaderConfig(ctx, m)
	} else {
		log.Debugf("AddOrRefcountDownloaderConfig: add for %s\n",
			safename)
		n := types.DownloaderConfig{
			Safename:        safename,
			DownloadURL:     ds.Fqdn + "/" + ds.Dpath + "/" + sc.Name,
			TransportMethod: ds.DsType,
			ApiKey:          ds.ApiKey,
			Password:        ds.Password,
			Dpath:           ds.Dpath,
			Region:          ds.Region,
			UseFreeUplinks:  true,
			Size:            sc.Size,
			ImageSha256:     sc.ImageSha256,
			RefCount:        1,
		}
		publishDownloaderConfig(ctx, &n)
	}
	log.Infof("AddOrRefcountDownloaderConfig done for %s\n",
		safename)
}

func MaybeRemoveDownloaderConfig(ctx *zedmanagerContext, safename string) {
	log.Infof("MaybeRemoveDownloaderConfig for %s\n", safename)

	m := lookupDownloaderConfig(ctx, safename)
	if m == nil {
		log.Infof("MaybeRemoveDownloaderConfig: config missing for %s\n",
			safename)
		return
	}
	m.RefCount -= 1
	if m.RefCount != 0 {
		log.Infof("MaybeRemoveDownloaderConfig remaining RefCount %d for %s\n",
			m.RefCount, safename)
		publishDownloaderConfig(ctx, m)
		return
	}
	log.Infof("MaybeRemoveDownloaderConfig RefCount zero for %s\n",
		safename)
	unpublishDownloaderConfig(ctx, m)
	log.Infof("MaybeRemoveDownloaderConfig done for %s\n", safename)
}

func publishDownloaderConfig(ctx *zedmanagerContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("publishDownloaderConfig(%s)\n", key)
	pub := ctx.pubAppImgDownloadConfig
	pub.Publish(key, config)
}

func unpublishDownloaderConfig(ctx *zedmanagerContext,
	config *types.DownloaderConfig) {

	key := config.Key()
	log.Debugf("unpublishDownloaderConfig(%s)\n", key)
	pub := ctx.pubAppImgDownloadConfig
	pub.Unpublish(key)
}

func handleDownloaderStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := cast.CastDownloaderStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleDownloaderStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	ctx := ctxArg.(*zedmanagerContext)
	log.Infof("handleDownloaderStatusModify for %s\n", status.Safename)

	// XXX Ignore if any Pending* flag is set
	// Passing in Progress percentage
	if false && status.Pending() {
		log.Infof("handleDownloaderStatusModify skipping due to Pending* for %s\n",
			status.Safename)
		return
	}
	updateAIStatusSafename(ctx, key)
	log.Infof("handleDownloaderStatusModify done for %s\n",
		status.Safename)
}

func lookupDownloaderConfig(ctx *zedmanagerContext,
	safename string) *types.DownloaderConfig {

	pub := ctx.pubAppImgDownloadConfig
	c, _ := pub.Get(safename)
	if c == nil {
		log.Infof("lookupDownloaderConfig(%s) not found\n", safename)
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

// Note that this function returns the entry even if Pending* is set.
func lookupDownloaderStatus(ctx *zedmanagerContext,
	safename string) *types.DownloaderStatus {

	sub := ctx.subAppImgDownloadStatus
	c, _ := sub.Get(safename)
	if c == nil {
		log.Infof("lookupDownloaderStatus(%s) not found\n", safename)
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

func handleDownloaderStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleDownloaderStatusDelete for %s\n", key)
	ctx := ctxArg.(*zedmanagerContext)
	removeAIStatusSafename(ctx, key)
	log.Infof("handleDownloaderStatusDelete done for %s\n", key)
}
