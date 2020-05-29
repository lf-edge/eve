// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

// Code for the interface with VolumeMgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// AddOrRefcountVolumeConfig makes sure we have a VolumeConfig with a non-zero
// RefCount
// We use the baseos object UUID as appInstID here
func AddOrRefcountVolumeConfig(ctx *baseOsMgrContext, blobSha256 string,
	appInstID uuid.UUID, volumeID uuid.UUID, ss types.StorageStatus) {

	// No PurgeCounter for baseos
	key := types.VolumeKeyFromParts(blobSha256, appInstID, volumeID, 0)
	log.Infof("AddOrRefcountVolumeConfig for %s", key)
	m := lookupVolumeConfig(ctx, key)
	if m != nil {
		m.RefCount++
		log.Infof("VolumeConfig exists for %s to refcount %d",
			key, m.RefCount)
		publishVolumeConfig(ctx, m)
	} else {
		log.Debugf("AddOrRefcountVolumeConfig: add for %s", key)
		// XXX hard-coded for OriginTypeDownload for now
		d := types.DownloadOriginConfig{
			ImageID:     ss.ImageID,
			DatastoreID: ss.DatastoreID,
			Name:        ss.Name,
			NameIsURL:   ss.NameIsURL,
			ImageSha256: ss.ImageSha256,
			IsContainer: ss.IsContainer,
			AllowNonFreePort: types.AllowNonFreePort(*ctx.globalConfig,
				types.AppImgObj),
			MaxDownSize: ss.MaxDownSize,
			FinalObjDir: ss.FinalObjDir,

			CertificateChain: ss.CertificateChain,
			ImageSignature:   ss.ImageSignature,
			SignatureKey:     ss.SignatureKey,
		}
		n := types.VolumeConfig{
			BlobSha256:     blobSha256,
			AppInstID:      appInstID,
			VolumeID:       volumeID,
			PurgeCounter:   0,
			DisplayName:    ss.Name,
			Origin:         types.OriginTypeDownload,
			DownloadOrigin: &d,
			MaxVolSize:     ss.MaxVolSize,
			ReadOnly:       ss.ReadOnly,
			Format:         ss.Format,
			Devtype:        ss.Devtype,
			Target:         ss.Target,
			RefCount:       1,
		}
		publishVolumeConfig(ctx, &n)
	}
	log.Infof("AddOrRefcountVolumeConfig done for %s", key)
}

// MaybeRemoveVolumeConfig decreases the RefCount and deletes the VolumeConfig
// when the RefCount reaches zero
// We use the baseos object UUID as appInstID here
func MaybeRemoveVolumeConfig(ctx *baseOsMgrContext, blobSha256 string,
	appInstID uuid.UUID, volumeID uuid.UUID) {

	// No PurgeCounter for baseos
	key := types.VolumeKeyFromParts(blobSha256, appInstID, volumeID, 0)
	log.Infof("MaybeRemoveVolumeConfig for %s", key)
	m := lookupVolumeConfig(ctx, key)
	if m == nil {
		log.Infof("MaybeRemoveVolumeConfig: config missing for %s", key)
		return
	}
	if m.RefCount == 0 {
		log.Fatalf("MaybeRemoveVolumeConfig: Attempting to reduce "+
			"0 RefCount for %s", key)
	}
	m.RefCount--
	if m.RefCount == 0 {
		log.Infof("MaybeRemoveVolumeConfig deleting %s", key)
		unpublishVolumeConfig(ctx, key)
	} else {
		log.Infof("MaybeRemoveVolumeConfig remaining RefCount %d for %s",
			m.RefCount, key)
		publishVolumeConfig(ctx, m)
	}
}

func lookupVolumeConfig(ctx *baseOsMgrContext, key string) *types.VolumeConfig {

	pub := ctx.pubVolumeConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupVolumeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeConfig)
	return &config
}

// Note that this function returns the entry even if Pending* is set.
// We use the baseos object UUID as appInstID here
func lookupVolumeStatus(ctx *baseOsMgrContext, blobSha256 string,
	appInstID uuid.UUID, volumeID uuid.UUID) *types.VolumeStatus {

	// No PurgeCounter for baseos
	key := types.VolumeKeyFromParts(blobSha256, appInstID, volumeID, 0)
	sub := ctx.subVolumeStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupVolumeStatus(%s) not found", key)
		return nil
	}
	status := st.(types.VolumeStatus)
	return &status
}

func publishVolumeConfig(ctx *baseOsMgrContext,
	status *types.VolumeConfig) {

	key := status.Key()
	log.Infof("publishVolumeConfig(%s)", key)
	pub := ctx.pubVolumeConfig
	pub.Publish(key, *status)
}

func unpublishVolumeConfig(ctx *baseOsMgrContext, uuidStr string) {

	key := uuidStr
	log.Infof("unpublishVolumeConfig(%s)", key)
	pub := ctx.pubVolumeConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishVolumeConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func handleVolumeStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.VolumeStatus)
	ctx := ctxArg.(*baseOsMgrContext)
	log.Infof("handleVolumeStatusModify: key:%s, name:%s",
		key, status.DisplayName)
	// Process even if a Pending* flag is set to update progress
	if status.BlobSha256 != "" {
		baseOsHandleStatusUpdateImageSha(ctx, status.BlobSha256)
	} else {
		log.Warnf("Unknown volume: appinstid %s volume %s",
			status.AppInstID, status.VolumeID)
	}
	log.Infof("handleVolumeStatusModify done for %s", key)
}

func handleVolumeStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleVolumeStatusDelete for %s", key)
	ctx := ctxArg.(*baseOsMgrContext)
	status := statusArg.(types.VolumeStatus)
	if status.BlobSha256 != "" {
		baseOsHandleStatusUpdateImageSha(ctx, status.BlobSha256)
	} else {
		log.Warnf("Unknown volume: appinstid %s volume %s",
			status.AppInstID, status.VolumeID)
	}
	log.Infof("handleVolumeStatusDelete done for %s", key)
}
