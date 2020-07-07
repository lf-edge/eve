// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of VolumeConfig structs
// from zedmanager and baseosmgr. Publish the status as VolumeStatus

package volumemgr

import (
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// vcCreate create a volume config, the initialization point
// of a new VolumeConfig and therefore a new volume
func vcCreate(ctx *volumemgrContext, objType string, key string,
	config types.OldVolumeConfig) {

	log.Infof("vcCreate(%s) objType %s for %s",
		config.Key(), objType, config.DisplayName)

	if objType == "" {
		log.Fatalf("vcCreate: No ObjType for %s",
			config.Key())
	}
	if lookupOldVolumeStatus(ctx, objType, config.Key()) != nil {
		log.Fatalf("status exists at Create for %s", config.Key())
	}
	var dos *types.DownloadOriginStatus
	if config.DownloadOrigin != nil {
		dos = &types.DownloadOriginStatus{
			DownloadOriginConfig: *config.DownloadOrigin,
		}
	}

	// Do we have a VolumeStatus from Init from before a device reboot?
	initStatus := lookupInitOldVolumeStatus(ctx, config.Key(), config.Origin,
		config.Format)
	if initStatus == nil {
		// XXX is we have an InitVolumeStatus from before boot with
		// purgeCounter=0 we assume this was an update and we will
		// use that volume
		save := config.PurgeCounter
		key := config.Key()
		config.PurgeCounter = save
		initStatus = lookupInitOldVolumeStatus(ctx, key, config.Origin,
			config.Format)
		if initStatus != nil {
			if initStatus.PreReboot {
				log.Infof("vcCreate found PreReboot from %s for %s; promoting",
					initStatus.LastUse, config.Key())
			} else {
				log.Infof("vcCreate found NOT PreReboot from %s for %s; ignored",
					initStatus.LastUse, config.Key())
				initStatus = nil
			}
		}
	}

	if initStatus != nil {
		log.Infof("vcCreate promote status from init for %s", config.Key())
		// We are moving this from unknown to this objType
		unpublishOldVolumeStatus(ctx, initStatus)

		// XXX where do we put this conversion code?
		initStatus.BlobSha256 = config.BlobSha256
		initStatus.AppInstID = config.AppInstID
		initStatus.VolumeID = config.VolumeID
		initStatus.PurgeCounter = config.PurgeCounter

		initStatus.DisplayName = config.DisplayName
		initStatus.ObjType = objType

		initStatus.Origin = config.Origin
		initStatus.DownloadOrigin = dos
		initStatus.MaxVolSize = config.MaxVolSize
		initStatus.ReadOnly = config.ReadOnly

		initStatus.State = types.CREATED_VOLUME
		initStatus.Progress = 100

		// FileLocation unchanged
		initStatus.Format = config.Format
		initStatus.RefCount = config.RefCount
		initStatus.LastUse = time.Now()
		initStatus.PreReboot = false
		if !initStatus.HasError() {
			log.Infof("vcCreate(%s) DONE objType %s for %s",
				config.Key(), objType, config.DisplayName)
			return
		}
		// Fall back to normal case of recreating since we got an
		// error from the container case above.
		log.Infof("vcCreate(%s) fallback from promote to normal create objType %s for %s",
			config.Key(), objType, config.DisplayName)
	}
	// blobType - we do not actually know until we download it, so we start by assuming
	// that it is binary if VM, unknown (i.e. to be parsed) if container
	// before we publish the blobstatus, see if it already exists
	sv := SignatureVerifier{
		Signature:        config.DownloadOrigin.ImageSignature,
		PublicKey:        config.DownloadOrigin.SignatureKey,
		CertificateChain: config.DownloadOrigin.CertificateChain,
	}
	if lookupOrCreateBlobStatus(ctx, sv, objType, dos.ImageSha256) == nil {
		blobType := types.BlobBinary
		if config.Format == zconfig.Format_CONTAINER {
			blobType = types.BlobUnknown
		}
		rootBlob := &types.BlobStatus{
			DatastoreID: dos.DatastoreID,
			RelativeURL: dos.Name,
			Sha256:      strings.ToLower(dos.ImageSha256),
			Size:        dos.MaxDownSize,
			State:       types.INITIAL,
			BlobType:    blobType,
			ObjType:     objType,
		}
		publishBlobStatus(ctx, rootBlob)
	}
	status := types.OldVolumeStatus{
		BlobSha256:     config.BlobSha256,
		AppInstID:      config.AppInstID,
		VolumeID:       config.VolumeID,
		PurgeCounter:   config.PurgeCounter,
		DisplayName:    config.DisplayName,
		ObjType:        objType,
		Origin:         config.Origin,
		DownloadOrigin: dos,
		MaxVolSize:     config.MaxVolSize,
		ReadOnly:       config.ReadOnly,
		Format:         config.Format,
		State:          types.INITIAL,
		// set the root of the content tree
		Blobs: []string{dos.ImageSha256},

		// XXX if these are not needed in Status they are not needed in Config
		//	DevType: config.DevType,
		//	Target: config.Target,
		RefCount: config.RefCount,
	}
	status.LastUse = time.Now()
	status.PendingAdd = true
	publishOldVolumeStatus(ctx, &status)
	// Ignore return value since we always publish
	doUpdateOld(ctx, &status)
	status.PendingAdd = false
	publishOldVolumeStatus(ctx, &status)
	log.Infof("vcCreate(%s) DONE objType %s for %s",
		config.Key(), objType, config.DisplayName)
}

func vcModify(ctx *volumemgrContext, objType string, key string,
	config types.OldVolumeConfig) {

	status := lookupOldVolumeStatus(ctx, objType, config.Key())
	if status == nil {
		log.Fatalf("No status exists at Modify for %s", config.Key())
	}

	log.Infof("vcModify(%s) objType %s for %s",
		config.Key(), status.ObjType, status.DisplayName)

	if status.ObjType == "" {
		log.Fatalf("vcModify: No ObjType for %s",
			status.Key())
	}
	status.PendingModify = true
	publishOldVolumeStatus(ctx, status)
	// XXX handle anything but refcount changes?
	// XXX change TargetSizeBytes to resize qcow2?
	log.Infof("vcModify(%s) from RefCount %d to %d", config.Key(),
		status.RefCount, config.RefCount)
	if status.RefCount == 0 && config.RefCount != 0 {
		status.LastUse = time.Now()
	} else if status.RefCount != 0 && config.RefCount == 0 {
		status.LastUse = time.Now()
	}
	status.RefCount = config.RefCount
	status.PendingModify = false
	publishOldVolumeStatus(ctx, status)
	log.Infof("vcModify(%s) DONE %s for %s",
		config.Key(), status.ObjType, status.DisplayName)
}

func vcDelete(ctx *volumemgrContext, objType string, key string,
	config types.OldVolumeConfig) {

	status := lookupOldVolumeStatus(ctx, objType, config.Key())
	if status == nil {
		log.Fatalf("No status exists at Delete for %s", config.Key())
	}

	log.Infof("vcDelete(%s) objType %s for %s",
		status.Key(), status.ObjType, status.DisplayName)

	if status.ObjType == "" {
		log.Fatalf("vcDelete: No ObjType for %s",
			status.Key())
	}
	status.PendingDelete = true
	publishOldVolumeStatus(ctx, status)
	doDelete(ctx, status)
	status.PendingDelete = false
	publishOldVolumeStatus(ctx, status)
	unpublishOldVolumeStatus(ctx, status)

	log.Infof("vcDelete(%s) DONE objType %s for %s",
		status.Key(), status.ObjType, status.DisplayName)

}

// Callers must be careful to publish any changes to VolumeStatus
func lookupOldVolumeStatus(ctx *volumemgrContext, objType string,
	key string) *types.OldVolumeStatus {

	pub := ctx.publication(types.OldVolumeStatus{}, objType)
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupOldVolumeStatus(%s) not found", key)
		return nil
	}
	status := st.(types.OldVolumeStatus)
	return &status
}

func lookupOldVolumeConfig(ctx *volumemgrContext, objType string,
	key string) *types.OldVolumeConfig {

	sub := ctx.subscription(types.OldVolumeConfig{}, objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupOldVolumeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.OldVolumeConfig)
	return &config
}

func publishOldVolumeStatus(ctx *volumemgrContext,
	status *types.OldVolumeStatus) {

	pub := ctx.publication(*status, status.ObjType)
	key := status.Key()
	log.Debugf("publishOldVolumeStatus(%s)", key)
	pub.Publish(key, *status)
}

func unpublishOldVolumeStatus(ctx *volumemgrContext,
	status *types.OldVolumeStatus) {

	pub := ctx.publication(*status, status.ObjType)
	key := status.Key()
	log.Debugf("unpublishOldVolumeStatus(%s)", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishOldVolumeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}
