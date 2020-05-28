// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Process input in the form of a collection of VolumeConfig structs
// from zedmanager and baseosmgr. Publish the status as VolumeStatus

package volumemgr

import (
	"fmt"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	log "github.com/sirupsen/logrus"
)

func vcCreate(ctx *volumemgrContext, objType string, key string,
	config types.VolumeConfig) {

	log.Infof("vcCreate(%s) objType %s for %s",
		config.Key(), objType, config.DisplayName)

	if objType == "" {
		log.Fatalf("vcCreate: No ObjType for %s",
			config.Key())
	}
	if lookupVolumeStatus(ctx, objType, config.Key()) != nil {
		log.Fatalf("status exists at Create for %s", config.Key())
	}
	var dos *types.DownloadOriginStatus
	if config.DownloadOrigin != nil {
		dos = &types.DownloadOriginStatus{
			DownloadOriginConfig: *config.DownloadOrigin,
		}
	}

	// Do we have a VolumeStatus from Init from before a device reboot?
	initStatus := lookupInitVolumeStatus(ctx, config.Key(), config.Origin,
		config.Format)
	if initStatus == nil {
		// XXX is we have an InitVolumeStatus from before boot with
		// purgeCounter=0 we assume this was an update and we will
		// use that volume
		save := config.PurgeCounter
		key := config.Key()
		config.PurgeCounter = save
		initStatus = lookupInitVolumeStatus(ctx, key, config.Origin,
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
		unpublishVolumeStatus(ctx, initStatus)

		// XXX After device reboot, somehow files created by containerd snapshot prepare
		// is getting deleted from /persist/runx/pods/prepared/<container-dir-name>/rootfs/
		// So, doing a hack here for containers by calling containerd snapshot prepare again
		// Note that this will fail if the verified image has been
		// garbage collected, in which case we will download again.
		if config.Format == zconfig.Format_CONTAINER {
			ociFilename, err := utils.VerifiedImageFileLocation(config.BlobSha256)
			if err != nil {
				errStr := fmt.Sprintf("failed to get Image File Location. err: %+s",
					err)
				log.Error(errStr)
				initStatus.SetError(errStr, time.Now())
			} else {
				if err := containerd.SnapshotPrepare(initStatus.FileLocation, ociFilename); err != nil {
					errStr := fmt.Sprintf("Failed to create ctr bundle. Error %s", err)
					log.Error(errStr)
					initStatus.SetError(errStr, time.Now())
				}
			}
		}

		// XXX where do we put this conversion code?
		initStatus.BlobSha256 = config.BlobSha256
		initStatus.AppInstID = config.AppInstID
		initStatus.VolumeID = config.VolumeID
		initStatus.PurgeCounter = config.PurgeCounter

		initStatus.DisplayName = config.DisplayName
		initStatus.ObjType = objType

		initStatus.Origin = config.Origin
		initStatus.DownloadOrigin = dos
		initStatus.TargetSizeBytes = config.TargetSizeBytes // XXX change?
		initStatus.ReadOnly = config.ReadOnly

		initStatus.State = types.CREATED_VOLUME
		initStatus.Progress = 100

		// FileLocation unchanged
		initStatus.Format = config.Format
		initStatus.RefCount = config.RefCount
		initStatus.LastUse = time.Now()
		initStatus.PreReboot = false
		if !initStatus.HasError() {
			if lookupPersistImageStatus(ctx, objType, initStatus.BlobSha256) != nil && !initStatus.DownloadOrigin.HasPersistRef {
				log.Infof("vcCreate: Adding PersistImageStatus reference for VolumeStatus: %s", initStatus.BlobSha256)
				AddOrRefCountPersistImageStatus(ctx, initStatus.DisplayName, objType, "", initStatus.BlobSha256, 0)
				initStatus.DownloadOrigin.HasPersistRef = true
			}
			publishVolumeStatus(ctx, initStatus)
			log.Infof("vcCreate(%s) DONE objType %s for %s",
				config.Key(), objType, config.DisplayName)
			return
		}
		// Fall back to normal case of recreating since we got an
		// error from the container case above.
		log.Infof("vcCreate(%s) fallback from promote to normal create objType %s for %s",
			config.Key(), objType, config.DisplayName)
	}
	status := types.VolumeStatus{
		BlobSha256:      config.BlobSha256,
		AppInstID:       config.AppInstID,
		VolumeID:        config.VolumeID,
		PurgeCounter:    config.PurgeCounter,
		DisplayName:     config.DisplayName,
		ObjType:         objType,
		Origin:          config.Origin,
		DownloadOrigin:  dos,
		TargetSizeBytes: config.TargetSizeBytes,
		ReadOnly:        config.ReadOnly,
		Format:          config.Format,
		State:           types.INITIAL,
		// XXX if these are not needed in Status they are not needed in Config
		//	DevType: config.DevType,
		//	Target: config.Target,
		RefCount: config.RefCount,
	}
	status.LastUse = time.Now()
	status.PendingAdd = true
	publishVolumeStatus(ctx, &status)
	// Ignore return value since we always publish
	doUpdate(ctx, &status)
	status.PendingAdd = false
	publishVolumeStatus(ctx, &status)
	log.Infof("vcCreate(%s) DONE objType %s for %s",
		config.Key(), objType, config.DisplayName)
}

func vcModify(ctx *volumemgrContext, objType string, key string,
	config types.VolumeConfig) {

	status := lookupVolumeStatus(ctx, objType, config.Key())
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
	publishVolumeStatus(ctx, status)
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
	publishVolumeStatus(ctx, status)
	log.Infof("vcModify(%s) DONE %s for %s",
		config.Key(), status.ObjType, status.DisplayName)
}

func vcDelete(ctx *volumemgrContext, objType string, key string,
	config types.VolumeConfig) {

	status := lookupVolumeStatus(ctx, objType, config.Key())
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
	publishVolumeStatus(ctx, status)
	doDelete(ctx, status)
	status.PendingDelete = false
	publishVolumeStatus(ctx, status)
	unpublishVolumeStatus(ctx, status)

	log.Infof("vcDelete(%s) DONE objType %s for %s",
		status.Key(), status.ObjType, status.DisplayName)

}

// Callers must be careful to publish any changes to VolumeStatus
func lookupVolumeStatus(ctx *volumemgrContext, objType string,
	key string) *types.VolumeStatus {

	pub := ctx.publication(types.VolumeStatus{}, objType)
	st, _ := pub.Get(key)
	if st == nil {
		log.Infof("lookupVolumeStatus(%s) not found", key)
		return nil
	}
	status := st.(types.VolumeStatus)
	return &status
}

func lookupVolumeConfig(ctx *volumemgrContext, objType string,
	key string) *types.VolumeConfig {

	sub := ctx.subscription(types.VolumeConfig{}, objType)
	c, _ := sub.Get(key)
	if c == nil {
		log.Infof("lookupVolumeConfig(%s) not found", key)
		return nil
	}
	config := c.(types.VolumeConfig)
	return &config
}

func publishVolumeStatus(ctx *volumemgrContext,
	status *types.VolumeStatus) {

	pub := ctx.publication(*status, status.ObjType)
	key := status.Key()
	log.Debugf("publishVolumeStatus(%s)", key)
	pub.Publish(key, *status)
}

func unpublishVolumeStatus(ctx *volumemgrContext,
	status *types.VolumeStatus) {

	pub := ctx.publication(*status, status.ObjType)
	key := status.Key()
	log.Debugf("unpublishVolumeStatus(%s)", key)
	st, _ := pub.Get(key)
	if st == nil {
		log.Errorf("unpublishVolumeStatus(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}
