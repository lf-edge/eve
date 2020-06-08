// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Returns changed
// XXX remove "done" boolean return?
func doUpdateVol(ctx *volumemgrContext, status *types.VolumeStatus) (bool, bool) {

	log.Infof("doUpdateVol(%s) name %s", status.Key(), status.DisplayName)

	// Anything to do?
	if status.State == types.CREATED_VOLUME {
		log.Infof("doUpdateVol(%s) name %s nothing to do",
			status.Key(), status.DisplayName)
		return false, true
	}
	changed := false
	switch status.VolumeContentOriginType {
	case zconfig.VolumeContentOriginType_VCOT_BLANK:
		// XXX TBD
		errStr := fmt.Sprintf("doUpdateVol(%s) name %s: Volume content origin type %v is not implemeted yet.",
			status.Key(), status.DisplayName, status.VolumeContentOriginType)
		status.SetErrorWithSource(errStr,
			types.VolumeStatus{}, time.Now())
		changed = true
		return changed, false
	case zconfig.VolumeContentOriginType_VCOT_DOWNLOAD:
		ctStatus := lookupContentTreeStatus(ctx, status.ContentID.String())
		if ctStatus == nil {
			// Content tree not available
			log.Infof("doUpdateVol(%s) name %s: waiting for content tree status %v",
				status.Key(), status.DisplayName, status.ContentID)
			return changed, false
		}
		if ctStatus.State < types.VERIFIED {
			// Waiting for content tree to be processed
			if ctStatus.HasError() {
				log.Errorf("doUpdateVol(%s) name %s: content tree status has following error %v",
					status.Key(), status.DisplayName, ctStatus.Error)
				errStr := fmt.Sprintf("Found error in content tree %s attached to volume %s: %v",
					ctStatus.DisplayName, status.DisplayName, ctStatus.Error)
				status.SetErrorWithSource(errStr,
					types.VolumeStatus{}, time.Now())
				changed = true
				return changed, false
			}
			log.Infof("doUpdateVol(%s) name %s: waiting for content tree status %v to be verified",
				status.Key(), status.DisplayName, ctStatus.DisplayName)
			return changed, false
		}
		if ctStatus.State == types.VERIFIED &&
			status.State != types.CREATING_VOLUME &&
			!status.VolumeCreated {

			status.State = types.CREATING_VOLUME
			status.FileLocation = ctStatus.FileLocation
			status.ContentFormat = ctStatus.Format
			changed = true
			// Asynch creation; ensure we have requested it
			MaybeAddWorkCreateVol(ctx, status)
		}
		if status.State == types.CREATING_VOLUME && !status.VolumeCreated {
			vr := lookupVolumeWorkResult(ctx, status.Key())
			if vr != nil {
				log.Infof("doUpdateVol: VolumeWorkResult(%s) location %s, created %t",
					status.Key(), vr.FileLocation, vr.VolumeCreated)
				deleteVolumeWorkResult(ctx, status.Key())
				if status.VolumeCreated != vr.VolumeCreated {
					log.Infof("From vr set VolumeCreated to %s for %s",
						vr.FileLocation, status.VolumeID)
					status.VolumeCreated = vr.VolumeCreated
					changed = true
				}
				if status.FileLocation != vr.FileLocation {
					log.Infof("doUpdate: From vr set FileLocation to %s for %s",
						vr.FileLocation, status.VolumeID)
					status.FileLocation = vr.FileLocation
					changed = true
				}
				if vr.Error != nil {
					status.SetErrorWithSource(vr.Error.Error(),
						types.VolumeStatus{}, vr.ErrorTime)
					changed = true
					return changed, false
				} else if status.IsErrorSource(types.VolumeStatus{}) {
					log.Infof("doUpdate: Clearing volume error %s", status.Error)
					status.ClearErrorWithSource()
					changed = true
				}
			} else {
				log.Infof("doUpdateVol: VolumeWorkResult(%s) not found", status.Key())
			}
		}
		if status.State == types.CREATING_VOLUME && status.VolumeCreated {
			if !status.HasError() {
				status.State = types.CREATED_VOLUME
			}
			changed = true
			// Work is done
			DeleteWorkCreateVol(ctx, status)
			return changed, true
		}
	default:
		// Unsupported volume content origin type
		errStr := fmt.Sprintf("doUpdateVol(%s) name %s: Volume content origin type %v not supported",
			status.Key(), status.DisplayName, status.VolumeContentOriginType)
		status.SetErrorWithSource(errStr,
			types.VolumeStatus{}, time.Now())
		changed = true
		return changed, false
	}
	return changed, false
}

// Find all the VolumeStatus which refer to this volume uuid
func updateVolumeStatus(ctx *volumemgrContext, volumeID uuid.UUID) {

	log.Infof("updateVolumeStatus for %s", volumeID)
	found := false
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.VolumeID == volumeID {
			log.Infof("Found VolumeStatus %s: name %s",
				status.Key(), status.DisplayName)
			found = true
			changed, _ := doUpdateVol(ctx, &status)
			if changed {
				publishVolumeStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateVolumeStatus(%s) NOT FOUND", volumeID)
	}
}

// Find all the VolumeStatus which refer to this content uuid
func updateVolumeStatusFromContentID(ctx *volumemgrContext, contentID uuid.UUID) {

	log.Infof("updateVolumeStatusFromContentID for %s", contentID)
	found := false
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.ContentID == contentID {
			log.Infof("Found VolumeStatus %s: name %s",
				status.Key(), status.DisplayName)
			found = true
			changed, _ := doUpdateVol(ctx, &status)
			if changed {
				publishVolumeStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateVolumeStatusFromContentID(%s) NOT FOUND", contentID)
	}
}
