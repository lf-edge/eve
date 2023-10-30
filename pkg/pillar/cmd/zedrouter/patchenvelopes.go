// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"encoding/json"
	"fmt"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// PatchEnvelopes is a structure representing
// Patch Envelopes exposed to App instances via metadata server
// for more info check docs/PATCH-ENVELOPES.md
// Must be created by calling NewPatchEnvelopes()
//
// Internally, PatchEnvelopes structure stores envelopes which
// come from EdgeDevConfig parsed by zedagent. This envelopes contains
// both inline binary artifacts which are ready to be downloaded by app instances
// and volume references, which are handled by volumemgr.
// So PatchEnvelopes struct has completedVolumes and contentTreeStatus to store
// information of all volumes and contentTree handled by volumemgr to link them with
// patch envelope volume references. ContentTreeStatus is used to retrieve SHA of underlying
// file.
// App instances are accessing PatchEnvelopes via metadata server handlers, which is calling
// PatchEnvelopes.Get() method to get list of available PatchEnvelopeInfo
// to certain App Instance which are stored in currentState.
// PatchEnvelopes also hasupdateStateNotificationCh channel
// to receive notification about the need of updating specified PatchEnvelopes.
// Those updates are written in envelopesToUpdate and envelopesToDelete boolean maps, that
// means that request to update same object will be only once, so there will be no queue of
// go routines piling up but it will take more CPU time to process it.
// NewPatchEnvelopes() starts goroutine processStateUpdate() which reads from the channel and updates
// currentState to desired one.
// This way handlers can do work of determining which patch envelopes actually need change (if any)
// and send back in go routine rest of the update including slow work.
// Note that this channels are only accessible from the outside by calling a function which returns
// write-only channel, meaning that updateStateNotificationCh should not be
// read from anywhere except processStateUpdate() so that there could not be any deadlock.
type PatchEnvelopes struct {
	updateStateNotificationCh chan struct{}

	envelopesToUpdate *generics.LockedMap[uuid.UUID, bool]
	envelopesToDelete *generics.LockedMap[uuid.UUID, bool]

	currentState      *generics.LockedMap[uuid.UUID, types.PatchEnvelopeInfo]
	envelopes         *generics.LockedMap[uuid.UUID, types.PatchEnvelopeInfo]
	completedVolumes  *generics.LockedMap[uuid.UUID, types.VolumeStatus]
	contentTreeStatus *generics.LockedMap[uuid.UUID, types.ContentTreeStatus]

	log *base.LogObject
}

// UpdateStateNotificationCh return update channel to send notifications to update currentState
func (pes *PatchEnvelopes) UpdateStateNotificationCh() chan<- struct{} {
	return pes.updateStateNotificationCh
}

// NewPatchEnvelopes returns PatchEnvelopes structure and starts goroutine
// to process messages from channels. Note that we create buffered channels
// to avoid unbounded processing time in writing to channel
func NewPatchEnvelopes(log *base.LogObject) *PatchEnvelopes {
	pe := &PatchEnvelopes{

		updateStateNotificationCh: make(chan struct{}, 1),

		envelopesToUpdate: generics.NewLockedMap[uuid.UUID, bool](),
		envelopesToDelete: generics.NewLockedMap[uuid.UUID, bool](),

		currentState:      generics.NewLockedMap[uuid.UUID, types.PatchEnvelopeInfo](),
		envelopes:         generics.NewLockedMap[uuid.UUID, types.PatchEnvelopeInfo](),
		completedVolumes:  generics.NewLockedMap[uuid.UUID, types.VolumeStatus](),
		contentTreeStatus: generics.NewLockedMap[uuid.UUID, types.ContentTreeStatus](),

		log: log,
	}

	go pe.processStateUpdate()

	return pe
}

func (pes *PatchEnvelopes) processStateUpdate() {
	for {
		select {
		case <-pes.updateStateNotificationCh:
			pes.updateState()
		}
	}
}

func (pes *PatchEnvelopes) updateState() {
	keys := pes.envelopesToDelete.Keys()
	for _, k := range keys {
		if toDelete, _ := pes.envelopesToDelete.Load(k); toDelete {
			pes.currentState.Delete(k)
			pes.envelopesToDelete.Store(k, false)
		}
	}

	keys = pes.envelopesToUpdate.Keys()
	for _, peUUID := range keys {
		if needsUpdate, _ := pes.envelopesToUpdate.Load(peUUID); needsUpdate {
			if peInfo, ok := pes.envelopes.Load(peUUID); ok {
				pes.currentState.Store(peUUID, peInfo)

				if pe, ok := pes.currentState.Load(peUUID); ok {
					peState := types.PatchEnvelopeStateActive
					for _, volRef := range pe.VolumeRefs {
						if blob, blobState := pes.blobFromVolumeRef(volRef); blob != nil {
							if blobState < peState {
								peState = blobState
							}
							if idx := types.CompletedBinaryBlobIdxByName(pe.BinaryBlobs, blob.FileName); idx != -1 {
								pe.BinaryBlobs[idx] = *blob
							} else {
								pe.BinaryBlobs = append(pe.BinaryBlobs, *blob)
							}
						}
					}

					if len(pe.Errors) > 0 {
						peState = types.PatchEnvelopeStateError
					}

					pe.State = peState
					pes.currentState.Store(peUUID, pe)
					pes.envelopesToUpdate.Store(peUUID, false)

				} else {
					pes.log.Errorf("No entry in currentState for %v to update", peUUID)
				}
			} else {
				pes.log.Errorf("No entry in envelopes for %v to fetch", peUUID)
			}
		}
	}
}

// Get returns list of Patch Envelopes available for this app instance
func (pes *PatchEnvelopes) Get(appUUID string) types.PatchEnvelopeInfoList {
	var res []types.PatchEnvelopeInfo
	pes.currentState.Range(func(patchEnvelopeUUID uuid.UUID, envelope types.PatchEnvelopeInfo) bool {
		for _, allowedUUID := range envelope.AllowedApps {
			if allowedUUID == appUUID {
				res = append(res, envelope)
				break
			}
		}
		return true
	})

	return types.PatchEnvelopeInfoList{
		Envelopes: res,
	}
}

func (pes *PatchEnvelopes) blobFromVolumeRef(vr types.BinaryBlobVolumeRef) (*types.BinaryBlobCompleted, types.PatchEnvelopeState) {
	volUUID, err := uuid.FromString(vr.ImageID)
	if err != nil {
		pes.log.Errorf("Failed to compose volUUID from string %v", err)
		return nil, types.PatchEnvelopeStateError
	}
	state := types.PatchEnvelopeStateRecieved
	if vs, hasVs := pes.completedVolumes.Load(volUUID); hasVs {
		state = types.PatchEnvelopeStateDownloading
		result := &types.BinaryBlobCompleted{
			FileName:         vr.FileName,
			FileMetadata:     vr.FileMetadata,
			ArtifactMetadata: vr.ArtifactMetadata,
			URL:              vs.FileLocation,
			Size:             vs.TotalSize,
		}

		if ct, hasCt := pes.contentTreeStatus.Load(vs.ContentID); hasCt {
			state = types.PatchEnvelopeStateActive
			result.FileSha = ct.ContentSha256
		}

		return result, state
	}

	return nil, state
}

// UpdateVolumeStatus adds or removes VolumeStatus from PatchEnvelopes structure
func (pes *PatchEnvelopes) UpdateVolumeStatus(vs types.VolumeStatus, deleteVolume bool) {
	if deleteVolume {
		pes.completedVolumes.Delete(vs.VolumeID)
	} else {
		if vs.State < types.CREATED_VOLUME {
			return
		}
		pes.completedVolumes.Store(vs.VolumeID, vs)
	}
	pes.affectedByVolumeStatus(vs)
}

// affectedByVolumeStatus fills in envelopesToUpdate map marking PatchEnvelopes
// which need to be updated
func (pes *PatchEnvelopes) affectedByVolumeStatus(vs types.VolumeStatus) {
	UUIDList := pes.envelopes.Keys()

	for _, UUID := range UUIDList {
		if pe, ok := pes.envelopes.Load(UUID); ok {
			for _, volRef := range pe.VolumeRefs {
				volUUID, err := uuid.FromString(volRef.ImageID)
				if err != nil {
					pes.log.Errorf("Failed to compose volUUID from string %v", err)
					continue
				}
				if vs.VolumeID == volUUID {
					pes.envelopesToUpdate.Store(UUID, true)
				}
			}
		} else {
			pes.log.Errorf("No %v UUID in envelopes to check in affectedByVolumeStatus", UUID)
		}
	}
}

// UpdateEnvelopes sets pes.envelopes and marks envelopes that are not
// present in new peInfo as ones to be deleted and updates the rest of them
// all of the updates will happen after notification to updateStateNotificationCh
// will be sent
func (pes *PatchEnvelopes) UpdateEnvelopes(peInfo []types.PatchEnvelopeInfo) {

	before := pes.envelopes.Keys()

	envelopes := generics.NewLockedMap[uuid.UUID, types.PatchEnvelopeInfo]()

	for _, pe := range peInfo {
		peUUID, err := uuid.FromString(pe.PatchID)
		if err != nil {
			pes.log.Errorf("Failed to Update Envelopes :%v", err)
		}
		envelopes.Store(peUUID, pe)
	}

	toUpdate := envelopes.Keys()

	toDelete, _ := generics.DiffSets(before, toUpdate)

	pes.envelopes = envelopes

	for _, deleteUUID := range toDelete {
		pes.envelopesToDelete.Store(deleteUUID, true)
	}

	for _, updateUUID := range toUpdate {
		pes.envelopesToUpdate.Store(updateUUID, true)
	}
}

// UpdateContentTree adds or removes ContentTreeStatus from PatchEnvelopes structure
// marks PatchEnvelopes which will require update. Update will happen explicitly
// after sending notification to updateStateNotificationCh
func (pes *PatchEnvelopes) UpdateContentTree(ct types.ContentTreeStatus, deleteCt bool) {
	if deleteCt {
		pes.contentTreeStatus.Delete(ct.ContentID)
	} else {
		pes.contentTreeStatus.Store(ct.ContentID, ct)
	}

	pes.affectedByContentTree(ct)
}

// affectedByContentTree fills in envelopesToUpdate map marking PatchEnvelopes
// which will require update because they are linked to ContentTreeStatus specified
func (pes *PatchEnvelopes) affectedByContentTree(ct types.ContentTreeStatus) {
	UUIDList := pes.completedVolumes.Keys()

	for _, UUID := range UUIDList {
		if vs, ok := pes.completedVolumes.Load(UUID); ok {
			if vs.ContentID == ct.ContentID {
				pes.affectedByVolumeStatus(vs)
			}
		} else {
			pes.log.Errorf("affectedByContentTree: no %v found in completedVolumes", UUID)
		}
	}
}

// PatchEnvelopeInfo contains fields that we don't want to expose to app instance (like AllowedApps), so we use
// peInfoToDisplay and patchEnvelopesJSONFOrAppInstance to marshal PatchEnvelopeInfoList in a format, which is
// suitable for app instance.
// We cannot use json:"-" structure tag to omit AllowedApps from json marshaling since we use PatchEnvelopeInfo between
// zedagent and zedrouter to communicate new PatchEnvelopes from EdgeDevConfig. This communication is done via pubSub,
// which uses json marshaling to communicate structures between processes. And using json:"-" will make AllowedApps "magically"
// disappear on zedrouter
type peInfoToDisplay struct {
	PatchID     string
	BinaryBlobs []types.BinaryBlobCompleted
	VolumeRefs  []types.BinaryBlobVolumeRef
}

// patchEnvelopesJSONForAppInstance returns json representation
// of Patch Envelopes list which are shown to app instances
func patchEnvelopesJSONForAppInstance(pe types.PatchEnvelopeInfoList) ([]byte, error) {
	toDisplay := make([]peInfoToDisplay, len(pe.Envelopes))

	for i, envelope := range pe.Envelopes {

		var binaryBlobs []types.BinaryBlobCompleted
		binaryBlobs = nil
		if envelope.BinaryBlobs != nil {
			binaryBlobs = make([]types.BinaryBlobCompleted, len(envelope.BinaryBlobs))
			copy(binaryBlobs, envelope.BinaryBlobs)
		}

		for j := range binaryBlobs {
			url := fmt.Sprintf("http://%s%sdownload/%s/%s", MetaDataServerIP, PatchEnvelopeURLPath, envelope.PatchID, binaryBlobs[j].FileName)
			binaryBlobs[j].URL = url
		}

		toDisplay[i] = peInfoToDisplay{
			PatchID:     envelope.PatchID,
			BinaryBlobs: binaryBlobs,
			VolumeRefs:  envelope.VolumeRefs,
		}
	}

	return json.Marshal(toDisplay)
}
