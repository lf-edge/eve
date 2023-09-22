// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/base"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

// PatchEnvelopes is a structure
type PatchEnvelopes struct {
	sync.Mutex
	VolumeStatusCh      chan PatchEnvelopesVsCh
	PatchEnvelopeInfoCh chan []PatchEnvelopeInfo
	Wg                  sync.WaitGroup

	envelopes        []PatchEnvelopeInfo
	completedVolumes []VolumeStatus
	log              *base.LogObject
}

// PatchEnvelopesVsChAction specifies action for patch envelope volume status
type PatchEnvelopesVsChAction uint8

const (
	// PatchEnvelopesVsChActionDelete -- delete reference with volume
	PatchEnvelopesVsChActionDelete PatchEnvelopesVsChAction = iota
	// PatchEnvelopesVsChActionPut -- create or update reference with volume
	PatchEnvelopesVsChActionPut
)

// PatchEnvelopesVsCh is a wrapper for VolumeStatus specifying action
// for external Patch Envelope
type PatchEnvelopesVsCh struct {
	Vs     VolumeStatus
	Action PatchEnvelopesVsChAction
}

// NewPatchEnvelopes returns PatchEnvelopes structure
func NewPatchEnvelopes(log *base.LogObject) *PatchEnvelopes {
	pe := &PatchEnvelopes{
		VolumeStatusCh:      make(chan PatchEnvelopesVsCh),
		PatchEnvelopeInfoCh: make(chan []PatchEnvelopeInfo),

		log: log,
	}

	go pe.processMessages()

	return pe
}

// Get returns list of Patch Envelopes available for this app instance
func (pes *PatchEnvelopes) Get(appUUID string) []PatchEnvelopeInfo {
	var res []PatchEnvelopeInfo

	for _, envelope := range pes.envelopes {
		for _, allowedUUID := range envelope.AllowedApps {
			if allowedUUID == appUUID {
				res = append(res, envelope)
				break
			}
		}
	}

	return res
}

func (pes *PatchEnvelopes) processMessages() {
	for {
		select {
		case volumeStatus := <-pes.VolumeStatusCh:
			switch volumeStatus.Action {
			case PatchEnvelopesVsChActionPut:
				pes.updateExternalPatches(volumeStatus.Vs)
			case PatchEnvelopesVsChActionDelete:
				pes.deleteExternalPatches(volumeStatus.Vs)
			}
			pes.Wg.Done()
		case newPatchEnvelopeInfo := <-pes.PatchEnvelopeInfoCh:
			pes.updateEnvelopes(newPatchEnvelopeInfo)
			pes.Wg.Done()
		}
	}
}

func (pes *PatchEnvelopes) updateExternalPatches(vs VolumeStatus) {
	if vs.State != INSTALLED {
		return
	}

	pes.Lock()
	defer pes.Unlock()

	volumeExists := false
	for i := range pes.completedVolumes {
		if pes.completedVolumes[i].VolumeID == vs.VolumeID {
			pes.completedVolumes[i] = vs
			volumeExists = true
			break
		}
	}
	if !volumeExists {
		pes.completedVolumes = append(pes.completedVolumes, vs)
	}

	if err := pes.processVolumeStatus(vs); err != nil {
		pes.log.Errorf("Failed to update external patches %v", err)
	}
}

func (pes *PatchEnvelopes) deleteExternalPatches(vs VolumeStatus) {
	pes.Lock()
	defer pes.Unlock()

	i := 0
	for _, vol := range pes.completedVolumes {
		if vol.VolumeID == vs.VolumeID {
			break
		}
		i++
	}

	pes.completedVolumes[i] = pes.completedVolumes[len(pes.completedVolumes)-1]
	pes.completedVolumes = pes.completedVolumes[:len(pes.completedVolumes)-1]
}

func (pes *PatchEnvelopes) updateEnvelopes(peInfo []PatchEnvelopeInfo) {
	pes.Lock()
	defer pes.Unlock()

	pes.envelopes = peInfo
	if err := pes.processVolumeStatusList(pes.completedVolumes); err != nil {
		pes.log.Errorf("Failed to update external patches %v", err)
	}
}

func (pes *PatchEnvelopes) processVolumeStatus(vs VolumeStatus) error {
	for i := range pes.envelopes {
		for j := range pes.envelopes[i].VolumeRefs {
			volUUID, err := uuid.FromString(pes.envelopes[i].VolumeRefs[j].ImageID)
			if err != nil {
				return err
			}
			if volUUID == vs.VolumeID {
				blob, err := blobFromVolRef(pes.envelopes[i].VolumeRefs[j], vs)
				if err != nil {
					return err
				}

				if idx := CompletedBinaryBlobIdxByName(pes.envelopes[i].BinaryBlobs, blob.FileName); idx != -1 {
					pes.envelopes[i].BinaryBlobs[idx] = *blob
				} else {
					pes.envelopes[i].BinaryBlobs = append(pes.envelopes[i].BinaryBlobs, *blob)
				}
			}
		}
	}
	return nil
}

func (pes *PatchEnvelopes) processVolumeStatusList(volumeStatuses []VolumeStatus) error {
	for _, vs := range volumeStatuses {
		if err := pes.processVolumeStatus(vs); err != nil {
			return err
		}
	}
	return nil
}

func blobFromVolRef(vr BinaryBlobVolumeRef, vs VolumeStatus) (*BinaryBlobCompleted, error) {
	sha, err := fileutils.ComputeShaFile(vs.FileLocation)
	if err != nil {
		return nil, err
	}
	return &BinaryBlobCompleted{
		FileName:     vr.FileName,
		FileMetadata: vr.FileMetadata,
		FileSha:      fmt.Sprintf("%x", sha),
		URL:          vs.FileLocation,
	}, nil
}

// PatchEnvelopeInfo - information
// about patch envelopes
type PatchEnvelopeInfo struct {
	AllowedApps []string
	PatchID     string
	BinaryBlobs []BinaryBlobCompleted
	VolumeRefs  []BinaryBlobVolumeRef
}

// PatchEnvelopeInfoKey returns key for pubsub
func PatchEnvelopeInfoKey() string {
	return "zedagent"
}

// since we use json in pubsub we cannot use json - tag
// and therefore we need some representational structure
// for PatchEnvelopeInfo.
type peInfoToDisplay struct {
	PatchID     string
	BinaryBlobs []BinaryBlobCompleted
	VolumeRefs  []BinaryBlobVolumeRef
}

// PatchEnvelopesJSONForAppInstance returns json representation
// of Patch Envelopes list which are shown to app instances
func PatchEnvelopesJSONForAppInstance(pe []PatchEnvelopeInfo) ([]byte, error) {
	toDisplay := make([]peInfoToDisplay, len(pe))

	for i, envelope := range pe {
		toDisplay[i] = peInfoToDisplay{
			PatchID:     envelope.PatchID,
			BinaryBlobs: envelope.BinaryBlobs,
			VolumeRefs:  envelope.VolumeRefs,
		}
	}

	return json.Marshal(toDisplay)
}

// FindPatchEnvelopesByApp returns PatchEnvelopeInfo which are allowed to certain app instance
func FindPatchEnvelopesByApp(pe []PatchEnvelopeInfo, appUUID string) []PatchEnvelopeInfo {
	var res []PatchEnvelopeInfo

	for _, envelope := range pe {
		for _, allowedUUID := range envelope.AllowedApps {
			if allowedUUID == appUUID {
				res = append(res, envelope)
				break
			}
		}
	}

	return res
}

// FindPatchEnvelopeByID returns patch envelope with given patchId
func FindPatchEnvelopeByID(pe []PatchEnvelopeInfo, patchID string) *PatchEnvelopeInfo {
	for _, pe := range pe {
		if pe.PatchID == patchID {
			return &pe
		}
	}
	return nil
}

// BinaryBlobCompleted is representation of
// binary blob ready to be downloaded by app instance
type BinaryBlobCompleted struct {
	FileName     string `json:"fileName"`
	FileSha      string `json:"fileSha"`
	FileMetadata string `json:"fileMetaData"`
	URL          string `json:"url"` //nolint:var-naming
}

// CompletedBinaryBlobIdxByName returns index of element in blobs list
// which FileName matches name
func CompletedBinaryBlobIdxByName(blobs []BinaryBlobCompleted, name string) int {
	for i := range blobs {
		if blobs[i].FileName == name {
			return i
		}
	}
	return -1
}

// BinaryBlobVolumeRef is representation of
// external binary blobs, which has not yet been
// downloaded
type BinaryBlobVolumeRef struct {
	FileName     string `json:"fileName"`
	ImageName    string `json:"imageName"`
	FileMetadata string `json:"fileMetaData"`
	ImageID      string `json:"imageId"`
}
