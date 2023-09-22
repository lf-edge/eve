// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
)

// PatchEnvelopeInfoList will be shared with zedrouter after parsing
// in zedagent
type PatchEnvelopeInfoList struct {
	Envelopes []PatchEnvelopeInfo
}

// Get returns list of patch envelopes, which are available to appUUID
func (pe *PatchEnvelopeInfoList) Get(appUUID string) PatchEnvelopeInfoList {
	var result []PatchEnvelopeInfo

	for _, envelope := range pe.Envelopes {
		for _, allowedUUID := range envelope.AllowedApps {
			if allowedUUID == appUUID {
				result = append(result, envelope)
				break
			}
		}
	}

	return PatchEnvelopeInfoList{
		Envelopes: result,
	}
}

// PatchEnvelopeInfo - information
// about patch envelopes
type PatchEnvelopeInfo struct {
	AllowedApps []string
	PatchID     string
	BinaryBlobs []BinaryBlobCompleted
	VolumeRefs  []BinaryBlobVolumeRef
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
func PatchEnvelopesJSONForAppInstance(pe PatchEnvelopeInfoList) ([]byte, error) {
	toDisplay := make([]peInfoToDisplay, len(pe.Envelopes))

	for i, envelope := range pe.Envelopes {
		toDisplay[i] = peInfoToDisplay{
			PatchID:     envelope.PatchID,
			BinaryBlobs: envelope.BinaryBlobs,
			VolumeRefs:  envelope.VolumeRefs,
		}
	}

	return json.Marshal(toDisplay)
}

// Key for pubsub
func (pe *PatchEnvelopeInfoList) Key() string {
	return "global"
}

// FindPatchEnvelopeByID returns patch envelope with given patchId
func (pe *PatchEnvelopeInfoList) FindPatchEnvelopeByID(patchID string) *PatchEnvelopeInfo {
	for _, pe := range pe.Envelopes {
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
