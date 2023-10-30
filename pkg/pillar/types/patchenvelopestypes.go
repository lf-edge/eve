// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

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
	Name        string
	Version     string
	AllowedApps []string
	PatchID     string
	Errors      []string
	State       PatchEnvelopeState
	BinaryBlobs []BinaryBlobCompleted
	VolumeRefs  []BinaryBlobVolumeRef
}

// Size returns sum of all sizes of BinaryBlobs of given PatchEnvelope
func (pe *PatchEnvelopeInfo) Size() (size int64) {
	for _, blob := range pe.BinaryBlobs {
		size += blob.Size
	}
	return
}

// PatchEnvelopeState repeats constants from patch_envelope.pb.go from info API
type PatchEnvelopeState int32

const (
	// PatchEnvelopeStateError - there is an error with config or during download
	// or verification failed
	PatchEnvelopeStateError PatchEnvelopeState = iota
	// PatchEnvelopeStateRecieved - configuration received but no downloads started
	PatchEnvelopeStateRecieved
	// PatchEnvelopeStateDownloading - artifact/Volume download started
	// One or more of the artifacts are being downloaded
	PatchEnvelopeStateDownloading
	// PatchEnvelopeStateDownloaded - all downloads finished, verified and added to content tree
	PatchEnvelopeStateDownloaded
	// PatchEnvelopeStateReady - patch envelope ready for application instances
	// application instances will still not be
	// allowed to fetch the patch envelope contents
	PatchEnvelopeStateReady
	// PatchEnvelopeStateActive - application instances are now allowed to fetch contents
	PatchEnvelopeStateActive
)

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
	FileName string `json:"fileName"`
	FileSha  string `json:"fileSha"`
	// FileMetadata is related to file, i.e. env variables, cli arguments
	FileMetadata string `json:"fileMetaData"`
	// ArtifactMetadata is generic info i.e. user info, desc etc.
	ArtifactMetadata string `json:"artifactMetaData"`
	URL              string `json:"url"` //nolint:var-naming
	Size             int64  `json:"size"`
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
	FileName  string `json:"fileName"`
	ImageName string `json:"imageName"`
	// FileMetadata is related to file, i.e. env variables, cli arguments
	FileMetadata string `json:"fileMetaData"`
	// ArtifactMetadata is generic info i.e. user info, desc etc.
	ArtifactMetadata string `json:"artifactMetaData"`
	ImageID          string `json:"imageId"`
}
