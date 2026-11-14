// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"reflect"
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
	Name        string
	Version     string
	AllowedApps []string
	PatchID     string
	Errors      []string
	State       PatchEnvelopeState
	BinaryBlobs []BinaryBlobCompleted
	VolumeRefs  []BinaryBlobVolumeRef
	CipherBlobs []BinaryCipherBlob
}

// Size returns sum of all sizes of BinaryBlobs of given PatchEnvelope
func (pe *PatchEnvelopeInfo) Size() (size int64) {
	for _, blob := range pe.BinaryBlobs {
		size += blob.Size
	}
	return
}

// Key for pubsub
func (pe *PatchEnvelopeInfo) Key() string {
	return pe.PatchID + "v" + pe.Version
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
	// Encrypted ArtifactMetadata for blob
	EncArtifactMeta CipherBlockStatus `json:"encArtifactMeta"`
	URL             string            `json:"url"` //nolint:var-naming
	Size            int64             `json:"size"`
}

// MarshalJSON is used to customize the JSON output for BinaryBlobCompleted
// The blob structures are also used in the return of json formatted
// patchenvelope description request. This is to suppress the
// CipherBlockStatus cipher structure items detail when displaying.
// Implement the json.Marshaler interface for BinaryBlobCompleted
func (b BinaryBlobCompleted) MarshalJSON() ([]byte, error) {
	return marshalWithCustomLogic(b)
}

// MarshalJSON is used to customize the JSON output for BinaryBlobVolumeRef
// Implement the json.Marshaler interface for BinaryBlobVolumeRef
func (b BinaryBlobVolumeRef) MarshalJSON() ([]byte, error) {
	return marshalWithCustomLogic(b)
}

// MarshalJSON is used to customize the JSON output for BinaryCipherBlob
// Implement the json.Marshaler interface for BinaryBlobVolumeRef
func (b BinaryCipherBlob) MarshalJSON() ([]byte, error) {
	return marshalWithCustomLogic(b)
}

// Generic marshal function with custom logic
func marshalWithCustomLogic(v interface{}) ([]byte, error) {
	val := reflect.ValueOf(v)
	typ := reflect.TypeOf(v)

	// Create a map to hold the JSON representation
	m := make(map[string]interface{})

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		fieldName := fieldType.Tag.Get("json")

		if fieldName == "" {
			fieldName = fieldType.Name
		}

		if fieldName == "encArtifactMeta" {
			if isEmpty(field.Interface()) {
				m[fieldName] = struct{}{}
			} else {
				m[fieldName] = field.Interface()
			}
		} else {
			m[fieldName] = field.Interface()
		}
	}

	return json.Marshal(m)
}

// isEmpty checks if a struct is empty using reflection
func isEmpty(v interface{}) bool {
	return reflect.DeepEqual(v, reflect.Zero(reflect.TypeOf(v)).Interface())
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

// CompletedCipherBlobIdxByName returns index of element in blobs list
// which FileName matches name
func CompletedCipherBlobIdxByName(blobs []BinaryCipherBlob, name string) int {
	for i := range blobs {
		if blobs[i].Inline != nil && blobs[i].Inline.FileName == name {
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
	// Encrypted ArtifactMetadata for blob
	EncArtifactMeta CipherBlockStatus `json:"encArtifactMeta"`
	ImageID         string            `json:"imageId"`
}

// PatchEnvelopeUsage stores information on how patchEnvelopes are
// used by App Instances to send this information back to controller
// reflects ZInfoPatchEnvelopeUsage proto message
type PatchEnvelopeUsage struct {
	AppUUID string
	PatchID string
	Version string
	// count the number of times app instance called patch APIs
	PatchAPICallCount uint64
	// count the number of times app instance actually downloaded
	// whole patch envelope or part of it
	DownloadCount uint64
}

// Key for pubsub
func (pe *PatchEnvelopeUsage) Key() string {
	return "patchEnvelopeUsage:" + pe.PatchID +
		"-v-" + pe.Version +
		"-app-" + pe.AppUUID
}

// PatchEnvelopeUsageFromInfo returns PatchEnvelopeUsage structure from
// PatchEnvelopeInfo struct
func PatchEnvelopeUsageFromInfo(peInfo PatchEnvelopeInfo) []PatchEnvelopeUsage {
	result := make([]PatchEnvelopeUsage, 0, len(peInfo.AllowedApps))

	for _, appUUID := range peInfo.AllowedApps {
		usage := PatchEnvelopeUsage{
			AppUUID: appUUID,
			PatchID: peInfo.PatchID,
			Version: peInfo.Version,
		}
		result = append(result, usage)
	}

	return result
}

// BlobEncrytedType - type of encrypted Binary blob
type BlobEncrytedType int8

const (
	// BlobEncrytedTypeNone - no encryption
	BlobEncrytedTypeNone BlobEncrytedType = iota
	// BlobEncrytedTypeInline - inline encryption
	BlobEncrytedTypeInline
	// BlobEncrytedTypeVolume - volume encryption
	BlobEncrytedTypeVolume
)

// BinaryCipherBlob is encrypted binary blob for Binary Artifact
type BinaryCipherBlob struct {
	// EncType is type of encryption
	EncType BlobEncrytedType `json:"encType"`
	// ArtifactMetadata is generic info i.e. user info, desc etc.
	ArtifactMetaData string `json:"artifactMetaData"`
	// Encrypted ArtifactMetadata for blob
	EncArtifactMeta CipherBlockStatus `json:"encArtifactMeta"`
	// EncURL is URL to download encrypted binary blob in CipherBlockStatus format
	// which contains either ONEOF inline or volume encrypted data
	EncURL string `json:"encURL"`
	// EncFileName is file name of the encrypted binary blob
	EncFileName string `json:"encFileName"`
	// Inline - used for post decrypt inline binary blob
	Inline *BinaryBlobCompleted `json:"inline"`
	// Volume - used for post decrypt volume binary blob
	Volume *BinaryBlobVolumeRef `json:"volume"`
}
