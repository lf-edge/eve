// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// PatchEnvelopeInfoList is a wrapper
// to send patch envelopes
type PatchEnvelopeInfoList struct {
	Envelopes []PatchEnvelopeInfo
}

// Get returns list of patch envelopes, which are available to appUUID
func (pe *PatchEnvelopeInfoList) Get(appUUID string) []PatchEnvelopeInfo {
	var res []PatchEnvelopeInfo

	for _, envelope := range pe.Envelopes {
		for _, allowedUUID := range envelope.AllowedApps {
			if allowedUUID == appUUID {
				res = append(res, envelope)
				break
			}
		}
	}

	return res
}

// Key for pubsub
func (PatchEnvelopeInfoList) Key() string {
	return "zedagent"
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

// FindPatchEnvelopeByID returns patch envelope with given patchId
func FindPatchEnvelopeByID(pe []PatchEnvelopeInfo, patchID string) *PatchEnvelopeInfo {
	for _, pe := range pe {
		if pe.PatchID == patchID {
			return &pe
		}
	}
	return nil
}

// GetZipArchive archives list of patch envelopes in a given path and returns
// full path to zip archive
func GetZipArchive(root string, pe PatchEnvelopeInfo) (string, error) {
	zipFilename := filepath.Join(root, pe.PatchID+".zip")
	zipFile, err := os.Create(zipFilename)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, b := range pe.BinaryBlobs {
		// We only want to archive binary blobs which are ready
		file, err := os.Open(b.URL)
		if err != nil {
			return "", err
		}
		defer file.Close()

		baseName := filepath.Base(b.URL)
		zipEntry, err := zipWriter.Create(baseName)
		if err != nil {
			return "", err
		}

		_, err = io.Copy(zipEntry, file)
		if err != nil {
			return "", err
		}

	}

	return zipFilename, nil
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
