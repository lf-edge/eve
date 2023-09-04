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

// PatchEnvelopes is a wrapper
// to send patch envelopes
type PatchEnvelopes struct {
	Envelopes []PatchEnvelopeInfo
}

// Get returns list of patch envelopes, which are available to appUuid
func (pe *PatchEnvelopes) Get(appUuid string) []PatchEnvelopeInfo {
	var res []PatchEnvelopeInfo

	for _, envelope := range pe.Envelopes {
		for _, allowedUuid := range envelope.AllowedApps {
			if allowedUuid == appUuid {
				res = append(res, envelope)
				break
			}
		}
	}

	return res
}

// Key for pubsub
func (PatchEnvelopes) Key() string {
	return "zedagent"
}

// PatchEnvelopeInfo - information
// about patch envelopes
type PatchEnvelopeInfo struct {
	AllowedApps []string
	PatchId     string
	BinaryBlobs []BinaryBlobCompleted
	VolumeRefs  []BinaryBlobVolumeRef
}

// since we use json in pubsub we cannot use json - tag
// and therefore we need some representational structure
// for PatchEnvelopeInfo.
type peInfoToDisplay struct {
	PatchId     string
	BinaryBlobs []BinaryBlobCompleted
	VolumeRefs  []BinaryBlobVolumeRef
}

// MarshalPatchEnvelopesForAppInstance returns json representation
// of Patch Envelopes list which are shown to app instances
func PatchEnvelopesJsonForAppInstance(pe []PatchEnvelopeInfo) ([]byte, error) {
	toDisplay := make([]peInfoToDisplay, len(pe))

	for i, envelope := range pe {
		toDisplay[i] = peInfoToDisplay{
			PatchId:     envelope.PatchId,
			BinaryBlobs: envelope.BinaryBlobs,
			VolumeRefs:  envelope.VolumeRefs,
		}
	}

	return json.Marshal(toDisplay)
}

// FindPatchEnvelopeById returns patch envelope with given patchId
func FindPatchEnvelopeById(pe []PatchEnvelopeInfo, patchId string) *PatchEnvelopeInfo {
	for _, pe := range pe {
		if pe.PatchId == patchId {
			return &pe
		}
	}
	return nil
}

// GetZipArchive archives list of patch envelopes in a given path and returns
// full path to zip archive
func GetZipArchive(root string, pe PatchEnvelopeInfo) (string, error) {
	zipFilename := filepath.Join(root, pe.PatchId+".zip")
	zipFile, err := os.Create(zipFilename)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, b := range pe.BinaryBlobs {
		// We only want to archive binary blobs which are ready
		file, err := os.Open(b.Url)
		if err != nil {
			return "", err
		}
		defer file.Close()

		baseName := filepath.Base(b.Url)
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
	FileName     string `json:"file-name"`
	FileSha      string `json:"file-sha"`
	FileMetadata string `json:"file-meta-data"`
	Url          string `json:"url"`
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
	FileName     string `json:"file-name"`
	ImageName    string `json:"image-name"`
	FileMetadata string `json:"file-meta-data"`
	ImageId      string `json:"image-id"`
}
