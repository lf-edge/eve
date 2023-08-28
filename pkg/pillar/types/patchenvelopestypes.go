// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

type PatchEnvelopes struct {
	AppsToEnvelopes map[string][]PatchEnvelopeInfo
}

// Key for pubsub
func (PatchEnvelopes) Key() string {
	return "zedagent"
}

// PatchEnvelopeInfo - information
// about patch envelopes
type PatchEnvelopeInfo struct {
	PatchId     string       `json:"patch-id"`
	BinaryBlobs []BinaryBlob `json:"binary-blobs"`
}

// BinaryBlob stores infromation about
// all files related to PatchEnvelope
type BinaryBlob struct {
	FileName     string `json:"file-name"`
	FileSha      string `json:"file-sha"`
	FileMetadata string `json:"file-meta-data"`
	Url          string `json:"url"`
}

func NewPatchEnvelopes() *PatchEnvelopes {
	pe := &PatchEnvelopes{}
	pe.AppsToEnvelopes = make(map[string][]PatchEnvelopeInfo)

	return pe
}

func (pe *PatchEnvelopes) Add(peInfo PatchEnvelopeInfo, allowedApps []string) error {
	for _, app := range allowedApps {
		pe.AppsToEnvelopes[app] = append(pe.AppsToEnvelopes[app], peInfo)
	}
	return nil
}

func (pe PatchEnvelopes) Get(appUuid string) []PatchEnvelopeInfo {
	return pe.AppsToEnvelopes[appUuid]
}
