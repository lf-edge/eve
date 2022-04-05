// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

//PartDefinition keeps information about one part
type PartDefinition struct {
	Ind  int64 `json:"i"` // index of part
	Size int64 `json:"s"` // current size of part
}

// DownloadedParts keeps information about downloaded parts of blob
type DownloadedParts struct {
	PartSize int64             // the maximum partition size
	Parts    []*PartDefinition // definition of downloaded parts
}

// Hash returns hash of DownloadedParts struct
func (dp *DownloadedParts) Hash() string {
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	err := encoder.Encode(dp)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hash.Sum(nil))
}

//SetPartSize search for ind in DownloadedParts and set its size.
//If not found, append parts with ind and size
func (dp *DownloadedParts) SetPartSize(ind, size int64) {
	for _, p := range dp.Parts {
		if p.Ind == ind {
			p.Size = size
			return
		}
	}
	dp.Parts = append(dp.Parts, &PartDefinition{Ind: ind, Size: size})
}
