// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// BlobStatus.IsIndex

func TestBlobStatusIsIndex(t *testing.T) {
	assert.True(t, BlobStatus{MediaType: "application/vnd.oci.image.index.v1+json"}.IsIndex())
	assert.True(t, BlobStatus{MediaType: "application/vnd.docker.distribution.manifest.list.v2+json"}.IsIndex())
	assert.False(t, BlobStatus{MediaType: "application/vnd.oci.image.manifest.v1+json"}.IsIndex())
	assert.False(t, BlobStatus{MediaType: ""}.IsIndex())
}

// BlobStatus.IsManifest

func TestBlobStatusIsManifest(t *testing.T) {
	assert.True(t, BlobStatus{MediaType: "application/vnd.oci.image.manifest.v1+json"}.IsManifest())
	assert.True(t, BlobStatus{MediaType: "application/vnd.docker.distribution.manifest.v1+json"}.IsManifest())
	assert.True(t, BlobStatus{MediaType: "application/vnd.docker.distribution.manifest.v2+json"}.IsManifest())
	assert.True(t, BlobStatus{MediaType: "application/vnd.docker.distribution.manifest.v1+prettyjws"}.IsManifest())
	assert.False(t, BlobStatus{MediaType: "application/vnd.oci.image.index.v1+json"}.IsManifest())
	assert.False(t, BlobStatus{MediaType: ""}.IsManifest())
}

// BlobStatus.GetDownloadedPercentage
// Note: uses integer division, so 50/100*100 = 0 (truncates before multiplying)

func TestBlobStatusGetDownloadedPercentage(t *testing.T) {
	// No sizes: returns 0
	assert.Equal(t, uint32(0), BlobStatus{}.GetDownloadedPercentage())

	// CurrentSize < TotalSize (integer division truncates to 0)
	s := BlobStatus{CurrentSize: 50, TotalSize: 100}
	assert.Equal(t, uint32(0), s.GetDownloadedPercentage())

	// Fully downloaded: 100/100*100 = 100
	s = BlobStatus{CurrentSize: 100, TotalSize: 100}
	assert.Equal(t, uint32(100), s.GetDownloadedPercentage())

	// 200 downloaded of 100 total: 200/100*100 = 200
	s = BlobStatus{CurrentSize: 200, TotalSize: 100}
	assert.Equal(t, uint32(200), s.GetDownloadedPercentage())

	// TotalSize zero: returns 0
	s = BlobStatus{CurrentSize: 50, TotalSize: 0}
	assert.Equal(t, uint32(0), s.GetDownloadedPercentage())
}
