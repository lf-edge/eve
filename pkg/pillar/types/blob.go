// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
)

// BlobStatus status of a downloaded blob
type BlobStatus struct {
	// DatastoreIDList list of datastores where the blob can be retrieved
	DatastoreIDList []uuid.UUID
	// RelativeURL URL relative to the root of the datastore
	RelativeURL string
	// Sha256 the sha of the blob
	Sha256 string
	// Size size of the expected download
	Size uint64
	// Path where this blob can be retrieved. This changes based on the state, e.g. after download
	// in one place, after verify might be another
	Path string
	// Content for short blobs, the content itself may be in memory and not in a Path.
	// Used *only* when this has data and Path is ""
	Content []byte
	// State of download of this blob; only supports: INITIAL, DOWNLOADING, DOWNLOADED, VERIFYING, VERIFIED
	State      SwState
	CreateTime time.Time
	// MediaType the actual media type string for this blob
	MediaType string
	// HasDownloaderRef whether or not we have started a downloader for this blob
	HasDownloaderRef bool
	// HasVerifierRef whether or not we have started a verifier for this blob
	HasVerifierRef bool
	// RefCount number of consumers referring this object
	RefCount               uint
	LastRefCountChangeTime time.Time
	TotalSize              int64 // expected size as reported by the downloader, if any
	CurrentSize            int64 // current total downloaded size as reported by the downloader
	// Progress percentage downloaded 0-100, defined by CurrentSize/TotalSize
	Progress uint
	// ErrorAndTimeWithSource provide common error handling capabilities
	ErrorAndTimeWithSource
}

// Key returns the pubsub Key.
func (status BlobStatus) Key() string {
	return status.Sha256
}

// IsIndex is this an index.
func (status BlobStatus) IsIndex() bool {
	switch v1types.MediaType(status.MediaType) {
	case v1types.OCIImageIndex, v1types.DockerManifestList:
		return true
	default:
		return false
	}
}

// IsManifest is this a manifest.
func (status BlobStatus) IsManifest() bool {
	switch v1types.MediaType(status.MediaType) {
	case v1types.OCIManifestSchema1, v1types.DockerManifestSchema1, v1types.DockerManifestSchema2, v1types.DockerManifestSchema1Signed:
		return true
	default:
		return false
	}
}

// LogCreate :
func (status BlobStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.BlobStatusLogType, status.RelativeURL,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}

	uuids := strings.Join(UuidsToStrings(status.DatastoreIDList), ",")

	logObject.CloneAndAddField("state", status.State.String()).
		AddField("datastoreid-uuids", uuids).
		AddField("size-int64", status.Size).
		AddField("blobtype-string", status.MediaType).
		AddField("refcount-int64", status.RefCount).
		AddField("has-verifier-ref-bool", status.HasVerifierRef).
		AddField("has-downloader-ref-bool", status.HasDownloaderRef).
		Noticef("Blob status create")
}

// LogModify :
func (status BlobStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.BlobStatusLogType, status.RelativeURL,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(BlobStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of BlobStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.RefCount != status.RefCount ||
		oldStatus.Size != status.Size {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("refcount-int64", status.RefCount).
			AddField("size-int64", status.Size).
			AddField("has-verifier-ref-bool", status.HasVerifierRef).
			AddField("has-downloader-ref-bool", status.HasDownloaderRef).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-refcount-int64", oldStatus.RefCount).
			AddField("old-size-int64", oldStatus.Size).
			AddField("old-has-verifier-ref-bool", oldStatus.HasVerifierRef).
			AddField("old-has-downloader-ref-bool", oldStatus.HasDownloaderRef).
			Noticef("Blob status modify")
	} else {
		// XXX remove?
		logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
			Noticef("Blob status modify other change")
	}

	if status.HasError() {
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("error", status.Error).
			AddField("error-time", status.ErrorTime).
			Noticef("Blob status modify")
	}
}

// LogDelete :
func (status BlobStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.BlobStatusLogType, status.RelativeURL,
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		AddField("has-verifier-ref-bool", status.HasVerifierRef).
		AddField("has-downloader-ref-bool", status.HasDownloaderRef).
		Noticef("Blob status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status BlobStatus) LogKey() string {
	return string(base.BlobStatusLogType) + "-" + status.Key()
}

// GetDownloadedPercentage returns blob's downloaded %
func (status BlobStatus) GetDownloadedPercentage() uint32 {
	if status.CurrentSize > 0 && status.TotalSize > 0 {
		return uint32((status.CurrentSize / status.TotalSize) * 100)
	}
	return 0
}
