package types

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// BlobStatus status of a downloaded blob
type BlobStatus struct {
	// DatastoreID ID of the datastore where the blob can be retrieved
	DatastoreID uuid.UUID
	// RelativeURL URL relative to the root of the datastore
	RelativeURL string
	// Sha256 the sha of the blob
	Sha256 string
	// Size size of the expected download
	Size uint64
	// Path where this blob can be retrieved. This changes based on the state, e.g. after download
	// in one place, after verify might be another
	Path string
	// State of download of this blob; only supports: INITIAL, DOWNLOADING, DOWNLOADED, VERIFYING, VERIFIED
	State SwState
	// BlobType what kind of blob type this is
	BlobType BlobType
	// HasDownloaderRef whether or not we have started a downloader for this blob
	HasDownloaderRef bool
	// HasVerifierRef whether or not we have started a verifier for this blob
	HasVerifierRef bool
	// HasPersistRef whether or not we have a reference to data that was persisted
	HasPersistRef bool
	// RefCount number of consumers of this blob
	RefCount uint
	// LastUse when RefCount dropped to zero
	LastUse time.Time
	// WaitingForCerts waiting for certificates and so cannot continue verifying
	WaitingForCerts bool
	TotalSize       int64 // expected size as reported by the downloader, if any
	CurrentSize     int64 // current total downloaded size as reported by the downloader
	// Progress percentage downloaded 0-100, defined by CurrentSize/TotalSize
	Progress uint
	// ErrorAndTimeWithSource provide common error handling capabilities
	ErrorAndTimeWithSource
	// XXX remove ObjType as part of cleanup of ObjType
	ObjType string
}

// BlobType what kind of blob this is. Usually we use the MediaType,
// but this is good shorthand to make it easier to process.
type BlobType uint8

const (
	// BlobBinary a binary layer
	BlobBinary BlobType = iota
	// BlobManifest an OCI manifest
	BlobManifest
	// BlobIndex an OCI index
	BlobIndex
	// BlobUnknown an unknown status
	BlobUnknown
)

// Key returns the pubsub Key
func (status BlobStatus) Key() string {
	return status.Sha256
}

// LogCreate :
func (status BlobStatus) LogCreate() {
	logObject := base.NewLogObject(base.BlobStatusLogType, status.RelativeURL,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("datastoreid-uuid", status.DatastoreID).
		AddField("size-int64", status.Size).
		AddField("blobtype-int64", status.BlobType).
		AddField("refcount-int64", status.RefCount).
		Infof("Blob status create")
}

// LogModify :
func (status BlobStatus) LogModify(old interface{}) {
	logObject := base.EnsureLogObject(base.BlobStatusLogType, status.RelativeURL,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(BlobStatus)
	if !ok {
		log.Errorf("LogModify: Old object interface passed is not of BlobStatus type")
	}
	if oldStatus.State != status.State ||
		oldStatus.RefCount != status.RefCount ||
		oldStatus.Size != status.Size {

		logObject.CloneAndAddField("state", status.State.String()).
			AddField("refcount-int64", status.RefCount).
			AddField("size-int64", status.Size).
			AddField("old-state", oldStatus.State.String()).
			AddField("old-refcount-int64", oldStatus.RefCount).
			AddField("old-size-int64", oldStatus.Size).
			Infof("Blob status modify")
	}

	if status.HasError() {
		logObject.CloneAndAddField("state", status.State.String()).
			AddField("error", status.Error).
			AddField("error-time", status.ErrorTime).
			Errorf("Blob status modify")
	}
}

// LogDelete :
func (status BlobStatus) LogDelete() {
	logObject := base.EnsureLogObject(base.BlobStatusLogType, status.RelativeURL,
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("state", status.State.String()).
		AddField("refcount-int64", status.RefCount).
		AddField("size-int64", status.Size).
		Infof("Blob status delete")

	base.DeleteLogObject(status.LogKey())
}

// LogKey :
func (status BlobStatus) LogKey() string {
	return string(base.BlobStatusLogType) + "-" + status.Key()
}

//GetDownloadedPercentage returns blob's downloaded %
func (status BlobStatus) GetDownloadedPercentage() uint32 {
	if status.CurrentSize > 0 && status.TotalSize > 0 {
		return uint32((status.CurrentSize / status.TotalSize) * 100)
	}
	return 0
}
