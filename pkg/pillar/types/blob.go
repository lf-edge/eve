package types

import (
	"time"

	uuid "github.com/satori/go.uuid"
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
	// RefCount number of consumers of this lbob
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
