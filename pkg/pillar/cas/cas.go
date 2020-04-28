package cas

import (
	"context"
	"fmt"
	"io"
)

//CAS  provides methods to interact with CAS clients
type CAS interface {
	//Blob APIs
	//CheckBlobExists: returns true if the blob exists.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	CheckBlobExists(blobHash string) bool
	//GetBlobSize: returns blob size.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	//Returns error if no blob is found for the given 'blobHash'.
	GetBlobSize(blobHash string) (int64, error)
	//ListBlobs: returns list of blobs where each entry is of format <algo>:<hash> (currently supporting only sha256:<hash>).
	ListBlobs() ([]string, error)
	//IngestBlob: reads the blob as raw data from arg 'reader' and validates the read blob's hash with the provided arg 'blobHash'.
	// If the validation succeeds, then the blob is ingested, else the given blob is rejected and an error is returned.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	//Arg 'ctx' must contain context with 'contextID':string with which we can relate two different blobs and
	// 'expires':time.Duration to set a validity duration for the context
	IngestBlob(ctx context.Context, blobHash string, reader io.Reader) error
	//ReadBlob: returns a reader to consume the raw data of the blob which matches the given arg 'blobHash'.
	//Returns error if no blob is found for the given 'blobHash'.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	ReadBlob(blobHash string) (io.Reader, error)
	//RemoveBlob: removes a blob which matches the given arg 'blobHash'.
	//To keep this method idempotent, no error is returned if the given arg 'blobHash' does not match any blob.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	RemoveBlob(blobHash string) error
	//Children: returns a list of child blob hashes if the given arg 'blobHash' belongs to a
	// index or a manifest blob, else an empty list is returned.
	//Format of returned blob hash list and arg 'blobHash' is <algo>:<hash> (currently supporting only sha256:<hash>)
	Children(blobHash string) ([]string, error)

	//Image APIs
	//CreateImage: creates a reference which points to a blob with 'blobHash'. 'blobHash' must belong to a index blob
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	//Returns error if no blob is found matching the given 'blobHash' or if the given 'blobHash' does not belong to an index.
	CreateImage(reference, blobHash string) error
	//GetImageHash: returns a blob hash of format <algo>:<hash> (currently supporting only sha256:<hash>) which the given 'reference' is pointing to.
	// Returns error if the given 'reference' is not found.
	GetImageHash(reference string) (string, error)
	//ListImages: returns a list of references
	ListImages() ([]string, error)
	//RemoveImage: removes an reference along with its contents unless the contents are referred by another reference or snapshot.
	//To keep this method idempotent, no error  is returned if the given 'reference' is not found.
	RemoveImage(reference string) error
	//ReplaceImage: replaces the blob hash to which the given 'reference' is pointing to with the given 'blobHash'.
	//Returns error if the given 'reference' or a blob matching the given arg 'blobHash' is not found.
	//Returns if the given 'blobHash' does not belong to an index.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	ReplaceImage(reference, blobHash string) error

	//Snapshot APIs
	//CreateSnapshotForImage: creates an snapshot with the given snapshotID for the given 'reference'
	//Arg 'snapshotID' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	CreateSnapshotForImage(snapshotID, reference string) error
	//MountSnapshot: mounts the snapshot on the given target path
	//Arg 'snapshotID' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	MountSnapshot(snapshotID, targetPath string) error
	//ListSnapshots: returns a list of snapshotIDs where each entry is of format <algo>:<hash> (currently supporting only sha256:<hash>).
	ListSnapshots() ([]string, error)
	//ListSnapshots: removes a snapshot matching the given 'snapshotID'.
	//Arg 'snapshotID' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	//To keep this method idempotent, no error  is returned if the given 'snapshotID' is not found.
	RemoveSnapshot(snapshotID string) error
}

type casDesc struct {
	constructor func() CAS
}

var knownCASHandlers = map[string]casDesc{
	"containerd": {constructor: newContainerdCAS},
}

//NewCAS  returns selectedCAS object
func NewCAS(selectedCAS string) (CAS, error) {
	if _, found := knownCASHandlers[selectedCAS]; !found {
		return nil, fmt.Errorf("Unknown CAS handler %s", selectedCAS)
	} else {
		return knownCASHandlers[selectedCAS].constructor(), nil
	}
}
