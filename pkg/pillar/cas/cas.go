package cas

import (
	"fmt"
	"io"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

//BlobInfo holds the info of a blob present in CAS's blob store
type BlobInfo struct {
	//Digest to identify the blob uniquely. The format will/should be <algo>:<hash> (currently supporting only sha256:<hash>).
	Digest string

	//Size of the blob
	Size int64

	//Labels to add/define properties for the blob
	Labels map[string]string
}

//CAS  provides methods to interact with CAS clients
type CAS interface {
	//Blob APIs
	//CheckBlobExists: returns true if the blob exists.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	CheckBlobExists(blobHash string) bool
	//GetBlobInfo: returns BlobInfo of type BlobInfo for the given blobHash.
	//Arg 'blobHash' should be of format <algo>:<hash> (currently supporting only sha256:<hash>).
	//Returns error if no blob is found for the given 'blobHash'.
	GetBlobInfo(blobHash string) (*BlobInfo, error)
	//ListBlobInfo: returns list of BlobInfo for all the blob present in CAS
	ListBlobInfo() ([]*BlobInfo, error)
	// ListBlobsMediaTypes get a map of all blobs and their media types.
	// If a blob does not have a media type, it is not returned here.
	// If you want *all* blobs, whether or not it has a type, use ListBlobInfo
	ListBlobsMediaTypes() (map[string]string, error)
	// IngestBlob: parses the given one or more `blobs` (BlobStatus) and for each blob reads the blob data from
	// BlobStatus.Path and ingests it into CAS's blob store.
	// Returns a list of loaded BlobStatus and an error is thrown if the read blob's hash does not match with the
	// respective BlobStatus.Sha256 or if there is an exception while reading the blob data.
	// In case of exception, the returned list of loaded blob will contain all the blob that were loaded until that point.
	IngestBlob(blobs ...*types.BlobStatus) ([]*types.BlobStatus, error)
	//UpdateBlobInfo updates BlobInfo of a blob in CAS.
	//Arg is BlobInfo type struct in which BlobInfo.Digest is mandatory, and other field to be fill only if need to be updated
	//Returns error is no blob is found match blobInfo.Digest
	UpdateBlobInfo(blobInfo BlobInfo) error
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
	//RemoveImage removes an reference from CAS
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

	// PrepareContainerRootDir creates a reference pointing to the rootBlob and prepares a writable snapshot
	// from the reference. Before preparing container's root directory, this API must remove any existing state
	// that may have accumulated (like existing snapshots being available, etc.)
	// This effectively voids any kind of caching, but on the flip side frees us
	// from cache invalidation. Additionally this API should deposit an OCI config json file and image name
	// next to the rootfs so that the effective structure becomes:
	//    rootPath/rootfs, rootPath/image-config.json, rootPath/image-name
	// The rootPath is expected to end in a basename that becomes the snapshotID
	PrepareContainerRootDir(rootPath, reference, rootBlobSha string) error

	// RemoveContainerRootDir removes contents of a container's rootPath, existing snapshot and reference.
	RemoveContainerRootDir(rootPath string) error

	// IngestBlobsAndCreateImage is a combination of IngestBlobs and CreateImage APIs,
	// but this API will add a lock, upload all the blobs, add reference to the blobs and release the lock.
	// By adding a lock before uploading the blobs we prevent the unreferenced blobs from getting GCed.
	// We will assume that the first blob in the list will be the root blob for which the reference will be created.
	// Returns an an error if the read blob's hash does not match with the respective BlobStatus.Sha256 or
	// if there is an exception while reading the blob data.
	//NOTE: This either loads all the blobs or loads nothing. In other words, in case of error,
	// this API will GC all blobs that were loaded until that point.
	IngestBlobsAndCreateImage(reference string, blobs ...*types.BlobStatus) ([]*types.BlobStatus, error)

	//CloseClient closes the respective CAS client initialized while calling `NewCAS()`
	CloseClient() error
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
