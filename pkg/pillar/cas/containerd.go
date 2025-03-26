package cas

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd/content"
	containerderrdefs "github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/mount"
	snapshot "github.com/containerd/containerd/snapshots"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/lf-edge/edge-containers/pkg/resolver"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/moby/sys/mountinfo"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	casClientType = "containerd"
	// relative path to rootfs for an individual container
	containerRootfsPath = "rootfs/"
	// container config file name
	imageConfigFilename = "image-config.json"
	// start of containerd gc ref label for children in content store
	containerdGCRef = "containerd.io/gc.ref.content"
)

var (
	// ErrImageNotFound describes the error for when image is not found in containerd
	ErrImageNotFound = errors.New("image not found")
)

type containerdCAS struct {
	ctrdClient *containerd.Client
}

// SnapshotUsage returns current usage of snapshot in bytes
// We create snapshots for every layer of image and one active snapshot on top of them
// which presents the writable layer to store modified files
// If parents defined also adds usage of all parents of provided snapshot,
// not only the top active one
func (c *containerdCAS) SnapshotUsage(snapshotID string, parents bool) (int64, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	var size int64
	snapshots := []string{snapshotID}
	if parents {
		snapshotInfoList, err := c.ctrdClient.CtrListSnapshotInfo(ctrdCtx)
		if err != nil {
			return 0, fmt.Errorf("SnapshotUsage: Exception while fetching snapshots: %s. %w", snapshotID, err)
		}
		getSnapshotInfoByID := func(snapshotID string) *snapshot.Info {
			for _, snap := range snapshotInfoList {
				if snap.Name == snapshotID {
					return &snap
				}
			}
			return nil
		}
		checkAlreadyInList := func(snapshotID string) bool {
			for _, el := range snapshots {
				if el == snapshotID {
					return true
				}
			}
			return false
		}
		currentSnapshotInfo := getSnapshotInfoByID(snapshotID)
		if currentSnapshotInfo == nil {
			return 0, fmt.Errorf("SnapshotUsage: Exception while fetching snapshot info: %s not found", snapshotID)
		}
		for {
			parentSnapshotID := currentSnapshotInfo.Parent
			if parentSnapshotID == "" {
				// no parent snapshot, assume it is root, we are done
				break
			}
			// check if already added to the list
			// which is not expected and indicates that we have
			// circular reference in info list
			if checkAlreadyInList(parentSnapshotID) {
				return 0, fmt.Errorf("SnapshotUsage: Exception while fetching parent snapshots of %s: circular reference",
					snapshotID)
			}
			snapshots = append(snapshots, parentSnapshotID)
			// try to get info for parent snapshot
			currentSnapshotInfo = getSnapshotInfoByID(parentSnapshotID)
			if currentSnapshotInfo == nil {
				return 0, fmt.Errorf("SnapshotUsage: Exception while fetching parent snapshots of %s: %s not found",
					snapshotID, parentSnapshotID)
			}
		}
	}
	for _, snap := range snapshots {
		su, err := c.ctrdClient.CtrGetSnapshotUsage(ctrdCtx, snap)
		if err != nil {
			return 0, fmt.Errorf("SnapshotUsage: Exception while fetching usage of snapshot: %s. %w", snapshotID, err)
		}
		size += su.Size
	}
	return size, nil
}

// CheckBlobExists: returns true if the blob exists. Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) CheckBlobExists(blobHash string) bool {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	_, err := c.ctrdClient.CtrGetBlobInfo(ctrdCtx, blobHash)
	return err == nil
}

// GetBlobInfo: returns BlobInfo of type BlobInfo for the given blobHash.
// Arg 'blobHash' should be of format sha256:<hash>.
// Returns error if no blob is found for the given 'blobHash'.
func (c *containerdCAS) GetBlobInfo(blobHash string) (*BlobInfo, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	info, err := c.ctrdClient.CtrGetBlobInfo(ctrdCtx, blobHash)
	if err != nil {
		return nil, fmt.Errorf("GetBlobInfo: Exception while getting size of blob: %s. %s", blobHash, err.Error())
	}

	return &BlobInfo{
		Digest: info.Digest.String(),
		Size:   info.Size,
		Labels: info.Labels,
	}, nil
}

// ListBlobInfo: returns list of BlobInfo for all the blob present in CAS
func (c *containerdCAS) ListBlobInfo() ([]*BlobInfo, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	infos, err := c.ctrdClient.CtrListBlobInfo(ctrdCtx)
	if err != nil {
		return nil, fmt.Errorf("ListBlobInfo: Exception while getting blob list. %s", err.Error())
	}
	blobInfos := make([]*BlobInfo, 0)
	for _, info := range infos {
		blobInfos = append(blobInfos, &BlobInfo{
			Digest: info.Digest.String(),
			Size:   info.Size,
			Labels: info.Labels,
		})
	}
	return blobInfos, nil
}

// ListBlobsMediaTypes get a map of all blobs and their media types.
// If a blob does not have a media type, it is not returned here.
// If you want *all* blobs, whether or not it has a type, use ListBlobInfo
func (c *containerdCAS) ListBlobsMediaTypes() (map[string]string, error) {
	hashMap := map[string]string{}
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	// start with all of the images
	imageObjectList, err := c.ctrdClient.CtrListImages(ctrdCtx)
	if err != nil {
		return nil, fmt.Errorf("ListBlobsMediaTypes: Exception while getting image list. %s", err.Error())
	}
	// save the root and type of each image
	for _, i := range imageObjectList {
		dig, mediaType := i.Target.Digest.String(), i.Target.MediaType
		hashMap[dig] = mediaType
		switch v1types.MediaType(mediaType) {
		case v1types.OCIImageIndex, v1types.DockerManifestList:
			index, err := getIndexManifest(c, dig)
			if err != nil {
				logrus.Infof("ListBlobsMediaTypes: could not get index for %s, ignoring", dig)
				continue
			}
			// save all of the manifests
			for _, m := range index.Manifests {
				digm := m.Digest.String()
				hashMap[digm] = string(m.MediaType)
				// and now read each manifest
				manifest, err := getManifest(c, digm)
				if err != nil {
					logrus.Infof("ListBlobsMediaTypes: could not get manifest for %s in index %s, ignoring", digm, dig)
					continue
				}
				// read the config and the layers
				hashMap[manifest.Config.Digest.String()] = string(manifest.Config.MediaType)
				for _, l := range manifest.Layers {
					hashMap[l.Digest.String()] = string(l.MediaType)
				}
			}
		case v1types.OCIManifestSchema1, v1types.DockerManifestSchema1, v1types.DockerManifestSchema2, v1types.DockerManifestSchema1Signed:
			manifest, err := getManifest(c, dig)
			if err != nil {
				logrus.Infof("ListBlobsMediaTypes: could not get manifest for %s, ignoring", dig)
				continue
			}
			// read the config and the layers
			hashMap[manifest.Config.Digest.String()] = string(manifest.Config.MediaType)
			for _, l := range manifest.Layers {
				hashMap[l.Digest.String()] = string(l.MediaType)
			}
		}
	}
	return hashMap, nil
}

// IngestBlob: parses the given one or more `blobs` (BlobStatus) and for each blob reads the blob data from
// BlobStatus.Path or BlobStatus.Content and ingests it into CAS's blob store.
// Accepts a custom context. If ctx is nil, then default context will be used.
// Returns a list of loaded BlobStatus and an error is thrown if the read blob's hash does not match with the
// respective BlobStatus.Sha256 or if there is an exception while reading the blob data.
// In case of exception, the returned list of loaded blobs will contain all the blob that were loaded until that point.
func (c *containerdCAS) IngestBlob(ctx context.Context, blobs ...types.BlobStatus) ([]types.BlobStatus, error) {
	var (
		index          *ocispec.Index
		indexHash      string
		manifests      = make([]*ocispec.Manifest, 0)
		manifestHashes = make([]string, 0)
	)
	loadedBlobs := make([]types.BlobStatus, 0)

	// Step 1: Load blobs into CAS
	for _, blob := range blobs {
		var (
			r, contentReader io.Reader
			err              error
			blobFile         = blob.Path
			// the sha MUST be lower-case for it to work with the ocispec utils
			sha = fmt.Sprintf("%s:%s", digest.SHA256, strings.ToLower(blob.Sha256))
		)

		logrus.Debugf("IngestBlob(%s): processing blob %+v", blob.Sha256, blob)
		// Process the blob only if its not in a loaded status already
		if blob.State == types.LOADED {
			logrus.Infof("IngestBlob(%s): Not loading blob as it is already marked as loaded", blob.Sha256)
			loadedBlobs = append(loadedBlobs, blob)
			continue
		}

		logrus.Infof("IngestBlob(%s): Attempting to load blob", blob.Sha256)

		// Step 1.1: Read the blob from verified dir or provided content
		switch {
		case blobFile == "" && len(blob.Content) == 0:
			err = fmt.Errorf("IngestBlob(%s): both blobFile and blobContent empty %s",
				blob.Sha256, blobFile)
			logrus.Error(err.Error())
			return loadedBlobs, err
		case blobFile != "" && len(blob.Content) != 0:
			err = fmt.Errorf("IngestBlob(%s): both blobFile and blobContent provided, cannot pick, %s",
				blob.Sha256, blobFile)
			logrus.Error(err.Error())
			return loadedBlobs, err
		case blobFile != "":
			fileReader, err := os.Open(blobFile)
			if err != nil {
				err = fmt.Errorf("IngestBlob(%s): could not open blob file for reading at %s: %+s",
					blob.Sha256, blobFile, err.Error())
				logrus.Error(err.Error())
				return loadedBlobs, err
			}
			defer fileReader.Close()
			contentReader = fileReader
			defer fileReader.Close()
		default:
			contentReader = bytes.NewReader(blob.Content)
		}

		// Step 1.2: Resolve blob type and if this is a manifest or index, we will need to process (parse) it accordingly
		switch {
		case blob.IsIndex():
			// read it in so we can process it
			data, err := io.ReadAll(contentReader)
			if err != nil {
				err = fmt.Errorf("IngestBlob(%s): could not read data at %s: %+s",
					blob.Sha256, blobFile, err.Error())
				logrus.Error(err.Error())
				return loadedBlobs, err
			}
			// create a new reader for the content.WriteBlob
			r = bytes.NewReader(data)
			// try to parse the index
			if err := json.Unmarshal(data, &index); err != nil {
				err = fmt.Errorf("IngestBlob(%s): could not parse index at %s: %+s",
					blob.Sha256, blobFile, err.Error())
				logrus.Error(err.Error())
				return loadedBlobs, err
			}
			indexHash = sha
		case blob.IsManifest():
			// read it in so we can process it
			data, err := io.ReadAll(contentReader)
			if err != nil {
				err = fmt.Errorf("IngestBlob(%s): could not read data at %s: %+s",
					blob.Sha256, blobFile, err.Error())
				logrus.Error(err.Error())
				return loadedBlobs, err
			}
			// create a new reader for the content.WriteBlob
			r = bytes.NewReader(data)
			// try to parse the index
			mfst := ocispec.Manifest{}
			if err := json.Unmarshal(data, &mfst); err != nil {
				err = fmt.Errorf("IngestBlob(%s): could not parse manifest at %s: %+s",
					blob.Sha256, blobFile, err.Error())
				logrus.Error(err.Error())
				return loadedBlobs, err
			}
			manifests = append(manifests, &mfst)
			manifestHashes = append(manifestHashes, sha)
		default:
			// do nothing special, just pass it on
			r = contentReader
		}

		// Step 1.3: Ingest the blob into CAS
		if err := c.ctrdClient.CtrWriteBlob(ctx, sha, blob.Size, r); err != nil {
			err = fmt.Errorf("IngestBlob(%s): could not load blob file into containerd at %s: %+s",
				blob.Sha256, blobFile, err.Error())
			logrus.Error(err.Error())
			return loadedBlobs, err
		}
		logrus.Infof("IngestBlob(%s): Loaded the blob successfully", blob.Sha256)
		blob.State = types.LOADED
		loadedBlobs = append(loadedBlobs, blob)
	}

	// Step 2: Walk the tree from the root to add the necessary labels
	if index != nil {
		info := BlobInfo{
			Digest: indexHash,
			Labels: map[string]string{},
		}
		for i, m := range index.Manifests {
			info.Labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = m.Digest.String()
		}
		if err := c.UpdateBlobInfo(info); err != nil {
			err = fmt.Errorf("IngestBlob(%s): could not update labels on index: %v", info.Digest, err.Error())
			logrus.Error(err.Error())
			return loadedBlobs, err
		}
	}

	if len(manifests) > 0 {
		for j, m := range manifests {
			info := BlobInfo{
				Digest: manifestHashes[j],
				Labels: map[string]string{},
			}
			for i, l := range m.Layers {
				info.Labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = l.Digest.String()
			}
			i := len(m.Layers)
			info.Labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = m.Config.Digest.String()
			// set eve-downloaded label for this blob
			info.Labels[types.EVEDownloadedLabel] = types.EVEDownloadedValue
			if err := c.UpdateBlobInfo(info); err != nil {
				err = fmt.Errorf("IngestBlob(%s): could not update labels on manifest: %v",
					info.Digest, err.Error())
				logrus.Error(err.Error())
				return loadedBlobs, err
			}
		}

	}
	return loadedBlobs, nil
}

// UpdateBlobInfo updates BlobInfo of a blob in CAS.
// Arg is BlobInfo type struct in which BlobInfo.Digest is mandatory, and other field are to be filled
// only if its needed to be updated
// Returns error is no blob is found match blobInfo.Digest
func (c *containerdCAS) UpdateBlobInfo(blobInfo BlobInfo) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	existingBlobIfo, err := c.GetBlobInfo(blobInfo.Digest)
	if err != nil {
		err = fmt.Errorf("UpdateBlobInfo: Exception while fetching existing blobInfo of %s: %s", blobInfo.Digest, err.Error())
		logrus.Error(err.Error())
		return err
	}

	changed := false
	updatedContentInfo := content.Info{
		Digest: digest.Digest(blobInfo.Digest),
	}

	updatedFields := make([]string, 0)
	if blobInfo.Size > 0 && blobInfo.Size != existingBlobIfo.Size {
		updatedFields = append(updatedFields, "size")
		updatedContentInfo.Size = blobInfo.Size
		changed = true
	}

	if blobInfo.Labels != nil {
		for k := range blobInfo.Labels {
			updatedFields = append(updatedFields, fmt.Sprintf("labels.%s", k))
		}
		updatedContentInfo.Labels = blobInfo.Labels
		changed = true
	}

	if changed {
		if err := c.ctrdClient.CtrUpdateBlobInfo(ctrdCtx, updatedContentInfo, updatedFields); err != nil {
			err = fmt.Errorf("UpdateBlobInfo: Exception while updating blobInfo of %s: %s",
				blobInfo.Digest, err.Error())
			logrus.Error(err.Error())
			return err
		}
	}
	return nil
}

// ReadBlob: returns a reader to consume the raw data of the blob which matches the given arg 'blobHash'.
// Returns error if no blob is found for the given 'blobHash'.
// Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) ReadBlob(ctrdCtx context.Context, blobHash string) (io.Reader, error) {
	reader, err := c.ctrdClient.CtrReadBlob(ctrdCtx, blobHash)
	if err != nil {
		logrus.Errorf("ReadBlob: Exception while reading blob: %s. %s", blobHash, err.Error())
		return nil, err
	}
	return reader, nil
}

// RemoveBlob: removes a blob which matches the given arg 'blobHash'.
// To keep this method idempotent, no error is returned if the given arg 'blobHash' does not match any blob.
// Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) RemoveBlob(blobHash string) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	if err := c.ctrdClient.CtrDeleteBlob(ctrdCtx, blobHash); err != nil && !isNotFoundError(err) {
		return fmt.Errorf("RemoveBlob: Exception while removing blob: %s. %s", blobHash, err.Error())
	}
	return nil
}

// Children: returns a list of child blob hashes if the given arg 'blobHash' belongs to a
// index or a manifest blob, else an empty list is returned.
// Format of returned blob hash list and arg 'blobHash' is sha256:<hash>.
func (c *containerdCAS) Children(blobHash string) ([]string, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	if _, err := c.ReadBlob(ctrdCtx, blobHash); err != nil {
		return nil, fmt.Errorf("Children: Exception while reading blob %s. %s", blobHash, err.Error())
	}
	childBlobSha256 := make([]string, 0)
	index, err := getIndexManifest(c, blobHash)
	if err == nil && index.Manifests != nil {
		for _, manifest := range index.Manifests {
			childBlobSha256 = append(childBlobSha256, manifest.Digest.String())
		}
	} else {
		manifest, err := getManifest(c, blobHash)
		if err != nil {
			return childBlobSha256, nil
		}
		childBlobSha256 = append(childBlobSha256, manifest.Config.Digest.String())
		for _, layer := range manifest.Layers {
			childBlobSha256 = append(childBlobSha256, layer.Digest.String())
		}
	}
	return childBlobSha256, nil
}

// CreateImage: creates a reference which points to a blob with 'blobHash'. 'blobHash' must belong to a index blob
// Arg 'blobHash' should be of format sha256:<hash>.
// Returns error if no blob is found matching the given 'blobHash' or if the given 'blobHash' does not belong to an index.
func (c *containerdCAS) CreateImage(reference, mediaType, blobHash string) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	size, err := getBlobSize(c, blobHash)
	if err != nil {
		return fmt.Errorf("CreateImage: exception while parsing blob %s: %s", blobHash, err.Error())
	}

	image := images.Image{
		Name:   reference,
		Labels: getEVEDownloadedLabel(),
		Target: ocispec.Descriptor{
			MediaType: mediaType,
			Digest:    digest.Digest(blobHash),
			Size:      size,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Time{},
	}

	_, err = c.ctrdClient.CtrCreateImage(ctrdCtx, image)
	if err != nil {
		return fmt.Errorf("CreateImage: Exception while creating reference: %s. %s", reference, err.Error())
	}
	return nil
}

// GetImageHash: returns a blob hash of format sha256:<hash> which the given 'reference' is pointing to.
// Returns error if the given 'reference' is not found.
func (c *containerdCAS) GetImageHash(reference string) (string, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	image, err := c.ctrdClient.CtrGetImage(ctrdCtx, reference)
	if errors.Is(err, containerderrdefs.ErrNotFound) {
		return "", ErrImageNotFound
	}

	if err != nil {
		return "", fmt.Errorf("GetImageHash: Exception while getting image: %s. %s", reference, err.Error())
	}
	return image.Target().Digest.String(), nil
}

// GetImageLabels returns the Image Labels of the reference
// Returns error if the given 'reference' is not found.
func (c *containerdCAS) GetImageLabels(reference string) (map[string]string, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	image, err := c.ctrdClient.CtrGetImage(ctrdCtx, reference)
	if errors.Is(err, containerderrdefs.ErrNotFound) {
		return nil, ErrImageNotFound
	}

	return image.Labels(), nil
}

// ListImages: returns a list of references
func (c *containerdCAS) ListImages() ([]string, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	imageObjectList, err := c.ctrdClient.CtrListImages(ctrdCtx)
	if err != nil {
		return nil, fmt.Errorf("ListImages: Exception while getting image list. %s", err.Error())
	}

	imageNameList := make([]string, 0)
	for _, image := range imageObjectList {
		imageNameList = append(imageNameList, image.Name)
	}
	return imageNameList, nil
}

// RemoveImage removes an reference from CAS
// To keep this method idempotent, no error  is returned if the given 'reference' is not found.
func (c *containerdCAS) RemoveImage(reference string) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	if err := c.ctrdClient.CtrDeleteImage(ctrdCtx, reference); err != nil {
		return fmt.Errorf("RemoveImage: Exception while removing image. %s", err.Error())
	}
	return nil
}

// ReplaceImage: replaces the blob hash to which the given 'reference' is pointing to with the given 'blobHash'.
// Returns error if the given 'reference' or a blob matching the given arg 'blobHash' is not found.
// Returns if the given 'blobHash' does not belong to an index.
// Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) ReplaceImage(reference, mediaType, blobHash string) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	size, err := getBlobSize(c, blobHash)
	if err != nil {
		return fmt.Errorf("CreateImage: exception while parsing blob %s: %s", blobHash, err.Error())
	}
	image := images.Image{
		Name:   reference,
		Labels: getEVEDownloadedLabel(),
		Target: ocispec.Descriptor{
			MediaType: mediaType,
			Digest:    digest.Digest(blobHash),
			Size:      size,
		},
	}
	if _, err := c.ctrdClient.CtrUpdateImage(ctrdCtx, image, "target"); err != nil {
		return fmt.Errorf("ReplaceImage: Exception while updating reference: %s. %s", reference, err.Error())
	}
	return nil
}

// CreateSnapshotForImage: creates an snapshot with the given snapshotID for the given 'reference'
// Arg 'snapshotID' should be of format sha256:<hash>.
func (c *containerdCAS) CreateSnapshotForImage(snapshotID, reference string) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	clientImageObj, err := c.ctrdClient.CtrGetImage(ctrdCtx, reference)
	if err != nil {
		return fmt.Errorf("CreateSnapshotForImage: Exception while getting clientImageObj: %s. %s", reference, err.Error())
	}
	if err := c.ctrdClient.UnpackClientImage(clientImageObj); err != nil {
		err = fmt.Errorf("CreateSnapshotForImage: could not unpack clientImageObj %s: %+s",
			clientImageObj.Name(), err.Error())
		logrus.Error(err.Error())
		return err
	}

	if _, err := c.ctrdClient.CtrPrepareSnapshot(ctrdCtx, snapshotID, clientImageObj); err != nil {
		return fmt.Errorf("CreateSnapshotForImage: Exception while creating snapshot: %s. %s", snapshotID, err.Error())
	}
	return nil
}

// MountSnapshot: mounts the snapshot on the given target path
// Arg 'snapshotID' should be of format sha256:<hash>.
func (c *containerdCAS) MountSnapshot(snapshotID, targetPath string) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	if err := c.ctrdClient.CtrMountSnapshot(ctrdCtx, snapshotID, targetPath); err != nil {
		return fmt.Errorf("MountSnapshot: Exception while fetching mounts of snapshot: %s. %w", snapshotID, err)
	}
	return nil
}

// ListSnapshots: returns a list of snapshotIDs where each entry is of format sha256:<hash>.
func (c *containerdCAS) ListSnapshots() ([]string, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	snapshotInfoList, err := c.ctrdClient.CtrListSnapshotInfo(ctrdCtx)
	if err != nil {
		return nil, fmt.Errorf("ListSnapshots: unable to get snapshot info list: %s", err.Error())
	}
	snapshotIDList := make([]string, 0)
	for _, snapshotInfo := range snapshotInfoList {
		snapshotIDList = append(snapshotIDList, snapshotInfo.Name)
	}
	return snapshotIDList, nil
}

// ListSnapshots: removes a snapshot matching the given 'snapshotID'.
// Arg 'snapshotID' should be of format sha256:<hash>.
// To keep this method idempotent, no error  is returned if the given 'snapshotID' is not found.
func (c *containerdCAS) RemoveSnapshot(snapshotID string) error {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()
	if err := c.ctrdClient.CtrRemoveSnapshot(ctrdCtx, snapshotID); err != nil && !isNotFoundError(err) {
		return fmt.Errorf("RemoveSnapshot: Exception while removing snapshot: %s. %s", snapshotID, err.Error())
	}
	return nil
}

// PrepareContainerRootDir prepares a writable snapshot from the reference. Before preparing container's root directory,
// this API removes any existing state that may have accumulated (like existing snapshots being available, etc.)
// This effectively voids any kind of caching, but on the flip side frees us
// from cache invalidation. Additionally this API should deposit an OCI config json file and image name
// next to the rootfs so that the effective structure becomes:
//
//	rootPath/rootfs, rootPath/image-config.json
//
// The rootPath is expected to end in a basename that becomes the snapshotID
func (c *containerdCAS) PrepareContainerRootDir(rootPath, reference, _ string) error {
	// Step 1: On device restart, the existing bundle is not deleted, we need to delete the
	// existing bundle of the container and recreate it. This is safe to run even
	// when bundle doesn't exist
	if c.RemoveContainerRootDir(rootPath) != nil {
		logrus.Warnf("PrepareContainerRootDir: tried to clean up any existing state, hopefully it worked")
	}

	// Step 2: create snapshot of the image so that it can be mounted as container's rootfs.
	snapshotID := containerd.GetSnapshotID(rootPath)
	if err := c.CreateSnapshotForImage(snapshotID, reference); err != nil {
		err = fmt.Errorf("PrepareContainerRootDir: Could not create snapshot %s. %w", snapshotID, err)
		logrus.Error(err.Error())
		return err
	}

	// Step 3: write OCI image config/spec json under the container's rootPath.
	clientImageSpec, err := getImageConfig(c, reference)
	if err != nil {
		err = fmt.Errorf("PrepareContainerRootDir: exception while fetching image config for reference %s: %s",
			reference, err.Error())
		logrus.Error(err.Error())
		return err
	}
	clientImageSpecJSON, err := json.MarshalIndent(clientImageSpec, "", "    ")
	if err != nil {
		err = fmt.Errorf("PrepareContainerRootDir: Could not build json of image: %v. %v",
			reference, err.Error())
		logrus.Error(err.Error())
		return err
	}

	if err := os.MkdirAll(rootPath, 0766); err != nil {
		err = fmt.Errorf("PrepareContainerRootDir: Exception while creating rootPath dir. %w", err)
		logrus.Error(err.Error())
		return err
	}
	ociConfPath := filepath.Join(rootPath, imageConfigFilename)
	if err := fileutils.WriteRename(ociConfPath, clientImageSpecJSON); err != nil {
		err = fmt.Errorf("PrepareContainerRootDir: Exception while writing image info to %s. %w",
			ociConfPath, err)
		logrus.Error(err.Error())
		return err
	}
	if err := os.Chmod(ociConfPath, 0666); err != nil {
		err = fmt.Errorf("PrepareContainerRootDir: Exception while setting permissions on %s. %w",
			ociConfPath, err)
		logrus.Error(err.Error())
		return err
	}
	logrus.Infof("written image config for reference %s. content: %s", reference, string(clientImageSpecJSON))
	if base.IsHVTypeKube() {
		err := c.prepareContainerRootDirForKubevirt(clientImageSpec, snapshotID, rootPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *containerdCAS) prepareContainerRootDirForKubevirt(clientImageSpec *ocispec.Image, snapshotID string, rootPath string) error {

	// On kubevirt eve we also write the mountpoints and cmdline files to the rootPath.
	// Once rootPath is populated with all necessary files, this rootPath directory will be
	// converted to a PVC and passed in to domainmgr to attach to VM as rootdisk
	// NOTE: For kvm eve these files are generated and passed to bootloader in pkg/pillar/containerd/oci.go:AddLoader()

	mountpoints := clientImageSpec.Config.Volumes
	execpath := clientImageSpec.Config.Entrypoint
	cmd := clientImageSpec.Config.Cmd
	workdir := clientImageSpec.Config.WorkingDir
	unProcessedEnv := clientImageSpec.Config.Env
	user := clientImageSpec.Config.User
	logrus.Infof("PrepareContainerRootDir: mountPoints %+v execpath %+v cmd %+v workdir %+v env %+v user %+v",
		mountpoints, execpath, cmd, workdir, unProcessedEnv, user)

	// Mount the snapshot
	// Do not unmount the rootfs in this code path, we need this containerdir to generate a qcow2->PVC from it in
	// pkg/pillar/volumehandlers/csihandler.go
	// Once qcow2 is successfully created, this directory will be unmounted in csihandler.go
	if err := c.MountSnapshot(snapshotID, GetRoofFsPath(rootPath)); err != nil {
		return fmt.Errorf("PrepareContainerRootDir error mount of snapshot: %s. %w", snapshotID, err)
	}

	err := c.writeKubevirtMountpointsFile(mountpoints, rootPath)
	if err != nil {
		return err
	}

	// create env manifest
	var envContent string
	if workdir != "" {
		envContent = fmt.Sprintf("export WORKDIR=\"%s\"\n", workdir)
	} else {
		envContent = "export WORKDIR=/\n"
	}
	for _, e := range unProcessedEnv {
		keyAndValueSlice := strings.SplitN(e, "=", 2)
		if len(keyAndValueSlice) == 2 {
			// handles Key=Value case
			envContent += fmt.Sprintf("export %s=\"%s\"\n", keyAndValueSlice[0], keyAndValueSlice[1])
		} else {
			// handles Key= case
			envContent += fmt.Sprintf("export %s\n", e)
		}
	}
	//nolint:gosec // we want this file to be 0644
	if err := os.WriteFile(filepath.Join(rootPath, "environment"), []byte(envContent), 0644); err != nil {
		return err
	}

	// create cmdline manifest
	// each item needs to be independently quoted for initrd
	execpathQuoted := make([]string, 0)

	// This loop is just to pick the execpath and eliminate any square braces around it.
	// Just pick /entrypoint.sh from [/entrypoint.sh]
	for _, c := range execpath {
		execpathQuoted = append(execpathQuoted, fmt.Sprintf("\"%s\"", c))
	}
	for _, s := range cmd {
		execpathQuoted = append(execpathQuoted, fmt.Sprintf("\"%s\"", s))
	}
	command := strings.Join(execpathQuoted, " ")
	if err := os.WriteFile(filepath.Join(rootPath, "cmdline"),
		[]byte(command), 0644); err != nil {
		return err
	}

	// Userid and GID are same
	ug := "0 0"
	if user != "" {
		uid, converr := strconv.Atoi(user)
		if converr != nil {
			return converr
		}
		ug = fmt.Sprintf("%d %d", uid, uid)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "ug"),
		[]byte(ug), 0644); err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Join(rootPath, "modules"), 0600)
	return err
}

func (*containerdCAS) writeKubevirtMountpointsFile(mountpoints map[string]struct{}, rootPath string) error {
	if len(mountpoints) > 0 {
		f, err := os.OpenFile(filepath.Join(rootPath, "mountPoints"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			err = fmt.Errorf("PrepareContainerRootDir: Exception while creating file  mountpoints to %v %w",
				rootPath, err)
			logrus.Error(err.Error())
			return err
		}

		defer f.Close()
		for m := range mountpoints {
			m += "\n"
			if _, err := f.WriteString(m); err != nil {
				err = fmt.Errorf("PrepareContainerRootDir: Exception while writing mountpoints to %v %w",
					rootPath, err)
				logrus.Error(err.Error())
				return err
			}
		}
	}
	return nil
}

// UnmountContainerRootDir unmounts container's rootPath
func (c *containerdCAS) UnmountContainerRootDir(rootPath string, force bool) error {
	// check if mounted before proceed
	mounted, err := mountinfo.Mounted(GetRoofFsPath(rootPath))
	if !mounted || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	flag := 0
	if force {
		flag = unix.MNT_FORCE
	}
	if err := mount.Unmount(GetRoofFsPath(rootPath), flag); err != nil {
		err = fmt.Errorf("UnmountContainerRootDir: exception while unmounting: %v/%v. %w",
			rootPath, containerRootfsPath, err)
		logrus.Error(err.Error())
		return err
	}
	return nil
}

// RemoveContainerRootDir removes contents of a container's rootPath and snapshot.
func (c *containerdCAS) RemoveContainerRootDir(rootPath string) error {

	// Step 1: Un-mount container's rootfs with force flag as we do not aware of content
	if err := c.UnmountContainerRootDir(rootPath, true); err != nil {
		err = fmt.Errorf("RemoveContainerRootDir: exception while unmounting: %v/%v. %w",
			rootPath, containerRootfsPath, err)
		logrus.Error(err.Error())
		// do not stop the flow here, we need to do cleanup regardless of mounting issues
	}

	// Step 2: Clean container rootPath
	if err := os.RemoveAll(rootPath); err != nil {
		err = fmt.Errorf("RemoveContainerRootDir: exception while deleting: %v. %w", rootPath, err)
		logrus.Error(err.Error())

		return err

	}

	// Step 3: Remove snapshot created for the image
	snapshotID := containerd.GetSnapshotID(rootPath)
	if err := c.RemoveSnapshot(snapshotID); err != nil {
		err = fmt.Errorf("RemoveContainerRootDir: unable to remove snapshot: %v. %w", snapshotID, err)
		logrus.Error(err.Error())

		return err

	}
	return nil
}

// IngestBlobsAndCreateImage is a combination of IngestBlobs and CreateImage APIs,
// but this API will add a lease, upload all the blobs, add reference to the blobs and release the lease.
// By adding a lock before uploading the blobs we prevent the unreferenced blobs from getting GCed.
// We will assume that the first blob in the list will be the root blob for which the reference will be created.
//
// Returns an an error if the read blob's hash does not match with the respective BlobStatus.Sha256 or
// if there is an exception while reading the blob data.
//
// This API will not delete any blobs that it loaded, even in case of error. In the case of error, as the lease
// is removed, if the blobs do not have an image or label reference, containerd automatically will GC them.
// We do *not* want to delete them in this routine, since this might remove blobs that other images are using.
// Instead, we let containerd GC them.
func (c *containerdCAS) IngestBlobsAndCreateImage(reference string, root types.BlobStatus, blobs ...types.BlobStatus) ([]types.BlobStatus, error) {

	logrus.Infof("IngestBlobsAndCreateImage: Attempting to Ingest %d blobs and add reference: %s", len(blobs), reference)
	newCtxWithLease, deleteLease, err := c.ctrdClient.CtrNewUserServicesCtxWithLease()
	if err != nil {
		err = fmt.Errorf("IngestBlobsAndCreateImage: Unable load blobs for reference %s. "+
			"Exception while creating lease: %v", reference, err.Error())
		logrus.Error(err.Error())
		return nil, err
	}
	// deleting the lease means that containerd will be free to GC any blob that doesn't have a tag
	// or image reference from elsewhere
	defer deleteLease()
	loadedBlobs, err := c.IngestBlob(newCtxWithLease, blobs...)
	if err != nil {
		err = fmt.Errorf("IngestBlobsAndCreateImage: Exception while loading blobs into CAS: %v", err.Error())
		logrus.Error(err.Error())
		return nil, err
	}
	rootBlobSha := fmt.Sprintf("%s:%s", digest.SHA256, strings.ToLower(root.Sha256))
	mediaType := root.MediaType
	imageHash, err := c.GetImageHash(reference)
	if errors.Is(err, ErrImageNotFound) || imageHash == "" {
		logrus.Infof("IngestBlobsAndCreateImage: image not found, creating reference: %s for rootBlob %s", reference, rootBlobSha)
		if err := c.CreateImage(reference, mediaType, rootBlobSha); err != nil {
			err = fmt.Errorf("IngestBlobsAndCreateImage: could not create reference %s with rootBlob %s: %v",
				reference, rootBlobSha, err.Error())
			logrus.Error(err.Error())
			return nil, err
		}
	} else if err != nil {
		retErr := fmt.Errorf("getting image hash for reference %s, rootBlob %s failed: %w", reference, rootBlobSha, err)
		logrus.Error(retErr)
		return nil, retErr
	} else {
		logrus.Infof("IngestBlobsAndCreateImage: updating reference: %s for rootBlob %s", reference, rootBlobSha)
		if err := c.ReplaceImage(reference, mediaType, rootBlobSha); err != nil {
			err = fmt.Errorf("IngestBlobsAndCreateImage: could not update reference %s with rootBlob %s: %v",
				reference, rootBlobSha, err.Error())
			logrus.Error(err.Error())
			return nil, err
		}
	}
	return loadedBlobs, nil
}

// Resolver get a resolver.ResolverCloser for containerd
func (c *containerdCAS) Resolver(ctrdCtx context.Context) (resolver.ResolverCloser, error) {
	return c.ctrdClient.Resolver(ctrdCtx)
}

// CloseClient closes the containerd CAS client initialized while calling `NewCAS()`
func (c *containerdCAS) CloseClient() error {
	if err := c.ctrdClient.CloseClient(); err != nil {
		err = fmt.Errorf("CloseClient: Exception while closinn %s CAS client: %s", casClientType, err.Error())
		logrus.Error(err.Error())
		return err
	}
	c.ctrdClient = nil
	return nil
}

// CtrNewUserServicesCtx wraps the underlying fn
func (c *containerdCAS) CtrNewUserServicesCtx() (context.Context, context.CancelFunc) {
	return c.ctrdClient.CtrNewUserServicesCtx()
}

// newContainerdCAS: constructor for containerd CAS
func newContainerdCAS() CAS {
	ctrdClient, err := containerd.NewContainerdClient(true)
	if err != nil {
		logrus.Fatalf("newContainerdCAS: exception while creating containerd client: %s", err.Error())
	}
	return &containerdCAS{ctrdClient: ctrdClient}
}

// getIndexManifest: returns a indexManifest by parsing the given blobSha256
func getIndexManifest(c *containerdCAS, blobSha256 string) (*v1.IndexManifest, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	reader, err := c.ReadBlob(ctrdCtx, blobSha256)
	if err != nil {
		return nil, fmt.Errorf("getIndexManifest: Exception while reading blob: %s. %w", blobSha256, err)
	}
	index, err := v1.ParseIndexManifest(reader)
	if err != nil {
		return nil, fmt.Errorf("getIndexManifest: Exception while reading blob Index: %s. %s", blobSha256, err.Error())
	}
	return index, nil
}

// getManifest: returns manifest as type v1.Manifest byr parsing the given blobSha256
func getManifest(c *containerdCAS, blobSha256 string) (*v1.Manifest, error) {
	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	reader, err := c.ReadBlob(ctrdCtx, blobSha256)
	if err != nil {
		return nil, fmt.Errorf("getManifest: Exception while reading blob: %s. %s", blobSha256, err.Error())
	}
	manifest, err := v1.ParseManifest(reader)
	if err != nil {
		return nil, fmt.Errorf("getManifest: Exception while reading blob Manifest: %s. %s", blobSha256, err.Error())
	}
	return manifest, nil
}

// isNotFoundError: returns true if the given error is a "not found" error
func isNotFoundError(err error) bool {
	return strings.HasSuffix(err.Error(), "not found")
}

// getBlobSize get the size of a blob
func getBlobSize(c *containerdCAS, blobHash string) (int64, error) {
	info, err := c.GetBlobInfo(blobHash)
	if err != nil {
		return 0, fmt.Errorf("unable to get blob info for %s: %w", blobHash, err)
	}
	return info.Size, nil
}

// getImageConfig returns imageConfig for a reference
func getImageConfig(c *containerdCAS, reference string) (*ocispec.Image, error) {
	index := ocispec.Index{}
	manifests := ocispec.Manifest{}
	imageConfig := ocispec.Image{}

	// Step 1: Get the hash of parent blob
	imageParentHash, err := c.GetImageHash(reference)
	if err != nil {
		err = fmt.Errorf("getImageConfig: exception while fetching reference hash of %s: %s", reference, err.Error())
		logrus.Error(err.Error())
		return nil, err
	}

	ctrdCtx, done := c.ctrdClient.CtrNewUserServicesCtx()
	defer done()

	// Step 2: Read the parent blob data
	blobReader, err := c.ReadBlob(ctrdCtx, imageParentHash)
	if err != nil {
		err = fmt.Errorf("getImageConfig: exception while reading blob %s for reference %s: %s",
			imageParentHash, reference, err.Error())
		logrus.Error(err.Error())
		return nil, err
	}
	blobData, err := io.ReadAll(blobReader)
	if err != nil {
		err = fmt.Errorf("getImageConfig: could not read blobdata %s for reference %s: %+s",
			imageParentHash, reference, err.Error())
		logrus.Error(err.Error())
		return nil, err
	}

	// Step 3: Get the manifest of the image

	// Step 3.1: Check if the blob is an index
	if err := json.Unmarshal(blobData, &index); err != nil || index.Manifests == nil {
		// Step 3.2: Check if the blob is an manifest
		if err := json.Unmarshal(blobData, &manifests); err != nil {
			err = fmt.Errorf("getImageConfig: could not read imageManifest %s for reference %s: %+s",
				imageParentHash, reference, err.Error())
			logrus.Error(err.Error())
			return nil, err
		}
	} else {
		// Step 3.1.1: Fetch manifest hash from index
		for _, m := range index.Manifests {
			// Step 3.1.2:  get the appropriate manifest has from index
			if m.Platform.Architecture == runtime.GOARCH {
				blobReader, err = c.ReadBlob(ctrdCtx, m.Digest.String())
				if err != nil {
					err = fmt.Errorf("getImageConfig: exception while reading manifest blob %s for reference %s: %s",
						m.Digest.String(), reference, err.Error())
					logrus.Error(err.Error())
					return nil, err
				}
				// Step 3.1.3: Read the manifest data
				blobData, err = io.ReadAll(blobReader)
				if err != nil {
					err = fmt.Errorf("getImageConfig: could not parsr manifestBlob %s for reference %s: %+s",
						m.Digest.String(), reference, err.Error())
					logrus.Error(err.Error())
					return nil, err
				}
				if err := json.Unmarshal(blobData, &manifests); err != nil {
					err = fmt.Errorf("getImageConfig: could not parse manifestBlob %s for reference %s: %+s",
						m.Digest.String(), reference, err.Error())
					logrus.Error(err.Error())
					return nil, err
				}
				break
			}
		}
	}

	// Step 4: Get the config hash from manifest and read the config data
	configHash := manifests.Config.Digest.String()
	blobReader, err = c.ReadBlob(ctrdCtx, configHash)
	if err != nil {
		err = fmt.Errorf("getImageConfig: exception while reading config blob %s for reference %s: %s",
			configHash, reference, err.Error())
		logrus.Error(err.Error())
		return nil, err
	}
	blobData, err = io.ReadAll(blobReader)
	if err != nil {
		err = fmt.Errorf("getImageConfig: could not read config blobdata %s for reference %s: %+s",
			configHash, reference, err.Error())
		logrus.Error(err.Error())
		return nil, err
	}
	if err := json.Unmarshal(blobData, &imageConfig); err != nil {
		err = fmt.Errorf("getImageConfig: could not parse configBlob %s for reference %s: %+s",
			configHash, reference, err.Error())
		logrus.Error(err.Error())
		return nil, err
	}
	return &imageConfig, nil
}

// GetRoofFsPath returns rootfs path
func GetRoofFsPath(rootPath string) string {
	return filepath.Join(rootPath, containerRootfsPath)
}

// getEVEDownloadedLabel returns the label eve-downloaded = true which can be set on images or blobs
// This label can be applied on image and blobs downloaded by eve. In kubevirt eve some images are downloaded by k3s.
// We will differentiate those by the presence of this label.
// This label will be used in Garbage collection of eve downloaded images
// NOTE: This label will be set for all images and blobs newly created on kvm eve too.
func getEVEDownloadedLabel() map[string]string {

	label := map[string]string{}
	label[types.EVEDownloadedLabel] = types.EVEDownloadedValue

	return label
}
