package cas

import (
	"context"
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/leases"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/snapshots"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	spec "github.com/opencontainers/image-spec/specs-go/v1"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"io"
	"time"
)

var (
	ctrdClient   *containerd.Client
	ctrdCtx      context.Context
	contentStore content.Store
)

const (
	// containerd socket
	ctrdSocket = "/run/containerd/containerd.sock"
	// ctrdServicesNamespace containerd namespace for running containers
	ctrdServicesNamespace = "eve-user-apps"
	//containerdRunTime - default runtime of containerd
	containerdRunTime = "io.containerd.runtime.v1.linux"
	// default snapshotter used by containerd
	defaultSnapshotter = "overlayfs"
)

type containerdCAS struct {
}

//CheckBlobExists: returns true if the blob exists. Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) CheckBlobExists(blobHash string) bool {
	_, err := contentStore.Info(ctrdCtx, digest.Digest(blobHash))
	return err == nil
}

//GetBlobSize: returns: blob size. Arg 'blobHash' should be of format sha256:<hash>.
//Returns error if no blob is found for the given 'blobHash'.
func (c *containerdCAS) GetBlobSize(blobHash string) (int64, error) {
	info, err := contentStore.Info(ctrdCtx, digest.Digest(blobHash))
	if err != nil {
		return -1, fmt.Errorf("GetBlobSize: Exception while getting size of blob: %s. %s", blobHash, err.Error())
	}
	return info.Size, nil
}

//ListBlobs: returns list of blobs where each entry is of format sha256:<hash>.
func (c *containerdCAS) ListBlobs() ([]string, error) {
	infos, err := getContentInfoList()
	if err != nil {
		return nil, fmt.Errorf("ListBlobs: Exception while getting blob list. %s", err.Error())
	}
	blobDigests := make([]string, 0)
	for _, info := range infos {
		blobDigests = append(blobDigests, info.Digest.String())
	}
	return blobDigests, nil
}

//IngestBlob: reads the blob as raw data from arg 'reader' and validates the read blob's hash with the provided arg 'blobHash'.
// If the validation succeeds, then the blob is ingested, else the given blob is rejected and an error is returned.
//Arg 'blobHash' should be of format sha256:<hash>.
//Arg 'ctx' must contain context with 'contextID':string with which we can relate two different blobs and
// 'expires':time.Duration to set a validity duration for the context
func (c *containerdCAS) IngestBlob(ctx context.Context, blobHash string, reader io.Reader) error {
	leaseOpts := make([]leases.Opt, 0)
	var leaseID string
	if ctx.Value("contextID") == nil {
		return fmt.Errorf("IngestBlob: context does not have 'contextID'")
	}
	if ctx.Value("expires") == nil {
		return fmt.Errorf("IngestBlob: context does not have 'expires'")
	}
	if leaseID = ctx.Value("contextID").(string); leaseID != "" {
		leaseOpts = append(leaseOpts, leases.WithID(leaseID))
	}

	if exp := ctx.Value("expires").(time.Duration); exp > 0 {
		leaseOpts = append(leaseOpts, leases.WithExpiration(exp))
	}

	_, err := ctrdClient.LeasesService().Create(ctrdCtx, leaseOpts...)
	if err != nil && !isAlreadyExistsError(err) {
		return fmt.Errorf("IngestBlob: Exception while creating lease: %s. %s", leaseID, err.Error())
	}
	ctrdCtx = leases.WithLease(ctrdCtx, leaseID)
	if blobHash == "" {
		return fmt.Errorf("IngestBlob: blobHash cannot be empty")
	}
	expectedSha256Digest := digest.Digest(blobHash)
	if err = content.WriteBlob(ctrdCtx, contentStore, blobHash, reader, spec.Descriptor{Digest: expectedSha256Digest}); err != nil {
		return fmt.Errorf("IngestBlob: Exception while writing blob: %s. %s", blobHash, err.Error())
	}
	return nil
}

//ReadBlob: returns a reader to consume the raw data of the blob which matches the given arg 'blobHash'.
//Returns error if no blob is found for the given 'blobHash'.
//Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) ReadBlob(blobHash string) (io.Reader, error) {
	shaDigest := digest.Digest(blobHash)
	_, err := contentStore.Info(ctrdCtx, shaDigest)
	if err != nil {
		return nil, fmt.Errorf("ReadBlob: Exception getting info of blob: %s. %s", blobHash, err.Error())
	}
	readerAt, err := contentStore.ReaderAt(ctrdCtx, spec.Descriptor{Digest: shaDigest})
	if err != nil {
		return nil, fmt.Errorf("ReadBlob: Exception while reading blob: %s. %s", blobHash, err.Error())
	}
	return content.NewReader(readerAt), nil
}

//RemoveBlob: removes a blob which matches the given arg 'blobHash'.
//To keep this method idempotent, no error is returned if the given arg 'blobHash' does not match any blob.
//Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) RemoveBlob(blobHash string) error {
	if err := contentStore.Delete(ctrdCtx, digest.Digest(blobHash)); err != nil && !isNotFoundError(err) {
		return fmt.Errorf("RemoveBlob: Exception while removing blob: %s. %s", blobHash, err.Error())
	}
	return nil
}

//Children: returns a list of child blob hashes if the given arg 'blobHash' belongs to a
// index or a manifest blob, else an empty list is returned.
//Format of returned blob hash list and arg 'blobHash' is sha256:<hash>.
func (c *containerdCAS) Children(blobHash string) ([]string, error) {
	if _, err := c.ReadBlob(blobHash); err != nil {
		return nil, fmt.Errorf("Children: Exception while reading blob %s. %s", blobHash, err.Error())
	}
	childBlobSha256 := make([]string, 0)
	index, err := getIndexManifest(c, blobHash)
	if err == nil && index.Manifests != nil {
		manifestSha256, err := getManifestBlobSha256FromIndex(index)
		if err != nil {
			return nil, fmt.Errorf("Children: Exception while fetching manifest blobHash. %s", err.Error())
		}
		manifest, err := getManifest(c, manifestSha256)
		if err != nil {
			return nil, fmt.Errorf("Children: Exception while fetching manifest. %s", err.Error())
		}
		childBlobSha256 = append(childBlobSha256, manifestSha256, manifest.Config.Digest.String())
		for _, layer := range manifest.Layers {
			childBlobSha256 = append(childBlobSha256, layer.Digest.String())
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

//CreateImage: creates a reference which points to a blob with 'blobHash'. 'blobHash' must belong to a index blob
//Arg 'blobHash' should be of format sha256:<hash>.
//Returns error if no blob is found matching the given 'blobHash' or if the given 'blobHash' does not belong to an index.
func (c *containerdCAS) CreateImage(reference, blobHash string) error {
	index, err := getIndexManifest(c, blobHash)
	if err != nil {
		return fmt.Errorf("CreateImage: Exception while fetching IndexManifest. %s", err.Error())
	}
	manifest, err := getManifestFromIndex(c, index)
	if err != nil {
		return fmt.Errorf("CreateImage: Exception while fetching Manifest. %s", err.Error())
	}
	image := images.Image{
		Name:   reference,
		Labels: nil,
		Target: spec.Descriptor{
			MediaType: images.MediaTypeDockerSchema2ManifestList,
			Digest:    digest.Digest(blobHash),
			Size:      manifest.Config.Size,
		},
		CreatedAt: time.Time{},
		UpdatedAt: time.Time{},
	}
	_, err = ctrdClient.ImageService().Create(ctrdCtx, image)
	if err != nil {
		return fmt.Errorf("CreateImage: Exception while creating reference: %s. %s", reference, err.Error())
	}
	return nil
}

//GetImageHash: returns a blob hash of format sha256:<hash> which the given 'reference' is pointing to.
// Returns error if the given 'reference' is not found.
func (c *containerdCAS) GetImageHash(reference string) (string, error) {
	image, err := ctrdClient.ImageService().Get(ctrdCtx, reference)
	if err != nil {
		return "", fmt.Errorf("GetImageHash: Exception while getting image: %s. %s", reference, err.Error())
	}
	return image.Target.Digest.String(), nil
}

//ListImages: returns a list of references
func (c *containerdCAS) ListImages() ([]string, error) {
	imageObjectList, err := ctrdClient.ImageService().List(ctrdCtx)
	if err != nil {
		return nil, fmt.Errorf("ListImages: Exception while getting image list. %s", err.Error())
	}
	imageNameList := make([]string, 0)
	for _, image := range imageObjectList {
		imageNameList = append(imageNameList, image.Name)
	}
	return imageNameList, nil
}

//RemoveImage: removes an reference along with its contents unless the contents are referred by another reference or snapshot.
//To keep this method idempotent, no error  is returned if the given 'reference' is not found.
func (c *containerdCAS) RemoveImage(reference string) error {
	if err := ctrdClient.ImageService().Delete(ctrdCtx, reference); err != nil {
		return fmt.Errorf("RemoveImage: Exception while removing image. %s", err.Error())
	}
	return nil
}

//ReplaceImage: replaces the blob hash to which the given 'reference' is pointing to with the given 'blobHash'.
//Returns error if the given 'reference' or a blob matching the given arg 'blobHash' is not found.
//Returns if the given 'blobHash' does not belong to an index.
//Arg 'blobHash' should be of format sha256:<hash>.
func (c *containerdCAS) ReplaceImage(reference, blobHash string) error {
	index, err := getIndexManifest(c, blobHash)
	if err != nil {
		return fmt.Errorf("ReplaceImage: Exception while fetching IndexManifest. %s", err.Error())
	}
	manifest, err := getManifestFromIndex(c, index)
	if err != nil {
		return fmt.Errorf("ReplaceImage: Exception while fetching Manifest. %s", err.Error())
	}
	image := images.Image{
		Name:   reference,
		Labels: nil,
		Target: spec.Descriptor{
			MediaType: images.MediaTypeDockerSchema2ManifestList,
			Digest:    digest.Digest(blobHash),
			Size:      manifest.Config.Size,
		},
		CreatedAt: time.Time{},
		UpdatedAt: time.Time{},
	}
	_, err = ctrdClient.ImageService().Update(ctrdCtx, image, "target")
	if err != nil {
		return fmt.Errorf("ReplaceImage: Exception while updating reference: %s. %s", reference, err.Error())
	}
	return nil
}

//CreateSnapshotForImage: creates an snapshot with the given snapshotID for the given 'reference'
//Arg 'snapshotID' should be of format sha256:<hash>.
func (c *containerdCAS) CreateSnapshotForImage(snapshotID, reference string) error {
	image, err := ctrdClient.GetImage(ctrdCtx, reference)
	if err != nil {
		return fmt.Errorf("CreateSnapshotForImage: Exception while getting image: %s. %s", reference, err.Error())
	}
	diffIDs, err := image.RootFS(ctrdCtx)
	if err != nil {
		return fmt.Errorf("CreateSnapshotForImage: Exception while getting "+
			"image %s rootfs. %s", reference, err.Error())
	}

	parent := identity.ChainID(diffIDs).String()
	snapshotter := ctrdClient.SnapshotService(defaultSnapshotter)
	_, err = snapshotter.Prepare(ctrdCtx, snapshotID, parent)
	if err != nil {
		return fmt.Errorf("CreateSnapshotForImage: Exception while creating snapshot: %s. %s", snapshotID, err.Error())
	}
	return nil
}

//MountSnapshot: mounts the snapshot on the given target path
//Arg 'snapshotID' should be of format sha256:<hash>.
func (c *containerdCAS) MountSnapshot(snapshotID, targetPath string) error {
	snapshotter := ctrdClient.SnapshotService(defaultSnapshotter)
	mounts, err := snapshotter.Mounts(ctrdCtx, snapshotID)
	if err != nil {
		return fmt.Errorf("MountSnapshot: Exception while fetching mounts of snapshot: %s. %s", snapshotID, err)
	}
	return mounts[0].Mount(targetPath)
}

//ListSnapshots: returns a list of snapshotIDs where each entry is of format sha256:<hash>.
func (c *containerdCAS) ListSnapshots() ([]string, error) {
	snapshotter := ctrdClient.SnapshotService(defaultSnapshotter)
	snapshotIDList := make([]string, 0)
	if err := snapshotter.Walk(ctrdCtx, func(i context.Context, info snapshots.Info) error {
		snapshotIDList = append(snapshotIDList, info.Name)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("ListSnapshots: Execption while fetching snapshot list. %s", err.Error())
	}
	return snapshotIDList, nil
}

//ListSnapshots: removes a snapshot matching the given 'snapshotID'.
//Arg 'snapshotID' should be of format sha256:<hash>.
//To keep this method idempotent, no error  is returned if the given 'snapshotID' is not found.
func (c *containerdCAS) RemoveSnapshot(snapshotID string) error {
	snapshotter := ctrdClient.SnapshotService(defaultSnapshotter)
	if err := snapshotter.Remove(ctrdCtx, snapshotID); err != nil && !isNotFoundError(err) {
		return fmt.Errorf("RemoveSnapshot: Exception while removing snapshot: %s. %s", snapshotID, err.Error())
	}
	return nil
}

//newContainerdCAS: constructor for containerd CAS
func newContainerdCAS() CAS {
	initContainerd()
	return &containerdCAS{}
}

//getContentInfoList: returns a list of blobs as content.Info type
func getContentInfoList() ([]content.Info, error) {
	infos := make([]content.Info, 0)
	walkFn := func(info content.Info) error {
		infos = append(infos, info)
		return nil
	}
	if err := contentStore.Walk(ctrdCtx, walkFn); err != nil {
		return nil, fmt.Errorf("getContentInfoList: Exception while getting content list. %s", err.Error())
	}
	return infos, nil
}

//getIndexManifest: returns a indexManifest by parsing the given blobSha256
func getIndexManifest(c *containerdCAS, blobSha256 string) (*v1.IndexManifest, error) {
	reader, err := c.ReadBlob(blobSha256)
	if err != nil {
		return nil, fmt.Errorf("getIndexManifest: Exception while reading blob: %s. %s", blobSha256, err)
	}
	index, err := v1.ParseIndexManifest(reader)
	if err != nil {
		return nil, fmt.Errorf("getIndexManifest: Exception while reading blob Index: %s. %s", blobSha256, err.Error())
	}
	return index, nil
}

//getManifestFromIndex: returns Manifest for the current architecture from IndexManifest
func getManifestFromIndex(c *containerdCAS, indexManifest *v1.IndexManifest) (*v1.Manifest, error) {
	manifestSha256, err := getManifestBlobSha256FromIndex(indexManifest)
	if err != nil {
		return nil, fmt.Errorf("getManifestFromIndex: Exception while fetching manifest sha256: %s", err.Error())
	}
	return getManifest(c, manifestSha256)
}

//getManifest: returns manifest as type v1.Manifest byr parsing the given blobSha256
func getManifest(c *containerdCAS, blobSha256 string) (*v1.Manifest, error) {
	reader, err := c.ReadBlob(blobSha256)
	if err != nil {
		return nil, fmt.Errorf("getManifest: Exception while reading blob: %s. %s", blobSha256, err.Error())
	}
	manifest, err := v1.ParseManifest(reader)
	if err != nil {
		return nil, fmt.Errorf("getManifest: Exception while reading blob Manifest: %s. %s", blobSha256, err.Error())
	}
	return manifest, nil
}

//getManifestBlobSha256FromIndex: return blobSha256 of an manifest for the current architecture
func getManifestBlobSha256FromIndex(indexManifest *v1.IndexManifest) (string, error) {
	if indexManifest.Manifests == nil {
		return "", fmt.Errorf("getManifestBlobSha256FromIndex: No manifests found in index")
	}
	for _, m := range indexManifest.Manifests {
		if m.Platform.Architecture == runtime.GOARCH {
			return m.Digest.String(), nil
		}
	}
	return "", fmt.Errorf("getManifestBlobSha256FromIndex: No manifest found in the Index for arch: %s", runtime.GOARCH)
}

func initContainerd() {
	var err error
	ctrdClient, err = containerd.New(ctrdSocket, containerd.WithDefaultRuntime(containerdRunTime))
	if err != nil {
		log.Fatalf("initContainerd: could not create containerd client. %v", err.Error())
		return
	}
	ctrdCtx = namespaces.WithNamespace(context.Background(), ctrdServicesNamespace)
	contentStore = ctrdClient.ContentStore()
}

//isNotFoundError: returns true if the given error is a "not found" error
func isNotFoundError(err error) bool {
	return strings.HasSuffix(err.Error(), "not found")
}

//isNotFoundError: returns true if the given error is a "not found" error
func isAlreadyExistsError(err error) bool {
	return strings.HasSuffix(err.Error(), "already exists")
}
