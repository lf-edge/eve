package containerd

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	v1stat "github.com/containerd/cgroups/stats/v1"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/leases"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/typeurl"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	spec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
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
	// default signal to kill tasks
	defaultSignal = "SIGTERM"
)

var (
	ctrdCtx context.Context
	// CtrdClient is a handle to the current containerd client API
	CtrdClient   *containerd.Client
	contentStore content.Store
)

// InitContainerdClient initializes CtrdClient and ctrdCtx
func InitContainerdClient() error {
	var err error
	ctrdCtx = namespaces.WithNamespace(context.Background(), ctrdServicesNamespace)
	CtrdClient, err = containerd.New(ctrdSocket, containerd.WithDefaultRuntime(containerdRunTime))
	if err != nil {
		log.Errorf("InitContainerdClient: could not create containerd client. %v", err.Error())
		return fmt.Errorf("initContainerdClient: could not create containerd client. %v", err.Error())
	}
	contentStore = CtrdClient.ContentStore()
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("InitContainerdClient: exception while verifying ctrd client: %s", err.Error())
	}
	return nil
}

//CtrWriteBlobWithLease reads the blob as raw data from `reader` and writes it into containerd with the given lease
func CtrWriteBlobWithLease(blobHash, leaseID string, reader io.Reader) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrWriteBlobWithLease: exception while verifying ctrd client: %s", err.Error())
	}
	ctrdCtx = leases.WithLease(ctrdCtx, leaseID)
	if blobHash == "" {
		return fmt.Errorf("CtrWriteBlobWithLease: blobHash cannot be empty")
	}
	expectedSha256Digest := digest.Digest(blobHash)
	if err := content.WriteBlob(ctrdCtx, contentStore, blobHash, reader, spec.Descriptor{Digest: expectedSha256Digest}); err != nil {
		return fmt.Errorf("CtrWriteBlobWithLease: Exception while writing blob: %s. %s", blobHash, err.Error())
	}
	return nil
}

//CtrReadBlob return a reader for the blob with given blobHash. Error is returned if no blob is found for the blobHash
func CtrReadBlob(blobHash string) (io.Reader, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrReadBlob: exception while verifying ctrd client: %s", err.Error())
	}
	shaDigest := digest.Digest(blobHash)
	_, err := contentStore.Info(ctrdCtx, shaDigest)
	if err != nil {
		return nil, fmt.Errorf("CtrReadBlob: Exception getting info of blob: %s. %s", blobHash, err.Error())
	}
	readerAt, err := contentStore.ReaderAt(ctrdCtx, spec.Descriptor{Digest: shaDigest})
	if err != nil {
		return nil, fmt.Errorf("CtrReadBlob: Exception while reading blob: %s. %s", blobHash, err.Error())
	}
	return content.NewReader(readerAt), nil
}

//CtrGetBlobInfo returns a bolb's info as content.Info
func CtrGetBlobInfo(blobHash string) (content.Info, error) {
	if err := verifyCtr(); err != nil {
		return content.Info{}, fmt.Errorf("CtrReadBlob: exception while verifying ctrd client: %s", err.Error())
	}
	return contentStore.Info(ctrdCtx, digest.Digest(blobHash))
}

//CtrListBlobInfo returns a list of blob infos as []content.Info
func CtrListBlobInfo() ([]content.Info, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrListBlobInfo: exception while verifying ctrd client: %s", err.Error())
	}
	infos := make([]content.Info, 0)
	walkFn := func(info content.Info) error {
		infos = append(infos, info)
		return nil
	}
	if err := contentStore.Walk(ctrdCtx, walkFn); err != nil {
		return nil, fmt.Errorf("CtrListBlobInfo: Exception while getting content list. %s", err.Error())
	}
	return infos, nil
}

//CtrDeleteBlob deletes blob with the given blobHash
func CtrDeleteBlob(blobHash string) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrDeleteBlob: exception while verifying ctrd client: %s", err.Error())
	}
	return contentStore.Delete(ctrdCtx, digest.Digest(blobHash))
}

//CtrCreateImage create an image in containerd's image store
func CtrCreateImage(image images.Image) (images.Image, error) {
	if err := verifyCtr(); err != nil {
		return images.Image{}, fmt.Errorf("CtrCreateImage: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().Create(ctrdCtx, image)
}

//CtrLoadImage reads image as raw data from `reader` and loads it into containerd
func CtrLoadImage(ctx context.Context, reader *os.File) ([]images.Image, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrLoadImage: exception while verifying ctrd client: %s", err.Error())
	}
	imgs, err := CtrdClient.Import(ctx, reader)
	if err != nil {
		log.Errorf("CtrLoadImage: could not load image %s into containerd: %+s", reader.Name(), err.Error())
		return nil, err
	}
	return imgs, nil
}

func CtrGetImage(reference string) (containerd.Image, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrGetImage: exception while verifying ctrd client: %s", err.Error())
	}
	image, err := CtrdClient.GetImage(ctrdCtx, reference)
	if err != nil {
		log.Errorf("CtrGetImage: could not get image %s from containerd: %+s", reference, err.Error())
		return nil, err
	}
	return image, nil
}

//CtrListImages returns a list of images object from ontainerd's image store
func CtrListImages() ([]images.Image, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrListImages: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().List(ctrdCtx)
}

//CtrUpdateImage updates the files provided in fieldpaths of the image in containerd'd image store
func CtrUpdateImage(image images.Image, fieldpaths ...string) (images.Image, error) {
	if err := verifyCtr(); err != nil {
		return images.Image{}, fmt.Errorf("CtrUpdateImage: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().Update(ctrdCtx, image, fieldpaths...)
}

//CtrDeleteImage deletes an image with the given reference
func CtrDeleteImage(reference string) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrDeleteImage: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().Delete(ctrdCtx, reference)
}

//CtrPrepareSnapshot creates snapshot for the given image
func CtrPrepareSnapshot(snapshotID string, image containerd.Image) ([]mount.Mount, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrPrepareSnapshot: exception while verifying ctrd client: %s", err.Error())
	}
	// use rootfs unpacked image to create a writable snapshot with default snapshotter
	diffIDs, err := image.RootFS(ctrdCtx)
	if err != nil {
		err = fmt.Errorf("CtrPrepareSnapshot: Could not load rootfs of image: %v. %v", image.Name(), err)
		return nil, err
	}

	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	parent := identity.ChainID(diffIDs).String()
	labels := map[string]string{"containerd.io/gc.root": time.Now().UTC().Format(time.RFC3339)}
	return snapshotter.Prepare(ctrdCtx, snapshotID, parent, snapshots.WithLabels(labels))
}

//CtrMountSnapshot mounts the snapshot with snapshotID on the given targetPath.
func CtrMountSnapshot(snapshotID, targetPath string) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrMountSnapshot: exception while verifying ctrd client: %s", err.Error())
	}
	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	mounts, err := snapshotter.Mounts(ctrdCtx, snapshotID)
	if err != nil {
		return fmt.Errorf("CtrMountSnapshot: Exception while fetching mounts of snapshot: %s. %s", snapshotID, err)
	}
	return mounts[0].Mount(targetPath)
}

//CtrListSnapshotInfo returns a list of all snapshot's info present in containerd's snapshot store.
func CtrListSnapshotInfo() ([]snapshots.Info, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrListSnapshotInfo: exception while verifying ctrd client: %s", err.Error())
	}
	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	snapshotInfoList := make([]snapshots.Info, 0)
	if err := snapshotter.Walk(ctrdCtx, func(i context.Context, info snapshots.Info) error {
		snapshotInfoList = append(snapshotInfoList, info)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("CtrListSnapshotInfo: Execption while fetching snapshot list. %s", err.Error())
	}
	return snapshotInfoList, nil
}

//CtrRemoveSnapshot removed snapshot by ID from containerd
func CtrRemoveSnapshot(snapshotID string) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrRemoveSnapshot: exception while verifying ctrd client: %s", err.Error())
	}
	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	if err := snapshotter.Remove(ctrdCtx, snapshotID); err != nil {
		log.Errorf("CtrRemoveSnapshot: unable to remove snapshot: %v. %v", snapshotID, err)
		return err
	}
	return nil
}

//CtrLoadContainer returns conatiner with the given `containerID`. Error is returned if there no container is found.
func CtrLoadContainer(containerID string) (containerd.Container, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrLoadContainer: exception while verifying ctrd client: %s", err.Error())
	}
	container, err := CtrdClient.LoadContainer(ctrdCtx, containerID)
	if err != nil {
		err = fmt.Errorf("CtrLoadContainer: Exception while loading container: %v", err)
	}
	return container, err
}

//CtrListContainerIds returns a list of all known container IDs
func CtrListContainerIds() ([]string, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrListContainerIds: exception while verifying ctrd client: %s", err.Error())
	}
	res := []string{}
	ctrs, err := CtrListContainer()
	if err != nil {
		return nil, err
	}
	for _, v := range ctrs {
		res = append(res, v.ID())
	}
	return res, nil
}

//CtrListContainer returns a list of containerd.Container ibjects
func CtrListContainer() ([]containerd.Container, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrListContainer: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.Containers(ctrdCtx)
}

// CtrGetContainerMetrics returns all runtime metrics associated with a container ID
func CtrGetContainerMetrics(containerID string) (*v1stat.Metrics, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrGetContainerMetrics: exception while verifying ctrd client: %s", err.Error())
	}
	c, err := CtrLoadContainer(containerID)
	if err != nil {
		return nil, err
	}

	t, err := c.Task(ctrdCtx, nil)
	if err != nil {
		return nil, err
	}

	m, err := t.Metrics(ctrdCtx)
	if err != nil {
		return nil, err
	}

	data, err := typeurl.UnmarshalAny(m.Data)
	if err != nil {
		return nil, err
	}

	switch v := data.(type) {
	case *v1stat.Metrics:
		return v, nil
	default:
		return nil, fmt.Errorf("can't parse task metric %v", data)
	}
}

// CtrContainerInfo looks up container's info
func CtrContainerInfo(name string) (int, string, error) {
	if err := verifyCtr(); err != nil {
		return 0, "", fmt.Errorf("CtrContainerInfo: exception while verifying ctrd client: %s", err.Error())
	}
	c, err := CtrLoadContainer(name)
	if err == nil {
		if t, err := c.Task(ctrdCtx, nil); err == nil {
			if stat, err := t.Status(ctrdCtx); err == nil {
				return int(t.Pid()), string(stat.Status), nil
			}
		}
	}
	return 0, "", err
}

// CtrStartContainer starts the default task in a pre-existing container and attaches its logging to memlogd
func CtrStartContainer(domainName string) (int, error) {
	if err := verifyCtr(); err != nil {
		return 0, fmt.Errorf("CtrStartContainer: exception while verifying ctrd client: %s", err.Error())
	}
	ctr, err := CtrLoadContainer(domainName)
	if err != nil {
		return 0, err
	}

	logger := GetLog()

	io := func(id string) (cio.IO, error) {
		stdoutFile := logger.Path(domainName + ".out")
		stderrFile := logger.Path(domainName)
		return &logio{
			cio.Config{
				Stdin:    "/dev/null",
				Stdout:   stdoutFile,
				Stderr:   stderrFile,
				Terminal: false,
			},
		}, nil
	}
	task, err := ctr.NewTask(ctrdCtx, io)
	if err != nil {
		return 0, err
	}

	if err := prepareProcess(int(task.Pid()), nil); err != nil {
		return 0, err
	}

	if err := task.Start(ctrdCtx); err != nil {
		return 0, err
	}

	return int(task.Pid()), nil
}

// CtrStopContainer stops (kills) the main task in the container
func CtrStopContainer(containerID string, force bool) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrStopContainer: exception while verifying ctrd client: %s", err.Error())
	}
	ctr, err := CtrLoadContainer(containerID)
	if err != nil {
		return fmt.Errorf("can't find cotainer %s (%v)", containerID, err)
	}

	signal, err := containerd.ParseSignal(defaultSignal)
	if err != nil {
		return err
	}
	if signal, err = containerd.GetStopSignal(ctrdCtx, ctr, signal); err != nil {
		return err
	}

	task, err := ctr.Task(ctrdCtx, nil)
	if err != nil {
		return err
	}

	// it is unclear whether we have to wait after this or proceed
	// straight away. It is also unclear whether paying any attention
	// to the err returned is worth anything at this point
	_ = task.Kill(ctrdCtx, signal, containerd.WithKillAll)

	if force {
		_, err = task.Delete(ctrdCtx, containerd.WithProcessKill)
	} else {
		_, err = task.Delete(ctrdCtx)
	}

	return err
}

// CtrDeleteContainer is a simple wrapper around container.Delete()
func CtrDeleteContainer(containerID string) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrDeleteContainer: exception while verifying ctrd client: %s", err.Error())
	}
	ctr, err := CtrLoadContainer(containerID)
	if err != nil {
		return err
	}

	// do this just in case
	_ = CtrStopContainer(containerID, true)

	return ctr.Delete(ctrdCtx)
}

//CtrCreateLease creates a lease with the given parameters
func CtrCreateLease(leaseOpts []leases.Opt) (leases.Lease, error) {
	if err := verifyCtr(); err != nil {
		return leases.Lease{}, fmt.Errorf("CtrDeleteContainer: exception while verifying ctrd client: %s",
			err.Error())
	}
	return CtrdClient.LeasesService().Create(ctrdCtx, leaseOpts...)
}

//verifyCtr verifies is containerd client and context.
func verifyCtr() error {
	if CtrdClient == nil {
		return fmt.Errorf("verifyCtr: Container client is nil")
	}

	if ctrdCtx == nil {
		return fmt.Errorf("verifyCtr: Container context is nil")
	}
	return nil
}
