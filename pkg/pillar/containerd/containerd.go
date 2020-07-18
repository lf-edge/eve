// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/snapshots"
	"github.com/containerd/typeurl"
	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"

	v1stat "github.com/containerd/cgroups/stats/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	spec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
)

const (
	// containerd socket
	ctrdSocket = "/run/containerd/containerd.sock"
	// ctrdSystemServicesNamespace containerd namespace for EVE system containers
	ctrdSystemServicesNamespace = "services.linuxkit"
	// ctrdServicesNamespace containerd namespace for running user containers
	ctrdServicesNamespace = "eve-user-apps"
	//containerdRunTime - default runtime of containerd
	containerdRunTime = "io.containerd.runtime.v1.linux"
	// default snapshotter used by containerd
	defaultSnapshotter = "overlayfs"
	// container config file name
	imageConfigFilename = "image-config.json"
	// default socket to connect tasks to memlogd
	logWriteSocket = "/var/run/linuxkit-external-logging.sock"
	// default socket to read from memlogd
	logReadSocket = "/var/run/memlogdq.sock"

	//TBD: Have a better way to calculate this number.
	//For now it is based on some trial-and-error experiments
	qemuOverHead = int64(500 * 1024 * 1024)

	// default signal to kill tasks
	defaultSignal = "SIGTERM"
	//containerd context lease
	ctrdCtxLeaseID = "eve-user-apps-lease"
	//To keep resource safe from getting GC while loading it in Ctrd
	tempLeaseDuration = 5 * time.Minute
)

var (
	ctrdCtx       context.Context
	ctrdSystemCtx context.Context
	// CtrdClient is a handle to the current containerd client API
	CtrdClient   *containerd.Client
	contentStore content.Store
)

// InitContainerdClient initializes CtrdClient and ctrdCtx
func InitContainerdClient() error {
	log.Infof("InitContainerdClient")
	var err error
	if ctrdCtx == nil {
		ctrdCtx = namespaces.WithNamespace(context.Background(), ctrdServicesNamespace)
	}
	if ctrdSystemCtx == nil {
		ctrdSystemCtx = namespaces.WithNamespace(context.Background(), ctrdSystemServicesNamespace)
	}
	if CtrdClient == nil {
		CtrdClient, err = containerd.New(ctrdSocket, containerd.WithDefaultRuntime(containerdRunTime))
		if err != nil {
			log.Errorf("InitContainerdClient: could not create containerd client. %v", err.Error())
			return fmt.Errorf("initContainerdClient: could not create containerd client. %v", err.Error())
		}
	}
	if contentStore == nil {
		contentStore = CtrdClient.ContentStore()
	}

	if err := verifyCtr(); err != nil {
		return fmt.Errorf("InitContainerdClient: exception while verifying ctrd client: %s", err.Error())
	}
	return nil
}

//CloseClient closes containerd client
func CloseClient() error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CloseClient: exception while verifying ctrd client: %s", err.Error())
	}
	if err := CtrdClient.Close(); err != nil {
		err = fmt.Errorf("CloseClient: exception while closing containerd client. %v", err.Error())
		log.Errorf(err.Error())
		return err
	}
	return nil
}

//CtrWriteBlob reads the blob as raw data from `reader` and writes it into containerd.
func CtrWriteBlob(blobHash string, expectedSize uint64, reader io.Reader) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrWriteBlob: exception while verifying ctrd client: %s", err.Error())
	}
	expectedDigest := digest.Digest(blobHash)
	if err := expectedDigest.Validate(); err != nil {
		return fmt.Errorf("CtrWriteBlob: exception while validating hash format of %s. %v", blobHash, err)
	}
	if err := content.WriteBlob(ctrdCtx, contentStore, blobHash, reader,
		spec.Descriptor{Digest: expectedDigest, Size: int64(expectedSize)}); err != nil {
		return fmt.Errorf("CtrWriteBlob: Exception while writing blob: %s. %s", blobHash, err.Error())
	}
	return nil
}

//CtrUpdateBlobInfo updates blobs info
func CtrUpdateBlobInfo(updatedContentInfo content.Info, updatedFields []string) error {
	if _, err := contentStore.Update(ctrdCtx, updatedContentInfo, updatedFields...); err != nil {
		return fmt.Errorf("CtrUpdateBlobInfo: exception while update blobInfo of %s: %s",
			updatedContentInfo.Digest.String(), err.Error())
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

//CtrGetImage returns image object for the reference. Returns error if no image is found for the reference.
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
	if err := os.MkdirAll(targetPath, 0766); err != nil {
		return fmt.Errorf("CtrMountSnapshot: Exception while creating targetPath dir. %v", err)
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

// CtrCreateTask creates (but doesn't start) the default task in a pre-existing container and attaches its logging to memlogd
func CtrCreateTask(domainName string) (int, error) {
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

	return int(task.Pid()), nil
}

// CtrStartTask starts the default task in a pre-existing container that was prepared by CtrCreateTask
func CtrStartTask(domainName string) error {
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrStartContainer: exception while verifying ctrd client: %s", err.Error())
	}
	ctr, err := CtrLoadContainer(domainName)
	if err != nil {
		return err
	}

	task, err := ctr.Task(ctrdCtx, nil)
	if err != nil {
		return err
	}

	if err := prepareProcess(int(task.Pid()), nil); err != nil {
		return err
	}

	return task.Start(ctrdCtx)
}

// ctrExec starts the executable in a running container and attaches its logging to memlogd
func ctrExec(ctx context.Context, domainName string, args []string) ([]byte, []byte, error) {
	if err := verifyCtr(); err != nil {
		return nil, nil, fmt.Errorf("ctrExec: exception while verifying ctrd client: %s", err.Error())
	}
	ctr, err := CtrdClient.LoadContainer(ctx, domainName)
	if err != nil {
		return nil, nil, fmt.Errorf("ctrExec: Exception while loading container: %v", err)
	}

	spec, err := ctr.Spec(ctx)
	if err != nil {
		return nil, nil, err
	}
	task, err := ctr.Task(ctx, nil)
	if err != nil {
		return nil, nil, err
	}

	pspec := spec.Process
	pspec.Terminal = true
	pspec.Args = args

	// plumb the process for I/O
	var (
		stdOut bytes.Buffer
		stdErr bytes.Buffer
	)
	cioOpts := []cio.Opt{cio.WithStreams(new(bytes.Buffer), &stdOut, &stdErr), cio.WithFIFODir(fifoDir)}
	process, err := task.Exec(ctx, domainName+strconv.Itoa(rand.Int()), pspec, cio.NewCreator(cioOpts...))
	if err != nil {
		return nil, nil, err
	}
	defer process.Delete(ctx)

	// prepare an exit code channel
	statusC, err := process.Wait(ctx)
	if err != nil {
		return nil, nil, err
	}

	// finally - run it (asynchronously)
	if err := process.Start(ctx); err != nil {
		return nil, nil, err
	}

	// block until the process exits or the timer fires
	timer := time.NewTimer(30 * time.Second)
	select {
	case status := <-statusC:
		if code, _, e := status.Result(); e == nil && code != 0 {
			err = fmt.Errorf("execution failed with exit status %d", code)
		} else {
			err = e
		}
	case <-timer.C:
		err = fmt.Errorf("execution timed out")
	}

	return stdOut.Bytes(), stdErr.Bytes(), err
}

// CtrExec starts the executable in a running user container
func CtrExec(domainName string, args []string) ([]byte, []byte, error) {
	return ctrExec(ctrdCtx, domainName, args)
}

// CtrSystemExec starts the executable in a running system (EVE's) container
func CtrSystemExec(domainName string, args []string) ([]byte, []byte, error) {
	return ctrExec(ctrdSystemCtx, domainName, args)
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

// LKTaskPrepare creates a new containter based on linuxkit /container/services runtime
// OCI spec file and optional bundle of DomainConfig settings and command line options.
// Because we're expecting a linuxkit produced filesystem layout we expect R/O portion of the
// filesystem to be available under `dirname specFile`/lower and we will be mounting
// it R/O into the container. On top of that we expect the usual suspects of /run,
// /persist and /config to be taken care of by the OCI config that lk produced.
func LKTaskPrepare(name, linuxkit string, domSettings *types.DomainConfig, memOverhead int64, args []string) error {
	config := "/containers/services/" + linuxkit + "/config.json"
	rootfs := "/containers/services/" + linuxkit + "/rootfs"

	log.Infof("Starting LKTaskLaunch for %s", linuxkit)
	f, err := os.Open("/hostfs" + config)
	if err != nil {
		return fmt.Errorf("LKTaskLaunch: can't open spec file %s %v", config, err)
	}

	spec, err := NewOciSpec(name)
	if err != nil {
		return fmt.Errorf("LKTaskLaunch: NewOciSpec failed with error %v", err)
	}
	if err = spec.Load(f); err != nil {
		return fmt.Errorf("LKTaskLaunch: can't load spec file from %s %v", config, err)
	}

	spec.Get().Root.Path = rootfs
	spec.Get().Root.Readonly = true
	if domSettings != nil {
		spec.UpdateFromDomain(*domSettings)
		if memOverhead > 0 {
			spec.AdjustMemLimit(*domSettings, memOverhead)
		}
	}

	if args != nil {
		spec.Get().Process.Args = args
	}

	return spec.CreateContainer(true)
}

//CtrCreateLease created a 24 hrs lease for a containerd context.
//Returns a func to delete the lease after use.
func CtrCreateLease() (func() error, error) {
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrCreateLease: exception while verifying ctrd client: %s", err.Error())
	}
	ctrdCtx, done, err := CtrdClient.WithLease(ctrdCtx)
	if err != nil {
		return nil, fmt.Errorf("CtrCreateLease: exception while creating lease: %s", err.Error())
	}
	return func() error {
		return done(ctrdCtx)
	}, nil
}

// Util methods

// FIXME: once we move to runX this function is going to go away
func createMountPointExecEnvFiles(containerPath string, mountpoints map[string]struct{}, execpath []string, workdir string, env []string, noOfDisks int) error {
	mpFileName := containerPath + "/mountPoints"
	cmdFileName := containerPath + "/cmdline"
	envFileName := containerPath + "/environment"

	mpFile, err := os.Create(mpFileName)
	if err != nil {
		log.Errorf("createMountPointExecEnvFiles: os.Create for %v, failed: %v", mpFileName, err.Error())
	}
	defer mpFile.Close()

	cmdFile, err := os.Create(cmdFileName)
	if err != nil {
		log.Errorf("createMountPointExecEnvFiles: os.Create for %v, failed: %v", cmdFileName, err.Error())
	}
	defer cmdFile.Close()

	envFile, err := os.Create(envFileName)
	if err != nil {
		log.Errorf("createMountPointExecEnvFiles: os.Create for %v, failed: %v", envFileName, err.Error())
	}
	defer envFile.Close()

	//Ignoring container image in status.DiskStatusList
	noOfDisks = noOfDisks - 1

	//Validating if there are enough disks provided for the mount-points
	switch {
	case noOfDisks > len(mountpoints):
		//If no. of disks is (strictly) greater than no. of mount-points provided, we will ignore excessive disks.
		log.Warnf("createMountPointExecEnvFiles: Number of volumes provided: %v is more than number of mount-points: %v. "+
			"Excessive volumes will be ignored", noOfDisks, len(mountpoints))
	case noOfDisks < len(mountpoints):
		//If no. of mount-points is (strictly) greater than no. of disks provided, we need to throw an error as there
		// won't be enough disks to satisfy required mount-points.
		return fmt.Errorf("createMountPointExecEnvFiles: Number of volumes provided: %v is less than number of mount-points: %v. ",
			noOfDisks, len(mountpoints))
	}

	for path := range mountpoints {
		if !strings.HasPrefix(path, "/") {
			//Target path is expected to be absolute.
			err := fmt.Errorf("createMountPointExecEnvFiles: targetPath should be absolute")
			log.Errorf(err.Error())
			return err
		}
		log.Infof("createMountPointExecEnvFiles: Processing mount point %s\n", path)
		if _, err := mpFile.WriteString(fmt.Sprintf("%s\n", path)); err != nil {
			err := fmt.Errorf("createMountPointExecEnvFiles: writing to %s failed %v", mpFileName, err)
			log.Errorf(err.Error())
			return err
		}
	}

	// each item needs to be independently quoted for initrd
	execpathQuoted := make([]string, 0)
	for _, s := range execpath {
		execpathQuoted = append(execpathQuoted, fmt.Sprintf("\"%s\"", s))
	}
	if _, err := cmdFile.WriteString(strings.Join(execpathQuoted, " ")); err != nil {
		err := fmt.Errorf("createMountPointExecEnvFiles: writing to %s failed %v", cmdFileName, err)
		log.Errorf(err.Error())
		return err
	}

	envContent := ""
	if workdir != "" {
		envContent = fmt.Sprintf("export WORKDIR=\"%s\"\n", workdir)
	}
	for _, e := range env {
		envContent = envContent + fmt.Sprintf("export %s\n", e)
	}
	if _, err := envFile.WriteString(envContent); err != nil {
		err := fmt.Errorf("createMountPointExecEnvFiles: writing to %s failed %v", envFileName, err)
		log.Errorf(err.Error())
		return err
	}

	return nil
}

// getContainerConfigs get the container configs needed, specifically
// - mount target paths
// - exec path
// - working directory
// - env var key/value pairs
// this can change based on the config format
func getContainerConfigs(imageInfo ocispec.Image, userEnvVars map[string]string) (map[string]struct{}, []string, string, []string, error) {

	mountpoints := imageInfo.Config.Volumes
	execpath := imageInfo.Config.Entrypoint
	execpath = append(execpath, imageInfo.Config.Cmd...)
	workdir := imageInfo.Config.WorkingDir
	unProcessedEnv := imageInfo.Config.Env
	var env []string
	for _, e := range unProcessedEnv {
		keyAndValueSlice := strings.Split(e, "=")
		if len(keyAndValueSlice) == 2 {
			//handles Key=Value case
			env = append(env, fmt.Sprintf("%s=\"%s\"", keyAndValueSlice[0], keyAndValueSlice[1]))
		} else {
			//handles Key= case
			env = append(env, e)
		}
	}

	for k, v := range userEnvVars {
		env = append(env, fmt.Sprintf("%s=\"%s\"", k, v))
	}
	return mountpoints, execpath, workdir, env, nil
}

// prepareProcess sets up anything that needs to be done after the container process is created,
// but before it runs (for example networking)
func prepareProcess(pid int, VifList []types.VifInfo) error {
	log.Infof("prepareProcess(%d, %v)", pid, VifList)
	for _, iface := range VifList {
		if iface.Vif == "" {
			return fmt.Errorf("Interface requires a name")
		}

		var link netlink.Link
		var err error

		link, err = netlink.LinkByName(iface.Vif)
		if err != nil {
			return fmt.Errorf("prepareProcess: Cannot find interface %s: %v", iface.Vif, err)
		}

		if err := netlink.LinkSetNsPid(link, int(pid)); err != nil {
			return fmt.Errorf("prepareProcess: Cannot move interface %s into namespace: %v", iface.Vif, err)
		}
	}

	binds := []struct {
		ns   string
		path string
	}{
		{"cgroup", ""},
		{"ipc", ""},
		{"mnt", ""},
		{"net", ""},
		{"pid", ""},
		{"user", ""},
		{"uts", ""},
	}

	for _, b := range binds {
		if err := bindNS(b.ns, b.path, pid); err != nil {
			return err
		}
	}

	return nil
}

func getSavedImageInfo(containerPath string) (ocispec.Image, error) {
	var image ocispec.Image

	data, err := ioutil.ReadFile(filepath.Join(containerPath, imageConfigFilename))
	if err != nil {
		return image, err
	}
	if err := json.Unmarshal(data, &image); err != nil {
		return image, err
	}
	return image, nil
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

// bind mount a namespace file
func bindNS(ns string, path string, pid int) error {
	if path == "" {
		return nil
	}
	// the path and file need to exist for the bind to succeed, so try to create
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("bindNS: Cannot create leading directories %s for bind mount destination: %v", dir, err)
	}
	fi, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("bindNS: Cannot create a mount point for namespace bind at %s: %v", path, err)
	}
	if err := fi.Close(); err != nil {
		return err
	}
	if err := unix.Mount(fmt.Sprintf("/proc/%d/ns/%s", pid, ns), path, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bindNS: Failed to bind %s namespace at %s: %v", ns, path, err)
	}
	return nil
}
