// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
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
	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	spec "github.com/opencontainers/image-spec/specs-go/v1"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
)

const (
	// root path to all containers
	containersRoot = types.ROContImgDirname
	// container config file name
	imageConfigFilename = "image-config.json"
	// default socket to connect tasks to memlogd
	logWriteSocket = "/var/run/linuxkit-external-logging.sock"
	// default socket to read from memlogd
	logReadSocket = "/var/run/memlogdq.sock"
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

	//TBD: Have a better way to calculate this number.
	//For now it is based on some trial-and-error experiments
	qemuOverHead = int64(500 * 1024 * 1024)
)

var (
	ctrdCtx context.Context
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

//CtrWriteBlobWithLease reads the blob as raw data from `reader` and writes it into containerd with the given lease
func CtrWriteBlobWithLease(blobHash, leaseID string, reader io.Reader) error {
	log.Infof("CtrWriteBlobWithLease: for blob hash: %s", blobHash)
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
	log.Infof("CtrReadBlob: for blob hash: %s", blobHash)
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
	log.Infof("CtrGetBlobInfo: for blob hash: %s", blobHash)
	if err := verifyCtr(); err != nil {
		return content.Info{}, fmt.Errorf("CtrReadBlob: exception while verifying ctrd client: %s", err.Error())
	}
	return contentStore.Info(ctrdCtx, digest.Digest(blobHash))
}

//CtrListBlobInfo returns a list of blob infos as []content.Info
func CtrListBlobInfo() ([]content.Info, error) {
	log.Infof("CtrListBlobInfo")
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
	log.Infof("CtrDeleteBlob: for blob hash: %s", blobHash)
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrDeleteBlob: exception while verifying ctrd client: %s", err.Error())
	}
	return contentStore.Delete(ctrdCtx, digest.Digest(blobHash))
}

//CtrCreateImage create an image in containerd's image store
func CtrCreateImage(image images.Image) (images.Image, error) {
	log.Infof("CtrCreateImage: for image reference: %s", image.Name)
	if err := verifyCtr(); err != nil {
		return images.Image{}, fmt.Errorf("CtrCreateImage: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().Create(ctrdCtx, image)
}

//CtrLoadImage reads image as raw data from `reader` and loads it into containerd. Returns list of loaded image metadata.
func CtrLoadImage(reader *os.File) ([]images.Image, error) {
	log.Infof("CtrLoadImage")
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrLoadImage: exception while verifying ctrd client: %s", err.Error())
	}
	imgs, err := CtrdClient.Import(ctrdCtx, reader)
	if err != nil {
		log.Errorf("CtrLoadImage: could not load image %s into containerd: %+s", reader.Name(), err.Error())
		return nil, err
	}
	return imgs, nil
}

//CtrGetImage returns image object for the reference. Returns error if no image is found for the reference.
func CtrGetImage(reference string) (containerd.Image, error) {
	log.Infof("CtrGetImage: for image reference: %s", reference)
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
	log.Infof("CtrListImages")
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrListImages: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().List(ctrdCtx)
}

//CtrUpdateImage updates the files provided in fieldpaths of the image in containerd'd image store
func CtrUpdateImage(image images.Image, fieldpaths ...string) (images.Image, error) {
	log.Infof("CtrUpdateImage: for image reference: %s. Updating: %v", image.Name, fieldpaths)
	if err := verifyCtr(); err != nil {
		return images.Image{}, fmt.Errorf("CtrUpdateImage: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().Update(ctrdCtx, image, fieldpaths...)
}

//CtrDeleteImage deletes an image with the given reference
func CtrDeleteImage(reference string) error {
	log.Infof("CtrDeleteImage: for image reference: %s", reference)
	if err := verifyCtr(); err != nil {
		return fmt.Errorf("CtrDeleteImage: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.ImageService().Delete(ctrdCtx, reference)
}

//CtrPrepareSnapshot creates snapshot for the given image
func CtrPrepareSnapshot(snapshotID string, image containerd.Image) ([]mount.Mount, error) {
	log.Infof("CtrPrepareSnapshot: for snapshotID: %s", snapshotID)
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
	log.Infof("CtrMountSnapshot: for snapshotID: %s", snapshotID)
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
	log.Infof("CtrListSnapshotInfo")
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
	log.Infof("CtrRemoveSnapshot: for snapshotID: %s", snapshotID)
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
	log.Infof("CtrLoadContainer: for containerID: %s", containerID)
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
	log.Infof("CtrListContainerIds")
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
	log.Infof("CtrListContainer")
	if err := verifyCtr(); err != nil {
		return nil, fmt.Errorf("CtrListContainer: exception while verifying ctrd client: %s", err.Error())
	}
	return CtrdClient.Containers(ctrdCtx)
}

// CtrGetContainerMetrics returns all runtime metrics associated with a container ID
func CtrGetContainerMetrics(containerID string) (*v1stat.Metrics, error) {
	log.Infof("CtrGetContainerMetrics: for containerID: %s", containerID)
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
func CtrContainerInfo(containerName string) (int, string, error) {
	log.Infof("CtrContainerInfo: for container: %s", containerName)
	if err := verifyCtr(); err != nil {
		return 0, "", fmt.Errorf("CtrContainerInfo: exception while verifying ctrd client: %s", err.Error())
	}
	c, err := CtrLoadContainer(containerName)
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
func CtrStartContainer(containerName string) (int, error) {
	log.Infof("CtrStartContainer: for container: %s", containerName)
	if err := verifyCtr(); err != nil {
		return 0, fmt.Errorf("CtrStartContainer: exception while verifying ctrd client: %s", err.Error())
	}
	ctr, err := CtrLoadContainer(containerName)
	if err != nil {
		return 0, err
	}

	logger := GetLog()

	io := func(id string) (cio.IO, error) {
		stdoutFile := logger.Path(containerName + ".out")
		stderrFile := logger.Path(containerName)
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
	log.Infof("CtrStopContainer: for containerID: %s", containerID)
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
	log.Infof("CtrDeleteContainer: for containerID: %s", containerID)
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
	log.Infof("CtrCreateLease: with lease options: %v", leaseOpts)
	if err := verifyCtr(); err != nil {
		return leases.Lease{}, fmt.Errorf("CtrDeleteContainer: exception while verifying ctrd client: %s",
			err.Error())
	}
	return CtrdClient.LeasesService().Create(ctrdCtx, leaseOpts...)
}

// LKTaskLaunch runs a task in a new containter created as per linuxkit runtime OCI spec
// file and optional bundle of DomainConfig settings and command line options. Because
// we're expecting a linuxkit produced filesystem layout we expect R/O portion of the
// filesystem to be available under `dirname specFile`/lower and we will be mounting
// it R/O into the container. On top of that we expect the usual suspects of /run,
// /persist and /config to be taken care of by the OCI config that lk produced.
func LKTaskLaunch(name, linuxkit string, domSettings *types.DomainConfig, args []string) (int, error) {
	config := "/containers/services/" + linuxkit + "/config.json"
	rootfs := "/containers/services/" + linuxkit + "/rootfs"

	log.Infof("Starting LKTaskLaunch for %s", linuxkit)
	f, err := os.Open("/hostfs" + config)
	if err != nil {
		return 0, fmt.Errorf("LKTaskLaunch: can't open spec file %s %v", config, err)
	}

	spec, err := NewOciSpec(name)
	if err != nil {
		log.Errorf("LKTaskLaunch: NewOciSpec failed with error %v", err)
		return 0, err
	}
	if err = spec.Load(f); err != nil {
		return 0, fmt.Errorf("LKTaskLaunch: can't load spec file from %s %v", config, err)
	}

	spec.Root.Path = rootfs
	spec.Root.Readonly = true
	if domSettings != nil {
		spec.UpdateFromDomain(*domSettings, false)
		spec.AdjustMemLimit(*domSettings, qemuOverHead)
	}

	if args != nil {
		spec.Process.Args = args
	}

	//Delete existing container, if any
	if err := CtrDeleteContainer(name); err == nil {
		log.Infof("LKTaskLaunch: Deleted previously existing container %s", name)
	}

	if err = spec.CreateContainer(true); err == nil {
		log.Infof("Starting LKTaskLaunch Container %s", name)
		return CtrStartContainer(name)
	}

	log.Errorf("LKTaskLaunch: CreateContainer failed with error %v", err)
	return 0, err
}

//Util Methods.

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
func getContainerConfigs(imageInfo v1.Image, userEnvVars map[string]string) (map[string]struct{}, []string, string, []string, error) {

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

// getContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below.
func getContainerPath(containerID string) string {
	if filepath.IsAbs(containerID) {
		return containerID
	} else {
		return path.Join(containersRoot, containerID)
	}
}

func getSavedImageInfo(containerPath string) (v1.Image, error) {
	var image v1.Image

	appDir := getContainerPath(containerPath)
	data, err := ioutil.ReadFile(filepath.Join(appDir, imageConfigFilename))
	if err != nil {
		return image, err
	}
	if err := json.Unmarshal(data, &image); err != nil {
		return image, err
	}
	return image, nil
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
