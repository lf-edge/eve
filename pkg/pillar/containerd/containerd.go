// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/opencontainers/image-spec/identity"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/sys/unix"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/snapshots"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
)

const (
	// containerd socket
	ctrdSocket = "/run/containerd/containerd.sock"
	// ctrdServicesNamespace containerd namespace for running containers
	ctrdServicesNamespace = "eve-user-apps"
	//containerdRunTime - default runtime of containerd
	containerdRunTime = "io.containerd.runtime.v1.linux"

	// root path to all containers
	containersRoot = "/persist/runx/pods/prepared"
	// relative path to rootfs for an individual container
	containerRootfsPath = "rootfs/"
	// container config file name
	imageConfigFilename = "image-config.json"
	// default snapshotter used by containerd
	defaultSnapshotter = "overlayfs"
	// default socket to connect tasks to memlogd
	logWriteSocket = "/var/run/linuxkit-external-logging.sock"
	// default socket to read from memlogd
	logReadSocket = "/var/run/memlogdq.sock"
	// default signal to kill tasks
	defaultSignal = "SIGTERM"
)

var (
	ctrdCtx context.Context
	// CtrdClient is a handle to the current containerd client API
	CtrdClient *containerd.Client
)

// InitContainerdClient initializes CtrdClient and ctrdCtx
func InitContainerdClient() error {
	var err error
	ctrdCtx = namespaces.WithNamespace(context.Background(), ctrdServicesNamespace)
	CtrdClient, err = containerd.New(ctrdSocket, containerd.WithDefaultRuntime(containerdRunTime))
	if err != nil {
		log.Errorf("could not create containerd client. %v", err.Error())
		return fmt.Errorf("initContainerdClient: could not create containerd client. %v", err.Error())
	}
	return nil
}

// GetContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func GetContainerPath(containerID string) string {
	return path.Join(containersRoot, containerID)
}

// containerdLoadImageTar load an image tar into the containerd content store
func containerdLoadImageTar(filename string) (map[string]images.Image, error) {
	// load the content into the containerd content store
	var err error

	if CtrdClient == nil {
		return nil, fmt.Errorf("containerdLoadImageTar: Container client is nil")
	}

	if ctrdCtx == nil {
		return nil, fmt.Errorf("containerdLoadImageTar: Container context is nil")
	}

	tarReader, err := os.Open(filename)
	if err != nil {
		log.Errorf("could not open tar file for reading at %s: %+s", filename, err.Error())
		return nil, err
	}

	imgs, err := CtrdClient.Import(ctrdCtx, tarReader)
	if err != nil {
		log.Errorf("could not load image tar at %s into containerd: %+s", filename, err.Error())
		return nil, err
	}
	// successful, so return the list of images we imported
	names := make(map[string]images.Image)
	for _, tag := range imgs {
		names[tag.Name] = tag
	}
	return names, nil
}

// SnapshotRm removes existing snapshot. If silent is true, then operation failures are ignored and no error is returned
func SnapshotRm(rootPath string, silent bool) error {
	log.Infof("snapshotRm %s\n", rootPath)

	snapshotID := filepath.Base(rootPath)

	if err := syscall.Unmount(filepath.Join(rootPath, containerRootfsPath), 0); err != nil {
		err = fmt.Errorf("snapshotRm: exception while unmounting: %v/%v. %v", rootPath, containerRootfsPath, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}

	if err := os.RemoveAll(rootPath); err != nil {
		err = fmt.Errorf("snapshotRm: exception while deleting: %v. %v", rootPath, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}

	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	if err := snapshotter.Remove(ctrdCtx, snapshotID); err != nil {
		err = fmt.Errorf("snapshotRm: unable to remove snapshot: %v. %v", snapshotID, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}
	return nil
}

// SnapshotPrepare prepares a writable snapshot from an OCI layers bundle
// We always do it from scratch all the way, ignoring any existing state
// that may have accumulated (like existing snapshots being avilable, etc.)
// This effectively voids any kind of caching, but on the flip side frees us
// from cache invalidation. Additionally we deposit an OCI config json file
// next to the rootfs so that the effective structure becomes:
//    rootPath/rootfs, rootPath/image-config.json
// We also expect rootPath to end in a basename that becomes containerd's
// snapshotID
func SnapshotPrepare(rootPath string, ociFilename string) error {
	log.Infof("snapshotPrepare(%s, %s)", rootPath, ociFilename)
	// On device restart, the existing bundle is not deleted, we need to delete the
	// existing bundle of the container and recreate it. This is safe to run even
	// when bundle doesn't exist
	if SnapshotRm(rootPath, true) != nil {
		log.Infof("snapshotPrepare: tried to clean up any existing state, hopefully it worked")
	}

	loadedImages, err := containerdLoadImageTar(ociFilename)
	if err != nil {
		log.Errorf("failed to load Image File at %s into containerd: %+s", ociFilename, err.Error())
		return err
	}

	// we currently only support one image per file; will change eventually
	if len(loadedImages) != 1 {
		log.Errorf("loaded %d images, expected just 1", len(loadedImages))
	}
	var image images.Image
	for _, imgObj := range loadedImages {
		image = imgObj
	}
	// doing this step as we need the image in containerd.Image structure for container create.
	ctrdImage := containerd.NewImage(CtrdClient, image)
	imageInfo, err := getImageInfo(ctrdCtx, ctrdImage)
	if err != nil {
		return fmt.Errorf("ctrPrepare: unable to get image: %v config: %v", ctrdImage.Name(), err)
	}
	mountpoints := imageInfo.Config.Volumes
	execpath := imageInfo.Config.Entrypoint
	cmd := imageInfo.Config.Cmd
	workdir := imageInfo.Config.WorkingDir
	unProcessedEnv := imageInfo.Config.Env
	log.Infof("mountPoints %+v execpath %+v cmd %+v workdir %+v env %+v",
		mountpoints, execpath, cmd, workdir, unProcessedEnv)

	// unpack the rootfs Image if needed
	unpacked, err := ctrdImage.IsUnpacked(ctrdCtx, defaultSnapshotter)
	if err != nil {
		return fmt.Errorf("snapshotPrepare: unable to get image metadata: %v config: %v", ctrdImage.Name(), err)
	}
	if !unpacked {
		if err := ctrdImage.Unpack(ctrdCtx, defaultSnapshotter); err != nil {
			return fmt.Errorf("snapshotPrepare: unable to unpack image: %v config: %v", ctrdImage.Name(), err)
		}
	}

	// use rootfs unpacked image to create a writable snapshot with default snapshotter
	diffIDs, err := ctrdImage.RootFS(ctrdCtx)
	if err != nil {
		log.Errorf("Could not load rootfs of image: %v. %v", ctrdImage.Name(), err)
		return fmt.Errorf("snapshotPrepare: Could not load rootfs of image: %v. %v", ctrdImage.Name(), err)
	}

	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	parent := identity.ChainID(diffIDs).String()
	snapshotID := filepath.Base(rootPath)
	labels := map[string]string{"containerd.io/gc.root": time.Now().UTC().Format(time.RFC3339)}
	mounts, err := snapshotter.Prepare(ctrdCtx, snapshotID, parent, snapshots.WithLabels(labels))
	if err != nil {
		log.Errorf("Could not create a snapshot from: %s. %v", parent, err)
		return fmt.Errorf("snapshotPrepare: Could not create a snapshot from: %s. %v", parent, err)
	} else {
		if len(mounts) > 1 {
			return fmt.Errorf("More than 1 mount-point for snapshot %v %v", rootPath, mounts)
		} else {
			log.Infof("snapshotPrepare: preared a snapshot for %v with the following mounts: %v", snapshotID, mounts)
		}
	}

	// final step is to mount the snapshot into rootPath/containerRootfsPath and unpack
	// image config OCI json into rootPath/imageConfigFilename
	rootFsDir := path.Join(rootPath, containerRootfsPath)
	if err := os.MkdirAll(rootFsDir, 0766); err != nil {
		return fmt.Errorf("createBundle: Exception while creating rootFS dir. %v", err)
	}
	if err = mounts[0].Mount(rootFsDir); err != nil {
		return fmt.Errorf("Exception while mounting rootfs %v via %v. Error: %v", rootFsDir, mounts, err)
	}

	// final step is to deposit OCI image config json
	imageConfigJSON, err := getImageInfoJSON(ctrdCtx, ctrdImage)
	if err != nil {
		log.Errorf("Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
		return fmt.Errorf("snapshotPrepare: Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
	}
	if err := ioutil.WriteFile(filepath.Join(rootPath, imageConfigFilename), []byte(imageConfigJSON), 0666); err != nil {
		return fmt.Errorf("createBundle: Exception while writing image info to %v/%v. %v", rootPath, imageConfigFilename, err)
	}

	return nil
}

func loadContainer(containerID string) (containerd.Container, error) {
	if CtrdClient == nil {
		return nil, fmt.Errorf("loadContainer: Container client is nil")
	}

	if ctrdCtx == nil {
		return nil, fmt.Errorf("loadContainer: Container context is nil")
	}

	container, err := CtrdClient.LoadContainer(ctrdCtx, containerID)
	if err != nil {
		err = fmt.Errorf("loadContainer: Exception while loading container: %v", err)
	}
	return container, err
}

func getImageInfo(ctrdCtx context.Context, image containerd.Image) (v1.Image, error) {
	var ociimage v1.Image
	ic, err := image.Config(ctrdCtx)
	if err != nil {
		return ociimage, fmt.Errorf("getImageConfig: ubable to fetch image: %v config. %v", image.Name(), err.Error())
	}
	switch ic.MediaType {
	case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
		p, err := content.ReadBlob(ctrdCtx, image.ContentStore(), ic)
		if err != nil {
			return ociimage, fmt.Errorf("getImageConfig: ubable to read cotentStore of image: %v config. %v", image.Name(), err.Error())
		}

		if err := json.Unmarshal(p, &ociimage); err != nil {
			return ociimage, fmt.Errorf("getImageConfig: ubable to marshal cotentStore of image: %v config. %v", image.Name(), err.Error())

		}
	default:
		return ociimage, fmt.Errorf("unknown image config media type %s", ic.MediaType)
	}
	return ociimage, nil
}

func getImageInfoJSON(ctrdCtx context.Context, image containerd.Image) (string, error) {
	ociimage, err := getImageInfo(ctrdCtx, image)
	if err != nil {
		return "", fmt.Errorf("getImageInfoJSON: ubable to fetch image: %v. %v", image.Name(), err.Error())
	}
	return getJSON(ociimage)
}

// Util methods

// getJSON - returns input in JSON format
func getJSON(x interface{}) (string, error) {
	b, err := json.MarshalIndent(x, "", "    ")
	if err != nil {
		return "", fmt.Errorf("getJSON: Exception while marshalling container spec JSON. %v", err)
	}
	return fmt.Sprint(string(b)), nil
}

func isContainerNotFound(e error) bool {
	return strings.HasSuffix(e.Error(), ": not found")
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

func getSavedImageInfo(containerID string) (v1.Image, error) {
	var image v1.Image

	appDir := getContainerPath(containerID)
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
		return fmt.Errorf("Cannot create leading directories %s for bind mount destination: %v", dir, err)
	}
	fi, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Cannot create a mount point for namespace bind at %s: %v", path, err)
	}
	if err := fi.Close(); err != nil {
		return err
	}
	if err := unix.Mount(fmt.Sprintf("/proc/%d/ns/%s", pid, ns), path, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("Failed to bind %s namespace at %s: %v", ns, path, err)
	}
	return nil
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
			return fmt.Errorf("Cannot find interface %s: %v", iface.Vif, err)
		}

		if err := netlink.LinkSetNsPid(link, int(pid)); err != nil {
			return fmt.Errorf("Cannot move interface %s into namespace: %v", iface.Vif, err)
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

// CtrInfo looks up
func CtrInfo(name string) (int, string, error) {
	c, err := loadContainer(name)
	if err == nil {
		if t, err := c.Task(ctrdCtx, nil); err == nil {
			if stat, err := t.Status(ctrdCtx); err == nil {
				return int(t.Pid()), string(stat.Status), nil
			}
		}
	}
	return 0, "", err
}

// CtrStart starts the default task in a pre-existing container and attaches its logging to memlogd
func CtrStart(domainName string) (int, error) {
	ctr, err := loadContainer(domainName)
	if err != nil {
		return 0, err
	}

	logger := GetLog()

	// This is silly but necessary due to containerd bug
	// https://github.com/containerd/containerd/issues/4019
	// essentially, when you create a container and then remove it,
	// containerd blows away everything in the parent dir of the first one it finds,
	// in this case, "/dev/null", so it blows away everything in "/dev".
	// This most certainly is a "bad thing".
	//
	// To fix it temporarily, we are creating a tmpdir and creating a null
	// device there, so that it can blow away the tempdir
	stdinDir := path.Join("/run", "containers-stdin", domainName)
	if err := os.MkdirAll(stdinDir, 0700); err != nil {
		return 0, err
	}
	stdinFile := path.Join(stdinDir, "null")
	// make a dev null in stdinDir
	if err := syscall.Mknod(stdinFile, uint32(os.FileMode(0660)|syscall.S_IFCHR), int(unix.Mkdev(1, 3))); err != nil {
		return 0, err
	}

	io := func(id string) (cio.IO, error) {
		stdoutFile := logger.Path(domainName + ".out")
		stderrFile := logger.Path(domainName)
		return &logio{
			cio.Config{
				Stdin:    stdinFile,
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

// CtrStop stops (kills) the main task in the container
func CtrStop(containerID string, force bool) error {
	ctr, err := CtrdClient.LoadContainer(ctrdCtx, containerID)
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

// CtrDelete is a simple wrapper around container.Delete()
func CtrDelete(containerID string) error {
	ctr, err := loadContainer(containerID)
	if err != nil {
		return err
	}

	// do this just in case
	_ = CtrStop(containerID, true)

	return ctr.Delete(ctrdCtx)
}

// CtrPrepareMount creates special files for running container inside a VM
func CtrPrepareMount(containerID uuid.UUID, containerPath string, envVars map[string]string, noOfDisks int) error {
	log.Infof("ctrPrepareMount(%s, %s, %v, %d)", containerID, containerPath,
		envVars, noOfDisks)
	imageInfo, err := getSavedImageInfo(containerID.String())
	if err != nil {
		log.Errorf("ctrPrepareMount(%s, %s) getImageInfo failed: %s",
			containerID, containerPath, err)
		return err
	}
	// inject a few files of our own into the bundle
	mountpoints, execpath, workdir, env, err := getContainerConfigs(imageInfo, envVars)
	if err != nil {
		log.Errorf("ctrPrepareMount(%s, %s) getContainerConfigs failed: %s",
			containerID, containerPath, err)
		return fmt.Errorf("ctrPrepare: unable to get container config: %v", err)
	}

	err = createMountPointExecEnvFiles(containerPath, mountpoints, execpath, workdir, env, noOfDisks)
	if err != nil {
		log.Errorf("ctrPrepareMount(%s, %s) createMountPointExecEnvFiles failed: %s",
			containerID, containerPath, err)
	}
	return err
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

// LKTaskLaunch runs a task in a new containter created as per linuxkit runtime OCI spec
// file and optional bundle of DomainConfig settings and command line options. Because
// we're expecting a linuxkit produced filesystem layout we expect R/O portion of the
// filesystem to be available under `dirname specFile`/lower and we will be mounting
// it R/O into the container. On top of that we expect the usual suspects of /run,
// /persist and /config to be taken care of by the OCI config that lk produced.
func LKTaskLaunch(name, linuxkit string, domSettings *types.DomainConfig, args []string) (int, error) {
	config := "/containers/services" + linuxkit + "/config.json"
	rootfs := "/containers/services" + linuxkit + "/lower"

	f, err := os.Open(config)
	if err != nil {
		return 0, fmt.Errorf("can't open spec file %s %v", config, err)
	}

	spec, err := NewOciSpec(name)
	if err != nil {
		return 0, err
	}
	if err = spec.Load(f); err != nil {
		return 0, fmt.Errorf("can't load spec file from %s %v", config, err)
	}

	spec.Root.Path = rootfs
	spec.Root.Readonly = true
	if domSettings != nil {
		spec.UpdateFromDomain(*domSettings)
	}

	if args != nil {
		spec.Process.Args = args
	}

	if err = spec.CreateContainer(true); err == nil {
		return CtrStart(name)
	}

	return 0, err
}
