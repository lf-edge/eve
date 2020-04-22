// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/opencontainers/image-spec/identity"
	uuid "github.com/satori/go.uuid"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/mount"
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
	containerConfigFilename = "config.json"
	// container config file name
	imageConfigFilename = "image-config.json"
	// container pid file name
	pidFilename = "pid"
	// default snapshotter used by containerd
	defaultSnapshotter = "overlayfs"
)

var (
	ctrdCtx context.Context
	// CtrdClient is a handle to the current containerd client API
	CtrdClient *containerd.Client
)

// InitContainerdClient initializes CtrdClient and ctrdCtx
func InitContainerdClient() error {
	var err error
	CtrdClient, err = containerd.New(ctrdSocket, containerd.WithDefaultRuntime(containerdRunTime))
	if err != nil {
		log.Errorf("could not create containerd client. %v", err.Error())
		return fmt.Errorf("initContainerdClient: could not create containerd client. %v", err.Error())
	}
	ctrdCtx = namespaces.WithNamespace(context.Background(), ctrdServicesNamespace)
	return nil
}

// GetContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func GetContainerPath(containerID string) string {
	return path.Join(containersRoot, containerID)
}

// getContainerRootfs return the path to the root of the container filesystem
func getContainerRootfs(containerID string) string {
	return path.Join(GetContainerPath(containerID), containerRootfsPath)
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
func SnapshotRm(containerPath string, silent bool) error {
	log.Infof("snapshotRm %s\n", containerPath)

	containerID := filepath.Base(containerPath)

	if err := deleteBundle(containerID, silent); err != nil {
		err = fmt.Errorf("snapshotRm: unable to delete bundle: %v. %v", containerID, err.Error())
		log.Error(err)
		if !silent {
			return err
		}
	}

	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	if err := snapshotter.Remove(ctrdCtx, getSnapshotName(containerID)); err != nil {
		err = fmt.Errorf("snapshotRm: unable to remove snapshot: %v. %v", containerID, err)
		log.Error(err)
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
// from cache invalidation
func SnapshotPrepare(containerPath string, ociFilename string) error {
	log.Infof("snapshotPrepare(%s, %s)", containerPath, ociFilename)
	containerID := filepath.Base(containerPath)
	// On device restart, the existing bundle is not deleted, we need to delete the
	// existing bundle of the container and recreate it. This is safe to run even
	// when bundle doesn't exist
	if SnapshotRm(containerID, true) != nil {
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
	snapshot := getSnapshotName(containerID)
	labels := map[string]string{"containerd.io/gc.root": time.Now().UTC().Format(time.RFC3339)}
	if mounts, err := snapshotter.Prepare(ctrdCtx, snapshot, parent, snapshots.WithLabels(labels)); err != nil {
		log.Errorf("Could not create a snapshot from: %s. %v", parent, err)
		return fmt.Errorf("snapshotPrepare: Could not create a snapshot from: %s. %v", parent, err)
	} else {
		log.Infof("snapshotPrepare: preared a snapshot for %v with the following mounts: %v", snapshot, mounts)
	}

	// retrieve image metadata to be passed into createBundle
	imageConfigJSON, err := getImageInfoJSON(ctrdCtx, ctrdImage)
	if err != nil {
		log.Errorf("Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
		return fmt.Errorf("snapshotPrepare: Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
	}

	err = createBundle(containerID, getSnapshotName(containerID), imageConfigJSON)
	if err != nil {
		log.Errorf("Could not build rootfs of container: %v. %v", containerID, err.Error())
		return fmt.Errorf("snapshotPrepare: Could not build rootfs of container: %v. %v", containerID, err.Error())
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

//createBundle - assigns a UUID and creates a bundle for container's rootFs
func createBundle(bundleID string, snapshotName, imageConfigJSON string) error {
	appDir := GetContainerPath(bundleID)
	rootFsDir := path.Join(appDir, containerRootfsPath)
	//rootFsDir := getContainerRootfs(container.ID())
	if err := os.MkdirAll(rootFsDir, 0766); err != nil {
		return fmt.Errorf("createBundle: Exception while creating rootFS dir. %v", err)
	}

	if err := ioutil.WriteFile(filepath.Join(appDir, imageConfigFilename), []byte(imageConfigJSON), 0666); err != nil {
		return fmt.Errorf("createBundle: Exception while writing image info to %v/%v. %v", appDir, imageConfigFilename, err)
	}

	if err := ioutil.WriteFile(filepath.Join(appDir, pidFilename), []byte(bundleID), 0666); err != nil {
		return fmt.Errorf("createBundle: Exception while writing container pid to %v/%v. %v", appDir, pidFilename, err)
	}
	snapshotMountPoints, err := getMountPointsFromSnapshot(snapshotName)
	if err != nil {
		return fmt.Errorf("Exception while preparing snapshot: %v mount-points. %v", snapshotName, err)
	}
	if len(snapshotMountPoints) > 1 {
		return fmt.Errorf("More than 1 mount-point for snapshot %v.", snapshotName)
	}
	if err = snapshotMountPoints[0].Mount(rootFsDir); err != nil {
		return fmt.Errorf("Exception while mounting rootfs. Error: %v", err)
	}
	return nil
}

func getMountPointsFromSnapshot(mountKey string) ([]mount.Mount, error) {
	snapshotter := CtrdClient.SnapshotService(defaultSnapshotter)
	mounts, err := snapshotter.Mounts(ctrdCtx, mountKey)
	if err != nil {
		return nil, err
	}
	return mounts, nil
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

// deleteBundle remove an existing container bundle. If silent is true, then operation failures are ignored and no error is returned
func deleteBundle(containerID string, silent bool) error {
	if err := syscall.Unmount(getContainerRootfs(containerID), 0); err != nil {
		log.Errorf("deleteBundle: exception while unmounting: %v. %v", getContainerRootfs(containerID), err.Error())
		if !silent {
			return fmt.Errorf("deleteBundle: Exception while unmounting: %v. %v", getContainerRootfs(containerID), err.Error())
		}
	}
	if err := os.RemoveAll(GetContainerPath(containerID)); err != nil {
		log.Errorf("deleteBundle: exception while deleting: %v. %v", GetContainerPath(containerID), err.Error())
		if !silent {
			return fmt.Errorf("deleteBundle: Exception while deleting: %v. %v", GetContainerPath(containerID), err.Error())
		}
	}
	return nil
}

func isContainerNotFound(e error) bool {
	return strings.HasSuffix(e.Error(), ": not found")
}

func getSnapshotName(containerID string) string {
	return fmt.Sprintf("%s-snapshot", containerID)
}

// getContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func getContainerPath(containerID string) string {
	return path.Join(containersRoot, containerID)
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

// ctrRun eventually will run a container. For now, we do not actually run it via containerd,
// but instead use containerd to set it up, and xl to run it, so this does not need to do anything.
// If/when we invert it, and have containerd launch the container with a microvm wrapper,
// *then* this will need to work.
func ctrRun(domainName, xenCfgFilename, imageHash string, envList map[string]string) (int, string, error) {

	log.Infof("ctrRun %s\n", domainName)
	return 0, "", nil
}

// ctrStop eventually will stop a container. For now, we do not actually run it via containerd,
// but instead use containerd to set it up, and xl to run it, so this does not need to do anything.
// If/when we invert it, and have containerd launch the container with a microvm wrapper,
// *then* this will need to work.
func ctrStop(containerID string, force bool) error {
	log.Infof("ctrStop %s %t\n", containerID, force)
	log.Infof("ctr stop done\n")
	return nil
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
