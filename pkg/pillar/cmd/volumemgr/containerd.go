// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/typeurl"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
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
	ctrdCtx    context.Context
	ctrdClient *containerd.Client
)

func initContainerdClient() error {
	var err error
	ctrdClient, err = containerd.New(ctrdSocket, containerd.WithDefaultRuntime(containerdRunTime))
	if err != nil {
		log.Errorf("could not create containerd client. %v", err.Error())
		return fmt.Errorf("initContainerdClient: could not create containerd client. %v", err.Error())
	}
	ctrdCtx = namespaces.WithNamespace(context.Background(), ctrdServicesNamespace)
	return nil
}

// getContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func getContainerPath(containerID string) string {
	return path.Join(containersRoot, containerID)
}

// getContainerRootfs return the path to the root of the container filesystem
func getContainerRootfs(containerID string) string {
	return path.Join(getContainerPath(containerID), containerRootfsPath)
}

// containerdLoadImageTar load an image tar into the containerd content store
func containerdLoadImageTar(filename string) (map[string]images.Image, error) {
	// load the content into the containerd content store
	var err error

	if ctrdClient == nil {
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

	imgs, err := ctrdClient.Import(ctrdCtx, tarReader)
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

// ctrRm remove an existing container. If silent is true, then operation failures are ignored and no error is returned
func ctrRm(containerPath string, silent bool) error {
	log.Infof("ctrRm %s\n", containerPath)

	containerID := filepath.Base(containerPath)
	container, err := loadContainer(containerID)
	if err != nil {
		err = fmt.Errorf("ctrRm: exception while loading container: %v. %v", containerID, err.Error())
		log.Error(err)
		if !silent {
			return err
		}
	}
	if container == nil {
		return nil
	}
	if err := container.Delete(ctrdCtx, containerd.WithSnapshotCleanup); err != nil {
		err = fmt.Errorf("ctrRm: unable to delete container: %v. %v", containerID, err.Error())
		log.Error(err)
		if !silent {
			return err
		}

	}
	if err := deleteBundle(containerID, silent); err != nil {
		err = fmt.Errorf("ctrRm: unable to delete bundle of container: %v. %v", containerID, err.Error())
		log.Error(err)
		if !silent {
			return err
		}
	}
	return nil
}

// ctrCreate create a new container but do not start it
func ctrCreate(containerID string, ctrdImage containerd.Image) error {
	var (
		ociOpts       []oci.SpecOpts
		containerOpts []containerd.NewContainerOpts
		ociSpec       oci.Spec
		err           error
	)
	if ctrdClient == nil {
		return fmt.Errorf("ctrCreate: Container client is nil")
	}

	if ctrdCtx == nil {
		return fmt.Errorf("ctrCreate: Container context is nil")
	}

	// containerOpts = append(containerOpts, containerd.WithNewSpec(oci.WithImageConfig(ctrdImage)))
	containerSnapshot := getSnapshotName(containerID)
	containerOpts = append(containerOpts,
		containerd.WithImage(ctrdImage),
		containerd.WithSnapshotter(defaultSnapshotter),
		containerd.WithNewSnapshot(containerSnapshot, ctrdImage),
		containerd.WithRuntime("io.containerd.runc.v2", &options.Options{}),
		containerd.WithSpec(&ociSpec, ociOpts...))
	container, err := ctrdClient.NewContainer(
		ctrdCtx,
		containerID,
		containerOpts...,
	)
	if err != nil {
		log.Errorf("Could not build new containerd container: %v. %v", containerID, err.Error())
		return fmt.Errorf("ctrCreate: Could not build new containerd container: %v. %v", containerID, err.Error())
	}
	imageConfigJSON, err := getImageInfoJSON(ctrdCtx, ctrdImage)
	if err != nil {
		container.Delete(ctrdCtx)
		log.Errorf("Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
		return fmt.Errorf("ctrCreate: Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
	}
	err = createBundle(container, containerSnapshot, imageConfigJSON)
	if err != nil {
		ctrRm(containerID, true)
		log.Errorf("Could not build rootfs of container: %v. %v", containerID, err.Error())
		return fmt.Errorf("ctrCreate: Could not build rootfs of container: %v. %v", containerID, err.Error())
	}
	return nil
}

// ctrPrepare prepare an existing container
func ctrPrepare(containerPath string, ociFilename string) error {
	log.Infof("ctrPrepare(%s, %s)", containerPath, ociFilename)
	containerID := filepath.Base(containerPath)
	// On device restart, the existing bundle is not deleted, we need to delete the existing bundle of the container and recreate it.
	if isBundleExists(containerID) {
		log.Infof("ctrPrepare: a bundle with ID: %v already exists. Cleaning existing bundle and recreating it", containerID)
		ctrRm(containerID, true)
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
	ctrdImage := containerd.NewImage(ctrdClient, image)
	imageInfo, err := getImageInfo(ctrdCtx, ctrdImage)
	mountpoints := imageInfo.Config.Volumes
	execpath := imageInfo.Config.Entrypoint
	cmd := imageInfo.Config.Cmd
	workdir := imageInfo.Config.WorkingDir
	unProcessedEnv := imageInfo.Config.Env
	log.Infof("mountPoints %+v execpath %+v cmd %+v workdir %+v env %+v",
		mountpoints, execpath, cmd, workdir, unProcessedEnv)

	if err != nil {
		return fmt.Errorf("ctrPrepare: unable to get image: %v config: %v", ctrdImage.Name(), err)
	}
	// containerd.NewImageWithPlatform(client, i, platforms.Only(platform))
	unpacked, err := ctrdImage.IsUnpacked(ctrdCtx, defaultSnapshotter)
	if err != nil {
		return fmt.Errorf("ctrPrepare: unable to get image metadata: %v config: %v", ctrdImage.Name(), err)
	}
	if !unpacked {
		if err := ctrdImage.Unpack(ctrdCtx, defaultSnapshotter); err != nil {
			return fmt.Errorf("ctrPrepare: unable to unpack image: %v config: %v", ctrdImage.Name(), err)
		}
	}
	if err = ctrCreate(filepath.Base(containerPath), ctrdImage); err != nil {
		return fmt.Errorf("ctrPrepare: failed to create container %s, error: %v", containerPath, err.Error())
	}
	return nil
}

func loadContainer(containerID string) (containerd.Container, error) {
	if ctrdClient == nil {
		return nil, fmt.Errorf("loadContainer: Container client is nil")
	}

	if ctrdCtx == nil {
		return nil, fmt.Errorf("loadContainer: Container context is nil")
	}

	container, err := ctrdClient.LoadContainer(ctrdCtx, containerID)
	if err != nil && !isContainerNotFound(err) {
		return nil, fmt.Errorf("loadContainer: Exception while loading container. %v", err)
	}
	return container, nil
}

// getContainerInfo - returns container config as JSON
func getContainerInfo(ctrdCtx context.Context, container containerd.Container) (string, error) {
	info, err := container.Info(ctrdCtx)
	if err != nil {
		return "", fmt.Errorf("getContainerInfo: Exception while fetching container info. %v", err)
	}
	if info.Spec != nil && info.Spec.Value != nil {
		typeurl.Register(&specs.Spec{}, "types.containerd.io", "opencontainers/runtime-spec", "1", "Spec")
		specValue, err := typeurl.UnmarshalAny(info.Spec)
		if err != nil {
			return "", fmt.Errorf("getContainerInfo: Exception while fetching container spec. %v", err)
		}
		if err != nil {
			return "", fmt.Errorf("getContainerInfo: Exception while fetching container spec. %v", err)
		}
		res, err := getJSON(struct {
			containers.Container
			Spec interface{} `json:"Spec,omitempty"`
		}{
			Container: info,
			Spec:      specValue,
		})
		if err != nil {
			return "", fmt.Errorf("getContainerInfo: Exception while unmarshalling existing container spec. %v", err)
		}
		return res, nil
	}
	res, err := getJSON(info)
	if err != nil {
		return "", fmt.Errorf("getContainerInfo: Exception while unmarshalling newly added container spec. %v", err)
	}
	return res, nil
}

//createBundle - assigns a UUID and creates a bundle for container's rootFs
func createBundle(container containerd.Container, snapshotName, imageConfigJSON string) error {
	appDir := getContainerPath(container.ID())
	rootFsDir := path.Join(appDir, containerRootfsPath)
	//rootFsDir := getContainerRootfs(container.ID())
	if err := os.MkdirAll(rootFsDir, 0766); err != nil {
		return fmt.Errorf("createBundle: Exception while creating rootFS dir. %v", err)
	}

	containerConfig, err := getContainerInfo(ctrdCtx, container)
	if err != nil {
		return fmt.Errorf("createBundle: Exception while fetching container info. %v", err)
	}
	if err = ioutil.WriteFile(filepath.Join(appDir, containerConfigFilename), []byte(containerConfig), 0666); err != nil {
		return fmt.Errorf("createBundle: Exception while writing container info to %v/%v. %v", appDir, containerConfigFilename, err)
	}

	if err = ioutil.WriteFile(filepath.Join(appDir, imageConfigFilename), []byte(imageConfigJSON), 0666); err != nil {
		return fmt.Errorf("createBundle: Exception while writing image info to %v/%v. %v", appDir, imageConfigFilename, err)
	}

	if err = ioutil.WriteFile(filepath.Join(appDir, pidFilename), []byte(container.ID()), 0666); err != nil {
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
	snapshotter := ctrdClient.SnapshotService(defaultSnapshotter)
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
	if err := os.RemoveAll(getContainerPath(containerID)); err != nil {
		log.Errorf("deleteBundle: exception while deleting: %v. %v", getContainerPath(containerID), err.Error())
		if !silent {
			return fmt.Errorf("deleteBundle: Exception while deleting: %v. %v", getContainerPath(containerID), err.Error())
		}
	}
	return nil
}

func isContainerNotFound(e error) bool {
	return strings.HasSuffix(e.Error(), ": not found")
}

func isBundleExists(containerID string) bool {
	if _, err := os.Stat(getContainerPath(containerID)); os.IsNotExist(err) {
		return false
	}
	return true
}

func getSnapshotName(containerID string) string {
	return fmt.Sprintf("%s-snapshot", containerID)
}
