// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	// root path to all containers
	containersRoot = types.ROContImgDirname
	// relative path to rootfs for an individual container
	containerRootfsPath = "rootfs/"
	// container config file name
	imageConfigFilename = "image-config.json"
	// default socket to connect tasks to memlogd
	logWriteSocket = "/var/run/linuxkit-external-logging.sock"
	// default socket to read from memlogd
	logReadSocket = "/var/run/memlogdq.sock"
	// start of containerd gc ref label for children in content store
	containerdGCRef = "containerd.io/gc.ref.content"
)

const (
	//TBD: Have a better way to calculate this number.
	//For now it is based on some trial-and-error experiments
	qemuOverHead = int64(500 * 1024 * 1024)
)

// GetContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func GetContainerPath(containerDir string) string {
	return path.Join(containersRoot, containerDir)
}

// GetSnapshotID handles the upgrade scenario when the snapshotID needs to be
// extracted from a file created by upgradeconverter
// Assumes that rootpath is a complete pathname
func GetSnapshotID(rootpath string) string {
	filename := filepath.Join(rootpath, "snapshotid.txt")
	if _, err := os.Stat(filename); err == nil {
		cont, err := ioutil.ReadFile(filename)
		if err == nil {
			snapshotID := string(cont)
			log.Infof("GetSnapshotID read %s from %s",
				snapshotID, filename)
			return snapshotID
		}
		log.Errorf("GetSnapshotID read %s failed: %s", filename, err)
	}
	snapshotID := filepath.Base(rootpath)
	log.Infof("GetSnapshotID basename %s from %s", snapshotID, rootpath)
	return snapshotID
}

// LoadBlobs load multiple blobs and reference via an image name
func LoadBlobs(blobs []*types.BlobStatus, ref string) error {
	// load the content into the containerd content store
	log.Infof("loadBlobs(%s)", ref)

	var (
		root           *types.BlobStatus
		rootDescriptor ocispec.Descriptor
		index          *ocispec.Index
		indexHash      string
		manifests      = make([]*ocispec.Manifest, 0)
		manifestHashes = make([]string, 0)
	)

	if CtrdClient == nil {
		return fmt.Errorf("LoadBlobs: Container client is nil")
	}

	if ctrdCtx == nil {
		return fmt.Errorf("LoadBlobs: Container context is nil")
	}

	cs := CtrdClient.ContentStore()

	for i, blob := range blobs {
		var (
			r        io.Reader
			filepath = blob.Path
			// the sha MUST be lower-case for it to work with the ocispec utils
			sha  = fmt.Sprintf("%s:%s", digest.SHA256, strings.ToLower(blob.Sha256))
			size = blob.TotalSize
		)
		log.Infof("LoadBlobs: processing blob %+v", blob)
		fileReader, err := os.Open(filepath)
		if err != nil {
			log.Errorf("could not open blob file for reading at %s: %+s", filepath, err.Error())
			return err
		}
		defer fileReader.Close()
		// if this is a manifest or index, we will need to process it as well, so read it
		switch blob.BlobType {
		case types.BlobIndex:
			// read it in so we can process it
			data, err := ioutil.ReadAll(fileReader)
			if err != nil {
				log.Errorf("could not read data at %s: %+s", filepath, err.Error())
				return err
			}
			fileReader.Close()
			// create a new reader for the content.WriteBlob
			r = bytes.NewReader(data)
			// try to parse the index
			if err := json.Unmarshal(data, index); err != nil {
				log.Errorf("could not parse index at %s: %+s", filepath, err.Error())
				return err
			}
			indexHash = sha
		case types.BlobManifest:
			// read it in so we can process it
			data, err := ioutil.ReadAll(fileReader)
			if err != nil {
				log.Errorf("could not read data at %s: %+s", filepath, err.Error())
				return err
			}
			fileReader.Close()
			// create a new reader for the content.WriteBlob
			r = bytes.NewReader(data)
			// try to parse the index
			mfst := ocispec.Manifest{}
			if err := json.Unmarshal(data, &mfst); err != nil {
				log.Errorf("could not parse manifest at %s: %+s", filepath, err.Error())
				return err
			}
			manifests = append(manifests, &mfst)
			manifestHashes = append(manifestHashes, sha)
		default:
			// do nothing special, just pass it on
			r = fileReader
		}
		expectedDigest := digest.Digest(sha)
		if err := expectedDigest.Validate(); err != nil {
			return fmt.Errorf("invalid digest: %v", err)
		}
		desc := ocispec.Descriptor{Size: size, Digest: expectedDigest}
		if err := content.WriteBlob(ctrdCtx, cs, ref, r, desc); err != nil {
			log.Errorf("could not load blob file into containerd at %s: %+s", filepath, err.Error())
			return err
		}
		// first one always is root
		if i == 0 {
			root = blob
			rootDescriptor = desc
		}
	}

	// add the image pointing to the root
	// and walk the tree from the root to add the necessary labels
	var mediaType string

	if index != nil {
		mediaType = ocispec.MediaTypeImageIndex
		info := content.Info{
			Digest: digest.Digest(indexHash),
			Labels: map[string]string{},
		}
		// add all of the labels to the blob
		fields := []string{}
		for i, m := range index.Manifests {
			info.Labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = m.Digest.String()
			fields = append(fields, fmt.Sprintf("labels.%s.%d", containerdGCRef, i))
		}
		_, err := cs.Update(ctrdCtx, info, fields...)
		if err != nil {
			log.Errorf("could not update labels on index: %v", err.Error())
			return err
		}
	}

	if len(manifests) > 0 {
		if mediaType == "" {
			mediaType = ocispec.MediaTypeImageManifest
		}
		for j, m := range manifests {
			info := content.Info{
				Digest: digest.Digest(manifestHashes[j]),
				Labels: map[string]string{},
			}
			// add all of the labels to the blob
			fields := []string{}
			for i, l := range m.Layers {
				info.Labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = l.Digest.String()
				fields = append(fields, fmt.Sprintf("labels.%s.%d", containerdGCRef, i))
			}
			i := len(m.Layers)
			info.Labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = m.Config.Digest.String()
			fields = append(fields, fmt.Sprintf("labels.%s.%d", containerdGCRef, i))
			_, err := cs.Update(ctrdCtx, info, fields...)
			if err != nil {
				log.Errorf("could not update labels on manifest: %v", err.Error())
				return err
			}
		}

	}
	rootDescriptor.MediaType = mediaType

	if root != nil {
		is := CtrdClient.ImageService()
		image := images.Image{
			Name:   ref,
			Target: rootDescriptor,
		}
		// if it already exists, update it rather than creating it
		existingImage, err := is.Get(ctrdCtx, ref)
		if err != nil || existingImage.Name == "" {
			if _, err := is.Create(ctrdCtx, image); err != nil {
				log.Errorf("could not create image for %+v: %v", image, err.Error())
				return err
			}
		} else {
			if _, err := is.Update(ctrdCtx, image); err != nil {
				log.Errorf("could not update image for %+v: %v", image, err.Error())
				return err
			}
		}
	}

	return nil
}

// SnapshotRm removes existing snapshot. If silent is true, then operation failures are ignored and no error is returned
func SnapshotRm(rootPath string, silent bool) error {
	log.Infof("SnapshotRm %s\n", rootPath)

	snapshotID := GetSnapshotID(rootPath)

	if err := syscall.Unmount(filepath.Join(rootPath, containerRootfsPath), 0); err != nil {
		err = fmt.Errorf("SnapshotRm: exception while unmounting: %v/%v. %v", rootPath, containerRootfsPath, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}

	if err := os.RemoveAll(rootPath); err != nil {
		err = fmt.Errorf("SnapshotRm: exception while deleting: %v. %v", rootPath, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}

	if err := CtrRemoveSnapshot(snapshotID); err != nil {
		err = fmt.Errorf("SnapshotRm: unable to remove snapshot: %v. %v", snapshotID, err)
		log.Error(err.Error())
		if !silent {
			return err
		}
	}
	return nil
}

// SnapshotPrepare prepares a writable snapshot from an OCI layers bundle
// We always do it from scratch all the way, ignoring any existing state
// that may have accumulated (like existing snapshots being available, etc.)
// This effectively voids any kind of caching, but on the flip side frees us
// from cache invalidation. Additionally we deposit an OCI config json file
// next to the rootfs so that the effective structure becomes:
//    rootPath/rootfs, rootPath/image-config.json
// We also expect rootPath to end in a basename that becomes containerd's
// snapshotID
func SnapshotPrepare(rootPath string, ref string) error {
	log.Infof("snapshotPrepare(%s, %s)", rootPath, ref)
	// On device restart, the existing bundle is not deleted, we need to delete the
	// existing bundle of the container and recreate it. This is safe to run even
	// when bundle doesn't exist
	if SnapshotRm(rootPath, true) != nil {
		log.Infof("SnapshotPrepare: tried to clean up any existing state, hopefully it worked")
	}

	// doing this step as we need the image in containerd.Image structure for container create.
	ctrdImage, err := CtrdClient.GetImage(ctrdCtx, ref)
	if err != nil {
		return fmt.Errorf("SnapshotPrepare: unable to get image from ref %s", ref)
	}
	imageInfo, err := getImageInfo(ctrdCtx, ctrdImage)
	if err != nil {
		return fmt.Errorf("SnapshotPrepare: unable to get image: %v config: %v", ctrdImage.Name(), err)
	}
	mountpoints := imageInfo.Config.Volumes
	execpath := imageInfo.Config.Entrypoint
	cmd := imageInfo.Config.Cmd
	workdir := imageInfo.Config.WorkingDir
	unProcessedEnv := imageInfo.Config.Env
	log.Infof("SnapshotPrepare: mountPoints %+v execpath %+v cmd %+v workdir %+v env %+v",
		mountpoints, execpath, cmd, workdir, unProcessedEnv)

	// unpack the rootfs Image if needed
	unpacked, err := ctrdImage.IsUnpacked(ctrdCtx, defaultSnapshotter)
	if err != nil {
		return fmt.Errorf("SnapshotPrepare: unable to get image metadata: %v config: %v", ctrdImage.Name(), err)
	}
	if !unpacked {
		if err := ctrdImage.Unpack(ctrdCtx, defaultSnapshotter); err != nil {
			return fmt.Errorf("SnapshotPrepare: unable to unpack image: %v config: %v", ctrdImage.Name(), err)
		}
	}
	snapshotID := GetSnapshotID(rootPath)
	mounts, err := CtrPrepareSnapshot(snapshotID, ctrdImage)
	if err != nil {
		log.Errorf("SnapshotPrepare: Could not create snapshot %s. %v", snapshotID, err)
		return fmt.Errorf("SnapshotPrepare: Could not create snapshot: %s. %v", snapshotID, err)
	} else {
		if len(mounts) > 1 {
			return fmt.Errorf("SnapshotPrepare: More than 1 mount-point for snapshot %v %v", rootPath, mounts)
		} else {
			log.Infof("SnapshotPrepare: preared a snapshot for %v with the following mounts: %v", snapshotID, mounts)
		}
	}

	// final step is to deposit OCI image config json
	imageConfigJSON, err := getImageInfoJSON(ctrdCtx, ctrdImage)
	if err != nil {
		log.Errorf("SnapshotPrepare: Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
		return fmt.Errorf("SnapshotPrepare: Could not build json of image: %v. %v", ctrdImage.Name(), err.Error())
	}
	if err := os.MkdirAll(rootPath, 0766); err != nil {
		return fmt.Errorf("SnapshotPrepare: Exception while creating rootPath dir. %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(rootPath, imageConfigFilename), []byte(imageConfigJSON), 0666); err != nil {
		return fmt.Errorf("SnapshotPrepare: Exception while writing image info to %v/%v. %v", rootPath, imageConfigFilename, err)
	}

	return nil
}

// PrepareMount creates special files for running container inside a VM
func PrepareMount(containerID uuid.UUID, containerPath string, envVars map[string]string, noOfDisks int) error {
	log.Infof("PrepareMount(%s, %s, %v, %d)", containerID, containerPath,
		envVars, noOfDisks)
	imageInfo, err := getSavedImageInfo(containerPath)
	if err != nil {
		log.Errorf("PrepareMount(%s, %s) getImageInfo failed: %s",
			containerID, containerPath, err)
		return err
	}
	// inject a few files of our own into the bundle
	mountpoints, execpath, workdir, env, err := getContainerConfigs(imageInfo, envVars)
	if err != nil {
		log.Errorf("PrepareMount(%s, %s) getContainerConfigs failed: %s",
			containerID, containerPath, err)
		return fmt.Errorf("PrepareMount: unable to get container config: %v", err)
	}

	err = createMountPointExecEnvFiles(containerPath, mountpoints, execpath, workdir, env, noOfDisks)
	if err != nil {
		log.Errorf("PrepareMount(%s, %s) createMountPointExecEnvFiles failed: %s",
			containerID, containerPath, err)
	}
	return err
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

// containerdLoadImageTar load an image tar into the containerd content store
func containerdLoadImageTar(filename string) (map[string]images.Image, error) {
	// load the content into the containerd content store
	var err error

	tarReader, err := os.Open(filename)
	if err != nil {
		log.Errorf("containerdLoadImageTar: could not open tar file for reading at %s: %+s", filename, err.Error())
		return nil, err
	}

	imgs, err := CtrLoadImage(ctrdCtx, tarReader)
	if err != nil {
		log.Errorf("containerdLoadImageTar: could not load image tar at %s into containerd: %+s", filename, err.Error())
		return nil, err
	}
	// successful, so return the list of images we imported
	names := make(map[string]images.Image)
	for _, tag := range imgs {
		names[tag.Name] = tag
	}
	return names, nil
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

func getImageInfo(ctrdCtx context.Context, image containerd.Image) (ocispec.Image, error) {
	var ociimage ocispec.Image
	ic, err := image.Config(ctrdCtx)
	if err != nil {
		return ociimage, fmt.Errorf("getImageConfig: ubable to fetch image: %v config. %v", image.Name(), err.Error())
	}
	switch ic.MediaType {
	case ocispec.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
		p, err := content.ReadBlob(ctrdCtx, image.ContentStore(), ic)
		if err != nil {
			return ociimage, fmt.Errorf("getImageConfig: ubable to read cotentStore of image: %v config. %v", image.Name(), err.Error())
		}

		if err := json.Unmarshal(p, &ociimage); err != nil {
			return ociimage, fmt.Errorf("getImageConfig: ubable to marshal cotentStore of image: %v config. %v", image.Name(), err.Error())

		}
	default:
		return ociimage, fmt.Errorf("getImageInfo: unknown image config media type %s", ic.MediaType)
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

func getSavedImageInfo(containerPath string) (ocispec.Image, error) {
	var image ocispec.Image

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
