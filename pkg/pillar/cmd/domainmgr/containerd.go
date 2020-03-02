package domainmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	// containerd socket
	ctrdSocket = "/run/containerd/containerd.sock"
	// CtrdServicesNamespace containerd namespace for running containers
	CtrdServicesNamespace = "eve-user-apps"

	// root path to all containers
	containersRoot = "/persist/rkt/pods/prepared"
	// relative path to rootfs for an individual container
	containerRootfsPath = "stage1/rootfs/opt/stage2/runx/"
)

// KeyValue a key-value pair
type KeyValue struct {
	Name  string
	Value string
}

// getContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func getContainerPath(id string) string {
	return path.Join(containersRoot, id)
}

// getContainerRootfs return the path to the root of the container filesystem
func getContainerRootfs(id string) string {
	return path.Join(getContainerPath(id), containerRootfsPath)
}

// containerdLoadImageTar load an image tar into the containerd content store
func containerdLoadImageTar(filename string) (map[string]string, error) {
	// load the content into the containerd content store
	ctr, err := containerd.New(ctrdSocket)
	if err != nil {
		log.Errorf("could not connect to containerd socket at %s: %+s", ctrdSocket, err.Error())
		return nil, err
	}
	defer ctr.Close()

	ctrdCtx := namespaces.WithNamespace(context.Background(), CtrdServicesNamespace)

	tarReader, err := os.Open(filename)
	if err != nil {
		log.Errorf("could not open tar file for reading at %s: %+s", filename, err.Error())
		return nil, err
	}

	imgs, err := ctr.Import(ctrdCtx, tarReader)
	if err != nil {
		log.Errorf("could not load image tar at %s into containerd: %+s", filename, err.Error())
		return nil, err
	}
	// successful, so return the list of images we imported
	names := make(map[string]string)
	for _, tag := range imgs {
		names[tag.Name] = string(tag.Target.Digest)
	}
	return names, nil
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
func ctrStop(id string, force bool) error {
	log.Infof("ctrStop %s %t\n", id, force)
	log.Infof("ctr stop done\n")
	return nil
}

// ctrRm remove an existing container
func ctrRm(id string) error {
	log.Infof("ctrRm %s\n", id)
	log.Infof("ctrRm done\n")
	return nil
}

// ctrCreate create a new container but do not start it
func ctrCreate(id, imageHash string) error {
	return nil
}

// ctrPrepare prepare an existing container
func ctrPrepare(containerImageSha256 string, status *types.DomainStatus) (string, error) {
	ctrID := uuid.NewV4().String()
	ociFilename, err := utils.VerifiedImageFileLocation(containerImageSha256)
	if err != nil {
		log.Errorf("failed to get Image File Location. "+
			"err: %+s", err.Error())
		return ctrID, err
	}
	log.Infof("ociFilename %s sha %s", ociFilename, containerImageSha256)

	loadedImages, err := containerdLoadImageTar(ociFilename)
	if err != nil {
		log.Errorf("failed to load Image File at %s into containerd: %+s", ociFilename, err.Error())
		return ctrID, err
	}

	// we currently only support one image per file; will change eventually
	if len(loadedImages) != 1 {
		log.Errorf("loaded %d images, expected just 1", len(loadedImages))
	}
	var imageHash string
	for _, hash := range loadedImages {
		imageHash = hash
	}

	// TODO:
	// 1. create a container using containerd - remember that containerd does not
	//    create a name for it, so we need to do so. Docker uses a hash of the config.
	//    We can just create a UUID.
	// 2. create a task using containerd - this will create the snapshot
	// 3. include any necessary mountpoints
	if err = ctrCreate(ctrID, imageHash); err != nil {
		return ctrID, fmt.Errorf("failed to create container %s: %v", ctrID, imageHash)
	}

	// inject a few files of our own into the bundle
	containerRootfs := getContainerRootfs(ctrID)
	mountpoints, execpath, workdir, env, err := getContainerConfigs(ctrID)
	if err != nil {
		return ctrID, fmt.Errorf("unable to get container config: %v", err)
	}

	err = createMountPointExecEnvFiles(containerRootfs, mountpoints, execpath, workdir, env, status)

	return ctrID, err
}

// getContainerConfigs get the container configs needed, specifically
// - mount target paths
// - exec path
// - working directory
// - env var key/value pairs
// this can change based on the config format
func getContainerConfigs(id string) (mountpoints, execpath []string, workdir string, env []KeyValue, err error) {
	appManifest, err := getRktPodManifest(path.Join(getContainerPath(id), "pod"))
	if err != nil {
		return mountpoints, execpath, workdir, env, fmt.Errorf("error while fetching app manfest: %v", err.Error())
	}
	app := appManifest.Apps[0].App

	mountpoints = make([]string, 0)
	for _, mp := range app.Mounts {
		mountpoints = append(mountpoints, mp.Path)
	}

	execpath = app.Exec[:]
	workdir = app.WorkDir
	env = app.Env[:]

	return
}

func getRktPodManifest(PodManifestFile string) (RktPodManifest, error) {
	// process the json to get the exact item we need
	var manifest RktPodManifest

	content, err := ioutil.ReadFile(PodManifestFile)
	if err != nil {
		log.Errorf("error reading rkt pod manifest %s failed: %v", PodManifestFile, err)
		return manifest, fmt.Errorf("error reading rkt pod manifest %s failed: %v", PodManifestFile, err)
	}

	err = json.Unmarshal(content, &manifest)
	if err != nil {
		return manifest, fmt.Errorf("error parsing pod rkt manifest for %s: %v", content, err)
	}
	return manifest, nil
}
