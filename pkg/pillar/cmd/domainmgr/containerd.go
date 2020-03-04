package domainmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/oci"
	"github.com/opencontainers/runtime-spec/specs-go"
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
	containersRoot = "/run/containerd"
	// relative path to rootfs for an individual container
	containerRootfsPath = "rootfs/"
)

// KeyValue a key-value pair
type KeyValue struct {
	Name  string
	Value string
}

// getContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func getContainerPath(containerId string) string {
	return path.Join(containersRoot, CtrdServicesNamespace, containerId)
}

// getContainerRootfs return the path to the root of the container filesystem
func getContainerRootfs(containerId string) string {
	return path.Join(getContainerPath(containerId), containerRootfsPath)
}

// containerdLoadImageTar load an image tar into the containerd content store
func containerdLoadImageTar(filename string) ([]string, error) {
	// load the content into the containerd content store
	var err error

	ctrdClient, err := getContainerdClient(ctrdSocket)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return nil, fmt.Errorf("Exception while loading container. %v", err)
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(CtrdServicesNamespace)

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
	imageNames := make([]string, 0)
	for _, tag := range imgs {
		imageNames = append(imageNames, tag.Name)
	}
	return imageNames, nil
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
func ctrStop(containerId string, force bool) error {
	log.Infof("ctrStop %s %t\n", containerId, force)
	log.Infof("ctr stop done\n")
	return nil
}

// ctrRm remove an existing container
func ctrRm(containerId string) error {
	log.Infof("ctrRm %s\n", containerId)
	ctrdClient, err := getContainerdClient(ctrdSocket)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return fmt.Errorf("Could not build containerd client. %v", err.Error())
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(CtrdServicesNamespace)

	container, err := loadContainer(containerId)
	if err != nil {
		return err
	}
	task, err := container.Task(ctrdCtx, cio.NewAttach(cio.WithStdio))
	if err != nil {
		log.Errorf("Could not fetch task of container: %v. %v", containerId, err.Error())
		return fmt.Errorf("Could not fetch task of container: %v. %v", containerId, err.Error())
	}
	_, err = task.Delete(ctrdCtx)
	if err != nil {
		log.Errorf("Unable to delete task of container: %v. %v", containerId, err.Error())
		return fmt.Errorf("Unable to delete task of container: %v. %v", containerId, err.Error())
	}
	err = container.Delete(ctrdCtx)
	if err != nil {
		log.Errorf("Unable to delete container: %v. %v", containerId, err.Error())
		return fmt.Errorf("Unable to delete container: %v. %v", containerId, err.Error())
	}
	log.Infof("ctrRm done\n")
	return nil
}

// ctrCreate create a new container but do not start it
func ctrCreate(containerId, imageName string, status *types.DomainStatus) (string, error) {
	var (
		ociOpts       []oci.SpecOpts
		containerOpts []containerd.NewContainerOpts
		ociSpec       oci.Spec
		err           error
	)
	ctrdClient, err := getContainerdClient(ctrdSocket)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return "", fmt.Errorf("Exception while loading container. %v", err)
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(CtrdServicesNamespace)

	if len(status.EnvVariables) > 0 {
		envVars := buildEnvVarsSlice(status.EnvVariables)
		ociOpts = append(ociOpts, oci.WithEnv(envVars))
	}

	if len(ociOpts) > 0 {
		containerOpts = append(containerOpts, containerd.WithSpec(&ociSpec, ociOpts...))
	}
	image, err := getImage(imageName)
	if err != nil {
		return "", fmt.Errorf("Unable to fetch image %v. %v", imageName, err.Error())
	}

	containerSnapshot := fmt.Sprintf("%s-snapshot", containerId)
	containerOpts = append(containerOpts, containerd.WithImage(image))
	containerOpts = append(containerOpts, containerd.WithNewSnapshot(containerSnapshot, image))
	containerOpts = append(containerOpts, containerd.WithNewSpec(oci.WithImageConfig(image)))
	_, err = ctrdClient.NewContainer(
		ctrdCtx,
		containerId,
		containerOpts...,
	)
	if err != nil {
		log.Errorf("Could not build new containerd container: %v. %v", containerId, err.Error())
		return "", fmt.Errorf("Could not build new containerd container: %v. %v", containerId, err.Error())
	}

	_, err = ctrCreateNewTask(containerId)
	if err != nil {
		log.Errorf("Could not create a new task for container: %v. %v", containerId, err.Error())
		return "", fmt.Errorf("Could not create a new task for container: %v. %v", containerId, err.Error())
	}
	return containerId, nil
}

// ctrCreateNewTask - Creates a new task for the container.
// This step is responsible for setting up rootfs of the container under /run/containerd/<RunTime>/<NameSpace>/<Container id>/
// NOTE: As per containerd's flow, to start a container, first a task is created which sets up container's rootfs,
// then the task is started which invokes runc binary with the rootfs. Since we are not using runc, we need to stop at task create step.
func ctrCreateNewTask(containerId string) (containerd.Task, error) {
	var err error
	ctrdClient, err := getContainerdClient(ctrdSocket)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return nil, fmt.Errorf("Exception while loading container. %v", err)
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(CtrdServicesNamespace)

	container, err := loadContainer(containerId)
	if err != nil {
		return nil, err
	}

	return container.NewTask(ctrdCtx, cio.NewCreator(cio.WithStdio))
}

// ctrPrepare prepare an existing container
func ctrPrepare(containerImageSha256 string, status *types.DomainStatus) (string, error) {
	containerId := buildContainerId(status.DisplayName)
	ociFilename, err := utils.VerifiedImageFileLocation(containerImageSha256)
	if err != nil {
		log.Errorf("failed to get Image File Location. "+
			"err: %+s", err.Error())
		return containerId, err
	}
	log.Infof("ociFilename %s sha %s", ociFilename, containerImageSha256)

	loadedImages, err := containerdLoadImageTar(ociFilename)
	if err != nil {
		log.Errorf("failed to load Image File at %s into containerd: %+s", ociFilename, err.Error())
		return containerId, err
	}

	// we currently only support one image per file; will change eventually
	if len(loadedImages) != 1 {
		log.Errorf("loaded %d images, expected just 1", len(loadedImages))
	}
	var imageName string
	for _, name := range loadedImages {
		imageName = name
	}

	if containerId, err := ctrCreate(containerId, imageName, status); err != nil {
		return containerId, fmt.Errorf("failed to create container %s: %v, error: %v", containerId, imageName, err.Error())
	}

	// inject a few files of our own into the bundle
	containerRootfs := getContainerRootfs(containerId)
	mountpoints, execpath, workdir, env, err := getContainerConfigs(containerId)
	if err != nil {
		return containerId, fmt.Errorf("unable to get container config: %v", err)
	}

	err = createMountPointExecEnvFiles(containerRootfs, mountpoints, execpath, workdir, env, status)

	return containerId, err
}

// getContainerConfigs get the container configs needed, specifically
// - mount target paths
// - exec path
// - working directory
// - env var key/value pairs
// this can change based on the config format
func getContainerConfigs(containerId string) ([]specs.Mount, []string, string, []string, error) {
	container, err := loadContainer(containerId)
	if err != nil {
		return nil, nil, "", nil, err
	}
	ctrdCtx := getContainerdContext(CtrdServicesNamespace)
	containerSpec, err := container.Spec(ctrdCtx)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("Unable to get container spec: %v", err)
	}
	mountpoints := containerSpec.Mounts
	execpath := containerSpec.Process.Args
	workdir := containerSpec.Process.Cwd
	env := containerSpec.Process.Env
	return mountpoints, execpath, workdir, env, nil
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

func loadContainer(containerId string) (containerd.Container, error) {
	ctrdClient, err := getContainerdClient(ctrdSocket)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return nil, fmt.Errorf("Exception while loading container. %v", err)
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(CtrdServicesNamespace)
	container, err := ctrdClient.LoadContainer(ctrdCtx, containerId)
	if err != nil {
		return nil, fmt.Errorf("Exception while loading container. %v", err)
	}
	return container, nil
}

func getContainerdClient(ctrdSocketPath string) (*containerd.Client, error) {
	ctrdClient, err := containerd.New(ctrdSocketPath)
	if err != nil {
		log.Errorf("could not connect to containerd socket at %s: %+s", ctrdSocketPath, err.Error())
		return nil, fmt.Errorf("could not connect to containerd socket at %s: %+s", ctrdSocketPath, err.Error())
	}
	return ctrdClient, nil
}

func getContainerdContext(ctrdNameSpace string) context.Context {
	ctrdCtx := namespaces.WithNamespace(context.Background(), ctrdNameSpace)
	return ctrdCtx
}

func getImage(imageName string) (containerd.Image, error) {
	var err error
	ctrdClient, err := getContainerdClient(ctrdSocket)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return nil, fmt.Errorf("Exception while loading container. %v", err)
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(CtrdServicesNamespace)
	return ctrdClient.GetImage(ctrdCtx, imageName)
}

// Util methods

func buildEnvVarsSlice(envMap map[string]string) []string {
	var envVars []string

	for envName, envValue := range envMap {
		envVars = append(envVars, fmt.Sprintf("%s=%s", envName, envValue))
	}

	return envVars
}

func buildContainerId(displayName string) string {
	uuid := uuid.NewV4().String()
	return fmt.Sprintf("%s-%s", displayName, uuid)
}
