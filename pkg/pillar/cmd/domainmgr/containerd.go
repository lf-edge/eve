package domainmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/typeurl"
	"github.com/opencontainers/runtime-spec/specs-go"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	uuid "github.com/satori/go.uuid"
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
	containersRoot = "/run/containerd"
	// relative path to rootfs for an individual container
	containerRootfsPath = "rootfs/"
	// container config (manifest) file name
	configFilename = "config.json"
	// container pid file name
	pidFilename = "pid"
	// default snapshotter used by containerd
	defaultSnapshotter = "overlayfs"
)

type command struct {
	name string
	args []string
}

// KeyValue a key-value pair
type KeyValue struct {
	Name  string
	Value string
}

// getContainerPath return the path to the root of the container. This is *not*
// necessarily the rootfs, which may be a layer below
func getContainerPath(containerID string) string {
	return path.Join(containersRoot, containerdRunTime, ctrdServicesNamespace, containerID)
}

// getContainerRootfs return the path to the root of the container filesystem
func getContainerRootfs(containerID string) string {
	return path.Join(getContainerPath(containerID), containerRootfsPath)
}

// containerdLoadImageTar load an image tar into the containerd content store
func containerdLoadImageTar(ctrdClient *containerd.Client, ctrdCtx context.Context, filename string) (map[string]images.Image, error) {
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

// ctrRm remove an existing container
func ctrRm(containerID string) error {
	log.Infof("ctrRm %s\n", containerID)

	ctrdClient, err := getContainerdClient(ctrdSocket, containerdRunTime)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return fmt.Errorf("ctrRm: Exception while loading container. %v", err)
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(ctrdServicesNamespace)

	return ctrDeleteContainer(ctrdClient, ctrdCtx, containerID)
}

func ctrDeleteContainer(ctrdClient *containerd.Client, ctrdCtx context.Context, containerID string) error {
	container, err := loadContainer(ctrdClient, ctrdCtx, containerID)
	if err != nil {
		return err
	}

	//delete container task (if any) before deleting container
	task, err := container.Task(ctrdCtx, cio.NewAttach(cio.WithStdio))
	if err != nil {
		log.Errorf("Could not fetch task of container: %v. %v", containerID, err.Error())
	}
	if task != nil {
		_, err = task.Delete(ctrdCtx)
		if err != nil {
			log.Errorf("Unable to delete task of container: %v. %v", containerID, err.Error())
			return fmt.Errorf("ctrDeleteContainer: Unable to delete task of container: %v. %v", containerID, err.Error())
		}
	}

	err = container.Delete(ctrdCtx)
	if err != nil {
		log.Errorf("Unable to delete container: %v. %v", containerID, err.Error())
		return fmt.Errorf("ctrDeleteContainer: Unable to delete container: %v. %v", containerID, err.Error())
	}

	return nil
}

// ctrCreate create a new container but do not start it
func ctrCreate(ctrdClient *containerd.Client, ctrdCtx context.Context, containerID string, image images.Image,
	envVars map[string]string) error {
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

	if len(envVars) > 0 {
		envVars := buildEnvVarsSlice(envVars)
		ociOpts = append(ociOpts, oci.WithEnv(envVars))
	}

	// doing this step as we need the image in containerd.Image structure for container create.
	ctrdImage := containerd.NewImage(ctrdClient, image)

	containerSnapshot := fmt.Sprintf("%s-snapshot", containerID)
	containerOpts = append(containerOpts, containerd.WithImage(ctrdImage))
	containerOpts = append(containerOpts, containerd.WithNewSnapshot(containerSnapshot, ctrdImage))
	containerOpts = append(containerOpts, containerd.WithNewSpec(oci.WithImageConfig(ctrdImage)))
	containerOpts = append(containerOpts, containerd.WithSpec(&ociSpec, ociOpts...))
	container, err := ctrdClient.NewContainer(
		ctrdCtx,
		containerID,
		containerOpts...,
	)
	if err != nil {
		log.Errorf("Could not build new containerd container: %v. %v", containerID, err.Error())
		return fmt.Errorf("ctrCreate: Could not build new containerd container: %v. %v", containerID, err.Error())
	}
	err = createBundle(ctrdClient, ctrdCtx, container, containerSnapshot)
	if err != nil {
		log.Errorf("Could not build rootfs of container: %v. %v", containerID, err.Error())
		return fmt.Errorf("ctrCreate: Could not build rootfs of container: %v. %v", containerID, err.Error())
	}
	return nil
}

// ctrPrepare prepare an existing container
func ctrPrepare(ociFilename string, envVars map[string]string, noOfDisks int) (string, error) {
	containerID := uuid.NewV4().String()

	ctrdClient, err := getContainerdClient(ctrdSocket, containerdRunTime)
	if err != nil {
		log.Errorf("Could not build containerd client. %v", err.Error())
		return "", fmt.Errorf("ctrPrepare: Exception while loading container. %v", err)
	}
	defer ctrdClient.Close()
	ctrdCtx := getContainerdContext(ctrdServicesNamespace)

	loadedImages, err := containerdLoadImageTar(ctrdClient, ctrdCtx, ociFilename)
	if err != nil {
		log.Errorf("failed to load Image File at %s into containerd: %+s", ociFilename, err.Error())
		return containerID, err
	}

	// we currently only support one image per file; will change eventually
	if len(loadedImages) != 1 {
		log.Errorf("loaded %d images, expected just 1", len(loadedImages))
	}
	var image images.Image
	for _, imgObj := range loadedImages {
		image = imgObj
	}

	if err = ctrCreate(ctrdClient, ctrdCtx, containerID, image, envVars); err != nil {
		return containerID, fmt.Errorf("ctrPrepare: failed to create container %s, error: %v", containerID, err.Error())
	}

	// inject a few files of our own into the bundle
	containerRootfs := getContainerRootfs(containerID)
	mountpoints, execpath, workdir, env, err := getContainerConfigs(ctrdClient, ctrdCtx, containerID)
	if err != nil {
		return containerID, fmt.Errorf("ctrPrepare: unable to get container config: %v", err)
	}

	err = createMountPointExecEnvFiles(containerRootfs, mountpoints, execpath, workdir, env, noOfDisks)

	return containerID, err
}

// getContainerConfigs get the container configs needed, specifically
// - mount target paths
// - exec path
// - working directory
// - env var key/value pairs
// this can change based on the config format
func getContainerConfigs(ctrdClient *containerd.Client, ctrdCtx context.Context, containerID string) ([]specs.Mount,
	[]string, string, []string, error) {
	container, err := loadContainer(ctrdClient, ctrdCtx, containerID)
	if err != nil {
		return nil, nil, "", nil, err
	}
	containerSpec, err := container.Spec(ctrdCtx)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("getContainerConfigs: Unable to get container spec: %v", err)
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
		return manifest, fmt.Errorf("getRktPodManifest: error reading rkt pod manifest %s failed: %v", PodManifestFile, err)
	}

	err = json.Unmarshal(content, &manifest)
	if err != nil {
		return manifest, fmt.Errorf("getRktPodManifest: error parsing pod rkt manifest for %s: %v", content, err)
	}
	return manifest, nil
}

func loadContainer(ctrdClient *containerd.Client, ctrdCtx context.Context, containerID string) (containerd.Container, error) {
	if ctrdClient == nil {
		return nil, fmt.Errorf("loadContainer: Container client is nil")
	}

	if ctrdCtx == nil {
		return nil, fmt.Errorf("loadContainer: Container context is nil")
	}

	container, err := ctrdClient.LoadContainer(ctrdCtx, containerID)

	if err != nil {
		return nil, fmt.Errorf("loadContainer: Exception while loading container. %v", err)
	}
	return container, nil
}

func getContainerdClient(ctrdSocketPath, ctrdRunTime string) (*containerd.Client, error) {
	ctrdClient, err := containerd.New(ctrdSocketPath, containerd.WithDefaultRuntime(ctrdRunTime))
	if err != nil {
		log.Errorf("could not connect to containerd socket at %s: %+s", ctrdSocketPath, err.Error())
		return nil, fmt.Errorf("getContainerdClient: could not connect to containerd socket at %s: %+s", ctrdSocketPath, err.Error())
	}
	return ctrdClient, nil
}

func getContainerdContext(ctrdNameSpace string) context.Context {
	ctrdCtx := namespaces.WithNamespace(context.Background(), ctrdNameSpace)
	return ctrdCtx
}

// getContainerInfo - returns container config as JSON
func getContainerInfo(ctrdCtx context.Context, container containerd.Container) (string, error) {
	info, err := container.Info(ctrdCtx)
	if err != nil {
		return "", fmt.Errorf("Exception while fetching container info. %v", err)
	}
	if info.Spec != nil && info.Spec.Value != nil {
		typeurl.Register(&specs.Spec{}, "types.containerd.io", "opencontainers/runtime-spec", "1", "Spec")
		specValue, err := typeurl.UnmarshalAny(info.Spec)
		if err != nil {
			return "", fmt.Errorf("Exception while fetching container spec. %v", err)
		}
		if err != nil {
			return "", fmt.Errorf("Exception while fetching container spec. %v", err)
		}
		res, err := getJSON(struct {
			containers.Container
			Spec interface{} `json:"Spec,omitempty"`
		}{
			Container: info,
			Spec:      specValue,
		})
		if err != nil {
			return "", fmt.Errorf("Exception while unmarshalling existing container spec. %v", err)
		}
		return res, nil
	}
	res, err := getJSON(info)
	if err != nil {
		return "", fmt.Errorf("Exception while unmarshalling newly added container spec. %v", err)
	}
	return res, nil
}

//createBundle - assigns a UUID and creates a bundle for container's rootFs
func createBundle(ctrdClient *containerd.Client, ctrdCtx context.Context, container containerd.Container, snapshotName string) error {
	appDir := getContainerPath(container.ID())
	appDir = appDir + "-test"
	rootFsDir := path.Join(appDir, containerRootfsPath)
	//rootFsDir := getContainerRootfs(container.ID())
	if err := os.MkdirAll(rootFsDir, 0766); err != nil {
		return fmt.Errorf("Exception while creating rootFS dir. %v", err)
	}

	mountCommands, err := getBundleMountCommand(ctrdClient, ctrdCtx, snapshotName, rootFsDir)
	if err != nil {
		return fmt.Errorf("Exception while preparing snapshot mount. %v", err)
	}
	containerConfig, err := getContainerInfo(ctrdCtx, container)
	if err != nil {
		return fmt.Errorf("Exception while fetching container info. %v", err)
	}
	err = ioutil.WriteFile(filepath.Join(appDir, configFilename), []byte(containerConfig), 0666)
	if err != nil {
		return fmt.Errorf("Exception while writing container info to %v/%v. %v", appDir, configFilename, err)
	}
	err = ioutil.WriteFile(filepath.Join(appDir, pidFilename), []byte(container.ID()), 0666)
	if err != nil {
		return fmt.Errorf("Exception while writing container pid to %v/%v. %v", appDir, pidFilename, err)
	}
	_, err = executeShellCommands(mountCommands)
	if err != nil {
		return fmt.Errorf("Exception while writing mount rootfs. Error: %v", err)
	}

	return nil
}

func getBundleMountCommand(ctrdClient *containerd.Client, ctrdCtx context.Context, mountKey string, mountTarget string) ([]*command, error) {
	snapshotter := ctrdClient.SnapshotService(defaultSnapshotter)
	mounts, err := snapshotter.Mounts(ctrdCtx, mountKey)
	if err != nil {
		return nil, fmt.Errorf("Exception while fetching container snapshot mounts. %v", err)
	}
	return getMountCommands(mountTarget, mounts), nil
}

// Util methods

func buildEnvVarsSlice(envMap map[string]string) []string {
	var envVars []string

	for envName, envValue := range envMap {
		envVars = append(envVars, fmt.Sprintf("%s=%s", envName, envValue))
	}

	return envVars
}

// getJSON - returns input in JSON format
func getJSON(x interface{}) (string, error) {
	b, err := json.MarshalIndent(x, "", "    ")
	if err != nil {
		return "", fmt.Errorf("Exception while unmarshalling container spec JSON. %v", err)
	}
	return fmt.Sprint(string(b)), nil
}

// getMountCommands - returns list of Unix mount commands for target and list of mounts
func getMountCommands(target string, mounts []mount.Mount) []*command {
	var mountCommands []*command
	for _, m := range mounts {
		mountCommands = append(mountCommands, &command{
			name: "mount",
			args: []string{"-t", m.Type, m.Source, target, "-o", strings.Join(m.Options, ",")},
		})
	}
	return mountCommands
}

func executeShellCommands(commands []*command) ([]string, error) {
	var results []string
	for _, command := range commands {
		//log.Printf("Executing %v %v", command.name, command.args)
		cmd := exec.Command(command.name, command.args...)
		out, err := cmd.CombinedOutput()
		//log.Printf("Result %v", out)
		if err != nil {
			return results, fmt.Errorf("Error while executing command: %v. Error: %v", command, err)
		}
		results = append(results, string(out))
	}
	return results, nil
}
