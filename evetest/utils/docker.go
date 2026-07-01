// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	"github.com/docker/cli/cli/config"
	ct "github.com/docker/cli/cli/config/types"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// EVEDockerImageName converts a EVE's ImageRef into a Docker image name of the form:
// <Repo>:<Version>-<hypervisor>-<arch>
// Returns an error if any required field is missing or unknown.
func EVEDockerImageName(ref *api.ImageRef) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("image reference is nil")
	}
	if ref.Repo == "" {
		return "", fmt.Errorf("image repo is not defined")
	}
	if ref.Version == "" {
		return "", fmt.Errorf("image version is not defined")
	}

	var hv string
	switch ref.Hypervisor {
	case api.HypervisorType_HV_KVM:
		hv = "kvm"
	case api.HypervisorType_HV_XEN:
		hv = "xen"
	case api.HypervisorType_HV_KUBEVIRT:
		hv = "k"
	default:
		return "", fmt.Errorf("unknown hypervisor type: %v", ref.Hypervisor)
	}

	var arch string
	switch ref.Arch {
	case api.ArchType_ARCH_AMD64:
		arch = "amd64"
	case api.ArchType_ARCH_ARM64:
		arch = "arm64"
	default:
		return "", fmt.Errorf("unknown architecture: %v", ref.Arch)
	}

	return fmt.Sprintf("%s:%s-%s-%s", ref.Repo, ref.Version, hv, arch), nil
}

// GetDockerAuthPlain returns the Docker registry username and password for a given
// registry FQDN. It reads credentials from the local Docker configuration and returns
// an error if none are found.
func GetDockerAuthPlain(log *logrus.Entry, fqdn string) (string, string, error) {
	authConfig, err := getRegistryAuth(log, fqdn)
	if err != nil {
		err = fmt.Errorf("failed to get docker auth config for FQDN %s: %w", fqdn, err)
		return "", "", err
	}

	if authConfig.Password == "" && authConfig.Username == "" {
		return "", "", fmt.Errorf("no Docker credentials found for FQDN %s", fqdn)
	}
	log.Infof("loaded docker credentials for: %s", fqdn)
	return authConfig.Username, authConfig.Password, nil
}

// HaveDockerImage checks if a Docker image exists locally.
// Returns true if the image exists, false if not, and an error if the check itself fails.
func HaveDockerImage(ctx context.Context, log *logrus.Entry, image string) (bool, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return false, fmt.Errorf("failed to create docker client: %w", err)
	}
	_, err = dockerClient.ImageInspect(ctx, image)
	return err == nil, nil
}

// IsErrDockerImageNotFound returns true if err indicates that a Docker image
// does not exist in the local Docker daemon (i.e. "No such image").
func IsErrDockerImageNotFound(err error) bool {
	return cerrdefs.IsNotFound(err)
}

// GetDockerImageSizeBytes returns the size of the given image in bytes.
func GetDockerImageSizeBytes(ctx context.Context, imageName string) (int64, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return 0, fmt.Errorf("failed to create docker client: %w", err)
	}
	inspect, err := cli.ImageInspect(ctx, imageName)
	if err != nil {
		return 0, fmt.Errorf("failed to inspect Docker image %q: %w", imageName, err)
	}
	return inspect.Size, nil
}

// StreamDockerImageGzip exports a Docker image from the local Docker daemon
// and returns a streaming reader that produces a gzip-compressed tar archive
// of the image.
// The returned ReadCloser streams the equivalent of:
//
//	docker save <imageName> | gzip
//
// Data is produced lazily and streamed directly from the Docker daemon,
// avoiding loading the full image into memory. The caller must read the
// stream until EOF and close it to release underlying resources.
func StreamDockerImageGzip(ctx context.Context, imageName string) (io.ReadCloser, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	reader, err := cli.ImageSave(ctx, []string{imageName})
	if err != nil {
		return nil, fmt.Errorf("failed to save Docker image %s: %w", imageName, err)
	}

	pr, pw := io.Pipe()

	go func() {
		defer reader.Close()
		defer pw.Close()

		gz := gzip.NewWriter(pw)
		defer gz.Close()

		_, err := io.Copy(gz, reader)
		if err != nil {
			pw.CloseWithError(err)
		}
	}()

	return pr, nil
}

// LoadDockerImageFromReader loads a Docker image into the local Docker daemon
// from a streaming gzip-compressed tar archive.
// The provided reader must yield data equivalent to the output of:
//
//	docker save <image> | gzip
//
// Image data is consumed incrementally and decompressed on the fly, allowing
// large images to be loaded without buffering the entire archive in memory.
func LoadDockerImageFromReader(ctx context.Context, log *logrus.Entry, r io.Reader) error {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	resp, err := dockerClient.ImageLoad(ctx, gzr, client.ImageLoadWithQuiet(false))
	if err != nil {
		return fmt.Errorf("failed to load Docker image: %w", err)
	}
	defer resp.Close()

	if err := logDockerResp(log, resp); err != nil {
		log.Warnf("failed to log ImageLoad response: %v", err)
	}
	return nil
}

// PullDockerImage ensures a Docker image is available locally by pulling it if necessary.
// If the image already exists, the function returns immediately.
func PullDockerImage(ctx context.Context, log *logrus.Entry, imageName string) error {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	_, err = dockerClient.ImageInspect(ctx, imageName)
	if err == nil {
		return nil // Image already present
	}

	authStr, err := getEncodedAuth(log, imageName)
	if err != nil {
		log.Warnf("Falling back to anonymous docker pull: %v", err)
		authStr = ""
	}
	resp, err := dockerClient.ImagePull(ctx, imageName, client.ImagePullOptions{
		RegistryAuth: authStr,
	})
	if err != nil {
		return fmt.Errorf("failed to pull Docker image %q: %w", imageName, err)
	}
	defer resp.Close()

	if err = logDockerResp(log, resp); err != nil {
		log.Warnf("Failed to log ImagePull response: %v", err)
	}
	return nil
}

// RunDockerCommand executes a Docker container using the specified image,
// command, and bind-mounted volumes, then returns the combined stdout/stderr
// output.
//
// Parameters:
//   - ctx: Context used for cancellation and timeouts.
//   - log: Logrus entry for structured logging.
//   - image: Docker image to run.
//   - command: Shell command string to execute inside the container.
//   - volumeMap: Mapping of container paths (keys) to host paths (values)
//     that will be mounted as bind volumes.
//   - platform: Optional platform (e.g., "linux/arm64" or "linux/amd64") to run
//     the container under. If empty, the host's default platform is used.
//
// Returns the container output as a string. If any Docker API call fails,
// an error is returned. Even if cleanup fails, the output (if available)
// is still returned.
func RunDockerCommand(ctx context.Context, log *logrus.Entry, image string, command string,
	volumeMap map[string]string, platform string) (result string, err error) {

	log.Debugf("Running 'docker run %s %s' (platform=%q) with volumes %v",
		image, command, platform, volumeMap)

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return "", fmt.Errorf("failed to create docker client: %w", err)
	}

	// Build mount list from the volume map (container target → host source).
	mounts := make([]mount.Mount, 0, len(volumeMap))
	for target, source := range volumeMap {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: source,
			Target: target,
		})
	}

	// Configure platform if provided.
	var platformSpec *ocispecs.Platform
	if platform != "" {
		parts := strings.SplitN(platform, "/", 2)
		if len(parts) == 2 {
			platformSpec = &ocispecs.Platform{
				OS:           parts[0],
				Architecture: parts[1],
			}
		} else {
			return "", fmt.Errorf("invalid platform string: %q", platform)
		}
	}

	// Create container.
	created, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Image: image,
		Config: &container.Config{
			Cmd: strings.Fields(command),
			Tty: true,
		},
		HostConfig: &container.HostConfig{
			Mounts: mounts,
		},
		Platform: platformSpec,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}
	containerID := created.ID

	// Start and wait for completion.
	if _, err := cli.ContainerStart(ctx, containerID, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("failed to start container: %w", err)
	}
	waitResult := cli.ContainerWait(ctx, containerID, client.ContainerWaitOptions{
		Condition: container.WaitConditionNotRunning,
	})
	select {
	case err := <-waitResult.Error:
		if err != nil {
			return "", fmt.Errorf("container wait error: %w", err)
		}
	case <-waitResult.Result:
	}

	// Collect logs.
	out, err := cli.ContainerLogs(ctx, containerID, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to fetch container logs: %w", err)
	}
	defer out.Close()

	b, readErr := io.ReadAll(out)

	// Cleanup container.
	_, removeErr := cli.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{RemoveVolumes: true})
	if removeErr != nil {
		log.Errorf("failed to remove container %q: %v", containerID, removeErr)
	}

	return string(b), readErr
}

// ExtractFromDockerImage extracts a file or directory from a Docker image
// without running it. It creates a temporary container, copies the specified
// path from it, and then removes the container. Returns an error if any step fails.
// The temporary container is always removed, even if extraction fails.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control.
//   - log: Logrus entry used for structured logging.
//   - imageName: Name of the Docker image to extract from.
//   - localPath: Destination path on the host where the extracted content
//     should be written.
//   - containerPath: Path inside the image (container filesystem) to extract.
func ExtractFromDockerImage(ctx context.Context, log *logrus.Entry,
	imageName, localPath, containerPath string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	// Create a temporary container from the image
	created, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Image: imageName,
	})
	if err != nil {
		return fmt.Errorf("failed to create container from image %q: %w", imageName, err)
	}
	containerID := created.ID

	// Ensure the container is always removed
	defer func() {
		_, rmErr := cli.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{Force: true})
		if rmErr != nil {
			log.Errorf("failed to remove temporary container %q: %v", containerID, rmErr)
		}
	}()

	// Copy the requested path from the container (as a TAR stream)
	copied, err := cli.CopyFromContainer(ctx, containerID, client.CopyFromContainerOptions{
		SourcePath: containerPath,
	})
	if err != nil {
		return fmt.Errorf("failed to copy %q from container: %w", containerPath, err)
	}
	defer copied.Content.Close()

	// Extract the TAR stream to the target path
	if err := ExtractFromTar(copied.Content, localPath); err != nil {
		return fmt.Errorf("failed to extract data to %q: %w", localPath, err)
	}

	log.Infof("Successfully extracted %q from image %q to %q",
		containerPath, imageName, localPath)
	return nil
}

// RunningInContainer returns true if the process is likely running inside a container.
// This is determined by checking for the presence of "/.dockerenv" (Docker-specific)
// and "/run/.containerenv" (Podman-specific).
func RunningInContainer() bool {
	return dockerEnvExists() || containerEnvExists()
}

// ContainerUsingHostNetwork tries to determine if this process is running inside the host
// network namespace, rather than in the container's own network namespace.
func ContainerUsingHostNetwork() bool {
	brNames := []string{"docker0", "cni-podman0"}
	for _, name := range brNames {
		if _, err := netlink.LinkByName(name); err == nil {
			// Found a host bridge in the current namespace → assume host network.
			return true
		}
	}
	// No host bridges found → the container is likely running in a separate net namespace.
	return false
}

// dockerEnvExists checks for the Docker-specific environment file /.dockerenv
func dockerEnvExists() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// containerEnvExists checks for the Podman-specific environment file /run/.containerenv
func containerEnvExists() bool {
	_, err := os.Stat("/run/.containerenv")
	return err == nil
}

// indexServer is the registry key Docker config files (config.json) use for
// Docker Hub. It matches the historical registry.IndexServer value from the
// docker/docker client library, which is no longer exported by moby/moby.
const indexServer = "https://index.docker.io/v1/"

// normalizeRegistry extracts the registry hostname from a Docker image reference.
// Supports references like "docker://<repo>", "repo:tag", and default docker.io.
// Returns the registry domain used for authentication lookup.
func normalizeRegistry(imageRef string) string {
	// Handle docker:// prefix if present
	imageRef = strings.TrimPrefix(imageRef, "docker://")

	// Parse the image reference using the current recommended function
	ref, err := reference.ParseNormalizedNamed(imageRef)
	if err == nil {
		domain := reference.Domain(ref)
		switch domain {
		case "docker.io", "":
			return indexServer
		default:
			return domain
		}
	}

	// Fallback for invalid references - extract host:port
	parts := strings.SplitN(imageRef, "/", 2)
	hostPart := parts[0]
	return hostPart
}

// getRegistryAuth returns the Docker AuthConfig for a given image's registry.
// It reads from the local Docker configuration, normalizes the registry hostname,
// and returns an error if no credentials are found or the config cannot be read.
func getRegistryAuth(log *logrus.Entry, image string) (*ct.AuthConfig, error) {
	registry := normalizeRegistry(image)

	log.Infof("Normalized registry for image %q: %s", image, registry)

	cfg, err := config.Load("")
	if err != nil {
		return nil, fmt.Errorf("failed to load docker config: %w", err)
	}
	log.Infof("Loaded Docker config (encoded) %q", cfg.GetFilename())

	authConfig, err := cfg.GetAuthConfig(registry)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth config for registry %q: %w", registry, err)
	}
	if authConfig.Username != "" {
		log.Infof("Authenticating to Docker registry as user %q", authConfig.Username)
	}

	// Return pointer to authConfig
	return &ct.AuthConfig{
		Username:      authConfig.Username,
		Password:      authConfig.Password,
		Auth:          authConfig.Auth,
		ServerAddress: authConfig.ServerAddress,
		IdentityToken: authConfig.IdentityToken,
		RegistryToken: authConfig.RegistryToken,
	}, nil
}

// getEncodedAuth returns the Base64-encoded JSON string of Docker credentials
// for the given image, suitable for use in ImagePull RegistryAuth field.
func getEncodedAuth(log *logrus.Entry, image string) (string, error) {
	authConfig, err := getRegistryAuth(log, image)
	if err != nil {
		err = fmt.Errorf("failed to get docker auth config for image %q: %w", image, err)
		return "", err
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth config: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encodedJSON), nil
}

// logDockerResp reads a Docker API response from resp and logs each line to log.Debug.
// Ensures the response body is closed when done.
// Returns an error if reading fails.
func logDockerResp(log *logrus.Entry, resp io.ReadCloser) error {
	defer resp.Close()
	rd := bufio.NewReader(resp)
	for {
		n, _, err := rd.ReadLine()
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		log.Debug(string(n))
	}
	return nil
}
