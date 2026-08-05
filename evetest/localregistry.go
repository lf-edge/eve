// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/moby/moby/client"

	"github.com/lf-edge/eve/evetest/utils"
)

// newLocalRegistryHandler returns an http.Handler implementing the Docker
// Registry HTTP API v2 (in-memory blob/manifest store), mounted at "/v2/" on
// the harness's image-server listeners alongside the plain file server. It
// lets EVE pull a container image (an upgrade rootfs, or an application
// content tree) directly from evetest, without that image ever having been
// published to a real, reachable registry -- see
// PushDockerImageToLocalRegistry.
func newLocalRegistryHandler() http.Handler {
	return registry.New()
}

// localRegistryPullDomain is the registry host:port EVE is pointed at: the
// harness's own HTTPS image-server listener. Its certificate is not in any
// public trust store, so callers must also set DockerContainer.
// TrustedCACertsPEM to GetCACertPEM.
func localRegistryPullDomain() string {
	return net.JoinHostPort(imgServerIPv4.String(), strconv.Itoa(imgServerHTTPSPort))
}

// localRegistryPushDomain is the same registry, reached over the harness's
// plain-HTTP image-server listener. evetest's own push (unlike EVE's pull)
// is a call this process makes directly, so it can simply ask for the
// insecure endpoint instead of dealing with its own self-signed certificate.
func localRegistryPushDomain() string {
	return net.JoinHostPort(imgServerIPv4.String(), strconv.Itoa(imgServerPort))
}

// saveDockerImageToTempFile exports imageName from the local Docker daemon
// into a temporary, uncompressed tar file in the same layout `docker save`
// produces (what tarball.ImageFromPath expects), and returns its path. The
// caller must remove it.
func saveDockerImageToTempFile(
	ctx context.Context, imageName string) (path string, err error) {
	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		return "", fmt.Errorf("failed to create docker client: %w", err)
	}
	reader, err := dockerClient.ImageSave(ctx, []string{imageName})
	if err != nil {
		return "", fmt.Errorf("failed to save docker image %q: %w", imageName, err)
	}
	defer reader.Close()

	f, err := os.CreateTemp("", "evetest-local-registry-*.tar")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer f.Close()
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()

	if _, err = io.Copy(f, reader); err != nil {
		err = fmt.Errorf("failed to save docker image %q to %q: %w",
			imageName, f.Name(), err)
		return "", err
	}
	return f.Name(), nil
}

// PushDockerImageToLocalRegistry copies a Docker image -- pulling it first if
// not already present locally -- from the local Docker daemon into evetest's
// own embedded OCI registry, and returns the DockerContainer fields that
// point an EVE datastore at that copy.
//
// This is what lets an OCI/container datastore be exercised (an EVE upgrade
// via BaseOSDatastoreOCI, or a DockerContainer volume/app image) without the
// image under test already being published to a real, externally reachable
// registry: evetest re-serves whatever the local Docker daemon has under
// imageName ("<repo>:<tag>", e.g. as returned by utils.EVEDockerImageName)
// as a datastore of its own.
func PushDockerImageToLocalRegistry(imageName string) (DockerContainer, error) {
	th := getTestHarness()
	log := th.log.WithField("component", "local-registry")

	repo, tag, ok := strings.Cut(imageName, ":")
	if !ok || repo == "" || tag == "" {
		return DockerContainer{}, fmt.Errorf(
			"invalid docker image reference %q: expected \"<repo>:<tag>\"", imageName)
	}
	if err := utils.PullDockerImage(th.ctx, log, imageName); err != nil {
		return DockerContainer{}, fmt.Errorf(
			"failed to obtain docker image %q: %w", imageName, err)
	}

	tarPath, err := saveDockerImageToTempFile(th.ctx, imageName)
	if err != nil {
		return DockerContainer{}, fmt.Errorf(
			"failed to export docker image %q: %w", imageName, err)
	}
	defer os.Remove(tarPath)

	img, err := tarball.ImageFromPath(tarPath, nil)
	if err != nil {
		return DockerContainer{}, fmt.Errorf(
			"failed to read exported docker image %q: %w", imageName, err)
	}

	dstRefStr := fmt.Sprintf("%s/%s:%s", localRegistryPushDomain(), repo, tag)
	dstRef, err := name.ParseReference(dstRefStr, name.Insecure)
	if err != nil {
		return DockerContainer{}, fmt.Errorf(
			"invalid local registry reference %q: %w", dstRefStr, err)
	}
	log.Infof("Pushing docker image %q into evetest's local OCI registry as %q",
		imageName, dstRefStr)
	if err := remote.Write(dstRef, img); err != nil {
		err = fmt.Errorf(
			"failed to push docker image %q to the local OCI registry: %w",
			imageName, err)
		return DockerContainer{}, err
	}

	return DockerContainer{
		Domain:            localRegistryPullDomain(),
		ImageName:         repo,
		Tag:               tag,
		TrustedCACertsPEM: []string{string(GetCACertPEM())},
	}, nil
}
