// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"context"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/moby/moby/client"
	"github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/evetest/utils"
)

// newLocalRegistryHandler returns an http.Handler implementing the Docker
// Registry HTTP API v2, mounted at "/v2/" on the harness's image-server
// listeners alongside the plain file server. It lets EVE pull a container
// image (an upgrade rootfs, or an application content tree) directly from
// evetest, without that image ever having been published to a real,
// reachable registry -- see PushDockerImageToLocalRegistry.
//
// Blobs are stored under dir (th.imgServerDir) rather than kept in memory --
// TestUpgradeSuite runs every variant under a single Init, so an in-memory
// registry would keep every pushed image (an EVE rootfs is hundreds of MB)
// resident for the whole suite. Manifest/blob request logging is routed
// through harnessLog (at debug level, since it logs every single request)
// instead of registry.New's default of printing to stderr, outside logrus
// and outside the artifact dir.
func newLocalRegistryHandler(dir string, harnessLog *logrus.Logger) http.Handler {
	registryLogger := stdlog.New(
		harnessLog.WriterLevel(logrus.DebugLevel), "OCI Registry: ", 0)
	return registry.New(
		registry.WithBlobHandler(registry.NewDiskBlobHandler(dir)),
		registry.Logger(registryLogger),
	)
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
	ctx context.Context, log *logrus.Entry, imageName string) (path string, err error) {
	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		return "", fmt.Errorf("failed to create docker client: %w", err)
	}
	reader, err := dockerClient.ImageSave(ctx, []string{imageName})
	if err != nil {
		return "", fmt.Errorf("failed to save docker image %q: %w", imageName, err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Warnf("failed to close docker image save reader: %v", err)
		}
	}()

	f, err := os.CreateTemp("", "evetest-local-registry-*.tar")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warnf("failed to close temp file %q: %v", f.Name(), err)
		}
	}()
	defer func() {
		if err != nil {
			if rmErr := os.Remove(f.Name()); rmErr != nil {
				log.Warnf("failed to remove temp file %q: %v", f.Name(), rmErr)
			}
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

	// Parsed with name.NewTag rather than a naive split on ":", so a
	// registry host carrying its own port (e.g.
	// "harbor.example.com:5000/lfedge/eve:1.2.3-kvm-amd64") still yields
	// the correct repository ("lfedge/eve") and tag.
	srcTag, err := name.NewTag(imageName)
	if err != nil {
		return DockerContainer{}, fmt.Errorf(
			"invalid docker image reference %q: expected \"<repo>:<tag>\": %w", imageName, err)
	}
	repo := srcTag.Context().RepositoryStr()
	tag := srcTag.TagStr()
	if err := utils.PullDockerImage(th.ctx, log, imageName); err != nil {
		return DockerContainer{}, fmt.Errorf(
			"failed to obtain docker image %q: %w", imageName, err)
	}

	tarPath, err := saveDockerImageToTempFile(th.ctx, log, imageName)
	if err != nil {
		return DockerContainer{}, fmt.Errorf(
			"failed to export docker image %q: %w", imageName, err)
	}
	defer func() {
		if err := os.Remove(tarPath); err != nil {
			log.Warnf("failed to remove temp file %q: %v", tarPath, err)
		}
	}()

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
