// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	ggcrtypes "github.com/google/go-containerregistry/pkg/v1/types"
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

// staticBlob is a registry blob held in memory, shaped as a v1.Layer so that
// go-containerregistry can upload it (remote.WriteLayer) or list it in a
// manifest (mutate.AppendLayers). It is whatever its media type says: a
// gzip-compressed layer, or an image config, which the registry stores like
// any other blob.
type staticBlob struct {
	data      []byte
	mediaType ggcrtypes.MediaType
}

func (b staticBlob) Digest() (v1.Hash, error) {
	h, _, err := v1.SHA256(bytes.NewReader(b.data))
	return h, err
}

func (b staticBlob) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(b.data)), nil
}

func (b staticBlob) Size() (int64, error) {
	return int64(len(b.data)), nil
}

func (b staticBlob) MediaType() (ggcrtypes.MediaType, error) {
	return b.mediaType, nil
}

// randomGzipLayer returns a layer of size random bytes, gzip-compressed, whose
// digest no other layer shares.
func randomGzipLayer(size int) (v1.Layer, error) {
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return partial.CompressedToLayer(
		staticBlob{data: buf.Bytes(), mediaType: ggcrtypes.DockerLayer})
}

// PushImageWithMissingLayersToLocalRegistry publishes, under repo:tag in
// evetest's embedded OCI registry, an image of numLayers layers of which only
// the manifest and the config blob are uploaded: the layer blobs never are. A
// pull of the image resolves the tag and fetches the manifest and the config
// without trouble, then fails on every layer with the registry's
// BLOB_UNKNOWN. That is the shape of a registry, or a pull-through mirror,
// that has lost or never received the blobs a manifest refers to, and of a
// registry that becomes unreachable right after serving the manifest: every
// layer fails on its own, and from every management port the downloader
// tries it from.
//
// Every layer is a few bytes of random gzip, so no two images published this
// way share a digest and nothing pulled earlier can stand in for a layer. The
// layers' digests are returned as volumemgr names them (lowercase hex, no
// "sha256:" prefix), in manifest order, for a test to recognize them in what
// EVE reports. The returned DockerContainer points an EVE datastore at the
// image, as PushDockerImageToLocalRegistry does.
func PushImageWithMissingLayersToLocalRegistry(repo, tag string, numLayers int) (
	image DockerContainer, layerDigests []string, err error) {
	th := getTestHarness()
	log := th.log.WithField("component", "local-registry")

	dstRefStr := fmt.Sprintf("%s/%s:%s", localRegistryPushDomain(), repo, tag)
	dstRef, err := name.ParseReference(dstRefStr, name.Insecure)
	if err != nil {
		return DockerContainer{}, nil, fmt.Errorf(
			"invalid local registry reference %q: %w", dstRefStr, err)
	}

	layers := make([]v1.Layer, 0, numLayers)
	for i := 0; i < numLayers; i++ {
		layer, err := randomGzipLayer(64)
		if err != nil {
			return DockerContainer{}, nil, fmt.Errorf(
				"failed to generate layer %d of %q: %w", i, dstRefStr, err)
		}
		digest, err := layer.Digest()
		if err != nil {
			return DockerContainer{}, nil, fmt.Errorf(
				"failed to digest layer %d of %q: %w", i, dstRefStr, err)
		}
		layers = append(layers, layer)
		layerDigests = append(layerDigests, digest.Hex)
	}
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return DockerContainer{}, nil, fmt.Errorf(
			"failed to assemble image %q: %w", dstRefStr, err)
	}
	rawConfig, err := img.RawConfigFile()
	if err != nil {
		return DockerContainer{}, nil, fmt.Errorf(
			"failed to serialize the config of image %q: %w", dstRefStr, err)
	}
	config, err := partial.CompressedToLayer(
		staticBlob{data: rawConfig, mediaType: ggcrtypes.DockerConfigJSON})
	if err != nil {
		return DockerContainer{}, nil, fmt.Errorf(
			"failed to wrap the config of image %q: %w", dstRefStr, err)
	}

	log.Infof("Pushing the manifest and config of a %d-layer image, without "+
		"its layers, into evetest's local OCI registry as %q", numLayers, dstRefStr)
	if err := remote.WriteLayer(dstRef.Context(), config); err != nil {
		return DockerContainer{}, nil, fmt.Errorf(
			"failed to push the config blob of image %q to the local OCI registry: %w",
			dstRefStr, err)
	}
	if err := remote.Put(dstRef, img); err != nil {
		return DockerContainer{}, nil, fmt.Errorf(
			"failed to push the manifest of image %q to the local OCI registry: %w",
			dstRefStr, err)
	}

	return DockerContainer{
		Domain:            localRegistryPullDomain(),
		ImageName:         repo,
		Tag:               tag,
		TrustedCACertsPEM: []string{string(GetCACertPEM())},
	}, layerDigests, nil
}
