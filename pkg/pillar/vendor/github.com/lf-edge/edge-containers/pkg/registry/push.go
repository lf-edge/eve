package registry

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"time"

	ecresolver "github.com/lf-edge/edge-containers/pkg/resolver"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/remotes"
	"github.com/deislabs/oras/pkg/content"
	"github.com/deislabs/oras/pkg/oras"

	"github.com/containerd/containerd/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	DefaultAuthor = "lf-edge/edge-containers"
	DefaultOS     = runtime.GOOS
	DefaultArch   = runtime.GOARCH
)

type Pusher struct {
	// Artifact artifact to push
	Artifact *Artifact
	// Image reference to image, e.g. docker.io/foo/bar:tagabc
	Image string
	// Timestamp set any files to have this timestamp, instead of the default of the file time
	Timestamp *time.Time
	// Impl the OCI artifacts pusher. Normally should be left blank, will be filled in to use oras. Override only for special cases like testing.
	Impl func(ctx context.Context, resolver remotes.Resolver, ref string, provider ctrcontent.Provider, descriptors []ocispec.Descriptor, opts ...oras.PushOpt) (ocispec.Descriptor, error)
}

// Push push the artifact to the appropriate registry. Arguments are the format to write,
// an io.Writer for sending debug output, ConfigOpts to configure how the image should be configured,
// and a target.
//
// The target determines the target type. target.Registry just uses the default registry,
// while target.Directory uses a local directory.
func (p Pusher) Push(format Format, verbose bool, writer io.Writer, configOpts ConfigOpts, resolver ecresolver.ResolverCloser) (string, error) {
	var (
		desc     ocispec.Descriptor
		err      error
		pushOpts []oras.PushOpt
	)

	// ensure the artifact and name are provided
	if p.Artifact == nil {
		return "", fmt.Errorf("must have valid Artifact")
	}
	if p.Image == "" {
		return "", fmt.Errorf("must have valid image ref")
	}
	// ensure we have a real pusher
	if p.Impl == nil {
		p.Impl = oras.Push
	}

	// get the saved context; if nil, create a background one
	ctx := resolver.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// if we have the container format, we need to create tgz layers
	var (
		tmpDir     string
		legacyOpts []LegacyOpt
	)
	legacyOpts = append(legacyOpts, WithTimestamp(p.Timestamp))

	if format == FormatLegacy {
		tmpDir, err = ioutil.TempDir("", "edge-containers")
		if err != nil {
			return "", fmt.Errorf("could not make temporary directory for tgz files: %v", err)
		}
		legacyOpts = append(legacyOpts, WithTmpDir(tmpDir))
		defer os.RemoveAll(tmpDir)
	}

	manifest, provider, err := p.Artifact.Manifest(format, configOpts, legacyOpts...)
	if err != nil {
		return "", fmt.Errorf("could not build manifest: %v", err)
	}
	pushOpts = append(pushOpts, oras.WithConfig(manifest.Config))

	if verbose {
		pushOpts = append(pushOpts, oras.WithPushBaseHandler(pushStatusTrack(writer)))
	}

	// push the data
	desc, err = p.Impl(ctx, resolver, p.Image, provider, manifest.Layers, pushOpts...)
	if err != nil {
		return "", err
	}
	if err := resolver.Finalize(ctx); err != nil {
		return desc.Digest.String(), fmt.Errorf("failed to finalize: %v", err)
	}
	return desc.Digest.String(), nil
}

func pushStatusTrack(writer io.Writer) images.Handler {
	var printLock sync.Mutex
	return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if name, ok := content.ResolveName(desc); ok {
			printLock.Lock()
			defer printLock.Unlock()
			writer.Write([]byte(fmt.Sprintf("Uploading %s %s\n", desc.Digest.Encoded()[:12], name)))
		}
		return nil, nil
	})
}
