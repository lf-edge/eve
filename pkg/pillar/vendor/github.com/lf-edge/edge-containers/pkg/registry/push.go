package registry

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"time"

	ecresolver "github.com/lf-edge/edge-containers/pkg/resolver"

	"oras.land/oras-go/pkg/oras"
	"oras.land/oras-go/pkg/target"

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
	Impl func(ctx context.Context, from target.Target, fromRef string, to target.Target, toRef string, opts ...oras.CopyOpt) (ocispec.Descriptor, error)
}

// Push push the artifact to the appropriate registry. Arguments are the format to write,
// an io.Writer for sending debug output, ConfigOpts to configure how the image should be configured,
// and a target.
//
// The target determines the target type. target.Registry just uses the default registry,
// while target.Directory uses a local directory.
func (p Pusher) Push(format Format, verbose bool, statusWriter io.Writer, configOpts ConfigOpts, to ecresolver.ResolverCloser) (string, error) {
	var (
		desc     ocispec.Descriptor
		err      error
		copyOpts []oras.CopyOpt
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
		p.Impl = oras.Copy
	}

	// get the saved context; if nil, create a background one
	ctx := to.Context()
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

	_, from, err := p.Artifact.Manifest(format, configOpts, p.Image, legacyOpts...)
	if err != nil {
		return "", fmt.Errorf("could not build manifest: %v", err)
	}

	if verbose {
		copyOpts = append(copyOpts, oras.WithPullStatusTrack(statusWriter))
	}

	// push the data
	desc, err = p.Impl(ctx, from, p.Image, to, "", copyOpts...)
	if err != nil {
		return "", err
	}
	if err := to.Finalize(ctx); err != nil {
		return desc.Digest.String(), fmt.Errorf("failed to finalize: %v", err)
	}
	return desc.Digest.String(), nil
}
