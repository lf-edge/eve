package registry

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	ecresolver "github.com/lf-edge/edge-containers/pkg/resolver"

	oras "oras.land/oras-go/v2"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	DefaultAuthor = "lf-edge/edge-containers"
	DefaultOS     = runtime.GOOS
	DefaultArch   = runtime.GOARCH
)

// CopyFunc copies an artifact between two oras targets. It matches oras.Copy.
type CopyFunc func(ctx context.Context, src oras.ReadOnlyTarget, srcRef string, dst oras.Target, dstRef string, opts oras.CopyOptions) (ocispec.Descriptor, error)

type Pusher struct {
	// Artifact artifact to push
	Artifact *Artifact
	// Image reference to image, e.g. docker.io/foo/bar:tagabc
	Image string
	// Timestamp set any files to have this timestamp, instead of the default of the file time
	Timestamp *time.Time
	// Impl the copy implementation. Normally should be left blank, will be filled in to use oras. Override only for special cases like testing.
	Impl CopyFunc
}

// Push push the artifact to the appropriate registry. Arguments are the format to write,
// an io.Writer for sending debug output, ConfigOpts to configure how the image should be configured,
// and a target.
//
// The target determines where the artifact is written: resolver.Registry for a
// registry, resolver.Directory for a local image layout, resolver.Containerd for
// a containerd content store.
func (p Pusher) Push(format Format, verbose bool, statusWriter io.Writer, configOpts ConfigOpts, to ecresolver.ResolverCloser) (string, error) {
	var err error

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
		tmpDir, err = os.MkdirTemp("", "edge-containers")
		if err != nil {
			return "", fmt.Errorf("could not make temporary directory for tgz files: %v", err)
		}
		legacyOpts = append(legacyOpts, WithTmpDir(tmpDir))
		defer func() { _ = os.RemoveAll(tmpDir) }()
	}

	_, from, err := p.Artifact.Manifest(format, configOpts, p.Image, legacyOpts...)
	if err != nil {
		return "", fmt.Errorf("could not build manifest: %v", err)
	}

	dst, err := to.Target(ctx, p.Image)
	if err != nil {
		return "", fmt.Errorf("could not get target for %s: %v", p.Image, err)
	}

	copyOpts := oras.CopyOptions{}
	if verbose {
		copyOpts.PostCopy = progressReporter(statusWriter, "Pushed")
	}

	desc, err := p.Impl(ctx, from, p.Image, dst, p.Image, copyOpts)
	if err != nil {
		return "", err
	}
	if err := to.Finalize(ctx); err != nil {
		return desc.Digest.String(), fmt.Errorf("failed to finalize: %v", err)
	}
	return desc.Digest.String(), nil
}

// progressReporter reports each part of the artifact as it goes by, naming it by
// the title the artifact gave it where there is one. oras calls this from as many
// goroutines as its copy concurrency allows, so the writes are serialized.
func progressReporter(w io.Writer, verb string) func(context.Context, ocispec.Descriptor) error {
	var mu sync.Mutex
	return func(_ context.Context, desc ocispec.Descriptor) error {
		if w == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		name := desc.Annotations[ocispec.AnnotationTitle]
		if name == "" {
			name = desc.MediaType
		}
		_, err := fmt.Fprintf(w, "%s %s %s\n", verb, shortDigest(desc.Digest.String()), name)
		return err
	}
}

// shortDigest the conventional abbreviation of a digest: the first 12 characters
// of the encoded part, matching what docker, oras and registries print.
func shortDigest(dgst string) string {
	const shortLen = 12
	encoded := dgst
	if i := strings.Index(encoded, ":"); i >= 0 {
		encoded = encoded[i+1:]
	}
	if len(encoded) > shortLen {
		return encoded[:shortLen]
	}
	return encoded
}
