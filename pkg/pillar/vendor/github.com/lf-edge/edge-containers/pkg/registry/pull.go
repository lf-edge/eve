package registry

import (
	"context"
	"fmt"
	"io"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/remotes"
	"github.com/deislabs/oras/pkg/oras"
	ecresolver "github.com/lf-edge/edge-containers/pkg/resolver"
	"github.com/lf-edge/edge-containers/pkg/store"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Puller struct {
	// Image reference to image, e.g. docker.io/foo/bar:tagabc
	Image string
	// Impl the OCI artifacts puller. Normally should be left blank, will be filled in to use oras. Override only for special cases like testing.
	Impl func(ctx context.Context, resolver remotes.Resolver, ref string, ingester ctrcontent.Ingester, opts ...oras.PullOpt) (ocispec.Descriptor, []ocispec.Descriptor, error)
}

// Pull pull the artifact from the appropriate registry and save it to a local directory.
// Arguments are the dir where to write it, an io.Writer for logging output, and a target.
//
// The resolver provides the channel to connect to the target type. resolver.Registry just uses the default registry,
// while resolver.Directory uses a local directory, etc.
func (p *Puller) Pull(target Target, blocksize int, verbose bool, writer io.Writer, resolver ecresolver.ResolverCloser) (*ocispec.Descriptor, *Artifact, error) {
	// must have valid image ref
	if p.Image == "" {
		return nil, nil, fmt.Errorf("must have valid image ref")
	}
	// ensure we have a real puller
	if p.Impl == nil {
		p.Impl = oras.Pull
	}

	var (
		err error
	)
	// get the saved context; if nil, create a background one
	ctx := resolver.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	pullOpts := []oras.PullOpt{}

	targetStore := target.Ingester()
	defer targetStore.Close()
	decompressStore := store.NewDecompressStore(targetStore, blocksize)

	allowedMediaTypes := AllMimeTypes()

	if verbose {
		pullOpts = append(pullOpts, oras.WithPullStatusTrack(writer))
	}
	pullOpts = append(pullOpts, oras.WithAllowedMediaTypes(allowedMediaTypes))
	// pull the images
	desc, layers, err := p.Impl(ctx, resolver, p.Image, decompressStore, pullOpts...)
	if err != nil {
		return nil, nil, err
	}
	// process the layers to fill in our artifact
	artifact := &Artifact{
		Disks: []*Disk{},
	}
	for _, l := range layers {
		if l.Annotations == nil {
			continue
		}
		filepath := l.Annotations[ocispec.AnnotationTitle]
		if filepath == "" {
			continue
		}
		mediaType := l.Annotations[AnnotationMediaType]
		switch l.Annotations[AnnotationRole] {
		case RoleKernel:
			artifact.Kernel = &FileSource{Path: filepath}
		case RoleInitrd:
			artifact.Initrd = &FileSource{Path: filepath}
		case RoleRootDisk:
			artifact.Root = &Disk{
				Source: &FileSource{Path: filepath},
				Type:   MimeToType[mediaType],
			}
		case RoleAdditionalDisk:
			artifact.Disks = append(artifact.Disks, &Disk{
				Source: &FileSource{Path: filepath},
				Type:   MimeToType[mediaType],
			})
		}
	}
	return &desc, artifact, nil
}
