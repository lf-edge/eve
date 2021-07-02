package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/remotes"
	ecresolver "github.com/lf-edge/edge-containers/pkg/resolver"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"

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
	dcstoreOpts := []content.WriterOpt{content.WithBlocksize(blocksize)}
	if target.MultiWriter() {
		dcstoreOpts = append(dcstoreOpts, content.WithMultiWriterIngester())
	}
	decompressStore := content.NewDecompressStore(targetStore, dcstoreOpts...)

	allowedMediaTypes := AllMimeTypes()

	if verbose {
		pullOpts = append(pullOpts, oras.WithPullStatusTrack(writer))
	}

	// provide our own cache because of https://github.com/deislabs/oras/issues/225 and https://github.com/deislabs/oras/issues/226
	store := newCacheStoreFromIngester(decompressStore)
	pullOpts = append(pullOpts, oras.WithAllowedMediaTypes(allowedMediaTypes), oras.WithPullEmptyNameAllowed(), oras.WithContentProvideIngester(store), oras.WithPullByBFS)

	// pull the images
	desc, layers, err := p.Impl(ctx, resolver, p.Image, decompressStore, pullOpts...)
	if err != nil {
		return nil, nil, err
	}
	// process the layers to fill in our artifact
	// these can be in the layers, or in the config
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
	// it might have been in the config

	return &desc, artifact, nil
}

// Config pull the config for the artifact from the appropriate registry and return it as an object
//
// The resolver provides the channel to connect to the target type. resolver.Registry just uses the default registry,
// while resolver.Directory uses a local directory, etc.
func (p *Puller) Config(verbose bool, writer io.Writer, resolver ecresolver.ResolverCloser) (*ocispec.Descriptor, *ocispec.Image, error) {
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

	store := content.NewMemoryStore()

	// we only pull indexes, manifests and configs
	allowedMediaTypes := []string{ocispec.MediaTypeImageIndex, ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageConfig, MimeTypeDockerImageConfig, MimeTypeDockerImageManifest, MimeTypeDockerImageIndex}

	if verbose {
		pullOpts = append(pullOpts, oras.WithPullStatusTrack(writer))
	}
	pullOpts = append(pullOpts, oras.WithAllowedMediaTypes(allowedMediaTypes), oras.WithPullEmptyNameAllowed())

	// pull the images
	_, layers, err := p.Impl(ctx, resolver, p.Image, store, pullOpts...)
	if err != nil {
		return nil, nil, err
	}
	// run through the layers, looking for configs
	return findConfig(store, layers, "", "")
}

func findConfig(store *content.Memorystore, layers []ocispec.Descriptor, os, arch string) (desc *ocispec.Descriptor, config *ocispec.Image, err error) {
	// run through the layers, looking for configs
	for _, l := range layers {
		switch l.MediaType {
		case ocispec.MediaTypeImageConfig, MimeTypeDockerImageConfig:
			var conf ocispec.Image
			if _, data, found := store.Get(l); found {
				if err := json.Unmarshal(data, &conf); err != nil {
					return nil, nil, err
				}
			}
			if (os != "" && conf.OS != os) || (arch != "" && conf.Architecture != arch) {
				continue
			}
			config = &conf
			desc = &l
		}
	}
	return desc, config, nil
}
