package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	ecresolver "github.com/lf-edge/edge-containers/pkg/resolver"
	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"
	"oras.land/oras-go/pkg/target"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Puller struct {
	// Image reference to image, e.g. docker.io/foo/bar:tagabc
	Image string
	// Impl the OCI artifacts puller. Normally should be left blank, will be filled in to use oras. Override only for special cases like testing.
	Impl func(ctx context.Context, from target.Target, fromRef string, to target.Target, toRef string, opts ...oras.CopyOpt) (ocispec.Descriptor, error)
}

// Pull pull the artifact from the appropriate registry and save it to a local directory.
// Arguments are the dir where to write it, an io.Writer for logging output, and a target.
//
// The resolver provides the channel to connect to the target type. resolver.Registry just uses the default registry,
// while resolver.Directory uses a local directory, etc.
func (p *Puller) Pull(to target.Target, blocksize int, verbose bool, writer io.Writer, resolver ecresolver.ResolverCloser) (*ocispec.Descriptor, *Artifact, error) {
	// must have valid image ref
	if p.Image == "" {
		return nil, nil, fmt.Errorf("must have valid image ref")
	}
	// ensure we have a real puller
	if p.Impl == nil {
		p.Impl = oras.Copy
	}

	var (
		err error
	)
	// get the saved context; if nil, create a background one
	ctx := resolver.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	copyOpts := []oras.CopyOpt{}

	allowedMediaTypes := AllMimeTypes()

	if verbose {
		copyOpts = append(copyOpts, oras.WithPullStatusTrack(writer))
	}

	var layers []ocispec.Descriptor
	copyOpts = append(copyOpts,
		oras.WithAllowedMediaTypes(allowedMediaTypes),
		oras.WithPullEmptyNameAllowed(),
		oras.WithPullByBFS,
		oras.WithAdditionalCachedMediaTypes(ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex, images.MediaTypeDockerSchema2Manifest, images.MediaTypeDockerSchema2ManifestList),
		oras.WithLayerDescriptors(func(l []ocispec.Descriptor) {
			layers = l
		}),
	)

	// pull the images
	desc, err := p.Impl(ctx, resolver, p.Image, to, "", copyOpts...)
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
		p.Impl = oras.Copy
	}

	// get the saved context; if nil, create a background one
	ctx := resolver.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	copyOpts := []oras.CopyOpt{}

	store := content.NewMemory()

	// we only pull indexes, manifests and configs
	allowedMediaTypes := []string{ocispec.MediaTypeImageIndex, ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageConfig, MimeTypeDockerImageConfig, MimeTypeDockerImageManifest, MimeTypeDockerImageIndex}

	if verbose {
		copyOpts = append(copyOpts, oras.WithPullStatusTrack(writer))
	}
	copyOpts = append(copyOpts, oras.WithAllowedMediaTypes(allowedMediaTypes), oras.WithPullEmptyNameAllowed(),
		oras.WithAdditionalCachedMediaTypes(ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex, images.MediaTypeDockerSchema2Manifest, images.MediaTypeDockerSchema2ManifestList),
	)

	// pull the images
	root, err := p.Impl(ctx, resolver, p.Image, store, "", copyOpts...)
	if err != nil {
		return nil, nil, err
	}
	// walk the tree, looking for configs
	ctx2 := context.TODO()
	provider := oras.ProviderWrapper{Fetcher: store}
	return findConfig(ctx2, &provider, "", "", []ocispec.Descriptor{root})
}

func findConfig(ctx context.Context, provider ctrcontent.Provider, os, arch string, descs []ocispec.Descriptor) (desc *ocispec.Descriptor, config *ocispec.Image, err error) {
	// find the configs
	for _, d := range descs {
		switch d.MediaType {
		case ocispec.MediaTypeImageConfig, MimeTypeDockerImageConfig:
			var (
				conf   ocispec.Image
				reader ctrcontent.ReaderAt
			)
			reader, err = provider.ReaderAt(ctx, d)
			if err != nil {
				continue
			}
			data := make([]byte, d.Size)
			_, err = io.ReadFull(content.NewReaderAtWrapper(reader), data)
			if err != nil {
				continue
			}
			if err := json.Unmarshal(data, &conf); err != nil {
				return nil, nil, err
			}
			if (os != "" && conf.OS != os) || (arch != "" && conf.Architecture != arch) {
				continue
			}
			// found a config with the right os and arch, so return it
			config = &conf
			desc = &d
			return
		default:
			children, err := images.Children(ctx, provider, d)
			if err != nil {
				continue
			}
			childDesc, childConfig, err := findConfig(ctx, provider, os, arch, children)
			if err != nil {
				return nil, nil, err
			}
			if childDesc != nil && childConfig != nil {
				return childDesc, childConfig, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("not found")
}
