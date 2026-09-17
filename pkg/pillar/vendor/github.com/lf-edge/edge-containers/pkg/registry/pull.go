package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	ecresolver "github.com/lf-edge/edge-containers/pkg/resolver"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Puller struct {
	// Image reference to image, e.g. docker.io/foo/bar:tagabc
	Image string
	// Impl the copy implementation. Normally should be left blank, will be filled in to use oras. Override only for special cases like testing.
	Impl CopyFunc
}

// Pull pull the artifact from the appropriate registry and save it to the given target.
// Arguments are the target to write to, a blocksize, an io.Writer for logging output,
// and the resolver that reaches the source.
//
// The resolver provides the channel to connect to the source type. resolver.Registry
// reads a registry, resolver.Directory a local image layout, resolver.Containerd a
// containerd content store.
func (p *Puller) Pull(to oras.Target, blocksize int, verbose bool, writer io.Writer, resolver ecresolver.ResolverCloser) (*ocispec.Descriptor, *Artifact, error) {
	// must have valid image ref
	if p.Image == "" {
		return nil, nil, fmt.Errorf("must have valid image ref")
	}
	// ensure we have a real puller
	if p.Impl == nil {
		p.Impl = oras.Copy
	}
	if t, ok := to.(*FilesTarget); ok && blocksize > 0 {
		t.BlockSize = blocksize
	}

	// get the saved context; if nil, create a background one
	ctx := resolver.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	src, err := resolver.Target(ctx, p.Image)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get source for %s: %v", p.Image, err)
	}

	// Read the manifests before copying anything. Their layer annotations say what
	// each blob is, and their configs name the file paths inside legacy layers --
	// which a target splitting a layer across writers needs before that layer
	// arrives, and the copy gives no ordering guarantee.
	_, manifests, err := fetchManifests(ctx, src, p.Image)
	if err != nil {
		return nil, nil, err
	}
	var layers []ocispec.Descriptor
	for _, m := range manifests {
		if err := copyBlob(ctx, src, to, m.Config); err != nil {
			return nil, nil, fmt.Errorf("could not read config: %v", err)
		}
		layers = append(layers, m.Layers...)
	}

	copyOpts := oras.CopyOptions{}
	if verbose {
		copyOpts.PostCopy = progressReporter(writer, "Pulled")
	}
	desc, err := p.Impl(ctx, src, p.Image, to, "", copyOpts)
	if err != nil {
		return nil, nil, err
	}
	return &desc, artifactFromLayers(layers), nil
}

// Config pull the config for the artifact from the appropriate registry and return it as an object
func (p *Puller) Config(verbose bool, writer io.Writer, resolver ecresolver.ResolverCloser) (*ocispec.Descriptor, *ocispec.Image, error) {
	// must have valid image ref
	if p.Image == "" {
		return nil, nil, fmt.Errorf("must have valid image ref")
	}

	ctx := resolver.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	src, err := resolver.Target(ctx, p.Image)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get source for %s: %v", p.Image, err)
	}

	_, manifests, err := fetchManifests(ctx, src, p.Image)
	if err != nil {
		return nil, nil, err
	}
	for _, m := range manifests {
		// only an image config decodes as an ocispec.Image; an eci config is a
		// caller-supplied blob and would silently unmarshal to an empty one.
		if m.Config.MediaType != MimeTypeOCIImageConfig && m.Config.MediaType != MimeTypeDockerImageConfig {
			continue
		}
		b, err := content.FetchAll(ctx, src, m.Config)
		if err != nil {
			return nil, nil, fmt.Errorf("could not read config %s: %v", m.Config.Digest, err)
		}
		var config ocispec.Image
		if err := json.Unmarshal(b, &config); err != nil {
			return nil, nil, fmt.Errorf("could not convert config from json: %v", err)
		}
		desc := m.Config
		return &desc, &config, nil
	}
	return nil, nil, fmt.Errorf("not found")
}

// fetchManifests resolve ref and return the root descriptor along with every
// manifest under it. An index contributes each of the manifests it lists.
func fetchManifests(ctx context.Context, src oras.ReadOnlyTarget, ref string) (ocispec.Descriptor, []ocispec.Manifest, error) {
	root, err := src.Resolve(ctx, ref)
	if err != nil {
		return ocispec.Descriptor{}, nil, fmt.Errorf("could not resolve %s: %v", ref, err)
	}
	manifests, err := collectManifests(ctx, src, root)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}
	return root, manifests, nil
}

func collectManifests(ctx context.Context, src oras.ReadOnlyTarget, desc ocispec.Descriptor) ([]ocispec.Manifest, error) {
	b, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %v", desc.Digest, err)
	}
	switch desc.MediaType {
	case ocispec.MediaTypeImageIndex, MimeTypeDockerImageIndex:
		var index ocispec.Index
		if err := json.Unmarshal(b, &index); err != nil {
			return nil, fmt.Errorf("could not convert index from json: %v", err)
		}
		var manifests []ocispec.Manifest
		for _, m := range index.Manifests {
			children, err := collectManifests(ctx, src, m)
			if err != nil {
				return nil, err
			}
			manifests = append(manifests, children...)
		}
		return manifests, nil
	default:
		var manifest ocispec.Manifest
		if err := json.Unmarshal(b, &manifest); err != nil {
			return nil, fmt.Errorf("could not convert manifest from json: %v", err)
		}
		return []ocispec.Manifest{manifest}, nil
	}
}

// copyBlob move one blob from src to dst. A destination that already holds the
// blob is not an error: pulling unchanged content twice is a no-op, which is
// what oras's own copy does with ErrAlreadyExists.
func copyBlob(ctx context.Context, src oras.ReadOnlyTarget, dst oras.Target, desc ocispec.Descriptor) error {
	r, err := src.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if err := dst.Push(ctx, desc, r); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return err
	}
	return nil
}

// artifactFromLayers read the roles off the layer annotations to say what the
// artifact is made of.
func artifactFromLayers(layers []ocispec.Descriptor) *Artifact {
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
	return artifact
}
