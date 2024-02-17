package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/containerd/containerd/remotes"
	"github.com/lf-edge/edge-containers/pkg/tgz"

	"oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/target"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Manifest create the manifest for the given Artifact.
func (a Artifact) Manifest(format Format, configOpts ConfigOpts, ref string, legacyOpts ...LegacyOpt) (*ocispec.Manifest, target.Target, error) {
	var (
		desc  ocispec.Descriptor
		err   error
		lOpts = legacyInfo{}
	)

	for _, o := range legacyOpts {
		o(&lOpts)
	}

	// Go through each file type in the registry and add the appropriate file type and path, along with annotations
	fileStore := content.NewFile("")
	defer fileStore.Close()
	memStore := content.NewMemory()
	multiStore := content.MultiReader{}
	multiStore.AddStore(fileStore, memStore)

	// if we have the container format, we need to create tgz layers
	var (
		tmpDir       string
		labels       = map[string]string{}
		pushContents = []ocispec.Descriptor{}
		layers       = []digest.Digest{}
		layerHash    digest.Digest
	)

	if format == FormatLegacy {
		tmpDir = lOpts.tmpdir
		if tmpDir == "" {
			return nil, nil, fmt.Errorf("did not provide valid temporary directory for format legacy")
		}
	}

	if a.Kernel != nil {
		name := "kernel"
		desc, err = createLayerAndDesc(RoleKernel, name, MimeTypeECIKernel, tmpDir, format, lOpts.timestamp, a.Kernel, fileStore, memStore)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding kernel: %v", err)
		}
		pushContents = append(pushContents, desc)
		if layerHash == "" {
			layerHash = desc.Digest
		}
		layers = append(layers, layerHash)

		labels[AnnotationKernelPath] = fmt.Sprintf("/%s", name)
	}

	if a.Initrd != nil {
		role := RoleInitrd
		name := "initrd"
		layerHash = ""
		customMediaType := MimeTypeECIInitrd

		desc, err = createLayerAndDesc(role, name, customMediaType, tmpDir, format, lOpts.timestamp, a.Initrd, fileStore, memStore)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding initrd: %v", err)
		}

		pushContents = append(pushContents, desc)
		if layerHash == "" {
			layerHash = desc.Digest
		}
		layers = append(layers, layerHash)

		labels[AnnotationInitrdPath] = fmt.Sprintf("/%s", name)
	}

	if disk := a.Root; disk != nil {
		if disk.Source == nil {
			return nil, nil, errors.New("root disk does not have valid source")
		}
		role := RoleRootDisk
		name := fmt.Sprintf("disk-root-%s", disk.Source.GetName())
		customMediaType := TypeToMime[disk.Type]

		desc, err = createLayerAndDesc(role, name, customMediaType, tmpDir, format, lOpts.timestamp, disk.Source, fileStore, memStore)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding %s disk: %v", name, err)
		}

		pushContents = append(pushContents, desc)
		if layerHash == "" {
			layerHash = desc.Digest
		}
		layers = append(layers, layerHash)

		labels[AnnotationRootPath] = fmt.Sprintf("/%s", name)
	}
	for i, disk := range a.Disks {
		if disk != nil {
			role := RoleAdditionalDisk
			name := fmt.Sprintf("disk-%d-%s", i, disk.Source.GetName())
			customMediaType := TypeToMime[disk.Type]

			desc, err = createLayerAndDesc(role, name, customMediaType, tmpDir, format, lOpts.timestamp, disk.Source, fileStore, memStore)
			if err != nil {
				return nil, nil, fmt.Errorf("error adding %s disk: %v", name, err)
			}

			pushContents = append(pushContents, desc)
			if layerHash == "" {
				layerHash = desc.Digest
			}
			layers = append(layers, layerHash)

			labels[fmt.Sprintf(AnnotationDiskIndexPathPattern, i)] = fmt.Sprintf("/%s", name)
		}
	}
	for _, other := range a.Other {
		if other != nil {
			customMediaType := MimeTypeECIOther
			name := other.GetName()

			desc, err = createLayerAndDesc("", name, customMediaType, tmpDir, format, lOpts.timestamp, other, fileStore, memStore)
			if err != nil {
				return nil, nil, fmt.Errorf("error adding other: %v", err)
			}
			pushContents = append(pushContents, desc)
			if layerHash == "" {
				layerHash = desc.Digest
			}
			layers = append(layers, layerHash)

			labels[AnnotationOther] = fmt.Sprintf("/%s", name)
		}
	}

	// was a config specified?
	if a.Config != nil {
		name := "config.json"
		customMediaType := MimeTypeECIConfig

		desc, err = createLayerAndDesc("", name, customMediaType, tmpDir, format, lOpts.timestamp, a.Config, fileStore, memStore)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding %s: %v", name, err)
		}
	} else {
		// for container format, we expect to have a specific config so docker can work with it
		created := time.Now()
		configAuthor, configOS, configArch := configOpts.Author, configOpts.OS, configOpts.Architecture
		if configAuthor == "" {
			configAuthor = DefaultAuthor
		}
		if configOS == "" {
			configOS = DefaultOS
		}
		if configArch == "" {
			configArch = DefaultArch
		}
		config := ocispec.Image{
			Created:  &created,
			Author:   configAuthor,
			Platform: ocispec.Platform{Architecture: configArch, OS: configOS},
			RootFS: ocispec.RootFS{
				Type:    "layers",
				DiffIDs: layers,
			},
			Config: ocispec.ImageConfig{
				Labels: labels,
			},
		}
		configBytes, err := json.Marshal(config)
		if err != nil {
			return nil, nil, fmt.Errorf("error marshaling config to json: %v", err)
		}

		name := "config.json"
		mediaType := MimeTypeOCIImageConfig
		desc, err = memStore.Add(name, mediaType, configBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding OCI config: %v", err)
		}
	}
	// make our manifest
	mediaType := ocispec.MediaTypeImageManifest
	manifest := &ocispec.Manifest{
		Config:    desc,
		Layers:    pushContents,
		MediaType: mediaType,
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to convert manifest to json: %v", err)
	}
	manifestDesc := ocispec.Descriptor{
		MediaType: mediaType,
		Size:      int64(len(b)),
		Digest:    digest.FromBytes(b),
	}
	target := newMultiTarget(multiStore)
	// It is a bit annoying that we need to store this twice, but the only oras structure
	// that supports multiple backends is content.MultiReader, and that does not have
	// support for Resolve(), only for Fetch().
	_ = memStore.StoreManifest(ref, manifestDesc, b)
	_ = target.StoreManifest(ref, manifestDesc, b)

	return manifest, target, nil
}

func getManifest(dig, name, mediaType string, size int64) (ocispec.Descriptor, error) {
	var (
		annotations map[string]string
		desc        ocispec.Descriptor
	)
	if name != "" {
		annotations = map[string]string{
			ocispec.AnnotationTitle: name,
		}
	}

	if mediaType == "" {
		mediaType = content.DefaultBlobMediaType
	}

	dige, err := digest.Parse(dig)
	if err != nil {
		return desc, fmt.Errorf("invalid digest %s: %v", dig, err)
	}
	desc = ocispec.Descriptor{
		MediaType:   mediaType,
		Digest:      dige,
		Size:        size,
		Annotations: annotations,
	}
	return desc, nil
}

func createLayerAndDesc(role, name, customMediaType, tmpDir string, format Format, timestamp *time.Time, source Source, fileStore *content.File, memStore *content.Memory) (ocispec.Descriptor, error) {
	var (
		desc ocispec.Descriptor
		err  error
	)
	mediaType := GetLayerMediaType(customMediaType, format)
	switch {
	case source.GetPath() != "":
		filepath := source.GetPath()
		if format == FormatLegacy {
			tgzfile := path.Join(tmpDir, name)
			_, _, err := tgz.Compress(filepath, name, tgzfile, timestamp)
			if err != nil {
				return desc, fmt.Errorf("error creating tgz file for %s: %v", filepath, err)
			}
			filepath = tgzfile
		}
		desc, err = fileStore.Add(name, mediaType, filepath)
		if err != nil {
			return desc, fmt.Errorf("error adding %s from file at %s: %v", name, filepath, err)
		}
	case source.GetContent() != nil:
		desc, err = memStore.Add(name, mediaType, source.GetContent())
		if err != nil {
			return desc, fmt.Errorf("error adding content for %s: %v", name, err)
		}
	case source.GetDigest() != "":
		desc, err = getManifest(source.GetDigest(), name, mediaType, source.GetSize())
		if err != nil {
			return desc, fmt.Errorf("error getting manifest for %s: %v", name, err)
		}
	default:
		return desc, fmt.Errorf("no valid source for %s", name)
	}
	desc.Annotations[AnnotationMediaType] = customMediaType
	desc.Annotations[AnnotationRole] = role
	desc.Annotations[ocispec.AnnotationTitle] = name
	return desc, nil
}

// multiTarget wrap a multiReader so it can be a proper target.Target. This really should be upstream in oras.
type multiTarget struct {
	reader *content.MultiReader
	memory *content.Memory
}

func newMultiTarget(reader content.MultiReader) *multiTarget {
	return &multiTarget{
		reader: &reader,
		memory: content.NewMemory(),
	}
}

func (m *multiTarget) StoreManifest(ref string, manifest ocispec.Descriptor, b []byte) error {
	return m.memory.StoreManifest(ref, manifest, b)
}
func (m *multiTarget) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	return m.reader, nil
}
func (m *multiTarget) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	return nil, fmt.Errorf("unsupported")
}
func (m *multiTarget) Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	return m.memory.Resolve(ctx, ref)
}
