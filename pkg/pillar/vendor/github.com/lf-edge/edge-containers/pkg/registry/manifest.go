package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/lf-edge/edge-containers/pkg/store"
	"github.com/lf-edge/edge-containers/pkg/tgz"

	"github.com/deislabs/oras/pkg/content"

	ctrcontent "github.com/containerd/containerd/content"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Manifest create the manifest for the given Artifact.
func (a Artifact) Manifest(format Format, configOpts ConfigOpts, legacyOpts ...LegacyOpt) (*ocispec.Manifest, ctrcontent.Provider, error) {
	var (
		desc  ocispec.Descriptor
		err   error
		lOpts = legacyInfo{}
	)

	for _, o := range legacyOpts {
		o(&lOpts)
	}

	// Go through each file type in the registry and add the appropriate file type and path, along with annotations
	fileStore := content.NewFileStore("")
	defer fileStore.Close()
	memStore := content.NewMemoryStore()
	multiStore := store.MultiReader{}
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
			Created:      &created,
			Author:       configAuthor,
			Architecture: configArch,
			OS:           configOS,
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
		desc = memStore.Add(name, mediaType, configBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error adding OCI config: %v", err)
		}
	}
	// make our manifest
	return &ocispec.Manifest{
		Config: desc,
		Layers: pushContents,
	}, multiStore, nil
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

func createLayerAndDesc(role, name, customMediaType, tmpDir string, format Format, timestamp *time.Time, source Source, fileStore *content.FileStore, memStore *content.Memorystore) (ocispec.Descriptor, error) {
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
		desc = memStore.Add(name, mediaType, source.GetContent())
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
