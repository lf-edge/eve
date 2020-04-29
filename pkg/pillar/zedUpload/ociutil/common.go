package ociutil

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1tarball "github.com/google/go-containerregistry/pkg/v1/tarball"
	log "github.com/sirupsen/logrus"
)

func manifestsDescImg(image string, options []remote.Option) (name.Reference, *remote.Descriptor, v1.Image, []byte, []byte, int64, error) {
	var (
		manifestDirect, manifestResolved []byte
		img                              v1.Image
		desc                             *remote.Descriptor
		size                             int64
		err                              error
		ref                              name.Reference
	)
	log.Infof("manifestsDescImg(%s)", image)

	// FIXME tar archive size is 1024 bytes greater than the sizes of
	// the underlying file. Currently, it has been added purely on the
	// basis of analysis. These changes will go away once underlying
	// "go-containerregistry" library will start supporting download progess
	size = 1024

	ref, err = name.ParseReference(image)
	if err != nil {
		log.Errorf("error parsing image (%s): %v", image, err)
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("parsing reference %q: %v", image, err)
	}

	// resolve out platform
	options = append(options, remote.WithPlatform(v1.Platform{Architecture: runtime.GOARCH, OS: runtime.GOOS}))
	log.Debugf("options %#v", options)

	// first get the root manifest. This might be an index or a manifest
	log.Infof("manifestsDescImg(%s) getting image ref %#v", image, ref)
	desc, err = remote.Get(ref, options...)
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error getting manifest: %v", err)
	}
	manifestDirect = desc.Manifest

	// This is where it gets the image manifest, but does not actually save anything
	// It is the manifest of the image itself, not of the index (if it is
	// an index), so it actually does resolve platform-specific
	img, err = desc.Image()
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error pulling image ref: %v", err)
	}

	// check out the manifest and hash
	manifestResolved, err = img.RawManifest()
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error getting resolved manifest bytes: %v", err)
	}

	// we now get the actual manifest, to get the layers and resolve the size
	manifest, err := img.Manifest()
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error getting resolved manifest object: %v", err)
	}

	// size starts at the default of 0
	// add the size of the config
	size += v1tarball.CalculateTarFileSize(manifest.Config.Size)

	// next the layers and their sizes, along with filenames for the manifest
	imgLayers, err := img.Layers()
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error getting layers of image: %v", err)
	}
	for _, layer := range imgLayers {
		layerSize, err := layer.Size()
		if err != nil {
			return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error getting size of layers: %v", err)
		}
		size += v1tarball.CalculateTarFileSize(layerSize)
	}

	// get our manifestFile that will be added, convert to bytes, get size
	manifestFile, err := v1tarball.ComputeManifest(map[name.Reference]v1.Image{
		ref: img,
	})
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error getting tar manifest file: %v", err)
	}
	manifestFileBytes, err := json.Marshal(manifestFile)
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error converting tar manifest file to json: %v", err)
	}
	size += v1tarball.CalculateTarFileSize(int64(len(manifestFileBytes)))

	return ref, desc, img, manifestDirect, manifestResolved, size, nil
}
