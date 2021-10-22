package ociutil

import (
	"fmt"
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1tarball "github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/sirupsen/logrus"
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
	logrus.Infof("manifestsDescImg(%s)", image)

	ref, err = name.ParseReference(image)
	if err != nil {
		logrus.Errorf("error parsing image (%s): %v", image, err)
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("parsing reference %q: %v", image, err)
	}

	// resolve our platform
	options = append(options, remote.WithPlatform(v1.Platform{Architecture: runtime.GOARCH, OS: runtime.GOOS}))
	logrus.Debugf("options %#v", options)

	// first get the root manifest. This might be an index or a manifest
	logrus.Infof("manifestsDescImg(%s) getting image ref %#v", image, ref)
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

	refToImage := make(map[name.Reference]v1.Image, 1)
	refToImage[ref] = img
	tarSize, err := v1tarball.CalculateSize(refToImage)
	if err != nil {
		return ref, desc, img, manifestDirect, manifestResolved, size, fmt.Errorf("error getting size: %v", err)
	}
	size = tarSize

	return ref, desc, img, manifestDirect, manifestResolved, size, nil
}
