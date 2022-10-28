// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// resolveIndex get the manifest for our platform from the index
func resolveIndex(ctx *volumemgrContext, blob *types.BlobStatus) (*v1.Descriptor, error) {
	ctrdCtx, done := ctx.casClient.CtrNewUserServicesCtx()
	defer done()

	var index *v1.IndexManifest
	//If the blob is loaded, then read the blob from CAS else read the verified image of the blob
	if blob.State == types.LOADED {
		blobHash := cas.CheckAndCorrectBlobHash(blob.Sha256)
		// try it as an index and as a straight manifest
		reader, err := ctx.casClient.ReadBlob(ctrdCtx, blobHash)
		if err != nil {
			err = fmt.Errorf("resolveIndex(%s): Exception while reading blob: %v", blob.Sha256, err)
			log.Errorf(err.Error())
			return nil, err
		}
		index, err = v1.ParseIndexManifest(reader)
		if err != nil && err != io.EOF {
			err = fmt.Errorf("resolveIndex(%s): Exception while parsing Index from cas: %v", blob.Sha256, err)
			log.Errorf(err.Error())
			return nil, err
		}
	} else {
		fileReader, err := os.Open(blob.Path)
		if err != nil {
			err = fmt.Errorf("resolveIndex(%s): failed to open file %s: %v", blob.Sha256, blob.Path, err)
			log.Errorf(err.Error())
			return nil, err
		}
		index, err = v1.ParseIndexManifest(fileReader)
		if err != nil && err != io.EOF {
			err = fmt.Errorf("resolveIndex(%s): Exception while parsing Index from %s: %v",
				blob.Sha256, blob.Path, err)
			log.Errorf(err.Error())
			return nil, err
		}
		defer fileReader.Close()
	}

	// find our platform
	var manifest *v1.Descriptor
	for _, m := range index.Manifests {
		if m.Platform != nil && m.Platform.OS == runtime.GOOS && m.Platform.Architecture == runtime.GOARCH {
			manifest = &m
			break
		}
	}
	return manifest, nil
}

// resolveManifestChildren get all of the children of a manifest, as well as
// expected total size
func resolveManifestChildren(ctx *volumemgrContext, blob *types.BlobStatus) (int64, []v1.Descriptor, error) {
	var manifest *v1.Manifest

	ctrdCtx, done := ctx.casClient.CtrNewUserServicesCtx()
	defer done()

	//If the blob is loaded, then read the blob from CAS else read the verified image of the blob
	if blob.State == types.LOADED {
		blobHash := cas.CheckAndCorrectBlobHash(blob.Sha256)
		// try it as an index and as a straight manifest
		reader, err := ctx.casClient.ReadBlob(ctrdCtx, blobHash)
		if err != nil {
			err = fmt.Errorf("resolveManifestChildren(%s): Exception while reading blob: %v", blob.Sha256, err)
			log.Errorf(err.Error())
			return 0, nil, err
		}
		manifest, err = v1.ParseManifest(reader)
		if err != nil && err != io.EOF {
			err = fmt.Errorf("resolveManifestChildren(%s): Exception while parsing Index from cas: %v", blob.Sha256, err)
			log.Errorf(err.Error())
			return 0, nil, err
		}
	} else {
		fileReader, err := os.Open(blob.Path)
		if err != nil {
			err = fmt.Errorf("resolveManifestChildren(%s): failed to open file %s: %v", blob.Sha256, blob.Path, err)
			log.Errorf(err.Error())
			return 0, nil, err
		}
		manifest, err = v1.ParseManifest(fileReader)
		if err != nil && err != io.EOF {
			err = fmt.Errorf("resolveManifestChildren(%s): Exception while parsing Index from %s: %v",
				blob.Sha256, blob.Path, err)
			log.Errorf(err.Error())
			return 0, nil, err
		}
		defer fileReader.Close()
	}

	// get all of the parts and calculate the size
	var size int64

	children := []v1.Descriptor{}
	children = append(children, manifest.Config)
	size += manifest.Config.Size
	for _, l := range manifest.Layers {
		children = append(children, l)
		size += l.Size
	}
	return size, children, nil
}

// descriptorSizes calculate the size of all of the descriptors, normally from
// a manifest
func descriptorSizes(desc []v1.Descriptor) int64 {
	var size int64
	for _, d := range desc {
		size += d.Size
	}
	return size
}

// replaceSha given the string URI for a docker image, replace the sha with the provided
// digest. If the URL does not have a digest, it appends it
func replaceSha(ref string, digest v1.Hash) string {
	// parse the ref
	repo := ref
	parts := strings.Split(ref, "@")
	if len(parts) >= 2 {
		repo = parts[0]
	}
	return fmt.Sprintf("%s@%s", repo, digest.String())
}

// errorCatcherReader io.Reader implementation that wraps a normal io.Reader,
// while returning all errors except for io.EOF, which is treated as no error.
// Useful for things that expect an io.Reader but cannot handle an io.EOF normally.
type errorCatcherReader struct {
	r       io.Reader
	ioError bool
}

func (e *errorCatcherReader) Read(p []byte) (n int, err error) {
	n, err = e.r.Read(p)
	// if it was no error or EOF, just return it
	if err == nil || err == io.EOF {
		return n, err
	}
	// it was some other kind of error, so capture it
	e.ioError = true
	return n, err
}
