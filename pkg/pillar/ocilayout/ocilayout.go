// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ocilayout reads a single image out of an OCI image-layout tar
// archive without unpacking the archive to disk.
package ocilayout

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	layoutFile = "oci-layout"
	indexFile  = "index.json"
	blobPrefix = "blobs/sha256/"

	// maxEntries and maxHeaderBytes bound the header walk over a hostile
	// archive: entry data is seeked over, but tar.Reader reads any number of
	// extended headers ahead of an entry.
	maxEntries     = 4096
	maxHeaderBytes = 16 << 20
	// maxLayoutSize bounds the oci-layout entry.
	maxLayoutSize = 4096
	// maxManifests bounds the manifests collected from the indexes.
	maxManifests = 64
	// maxJSONSize bounds every index, manifest and config read into memory.
	maxJSONSize = 4 << 20

	tarMagicOffset = 257
	tarMagic       = "ustar"

	mediaTypeDockerManifest     = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
)

// ErrNotLayout is returned by Open for a file that is not an OCI image-layout
// tar archive.
var ErrNotLayout = errors.New("not an OCI image-layout tar archive")

type entry struct {
	offset int64
	size   int64
}

// Archive is an open OCI image-layout tar archive.
type Archive struct {
	f       *os.File
	entries map[string]entry
}

// Image describes the one image an archive holds.
type Image struct {
	// Manifest is the descriptor of the image manifest and ManifestRaw its
	// content.
	Manifest    ocispec.Descriptor
	ManifestRaw []byte
	Config      ocispec.Descriptor
	Layers      []ocispec.Descriptor
}

// IsLayoutTar reports whether file is an OCI image-layout tar archive. The
// error is that of Open, other than ErrNotLayout.
func IsLayoutTar(file string) (bool, error) {
	a, err := Open(file)
	if errors.Is(err, ErrNotLayout) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	a.Close()
	return true, nil
}

// Open indexes the entries of the archive in file, reading the tar headers
// and the oci-layout entry. It returns ErrNotLayout if file is not a tar
// archive holding an OCI image layout. Any other error means that the file
// could not be read, or that it is such an archive and is damaged or over
// the limits; the caller must then not use the file as anything else.
func Open(file string) (*Archive, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	a := &Archive{f: f, entries: map[string]entry{}}
	if err := a.index(); err != nil {
		f.Close()
		return nil, err
	}
	return a, nil
}

// Close releases the archive file.
func (a *Archive) Close() error {
	return a.f.Close()
}

// headerReader limits the bytes read from f, as opposed to seeked over.
type headerReader struct {
	f    *os.File
	left int64
}

func (r *headerReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errors.New("too much tar metadata")
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, err := r.f.Read(p)
	r.left -= int64(n)
	return n, err
}

func (r *headerReader) Seek(offset int64, whence int) (int64, error) {
	return r.f.Seek(offset, whence)
}

func (a *Archive) index() error {
	magic := make([]byte, len(tarMagic))
	if _, err := a.f.ReadAt(magic, tarMagicOffset); err != nil && err != io.EOF {
		return err
	}
	if string(magic) != tarMagic {
		return ErrNotLayout
	}
	// Once an entry of a layout was seen, a failure is an error of its own:
	// the file is then no artifact to be used as it is.
	isLayout := false
	fail := func(err error) error {
		if isLayout {
			return fmt.Errorf("damaged OCI image-layout archive: %w", err)
		}
		return fmt.Errorf("%w: %v", ErrNotLayout, err)
	}
	// tar.Reader reads headers unbuffered and seeks over entry data, so after
	// Next the file offset is where the entry's data starts.
	tr := tar.NewReader(&headerReader{f: a.f, left: maxHeaderBytes})
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
		if n >= maxEntries {
			return fail(fmt.Errorf("more than %d entries", maxEntries))
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(hdr.Name)
		if name == layoutFile || strings.HasPrefix(name, blobPrefix) {
			isLayout = true
		}
		for k := range hdr.PAXRecords {
			// the data of a sparse entry is not its content
			if strings.HasPrefix(k, "GNU.sparse.") {
				return fail(fmt.Errorf("sparse entry %s", hdr.Name))
			}
		}
		offset, err := a.f.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		a.entries[name] = entry{offset: offset, size: hdr.Size}
	}
	e, ok := a.entries[layoutFile]
	if !ok || e.size > maxLayoutSize {
		return ErrNotLayout
	}
	data, err := io.ReadAll(io.NewSectionReader(a.f, e.offset, e.size))
	if err != nil {
		return err
	}
	var layout ocispec.ImageLayout
	if json.Unmarshal(data, &layout) != nil || layout.Version == "" {
		return ErrNotLayout
	}
	if _, ok := a.entries[indexFile]; !ok {
		return fmt.Errorf("damaged OCI image-layout archive: no %s", indexFile)
	}
	return nil
}

// Blob returns a reader over the content of the blob desc refers to. The
// content is not verified against the digest; that is left to whoever
// consumes it.
func (a *Archive) Blob(desc ocispec.Descriptor) (io.Reader, error) {
	// Validate first: Algorithm panics on a digest without a separator.
	if desc.Digest.Validate() != nil || desc.Digest.Algorithm() != digest.SHA256 {
		return nil, fmt.Errorf("unsupported digest %q", desc.Digest)
	}
	e, ok := a.entries[blobPrefix+desc.Digest.Encoded()]
	if !ok {
		return nil, fmt.Errorf("blob %s is not in the archive", desc.Digest)
	}
	if e.size != desc.Size {
		return nil, fmt.Errorf("blob %s is %d bytes, descriptor says %d",
			desc.Digest, e.size, desc.Size)
	}
	return io.NewSectionReader(a.f, e.offset, e.size), nil
}

// readJSON reads a blob into memory and verifies its digest.
func (a *Archive) readJSON(desc ocispec.Descriptor) ([]byte, error) {
	if desc.Size > maxJSONSize {
		return nil, fmt.Errorf("blob %s is too large to parse: %d bytes", desc.Digest, desc.Size)
	}
	r, err := a.Blob(desc)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if got := digest.FromBytes(data); got != desc.Digest {
		return nil, fmt.Errorf("blob %s has digest %s", desc.Digest, got)
	}
	return data, nil
}

func isIndex(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageIndex || mediaType == mediaTypeDockerManifestList
}

func isManifest(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageManifest || mediaType == mediaTypeDockerManifest
}

// Image returns the single image for the linux/arch platform. Manifests for
// other platforms are skipped; one without a platform counts. An archive with
// no such image, or with more than one, is rejected. One level of nested
// index is followed, which is what buildx writes. Every blob of the image is
// in the archive under a sha256 digest.
func (a *Archive) Image(arch string) (*Image, error) {
	e := a.entries[indexFile]
	if e.size > maxJSONSize {
		return nil, fmt.Errorf("%s is too large: %d bytes", indexFile, e.size)
	}
	data, err := io.ReadAll(io.NewSectionReader(a.f, e.offset, e.size))
	if err != nil {
		return nil, err
	}
	var top ocispec.Index
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", indexFile, err)
	}

	var candidates []ocispec.Descriptor
	for _, d := range top.Manifests {
		switch {
		case isManifest(d.MediaType):
			candidates = append(candidates, d)
		case isIndex(d.MediaType):
			raw, err := a.readJSON(d)
			if err != nil {
				return nil, err
			}
			var nested ocispec.Index
			if err := json.Unmarshal(raw, &nested); err != nil {
				return nil, fmt.Errorf("parsing index %s: %w", d.Digest, err)
			}
			for _, nd := range nested.Manifests {
				if !isManifest(nd.MediaType) {
					return nil, fmt.Errorf("index %s nests %s", d.Digest, nd.MediaType)
				}
				candidates = append(candidates, nd)
			}
		default:
			return nil, fmt.Errorf("unsupported media type %q in %s", d.MediaType, indexFile)
		}
		if len(candidates) > maxManifests {
			return nil, fmt.Errorf("archive lists more than %d manifests", maxManifests)
		}
	}

	var matches []ocispec.Descriptor
	for _, d := range candidates {
		if p := d.Platform; p != nil && (p.OS != "linux" || p.Architecture != arch) {
			continue
		}
		matches = append(matches, d)
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("archive must hold exactly one image for linux/%s, found %d",
			arch, len(matches))
	}

	img := &Image{Manifest: matches[0]}
	if img.ManifestRaw, err = a.readJSON(img.Manifest); err != nil {
		return nil, err
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(img.ManifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", img.Manifest.Digest, err)
	}
	img.Config = manifest.Config
	img.Layers = manifest.Layers

	// A manifest listed without a platform still has one in its config.
	rawConfig, err := a.readJSON(img.Config)
	if err != nil {
		return nil, err
	}
	var config ocispec.Image
	if err := json.Unmarshal(rawConfig, &config); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", img.Config.Digest, err)
	}
	if config.Architecture != "" && config.Architecture != arch {
		return nil, fmt.Errorf("image is built for %s, not %s", config.Architecture, arch)
	}
	for _, l := range img.Layers {
		if _, err := a.Blob(l); err != nil {
			return nil, err
		}
	}
	return img, nil
}
