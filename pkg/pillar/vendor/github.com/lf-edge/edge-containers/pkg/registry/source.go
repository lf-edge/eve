package registry

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
)

// artifactSource is the read-only store an artifact is copied out of. A blob is
// either a file on disk or bytes held in memory, so a multi-gigabyte disk image
// streams from where it already lives instead of being buffered.
type artifactSource struct {
	ref      string
	manifest ocispec.Descriptor
	files    map[digest.Digest]string
	blobs    map[digest.Digest][]byte
}

func newArtifactSource(ref string) *artifactSource {
	return &artifactSource{
		ref:   ref,
		files: map[digest.Digest]string{},
		blobs: map[digest.Digest][]byte{},
	}
}

// addFile record the file at path as a blob, digesting it where it lies.
func (s *artifactSource) addFile(name, mediaType, path string) (ocispec.Descriptor, error) {
	f, err := os.Open(path)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	defer func() { _ = f.Close() }()
	digester := digest.Canonical.Digester()
	size, err := io.Copy(digester.Hash(), f)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	dgst := digester.Digest()
	s.files[dgst] = path
	return descriptorFor(name, mediaType, dgst, size), nil
}

// addBytes record b as a blob.
func (s *artifactSource) addBytes(name, mediaType string, b []byte) (ocispec.Descriptor, error) {
	dgst := digest.FromBytes(b)
	s.blobs[dgst] = b
	return descriptorFor(name, mediaType, dgst, int64(len(b))), nil
}

// setManifest record the manifest bytes and make them what the reference resolves to.
func (s *artifactSource) setManifest(desc ocispec.Descriptor, b []byte) {
	s.blobs[desc.Digest] = b
	s.manifest = desc
}

func descriptorFor(name, mediaType string, dgst digest.Digest, size int64) ocispec.Descriptor {
	annotations := map[string]string{}
	if name != "" {
		annotations[ocispec.AnnotationTitle] = name
	}
	return ocispec.Descriptor{
		MediaType:   mediaType,
		Digest:      dgst,
		Size:        size,
		Annotations: annotations,
	}
}

func (s *artifactSource) Fetch(_ context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	if b, ok := s.blobs[target.Digest]; ok {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	if path, ok := s.files[target.Digest]; ok {
		return os.Open(path)
	}
	return nil, fmt.Errorf("%s: %w", target.Digest, errdef.ErrNotFound)
}

func (s *artifactSource) Exists(_ context.Context, target ocispec.Descriptor) (bool, error) {
	if _, ok := s.blobs[target.Digest]; ok {
		return true, nil
	}
	_, ok := s.files[target.Digest]
	return ok, nil
}

// Resolve the artifact is stored under exactly one reference, the one it was built for.
func (s *artifactSource) Resolve(_ context.Context, ref string) (ocispec.Descriptor, error) {
	if s.manifest.Digest == "" {
		return ocispec.Descriptor{}, fmt.Errorf("no manifest stored: %w", errdef.ErrNotFound)
	}
	if ref != s.ref && ref != s.manifest.Digest.String() {
		return ocispec.Descriptor{}, fmt.Errorf("%s: %w", ref, errdef.ErrNotFound)
	}
	return s.manifest, nil
}
