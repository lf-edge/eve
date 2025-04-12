package resolver

/*
 Provides a github.com/containerd/containerd/remotes#Resolver that resolves
 to a local filesystem directory.

 The format in the directory is the OCI spec for an image layout,
 at https://github.com/opencontainers/image-spec/blob/master/image-layout.md

 The image reference name is stored in the root index.json, with the image name stored
 as the annotation for image name, i.e. org.opencontainers.image.ref.name

 The spec for annotations is available https://github.com/opencontainers/image-spec/blob/master/annotations.md
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Directory struct {
	dir string
	ctx context.Context
}

func NewDirectory(ctx context.Context, dir string) (context.Context, *Directory, error) {
	// make sure it exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ctx, nil, fmt.Errorf("could not create directory %s: %v", dir, err)
	}
	return ctx, &Directory{dir: dir, ctx: ctx}, nil
}

func (d *Directory) Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	refspec, err := reference.Parse(ref)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}

	if refspec.Object == "" {
		return "", ocispec.Descriptor{}, reference.ErrObjectRequired
	}

	// get the root manifest
	// try to get it from the image reference file
	indexFile := path.Join(d.dir, "index.json")
	contents, err := ioutil.ReadFile(indexFile)
	if err != nil {
		return "", ocispec.Descriptor{}, reference.ErrInvalid
	}
	var rootDesc ocispec.Index
	if err := json.Unmarshal(contents, &rootDesc); err != nil {
		return "", ocispec.Descriptor{}, fmt.Errorf("could not convert manifest description to json: %v", err)
	}
	if len(rootDesc.Manifests) < 1 {
		return "", ocispec.Descriptor{}, fmt.Errorf("index %s did not have any manifests", indexFile)
	}

	return ref, rootDesc.Manifests[0], nil
}

func (d Directory) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	return directoryFetcher{ref, d.dir}, nil
}

func (d *Directory) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	return directoryPusher{ref, d.dir}, nil
}

func (d *Directory) Finalize(ctx context.Context) error {
	return nil
}

func (d *Directory) Context() context.Context {
	return d.ctx
}

type directoryFetcher struct {
	ref string
	dir string
}

type directoryPusher struct {
	ref string
	dir string
}

type rcWrapper struct {
	rc   io.ReadCloser
	desc ocispec.Descriptor
}

func (r rcWrapper) Close() error {
	return r.rc.Close()
}
func (r rcWrapper) Read(b []byte) (int, error) {
	return r.rc.Read(b)
}

func (d directoryFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	blobsDir := path.Join(d.dir, "blobs", desc.Digest.Algorithm().String())
	filename := path.Join(blobsDir, desc.Digest.Hex())
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open for reading %s: %v", filename, err)
	}
	return &rcWrapper{rc: file, desc: desc}, nil
}

func (d directoryPusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	blobsDir := path.Join(d.dir, "blobs", desc.Digest.Algorithm().String())
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return nil, fmt.Errorf("could not create directory %s: %v", blobsDir, err)
	}
	filename := path.Join(blobsDir, desc.Digest.Hex())
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("could not create for writing %s: %v", filename, err)
	}
	var isManifest bool
	switch desc.MediaType {
	case images.MediaTypeDockerSchema2Manifest, images.MediaTypeDockerSchema2ManifestList,
		ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex:
		isManifest = true
	}

	return directoryWriter{
		file:       file,
		desc:       desc,
		isManifest: isManifest,
		ref:        d.ref,
		indexFile:  path.Join(d.dir, "index.json"),
	}, nil
}

type directoryWriter struct {
	file       *os.File
	ref        string
	isManifest bool
	desc       ocispec.Descriptor
	committed  bool
	start      time.Time
	updated    time.Time
	total      int64
	indexFile  string
}

// Digest may return empty digest or panics until committed.
func (d directoryWriter) Digest() digest.Digest {
	return d.desc.Digest
}

func (d directoryWriter) Close() error {
	return d.file.Close()
}

func (d directoryWriter) Write(p []byte) (n int, err error) {
	n, err = d.file.Write(p)
	d.total += int64(n) //nolint:staticcheck
	return n, err
}

// Commit commits the blob (but no roll-back is guaranteed on an error).
// size and expected can be zero-value when unknown.
// Commit always closes the writer, even on error.
// ErrAlreadyExists aborts the writer.
func (d directoryWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	if d.committed {
		return nil
	}
	if err := d.Close(); err != nil {
		return err
	}
	// when we commit, we also need to write the image file
	if d.isManifest {
		// ensure that the name annotation exists
		if d.desc.Annotations == nil {
			d.desc.Annotations = map[string]string{}
		}
		if value, ok := d.desc.Annotations[ocispec.AnnotationRefName]; !ok || value == "" {
			d.desc.Annotations[ocispec.AnnotationRefName] = d.ref
		}
		// convert the manifest to json bytes and write it to the index.json
		index := ocispec.Index{
			Manifests: []ocispec.Descriptor{
				d.desc,
			},
		}
		b, err := json.Marshal(index)
		if err != nil {
			return fmt.Errorf("could not convert index to json: %v", err)
		}
		if err := ioutil.WriteFile(d.indexFile, b, 0644); err != nil {
			return fmt.Errorf("error writing index file %s: %v", d.indexFile, err)
		}
	}
	return nil
}

// Status returns the current state of write
func (d directoryWriter) Status() (content.Status, error) {
	status := content.Status{
		Ref:       d.ref,
		Offset:    d.total,
		Total:     d.total,
		Expected:  d.Digest(),
		StartedAt: d.start,
		UpdatedAt: d.updated,
	}
	return status, nil
}

// Truncate updates the size of the target blob
func (d directoryWriter) Truncate(size int64) error {
	return fmt.Errorf("unsupported")
}
