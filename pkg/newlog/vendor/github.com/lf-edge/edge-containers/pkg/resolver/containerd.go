package resolver

/*
 Provides an oras target backed by a containerd content store and image service.

*/

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
)

const (
	containerdGCRef = "containerd.io/gc.ref.content"
)

// Containerd resolver to push to/pull from containerd. Finalize releases the
// lease taken when the resolver was created, so a Containerd is good for one
// unit of work and should be discarded afterwards.
type Containerd struct {
	client    *containerd.Client
	namespace string // we do not really need to keep this, as we consume it on NewContainer; just here for posterity
	done      func(context.Context) error
	ctx       context.Context
}

// NewContainerd create a containerd resolver given the containerd address and namespace (optional)
func NewContainerd(ctx context.Context, address, namespace string) (context.Context, *Containerd, error) {
	client, err := containerd.New(address)
	if err != nil {
		return nil, nil, err
	}
	if namespace == "" {
		namespace = "default"
	}
	ctx, done, err := client.WithLease(namespaces.WithNamespace(ctx, namespace))
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get lease: %v", err)
	}
	return ctx, &Containerd{client: client, ctx: ctx, namespace: namespace, done: done}, nil
}

// NewContainerdWithClient create a containerd resolver with an existing containerd client connection
func NewContainerdWithClient(ctx context.Context, client *containerd.Client) (context.Context, *Containerd, error) {
	if client == nil {
		return nil, nil, errors.New("no containerd client provided")
	}
	ctx, done, err := client.WithLease(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get lease: %v", err)
	}
	return ctx, &Containerd{client: client, ctx: ctx, done: done}, nil
}

// Target returns the containerd store, which serves every reference it holds.
func (d *Containerd) Target(_ context.Context, _ string) (oras.Target, error) {
	return d, nil
}

func (d *Containerd) Finalize(ctx context.Context) error {
	if d.done != nil {
		_ = d.done(ctx)
	}
	return nil
}

func (d *Containerd) Context() context.Context {
	return d.ctx
}

// Resolve look up the image by reference and return the descriptor it points at.
func (d *Containerd) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	if _, err := reference.Parse(ref); err != nil {
		return ocispec.Descriptor{}, err
	}
	image, err := d.client.ImageService().Get(ctx, ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return image.Target, nil
}

// Tag point the given reference at desc, creating the image if it is not there yet.
func (d *Containerd) Tag(ctx context.Context, desc ocispec.Descriptor, ref string) error {
	is := d.client.ImageService()
	existing, err := is.Get(ctx, ref)
	// TODO: should differentiate between communication error and image-not-there error
	if err != nil || existing.Target.Digest.String() == "" {
		_, err = is.Create(ctx, images.Image{
			Name:      ref,
			Target:    desc,
			CreatedAt: time.Now(),
		})
		return err
	}
	_, err = is.Update(ctx, images.Image{
		Name:   ref,
		Target: desc,
	})
	return err
}

// Fetch return a reader for the content named by desc.
func (d *Containerd) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	readerAt, err := d.client.ContentStore().ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	return &containerdReader{readerAt: readerAt, reader: content.NewReader(readerAt)}, nil
}

// Exists report whether the content named by desc is already in the store.
func (d *Containerd) Exists(ctx context.Context, desc ocispec.Descriptor) (bool, error) {
	_, err := d.client.ContentStore().Info(ctx, desc.Digest)
	if err == nil {
		return true, nil
	}
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// Push write the content to the store. A manifest or index is also given the
// containerd GC labels that keep its children from being collected; without them
// containerd is free to remove blobs this manifest still references.
func (d *Containerd) Push(ctx context.Context, expected ocispec.Descriptor, r io.Reader) error {
	cs := d.client.ContentStore()
	writer, err := content.OpenWriter(ctx, cs, content.WithDescriptor(expected), content.WithRef(expected.Digest.String()))
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	defer func() { _ = writer.Close() }()

	// a manifest or index has to be read back to find its children, and is small
	// enough to keep while it streams past
	var cache *bytes.Buffer
	if isManifest(expected.MediaType) {
		cache = &bytes.Buffer{}
		r = io.TeeReader(r, cache)
	}

	if _, err := io.Copy(writer, r); err != nil {
		return err
	}
	if err := writer.Commit(ctx, expected.Size, expected.Digest); err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	if cache == nil {
		return nil
	}

	labels, err := getChildRefs(cache.Bytes(), expected.MediaType)
	if err != nil {
		return err
	}
	updatedFields := make([]string, 0, len(labels))
	for k := range labels {
		updatedFields = append(updatedFields, fmt.Sprintf("labels.%s", k))
	}
	if len(updatedFields) == 0 {
		return nil
	}
	_, err = cs.Update(ctx, content.Info{Digest: expected.Digest, Labels: labels}, updatedFields...)
	return err
}

func isManifest(mediaType string) bool {
	switch mediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest,
		images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		return true
	}
	return false
}

type containerdReader struct {
	readerAt content.ReaderAt
	reader   io.Reader
}

func (c *containerdReader) Close() error {
	return c.readerAt.Close()
}

func (c *containerdReader) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func getChildRefs(b []byte, mediaType string) (labels map[string]string, err error) {
	switch mediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
		var manifest ocispec.Manifest
		if err := json.Unmarshal(b, &manifest); err != nil {
			return nil, fmt.Errorf("did not have valid manifest: %v", err)
		}
		labels = map[string]string{}
		for i, l := range manifest.Layers {
			labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = l.Digest.String()
		}
		labels[fmt.Sprintf("%s.%d", containerdGCRef, len(manifest.Layers))] = manifest.Config.Digest.String()
	case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		var index ocispec.Index
		if err := json.Unmarshal(b, &index); err != nil {
			return nil, fmt.Errorf("did not have valid index: %v", err)
		}
		labels = map[string]string{}
		for i, l := range index.Manifests {
			labels[fmt.Sprintf("%s.%d", containerdGCRef, i)] = l.Digest.String()
		}
	}
	return labels, err
}
