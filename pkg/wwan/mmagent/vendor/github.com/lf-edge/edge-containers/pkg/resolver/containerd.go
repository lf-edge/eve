package resolver

/*
 Provides a github.com/containerd/containerd/remotes#Resolver that resolves
 to a containerd socket

*/

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/reference"
	"github.com/containerd/containerd/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	containerdGCRef = "containerd.io/gc.ref.content"
)

// Containerd resolver to push to/pull from containerd.
// Due to an inability to know when a pusher is complete,
// we complete here on the Containerd resolver, which means
// this should be used exactly once for Pusher, and then discarded,
// as finalize will be called.
// See https://github.com/deislabs/oras/issues/172
// When the above is fixed, we can do better with this.
type Containerd struct {
	client    *containerd.Client
	namespace string // we do not really need to keep this, as we consume it on NewContainer; just here for posterity
	pusher    *containerdPusher
	done      func(context.Context) error
	ctx       context.Context
}

// NewContainerd create a containerd ResolverFinalizer given the containerd address and namespace (optional)
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

// NewContainerdWithClient create a containerd ResolverFinalizer with an existing containerd client connection
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

func (d *Containerd) Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	if _, err := reference.Parse(ref); err != nil {
		return "", ocispec.Descriptor{}, err
	}

	// get our image
	is := d.client.ImageService()
	image, err := is.Get(ctx, ref)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}
	return ref, image.Target, nil
}

func (d Containerd) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	return containerdFetcher{ref, d.client.ContentStore()}, nil
}

func (d *Containerd) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	p := containerdPusher{ref, d.client}
	d.pusher = &p
	return p, nil
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

type containerdFetcher struct {
	ref string
	cs  content.Store
}

func (d containerdFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	reader, err := d.cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	return &containerdReader{
		reader: content.NewReader(reader),
	}, nil
}

type containerdReader struct {
	reader io.Reader
}

func (c *containerdReader) Close() error {
	return nil
}

func (c *containerdReader) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

type containerdPusher struct {
	ref    string
	client *containerd.Client
}

func (d containerdPusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	cs := d.client.ContentStore()
	writer, err := content.OpenWriter(ctx, cs, content.WithDescriptor(desc), content.WithRef(desc.Digest.String()))
	if err != nil {
		return nil, err
	}
	// if it is a manifest or index, we will cache the data
	var cache []byte
	switch desc.MediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest,
		images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		cache = make([]byte, 0)
	}
	return &containerdWriter{
		writer: writer,
		client: d.client,
		desc:   desc,
		ref:    d.ref,
		cache:  cache,
	}, nil
}

type containerdWriter struct {
	writer    content.Writer
	client    *containerd.Client
	ref       string
	desc      ocispec.Descriptor
	committed bool
	cache     []byte
}

// Digest may return empty digest or panics until committed.
func (c *containerdWriter) Digest() digest.Digest {
	return c.desc.Digest
}

func (c *containerdWriter) Close() error {
	return c.writer.Close()
}

// Commit commits the blob (but no roll-back is guaranteed on an error).
// size and expected can be zero-value when unknown.
// Commit always closes the writer, even on error.
// ErrAlreadyExists aborts the writer.
func (c *containerdWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	if c.committed {
		return nil
	}
	if err := c.writer.Commit(ctx, size, expected); err != nil {
		return err
	}
	// when we commit, we also need to write the image and the various parentage tags
	is := c.client.ImageService()

	switch c.desc.MediaType {
	case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest,
		images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
		existingImage, err := is.Get(ctx, c.ref)
		// TODO: should differentiate between communication error and image-not-there error
		if err != nil || existingImage.Target.Digest.String() == "" {
			image := images.Image{
				Name:      c.ref,
				Labels:    nil,
				Target:    c.desc,
				CreatedAt: time.Now(),
				UpdatedAt: time.Time{},
			}
			_, err = is.Create(ctx, image)
		} else {
			image := images.Image{
				Name:      c.ref,
				Labels:    nil,
				Target:    c.desc,
				UpdatedAt: time.Time{},
			}
			_, err = is.Update(ctx, image)
		}
		if err != nil {
			return err
		}
		// add GC prevention tags
		labels, err := getChildRefs(c.cache, c.desc.MediaType)
		if err != nil {
			return err
		}

		updatedFields := make([]string, 0)
		for k := range labels {
			updatedFields = append(updatedFields, fmt.Sprintf("labels.%s", k))
		}
		updatedContentInfo := content.Info{
			Digest: digest.Digest(c.desc.Digest),
			Labels: labels,
		}
		if _, err := c.client.ContentStore().Update(ctx, updatedContentInfo, updatedFields...); err != nil {
			return err
		}
	}
	c.committed = true
	// clear the cache
	c.cache = nil
	return nil
}

// Status returns the current state of write
func (c *containerdWriter) Status() (content.Status, error) {
	return c.writer.Status()
}

func (c *containerdWriter) Truncate(size int64) error {
	return c.writer.Truncate(size)
}
func (c *containerdWriter) Write(p []byte) (n int, err error) {
	if c.cache != nil {
		c.cache = append(c.cache, p...)
	}
	return c.writer.Write(p)
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
