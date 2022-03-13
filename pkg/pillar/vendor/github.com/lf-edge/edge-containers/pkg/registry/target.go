package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/containerd/containerd/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/pkg/content"
)

// IngesterCloser an ingester that also has a Close(). May return nil
type IngesterCloser interface {
	ctrcontent.Ingester
	io.Closer
}

// Target a target where to send the contents of the artifact. May also
// handle processing config.
type Target interface {
	Ingester() IngesterCloser
	MultiWriter() bool
}

// FilesTarget provides targets for each file type. If a type is nil,
// its content is ignored
type FilesTarget struct {
	// Kernel writer where to write the kernel
	Kernel io.Writer
	// Initrd writer where to write the initrd
	Initrd io.Writer
	// Config writer where to write the config
	Config io.Writer
	// Root writer where to write the root disk
	Root io.Writer
	// Disks writers where to write each additional disk
	Disks []io.Writer
	// Other writer where to write the other elements
	Other []io.Writer
	// BlockSize how big a blocksize to use when reading/writing. Defaults to whatever io.Copy uses
	BlockSize int
	// AcceptHash if set to true, accept the hash in the descriptor as is, i.e. do not recalculate it
	AcceptHash bool
	// config stores the config annotations, if they exist
	config map[string]string
	// pathWriters store the reverse, from a path to the target writer, used for quick lookups
	pathWriters map[string]io.Writer
}

// Resolver get a resolver for content
func (f *FilesTarget) Resolver() remotes.Resolver {
	return f
}

// Resolve resolve a specific reference, currently unsupported
func (f *FilesTarget) Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	return "", ocispec.Descriptor{}, fmt.Errorf("unsupported")
}

// Fetcher fetch the content for a specific ref
func (f *FilesTarget) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	return nil, fmt.Errorf("unsupported")
}

// Fetch get an io.ReadCloser for the specific content
func (f *FilesTarget) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	return nil, fmt.Errorf("unsupported")
}

// Ingester get the IngesterCloser
func (f *FilesTarget) Ingester() IngesterCloser {
	return f
}

// Close close anything that might be open
func (f *FilesTarget) Close() error {
	return nil
}

// Pusher get a pusher to push content
func (f *FilesTarget) Pusher(ctx context.Context, ref string) (remotes.Pusher, error) {
	var tag, hash string
	parts := strings.SplitN(ref, "@", 2)
	if len(parts) > 0 {
		tag = parts[0]
	}
	if len(parts) > 1 {
		hash = parts[1]
	}
	pusher := &filesPusher{
		target: f,
		ref:    tag,
		hash:   hash,
	}
	return content.NewDecompress(pusher, content.WithMultiWriterIngester()), nil
}

func (f *FilesTarget) Writer(ctx context.Context, opts ...ctrcontent.WriterOpt) (ctrcontent.Writer, error) {
	// we have to reprocess the opts to find the desc
	var wOpts ctrcontent.WriterOpts
	for _, opt := range opts {
		if err := opt(&wOpts); err != nil {
			return nil, err
		}
	}
	desc := wOpts.Desc

	p := &filesPusher{
		target: f,
	}
	return p.Push(ctx, desc)
}

// Writers get writers by filename
func (f *FilesTarget) Writers(ctx context.Context, opts ...ctrcontent.WriterOpt) (func(name string) (ctrcontent.Writer, error), error) {
	// we have to reprocess the opts to find the desc
	var wOpts ctrcontent.WriterOpts
	for _, opt := range opts {
		if err := opt(&wOpts); err != nil {
			return nil, err
		}
	}
	desc := wOpts.Desc

	writerOpts := []content.WriterOpt{}
	if f.BlockSize > 0 {
		writerOpts = append(writerOpts, content.WithBlocksize(f.BlockSize))
	}
	if f.AcceptHash {
		writerOpts = append(writerOpts, content.WithInputHash(desc.Digest))
		writerOpts = append(writerOpts, content.WithOutputHash(desc.Digest))
	}
	return func(name string) (ctrcontent.Writer, error) {
		if f.pathWriters == nil {
			return nil, nil
		}
		if w, ok := f.pathWriters[name]; ok {
			return content.NewIoContentWriter(w, writerOpts...), nil
		}

		return nil, nil
	}, nil
}

type filesPusher struct {
	target *FilesTarget
	ref    string
	hash   string
}

func (f *filesPusher) Push(ctx context.Context, desc ocispec.Descriptor) (ctrcontent.Writer, error) {
	writerOpts := []content.WriterOpt{}
	if f.target.BlockSize > 0 {
		writerOpts = append(writerOpts, content.WithBlocksize(f.target.BlockSize))
	}
	if f.target.AcceptHash {
		writerOpts = append(writerOpts, content.WithInputHash(desc.Digest))
		writerOpts = append(writerOpts, content.WithOutputHash(desc.Digest))
	}

	// save any config
	// because the config always is pulled first, this should work. But it depends on this remaining the same:
	// https://github.com/containerd/containerd/blob/178e9a10121b344aece9fe918f6fc4dc4dbde9a3/images/image.go#L346-L347
	if IsConfigType(desc.MediaType) {
		// process the config, looking for annotations
		return f.configIngestor(), nil
	}

	// check if it meets the requirements
	switch desc.Annotations[AnnotationRole] {
	case RoleKernel:
		if f.target.Kernel != nil {
			return content.NewIoContentWriter(f.target.Kernel, writerOpts...), nil
		}
	case RoleInitrd:
		if f.target.Initrd != nil {
			return content.NewIoContentWriter(f.target.Initrd, writerOpts...), nil
		}
	case RoleRootDisk:
		if f.target.Root != nil {
			return content.NewIoContentWriter(f.target.Root, writerOpts...), nil
		}
	case RoleAdditionalDisk:
	}

	//return content.NewIoContentWriter(nil, writerOpts...), nil
	return content.NewIoContentWriter(nil, writerOpts...), nil
}

func (f *filesPusher) Pushers(ctx context.Context, desc ocispec.Descriptor) (func(name string) (ctrcontent.Writer, error), error) {
	writerOpts := []content.WriterOpt{}
	if f.target.BlockSize > 0 {
		writerOpts = append(writerOpts, content.WithBlocksize(f.target.BlockSize))
	}
	if f.target.AcceptHash {
		writerOpts = append(writerOpts, content.WithInputHash(desc.Digest))
		writerOpts = append(writerOpts, content.WithOutputHash(desc.Digest))
	}
	return func(name string) (ctrcontent.Writer, error) {
		if f.target.pathWriters == nil {
			return nil, nil
		}
		if w, ok := f.target.pathWriters[name]; ok {
			return content.NewIoContentWriter(w, writerOpts...), nil
		}

		return nil, nil
	}, nil
}

func (f *filesPusher) configIngestor() ctrcontent.Writer {
	return &configIngestor{target: f.target}
}

type configIngestor struct {
	target    *FilesTarget
	ref       string
	content   []byte
	start     time.Time
	updated   time.Time
	committed bool
}

func (c *configIngestor) Digest() digest.Digest {
	return digest.FromBytes(c.content)
}
func (c *configIngestor) Status() (ctrcontent.Status, error) {
	return ctrcontent.Status{
		Ref:       c.ref,
		Offset:    0,
		Total:     int64(len(c.content)),
		Expected:  c.Digest(),
		StartedAt: c.start,
		UpdatedAt: c.updated,
	}, nil
}
func (c *configIngestor) Truncate(size int64) error {
	if len(c.content) > int(size) {
		c.content = c.content[:size]
	}
	return nil
}
func (c *configIngestor) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...ctrcontent.Opt) error {
	if c.committed {
		return nil
	}
	if err := c.Close(); err != nil {
		return err
	}
	image := ocispec.Image{}
	if err := json.Unmarshal(c.content, &image); err != nil {
		return fmt.Errorf("could not convert image config from json: %v", err)
	}
	c.target.config = image.Config.Labels
	c.target.pathWriters = map[string]io.Writer{}

	// pattern to use to check for other disks
	disksPattern := strings.ReplaceAll(AnnotationDiskIndexPathPattern, "%d", `([\d]+)`)
	// we are ignoring errors for now, as that should never happen
	re, _ := regexp.Compile(disksPattern)

	for annotation, value := range c.target.config {
		// ignore absolute oaths, because tar does
		if value == "" {
			continue
		}
		if value[0] == '/' {
			value = value[1:]
		}
		switch {
		case annotation == AnnotationKernelPath && c.target.Kernel != nil:
			c.target.pathWriters[value] = c.target.Kernel
		case annotation == AnnotationInitrdPath && c.target.Initrd != nil:
			c.target.pathWriters[value] = c.target.Initrd
		case annotation == AnnotationRootPath && c.target.Root != nil:
			c.target.pathWriters[value] = c.target.Root
		default:
			// didn't find it yet
			matches := re.FindStringSubmatch(annotation)
			if len(matches) < 2 {
				continue
			}
			index, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}
			if len(c.target.Disks) > index && c.target.Disks[index] != nil {
				c.target.pathWriters[value] = c.target.Disks[index]
			}
		}
	}

	return nil
}

func (c *configIngestor) Close() error {
	return nil
}

func (c *configIngestor) Write(p []byte) (n int, err error) {
	c.content = append(c.content, p...)
	return len(p), nil
}
