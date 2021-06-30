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

// DirTarget save the entire contents to a single directory.
type DirTarget struct {
	Dir string
}

// Ingester get the IngesterCloser
func (d DirTarget) Ingester() IngesterCloser {
	return content.NewFileStore(d.Dir)
}

// MultiWriter does this support multiwriter
func (d DirTarget) MultiWriter() bool {
	return false
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

// Ingester get the IngesterCloser
func (f *FilesTarget) Ingester() IngesterCloser {
	return f
}

// MultiWriter does this support multiwriter
func (f *FilesTarget) MultiWriter() bool {
	return true
}

// Close close anything that might be open
func (f *FilesTarget) Close() error {
	return nil
}

// Writer get a writer
func (f *FilesTarget) Writer(ctx context.Context, opts ...ctrcontent.WriterOpt) (ctrcontent.Writer, error) {
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
		if f.Kernel != nil {
			return content.NewIoContentWriter(f.Kernel, writerOpts...), nil
		}
	case RoleInitrd:
		if f.Initrd != nil {
			return content.NewIoContentWriter(f.Initrd, writerOpts...), nil
		}
	case RoleRootDisk:
		if f.Root != nil {
			return content.NewIoContentWriter(f.Root, writerOpts...), nil
		}
	case RoleAdditionalDisk:
	}

	return content.NewIoContentWriter(nil, writerOpts...), nil
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

func (f *FilesTarget) configIngestor() ctrcontent.Writer {
	return &configIngestor{target: f}
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
