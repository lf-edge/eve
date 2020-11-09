package registry

import (
	"context"
	"io"

	ctrcontent "github.com/containerd/containerd/content"
	"github.com/deislabs/oras/pkg/content"
)

// IngesterCloser an ingester that also has a Close(). May return nil
type IngesterCloser interface {
	ctrcontent.Ingester
	io.Closer
}

// Target a target where to send the contents of the artifact
type Target interface {
	Ingester() IngesterCloser
}

// DirTarget save the entire contents to a single directory.
type DirTarget struct {
	Dir string
}

// Ingester get the IngesterCloser
func (d DirTarget) Ingester() IngesterCloser {
	return content.NewFileStore(d.Dir)
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
}

// Ingester get the IngesterCloser
func (f FilesTarget) Ingester() IngesterCloser {
	return f
}

// Close close anything that might be open
func (f FilesTarget) Close() error {
	return nil
}

// Writer get a writer
func (w FilesTarget) Writer(ctx context.Context, opts ...ctrcontent.WriterOpt) (ctrcontent.Writer, error) {
	// we have to reprocess the opts to find the desc
	var wOpts ctrcontent.WriterOpts
	for _, opt := range opts {
		if err := opt(&wOpts); err != nil {
			return nil, err
		}
	}
	desc := wOpts.Desc

	writerOpts := []content.WriterOpt{}
	if w.BlockSize > 0 {
		writerOpts = append(writerOpts, content.WithBlocksize(w.BlockSize))
	}
	if w.AcceptHash {
		writerOpts = append(writerOpts, content.WithInputHash(desc.Digest))
		writerOpts = append(writerOpts, content.WithOutputHash(desc.Digest))
	}
	// check if it meets the requirements
	switch desc.Annotations[AnnotationRole] {
	case RoleKernel:
		if w.Kernel != nil {
			return content.NewIoContentWriter(w.Kernel, writerOpts...), nil
		}
	case RoleInitrd:
		if w.Initrd != nil {
			return content.NewIoContentWriter(w.Initrd, writerOpts...), nil
		}
	case RoleRootDisk:
		if w.Root != nil {
			return content.NewIoContentWriter(w.Root, writerOpts...), nil
		}
	case RoleAdditionalDisk:
	}
	// nothing, so return something that dumps to /var/null
	return content.NewIoContentWriter(nil, writerOpts...), nil
}
