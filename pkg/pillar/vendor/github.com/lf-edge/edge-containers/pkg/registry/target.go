package registry

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// DefaultBlockSize size of each slice of bytes read in each write through in gunzip and untar.
const DefaultBlockSize = 32768

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
	// BlockSize how big a blocksize to use when reading/writing. Defaults to DefaultBlockSize
	BlockSize int
	// AcceptHash if set to true, accept the hash in the descriptor as is, i.e. do not recalculate it
	AcceptHash bool
	// mu guards the fields below, which one part of the artifact fills in and the
	// rest read. A copy is pushed concurrently with the layers it describes.
	mu sync.Mutex
	// configLoaded whether the config has already been read
	configLoaded bool
	// config stores the config annotations, if they exist
	config map[string]string
	// pathWriters store the reverse, from a path to the target writer, used for quick lookups
	pathWriters map[string]io.Writer
}

// Exists always reports false, so that every part of the artifact is offered to Push.
func (f *FilesTarget) Exists(_ context.Context, _ ocispec.Descriptor) (bool, error) {
	return false, nil
}

// Fetch is unsupported: a FilesTarget is written to, never read from.
func (f *FilesTarget) Fetch(_ context.Context, _ ocispec.Descriptor) (io.ReadCloser, error) {
	return nil, fmt.Errorf("unsupported")
}

// Resolve is unsupported: a FilesTarget holds no references.
func (f *FilesTarget) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, fmt.Errorf("unsupported")
}

// Tag discards the reference, as the files written carry no name of their own.
func (f *FilesTarget) Tag(_ context.Context, _ ocispec.Descriptor, _ string) error {
	return nil
}

// Push route one part of the artifact to the writer that wants it. The config is
// consumed here rather than written out: its labels name the file paths inside
// legacy layers, which is what lets those layers be split across writers.
func (f *FilesTarget) Push(_ context.Context, desc ocispec.Descriptor, r io.Reader) error {
	if IsConfigType(desc.MediaType) {
		return f.ingestConfig(desc, r)
	}
	gzipped, tarred := layerEncoding(desc.MediaType)
	switch {
	case tarred:
		return f.untar(desc, gzipped, r)
	case gzipped:
		return f.gunzipTo(f.writerForRole(desc.Annotations[AnnotationRole]), desc, r)
	default:
		return f.copyTo(f.writerForRole(desc.Annotations[AnnotationRole]), desc, r)
	}
}

// writerForRole the writer that takes a whole layer of the given role. An
// additional disk has no writer here; in the legacy format it is reached by path
// through pathWriters instead.
func (f *FilesTarget) writerForRole(role string) io.Writer {
	switch role {
	case RoleKernel:
		return f.Kernel
	case RoleInitrd:
		return f.Initrd
	case RoleRootDisk:
		return f.Root
	}
	return nil
}

// copyTo stream the content to w, discarding it if there is no writer for it.
func (f *FilesTarget) copyTo(w io.Writer, desc ocispec.Descriptor, r io.Reader) error {
	if w == nil {
		w = io.Discard
	}
	verified, verify := f.verifier(desc, r)
	if _, err := io.CopyBuffer(w, verified, f.buffer()); err != nil {
		return err
	}
	return verify()
}

// gunzipTo stream the decompressed content to w, discarding it if there is no
// writer for it.
func (f *FilesTarget) gunzipTo(w io.Writer, desc ocispec.Descriptor, r io.Reader) error {
	if w == nil {
		w = io.Discard
	}
	verified, verify := f.verifier(desc, r)
	gz, err := gzip.NewReader(verified)
	if err != nil {
		return fmt.Errorf("could not read layer %s as gzip: %v", desc.Digest, err)
	}
	defer func() { _ = gz.Close() }()
	buf := f.buffer()
	if _, err := io.CopyBuffer(w, gz, buf); err != nil {
		return err
	}
	// the descriptor covers the compressed blob, so the gzip trailer has to be
	// read before the digest can be checked
	if _, err := io.CopyBuffer(io.Discard, verified, buf); err != nil {
		return err
	}
	return verify()
}

// untar unpack a tar layer, handing each file inside to the writer registered
// for its path by the config. gzipped says the tar is wrapped in gzip.
func (f *FilesTarget) untar(desc ocispec.Descriptor, gzipped bool, r io.Reader) error {
	verified, verify := f.verifier(desc, r)
	src := verified
	if gzipped {
		gz, err := gzip.NewReader(verified)
		if err != nil {
			return fmt.Errorf("could not read layer %s as gzip: %v", desc.Digest, err)
		}
		defer func() { _ = gz.Close() }()
		src = gz
	}

	buf := f.buffer()
	tr := tar.NewReader(src)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("could not read layer %s as tar: %v", desc.Digest, err)
		}
		w := f.writerForPath(header.Name)
		if w == nil {
			w = io.Discard
		}
		if _, err := io.CopyBuffer(w, tr, buf); err != nil {
			return err
		}
	}
	// the descriptor covers the compressed blob, so the tail past the tar has to
	// be read before the digest can be checked
	if _, err := io.CopyBuffer(io.Discard, verified, buf); err != nil {
		return err
	}
	return verify()
}

// ingestConfig read the image config and map each path it names to the writer
// that should receive that file.
func (f *FilesTarget) ingestConfig(desc ocispec.Descriptor, r io.Reader) error {
	verified, verify := f.verifier(desc, r)
	b, err := io.ReadAll(verified)
	if err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	image := ocispec.Image{}
	if err := json.Unmarshal(b, &image); err != nil {
		return fmt.Errorf("could not convert image config from json: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	// A pull hands the config over before the copy starts, and the copy then offers
	// it again. Reading it once keeps the second copy from emptying the map while
	// the layers it describes are being written.
	if f.configLoaded {
		return nil
	}
	f.config = image.Config.Labels
	f.pathWriters = map[string]io.Writer{}
	f.configLoaded = true

	// pattern to use to check for other disks
	disksPattern := strings.ReplaceAll(AnnotationDiskIndexPathPattern, "%d", `([\d]+)`)
	// we are ignoring errors for now, as that should never happen
	re, _ := regexp.Compile(disksPattern)

	for annotation, value := range f.config {
		// ignore absolute paths, because tar does
		if value == "" {
			continue
		}
		value = strings.TrimPrefix(value, "/")
		switch {
		case annotation == AnnotationKernelPath && f.Kernel != nil:
			f.pathWriters[value] = f.Kernel
		case annotation == AnnotationInitrdPath && f.Initrd != nil:
			f.pathWriters[value] = f.Initrd
		case annotation == AnnotationRootPath && f.Root != nil:
			f.pathWriters[value] = f.Root
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
			if len(f.Disks) > index && f.Disks[index] != nil {
				f.pathWriters[value] = f.Disks[index]
			}
		}
	}
	return nil
}

// writerForPath the writer registered for a file inside a legacy layer.
func (f *FilesTarget) writerForPath(name string) io.Writer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pathWriters[strings.TrimPrefix(name, "/")]
}

// verifier wraps r so the content can be checked against the digest the descriptor
// claims, and returns the check to run once the reader is drained. AcceptHash
// takes the descriptor's word for it and skips the work.
func (f *FilesTarget) verifier(desc ocispec.Descriptor, r io.Reader) (io.Reader, func() error) {
	if f.AcceptHash {
		return r, func() error { return nil }
	}
	// Algorithm() panics on a digest with no ":" separator, so an empty digest has
	// to be screened out before it is asked anything. Unverifiable content is
	// refused rather than passed through.
	if desc.Digest == "" {
		return r, func() error {
			return fmt.Errorf("descriptor for %s carries no digest to verify against", desc.MediaType)
		}
	}
	if !desc.Digest.Algorithm().Available() {
		return r, func() error { return nil }
	}
	digester := desc.Digest.Algorithm().Digester()
	return io.TeeReader(r, digester.Hash()), func() error {
		if got := digester.Digest(); got != desc.Digest {
			return fmt.Errorf("content digest %s does not match descriptor digest %s", got, desc.Digest)
		}
		return nil
	}
}

func (f *FilesTarget) buffer() []byte {
	size := f.BlockSize
	if size <= 0 {
		size = DefaultBlockSize
	}
	return make([]byte, size)
}

// layerEncoding whether a layer's media type says its bytes are gzipped and/or
// wrapped in a tar. The suffixes are what carry this, not the type as a whole:
// a registry may hand back an uncompressed tar layer, and every combination has
// to be unwrapped or the caller receives the container instead of the content.
func layerEncoding(mediaType string) (gzipped, tarred bool) {
	mt := mediaType
	switch {
	case strings.HasSuffix(mt, "+gzip"):
		mt = strings.TrimSuffix(mt, "+gzip")
		gzipped = true
	case strings.HasSuffix(mt, ".gzip"):
		mt = strings.TrimSuffix(mt, ".gzip")
		gzipped = true
	}
	if strings.HasSuffix(mt, ".tar") {
		tarred = true
	}
	return gzipped, tarred
}
