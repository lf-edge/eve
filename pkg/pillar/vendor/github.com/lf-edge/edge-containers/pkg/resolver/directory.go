package resolver

/*
 Provides a github.com/containerd/containerd/remotes#Resolver that resolves
 to a local filesystem directory.

 The format in the directory is one file for each blob, named `sha256:<hash>`.
 Even manifest and index files are saved as blob files. In addition,
 The image reference named is sha256 hashed and hex-encoded. That is used as
 a filename for a file that contains the OCI spec descriptor for the root manifest.

 For example, if the image name is docker.io/foo/bar:1.2.3, that can be hashed as
 sha256:24b80c31240b48117e63156af80951a987c43de267050c7c768dd4d20d5e9a3b

 A file will be created named sha256:24b80c31240b48117e63156af80951a987c43de267050c7c768dd4d20d5e9a3b
 whose contents will be the descriptor for the root.
*/

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	imageFile := getImageFilename(ref)
	if imageFile == "" {
		return "", ocispec.Descriptor{}, fmt.Errorf("invalid reference: %s", ref)
	}
	// try to get it from the image reference file
	contents, err := ioutil.ReadFile(path.Join(d.dir, imageFile))
	if err != nil {
		return "", ocispec.Descriptor{}, reference.ErrInvalid
	}
	var rootDesc ocispec.Descriptor
	if err := json.Unmarshal(contents, &rootDesc); err != nil {
		return "", ocispec.Descriptor{}, fmt.Errorf("could not convert manifest description to json: %v", err)
	}

	dgst := refspec.Digest()
	if dgst == "" {
		dgst = digest.Digest(rootDesc.Digest.String())
	}

	// need to get the descriptor for the contents of it
	desc = ocispec.Descriptor{
		Digest:    dgst,
		MediaType: rootDesc.MediaType,
		Size:      rootDesc.Size,
	}
	return ref, desc, nil
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

func (d directoryFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	filename := path.Join(d.dir, desc.Digest.String())
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open for reading %s: %v", filename, err)
	}
	return file, nil
}

func (d directoryPusher) Push(ctx context.Context, desc ocispec.Descriptor) (content.Writer, error) {
	filename := path.Join(d.dir, desc.Digest.String())
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

	imageFile := getImageFilename(d.ref)
	if imageFile == "" {
		return nil, fmt.Errorf("invalid reference: %s", d.ref)
	}

	return directoryWriter{
		file:       file,
		desc:       desc,
		isManifest: isManifest,
		ref:        remotes.MakeRefKey(ctx, desc),
		imageFile:  path.Join(d.dir, imageFile),
	}, nil
}

type directoryWriter struct {
	file       *os.File
	ref        string
	isManifest bool
	desc       ocispec.Descriptor
	imageFile  string
	committed  bool
	start      time.Time
	updated    time.Time
	total      int64
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
	d.total += int64(n)
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
		// convert the manifest to json bytes and write it
		b, err := json.Marshal(d.desc)
		if err != nil {
			return fmt.Errorf("could not convert manifest description to json: %v", err)
		}
		if err := ioutil.WriteFile(d.imageFile, b, 0644); err != nil {
			return fmt.Errorf("error writing imagefile %s: %v", d.imageFile, err)
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

func getImageFilename(ref string) string {
	refspec, err := reference.Parse(ref)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(refspec.String()))
	return fmt.Sprintf("%s:%s", "sha256", hex.EncodeToString(sum[:]))
}
