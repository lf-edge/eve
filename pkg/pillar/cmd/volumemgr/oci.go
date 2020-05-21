package volumemgr

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// resolveIndex get the manifest for our platform from the index
func resolveIndex(filename string) (*v1.Descriptor, error) {
	// try it as an index and as a straight manifest
	r, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer r.Close()

	index, err := v1.ParseIndexManifest(r)
	if err != nil && err != io.EOF {
		return nil, err
	}
	// find our platform
	var manifest *v1.Descriptor
	for _, m := range index.Manifests {
		if m.Platform != nil && m.Platform.OS == runtime.GOOS && m.Platform.Architecture == runtime.GOARCH {
			manifest = &m
			break
		}
	}
	return manifest, nil
}

// resolveManifestChildren get all of the children of a manifest, as well as
// expected total size
func resolveManifestChildren(filename string) (int64, []v1.Descriptor, error) {
	// try it as an index and as a straight manifest
	r, err := os.Open(filename)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer r.Close()

	manifest, err := v1.ParseManifest(r)

	// any non-EOF errors should be passed back
	if err != nil && err != io.EOF {
		return 0, nil, err
	}

	// get all of the parts and calculate the size
	var size int64

	children := []v1.Descriptor{}
	children = append(children, manifest.Config)
	size += manifest.Config.Size
	for _, l := range manifest.Layers {
		children = append(children, l)
		size += l.Size
	}
	return size, children, nil
}

// descriptorSizes calculate the size of all of the descriptors, normally from
// a manifest
func descriptorSizes(desc []v1.Descriptor) int64 {
	var size int64
	for _, d := range desc {
		size += d.Size
	}
	return size
}

// replaceSha given the string URI for a docker image, replace the sha with the provided
// digest. If the URL does not have a digest, it appends it
func replaceSha(ref string, digest v1.Hash) string {
	// parse the ref
	repo := ref
	parts := strings.Split(ref, "@")
	if len(parts) >= 2 {
		repo = parts[0]
	}
	return fmt.Sprintf("%s@%s", repo, digest.String())
}

// errorCatcherReader io.Reader implementation that wraps a normal io.Reader,
// while reyurning all errors except for io.EOF, which is treated as no error.
// Useful for things that expect an io.Reader but cannot handle an io.EOF normally.
type errorCatcherReader struct {
	r       io.Reader
	ioError bool
}

func (e *errorCatcherReader) Read(p []byte) (n int, err error) {
	n, err = e.r.Read(p)
	// if it was no error or EOF, just return it
	if err == nil || err == io.EOF {
		return n, err
	}
	// it was some other kind of error, so capture it
	e.ioError = true
	return n, err
}
