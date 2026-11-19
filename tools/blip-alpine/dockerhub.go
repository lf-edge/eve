// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"go.podman.io/image/v5/docker"
	"go.podman.io/image/v5/image"
	"go.podman.io/image/v5/pkg/blobinfocache/none"
	"go.podman.io/image/v5/pkg/compression"
	"go.podman.io/image/v5/types"
)

// extractFromDockerImage returns a file of a container image to read.
// imageName is what "docker pull" takes, like lfedge/eve-alpine:tag, and
// filepath is the path of the file in the image. The file has to be closed
// when it is not read any more.
//
// The image is read from its registry without a login, so it has to be one
// that all may read. The registries.conf of podman applies, if there is
// one. Of an image for several platforms it is the one for the platform of
// this program.
//
// The image is not pulled as a whole. Its layers are read from the top one
// down until one has the file or removes it. The file is then read as it
// comes from the registry, so that what goes wrong with the download shows
// as an error of reading, and closing the file ends the download of its
// layer: eve-alpine has the index of its mirror within the first megabytes
// of a layer of more than a gigabyte. That is also why the content is not
// checked against the digest of the layer, which would take all of the
// layer.
//
// Only a regular file can be read, and symbolic links are not followed: if
// the file or a directory on the way to it is one, the error says where it
// points to.
func extractFromDockerImage(imageName string, filepath string) (_ io.ReadCloser, err error) {
	ctx := context.Background()
	file := path.Clean("/" + filepath)
	failed := func(err error) error {
		return fmt.Errorf("extracting %s from %s: %w", file, imageName, err)
	}
	defer func() {
		if err != nil {
			err = failed(err)
		}
	}()
	if file == "/" {
		return nil, fmt.Errorf("%q names no file", filepath)
	}

	// No login: left to itself the library takes any one of the entries
	// that ~/.docker/config.json has for a registry, and of those that the
	// docker command keeps for Docker Hub not every one is a login.
	sys := &types.SystemContext{DockerAuthConfig: &types.DockerAuthConfig{}}
	ref, err := docker.ParseReference("//" + imageName)
	if err != nil {
		return nil, err
	}
	src, err := ref.NewImageSource(ctx, sys)
	if err != nil {
		return nil, err
	}
	// the file is read from src, which is closed with it: only if there is
	// no file it is closed here
	defer func() {
		if err != nil {
			src.Close()
		}
	}()
	img, err := image.FromUnparsedImage(ctx, sys, image.UnparsedInstance(src, nil))
	if err != nil {
		return nil, err
	}

	layers := img.LayerInfos()
	for i := len(layers) - 1; i >= 0; i-- {
		blob, _, err := src.GetBlob(ctx, layers[i], none.NoCache)
		if err != nil {
			return nil, err
		}
		content, removed, err := openInLayer(blob, file)
		if content != nil {
			// once only: what unpacks a layer panics when it is closed again
			closeAll := sync.OnceValue(func() error {
				return errors.Join(content.Close(), blob.Close(), src.Close())
			})
			return &imageFile{content: content, close: closeAll, failed: failed}, nil
		}
		blob.Close()
		if err != nil {
			return nil, err
		}
		if removed {
			break
		}
	}
	return nil, errors.New("the image has no such file")
}

// imageFile is a file of an image that is read from the registry.
type imageFile struct {
	content io.Reader
	// close closes the content, the download of the layer that it comes
	// from and what the layer is downloaded from
	close func() error
	// failed says what an error was of
	failed func(error) error
}

func (f *imageFile) Read(p []byte) (int, error) {
	n, err := f.content.Read(p)
	if err != nil && err != io.EOF {
		err = f.failed(err)
	}
	return n, err
}

// Close ends the download of the layer, whether the file was read to its
// end or not. It may be called more than once.
func (f *imageFile) Close() error {
	return f.close()
}

// openInLayer looks for the file in a layer, a tar archive that may be
// compressed. If the layer has the file, it returns its content, which is
// read straight from the layer and has to be closed. If the layer does not
// have the file, it tells whether it removes the one that the layers below
// may have.
func openInLayer(layer io.Reader, file string) (content io.ReadCloser, removed bool, err error) {
	plain, _, err := compression.AutoDecompress(layer)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if content == nil {
			plain.Close()
		}
	}()
	archive := tar.NewReader(plain)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return nil, removed, nil
		}
		if err != nil {
			return nil, false, err
		}
		name := path.Clean("/" + header.Name)
		if removes(name, file) {
			removed = true
		}
		// what is no directory any more has nothing in it, whatever the
		// layers below have there
		if strings.HasPrefix(file, name+"/") && header.Typeflag != tar.TypeDir {
			return nil, false, fmt.Errorf("%s is %s", name, kind(header))
		}
		if name != file {
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, false, fmt.Errorf("%s is %s, not a regular file", name, kind(header))
		}
		// until the next file is asked for, the archive reads this one
		return readCloser{archive, plain}, false, nil
	}
}

// readCloser reads from one thing and closes another.
type readCloser struct {
	io.Reader
	io.Closer
}

// removes tells whether name, which a layer has, is a whiteout that removes
// file from the layers below: one for the file or for a directory that it
// is in, or an opaque one, which is for all that a directory has.
func removes(name, file string) bool {
	dir, base := path.Split(name)
	if base == ".wh..wh..opq" {
		return strings.HasPrefix(file, dir)
	}
	gone, isWhiteout := strings.CutPrefix(base, ".wh.")
	if !isWhiteout {
		return false
	}
	return file == dir+gone || strings.HasPrefix(file, dir+gone+"/")
}

// kind says what a layer has under a name, for an error.
func kind(header *tar.Header) string {
	switch header.Typeflag {
	case tar.TypeReg:
		return "a regular file"
	case tar.TypeDir:
		return "a directory"
	case tar.TypeSymlink:
		return "a symbolic link to " + header.Linkname
	case tar.TypeLink:
		return "a hard link to " + header.Linkname
	}
	return "a special file"
}
