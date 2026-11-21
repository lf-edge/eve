// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zboot

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/cas"
)

// rootFileSize returns the size of the file rootPath inside the image's tar
// layers: the rootfs of an image that names it by path in a config label
// instead of giving it a layer of its own. found is false when no tar layer
// holds that file.
//
// Only tar headers are read, but a gzipped layer has to be decompressed up to
// the header of rootPath.
func rootFileSize(ctx context.Context, casClient cas.CAS, image, rootPath string) (size int64, found bool, err error) {
	rootPath = strings.TrimPrefix(rootPath, "/")
	if rootPath == "" {
		return 0, false, nil
	}
	layers, err := casClient.GetImageLayers(image)
	if err != nil {
		return 0, false, err
	}
	for _, l := range layers {
		mt, gzipped := strings.CutSuffix(l.MediaType, "+gzip")
		if !gzipped {
			mt, gzipped = strings.CutSuffix(mt, ".gzip")
		}
		if !strings.HasSuffix(mt, ".tar") {
			continue
		}
		size, found, err = tarEntrySize(ctx, casClient, l.Digest, gzipped, rootPath)
		if err != nil || found {
			return size, found, err
		}
	}
	return 0, false, nil
}

func tarEntrySize(ctx context.Context, casClient cas.CAS, blobHash string, gzipped bool, name string) (int64, bool, error) {
	r, err := casClient.ReadBlob(ctx, blobHash)
	if err != nil {
		return 0, false, err
	}
	if c, ok := r.(io.Closer); ok {
		defer c.Close()
	}
	if gzipped {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return 0, false, fmt.Errorf("layer %s is not gzip: %w", blobHash, err)
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return 0, false, nil
		}
		if err != nil {
			return 0, false, fmt.Errorf("layer %s is not a tar: %w", blobHash, err)
		}
		if strings.TrimPrefix(hdr.Name, "/") == name {
			return hdr.Size, true, nil
		}
	}
}
