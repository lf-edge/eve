// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zboot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cas"
)

const (
	mtTar     = "application/vnd.oci.image.layer.v1.tar"
	mtTarGzip = "application/vnd.oci.image.layer.v1.tar+gzip"
	mtDocker  = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	mtRaw     = "application/vnd.lfedge.disk.layer.v1+raw"
)

type blobCAS struct {
	cas.CAS
	layers []cas.ImageLayer
	blobs  map[string][]byte
}

func (b *blobCAS) GetImageLayers(string) ([]cas.ImageLayer, error) {
	return b.layers, nil
}

func (b *blobCAS) ReadBlob(_ context.Context, hash string) (io.Reader, error) {
	data, ok := b.blobs[hash]
	if !ok {
		return nil, fmt.Errorf("no blob %s", hash)
	}
	return bytes.NewReader(data), nil
}

type tarFile struct {
	name string
	size int
}

func makeTar(t *testing.T, gzipped bool, files ...tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.Writer = &buf
	var gz *gzip.Writer
	if gzipped {
		gz = gzip.NewWriter(&buf)
		w = gz
	}
	tw := tar.NewWriter(w)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0644, Size: int64(f.size)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(make([]byte, f.size)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestRootFileSize(t *testing.T) {
	bits := []tarFile{{"bits/rootfs-ext.img", 7000}, {"bits/rootfs.img", 3000}}

	tests := []struct {
		name      string
		layers    []cas.ImageLayer
		blobs     map[string][]byte
		rootPath  string
		wantSize  int64
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "plain tar, root after the extension",
			layers:    []cas.ImageLayer{{Digest: "a", MediaType: mtTar}},
			blobs:     map[string][]byte{"a": makeTar(t, false, bits...)},
			rootPath:  "/bits/rootfs.img",
			wantSize:  3000,
			wantFound: true,
		},
		{
			name:      "gzipped OCI layer",
			layers:    []cas.ImageLayer{{Digest: "a", MediaType: mtTarGzip}},
			blobs:     map[string][]byte{"a": makeTar(t, true, bits...)},
			rootPath:  "/bits/rootfs.img",
			wantSize:  3000,
			wantFound: true,
		},
		{
			name:      "gzipped docker layer",
			layers:    []cas.ImageLayer{{Digest: "a", MediaType: mtDocker}},
			blobs:     map[string][]byte{"a": makeTar(t, true, bits...)},
			rootPath:  "bits/rootfs.img",
			wantSize:  3000,
			wantFound: true,
		},
		{
			name: "root in a later layer, non-tar layer skipped",
			layers: []cas.ImageLayer{
				{Digest: "raw", MediaType: mtRaw},
				{Digest: "a", MediaType: mtTar},
				{Digest: "b", MediaType: mtTar},
			},
			blobs: map[string][]byte{
				"a": makeTar(t, false, tarFile{"runme.sh", 10}),
				"b": makeTar(t, false, bits...),
			},
			rootPath:  "/bits/rootfs.img",
			wantSize:  3000,
			wantFound: true,
		},
		{
			name:     "file not in any layer",
			layers:   []cas.ImageLayer{{Digest: "a", MediaType: mtTar}},
			blobs:    map[string][]byte{"a": makeTar(t, false, tarFile{"bits/other", 10})},
			rootPath: "/bits/rootfs.img",
		},
		{
			name:   "no root path label",
			layers: []cas.ImageLayer{{Digest: "a", MediaType: mtTar}},
			blobs:  map[string][]byte{"a": makeTar(t, false, bits...)},
		},
		{
			name:     "layer is not a tar",
			layers:   []cas.ImageLayer{{Digest: "a", MediaType: mtTar}},
			blobs:    map[string][]byte{"a": bytes.Repeat([]byte("x"), 2048)},
			rootPath: "/bits/rootfs.img",
			wantErr:  true,
		},
		{
			name:     "layer is not gzip",
			layers:   []cas.ImageLayer{{Digest: "a", MediaType: mtTarGzip}},
			blobs:    map[string][]byte{"a": makeTar(t, false, bits...)},
			rootPath: "/bits/rootfs.img",
			wantErr:  true,
		},
		{
			name:     "layer blob missing",
			layers:   []cas.ImageLayer{{Digest: "a", MediaType: mtTar}},
			rootPath: "/bits/rootfs.img",
			wantErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &blobCAS{layers: tc.layers, blobs: tc.blobs}
			size, found, err := rootFileSize(context.Background(), c, "ref", tc.rootPath)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if found != tc.wantFound || size != tc.wantSize {
				t.Fatalf("got size=%d found=%v, want %d/%v", size, found, tc.wantSize, tc.wantFound)
			}
		})
	}
}
