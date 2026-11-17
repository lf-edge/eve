// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package ocilayout

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type tarEntry struct {
	name string
	data []byte
	typ  byte
}

func blobEntry(data []byte) tarEntry {
	return tarEntry{name: blobPrefix + digest.FromBytes(data).Encoded(), data: data}
}

func desc(mediaType string, data []byte) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeTar(t *testing.T, entries []tarEntry) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0644}
		if typ == tar.TypeReg {
			hdr.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}

// testImage is the content of a one-layer image and its blob entries.
type testImage struct {
	layer, config, manifest []byte
	manifestDesc            ocispec.Descriptor
}

func newTestImage(t *testing.T, arch, layer string) testImage {
	t.Helper()
	img := testImage{layer: []byte(layer)}
	img.config = mustJSON(t, ocispec.Image{
		Platform: ocispec.Platform{OS: "linux", Architecture: arch},
		Config:   ocispec.ImageConfig{Labels: map[string]string{"org.lfedge.eci.artifact.root": "/bits/rootfs.img"}},
	})
	img.manifest = mustJSON(t, ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    desc(ocispec.MediaTypeImageConfig, img.config),
		Layers:    []ocispec.Descriptor{desc(ocispec.MediaTypeImageLayer, img.layer)},
	})
	img.manifestDesc = desc(ocispec.MediaTypeImageManifest, img.manifest)
	return img
}

func (i testImage) blobs() []tarEntry {
	return []tarEntry{blobEntry(i.layer), blobEntry(i.config), blobEntry(i.manifest)}
}

func layout(t *testing.T, index ocispec.Index, blobs ...tarEntry) []tarEntry {
	t.Helper()
	entries := []tarEntry{{name: "blobs/", typ: tar.TypeDir}, {name: "blobs/sha256/", typ: tar.TypeDir}}
	entries = append(entries, blobs...)
	return append(entries,
		tarEntry{name: indexFile, data: mustJSON(t, index)},
		tarEntry{name: layoutFile, data: []byte(`{"imageLayoutVersion":"1.0.0"}`)})
}

func TestImage(t *testing.T) {
	img := newTestImage(t, "amd64", "layer content")
	file := writeTar(t, layout(t,
		ocispec.Index{Manifests: []ocispec.Descriptor{img.manifestDesc}}, img.blobs()...))

	if !IsLayoutTar(file) {
		t.Fatal("IsLayoutTar is false for a layout archive")
	}
	a, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	got, err := a.Image("amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.Digest != img.manifestDesc.Digest || string(got.ManifestRaw) != string(img.manifest) {
		t.Errorf("wrong manifest: %+v", got.Manifest)
	}
	if got.Config.Digest != digest.FromBytes(img.config) {
		t.Errorf("wrong config: %+v", got.Config)
	}
	if len(got.Layers) != 1 {
		t.Fatalf("got %d layers", len(got.Layers))
	}
	r, err := a.Blob(got.Layers[0])
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil || string(data) != "layer content" {
		t.Errorf("layer read %q, err %v", data, err)
	}
}

func TestImageSelection(t *testing.T) {
	amd := newTestImage(t, "amd64", "amd64 layer")
	arm := newTestImage(t, "arm64", "arm64 layer")
	withPlatform := func(i testImage, arch string) ocispec.Descriptor {
		d := i.manifestDesc
		d.Platform = &ocispec.Platform{OS: "linux", Architecture: arch}
		return d
	}
	attestation := amd.manifestDesc
	attestation.Platform = &ocispec.Platform{OS: "unknown", Architecture: "unknown"}

	nested := mustJSON(t, ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{withPlatform(amd, "amd64"), attestation},
	})

	tests := []struct {
		name    string
		index   ocispec.Index
		blobs   []tarEntry
		wantErr string
	}{
		{
			name:  "nested index with attestation",
			index: ocispec.Index{Manifests: []ocispec.Descriptor{desc(ocispec.MediaTypeImageIndex, nested)}},
			blobs: append(amd.blobs(), blobEntry(nested)),
		},
		{
			name: "two platforms",
			index: ocispec.Index{Manifests: []ocispec.Descriptor{
				withPlatform(amd, "amd64"), withPlatform(arm, "arm64")}},
			blobs: append(amd.blobs(), arm.blobs()...),
		},
		{
			name: "two images for the platform",
			index: ocispec.Index{Manifests: []ocispec.Descriptor{
				amd.manifestDesc, newTestImage(t, "amd64", "other").manifestDesc}},
			blobs:   amd.blobs(),
			wantErr: "exactly one image",
		},
		{
			name:    "platform absent",
			index:   ocispec.Index{Manifests: []ocispec.Descriptor{withPlatform(arm, "arm64")}},
			blobs:   arm.blobs(),
			wantErr: "exactly one image",
		},
		{
			name:    "architecture only in config",
			index:   ocispec.Index{Manifests: []ocispec.Descriptor{arm.manifestDesc}},
			blobs:   arm.blobs(),
			wantErr: "built for arm64",
		},
		{
			name:    "missing layer",
			index:   ocispec.Index{Manifests: []ocispec.Descriptor{amd.manifestDesc}},
			blobs:   amd.blobs()[1:],
			wantErr: "not in the archive",
		},
		{
			name:    "empty index",
			index:   ocispec.Index{},
			wantErr: "exactly one image",
		},
		{
			name:    "too many manifests",
			index:   ocispec.Index{Manifests: slices.Repeat([]ocispec.Descriptor{amd.manifestDesc}, maxManifests+1)},
			blobs:   amd.blobs(),
			wantErr: "more than",
		},
		{
			name: "nested index with a malformed digest",
			index: ocispec.Index{Manifests: []ocispec.Descriptor{
				{MediaType: ocispec.MediaTypeImageIndex, Digest: "invalid"}}},
			wantErr: "unsupported digest",
		},
		{
			name: "manifest with a malformed digest",
			index: ocispec.Index{Manifests: []ocispec.Descriptor{
				{MediaType: ocispec.MediaTypeImageManifest}}},
			wantErr: "unsupported digest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Open(writeTar(t, layout(t, tt.index, tt.blobs...)))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			_, err = a.Image("amd64")
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("got error %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestBlobMismatch(t *testing.T) {
	img := newTestImage(t, "amd64", "layer content")
	blobs := img.blobs()
	// Same name, different content: the manifest no longer hashes to its name.
	blobs[2].data = append([]byte{}, blobs[2].data...)
	blobs[2].data[0] ^= 0xff
	a, err := Open(writeTar(t, layout(t,
		ocispec.Index{Manifests: []ocispec.Descriptor{img.manifestDesc}}, blobs...)))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Image("amd64"); err == nil || !strings.Contains(err.Error(), "has digest") {
		t.Fatalf("corrupt manifest: got error %v", err)
	}

	wrongSize := img.manifestDesc
	wrongSize.Size++
	if _, err := a.Blob(wrongSize); err == nil {
		t.Fatal("size mismatch was accepted")
	}
	if _, err := a.Blob(ocispec.Descriptor{Digest: "sha512:abcd"}); err == nil {
		t.Fatal("non-sha256 digest was accepted")
	}
	for _, d := range []digest.Digest{"sha256:../../etc/passwd", "invalid", ""} {
		if _, err := a.Blob(ocispec.Descriptor{Digest: d}); err == nil {
			t.Fatalf("malformed digest %q was accepted", d)
		}
	}
}

func TestNotLayout(t *testing.T) {
	img := newTestImage(t, "amd64", "layer content")
	dir := t.TempDir()

	squashfs := filepath.Join(dir, "rootfs.img")
	if err := os.WriteFile(squashfs, append([]byte("hsqs"), make([]byte, 4096)...), 0644); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("hsqs"), 0644); err != nil {
		t.Fatal(err)
	}
	full := layout(t, ocispec.Index{Manifests: []ocispec.Descriptor{img.manifestDesc}}, img.blobs()...)
	plainTar := writeTar(t, []tarEntry{{name: "rootfs.img", data: []byte("data")}})
	noIndex := writeTar(t, full[:len(full)-2])
	linkedIndex := writeTar(t, append(append([]tarEntry{}, full[:len(full)-2]...),
		tarEntry{name: indexFile, typ: tar.TypeSymlink}, full[len(full)-1]))

	fakeLayout := writeTar(t, []tarEntry{{name: indexFile, data: []byte("{}")}, {name: layoutFile, data: []byte("{}")}})
	bigLayout := writeTar(t, []tarEntry{{name: indexFile, data: []byte("{}")},
		{name: layoutFile, data: append([]byte(`{"imageLayoutVersion":"1.0.0"}`), make([]byte, maxLayoutSize)...)}})

	truncated := filepath.Join(dir, "truncated.tar")
	data, err := os.ReadFile(writeTar(t, full))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truncated, data[:len(data)/2], 0644); err != nil {
		t.Fatal(err)
	}

	for name, file := range map[string]string{
		"squashfs":      squashfs,
		"short file":    short,
		"plain tar":     plainTar,
		"no index":      noIndex,
		"symlink index": linkedIndex,
		"empty layout":  fakeLayout,
		"large layout":  bigLayout,
		"truncated":     truncated,
		"missing":       filepath.Join(dir, "absent"),
	} {
		if IsLayoutTar(file) {
			t.Errorf("%s: IsLayoutTar is true", name)
		}
	}
	if _, err := Open(squashfs); !errors.Is(err, ErrNotLayout) {
		t.Errorf("squashfs: got error %v, want ErrNotLayout", err)
	}
}

// Extended headers ahead of an entry are read by tar.Reader without counting
// as entries, so their volume has to be bounded separately.
func TestHeaderFlood(t *testing.T) {
	img := newTestImage(t, "amd64", "layer content")
	file := filepath.Join(t.TempDir(), "flood.tar")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	pad := map[string]string{"EVE.pad": strings.Repeat("x", 64<<10)}
	for written := 0; written <= maxHeaderBytes; written += 64 << 10 {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, PAXRecords: pad}); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range layout(t, ocispec.Index{Manifests: []ocispec.Descriptor{img.manifestDesc}}, img.blobs()...) {
		if e.typ != 0 {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(e.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if IsLayoutTar(file) {
		t.Fatal("an archive with more metadata than the limit was accepted")
	}
}

func TestEntryNames(t *testing.T) {
	img := newTestImage(t, "amd64", "layer content")
	entries := layout(t, ocispec.Index{Manifests: []ocispec.Descriptor{img.manifestDesc}}, img.blobs()...)
	// oci-layout first and every name with a "./" prefix, as some tools write.
	last := len(entries) - 1
	entries[0], entries[last] = entries[last], entries[0]
	for i := range entries {
		entries[i].name = "./" + entries[i].name
	}
	a, err := Open(writeTar(t, entries))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Image("amd64"); err != nil {
		t.Fatal(err)
	}
}
