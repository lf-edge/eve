// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// withSources points the assembly at two fake source files, standing in
// for the rootfs's kernel and runx-initrd. They are created read-only and
// root-ish (0400) on purpose: the originals ship 0600 on a read-only
// squashfs, so the staging step has to copy rather than link.
func withSources(t *testing.T) map[string][]byte {
	t.Helper()
	dir := t.TempDir()
	want := map[string][]byte{
		"kernel":      []byte("vmlinuz-ish"),
		"runx-initrd": []byte("initrd-ish"),
	}
	saved := bootImageSources
	t.Cleanup(func() { bootImageSources = saved })
	bootImageSources = map[string]string{}
	for name, data := range want {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0400); err != nil {
			t.Fatal(err)
		}
		bootImageSources[name] = p
	}
	return want
}

// fakeMkfs stands in for mkfs.erofs: it records the staged tree instead
// of building a filesystem, so the assembly can be tested without
// erofs-utils. The bytes are a function of the input, like the real
// thing.
func fakeMkfs(out, srcDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	var blob []byte
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			return err
		}
		fi, err := e.Info()
		if err != nil {
			return err
		}
		blob = append(blob, []byte(e.Name()+":"+fi.Mode().String()+":")...)
		blob = append(blob, b...)
	}
	return os.WriteFile(out, blob, 0644)
}

func TestStageBootImageMakesFilesReadableByNonRoot(t *testing.T) {
	// KubeVirt runs the container-disk container as a non-root user, so
	// a layer whose files are 0600 root (which is how runx-initrd ships)
	// or whose root lacks +x is unusable there.
	withSources(t)
	dir := filepath.Join(t.TempDir(), "root")
	if err := stageBootImage(dir); err != nil {
		t.Fatal(err)
	}
	if mode := statMode(t, dir); mode != bootImageRootMode {
		t.Errorf("layer root mode = %#o, want %#o", mode, bootImageRootMode)
	}
	for name := range bootImageSources {
		if mode := statMode(t, filepath.Join(dir, name)); mode != bootImageFileMode {
			t.Errorf("%s mode = %#o, want %#o", name, mode, bootImageFileMode)
		}
	}
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestBuildBootImageLayerContentAndDeterminism(t *testing.T) {
	want := withSources(t)
	build := func() (string, ocispec.Descriptor) {
		path, desc, err := buildBootImageLayer(t.TempDir(), fakeMkfs)
		if err != nil {
			t.Fatal(err)
		}
		return path, desc
	}
	path, desc := build()

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := digest.FromBytes(blob); got != desc.Digest {
		t.Errorf("descriptor digest %s does not describe the blob (%s)", desc.Digest, got)
	}
	if desc.Size != int64(len(blob)) {
		t.Errorf("descriptor size = %d, blob is %d", desc.Size, len(blob))
	}
	// containerd's isErofsMediaType: ends in ".erofs", carries no "+suffix".
	if desc.MediaType != erofsLayerMediaType {
		t.Errorf("media type = %q, want %q", desc.MediaType, erofsLayerMediaType)
	}
	for _, data := range want {
		if !bytes.Contains(blob, data) {
			t.Errorf("layer does not contain %q", data)
		}
	}

	// Re-running on every boot is only free because an unchanged kernel
	// yields an unchanged digest, and so an already-placed snapshot.
	if _, again := build(); again.Digest != desc.Digest {
		t.Errorf("rebuild changed the digest: %s -> %s", desc.Digest, again.Digest)
	}
}

func TestBuildBootImageLayerFailsWhenASourceIsMissing(t *testing.T) {
	withSources(t)
	bootImageSources["kernel"] = filepath.Join(t.TempDir(), "absent")
	if _, _, err := buildBootImageLayer(t.TempDir(), fakeMkfs); err == nil {
		t.Fatal("expected an error when the kernel is missing")
	}
}

func TestBootImageBlobsDescribeANativeErofsImage(t *testing.T) {
	layer := ocispec.Descriptor{
		MediaType: erofsLayerMediaType,
		Digest:    digest.FromString("layer"),
		Size:      42,
	}
	cfg, man, cfgDesc, manDesc, err := bootImageBlobs(layer)
	if err != nil {
		t.Fatal(err)
	}
	if digest.FromBytes(cfg) != cfgDesc.Digest || int64(len(cfg)) != cfgDesc.Size {
		t.Error("config descriptor does not describe the config blob")
	}
	if digest.FromBytes(man) != manDesc.Digest || int64(len(man)) != manDesc.Size {
		t.Error("manifest descriptor does not describe the manifest blob")
	}

	// The unpacker compares Apply()'s returned digest against the
	// config's diff_id; for a native erofs layer that IS the layer
	// digest, so anything else wedges the image at unpack.
	var image ocispec.Image
	if err := json.Unmarshal(cfg, &image); err != nil {
		t.Fatal(err)
	}
	if len(image.RootFS.DiffIDs) != 1 || image.RootFS.DiffIDs[0] != layer.Digest {
		t.Errorf("diff_ids = %v, want [%s]", image.RootFS.DiffIDs, layer.Digest)
	}
	if image.OS != "linux" || image.Architecture == "" {
		t.Errorf("config platform = %s/%s", image.OS, image.Architecture)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(man, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("manifest = v%d %q", manifest.SchemaVersion, manifest.MediaType)
	}
	if len(manifest.Layers) != 1 || manifest.Layers[0].Digest != layer.Digest {
		t.Errorf("manifest layers = %v", manifest.Layers)
	}
	if manifest.Config.Digest != cfgDesc.Digest {
		t.Error("manifest does not point at the config blob")
	}
}

// TestMkfsErofsBootImageProducesAPlaceableLayer exercises the real
// mkfs.erofs: the flags have to yield a filesystem containerd's native
// differ will accept (EROFS magic) and a digest that is stable across
// runs, which is what the -U/-T pinning buys.
func TestMkfsErofsBootImageProducesAPlaceableLayer(t *testing.T) {
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		t.Skipf("mkfs.erofs not installed: %v", err)
	}
	withSources(t)
	_, first, err := buildBootImageLayer(t.TempDir(), mkfsErofsBootImage)
	if err != nil {
		t.Fatal(err)
	}
	path, second, err := buildBootImageLayer(t.TempDir(), mkfsErofsBootImage)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Errorf("mkfs is not reproducible: %s != %s", first.Digest, second.Digest)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) < 1056 || string(blob[1024:1028]) != "\xe2\xe1\xf5\xe0" {
		t.Fatal("layer is not an EROFS image")
	}
	// Two back-to-back builds can match by luck -- mkfs stamps the
	// superblock with a coarse build time, so both would land in the same
	// second even without -T. Check the field itself (build_time is 8
	// bytes at offset 24 of the superblock): pinned to 0 is what makes the
	// digest stable across boots, and therefore makes re-running free.
	if bt := binary.LittleEndian.Uint64(blob[1024+24 : 1024+32]); bt != 0 {
		t.Errorf("superblock build_time = %d, want 0 (-T not applied)", bt)
	}
}
