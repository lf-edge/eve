// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// fakeSnapshotter records what placeLayers asks of it and hands back the
// directory layout the erofs snapshotter would have created.
type fakeSnapshotter struct {
	root      string
	committed map[string]string // chainID -> parent
	prepared  map[string]string // key -> parent
	dirs      map[string]string // key -> snapshot dir
	nextID    int
	// activeMountType shapes what Prepare returns: the erofs snapshotter
	// gives a bind mount for a parentless layer and an overlay otherwise.
	failCommit   bool
	commitExists bool
}

func newFakeSnapshotter(root string) *fakeSnapshotter {
	return &fakeSnapshotter{
		root:      root,
		committed: map[string]string{},
		prepared:  map[string]string{},
		dirs:      map[string]string{},
	}
}

func (f *fakeSnapshotter) Stat(_ context.Context, key string) (snapshots.Info, error) {
	if parent, ok := f.committed[key]; ok {
		return snapshots.Info{Name: key, Parent: parent}, nil
	}
	return snapshots.Info{}, errdefs.ErrNotFound
}

func (f *fakeSnapshotter) Update(_ context.Context, info snapshots.Info, _ ...string) (snapshots.Info, error) {
	return info, nil
}

func (f *fakeSnapshotter) Usage(context.Context, string) (snapshots.Usage, error) {
	return snapshots.Usage{}, nil
}

func (f *fakeSnapshotter) Mounts(context.Context, string) ([]mount.Mount, error) {
	return nil, errdefs.ErrNotImplemented
}

func (f *fakeSnapshotter) Prepare(_ context.Context, key, parent string, _ ...snapshots.Opt) ([]mount.Mount, error) {
	f.nextID++
	dir := filepath.Join(f.root, "snapshots", fmt.Sprint(f.nextID))
	if err := os.MkdirAll(filepath.Join(dir, "fs"), 0755); err != nil {
		return nil, err
	}
	// The marker the real snapshotter writes; mountsToLayer requires it.
	if err := os.WriteFile(filepath.Join(dir, erofsLayerMarker), nil, 0644); err != nil {
		return nil, err
	}
	f.prepared[key] = parent
	f.dirs[key] = dir
	if parent == "" {
		return []mount.Mount{{Type: "bind", Source: filepath.Join(dir, "fs")}}, nil
	}
	return []mount.Mount{{Type: "overlay", Source: "overlay", Options: []string{
		"workdir=" + filepath.Join(dir, "work"),
		"upperdir=" + filepath.Join(dir, "fs"),
	}}}, nil
}

func (f *fakeSnapshotter) View(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	return nil, errdefs.ErrNotImplemented
}

func (f *fakeSnapshotter) Commit(_ context.Context, name, key string, _ ...snapshots.Opt) error {
	if f.failCommit {
		return fmt.Errorf("commit refused")
	}
	if f.commitExists {
		return fmt.Errorf("commit %s: %w", name, errdefs.ErrAlreadyExists)
	}
	// The real snapshotter converts an upperdir when layer.erofs is
	// missing; placement is only correct if the file is already there.
	if _, err := os.Lstat(filepath.Join(f.dirs[key], erofsLayerFile)); err != nil {
		return fmt.Errorf("layer blob missing at commit: %w", err)
	}
	f.committed[name] = f.prepared[key]
	delete(f.prepared, key)
	return nil
}

func (f *fakeSnapshotter) Remove(_ context.Context, key string) error {
	delete(f.prepared, key)
	return nil
}

func (f *fakeSnapshotter) Walk(context.Context, snapshots.WalkFunc, ...string) error { return nil }
func (f *fakeSnapshotter) Close() error                                              { return nil }
func (f *fakeSnapshotter) Cleanup(context.Context) error                             { return nil }

// fakeContentStore captures only the label update placeLayers performs;
// every other method of the interface is left to panic if ever called.
type fakeContentStore struct {
	content.Store
	labels map[digest.Digest]map[string]string
}

func (f *fakeContentStore) Update(_ context.Context, info content.Info, _ ...string) (content.Info, error) {
	if f.labels == nil {
		f.labels = map[digest.Digest]map[string]string{}
	}
	f.labels[info.Digest] = info.Labels
	return info, nil
}

// writeLayout builds a layout holding one image with nLayers native erofs
// layers, and returns it plus the chainIDs those layers must land under.
func writeLayout(t *testing.T, dir string, nLayers int) (layoutImage, []digest.Digest) {
	t.Helper()
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0755); err != nil {
		t.Fatal(err)
	}
	write := func(b []byte) ocispec.Descriptor {
		d := digest.FromBytes(b)
		if err := os.WriteFile(filepath.Join(blobs, d.Encoded()), b, 0644); err != nil {
			t.Fatal(err)
		}
		return ocispec.Descriptor{Digest: d, Size: int64(len(b))}
	}

	var layers []ocispec.Descriptor
	var diffIDs []digest.Digest
	for i := 0; i < nLayers; i++ {
		d := write([]byte(fmt.Sprintf("erofs-layer-%d", i)))
		d.MediaType = "application/vnd.oci.image.layer.v1.erofs"
		layers = append(layers, d)
		diffIDs = append(diffIDs, d.Digest) // native layer: diffID == digest
	}
	cfgBytes, err := json.Marshal(ocispec.Image{
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := write(cfgBytes)
	cfg.MediaType = ocispec.MediaTypeImageConfig
	manBytes, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfg,
		Layers:    layers,
	})
	if err != nil {
		t.Fatal(err)
	}
	man := write(manBytes)
	man.MediaType = ocispec.MediaTypeImageManifest

	img := layoutImage{RefName: "test-image", Manifest: man,
		Blobs: append([]ocispec.Descriptor{man, cfg}, layers...)}
	return img, identity.ChainIDs(append([]digest.Digest{}, diffIDs...))
}

func TestPlaceLayersCommitsChainIDsAndLinksBlobs(t *testing.T) {
	dir := t.TempDir()
	img, chain := writeLayout(t, dir, 3)
	sn := newFakeSnapshotter(t.TempDir())
	cs := &fakeContentStore{}

	if err := placeLayers(context.Background(), sn, cs, dir, img); err != nil {
		t.Fatalf("placeLayers: %v", err)
	}

	// Every layer is committed under its chainID, chained to the previous
	// one -- these are the names CRI resolves at CreateContainer.
	if len(sn.committed) != 3 {
		t.Fatalf("committed %d snapshots, want 3", len(sn.committed))
	}
	for i, c := range chain {
		want := ""
		if i > 0 {
			want = chain[i-1].String()
		}
		got, ok := sn.committed[c.String()]
		if !ok {
			t.Fatalf("chainID %s not committed", c)
		}
		if got != want {
			t.Errorf("chainID %s parent = %q, want %q", c, got, want)
		}
	}
	if len(sn.prepared) != 0 {
		t.Errorf("%d snapshots left uncommitted", len(sn.prepared))
	}

	// Without this label on the manifest blob containerd's GC cannot see
	// the snapshots and reaps them once the import lease is released.
	got := cs.labels[img.Manifest.Digest][gcSnapshotRefLabel]
	if want := chain[len(chain)-1].String(); got != want {
		t.Errorf("gc snapshot label = %q, want the top chainID %q", got, want)
	}
}

func TestPlaceLayersWritesSymlinkNotACopy(t *testing.T) {
	dir := t.TempDir()
	img, _ := writeLayout(t, dir, 1)
	sn := newFakeSnapshotter(t.TempDir())
	cs := &fakeContentStore{}

	if err := placeLayers(context.Background(), sn, cs, dir, img); err != nil {
		t.Fatalf("placeLayers: %v", err)
	}

	var snapDir string
	for _, d := range sn.dirs {
		snapDir = d
	}
	link := filepath.Join(snapDir, erofsLayerFile)
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat %s: %v", link, err)
	}
	// The whole point: no bytes were written into /persist.
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is a regular file, expected a symlink into the payload", link)
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	want := blobPath(dir, img.Blobs[2]) // blobs = [manifest, config, layer0]
	if target != want {
		t.Errorf("symlink -> %s, want %s", target, want)
	}
}

func TestPlaceLayersSkipsLayersAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	img, chain := writeLayout(t, dir, 2)
	sn := newFakeSnapshotter(t.TempDir())
	cs := &fakeContentStore{}
	// Pretend the first layer was placed by an earlier image sharing it.
	sn.committed[chain[0].String()] = ""

	if err := placeLayers(context.Background(), sn, cs, dir, img); err != nil {
		t.Fatalf("placeLayers: %v", err)
	}
	if len(sn.dirs) != 1 {
		t.Errorf("prepared %d snapshots, want 1 (shared layer must be reused)", len(sn.dirs))
	}
	if parent := sn.committed[chain[1].String()]; parent != chain[0].String() {
		t.Errorf("second layer parent = %q, want the shared layer %q", parent, chain[0])
	}
}

func TestPlaceLayersRejectsNonErofsLayers(t *testing.T) {
	dir := t.TempDir()
	img, _ := writeLayout(t, dir, 1)
	// Rewrite the manifest with a tar layer: placement is only valid for
	// layers that are already erofs images.
	man, err := readManifest(dir, img.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	man.Layers[0].MediaType = ocispec.MediaTypeImageLayerGzip
	b, err := json.Marshal(man)
	if err != nil {
		t.Fatal(err)
	}
	d := digest.FromBytes(b)
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", d.Encoded()), b, 0644); err != nil {
		t.Fatal(err)
	}
	img.Manifest = ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest,
		Digest: d, Size: int64(len(b))}

	sn := newFakeSnapshotter(t.TempDir())
	cs := &fakeContentStore{}
	err = placeLayers(context.Background(), sn, cs, dir, img)
	if err == nil {
		t.Fatal("expected placement to refuse a non-erofs layer")
	}
	if len(sn.committed) != 0 {
		t.Errorf("committed %d snapshots despite refusing", len(sn.committed))
	}
}

func TestPlaceOneCleansUpWhenCommitFails(t *testing.T) {
	dir := t.TempDir()
	img, _ := writeLayout(t, dir, 1)
	sn := newFakeSnapshotter(t.TempDir())
	cs := &fakeContentStore{}
	sn.failCommit = true

	if err := placeLayers(context.Background(), sn, cs, dir, img); err == nil {
		t.Fatal("expected an error when commit fails")
	}
	if len(sn.prepared) != 0 {
		t.Errorf("%d prepared snapshots left behind after a failed commit", len(sn.prepared))
	}
}

func TestPlaceOneCleansUpWhenTheChainIDIsAlreadyCommitted(t *testing.T) {
	// Losing the race is normal -- a shared base layer, or a re-run after
	// reboot -- and costs nothing only if the prepared snapshot we no
	// longer need goes away with it.
	dir := t.TempDir()
	img, _ := writeLayout(t, dir, 1)
	sn := newFakeSnapshotter(t.TempDir())
	sn.commitExists = true

	if err := placeLayers(context.Background(), sn, &fakeContentStore{}, dir, img); err != nil {
		t.Fatalf("an already-committed chainID is not an error: %v", err)
	}
	if len(sn.prepared) != 0 {
		t.Errorf("%d prepared snapshots left behind", len(sn.prepared))
	}
}

// containerd v2.2's erofs snapshotter returns one erofs mount per parent
// followed by the target snapshot. Keying off the first entry there picks
// a parent, whose layer.erofs already exists -- so placement would fail
// and every multi-layer image would fall back to a copying unpack the
// moment k3s bumps containerd.
func TestMountsToLayerUsesTheLastEntry(t *testing.T) {
	dir := t.TempDir()
	parent, target := filepath.Join(dir, "1"), filepath.Join(dir, "2")
	for _, d := range []string{parent, target} {
		if err := os.MkdirAll(filepath.Join(d, "fs"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, erofsLayerMarker), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		mounts []mount.Mount
	}{
		{"erofs parent then overlay target", []mount.Mount{
			{Type: "erofs", Source: filepath.Join(parent, "layer.erofs")},
			{Type: "overlay", Options: []string{"upperdir=" + filepath.Join(target, "fs")}},
		}},
		{"mkfs-prefixed type", []mount.Mount{
			{Type: "erofs", Source: filepath.Join(parent, "layer.erofs")},
			{Type: "mkfs/erofs", Source: filepath.Join(target, "fs")},
		}},
	} {
		got, err := mountsToLayer(tc.mounts)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != target {
			t.Errorf("%s: got %s, want the target snapshot %s", tc.name, got, target)
		}
	}
}

func TestPlaceOneRejectsADanglingLayerBlob(t *testing.T) {
	// Commit converts the upperdir when layer.erofs is missing, so a
	// dangling link commits a valid-looking snapshot with an empty
	// rootfs. Failing here sends the caller to the unpack fallback.
	sn := newFakeSnapshotter(t.TempDir())
	err := placeOne(context.Background(), sn, "chain", "",
		filepath.Join(t.TempDir(), "absent.erofs"))
	if err == nil {
		t.Fatal("expected an error for a blob that does not resolve")
	}
	if len(sn.prepared) != 0 {
		t.Errorf("%d prepared snapshots left behind", len(sn.prepared))
	}
}

func TestMountsToLayer(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "42")
	if err := os.MkdirAll(filepath.Join(snap, "fs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap, erofsLayerMarker), nil, 0644); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(dir, "not-erofs")
	if err := os.MkdirAll(filepath.Join(bare, "fs"), 0755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		mounts  []mount.Mount
		want    string
		wantErr bool
	}{
		{
			name:   "bind mount of a parentless layer",
			mounts: []mount.Mount{{Type: "bind", Source: filepath.Join(snap, "fs")}},
			want:   snap,
		},
		{
			name: "overlay mount uses the upperdir's parent",
			mounts: []mount.Mount{{Type: "overlay", Options: []string{
				"workdir=" + filepath.Join(snap, "work"),
				"upperdir=" + filepath.Join(snap, "fs"),
			}}},
			want: snap,
		},
		{
			name:    "directory without the erofs marker is refused",
			mounts:  []mount.Mount{{Type: "bind", Source: filepath.Join(bare, "fs")}},
			wantErr: true,
		},
		{
			name:    "unknown mount type is refused",
			mounts:  []mount.Mount{{Type: "9p", Source: "/somewhere"}},
			wantErr: true,
		},
		{
			name:    "no mounts",
			mounts:  nil,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mountsToLayer(tc.mounts)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsErofsLayer(t *testing.T) {
	// Mirrors containerd's isErofsMediaType.
	for mt, want := range map[string]bool{
		"application/vnd.oci.image.layer.v1.erofs":      true,
		"application/vnd.oci.image.layer.v1.erofs+gzip": false,
		"application/vnd.oci.image.layer.v1.tar":        false,
		"application/vnd.oci.image.layer.v1.tar+gzip":   false,
	} {
		if got := isErofsLayer(mt); got != want {
			t.Errorf("isErofsLayer(%q) = %v, want %v", mt, got, want)
		}
	}
}
