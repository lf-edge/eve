// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

const (
	tFrom = "eve-user-apps"
	tTo   = "k8s.io"
)

// initTestLog wires the package-level log var so log.Noticef etc. don't NPE.
// Mirrors the pattern in upgradeconverter_test.go.
func initTestLog() {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
}

// seedSourceBlobs creates a bolt DB at dbPath with the supplied blob digests
// in the source namespace. Each blob bucket gets a `size` key and a
// `labels/category` sub-bucket entry so the recursive copy path is exercised.
func seedSourceBlobs(t *testing.T, dbPath string, digests []string) {
	t.Helper()
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("seedSourceBlobs: open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		v1, _ := tx.CreateBucketIfNotExists([]byte("v1"))
		ns, _ := v1.CreateBucketIfNotExists([]byte(tFrom))
		content, _ := ns.CreateBucketIfNotExists([]byte("content"))
		blob, _ := content.CreateBucketIfNotExists([]byte("blob"))
		for _, d := range digests {
			b, err := blob.CreateBucket([]byte(d))
			if err != nil {
				return err
			}
			if err := b.Put([]byte("size"), []byte("1234")); err != nil {
				return err
			}
			labels, err := b.CreateBucket([]byte("labels"))
			if err != nil {
				return err
			}
			if err := labels.Put([]byte("category"), []byte("test")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seedSourceBlobs: update: %v", err)
	}
}

// destBlobDigests returns the set of digests present in the destination
// namespace's content/blob bucket.
func destBlobDigests(t *testing.T, dbPath string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		t.Fatalf("destBlobDigests: open: %v", err)
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		if v1 == nil {
			return nil
		}
		ns := v1.Bucket([]byte(tTo))
		if ns == nil {
			return nil
		}
		content := ns.Bucket([]byte("content"))
		if content == nil {
			return nil
		}
		blob := content.Bucket([]byte("blob"))
		if blob == nil {
			return nil
		}
		return blob.ForEach(func(k, _ []byte) error {
			out[string(k)] = true
			return nil
		})
	})
	return out
}

// seedSourceImages creates an images sub-bucket under the source namespace
// with the supplied image refs. Each image gets a target/digest key and an
// EVEDownloadedLabel in its labels/ sub-bucket — mirrors what pillar's
// cas.CreateImage() writes.
func seedSourceImages(t *testing.T, dbPath string, imageRefs []string) {
	t.Helper()
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("seedSourceImages: open: %v", err)
	}
	defer db.Close()
	if err := db.Update(func(tx *bolt.Tx) error {
		v1, _ := tx.CreateBucketIfNotExists([]byte("v1"))
		ns, _ := v1.CreateBucketIfNotExists([]byte(tFrom))
		images, _ := ns.CreateBucketIfNotExists([]byte("images"))
		for _, ref := range imageRefs {
			ib, err := images.CreateBucket([]byte(ref))
			if err != nil {
				return err
			}
			tgt, _ := ib.CreateBucket([]byte("target"))
			_ = tgt.Put([]byte("digest"), []byte("sha256:adda3d3f"))
			_ = tgt.Put([]byte("mediatype"), []byte("application/vnd.oci.image.manifest.v1+json"))
			labels, _ := ib.CreateBucket([]byte("labels"))
			_ = labels.Put([]byte("eve-downloaded"), []byte("true"))
		}
		return nil
	}); err != nil {
		t.Fatalf("seedSourceImages: update: %v", err)
	}
}

// destImageRefs returns the set of image refs present in dst namespace.
func destImageRefs(t *testing.T, dbPath string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		t.Fatalf("destImageRefs: open: %v", err)
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		if v1 == nil {
			return nil
		}
		ns := v1.Bucket([]byte(tTo))
		if ns == nil {
			return nil
		}
		images := ns.Bucket([]byte("images"))
		if images == nil {
			return nil
		}
		return images.ForEach(func(k, _ []byte) error {
			out[string(k)] = true
			return nil
		})
	})
	return out
}

// destImageLabel reads dst namespace's images/<ref>/labels/<key>.
func destImageLabel(t *testing.T, dbPath, ref, key string) string {
	t.Helper()
	var val string
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		t.Fatalf("destImageLabel: open: %v", err)
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		img := v1.Bucket([]byte(tTo)).Bucket([]byte("images")).Bucket([]byte(ref))
		if img == nil {
			return nil
		}
		labels := img.Bucket([]byte("labels"))
		if labels == nil {
			return nil
		}
		if v := labels.Get([]byte(key)); v != nil {
			val = string(v)
		}
		return nil
	})
	return val
}

// destImageTarget reads dst namespace's images/<ref>/target/<key>.
func destImageTarget(t *testing.T, dbPath, ref, key string) string {
	t.Helper()
	var val string
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		t.Fatalf("destImageTarget: open: %v", err)
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		img := v1.Bucket([]byte(tTo)).Bucket([]byte("images")).Bucket([]byte(ref))
		if img == nil {
			return nil
		}
		tgt := img.Bucket([]byte("target"))
		if tgt == nil {
			return nil
		}
		if v := tgt.Get([]byte(key)); v != nil {
			val = string(v)
		}
		return nil
	})
	return val
}

// destBlobLabel reads the destination's <digest>/labels/<key> for verification.
func destBlobLabel(t *testing.T, dbPath, digest, key string) string {
	t.Helper()
	var val string
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		t.Fatalf("destBlobLabel: open: %v", err)
	}
	defer db.Close()
	_ = db.View(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		ns := v1.Bucket([]byte(tTo))
		blob := ns.Bucket([]byte("content")).Bucket([]byte("blob")).Bucket([]byte(digest))
		if blob == nil {
			return nil
		}
		labels := blob.Bucket([]byte("labels"))
		if labels == nil {
			return nil
		}
		v := labels.Get([]byte(key))
		if v != nil {
			val = string(v)
		}
		return nil
	})
	return val
}

func TestPortContainerdNamespace_SentinelShortCircuits(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	// Pre-create the sentinel.
	if err := os.WriteFile(sentinel, nil, 0644); err != nil {
		t.Fatal(err)
	}
	// Also create a bolt DB with seeded data; we expect it untouched.
	seedSourceBlobs(t, dbPath, []string{"sha256:aaa"})

	err := portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	// Destination must remain empty — port did not run.
	assert.Empty(t, destBlobDigests(t, dbPath))
}

func TestPortContainerdNamespace_FreshInstallNoDB(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	// dbPath does NOT exist.

	err := portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	// Sentinel must be written so we don't probe every boot.
	_, statErr := os.Stat(sentinel)
	assert.NoError(t, statErr, "sentinel should be created on fresh-install path")
	// And the DB itself should still not exist (we didn't create it).
	_, statErr = os.Stat(dbPath)
	assert.True(t, os.IsNotExist(statErr), "must not create the DB ourselves")
}

func TestPortContainerdNamespace_DBExistsNoSchema(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	// Create an empty DB (no v1 bucket).
	db, err := bolt.Open(dbPath, 0600, nil)
	assert.NoError(t, err)
	db.Close()

	err = portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	_, statErr := os.Stat(sentinel)
	assert.NoError(t, statErr)
	assert.Empty(t, destBlobDigests(t, dbPath))
}

func TestPortContainerdNamespace_NoSourceNamespace(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	// Create a v1 bucket but no eve-user-apps namespace.
	db, err := bolt.Open(dbPath, 0600, nil)
	assert.NoError(t, err)
	assert.NoError(t, db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte("v1"))
		return e
	}))
	db.Close()

	err = portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	_, statErr := os.Stat(sentinel)
	assert.NoError(t, statErr)
	assert.Empty(t, destBlobDigests(t, dbPath))
}

func TestPortContainerdNamespace_HappyPath(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	digests := []string{
		"sha256:587eecb3b19b7369b22aa6276c2663162f0c7d869fa315462fe7829e8aa8725c",
		"sha256:da570fff24b1cb07f0e430b3969e16d8dc819501b48307163e9a331b3a437acf",
		"sha256:adda3d3f34fd86576e7b29ddbfe98a0d98f14b9681820055a45f177e8727d40f",
	}
	seedSourceBlobs(t, dbPath, digests)

	err := portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	// Sentinel written.
	_, statErr := os.Stat(sentinel)
	assert.NoError(t, statErr)
	// All 3 ported.
	got := destBlobDigests(t, dbPath)
	for _, d := range digests {
		assert.True(t, got[d], "digest %q should be in dest", d)
	}
	assert.Len(t, got, len(digests))
	// Labels sub-bucket was copied recursively.
	for _, d := range digests {
		assert.Equal(t, "test", destBlobLabel(t, dbPath, d, "category"),
			"labels sub-bucket should have been copied for %q", d)
	}
}

func TestPortContainerdNamespace_IdempotentPartialDestination(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	srcDigests := []string{
		"sha256:aaa", "sha256:bbb", "sha256:ccc",
	}
	seedSourceBlobs(t, dbPath, srcDigests)
	// Pre-populate destination with one digest (different label value, so
	// we can verify it was NOT overwritten).
	db, err := bolt.Open(dbPath, 0600, nil)
	assert.NoError(t, err)
	assert.NoError(t, db.Update(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		dst, _ := v1.CreateBucketIfNotExists([]byte(tTo))
		c, _ := dst.CreateBucketIfNotExists([]byte("content"))
		b, _ := c.CreateBucketIfNotExists([]byte("blob"))
		existing, _ := b.CreateBucket([]byte("sha256:aaa"))
		l, _ := existing.CreateBucket([]byte("labels"))
		return l.Put([]byte("category"), []byte("preexisting"))
	}))
	db.Close()

	err = portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	got := destBlobDigests(t, dbPath)
	assert.Len(t, got, 3, "all 3 digests should now be in dest")
	// The preexisting entry must NOT have been overwritten.
	assert.Equal(t, "preexisting", destBlobLabel(t, dbPath, "sha256:aaa", "category"),
		"existing destination record should be left untouched")
	// The freshly-ported entries should have the seeded value.
	assert.Equal(t, "test", destBlobLabel(t, dbPath, "sha256:bbb", "category"))
	assert.Equal(t, "test", destBlobLabel(t, dbPath, "sha256:ccc", "category"))
}

// TestPortContainerdNamespace_RealOnDevicePathLayout exercises the actual
// on-device path layout: a persistDir whose vault/containerd/ subtree
// contains an io.containerd.metadata.v1.bolt/ DIRECTORY (containerd 1.x's
// metadata-plugin layout), with the bolt meta.db file INSIDE that
// directory. Regression guard against the v8 bug where the converter
// constructed dbPath = .../io.containerd.metadata.v1.bolt (the dir) and
// bolt.Open failed with EISDIR, silently no-op'ing the whole port and
// leaving the sentinel un-written.
func TestPortContainerdNamespace_RealOnDevicePathLayout(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	// Mirror the on-device tree under /persist/.
	dbDir := filepath.Join(dir, "vault", "containerd",
		"io.containerd.metadata.v1.bolt")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	dbPath := userContainerdBoltDBPath(dir)
	sentinelPath := userContainerdPortSentinelPath(dir)
	// Confirm path helpers point at the expected on-device layout.
	assert.Equal(t,
		filepath.Join(dir, "vault", "containerd",
			"io.containerd.metadata.v1.bolt", "meta.db"),
		dbPath)
	assert.Equal(t,
		filepath.Join(dir, "vault", "containerd",
			".eve-namespace-port-done"),
		sentinelPath)
	// Seed the meta.db file with source-namespace blobs.
	seedSourceBlobs(t, dbPath, []string{"sha256:aaa", "sha256:bbb"})
	// The dbPath we used above must really be a regular file, not a dir.
	st, err := os.Stat(dbPath)
	assert.NoError(t, err)
	assert.False(t, st.IsDir(), "%s must be a file, not a dir", dbPath)

	err = portContainerdNamespace(dbPath, sentinelPath, tFrom, tTo)
	assert.NoError(t, err)
	// Sentinel landed at the expected path under /persist/vault/containerd/.
	_, statErr := os.Stat(sentinelPath)
	assert.NoError(t, statErr)
	// Records were ported.
	got := destBlobDigests(t, dbPath)
	assert.True(t, got["sha256:aaa"])
	assert.True(t, got["sha256:bbb"])
}

// TestPortContainerdNamespace_PortsImages verifies the IMAGES bucket gets
// copied alongside content/blob. Pillar's populateInitBlobStatus() depends
// on ListBlobsMediaTypes() walking from IMAGES (cas/containerd.go:170) to
// learn each blob's mediaType; without ported image entries, mediaTypes are
// unknown and populateInitBlobStatus skips every blob — defeating the whole
// purpose of porting the blob bucket. Regression guard against the v10 bug.
func TestPortContainerdNamespace_PortsImages(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	// Seed both blobs and images under the source namespace.
	seedSourceBlobs(t, dbPath, []string{"sha256:aaa"})
	seedSourceImages(t, dbPath, []string{
		"docker.io/lfedge/eden-eclient:7a72275",
		"docker.io/aaa-content/manifest",
	})

	err := portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)

	// Both buckets ported.
	gotBlobs := destBlobDigests(t, dbPath)
	assert.True(t, gotBlobs["sha256:aaa"])

	gotImages := destImageRefs(t, dbPath)
	assert.True(t, gotImages["docker.io/lfedge/eden-eclient:7a72275"])
	assert.True(t, gotImages["docker.io/aaa-content/manifest"])

	// Image target/digest + target/mediatype are preserved (recursive copy
	// into the target/ sub-bucket).
	assert.Equal(t, "sha256:adda3d3f",
		destImageTarget(t, dbPath, "docker.io/lfedge/eden-eclient:7a72275", "digest"))
	assert.Equal(t, "application/vnd.oci.image.manifest.v1+json",
		destImageTarget(t, dbPath, "docker.io/lfedge/eden-eclient:7a72275", "mediatype"))

	// EVEDownloadedLabel on the image survives — pillar's hvTypeKube
	// filter in populateInitBlobStatus blob.go:543 relies on this.
	assert.Equal(t, "true",
		destImageLabel(t, dbPath, "docker.io/lfedge/eden-eclient:7a72275", "eve-downloaded"))
}

// TestPortContainerdNamespace_BlobsOnlyNoImages exercises the case where the
// source namespace has blob records but no images bucket (e.g. a freshly-
// downloaded but not-yet-imported blob). Should port blobs cleanly with no
// error.
func TestPortContainerdNamespace_BlobsOnlyNoImages(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	seedSourceBlobs(t, dbPath, []string{"sha256:bbb"})
	// No seedSourceImages.

	err := portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	assert.True(t, destBlobDigests(t, dbPath)["sha256:bbb"])
	assert.Empty(t, destImageRefs(t, dbPath))
}

// TestPortContainerdNamespace_ImagesOnlyNoBlobs exercises the symmetric case —
// source has images but no blobs (unusual but possible if the test sequence
// only manipulates images). Both bucket-port loops should tolerate either
// side being absent.
func TestPortContainerdNamespace_ImagesOnlyNoBlobs(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	seedSourceImages(t, dbPath, []string{"docker.io/foo"})

	err := portContainerdNamespace(dbPath, sentinel, tFrom, tTo)
	assert.NoError(t, err)
	assert.Empty(t, destBlobDigests(t, dbPath))
	assert.True(t, destImageRefs(t, dbPath)["docker.io/foo"])
}

func TestPortContainerdNamespace_SecondRunIsNoop(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bolt.db")
	sentinel := filepath.Join(dir, "done")
	seedSourceBlobs(t, dbPath, []string{"sha256:aaa", "sha256:bbb"})

	// First run: ports.
	assert.NoError(t, portContainerdNamespace(dbPath, sentinel, tFrom, tTo))
	firstSet := destBlobDigests(t, dbPath)
	// Sentinel mtime captured.
	st1, err := os.Stat(sentinel)
	assert.NoError(t, err)

	// Sleep one filesystem tick so a re-create would have a visibly newer mtime.
	time.Sleep(10 * time.Millisecond)

	// Second run: sentinel exists → must short-circuit, must not touch the DB
	// or rewrite the sentinel.
	assert.NoError(t, portContainerdNamespace(dbPath, sentinel, tFrom, tTo))
	secondSet := destBlobDigests(t, dbPath)
	assert.Equal(t, firstSet, secondSet, "second run must not change destination")
	st2, err := os.Stat(sentinel)
	assert.NoError(t, err)
	assert.Equal(t, st1.ModTime(), st2.ModTime(),
		"second run must not rewrite the sentinel file")
}
