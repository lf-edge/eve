// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	bolt "go.etcd.io/bbolt"
)

// portContainerdNamespaceForKube ports user-containerd content-blob metadata
// records from the EVE-kvm namespace ("eve-user-apps") to the EVE-k namespace
// ("k8s.io") in the user containerd's bolt metadata DB.
//
// Why: pillar's containerd client switches its namespace from "eve-user-apps"
// to "k8s.io" on EVE-k boot (see pkg/pillar/containerd/containerd.go init()).
// The user containerd's content store at /persist/vault/containerd survives
// the kvm->k upgrade — blob files at .../sha256/<digest> are intact and the
// bolt metadata DB still records them — but only under "eve-user-apps". From
// pillar's "k8s.io" view the store appears empty, so any ContentTree it tries
// to process triggers a full re-download from the registry, overwriting the
// on-disk blob with bit-identical content.
//
// This handler runs in the post-vault phase, after /persist/vault is decrypted
// but before the user containerd has been started (k3s starts it later via
// pkg/kube/cluster-init.sh). With containerd idle, it is safe to mutate the
// bolt DB directly.
//
// The port is metadata-only: each blob record under v1/eve-user-apps/content/
// blob/<digest>/ gets copied into v1/k8s.io/content/blob/<digest>/. No HTTP
// fetch, no blob copy. Idempotent — skips digests already present in the
// destination namespace. A sentinel file at /persist/vault/containerd/
// .eve-namespace-port-done short-circuits subsequent boots.
//
// No-op on EVE-kvm (only relevant on the post-upgrade EVE-k boot).
func portContainerdNamespaceForKube(ctx *ucContext) error {
	if !base.IsHVTypeKube() {
		log.Functionf("portContainerdNamespaceForKube: not EVE-k, skipping")
		return nil
	}
	return portContainerdNamespace(
		userContainerdBoltDBPath(ctx.persistDir),
		userContainerdPortSentinelPath(ctx.persistDir),
		ctrdKvmNamespace, ctrdKubeNamespace)
}

// userContainerdBoltDBPath returns the path of the user containerd's bolt
// metadata DB. containerd's metadata plugin stores it at
// <root>/io.containerd.metadata.v1.bolt/meta.db — note that the
// io.containerd.metadata.v1.bolt component is a *directory* (the plugin's
// own root), not the bolt file itself. Verified on
// /persist/vault/containerd/io.containerd.metadata.v1.bolt/meta.db in
// EVE 16.x; matches containerd 1.x's metadata.Plugin layout.
func userContainerdBoltDBPath(persistDir string) string {
	return filepath.Join(persistDir, "vault", "containerd",
		"io.containerd.metadata.v1.bolt", "meta.db")
}

// userContainerdPortSentinelPath returns the path of the sentinel file that
// records whether the namespace port has already run.
func userContainerdPortSentinelPath(persistDir string) string {
	return filepath.Join(persistDir, "vault", "containerd",
		".eve-namespace-port-done")
}

// Pillar's user-containerd namespace names. Mirror the constants in
// pkg/pillar/containerd/containerd.go (ctrdServicesNamespace,
// ctrdKubeServicesNamespace) — duplicated here to avoid an import cycle
// (the containerd package depends on types/pubsub, which this package
// also uses, and pulling in containerd here would also drag in the
// containerd client library at upgradeconverter link time).
const (
	ctrdKvmNamespace  = "eve-user-apps"
	ctrdKubeNamespace = "k8s.io"
)

// portContainerdNamespace is the testable core: open the bolt DB at dbPath,
// copy content/blob and images records from the kvm namespace to the kube
// namespace, and write a sentinel at sentinelPath on success. If the
// sentinel already exists, this is a no-op. If the DB does not exist, the
// sentinel is written and no other work is done.
//
// We port TWO buckets, not just blobs:
//   - v1/<ns>/content/blob/<digest> — the blob metadata (labels carry GC
//     refs and the EVEDownloadedLabel pillar checks).
//   - v1/<ns>/images/<ref>         — pillar's CAS treats images as the GC
//     roots and as the source of digest→mediaType lookups. Pillar's
//     populateInitBlobStatus() (cmd/volumemgr/blob.go) gets media types
//     by walking images via ListBlobsMediaTypes() (cas/containerd.go:170),
//     not blobs directly. Without the images bucket, blobs are visible
//     but their media types are unknown, so populateInitBlobStatus
//     skips them with "could not get mediaType" — the same end result
//     as if they weren't ported at all (re-download).
func portContainerdNamespace(dbPath, sentinelPath, fromNamespace, toNamespace string) error {
	const schemaVersion = "v1"
	if _, err := os.Stat(sentinelPath); err == nil {
		log.Functionf("portContainerdNamespace: sentinel %s exists, skipping",
			sentinelPath)
		return nil
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Fresh install — no prior kvm boot left a bolt DB. Mark done so we
		// don't probe every boot.
		log.Noticef("portContainerdNamespace: %s does not exist (fresh install); marking done",
			dbPath)
		return writeSentinel(sentinelPath)
	}

	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("portContainerdNamespace: open %s: %w", dbPath, err)
	}
	defer db.Close()

	type subPath struct {
		// Path components from the namespace bucket down to the bucket
		// whose direct children we walk (one bucket per key).
		path []string
		// Human name used in log messages.
		label string
	}
	subPaths := []subPath{
		{path: []string{"content", "blob"}, label: "blob"},
		{path: []string{"images"}, label: "image"},
	}

	totals := map[string][2]int{} // label → {ported, skipped}
	err = db.Update(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte(schemaVersion))
		if v1 == nil {
			log.Noticef("portContainerdNamespace: schema bucket %q absent; nothing to port",
				schemaVersion)
			return nil
		}
		src := v1.Bucket([]byte(fromNamespace))
		if src == nil {
			log.Noticef("portContainerdNamespace: source namespace %q absent; nothing to port",
				fromNamespace)
			return nil
		}
		dst, err := v1.CreateBucketIfNotExists([]byte(toNamespace))
		if err != nil {
			return fmt.Errorf("create %q namespace: %w", toNamespace, err)
		}
		for _, sp := range subPaths {
			ported, skipped, err := portSubBucket(src, dst, sp.path, sp.label)
			if err != nil {
				return err
			}
			totals[sp.label] = [2]int{ported, skipped}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("portContainerdNamespace: %w", err)
	}

	for _, sp := range subPaths {
		t := totals[sp.label]
		log.Noticef("portContainerdNamespace: ported %d %s record(s) from %q to %q (%d already present)",
			t[0], sp.label, fromNamespace, toNamespace, t[1])
	}
	return writeSentinel(sentinelPath)
}

// portSubBucket walks src/<path...>/<key> and copies each <key>'s sub-bucket
// (recursively, including the labels/ sub-bucket containerd uses for GC refs
// and the EVEDownloadedLabel) into dst/<path...>/<key>. Returns ported and
// skipped counts. If the source path doesn't exist, returns (0,0,nil) — the
// namespace may legitimately have only blobs or only images.
func portSubBucket(src, dst *bolt.Bucket, path []string, label string) (int, int, error) {
	cur := src
	for _, p := range path {
		next := cur.Bucket([]byte(p))
		if next == nil {
			log.Functionf("portSubBucket: source has no %s/%s bucket; nothing to port",
				path[0], label)
			return 0, 0, nil
		}
		cur = next
	}
	srcLeaf := cur
	dstCur := dst
	for _, p := range path {
		next, err := dstCur.CreateBucketIfNotExists([]byte(p))
		if err != nil {
			return 0, 0, fmt.Errorf("create dst %s: %w", p, err)
		}
		dstCur = next
	}
	dstLeaf := dstCur
	var ported, skipped int
	err := srcLeaf.ForEach(func(key, _ []byte) error {
		if dstLeaf.Bucket(key) != nil {
			skipped++
			return nil
		}
		srcSub := srcLeaf.Bucket(key)
		if srcSub == nil {
			// Unexpected key shape — skip, don't fail the whole port.
			return nil
		}
		dstSub, err := dstLeaf.CreateBucket(key)
		if err != nil {
			return fmt.Errorf("create dst %s bucket %s: %w", label, key, err)
		}
		if err := copyBucket(srcSub, dstSub); err != nil {
			return fmt.Errorf("copy %s %s: %w", label, key, err)
		}
		ported++
		return nil
	})
	return ported, skipped, err
}

// copyBucket copies every key/value pair from src into dst, recursing into
// sub-buckets. dst is expected to be freshly created and empty.
func copyBucket(src, dst *bolt.Bucket) error {
	return src.ForEach(func(k, v []byte) error {
		if v == nil {
			// Sub-bucket
			srcSub := src.Bucket(k)
			if srcSub == nil {
				return nil
			}
			dstSub, err := dst.CreateBucket(k)
			if err != nil {
				return fmt.Errorf("create sub-bucket %s: %w", k, err)
			}
			return copyBucket(srcSub, dstSub)
		}
		return dst.Put(k, v)
	})
}

func writeSentinel(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("write sentinel %s: %w", path, err)
	}
	return f.Close()
}
