// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// KubeSaveVarLib is the backup location on the persistent volume
// where /var/lib/ is snapshotted before a destructive cluster-mode
// transition. Lives under /persist/vault so the contents are
// encrypted at rest alongside the rest of kube state. Older EVE
// images wrote to /persist/kube-save-var-lib — MigrateVarLib
// relocates it on first boot after upgrade.
const KubeSaveVarLib = "/persist/vault/kube-save-var-lib"

// legacyKubeSaveVarLib is the pre-vault location. Read-only —
// MigrateVarLib copies its contents to KubeSaveVarLib and removes
// the source. New writes go straight to KubeSaveVarLib.
const legacyKubeSaveVarLib = "/persist/kube-save-var-lib"

// MigrateVarLib relocates a pre-vault kube-save-var-lib backup to
// the new vault-backed location, then removes the legacy directory.
// No-op when either (a) the legacy directory does not exist or (b)
// the new location already has content (a prior boot already
// migrated). Vault must be available before this is called.
//
// The copy is recursive because src and dst may sit on different
// filesystems (legacy ext4 vs vault). copyTree preserves symlinks
// and permission bits.
//
// Addresses upstream commit 647a03b2d ("Move kube-save-var-lib
// under vault").
func MigrateVarLib() error {
	if _, err := os.Stat(legacyKubeSaveVarLib); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", legacyKubeSaveVarLib, err)
	}
	// If the vault location already exists, the migration ran on a
	// prior boot. Just remove the legacy directory so we don't keep
	// rechecking it forever.
	if _, err := os.Stat(KubeSaveVarLib); err == nil {
		log.Printf("state: legacy and vault kube-save-var-lib both present; "+
			"removing legacy %s", legacyKubeSaveVarLib)
		return os.RemoveAll(legacyKubeSaveVarLib)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", KubeSaveVarLib, err)
	}

	log.Printf("state: migrating kube-save-var-lib %s -> %s",
		legacyKubeSaveVarLib, KubeSaveVarLib)
	if err := copyTree(legacyKubeSaveVarLib+"/.",
		KubeSaveVarLib+"/", "migrate"); err != nil {
		return err
	}
	if err := os.RemoveAll(legacyKubeSaveVarLib); err != nil {
		// Migration succeeded; legacy cleanup failure is
		// recoverable (next boot will see both and re-clean).
		log.Printf("WARNING: state: remove legacy %s after migrate: %v",
			legacyKubeSaveVarLib, err)
	}
	return nil
}

// SaveVarLib snapshots /var/lib/ to KubeSaveVarLib so a destructive
// cluster-mode transition can be rolled back. The contents are
// staged into a `<dst>.tmp` directory and renamed into place on
// success — a failed cp does not leave a half-populated backup that
// a later RestoreVarLib could silently apply.
//
// Returns an error wrapping os.ErrNotExist if /var/lib itself is
// missing — callers should treat that as "nothing to save".
func SaveVarLib() error {
	return saveVarLibTo("/var/lib", KubeSaveVarLib)
}

// RestoreVarLib copies the contents of KubeSaveVarLib back into
// /var/lib/. Returns an error that unwraps to os.ErrNotExist if the
// backup directory does not exist — callers should treat that as
// "nothing to restore" rather than a hard failure.
func RestoreVarLib() error {
	return restoreVarLibFrom(KubeSaveVarLib, "/var/lib")
}

// longhornReplicaDir holds Longhorn's replica data for this node,
// under its default disk path (/persist/vault/volumes).
const longhornReplicaDir = "/persist/vault/volumes/replicas"

// WipeOrphanedReplicas empties the Longhorn replica directory. Called
// on the cluster→single boot, immediately after RestoreVarLib.
//
// The restored /var/lib predates this node's cluster membership, so
// Longhorn's metadata in it has no record of any replica created while
// the node was a member — but the replica directories are on /persist
// and survive the rollback. Left in place they are unreferenced by any
// volume: dead weight on the persist partition that nothing will ever
// reclaim, sitting on the disk Longhorn is about to re-inventory.
//
// The directory itself is kept (Longhorn's default disk points at its
// parent and must stay stattable), only its contents go. A missing
// directory is not an error — a node converted before Longhorn ever
// came up has nothing to clean.
func WipeOrphanedReplicas() error {
	return wipeReplicasIn(longhornReplicaDir)
}

// wipeReplicasIn is WipeOrphanedReplicas with an injectable path.
func wipeReplicasIn(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}

	var joined error
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if rmErr := os.RemoveAll(p); rmErr != nil {
			joined = errors.Join(joined, fmt.Errorf("remove %s: %w", p, rmErr))
		}
	}
	if joined != nil {
		return joined
	}
	if len(entries) > 0 {
		log.Printf("wiped %d unreferenced Longhorn replica(s) from %s",
			len(entries), dir)
	}
	return nil
}

// varLibStatePaths are the /var/lib subtrees that carry real node
// identity and must survive a cluster→single rollback. Everything else
// under /var/lib is re-derivable: rancher/k3s/server/data (the unpacked
// k3s bundle), cni (CNI binaries) and k3s (k3s binaries) account for
// ~419MB of a ~443MB tree and are reproduced by the install path.
//
// Copied live: each of these is written once at k3s init and does not
// churn afterwards, so no quiesce is needed. Missing entries are
// skipped — a node that never got as far as writing one has no state
// there to preserve.
// Audited against a live first-boot node. Everything else present under
// /var/lib there is deliberately excluded:
//
//	server/etc         k3s regenerates egress-selector/cloud-config from
//	                   the config drop-ins; a stale copy could contradict
//	                   a changed config.
//	server/manifests   auto-deploy manifests, re-staged from the image.
//	server/static      static pod manifests, likewise.
//	longhorn/          engine-binaries + a socket dir, extracted from the
//	                   Longhorn image on demand.
//	kubelet/           runtime only, and restoring it is worse than not:
//	                   prereqs already deletes stale cpu_manager_state on
//	                   boot precisely because carrying it over breaks
//	                   kubelet.
//	kubevirt-node-labeller/, cni/, k3s/, rancher/k3s/server/data
//	                   re-derivable.
var varLibStatePaths = []string{
	"rancher/k3s/server/tls",         // server + CA certs
	"rancher/k3s/server/cred",        // node password, ipsec psk
	"rancher/k3s/server/token",       // cluster token
	"rancher/k3s/server/node-token",  // symlink -> token
	"rancher/k3s/server/agent-token", // symlink -> token
	"rancher/k3s/agent",              // node identity: client certs + kubeconfigs
}

// varLibMarkerGlob matches the component markers kube-init keeps at the
// top of /var/lib (all_components_initialized, longhorn_initialized,
// node-labels-initialized, …). They are part of the restored state:
// the snapshot is taken before they are written, so a restored tree
// reads "components installed, not yet initialized".
const varLibMarkerGlob = "*initialized"

// kineDBRelPath is the kine datastore, the one file that IS written
// continuously and therefore cannot be copied byte-for-byte under a
// live writer. Snapshotted with SQLite's online-consistent copy instead.
//
// Note this is kine/SQLite, not etcd: server/db/etcd/ is a vestigial
// stub holding only "name" on a single-node server, so `k3s
// etcd-snapshot` does not apply here. Re-check if EVE ever moves
// single-node k3s to embedded etcd.
const kineDBRelPath = "rancher/k3s/server/db/state.db"

// clusterOnlyVarLibPaths are artifacts a cluster-mode k3s leaves behind
// that must NOT survive a rollback to single-node. The restore is an
// overlay copy, so anything the snapshot does not contain stays on disk
// unless it is removed explicitly.
//
// server/db/etcd matters most: in cluster mode k3s runs embedded etcd
// and writes a real member/ directory there. Leaving it next to a
// restored kine datastore gives k3s two conflicting datastores, and it
// also makes etcdClusterInitialized() (k3s/config.go) report a
// bootstrapped cluster that no longer exists.
var clusterOnlyVarLibPaths = []string{
	"rancher/k3s/server/db/etcd",

	// The datastore's write-ahead log and shared-memory index belong to
	// the cluster-mode database, not to the one we just restored over
	// it. SQLite treats a -wal sitting next to a database as that
	// database's own journal and replays it on open, so leaving them
	// here feeds pages from the old datastore into the new one: the
	// restored file grows past its snapshot size, integrity_check
	// reports "invalid page number", and k3s dies with "database disk
	// image is malformed" on every start with no way back.
	//
	// Observed 2026-08-02 on edge-dev3: the snapshot passed
	// integrity_check while the restored copy failed it, and the file
	// was 18403328 bytes against the snapshot's 17821696.
	//
	// The snapshot never contains these — VACUUM INTO writes a single
	// self-contained file — so removing them is unconditional.
	"rancher/k3s/server/db/state.db-wal",
	"rancher/k3s/server/db/state.db-shm",
	"rancher/k3s/server/db/state.db-journal",
}

// saveVarLibTo / restoreVarLibFrom are the inner halves of the
// public pair, with paths injected so tests can run against temp
// dirs.
func saveVarLibTo(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("save /var/lib: source %s missing: %w",
				src, err)
		}
		return fmt.Errorf("stat source %s: %w", src, err)
	}
	staging := dst + ".tmp"
	// Wipe any prior staging dir so a previous failed run doesn't
	// contaminate this one.
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("save: clean staging %s: %w", staging, err)
	}
	if err := saveVarLibState(src, staging); err != nil {
		// Make sure we don't leak a half-populated staging dir on
		// failure — RestoreVarLib must never see one.
		_ = os.RemoveAll(staging)
		return err
	}
	// Atomic-ish swap: remove old backup, rename staging into place.
	if err := os.RemoveAll(dst); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("save: remove prior backup %s: %w", dst, err)
	}
	if err := os.Rename(staging, dst); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("save: rename %s -> %s: %w", staging, dst, err)
	}
	return nil
}

// saveVarLibState populates staging with the state-only snapshot: the
// varLibStatePaths subtrees, the top-level markers, and an
// online-consistent copy of the kine datastore.
func saveVarLibState(src, staging string) error {
	if err := os.MkdirAll(staging, 0700); err != nil {
		return fmt.Errorf("save: mkdir staging %s: %w", staging, err)
	}
	for _, rel := range varLibStatePaths {
		from := filepath.Join(src, rel)
		fi, err := os.Lstat(from)
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("state: save: %s absent, skipping", rel)
			continue
		}
		if err != nil {
			return fmt.Errorf("save: stat %s: %w", rel, err)
		}
		to := filepath.Join(staging, rel)
		if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
			return fmt.Errorf("save: mkdir %s: %w", filepath.Dir(to), err)
		}
		if fi.IsDir() {
			if err := copyTree(from+"/.", to+"/", "save"); err != nil {
				return err
			}
			continue
		}
		if _, err := copyEntry(from, to, fs.FileInfoToDirEntry(fi)); err != nil {
			return fmt.Errorf("save: copy %s: %w", rel, err)
		}
	}

	markers, err := filepath.Glob(filepath.Join(src, varLibMarkerGlob))
	if err != nil {
		return fmt.Errorf("save: glob markers: %w", err)
	}
	for _, m := range markers {
		fi, err := os.Lstat(m)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		to := filepath.Join(staging, filepath.Base(m))
		if err := copyFileContents(m, to, fi.Mode().Perm()); err != nil {
			return fmt.Errorf("save: copy marker %s: %w", filepath.Base(m), err)
		}
	}

	db := filepath.Join(src, kineDBRelPath)
	if _, err := os.Stat(db); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No kine datastore: either k3s never reached the point of
			// creating one, or this server is on embedded etcd. Nothing
			// to snapshot here either way.
			log.Printf("state: save: %s absent, skipping datastore copy",
				kineDBRelPath)
			return nil
		}
		return fmt.Errorf("save: stat datastore: %w", err)
	}
	to := filepath.Join(staging, kineDBRelPath)
	if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
		return fmt.Errorf("save: mkdir %s: %w", filepath.Dir(to), err)
	}
	if err := sqliteVacuumInto(db, to); err != nil {
		return fmt.Errorf("save: snapshot datastore: %w", err)
	}
	return nil
}

// sqliteVacuumInto writes an online-consistent copy of the SQLite
// database at src to dst. Declared as a var so tests can stub it.
//
// VACUUM INTO runs inside a read transaction, so the result is a
// point-in-time image even while k3s writes — that is what lets the
// snapshot run without stopping k3s. It also compacts, so the copy is
// smaller than the live file.
//
// Shelling out to sqlite3 keeps kube-init a static CGO_ENABLED=0 binary:
// the cgo driver would force dynamic linking and the pure-Go one is a
// very large vendor addition, both for a single statement.
var sqliteVacuumInto = func(src, dst string) error {
	// dst must not exist — VACUUM INTO refuses to overwrite.
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear %s: %w", dst, err)
	}
	// busy_timeout so a concurrent kine write cannot fail the snapshot
	// outright; VACUUM INTO only needs a read lock, so this is a margin
	// against lock churn rather than an expected wait.
	cmd := exec.Command("sqlite3", "-cmd", ".timeout 60000", src,
		fmt.Sprintf("VACUUM INTO '%s'", dst))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sqlite3 VACUUM INTO %s: %w (output: %s)",
			dst, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func restoreVarLibFrom(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("restore /var/lib: backup %s missing: %w",
				src, err)
		}
		return fmt.Errorf("stat backup dir %s: %w", src, err)
	}
	if err := copyTree(src+"/.", dst+"/", "restore"); err != nil {
		return err
	}
	// The copy above is an overlay: it replaces what the snapshot holds
	// and leaves everything else — including cluster-mode artifacts the
	// single-node tree must not inherit.
	for _, rel := range clusterOnlyVarLibPaths {
		p := filepath.Join(dst, rel)
		if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
			continue
		}
		log.Printf("state: restore: removing cluster-mode artifact %s", rel)
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("restore: remove %s: %w", rel, err)
		}
	}
	return nil
}

// volatileVarLibPaths are trees whose contents are recreated at runtime
// and are worthless in a snapshot. multus writes one result file per pod
// interface, so entries appear and vanish continuously — copying that
// directory is both pointless and the likeliest source of a
// vanished-file race.
var volatileVarLibPaths = []string{
	"cni/multus/results",
	"cni/results",
}

// copyTree recursively copies src's contents into dst, preserving mode,
// ownership, timestamps and symlinks. src is given with a trailing `/.`
// by callers, matching the cp(1) content-only idiom; it is trimmed here.
//
// /var/lib is live while the snapshot runs, so an entry can disappear
// between readdir and open. Such an entry is skipped rather than failing
// the whole copy — `cp -a` treated it as fatal, which meant a single pod
// teardown mid-snapshot lost the entire backup while the caller went on
// to write the initialized marker.
//
// Sockets, fifos and device nodes are skipped: their content cannot be
// copied meaningfully and whatever owns them recreates them on restore.
//
// op is "save" / "restore" — it ends up in log lines so the two call
// sites are distinguishable in journalctl.
//
// The destination root is created at mode 0700 because /var/lib carries
// secrets (k3s tokens, kubeconfigs) and the backup must not be more
// permissive than the live tree.
func copyTree(src, dst, op string) error {
	src = strings.TrimSuffix(strings.TrimSuffix(src, "."), "/")
	dst = strings.TrimSuffix(dst, "/")
	log.Printf("state: %s tree %s -> %s", op, src, dst)
	if err := os.MkdirAll(dst, 0700); err != nil {
		return fmt.Errorf("%s: mkdir %s: %w", op, dst, err)
	}

	skipped := 0
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Only a descendant may legitimately vanish. A missing root
			// means the caller asked to copy something that is not
			// there, and reporting success would have
			// restoreVarLibFrom claim it restored an absent backup.
			if errors.Is(err, fs.ErrNotExist) && path != src {
				skipped++
				return nil
			}
			return err
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		if slices.Contains(volatileVarLibPaths, filepath.ToSlash(rel)) {
			return fs.SkipDir
		}

		target := filepath.Join(dst, rel)
		copied, cErr := copyEntry(path, target, d)
		if cErr != nil {
			if errors.Is(cErr, fs.ErrNotExist) {
				// Vanished under us; nothing to preserve.
				skipped++
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return fmt.Errorf("%s: %w", rel, cErr)
		}
		if !copied && d.IsDir() {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%s: copy %s -> %s: %w", op, src, dst, err)
	}
	if skipped > 0 {
		log.Printf("state: %s tree %s -> %s done (%d entry/entries vanished mid-copy)",
			op, src, dst, skipped)
		return nil
	}
	log.Printf("state: %s tree %s -> %s done", op, src, dst)
	return nil
}

// copyEntry reproduces one directory entry at target. The bool reports
// whether the entry was reproduced; false means it was deliberately
// skipped (a socket, fifo or device node).
func copyEntry(path, target string, d fs.DirEntry) (bool, error) {
	info, err := d.Info()
	if err != nil {
		return false, err
	}

	switch {
	case d.IsDir():
		if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
			return false, err
		}
	case info.Mode()&fs.ModeSymlink != 0:
		link, err := os.Readlink(path)
		if err != nil {
			return false, err
		}
		// A stale target from an earlier pass must not make this fail.
		if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		if err := os.Symlink(link, target); err != nil {
			return false, err
		}
		// Timestamps and mode do not apply to the link itself; only
		// ownership is preserved, and lchown needs the raw syscall.
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = os.Lchown(target, int(st.Uid), int(st.Gid))
		}
		return true, nil
	case info.Mode().IsRegular():
		if err := copyFileContents(path, target, info.Mode().Perm()); err != nil {
			return false, err
		}
	default:
		// Socket, fifo or device node.
		return false, nil
	}

	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Lchown(target, int(st.Uid), int(st.Gid)); err != nil &&
			!errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil &&
		!errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, nil
}

func copyFileContents(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// O_CREATE honours umask, so set the mode explicitly.
	return os.Chmod(dst, perm)
}
