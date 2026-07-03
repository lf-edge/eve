// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// /config backup + restore for the persist shrink (design-doc requirements 3 & 4):
// if the shrink ever recreates /persist empty (fsck failure), the device must
// still come up on cellular, keep its ssh access, and retain its device-identity
// certs/keys in /persist/certs/ (attestation + credential decryption) so it can
// re-attest and recover its vault key from the controller. Those keys cannot be
// re-derived once the filesystem is wiped, so the critical files are copied to a
// small directory on the CONFIG partition before the destructive work, and
// restored into /persist afterwards if missing or changed.
//
// IMPORTANT: the --backup-dir/--flag-file paths must point at the CONFIG
// partition mounted READ-WRITE (find PARTLABEL=CONFIG, mount it rw, sync,
// unmount). At runtime EVE's /config is a read-only tmpfs RAM copy of that
// partition, so writes to the runtime /config land in RAM and are lost on the
// very reboot the shrink depends on. The caller owns that mount (see
// pkg/pillar/docs/diskconvert.md); these subcommands just read/write the paths
// they are given.
//
// Timing is also owned by the caller, because the files can only be read/written
// when /persist is mounted:
//   - `backup`  runs ONLINE (baseosmgr), /persist mounted, before the reboot.
//              It writes the backups first and the repartition-inprogress flag
//              file last. With --grow-only it writes only the flag (the grow is
//              non-destructive, so no /persist backup is needed).
//   - `shrink`  runs with /persist UNMOUNTED (storage-init), does the shrink.
//   - `restore` runs after /persist is mounted again. If the flag file is gone
//              it garbage-collects any leftover backup dir (so stray /config
//              files don't perturb the measure-config PCR). If the flag file is
//              present it restores the files the shrink lost — those missing,
//              empty, or invalid for their type (see needsRestore) — then (with
//              --cleanup) removes the flag file FIRST and the backup dir second,
//              so a crash mid-cleanup is safe.
//   - `cleanup` is the idempotent end-of-conversion sweep the caller runs after
//              ANY backup, independent of whether a restore ran. A crash during
//              restore's --cleanup can clear the flag file but leave the backup
//              dir behind; once the device reaches the steady `proceed` state
//              nothing re-runs restore to GC it, so the leftover dir would linger
//              and keep perturbing the measure-config PCR. cleanup removes the
//              backup dir, but only once the flag file is gone (while it is
//              present a shrink is still pending and the dir is the only copy of
//              the device-identity files).

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultBackupPatterns are globs relative to the persist root. They cover the
// state needed to reach the controller over cellular, keep ssh access, and
// preserve the device-identity certs/keys (attestation + credential decryption)
// even if /persist is recreated empty. The saved device UUID (OnboardingStatus)
// is included so cmd/client can take its already-onboarded shortcut and re-apply
// the checkpointed config with no controller reachable; without it the device
// would sit at onboarding offline after a recreate.
var defaultBackupPatterns = []string{
	"checkpoint/lastconfig*",             // saved EdgeDevConfig: ConfigItemValueMap (ssh keys) + network
	"checkpoint/controllercerts*",        // controller signing certs
	"certs/ecdh.*.pem",                   // ecdh key+cert: decrypt credentials
	"certs/attest.*.pem",                 // attestation key+cert
	"certs/ek.*.pem",                     // endorsement cert
	"status/nim/DevicePortConfigList",    // persisted DPC list: lastresort/cellular fallback
	"status/zedclient/OnboardingStatus*", // saved device UUID: cmd/client offline shortcut
}

// repartitionGrowOnly is the sentinel written to the repartition-inprogress flag
// file for the grow-only (no-shrink) path: storage-init skips the shrink and runs
// only the grow. Any other non-empty value is a shrink target size.
const repartitionGrowOnly = "grow-only"

func cmdBackup(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	persist := fs.String("persist", "/persist", "mounted persist root to back up from")
	backupDir := fs.String("backup-dir", "/config/backup-persist", "destination on /config")
	flagFile := fs.String("flag-file", "/config/repartition-inprogress", "repartition flag file to write last")
	target := fs.String("target", "", "shrink target size recorded in the flag file (e.g. 78G) (required unless --grow-only)")
	growOnly := fs.Bool("grow-only", false, "arm a grow-only repartition: write the grow-only sentinel and copy no backup (the grow is non-destructive)")
	_ = fs.Parse(args)

	// Grow-only: nothing destructive runs offline, so there is no /persist to back
	// up. Arm the flag with the sentinel; storage-init skips the shrink and runs
	// only the grow.
	if *growOnly {
		if err := writeFileAtomic(*flagFile, []byte(repartitionGrowOnly+"\n")); err != nil {
			fmt.Fprintln(os.Stderr, "backup: write flag file:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "armed grow-only repartition; wrote %s=%s\n", *flagFile, repartitionGrowOnly)
		return 0
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "backup: --target is required (or pass --grow-only)")
		return 2
	}
	if _, err := parseSize(*target); err != nil {
		fmt.Fprintln(os.Stderr, "backup: bad --target:", err)
		return 2
	}

	n, err := backupPersistFiles(*persist, *backupDir, defaultBackupPatterns)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup failed:", err)
		return 1
	}
	// Write the flag file LAST: the read side treats an absent/empty flag file as
	// "not started" and ignores a partial backup dir.
	if err := writeFileAtomic(*flagFile, []byte(*target+"\n")); err != nil {
		fmt.Fprintln(os.Stderr, "backup: write flag file:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "backed up %d file(s) to %s; wrote %s=%s\n", n, *backupDir, *flagFile, *target)
	return 0
}

func cmdRestore(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	persist := fs.String("persist", "/persist", "mounted persist root to restore into")
	backupDir := fs.String("backup-dir", "/config/backup-persist", "backup source on /config")
	flagFile := fs.String("flag-file", "/config/repartition-inprogress", "repartition flag file (gates restore; removed first on --cleanup)")
	cleanup := fs.Bool("cleanup", false, "after restoring, remove the flag file (first) and the backup dir")
	failureMarker := fs.String("failure-marker", "", "resize-failed.json to stamp with persist_recreated (optional)")
	persistRecreated := fs.Bool("persist-recreated", false, "record into --failure-marker that /persist was recreated from scratch")
	_ = fs.Parse(args)

	// The flag file gates the backup dir. If it is absent (conversion finished,
	// never started, or a crash cleared it), garbage-collect any leftover backup dir
	// WITHOUT restoring: stray files left in /config would otherwise be measured
	// into PCR 14 by measure-config and break the vault unseal on the next boot.
	if _, present := readFlagFile(*flagFile); !present {
		if err := os.RemoveAll(*backupDir); err != nil {
			fmt.Fprintln(os.Stderr, "restore: GC leftover backup dir:", err)
			return 1
		}
		return 0
	}

	restored, err := restorePersistFiles(*backupDir, *persist)
	if err != nil {
		fmt.Fprintln(os.Stderr, "restore failed:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "restored %d file(s) into %s\n", restored, *persist)

	// If /persist was recreated from scratch (the shrink corrupted it and the
	// P3-mount fsck reformatted it), record that in the failure marker so
	// baseosmgr can report the severity (workloads lost; only identity restored).
	// The marker is diagnostic, so a stamping failure must not fail the restore.
	if *persistRecreated && *failureMarker != "" {
		if err := stampPersistRecreated(*failureMarker); err != nil {
			fmt.Fprintln(os.Stderr, "restore: stamp persist_recreated:", err)
		}
	}

	if *cleanup {
		// Remove the flag file FIRST (the reverse of backup's flag-file-last
		// order): once the flag file is gone the backup dir is ignored, so a crash
		// between the two removals is safe (the next boot GCs the leftover dir, above).
		if err := os.Remove(*flagFile); err != nil && !os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "restore: remove flag file:", err)
			return 1
		}
		if err := os.RemoveAll(*backupDir); err != nil {
			fmt.Fprintln(os.Stderr, "restore: remove backup dir:", err)
			return 1
		}
	}
	return 0
}

// stampPersistRecreated sets "persist_recreated": true in the resize-failed.json
// marker at markerPath, preserving the fields storage-init's resize_abort already
// wrote (eve_release/step/rc/ts). baseosmgr reads this to report whether a failed
// conversion also wiped /persist (workloads lost) or left it intact.
func stampPersistRecreated(markerPath string) error {
	b, err := os.ReadFile(markerPath)
	if err != nil {
		return err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("parse %s: %w", markerPath, err)
	}
	m["persist_recreated"] = true
	out, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(markerPath, append(out, '\n'), 0o644)
}

func cmdCleanup(args []string) int {
	fs := flag.NewFlagSet("cleanup", flag.ExitOnError)
	backupDir := fs.String("backup-dir", "/config/backup-persist", "backup dir on /config to remove")
	flagFile := fs.String("flag-file", "/config/repartition-inprogress", "repartition flag file that must already be gone")
	_ = fs.Parse(args)

	// The flag file gates the backup dir, so it MUST already be gone: while it is
	// present a shrink is still pending and the backup dir holds the only copy of
	// the device-identity files, so removing it would be data loss. Refuse.
	if _, present := readFlagFile(*flagFile); present {
		fmt.Fprintf(os.Stderr, "cleanup: flag file %s still present; shrink unfinished, refusing to remove %s\n",
			*flagFile, *backupDir)
		return 1
	}
	// Idempotent: RemoveAll on an absent dir is a no-op, so the caller may run
	// this after every backup cycle regardless of whether a restore happened.
	if err := os.RemoveAll(*backupDir); err != nil {
		fmt.Fprintln(os.Stderr, "cleanup: remove backup dir:", err)
		return 1
	}
	return 0
}

// backupPersistFiles copies every file matching the patterns (relative to
// persist) into backupDir, preserving the relative path. Returns the file count.
func backupPersistFiles(persist, backupDir string, patterns []string) (int, error) {
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return 0, err
	}
	count := 0
	for _, p := range patterns {
		matches, err := filepath.Glob(filepath.Join(persist, p))
		if err != nil {
			return count, fmt.Errorf("glob %q: %w", p, err)
		}
		for _, m := range matches {
			rel, err := filepath.Rel(persist, m)
			if err != nil {
				return count, err
			}
			n, err := copyTree(m, filepath.Join(backupDir, rel))
			if err != nil {
				return count, err
			}
			count += n
		}
	}
	return count, nil
}

// restorePersistFiles walks backupDir and copies each file into persist at the
// same relative path when the live copy is missing, empty, or fails its content
// validity check (see needsRestore). Returns the number of files written.
func restorePersistFiles(backupDir, persist string) (int, error) {
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return 0, nil // nothing backed up
	}
	restored := 0
	err := filepath.Walk(backupDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(backupDir, path)
		if err != nil {
			return err
		}
		dst := filepath.Join(persist, rel)
		need, err := needsRestore(rel, dst)
		if err != nil {
			return err
		}
		if !need {
			return nil
		}
		if err := copyFileAtomic(path, dst); err != nil {
			return err
		}
		restored++
		return nil
	})
	return restored, err
}

// needsRestore reports whether the backed-up file should overwrite the live
// /persist copy at dst. The live copy is always restored when it is missing or
// empty (the shrink lost it). When it is present and non-empty we restore only
// if it fails a per-type validity check, because truncation can leave a
// non-empty but unusable file that the size check alone would miss:
//
//   - certs/keys (*.pem): a valid file ends each block with a "-----END" marker,
//     so its absence means a truncated/corrupt cert -> restore.
//   - the DevicePortConfigList (*.json): must parse as JSON; truncation always
//     yields invalid JSON -> restore.
//
// Other backed-up files (the saved config lastconfig/.bak and controllercerts)
// have no cheap standalone validator here and can be legitimately newer on the
// live /persist than in the (stale) backup, so a present non-empty copy is kept.
// pillar validates those itself and falls back to its .bak copies when one is
// truncated, and both copies are in the backup set for the wiped case.
func needsRestore(rel, dst string) (bool, error) {
	data, err := os.ReadFile(dst)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // missing
		}
		return false, err
	}
	if len(data) == 0 {
		return true, nil // empty / truncated to zero length
	}
	switch {
	case strings.HasSuffix(rel, ".pem"):
		return !bytes.Contains(data, []byte("-----END")), nil
	case strings.HasSuffix(rel, ".json"):
		return !json.Valid(data), nil
	default:
		return false, nil // present, non-empty, no validator -> keep the live copy
	}
}

// copyTree copies a file, or recursively a directory, from src to dst preserving
// structure. Returns the number of regular files copied.
func copyTree(src, dst string) (int, error) {
	info, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 1, copyFileAtomic(src, dst)
	}
	count := 0
	err = filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if err := copyFileAtomic(path, filepath.Join(dst, rel)); err != nil {
			return err
		}
		count++
		return nil
	})
	return count, err
}

// copyFileAtomic copies src to dst durably. The backed-up files are small, so it
// reads src fully and writes it through writeFileAtomic.
func copyFileAtomic(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, data)
}

// writeFileAtomic writes data to dst by streaming into a temp file in the same
// directory, fsyncing it, atomically renaming it into place, and fsyncing the
// directory. The rename means a crash leaves either the old file or the complete
// new one, never a truncated or zero-length file — critical because the shrink
// flag file gates a destructive repartition and the backup may be the only copy
// of the device-identity files. (The plain content fsync alone would still let a
// crash mid-write leave a partial file, and would not make the new directory
// entry durable.) Temp files are created 0o600, which suits the key material.
func writeFileAtomic(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a newly created or renamed entry in it is
// durable; a file's own fsync persists its data, not its directory entry.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
