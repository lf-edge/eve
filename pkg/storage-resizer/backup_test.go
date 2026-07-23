// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// the critical files a real EVE /persist would hold (verified paths/names).
// The PEM certs carry a "-----END" marker so they pass the restore validity
// check; the DPCL is valid JSON.
var persistFixture = map[string]string{
	"checkpoint/lastconfig":                       "edgedevconfig-with-ssh-keys",
	"checkpoint/lastconfig.bak":                   "edgedevconfig-backup",
	"checkpoint/controllercerts":                  "controller-signing-certs",
	"certs/ecdh.key.pem":                          "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n",
	"certs/ecdh.cert.pem":                         "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n",
	"certs/attest.cert.pem":                       "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n",
	"certs/ek.cert.pem":                           "-----BEGIN CERTIFICATE-----\nDDDD\n-----END CERTIFICATE-----\n",
	"status/nim/DevicePortConfigList/global.json": `{"dpc":"cellular-fallback"}`,
	// a file that must NOT be backed up (not in the patterns)
	"vault/volumes/app1.qcow2": "big-app-volume",
	"newlog/keep/log.gz":       "logs",
}

func writePersist(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		mustWrite(t, filepath.Join(root, rel), content)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}

// backedUpRels is the set of fixture paths the patterns should select.
var backedUpRels = []string{
	"checkpoint/lastconfig", "checkpoint/lastconfig.bak", "checkpoint/controllercerts",
	"certs/ecdh.key.pem", "certs/ecdh.cert.pem", "certs/attest.cert.pem", "certs/ek.cert.pem",
	"status/nim/DevicePortConfigList/global.json",
}

func TestBackupSelectsTheRightFiles(t *testing.T) {
	persist := t.TempDir()
	backup := filepath.Join(t.TempDir(), "backup-persist")
	writePersist(t, persist, persistFixture)

	n, err := backupPersistFiles(persist, backup, defaultBackupPatterns)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if n != len(backedUpRels) {
		t.Errorf("backed up %d files, want %d", n, len(backedUpRels))
	}
	for _, rel := range backedUpRels {
		if _, err := os.Stat(filepath.Join(backup, rel)); err != nil {
			t.Errorf("missing from backup: %s (%v)", rel, err)
		}
	}
	// the non-pattern files must NOT be backed up
	for _, rel := range []string{"vault/volumes/app1.qcow2", "newlog/keep/log.gz"} {
		if _, err := os.Stat(filepath.Join(backup, rel)); err == nil {
			t.Errorf("%s should not have been backed up", rel)
		}
	}
}

func TestRestoreIntoWipedPersist(t *testing.T) {
	persist := t.TempDir()
	backup := filepath.Join(t.TempDir(), "backup-persist")
	writePersist(t, persist, persistFixture)
	if _, err := backupPersistFiles(persist, backup, defaultBackupPatterns); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// simulate fsck failure: /persist recreated empty
	wiped := t.TempDir()

	restored, err := restorePersistFiles(backup, wiped)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored != len(backedUpRels) {
		t.Errorf("restored %d, want %d", restored, len(backedUpRels))
	}
	for _, rel := range backedUpRels {
		got, err := os.ReadFile(filepath.Join(wiped, rel))
		if err != nil {
			t.Errorf("not restored: %s (%v)", rel, err)
			continue
		}
		if string(got) != persistFixture[rel] {
			t.Errorf("%s content = %q, want %q", rel, got, persistFixture[rel])
		}
	}
}

// Mutable files (lastconfig, controllercerts) are kept when present and
// non-empty — they may be a legitimately newer version the stale backup must not
// clobber — and restored only when missing or empty.
func TestRestoreKeepsNewerMutableFiles(t *testing.T) {
	persist := t.TempDir()
	backup := filepath.Join(t.TempDir(), "backup-persist")
	writePersist(t, persist, persistFixture)
	if _, err := backupPersistFiles(persist, backup, defaultBackupPatterns); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// lastconfig was updated after the backup: a non-empty, legitimately newer file.
	newer := "edgedevconfig-NEWER-than-backup"
	mustWrite(t, filepath.Join(persist, "checkpoint/lastconfig"), newer)
	// controllercerts went missing entirely.
	mustRemove(t, filepath.Join(persist, "checkpoint/controllercerts"))

	restored, err := restorePersistFiles(backup, persist)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored != 1 {
		t.Errorf("restored %d, want 1 (only the missing controllercerts)", restored)
	}
	if got, _ := os.ReadFile(filepath.Join(persist, "checkpoint/lastconfig")); string(got) != newer {
		t.Errorf("newer lastconfig was clobbered by the stale backup: got %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(persist, "checkpoint/controllercerts")); string(got) != persistFixture["checkpoint/controllercerts"] {
		t.Errorf("missing controllercerts not restored")
	}
}

// Files with a format validator are restored when the live copy is non-empty but
// malformed (truncation the size check alone would miss): a cert without its
// "-----END" marker, or a DPCL that is not valid JSON.
func TestRestoreRepairsTruncatedValidatedFiles(t *testing.T) {
	persist := t.TempDir()
	backup := filepath.Join(t.TempDir(), "backup-persist")
	writePersist(t, persist, persistFixture)
	if _, err := backupPersistFiles(persist, backup, defaultBackupPatterns); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// ecdh key truncated: non-empty but missing the END marker -> restore.
	mustWrite(t, filepath.Join(persist, "certs/ecdh.key.pem"), "-----BEGIN EC PRIVATE KEY-----\nAAA")
	// DPCL truncated: non-empty but invalid JSON -> restore.
	mustWrite(t, filepath.Join(persist, "status/nim/DevicePortConfigList/global.json"), `{"dpc":`)
	// attest cert went missing -> restore.
	mustRemove(t, filepath.Join(persist, "certs/attest.cert.pem"))
	// ek.cert.pem and ecdh.cert.pem are intact (have END) -> kept.

	restored, err := restorePersistFiles(backup, persist)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored != 3 {
		t.Errorf("restored %d, want 3 (truncated key + invalid JSON + missing cert)", restored)
	}
	for _, rel := range []string{"certs/ecdh.key.pem", "status/nim/DevicePortConfigList/global.json", "certs/attest.cert.pem"} {
		if got, _ := os.ReadFile(filepath.Join(persist, rel)); string(got) != persistFixture[rel] {
			t.Errorf("%s not restored to the backup copy", rel)
		}
	}
}

func TestRestoreNoBackupDirIsNoop(t *testing.T) {
	persist := t.TempDir()
	n, err := restorePersistFiles(filepath.Join(t.TempDir(), "absent"), persist)
	if err != nil || n != 0 {
		t.Errorf("restore with no backup dir: n=%d err=%v, want 0/nil", n, err)
	}
}

func TestCmdBackupGrowOnlyArmsFlagNoBackup(t *testing.T) {
	persist := t.TempDir()
	// a file that WOULD be backed up on the shrink path, to prove grow-only skips it
	if err := os.MkdirAll(filepath.Join(persist, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(persist, "certs/ek.cert.pem"), []byte("EK"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup-persist")
	flagFile := filepath.Join(t.TempDir(), "repartition-inprogress")

	if rc := cmdBackup([]string{"--persist", persist, "--backup-dir", backup, "--flag-file", flagFile, "--grow-only"}); rc != 0 {
		t.Fatalf("cmdBackup --grow-only rc=%d", rc)
	}
	got, err := os.ReadFile(flagFile)
	if err != nil {
		t.Fatalf("grow-only must write the flag file: %v", err)
	}
	if strings.TrimSpace(string(got)) != repartitionGrowOnly {
		t.Errorf("flag value = %q, want %q", strings.TrimSpace(string(got)), repartitionGrowOnly)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Error("grow-only must NOT create a backup dir")
	}
}

func TestCmdRestoreGCWhenFlagAbsent(t *testing.T) {
	persist := t.TempDir()
	backup := filepath.Join(t.TempDir(), "backup-persist")
	if err := os.MkdirAll(filepath.Join(backup, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "certs/ek.cert.pem"), []byte("EK"), 0o600); err != nil {
		t.Fatal(err)
	}
	flagFile := filepath.Join(t.TempDir(), "repartition-inprogress") // absent

	if rc := cmdRestore([]string{"--persist", persist, "--backup-dir", backup, "--flag-file", flagFile}); rc != 0 {
		t.Fatalf("cmdRestore rc=%d", rc)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Error("flag absent: leftover backup dir must be GC'd")
	}
	if _, err := os.Stat(filepath.Join(persist, "certs/ek.cert.pem")); err == nil {
		t.Error("flag absent: must NOT restore into /persist")
	}
}

func TestCmdCleanupRemovesBackupWhenFlagGone(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "backup-persist")
	if err := os.MkdirAll(filepath.Join(backup, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "certs/ek.cert.pem"), []byte("EK"), 0o600); err != nil {
		t.Fatal(err)
	}
	flagFile := filepath.Join(t.TempDir(), "repartition-inprogress") // absent

	if rc := cmdCleanup([]string{"--backup-dir", backup, "--flag-file", flagFile}); rc != 0 {
		t.Fatalf("cmdCleanup rc=%d", rc)
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Error("cleanup must remove the leftover backup dir when the flag file is gone")
	}
}

func TestCmdCleanupIsIdempotent(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "absent")    // never created
	flagFile := filepath.Join(t.TempDir(), "no-flag") // absent

	if rc := cmdCleanup([]string{"--backup-dir", backup, "--flag-file", flagFile}); rc != 0 {
		t.Fatalf("cmdCleanup on absent dir rc=%d, want 0 (no-op)", rc)
	}
}

func TestCmdCleanupRefusesWhileFlagPresent(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "backup-persist")
	if err := os.MkdirAll(backup, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "marker"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	flagFile := filepath.Join(t.TempDir(), "repartition-inprogress")
	if err := os.WriteFile(flagFile, []byte("78G\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if rc := cmdCleanup([]string{"--backup-dir", backup, "--flag-file", flagFile}); rc == 0 {
		t.Fatal("cmdCleanup must refuse while the flag file is still present")
	}
	if _, err := os.Stat(backup); err != nil {
		t.Error("cleanup must NOT remove the backup dir while the flag file is present")
	}
}

func TestCmdRestoreCleanupRemovesFlagFirstThenBackup(t *testing.T) {
	persist := t.TempDir() // simulate wiped /persist
	backup := filepath.Join(t.TempDir(), "backup-persist")
	if err := os.MkdirAll(filepath.Join(backup, "certs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "certs/ek.cert.pem"), []byte("EK"), 0o600); err != nil {
		t.Fatal(err)
	}
	flagFile := filepath.Join(t.TempDir(), "repartition-inprogress")
	if err := os.WriteFile(flagFile, []byte("78G\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if rc := cmdRestore([]string{"--persist", persist, "--backup-dir", backup, "--flag-file", flagFile, "--cleanup"}); rc != 0 {
		t.Fatalf("cmdRestore rc=%d", rc)
	}
	if got, _ := os.ReadFile(filepath.Join(persist, "certs/ek.cert.pem")); string(got) != "EK" {
		t.Error("flag present: must restore the backed-up file")
	}
	if _, err := os.Stat(flagFile); !os.IsNotExist(err) {
		t.Error("cleanup must remove the flag")
	}
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Error("cleanup must remove the backup dir")
	}
}
