// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"path/filepath"
	"testing"
)

// committedModel rebuilds the expected state up to the committed index, mirroring
// what Verify does, so a test can locate specific live/deleted files to corrupt.
func committedModel(dir string, cfg Config) *model {
	gen := newGenerator(cfg)
	m := newModel(cfg)
	c := readCommit(dir)
	for n := uint64(0); int64(n) <= c; n++ {
		m.apply(gen.next(m, n))
	}
	return m
}

func writeVolume(t *testing.T, cfg Config) (string, *model) {
	t.Helper()
	dir := t.TempDir()
	w, err := NewWriter(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Run(); err != nil {
		t.Fatal(err)
	}
	return dir, committedModel(dir, cfg)
}

func aLiveFile(t *testing.T, m *model) (uint64, int) {
	t.Helper()
	if len(m.liveIDs) == 0 {
		t.Fatal("no live files after write")
	}
	id := m.liveIDs[0]
	return id, m.files[id].nblocks
}

func TestWriteVerifyClean(t *testing.T) {
	cfg := testConfig()
	dir, m := writeVolume(t, cfg)
	rep, err := Verify(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Clean() {
		t.Fatalf("expected clean, got %s\n%+v", rep, rep.Anomalies)
	}
	if rep.FilesOK != len(m.liveIDs) {
		t.Fatalf("FilesOK=%d, want %d", rep.FilesOK, len(m.liveIDs))
	}
}

func TestTruncateDetected(t *testing.T) {
	cfg := testConfig()
	dir, m := writeVolume(t, cfg)
	id, _ := aLiveFile(t, m)
	if err := os.Truncate(filepath.Join(dir, filePathFor(cfg, id)), 0); err != nil {
		t.Fatal(err)
	}
	rep, _ := Verify(dir, cfg)
	a := findAnomaly(rep, id)
	if a == nil || a.Verdict != FilePresentCorrupt || !a.SizeMismatch {
		t.Fatalf("truncate not detected as present-corrupt: %+v", a)
	}
}

func TestZeroBlockDetected(t *testing.T) {
	cfg := testConfig()
	dir, m := writeVolume(t, cfg)
	id, _ := aLiveFile(t, m)
	f, err := os.OpenFile(filepath.Join(dir, filePathFor(cfg, id)), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(make([]byte, cfg.BlockSize), 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	rep, _ := Verify(dir, cfg)
	a := findAnomaly(rep, id)
	if a == nil || a.Verdict != FilePresentCorrupt || a.BlockCounts[BlockZeroed] == 0 {
		t.Fatalf("zeroed block not detected: %+v", a)
	}
}

func TestMisplacedDetected(t *testing.T) {
	cfg := testConfig()
	dir, m := writeVolume(t, cfg)
	id, nblocks := aLiveFile(t, m)
	other := id + 100000 // an identity distinct from every live/deleted file
	f, err := os.OpenFile(filepath.Join(dir, filePathFor(cfg, id)), os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nblocks; i++ {
		if _, err := f.Write(BuildBlock(other, uint64(i), cfg.BlockSize)); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	rep, _ := Verify(dir, cfg)
	a := findAnomaly(rep, id)
	if a == nil || a.BlockCounts[BlockMisplaced] == 0 {
		t.Fatalf("misplaced data not detected: %+v", a)
	}
}

func TestLostThenOrphaned(t *testing.T) {
	cfg := testConfig()
	dir, m := writeVolume(t, cfg)
	id, _ := aLiveFile(t, m)
	if err := os.Remove(filepath.Join(dir, filePathFor(cfg, id))); err != nil {
		t.Fatal(err)
	}
	rep, _ := Verify(dir, cfg)
	if a := findAnomaly(rep, id); a == nil || a.Verdict != FileLost {
		t.Fatalf("removed file not reported lost: %+v", a)
	}
	// Now place the file in lost+found (identified by its first block header).
	lf := filepath.Join(dir, "lost+found")
	if err := os.MkdirAll(lf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lf, "#131074"), BuildBlock(id, 0, cfg.BlockSize), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ = Verify(dir, cfg)
	if a := findAnomaly(rep, id); a == nil || a.Verdict != FileOrphaned {
		t.Fatalf("lost+found file not reported orphaned: %+v", a)
	}
}

func TestResurrectedDetected(t *testing.T) {
	cfg := testConfig()
	dir, m := writeVolume(t, cfg)
	var delID uint64
	found := false
	for id := range m.deleted {
		delID = id
		found = true
		break
	}
	if !found {
		t.Skip("no deleted files in this op stream")
	}
	path := filepath.Join(dir, filePathFor(cfg, delID))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, BuildBlock(delID, 0, cfg.BlockSize), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := Verify(dir, cfg)
	if len(rep.Resurrected) == 0 {
		t.Fatal("resurrected deleted file not detected")
	}
}

func TestCrashResumeIdempotent(t *testing.T) {
	cfg := testConfig()
	dir, _ := writeVolume(t, cfg)
	// Running the writer again must resume from the commit and leave the volume
	// clean (idempotent re-application of already-committed ops).
	w, _ := NewWriter(dir, cfg)
	if err := w.Run(); err != nil {
		t.Fatal(err)
	}
	rep, _ := Verify(dir, cfg)
	if !rep.Clean() {
		t.Fatalf("resume left volume dirty: %s", rep)
	}
}

func TestInFlightExtraFileTolerated(t *testing.T) {
	cfg := testConfig()
	dir, _ := writeVolume(t, cfg)
	// A file whose id was never part of the committed op stream stands in for an
	// in-flight (op > committed index) create. It is outside the expected set, so
	// the verifier must tolerate it rather than flag it (design §4.2).
	extra := cfg.Ops + 5
	path := filepath.Join(dir, filePathFor(cfg, extra))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, BuildBlock(extra, 0, cfg.BlockSize), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := Verify(dir, cfg)
	if !rep.Clean() {
		t.Fatalf("in-flight extra file should be tolerated, got %s\n%+v", rep, rep.Anomalies)
	}
}

func TestExpectCommittedSurvivesMetadataLoss(t *testing.T) {
	cfg := testConfig()
	dir, m := writeVolume(t, cfg)
	id, _ := aLiveFile(t, m)
	// Simulate fsck clearing both the on-volume commit metadata and a last file.
	if err := os.RemoveAll(filepath.Join(dir, commitDirName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, filePathFor(cfg, id))); err != nil {
		t.Fatal(err)
	}
	// Without the floor the verifier reads no commit, expects nothing, and the
	// loss is masked.
	if rep, _ := Verify(dir, cfg); !rep.Clean() {
		t.Fatalf("baseline: expected masked-clean without floor, got %s", rep)
	}
	// With the harness high-water mark as a floor, the loss is caught.
	cfg.ExpectCommitted = int64(cfg.Ops - 1)
	rep, _ := Verify(dir, cfg)
	if a := findAnomaly(rep, id); a == nil || a.Verdict != FileLost {
		t.Fatalf("floor: loss after metadata clearing not caught: %+v", a)
	}
}

func findAnomaly(rep Report, id uint64) *FileAnomaly {
	for i := range rep.Anomalies {
		if rep.Anomalies[i].FileID == id {
			return &rep.Anomalies[i]
		}
	}
	return nil
}
