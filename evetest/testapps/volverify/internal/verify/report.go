// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import "fmt"

// FileVerdict is the outcome for one expected-live file.
type FileVerdict int

const (
	// FileOK means the file is present, correctly sized, and every block verified.
	FileOK FileVerdict = iota
	// FilePresentCorrupt means the file is present but has bad/misplaced/short
	// blocks — the dangerous case EVE serves as-is (design §2.4, §4.3).
	FilePresentCorrupt
	// FileOrphaned means the file is missing from its path but was recovered in
	// lost+found — self-heals to a blank/content-tree recreate (safe).
	FileOrphaned
	// FileLost means the file is missing and not in lost+found — data loss.
	FileLost
)

func (v FileVerdict) String() string {
	switch v {
	case FileOK:
		return "ok"
	case FilePresentCorrupt:
		return "present-corrupt"
	case FileOrphaned:
		return "orphaned"
	case FileLost:
		return "lost"
	}
	return "unknown"
}

// FileAnomaly describes one non-OK expected file.
type FileAnomaly struct {
	FileID       uint64
	Path         string
	Verdict      FileVerdict
	ExpectBlocks int
	// BlockCounts tallies each block status seen in a present-corrupt file.
	BlockCounts map[BlockStatus]int
	// SizeMismatch is set when the on-disk size differs from expected.
	SizeMismatch bool
}

// Report summarizes a verification pass. It is the volume-content ground truth
// the soak harness pairs with the resize fsck marker.
type Report struct {
	CommittedIndex  int64
	LiveExpected    int
	DeletedExpected int
	FilesOK         int
	Anomalies       []FileAnomaly
	// Resurrected lists committed-deleted files that reappeared (e.g. from
	// lost+found) — an anomaly in its own right.
	Resurrected []uint64
}

// Clean reports whether the pass found no anomalies of any kind.
func (r Report) Clean() bool {
	return len(r.Anomalies) == 0 && len(r.Resurrected) == 0
}

// Counts returns the number of anomalies of each verdict.
func (r Report) Counts() map[FileVerdict]int {
	c := make(map[FileVerdict]int)
	for _, a := range r.Anomalies {
		c[a.Verdict]++
	}
	return c
}

// String renders a compact human-readable summary.
func (r Report) String() string {
	c := r.Counts()
	return fmt.Sprintf(
		"committed=%d live=%d deleted=%d ok=%d present-corrupt=%d orphaned=%d lost=%d resurrected=%d",
		r.CommittedIndex, r.LiveExpected, r.DeletedExpected, r.FilesOK,
		c[FilePresentCorrupt], c[FileOrphaned], c[FileLost], len(r.Resurrected))
}
