// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Writer applies the deterministic op stream to a volume, fsyncing and advancing
// the committed index every Config.CommitEvery ops so that, after an abrupt power
// loss, everything through the last committed index is durable (design §4.2).
type Writer struct {
	volDir string
	cfg    Config
}

// NewWriter returns a Writer that operates on the volume mounted at volDir.
func NewWriter(volDir string, cfg Config) (*Writer, error) {
	if !cfg.valid() {
		return nil, fmt.Errorf("invalid config: %+v", cfg)
	}
	return &Writer{volDir: volDir, cfg: cfg}, nil
}

// Run applies ops until Config.Ops (or until the volume fills), resuming after a
// crash from the committed index. It is safe to call repeatedly across reboots on
// the same volume. It returns the final committed op index — the high-water mark
// the verifier should expect (equal to Ops-1 on full completion, or lower when the
// volume filled first). Filling the volume is the expected end state for the
// corruption soak, so ENOSPC is a clean stop, not an error.
func (w *Writer) Run() (int64, error) {
	gen := newGenerator(w.cfg)
	m := newModel(w.cfg)

	// Rebuild in-memory state up to the committed index without touching disk;
	// this also advances the generator to the first uncommitted op.
	committed := readCommit(w.volDir)
	for n := uint64(0); int64(n) <= committed; n++ {
		m.apply(gen.next(m, n))
	}
	gen64 := nextGeneration(w.volDir)
	lastCommitted := committed

	touchedFiles := make(map[string]bool)
	touchedDirs := make(map[string]bool)

	commit := func(index uint64) error {
		for p := range touchedFiles {
			if err := fsyncFile(p); err != nil {
				return err
			}
		}
		for d := range touchedDirs {
			if err := fsyncDir(d); err != nil {
				return err
			}
		}
		if err := writeCommit(w.volDir, commitRecord{generation: gen64, index: int64(index)}); err != nil {
			return err
		}
		gen64++
		lastCommitted = int64(index)
		touchedFiles = make(map[string]bool)
		touchedDirs = make(map[string]bool)
		return nil
	}

	start := uint64(committed + 1)
	for n := start; n < w.cfg.Ops; n++ {
		o := gen.next(m, n)
		if err := w.applyOp(o, touchedFiles, touchedDirs); err != nil {
			if errors.Is(err, syscall.ENOSPC) {
				// Volume full: stop cleanly at the last fully-written op. Drop the
				// partial file (it is an uncommitted op the verifier ignores) and
				// commit everything through n-1, then report that index.
				if o.typ == opCreate {
					_ = os.Remove(filepath.Join(w.volDir, filePathFor(w.cfg, o.fileID)))
				}
				if n > start {
					if err := commit(n - 1); err != nil {
						return lastCommitted, err
					}
				}
				return lastCommitted, nil
			}
			return lastCommitted, fmt.Errorf("op %d (%v): %w", n, o.typ, err)
		}
		m.apply(o)
		if (n+1)%w.cfg.CommitEvery == 0 {
			if err := commit(n); err != nil {
				return lastCommitted, err
			}
		}
	}
	if w.cfg.Ops > start {
		if err := commit(w.cfg.Ops - 1); err != nil {
			return lastCommitted, err
		}
	}
	return lastCommitted, nil
}

// applyOp performs one op against the volume and records what it touched so the
// next commit can fsync it.
func (w *Writer) applyOp(o op, touchedFiles, touchedDirs map[string]bool) error {
	switch o.typ {
	case opCreate:
		rel := filePathFor(w.cfg, o.fileID)
		path := filepath.Join(w.volDir, rel)
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
		if err := w.writeFile(path, o.fileID, o.nblocks); err != nil {
			return err
		}
		touchedFiles[path] = true
		touchedDirs[parent] = true
	case opDelete:
		rel := filePathFor(w.cfg, o.fileID)
		path := filepath.Join(w.volDir, rel)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		touchedDirs[filepath.Dir(path)] = true
	case opMkdir:
		path := filepath.Join(w.volDir, o.dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
		touchedDirs[filepath.Dir(path)] = true
	case opRmdir:
		path := filepath.Join(w.volDir, o.dir)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			// A non-empty scratch dir cannot be removed; leave it in place.
			if !isNotEmpty(err) {
				return err
			}
		}
		touchedDirs[filepath.Dir(path)] = true
	}
	return nil
}

// writeFile writes nblocks Layer-1 blocks for fileID, replacing any prior content.
func (w *Writer) writeFile(path string, fileID uint64, nblocks int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for i := 0; i < nblocks; i++ {
		if _, err := f.Write(BuildBlock(fileID, uint64(i), w.cfg.BlockSize)); err != nil {
			return err
		}
	}
	return nil
}

// Verify reconstructs the expected committed state and checks the on-disk tree
// against it, classifying every expected file (design §4.2, §4.3).
func Verify(volDir string, cfg Config) (Report, error) {
	if !cfg.valid() {
		return Report{}, fmt.Errorf("invalid config: %+v", cfg)
	}
	gen := newGenerator(cfg)
	m := newModel(cfg)
	committed := readCommit(volDir)
	if cfg.ExpectCommitted > committed {
		// Trust the harness-supplied high-water mark over on-volume bookkeeping
		// that fsck may have cleared alongside the data (see Config.ExpectCommitted).
		committed = cfg.ExpectCommitted
	}
	for n := uint64(0); int64(n) <= committed; n++ {
		m.apply(gen.next(m, n))
	}

	orphans := scanLostFound(volDir, cfg.BlockSize)

	rep := Report{
		CommittedIndex:  committed,
		LiveExpected:    len(m.liveIDs),
		DeletedExpected: len(m.deleted),
	}

	for _, id := range m.liveIDs {
		meta := m.files[id]
		rel := m.filePath(id)
		path := filepath.Join(volDir, rel)
		anom, ok := checkFile(path, id, meta.nblocks, cfg.BlockSize)
		if ok {
			rep.FilesOK++
			continue
		}
		if anom.Verdict == FileLost && orphans[id] {
			anom.Verdict = FileOrphaned
		}
		anom.FileID = id
		anom.Path = rel
		anom.ExpectBlocks = meta.nblocks
		rep.Anomalies = append(rep.Anomalies, anom)
	}

	for id := range m.deleted {
		path := filepath.Join(volDir, m.filePath(id))
		if _, err := os.Stat(path); err == nil {
			rep.Resurrected = append(rep.Resurrected, id)
		}
	}
	return rep, nil
}

// checkFile classifies one expected-live file. ok is true only for a fully-clean
// file (present, correct size, every block OK).
func checkFile(path string, fileID uint64, nblocks, blockSize int) (FileAnomaly, bool) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return FileAnomaly{Verdict: FileLost}, false
		}
		return FileAnomaly{Verdict: FileLost}, false
	}
	defer f.Close()

	anom := FileAnomaly{Verdict: FilePresentCorrupt, BlockCounts: make(map[BlockStatus]int)}
	if fi, err := f.Stat(); err == nil {
		if fi.Size() != int64(nblocks)*int64(blockSize) {
			anom.SizeMismatch = true
		}
	}

	buf := make([]byte, blockSize)
	allOK := !anom.SizeMismatch
	for i := 0; i < nblocks; i++ {
		n, err := io.ReadFull(f, buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// Fewer blocks than expected: treat the missing tail as zeroed.
			for ; n < blockSize; n++ {
				buf[n] = 0
			}
			res := VerifyBlock(buf, fileID, uint64(i), blockSize)
			anom.BlockCounts[res.Status]++
			allOK = false
			continue
		}
		if err != nil {
			anom.BlockCounts[BlockGarbage]++
			allOK = false
			continue
		}
		res := VerifyBlock(buf, fileID, uint64(i), blockSize)
		anom.BlockCounts[res.Status]++
		if res.Status != BlockOK {
			allOK = false
		}
	}
	if allOK {
		return FileAnomaly{}, true
	}
	return anom, false
}

// scanLostFound returns the set of fileIDs recoverable from a lost+found
// directory at the volume root, identified by reading each entry's first block
// header (design §4.3). It is best-effort: a missing or unreadable lost+found
// yields an empty set.
func scanLostFound(volDir string, blockSize int) map[uint64]bool {
	out := make(map[uint64]bool)
	lf := filepath.Join(volDir, "lost+found")
	entries, err := os.ReadDir(lf)
	if err != nil {
		return out
	}
	buf := make([]byte, blockSize)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(lf, e.Name()))
		if err != nil {
			continue
		}
		n, _ := io.ReadFull(f, buf)
		f.Close()
		if n < blockSize {
			continue
		}
		if id, ok := headerFileID(buf, blockSize); ok {
			out[id] = true
		}
	}
	return out
}

func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	return f.Sync()
}
