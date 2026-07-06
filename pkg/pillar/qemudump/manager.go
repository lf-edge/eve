// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Kind is the on-disk suffix (including .zst) that identifies a dump artifact
// type and gives each type its own rotation ring.
type Kind string

const (
	// KindGuestCore is a guest physical-RAM ELF core (QMP dump-guest-memory).
	KindGuestCore Kind = "guestmem.elf.zst"
	// KindProcessCore is a qemu process core (kernel coredump of qemu itself).
	KindProcessCore Kind = "qemu-core.zst"
)

// tsLayout timestamps every dump so a crash's dump and trace pair by proximity
// and no two dumps of a domain collide.
const tsLayout = "20060102-150405"

// SpaceProvider reports free and total bytes of the filesystem holding the dump
// directory. Injectable so the package is unit-testable without a real vault.
type SpaceProvider func() (free, total uint64, err error)

// Config parameterizes a Manager. The absolute GlobalCap / FreeSpaceFloor byte
// values are computed by the caller (e.g. from PersistUsageStat); this package
// only enforces them.
type Config struct {
	Dir            string        // dump root, e.g. /persist/vault/qemu-trace
	KeepPerDomain  int           // rotation ring size K per (domain, kind)
	PerDomainQuota uint64        // max retained bytes per (domain, kind) ring
	GlobalCap      uint64        // max total dump bytes under Dir
	FreeSpaceFloor uint64        // never let filesystem free space drop below this
	Concurrency    int           // zstd encoder workers (1–2 on the crash path)
	Space          SpaceProvider // free/total of the dump filesystem
	// AvailMem returns the memory (bytes) available to the compressor — pillar's
	// cgroup headroom (limit - usage), NOT system free RAM. The zstd window is
	// anonymous memory charged to pillar's cgroup; sizing it from system RAM
	// OOM-kills zedbox. nil (or 0) forces the minimum window, which is safe.
	AvailMem func() uint64
	// Log, if set, records the chosen window/limit for each dump (diagnostics).
	Log func(format string, args ...interface{})
}

// Manager owns the dump-storage lifecycle: compression, on-the-fly quota, and
// rotation. It is safe to construct once and reuse for every dump.
type Manager struct {
	cfg Config
	seq atomic.Uint64 // monotonic dump sequence, for unique recency-ordered names
}

// NewManager returns a Manager for cfg.
func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

// Dump is an open, compressing, quota-enforced dump. Callers write the raw
// (uncompressed) dump stream; bytes are zstd-compressed to the vault and the
// compressed size is bounded on the fly. Write returns ErrQuotaExceeded and
// removes the partial file if a limit is crossed; Close finalizes.
type Dump struct {
	path string
	enc  *zstd.Encoder
	lw   *limitedFileWriter
}

// NewDump rotates old dumps of this (domain, kind), computes the on-the-fly
// byte limit from the per-domain quota, global cap, and free-space floor, sizes
// the zstd window to a memory budget, and opens a compressing writer.
func (m *Manager) NewDump(domain string, kind Kind) (*Dump, error) {
	dir := m.domainDir(domain)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("qemudump: mkdir %s: %w", dir, err)
	}

	// Evict old dumps of this kind up front so the ring is bounded before we
	// start writing (keep K-1; the new dump becomes the Kth).
	if err := pruneToNewest(dir, string(kind), max(m.cfg.KeepPerDomain-1, 0)); err != nil {
		return nil, err
	}

	limit, err := m.computeLimit(dir, kind)
	if err != nil {
		return nil, err
	}

	path := m.uniqueDumpPath(dir, time.Now().UTC().Format(tsLayout), kind)
	lw, err := newLimitedFileWriter(path, limit)
	if err != nil {
		return nil, err
	}

	avail := m.availMem()
	budget := ComputeBudget(avail)
	windowLog := ChooseWindowLog(budget, m.cfg.Concurrency)
	if m.cfg.Log != nil {
		m.cfg.Log("qemudump: %s: cgroup headroom %d MiB, budget %d MiB, windowLog %d (%d MiB window), disk limit %d MiB",
			filepath.Base(path), avail>>20, budget>>20, windowLog, (uint64(1)<<windowLog)>>20, limit>>20)
	}
	// SpeedFastest keeps the encoder's resident memory lowest — critical on the
	// crash path inside pillar's small cgroup; zero/duplicate pages in a core
	// still compress well at the fastest level.
	enc, err := zstd.NewWriter(lw,
		zstd.WithWindowSize(1<<windowLog),
		zstd.WithEncoderConcurrency(max(m.cfg.Concurrency, 1)),
		zstd.WithEncoderLevel(zstd.SpeedFastest),
	)
	if err != nil {
		lw.abort()
		return nil, fmt.Errorf("qemudump: zstd writer: %w", err)
	}
	return &Dump{path: path, enc: enc, lw: lw}, nil
}

// Write compresses p into the dump, enforcing the byte limit on the fly.
func (d *Dump) Write(p []byte) (int, error) {
	return d.enc.Write(p)
}

// Close flushes the encoder and finalizes the file. After a quota abort it
// still returns ErrQuotaExceeded so callers see the dump did not complete.
func (d *Dump) Close() error {
	encErr := d.enc.Close()
	closeErr := d.lw.Close()
	if d.lw.aborted {
		return ErrQuotaExceeded
	}
	if encErr != nil {
		return fmt.Errorf("qemudump: finalize %s: %w", d.path, encErr)
	}
	return closeErr
}

// Path is the absolute path of the (compressed) dump file.
func (d *Dump) Path() string { return d.path }

// CompressFile compresses an existing raw dump file (e.g. a kernel-written qemu
// process core landed in the vault) into a rotated, quota-enforced .zst under
// the domain's directory and returns its path. On success, or when the quota
// aborts the compression, the raw source is removed — an uncompressed core must
// never linger in the vault. On any other I/O error the raw is left in place so
// a later pass can retry.
func (m *Manager) CompressFile(domain string, kind Kind, srcPath string) (string, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("qemudump: open raw %s: %w", srcPath, err)
	}
	defer src.Close()

	w, err := m.NewDump(domain, kind)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(w, src)
	closeErr := w.Close()

	if err := firstErr(copyErr, closeErr); err != nil {
		if errors.Is(err, ErrQuotaExceeded) {
			os.Remove(srcPath) // NewDump/limitedFileWriter already removed the partial
		}
		return "", err
	}
	os.Remove(srcPath)
	return w.Path(), nil
}

// Dir is the dump root this Manager writes under.
func (m *Manager) Dir() string { return m.cfg.Dir }

// PickupProcessCore looks for a raw, kernel-written qemu process core for pid in
// the staging dir and, if one is waiting, compresses it into the domain's ring
// (removing the raw). Returns the .zst path, or "" if no core was waiting. Call
// it when a domain's qemu has died (mode B) with its last-known pid.
func (m *Manager) PickupProcessCore(domain string, pid int) (string, error) {
	raw, err := FindCoreForPID(m.cfg.Dir, pid)
	if err != nil || raw == "" {
		return "", err
	}
	return m.CompressFile(domain, KindProcessCore, raw)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// uniqueDumpPath returns dir/<ts>-<seq>.<kind> using a monotonic per-Manager
// sequence, so several dumps of one domain in the same wall-clock second (a
// crash loop) never collide and are never reused after eviction. The fixed
// width makes lexicographic name order equal recency order (ts primary, seq
// secondary), which is what pruneToNewest relies on for deterministic eviction.
// A stat guard bumps the sequence in the unlikely event a name already exists
// (e.g. same second as a pre-restart dump, since seq resets across restarts).
func (m *Manager) uniqueDumpPath(dir, ts string, kind Kind) string {
	for {
		seq := m.seq.Add(1)
		path := filepath.Join(dir, fmt.Sprintf("%s-%06d.%s", ts, seq, kind))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return path
		}
	}
}

func (m *Manager) domainDir(domain string) string {
	return filepath.Join(m.cfg.Dir, filepath.Base(filepath.Clean("/"+domain)))
}

// availMem returns the memory available to the compressor. If no provider is
// configured it returns 0, which floors the window at its minimum — the safe
// default (never size a window from system RAM, which would OOM pillar).
func (m *Manager) availMem() uint64 {
	if m.cfg.AvailMem != nil {
		return m.cfg.AvailMem()
	}
	return 0
}

// computeLimit derives the maximum compressed bytes this dump may write, as the
// smallest of the three headrooms: per-domain quota, global cap, and free space
// above the floor.
func (m *Manager) computeLimit(domainDir string, kind Kind) (uint64, error) {
	free, _, err := m.space()
	if err != nil {
		return 0, fmt.Errorf("qemudump: free space: %w", err)
	}
	freeHeadroom := saturatingSub(free, m.cfg.FreeSpaceFloor)

	usedGlobal, err := dirBytes(m.cfg.Dir)
	if err != nil {
		return 0, err
	}
	globalHeadroom := saturatingSub(m.cfg.GlobalCap, usedGlobal)

	usedDomain, err := kindBytes(domainDir, string(kind))
	if err != nil {
		return 0, err
	}
	perDomainHeadroom := saturatingSub(m.cfg.PerDomainQuota, usedDomain)

	return min(freeHeadroom, min(globalHeadroom, perDomainHeadroom)), nil
}

func (m *Manager) space() (free, total uint64, err error) {
	if m.cfg.Space != nil {
		return m.cfg.Space()
	}
	return hostSpace(m.cfg.Dir)
}

func saturatingSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}
