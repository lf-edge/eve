// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// incompressible returns n bytes that zstd cannot shrink, so the on-disk
// (compressed) size tracks the input size and small limits actually bind.
func incompressible(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(1)).Read(b)
	return b
}

// writeAndClose drives a full dump and returns whichever error surfaced (Write
// may abort mid-stream, or the abort may only surface at Close when the encoder
// flushes).
func writeAndClose(t *testing.T, w *Dump, data []byte) error {
	t.Helper()
	_, werr := w.Write(data)
	cerr := w.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func assertNoDumps(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) != 0 {
		t.Fatalf("partial dump not removed: %v", ents)
	}
}

// A dump that would exceed the per-domain quota aborts and deletes its partial,
// so a domain's retained dumps can never exceed the quota (design doc §7).
func TestManagerAbortsOnPerDomainQuota(t *testing.T) {
	dir := t.TempDir()
	cfg := generousConfig(dir)
	cfg.PerDomainQuota = 4 * kib
	m := NewManager(cfg)

	w, err := m.NewDump("dom1", KindGuestCore)
	if err != nil {
		t.Fatalf("NewDump: %v", err)
	}
	if err := writeAndClose(t, w, incompressible(1*mib)); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	assertNoDumps(t, filepath.Join(dir, "dom1"))
}

// A dump that would push filesystem free space below the floor aborts, so
// diagnostics can never cross the device-management headroom (design doc §7).
func TestManagerAbortsOnFreeSpaceFloor(t *testing.T) {
	dir := t.TempDir()
	cfg := generousConfig(dir)
	// Only 4 KiB of headroom above the floor.
	cfg.FreeSpaceFloor = 100 * mib
	cfg.Space = func() (free, total uint64, err error) { return 100*mib + 4*kib, 1 * gib, nil }
	m := NewManager(cfg)

	w, err := m.NewDump("dom1", KindGuestCore)
	if err != nil {
		t.Fatalf("NewDump: %v", err)
	}
	if err := writeAndClose(t, w, incompressible(1*mib)); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	assertNoDumps(t, filepath.Join(dir, "dom1"))
}

// The global cap counts bytes already retained across all domains, so it binds
// even when this domain's own quota has room.
func TestManagerAbortsOnGlobalCap(t *testing.T) {
	dir := t.TempDir()
	cfg := generousConfig(dir)
	cfg.GlobalCap = 8 * kib
	m := NewManager(cfg)

	// Pre-existing dump in another domain consumes most of the global cap.
	other := filepath.Join(dir, "dom0")
	if err := os.MkdirAll(other, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(other, "20260101-000001-000001."+string(KindGuestCore)), make([]byte, 7*kib), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w, err := m.NewDump("dom1", KindGuestCore)
	if err != nil {
		t.Fatalf("NewDump: %v", err)
	}
	if err := writeAndClose(t, w, incompressible(1*mib)); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	assertNoDumps(t, filepath.Join(dir, "dom1"))
}
