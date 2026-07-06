// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// CompressFile turns a kernel-written raw core into a rotated, quota-enforced
// .zst under the domain's dir and removes the raw source (design doc §4.2, §7).
func TestCompressFileHappyPath(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(generousConfig(dir))

	raw := filepath.Join(t.TempDir(), "core.1234")
	content := bytes.Repeat([]byte("QEMUCORE"), 4096) // compressible
	if err := os.WriteFile(raw, content, 0600); err != nil {
		t.Fatalf("seed raw: %v", err)
	}

	dst, err := m.CompressFile("dom1", KindProcessCore, raw)
	if err != nil {
		t.Fatalf("CompressFile: %v", err)
	}
	if _, err := os.Stat(raw); !os.IsNotExist(err) {
		t.Fatalf("raw source not removed (err=%v)", err)
	}
	if got := decompress(t, dst); !bytes.Equal(got, content) {
		t.Fatalf("round-trip mismatch: %d vs %d bytes", len(got), len(content))
	}
}

// If compression can't fit the quota, both the partial .zst and the raw source
// are removed — an uncompressed core must never be left in the vault.
func TestCompressFileQuotaAbortRemovesBoth(t *testing.T) {
	dir := t.TempDir()
	cfg := generousConfig(dir)
	cfg.PerDomainQuota = 4 * kib
	m := NewManager(cfg)

	raw := filepath.Join(t.TempDir(), "core.1234")
	if err := os.WriteFile(raw, incompressible(1*mib), 0600); err != nil {
		t.Fatalf("seed raw: %v", err)
	}

	_, err := m.CompressFile("dom1", KindProcessCore, raw)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	if _, err := os.Stat(raw); !os.IsNotExist(err) {
		t.Fatalf("raw source not removed after abort (err=%v)", err)
	}
	assertNoDumps(t, filepath.Join(dir, "dom1"))
}

// PickupProcessCore finds a kernel-written raw core for a pid in staging and
// compresses it into the domain's ring, removing the raw.
func TestPickupProcessCore(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(generousConfig(dir))
	staging := StagingDir(dir)
	if err := os.MkdirAll(staging, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	raw := filepath.Join(staging, "core-4242-1720000000")
	content := bytes.Repeat([]byte("QEMU"), 4096)
	if err := os.WriteFile(raw, content, 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	dst, err := m.PickupProcessCore("dom1", 4242)
	if err != nil {
		t.Fatalf("PickupProcessCore: %v", err)
	}
	if dst == "" {
		t.Fatalf("expected a dump path")
	}
	if _, err := os.Stat(raw); !os.IsNotExist(err) {
		t.Fatalf("raw not removed")
	}
	if got := decompress(t, dst); !bytes.Equal(got, content) {
		t.Fatalf("round-trip mismatch")
	}

	// No core waiting for an unknown pid -> ("", nil).
	if dst, err := m.PickupProcessCore("dom1", 9999); err != nil || dst != "" {
		t.Fatalf("PickupProcessCore(absent) = %q, %v; want \"\", nil", dst, err)
	}
}
