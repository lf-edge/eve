// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// generousConfig returns a Manager whose limits never bind, with injected
// space/RAM providers so tests never touch the real /persist or host memory.
func generousConfig(dir string) Config {
	return Config{
		Dir:            dir,
		KeepPerDomain:  3,
		PerDomainQuota: 1 << 40, // 1 TiB
		GlobalCap:      1 << 40,
		FreeSpaceFloor: 0,
		Concurrency:    1,
		Space:          func() (free, total uint64, err error) { return 1 << 50, 1 << 50, nil },
		AvailMem:       func() uint64 { return 512 * mib },
	}
}

func decompress(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	dec, err := zstd.NewReader(f, zstd.WithDecoderMaxWindow(1<<31))
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer dec.Close()
	out, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("decompress %s: %v", path, err)
	}
	return out
}

// A dump written through the manager round-trips: the on-disk .zst decompresses
// back to exactly the bytes written, lands in the domain's directory with the
// kind suffix, and is smaller than the (compressible) input.
func TestManagerDumpRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(generousConfig(dir))

	// Highly compressible: 4 MiB of zeros plus a marker — mimics a RAM dump.
	input := make([]byte, 4*mib)
	copy(input, []byte("GUESTCORE-START"))
	copy(input[len(input)-3:], []byte("END"))

	w, err := m.NewDump("dom1", KindGuestCore)
	if err != nil {
		t.Fatalf("NewDump: %v", err)
	}
	if _, err := w.Write(input); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	path := w.Path()
	if !strings.HasPrefix(path, filepath.Join(dir, "dom1")+string(os.PathSeparator)) {
		t.Fatalf("path %q not under domain dir", path)
	}
	if !strings.HasSuffix(path, string(KindGuestCore)) {
		t.Fatalf("path %q missing kind suffix %q", path, KindGuestCore)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat dump: %v", err)
	}
	if uint64(fi.Size()) >= uint64(len(input)) {
		t.Fatalf("dump not compressed: %d >= %d", fi.Size(), len(input))
	}
	if got := decompress(t, path); !bytes.Equal(got, input) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(input))
	}
}
