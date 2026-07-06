// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeDump(t *testing.T, m *Manager, domain string, kind Kind, data []byte) string {
	t.Helper()
	w, err := m.NewDump(domain, kind)
	if err != nil {
		t.Fatalf("NewDump: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return w.Path()
}

// Successive dumps of a (domain, kind) form a bounded ring: after writing more
// than K the oldest are evicted and only the K newest (by content) survive.
// Dumps landing in the same wall-clock second must not overwrite a live file.
func TestManagerRotatesPerDomainKind(t *testing.T) {
	dir := t.TempDir()
	cfg := generousConfig(dir)
	cfg.KeepPerDomain = 3
	m := NewManager(cfg)

	for i := 0; i < 5; i++ {
		content := []byte("dump-" + strconv.Itoa(i))
		w, err := m.NewDump("dom1", KindGuestCore)
		if err != nil {
			t.Fatalf("NewDump: %v", err)
		}
		// The just-opened file must not have clobbered a still-live dump: a
		// same-second dump gets a unique name before any eviction.
		if _, err := w.Write(content); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}

	ents, err := os.ReadDir(filepath.Join(dir, "dom1"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(ents) != 3 {
		t.Fatalf("kept %d dumps, want 3", len(ents))
	}
	survivors := map[string]bool{}
	for _, e := range ents {
		survivors[string(decompress(t, filepath.Join(dir, "dom1", e.Name())))] = true
	}
	for _, want := range []string{"dump-2", "dump-3", "dump-4"} {
		if !survivors[want] {
			t.Fatalf("survivors %v missing newest dump %q", survivors, want)
		}
	}
	for _, gone := range []string{"dump-0", "dump-1"} {
		if survivors[gone] {
			t.Fatalf("oldest dump %q was not evicted", gone)
		}
	}
}

// Rings for different kinds in the same domain rotate independently.
func TestManagerRingsIndependentPerKind(t *testing.T) {
	dir := t.TempDir()
	cfg := generousConfig(dir)
	cfg.KeepPerDomain = 2
	m := NewManager(cfg)

	for i := 0; i < 3; i++ {
		writeDump(t, m, "dom1", KindGuestCore, []byte("g"))
	}
	writeDump(t, m, "dom1", KindProcessCore, []byte("p"))

	ents, _ := os.ReadDir(filepath.Join(dir, "dom1"))
	var guest, proc int
	for _, e := range ents {
		switch {
		case filepath.Ext(e.Name()) == ".zst" && hasKind(e.Name(), KindGuestCore):
			guest++
		case hasKind(e.Name(), KindProcessCore):
			proc++
		}
	}
	if guest != 2 || proc != 1 {
		t.Fatalf("guest=%d proc=%d, want guest=2 proc=1 (rings not independent)", guest, proc)
	}
}

func hasKind(name string, k Kind) bool {
	return len(name) >= len(k) && name[len(name)-len(k):] == string(k)
}
