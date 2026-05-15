// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// rebootReasonLine matches the legacy on-disk format:
//
//	 [YYYY-MM-DD HH:MM:SS]: BootReasonKubeTransition, <reason>
var rebootReasonLine = regexp.MustCompile(
	`^ \[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]: BootReasonKubeTransition, (.+)$`)

func TestPrepareRebootFirstCall(t *testing.T) {
	dir := t.TempDir()
	bootPath := filepath.Join(dir, "boot-reason")
	rebootPath := filepath.Join(dir, "reboot-reason")

	if err := prepareReboot("test-reason", bootPath, rebootPath); err != nil {
		t.Fatalf("prepareReboot: %v", err)
	}

	got, err := os.ReadFile(bootPath)
	if err != nil {
		t.Fatalf("read boot reason: %v", err)
	}
	if string(got) != BootReasonKubeTransition {
		t.Errorf("boot reason = %q, want %q", string(got), BootReasonKubeTransition)
	}

	gotReboot, err := os.ReadFile(rebootPath)
	if err != nil {
		t.Fatalf("read reboot reason: %v", err)
	}
	line := strings.TrimRight(string(gotReboot), "\n")
	m := rebootReasonLine.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("reboot reason line does not match expected format: %q", line)
	}
	if m[1] != "test-reason" {
		t.Errorf("captured reason = %q, want %q", m[1], "test-reason")
	}
}

func TestPrepareRebootBootReasonStickyAndAppendsReason(t *testing.T) {
	dir := t.TempDir()
	bootPath := filepath.Join(dir, "boot-reason")
	rebootPath := filepath.Join(dir, "reboot-reason")

	// Pre-seed an unrelated boot reason — simulating a base-OS layer
	// having already written the file. We must NOT overwrite it, but
	// we MUST still append our reboot-reason line.
	if err := os.WriteFile(bootPath, []byte("OriginalReason"), 0644); err != nil {
		t.Fatalf("seed boot reason: %v", err)
	}

	if err := prepareReboot("kube-step-1", bootPath, rebootPath); err != nil {
		t.Fatalf("prepareReboot: %v", err)
	}

	// Boot reason untouched.
	got, err := os.ReadFile(bootPath)
	if err != nil {
		t.Fatalf("read boot reason: %v", err)
	}
	if string(got) != "OriginalReason" {
		t.Errorf("boot reason was overwritten: got %q, want %q",
			string(got), "OriginalReason")
	}

	// Reboot reason appended despite the boot-reason short-circuit.
	gotReboot, err := os.ReadFile(rebootPath)
	if err != nil {
		t.Fatalf("read reboot reason: %v", err)
	}
	if !strings.Contains(string(gotReboot), "kube-step-1") {
		t.Errorf("reboot reason file did not record the appended reason: %q",
			string(gotReboot))
	}
}

func TestPrepareRebootAppendsReasonsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	bootPath := filepath.Join(dir, "boot-reason")
	rebootPath := filepath.Join(dir, "reboot-reason")

	reasons := []string{"first", "second", "third"}
	for _, r := range reasons {
		if err := prepareReboot(r, bootPath, rebootPath); err != nil {
			t.Fatalf("prepareReboot(%q): %v", r, err)
		}
	}

	f, err := os.Open(rebootPath)
	if err != nil {
		t.Fatalf("open reboot reason: %v", err)
	}
	defer f.Close()

	var captured []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := rebootReasonLine.FindStringSubmatch(scanner.Text())
		if m == nil {
			t.Fatalf("line does not match format: %q", scanner.Text())
		}
		captured = append(captured, m[1])
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(captured) != len(reasons) {
		t.Fatalf("got %d lines, want %d (lines: %v)",
			len(captured), len(reasons), captured)
	}
	for i, want := range reasons {
		if captured[i] != want {
			t.Errorf("line %d reason = %q, want %q", i, captured[i], want)
		}
	}
}

func TestPrepareRebootBootReasonOpenError(t *testing.T) {
	// Failure path on writeFirstBootReason: parent dir unreadable so
	// the O_EXCL open fails with EACCES (not EEXIST).
	if os.Geteuid() == 0 {
		t.Skip("root bypasses dir-exec permissions")
	}
	parent := t.TempDir()
	blocked := filepath.Join(parent, "blocked")
	if err := os.Mkdir(blocked, 0000); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blocked, 0700); err != nil {
			t.Logf("chmod restore: %v", err)
		}
	})

	err := prepareReboot("x",
		filepath.Join(blocked, "boot-reason"),
		filepath.Join(blocked, "reboot-reason"))
	if err == nil {
		t.Fatal("expected error from unreadable parent dir, got nil")
	}
}

func TestPrepareRebootAppendRebootReasonOpenError(t *testing.T) {
	// Failure path on appendRebootReason: boot reason file writes
	// successfully (its parent is writable), but the reboot reason
	// file is in a dir we can't write to.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses dir-exec permissions")
	}
	bootDir := t.TempDir()
	bootPath := filepath.Join(bootDir, "boot-reason")

	parent := t.TempDir()
	blocked := filepath.Join(parent, "blocked")
	if err := os.Mkdir(blocked, 0000); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blocked, 0700); err != nil {
			t.Logf("chmod restore: %v", err)
		}
	})

	err := prepareReboot("x", bootPath, filepath.Join(blocked, "reboot-reason"))
	if err == nil {
		t.Fatal("expected error from unwritable reboot-reason parent, got nil")
	}
	// Sanity: boot reason DID get written (its parent was OK), so the
	// failure is provably from the second helper not the first.
	if _, statErr := os.Stat(bootPath); statErr != nil {
		t.Errorf("expected boot reason to be written before appendRebootReason fails, got stat err: %v", statErr)
	}
}

func TestRebootWithReasonRejectsNewline(t *testing.T) {
	err := RebootWithReason("first line\nsecond line")
	if err == nil {
		t.Fatal("expected error for reason with newline, got nil")
	}
	if !errors.Is(err, ErrInvalidRebootReason) {
		t.Errorf("expected ErrInvalidRebootReason in chain, got: %v", err)
	}
}
