// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build faultinjection

package evetpm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTakeKeyPresenceFault(t *testing.T) {
	saved := keyPresenceFaultFile
	keyPresenceFaultFile = filepath.Join(t.TempDir(), "tpm-key-presence-fault")
	t.Cleanup(func() { keyPresenceFaultFile = saved })

	if takeKeyPresenceFault() {
		t.Fatalf("fault taken with no marker")
	}

	if err := os.WriteFile(keyPresenceFaultFile, []byte("2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for i, want := range []bool{true, true, false, false} {
		if got := takeKeyPresenceFault(); got != want {
			t.Fatalf("check %d with a count of 2: got %v, want %v", i+1, got, want)
		}
	}
	if data, err := os.ReadFile(keyPresenceFaultFile); err != nil || string(data) != "0" {
		t.Fatalf("marker after the count ran out: %q, %v", data, err)
	}

	if err := os.WriteFile(keyPresenceFaultFile, []byte("always"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if !takeKeyPresenceFault() {
			t.Fatalf("check %d with \"always\" was not failed", i+1)
		}
	}

	if err := os.WriteFile(keyPresenceFaultFile, []byte("bogus"), 0644); err != nil {
		t.Fatal(err)
	}
	if takeKeyPresenceFault() {
		t.Fatalf("fault taken with an unparsable marker")
	}
}
