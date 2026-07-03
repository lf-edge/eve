// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStampPersistRecreatedAddsFieldAndPreservesRest(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resize-failed.json")
	// the shape storage-init's resize_abort writes (no persist_recreated yet)
	orig := `{"eve_release":"1.2.3","step":"shrink","rc":"1","ts":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := stampPersistRecreated(p); err != nil {
		t.Fatalf("stampPersistRecreated: %v", err)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if m["persist_recreated"] != true {
		t.Errorf("persist_recreated = %v, want true", m["persist_recreated"])
	}
	for k, want := range map[string]string{
		"eve_release": "1.2.3", "step": "shrink", "rc": "1", "ts": "2026-01-01T00:00:00Z",
	} {
		if m[k] != want {
			t.Errorf("field %q = %v, want %q", k, m[k], want)
		}
	}
}

func TestStampPersistRecreatedMissingFile(t *testing.T) {
	if err := stampPersistRecreated(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Error("expected an error for a missing marker")
	}
}

func TestStampPersistRecreatedMalformed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resize-failed.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := stampPersistRecreated(p); err == nil {
		t.Error("expected an error for a malformed marker")
	}
}
