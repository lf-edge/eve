// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSameToken(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"K10abc::server:s3cret", "s3cret", true},
		{"K10abc::server:s3cret\n", "K10def::server:s3cret", true},
		{"K10abc::server:old", "new", false},
		{"s3cret", "s3cret", true},
	}
	for _, c := range cases {
		if got := SameToken(c.a, c.b); got != c.want {
			t.Errorf("SameToken(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestAlternateToken covers both orders a token change can land in: k3s
// rejecting the controller token (bootstrap not yet rotated) and k3s
// rejecting the stored one after a fallback (bootstrap has rotated).
func TestAlternateToken(t *testing.T) {
	const controller, stored = "new", "K10abc::server:old"
	cases := []struct {
		name, rejected, stored, want string
	}{
		{"controller rejected", controller, stored, stored},
		{"stored rejected", stored, stored, controller},
		{"nothing else to try", controller, "K10abc::server:new", ""},
		{"no stored token", controller, "", ""},
	}
	for _, c := range cases {
		if got := alternateToken(c.rejected, controller, c.stored); got != c.want {
			t.Errorf("%s: alternateToken = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestConfiguredTokenReadsWrittenConfig keeps the parser in step with
// the format the bootstrap and join writers emit.
func TestConfiguredTokenReadsWrittenConfig(t *testing.T) {
	cs := &ClusterStatus{
		ClusterInterface: "eth0",
		JoinServerIP:     "10.0.0.1",
		EncryptedToken:   "K10abc::server:tok",
		ClusterIP:        "10.1.0.2",
		ClusterIPIsReady: true,
		ClusterID:        "u",
	}
	dir := t.TempDir()
	boot := filepath.Join(dir, "boot.yaml")
	if err := writeBootstrapConfig(boot, cs, true); err != nil {
		t.Fatalf("writeBootstrapConfig: %v", err)
	}
	join := filepath.Join(dir, "join.yaml")
	if err := writeJoinConfig(t.Context(), join, cs, false); err != nil {
		t.Fatalf("writeJoinConfig: %v", err)
	}
	for _, p := range []string{boot, join} {
		got, err := configuredToken(p)
		if err != nil || got != cs.EncryptedToken {
			t.Errorf("configuredToken(%s) = %q, %v; want %q", filepath.Base(p), got, err, cs.EncryptedToken)
		}
	}
}

// TestLogTailContainsOnlyLastRun checks that a fatal from an earlier run
// is not attributed to the run that started at offset start.
func TestLogTailContainsOnlyLastRun(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k3s.log")
	// Written out as k3s v1.34.2 logs it, not built from tokenMismatchFatal,
	// so an edit to the constant that no longer matches k3s fails here.
	earlier := `time="2026-01-01T00:00:00Z" level=fatal msg="Error: starting kubernetes: ` +
		`preparing server: failed to bootstrap cluster data: ` +
		`bootstrap data already found and encrypted with different token"` + "\n"
	if err := os.WriteFile(p, []byte(earlier), 0644); err != nil {
		t.Fatal(err)
	}
	start := int64(len(earlier))
	appendLog := func(s string) {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}

	appendLog("level=info msg=\"Running kube-apiserver\"\n")
	if logTailContains(p, start, tokenMismatchFatal) {
		t.Error("fatal from an earlier run reported for the last run")
	}
	appendLog(earlier)
	if !logTailContains(p, start, tokenMismatchFatal) {
		t.Error("fatal in the last run not detected")
	}
	if !logTailContains(p, 1<<20, tokenMismatchFatal) {
		t.Error("a log rotated below the start offset must be scanned from its head")
	}
}
