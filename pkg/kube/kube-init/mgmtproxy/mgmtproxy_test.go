// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package mgmtproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// redirectPaths points DisableFlag and SentinelFile at t.TempDir()
// so tests are isolated from any real /run state and from each
// other.
func redirectPaths(t *testing.T) (disable, sentinel string) {
	t.Helper()
	dir := t.TempDir()
	disable = filepath.Join(dir, "disable")
	sentinel = filepath.Join(dir, "sentinel")
	oldD, oldS := DisableFlag, SentinelFile
	DisableFlag = disable
	SentinelFile = sentinel
	t.Cleanup(func() {
		DisableFlag = oldD
		SentinelFile = oldS
	})
	return
}

func TestEnabled_NoFlag(t *testing.T) {
	redirectPaths(t)
	if !Enabled() {
		t.Error("Enabled() should be true when DisableFlag does not exist")
	}
}

func TestEnabled_FlagPresent(t *testing.T) {
	disable, _ := redirectPaths(t)
	if err := os.WriteFile(disable, nil, 0o644); err != nil {
		t.Fatalf("seed disable: %v", err)
	}
	if Enabled() {
		t.Error("Enabled() should be false when DisableFlag exists")
	}
}

func TestNoProxy_NoClusterIP(t *testing.T) {
	got := NoProxy("", 0)
	want := baseNoProxy
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNoProxy_ClusterIPNoPrefix(t *testing.T) {
	got := NoProxy("10.1.2.3", 0)
	want := baseNoProxy + ",10.1.2.3"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNoProxy_ClusterIPWithPrefix(t *testing.T) {
	got := NoProxy("10.1.2.3", 24)
	want := baseNoProxy + ",10.1.2.3/24"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNoProxy_NegativePrefixTreatedAsUnknown(t *testing.T) {
	// Defensive — caller passes zero or negative when ENC status
	// hasn't published the mask yet. Should fall back to bare IP,
	// not emit "10.1.2.3/-1".
	got := NoProxy("10.1.2.3", -1)
	want := baseNoProxy + ",10.1.2.3"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEnv_Enabled(t *testing.T) {
	redirectPaths(t)
	env := Env("10.1.2.3", 24)
	if len(env) != 2 {
		t.Fatalf("got %d env entries, want 2", len(env))
	}
	if env[0] != "HTTPS_PROXY="+URL {
		t.Errorf("env[0] = %q, want HTTPS_PROXY=%s", env[0], URL)
	}
	if !strings.HasPrefix(env[1], "NO_PROXY=") ||
		!strings.HasSuffix(env[1], ",10.1.2.3/24") {
		t.Errorf("env[1] = %q does not look like NO_PROXY=...,10.1.2.3/24", env[1])
	}
}

func TestEnv_Disabled(t *testing.T) {
	disable, _ := redirectPaths(t)
	if err := os.WriteFile(disable, nil, 0o644); err != nil {
		t.Fatalf("seed disable: %v", err)
	}
	if env := Env("10.1.2.3", 24); env != nil {
		t.Errorf("Env() should be nil when disabled, got %v", env)
	}
}

func TestWriteContainerdSentinel_Enabled(t *testing.T) {
	_, sentinel := redirectPaths(t)
	if err := WriteContainerdSentinel(12345, "10.1.2.3", 24); err != nil {
		t.Fatalf("WriteContainerdSentinel: %v", err)
	}
	body, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	s := string(body)
	for _, want := range []string{
		"pid=12345",
		"started=",
		"HTTPS_PROXY=" + URL,
		"NO_PROXY=" + baseNoProxy + ",10.1.2.3/24",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("sentinel body missing %q\n--- body ---\n%s", want, s)
		}
	}
}

func TestWriteContainerdSentinel_Disabled(t *testing.T) {
	disable, sentinel := redirectPaths(t)
	if err := os.WriteFile(disable, nil, 0o644); err != nil {
		t.Fatalf("seed disable: %v", err)
	}
	if err := WriteContainerdSentinel(12345, "10.1.2.3", 24); err != nil {
		t.Fatalf("WriteContainerdSentinel: %v", err)
	}
	body, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "HTTPS_PROXY=(disabled") {
		t.Errorf("expected disabled marker in sentinel, got:\n%s", s)
	}
	if strings.Contains(s, "NO_PROXY="+baseNoProxy) {
		t.Errorf("disabled sentinel should not name the proxy NO_PROXY list:\n%s", s)
	}
}
