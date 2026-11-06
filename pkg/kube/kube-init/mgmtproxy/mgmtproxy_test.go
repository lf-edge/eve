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

// redirectTokenFile points TokenFile at t.TempDir() so tests never touch a
// real /persist/vault path.
func redirectTokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	old := TokenFile
	TokenFile = path
	t.Cleanup(func() { TokenFile = old })
	return path
}

func TestReadProxyTokenMissingFile(t *testing.T) {
	redirectTokenFile(t)
	if _, err := readProxyToken(); err == nil {
		t.Error("readProxyToken() with no file present should error, got nil")
	}
}

func TestReadProxyTokenEmptyFile(t *testing.T) {
	path := redirectTokenFile(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed empty token file: %v", err)
	}
	if _, err := readProxyToken(); err == nil {
		t.Error("readProxyToken() with an empty file should error, got nil")
	}
}

// TestReadProxyTokenMatchesPillarWriter simulates the real cross-process
// setup: pillar's mgmtproxy writes the token file (trailing newline and all,
// matching os.WriteFile of a plain string), kube-init only reads it.
func TestReadProxyTokenMatchesPillarWriter(t *testing.T) {
	path := redirectTokenFile(t)
	if err := os.WriteFile(path, []byte("deadbeef1234\n"), 0o600); err != nil {
		t.Fatalf("seed token file: %v", err)
	}
	got, err := readProxyToken()
	if err != nil {
		t.Fatalf("readProxyToken: %v", err)
	}
	if got != "deadbeef1234" {
		t.Errorf("got %q, want trimmed %q", got, "deadbeef1234")
	}
}

// redirectTLSCertFile points TLSCertFile at t.TempDir() so tests never touch
// a real /persist/vault path.
func redirectTLSCertFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cert.pem")
	old := TLSCertFile
	TLSCertFile = path
	t.Cleanup(func() { TLSCertFile = old })
	return path
}

func TestReadProxyCACertMissingFile(t *testing.T) {
	redirectTLSCertFile(t)
	if _, err := readProxyCACert(); err == nil {
		t.Error("readProxyCACert() with no file present should error, got nil")
	}
}

func TestReadProxyCACertEmptyFile(t *testing.T) {
	path := redirectTLSCertFile(t)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("seed empty cert file: %v", err)
	}
	if _, err := readProxyCACert(); err == nil {
		t.Error("readProxyCACert() with an empty file should error, got nil")
	}
}

// TestReadProxyCACertMatchesPillarWriter simulates the real cross-process
// setup: pillar's mgmtproxy writes the PEM cert file, kube-init only reads
// it verbatim (no trimming — it's embedded as-is in a ConfigMap).
func TestReadProxyCACertMatchesPillarWriter(t *testing.T) {
	path := redirectTLSCertFile(t)
	const pem = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(pem), 0o644); err != nil {
		t.Fatalf("seed cert file: %v", err)
	}
	got, err := readProxyCACert()
	if err != nil {
		t.Fatalf("readProxyCACert: %v", err)
	}
	if string(got) != pem {
		t.Errorf("got %q, want %q", got, pem)
	}
}

func TestWithProxyToken(t *testing.T) {
	got := withProxyToken("http://169.254.100.1:5443", "deadbeef1234")
	want := "http://cdi:deadbeef1234@169.254.100.1:5443"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWithProxyTokenInvalidURLFallsBack(t *testing.T) {
	// A control character makes url.Parse fail; withProxyToken must return
	// the input unchanged rather than panic or silently drop the token.
	bad := "http://\x7f"
	if got := withProxyToken(bad, "deadbeef"); got != bad {
		t.Errorf("got %q, want unchanged %q", got, bad)
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
