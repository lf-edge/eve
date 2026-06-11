// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shadowPaths reroutes the package's well-known paths onto tmp dirs
// for the lifetime of a single test. The returned configDir is the
// new value of K3sConfigDir.
func shadowPaths(t *testing.T) (configDir, userOverrideSrc, encStatus, clusterCfg string) {
	t.Helper()
	dir := t.TempDir()
	configDir = filepath.Join(dir, "k3s-cfg")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir configDir: %v", err)
	}
	userOverrideSrc = filepath.Join(dir, "user-override.yaml")
	encStatus = filepath.Join(dir, "EdgeNodeClusterStatus.json")
	clusterCfg = filepath.Join(dir, "EdgeNodeClusterConfig.json")

	origCD, origUO, origES, origCC, origCW :=
		K3sConfigDir, UserOverrideSrc, EncStatusFile, ClusterConfigFile, clusterWaitFile
	K3sConfigDir = configDir
	UserOverrideSrc = userOverrideSrc
	EncStatusFile = encStatus
	ClusterConfigFile = clusterCfg
	clusterWaitFile = filepath.Join(dir, "cluster-wait")
	t.Cleanup(func() {
		K3sConfigDir = origCD
		UserOverrideSrc = origUO
		EncStatusFile = origES
		ClusterConfigFile = origCC
		clusterWaitFile = origCW
	})
	return
}

func TestBracketIPv6(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"10.0.0.1", "10.0.0.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"::1", "[::1]"},
		{"2001:db8::1", "[2001:db8::1]"},
		{"fe80::1", "[fe80::1]"},
		{"", ""},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tc := range cases {
		if got := bracketIPv6(tc.in); got != tc.want {
			t.Errorf("bracketIPv6(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseIPField(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{"ipv4 string", `"10.0.0.1"`, "10.0.0.1"},
		{"ipv6 string", `"2001:db8::1"`, "2001:db8::1"},
		{"null", "null", ""},
		{"object", `{"a":1}`, ""},
		{"number", "42", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseIPField(json.RawMessage(tc.raw))
			if got != tc.want {
				t.Errorf("parseIPField(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestClusterStatusValidate(t *testing.T) {
	full := ClusterStatus{
		ClusterInterface: "eth0",
		JoinServerIP:     "10.0.0.1",
		EncryptedToken:   "secret",
		ClusterIP:        "10.1.0.1",
		ClusterIPIsReady: true,
		ClusterID:        "uuid-1",
	}
	if err := full.validate(); err != nil {
		t.Fatalf("full validate: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*ClusterStatus)
	}{
		{"missing iface", func(cs *ClusterStatus) { cs.ClusterInterface = "" }},
		{"missing join ip", func(cs *ClusterStatus) { cs.JoinServerIP = "" }},
		{"missing token", func(cs *ClusterStatus) { cs.EncryptedToken = "" }},
		{"missing cluster ip", func(cs *ClusterStatus) { cs.ClusterIP = "" }},
		{"ip not ready", func(cs *ClusterStatus) { cs.ClusterIPIsReady = false }},
		{"missing uuid", func(cs *ClusterStatus) { cs.ClusterID = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cs := full
			c.mut(&cs)
			if err := cs.validate(); err == nil {
				t.Errorf("expected validate to fail for %s, got nil", c.name)
			}
		})
	}
}

func TestClusterTypeIsValid(t *testing.T) {
	cases := []struct {
		ct   ClusterType
		want bool
	}{
		{ClusterTypeUnspecified, true},
		{ClusterTypeBase, true},
		{ClusterTypeReplicated, true},
		{ClusterType(3), false},
		{ClusterType(-1), false},
	}
	for _, c := range cases {
		if got := c.ct.IsValid(); got != c.want {
			t.Errorf("ClusterType(%d).IsValid() = %v, want %v", c.ct, got, c.want)
		}
	}
}

func TestGetClusterStatusRoundTrip(t *testing.T) {
	_, _, encStatus, _ := shadowPaths(t)
	payload := `{
        "ClusterInterface": "eth0",
        "BootstrapNode": true,
        "JoinServerIP": "10.0.0.1",
        "EncryptedClusterToken": "ZW5jcnlwdGVk",
        "ClusterIPPrefix": {"IP": "10.1.0.1"},
        "ClusterIPIsReady": true,
        "ClusterID": {"UUID": "abc-123"}
    }`
	if err := os.WriteFile(encStatus, []byte(payload), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cs, err := GetClusterStatus()
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if cs.ClusterInterface != "eth0" || cs.JoinServerIP != "10.0.0.1" ||
		cs.ClusterIP != "10.1.0.1" || cs.ClusterID != "abc-123" ||
		!cs.IsBootstrapNode {
		t.Errorf("parsed wrong: %+v", cs)
	}
}

func TestGetClusterStatusMissingFile(t *testing.T) {
	shadowPaths(t)
	_, err := GetClusterStatus()
	if err == nil {
		t.Fatal("expected error on missing file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist in chain, got %v", err)
	}
}

func TestGetClusterTypeBranches(t *testing.T) {
	_, _, _, clusterCfg := shadowPaths(t)

	// Missing file → Replicated, no error.
	ct, err := GetClusterType()
	if err != nil {
		t.Fatalf("missing file: %v", err)
	}
	if ct != ClusterTypeReplicated {
		t.Errorf("missing file -> %v, want Replicated", ct)
	}

	cases := []struct {
		name    string
		payload string
		want    ClusterType
		wantErr bool
	}{
		{"explicit base", `{"ClusterType": 1}`, ClusterTypeBase, false},
		{"explicit replicated", `{"ClusterType": 2}`, ClusterTypeReplicated, false},
		{"omitted field defaults to replicated", `{}`, ClusterTypeReplicated, false},
		{"unknown int passes through", `{"ClusterType": 99}`, ClusterType(99), false},
		{"malformed json", `not-json`, ClusterTypeReplicated, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(clusterCfg, []byte(c.payload), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			ct, err := GetClusterType()
			if (err != nil) != c.wantErr {
				t.Errorf("err=%v wantErr=%v", err, c.wantErr)
			}
			if ct != c.want {
				t.Errorf("ct = %v, want %v", ct, c.want)
			}
		})
	}
}

func TestWriteNodeName(t *testing.T) {
	configDir, _, _, _ := shadowPaths(t)
	if err := WriteNodeName("My_Node_01"); err != nil {
		t.Fatalf("WriteNodeName: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(configDir, NodeNameConfig))
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(body) != "node-name: my-node-01\n" {
		t.Errorf("body = %q, want %q", string(body), "node-name: my-node-01\n")
	}
}

func TestApplyUserOverridesBranches(t *testing.T) {
	configDir, userOverride, _, _ := shadowPaths(t)
	dst := filepath.Join(configDir, UserOverrideConfig)

	// No src, no dst → no change, no error.
	changed, err := ApplyUserOverrides()
	if err != nil || changed {
		t.Errorf("no-src-no-dst: changed=%v err=%v", changed, err)
	}

	// Src exists, dst missing → create dst, changed=true.
	if err := os.WriteFile(userOverride, []byte("foo: bar\n"), 0644); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	changed, err = ApplyUserOverrides()
	if err != nil || !changed {
		t.Errorf("src-only first apply: changed=%v err=%v", changed, err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "foo: bar\n" {
		t.Errorf("dst content = %q", string(got))
	}

	// Src matches dst → no change.
	changed, err = ApplyUserOverrides()
	if err != nil || changed {
		t.Errorf("matched: changed=%v err=%v", changed, err)
	}

	// Src changes → dst updated, changed=true.
	if err := os.WriteFile(userOverride, []byte("baz: qux\n"), 0644); err != nil {
		t.Fatalf("rewrite src: %v", err)
	}
	changed, err = ApplyUserOverrides()
	if err != nil || !changed {
		t.Errorf("src-changed: changed=%v err=%v", changed, err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "baz: qux\n" {
		t.Errorf("dst after update = %q", string(got))
	}

	// Src removed → dst removed, changed=true.
	if err := os.Remove(userOverride); err != nil {
		t.Fatalf("remove src: %v", err)
	}
	changed, err = ApplyUserOverrides()
	if err != nil || !changed {
		t.Errorf("src-removed: changed=%v err=%v", changed, err)
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("dst should be gone, stat err = %v", statErr)
	}

	// Src still absent, dst still absent → no change.
	changed, err = ApplyUserOverrides()
	if err != nil || changed {
		t.Errorf("steady-absent: changed=%v err=%v", changed, err)
	}
}

func TestProvisionDisableLocalPathBranches(t *testing.T) {
	configDir, _, _, clusterCfg := shadowPaths(t)
	dlp := filepath.Join(configDir, DisableLocalPath)

	cases := []struct {
		name         string
		clusterCfg   string // empty = no file
		wantExists   bool
		wantContent  string
		preSeedExist bool
	}{
		{"missing file defaults to replicated -> dlp written",
			"", true, disableLocalPathContent, false},
		{"replicated -> dlp written",
			`{"ClusterType":2}`, true, disableLocalPathContent, false},
		{"unspecified -> dlp written",
			`{"ClusterType":0}`, true, disableLocalPathContent, false},
		{"base -> dlp removed",
			`{"ClusterType":1}`, false, "", true},
		{"unknown -> dlp written (default to replicated)",
			`{"ClusterType":99}`, true, disableLocalPathContent, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_ = os.Remove(dlp)
			_ = os.Remove(clusterCfg)
			if c.preSeedExist {
				if err := os.WriteFile(dlp, []byte("stale"), 0644); err != nil {
					t.Fatalf("seed dlp: %v", err)
				}
			}
			if c.clusterCfg != "" {
				if err := os.WriteFile(clusterCfg, []byte(c.clusterCfg), 0644); err != nil {
					t.Fatalf("seed cfg: %v", err)
				}
			}
			if err := provisionDisableLocalPath(); err != nil {
				t.Fatalf("provisionDisableLocalPath: %v", err)
			}
			body, err := os.ReadFile(dlp)
			gone := errors.Is(err, os.ErrNotExist)
			if c.wantExists && gone {
				t.Errorf("expected dlp present, got missing")
			}
			if !c.wantExists && !gone {
				t.Errorf("expected dlp absent, got present (body=%q)", string(body))
			}
			if c.wantExists && string(body) != c.wantContent {
				t.Errorf("dlp body = %q, want %q", string(body), c.wantContent)
			}
		})
	}
}

func TestWriteBootstrapConfigShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "01-cluster.yaml")
	cs := &ClusterStatus{
		ClusterInterface: "eth0",
		JoinServerIP:     "10.0.0.1",
		EncryptedToken:   "tok",
		ClusterIP:        "10.1.0.1",
		ClusterIPIsReady: true,
		ClusterID:        "u",
	}
	if err := writeBootstrapConfig(path, cs, true); err != nil {
		t.Fatalf("writeBootstrapConfig firstBoot: %v", err)
	}
	body := readFile(t, path)
	for _, sub := range []string{
		"cluster-init: true\n",
		"token: \"tok\"\n",
		"tls-san:\n",
		"  - \"10.0.0.1\"\n",
		"flannel-iface: \"eth0\"\n",
		"node-ip: \"10.1.0.1\"\n",
	} {
		if !strings.Contains(body, sub) {
			t.Errorf("first-boot missing %q:\n%s", sub, body)
		}
	}
	if strings.Contains(body, "server:") {
		t.Errorf("first-boot must NOT contain server:\n%s", body)
	}

	if err := writeBootstrapConfig(path, cs, false); err != nil {
		t.Fatalf("writeBootstrapConfig restart: %v", err)
	}
	body = readFile(t, path)
	if !strings.Contains(body, `server: "https://10.0.0.1:6443"`) {
		t.Errorf("restart missing server stanza:\n%s", body)
	}
	if strings.Contains(body, "cluster-init:") {
		t.Errorf("restart must NOT contain cluster-init:\n%s", body)
	}
}

func TestWriteBootstrapConfigBracketsIPv6(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "01-cluster.yaml")
	cs := &ClusterStatus{
		ClusterInterface: "eth0",
		JoinServerIP:     "2001:db8::1",
		EncryptedToken:   "tok",
		ClusterIP:        "2001:db8::2",
		ClusterIPIsReady: true,
		ClusterID:        "u",
	}
	if err := writeBootstrapConfig(path, cs, false); err != nil {
		t.Fatalf("writeBootstrapConfig: %v", err)
	}
	body := readFile(t, path)
	if !strings.Contains(body, `server: "https://[2001:db8::1]:6443"`) {
		t.Errorf("IPv6 not bracketed in URL:\n%s", body)
	}
	if !strings.Contains(body, `  - "2001:db8::1"`) {
		t.Errorf("tls-san should hold raw IPv6:\n%s", body)
	}
}

func TestWriteJoinConfigShape(t *testing.T) {
	// isFirstBoot=false avoids entering waitForBootstrapServer.
	dir := t.TempDir()
	path := filepath.Join(dir, "01-cluster.yaml")
	cs := &ClusterStatus{
		ClusterInterface: "eth0",
		JoinServerIP:     "10.0.0.1",
		EncryptedToken:   "tok",
		ClusterIP:        "10.1.0.1",
		ClusterIPIsReady: true,
		ClusterID:        "u",
	}
	if err := writeJoinConfig(context.Background(), path, cs, false); err != nil {
		t.Fatalf("writeJoinConfig: %v", err)
	}
	body := readFile(t, path)
	if !strings.Contains(body, `server: "https://10.0.0.1:6443"`) {
		t.Errorf("missing server stanza:\n%s", body)
	}
	if strings.Contains(body, "cluster-init:") || strings.Contains(body, "tls-san:") {
		t.Errorf("join config must NOT contain cluster-init or tls-san:\n%s", body)
	}
}

func TestWaitForBootstrapServerHappyPath(t *testing.T) {
	_, _, encStatus, _ := shadowPaths(t)

	// EncStatusFile must exist so the in-loop stat doesn't trip the
	// withdrawn-config path.
	if err := os.WriteFile(encStatus, []byte("{}"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	expectedUUID := "the-uuid"
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(api.Close)
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cluster:" + expectedUUID))
	}))
	t.Cleanup(status.Close)

	if err := waitForBootstrapServer(context.Background(),
		api.URL, status.URL, expectedUUID); err != nil {
		t.Fatalf("waitForBootstrapServer: %v", err)
	}
}

func TestWaitForBootstrapServerUUIDMismatchRetries(t *testing.T) {
	_, _, encStatus, _ := shadowPaths(t)
	if err := os.WriteFile(encStatus, []byte("{}"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(api.Close)
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cluster:wrong-uuid"))
	}))
	t.Cleanup(status.Close)

	// joinPollInterval is a const (10s). Bound the test with a tight
	// ctx deadline so the mismatch loop hits ctx.Done after the
	// first immediate probe.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := waitForBootstrapServer(ctx, api.URL, status.URL, "expected-uuid")
	if err == nil {
		t.Fatal("expected ctx deadline error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestWaitForBootstrapServerWithdrawnConfig(t *testing.T) {
	shadowPaths(t)
	// Do NOT seed EncStatusFile; the first probe should detect the
	// missing file and return ErrClusterStatusWithdrawn.

	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(api.Close)
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cluster:u"))
	}))
	t.Cleanup(status.Close)

	err := waitForBootstrapServer(context.Background(),
		api.URL, status.URL, "u")
	if err == nil {
		t.Fatal("expected withdrawn-config error, got nil")
	}
	if !errors.Is(err, ErrClusterStatusWithdrawn) {
		t.Errorf("expected ErrClusterStatusWithdrawn, got %v", err)
	}
}

func TestClassifyHTTPErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want probeErrClass
	}{
		{"nil is transient", nil, probeTransient},
		{"dns not-found is non-transient",
			&net.DNSError{IsNotFound: true}, probeNonTransient},
		{"dns timeout is transient",
			&net.DNSError{IsTimeout: true}, probeTransient},
		{"unknown-error is transient",
			errors.New("connection refused"), probeTransient},
		{"url.Error wrapping dns NXDOMAIN is non-transient",
			&url.Error{Err: &net.DNSError{IsNotFound: true}}, probeNonTransient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyHTTPErr(c.err); got != c.want {
				t.Errorf("classifyHTTPErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
