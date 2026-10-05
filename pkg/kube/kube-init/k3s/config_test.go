// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
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

	"github.com/lf-edge/eve/pkg/kube/kube-init/encconfig"
	"github.com/lf-edge/eve/pkg/kube/kube-init/encstatus"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// shadowPaths reroutes the package's well-known paths onto tmp dirs
// for the lifetime of a single test. The returned configDir is the
// new value of K3sConfigDir.
func shadowPaths(t *testing.T) (configDir, userOverrideSrc string) {
	t.Helper()
	dir := t.TempDir()
	configDir = filepath.Join(dir, "k3s-cfg")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir configDir: %v", err)
	}
	userOverrideSrc = filepath.Join(dir, "user-override.yaml")

	origCD, origUO, origCW :=
		K3sConfigDir, UserOverrideSrc, clusterWaitFile
	K3sConfigDir = configDir
	UserOverrideSrc = userOverrideSrc
	clusterWaitFile = filepath.Join(dir, "cluster-wait")
	t.Cleanup(func() {
		K3sConfigDir = origCD
		UserOverrideSrc = origUO
		clusterWaitFile = origCW
	})
	return
}

// shadowEtcdInitialized points etcdMemberDir at an existing directory
// (initialized=true) or a path that does not exist (false), so tests can
// pick which side of the bootstrap-vs-rejoin decision they exercise
// without touching the real /var/lib/rancher tree.
func shadowEtcdInitialized(t *testing.T, initialized bool) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etcd", "member")
	if initialized {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("mkdir etcd member dir: %v", err)
		}
	}
	orig := etcdMemberDir
	etcdMemberDir = dir
	t.Cleanup(func() { etcdMemberDir = orig })
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
	encstatus.ResetForTest()
	t.Cleanup(encstatus.ResetForTest)
	cid := uuid.FromStringOrNil("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	encstatus.SetForTest(types.EdgeNodeClusterStatus{
		ClusterInterface:      "eth0",
		BootstrapNode:         true,
		JoinServerIP:          net.ParseIP("10.0.0.1"),
		EncryptedClusterToken: "ZW5jcnlwdGVk",
		ClusterIPPrefix: &net.IPNet{
			IP:   net.ParseIP("10.1.0.1"),
			Mask: net.CIDRMask(24, 32),
		},
		ClusterIPIsReady: true,
		ClusterID:        types.UUIDandVersion{UUID: cid},
	})
	cs, err := GetClusterStatus()
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if cs.ClusterInterface != "eth0" || cs.JoinServerIP != "10.0.0.1" ||
		cs.ClusterIP != "10.1.0.1" || cs.ClusterID != cid.String() ||
		cs.PrefixLen != 24 || !cs.IsBootstrapNode {
		t.Errorf("parsed wrong: %+v", cs)
	}
}

func TestGetClusterStatusNoDelivery(t *testing.T) {
	encstatus.ResetForTest()
	t.Cleanup(encstatus.ResetForTest)
	_, err := GetClusterStatus()
	if err == nil {
		t.Fatal("expected error on no delivery, got nil")
	}
	if !errors.Is(err, ErrClusterStatusUnavailable) {
		t.Errorf("expected ErrClusterStatusUnavailable in chain, got %v", err)
	}
}

func TestGetClusterTypeBranches(t *testing.T) {
	encconfig.ResetForTest()
	t.Cleanup(encconfig.ResetForTest)

	// No subscription delivery yet → Replicated, no error
	// (the kube-init default for devices the controller has not
	// configured yet).
	ct, err := GetClusterType()
	if err != nil {
		t.Fatalf("no delivery: %v", err)
	}
	if ct != ClusterTypeReplicated {
		t.Errorf("no delivery -> %v, want Replicated", ct)
	}

	cases := []struct {
		name string
		seed types.ClusterType
		want ClusterType
	}{
		{"explicit base", types.ClusterTypeK3sBase, ClusterTypeBase},
		{"explicit replicated", types.ClusterTypeReplicatedStorage, ClusterTypeReplicated},
		{"none defaults to replicated", types.ClusterTypeNone, ClusterTypeReplicated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encconfig.ResetForTest()
			encconfig.SetForTest(types.EdgeNodeClusterConfig{
				ClusterType: c.seed,
			})
			ct, err := GetClusterType()
			if err != nil {
				t.Errorf("unexpected err: %v", err)
			}
			if ct != c.want {
				t.Errorf("ct = %v, want %v", ct, c.want)
			}
		})
	}
}

func TestWriteNodeName(t *testing.T) {
	configDir, _ := shadowPaths(t)
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
	configDir, userOverride := shadowPaths(t)
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
	configDir, _ := shadowPaths(t)
	dlp := filepath.Join(configDir, DisableLocalPath)

	cases := []struct {
		name         string
		seedCT       *types.ClusterType // nil = no delivery
		wantExists   bool
		wantContent  string
		preSeedExist bool
	}{
		{"no delivery defaults to replicated -> dlp written",
			nil, true, disableLocalPathContent, false},
		{"replicated -> dlp written",
			ptrCT(types.ClusterTypeReplicatedStorage), true, disableLocalPathContent, false},
		{"none -> dlp written (default to replicated)",
			ptrCT(types.ClusterTypeNone), true, disableLocalPathContent, false},
		{"base -> dlp removed",
			ptrCT(types.ClusterTypeK3sBase), false, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_ = os.Remove(dlp)
			encconfig.ResetForTest()
			t.Cleanup(encconfig.ResetForTest)
			if c.preSeedExist {
				if err := os.WriteFile(dlp, []byte("stale"), 0644); err != nil {
					t.Fatalf("seed dlp: %v", err)
				}
			}
			if c.seedCT != nil {
				encconfig.SetForTest(types.EdgeNodeClusterConfig{
					ClusterType: *c.seedCT,
				})
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

// ptrCT is a small helper to take the address of a types.ClusterType
// literal in struct-literal-heavy tests.
func ptrCT(v types.ClusterType) *types.ClusterType { return &v }

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

	// Restart of a node that HAS already bootstrapped etcd: rejoin our
	// own cluster. The initialized datastore is what makes the rejoin
	// stanza correct here.
	shadowEtcdInitialized(t, true)
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

// TestWriteBootstrapConfigSingleToCluster covers the single→cluster
// transition: the device is past first boot (isFirstBoot=false) but has
// never initialized a managed-etcd datastore, because it was running
// single-node against kine. It must still cluster-init. Emitting the
// rejoin stanza points the node at its own apiserver, which cannot come
// up until bootstrap data exists, and k3s then dies on every restart
// with "Managed etcd cluster not yet initialized".
func TestWriteBootstrapConfigSingleToCluster(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "01-cluster.yaml")
	cs := &ClusterStatus{
		ClusterInterface: "eth0",
		JoinServerIP:     "10.0.0.1",
		EncryptedToken:   "tok",
		ClusterIP:        "10.0.0.1", // bootstrap node: JoinServerIP == own IP
		ClusterIPIsReady: true,
		ClusterID:        "u",
	}
	shadowEtcdInitialized(t, false)
	if err := writeBootstrapConfig(path, cs, false); err != nil {
		t.Fatalf("writeBootstrapConfig single→cluster: %v", err)
	}
	body := readFile(t, path)
	if !strings.Contains(body, "cluster-init: true\n") {
		t.Errorf("uninitialized etcd must cluster-init:\n%s", body)
	}
	if strings.Contains(body, "server:") {
		t.Errorf("must NOT point at its own apiserver (deadlock):\n%s", body)
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
	// Rejoin stanza only renders once etcd is initialized.
	shadowEtcdInitialized(t, true)
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
	_, _ = shadowPaths(t)

	// EncStatus must be Present so the in-loop check doesn't trip
	// the withdrawn-config path. Use a non-nil ClusterID UUID.
	encstatus.ResetForTest()
	t.Cleanup(encstatus.ResetForTest)
	encstatus.SetForTest(types.EdgeNodeClusterStatus{
		ClusterID: types.UUIDandVersion{
			UUID: uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555"),
		},
	})

	expectedUUID := "the-uuid"
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(api.Close)
	status := newClusterStatusTestServer(t, testJoinToken, "cluster:"+expectedUUID)

	if err := waitForBootstrapServer(context.Background(),
		api.URL, status.URL, expectedUUID, testJoinToken); err != nil {
		t.Fatalf("waitForBootstrapServer: %v", err)
	}
}

func TestWaitForBootstrapServerUUIDMismatchRetries(t *testing.T) {
	_, _ = shadowPaths(t)
	encstatus.ResetForTest()
	t.Cleanup(encstatus.ResetForTest)
	encstatus.SetForTest(types.EdgeNodeClusterStatus{
		ClusterID: types.UUIDandVersion{
			UUID: uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555"),
		},
	})

	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(api.Close)
	status := newClusterStatusTestServer(t, testJoinToken, "cluster:wrong-uuid")

	// joinPollInterval is a const (10s). Bound the test with a tight
	// ctx deadline so the mismatch loop hits ctx.Done after the
	// first immediate probe.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := waitForBootstrapServer(ctx, api.URL, status.URL, "expected-uuid", testJoinToken)
	if err == nil {
		t.Fatal("expected ctx deadline error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestWaitForBootstrapServerWithdrawnConfig(t *testing.T) {
	shadowPaths(t)
	// Do NOT seed encstatus; the first probe should detect the
	// missing payload and return ErrClusterStatusWithdrawn.
	encstatus.ResetForTest()
	t.Cleanup(encstatus.ResetForTest)

	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(api.Close)
	status := newClusterStatusTestServer(t, testJoinToken, "cluster:u")

	err := waitForBootstrapServer(context.Background(),
		api.URL, status.URL, "u", testJoinToken)
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

// TestRemoveServerTLSDirEmptiesTree pins the property the join path
// depends on: nothing signed by the retired CA may survive under
// server/tls — dynamic-cert.json and the nested etcd/ dir included —
// while the directory itself stays put.
func TestRemoveServerTLSDirEmptiesTree(t *testing.T) {
	root := t.TempDir()
	tlsRoot := filepath.Join(root, "server", "tls")
	ipsecPSK := filepath.Join(root, "server", "cred", "ipsec.psk")

	for _, rel := range []string{
		"server-ca.crt", "server-ca.key", "client-ca.crt", "client-ca.key",
		"dynamic-cert.json", "serving-kube-apiserver.crt", "service.current.key",
		"etcd/peer-ca.crt", "etcd/server-ca.crt", "temporary-certs/keep-out",
		"kube-scheduler/kube-scheduler.crt",
	} {
		p := filepath.Join(tlsRoot, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte("stale"), 0600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(ipsecPSK), 0700); err != nil {
		t.Fatalf("mkdir cred: %v", err)
	}
	if err := os.WriteFile(ipsecPSK, []byte("psk"), 0600); err != nil {
		t.Fatalf("write ipsec.psk: %v", err)
	}

	if err := removeServerTLSDir(tlsRoot, ipsecPSK); err != nil {
		t.Fatalf("removeServerTLSDir: %v", err)
	}

	entries, err := os.ReadDir(tlsRoot)
	if err != nil {
		t.Fatalf("tls dir must survive: %v", err)
	}
	if len(entries) != 0 {
		var left []string
		for _, e := range entries {
			left = append(left, e.Name())
		}
		t.Errorf("tls dir not empty, left behind: %v", left)
	}
	if _, err := os.Stat(ipsecPSK); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ipsec.psk still present (stat err = %v)", err)
	}
}

// TestRemoveServerTLSDirMissingTree covers a first-boot node that never
// wrote server/tls: absent paths are not an error.
func TestRemoveServerTLSDirMissingTree(t *testing.T) {
	root := t.TempDir()
	err := removeServerTLSDir(
		filepath.Join(root, "server", "tls"),
		filepath.Join(root, "server", "cred", "ipsec.psk"))
	if err != nil {
		t.Errorf("missing paths must be a no-op, got %v", err)
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

// TestRemoveServerTLSDirDropsDerivedKubeconfigs pins the fix for the
// stale-client failure: a kubeconfig embeds the CA, so it must not
// outlive the CA it describes.
//
// If one survives, WaitKubeconfig — which only waits for the file to
// exist — adopts it instantly and the readiness client is built against
// an authority that no longer exists. Every call then fails the TLS
// handshake against a perfectly healthy apiserver, which is how a
// correctly-joined edge-dev2 burned 5m13s and got rebooted by the join
// watchdog on 2026-08-05.
func TestRemoveServerTLSDirDropsDerivedKubeconfigs(t *testing.T) {
	root := t.TempDir()
	tlsRoot := filepath.Join(root, "server", "tls")
	ipsecPSK := filepath.Join(root, "server", "cred", "ipsec.psk")
	etcKubeconfig := filepath.Join(root, "etc-rancher", "k3s.yaml")
	runKubeconfig := filepath.Join(root, "run-kube", "k3s.yaml")

	if err := os.MkdirAll(tlsRoot, 0700); err != nil {
		t.Fatalf("mkdir tls: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tlsRoot, "server-ca.crt"),
		[]byte("retired-ca"), 0600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	for _, p := range []string{etcKubeconfig, runKubeconfig} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatalf("mkdir for %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte("certificate-authority-data: retired"),
			0600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	if err := removeServerTLSDir(tlsRoot, ipsecPSK,
		etcKubeconfig, runKubeconfig); err != nil {
		t.Fatalf("removeServerTLSDir: %v", err)
	}

	for _, p := range []string{etcKubeconfig, runKubeconfig} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived the CA it describes (stat err = %v)", p, err)
		}
	}

	// The parent directories must stay: k3s and the copy step write back
	// into them, and pillar's bind of the /run path must not break.
	for _, d := range []string{filepath.Dir(etcKubeconfig), filepath.Dir(runKubeconfig)} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			t.Errorf("directory %s must survive (err = %v)", d, err)
		}
	}
}

// TestRemoveServerTLSDirMissingKubeconfigs covers the first-boot and
// repeat-transition cases: a kubeconfig that was never written, or was
// already removed, is not an error.
func TestRemoveServerTLSDirMissingKubeconfigs(t *testing.T) {
	root := t.TempDir()
	err := removeServerTLSDir(
		filepath.Join(root, "server", "tls"),
		filepath.Join(root, "server", "cred", "ipsec.psk"),
		filepath.Join(root, "absent", "k3s.yaml"),
		filepath.Join(root, "also-absent", "k3s.yaml"))
	if err != nil {
		t.Errorf("absent kubeconfigs must be a no-op, got %v", err)
	}
}

// TestRemoveStaleCNIStateClearsSubnetAndReservations pins the property the
// join path depends on: nothing may survive that could hand a pod an address
// from the subnet this node owned while it ran standalone.
func TestRemoveStaleCNIStateClearsSubnetAndReservations(t *testing.T) {
	root := t.TempDir()
	subnetEnv := filepath.Join(root, "run", "flannel", "subnet.env")
	ipamDir := filepath.Join(root, "var", "lib", "cni", "networks", "cbr0")

	if err := os.MkdirAll(filepath.Dir(subnetEnv), 0755); err != nil {
		t.Fatalf("mkdir flannel: %v", err)
	}
	if err := os.WriteFile(subnetEnv,
		[]byte("FLANNEL_NETWORK=10.42.0.0/16\nFLANNEL_SUBNET=10.42.0.1/24\n"),
		0644); err != nil {
		t.Fatalf("write subnet.env: %v", err)
	}
	if err := os.MkdirAll(ipamDir, 0755); err != nil {
		t.Fatalf("mkdir ipam: %v", err)
	}
	for _, name := range []string{"10.42.0.2", "10.42.0.3", "last_reserved_ip.0"} {
		if err := os.WriteFile(filepath.Join(ipamDir, name), []byte("x"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := removeStaleCNIState(subnetEnv, ipamDir); err != nil {
		t.Fatalf("removeStaleCNIState: %v", err)
	}

	if _, err := os.Stat(subnetEnv); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("subnet.env survived (stat err = %v); a CNI ADD could still "+
			"read the retired subnet", err)
	}
	if _, err := os.Stat(ipamDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("IPAM reservations survived (stat err = %v)", err)
	}
}

// TestRemoveStaleCNIStateMissingPaths covers a node whose CNI never ran:
// absent paths are not an error.
func TestRemoveStaleCNIStateMissingPaths(t *testing.T) {
	root := t.TempDir()
	err := removeStaleCNIState(
		filepath.Join(root, "run", "flannel", "subnet.env"),
		filepath.Join(root, "var", "lib", "cni", "networks", "cbr0"))
	if err != nil {
		t.Errorf("missing paths must be a no-op, got %v", err)
	}
}

// shadowClusterIdentity reroutes clusterIdentityPath and k3sServerDir
// onto a fresh tmp dir for the lifetime of a single test, mirroring
// shadowPaths/shadowEtcdInitialized above.
func shadowClusterIdentity(t *testing.T) (identityPath, serverDir string) {
	t.Helper()
	dir := t.TempDir()
	identityPath = filepath.Join(dir, "cluster-identity")
	serverDir = filepath.Join(dir, "server")

	// Everything DiscardClusterState removes is redirected too, so a reset
	// under test can never touch the real node's files.
	origIdentity, origServer := clusterIdentityPath, k3sServerDir
	origLabels, origDebug, origKubeconfigs := nodeLabelsMarker, debugUserMarker, derivedKubeconfigs
	origSubnetEnv, origIPAM := flannelSubnetEnv, cniIPAMStateDir
	clusterIdentityPath = identityPath
	k3sServerDir = serverDir
	nodeLabelsMarker = state.Marker(filepath.Join(dir, "node-labels-initialized"))
	debugUserMarker = state.Marker(filepath.Join(dir, "debuguser-initialized"))
	derivedKubeconfigs = []string{filepath.Join(dir, "k3s.yaml")}
	flannelSubnetEnv = filepath.Join(dir, "subnet.env")
	cniIPAMStateDir = filepath.Join(dir, "cbr0")
	t.Cleanup(func() {
		clusterIdentityPath = origIdentity
		k3sServerDir = origServer
		nodeLabelsMarker, debugUserMarker, derivedKubeconfigs = origLabels, origDebug, origKubeconfigs
		flannelSubnetEnv, cniIPAMStateDir = origSubnetEnv, origIPAM
	})
	return
}

func TestClusterIdentityRoundTrip(t *testing.T) {
	shadowClusterIdentity(t)
	want := Generation{ClusterID: "aaaa-bbbb", Counter: 7}
	if err := writeClusterIdentity(want); err != nil {
		t.Fatalf("writeClusterIdentity: %v", err)
	}
	got, recorded, err := readClusterIdentity()
	if err != nil {
		t.Fatalf("readClusterIdentity: %v", err)
	}
	if !recorded || got != want {
		t.Errorf("readClusterIdentity = (%+v, %v), want (%+v, true)", got, recorded, want)
	}
}

func TestReadClusterIdentityNoFile(t *testing.T) {
	shadowClusterIdentity(t)
	identity, recorded, err := readClusterIdentity()
	if err != nil {
		t.Fatalf("readClusterIdentity: %v", err)
	}
	if recorded || identity != (Generation{}) {
		t.Errorf("no file must read as unrecorded, got (%+v, %v)", identity, recorded)
	}
}

// TestReadClusterIdentityLegacyFormat covers upgrading from a build
// that wrote only the ClusterID: it must read as unrecorded, not as a
// mismatch forcing a reset.
func TestReadClusterIdentityLegacyFormat(t *testing.T) {
	path, _ := shadowClusterIdentity(t)
	if err := os.WriteFile(path, []byte("aaaa-bbbb"), 0644); err != nil {
		t.Fatalf("write legacy identity file: %v", err)
	}
	identity, recorded, err := readClusterIdentity()
	if err != nil {
		t.Fatalf("readClusterIdentity: %v", err)
	}
	if recorded || identity != (Generation{}) {
		t.Errorf("legacy single-field file must read as unrecorded, got (%+v, %v)", identity, recorded)
	}
}

// TestResetStaleServerStateOnQuorumRecoveryGenerationChange pins the
// regression: a quorum-loss recovery keeps ClusterID unchanged and
// only bumps QuorumRecoveryGeneration, so a non-bootstrap node that
// held bootstrap state here before the reset must still reset it on
// rejoin.
func TestResetStaleServerStateOnQuorumRecoveryGenerationChange(t *testing.T) {
	_, serverDir := shadowClusterIdentity(t)

	// Same ClusterID, earlier recovery generation.
	if err := writeClusterIdentity(Generation{
		ClusterID: "u1", Counter: 1,
	}); err != nil {
		t.Fatalf("seed stale identity: %v", err)
	}
	sentinel := filepath.Join(serverDir, "tls", "server-ca.crt")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0700); err != nil {
		t.Fatalf("mkdir server dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("stale-ca"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	current := Generation{ClusterID: "u1", Counter: 2}
	reset, err := resetStaleServerState(current, false)
	if err != nil {
		t.Fatalf("resetStaleServerState: %v", err)
	}
	if !reset {
		t.Error("resetStaleServerState must report reset=true on a recovery-generation change")
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale server state must be reset on a recovery-generation "+
			"change (same ClusterID), stat err = %v", err)
	}
}

// TestResetStaleServerStateDefersGenerationChangeForBootstrapNode pins
// the regression: the node named bootstrap must not have its etcd
// datastore wiped for its own generation bump — quorum.Promote needs
// that data to recover from.
func TestResetStaleServerStateDefersGenerationChangeForBootstrapNode(t *testing.T) {
	_, serverDir := shadowClusterIdentity(t)

	if err := writeClusterIdentity(Generation{
		ClusterID: "u1", Counter: 1,
	}); err != nil {
		t.Fatalf("seed stale identity: %v", err)
	}
	sentinel := filepath.Join(serverDir, "db", "etcd")
	if err := os.MkdirAll(sentinel, 0700); err != nil {
		t.Fatalf("mkdir etcd datastore: %v", err)
	}

	current := Generation{ClusterID: "u1", Counter: 2}
	reset, err := resetStaleServerState(current, true)
	if err != nil {
		t.Fatalf("resetStaleServerState: %v", err)
	}
	if reset {
		t.Error("resetStaleServerState must report reset=false for a bootstrap node's own generation bump")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("bootstrap node's etcd datastore must survive its own generation bump, stat err = %v", err)
	}
}

// TestResetStaleServerStateClusterIDChangeAlwaysResetsBootstrapNode
// covers what the bootstrap gate above must not weaken: a genuine
// ClusterID change still resets regardless of role.
func TestResetStaleServerStateClusterIDChangeAlwaysResetsBootstrapNode(t *testing.T) {
	_, serverDir := shadowClusterIdentity(t)

	if err := writeClusterIdentity(Generation{
		ClusterID: "old-cluster", Counter: 1,
	}); err != nil {
		t.Fatalf("seed stale identity: %v", err)
	}
	sentinel := filepath.Join(serverDir, "tls", "server-ca.crt")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0700); err != nil {
		t.Fatalf("mkdir server dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("foreign-ca"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	current := Generation{ClusterID: "new-cluster", Counter: 1}
	reset, err := resetStaleServerState(current, true)
	if err != nil {
		t.Fatalf("resetStaleServerState: %v", err)
	}
	if !reset {
		t.Error("resetStaleServerState must report reset=true on a ClusterID change even for a bootstrap node")
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("foreign cluster's state must be reset, stat err = %v", err)
	}
}

// TestResetStaleServerStateNoResetWhenIdentityMatches is the control
// case: nothing is reset when the recorded identity already matches.
func TestResetStaleServerStateNoResetWhenIdentityMatches(t *testing.T) {
	_, serverDir := shadowClusterIdentity(t)

	current := Generation{ClusterID: "u1", Counter: 2}
	if err := writeClusterIdentity(current); err != nil {
		t.Fatalf("seed matching identity: %v", err)
	}
	sentinel := filepath.Join(serverDir, "tls", "server-ca.crt")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0700); err != nil {
		t.Fatalf("mkdir server dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("current-ca"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	reset, err := resetStaleServerState(current, false)
	if err != nil {
		t.Fatalf("resetStaleServerState: %v", err)
	}
	if reset {
		t.Error("resetStaleServerState must report reset=false when identity matches")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("matching identity must NOT reset existing server state, stat err = %v", err)
	}
}

// TestRecordSingleNodeIdentityReplacesClusterIdentity pins the failure
// where a cluster to single-node restore left the post-snapshot cluster
// identity next to the restored single-node TLS.
func TestRecordSingleNodeIdentityReplacesClusterIdentity(t *testing.T) {
	shadowClusterIdentity(t)
	if err := writeClusterIdentity(Generation{ClusterID: "u1", Counter: 3}); err != nil {
		t.Fatalf("seed cluster identity: %v", err)
	}
	if err := RecordSingleNodeIdentity(); err != nil {
		t.Fatalf("RecordSingleNodeIdentity: %v", err)
	}
	got, recorded, err := readClusterIdentity()
	if err != nil || !recorded {
		t.Fatalf("readClusterIdentity = %v, recorded=%v, err=%v", got, recorded, err)
	}
	if want := (Generation{ClusterID: SingleNodeClusterID}); got != want {
		t.Errorf("identity = %v, want %v", got, want)
	}
}

// TestResetStaleServerStateResetsRestoredSingleNodeStateForJoiner pins
// the post-rollback failure: a restore puts the node's own pre-cluster
// CA back, and a joining node must discard it rather than present it to
// the cluster ("certificate signed by unknown authority").
func TestResetStaleServerStateResetsRestoredSingleNodeStateForJoiner(t *testing.T) {
	_, serverDir := shadowClusterIdentity(t)

	if err := writeClusterIdentity(Generation{ClusterID: SingleNodeClusterID}); err != nil {
		t.Fatalf("seed single-node identity: %v", err)
	}
	sentinel := filepath.Join(serverDir, "tls", "server-ca.crt")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0700); err != nil {
		t.Fatalf("mkdir server dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("single-node-ca"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	reset, err := resetStaleServerState(Generation{ClusterID: "u1", Counter: 0}, false)
	if err != nil {
		t.Fatalf("resetStaleServerState: %v", err)
	}
	if !reset {
		t.Error("restored single-node state must be reset for a joining node")
	}
	if _, err := os.Stat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("single-node CA must be removed before joining, stat err = %v", err)
	}
}

// TestResetStaleServerStateKeepsRestoredSingleNodeStateForBootstrap is
// the counterpart: the bootstrap node seeds the cluster from its
// single-node datastore and CA, so they must survive.
func TestResetStaleServerStateKeepsRestoredSingleNodeStateForBootstrap(t *testing.T) {
	_, serverDir := shadowClusterIdentity(t)

	if err := writeClusterIdentity(Generation{ClusterID: SingleNodeClusterID}); err != nil {
		t.Fatalf("seed single-node identity: %v", err)
	}
	sentinel := filepath.Join(serverDir, "tls", "server-ca.crt")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0700); err != nil {
		t.Fatalf("mkdir server dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("single-node-ca"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	reset, err := resetStaleServerState(Generation{ClusterID: "u1", Counter: 0}, true)
	if err != nil {
		t.Fatalf("resetStaleServerState: %v", err)
	}
	if reset {
		t.Error("bootstrap node must keep its restored single-node state")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("bootstrap node's single-node CA must survive, stat err = %v", err)
	}
}

// seedClusterState creates, under the paths shadowClusterIdentity
// redirected, one file for each piece of state DiscardClusterState may
// remove, and returns them by name.
func seedClusterState(t *testing.T) map[string]string {
	t.Helper()
	paths := map[string]string{
		"datastore":   filepath.Join(k3sServerDir, "db", "state.db"),
		"tls":         filepath.Join(k3sServerDir, "tls", "server-ca.crt"),
		"ipsec":       filepath.Join(k3sServerDir, "cred", "ipsec.psk"),
		"kubeconfig":  derivedKubeconfigs[0],
		"subnet.env":  flannelSubnetEnv,
		"ipam":        filepath.Join(cniIPAMStateDir, "10.42.0.5"),
		"node-labels": string(nodeLabelsMarker),
		"debug-user":  string(debugUserMarker),
	}
	for name, p := range paths {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	return paths
}

// TestDiscardClusterState pins what each caller drops. The two failures
// it guards: a reset that left the node-labels marker set, so the rejoined
// Node object never got its Longhorn default-disk label and annotation and
// the node's app volumes were never created; and a debug-user certificate
// signed by a client CA the reset had removed, never regenerated.
func TestDiscardClusterState(t *testing.T) {
	cases := []struct {
		name          string
		isBootstrap   bool
		wipeServerDir bool
		// gone lists the state that must be removed; everything else
		// seeded must survive.
		gone []string
	}{
		{
			name: "joiner after the single to cluster transition",
			gone: []string{"tls", "ipsec", "kubeconfig", "subnet.env", "ipam", "node-labels", "debug-user"},
		},
		{
			name:        "bootstrap after the single to cluster transition",
			isBootstrap: true,
			gone:        []string{"node-labels"},
		},
		{
			name:          "joiner whose state belongs to a different cluster",
			wipeServerDir: true,
			gone: []string{"datastore", "tls", "ipsec", "kubeconfig", "subnet.env", "ipam",
				"node-labels", "debug-user"},
		},
		{
			name:          "bootstrap whose state belongs to a different cluster",
			isBootstrap:   true,
			wipeServerDir: true,
			gone:          []string{"datastore", "tls", "ipsec", "kubeconfig", "node-labels", "debug-user"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shadowClusterIdentity(t)
			paths := seedClusterState(t)

			if err := DiscardClusterState(tc.isBootstrap, tc.wipeServerDir); err != nil {
				t.Fatalf("DiscardClusterState: %v", err)
			}

			gone := map[string]bool{}
			for _, name := range tc.gone {
				gone[name] = true
			}
			for name, p := range paths {
				_, err := os.Stat(p)
				switch {
				case gone[name] && !errors.Is(err, os.ErrNotExist):
					t.Errorf("%s must be removed, stat err = %v", name, err)
				case !gone[name] && err != nil:
					t.Errorf("%s must survive, stat err = %v", name, err)
				}
			}
		})
	}
}

// TestResetStaleServerStateNoRecordYet is the upgrade-safety case: a
// device with no recorded identity at all (e.g. upgrading from a build
// that never tracked one) must not be disrupted.
func TestResetStaleServerStateNoRecordYet(t *testing.T) {
	_, serverDir := shadowClusterIdentity(t)
	sentinel := filepath.Join(serverDir, "tls", "server-ca.crt")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0700); err != nil {
		t.Fatalf("mkdir server dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("existing-ca"), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	reset, err := resetStaleServerState(Generation{ClusterID: "u1", Counter: 2}, false)
	if err != nil {
		t.Fatalf("resetStaleServerState: %v", err)
	}
	if reset {
		t.Error("resetStaleServerState must report reset=false with no prior record")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("no prior record must NOT reset existing server state, stat err = %v", err)
	}
}
