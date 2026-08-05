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
	// Do NOT seed encstatus; the first probe should detect the
	// missing payload and return ErrClusterStatusWithdrawn.
	encstatus.ResetForTest()
	t.Cleanup(encstatus.ResetForTest)

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
