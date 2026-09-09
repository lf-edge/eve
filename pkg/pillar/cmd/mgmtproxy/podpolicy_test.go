// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package mgmtproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Proxy-Authorization token -------------------------------------------

func proxyAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestEnsureProxyTokenGeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault", "mgmtproxy", "token")
	tok1, err := ensureProxyToken(path, "")
	if err != nil {
		t.Fatalf("ensureProxyToken (generate): %v", err)
	}
	if len(tok1) == 0 {
		t.Fatal("generated token is empty")
	}
	tok2, err := ensureProxyToken(path, "")
	if err != nil {
		t.Fatalf("ensureProxyToken (reload): %v", err)
	}
	if tok1 != tok2 {
		t.Errorf("token changed across calls: %q != %q, want stable across reboots", tok1, tok2)
	}
}

func TestEnsureProxyTokenTwoInstancesAgreeOnFile(t *testing.T) {
	// Simulates kube-init reading the same file mgmtproxy wrote.
	path := filepath.Join(t.TempDir(), "token")
	want, err := ensureProxyToken(path, "")
	if err != nil {
		t.Fatalf("ensureProxyToken: %v", err)
	}
	got, err := ensureProxyToken(path, "")
	if err != nil {
		t.Fatalf("ensureProxyToken (second reader): %v", err)
	}
	if got != want {
		t.Errorf("second reader got %q, want %q", got, want)
	}
}

// --- Clustered (deterministic) token/cert derivation -----------------------

func TestDeriveProxyTokenDeterministic(t *testing.T) {
	tok1 := deriveProxyToken("shared-cluster-token")
	tok2 := deriveProxyToken("shared-cluster-token")
	if tok1 != tok2 {
		t.Errorf("deriveProxyToken not deterministic: %q != %q", tok1, tok2)
	}
	if len(tok1) == 0 {
		t.Fatal("derived token is empty")
	}
}

func TestDeriveProxyTokenDiffersByClusterToken(t *testing.T) {
	tokA := deriveProxyToken("cluster-a-token")
	tokB := deriveProxyToken("cluster-b-token")
	if tokA == tokB {
		t.Error("different cluster tokens derived the same proxy token")
	}
}

// TestEnsureProxyTokenClusteredTwoNodesAgree: two independent "nodes" given
// the same clusterToken must persist the identical token — the core
// regression test for the multi-node race.
func TestEnsureProxyTokenClusteredTwoNodesAgree(t *testing.T) {
	const clusterToken = "shared-k3s-join-token"
	pathNode1 := filepath.Join(t.TempDir(), "token")
	pathNode2 := filepath.Join(t.TempDir(), "token")

	tokNode1, err := ensureProxyToken(pathNode1, clusterToken)
	if err != nil {
		t.Fatalf("ensureProxyToken (node1): %v", err)
	}
	tokNode2, err := ensureProxyToken(pathNode2, clusterToken)
	if err != nil {
		t.Fatalf("ensureProxyToken (node2): %v", err)
	}
	if tokNode1 != tokNode2 {
		t.Errorf("node1 %q != node2 %q, want identical", tokNode1, tokNode2)
	}
}

// TestEnsureProxyTokenClusteredOverwritesRandomFallback: a node that
// generated a random token before it knew it was clustered must switch to
// the derived value once it learns it is.
func TestEnsureProxyTokenClusteredOverwritesRandomFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	randomTok, err := ensureProxyToken(path, "")
	if err != nil {
		t.Fatalf("ensureProxyToken (standalone): %v", err)
	}
	derivedTok, err := ensureProxyToken(path, "shared-cluster-token")
	if err != nil {
		t.Fatalf("ensureProxyToken (clustered): %v", err)
	}
	if derivedTok == randomTok {
		t.Fatal("derived token equals random one, test not exercising overwrite")
	}
	want := deriveProxyToken("shared-cluster-token")
	if derivedTok != want {
		t.Errorf("got %q, want derived value %q", derivedTok, want)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if strings.TrimSpace(string(persisted)) != want {
		t.Errorf("persisted file has stale content %q, want %q", persisted, want)
	}
}

// TestEnsureProxyTokenClusterTokenRotationOverwrites: a new cluster token
// (e.g. k3s token rotate) must re-derive and re-persist, not keep serving
// the old value.
func TestEnsureProxyTokenClusterTokenRotationOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	before, err := ensureProxyToken(path, "cluster-token-v1")
	if err != nil {
		t.Fatalf("ensureProxyToken (v1): %v", err)
	}
	after, err := ensureProxyToken(path, "cluster-token-v2")
	if err != nil {
		t.Fatalf("ensureProxyToken (v2): %v", err)
	}
	if before == after {
		t.Fatal("token did not change across a cluster-token rotation")
	}
	if want := deriveProxyToken("cluster-token-v2"); after != want {
		t.Errorf("got %q, want %q", after, want)
	}
}

// --- cni0 TLS certificate -------------------------------------------------

func TestEnsureProxyTLSCertGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert1, err := ensureProxyTLSCert(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("ensureProxyTLSCert (generate): %v", err)
	}
	if len(cert1.Certificate) == 0 {
		t.Fatal("generated certificate is empty")
	}
	leaf, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	if !leaf.IsCA {
		t.Error("certificate must be its own CA (self-signed trust root for TrustedCAProxy)")
	}
	if !leaf.NotAfter.Equal(noWellDefinedExpiration) {
		t.Errorf("NotAfter = %s, want the RFC 5280 no-well-defined-expiration "+
			"sentinel %s", leaf.NotAfter, noWellDefinedExpiration)
	}
	wantIP, _, err := net.SplitHostPort(CNI0ListenAddr)
	if err != nil {
		t.Fatalf("split CNI0ListenAddr: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != wantIP {
		t.Errorf("certificate IP SANs = %v, want [%s]", leaf.IPAddresses, wantIP)
	}

	cert2, err := ensureProxyTLSCert(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("ensureProxyTLSCert (reload): %v", err)
	}
	if !bytes.Equal(cert1.Certificate[0], cert2.Certificate[0]) {
		t.Error("certificate changed across calls, want stable across reboots")
	}
}

func TestEnsureProxyTLSCertTwoInstancesAgreeOnFile(t *testing.T) {
	// Simulates kube-init reading the same cert file mgmtproxy wrote.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	want, err := ensureProxyTLSCert(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("ensureProxyTLSCert: %v", err)
	}
	got, err := ensureProxyTLSCert(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("ensureProxyTLSCert (second reader): %v", err)
	}
	if !bytes.Equal(want.Certificate[0], got.Certificate[0]) {
		t.Error("second reader got a different certificate")
	}

	// The persisted cert.pem alone (no key) must also verify with the
	// standard library's own PEM parsing, the same way kube-init reads it
	// to publish as CDI's TrustedCAProxy ConfigMap.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read %s: %v", certPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("persisted cert.pem did not parse as a valid PEM certificate")
	}
}

// --- Clustered (deterministic) TLS cert derivation --------------------------

func TestDeriveProxyTLSCertDeterministic(t *testing.T) {
	cert1, key1, err := deriveProxyTLSCert("shared-cluster-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	cert2, key2, err := deriveProxyTLSCert("shared-cluster-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	if !bytes.Equal(cert1, cert2) {
		t.Error("derived certificate is not deterministic")
	}
	if !bytes.Equal(key1, key2) {
		t.Error("derived key is not deterministic")
	}
}

func TestDeriveProxyTLSCertDiffersByClusterToken(t *testing.T) {
	certA, _, err := deriveProxyTLSCert("cluster-a-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	certB, _, err := deriveProxyTLSCert("cluster-b-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	if bytes.Equal(certA, certB) {
		t.Error("different cluster tokens derived the same certificate")
	}
}

// TestEnsureProxyTLSCertClusteredTwoNodesAgree is the TLS-cert equivalent of
// TestEnsureProxyTokenClusteredTwoNodesAgree.
func TestEnsureProxyTLSCertClusteredTwoNodesAgree(t *testing.T) {
	const clusterToken = "shared-k3s-join-token"
	dir1, dir2 := t.TempDir(), t.TempDir()
	cert1, key1 := filepath.Join(dir1, "cert.pem"), filepath.Join(dir1, "key.pem")
	cert2, key2 := filepath.Join(dir2, "cert.pem"), filepath.Join(dir2, "key.pem")

	node1, err := ensureProxyTLSCert(cert1, key1, clusterToken)
	if err != nil {
		t.Fatalf("ensureProxyTLSCert (node1): %v", err)
	}
	node2, err := ensureProxyTLSCert(cert2, key2, clusterToken)
	if err != nil {
		t.Fatalf("ensureProxyTLSCert (node2): %v", err)
	}
	if !bytes.Equal(node1.Certificate[0], node2.Certificate[0]) {
		t.Error("node1 and node2 derived different certificates")
	}
}

// TestEnsureProxyTLSCertClusteredOverwritesRandomFallback mirrors
// TestEnsureProxyTokenClusteredOverwritesRandomFallback for the TLS cert.
func TestEnsureProxyTLSCertClusteredOverwritesRandomFallback(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")

	randomCert, err := ensureProxyTLSCert(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("ensureProxyTLSCert (standalone): %v", err)
	}
	derivedCert, err := ensureProxyTLSCert(certPath, keyPath, "shared-cluster-token")
	if err != nil {
		t.Fatalf("ensureProxyTLSCert (clustered): %v", err)
	}
	if bytes.Equal(derivedCert.Certificate[0], randomCert.Certificate[0]) {
		t.Fatal("derived cert equals random one, test not exercising overwrite")
	}
	wantCertPEM, _, err := deriveProxyTLSCert("shared-cluster-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	persisted, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read %s: %v", certPath, err)
	}
	if !bytes.Equal(persisted, wantCertPEM) {
		t.Error("persisted cert file still has stale (random) content")
	}
}

// --- ensurePersistedCert re-verification ------------------------------------

func TestEnsurePersistedCertMatchIsNoOp(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM, keyPEM, err := deriveProxyTLSCert("shared-cluster-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	if _, err := ensurePersistedCert(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("ensurePersistedCert (first): %v", err)
	}
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read %s: %v", keyPath, err)
	}
	if _, err := ensurePersistedCert(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("ensurePersistedCert (second): %v", err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read %s: %v", keyPath, err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Error("ensurePersistedCert rewrote key file although both matched")
	}
}

// TestEnsurePersistedCertRewritesOnCertMismatch covers the self-heal case:
// the cert file was wiped/replaced externally, so ensurePersistedCert must
// restore it from the given certPEM rather than silently keeping the stale
// content.
func TestEnsurePersistedCertRewritesOnCertMismatch(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM, keyPEM, err := deriveProxyTLSCert("shared-cluster-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	if _, err := ensurePersistedCert(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("ensurePersistedCert (first): %v", err)
	}
	if err := os.WriteFile(certPath, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensurePersistedCert(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("ensurePersistedCert (second): %v", err)
	}
	persisted, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read %s: %v", certPath, err)
	}
	if !bytes.Equal(persisted, certPEM) {
		t.Error("ensurePersistedCert did not restore the tampered cert file")
	}
}

// TestEnsurePersistedCertRewritesOnKeyMissing is the regression test for the
// bug this pins: a matching certPath alone is not enough to skip the
// rewrite, because tls.X509KeyPair(certPEM, keyPEM) only parses the
// in-memory arguments -- it proves nothing about keyPath's actual on-disk
// content. A keyPath wiped independently of certPath must still be noticed
// and restored.
func TestEnsurePersistedCertRewritesOnKeyMissing(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM, keyPEM, err := deriveProxyTLSCert("shared-cluster-token")
	if err != nil {
		t.Fatalf("deriveProxyTLSCert: %v", err)
	}
	if _, err := ensurePersistedCert(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("ensurePersistedCert (first): %v", err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ensurePersistedCert(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("ensurePersistedCert (second): %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not restored after being wiped: %v", err)
	}
}

func TestCheckProxyAuthNotReadyWithoutToken(t *testing.T) {
	ctx := newTestContext(mkDNS(), 0)
	req := httptest.NewRequest("CONNECT", "//example.com:443", nil)
	ready, ok := ctx.checkProxyAuth(req)
	if ready {
		t.Error("ready = true before any token was loaded, want false")
	}
	if ok {
		t.Error("ok = true before any token was loaded, want false")
	}
}

func TestCheckProxyAuthMissingHeader(t *testing.T) {
	ctx := newTestContext(mkDNS(), 0)
	ctx.authToken.Store("secret-token")
	req := httptest.NewRequest("CONNECT", "//example.com:443", nil)
	ready, ok := ctx.checkProxyAuth(req)
	if !ready {
		t.Error("ready = false once token loaded, want true")
	}
	if ok {
		t.Error("ok = true with no Proxy-Authorization header, want false")
	}
}

func TestCheckProxyAuthWrongToken(t *testing.T) {
	ctx := newTestContext(mkDNS(), 0)
	ctx.authToken.Store("secret-token")
	req := httptest.NewRequest("CONNECT", "//example.com:443", nil)
	req.Header.Set("Proxy-Authorization", proxyAuthHeader("cdi", "wrong-token"))
	if _, ok := ctx.checkProxyAuth(req); ok {
		t.Error("ok = true with wrong token, want false")
	}
}

func TestCheckProxyAuthCorrectToken(t *testing.T) {
	ctx := newTestContext(mkDNS(), 0)
	ctx.authToken.Store("secret-token")
	req := httptest.NewRequest("CONNECT", "//example.com:443", nil)
	// Username is arbitrary/ignored — only the password (token) is checked.
	req.Header.Set("Proxy-Authorization", proxyAuthHeader("cdi", "secret-token"))
	ready, ok := ctx.checkProxyAuth(req)
	if !ready || !ok {
		t.Errorf("ready=%v ok=%v, want true,true for correct token", ready, ok)
	}
}

func TestCheckProxyAuthMalformedHeader(t *testing.T) {
	ctx := newTestContext(mkDNS(), 0)
	ctx.authToken.Store("secret-token")
	for _, hdr := range []string{
		"",
		"Bearer secret-token",
		"Basic not-valid-base64!!!",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")),
	} {
		req := httptest.NewRequest("CONNECT", "//example.com:443", nil)
		if hdr != "" {
			req.Header.Set("Proxy-Authorization", hdr)
		}
		if _, ok := ctx.checkProxyAuth(req); ok {
			t.Errorf("header %q: ok = true, want false", hdr)
		}
	}
}

// --- Cluster departure (markSingleNode / markClusterWide) ------------------

// withDerivedFiles redirects TokenFile, TLSCertFile, TLSKeyFile, and
// clusterWideSecretsMarker into a temp dir for the test, restoring the
// originals on cleanup.
func withDerivedFiles(t *testing.T) (tokenFile, certFile, keyFile, marker string) {
	t.Helper()
	dir := t.TempDir()
	tokenFile = filepath.Join(dir, "token")
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	marker = filepath.Join(dir, "cluster-wide-secrets")

	origToken := TokenFile
	origCert := TLSCertFile
	origKey := TLSKeyFile
	origMarker := clusterWideSecretsMarker
	TokenFile = tokenFile
	TLSCertFile = certFile
	TLSKeyFile = keyFile
	clusterWideSecretsMarker = marker
	t.Cleanup(func() {
		TokenFile = origToken
		TLSCertFile = origCert
		TLSKeyFile = origKey
		clusterWideSecretsMarker = origMarker
	})
	return tokenFile, certFile, keyFile, marker
}

// TestMarkClusterWideSetsMarker verifies markClusterWide creates the
// marker when it's missing.
func TestMarkClusterWideSetsMarker(t *testing.T) {
	_, _, _, marker := withDerivedFiles(t)
	if err := markClusterWide(); err != nil {
		t.Fatalf("markClusterWide: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("marker not created: %v", err)
	}
}

// TestMarkClusterWideIdempotent verifies a second call is a cheap no-op.
func TestMarkClusterWideIdempotent(t *testing.T) {
	_, _, _, marker := withDerivedFiles(t)
	if err := markClusterWide(); err != nil {
		t.Fatalf("markClusterWide (first): %v", err)
	}
	if err := markClusterWide(); err != nil {
		t.Fatalf("markClusterWide (second): %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("marker missing after second call: %v", err)
	}
}

// --- secretsFilesExist (cheap existence check) ------------------------------

func TestSecretsFilesExistAllPresent(t *testing.T) {
	tokenFile, certFile, keyFile, _ := withDerivedFiles(t)
	for _, f := range []string{tokenFile, certFile, keyFile} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !secretsFilesExist() {
		t.Error("secretsFilesExist() = false, want true when all three exist")
	}
}

// TestSecretsFilesExistDetectsEachMissingFile covers the wipe cases
// startProxySecretsReconciler relies on secretsFilesExist to catch: the
// token, the cert, or just the key disappearing must all be noticed.
func TestSecretsFilesExistDetectsEachMissingFile(t *testing.T) {
	for _, missing := range []string{"token", "cert", "key"} {
		t.Run(missing, func(t *testing.T) {
			tokenFile, certFile, keyFile, _ := withDerivedFiles(t)
			files := map[string]string{
				"token": tokenFile, "cert": certFile, "key": keyFile,
			}
			for name, f := range files {
				if name == missing {
					continue
				}
				err := os.WriteFile(f, []byte("x"), 0o600)
				if err != nil {
					t.Fatal(err)
				}
			}
			if secretsFilesExist() {
				t.Errorf("exists=true, %s missing, want false", missing)
			}
		})
	}
}

func TestMarkSingleNodeWipesFilesOnDeparture(t *testing.T) {
	tokenFile, certFile, keyFile, marker := withDerivedFiles(t)
	for _, f := range []string{tokenFile, certFile, keyFile, marker} {
		if err := os.WriteFile(f, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := markSingleNode(); err != nil {
		t.Fatalf("markSingleNode: %v", err)
	}
	for _, f := range []string{tokenFile, certFile, keyFile, marker} {
		if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists after leaving the cluster", f)
		}
	}
}

// TestMarkSingleNodeAlreadySingleNodeIsNoOp covers the steady-state case: no
// cluster-wide marker to react to, so markSingleNode must leave an already
// single-node node's own token untouched.
func TestMarkSingleNodeAlreadySingleNodeIsNoOp(t *testing.T) {
	tokenFile, _, _, marker := withDerivedFiles(t)
	if err := os.WriteFile(tokenFile, []byte("random-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := markSingleNode(); err != nil {
		t.Fatalf("markSingleNode: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Error("marker unexpectedly created for a standalone node")
	}
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("token file was removed: %v", err)
	}
	if string(data) != "random-token" {
		t.Errorf("token file content changed to %q, want untouched", data)
	}
}

// TestSecretsScopeEndToEndClusterDeparture drives the real ensureProxyToken
// through a full standalone -> clustered -> standalone cycle, calling
// markSingleNode/markClusterWide the same way applyProxySecrets does
// (markSingleNode only when clusterToken == "", markClusterWide *before* the
// clustered derive, not after -- see applyProxySecrets for why): the
// persisted token must go from random, to derived, and back to a *fresh*
// random value on departure -- not the stale derived one, which nothing but
// a former cluster member could still reproduce.
func TestSecretsScopeEndToEndClusterDeparture(t *testing.T) {
	tokenFile, _, _, _ := withDerivedFiles(t)

	if err := markSingleNode(); err != nil {
		t.Fatalf("markSingleNode (standalone): %v", err)
	}
	randomTok, err := ensureProxyToken(tokenFile, "")
	if err != nil {
		t.Fatalf("ensureProxyToken (standalone): %v", err)
	}

	// Becoming clustered: no markSingleNode call this tick, since
	// clusterToken != "". markClusterWide runs *before* the derive, mirroring
	// applyProxySecrets; skipping it would make the next markSingleNode a
	// no-op, since it'd see no marker to react to -- leaving the stale
	// derived token in place instead of regenerating it below.
	if err := markClusterWide(); err != nil {
		t.Fatalf("markClusterWide: %v", err)
	}
	derivedTok, err := ensureProxyToken(tokenFile, "shared-cluster-token")
	if err != nil {
		t.Fatalf("ensureProxyToken (clustered): %v", err)
	}
	if derivedTok == randomTok {
		t.Fatal("derived token equals random one, test not exercising transition")
	}

	if err := markSingleNode(); err != nil {
		t.Fatalf("markSingleNode (departed): %v", err)
	}
	afterDeparture, err := ensureProxyToken(tokenFile, "")
	if err != nil {
		t.Fatalf("ensureProxyToken (departed): %v", err)
	}
	if afterDeparture == derivedTok {
		t.Error("node kept the cluster-derived token after leaving the cluster")
	}
}

// --- Destination policy ---------------------------------------------------

func TestDestinationAllowedDenied(t *testing.T) {
	for _, ip := range []string{
		"169.254.169.254", // cloud metadata
		"127.0.0.1",       // loopback
		"::1",             // IPv6 loopback
		"fe80::1",         // IPv6 link-local
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
		"10.42.0.5",       // pod CIDR
		"10.43.0.1",       // service CIDR
	} {
		if err := destinationAllowed(net.ParseIP(ip)); err == nil {
			t.Errorf("destinationAllowed(%s) = nil, want denied", ip)
		}
	}
}

func TestDestinationAllowedPermitted(t *testing.T) {
	for _, ip := range []string{
		"93.184.216.34", // external public IP
		"8.8.8.8",
	} {
		if err := destinationAllowed(net.ParseIP(ip)); err != nil {
			t.Errorf("destinationAllowed(%s) = %v, want allowed", ip, err)
		}
	}
}

func TestResolvePinnedTargetIPLiteralDenied(t *testing.T) {
	_, err := resolvePinnedTarget(context.Background(), "169.254.169.254", "80")
	if err == nil {
		t.Fatal("expected denial for metadata IP literal")
	}
}

func TestResolvePinnedTargetIPLiteralAllowed(t *testing.T) {
	got, err := resolvePinnedTarget(context.Background(), "93.184.216.34", "443")
	if err != nil {
		t.Fatalf("resolvePinnedTarget: %v", err)
	}
	if got != "93.184.216.34:443" {
		t.Errorf("got %q, want %q", got, "93.184.216.34:443")
	}
}

// stubLookup swaps lookupIPAddr for the duration of the test.
func stubLookup(t *testing.T, addrs ...string) {
	t.Helper()
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	var ipa []net.IPAddr
	for _, a := range addrs {
		ipa = append(ipa, net.IPAddr{IP: net.ParseIP(a)})
	}
	lookupIPAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return ipa, nil
	}
}

// TestResolvePinnedTargetHostnameResolvesToDenied is the metadata-via-hostname
// scenario the original report flagged as a gap: an IP-literal-only check
// lets `metadata.google.internal` (which resolves to 169.254.169.254) straight
// through. resolvePinnedTarget must resolve first and check the result.
func TestResolvePinnedTargetHostnameResolvesToDenied(t *testing.T) {
	stubLookup(t, "169.254.169.254")
	_, err := resolvePinnedTarget(context.Background(), "metadata.google.internal", "80")
	if err == nil {
		t.Fatal("expected denial for hostname resolving to metadata IP")
	}
}

func TestResolvePinnedTargetHostnameAllowedPinsResolvedAddress(t *testing.T) {
	stubLookup(t, "93.184.216.34")
	got, err := resolvePinnedTarget(context.Background(), "example.com", "443")
	if err != nil {
		t.Fatalf("resolvePinnedTarget: %v", err)
	}
	if got != "93.184.216.34:443" {
		t.Errorf("got %q, want dial pinned to the resolved address", got)
	}
}

// TestResolvePinnedTargetMultiAnswerAnyDenied ensures a hostname with several
// A/AAAA records is rejected outright if ANY resolved address is denied — not
// just the one that would happen to be dialed — since which record the
// dialer picks isn't guaranteed to be the one that was inspected.
func TestResolvePinnedTargetMultiAnswerAnyDenied(t *testing.T) {
	stubLookup(t, "93.184.216.34", "127.0.0.1")
	_, err := resolvePinnedTarget(context.Background(), "multi.example", "443")
	if err == nil {
		t.Fatal("expected denial when any resolved address is denied")
	}
}

func TestResolvePinnedTargetLookupFailure(t *testing.T) {
	orig := lookupIPAddr
	defer func() { lookupIPAddr = orig }()
	lookupIPAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "bad.example", IsNotFound: true}
	}
	_, err := resolvePinnedTarget(context.Background(), "bad.example", "443")
	if err == nil {
		t.Fatal("expected error when resolution fails")
	}
}

// --- newProxyHandler(ctx, podFacing=true) routing --------------------------
//
// These exercise the cni0 listener's full handler stack (auth + destination
// policy + /healthz restriction) together, as opposed to the unit-level
// checks above.

func connectReq(target string) *http.Request {
	req := httptest.NewRequest(http.MethodConnect, "//"+target, nil)
	req.URL.Host = target
	req.Host = target
	return req
}

// TestPodFacingHealthzNotServed pins the report's second recommendation:
// /healthz is an operator-debug endpoint and must not be reachable from the
// cni0 (pod-facing) listener, unlike the loopback one.
func TestPodFacingHealthzNotServed(t *testing.T) {
	ctx := newTestContext(mkDNS(), 0)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://169.254.100.1:5443/healthz", nil)
	newProxyHandler(ctx, true).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("pod-facing /healthz status = %d, want 404", rec.Code)
	}
}

func TestPodFacingConnectNotReadyWithoutToken(t *testing.T) {
	ctx := newTestContext(mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10"))), 0)
	rec := httptest.NewRecorder()
	newProxyHandler(ctx, true).ServeHTTP(rec, connectReq("93.184.216.34:443"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("CONNECT before token loaded: status = %d, want 503", rec.Code)
	}
}

func TestPodFacingConnectRequiresAuth(t *testing.T) {
	ctx := newTestContext(mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10"))), 0)
	ctx.authToken.Store("secret-token")
	rec := httptest.NewRecorder()
	newProxyHandler(ctx, true).ServeHTTP(rec, connectReq("93.184.216.34:443"))
	if rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT without credentials: status = %d, want 407", rec.Code)
	}
}

func TestPodFacingConnectWrongTokenRejected(t *testing.T) {
	ctx := newTestContext(mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10"))), 0)
	ctx.authToken.Store("secret-token")
	req := connectReq("93.184.216.34:443")
	req.Header.Set("Proxy-Authorization", proxyAuthHeader("cdi", "wrong"))
	rec := httptest.NewRecorder()
	newProxyHandler(ctx, true).ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT with wrong token: status = %d, want 407", rec.Code)
	}
}

// TestPodFacingConnectDeniedDestination reproduces the live-verified exploit:
// even with a valid token, a pod-facing CONNECT to a denied destination
// (here, the metadata address) must be rejected with 403 before any dial.
func TestPodFacingConnectDeniedDestination(t *testing.T) {
	ctx := newTestContext(mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10"))), 0)
	ctx.authToken.Store("secret-token")
	req := connectReq("169.254.169.254:80")
	req.Header.Set("Proxy-Authorization", proxyAuthHeader("cdi", "secret-token"))
	rec := httptest.NewRecorder()
	newProxyHandler(ctx, true).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("CONNECT to metadata IP with valid auth: status = %d, want 403", rec.Code)
	}
}

// TestPodFacingConnectAllowedDestinationReachesDialer confirms legitimate CDI
// importer traffic (an external target, valid token) is not blocked by the
// new checks: it reaches the dialer. The mgmt port's source IP is
// deliberately unroutable so the test distinguishes "forwarded to the
// dialer" (502) from "blocked by policy" (403), same technique as the
// original report's reproduction.
func TestPodFacingConnectAllowedDestinationReachesDialer(t *testing.T) {
	ctx := newTestContext(mkDNS(mkPort("eth0", 0, net.ParseIP("192.0.2.10"))), 0)
	ctx.authToken.Store("secret-token")
	req := connectReq("93.184.216.34:443")
	req.Header.Set("Proxy-Authorization", proxyAuthHeader("cdi", "secret-token"))
	rec := httptest.NewRecorder()
	newProxyHandler(ctx, true).ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusProxyAuthRequired {
		t.Errorf("legitimate external target wrongly blocked: status = %d", rec.Code)
	}
}
