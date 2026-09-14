// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package mgmtproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- Proxy-Authorization token -------------------------------------------

func proxyAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestEnsureProxyTokenGeneratesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault", "mgmtproxy", "token")
	tok1, err := ensureProxyToken(path)
	if err != nil {
		t.Fatalf("ensureProxyToken (generate): %v", err)
	}
	if len(tok1) == 0 {
		t.Fatal("generated token is empty")
	}
	tok2, err := ensureProxyToken(path)
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
	want, err := ensureProxyToken(path)
	if err != nil {
		t.Fatalf("ensureProxyToken: %v", err)
	}
	got, err := ensureProxyToken(path)
	if err != nil {
		t.Fatalf("ensureProxyToken (second reader): %v", err)
	}
	if got != want {
		t.Errorf("second reader got %q, want %q", got, want)
	}
}

// --- cni0 TLS certificate -------------------------------------------------

func TestEnsureProxyTLSCertGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert1, err := ensureProxyTLSCert(certPath, keyPath)
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

	cert2, err := ensureProxyTLSCert(certPath, keyPath)
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

	want, err := ensureProxyTLSCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("ensureProxyTLSCert: %v", err)
	}
	got, err := ensureProxyTLSCert(certPath, keyPath)
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
