// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testJoinToken = "test-join-token"

// TestClusterStatusCredsKnownAnswer pins the derivation that
// cluster-status-probe's copy
// (pkg/kube/cluster-status-probe/statusauth_test.go) pins to the same values.
func TestClusterStatusCredsKnownAnswer(t *testing.T) {
	creds, err := deriveClusterStatusCreds(testJoinToken)
	if err != nil {
		t.Fatal(err)
	}
	const wantBearer = "8e9df6c76b89b9a2965bc34190469f2dac724bbe5ce18beb08a1214d94e6ddfc"
	const wantCertSHA256 = "b2cd067de4af8389b7abb9a86f549f82420d82aebe08b984e483b49ac130e90b"
	if creds.bearer != wantBearer {
		t.Errorf("bearer = %s, want %s", creds.bearer, wantBearer)
	}
	sum := sha256.Sum256(creds.cert.Certificate[0])
	if got := hex.EncodeToString(sum[:]); got != wantCertSHA256 {
		t.Errorf("certificate SHA-256 = %s, want %s", got, wantCertSHA256)
	}
}

// newClusterStatusTestServer serves 200 behind the cluster-status server's
// TLS configuration and authentication, keyed on z's join token.
func newClusterStatusTestServer(t *testing.T, z *zedkube) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(z.requireClusterStatusAuth(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))
	srv.TLS = z.clusterStatusServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func clusterStatusGet(t *testing.T, c *http.Client, url, authorization string) (int, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func TestClusterStatusServerAuth(t *testing.T) {
	server := &zedkube{}
	server.setClusterJoinToken(testJoinToken)
	srv := newClusterStatusTestServer(t, server)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	url := "https://127.0.0.1:" + port + "/status"

	peer := &zedkube{}
	peer.setClusterJoinToken(testJoinToken)
	client, authorization, err := peer.clusterStatusClient(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := clusterStatusGet(t, client, url, authorization); err != nil ||
		status != http.StatusOK {
		t.Errorf("peer with the join token: status %d, err %v; want 200", status, err)
	}
	if status, err := clusterStatusGet(t, client, url, ""); err != nil ||
		status != http.StatusUnauthorized {
		t.Errorf("request without credentials: status %d, err %v; want 401", status, err)
	}
	if status, err := clusterStatusGet(t, client, url, "Bearer "+testJoinToken); err != nil ||
		status != http.StatusUnauthorized {
		t.Errorf("request with a wrong token: status %d, err %v; want 401", status, err)
	}

	other := &zedkube{}
	other.setClusterJoinToken("other-join-token")
	otherClient, otherAuthorization, err := other.clusterStatusClient(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clusterStatusGet(t, otherClient, url, otherAuthorization); err == nil {
		t.Error("peer with another join token accepted the server's certificate")
	}
}

func TestClusterStatusServerWithoutToken(t *testing.T) {
	server := &zedkube{}
	server.setClusterJoinToken(testJoinToken)
	server.setClusterJoinToken("")
	srv := newClusterStatusTestServer(t, server)

	peer := &zedkube{}
	peer.setClusterJoinToken(testJoinToken)
	client, authorization, err := peer.clusterStatusClient(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clusterStatusGet(t, client, srv.URL+"/status", authorization); err == nil {
		t.Error("server without a join token completed a TLS handshake")
	}
	if _, _, err := server.clusterStatusClient(time.Second); err == nil {
		t.Error("clusterStatusClient succeeded without a join token")
	}
}
