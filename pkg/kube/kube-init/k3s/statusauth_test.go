// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testJoinToken = "test-join-token"

// newClusterStatusTestServer serves body at /status the way zedkube's
// cluster-status server does for joinToken: over TLS with the derived
// certificate, and only to requests carrying the derived bearer token.
func newClusterStatusTestServer(t *testing.T, joinToken, body string) *httptest.Server {
	t.Helper()
	cert, err := deriveClusterStatusCert(joinToken)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := deriveClusterStatusAuth(joinToken)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != auth.authorization {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestClusterStatusAuthKnownAnswer pins the derivation that zedkube's copy
// (pkg/pillar/cmd/zedkube/clusterstatusauth_test.go) pins to the same values.
func TestClusterStatusAuthKnownAnswer(t *testing.T) {
	auth, err := deriveClusterStatusAuth(testJoinToken)
	if err != nil {
		t.Fatal(err)
	}
	const wantAuthorization = "Bearer 8e9df6c76b89b9a2965bc34190469f2dac724bbe5ce18beb08a1214d94e6ddfc"
	const wantCertSHA256 = "b2cd067de4af8389b7abb9a86f549f82420d82aebe08b984e483b49ac130e90b"
	if auth.authorization != wantAuthorization {
		t.Errorf("authorization = %q, want %q", auth.authorization, wantAuthorization)
	}
	sum := sha256.Sum256(auth.certDER)
	if got := hex.EncodeToString(sum[:]); got != wantCertSHA256 {
		t.Errorf("certificate SHA-256 = %s, want %s", got, wantCertSHA256)
	}
}

func TestFetchClusterStatusRejectsOtherCluster(t *testing.T) {
	srv := newClusterStatusTestServer(t, "other-join-token", "cluster:u")
	auth, err := deriveClusterStatusAuth(testJoinToken)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: auth.tlsConfig()},
		Timeout:   5 * time.Second,
	}
	if body, err := fetchClusterStatus(c, srv.URL+"/status", auth.authorization); err == nil {
		t.Fatalf("fetchClusterStatus accepted a server with another join token: %q", body)
	}
}

func TestWaitForBootstrapServerEmptyToken(t *testing.T) {
	if err := waitForBootstrapServer(context.Background(),
		"https://127.0.0.1:1", "https://127.0.0.1:1/status", "u", ""); err == nil {
		t.Fatal("expected an error for an empty join token")
	}
}
