// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// The cluster-status server on the cluster IP authenticates both ways with
// credentials every node derives from the cluster join token: a TLS
// certificate the client pins, and a bearer token the client presents.
// cluster-init.sh derives the same credentials to probe /status before it
// joins (pkg/kube/cluster-status-probe/statusauth.go), so the HKDF labels,
// the server name and the certificate template must match there byte for
// byte; the known-answer tests in both packages pin that.
const (
	clusterStatusTokenHKDFInfo     = "eve-zedkube-cluster-status-token-v1"
	clusterStatusTLSKeyHKDFInfo    = "eve-zedkube-cluster-status-tls-key-v1"
	clusterStatusTLSSerialHKDFInfo = "eve-zedkube-cluster-status-tls-serial-v1"

	// clusterStatusServerName is the only name in the derived certificate.
	// It is the same on every node, so clients verify it rather than the
	// peer's IP address.
	clusterStatusServerName = "cluster-status.zedkube.eve"
)

// The validity period is fixed so that the certificate is byte-identical on
// every node. 99991231235959Z is RFC 5280's "no well-defined expiration".
var (
	clusterStatusCertNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clusterStatusCertNotAfter  = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// clusterStatusCreds are the credentials derived from one cluster join token.
type clusterStatusCreds struct {
	joinToken string
	bearer    string
	cert      tls.Certificate
	roots     *x509.CertPool
}

// deriveClusterStatusCreds derives the bearer token and the self-signed
// Ed25519 certificate from joinToken. Ed25519 key generation from a seed and
// Ed25519 signing are both deterministic, so every node produces the same
// certificate.
func deriveClusterStatusCreds(joinToken string) (*clusterStatusCreds, error) {
	if joinToken == "" {
		return nil, errors.New("empty cluster join token")
	}
	bearer, err := hkdf.Key(sha256.New, []byte(joinToken), nil,
		clusterStatusTokenHKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	seed, err := hkdf.Key(sha256.New, []byte(joinToken), nil,
		clusterStatusTLSKeyHKDFInfo, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	serial, err := hkdf.Key(sha256.New, []byte(joinToken), nil,
		clusterStatusTLSSerialHKDFInfo, 16)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               pkix.Name{CommonName: clusterStatusServerName},
		DNSNames:              []string{clusterStatusServerName},
		NotBefore:             clusterStatusCertNotBefore,
		NotAfter:              clusterStatusCertNotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &clusterStatusCreds{
		joinToken: joinToken,
		bearer:    hex.EncodeToString(bearer),
		cert:      tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf},
		roots:     roots,
	}, nil
}

// setClusterJoinToken re-derives the cluster-status credentials when the
// decrypted join token changes. An empty token clears them, which makes the
// cluster-status server fail every TLS handshake.
func (z *zedkube) setClusterJoinToken(joinToken string) {
	if cur := z.clusterStatusCreds.Load(); cur != nil && cur.joinToken == joinToken {
		return
	}
	if joinToken == "" {
		z.clusterStatusCreds.Store(nil)
		return
	}
	creds, err := deriveClusterStatusCreds(joinToken)
	if err != nil {
		log.Errorf("setClusterJoinToken: %v", err)
		z.clusterStatusCreds.Store(nil)
		return
	}
	z.clusterStatusCreds.Store(creds)
}

// clusterStatusServerTLSConfig serves the certificate derived from the
// current join token.
func (z *zedkube) clusterStatusServerTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			creds := z.clusterStatusCreds.Load()
			if creds == nil {
				return nil, errors.New("cluster join token not available")
			}
			return &creds.cert, nil
		},
	}
}

// requireClusterStatusAuth rejects any request that does not carry the
// bearer token derived from the current join token.
func (z *zedkube) requireClusterStatusAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		creds := z.clusterStatusCreds.Load()
		want := ""
		if creds != nil {
			want = "Bearer " + creds.bearer
		}
		got := r.Header.Get("Authorization")
		if creds == nil || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="zedkube"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clusterStatusClient returns an HTTP client for a peer's cluster-status
// server, and the Authorization header value to send, or an error if the
// join token is not yet available.
func (z *zedkube) clusterStatusClient(timeout time.Duration) (*http.Client, string, error) {
	creds := z.clusterStatusCreds.Load()
	if creds == nil {
		return nil, "", errors.New("cluster join token not available")
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    creds.roots,
				ServerName: clusterStatusServerName,
			},
		},
	}, "Bearer " + creds.bearer, nil
}
