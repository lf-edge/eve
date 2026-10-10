// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// The bootstrap node's cluster-status server (pillar's zedkube, in
// pkg/pillar/cmd/zedkube/clusterstatusauth.go) presents a certificate and
// requires a bearer token, both derived from the cluster join token. This
// helper cannot import that package, so this is a copy of the derivation; the
// HKDF labels, the server name and the certificate template must match there
// byte for byte, and the known-answer tests in both packages pin that.
const (
	clusterStatusTokenHKDFInfo     = "eve-zedkube-cluster-status-token-v1"
	clusterStatusTLSKeyHKDFInfo    = "eve-zedkube-cluster-status-tls-key-v1"
	clusterStatusTLSSerialHKDFInfo = "eve-zedkube-cluster-status-tls-serial-v1"
	clusterStatusServerName        = "cluster-status.zedkube.eve"
)

var (
	clusterStatusCertNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clusterStatusCertNotAfter  = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
)

// clusterStatusAuth holds what a client of the cluster-status server needs:
// the value of its Authorization header, and the pinned server certificate.
type clusterStatusAuth struct {
	authorization string
	certDER       []byte
	roots         *x509.CertPool
}

// deriveClusterStatusAuth derives the cluster-status client credentials from
// joinToken.
func deriveClusterStatusAuth(joinToken string) (*clusterStatusAuth, error) {
	if joinToken == "" {
		return nil, errors.New("empty cluster join token")
	}
	bearer, err := hkdf.Key(sha256.New, []byte(joinToken), nil,
		clusterStatusTokenHKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	cert, err := deriveClusterStatusCert(joinToken)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	return &clusterStatusAuth{
		authorization: "Bearer " + hex.EncodeToString(bearer),
		certDER:       cert.Certificate[0],
		roots:         roots,
	}, nil
}

// deriveClusterStatusCert derives the server's self-signed Ed25519
// certificate and key. Ed25519 key generation from a seed and Ed25519 signing
// are both deterministic, so every node produces the same certificate.
func deriveClusterStatusCert(joinToken string) (tls.Certificate, error) {
	seed, err := hkdf.Key(sha256.New, []byte(joinToken), nil,
		clusterStatusTLSKeyHKDFInfo, ed25519.SeedSize)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := hkdf.Key(sha256.New, []byte(joinToken), nil,
		clusterStatusTLSSerialHKDFInfo, 16)
	if err != nil {
		return tls.Certificate{}, err
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
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

// tlsConfig verifies the server against the pinned derived certificate.
func (a *clusterStatusAuth) tlsConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    a.roots,
		ServerName: clusterStatusServerName,
	}
}
