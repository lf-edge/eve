// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

// This file holds the two checks enforced only on the cni0 (pod-facing)
// listener, never the loopback one: the Proxy-Authorization token
// (checkProxyAuth) and the CONNECT destination policy (destinationAllowed /
// resolvePinnedTarget). See newProxyHandler in proxy.go for where both are
// wired in, and README.md for the full rationale.
package mgmtproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
)

// --- Proxy-Authorization token -----------------------------------------

// TokenFile persists the shared secret that gates the cni0 listener, under
// /persist/vault so it survives reboots (matching the k3s-node-password
// precedent: a random per-node secret two on-node processes must agree on).
// /persist is bind-mounted identically into the pillar and kube containers,
// so kube-init's PatchCDIProxyConfig can read this same path directly to
// embed the token in the CDI CR's importProxy URL; its TokenFile constant
// must match. mgmtproxy is the sole writer. var so tests can redirect.
//
// The token alone doesn't protect against an on-path attacker: cni0 is a
// plain shared L2 bridge, and a pod there could ARP-spoof the anchor IP to
// intercept the CONNECT request (and the token in it) before it even
// reaches mgmtproxy. TLSCertFile/TLSKeyFile close that gap.
var TokenFile = "/persist/vault/mgmtproxy/token"

// TLSCertFile and TLSKeyFile persist the self-signed certificate/key pair
// the cni0 listener presents on TLS handshake, so importer pods can
// cryptographically verify they're really talking to mgmtproxy (via CDI's
// TrustedCAProxy) instead of trusting whoever answers on cni0. Same
// persistence convention as TokenFile: mgmtproxy is the sole writer,
// kube-init's PatchCDIProxyConfig only reads TLSCertFile to publish it as
// the TrustedCAProxy ConfigMap, and the paths must match.
var (
	TLSCertFile = "/persist/vault/mgmtproxy/cert.pem"
	TLSKeyFile  = "/persist/vault/mgmtproxy/key.pem"
)

// ensureProxyTLSCert loads the persisted cert/key pair, generating and
// persisting a new one on first boot or on any load error (e.g. a wiped
// /persist). The certificate is self-signed and its own root (IsCA) rather
// than issued by a separate CA: the same PEM doubles as both the TLS
// listener's certificate and the trust anchor importer pods are given via
// TrustedCAProxy, so there's no separate CA to generate or manage. Its
// NotAfter is the RFC 5280 "no well-defined expiration date" sentinel (see
// generateProxyTLSCert) -- there is no revocation mechanism here either, so
// a bounded validity period would only add a rotation problem to solve
// without buying any actual security property.
func ensureProxyTLSCert(certPath, keyPath string) (tls.Certificate, error) {
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}
	certPEM, keyPEM, err := generateProxyTLSCert()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate TLS cert: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("mkdir %s: %w", filepath.Dir(certPath), err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write %s: %w", keyPath, err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// noWellDefinedExpiration is the RFC 5280 4.1.2.5 convention for a
// certificate with no well-defined expiration date: GeneralizedTime
// 99991231235959Z.
var noWellDefinedExpiration = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// generateProxyTLSCert creates a fresh self-signed ECDSA certificate valid
// for CNI0IP (parsed from CNI0ListenAddr), PEM-encoding both the
// certificate and its private key.
func generateProxyTLSCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	cni0IP, _, err := net.SplitHostPort(CNI0ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("split %s: %w", CNI0ListenAddr, err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mgmtproxy cni0"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              noWellDefinedExpiration,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP(cni0IP)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// tokenBytes is the random secret's length before hex encoding.
const tokenBytes = 32

// startProxyAuthLoader waits for the vault to unseal, then retries
// persisting/loading the cni0 proxy-auth token and TLS certificate until
// both succeed, storing them on ctx for checkProxyAuth and the cni0
// listener's tls.Config.GetCertificate. Runs as a background goroutine (same
// pattern as downloader, volumemgr, etc.) so it never blocks the rest of
// mgmtproxy, whose loopback listener has no vault dependency of its own.
// Both fail closed until ready, which is fine: no legitimate CDI importer
// pod can exist before vault unseal either.
func startProxyAuthLoader(ctx *mgmtProxyContext) {
	go func() {
		if err := wait.WaitForVault(ctx.ps, log, agentName, warningTime, errorTime); err != nil {
			log.Errorf("mgmtproxy: cni0 proxy-auth token: wait for vault: %v", err)
			return
		}
		for {
			tok, tokErr := ensureProxyToken(TokenFile)
			cert, certErr := ensureProxyTLSCert(TLSCertFile, TLSKeyFile)
			if tokErr == nil && certErr == nil {
				ctx.authToken.Store(tok)
				ctx.tlsCert.Store(&cert)
				log.Noticef("mgmtproxy: cni0 proxy-auth token and TLS cert ready")
				return
			}
			log.Warnf("mgmtproxy: cni0 proxy-auth not yet ready (token: %v, cert: %v), retrying",
				tokErr, certErr)
			time.Sleep(10 * time.Second)
		}
	}()
}

// ensureProxyToken reads the persisted token, generating and persisting a
// new one on first boot (or if the file is missing or empty — e.g. a wiped
// /persist). The caller already waited for vault unseal, so failure here is
// unexpected but still retried.
func ensureProxyToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if tok := strings.TrimSpace(string(data)); tok != "" {
			return tok, nil
		}
		// Empty/corrupt file: fall through and regenerate.
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	tok, err := generateProxyToken()
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return tok, nil
}

// generateProxyToken returns a fresh random hex-encoded secret.
func generateProxyToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// checkProxyAuth validates the Proxy-Authorization header on the cni0
// listener against the loaded token. ready is false while the token hasn't
// loaded yet — callers should respond 503, not 407, so operators can tell
// "not ready" apart from "wrong credentials". Only the password half of the
// Basic credential is checked; the username is ignored (see withProxyToken).
func (ctx *mgmtProxyContext) checkProxyAuth(req *http.Request) (ready, ok bool) {
	v := ctx.authToken.Load()
	want, _ := v.(string)
	if want == "" {
		return false, false
	}
	const prefix = "Basic "
	hdr := req.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(hdr, prefix) {
		return true, false
	}
	decoded, err := base64.StdEncoding.DecodeString(hdr[len(prefix):])
	if err != nil {
		return true, false
	}
	_, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return true, false
	}
	return true, subtle.ConstantTimeCompare([]byte(pass), []byte(want)) == 1
}

// --- Destination policy -------------------------------------------------

// deniedDestCIDRs are ranges a pod must never reach through mgmtproxy's cni0
// listener: the k3s pod and service CIDRs. Loopback, link-local, unspecified
// and multicast are handled by net.IP predicates in destinationAllowed.
var deniedDestCIDRs = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.42.0.0/16", "10.43.0.0/16"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// destinationAllowed rejects CONNECT targets a CDI importer pod has no
// legitimate reason to reach: loopback, link-local (including the cloud
// metadata address 169.254.169.254), unspecified, multicast, and the
// cluster pod/service CIDRs. Legitimate importer traffic is external
// http(s)/registry URLs, outside all of these ranges.
func destinationAllowed(ip net.IP) error {
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("loopback destination %s not allowed", ip)
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return fmt.Errorf("link-local destination %s not allowed", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("unspecified destination %s not allowed", ip)
	case ip.IsMulticast():
		return fmt.Errorf("multicast destination %s not allowed", ip)
	}
	for _, n := range deniedDestCIDRs {
		if n.Contains(ip) {
			return fmt.Errorf("cluster-internal destination %s not allowed", ip)
		}
	}
	return nil
}

// lookupIPAddr resolves hostnames for resolvePinnedTarget. var so tests can
// stub it without making real DNS queries, matching the rest of this
// package's "var so tests can redirect" convention.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

// resolvePinnedTarget applies destinationAllowed to a CONNECT target's host,
// resolving hostnames first so a name mapping into a denied range (e.g.
// metadata.google.internal -> 169.254.169.254) can't slip past an
// IP-literal-only check. Every resolved address is checked, not just the one
// that will be dialed, so a multi-answer hostname can't sneak a denied
// address past the check. The returned target has its host rewritten to the
// single checked address, pinning the dial against DNS rebinding.
func resolvePinnedTarget(ctx context.Context, host, port string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if err := destinationAllowed(ip); err != nil {
			return "", err
		}
		return net.JoinHostPort(host, port), nil
	}
	addrs, err := lookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses returned", host)
	}
	for _, a := range addrs {
		if err := destinationAllowed(a.IP); err != nil {
			return "", fmt.Errorf("%s resolves to a denied address: %w", host, err)
		}
	}
	return net.JoinHostPort(addrs[0].IP.String(), port), nil
}
