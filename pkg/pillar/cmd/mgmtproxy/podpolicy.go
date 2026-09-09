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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"golang.org/x/crypto/hkdf"
)

// --- Proxy-Authorization token -----------------------------------------

// TokenFile persists the shared secret that gates the cni0 listener, under
// /persist/vault so it survives reboots. /persist is bind-mounted identically
// into the pillar and kube containers, so kube-init's PatchCDIProxyConfig can
// read this same path directly to embed the token in the CDI CR's
// importProxy URL; its TokenFile constant must match. mgmtproxy is the sole
// writer. var so tests can redirect.
//
// On a clustered node this value is derived, not random — see ensureProxyToken.
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

// clusterWideSecretsMarker records whether TokenFile/TLSCertFile currently
// hold cluster-wide secrets (derived from the cluster's shared join token,
// identical on every node) rather than single-node ones (randomly
// generated, unique to this node). A node leaving a cluster has no way to
// tell "this persisted secret is cluster-wide, derived from a token I no
// longer know" from "this is already my own single-node secret" just by
// looking at the file content, so markSingleNode uses this marker to
// force fresh single-node secrets on that transition instead of continuing
// to serve ones nothing but a former cluster member could still reproduce.
var clusterWideSecretsMarker = "/persist/vault/mgmtproxy/cluster-wide-secrets"

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

// startProxySecretsReconciler waits for the vault to unseal, then polls
// ctx.proxyIdentity() forever. Every tick it marks the current scope
// (markClusterWide or markSingleNode) regardless of cache state, then
// re-derives the cni0 token/cert (Ed25519 keygen, X.509 cert creation) only
// when ctx.authTokenKey shows the cluster token actually changed since the
// last tick, and otherwise only checks (via secretsFilesExist) that nothing
// got wiped.
func (ctx *mgmtProxyContext) startProxySecretsReconciler() {
	go func() {
		err := wait.WaitForVault(ctx.ps, log, agentName, warningTime, errorTime)
		if err != nil {
			log.Errorf("mgmtproxy: cni0 proxy-auth: wait for vault: %v", err)
			return
		}
		for {
			interval := time.Minute
			clusterToken, ready := ctx.proxyIdentity()
			if !ready {
				time.Sleep(2 * time.Second)
				continue
			}
			// Checked every tick, not only when applyProxySecrets runs
			// below: secretsFilesExist only checks TokenFile/TLSCertFile/
			// TLSKeyFile, not the marker, so a marker wiped independently
			// of those (while the cached secret is still fresh) would
			// otherwise never get noticed and re-created.
			var markErr error
			if clusterToken == "" {
				markErr = markSingleNode()
			} else {
				markErr = markClusterWide()
			}
			if markErr != nil {
				log.Warnf("mgmtproxy: mark scope: %v", markErr)
				time.Sleep(10 * time.Second)
				continue
			}

			_, hasCachedTok := ctx.authToken.Load().(string)
			_, hasCachedCert := ctx.tlsCert.Load().(*tls.Certificate)
			key, hasCachedKey := ctx.authTokenKey.Load().(string)
			haveCache := hasCachedKey && hasCachedTok && hasCachedCert

			if !haveCache || key != clusterToken || !secretsFilesExist() {
				interval = ctx.applyProxySecrets(clusterToken)
			}

			time.Sleep(interval)
		}
	}()
}

// applyProxySecrets derives (or generates) and persists the cni0 token/cert
// for clusterToken, storing them on ctx. Returns the interval the caller
// should sleep before the next tick.
//
// The caller (startProxySecretsReconciler) marks the scope -- markClusterWide
// or markSingleNode -- on every tick, before ever calling this, not just
// when it's about to. That order matters for what a crash between marking
// and persisting leaves behind: marker-then-secrets means a crash leaves, at
// worst, a marker with no (or stale) matching secrets yet -- harmless, since
// the next tick just re-derives and overwrites them, or markSingleNode wipes
// the lot if the node has left the cluster by then. The reverse order is
// unsafe: secrets persisted with no marker yet look, after a departure,
// exactly like a node's own genuine standalone secret, so markSingleNode's
// absence check would never fire and a value every former cluster member can
// still reproduce would be reused forever -- the exposure the marker exists
// to prevent.
func (ctx *mgmtProxyContext) applyProxySecrets(clusterToken string) time.Duration {
	tok, tokErr := ensureProxyToken(TokenFile, clusterToken)
	cert, certErr := ensureProxyTLSCert(TLSCertFile, TLSKeyFile, clusterToken)
	if tokErr != nil || certErr != nil {
		log.Warnf("mgmtproxy: cni0 auth: token=%v cert=%v", tokErr, certErr)
		return 10 * time.Second
	}
	ctx.authToken.Store(tok)
	ctx.tlsCert.Store(&cert)
	ctx.authTokenKey.Store(clusterToken)
	ctx.logProxyAuthReadyOnce(clusterToken != "")
	return time.Minute
}

// markSingleNode detects a clustered -> single-node transition (via
// clusterWideSecretsMarker) and deletes TokenFile/TLSCertFile/TLSKeyFile so
// ensureProxyToken/ensureProxyTLSCert regenerate fresh random values, the
// same as on first boot. Call only when the node is not (or no longer)
// clustered -- see markClusterWide for the other direction.
func markSingleNode() error {
	_, err := os.Stat(clusterWideSecretsMarker)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", clusterWideSecretsMarker, err)
	}
	for _, f := range []string{TokenFile, TLSCertFile, TLSKeyFile} {
		rmErr := os.Remove(f)
		if rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", f, rmErr)
		}
	}
	return os.Remove(clusterWideSecretsMarker)
}

// markClusterWide records that TokenFile/TLSCertFile are about to be (or
// already are) derived, cluster-wide values, ahead of actually persisting
// them -- see applyProxySecrets for why that order matters. Call only when
// the node is (or remains) clustered.
func markClusterWide() error {
	_, err := os.Stat(clusterWideSecretsMarker)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", clusterWideSecretsMarker, err)
	}
	return os.WriteFile(clusterWideSecretsMarker, nil, 0o600)
}

// ensureProxyTLSCert loads the persisted cert/key pair, generating and
// persisting a new one on first boot or on any load error (e.g. a wiped
// /persist). With clusterToken set, the pair is deterministically derived
// instead (see deriveProxyTLSCert) and re-persisted whenever it doesn't
// match — no cross-node coordination needed.
func ensureProxyTLSCert(certPath, keyPath, clusterToken string) (tls.Certificate, error) {
	if clusterToken != "" {
		certPEM, keyPEM, err := deriveProxyTLSCert(clusterToken)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("derive TLS cert: %w", err)
		}
		return ensurePersistedCert(certPath, keyPath, certPEM, keyPEM)
	}
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}
	certPEM, keyPEM, err := generateProxyTLSCert()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate TLS cert: %w", err)
	}
	return ensurePersistedCert(certPath, keyPath, certPEM, keyPEM)
}

// ensurePersistedCert writes certPEM/keyPEM to disk only if certPath and
// keyPath don't already hold exactly that content, then returns the parsed
// pair. Both files are checked, not just certPath: tls.X509KeyPair below
// only parses the certPEM/keyPEM bytes already in memory, so it can't by
// itself detect a keyPath wiped or corrupted independently of certPath.
func ensurePersistedCert(certPath, keyPath string,
	certPEM, keyPEM []byte) (tls.Certificate, error) {
	existingCert, certReadErr := os.ReadFile(certPath)
	existingKey, keyReadErr := os.ReadFile(keyPath)
	if certReadErr == nil && keyReadErr == nil &&
		bytes.Equal(existingCert, certPEM) && bytes.Equal(existingKey, keyPEM) {
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"mkdir %s: %w", filepath.Dir(certPath), err)
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
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mgmtproxy cni0"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     noWellDefinedExpiration,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP(cni0IP)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &key.PublicKey, key)
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

// proxyTLSKeyHKDFInfo and proxyTLSSerialHKDFInfo are the HKDF "info" labels
// for deriveProxyTLSCert. Versioned so the derivation can change later
// without colliding with an older scheme's output.
const (
	proxyTLSKeyHKDFInfo    = "eve-mgmtproxy-cni0-tls-key-v1"
	proxyTLSSerialHKDFInfo = "eve-mgmtproxy-cni0-tls-serial-v1"
)

// deterministicCertNotBefore stands in for time.Now() so the derived
// certificate is byte-identical across nodes. The exact value doesn't
// matter (see noWellDefinedExpiration).
var deterministicCertNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// deriveHKDF returns n bytes of HKDF-SHA256 output keyed on clusterToken,
// using info for domain separation between values derived from the same
// cluster token.
func deriveHKDF(clusterToken, info string, n int) ([]byte, error) {
	out := make([]byte, n)
	r := hkdf.New(sha256.New, []byte(clusterToken), nil, []byte(info))
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// deriveProxyTLSCert derives the cni0 listener's Ed25519 keypair and
// self-signed certificate from the cluster's shared join token (see
// deriveProxyToken), so every node computes the identical certificate with
// no coordination. Ed25519 over generateProxyTLSCert's ECDSA because
// ed25519.NewKeyFromSeed is a spec-mandated deterministic KDF (RFC 8032),
// and signing is deterministic too, so the whole cert is reproducible.
func deriveProxyTLSCert(clusterToken string) (certPEM, keyPEM []byte, err error) {
	seed, err := deriveHKDF(clusterToken, proxyTLSKeyHKDFInfo, ed25519.SeedSize)
	if err != nil {
		return nil, nil, fmt.Errorf("derive key seed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	serialBytes, err := deriveHKDF(clusterToken, proxyTLSSerialHKDFInfo, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("derive serial: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)

	cni0IP, _, err := net.SplitHostPort(CNI0ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("split %s: %w", CNI0ListenAddr, err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "mgmtproxy cni0"},
		NotBefore:    deterministicCertNotBefore,
		NotAfter:     noWellDefinedExpiration,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP(cni0IP)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// tokenBytes is the random secret's length before hex encoding.
const tokenBytes = 32

// logProxyAuthReadyOnce logs that the cni0 token/cert are ready, once per
// process lifetime -- a later rotation or scope change re-derives silently.
func (ctx *mgmtProxyContext) logProxyAuthReadyOnce(clusterWide bool) {
	if ctx.authReady.Load() {
		return
	}
	log.Noticef("mgmtproxy: cni0 auth ready (clusterWide=%v)", clusterWide)
	ctx.authReady.Store(true)
}

// secretsFilesExist reports whether TokenFile/TLSCertFile/TLSKeyFile are all
// still present, via os.Stat rather than reading their content.
func secretsFilesExist() bool {
	for _, p := range []string{TokenFile, TLSCertFile, TLSKeyFile} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// ensureProxyToken returns the cni0 proxy-auth token: derived (deriveProxyToken)
// and re-persisted on mismatch when clusterToken is set, otherwise the
// original random-per-node behavior — reuse what's persisted, or generate
// and persist a fresh one.
func ensureProxyToken(path, clusterToken string) (string, error) {
	if clusterToken != "" {
		return ensurePersisted(path, deriveProxyToken(clusterToken), 0o600)
	}
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
	return ensurePersisted(path, tok, 0o600)
}

// ensurePersisted writes want to path only if it isn't already there, then
// returns want.
func ensurePersisted(path, want string, perm os.FileMode) (string, error) {
	if data, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(data)) == want {
			return want, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(want), perm); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return want, nil
}

// generateProxyToken returns a fresh random hex-encoded secret.
func generateProxyToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// proxyTokenHKDFInfo is the HKDF "info" label for deriveProxyToken.
// Versioned so the derivation can change later without colliding with an
// older scheme's output.
const proxyTokenHKDFInfo = "eve-mgmtproxy-cni0-token-v1"

// deriveProxyToken deterministically derives the cni0 proxy-auth token from
// the cluster's shared join token via HKDF-SHA256, so every node computes
// the identical value independently — no coordination, no write to race on.
func deriveProxyToken(clusterToken string) string {
	out, err := deriveHKDF(clusterToken, proxyTokenHKDFInfo, tokenBytes)
	if err != nil {
		// Only possible if tokenBytes exceeded HKDF-SHA256's 255*32-byte
		// output limit, which a 32-byte token never does.
		panic("mgmtproxy: derive proxy token: " + err.Error())
	}
	return hex.EncodeToString(out)
}

// --- Destination policy -------------------------------------------------

// deniedDestCIDRs are ranges a pod must never reach through mgmtproxy's cni0
// listener: the k3s pod and service CIDRs. Loopback, link-local, unspecified
// and multicast are handled by net.IP predicates in destinationAllowed.
//
// Deliberately not broadened to all of RFC1918: this list mirrors noProxy
// (see cdiImportProxyNoProxy), blocking only ranges that can never be a
// legitimate registry. General private-network addresses are a real
// import source (on-prem/air-gapped registries), so they're intentionally
// left reachable.
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
