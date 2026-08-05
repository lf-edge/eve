// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
)

// Diagnostics for the case where a readiness poll cannot get an answer
// out of the local apiserver.
//
// A join leaves several things able to fail in ways that look identical
// from a hanging Get: the apiserver may not be listening, it may be
// listening but not admitting requests, it may be serving under a CA the
// client does not trust, or it may be up and merely waiting on etcd. The
// helpers here separate those, so one run says which it was rather than
// leaving the next run to narrow it down.
//
// Deliberately limited to what only the client can see — the moment a
// call failed, and what it was pointed at when it did. k3s's own account
// of the same window is in /persist/kubelog/k3s.log, which collect-info
// already carries off the device; it is not copied in here.
const (
	// diagDialBudget bounds the raw TCP probe. Only distinguishing
	// "nothing is listening" from "something is", so it can be short.
	diagDialBudget = 3 * time.Second

	// diagHTTPBudget bounds the /readyz probe. Longer than the dial —
	// an apiserver that is up but converging can take a moment to
	// render the check list.
	diagHTTPBudget = 5 * time.Second
)

// logAPITarget records what the client is pointed at and what it will
// trust, once, when the wait starts. A join rewrites the kubeconfig with
// the cluster's CA; if a client built before that is still in use, every
// call fails the TLS handshake and the only visible symptom is a timeout.
// The CA fingerprint is what makes that case obvious.
func logAPITarget(kc *kubeclient.Client, kubeconfigPath string) {
	host := "<nil config>"
	if kc != nil && kc.Config != nil {
		host = kc.Config.Host
	}
	var mtime string
	if st, err := os.Stat(kubeconfigPath); err == nil {
		mtime = st.ModTime().Format(time.RFC3339)
	} else {
		mtime = "stat: " + err.Error()
	}
	log.Printf("readiness: API target %s (kubeconfig %s written %s, CA %s)",
		host, kubeconfigPath, mtime, caFingerprint(kc))
}

// caFingerprint renders a short sha256 of the CA the client trusts, plus
// the issuer subject. Two nodes in one cluster must agree on this; a
// mismatch after a join is the stale-client case.
func caFingerprint(kc *kubeclient.Client) string {
	if kc == nil || kc.Config == nil {
		return "unknown"
	}
	pemBytes := kc.Config.CAData
	if len(pemBytes) == 0 && kc.Config.CAFile != "" {
		b, err := os.ReadFile(kc.Config.CAFile)
		if err != nil {
			return "unreadable: " + err.Error()
		}
		pemBytes = b
	}
	if len(pemBytes) == 0 {
		return "none (insecure or system trust)"
	}
	sum := sha256.Sum256(pemBytes)
	short := fmt.Sprintf("%x", sum[:6])
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return short + " (unparseable PEM)"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return short + " (unparseable cert)"
	}
	return fmt.Sprintf("%s issuer=%q notAfter=%s",
		short, cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))
}

// kubeconfigChanged reports whether the kubeconfig has been rewritten
// since the client was built, and is the direct test for the
// stale-client case: a cluster join replaces the file with one carrying
// the cluster's CA, and a client constructed before that keeps
// presenting and trusting the retired one. Every call then fails at the
// TLS handshake, which surfaces only as a timeout.
func kubeconfigChanged(path, builtAt string) string {
	st, err := os.Stat(path)
	if err != nil {
		return "kubeconfig-stat-failed(" + errShort(err) + ")"
	}
	now := st.ModTime().Format(time.RFC3339)
	if now == builtAt {
		return "kubeconfig-unchanged"
	}
	return fmt.Sprintf("KUBECONFIG-REWRITTEN(client built against %s, file now %s "+
		"— this client is stale)", builtAt, now)
}

// probeAPI reports, in one line, why the apiserver is not answering.
//
// Three layers, each narrowing the previous:
//
//  1. TCP — is anything accepting on the API port at all.
//  2. /readyz?verbose — is the apiserver admitting requests, and which
//     of its own checks are failing. This is the layer that names etcd,
//     informer sync or a poststarthook as the thing being waited on.
//  3. the failing call's own error, which the caller already has.
//
// Best-effort throughout: this runs on a failure path and must never
// itself block or fail the wait.
func probeAPI(ctx context.Context, kc *kubeclient.Client, kubeconfigPath, builtAt string) string {
	if kc == nil || kc.Config == nil {
		return "no client config to probe"
	}
	var parts []string
	parts = append(parts, "tcp="+probeTCP(kc.Config.Host))
	parts = append(parts, "readyz="+probeReadyz(ctx, kc))
	parts = append(parts, kubeconfigChanged(kubeconfigPath, builtAt))
	return strings.Join(parts, " ")
}

// kubeconfigMtime is the timestamp logAPITarget recorded, so the failure
// path can tell whether the file moved underneath the client.
func kubeconfigMtime(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return st.ModTime().Format(time.RFC3339)
}

// probeTCP dials the API host to separate "nothing listening" from
// "listening but unresponsive" — the difference between k3s being down
// and k3s being up but wedged.
func probeTCP(host string) string {
	u, err := url.Parse(host)
	if err != nil || u.Host == "" {
		return "unparseable-host"
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, diagDialBudget)
	if err != nil {
		return fmt.Sprintf("refused-or-timeout(%s after %s)",
			errShort(err), time.Since(start).Round(time.Millisecond))
	}
	_ = conn.Close()
	return fmt.Sprintf("open(%s)", time.Since(start).Round(time.Millisecond))
}

// probeReadyz asks the apiserver for its own readiness breakdown. A 200
// means it considers itself ready and the failing call is something
// else; a 500 body lists exactly which checks are outstanding.
func probeReadyz(ctx context.Context, kc *kubeclient.Client) string {
	callCtx, cancel := context.WithTimeout(ctx, diagHTTPBudget)
	defer cancel()

	var code int
	body, err := kc.Discovery.RESTClient().Get().
		AbsPath("/readyz").Param("verbose", "").
		Do(callCtx).StatusCode(&code).Raw()
	if err != nil && code == 0 {
		// Never reached the server, or TLS refused it. This is the
		// case a hanging Get cannot distinguish on its own.
		return "unreachable(" + errShort(err) + ")"
	}
	failed := failedReadyzChecks(string(body))
	if len(failed) == 0 {
		return fmt.Sprintf("%d(all checks ok)", code)
	}
	return fmt.Sprintf("%d(failing: %s)", code, strings.Join(failed, ","))
}

// failedReadyzChecks pulls the non-ok lines out of a verbose /readyz
// body, whose format is one "[+]name ok" or "[-]name failed" per line.
func failedReadyzChecks(body string) []string {
	var failed []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[+]") {
			continue
		}
		if strings.HasPrefix(line, "[-]") {
			failed = append(failed, strings.TrimPrefix(line, "[-]"))
		}
	}
	return failed
}

// errShort keeps a probe line to one line: client-go errors can carry a
// whole certificate chain.
func errShort(err error) string {
	if err == nil {
		return "nil"
	}
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}
