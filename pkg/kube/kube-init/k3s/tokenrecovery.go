// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoAlternateToken is returned by RecoverTokenMismatch when neither the
// controller token nor the stored one differs from the token k3s just
// rejected, so there is nothing else to try.
var ErrNoAlternateToken = errors.New("no alternate cluster token to try")

// StoredToken returns the token k3s last recorded for its datastore in
// k3sTokenFile, in k3s's full "K10<ca-hash>::server:<secret>" form.
func StoredToken() (string, error) {
	data, err := os.ReadFile(k3sTokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// SameToken reports whether a and b carry the same secret. Either may be
// in k3s's full token form or the bare secret the controller delivers.
func SameToken(a, b string) bool {
	return tokenSecret(a) == tokenSecret(b)
}

// tokenSecret strips the "K10<ca-hash>::server:" prefix of a full k3s
// token. A bare secret is returned unchanged.
func tokenSecret(tok string) string {
	tok = strings.TrimSpace(tok)
	if strings.HasPrefix(tok, "K10") {
		if i := strings.Index(tok, "::"); i >= 0 {
			tok = tok[i+2:]
			tok = strings.TrimPrefix(tok, "server:")
		}
	}
	return tok
}

// RecoverTokenMismatch rewrites the cluster drop-in after k3s refused to
// start because its bootstrap data was encrypted with a different token.
//
// The two candidates are the controller token and the token k3s recorded
// for its datastore. Whichever one k3s just rejected, the other is tried
// next. This covers both orders a token change can land in: a node that
// restarts before the bootstrap node rotates the cluster still needs the
// old token, and a node that fell back to the old token needs the
// controller one again once the rotation has happened. The next Configure
// writes the controller token again, so the override lasts only until
// then.
func RecoverTokenMismatch(ctx context.Context) error {
	cluster, err := IsClusterMode()
	if err != nil {
		return fmt.Errorf("detect cluster mode: %w", err)
	}
	if !cluster {
		return nil
	}
	cs, err := GetClusterStatus()
	if err != nil {
		return fmt.Errorf("get cluster status: %w", err)
	}
	current, err := configuredToken(filepath.Join(K3sConfigDir, ClusterConfig))
	if err != nil {
		return fmt.Errorf("read configured token: %w", err)
	}
	stored, err := StoredToken()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read stored token: %w", err)
	}
	next := alternateToken(current, cs.EncryptedToken, stored)
	if next == "" {
		return ErrNoAlternateToken
	}
	source := "controller"
	if next == stored {
		source = "stored"
	}
	log.Printf("k3s rejected the configured cluster token; retrying with the %s token", source)
	return provisionClusterConfig(ctx, false, next)
}

// alternateToken returns the first of controller and stored whose secret
// differs from rejected, or "" when neither does. A member that stayed up
// through two token changes knows neither token in use; it recovers only
// once the bootstrap node has rotated the cluster to the controller's.
func alternateToken(rejected, controller, stored string) string {
	for _, c := range []string{controller, stored} {
		if c != "" && !SameToken(c, rejected) {
			return c
		}
	}
	return ""
}

// configuredToken returns the token value from a cluster drop-in written
// by writeBootstrapConfig or writeJoinConfig.
func configuredToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "token:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"`), nil
		}
	}
	return "", fmt.Errorf("no token in %s", path)
}

// ClusterConfigPresent reports whether the cluster-mode drop-in exists.
// It is written only once a node has entered cluster mode, so it also
// distinguishes a settled member from one still mid-transition.
func ClusterConfigPresent() (bool, error) {
	_, err := os.Stat(filepath.Join(K3sConfigDir, ClusterConfig))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	}
	return false, err
}
