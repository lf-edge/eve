// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package mgmtproxy

import (
	"strings"
	"testing"
)

// TestBuildCDIProxyPatch pins the JSON payload format expected by
// the CDI ImportProxy API. The CDI controller is strict about the
// keys (HTTPSProxy, noProxy — case-sensitive); a typo here would
// silently fail to set the proxy on importer pods and only show up
// when a DataVolume import surprisingly hits cellular bandwidth.
func TestBuildCDIProxyPatch(t *testing.T) {
	got := buildCDIProxyPatch("http://169.254.100.1:5443",
		"10.42.0.0/16,localhost")
	want := `{"spec":{"config":{"importProxy":{"HTTPSProxy":"http://169.254.100.1:5443","noProxy":"10.42.0.0/16,localhost"}}}}`
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

// TestBuildCDIProxyPatch_EscapesValues verifies that string values
// containing JSON-meaningful characters (quotes, backslashes) are
// properly escaped, so a maliciously-set CNI0URL can't corrupt the
// patch. %q with a string is the standard Go escape.
func TestBuildCDIProxyPatch_EscapesValues(t *testing.T) {
	got := buildCDIProxyPatch(`http://"evil"`, `a"b`)
	// Each `"` must appear escaped as `\"` exactly twice per arg.
	for _, want := range []string{`\"evil\"`, `a\"b`} {
		if !strings.Contains(got, want) {
			t.Errorf("patch missing escaped form %q\n%s", want, got)
		}
	}
}

// TestCDIImportProxyNoProxy_HasClusterCIDRs pins the cluster-local
// targets that importer pods must NOT route via mgmtproxy. Missing
// any of these means importer pods would HTTP-PROXY their calls to
// the kube-apiserver, longhorn endpoints, or CDI services — all of
// which live in-cluster and would fail.
func TestCDIImportProxyNoProxy_HasClusterCIDRs(t *testing.T) {
	for _, want := range []string{
		"10.42.0.0/16",        // pod CIDR
		"10.43.0.0/16",        // service CIDR
		"127.0.0.0/8",         // loopback
		".svc",                // service DNS suffix
		".cluster.local",      // cluster DNS suffix
		"169.254.0.0/16",      // link-local (includes our anchor)
	} {
		if !strings.Contains(cdiImportProxyNoProxy, want) {
			t.Errorf("cdiImportProxyNoProxy missing %q", want)
		}
	}
}
