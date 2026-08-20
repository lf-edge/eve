// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import "testing"

// KubeAppUUID must be a pure function of (namespace, ownerName): every cluster node
// must derive the identical synthetic appUUID so the ClusterDeterministic MAC matches.
func TestKubeAppUUIDDeterministic(t *testing.T) {
	if KubeAppUUID("ns1", "myapp") != KubeAppUUID("ns1", "myapp") {
		t.Fatal("KubeAppUUID must be deterministic for the same (namespace, ownerName)")
	}
}

func TestKubeAppUUIDDistinctByNamespace(t *testing.T) {
	if KubeAppUUID("ns1", "myapp") == KubeAppUUID("ns2", "myapp") {
		t.Fatal("KubeAppUUID must differ when the namespace differs")
	}
}

func TestKubeAppUUIDDistinctByOwner(t *testing.T) {
	if KubeAppUUID("ns1", "a") == KubeAppUUID("ns1", "b") {
		t.Fatal("KubeAppUUID must differ when the owner name differs")
	}
}

// KubePodMatchesOwner identifies either a bare Pod by its exact name or a Pod belonging
// to a bare ReplicaSet. ReplicaSet pods are named "<ownerName>-<5 lowercase-alnum chars>".
func TestKubePodMatchesOwner(t *testing.T) {
	cases := []struct {
		pod, owner string
		want       bool
	}{
		{"myapp-x2k4p", "myapp", true},     // normal RS pod
		{"app-foo-x2k4p", "app-foo", true}, // owner name itself contains a dash
		{"app-foo-x2k4p", "app", false},    // nested prefix: leftover "foo-x2k4p" is not a valid suffix
		{"myapp", "myapp", true},           // ownerless bare Pod uses its own name
		{"myapp-x2k", "myapp", false},      // suffix too short (3 chars)
		{"myapp-x2k4pq", "myapp", false},   // suffix too long (6 chars)
		{"myapp-X2K4P", "myapp", false},    // uppercase is not in the RS suffix alphabet
		{"myapp-x2k4p", "", false},         // empty owner name
		{"other-x2k4p", "myapp", false},    // different owner
	}
	for _, c := range cases {
		if got := KubePodMatchesOwner(c.pod, c.owner); got != c.want {
			t.Errorf("KubePodMatchesOwner(%q, %q) = %v, want %v", c.pod, c.owner, got, c.want)
		}
	}
}
