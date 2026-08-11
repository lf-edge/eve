// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package role distinguishes the two k3s instances this binary can
// supervise: the node's own k3s, and the etcd-only witness that gives a
// two-node HA cluster a third quorum vote.
//
// Both run as separate containers on the same device and both bind-mount
// the host /run and /persist, so every runtime path either one writes has
// to differ. Pick is how that difference is expressed.
package role

import (
	"os"
	"strings"
	"sync"
)

// Role selects which k3s instance this process supervises.
type Role int

// Roles.
const (
	Kube Role = iota
	Witness
)

// String returns the role name, which is also its pubsub agent name.
func (r Role) String() string {
	if r == Witness {
		return "kube-witness"
	}
	return "kube-init"
}

// roleFile names the role of the container a process is running in.
// Shipped in the witness image, absent from the kube image, following
// /etc/eve-hv-type. A var so tests can redirect it.
var roleFile = "/etc/kube-init-role"

// witnessMarker is the roleFile content selecting the witness.
const witnessMarker = "witness"

// detect resolves the role from the image rather than from a flag, and
// the file is the only way to select it. Packages hold their paths in
// package-level vars initialised before main can parse anything, so a
// flag could not reach them; and a second mechanism alongside this one
// would only add a way for the two to disagree. Tools sharing the image
// get the role for free: k3s-sctl should not need an operator to name
// the role of the container they are already inside. The file cannot
// change under a running process, so caching is safe.
//
// Anything unreadable or unrecognised means kube, which is what every
// other image on the device is.
var detect = sync.OnceValue(readRole)

func readRole() Role {
	raw, err := os.ReadFile(roleFile)
	if err != nil {
		return Kube
	}
	if strings.TrimSpace(string(raw)) == witnessMarker {
		return Witness
	}
	return Kube
}

// override, when set, wins over the role file. Tests only.
var override *Role

// Override forces the role and returns a function restoring the previous
// value. Production never calls it: the role comes from the image, which
// is fixed for the life of the process, so there is nothing to set.
func Override(r Role) (restore func()) {
	prev := override
	override = &r
	return func() { override = prev }
}

// Current returns the role of this process.
func Current() Role {
	if override != nil {
		return *override
	}
	return detect()
}

// IsWitness reports whether this process supervises the witness.
func IsWitness() bool { return Current() == Witness }

// AgentName is the pubsub identity. It also determines /run/<agent>/ and
// /var/run/<agent>.sock, so the two roles must never share it.
func AgentName() string { return Current().String() }

// Pick returns kube when running as the node's k3s, witness otherwise.
func Pick[T any](kube, witness T) T {
	if IsWitness() {
		return witness
	}
	return kube
}
