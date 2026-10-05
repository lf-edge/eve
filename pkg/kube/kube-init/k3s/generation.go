// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"fmt"
	"strconv"
	"strings"
)

// Generation identifies a cluster at a point in its recovery history.
//
// The cluster UUID alone is not enough: a quorum-loss recovery keeps
// the UUID the controller assigned while replacing the etcd cluster
// underneath it, so two nodes can agree on the UUID and still hold
// incompatible etcd state. Pairing it with the counter is what makes
// "same cluster, after a reset" a detectable difference.
//
// Shared by every package that has to recognize that difference
// (package quorum's own convergence record, the witness's membership
// marker, this package's server-state identity) so a format drifting
// between them can't make one wipe when it should not, or not when it
// should.
type Generation struct {
	ClusterID string
	Counter   uint32
}

// String is the on-disk form.
func (g Generation) String() string {
	return fmt.Sprintf("%s %d", g.ClusterID, g.Counter)
}

// ParseGeneration reads back what String wrote. An empty input means no
// generation has been recorded yet, which is not an error.
func ParseGeneration(s string) (g Generation, recorded bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Generation{}, false, nil
	}
	id, counter, ok := strings.Cut(s, " ")
	if !ok {
		return Generation{}, false, fmt.Errorf("malformed generation %q", s)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(counter), 10, 32)
	if err != nil {
		return Generation{}, false, fmt.Errorf("malformed generation %q: %w", s, err)
	}
	return Generation{ClusterID: id, Counter: uint32(n)}, true, nil
}
