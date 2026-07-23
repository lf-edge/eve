// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kcus"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// KubeVersion is the version this build expects to converge the
// cluster onto. Bump when a new migration or component upgrade pass
// must run. The applied version is persisted to AppliedKubeVersion;
// CheckClusterComponents short-circuits when applied >= KubeVersion
// (i.e. node already at target, or EVE was downgraded — downgrades
// are unsupported, see addresses upstream a67d55ce9).
const KubeVersion = 3

// VersionGet returns the last applied KubeVersion as a string, or
// "0" if the marker file is missing or unreadable.
//
// A genuinely fresh device (no marker) and a device whose marker
// is transiently unreadable (EIO, EACCES) both map to "0". This is
// safe by design: the convergence path is itself version-checked
// and idempotent. The "0" sentinel is also load-bearing as the
// first-boot gate inside PublishUpdateStatus.
//
// Read failures other than ErrNotExist are logged so a permissions
// regression on the marker path leaves a forensic trail.
func VersionGet() string {
	data, err := os.ReadFile(AppliedKubeVersion)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("update: read %s: %v (treating as version 0)",
				AppliedKubeVersion, err)
		}
		return "0"
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "0"
	}
	return v
}

// VersionSet persists the current KubeVersion to the marker file.
// Uses AtomicWriteFile so a power-loss between rename and the
// caller's return cannot leave a torn marker that would re-trigger
// the upgrade pass on next boot.
func VersionSet() error {
	return state.AtomicWriteFile(
		AppliedKubeVersion,
		[]byte(strconv.Itoa(KubeVersion)+"\n"),
		0644,
	)
}

// updateFailed reports whether pillar has recorded a failed update
// pass targeting the current KubeVersion. A missing kcus file is
// not a failure (returns false): pillar has not yet published a
// status, which is the normal case on a clean boot.
//
// Non-ErrNotExist read errors and JSON parse errors also return
// false but are logged. The alternative (returning true) would
// permanently block convergence on a transient I/O blip; with the
// false-return policy the worst-case is one extra retry per boot,
// and the next status publish from pillar will rewrite the file
// cleanly.
func updateFailed() bool {
	status, ok := kcus.Get()
	if !ok {
		return false
	}
	return status.Status == types.CompStatusFailed &&
		status.DestinationKubeUpdateVersion == uint32(KubeVersion)
}

// appliedVersionGEQ reports whether the persisted applied version
// is >= target. The applied marker is the textual decimal written
// by VersionSet, so this is a parsed-int compare. An unparsable
// value is treated as "0" — same fallback as VersionGet — so a
// corrupted marker re-triggers convergence rather than blocking
// it.
func appliedVersionGEQ(applied string, target int) bool {
	n, err := strconv.Atoi(strings.TrimSpace(applied))
	if err != nil {
		return false
	}
	return n >= target
}

