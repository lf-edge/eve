// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// KubeVersion is the version this build expects to converge the
// cluster onto. Bump when a new migration or component upgrade pass
// must run. The applied version is persisted to AppliedKubeVersion;
// CheckClusterComponents short-circuits when applied >= KubeVersion
// (i.e. node already at target, or EVE was downgraded — downgrades
// are unsupported, see addresses upstream a67d55ce9).
const KubeVersion = 3

// kcusJSON is the minimal subset of pillar's KubeClusterUpdateStatus
// we read to detect a failed upgrade pass targeting our KubeVersion.
//
// MUST stay in sync with the canonical type in pillar
// (pkg/pillar/types/kubeclusterupdate.go: KubeClusterUpdateStatus
// and KubeClusterUpdateStatusType). A field rename on the pillar
// side will silently zero our Status / DestinationKubeUpdateVersion
// reads and disable the failed-upgrade guard.
type kcusJSON struct {
	Status                       int    `json:"Status"`
	DestinationKubeUpdateVersion string `json:"DestinationKubeUpdateVersion"`
}

// kcusStatusFailed mirrors pillar's KubeClusterUpdateStatusFailed.
// We hold the magic number locally to avoid pulling in the heavy
// pkg/pillar/types reverse dependency; it must move in lockstep
// with that enum if pillar ever reorders it.
const kcusStatusFailed = 4

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
	data, err := os.ReadFile(kcusFilePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("update: read %s: %v (treating as no prior failure)",
				kcusFilePath, err)
		}
		return false
	}
	var status kcusJSON
	if err := json.Unmarshal(data, &status); err != nil {
		log.Printf("update: parse %s: %v (treating as no prior failure)",
			kcusFilePath, err)
		return false
	}
	return status.Status == kcusStatusFailed &&
		status.DestinationKubeUpdateVersion == strconv.Itoa(KubeVersion)
}

// readDeviceName parses EdgeNodeInfo for the local device's name,
// returning "" if the file is missing or malformed. Duplicated
// across update / k3s / prereqs / components; the helper is small
// enough that the duplication is cheaper than a new shared package
// whose only consumers are these one-line readers.
func readDeviceName() string {
	data, err := os.ReadFile(EdgeNodeInfoPath)
	if err != nil {
		return ""
	}
	var info struct {
		DeviceName string `json:"DeviceName"`
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return ""
	}
	return info.DeviceName
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

// readDeviceK8sName returns the device name normalised to a
// Kubernetes-compatible DNS label, or "" when unavailable.
func readDeviceK8sName() string {
	name := readDeviceName()
	if name == "" {
		return ""
	}
	return state.ToK8sName(name)
}
