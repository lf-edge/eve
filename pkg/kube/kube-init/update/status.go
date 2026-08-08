// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
)

// Per-component lifecycle stages reported back to pillar. These
// must match the strings zedkube's pubKubeClusterUpdateStatus
// expects on its third positional argument; see
// pkg/pillar/cmd/zedkube/zedkube.go.
const (
	StatusDownload  = "download"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
)

// PublishUpdateStatus shells out to pillar's zedkube binary to emit
// a KubeClusterUpdateStatus pubsub message for the given component.
//
// On first boot (applied version == "0") this is a no-op: there is
// no previous version to report a delta from, and pillar treats the
// absence of a status as "not yet started" already. The same gate
// also fires when VersionGet can't read the marker file — see
// VersionGet's doc for the rationale.
//
// Errors are logged but not returned: a status-publish failure must
// not stall the upgrade flow.
func PublishUpdateStatus(component, status, errorStr string) {
	if VersionGet() == "0" {
		log.Printf("update: skip publish for %s/%s (no applied-kube-version marker)",
			component, status)
		return
	}

	nodeName := edgenodeinfo.DeviceName()
	if nodeName == "" {
		log.Printf("update: cannot publish %s/%s, device name unavailable",
			component, status)
		return
	}

	zedkubePath := pillarRootfs + zedkubeBinRel
	ldLibPath := pillarRootfs + pillarLibDirRel
	kubeVersionStr := strconv.Itoa(KubeVersion)

	cmd := exec.Command(zedkubePath,
		"pubKubeClusterUpdateStatus",
		nodeName,
		component,
		status,
		kubeVersionStr,
		errorStr,
	)
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+ldLibPath)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("update: publish status failed: %v (output: %s)",
			err, truncateForLog(string(out), 4096))
		return
	}
	log.Printf("update: published status component=%s status=%s version=%s",
		component, status, kubeVersionStr)
}

// truncateForLog clips s to at most maxLen bytes, appending an
// ellipsis when it had to cut. Used on combined kubectl /
// update-component output before it ends up as an exec argument
// to zedkube — long stderr dumps can push the argv past E2BIG on
// small embedded devices.
func truncateForLog(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}
