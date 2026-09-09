// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// EVE-K's storage stack comes up in stages, and each stage's budget is set by
// how long the stage below it can block rather than by how long it usually
// takes. They are waited on in order so that a failure names the stage that
// stalled instead of surfacing as an app that never started.
// Budgets taken from the eden escripts these tests are ported from, which are
// the only calibration anyone has for how long EVE-K actually takes here.
const (
	// volumemgrReadyTimeout must exceed volumemgr's own pre-publish block: it
	// waits up to 20 minutes in WaitForKubernetes and up to 20 more in
	// storageWait before publishing any status at all.
	volumemgrReadyTimeout = 90 * time.Minute
	// longhornSCTimeout covers Longhorn installing its StorageClass.
	longhornSCTimeout = 50 * time.Minute
	// appRunningAfterRepartitionTimeout is what the repartition escript allows
	// an app after the conversion; the flavor switch alone gets less, because
	// no offline resize preceded it.
	appRunningAfterRepartitionTimeout = 65 * time.Minute
	// appRunningAfterSwitchTimeout is the budget the cross-flavor and
	// volume-migration escripts use.
	appRunningAfterSwitchTimeout = 45 * time.Minute
	// appSSHTimeout absorbs the app's network reconvergence as well as SSH
	// itself, which is what the escripts do -- their marker script retries for
	// about twelve minutes rather than gating on an address first.
	appSSHTimeout = 12 * time.Minute
)

// waitVolumemgrReady blocks until volumemgr reports itself initialized, which
// is the point after which a volume request is acted on rather than queued.
func waitVolumemgrReady(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func() string {
		out, _, _ := device.RunShellScript(
			"eve exec pillar cat /run/volumemgr/VolumeMgrStatus/volumemgr.json 2>/dev/null",
			eveShellTimeout, 0)
		return out
	}, volumemgrReadyTimeout, 15*time.Second).Should(ContainSubstring(`"Initialized":true`),
		"volumemgr never reported Initialized")
}

// waitLonghornSC blocks until Longhorn's StorageClass exists, without which a
// PVC has nothing to bind to.
func waitLonghornSC(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func() string {
		out, _, _ := device.RunShellScript("eve exec kube kubectl get sc 2>/dev/null",
			eveShellTimeout, 0)
		return out
	}, longhornSCTimeout, 30*time.Second).Should(ContainSubstring("longhorn"),
		"Longhorn's StorageClass never appeared")
}

// waitClusterStorageReady runs the EVE-K storage gates in order. Order is the
// point: each can only be reached once the one before it has passed, so waiting
// on them in sequence turns a stall into a named stage.
//
// No k3s-readiness gate, deliberately: none of the escripts has one, and
// volumemgr will not report itself initialized until the cluster is up anyway,
// so gating on node health first only moves where a stall is reported.
func waitClusterStorageReady(t Gomega, device *evetest.EdgeDevice) {
	log := evetest.Logger()
	log.Infof("waiting for volumemgr to initialize")
	waitVolumemgrReady(t, device)
	log.Infof("waiting for Longhorn's StorageClass")
	waitLonghornSC(t, device)
}
