// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// ============================================================================
// REMOVE ME
// ============================================================================
//
// This file works around an infra bug in Longhorn's CSI provisioner. It is
// not related to anything this suite tests. Delete this file and the one
// call to waitForAppRunningMitigatingPVCStall (grep for it, in
// purge_during_failover_test.go) once Longhorn no longer needs a pod restart
// to recover from a stuck PVC.
//
// Observed symptom: a PVC stays Pending indefinitely. Its ProvisioningFailed
// events alternate "volume ... not found" (404) and "volume ... already
// exists" (500) - the provisioner created the Longhorn backend volume once,
// lost track of that success in its own cache, and keeps retrying against a
// name it no longer recognises.
//
// Confirmed live, on the current Longhorn version, with no EVE or pillar
// change involved: deleting the csi-provisioner pod forces a fresh leader
// election and cache, and the very next retry succeeds
// (ProvisioningSucceeded within minutes).
//
// Only wired into TestVMAppPurgeDuringFailover: that is the one test this has
// actually been observed to fail, and restarting a cluster-wide Longhorn pod
// is not something to do reflexively from every test that creates a volume.
//
// Scope note: this deletes a cluster-wide Longhorn pod. Safe here because
// each purge test gets its own freshly-created device/cluster
// (purgeDeviceRequirements), so nothing else is using it. Do not call this
// against a shared or long-lived cluster.
package apps_test

import (
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest"
)

// pvcStallSignature is the substring both ends of the failure oscillation
// share. "not found" alone is not distinctive enough to key on - a PVC can
// legitimately report "not found" for a moment during normal provisioning.
const pvcStallSignature = "already exists"

// pvcStallCheckInterval is how often waitForAppRunningMitigatingPVCStall
// polls for the stuck-PVC signature while waitFn is blocked.
const pvcStallCheckInterval = 30 * time.Second

// pvcStallThreshold is how long a PVC must show the signature, continuously,
// before this mitigation acts. A PVC that clears - becomes Bound, or simply
// stops matching the signature - before this elapses is a normal, if slow,
// provisioning retry; passing through and leaving it alone is the point.
const pvcStallThreshold = 2 * time.Minute

// waitForAppRunningMitigatingPVCStall wraps waitFn - normally
// cluster.WaitUntilAppIsRunning - with a background watcher that restarts
// Longhorn's csi-provisioner if a PVC shows the stuck-PVC signature for at
// least pvcStallThreshold while waitFn is blocked.
//
// waitFn still Fatalf's on its own timeout exactly as it would unwrapped;
// this only gives the provisioner a chance to recover before that timeout.
// kubeDev is any device that can reach the cluster's kubectl - for a cluster
// test, any member node.
func waitForAppRunningMitigatingPVCStall(kubeDev *evetest.EdgeDevice, waitFn func()) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(pvcStallCheckInterval)
		defer ticker.Stop()
		firstSeenStalled := map[string]time.Time{}
		kicked := false
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if kicked {
					// One restart per wait is enough. Retrying it on every
					// tick would fight a genuinely slow (but healthy)
					// provision with unnecessary leader-election churn.
					continue
				}
				now := time.Now()
				stalled := stalledPVCNames(kubeDev)
				// A PVC no longer in the stalled set recovered on its own -
				// forget it, so a later, unrelated stall starts its own
				// clock rather than inheriting an old one.
				for name := range firstSeenStalled {
					if !stalled[name] {
						delete(firstSeenStalled, name)
					}
				}
				for name := range stalled {
					if _, tracked := firstSeenStalled[name]; !tracked {
						firstSeenStalled[name] = now
					}
				}
				for name, since := range firstSeenStalled {
					if now.Sub(since) < pvcStallThreshold {
						continue
					}
					evetest.Logger().Warnf(
						"waitForAppRunningMitigatingPVCStall: PVC %q stuck for over %s, "+
							"restarting csi-provisioner - see the REMOVE ME note in "+
							"longhorn_provisioner_workaround_test.go", name, pvcStallThreshold)
					restartCSIProvisioner(kubeDev)
					kicked = true
					break
				}
			}
		}
	}()
	waitFn()
	close(stop)
	<-done
}

// stalledPVCNames returns the names of PVCs that are currently Pending and
// have a ProvisioningFailed event carrying pvcStallSignature. Checking events
// against PVCs still Pending, rather than events alone, means a PVC that has
// since become Bound is never counted, even though its old events persist
// for a while - that is exactly the "passes through once bound" behaviour
// this mitigation is meant to have.
//
// Empty on any read failure - a transient kubectl error must never
// contribute to the stall clock.
func stalledPVCNames(dev *evetest.EdgeDevice) map[string]bool {
	stalled := map[string]bool{}

	pvcs, found := kubectlListItems(dev, "pvc")
	if !found {
		return stalled
	}
	pending := make(map[string]bool)
	for _, item := range pvcs.Items {
		if item.Status.Phase == "Pending" {
			pending[item.Metadata.Name] = true
		}
	}
	if len(pending) == 0 {
		return stalled
	}

	events, found := kubectlEvents(dev)
	if !found {
		return stalled
	}
	for _, ev := range events.Items {
		if ev.Reason != "ProvisioningFailed" || !pending[ev.InvolvedObject.Name] {
			continue
		}
		if strings.Contains(ev.Message, pvcStallSignature) {
			stalled[ev.InvolvedObject.Name] = true
		}
	}
	return stalled
}
