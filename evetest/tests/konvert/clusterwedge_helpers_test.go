// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"net"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
)

// An app whose volume has to be provisioned by EVE-K's storage stack after the
// conversion does not simply take a long time: a Longhorn CSI create/verify race
// leaves the claim Pending for good, and a CDI import can be refused outright on
// size. Waiting longer rescues neither, so this is where a test distinguishes the
// two from an app that is merely slow.
const (
	// pvcRecoveryRounds is how many times "wait, then re-drive the claims" is
	// tried before the app is declared stuck, and pvcRecoveryWait how long each
	// round waits.
	pvcRecoveryRounds = 3
	pvcRecoveryWait   = 12 * time.Minute
)

// waitDeviceOnTarget waits until the device is RUNNING the target flavor, which
// is a weaker and much earlier condition than the framework's upgrade wait: that
// one blocks until EVE commits the partition, whereas this returns as soon as the
// target is the booted partition.
//
// It fails fast if EVE flags any base image FAILED, so a rejected conversion
// surfaces immediately rather than burning the whole budget.
func waitDeviceOnTarget(t Gomega, device *evetest.EdgeDevice,
	hv evetest.Hypervisor, timeout time.Duration) {
	// The target's short version carries a flavor suffix; for the conversion
	// that suffix is the only thing distinguishing it from the kvm hop.
	suffix := "-kvm-"
	if hv == evetest.HypervisorKubevirt {
		suffix = "-k-"
	}
	t.Eventually(func(g Gomega) {
		info := device.GetDeviceInfo()
		g.Expect(info).NotTo(BeNil())
		var seen []string
		for _, sw := range info.GetSwList() {
			ver, state := sw.GetShortVersion(), sw.GetPartitionState()
			seen = append(seen, fmt.Sprintf("%s[%s/%s]", ver, state, sw.GetUserStatus()))
			if !strings.Contains(ver, suffix) {
				continue
			}
			g.Expect(sw.GetUserStatus()).NotTo(Equal(eveinfo.BaseOsStatus_FAILED),
				"EVE flagged %s FAILED: %s", ver, sw.GetSubStatusStr())
			if state == "inprogress" || state == "active" {
				evetest.Logger().Infof("device is running %s (partition %s)", ver, state)
				return
			}
		}
		g.Expect(false).To(BeTrue(), "device not running a %s image yet: %v", suffix, seen)
	}, timeout, 15*time.Second).Should(Succeed())
}

// isK3sReady reports whether the single k3s node is ready with healthy storage.
func isK3sReady(info *eveinfo.ZInfoKubeCluster) bool {
	if info == nil || len(info.Nodes) != 1 {
		return false
	}
	if info.Storage.Health != eveinfo.ServiceStatus_SERVICE_STATUS_HEALTHY {
		return false
	}
	for _, cond := range info.Nodes[0].GetConditions() {
		if cond.GetType() == eveinfo.KubeNodeConditionType_KUBE_NODE_CONDITION_TYPE_READY {
			return cond.GetSet()
		}
	}
	return false
}

// waitK3sNodeReady blocks until the cluster reports its node ready.
//
// Waited on before the storage gates, unlike waitClusterStorageReady, which
// deliberately has no such gate: here the point is to localize a stall, since a
// node that never becomes ready and storage that never initializes are different
// findings and volumemgr's silence cannot tell them apart.
func waitK3sNodeReady(t Gomega, device *evetest.EdgeDevice, timeout time.Duration) {
	if isK3sReady(device.GetClusterInfo()) {
		return
	}
	clusterUpdates, stop := device.WatchClusterInfo()
	defer stop()
	t.Eventually(clusterUpdates, timeout).Should(Receive(
		matchers.SatisfyPredicate("K3s node is ready", isK3sReady)))
}

// waitAppHasRoutableIPv4 blocks until the app reports a routable
// (non-link-local) IPv4 address, and logs the one it settles on.
//
// This is the app-network readiness signal: without a reported address the
// harness cannot build a direct SSH endpoint to the app, so a still-converging
// app looks exactly like an unreachable one.
func waitAppHasRoutableIPv4(t Gomega, device *evetest.EdgeDevice,
	appUUID uuid.UUID, timeout time.Duration) {
	t.Eventually(func(g Gomega) {
		info := device.GetAppInfo(appUUID)
		g.Expect(info).NotTo(BeNil())
		var found string
		for _, netInfo := range info.GetNetwork() {
			for _, ipStr := range netInfo.GetIPAddrs() {
				ip := net.ParseIP(ipStr)
				if ip != nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
					found = ipStr
				}
			}
		}
		g.Expect(found).NotTo(BeEmpty(), "the app reports no routable IPv4 yet")
		evetest.Logger().Infof("app reports routable IPv4 %s", found)
	}, timeout, 5*time.Second).Should(Succeed())
}

// appIsRunning reports the app's current state without asserting.
func appIsRunning(device *evetest.EdgeDevice, appUUID uuid.UUID) bool {
	info := device.GetAppInfo(appUUID)
	return info != nil && info.GetState() == eveinfo.ZSwState_RUNNING
}

// waitAppRunningQuietly polls until the app is RUNNING or the timeout expires,
// returning whether it got there. Unlike the framework's waiter it does not fail
// the test on timeout, so the caller can intervene and keep waiting.
func waitAppRunningQuietly(device *evetest.EdgeDevice, appUUID uuid.UUID,
	timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if appIsRunning(device, appUUID) {
			return true
		}
		time.Sleep(15 * time.Second)
	}
	return appIsRunning(device, appUUID)
}

// waitAppRunningWithPVCRecovery waits for the app to reach RUNNING on EVE-K,
// re-driving a wedged claim between attempts.
//
// The wedge is a Longhorn CSI create/verify race that leaves a claim Pending
// forever: it is stuck, not slow, so waiting longer never rescues it. Deleting
// the claim lets the provisioner re-drive it cleanly, which is what makes data
// volumes above roughly 256 MiB usable at all -- below that the race is rare,
// above it the wedge is the norm.
func waitAppRunningWithPVCRecovery(t Gomega, device *evetest.EdgeDevice,
	appUUID uuid.UUID, dataVolMiB uint32) {
	log := evetest.Logger()
	for round := 1; round <= pvcRecoveryRounds; round++ {
		if waitAppRunningQuietly(device, appUUID, pvcRecoveryWait) {
			logVolumeSizing(device, "app-running")
			log.Infof("app RUNNING; CDI size verdict: %q", cdiImportSizeVerdict(device))
			return
		}
		logVolumeSizing(device, fmt.Sprintf("app-not-running-round-%d", round))
		// An import CDI has rejected on size cannot be recovered by re-driving
		// the claims, so stop rather than spend the remaining rounds
		// re-confirming it.
		if verdict := cdiImportSizeVerdict(device); verdict != "" {
			t.Expect(false).To(BeTrue(),
				"CDI refuses the import and retrying cannot change it: %s", verdict)
		}
		log.Errorf("app not RUNNING after %s (round %d/%d) -- re-driving the claims",
			pvcRecoveryWait, round, pvcRecoveryRounds)
		if !recoverWedgedAppPVCs(device, dataVolMiB) {
			log.Errorf("nothing safe to recover this round")
		}
	}
	t.Expect(appIsRunning(device, appUUID)).To(BeTrue(),
		"app never reached RUNNING after %d recovery attempts (CDI size verdict: %q)",
		pvcRecoveryRounds, cdiImportSizeVerdict(device))
}

// cdiImportSizeVerdict returns CDI's own size comparison for the app's import, or
// "" when it has not made one.
//
// CDI refuses an import whose virtual image size exceeds the capacity of the
// claim it was handed, and then retries on a ~70-90 s loop indefinitely, so the
// app never reaches RUNNING. Deleting claims cannot help, since the sizes are the
// same on the next attempt, which is why this is worth reading rather than
// waiting out.
//
// Read on the success path too, deliberately: the failing runs compare one figure
// against another, but the same pair is present in runs that pass, so sampling
// only failures cannot distinguish the two outcomes.
func cdiImportSizeVerdict(device *evetest.EdgeDevice) string {
	// Run at dom0 level, NOT through runEVEScript: that wraps its script in
	// `eve exec pillar sh -c`, and the pillar container has no `eve` binary, so
	// a nested `eve exec kube` dies with "eve: not found" and the verdict comes
	// back empty -- indistinguishable from CDI having made no comparison, which
	// is the very thing this is here to tell apart.
	const script = `eve exec kube kubectl -n eve-kube-app logs ` +
		`-l cdi.kubevirt.io=cdi-upload-server --tail=400 2>/dev/null | ` +
		`grep -aoE "Virtual image size [0-9]+ is larger than the reported available storage [0-9]+" | ` +
		`tail -1`
	out, errOut, err := device.RunShellScript(script, 2*time.Minute, 0)
	if err != nil {
		evetest.Logger().Warnf("CDI size verdict unavailable: %v%s", err, errOut)
		return ""
	}
	return strings.TrimSpace(out)
}

// startCDISampler records the upload server's own view of the import while it is
// in flight, alongside the claim's requested and provisioned sizes read at the
// same moment. Returns a stop func; call it once.
//
// Sampling has to happen during the wait rather than after it. CDI removes the
// upload pod as soon as an import completes, so a run that succeeds leaves
// nothing to read afterwards, and reading later cannot distinguish "no size
// comparison was made" from "the pod is already gone".
//
// The pairing is the point: CDI rejects an import when the volume it is given is
// larger than the size it was told to expect, and a claim's provisioned size is
// only observable after Longhorn has settled it. Sampling both together shows
// what CDI saw at the moment it decided, rather than what the claim looked like
// minutes later.
func startCDISampler(device *evetest.EdgeDevice, interval time.Duration) (stop func()) {
	// UPLOAD_IMAGE_SIZE is what CDI was told to expect. The upload pod carries
	// it, the scratch claim is provisioned at exactly that figure while the
	// Longhorn destination is rounded past it, and the rejection quotes both
	// numbers -- so capture all three together rather than inferring which the
	// check compares.
	const probe = `eve exec kube kubectl -n eve-kube-app logs ` +
		`-l cdi.kubevirt.io=cdi-upload-server --tail=25 2>/dev/null | ` +
		`grep -aE "Target size|irtual image size|block volume size|New phase|Saving stream failed" ; ` +
		`eve exec kube kubectl -n eve-kube-app get pod -l cdi.kubevirt.io=cdi-upload-server ` +
		`-o yaml 2>/dev/null | grep -aA1 "name: UPLOAD_IMAGE_SIZE" | grep -a value ; ` +
		`eve exec kube kubectl -n eve-kube-app get pvc ` +
		`-o custom-columns=NAME:.metadata.name,REQ:.spec.resources.requests.storage,` +
		`PROV:.status.capacity.storage --no-headers 2>/dev/null`

	done := make(chan struct{})
	go func() {
		log := evetest.Logger()
		for n := 0; ; n++ {
			out, errOut, err := device.RunShellScript(probe, 90*time.Second, 0)
			log.Infof("[cdi:sample #%d]\n%s%s(err=%v)", n, strings.TrimSpace(out), errOut, err)
			select {
			case <-done:
				return
			case <-time.After(interval):
			}
		}
	}()
	return func() { close(done) }
}

// logVolumeSizing logs the numbers that decide whether CDI will accept the
// import, on every run rather than only on failures.
//
// A verdict alone cannot explain an outcome here. CDI removes the upload pod once
// an import succeeds, so reading its log after the app is RUNNING returns nothing
// whether or not a size comparison ever happened, and a run that passes looks
// identical to one whose log query simply arrived too late. The sizes do explain
// it: Longhorn rounds a claim up to a 2 MiB multiple, so a claim whose requested
// and provisioned sizes differ is one CDI will reject, and one where they agree is
// one it will accept. Recording both, next to the virtual and allocated size of
// the file the request was derived from, says which case a run was and why.
func logVolumeSizing(device *evetest.EdgeDevice, label string) {
	log := evetest.Logger()

	const pvc = `eve exec kube kubectl -n eve-kube-app get pvc ` +
		`-o custom-columns=NAME:.metadata.name,REQUESTED:.spec.resources.requests.storage,` +
		`PROVISIONED:.status.capacity.storage --no-headers 2>/dev/null || echo none`
	out, errOut, err := device.RunShellScript(pvc, 90*time.Second, 0)
	log.Infof("[sizing:%s] pvc requested vs provisioned:\n%s%s(err=%v)",
		label, strings.TrimSpace(out), errOut, err)

	// Virtual size is the volume's size; the allocated figure is what the file
	// occupies on /persist, which is what can push a request off a 2 MiB
	// boundary.
	const files = `set -u
for f in /persist/vault/volumes-kvm/*.raw /persist/vault/volumes/*.raw; do
  [ -f "$f" ] || continue
  echo "$f virtual=$(stat -c %s "$f") allocated=$(( $(stat -c %b "$f") * 512 ))"
done`
	fout, ferr := runEVEScript(device, files, 2*time.Minute)
	if ferr != nil {
		log.Infof("[sizing:%s] volume files unavailable: %v", label, ferr)
		return
	}
	log.Infof("[sizing:%s] volume files:\n%s", label, strings.TrimSpace(fout))
}

// recoverWedgedAppPVCs deletes Pending claims in the app namespace so the
// provisioner re-drives them, and reports whether it deleted any.
//
// It must never delete the data volume's claim or that volume's CDI scratch: the
// data volume holds what the test verifies, and EVE recreates a deleted volume
// BLANK -- the verify would then find an empty volume and the run would report a
// clean pass, a false negative wearing the clothes of a result. So the size check
// is deliberately biased towards protecting: anything within reach of the data
// volume's size is left alone, and if that is the wedged claim then no recovery
// happens and the run is allowed to fail honestly.
//
// The discriminator is size because the harness does not know the volume UUIDs
// EVE assigns. That is sound while the data volume is comfortably larger than the
// app's image claim (a few hundred MiB), which is exactly the case where recovery
// is needed. At data-volume sizes near the image size the app's own claim gets
// protected too and recovery no-ops; the classification is logged so that is
// visible rather than silent.
//
// Sizes arrive in whatever form kubectl prints, which for these claims is a plain
// byte count rather than the Gi/Mi suffixes one might expect, so every form is
// handled and anything unrecognised is protected rather than deleted. Getting
// this wrong is not a missed recovery but a destroyed volume followed by a run
// that passes because the volume came back empty.
func recoverWedgedAppPVCs(device *evetest.EdgeDevice, dataVolMiB uint32) bool {
	script := fmt.Sprintf(`set -u
DV=%d
LIST=$(eve exec kube kubectl -n eve-kube-app get pvc \
  -o custom-columns=N:.metadata.name,P:.status.phase,R:.spec.resources.requests.storage \
  --no-headers 2>/dev/null)
[ -z "$LIST" ] && { echo NO-PVCS; exit 0; }
echo "$LIST" | sed 's/^/PVC: /'
VICTIMS=$(echo "$LIST" | awk -v dv="$DV" '
  function mib(s) {
    if (s ~ /^[0-9]+$/)   { return s / 1048576 }
    if (s ~ /^[0-9]+Ki$/) { sub(/Ki$/, "", s); return s / 1024 }
    if (s ~ /^[0-9]+Mi$/) { sub(/Mi$/, "", s); return s + 0 }
    if (s ~ /^[0-9]+Gi$/) { sub(/Gi$/, "", s); return s * 1024 }
    if (s ~ /^[0-9]+Ti$/) { sub(/Ti$/, "", s); return s * 1048576 }
    return -1
  }
  $2 == "Pending" {
    v = mib($3)
    if (v < 0 || v >= dv - 32) { printf "PROTECTED %%s (%%s)\n", $1, $3; next }
    printf "VICTIM %%s (%%s)\n", $1, $3
  }')
echo "$VICTIMS"
NAMES=$(echo "$VICTIMS" | awk '$1=="VICTIM" {print $2}')
[ -z "$NAMES" ] && { echo NOTHING-TO-RECOVER; exit 0; }
for v in $NAMES; do
  echo "RECOVERING $v"
  eve exec kube kubectl -n eve-kube-app delete pvc "$v" --wait=false 2>&1 | sed 's/^/  /'
done`, dataVolMiB)
	out, errOut, err := device.RunShellScript(script, 3*time.Minute, 0)
	evetest.Logger().Errorf("[pvc-recovery]\n%s%s(err=%v)",
		strings.TrimSpace(out), errOut, err)
	return strings.Contains(out, "RECOVERING ")
}
