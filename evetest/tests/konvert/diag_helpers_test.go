// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest"
)

// Everything here is best-effort: it runs when an assertion is already about to
// fail, and must never turn a diagnosable failure into a second one. Each probe
// logs whatever it gets, including its error.

// probe is one diagnostic command and the label its output is filed under.
type probe struct {
	what   string
	script string
}

// runProbes logs each probe's output under label. Errors are logged, not
// raised.
func runProbes(device *evetest.EdgeDevice, label string, probes []probe) {
	runProbesWithTimeout(device, label, probes, eveShellTimeout)
}

// runProbesWithTimeout is runProbes for probes that need longer than a status
// read: a kubectl call against a cluster that is still coming up, or a scan of
// the whole log archive.
func runProbesWithTimeout(device *evetest.EdgeDevice, label string,
	probes []probe, timeout time.Duration) {
	log := evetest.Logger()
	log.Errorf("=== %s ===", label)
	for _, p := range probes {
		out, errOut, err := device.RunShellScript(p.script, timeout, 0)
		log.Errorf("[%s] %s:\n%s%s(err=%v)", label, p.what, out, errOut, err)
	}
}

// newlogCat emits every device log record newlogd has kept, for a grep to
// consume.
//
// This is the retrieval form the eve-device-logs procedure prescribes. Narrowing
// to collect/ finds almost nothing: newlogd moves a collect file into the
// gzipped queues once it passes 550000 bytes or a 300 s timer, so that directory
// is a ~5-minute window rather than a boot's worth of records. The -exec ... \;
// form runs one zcat per file, which keeps -f safe on the plaintext chunks and
// avoids an argument list that a device with tens of thousands of chunks
// overflows.
const newlogCat = `find /persist/newlog -name "dev.log.*" -exec zcat -f {} \; 2>/dev/null`

// newlogProbe builds a command running pipeline over that history. pipeline must
// not contain single quotes.
func newlogProbe(pipeline string) string {
	return `eve exec pillar sh -c '` + newlogCat + ` | ` + pipeline + `' || echo none`
}

// dumpConversionFailure captures why EVE marked the conversion failed. By the
// time this runs the device is back online on the unconverted partition, so it
// can still be asked directly -- which is the only window in which the resizer's
// own verdict is readable.
func dumpConversionFailure(device *evetest.EdgeDevice) {
	runProbes(device, "conversion FAILED", []probe{
		{"resize-failed.json", "cat /config/resize-failed.json 2>/dev/null || echo NONE"},
		{"resize flags", "echo repartition-inprogress=$(cat /config/repartition-inprogress 2>/dev/null); " +
			"echo resize-reboots=$(cat /config/resize-reboots 2>/dev/null)"},
		{"zboot status", "zboot status 2>&1 || true"},
		{"BaseOsStatus", "eve exec pillar sh -c 'cat /run/baseosmgr/BaseOsStatus/*.json 2>/dev/null' || echo NONE"},
		// The broker's log stream can stop minutes before the failure, and the
		// collect-info tarball is a separate transfer that can fail on its own,
		// so newlog is the only carrier of the device's own account that is
		// still readable here.
		{"baseos errors (newlog)", newlogProbe(
			`grep -aiE "baseosmgr|downloader|verifier" | grep -aiE "error|fail|refus" | tail -60`)},
		{"partitions", partsLsblk},
	})
}

// dumpAppNetwork snapshots what stands between the controller and the app: the
// port-forward rules, the app's own network status, and the node's addresses.
// Taken on both flavors so a working baseline can be diffed against a failure.
func dumpAppNetwork(device *evetest.EdgeDevice, label string) {
	runProbes(device, "app network: "+label, []probe{
		{"NAT port map", "eve exec pillar iptables -t nat -S 2>/dev/null | grep -aiE '2222|DNAT|to-destination' || echo none"},
		{"AppNetworkStatus", "eve exec pillar sh -c 'cat /run/zedrouter/AppNetworkStatus/*.json 2>/dev/null' || echo none"},
		{"addresses", "eve exec pillar ip -br addr 2>/dev/null || echo none"},
	})
}

// dumpClusterStorage captures the EVE-K storage stack when an app is stuck
// waiting for a volume: which stage is not ready, and what Longhorn and CDI
// think of the PVC.
func dumpClusterStorage(device *evetest.EdgeDevice) {
	runProbes(device, "EVE-K cluster storage", []probe{
		{"volumemgr", "eve exec pillar cat /run/volumemgr/VolumeMgrStatus/volumemgr.json 2>/dev/null || echo NONE"},
		{"storage classes", "eve exec kube kubectl get sc 2>&1 || true"},
		{"PVCs", "eve exec kube kubectl get pvc -A 2>&1 || true"},
		{"pods", "eve exec kube kubectl get pods -A 2>&1 || true"},
		{"longhorn volumes", "eve exec kube kubectl get volumes.longhorn.io -A 2>&1 || true"},
		{"persist usage", "df -h /persist 2>&1 || true"},
	})
}

// dumpRestoreState captures what early boot made of a damaged /persist: whether
// the backup was there to restore from, and what came back.
func dumpRestoreState(device *evetest.EdgeDevice) {
	runProbes(device, "identity restore", []probe{
		{"config backup", "ls -lR /config/backup-persist 2>&1 || echo NONE"},
		{"restore flag", "ls -l /config/repartition-inprogress 2>&1 || echo NONE"},
		{"uuid", "cat /persist/status/uuid 2>/dev/null || echo NONE"},
		{"certs", "ls -l /persist/certs 2>&1 || echo NONE"},
		{"checkpoint", "ls -l /persist/checkpoint 2>&1 || echo NONE"},
		{"onboarding", "eve exec pillar sh -c 'cat /persist/status/zedclient/OnboardingStatus/global.json 2>/dev/null' || echo NONE"},
		{"cipher status", "eve exec pillar sh -c 'cat /run/nim/CipherBlockStatus/*.json 2>/dev/null' || echo NONE"},
	})
}

// dumpPersistAccounting snapshots /persist sizing and usage plus Longhorn's own
// view of the node disk -- storageMaximum/Available/Scheduled/Reserved and the
// scheduling settings -- which is the accounting behind "no available disk for
// replica". The kube and Longhorn probes no-op on EVE-kvm and light up on EVE-K.
func dumpPersistAccounting(device *evetest.EdgeDevice, label string) {
	probes := []probe{
		{"df persist+submounts", `eve exec pillar sh -c 'df -B1 | awk "NR==1 || /persist/"' 2>/dev/null || echo none`},
		{"lsblk sizes+mounts", `eve exec pillar lsblk -b -o NAME,PARTLABEL,SIZE,FSTYPE,MOUNTPOINT 2>/dev/null || echo none`},
		{"du -d1 /persist", `eve exec pillar sh -c 'du -x -B1 -d1 /persist 2>/dev/null | sort -rn' || echo none`},
		// status: is load-bearing, not noise: the disk-level Schedulable
		// condition is what gates cluster storage, and the NODE column the next
		// probe prints stays True while a disk is unschedulable.
		{"longhorn node disk accounting", `eve exec kube kubectl -n longhorn-system get nodes.longhorn.io -o yaml 2>/dev/null | grep -aE "name:|path:|storageMaximum|storageAvailable|storageScheduled|storageReserved|allowScheduling|diskUUID|type:|status:|reason:|message:" || echo none`},
		{"longhorn node -o wide", `eve exec kube kubectl -n longhorn-system get nodes.longhorn.io -o wide 2>/dev/null || echo none`},
		{"longhorn storage settings", `eve exec kube kubectl -n longhorn-system get settings.longhorn.io -o custom-columns=NAME:.metadata.name,VALUE:.value 2>/dev/null | grep -aiE "NAME|reserved|over-provisioning|minimal-available|soft-anti-affinity" || echo none`},
		{"eve-kube-app pvc (requested sizes)", `eve exec kube kubectl -n eve-kube-app get pvc 2>/dev/null || echo none`},
	}
	// The same pre-flight the conversion runs to decide. When it declines, the
	// controller carries only the one-line reason ("persist is too full to free
	// the needed space"); the JSON carries the numbers behind it -- needed,
	// target and used bytes, the resize2fs floor estimate and the fullness
	// policy -- which is the difference between knowing that it declined and
	// knowing why.
	if disk, err := bootDiskPath(device); err == nil {
		probes = append(probes, probe{"storage-resizer check (conversion pre-flight)",
			"eve exec pillar /usr/bin/storage-resizer check --disk " + disk + " --json 2>&1 || echo none"})
	}
	runProbesWithTimeout(device, "/persist accounting: "+label, probes, time.Minute)
}

// startPersistSampler runs dumpPersistAccounting every interval so /persist and
// Longhorn's disk accounting can be watched evolving while k3s, Longhorn and CDI
// start after the conversion. Returns a stop func; call it once.
func startPersistSampler(device *evetest.EdgeDevice, interval time.Duration) (stop func()) {
	done := make(chan struct{})
	go func() {
		// Bounded only so a wedged run does not sample forever. The
		// cluster-storage wait alone is an hour, and at 13 samples the series
		// stopped ten minutes in, leaving the rest of every "storage never
		// became ready" failure unobserved -- the window that explains it.
		for n := 0; n < 90; n++ {
			dumpPersistAccounting(device, fmt.Sprintf("post-conversion startup sample #%d", n))
			select {
			case <-done:
				return
			case <-time.After(interval):
			}
		}
	}()
	return func() { close(done) }
}

// dumpAppPVCWedge characterizes the EVE-K app-volume wedge that leaves an app
// stuck waiting for storage: the claim and upload-pod state, what Longhorn and
// CDI made of them, and whether the recovery engaged.
func dumpAppPVCWedge(device *evetest.EdgeDevice) {
	runProbesWithTimeout(device, "EVE-K app-volume wedge", []probe{
		{"eve-kube-app pvc+pods -o wide", `eve exec kube kubectl -n eve-kube-app get pvc,pods -o wide 2>/dev/null || echo none`},
		{"describe pvc", `eve exec kube kubectl -n eve-kube-app describe pvc 2>/dev/null || echo none`},
		{"describe pods", `eve exec kube kubectl -n eve-kube-app describe pods 2>/dev/null || echo none`},
		{"longhorn volumes", `eve exec kube kubectl get volumes.longhorn.io -A -o wide 2>/dev/null || echo none`},
		{"volumeattachments", `eve exec kube kubectl get volumeattachments 2>/dev/null || echo none`},
		{"csi-provisioner log", `eve exec kube kubectl -n longhorn-system logs deployment/csi-provisioner -c csi-provisioner --tail=250 2>/dev/null || echo none`},
		{"longhorn-manager log", `eve exec kube kubectl -n longhorn-system logs -l app=longhorn-manager -c longhorn-manager --tail=250 --prefix 2>/dev/null || echo none`},
		{"longhorn StorageClass", `eve exec kube kubectl get sc longhorn -o yaml 2>/dev/null || echo none`},
		{"longhorn version", `eve exec kube kubectl -n longhorn-system get ds longhorn-manager -o wide 2>/dev/null || echo none`},
		{"CDI controller log", `eve exec kube kubectl -n cdi logs deployment/cdi-deployment --tail=60 2>/dev/null || echo none`},
		// The upload SERVER, not the controller: this is the process that
		// receives the transfer, and the one observed Ready and idle while the
		// upload never completes. --previous as well as the live log, because a
		// pod that reported Succeeded is gone by the time this runs and its own
		// account of the transfer would be lost with it.
		{"CDI upload-server pod log", `eve exec kube kubectl -n eve-kube-app logs -l cdi.kubevirt.io=cdi-upload-server --tail=120 --prefix 2>/dev/null; eve exec kube kubectl -n eve-kube-app logs -l cdi.kubevirt.io=cdi-upload-server --tail=120 --prefix --previous 2>/dev/null; echo "--- end upload-server logs"`},
		// Warning events outlive the pods that caused them, so an attach
		// failure still shows up after the upload pod has terminated. The
		// observed end state is a Bound claim whose Longhorn volume is
		// detached, which no pod-scoped probe explains.
		{"eve-kube-app warning events", `eve exec kube kubectl -n eve-kube-app get events --field-selector type=Warning --sort-by=.lastTimestamp 2>/dev/null | tail -40 || echo none`},
		{"longhorn-system warning events", `eve exec kube kubectl -n longhorn-system get events --field-selector type=Warning --sort-by=.lastTimestamp 2>/dev/null | tail -30 || echo none`},
		// How far the transfer got: stuck at 0% means it never started
		// (proxy/route), stuck partway means it began and stalled.
		{"CDI upload progress annotations", `eve exec kube kubectl -n eve-kube-app get pvc -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,PROGRESS:'.metadata.annotations.cdi\.kubevirt\.io/storage\.pod\.progress',PODPHASE:'.metadata.annotations.cdi\.kubevirt\.io/storage\.pod\.phase',RUNNING:'.metadata.annotations.cdi\.kubevirt\.io/storage\.condition\.running' 2>/dev/null || echo none`},
		{"longhorn volume detail", `eve exec kube kubectl -n longhorn-system get volumes.longhorn.io -o custom-columns=NAME:.metadata.name,STATE:.status.state,ROBUST:.status.robustness,NODE:.status.currentNodeID,SIZE:.spec.size 2>/dev/null || echo none`},
		// A wedged import re-drives the rollout for tens of minutes, so a short
		// window comes back full of retry noise and crowds out the one line that
		// says whether the recovery below ran -- and an absent line then cannot
		// be told from a truncated one.
		{"volumemgr rollout (newlog)", newlogProbe(`grep -aiE "RolloutDiskToPVC|retryFailedClusterVolumeCreate|terminating:true|local-path" | tail -200`)},
		{"PVC recovery actions taken", newlogProbe(`grep -aiE "deleted wedged scratch PVC|could not delete wedged scratch|deleted wedged target PVC" | tail -40`)},
		{"kubevirt vmi -A", `eve exec kube kubectl get vmi -A -o wide 2>/dev/null || echo none`},
	}, 90*time.Second)
}

// dumpResizeEvidence records whether the offline resize was actually interrupted,
// which is the premise of the app-volume test and is otherwise invisible: a clean
// conversion and a fault-injected one that happened to converge look identical
// from the harness side.
//
// The resize attempt counter on the CONFIG partition is not usable for this:
// storage-resize.sh deletes it on the success path, so once the conversion has
// finished it always reads empty regardless of how many attempts it took. The
// durable evidence is what EVE recorded about why it rebooted -- a watchdog reset
// is reported as its own boot reason -- plus whatever the resizer left in the log.
func dumpResizeEvidence(device *evetest.EdgeDevice) {
	runProbesWithTimeout(device, "offline-resize fault evidence", []probe{
		{"boot / reboot reasons", `for f in /persist/boot-reason /persist/reboot-reason /persist/status/boot-reason /persist/status/reboot-reason /persist/log/reboot-reason.log; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done 2>/dev/null || echo NONE`},
		{"watchdog boot reason in logs", newlogProbe(`grep -ahoE "BootReason[A-Za-z]+" | sort | uniq -c | sort -rn | head`)},
		{"resize-failed.json", `cat /config/resize-failed.json 2>/dev/null || echo NONE`},
		{"watchdog device", `[ -c /dev/watchdog ] && echo PRESENT || echo MISSING; wdctl /dev/watchdog 2>&1 | head -8`},
		{"resizer/watchdog log lines", newlogProbe(`grep -ahiE "run-watchdog|storage-resizer|resize did not converge|watchdog" | tail -30`)},
	}, time.Minute)
}

// dumpLostFound records what an e2fsck repair moved into /persist/lost+found --
// inode numbers, sizes, modes and the space held.
//
// Each interrupted shrink reboots the device and storage-init fscks /persist
// again, so a structural repair there is a candidate cause of damage to a volume
// under test. The serial console reports such a repair only as inode numbers, and
// by the time the console is read the device is gone, so this is the one reading
// that ties those numbers to a size and a mode. Nothing reclaims the space
// either, which is why the total is worth a line of its own. Taken before and
// after the conversion, so residue can be attributed to it.
func dumpLostFound(device *evetest.EdgeDevice, when string) {
	// du before ls: on a repair that reconnected a large subtree the listing is
	// long, and the total is the number worth having even if it is truncated.
	// ls -i because the console names what e2fsck reconnected only by inode
	// number, and nothing on the device resolves those afterwards.
	const script = `set -u
echo "--- total"
du -sh /persist/lost+found 2>/dev/null || echo NONE
echo "--- per-entry (largest first)"
du -sh /persist/lost+found/* 2>/dev/null | sort -rh | head -20 || true
echo "--- ls -li"
ls -li /persist/lost+found 2>/dev/null | head -40 || true
`
	log := evetest.Logger()
	out, err := runEVEScript(device, script, 90*time.Second)
	if err != nil {
		log.Infof("[lost+found:%s] capture failed: %v\n%s", when, err, strings.TrimSpace(out))
		return
	}
	log.Infof("[lost+found:%s]\n%s", when, strings.TrimSpace(out))
}

// dumpVolumeManifest reports whether the post-resize volume-manifest check ran
// and what it concluded -- whether it found the pre-shrink hashes, judged any
// volume torn, and removed it. This is what separates "the shrink left the volume
// alone" from "the detector cleaned up after it".
func dumpVolumeManifest(device *evetest.EdgeDevice) {
	runProbesWithTimeout(device, "volume manifest (post-resize detect+recreate)", []probe{
		{"manifest files on /persist", `eve exec pillar sh -c 'ls -l /persist/vault/volumes/.sha256 /persist/clear/volumes/.sha256 2>&1'`},
		{"volmanifest / recreate signatures (newlog)", newlogProbe(`grep -ahiE "volmanifest|recreateCorruptVolumes|verifyVolumes|torn by the resize" | tail -40`)},
		{"app volume files", `eve exec pillar sh -c 'ls -l /persist/vault/volumes /persist/clear/volumes 2>&1'`},
	}, time.Minute)
}

// logPartitionState records what EVE reports for each base image, so a run that
// did not commit its target, or reverted it, is visible after the fact.
func logPartitionState(device *evetest.EdgeDevice) {
	log := evetest.Logger()
	info := device.GetDeviceInfo()
	if info == nil {
		log.Errorf("[partition-state] no device info")
		return
	}
	for _, sw := range info.GetSwList() {
		log.Errorf("[partition-state] %s partition=%s status=%s %s",
			sw.GetShortVersion(), sw.GetPartitionState(), sw.GetUserStatus(),
			sw.GetSubStatusStr())
	}
}
