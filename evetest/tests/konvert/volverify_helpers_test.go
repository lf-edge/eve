// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/evetest"
)

// volverify (evetest/testapps/volverify) writes a deterministic self-describing
// pattern into an app's data volume and later judges what is still there. Each
// block carries its own logical identity and checksum, and a seeded
// create/delete op stream with a committed index on the volume makes an
// interrupted write distinguishable from lost data -- which is what lets a
// verdict say whether the conversion damaged the data rather than only whether
// the app came back.
const (
	// seedParamKey and opsParamKey shape the op stream. The writer stops early
	// once the volume fills and reports the committed high-water mark, which the
	// verify is then held to.
	seedParamKey = "VOLVERIFY_SEED"
	opsParamKey  = "VOLVERIFY_OPS"
	// volverifyImageParamKey is the repo the app image is pulled from.
	volverifyImageParamKey = "VOLVERIFY_IMAGE"
	// devsideOnlyParamKey stops a run once the volume verdict is taken.
	devsideOnlyParamKey = "DEVSIDE_ONLY"

	defaultVolverifySeed = uint64(20260723)
	defaultVolverifyOps  = uint64(200000)

	// defaultVolverifyImage is where the app is currently published.
	// lfedge/evetest-volverify exists but carries no tag yet; point
	// VOLVERIFY_IMAGE at it once the app is published there.
	defaultVolverifyImage = "eriknordmark/evetest-volverify"
	volverifyImageTag     = "1.2"

	// volverifyBlockSize is the on-disk block size of the pattern; it must be
	// identical for the write and the verify, which replay the same stream.
	volverifyBlockSize = 4096

	// volverifyCommitDir is the on-volume committed-index directory. Its
	// presence identifies the data volume among the guest's block devices after
	// the conversion, when the volume is no longer mounted at its MountDir.
	volverifyCommitDir = ".vv-commit"
)

// Outcomes of locating the app's data volume after the conversion.
const (
	volumeStatePattern = "PATTERN" // mounted and still carrying the pattern
	volumeStateBlank   = "BLANK"   // the volume exists but the pattern is gone
)

// addVolverifyApp adds the volverify app with a data volume mounted at
// dataMountDir, on a switch network instance for the reason addTestApp gives.
func addVolverifyApp(devConfig *evetest.EdgeDeviceConfig, displayName, image string,
	niUUID, dataVolUUID uuid.UUID) uuid.UUID {
	appConfig := testAppConfig(displayName, niUUID)
	appConfig.Image = evetest.DockerContainer{ImageName: image, Tag: volverifyImageTag}
	appConfig.Mounts = []evetest.MountConfig{
		{VolumeUUID: dataVolUUID, MountDir: dataMountDir},
	}
	return devConfig.AddApplication(appConfig)
}

// volverifyArgs is the argument string both the write and the verify are driven
// with; replaying the same stream is what makes the two comparable.
func volverifyArgs(dataVolMiB uint32, seed, ops uint64) string {
	return fmt.Sprintf("--dir %s --seed %d --ops %d --block-size %d --max-blocks %d",
		dataMountDir, seed, ops, volverifyBlockSize, volverifyMaxBlocks(dataVolMiB))
}

// volverifyMaxBlocks caps a single file at a sixteenth of the volume.
// volverify's own large-file bound is 256 MiB, which on a small volume would let
// one op consume the whole thing and leave the pattern with almost no files to
// place -- and so almost no coverage of the relocated block range.
func volverifyMaxBlocks(dataVolMiB uint32) uint64 {
	maxBlocks := uint64(dataVolMiB) * evetest.MiB / 16 / volverifyBlockSize
	if maxBlocks < 256 {
		maxBlocks = 256
	}
	return maxBlocks
}

// volverifyParameterDefinitions declares the pattern's axes.
func volverifyParameterDefinitions() []evetest.TestParameterDefinition {
	return []evetest.TestParameterDefinition{
		{
			Key:          seedParamKey,
			DefaultValue: defaultVolverifySeed,
			Description: evetest.TestParameterDescription{
				Summary: "volverify master seed for the fill/delete pattern",
				Default: "20260723",
			},
		},
		{
			Key:          opsParamKey,
			DefaultValue: defaultVolverifyOps,
			Description: evetest.TestParameterDescription{
				Summary: "volverify op count; the writer stops early once the volume fills",
				Default: "200000",
			},
		},
		{
			Key:          volverifyImageParamKey,
			DefaultValue: defaultVolverifyImage,
			Description: evetest.TestParameterDescription{
				Summary: "Docker repo of the volverify test app",
				// A literal: cmd/list-tests parses this out of the AST and
				// cannot resolve a constant.
				Default: "eriknordmark/evetest-volverify",
			},
		},
	}
}

// writeVolverifyPattern fills the app's data volume with the pattern and returns
// the committed op index the writer reached. It requires the volume to be mounted
// at its MountDir, which the runx shim does on EVE-kvm.
func writeVolverifyPattern(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	args string) int {
	script := fmt.Sprintf(
		"grep -q ' %s ' /proc/mounts || { echo NOT-MOUNTED; cat /proc/mounts; exit 1; }; "+
			"volverify write %s && sync", dataMountDir, args)
	committed := -1
	t.Eventually(func(g Gomega) {
		stdout, stderr, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			script, 60*time.Minute, 0)
		g.Expect(err).NotTo(HaveOccurred(), "volverify write failed:\n%s%s", stdout, stderr)
		committed = reportField(stdout, "committed")
		g.Expect(committed).To(BeNumerically(">=", 0),
			"volverify write reported no committed index:\n%s", stdout)
	}, 65*time.Minute, 10*time.Second).Should(Succeed())
	return committed
}

// verifyVolverifyPattern replays the pattern against the volume and returns the
// report. volverify exits non-zero on a dirty report, so the exit status is not an
// assertion failure here -- the caller classifies the report instead.
func verifyVolverifyPattern(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	args string, expectCommitted int) string {
	cmd := fmt.Sprintf("volverify verify %s --expect-committed %d", args, expectCommitted)
	var report string
	t.Eventually(func(g Gomega) {
		stdout, _, _ := device.RunShellScriptInsideApp(appUUID, appAuth, cmd,
			30*time.Minute, 0)
		g.Expect(stdout).NotTo(BeEmpty(), "volverify verify produced no output")
		report = strings.TrimSpace(stdout)
	}, 32*time.Minute, 10*time.Second).Should(Succeed())
	return report
}

// reportField extracts an integer "key=N" field from a volverify summary line,
// returning -1 when the field is absent or unparsable.
func reportField(report, key string) int {
	for _, tok := range strings.Fields(report) {
		if !strings.HasPrefix(tok, key+"=") {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(strings.TrimPrefix(tok, key+"="), "%d", &n); err != nil {
			return -1
		}
		return n
	}
	return -1
}

// volverifySummary pulls volverify's one-line tally out of the device-side output
// so an outcome record carries the counts rather than the whole transcript.
func volverifySummary(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "committed=") && strings.Contains(line, "ok=") {
			return strings.TrimSpace(line)
		}
	}
	return "no-summary"
}

// devsideVerifyScript locates the carried-over volume on the device and hands it
// to the verdict script the volverify app ships
// (testapps/volverify/scripts/devside-verify.sh), which is also runnable by hand
// inside the app during a stuck upgrade.
//
// The conversion moves the pre-conversion app volumes out of the directory
// Longhorn must own on EVE-K into a kvm sibling, and volumemgr rolls them into
// claims lazily once the cluster is up. In between, and for as long as that
// import keeps failing, the file sits there as a plain ext4 image holding the
// volume exactly as the shrink left it: the data-volume path returns on a failed
// rollout without removing the source, so a wedged import preserves it rather
// than consuming it.
//
// Neither the verdict script nor volverify has to be shipped in: containerd has
// already unpacked the app image, so the pair the app would run is on disk. Args:
// seed, ops, max-blocks, expect-committed.
const devsideVerifyScript = `set -u
# Both artifacts appear on their own schedule after the conversion: containerd unpacks
# the app image, and the post-vault phase of upgradeconverter moves the volumes. The
# device reports itself on the target before either is guaranteed, so wait for both
# together -- checking one first and exiting early skips the wait on the other.
# Encrypted volumes land in vault/volumes-kvm; clear ones stay in clear/volumes.
S=""
F=""
i=0
while [ "$i" -lt 60 ]; do
  [ -n "$S" ] || S=$(find /persist/vault/containerd -path '*usr/local/bin/devside-verify.sh' 2>/dev/null | head -1)
  # A *.raw.corrupt is EVE's post-resize hash check having caught the interrupted
  # shrink tearing this volume, quarantined instead of deleted (see the marker the
  # caller drops before the conversion). That IS the finding, not a missing volume:
  # verify it exactly like an intact one, so fsck and volverify can say whether the
  # damage is structurally visible or silent. Quarantined copies are therefore
  # listed first -- picking an intact sibling ahead of one would report a clean
  # verdict for a conversion already caught tearing a volume.
  [ -n "$F" ] || F=$(ls /persist/vault/volumes-kvm/*.raw.corrupt /persist/clear/volumes/*.raw.corrupt \
      /persist/vault/volumes-kvm/*.raw /persist/clear/volumes/*.raw \
      2>/dev/null | head -1)
  [ -n "$S" ] && [ -n "$F" ] && break
  i=$((i + 1)); sleep 10
done
echo "DEVSIDE-WAITED=${i}0s"
# Giving up is only actionable with the layout that defeated the search: an 8 GiB run
# put ~8 GiB somewhere under /persist/vault inside the wait window, yet matched nothing
# here, and du -d1 could not say where. List the candidates so the next occurrence
# reports the actual path instead of only that it is not the expected one.
if [ -z "$S" ] || [ -z "$F" ]; then
  echo "DEVSIDE-LAYOUT:"
  for d in /persist/vault/volumes-kvm /persist/vault/volumes /persist/clear/volumes; do
    echo "  $d:"
    ls -l "$d" 2>&1
  done
  echo "  largest under /persist/vault:"
  du -x -B1 -d2 /persist/vault 2>/dev/null | sort -rn | head -12
fi
[ -n "$S" ] || { echo "DEVSIDE=no-devside-verify"; exit 0; }
[ -n "$F" ] || { echo "DEVSIDE=no-relocated-volume"; exit 0; }
echo "DEVSIDE-FILE=$F size=$(stat -c %s "$F")"
# Whether the selection above had a choice at all: >1 means head -1 discarded a
# candidate and the verdict may describe the wrong volume.
echo "DEVSIDE-CANDIDATES=$(ls /persist/vault/volumes-kvm/*.raw.corrupt \
    /persist/clear/volumes/*.raw.corrupt /persist/vault/volumes-kvm/*.raw \
    /persist/clear/volumes/*.raw 2>/dev/null | wc -l)"
sh "$S" "$F" "$1" "$2" "$3" "$4"`

// assertRelocatedVolumeIntact takes the volume verdict without involving the app,
// Longhorn, the claim or a completed import -- see devsideVerifyScript.
//
// Not finding anything to check is non-fatal ONLY when the app-side verdict is
// still to come: on a clear-volume or ZFS layout the file may not be where this
// looks. Under DEVSIDE_ONLY there is no second verdict, so the same silence means
// the iteration measured nothing -- and a run that measures nothing must not
// report PASS, or a soak banks clean-looking rows that never examined a volume. A
// volume it does read and find corrupt fails the run either way; that is the
// finding being hunted.
func assertRelocatedVolumeIntact(t Gomega, device *evetest.EdgeDevice, dataVolMiB uint32,
	seed, ops uint64, expectCommitted int) {
	log := evetest.Logger()
	out, err := runEVEScript(device, devsideVerifyScript, 15*time.Minute,
		fmt.Sprintf("%d", seed), fmt.Sprintf("%d", ops),
		fmt.Sprintf("%d", volverifyMaxBlocks(dataVolMiB)),
		fmt.Sprintf("%d", expectCommitted))
	if err != nil {
		log.Errorf("device-side volume verify could not run:\n%s", out)
		return
	}
	log.Infof("device-side volume verify:\n%s", strings.TrimSpace(out))

	if i := strings.Index(out, "DEVSIDE="); i >= 0 {
		var reason string
		_, _ = fmt.Sscanf(out[i:], "DEVSIDE=%s", &reason)
		log.Errorf("device-side volume verify skipped: %s", reason)
		// The volume was present and written before the conversion, so its
		// absence afterwards is upgradeconverter's account to give: it logs
		// what it relocated and skipped per run, plus a line for each entry it
		// declined to move. Without this the layout dump can only say the
		// volume is not there, not whether it was moved elsewhere, skipped, or
		// never seen.
		runProbesWithTimeout(device, "device-side verify found nothing", []probe{
			{"upgradeconverter volume relocation", newlogProbe("grep -a stageKvmVolumes | tail -20")},
			{"upgradeconverter kube entry", newlogProbe("grep -a relocateKvmVolumesForKube | tail -10")},
			// The relocation reports moving everything it finds, so the volume
			// is already gone when it runs. Grep for the file itself rather
			// than any one agent's wording: whoever removed it had to name it.
			{"every mention of a volume file", newlogProbe(`grep -a "#0.raw" | tail -40`)},
			{"volumemgr delete path", newlogProbe(`grep -a volumemgr | grep -aiE "delete|destroy|purge|remov" | tail -30`)},
		}, 90*time.Second)
		t.Expect(evetest.GetTestParameter[bool](devsideOnlyParamKey)).To(BeFalse(),
			"a DEVSIDE_ONLY run banked no volume verdict (%s): this iteration "+
				"measured nothing about shrink corruption:\n%s", reason, out)
		return
	}

	fsckRC, verifyRC := -1, -1
	if i := strings.Index(out, "DEVSIDE-FSCK-RC="); i >= 0 {
		_, _ = fmt.Sscanf(out[i:], "DEVSIDE-FSCK-RC=%d", &fsckRC)
	}
	if i := strings.Index(out, "DEVSIDE-VERIFY-RC="); i >= 0 {
		_, _ = fmt.Sscanf(out[i:], "DEVSIDE-VERIFY-RC=%d", &verifyRC)
	}
	// eve-detected records whether EVE's own post-resize hash check had already
	// condemned this volume, in which case the file handed over is the
	// quarantined copy. A clean volverify on such a file would mean the two
	// checks disagree, so the distinction has to survive into the row rather
	// than being inferred from a path.
	eveDetected := strings.Contains(out, ".raw"+".corrupt")
	log.Infof("[DEVICE-VOLUME-OUTCOME] datavolMiB=%d app-independent=true "+
		"eve-detected-corrupt=%t fsck-rc=%d structural-damage=%t verify-rc=%d verify=[%s]",
		dataVolMiB, eveDetected, fsckRC, fsckFoundStructuralDamage(out), verifyRC,
		volverifySummary(out))
	evetest.Checkpoint("devside-volume-verified")

	// volverify exits non-zero on ANY anomaly, so its status is the catch-all: a
	// verdict class not named individually below still fails the run.
	t.Expect(verifyRC).To(BeNumerically("==", 0),
		"volverify rejected the relocated volume (DEVSIDE-VERIFY-RC=%d):\n%s", verifyRC, out)

	presentCorrupt := reportField(out, "present-corrupt")
	// An absent field reads as -1, which would satisfy the bound below and bank
	// a clean-looking row for a run that measured nothing.
	t.Expect(presentCorrupt).To(BeNumerically(">=", 0),
		"volverify produced no present-corrupt count, so this iteration measured "+
			"nothing about shrink corruption:\n%s", out)
	t.Expect(presentCorrupt).To(BeNumerically("<=", 0),
		"the relocated pre-conversion volume is present but CORRUPT "+
			"(present-corrupt=%d) -- the interrupted shrink tore data the filesystem "+
			"check cannot see:\n%s", presentCorrupt, out)
	// Losing a committed file outright, or resurrecting a committed-deleted one,
	// is data loss just as much as torn content. Orphaned is excluded: recovery
	// into lost+found self-heals to a blank or content-tree recreate.
	for _, key := range []string{"lost", "resurrected"} {
		n := reportField(out, key)
		t.Expect(n).To(BeNumerically("<=", 0),
			"the relocated pre-conversion volume lost committed data (%s=%d):\n%s",
			key, n, out)
	}
}

// logVolumeOutcome emits one line pairing what the filesystem check concluded
// with what the content verify found, which is the row a soak accumulates over
// many iterations. Read on its own either verdict is ambiguous; together they say
// whether corruption occurred and whether a structural check would have noticed.
//
// The line is deliberately single and grep-friendly, since the point is to
// compare hundreds of these rather than to read one.
func logVolumeOutcome(dataVolMiB uint32, state string, fsckRC int, report, fsckOut string,
	replayRC int, replayOut string) {
	// Before the journal is replayed, count mismatches are expected and mean
	// nothing; after it, anything found is real.
	dirty := fmt.Sprintf("rc=%d", fsckRC)
	switch fsckRC {
	case 0:
		dirty += "(clean)"
	case 4:
		dirty += "(errors-unreplayed)"
	}
	if strings.Contains(fsckOut, "skipping journal recovery") {
		dirty += "+journal-not-replayed"
	}
	replayed := "not-run"
	if replayRC >= 0 {
		replayed = fmt.Sprintf("rc=%d", replayRC)
		switch replayRC {
		case 0:
			replayed += "(clean)"
		case 1, 2:
			// A non-zero status is not by itself damage. A volume captured
			// while it was still being written to has stale superblock
			// counters, an orphan flag and extent trees e2fsck would rather
			// rewrite, and it repairs all of those on every run while saying
			// nothing about the data. Only findings that imply lost, crossed or
			// unreachable blocks mean the interrupted shrink actually hurt it.
			if fsckFoundStructuralDamage(replayOut) {
				replayed += "(STRUCTURAL-DAMAGE)"
			} else {
				replayed += "(accounting-only)"
			}
		case 4:
			replayed += "(errors-left)"
		}
		if strings.Contains(replayOut, "FILE SYSTEM WAS MODIFIED") {
			replayed += "+modified"
		}
	}
	if report == "" {
		report = "no-content-verify"
	}
	evetest.Logger().Errorf(
		"[VOLUME-OUTCOME] datavolMiB=%d state=%s fsck-dirty=%s fsck-replayed=%s verify=[%s]",
		dataVolMiB, state, dirty, replayed, strings.ReplaceAll(report, "\n", " | "))
}

// fsckDataVolume runs a read-only filesystem check on the data volume's block
// device and returns e2fsck's exit status and output.
//
// This is the counterpart to the content verify, and the pair is the point: a
// structural check is blind to data blocks that were relocated wrongly but left
// self-consistent, so the interesting result is fsck reporting a clean filesystem
// while the content verify finds files quietly full of zeroes. Recording only one
// of the two would lose exactly that comparison.
//
// It must run before anything mounts the volume -- a mount can replay the journal
// and repair the very damage being measured -- and with -n so the check itself
// changes nothing. Exit status 0 means a clean filesystem; 4 means errors it was
// not allowed to fix.
func fsckDataVolume(device *evetest.EdgeDevice, appUUID uuid.UUID, dev string) (int, string) {
	script := fmt.Sprintf("e2fsck -fn %s 2>&1; echo FSCK_RC=$?", dev)
	out, _, _ := device.RunShellScriptInsideApp(appUUID, appAuth, script, 20*time.Minute, 0)
	rc := -1
	if i := strings.Index(out, "FSCK_RC="); i >= 0 {
		_, _ = fmt.Sscanf(out[i:], "FSCK_RC=%d", &rc)
	}
	evetest.Logger().Errorf("[fsck] %s exit=%d\n%s", dev, rc, strings.TrimSpace(out))
	return rc, strings.TrimSpace(out)
}

// fsckDataVolumeAfterVerify unmounts the volume and checks it again, this time
// letting e2fsck replay the journal and repair what it finds.
//
// The read-only check taken before the mount cannot distinguish real damage from
// bookkeeping: the volume was never cleanly unmounted, so its journal is
// unreplayed and the superblock's free counts necessarily disagree with the disk.
// That check therefore reports errors on every run and says nothing on its own.
// Replaying first removes that noise, so whatever is still wrong here is genuine
// -- at the cost of modifying the filesystem, which is why it runs only after the
// content verify has already been recorded.
//
// Exit 0 means clean once the journal was applied; 1 means e2fsck found and fixed
// real structural damage.
func fsckDataVolumeAfterVerify(device *evetest.EdgeDevice, appUUID uuid.UUID,
	dev, mountDir string) (int, string) {
	script := fmt.Sprintf(
		"umount %s 2>/dev/null; e2fsck -fy %s 2>&1; echo FSCK_RC=$?", mountDir, dev)
	out, _, _ := device.RunShellScriptInsideApp(appUUID, appAuth, script, 20*time.Minute, 0)
	rc := -1
	if i := strings.Index(out, "FSCK_RC="); i >= 0 {
		_, _ = fmt.Sscanf(out[i:], "FSCK_RC=%d", &rc)
	}
	evetest.Logger().Errorf("[fsck-replayed] %s exit=%d\n%s", dev, rc, strings.TrimSpace(out))
	return rc, strings.TrimSpace(out)
}

// fsckFoundStructuralDamage reports whether an e2fsck transcript contains
// findings that mean blocks or inodes were actually lost, crossed or orphaned --
// as opposed to the accounting an unclean capture always produces.
//
// Repairing stale free-block and free-inode counters, clearing the orphan-file
// feature flag and narrowing extent trees all happen on a volume that was simply
// snapshotted mid-write; treating those as damage would mark every iteration of a
// soak as a hit and bury the real signal. The patterns below are the ones that
// imply data actually went missing.
func fsckFoundStructuralDamage(out string) bool {
	damage := []string{
		"Unattached inode",
		"Unattached zero-length inode",
		"multiply-claimed",
		"Multiply-claimed",
		"illegal block",
		"Illegal block",
		"illegal indirect block",
		"lost+found",
		"Inode bitmap differences",
		"Block bitmap differences",
		"Directory inode",
		"has an incorrect filesize",
		"Entry '",
		"deleted/unused inode",
		"root inode is not a directory",
		"Corrupt",
		"corrupted",
	}
	for _, d := range damage {
		if strings.Contains(out, d) {
			return true
		}
	}
	return false
}

// findDataVolumeDevice returns the guest block device holding the app's data
// volume, identified by size rather than by mounting anything, so the caller can
// check the filesystem before it is touched. The app's own root disk differs in
// size by orders of magnitude, so a size match is unambiguous here.
func findDataVolumeDevice(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	dataVolMiB uint32) string {
	script := fmt.Sprintf(`set -u
WANT=%d
for d in /dev/vd[b-z] /dev/sd[b-z]; do
  [ -b "$d" ] || continue
  sz=$(blockdev --getsize64 "$d" 2>/dev/null) || continue
  mib=$(( sz / 1048576 ))
  echo "CAND $d ${mib}MiB"
  diff=$(( mib - WANT )); [ "$diff" -lt 0 ] && diff=$(( -diff ))
  [ "$diff" -le 128 ] && { echo "DEV=$d"; break; }
done`, dataVolMiB)
	var dev string
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth, script,
			2*time.Minute, 0)
		g.Expect(err).NotTo(HaveOccurred(), "listing guest block devices failed:\n%s", out)
		for _, tok := range strings.Fields(out) {
			if d, ok := strings.CutPrefix(tok, "DEV="); ok {
				dev = d
			}
		}
		g.Expect(dev).NotTo(BeEmpty(),
			"no guest block device close to %d MiB -- the data volume is not attached:\n%s",
			dataVolMiB, out)
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
	evetest.Logger().Infof("data volume device: %s", dev)
	return dev
}

// mountDataVolumeRO finds the app's data volume among the guest's block devices
// and mounts it at mountDir, returning which state it is in. EVE-K does not
// auto-mount a container app's data volume at its MountDir (lf-edge/eve#6145), so
// after the conversion the verify has to do it; volverify's committed-index
// directory is what identifies the volume.
//
// The mount is read-only and skips the ext4 journal: the verify only reads, and
// replaying the journal would heal exactly the torn state being measured.
//
// A volume that holds no pattern is reported as BLANK rather than as a failure --
// that is what the caller sees when the post-resize manifest check removed a torn
// volume and EVE recreated it empty. Only finding no data volume at all is an
// error, so the block-device inventory is dumped either way.
func mountDataVolumeRO(t Gomega, device *evetest.EdgeDevice, appUUID uuid.UUID,
	mountDir string) string {
	script := fmt.Sprintf(`set -u
mkdir -p %[1]s
[ -d %[1]s/%[2]s ] && { echo STATE=%[3]s already-mounted; exit 0; }
mountpoint -q %[1]s && umount %[1]s
found=
for d in /dev/vd[b-z] /dev/sd[b-z]; do
  [ -b "$d" ] || continue
  found="$found $d"
  mount -o ro,noload -t ext4 "$d" %[1]s 2>/dev/null || continue
  if [ -d %[1]s/%[2]s ]; then echo "STATE=%[3]s $d"; exit 0; fi
  umount %[1]s
done
echo "candidates:$found"
lsblk 2>/dev/null; blkid 2>/dev/null; cat /proc/mounts
[ -n "$found" ] && { echo STATE=%[4]s; exit 0; }
echo STATE=NO-DATA-DEVICE
exit 1`, mountDir, volverifyCommitDir, volumeStatePattern, volumeStateBlank)
	state := ""
	t.Eventually(func(g Gomega) {
		stdout, stderr, err := device.RunShellScriptInsideApp(appUUID, appAuth, script,
			2*time.Minute, 0)
		g.Expect(err).NotTo(HaveOccurred(),
			"no data volume among the guest block devices after the conversion:\n%s%s",
			stdout, stderr)
		for _, tok := range strings.Fields(stdout) {
			if s, ok := strings.CutPrefix(tok, "STATE="); ok {
				state = s
			}
		}
		g.Expect(state).To(Or(Equal(volumeStatePattern), Equal(volumeStateBlank)),
			"could not classify the data volume:\n%s", stdout)
		evetest.Logger().Infof("data volume state %s:\n%s", state, strings.TrimSpace(stdout))
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
	return state
}
