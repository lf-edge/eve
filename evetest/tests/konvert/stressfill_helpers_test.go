// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// Where a volume lands in /persist, and whether the shrink therefore has to
// relocate it, is arranged in two steps with the volume created between them:
// fillPersistToPeak drives the filesystem near full so the volume is allocated in
// the high block groups, and trimPersistFill then frees the low ones so the
// shrink can fit at all. fillPersist does both in one call and is what a test
// that only needs the shrink to have work to do should use.
const (
	// fillPeakPctParamKey is how full /persist is driven before the volume is
	// created, and fillKeepGiBParamKey how much filler is left afterwards.
	fillPeakPctParamKey = "FILL_PEAK_PCT"
	fillKeepGiBParamKey = "FILL_KEEP_GIB"

	// The peak has to sit well above where the shrink boundary will fall (~38
	// GiB of a 61.7 GiB /persist on a 64 GiB boot disk) so that the volume,
	// allocated last, lands above it.
	defaultFillPeakPct = 90
	// Filler left after the trim. Small on purpose: the data volume alone keeps
	// the shrink slow enough to interrupt, while every GiB kept here is a GiB
	// EVE-K does not have for Longhorn. The figure has to stay under the
	// resizer's own limit (~34 GiB) and leave room for EVE-K's images (~8 GiB
	// measured).
	defaultFillKeepGiB = 2

	// stressFillDir is where the two-step filler is written.
	//
	// Under /persist/log, not /persist/tmp: onboot.sh removes /persist/tmp
	// unconditionally on every boot -- no threshold, no df -- so a reboot
	// anywhere between the fill and the trim would silently void the placement
	// this exists to create. /persist/log survives a boot and is still the first
	// entry in onboot.sh's cleanup list, so a device that genuinely runs out of
	// space reclaims it rather than wedging.
	stressFillDir = "/persist/log/stressfill"
)

// fillPersistToPeak fills /persist with incompressible files until it is pct
// percent full, so that a volume created next -- while the filesystem is at its
// peak -- is allocated in the high block groups the shrink must evacuate.
//
// The bytes have to be incompressible. Zeroes would let the qcow2 backing file
// store the blocks sparsely, and the relocation would then read and write
// nothing, leaving the shrink as fast as it is on an empty filesystem, which is
// the whole problem this is here to fix.
//
// reserveMiB is the size of the volume written next: the fill stops that much
// short of pct, so the peak INCLUDING the volume is the requested percentage.
// Filling all the way to pct and then writing the volume into what little is left
// collapses the allowance volumemgr grants apps -- the filler counts as dom0
// usage, which is subtracted from it -- and at no remaining space the device
// enters low-disk maintenance mode and reboots. Observed 3 of 3 runs at an 8 GiB
// volume (peak 95%, 3.0 GiB free) and 0 of 3 at 2 GiB, where the volume still fit
// in the slack.
func fillPersistToPeak(t Gomega, device *evetest.EdgeDevice, pct int, reserveMiB uint32) {
	const script = `set -u
PCT=$1
RESERVE_KB=$(( $2 * 1024 ))
DIR=` + stressFillDir + `
rm -rf "$DIR"; mkdir -p "$DIR"
cap=$(df -k /persist | tail -1 | awk '{print $2}')
want=$(( cap * PCT / 100 - RESERVE_KB ))
[ "$want" -lt 0 ] && want=0
n=0
while [ "$(df -k /persist | tail -1 | awk '{print $3}')" -lt "$want" ]; do
  f=$(printf "%s/%06d" "$DIR" "$n")
  dd if=/dev/urandom of="$f" bs=1M count=256 2>/dev/null || break
  n=$((n + 1))
done
sync
echo "FILLED files=$n $(df -h /persist | tail -1)"`
	out, err := runEVEScript(device, script, fillPersistTimeout,
		fmt.Sprintf("%d", pct), fmt.Sprintf("%d", reserveMiB))
	t.Expect(err).NotTo(HaveOccurred(), "filling /persist failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("FILLED"),
		"the fill did not report completion:\n%s", out)
	evetest.Logger().Infof("filled /persist to ~%d%%: %s", pct, strings.TrimSpace(out))
}

// trimPersistFill deletes the LOWEST-numbered filler files until the FILLER is
// down to keepGiB, which leaves the survivors -- and the volume created at the
// peak -- concentrated in the high blocks above the future shrink boundary.
//
// Trimming is what makes the shrink possible at all: the resizer refuses when the
// filesystem cannot fit in the target size, and EVE-K needs room afterwards for
// its own images. Deleting from the bottom is what keeps the relocation work
// high.
//
// keepGiB measures the filler directory alone, deliberately: a budget on total
// /persist usage also counts the volume, so a large one consumes the budget and
// the trim stops early. At 8 GiB the total-usage form left 6.75 GiB of filler,
// EVE-K then booted onto a ~40%-full /persist, and Longhorn refused to place
// replicas below its 25%-of-total floor -- a harness artifact that read as a
// product failure in 3 of 12 iterations and vanished once the filler was actually
// removed.
func trimPersistFill(t Gomega, device *evetest.EdgeDevice, keepGiB int) {
	const script = `set -u
KEEP_KB=$(( $1 * 1024 * 1024 ))
DIR=` + stressFillDir + `
# A missing filler means the volume was not placed in the evacuation zone, so the
# iteration cannot say anything about shrink safety. Fail rather than continue:
# the silent version of this produced three clean-looking rows that had measured
# nothing.
[ -d "$DIR" ] || { echo "TRIM-FAILED no-fill-dir"; exit 1; }
for f in $(ls -1 "$DIR" 2>/dev/null | sort); do
  [ "$(du -sk "$DIR" | awk '{print $1}')" -le "$KEEP_KB" ] && break
  rm -f "$DIR/$f"
done
sync
echo "TRIMMED remaining=$(ls -1 "$DIR" 2>/dev/null | wc -l) fillerKB=$(du -sk "$DIR" | awk '{print $1}') $(df -h /persist | tail -1)"`
	out, err := runEVEScript(device, script, 10*time.Minute, fmt.Sprintf("%d", keepGiB))
	t.Expect(err).NotTo(HaveOccurred(), "trimming /persist failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("TRIMMED"),
		"the trim did not report completion:\n%s", out)
	evetest.Logger().Infof("trimmed the filler to ~%d GiB: %s", keepGiB, strings.TrimSpace(out))
}

// assertVolumeAboveShrinkBoundary fails the run unless an app data volume has
// blocks above the size the shrink will cut /persist down to -- that is, unless
// the shrink will actually have to relocate it.
//
// Without this a test can pass for the wrong reason: a volume that sits entirely
// below the boundary is untouched by the shrink, so a clean verify afterwards says
// nothing about whether an interrupted relocation corrupts data. The boundary
// comes from the resizer's own check rather than from an assumption, and the block
// placement from filefrag, which reports physical extents relative to the
// filesystem the file lives on.
func assertVolumeAboveShrinkBoundary(t Gomega, device *evetest.EdgeDevice) {
	// targetBytes is the post-shrink filesystem size.
	target, err := shrinkTargetBytes(device)
	t.Expect(err).NotTo(HaveOccurred())
	t.Expect(target).To(BeNumerically(">", 0))

	// The physical range is the third column once any space inside "start.. end"
	// is closed up, which keeps the parse independent of filefrag's alignment;
	// the second half of that range is the file's highest block. Verified against
	// real filefrag output for both spacings and for a file with no extents.
	const script = `set -u
sync
FF=/usr/sbin/filefrag
[ -x "$FF" ] || FF=$(command -v filefrag 2>/dev/null || echo filefrag)
max=0
for d in /persist/vault/volumes /persist/clear/volumes /persist/vault/volumes-kvm /persist/clear/volumes-kvm; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    e=$("$FF" -b4096 -v "$f" 2>/dev/null | awk '
      { line=$0; gsub(/\.\.[ \t]+/, "..", line); $0=line }
      $1 ~ /^[0-9]+:$/ { split($3, r, /\.\./); x=r[2]; sub(/:$/, "", x); if (x+0 > m) m=x+0 }
      END { print m+0 }')
    [ -n "$e" ] || continue
    echo "VOL $f top4k=$e"
    [ "$e" -gt "$max" ] && max=$e
  done
done
echo "MAXTOP4K $max"`
	fragOut, err := runEVEScript(device, script, 5*time.Minute)
	t.Expect(err).NotTo(HaveOccurred(),
		"reading volume block placement failed:\n%s", fragOut)
	var top4k int64
	if i := strings.Index(fragOut, "MAXTOP4K "); i >= 0 {
		_, _ = fmt.Sscanf(fragOut[i:], "MAXTOP4K %d", &top4k)
	}
	topByte := top4k * 4096
	evetest.Logger().Infof("volume top block %d (%.1f GiB) vs shrink target %.1f GiB\n%s",
		top4k, float64(topByte)/float64(giB), float64(target)/float64(giB),
		strings.TrimSpace(fragOut))
	t.Expect(topByte).To(BeNumerically(">", target),
		"the data volume lies entirely below the shrink boundary (top %.1f GiB vs "+
			"target %.1f GiB), so the shrink would not relocate it and a clean verify "+
			"would prove nothing",
		float64(topByte)/float64(giB), float64(target)/float64(giB))
}

// assertWatchdogDriverBound fails the run if no watchdog driver is bound in the
// guest, which is what a test relying on the watchdog to interrupt the offline
// resize needs of its device.
//
// It checks sysfs rather than the device node: a /dev/watchdog character node can
// exist with nothing behind it, so its presence alone proves nothing, whereas an
// entry under /sys/class/watchdog means a driver registered. It does not try to
// open the node -- once EVE's watchdog service is up it holds it, and EBUSY here
// would be a false alarm.
//
// This checks the QEMU setup, not EVE. A stress build's resizer arms
// /dev/watchdog and then deliberately stops feeding it, which is how the resize
// gets interrupted -- but if the resizer cannot open the device it exits quietly
// and nothing is interrupted. The conversion then completes and the volume
// verifies perfectly, which reads exactly like evidence that an interrupted shrink
// preserves the data.
//
// Necessary but not sufficient: this runs with the system fully up, whereas the
// resizer runs from an onboot container much earlier. Only the resizer's own
// console output confirms it armed the watchdog on that path.
func assertWatchdogDriverBound(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device,
			`ls /sys/class/watchdog/ 2>/dev/null | grep -q watchdog && `+
				`echo WATCHDOG-DRIVER-BOUND || echo WATCHDOG-DRIVER-MISSING; `+
				`ls /sys/class/watchdog/ 2>&1; `+
				`cat /sys/class/watchdog/watchdog0/identity 2>/dev/null`)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("WATCHDOG-DRIVER-BOUND"),
			"no watchdog driver is bound in the guest, so the resizer cannot be "+
				"interrupted and a clean result here would mean nothing; check that "+
				"QEMU exposes a watchdog and that the chipset may reset:\n%s", out)
		evetest.Logger().Infof("watchdog driver:\n%s", strings.TrimSpace(out))
	}, 2*time.Minute, 10*time.Second).Should(Succeed())
}
