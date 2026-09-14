// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// Reasons the conversion cannot go ahead, as the escripts name them.
const (
	// refuseZFS is a ZFS /persist with no free tail. ZFS cannot be shrunk, so
	// with nothing to grow into there is no way to free the space.
	refuseZFS = "zfs"
	// refuseTooFull is an ext4 /persist holding too much to give up what the
	// EVE-K layout needs while staying under the resizer's fullness limit.
	refuseTooFull = "too-full"
)

// Decisions storage-resizer's pre-flight check can reach, as they appear in its
// --json output.
const (
	// decisionShrink frees the space the EVE-K layout needs by shrinking
	// /persist, which is what a boot disk with no free tail requires. This is
	// the field layout.
	decisionShrink = "shrink"
	// decisionGrow takes the space from an unallocated tail instead, leaving
	// /persist alone.
	decisionGrow = "grow"
	// decisionInsufficient is the refusal: no room can be freed either way.
	decisionInsufficient = "insufficient"
)

const (
	miB = int64(1) << 20
	giB = int64(1) << 30

	// The released layout: a 36 MiB ESP and 512 MiB IMGA/IMGB. The ceilings sit
	// well above those so that alignment jitter cannot fail the check, while
	// staying far below anything the conversion produces.
	smallESPCeiling = 256 * miB
	smallImgCeiling = giB

	// The EVE-K layout: a 2 GiB ESP, a reserved 2 GiB ESP-B, and 10 GiB
	// IMGA/IMGB. The floors sit below each target for the same reason.
	largeESPFloor  = giB
	largeImgFloor  = 8 * giB
	largeESPBFloor = giB

	// espBPartitionNumber is where the conversion must place the reserved
	// second ESP, so that a converted disk has the same partition numbering as
	// a fresh EVE-K install.
	espBPartitionNumber = 7

	// freeTailNeeded is the unallocated space past the last partition below
	// which storage-resizer will not choose to grow.
	freeTailNeeded = 22 * giB
	// gptSectorSize is the logical sector size EVE's images are built with.
	gptSectorSize = 512
)

// persistFillDir is where the pre-conversion fill is written, so the fill and
// the cleanup that frees it cannot drift apart.
const persistFillDir = "/persist/konvert-fill"

// fillPersistTimeout bounds the pre-conversion fill. It is generous because the
// work is proportional to the fill size and runs against a virtual disk.
const fillPersistTimeout = 40 * time.Minute

// espBGUIDSuffix identifies the reserved second ESP. Both ESPs carry the same
// "EFI System" partition label, so the fresh-install GUID is what tells them
// apart -- and a partition that is an ESP-B in every way except its GUID is not
// one, because that is what EVE itself keys on.
const espBGUIDSuffix = "30056"

// partsLsblk dumps the partition table in a form every field the geometry
// assertions need can be read out of in one call.
const partsLsblk = "eve exec pillar lsblk -b -P -o NAME,TYPE,PARTLABEL,PARTUUID,SIZE"

// geometry is the boot disk's partition sizes in bytes, keyed the way the
// conversion talks about them. A partition that is absent reads as zero, which
// is meaningful for P3: the two-disk layouts have none.
type geometry struct {
	esp      int64
	espB     int64
	espBName string
	imgA     int64
	imgB     int64
	p3       int64
	// diskSize and partitionSum give the unallocated tail.
	diskSize     int64
	partitionSum int64
}

// freeTail is the unallocated space past the last partition.
func (g geometry) freeTail() int64 { return g.diskSize - g.partitionSum }

// String renders the geometry for a failure message, since every assertion
// here wants to show what it actually saw.
func (g geometry) String() string {
	return fmt.Sprintf(
		"ESP=%d ESP-B=%d(%s) IMGA=%d IMGB=%d P3=%d disk=%d freeTail=%d",
		g.esp, g.espB, g.espBName, g.imgA, g.imgB, g.p3, g.diskSize, g.freeTail())
}

// lsblkFieldRE matches the KEY="value" pairs `lsblk -P` emits.
var lsblkFieldRE = regexp.MustCompile(`(\w+)="([^"]*)"`)

// parseGeometry reads an `lsblk -b -P` dump into a geometry.
func parseGeometry(dump string) geometry {
	var g geometry
	for _, line := range strings.Split(dump, "\n") {
		fields := map[string]string{}
		for _, m := range lsblkFieldRE.FindAllStringSubmatch(line, -1) {
			fields[m[1]] = m[2]
		}
		size, err := strconv.ParseInt(fields["SIZE"], 10, 64)
		if err != nil {
			continue
		}
		switch fields["TYPE"] {
		case "disk":
			if size > g.diskSize {
				g.diskSize = size
			}
			continue
		case "part":
			g.partitionSum += size
		default:
			continue
		}
		switch fields["PARTLABEL"] {
		case "EFI System":
			if strings.HasSuffix(strings.ToLower(fields["PARTUUID"]), espBGUIDSuffix) {
				g.espB = size
				g.espBName = fields["NAME"]
			} else {
				g.esp = size
			}
		case "IMGA":
			g.imgA = size
		case "IMGB":
			g.imgB = size
		case "P3":
			g.p3 = size
		}
	}
	return g
}

// readGeometry returns the device's current boot-disk geometry, retrying while
// EVE's SSH and pillar come back after a reboot.
func readGeometry(t Gomega, device *evetest.EdgeDevice) geometry {
	var g geometry
	t.Eventually(func(g2 Gomega) {
		out, err := runEVE(device, partsLsblk)
		g2.Expect(err).NotTo(HaveOccurred())
		g = parseGeometry(out)
		g2.Expect(g.imgA).To(BeNumerically(">", 0), "could not read IMGA size:\n%s", out)
	}, 5*time.Minute, 10*time.Second).Should(Succeed())
	return g
}

// assertSmallGeometry asserts the device is still on the released layout, which
// is the precondition for the conversion being worth running: on a disk that is
// already large there is nothing to repartition and a passing test would prove
// nothing.
func assertSmallGeometry(t Gomega, device *evetest.EdgeDevice) geometry {
	g := readGeometry(t, device)
	t.Expect(g.esp).To(BeNumerically("<", smallESPCeiling),
		"ESP is not the released size: %s", g)
	t.Expect(g.imgA).To(BeNumerically("<", smallImgCeiling),
		"IMGA is not the released size: %s", g)
	t.Expect(g.imgB).To(BeNumerically("<", smallImgCeiling),
		"IMGB is not the released size: %s", g)
	t.Expect(g.espB).To(BeZero(),
		"the released layout already has an ESP-B, so the conversion has run before: %s", g)
	return g
}

// sgdiskPrint dumps the partition table the way the GPT itself describes it,
// including where usable space actually ends.
const sgdiskPrint = "eve exec pillar sgdisk -p "

var (
	// lastUsableRE reads the last sector the GPT will let a partition occupy.
	lastUsableRE = regexp.MustCompile(`last usable sector is (\d+)`)
	// partitionRowRE reads a partition row's start and end sector.
	partitionRowRE = regexp.MustCompile(`^\s*\d+\s+(\d+)\s+(\d+)\s`)
)

// assertFreeTail asserts the GPT exposes enough unallocated space past the last
// partition for storage-resizer to choose the grow.
//
// Asked of the GPT rather than computed from the disk's size, because those are
// different questions and only the GPT's answer matters. Growing an image moves
// the end of the disk but leaves the table describing the old one, so
// subtracting the partition sizes from the disk size reports a healthy tail
// that nothing can allocate from -- a check that passes in exactly the case it
// exists to catch.
func assertFreeTail(t Gomega, device *evetest.EdgeDevice) {
	var tail int64
	t.Eventually(func(g Gomega) {
		disk, err := bootDiskPath(device)
		g.Expect(err).NotTo(HaveOccurred())
		out, err := runEVE(device, sgdiskPrint+disk)
		g.Expect(err).NotTo(HaveOccurred())

		m := lastUsableRE.FindStringSubmatch(out)
		g.Expect(m).NotTo(BeNil(), "could not read the last usable sector:\n%s", out)
		lastUsable, err := strconv.ParseInt(m[1], 10, 64)
		g.Expect(err).NotTo(HaveOccurred())

		var lastPartitionEnd int64
		for _, line := range strings.Split(out, "\n") {
			if row := partitionRowRE.FindStringSubmatch(line); row != nil {
				end, convErr := strconv.ParseInt(row[2], 10, 64)
				g.Expect(convErr).NotTo(HaveOccurred())
				if end > lastPartitionEnd {
					lastPartitionEnd = end
				}
			}
		}
		g.Expect(lastPartitionEnd).To(BeNumerically(">", 0),
			"could not read any partition row:\n%s", out)
		tail = (lastUsable - lastPartitionEnd) * gptSectorSize
	}, 3*time.Minute, 10*time.Second).Should(Succeed())

	evetest.Logger().Infof("the GPT exposes %d bytes of usable free tail", tail)
	t.Expect(tail).To(BeNumerically(">=", freeTailNeeded),
		"the GPT exposes only %d bytes past the last partition; the conversion needs %d to grow into",
		tail, freeTailNeeded)
}

// assertLargeGeometry asserts the conversion reached the EVE-K layout, given
// the geometry it started from.
//
// wantP3 says what must have happened to /persist, which is the part that
// differs by route: the shrink takes its space from P3, the grow takes it from
// the free tail and must leave P3 alone. Comparing against the baseline rather
// than against a fixed size is what makes that distinguishable at all.
func assertLargeGeometry(t Gomega, device *evetest.EdgeDevice, before geometry, wantP3 p3Expectation) {
	g := readGeometry(t, device)

	t.Expect(g.esp).To(BeNumerically(">", before.esp), "ESP did not grow: %s", g)
	t.Expect(g.imgA).To(BeNumerically(">", before.imgA), "IMGA did not grow: %s", g)
	t.Expect(g.imgB).To(BeNumerically(">", before.imgB), "IMGB did not grow: %s", g)
	t.Expect(g.esp).To(BeNumerically(">=", largeESPFloor), "ESP is below the EVE-K size: %s", g)
	t.Expect(g.imgA).To(BeNumerically(">=", largeImgFloor), "IMGA is below the EVE-K size: %s", g)
	t.Expect(g.imgB).To(BeNumerically(">=", largeImgFloor), "IMGB is below the EVE-K size: %s", g)

	t.Expect(g.espB).NotTo(BeZero(),
		"the conversion did not create the reserved ESP-B: %s", g)
	t.Expect(g.espB).To(BeNumerically(">=", largeESPBFloor),
		"the reserved ESP-B is below its EVE-K size: %s", g)
	t.Expect(g.espBName).To(HaveSuffix(strconv.Itoa(espBPartitionNumber)),
		"the reserved ESP-B is not partition #%d, so a converted disk is numbered "+
			"differently from a fresh EVE-K install: %s", espBPartitionNumber, g)

	switch wantP3 {
	case p3MustShrink:
		t.Expect(g.p3).To(BeNumerically("<", before.p3),
			"/persist did not shrink, so the space came from somewhere else: %s", g)
	case p3MustBeUnchanged:
		// A megabyte of tolerance for GPT alignment; anything more is a shrink.
		t.Expect(g.p3).To(BeNumerically(">=", before.p3-miB),
			"/persist shrank on a path that should have grown into the free tail: %s", g)
	case p3MustBeAbsent:
		t.Expect(g.p3).To(BeZero(),
			"the boot disk has a /persist partition, but this layout keeps it on another disk: %s", g)
	}
}

// p3Expectation is what the conversion must have done to /persist, which is
// how the two routes to the same geometry are told apart.
type p3Expectation int

const (
	// p3MustShrink is the shrink route: the space came out of /persist.
	p3MustShrink p3Expectation = iota
	// p3MustBeUnchanged is the grow route: the space came from the free tail.
	p3MustBeUnchanged
	// p3MustBeAbsent is a layout that keeps /persist on another disk entirely.
	p3MustBeAbsent
)

// bootDiskPath resolves the boot disk as the parent of the IMGA partition,
// e.g. /dev/vda under evetest's virtio QEMU.
func bootDiskPath(device *evetest.EdgeDevice) (string, error) {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'lsblk -ndo pkname $(findfs PARTLABEL=IMGA)'`)
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("could not resolve the boot disk (IMGA's parent)")
	}
	return "/dev/" + name, nil
}

// assertCheckDecision asserts storage-resizer's pre-flight check reaches the
// expected decision on the live boot disk.
//
// This is what separates a conversion that took the intended route from one
// that reached the same geometry another way, and it has to be asserted before
// the conversion: afterwards the inputs it decided on are gone.
func assertCheckDecision(t Gomega, device *evetest.EdgeDevice, want string) {
	t.Eventually(func(g Gomega) {
		disk, err := bootDiskPath(device)
		g.Expect(err).NotTo(HaveOccurred())
		out, err := runEVEWithTimeout(device,
			"eve exec pillar /usr/bin/storage-resizer check --disk "+disk+" --json",
			2*time.Minute)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(fmt.Sprintf("%q", want)),
			"storage-resizer check did not decide %q:\n%s", want, out)
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// Shaping constants for the pre-conversion fill. peakFillPercent is how full
// /persist is driven before trimming, and fillChunkMiB the size of each numbered
// file -- large enough that the loop is not dominated by process startup, small
// enough that the trim can approach the target closely.
const (
	peakFillPercent = 90
	fillChunkMiB    = 1024
)

// fillPersist leaves /persist holding data ABOVE where the shrink boundary will
// fall, so the offline resize2fs has to relocate it.
//
// Filling straight to the target size does not work, and that is why this is
// more than a single dd: a freshly formatted ext4 allocates sequentially created
// files from low blocks upward, so data written directly to the target sits
// below the boundary and the shrink moves nothing. Writing zeros compounds it,
// since they cost almost nothing to store on a sparse image.
//
// So: fill to peakFillPercent of the filesystem with equal-size numbered files of
// incompressible bytes, pushing allocation into the high block groups, then
// delete the earliest -- lowest-block -- files until usage falls back to the
// target. What survives is concentrated above the boundary, which is exactly
// what resize2fs then has to move down.
func fillPersist(t Gomega, device *evetest.EdgeDevice, gib int) {
	if gib <= 0 {
		return
	}
	log := evetest.Logger()
	log.Infof("filling /persist to %d%% then trimming to %d GiB, so the shrink has high blocks to relocate",
		peakFillPercent, gib)
	script := fmt.Sprintf(`set -u
DIR=%[2]s
rm -rf "$DIR"; mkdir -p "$DIR"
used_kb() { df -k /persist | awk 'NR==2{print $3}'; }
size_kb=$(df -k /persist | awk 'NR==2{print $2}')
peak_kb=$(( size_kb * %[4]d / 100 ))
target_kb=$(( %[1]d * 1024 * 1024 ))
n=0
while [ "$(used_kb)" -lt "$peak_kb" ]; do
  dd if=/dev/urandom of="$DIR/$(printf %%06d $n)" bs=1M count=%[3]d 2>/dev/null || break
  n=$((n + 1))
done
sync
echo "PEAK files=$n used=$(df -k /persist | awk 'NR==2{print $5}')"
i=0
while [ "$i" -lt "$n" ] && [ "$(used_kb)" -gt "$target_kb" ]; do
  rm -f "$DIR/$(printf %%06d $i)"
  i=$((i + 1))
done
sync
echo "FILLED trimmed=$i kept=$(( n - i ))"
df -k /persist | awk 'NR==2{print "PERSIST used="$5}'`, gib, persistFillDir, fillChunkMiB, peakFillPercent)

	// One attempt, not a retry: this writes tens of gigabytes, and a second
	// pass would start over rather than continue.
	out, err := runEVEWithTimeout(device, script, fillPersistTimeout)
	t.Expect(err).NotTo(HaveOccurred(), "could not fill /persist:\n%s", out)
	t.Expect(out).To(ContainSubstring("FILLED"), "could not fill /persist:\n%s", out)
	log.Infof("pre-fill result: %s", strings.TrimSpace(out))
}

// assertGeometryUnchanged asserts every partition still has the size it had.
//
// ESP-B is compared like any other partition rather than required to be absent:
// a device that is already on the EVE-K layout has one, and for it "unchanged"
// means the ESP-B it started with is still there. Where the caller starts on a
// released image the comparison is against zero anyway, so a conversion that
// rewrote the table is still caught.
//
// Compared partition by partition rather than as whole text: lsblk also prints
// device names, which a reboot can renumber without anything having moved.
func assertGeometryUnchanged(t Gomega, device *evetest.EdgeDevice, before geometry) {
	after := readGeometry(t, device)
	t.Expect(after.esp).To(Equal(before.esp), "ESP changed size: %s", after)
	t.Expect(after.imgA).To(Equal(before.imgA), "IMGA changed size: %s", after)
	t.Expect(after.imgB).To(Equal(before.imgB), "IMGB changed size: %s", after)
	t.Expect(after.p3).To(Equal(before.p3), "/persist changed size: %s", after)
	t.Expect(after.espB).To(Equal(before.espB),
		"the ESP-B changed, so the partition table was rewritten: %s", after)
}

// persistTypeFile is where EVE records what /persist was formatted as.
const persistTypeFile = "/run/eve.persist_type"

// assertPersistType waits for EVE to report the expected /persist filesystem.
//
// A precondition, not an observation: the filesystem decides which way the
// conversion can free space, so a device that came up ext4 when the test meant
// ZFS would exercise a different path and could still satisfy the test's other
// assertions for the wrong reason.
func assertPersistType(t Gomega, device *evetest.EdgeDevice, want string) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "cat "+persistTypeFile)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal(want),
			"/persist is not %s, so this variant would refuse for the wrong reason", want)
	}, 10*time.Minute, 15*time.Second).Should(Succeed())
}

// fillPersistToPercent fills /persist until it is at least pct percent used, so
// that no shrink can free what the EVE-K layout needs.
//
// Sized as a proportion of the filesystem rather than as an absolute, because
// what makes a shrink impossible is how full /persist is relative to itself.
func fillPersistToPercent(t Gomega, device *evetest.EdgeDevice, pct int) {
	log := evetest.Logger()
	log.Infof("filling /persist to %d%% so no shrink can free enough", pct)
	script := fmt.Sprintf(`set -e
target=%[1]d
size=$(df -k /persist | awk 'NR==2{print $2}')
used=$(df -k /persist | awk 'NR==2{print $3}')
avail=$(df -k /persist | awk 'NR==2{print $4}')
need=$(( size * target / 100 - used ))
if [ "$need" -le 0 ]; then echo "ALREADY-FULL"; else
  [ "$need" -lt "$avail" ] || need=$(( avail - 1048576 ))
  mkdir -p %[2]s
  dd if=/dev/zero of=%[2]s/fill bs=1M count=$(( need / 1024 )) 2>/dev/null
  sync
fi
df -k /persist | awk 'NR==2{print "PERSIST used="$5}'`, pct, persistFillDir)
	out, err := runEVEWithTimeout(device, script, fillPersistTimeout)
	t.Expect(err).NotTo(HaveOccurred(), "could not fill /persist:\n%s", out)
	t.Expect(out).To(ContainSubstring("PERSIST used="), "could not fill /persist:\n%s", out)
	log.Infof("fill result: %s", strings.TrimSpace(out))
}

// freePersistFill removes the pre-conversion filler.
//
// It exists only to give the offline shrink real blocks to relocate, and once
// the resize is done it is actively harmful: the shrink leaves /persist smaller
// than it found it, so the same filler now occupies most of what remains, and
// EVE-K's storage never reports healthy because Longhorn has nowhere to place a
// replica. Freed here rather than left for teardown, because the cluster comes
// up in between.
func freePersistFill(t Gomega, device *evetest.EdgeDevice) {
	log := evetest.Logger()
	out, err := runEVEWithTimeout(device,
		"eve exec pillar sh -c 'rm -rf "+persistFillDir+"; sync; df -h /persist | tail -1'",
		5*time.Minute)
	t.Expect(err).NotTo(HaveOccurred(), "could not free the fill:\n%s", out)
	log.Infof("freed the pre-conversion fill; /persist is now: %s", strings.TrimSpace(out))
}

// resizerCheck is what storage-resizer's pre-flight check reports, limited to
// the fields that say whether the conversion can go ahead and why not.
type resizerCheck struct {
	Decision       string `json:"decision"`
	DecisionReason string `json:"decisionReason"`
	PersistType    string `json:"persistType"`
	// ShrinkApplicable is whether a shrink was even considered; it is false for
	// a filesystem that cannot be shrunk at all.
	ShrinkApplicable bool `json:"shrinkApplicable"`
	SpaceToShrinkExt struct {
		OK bool `json:"ok"`
	} `json:"spaceToShrinkExt"`
}

// readResizerCheck runs the pre-flight check and decodes its verdict.
func readResizerCheck(device *evetest.EdgeDevice) (resizerCheck, error) {
	var check resizerCheck
	disk, err := bootDiskPath(device)
	if err != nil {
		return check, err
	}
	out, err := runEVEWithTimeout(device,
		"eve exec pillar /usr/bin/storage-resizer check --disk "+disk+" --json",
		2*time.Minute)
	if err != nil {
		return check, err
	}
	if err := json.Unmarshal([]byte(out), &check); err != nil {
		return check, fmt.Errorf("could not decode the check's verdict %q: %w", out, err)
	}
	return check, nil
}

// assertCheckRefuses asserts the pre-flight check declines, and declines for the
// reason this variant set up.
//
// The reason matters as much as the refusal. Both variants end at the same
// verdict, so a test that only checked for a refusal would pass on a device that
// refused for some third reason entirely -- and would keep passing if the
// condition it meant to create had quietly stopped happening.
func assertCheckRefuses(t Gomega, device *evetest.EdgeDevice, reason string) {
	t.Eventually(func(g Gomega) {
		check, err := readResizerCheck(device)
		g.Expect(err).NotTo(HaveOccurred())
		evetest.Logger().Infof(
			"resizer check: decision=%s persistType=%s shrinkApplicable=%t shrink.ok=%t reason=%q",
			check.Decision, check.PersistType, check.ShrinkApplicable,
			check.SpaceToShrinkExt.OK, check.DecisionReason)

		g.Expect(check.Decision).To(Equal(decisionInsufficient),
			"the check did not refuse: %+v", check)
		switch reason {
		case refuseZFS:
			g.Expect(check.PersistType).To(Equal("zfs"),
				"the refusal is not the ZFS one: %+v", check)
		case refuseTooFull:
			g.Expect(check.ShrinkApplicable).To(BeTrue(),
				"a shrink was never considered, so this is not the too-full refusal: %+v", check)
			g.Expect(check.SpaceToShrinkExt.OK).To(BeFalse(),
				"the shrink would have fit, so /persist is not too full: %+v", check)
		}
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
}

// The absolute EVE-K target layout, which every conversion must reach whatever
// it started from: two 2 GiB ESPs (ESP-A and the reserved ESP-B) and 10 GiB
// IMGA/IMGB -- "2+2+10+10". The floors sit below each target to tolerate GPT
// alignment while staying unambiguous about which layout is present.
const (
	targetESPFloor = 3 * giB / 2
	targetImgFloor = 9 * giB
)

// isEVEKLayout reports whether a geometry is already the EVE-K target.
func isEVEKLayout(g geometry) bool {
	return g.espB >= targetESPFloor && g.esp >= targetESPFloor &&
		g.imgA >= targetImgFloor && g.imgB >= targetImgFloor
}

// assertFinalEVEKLayout asserts the boot disk reached the EVE-K target layout
// in absolute terms, rather than relative to where it started.
//
// This is the stricter of the two geometry checks and the one that pins the
// contract: a conversion that grew every partition but stopped short of the
// target would satisfy a relative check and still leave a disk that is not
// laid out like a fresh EVE-K install.
func assertFinalEVEKLayout(t Gomega, device *evetest.EdgeDevice) {
	g := readGeometry(t, device)
	evetest.Logger().Infof("final geometry: %s", g)
	t.Expect(g.espB).NotTo(BeZero(),
		"the conversion did not create the reserved ESP-B: %s", g)
	t.Expect(g.esp).To(BeNumerically(">=", targetESPFloor),
		"ESP-A is below the 2 GiB target: %s", g)
	t.Expect(g.espB).To(BeNumerically(">=", targetESPFloor),
		"the reserved ESP-B is below the 2 GiB target: %s", g)
	t.Expect(g.imgA).To(BeNumerically(">=", targetImgFloor),
		"IMGA is below the 10 GiB target: %s", g)
	t.Expect(g.imgB).To(BeNumerically(">=", targetImgFloor),
		"IMGB is below the 10 GiB target: %s", g)
	t.Expect(g.espBName).To(HaveSuffix(strconv.Itoa(espBPartitionNumber)),
		"the reserved ESP-B is not partition #%d: %s", espBPartitionNumber, g)
}
