// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest"
)

// The shrink relocates every block that lies above the size /persist is cut
// down to. Whether the identity- and vault-critical files are among them
// decides what a clean digest afterwards is worth: if they all sit below the
// boundary the shrink never touched them, so the digest says the conversion
// left them alone rather than that relocating them is safe.
//
// So the volume-less shrink stages them there first (stageCriticalsHigh), and the tally
// reports three things: how many were above the boundary going in, how many the
// shrink moved down, and whether any came out damaged or had to be restored.
//
// Nothing here asserts. Block allocation decides how many of the copies land
// high, so any one run may stage none, and failing it would convert a
// measurement into a flake. What matters is that the soak as a whole sees
// criticals moved down; the soak report totals it across runs.
const (
	// criticalBlocksTimeout bounds one capture. filefrag is a per-file FIEMAP
	// read over ~13 small files, but it runs behind ssh and `eve exec pillar`
	// on a device that may be busy converting.
	criticalBlocksTimeout = 5 * time.Minute

	// criticalBlocksTally is the one line per run that the soak driver greps
	// out of the test log and banks in the unit's result file.
	criticalBlocksTally = "[CRITICAL-BLOCKS]"
)

// criticalBlock is one critical file's physical placement, in 4 KiB filesystem
// blocks: lo4k and hi4k are the lowest and highest block any of its extents
// covers.
type criticalBlock struct {
	path       string
	size       int64
	extents    int
	lo4k       int64
	hi4k       int64
	sha256     string
	offPersist bool
}

// volatile reports whether EVE rewrites this file on its own, so a change in
// its blocks or content across the conversion is not evidence of the shrink.
// Mirrors storage-resizer's volatileBackupPatterns.
func (f criticalBlock) volatile() bool {
	return strings.HasPrefix(f.path, "/persist/checkpoint/lastconfig") ||
		strings.HasPrefix(f.path, "/persist/status/nim/DevicePortConfigList/")
}

// criticalSnapshot is where every critical file sat at one point in the run,
// against the boundary the shrink was going to cut at.
//
// boundary4k is the resizer's own target size, not a fraction of the current
// one: a file at or above it is in the evacuation zone by definition. fsBlocks
// comes from dumpe2fs rather than df because statvfs reports the size NET of
// ext4 metadata -- ~238k of 10.2M blocks on a post-shrink /persist -- so a file
// between the two figures is inside the filesystem and reading the df figure as
// the boundary reports it stranded.
type criticalSnapshot struct {
	label      string
	files      map[string]criticalBlock
	fsBlocks4k int64
	dfBlocks4k int64
	boundary4k int64
	haveFrag   bool
	raw        string
}

// high returns the files with blocks at or above the shrink boundary -- the
// ones the shrink has to move. Empty when the boundary is unknown.
func (s criticalSnapshot) high() []criticalBlock {
	var out []criticalBlock
	if s.boundary4k <= 0 {
		return out
	}
	for _, f := range s.files {
		if f.hi4k >= s.boundary4k && !f.offPersist {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].hi4k > out[j].hi4k })
	return out
}

// top4k is the highest block any critical file occupies.
func (s criticalSnapshot) top4k() int64 {
	var top int64
	for _, f := range s.files {
		if f.hi4k > top {
			top = f.hi4k
		}
	}
	return top
}

// captureCriticalBlockScript reads the placement of the identity- and
// vault-critical files inside the pillar container.
//
// It emits one CRITBLK line per file and one CRITBLK-SUMMARY, and exits 0
// whatever it finds: a capture that fails a run would make the placement
// measurement more expensive than the property it measures.
//
// filefrag reports physical blocks relative to the filesystem the file actually
// lives on, so a file on some other mount is not a witness for the /persist
// shrink at all. Comparing st_dev against /persist's catches that and marks the
// file off= rather than letting an unrelated block number read as an unmoved
// survivor.
const captureCriticalBlockScript = `set -u
LABEL=$1
# Without this every file written recently reports a single extent at block 0:
# ext4 delays allocation until writeback, and filefrag reports what is on disk.
# The volatile criticals -- lastconfig, DevicePortConfigList -- are rewritten
# throughout the run, so they are exactly the ones an unsynced capture would
# record as sitting below the boundary when they may be the only ones above it.
sync
FF=/usr/sbin/filefrag
[ -x "$FF" ] || FF=$(command -v filefrag 2>/dev/null || echo filefrag)
HAVEFF=0
command -v "$FF" >/dev/null 2>&1 && HAVEFF=1
cd /persist 2>/dev/null || { echo "CRITBLK-SUMMARY label=$LABEL files=0 ff=0 err=no-persist"; exit 0; }
DE=/usr/sbin/dumpe2fs
[ -x "$DE" ] || DE=$(command -v dumpe2fs 2>/dev/null || echo dumpe2fs)
SRC=$(df /persist | tail -1 | awk '{print $1}')
dfb4k=$(( $(df -k /persist | tail -1 | awk '{print $2}') / 4 ))
tot4k=$("$DE" -h "$SRC" 2>/dev/null | awk -F: '/^Block count/{gsub(/[^0-9]/,"",$2); print $2}')
PDEV=$(stat -Lc '%d' /persist 2>/dev/null)
cap_one() {
  f=$1
  [ -f "$f" ] || return 0
  out=$("$FF" -b4096 -v "$f" 2>/dev/null) || out=""
  stats=$(printf '%s\n' "$out" | awk '
    { line=$0; gsub(/\.\.[ \t]+/, "..", line); $0=line }
    $1 ~ /^[0-9]+:$/ {
      split($3, r, /\.\./); a=r[1]+0; b=r[2]; sub(/:$/, "", b); b=b+0
      if (seen == 0 || a < lo) lo = a
      if (b > hi) hi = b
      seen++
    }
    END { printf "%d %d %d", (seen ? lo : -1), (seen ? hi : -1), seen }')
  lo=$(echo "$stats" | cut -d" " -f1)
  hi=$(echo "$stats" | cut -d" " -f2)
  ne=$(echo "$stats" | cut -d" " -f3)
  sz=$(wc -c < "$f" 2>/dev/null)
  sha=$(sha256sum "$f" 2>/dev/null | cut -c1-64)
  fdev=$(stat -Lc "%d" "$f" 2>/dev/null)
  off=0
  if [ -n "$fdev" ] && [ -n "$PDEV" ] && [ "$fdev" != "$PDEV" ]; then
    off=1
    echo "CRITBLK-OFF-PERSIST f=/persist/$f dev=$fdev persistdev=$PDEV real=$(readlink -f "$f" 2>/dev/null) mnt=$(df "$f" 2>/dev/null | tail -1 | awk '{print $NF}')"
  fi
  echo "CRITBLK f=/persist/$f size=${sz:-0} ext=${ne:-0} lo4k=${lo:--1} hi4k=${hi:--1} sha=${sha:-none} off=$off"
}
for pat in checkpoint/lastconfig* checkpoint/controllercerts* \
           certs/ecdh.*.pem certs/attest.*.pem certs/ek.*.pem \
           status/nim/DevicePortConfigList status/zedclient/OnboardingStatus* \
           status/vaultmgr/VaultConfig .fscrypt/policies .fscrypt/protectors; do
  [ -e "$pat" ] || continue
  if [ -f "$pat" ]; then
    cap_one "$pat"
  elif [ -d "$pat" ]; then
    find "$pat" -type f 2>/dev/null | while IFS= read -r ff; do cap_one "$ff"; done
  fi
done
echo "CRITBLK-SUMMARY label=$LABEL src=${SRC:-?} tot4k=${tot4k:-0} dfb4k=${dfb4k:-0} dev=${PDEV:-?} ff=$HAVEFF"`

// captureCriticalBlocks reads where the critical files sit, against boundary4k
// -- the 4 KiB block the shrink will cut at, or 0 when this run has no shrink
// to measure against.
func captureCriticalBlocks(device *evetest.EdgeDevice, label string,
	boundary4k int64) criticalSnapshot {
	snap := criticalSnapshot{
		label:      label,
		files:      map[string]criticalBlock{},
		boundary4k: boundary4k,
	}
	out, err := runEVEScript(device, captureCriticalBlockScript,
		criticalBlocksTimeout, label)
	snap.raw = strings.TrimSpace(out)
	if err != nil {
		evetest.Logger().Warnf("critical-blocks[%s]: capture failed: %v\n%s",
			label, err, snap.raw)
		return snap
	}
	for _, line := range strings.Split(out, "\n") {
		fields := kvFields(line)
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), "CRITBLK f="):
			f := criticalBlock{
				path:       fields["f"],
				size:       atoi64(fields["size"]),
				extents:    int(atoi64(fields["ext"])),
				lo4k:       atoi64(fields["lo4k"]),
				hi4k:       atoi64(fields["hi4k"]),
				sha256:     fields["sha"],
				offPersist: fields["off"] == "1",
			}
			if f.path != "" {
				snap.files[f.path] = f
			}
		case strings.HasPrefix(strings.TrimSpace(line), "CRITBLK-SUMMARY"):
			snap.fsBlocks4k = atoi64(fields["tot4k"])
			snap.dfBlocks4k = atoi64(fields["dfb4k"])
			snap.haveFrag = fields["ff"] != "0"
		}
	}
	return snap
}

// recordCriticalBlocks captures the placement and logs how many critical files
// lie above the shrink boundary. Its verdict word is ALL, SOME, NONE or SKIP;
// none of them is a failure.
func recordCriticalBlocks(device *evetest.EdgeDevice, label string,
	boundary4k int64) criticalSnapshot {
	snap := captureCriticalBlocks(device, label, boundary4k)
	log := evetest.Logger()
	log.Infof("critical-blocks[%s]: /persist %d fs-blocks (4KiB, dumpe2fs Block "+
		"count = shrink boundary; df-derived %d excludes metadata), boundary %d, "+
		"%d critical file(s)\n%s",
		label, snap.fsBlocks4k, snap.dfBlocks4k, boundary4k, len(snap.files), snap.raw)
	verdict, why := criticalStagingVerdict(snap)
	log.Infof("reloc-high staged: %s -- %s (%s)", verdict, why, label)
	return snap
}

// criticalStagingVerdict says how many critical files lie in the evacuation
// zone: ALL, SOME or NONE, or SKIP when the question does not apply or could
// not be read.
func criticalStagingVerdict(s criticalSnapshot) (string, string) {
	high := len(s.high())
	switch {
	case !s.haveFrag:
		return "SKIP", "filefrag absent from the pillar image, placement unverified"
	case len(s.files) == 0:
		return "SKIP", "no critical files found under /persist"
	case s.boundary4k <= 0:
		return "SKIP", "no shrink boundary for this route, nothing to relocate past"
	case high == 0:
		return "NONE", fmt.Sprintf("0/%d critical files above block %d; the shrink "+
			"will relocate none of them this run", len(s.files), s.boundary4k)
	case high < len(s.files):
		return "SOME", fmt.Sprintf("%d/%d critical files above block %d",
			high, len(s.files), s.boundary4k)
	default:
		return "ALL", fmt.Sprintf("%d/%d critical files above block %d",
			high, len(s.files), s.boundary4k)
	}
}

// stageCriticalsHighScript rewrites the critical files above block $2 while
// /persist is at peak fill, the fill's chunks being in directory $1 and $3 MiB
// each. A small file lands high only if no free extent is left below the
// boundary, because ext4 allocates near the file's parent directory, so it:
//
//  1. tops /persist off to ENOSPC with more chunks and ever smaller tails;
//  2. frees a hole by deleting chunks whose first block is above the boundary
//     (after a top-off, name order no longer tracks block order);
//  3. copies each critical file into that hole, checks with filefrag and cmp
//     that the copy landed high and is identical, and retries the ones that did
//     not with a bigger hole;
//  4. renames the copies over the originals only at the end, since each rename
//     frees a low original that the next copy would otherwise take;
//  5. with $4 = 1, deletes the chunks and tails step 1 added, handing that space
//     back to whatever the caller allocates next.
//
// It reports every file's outcome and exits 0 whatever happened.
const stageCriticalsHighScript = `set -u
DIR=$1; BOUND=$2; CHUNK_MIB=$3; RELEASE=$4
mkdir -p "$DIR"
FF=/usr/sbin/filefrag
[ -x "$FF" ] || FF=$(command -v filefrag 2>/dev/null || echo "")
if [ -z "$FF" ]; then
  echo "STAGE-SUMMARY staged=0 already=0 high=0 total=0 boundary=$BOUND rounds=0 ff=0"
  exit 0
fi
lowblk() { "$FF" -b4096 -v "$1" 2>/dev/null | awk '
  { line=$0; gsub(/\.\.[ \t]+/, "..", line); $0=line }
  $1 ~ /^[0-9]+:$/ { split($3, r, /\.\./); a=r[1]+0; if (seen == 0 || a < lo) lo = a; seen++ }
  END { if (seen) print lo }'; }
ishigh() { [ -n "$1" ] && [ "$1" -ge "$BOUND" ] 2>/dev/null; }
n=$(ls "$DIR" 2>/dev/null | grep -c '^[0-9]'); n0=$n
while dd if=/dev/urandom of="$DIR/$(printf %06d "$n")" bs=1M count="$CHUNK_MIB" 2>/dev/null; do
  n=$((n + 1))
done
for bs in 1M 64k 4k; do dd if=/dev/urandom of="$DIR/tail.$bs" bs="$bs" 2>/dev/null; done
sync
echo "STAGE topped-off used=$(df -k /persist | awk 'NR==2{print $5}')"
hi_pool=""
for cf in "$DIR"/[0-9]*; do
  [ -f "$cf" ] || continue
  ishigh "$(lowblk "$cf")" && hi_pool="$hi_pool $cf"
done
hole_top=$n
grow_hole() {
  k=0; rest=""
  for cf in $hi_pool; do
    if [ "$k" -lt "$1" ] && rm -f "$cf" 2>/dev/null; then k=$((k + 1)); else rest="$rest $cf"; fi
  done
  hi_pool=$rest
  while [ "$k" -lt "$1" ] && [ "$hole_top" -ge 0 ]; do
    rm -f "$DIR/$(printf %06d "$hole_top")"; hole_top=$((hole_top - 1)); k=$((k + 1))
  done
  sync
}
hole_chunks=$(( 2048 / CHUNK_MIB )); [ "$hole_chunks" -ge 1 ] || hole_chunks=1
grow_hole "$hole_chunks"
cd /persist || exit 0
targets=""
for pat in checkpoint/lastconfig* checkpoint/controllercerts* \
           certs/ecdh.*.pem certs/attest.*.pem certs/ek.*.pem \
           status/nim/DevicePortConfigList status/zedclient/OnboardingStatus* \
           status/vaultmgr/VaultConfig .fscrypt/policies .fscrypt/protectors; do
  [ -e "$pat" ] || continue
  if [ -f "$pat" ]; then targets="$targets $pat"
  elif [ -d "$pat" ]; then targets="$targets $(find "$pat" -type f 2>/dev/null)"; fi
done
total=0; already=0; pending=""
for ff in $targets; do
  total=$((total + 1))
  fb=$(lowblk "$ff")
  if ishigh "$fb"; then already=$((already + 1)); echo "STAGE-ALREADY-HIGH f=/persist/$ff blk=$fb"
  else pending="$pending $ff"; fi
done
staged=""; round=0
while [ -n "$pending" ] && [ "$round" -lt 6 ]; do
  round=$((round + 1)); failed=""
  for ff in $pending; do
    [ -f "$ff" ] || continue
    dd if="$ff" of="$ff.stage.$$" bs=1M 2>/dev/null; sync
    if ishigh "$(lowblk "$ff.stage.$$")" && cmp -s "$ff" "$ff.stage.$$"; then
      staged="$staged $ff"
    else
      rm -f "$ff.stage.$$"; failed="$failed $ff"
    fi
  done
  pending=$failed
  [ -n "$pending" ] && grow_hole "$hole_chunks"
done
nstaged=0
for ff in $staged; do
  mv "$ff.stage.$$" "$ff" 2>/dev/null && nstaged=$((nstaged + 1))
done
sync
high=0
for ff in $targets; do
  [ -f "$ff" ] || continue
  fb=$(lowblk "$ff")
  if ishigh "$fb"; then high=$((high + 1)); echo "STAGE-HIGH f=/persist/$ff blk=$fb"
  else echo "STAGE-LOW f=/persist/$ff blk=${fb:-?}"; fi
done
if [ "$RELEASE" = 1 ]; then
  i=$n0
  while [ "$i" -le "$n" ]; do rm -f "$DIR/$(printf %06d "$i")"; i=$((i + 1)); done
  rm -f "$DIR"/tail.*
  [ "$n0" -eq 0 ] && rm -rf "$DIR"
  sync
  echo "STAGE released used=$(df -k /persist | awk 'NR==2{print $5}')"
fi
echo "STAGE-SUMMARY staged=$nstaged already=$already high=$high total=$total boundary=$BOUND rounds=$round ff=1"`

// stageCriticalsHigh runs stageCriticalsHighScript against the fill in dir, of
// chunkMiB chunks; dir need not exist, and a test with no fill of its own passes
// a fresh one. release gives back the space the top-off took, for a test that
// still has a volume to allocate high. How many copies land high depends on
// block allocation, so it reports rather than asserts; the capture before the
// conversion is what the tally counts.
//
// The top-off leaves /persist with no space at all for a few minutes, and
// nodeagent can enter low-disk maintenance mode if volumemgr samples it then.
func stageCriticalsHigh(device *evetest.EdgeDevice, boundary4k int64, dir string,
	chunkMiB int, release bool) {
	log := evetest.Logger()
	releaseArg := "0"
	if release {
		releaseArg = "1"
	}
	log.Infof("staging the critical files above block %d so the shrink has to move them",
		boundary4k)
	out, err := runEVEScript(device, stageCriticalsHighScript, fillPersistTimeout,
		dir, strconv.FormatInt(boundary4k, 10), strconv.Itoa(chunkMiB), releaseArg)
	out = strings.TrimSpace(out)
	if err != nil {
		log.Warnf("critical-file staging did not complete: %v\n%s", err, out)
		return
	}
	summary := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "STAGE-SUMMARY") {
			summary = line
		}
	}
	f := kvFields(summary)
	log.Infof("critical-file staging:\n%s", out)
	log.Infof("reloc-high staging: %s/%s critical files above block %d "+
		"(%s copied there, %s already there, %s rounds)",
		f["high"], f["total"], boundary4k, f["staged"], f["already"], f["rounds"])
}

// relocateCriticalHighParameter declares whether a shrink test stages the
// critical files above the boundary before the conversion.
func relocateCriticalHighParameter() evetest.TestParameterDefinition {
	return evetest.TestParameterDefinition{
		Key:          relocateCriticalHighParamKey,
		DefaultValue: true,
		Description: evetest.TestParameterDescription{
			Summary: "Before a shrink, rewrite the identity- and vault-critical files above the shrink boundary so the shrink has to move them",
			Default: "true",
		},
	}
}

// criticalIntegrity is what the conversion's own checks said about the critical
// files, read from the console: storage-resizer's digest comparison against the
// pre-shrink backup, how many files its restore had to put back, and whether
// storage-init found /persist too corrupt to mount and recreated it.
type criticalIntegrity struct {
	read          bool
	digestRan     bool
	digestSkipped bool
	digestErr     bool
	checked       int
	mismatch      int
	volatile      int
	missing       int
	damaged       []string
	restored      int
	restoreRan    bool
	restoreFailed bool
	recreated     bool
}

var (
	reDigestSummary = regexp.MustCompile(`digest check: checked=(\d+) match=\d+ ` +
		`mismatch=(\d+) changed-volatile=(\d+) missing=(\d+)`)
	reDigestFile = regexp.MustCompile(`digest (?:MISMATCH: (\S+) differs|missing: (\S+) absent)`)
	reRestored   = regexp.MustCompile(`restored (\d+) file\(s\) into `)
)

// parseCriticalIntegrity reads the conversion's integrity lines out of the
// console. The console holds every boot of the test, so each count is the worst
// any boot reported: a clean check on a later boot must not hide a bad one.
//
// storage-init reports a recreated ext4 /persist as "appears to be corrupted,
// recreating it as" and a ZFS pool it cannot import as "Cannot import persist
// pool ... recreating it as". A device provisioned from a live image has no P3
// until storage-init's first-boot path creates it with sgdisk, and the fsck of
// that blank partition then prints the ext4 line a real loss does. sgdisk runs only on that path, so a recreate in a boot that printed
// sgdisk's completion line is the first boot and is not counted.
//
// That line is an echo storage-init does not copy to the console, so after the
// first boot it only shows up on images that print their onboot output there.
// Every critical file missing from /persist and restored from the backup is the
// fallback: a recreated /persist, or one that never mounted, looks the same.
func parseCriticalIntegrity(console string) criticalIntegrity {
	r := criticalIntegrity{read: true}
	seen := map[string]bool{}
	firstBoot := false
	for _, line := range strings.Split(console, "\n") {
		if strings.Contains(line, "Linux version ") {
			firstBoot = false
		}
		if strings.Contains(line, "storage-init.out;The operation has completed successfully.") {
			firstBoot = true
		}
		if m := reDigestSummary.FindStringSubmatch(line); m != nil {
			r.digestRan = true
			r.checked = max(r.checked, int(atoi64(m[1])))
			r.mismatch = max(r.mismatch, int(atoi64(m[2])))
			r.volatile = max(r.volatile, int(atoi64(m[3])))
			r.missing = max(r.missing, int(atoi64(m[4])))
		}
		if m := reDigestFile.FindStringSubmatch(line); m != nil {
			f := m[1] + m[2]
			if !seen[f] {
				seen[f] = true
				r.damaged = append(r.damaged, f)
			}
		}
		if m := reRestored.FindStringSubmatch(line); m != nil {
			r.restoreRan = true
			r.restored = max(r.restored, int(atoi64(m[1])))
		}
		switch {
		case strings.Contains(line, "digest check: skipped"):
			r.digestSkipped = true
		case strings.Contains(line, "restore: digest check failed:"):
			r.digestErr = true
		case strings.Contains(line, "restore failed:"):
			r.restoreFailed = true
		case strings.Contains(line, "appears to be corrupted, recreating it as") && !firstBoot,
			strings.Contains(line, "Cannot import persist pool") &&
				strings.Contains(line, "recreating it as") && !firstBoot:
			r.recreated = true
		}
	}
	if r.checked > 0 && r.missing == r.checked && r.restored == r.checked {
		r.recreated = true
	}
	return r
}

// digestWord condenses the digest check into one tally token.
func (r criticalIntegrity) digestWord() string {
	switch {
	case !r.read:
		return "no-console"
	case r.digestErr:
		return "error"
	case r.mismatch > 0 || r.missing > 0:
		return fmt.Sprintf("DAMAGED:%d", r.mismatch+r.missing)
	case r.digestRan:
		return "clean"
	case r.digestSkipped:
		return "skipped"
	default:
		return "n/a"
	}
}

// logCriticalRelocation captures the placement again after the conversion,
// compares it with before, and emits the single tally line the soak driver
// banks per run. The line carries the three numbers a run contributes:
//
//   - high: critical files above the shrink boundary going in;
//   - moved-down: files that were above it and changed blocks, split into
//     moved-down-stable, which only the shrink can have moved, and the volatile
//     ones EVE rewrites on its own;
//   - damage: the resizer's digest verdict (clean, DAMAGED:N, ...), how many
//     files its restore put back, whether it failed, whether /persist was
//     recreated, and how many stable files hash differently afterwards than
//     before -- damage that got past the restore.
//
// stranded counts criticals left above the boundary afterwards, which a
// successful shrink cannot leave behind, so a non-zero count points at the
// boundary reading rather than at the data.
//
// It returns the integrity reading, so a later failure can say whether
// /persist was recreated under it.
func logCriticalRelocation(device *evetest.EdgeDevice, before criticalSnapshot) criticalIntegrity {
	log := evetest.Logger()
	after := captureCriticalBlocks(device, "post-conversion", before.boundary4k)
	boundary := before.boundary4k
	beforeHigh := before.high()

	var moved, movedDown, movedDownStable, changedStable int
	var detail, changed []string
	offPersistPaths := map[string]bool{}
	for path, f := range before.files {
		if f.offPersist {
			offPersistPaths[path] = true
		}
	}
	for path, f := range after.files {
		if f.offPersist {
			offPersistPaths[path] = true
		}
	}
	for path, b := range before.files {
		if offPersistPaths[path] {
			continue
		}
		a, ok := after.files[path]
		if !ok {
			detail = append(detail, fmt.Sprintf("%s: GONE (was %d..%d)",
				path, b.lo4k, b.hi4k))
			continue
		}
		if !b.volatile() && b.sha256 != "" && b.sha256 != "none" && a.sha256 != b.sha256 {
			changedStable++
			changed = append(changed, fmt.Sprintf("%s: size %d -> %d, sha256 %.12s -> %.12s",
				path, b.size, a.size, b.sha256, a.sha256))
		}
		if a.lo4k == b.lo4k && a.hi4k == b.hi4k {
			continue
		}
		moved++
		mark := ""
		if boundary > 0 && b.hi4k >= boundary {
			movedDown++
			mark = " [moved down from above the boundary]"
			if !b.volatile() {
				movedDownStable++
			}
		}
		detail = append(detail, fmt.Sprintf("%s: %d..%d -> %d..%d%s",
			path, b.lo4k, b.hi4k, a.lo4k, a.hi4k, mark))
	}
	var stranded int
	if boundary > 0 {
		for path, f := range after.files {
			if !offPersistPaths[path] && f.hi4k >= boundary {
				stranded++
			}
		}
	}

	integrity := criticalIntegrity{}
	if console, err := device.ConsoleOutput(); err != nil {
		log.Warnf("critical-file integrity: console unavailable (%v)", err)
	} else {
		integrity = parseCriticalIntegrity(console)
	}

	if len(detail) > 0 {
		sort.Strings(detail)
		log.Infof("critical-blocks moved across the conversion:\n  %s",
			strings.Join(detail, "\n  "))
	}
	log.Infof("reloc-high moved: %d/%d critical files relocated by the conversion; "+
		"%d of the %d above block %d moved down (%d of them not rewritten by EVE, "+
		"so moved by the shrink)",
		moved, len(before.files), movedDown, len(beforeHigh), boundary, movedDownStable)
	if len(integrity.damaged) > 0 {
		log.Warnf("critical-file digest check found damage the shrink left: %s",
			strings.Join(integrity.damaged, " "))
	}
	if len(changed) > 0 {
		sort.Strings(changed)
		log.Warnf("critical files that EVE does not rewrite differ after the conversion:\n  %s",
			strings.Join(changed, "\n  "))
	}

	verdict, _ := criticalStagingVerdict(before)
	log.Infof("%s boundary4k=%d files=%d high=%d top4k=%d moved=%d moved-high=%d "+
		"moved-down-stable=%d stranded=%d offpersist=%d filefrag=%t staged=%s "+
		"digest=%s restored=%d restore-failed=%t recreated=%t changed-stable=%d",
		criticalBlocksTally, boundary, len(before.files), len(beforeHigh),
		before.top4k(), moved, movedDown, movedDownStable, stranded,
		len(offPersistPaths), before.haveFrag, verdict,
		integrity.digestWord(), integrity.restored, integrity.restoreFailed,
		integrity.recreated, changedStable)
	return integrity
}

// shrinkBoundaryBlocks is the 4 KiB block the shrink will cut /persist at,
// taken from the resizer's own pre-flight check. It returns 0 rather than an
// error when the check reports no shrink: a grow-route run has no boundary, and
// that is a fact about the run, not a failure to read one.
func shrinkBoundaryBlocks(device *evetest.EdgeDevice) int64 {
	target, err := shrinkTargetBytes(device)
	if err != nil || target <= 0 {
		return 0
	}
	return target / 4096
}

// shrinkTargetBytes reads the post-shrink filesystem size out of the resizer's
// pre-flight check, which is where the boundary comes from rather than from an
// assumption about it.
func shrinkTargetBytes(device *evetest.EdgeDevice) (int64, error) {
	disk, err := bootDiskPath(device)
	if err != nil {
		return 0, err
	}
	out, err := runEVE(device,
		"eve exec pillar /usr/bin/storage-resizer check --disk "+disk+" --json")
	if err != nil {
		return 0, fmt.Errorf("resizer check failed: %w\n%s", err, out)
	}
	var target int64
	if i := strings.Index(out, `"targetBytes"`); i >= 0 {
		_, _ = fmt.Sscanf(out[i:], `"targetBytes": %d`, &target)
	}
	if target <= 0 {
		return 0, fmt.Errorf("no targetBytes in the resizer check:\n%s", out)
	}
	return target, nil
}

// kvFields splits a whitespace-separated key=value line. Values never contain
// spaces in what the capture emits, and a field without '=' is skipped, so a
// human prefix on the line does not derail the parse.
func kvFields(line string) map[string]string {
	out := map[string]string{}
	for _, f := range strings.Fields(line) {
		if k, v, ok := strings.Cut(f, "="); ok {
			out[k] = v
		}
	}
	return out
}

func atoi64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
