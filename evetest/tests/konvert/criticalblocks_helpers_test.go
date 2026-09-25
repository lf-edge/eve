// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
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
// Nothing here asserts. A run where no critical file is in the evacuation zone
// is a weaker run, not a broken one, and failing it would only convert a
// measurement into a flake -- staging the criticals high deliberately was tried
// in the predecessor campaign and worked in 20 of 56 iterations. Recording the
// placement is what makes the difference visible in the tally instead.
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
	offPersist bool
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
  fdev=$(stat -Lc "%d" "$f" 2>/dev/null)
  off=0
  if [ -n "$fdev" ] && [ -n "$PDEV" ] && [ "$fdev" != "$PDEV" ]; then
    off=1
    echo "CRITBLK-OFF-PERSIST f=/persist/$f dev=$fdev persistdev=$PDEV real=$(readlink -f "$f" 2>/dev/null) mnt=$(df "$f" 2>/dev/null | tail -1 | awk '{print $NF}')"
  fi
  echo "CRITBLK f=/persist/$f size=${sz:-0} ext=${ne:-0} lo4k=${lo:--1} hi4k=${hi:--1} off=$off"
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

// recordCriticalBlocks captures the placement and logs it in the form the soak
// report reads back: the resize campaign's `reloc-high verify:` count and its
// PASS/FAIL/SKIP verdict on whether this run has any critical relocation to
// observe at all.
func recordCriticalBlocks(device *evetest.EdgeDevice, label string,
	boundary4k int64) criticalSnapshot {
	snap := captureCriticalBlocks(device, label, boundary4k)
	log := evetest.Logger()
	log.Infof("critical-blocks[%s]: /persist %d fs-blocks (4KiB, dumpe2fs Block "+
		"count = shrink boundary; df-derived %d excludes metadata), boundary %d, "+
		"%d critical file(s)\n%s",
		label, snap.fsBlocks4k, snap.dfBlocks4k, boundary4k, len(snap.files), snap.raw)

	high := snap.high()
	log.Infof("reloc-high verify: %d/%d critical files above block %d (%s)",
		len(high), len(snap.files), boundary4k, label)
	switch verdict, why := criticalStagingVerdict(snap); verdict {
	case "SKIP":
		log.Infof("reloc-high ASSERT: SKIP -- %s", why)
	case "FAIL":
		log.Infof("reloc-high ASSERT: FAIL -- %s", why)
	default:
		log.Infof("reloc-high ASSERT: PASS -- %s", why)
	}
	return snap
}

// criticalStagingVerdict says whether this run can observe the shrink
// relocating a critical file. PASS means at least one lies in the evacuation
// zone; FAIL means none does, so a clean digest afterwards shows the criticals
// were left alone rather than moved intact; SKIP means the question does not
// apply or could not be read.
func criticalStagingVerdict(s criticalSnapshot) (string, string) {
	switch {
	case !s.haveFrag:
		return "SKIP", "filefrag absent from the pillar image, placement unverified"
	case len(s.files) == 0:
		return "SKIP", "no critical files found under /persist"
	case s.boundary4k <= 0:
		return "SKIP", "no shrink boundary for this route, nothing to relocate past"
	case len(s.high()) == 0:
		return "FAIL", fmt.Sprintf(
			"all %d critical files sit below block %d, so the shrink will not "+
				"relocate any of them and a clean digest afterwards says only that "+
				"they were left alone", len(s.files), s.boundary4k)
	default:
		return "PASS", fmt.Sprintf("%d of %d critical files lie above block %d",
			len(s.high()), len(s.files), s.boundary4k)
	}
}

// logCriticalRelocation compares the two captures and emits the single tally
// line the soak driver banks per run.
//
// moved counts the files whose physical blocks changed across the conversion,
// which is what actually witnesses the relocation; movedHigh restricts that to
// the ones that were in the evacuation zone beforehand, and is the number a
// reader should weigh -- a volatile file rewritten by pillar during the
// conversion also "moves" without the shrink having anything to do with it.
// stranded counts criticals left above the boundary afterwards, which a
// successful shrink cannot leave behind and a non-zero count therefore points
// at the boundary reading rather than at the data.
func logCriticalRelocation(before, after criticalSnapshot) {
	log := evetest.Logger()
	boundary := before.boundary4k
	beforeHigh := before.high()

	var moved, movedHigh int
	var detail []string
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
		if a.lo4k == b.lo4k && a.hi4k == b.hi4k {
			continue
		}
		moved++
		mark := ""
		if boundary > 0 && b.hi4k >= boundary {
			movedHigh++
			mark = " [was above the boundary]"
		}
		detail = append(detail, fmt.Sprintf("%s: %d..%d -> %d..%d%s",
			path, b.lo4k, b.hi4k, a.lo4k, a.hi4k, mark))
	}
	// Counted on the AFTER snapshot: this asks what the conversion left above
	// the boundary, which includes a critical that only exists afterwards.
	var stranded int
	if boundary > 0 {
		for path, f := range after.files {
			if !offPersistPaths[path] && f.hi4k >= boundary {
				stranded++
			}
		}
	}

	if len(detail) > 0 {
		sort.Strings(detail)
		log.Infof("critical-blocks moved across the conversion:\n  %s",
			strings.Join(detail, "\n  "))
	}
	log.Infof("reloc-high moved: %d/%d critical files relocated by the conversion "+
		"(%d of the %d staged above block %d)",
		moved, len(before.files), movedHigh, len(beforeHigh), boundary)

	verdict, _ := criticalStagingVerdict(before)
	log.Infof("%s boundary4k=%d files=%d high=%d top4k=%d moved=%d moved-high=%d "+
		"stranded=%d offpersist=%d filefrag=%t assert=%s",
		criticalBlocksTally, boundary, len(before.files), len(beforeHigh),
		before.top4k(), moved, movedHigh, stranded, len(offPersistPaths),
		before.haveFrag, verdict)
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
