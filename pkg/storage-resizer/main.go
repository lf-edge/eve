// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command storage-resizer is the EVE-kvm -> EVE-k repartition helper. It is
// invoked offline from storage-init (when /persist must be shrunk) and online
// from baseosmgr (when only a grow is needed); baseosmgr also calls its `check`
// subcommand for the pre-flight size decision.
//
// All dependence on go-diskfs/partitionresizer stays inside this one binary and
// out of pillar: the shrink/grow subcommands drive
// github.com/diskfs/partitionresizer here so pillar never imports it. The
// subcommands are check, backup, shrink, grow, restore, and cleanup.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		os.Exit(cmdCheck(os.Args[2:]))
	case "shrink":
		os.Exit(cmdShrink(os.Args[2:]))
	case "grow":
		os.Exit(cmdGrow(os.Args[2:]))
	case "backup":
		os.Exit(cmdBackup(os.Args[2:]))
	case "restore":
		os.Exit(cmdRestore(os.Args[2:]))
	case "cleanup":
		os.Exit(cmdCleanup(os.Args[2:]))
	case "run-watchdog":
		os.Exit(cmdRunWatchdog(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  storage-resizer check   --disk <path> [--persist-disk <path>] [--persist-type ext4|zfs|auto] [--need 22G] [--max-full 90] [--json]")
	fmt.Fprintln(os.Stderr, "  storage-resizer backup  [--persist /persist] [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress] (--target 78G | --grow-only)")
	fmt.Fprintln(os.Stderr, "  storage-resizer shrink  --disk <path> (--shrink-to 78G | --flag-file /config/repartition-inprogress) [--dry-run]   (storage-init/offline)")
	fmt.Fprintln(os.Stderr, "  storage-resizer grow    --disk <path> [--esp 2G] [--imga 10G] [--imgb 10G] [--dry-run]                     (baseosmgr/online)")
	fmt.Fprintln(os.Stderr, "  storage-resizer restore [--persist /persist] [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress] [--failure-marker /config/resize-failed.json] [--persist-recreated] [--cleanup]")
	fmt.Fprintln(os.Stderr, "  storage-resizer cleanup [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress]")
	fmt.Fprintln(os.Stderr, "  storage-resizer run-watchdog [--timeout 30] [--interval 10s] [--no-pet]   (background; feeds /dev/watchdog until signaled)")
}

// checkReport is the machine-readable result of the pre-flight check.
type checkReport struct {
	Disk        string      `json:"disk"`
	DiskSize    int64       `json:"diskSizeBytes"`
	Partitions  []Partition `json:"partitions"`
	PersistDisk string      `json:"persistDisk"`
	PersistType string      `json:"persistType"` // ext4 | zfs | unknown
	Large       LargeResult `json:"largePartitionsInPlace"`
	Space       SpaceResult `json:"spaceForLargePartitions"`
	// ShrinkApplicable is false in the multi-disk and ZFS cases, where shrinking
	// /persist cannot free space on the boot disk; ShrinkReason then explains why.
	ShrinkApplicable bool          `json:"shrinkApplicable"`
	ShrinkReason     string        `json:"shrinkReason,omitempty"`
	Shrink           *ShrinkResult `json:"spaceToShrinkExt,omitempty"`
	// Decision is the recommended next step (proceed | grow | shrink | insufficient).
	Decision       string `json:"decision"`
	DecisionReason string `json:"decisionReason"`
}

// checkParams are the resolved inputs to evaluate.
type checkParams struct {
	disk        string // boot disk (carries ESP/IMGA/IMGB)
	persistDisk string // where /persist lives ("" or == disk means on the boot disk)
	persistType string // ext4 | zfs | unknown
	persistLbl  string
	need        int64
	maxFull     int // resulting persist fs must be <= this % full after shrinking
	sector      int64
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	disk := fs.String("disk", "", "boot disk image or block device (carries ESP/IMGA/IMGB) (required)")
	persistDisk := fs.String("persist-disk", "", "disk holding /persist, if different from --disk (multi-disk installs)")
	persistType := fs.String("persist-type", "auto", "ext4|zfs|auto (auto reads /run/eve.persist_type)")
	persistLabel := fs.String("persist-label", labelPersist, "GPT label of the persist partition")
	needStr := fs.String("need", "auto", "space the new partitions need; \"auto\" computes it per-disk from which targets are absent/undersized")
	maxFull := fs.Int("max-full", 90, "max %% the persist fs may be full after shrinking")
	sector := fs.Int64("sector", 512, "logical sector size")
	asJSON := fs.Bool("json", false, "emit JSON")
	_ = fs.Parse(args)

	if *disk == "" {
		usage()
		return 2
	}
	need := int64(-1) // sentinel: compute per-disk in evaluate
	if *needStr != "auto" {
		v, err := parseSize(*needStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad --need:", err)
			return 2
		}
		need = v
	}

	rep, err := evaluate(checkParams{
		disk: *disk, persistDisk: *persistDisk,
		persistType: resolvePersistType(*persistType),
		persistLbl:  *persistLabel, need: need, maxFull: *maxFull, sector: *sector,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printHuman(rep)
	}
	return 0
}

// evaluate runs the three size checks and the multi-disk/ZFS-aware decision.
func evaluate(p checkParams) (checkReport, error) {
	parts, diskSize, err := readGPT(p.disk, p.sector)
	if err != nil {
		return checkReport{}, fmt.Errorf("read GPT of boot disk %s: %w", p.disk, err)
	}
	rep := checkReport{
		Disk: p.disk, DiskSize: diskSize, Partitions: parts,
		PersistDisk: p.persistDisk, PersistType: p.persistType,
	}
	// Compute the space needed per-disk (absent/undersized targets) unless the
	// caller pinned it with --need.
	need := p.need
	if need < 0 {
		need = neededBytes(parts)
	}
	rep.Large = LargePartitionsInPlace(parts)
	rep.Space = SpaceForLargePartitions(parts, diskSize, p.sector, need)

	// Shrinking /persist only frees space on the boot disk when /persist is an
	// ext4 partition ON the boot disk. In multi-disk installs (persist on another
	// disk) or with a ZFS persist, the shrink path does not apply — the room must
	// come from the boot disk's free tail instead.
	persistOnBoot := p.persistDisk == "" || p.persistDisk == p.disk
	p3, hasP3 := partByName(parts, p.persistLbl)
	switch {
	case !persistOnBoot:
		rep.ShrinkReason = "persist is on a different disk (" + p.persistDisk + "); using boot-disk free space instead"
	case p.persistType == "zfs":
		rep.ShrinkReason = "persist is ZFS (shrinking ZFS is not supported)"
	case !hasP3:
		rep.ShrinkReason = "no " + p.persistLbl + " partition on the boot disk (persist likely ZFS/another disk)"
	default:
		sr, err := SpaceToShrinkExt(p.disk, int64(p3.FirstLBA)*p.sector, need, p.maxFull)
		if err != nil {
			// e.g. ZFS we were not told about: not an ext4 superblock
			rep.ShrinkReason = "persist not shrinkable: " + err.Error()
		} else {
			rep.ShrinkApplicable = true
			rep.Shrink = &sr
		}
	}
	rep.Decision, rep.DecisionReason = decide(rep)
	return rep, nil
}

// decide maps the check results to the recommended next step and a reason.
func decide(rep checkReport) (string, string) {
	switch {
	case rep.Large.InPlace:
		return "proceed", "boot disk already has the EVE-k geometry"
	case rep.Space.OK:
		return "grow", "boot disk has enough free tail; create the partitions without shrinking"
	case rep.ShrinkApplicable && rep.Shrink != nil && rep.Shrink.OK:
		return "shrink", "shrink the ext4 /persist on the boot disk to make room, then grow"
	case rep.ShrinkApplicable:
		return "insufficient", "persist is too full to free the needed space"
	default:
		return "insufficient", rep.ShrinkReason
	}
}

// resolvePersistType resolves the persist filesystem type: an explicit ext4/zfs
// flag wins; "auto"/"" consults /run/eve.persist_type (set by storage-init);
// otherwise "unknown".
func resolvePersistType(flagVal string) string {
	if flagVal != "" && flagVal != "auto" {
		return normalizePersistType(flagVal)
	}
	if b, err := os.ReadFile("/run/eve.persist_type"); err == nil {
		return normalizePersistType(strings.TrimSpace(string(b)))
	}
	return "unknown"
}

func normalizePersistType(s string) string {
	switch s {
	case "ext2", "ext3", "ext4":
		return "ext4"
	case "zfs", "zfs_member":
		return "zfs"
	default:
		return s
	}
}

func printHuman(rep checkReport) {
	fmt.Printf("disk %s (%s)\n", rep.Disk, human(rep.DiskSize))
	for _, p := range rep.Partitions {
		fmt.Printf("  [%d] %-12s %s\n", p.Index, p.Name, human(p.SizeBytes))
	}
	fmt.Printf("persist: type=%s disk=%s\n", rep.PersistType, persistDiskStr(rep))
	fmt.Printf("large-partitions-in-place: %v (ESP=%s IMGA=%s IMGB=%s)\n",
		rep.Large.InPlace, human(rep.Large.ESP), human(rep.Large.IMGA), human(rep.Large.IMGB))
	fmt.Printf("space-for-large-partitions: %v (free tail %s, need %s)\n",
		rep.Space.OK, human(rep.Space.FreeTailBytes), human(rep.Space.NeededBytes))
	if rep.Shrink != nil {
		fmt.Printf("space-to-shrink-ext: %v (used %s of %s; after freeing %s -> %s, result %d%% full, max %d%%; floor ~%s, margin %s)\n",
			rep.Shrink.OK, human(rep.Shrink.UsedBytes), human(rep.Shrink.TotalBytes),
			human(rep.Shrink.NeededBytes), human(rep.Shrink.TargetBytes),
			rep.Shrink.ResultPercent, rep.Shrink.MaxFullPercent,
			human(rep.Shrink.FloorEstBytes), human(rep.Shrink.MarginBytes))
	} else {
		fmt.Printf("space-to-shrink-ext: n/a (%s)\n", rep.ShrinkReason)
	}
	fmt.Printf("decision: %s (%s)\n", rep.Decision, rep.DecisionReason)
}

func persistDiskStr(rep checkReport) string {
	if rep.PersistDisk == "" {
		return rep.Disk + " (same as boot)"
	}
	return rep.PersistDisk
}

// parseSize parses sizes like "22G", "300M", "512", with binary K/M/G/T suffixes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult = 1 << 10
	case 'M', 'm':
		mult = 1 << 20
	case 'G', 'g':
		mult = 1 << 30
	case 'T', 't':
		mult = 1 << 40
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

// human renders a byte count in binary units.
func human(b int64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(b)/float64(div), "KMGT"[exp])
}
