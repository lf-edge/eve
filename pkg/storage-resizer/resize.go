// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// The repartition mechanics, split into two subcommands that run in different
// contexts, each driving github.com/diskfs/partitionresizer:
//
//	shrink  shrink the ext4 persist partition in place to the target size,
//	        freeing space at the end of the disk. Runs with /persist UNMOUNTED,
//	        so it is called from storage-init in early boot (single-disk ext4).
//	grow    grow ESP/IMGA/IMGB into the freed space, preserving their original
//	        partition numbers (partitionresizer copies content to relocated
//	        slots, then does one rename+delete GPT write). Does not need /persist
//	        unmounted, so it is called from baseosmgr (online) or from
//	        storage-init right after the shrink.
//
// Each is a partitionresizer.Run call that re-plans from the live GPT, so a
// crash between or within them is recovered by re-running.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	pr "github.com/diskfs/partitionresizer"
)

// exitRebootToApply is returned by shrink/grow when the new partition table was
// committed to disk but the kernel could not re-read it live because the boot
// disk is busy (a partition is mounted -- repartitioning the disk we booted
// from). The on-disk table is correct; storage-init treats this as "reboot to
// apply" rather than a failure.
const exitRebootToApply = 64

// cmdShrink shrinks the persist partition (storage-init / offline).
func cmdShrink(args []string) int {
	fs := flag.NewFlagSet("shrink", flag.ExitOnError)
	disk := fs.String("disk", "", "boot disk image or block device (required)")
	shrinkTo := fs.String("shrink-to", "", "target persist size, e.g. 78G")
	flagFile := fs.String("flag-file", "", "read the target from this file if present and non-empty (e.g. /config/repartition-inprogress); overrides --shrink-to")
	persistLabel := fs.String("persist-label", labelPersist, "persist partition GPT label")
	fixErrors := fs.Bool("fix-errors", false, "let fsck repair the persist filesystem before shrinking")
	dryRun := fs.Bool("dry-run", false, "plan only; do not modify the disk")
	_ = fs.Parse(args)

	if *disk == "" {
		usage()
		return 2
	}
	// A non-empty flag file wins (the storage-init path), else --shrink-to.
	target := *shrinkTo
	if *flagFile != "" {
		if v, ok := readFlagFile(*flagFile); ok {
			target = v
		}
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "shrink: no target (set --shrink-to or a non-empty --flag-file)")
		return 2
	}
	sz, err := parseSize(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "shrink: bad target:", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "shrink %s to %s\n", *persistLabel, target)
	changes := []pr.PartitionChange{pr.NewPartitionChange(pr.IdentifierByLabel, *persistLabel, sz)}
	if err := pr.Run(*disk, nil, changes, *fixErrors, *dryRun, false); err != nil {
		if errors.Is(err, pr.ErrRebootToApply) {
			fmt.Fprintln(os.Stderr, "shrink: GPT committed, reboot required to apply:", err)
			return exitRebootToApply
		}
		fmt.Fprintln(os.Stderr, "shrink failed:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "shrink complete")
	return 0
}

// cmdGrow grows ESP/IMGA/IMGB into freed space (baseosmgr/online or post-shrink).
func cmdGrow(args []string) int {
	fs := flag.NewFlagSet("grow", flag.ExitOnError)
	disk := fs.String("disk", "", "boot disk image or block device (required)")
	espSize := fs.String("esp", "2G", "target ESP size")
	imgaSize := fs.String("imga", "10G", "target IMGA size")
	imgbSize := fs.String("imgb", "10G", "target IMGB size")
	espLabel := fs.String("esp-label", labelESP, "ESP partition GPT label")
	fixErrors := fs.Bool("fix-errors", false, "let fsck repair source filesystems before copying")
	dryRun := fs.Bool("dry-run", false, "plan only; do not modify the disk")
	_ = fs.Parse(args)

	if *disk == "" {
		usage()
		return 2
	}
	changes := []pr.PartitionChange{
		pr.NewPartitionChange(pr.IdentifierByLabel, *espLabel, mustParseSize("esp", *espSize)),
		pr.NewPartitionChange(pr.IdentifierByLabel, labelIMGA, mustParseSize("imga", *imgaSize)),
		pr.NewPartitionChange(pr.IdentifierByLabel, labelIMGB, mustParseSize("imgb", *imgbSize)),
	}
	fmt.Fprintf(os.Stderr, "grow %s=%s IMGA=%s IMGB=%s\n", *espLabel, *espSize, *imgaSize, *imgbSize)
	if err := pr.Run(*disk, nil, changes, *fixErrors, *dryRun, true); err != nil {
		if errors.Is(err, pr.ErrRebootToApply) {
			fmt.Fprintln(os.Stderr, "grow: GPT committed, reboot required to apply:", err)
			return exitRebootToApply
		}
		fmt.Fprintln(os.Stderr, "grow failed:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "grow complete")
	return 0
}

// readFlagFile returns the trimmed contents of path and whether it exists with
// non-empty content (the design gates the shrink on a non-zero-length
// /config/repartition-inprogress).
func readFlagFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(b))
	return s, s != ""
}

func mustParseSize(name, s string) int64 {
	n, err := parseSize(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad --%s: %v\n", name, err)
		os.Exit(2)
	}
	return n
}
