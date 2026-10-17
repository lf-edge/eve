// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command volverify writes and later verifies a deterministic, self-describing
// fill/delete pattern on an application volume, to detect corruption caused by a
// watchdog-interrupted EVE-kvm→EVE-k offline filesystem shrink.
//
// It is deployed inside the evetest test app and driven over SSH:
//
//	volverify write  --dir /mnt/data --seed 42 --ops 100000
//	volverify verify --dir /mnt/data --seed 42 --ops 100000
//
// write is crash-safe and resumable: run it repeatedly across reboots. verify
// exits non-zero when it finds any anomaly and prints a machine-readable summary.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lf-edge/eve/evetest/testapps/volverify/internal/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "", "volume mount point to operate on (required)")
	def := verify.DefaultConfig()
	seed := fs.Uint64("seed", def.Seed, "master seed for the op stream")
	ops := fs.Uint64("ops", def.Ops, "number of ops to apply / expect")
	commitEvery := fs.Uint64("commit-every", def.CommitEvery, "fsync + commit cadence in ops")
	blockSize := fs.Int("block-size", def.BlockSize, "on-disk block size in bytes")
	dirFanout := fs.Int("dir-fanout", def.DirFanout, "per-level file-tree fan-out")
	smallBlocks := fs.Int("small-blocks", def.SmallBlocks, "max blocks for a small file")
	medBlocks := fs.Int("med-blocks", def.MedBlocks, "max blocks for a medium file")
	maxBlocks := fs.Int("max-blocks", def.MaxBlocks, "max blocks for a large file")
	expectCommitted := fs.Int64("expect-committed", def.ExpectCommitted,
		"verify: floor on the committed op index (harness high-water mark); -1 = trust on-volume commit only")
	_ = fs.Parse(os.Args[2:])

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: --dir is required")
		os.Exit(2)
	}
	cfg := verify.Config{
		Seed:            *seed,
		BlockSize:       *blockSize,
		Ops:             *ops,
		CommitEvery:     *commitEvery,
		DirFanout:       *dirFanout,
		SmallBlocks:     *smallBlocks,
		MedBlocks:       *medBlocks,
		MaxBlocks:       *maxBlocks,
		ExpectCommitted: *expectCommitted,
	}

	switch cmd {
	case "write":
		w, err := verify.NewWriter(*dir, cfg)
		if err != nil {
			fatal(err)
		}
		committed, err := w.Run()
		if err != nil {
			fatal(err)
		}
		fmt.Printf("write: complete committed=%d\n", committed)
	case "verify":
		rep, err := verify.Verify(*dir, cfg)
		if err != nil {
			fatal(err)
		}
		fmt.Println(rep.String())
		for _, a := range rep.Anomalies {
			fmt.Printf("  ANOMALY file=%d verdict=%s path=%s expBlocks=%d sizeMismatch=%v blocks=%v\n",
				a.FileID, a.Verdict, a.Path, a.ExpectBlocks, a.SizeMismatch, blockCountsString(a.BlockCounts))
		}
		for _, id := range rep.Resurrected {
			fmt.Printf("  ANOMALY resurrected file=%d\n", id)
		}
		if !rep.Clean() {
			os.Exit(1)
		}
		fmt.Println("verify: clean")
	default:
		usage()
		os.Exit(2)
	}
}

func blockCountsString(m map[verify.BlockStatus]int) string {
	out := ""
	for s, n := range m {
		if s == verify.BlockOK {
			continue
		}
		out += fmt.Sprintf("%s=%d ", s, n)
	}
	if out == "" {
		return "-"
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: volverify <write|verify> --dir <mount> [--seed N --ops N ...]")
}
