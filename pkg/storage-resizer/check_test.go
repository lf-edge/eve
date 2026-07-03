// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"testing"
)

// smallFront is a pre-conversion boot-disk layout: tiny ESP + small IMGA/IMGB +
// CONFIG, no P3 (persist lives elsewhere or is ZFS).
var smallFront = []partSpec{
	{labelESP, 10 << 20},
	{labelIMGA, 300 << 20},
	{labelIMGB, 300 << 20},
	{"CONFIG", 5 << 20},
}

func TestEvaluateMultiDiskAndZFS(t *testing.T) {
	const otherDisk = "/dev/sdb" // never opened by evaluate; only compared to --disk

	cases := []struct {
		name        string
		parts       []partSpec
		diskSize    int64
		persistDisk string
		persistType string
		wantDec     string
	}{
		{
			name:        "multi-disk ext4, boot has free tail -> grow",
			parts:       smallFront,
			diskSize:    30 * GiB,
			persistDisk: otherDisk,
			persistType: "ext4",
			wantDec:     "grow",
		},
		{
			name:        "multi-disk ext4, boot has no tail -> insufficient",
			parts:       smallFront,
			diskSize:    22*GiB + 200*(1<<20),
			persistDisk: otherDisk,
			persistType: "ext4",
			wantDec:     "insufficient",
		},
		{
			name:        "multi-disk ZFS, boot has free tail -> grow",
			parts:       smallFront,
			diskSize:    30 * GiB,
			persistDisk: otherDisk,
			persistType: "zfs",
			wantDec:     "grow",
		},
		{
			name:        "multi-disk ZFS, boot has no tail -> insufficient",
			parts:       smallFront,
			diskSize:    22*GiB + 200*(1<<20),
			persistDisk: otherDisk,
			persistType: "zfs",
			wantDec:     "insufficient",
		},
		{
			name:        "single-disk ZFS persist on boot, no tail -> insufficient (no ZFS shrink)",
			parts:       append(append([]partSpec{}, smallFront...), partSpec{labelPersist, 21 * GiB}),
			diskSize:    22*GiB + 200*(1<<20),
			persistDisk: "", // same as boot
			persistType: "zfs",
			wantDec:     "insufficient",
		},
		{
			name:        "already EVE-k geometry incl ESP-B -> proceed",
			parts:       []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelIMGB, 10 * GiB}, {"ESP-B", 2 * GiB}, {labelPersist, 1 * GiB}},
			diskSize:    40 * GiB,
			persistDisk: "",
			persistType: "ext4",
			wantDec:     "proceed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "boot.img")
			buildGPTImage(t, path, c.diskSize, c.parts)
			rep, err := evaluate(checkParams{
				disk: path, persistDisk: c.persistDisk, persistType: c.persistType,
				persistLbl: labelPersist, need: 22 * GiB, maxFull: 90, sector: testSector,
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if rep.Decision != c.wantDec {
				t.Errorf("decision = %q (%s), want %q", rep.Decision, rep.DecisionReason, c.wantDec)
			}
			// shrink must never be attempted when persist is ZFS or on another disk
			if (c.persistType == "zfs" || c.persistDisk != "") && rep.ShrinkApplicable {
				t.Errorf("shrink marked applicable for persistType=%s persistDisk=%q", c.persistType, c.persistDisk)
			}
		})
	}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		rep  checkReport
		want string
	}{
		{"large in place", checkReport{Large: LargeResult{InPlace: true}}, "proceed"},
		{"space ok", checkReport{Space: SpaceResult{OK: true}}, "grow"},
		{"shrinkable ok", checkReport{ShrinkApplicable: true, Shrink: &ShrinkResult{OK: true}}, "shrink"},
		{"shrinkable but too full", checkReport{ShrinkApplicable: true, Shrink: &ShrinkResult{OK: false}}, "insufficient"},
		{"not applicable", checkReport{ShrinkApplicable: false, ShrinkReason: "persist is ZFS"}, "insufficient"},
		{"space wins over shrinkable", checkReport{Space: SpaceResult{OK: true}, ShrinkApplicable: true, Shrink: &ShrinkResult{OK: true}}, "grow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := decide(c.rep)
			if got != c.want {
				t.Errorf("decide = %q, want %q", got, c.want)
			}
		})
	}
}
