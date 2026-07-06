// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package qemudump owns the on-device storage lifecycle for qemu/KVM
// post-mortem artifacts (guest cores, qemu process cores). It compresses dump
// streams in-process with zstd, enforces a disk quota on the fly, and rotates
// old dumps — so diagnostics can be left on by default without ever threatening
// device management.
package qemudump

const (
	// minWindowLog / maxWindowLog bound the zstd window exponent. 20 (1 MiB) is
	// a negligible-RAM floor; 28 (256 MiB) is the ceiling (a larger window is a
	// marginal ratio gain per the design). The memory budget (ComputeBudget),
	// sized from the caller's available memory, is what actually picks the
	// window — small on a tight cgroup, larger when there is real headroom.
	minWindowLog uint8 = 20
	maxWindowLog uint8 = 28

	// encoderRAMPerWindow conservatively estimates the encoder's resident
	// (anonymous, non-reclaimable) memory as a multiple of the window size
	// (window + hash/match tables + block buffers). Overestimating keeps the
	// crash-time compressor from OOM-killing pillar in its cgroup.
	encoderRAMPerWindow = 3
)

// ChooseWindowLog returns the largest zstd windowLog whose estimated encoder
// RAM — encoderRAMPerWindow * window * concurrency — fits within budgetBytes,
// clamped to [minWindowLog, maxWindowLog]. If even the floor window does not
// fit, the floor is returned (a 1 MiB window costs negligible RAM). concurrency
// <= 0 is treated as a single worker.
func ChooseWindowLog(budgetBytes uint64, concurrency int) uint8 {
	if concurrency < 1 {
		concurrency = 1
	}
	best := minWindowLog
	for wl := minWindowLog; wl <= maxWindowLog; wl++ {
		ram := uint64(encoderRAMPerWindow) * (uint64(1) << wl) * uint64(concurrency)
		if ram <= budgetBytes {
			best = wl
		}
	}
	return best
}
