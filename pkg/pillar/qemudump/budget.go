// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

const (
	// budgetHeadroomPercent is the fraction of the compressor's available
	// memory (pillar's cgroup headroom) that the zstd window(s) may claim. Kept
	// small so the crash-time compressor leaves most of the headroom untouched
	// — the window is anonymous, non-reclaimable memory, and blowing pillar's
	// cgroup limit OOM-kills zedbox and reboots the device.
	budgetHeadroomPercent = 25
	// budgetHardCapBytes is the absolute ceiling on the compressor memory
	// budget, independent of headroom — a bigger window is a marginal ratio
	// gain per the design. On a tight cgroup the headroom fraction (not this
	// cap) is what binds; on a device with real headroom the window can grow up
	// to this.
	budgetHardCapBytes uint64 = 512 << 20
)

// ComputeBudget returns the compressor memory budget: budgetHeadroomPercent of
// availBytes, hard-capped at budgetHardCapBytes. availBytes MUST be the memory
// actually available to pillar (its cgroup headroom = limit - usage), NOT
// system-wide free RAM — the window is charged to pillar's cgroup and must fit
// its headroom or the kernel OOM-kills zedbox. Feed the result to
// ChooseWindowLog. A small or zero budget is fine — ChooseWindowLog floors the
// window at a negligible-RAM size.
func ComputeBudget(availBytes uint64) uint64 {
	budget := availBytes * budgetHeadroomPercent / 100
	if budget > budgetHardCapBytes {
		budget = budgetHardCapBytes
	}
	return budget
}
