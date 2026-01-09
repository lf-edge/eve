// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"os"
	"strings"
)

// getFlavorFromKernelVersion extracts flavor from kernel version string
// e.g. 6.12.49-linuxkit-core-ef7ccc4d151c -> core
func getFlavorFromKernelVersion(version string) string {
	parts := strings.Split(version, "-")
	for i, part := range parts {
		if part == "linuxkit" && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	// In case the version string does not follow the expected pattern
	// still try to identify common flavors
	if strings.Contains(version, "-core") {
		return "core"
	}
	if strings.Contains(version, "-hwe") {
		return "hwe"
	}
	if strings.Contains(version, "-rt") {
		return "rt"
	}
	return ""
}

// GetKernelVersion reads and returns the kernel version from /proc/sys/kernel/osrelease
func GetKernelVersion() string {
	out, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// GetKernelCmdline reads and returns the kernel command line from /proc/cmdline
func GetKernelCmdline() string {
	out, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// GetKernelFlavor tries to deduce the kernel flavor
func GetKernelFlavor() string {
	// Try to deduce from kernel version or /proc/version
	version := GetKernelVersion()
	if flavor := getFlavorFromKernelVersion(version); flavor != "" {
		return flavor
	}

	// Check /proc/version for more details
	out, err := os.ReadFile("/proc/version")
	if err == nil {
		content := string(out)
		if strings.Contains(content, "PREEMPT_RT") {
			return "rt"
		}
	}
	return "pc"
}
