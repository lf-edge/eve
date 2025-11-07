// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/spf13/afero"
)

const (
	// InventoryBaseDir is the base directory for inventory collection
	InventoryBaseDir = "/persist/eval"
)

var (
	// Paths to debug container scripts (mounted via rootfs.yml.in)
	// These are variables so they can be overridden in tests

	// IOMmuGroupsScript is the path to the IOMMU groups collection script
	IOMmuGroupsScript = "/debug/usr/bin/iommu-groups.sh"
	// SpecScript is the path to the hardware specification collection script
	SpecScript = "/debug/usr/bin/spec.sh"
)

// InventoryCollector manages hardware inventory collection
type InventoryCollector struct {
	log *base.LogObject
	fs  afero.Fs
}

// NewInventoryCollector creates a new inventory collector
func NewInventoryCollector(log *base.LogObject, fs afero.Fs) *InventoryCollector {
	return &InventoryCollector{
		log: log,
		fs:  fs,
	}
}

// CollectInventory collects hardware inventory for the current partition
// and stores it in /persist/eval/<partition>-<timestamp>/
func (ic *InventoryCollector) CollectInventory(slot string) error {
	ic.log.Functionf("CollectInventory: Starting inventory collection for %s", slot)

	// Create timestamped directory
	timestamp := time.Now().Format("2006-01-02-15:04")
	inventoryDir := filepath.Join(InventoryBaseDir, fmt.Sprintf("%s-%s", slot, timestamp))

	if err := ic.fs.MkdirAll(inventoryDir, 0755); err != nil {
		return fmt.Errorf("failed to create inventory directory %s: %w", inventoryDir, err)
	}

	ic.log.Noticef("CollectInventory: Created directory %s", inventoryDir)

	// Collect all inventory items
	items := []struct {
		name    string
		command func() ([]byte, error)
	}{
		{
			name: "lspci.txt",
			command: func() ([]byte, error) {
				return exec.Command("lspci", "-kvv").CombinedOutput()
			},
		},
		{
			name: "lsusb.txt",
			command: func() ([]byte, error) {
				return exec.Command("lsusb", "-v").CombinedOutput()
			},
		},
		{
			name: "lsmod.txt",
			command: func() ([]byte, error) {
				return exec.Command("lsmod").CombinedOutput()
			},
		},
		{
			name: "dmidecode.txt",
			command: func() ([]byte, error) {
				return exec.Command("dmidecode").CombinedOutput()
			},
		},
		{
			name: "dmesg.txt",
			command: func() ([]byte, error) {
				return exec.Command("dmesg").CombinedOutput()
			},
		},
		{
			name: "cmdline.txt",
			command: func() ([]byte, error) {
				return os.ReadFile("/proc/cmdline")
			},
		},
		{
			name: "iommu-groups.txt",
			command: func() ([]byte, error) {
				return exec.Command(IOMmuGroupsScript).CombinedOutput()
			},
		},
		{
			name: "inventory.json",
			command: func() ([]byte, error) {
				return exec.Command(SpecScript).CombinedOutput()
			},
		},
	}

	// Collect each item
	for _, item := range items {
		outputPath := filepath.Join(inventoryDir, item.name)
		ic.log.Functionf("CollectInventory: Collecting %s", item.name)

		output, err := item.command()
		if err != nil {
			// Log error but continue with other items
			ic.log.Warnf("CollectInventory: Failed to collect %s: %v (output: %s)",
				item.name, err, string(output))
			// Write error message to file so we know it was attempted
			errMsg := fmt.Sprintf("Error collecting data: %v\nOutput: %s\n", err, string(output))
			if writeErr := afero.WriteFile(ic.fs, outputPath, []byte(errMsg), 0644); writeErr != nil {
				ic.log.Errorf("CollectInventory: Failed to write error file %s: %v",
					outputPath, writeErr)
			}
			continue
		}

		// Write output to file
		if err := afero.WriteFile(ic.fs, outputPath, output, 0644); err != nil {
			ic.log.Errorf("CollectInventory: Failed to write %s: %v", outputPath, err)
			continue
		}

		ic.log.Functionf("CollectInventory: Successfully collected %s (%d bytes)",
			item.name, len(output))
	}

	ic.log.Noticef("CollectInventory: Completed inventory collection for %s in %s",
		slot, inventoryDir)
	return nil
}

// GetInventoryDir returns the path to the most recent inventory directory for a slot
// Returns empty string if no inventory found
func (ic *InventoryCollector) GetInventoryDir(slot string) string {
	// List all directories matching the pattern
	entries, err := afero.ReadDir(ic.fs, InventoryBaseDir)
	if err != nil {
		return ""
	}

	// Find directories that match the slot prefix
	prefix := fmt.Sprintf("%s-", slot)
	latest := ""
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.HasPrefix(name, prefix) {
			fullPath := filepath.Join(InventoryBaseDir, name)
			if fullPath > latest {
				latest = fullPath
			}
		}
	}

	return latest
}

// CleanupOldInventories removes inventory directories older than the specified duration
func (ic *InventoryCollector) CleanupOldInventories(maxAge time.Duration) error {
	ic.log.Functionf("CleanupOldInventories: Cleaning up inventories older than %v", maxAge)

	entries, err := afero.ReadDir(ic.fs, InventoryBaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist yet, nothing to clean
		}
		return fmt.Errorf("failed to read inventory directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dirPath := filepath.Join(InventoryBaseDir, entry.Name())
		info, err := ic.fs.Stat(dirPath)
		if err != nil {
			ic.log.Warnf("CleanupOldInventories: Failed to get info for %s: %v",
				dirPath, err)
			continue
		}

		if info.ModTime().Before(cutoff) {
			ic.log.Noticef("CleanupOldInventories: Removing old inventory %s (age: %v)",
				dirPath, time.Since(info.ModTime()))
			if err := ic.fs.RemoveAll(dirPath); err != nil {
				ic.log.Errorf("CleanupOldInventories: Failed to remove %s: %v",
					dirPath, err)
				continue
			}
			removed++
		}
	}

	if removed > 0 {
		ic.log.Noticef("CleanupOldInventories: Removed %d old inventory directories", removed)
	}

	return nil
}
