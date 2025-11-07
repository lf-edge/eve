// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

func TestInventoryCollector(t *testing.T) {
	// Create test logger
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 0)

	// Use in-memory filesystem for testing
	fs := afero.NewMemMapFs()

	t.Run("CollectInventory creates directory structure", func(t *testing.T) {
		collector := NewInventoryCollector(log, fs)

		// Collect inventory for IMGA
		err := collector.CollectInventory("IMGA")
		if err != nil {
			t.Fatalf("CollectInventory failed: %v", err)
		}

		// Check that directory was created
		entries, err := afero.ReadDir(fs, InventoryBaseDir)
		if err != nil {
			t.Fatalf("Failed to read inventory dir: %v", err)
		}

		found := false
		for _, entry := range entries {
			if entry.IsDir() && filepath.HasPrefix(entry.Name(), "IMGA-") {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Expected to find IMGA inventory directory")
		}
	})

	t.Run("CollectInventory creates expected files", func(t *testing.T) {
		collector := NewInventoryCollector(log, fs)

		err := collector.CollectInventory("IMGB")
		if err != nil {
			t.Fatalf("CollectInventory failed: %v", err)
		}

		// Get the created directory
		inventoryDir := collector.GetInventoryDir("IMGB")
		if inventoryDir == "" {
			t.Fatal("No inventory directory found for IMGB")
		}

		// Check for expected files (some may have errors but should exist)
		expectedFiles := []string{
			"lspci.txt",
			"lsusb.txt",
			"cmdline.txt",
			"iommu-groups.txt",
			"inventory.json",
		}

		for _, filename := range expectedFiles {
			filePath := filepath.Join(inventoryDir, filename)
			if _, err := fs.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected file %s to exist", filename)
			}
		}
	})

	t.Run("GetInventoryDir returns most recent", func(t *testing.T) {
		collector := NewInventoryCollector(log, fs)

		// Collect twice
		err := collector.CollectInventory("IMGC")
		if err != nil {
			t.Fatalf("First collection failed: %v", err)
		}

		time.Sleep(1 * time.Second) // Ensure different timestamp

		err = collector.CollectInventory("IMGC")
		if err != nil {
			t.Fatalf("Second collection failed: %v", err)
		}

		// Should return the most recent
		dir := collector.GetInventoryDir("IMGC")
		if dir == "" {
			t.Fatal("No inventory directory found")
		}

		// Verify it's a directory
		info, err := fs.Stat(dir)
		if err != nil {
			t.Fatalf("Failed to stat directory: %v", err)
		}
		if !info.IsDir() {
			t.Error("GetInventoryDir should return a directory")
		}
	})

	t.Run("GetInventoryDir returns empty for non-existent slot", func(t *testing.T) {
		collector := NewInventoryCollector(log, fs)

		dir := collector.GetInventoryDir("NONEXISTENT")
		if dir != "" {
			t.Errorf("Expected empty string for non-existent slot, got %s", dir)
		}
	})

	t.Run("CleanupOldInventories removes old directories", func(t *testing.T) {
		collector := NewInventoryCollector(log, fs)

		// Create an old directory manually
		oldTimestamp := time.Now().Add(-40 * 24 * time.Hour).Format("2006-01-02-15:04")
		oldDir := filepath.Join(InventoryBaseDir, "TESTSLOT-"+oldTimestamp)
		if err := fs.MkdirAll(oldDir, 0755); err != nil {
			t.Fatalf("Failed to create old directory: %v", err)
		}

		// Create a dummy file to make it real
		dummyFile := filepath.Join(oldDir, "test.txt")
		if err := afero.WriteFile(fs, dummyFile, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create dummy file: %v", err)
		}

		// Set old modification time on the directory
		oldTime := time.Now().Add(-40 * 24 * time.Hour)
		if err := fs.Chtimes(oldDir, oldTime, oldTime); err != nil {
			t.Fatalf("Failed to set old time on directory: %v", err)
		}

		// Verify it exists
		if _, err := fs.Stat(oldDir); os.IsNotExist(err) {
			t.Fatal("Old directory should exist before cleanup")
		}

		// Run cleanup (keep last 30 days)
		if err := collector.CleanupOldInventories(30 * 24 * time.Hour); err != nil {
			t.Fatalf("CleanupOldInventories failed: %v", err)
		}

		// Verify old directory was removed
		if _, err := fs.Stat(oldDir); !os.IsNotExist(err) {
			t.Error("Old directory should have been removed")
		}
	})

	t.Run("CleanupOldInventories preserves recent directories", func(t *testing.T) {
		collector := NewInventoryCollector(log, fs)

		// Create a recent directory
		err := collector.CollectInventory("RECENT")
		if err != nil {
			t.Fatalf("Failed to create recent inventory: %v", err)
		}

		recentDir := collector.GetInventoryDir("RECENT")
		if recentDir == "" {
			t.Fatal("Recent directory should exist")
		}

		// Run cleanup
		if err := collector.CleanupOldInventories(30 * 24 * time.Hour); err != nil {
			t.Fatalf("CleanupOldInventories failed: %v", err)
		}

		// Verify recent directory still exists
		if _, err := fs.Stat(recentDir); os.IsNotExist(err) {
			t.Error("Recent directory should not have been removed")
		}
	})
}

func TestInventoryCollectorGracefulFailure(t *testing.T) {
	// Create test logger
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "test", 0)

	// Use in-memory filesystem for testing
	fs := afero.NewMemMapFs()

	t.Run("CollectInventory continues on command failures", func(t *testing.T) {
		collector := NewInventoryCollector(log, fs)

		// Even if some commands fail (e.g., scripts not available),
		// CollectInventory should not return error
		err := collector.CollectInventory("FAILTEST")
		if err != nil {
			t.Fatalf("CollectInventory should not fail even if commands fail: %v", err)
		}

		// Directory should still be created
		dir := collector.GetInventoryDir("FAILTEST")
		if dir == "" {
			t.Error("Directory should be created even on command failures")
		}
	})
}
