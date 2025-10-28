// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package watcher //nolint:testpackage // Internal tests need access to unexported helpers

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	immcore "github.com/lf-edge/eve/pkg/pillar/cmd/watcher/internal/immcore"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	oldExt = ".old"
)

// isPersistAccessible checks if the /persist directory is writable
func isPersistAccessible() bool {
	// Try to create the memory monitor output directory
	if err := os.MkdirAll(types.MemoryMonitorOutputDir, 0755); err != nil {
		return false
	}

	// Try to create a test file to verify write access
	testFile := filepath.Join(types.MemoryMonitorOutputDir, ".test_access")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return false
	}
	_ = os.Remove(testFile)

	return true
}

// mmFSLock serializes tests that manipulate files under types.MemoryMonitorOutputDir.
var mmFSLock sync.Mutex

// TestInternalMemoryMonitorParams verifies thread-safe parameter management
func TestInternalMemoryMonitorParams(t *testing.T) {
	t.Parallel()
	var params InternalMemoryMonitorParams

	// Test default state
	store, analyze := params.Get()
	if store || analyze {
		t.Error("Expected both flags to be false initially")
	}

	// Test enabling both
	params.Set(true, true)
	store, analyze = params.Get()
	if !store || !analyze {
		t.Error("Expected both flags to be true")
	}

	// Test dependency: analyze requires store
	params.Set(false, true)
	store, analyze = params.Get()
	if store || analyze {
		t.Error("Expected both flags to be false when store disabled")
	}

	// Test store-only mode
	params.Set(true, false)
	store, analyze = params.Get()
	if !store || analyze {
		t.Error("Expected store=true, analyze=false")
	}
}

// TestBackupOldCsvFile verifies CSV backup functionality
func TestBackupOldCsvFile(t *testing.T) {
	t.Parallel()
	mmFSLock.Lock()
	defer mmFSLock.Unlock()
	if !isPersistAccessible() {
		t.Skip("Skipping test: /persist directory not accessible (run with 'make test' to run in container)")
	}

	fileName := filepath.Join(types.MemoryMonitorOutputDir, "memory_usage.csv")

	// Clean up any existing test files
	defer func() {
		_ = os.Remove(fileName)
		// Clean up any .old files created during test
		files, _ := os.ReadDir(types.MemoryMonitorOutputDir)
		for _, file := range files {
			if filepath.Ext(file.Name()) == oldExt {
				_ = os.Remove(filepath.Join(types.MemoryMonitorOutputDir, file.Name()))
			}
		}
	}()

	// Create a test CSV file
	content := []byte("time,heap,rss,score\n2025-01-01T00:00:00Z,1000,2000,0.5\n")
	if err := os.WriteFile(fileName, content, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Backup the file
	backupOldCsvFile()

	// Verify original file no longer exists
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		t.Error("Original file should have been renamed")
	}

	// Verify backup file exists
	files, err := os.ReadDir(types.MemoryMonitorOutputDir)
	if err != nil {
		t.Fatalf("Failed to read output dir: %v", err)
	}

	foundBackup := false
	for _, file := range files {
		if filepath.Ext(file.Name()) == oldExt {
			foundBackup = true
			t.Logf("Found backup file: %s", file.Name())
			break
		}
	}

	if !foundBackup {
		t.Error("Expected to find backup file with .old extension")
	}
}

// TestBackupEmptyFile verifies that empty files aren't backed up
func TestBackupEmptyFile(t *testing.T) {
	t.Parallel()
	mmFSLock.Lock()
	defer mmFSLock.Unlock()
	if !isPersistAccessible() {
		t.Skip("Skipping test: /persist directory not accessible (run with 'make test' in container)")
	}

	fileName := filepath.Join(types.MemoryMonitorOutputDir, "memory_usage.csv")

	// Clean up after test
	defer func() { _ = os.Remove(fileName) }()

	// Create empty file
	if err := os.WriteFile(fileName, []byte{}, 0600); err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	// Backup should not rename empty file
	backupOldCsvFile()

	// Original file should still exist
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		t.Error("Empty file should not be backed up")
	}

	// Verify file is still empty
	info, err := os.Stat(fileName)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("Expected empty file to remain empty, got size %d", info.Size())
	}
}

// TestCleanupOldCsvFiles verifies old file cleanup
func TestCleanupOldCsvFiles(t *testing.T) {
	t.Parallel()
	mmFSLock.Lock()
	defer mmFSLock.Unlock()
	if !isPersistAccessible() {
		t.Skip("Skipping test: /persist directory not accessible (run with 'make test' in container)")
	}

	// Clean up any pre-existing test files
	files, _ := os.ReadDir(types.MemoryMonitorOutputDir)
	for _, file := range files {
		if filepath.Ext(file.Name()) == oldExt {
			_ = os.Remove(filepath.Join(types.MemoryMonitorOutputDir, file.Name()))
		}
	}

	// Create multiple old CSV files with total size > 10MB
	// Each file 2MB, create 6 files = 12MB total
	fileSize := 2 * 1024 * 1024
	content := make([]byte, fileSize)

	createdFiles := []string{}
	for i := range 6 { // create old files
		fileName := filepath.Join(types.MemoryMonitorOutputDir,
			"memory_usage.csv."+time.Now().Add(-time.Duration(6-i)*time.Hour).Format("20060102T150405")+oldExt)
		if err := os.WriteFile(fileName, content, 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		createdFiles = append(createdFiles, fileName)
		// Sleep briefly to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Clean up all created test files at the end
	defer func() {
		for _, f := range createdFiles {
			_ = os.Remove(f)
		}
	}()

	// Run cleanup
	cleanupOldCsvFiles()

	// Count remaining files
	files, err := os.ReadDir(types.MemoryMonitorOutputDir)
	if err != nil {
		t.Fatalf("Failed to read output dir: %v", err)
	}

	csvCount := 0
	var totalSize int64
	for _, file := range files {
		if filepath.Ext(file.Name()) == oldExt || filepath.Ext(file.Name()) == ".csv" {
			csvCount++
			info, err := file.Info()
			if err == nil {
				totalSize += info.Size()
			}
		}
	}

	// Should have removed oldest files to get under 10MB
	if totalSize > 10*1024*1024 {
		t.Errorf("Expected total size <= 10MB after cleanup, got %d bytes", totalSize)
	}

	t.Logf("After cleanup: %d files, %d bytes", csvCount, totalSize)
}

// TestWriteProbesCSV verifies CSV writing
func TestWriteProbesCSV(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	fileName := filepath.Join(tempDir, "test_memory_usage.csv")

	// Create test probes
	now := time.Now()
	probes := []immcore.Probe{
		{
			Time:          now,
			Values:        [immcore.NumMetrics]uint64{1024 * 1024 * 100, 1024 * 1024 * 150},
			SRecent:       [immcore.NumMetrics]float64{0.1, 0.2},
			SEntire:       [immcore.NumMetrics]float64{0.05, 0.1},
			RecentFeature: 0.15,
			EntireFeature: 0.075,
			Score:         1.5,
		},
		{
			Time:          now.Add(5 * time.Second),
			Values:        [immcore.NumMetrics]uint64{1024 * 1024 * 101, 1024 * 1024 * 151},
			SRecent:       [immcore.NumMetrics]float64{0.12, 0.22},
			SEntire:       [immcore.NumMetrics]float64{0.06, 0.11},
			RecentFeature: 0.17,
			EntireFeature: 0.085,
			Score:         1.7,
		},
	}

	// Write CSV
	writeProbesCSV(probes, fileName)

	// Verify file exists
	info, err := os.Stat(fileName)
	if err != nil {
		t.Fatalf("Failed to stat CSV file: %v", err)
	}

	if info.Size() == 0 {
		t.Error("CSV file should not be empty")
	}

	// Read and verify content
	content, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	contentStr := string(content)

	// Verify header is present
	if !contains(contentStr, "time") {
		t.Error("CSV should contain 'time' header")
	}

	// Verify metric names are in header
	for _, spec := range immcore.MetricRegistry {
		if !contains(contentStr, spec.Name) {
			t.Errorf("CSV header should contain metric name: %s", spec.Name)
		}
	}

	// Verify we have the right number of lines (header + 2 data rows)
	lines := countLines(contentStr)
	if lines != 3 {
		t.Errorf("Expected 3 lines (header + 2 data), got %d", lines)
	}

	t.Logf("CSV content:\n%s", contentStr)
}

// TestWriteProbesCSVEmpty verifies writing empty probe list
func TestWriteProbesCSVEmpty(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	fileName := filepath.Join(tempDir, "test_empty.csv")

	// Write empty probe list
	writeProbesCSV([]immcore.Probe{}, fileName)

	// File should still exist with just header
	content, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	if len(content) == 0 {
		t.Error("CSV file should have header even when empty")
	}

	lines := countLines(string(content))
	if lines != 1 {
		t.Errorf("Expected 1 line (header only), got %d", lines)
	}
}

// TestUpdateInternalMemoryMonitorConfig verifies config update logic
func TestUpdateInternalMemoryMonitorConfig(t *testing.T) {
	t.Parallel()
	// This test would require mocking the global config subscription
	// For now, we'll test the parameter setting logic separately
	// which we already covered in TestInternalMemoryMonitorParams
	t.Skip("Requires global config subscription mock")
}

// TestHistoryTrimming verifies that history is trimmed to MaxHistory
func TestHistoryTrimming(t *testing.T) {
	t.Parallel()
	cfg := immcore.DefaultConfig()
	cfg.MaxHistory = 10

	engine := immcore.NewState(cfg)

	now := time.Now()

	// Add more probes than MaxHistory
	for i := range 20 {
		input := immcore.Input{
			Time: now.Add(time.Duration(i) * time.Second),
			Values: [immcore.NumMetrics]uint64{
				100*1024*1024 + uint64(i)*1024, //nolint:gosec // i is bounded by range 20
				150*1024*1024 + uint64(i)*1024, //nolint:gosec // i is bounded by range 20
			},
		}
		engine.Step(input)
	}

	// History should be capped
	if len(engine.History()) > cfg.MaxHistory {
		t.Errorf("Expected history length <= %d, got %d", cfg.MaxHistory, len(engine.History()))
	}
}

// TestStoreOnlyMode verifies store-only operation
func TestStoreOnlyMode(t *testing.T) {
	t.Parallel()
	cfg := immcore.DefaultConfig()
	cfg.MaxHistory = 100

	engine := immcore.NewState(cfg)

	now := time.Now()

	// Use AppendOnly for store-only mode
	for i := range 10 {
		input := immcore.Input{
			Time: now.Add(time.Duration(i) * time.Second),
			Values: [immcore.NumMetrics]uint64{
				100*1024*1024 + uint64(i)*1024, //nolint:gosec // i is bounded by range 10
				150*1024*1024 + uint64(i)*1024, //nolint:gosec // i is bounded by range 10
			},
		}
		probe := engine.AppendOnly(input)

		// Verify no analysis was done (all scores zero)
		if probe.Score != 0 || probe.RecentFeature != 0 || probe.EntireFeature != 0 {
			t.Errorf("Store-only mode should not compute scores, got score=%f, recent=%f, entire=%f",
				probe.Score, probe.RecentFeature, probe.EntireFeature)
		}
	}

	// Verify all probes were stored
	if len(engine.History()) != 10 {
		t.Errorf("Expected 10 probes in history, got %d", len(engine.History()))
	}
}

// TestMemoryLeakScenario simulates a realistic memory leak
func TestMemoryLeakScenario(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("Skipping leak scenario test in short mode")
	}

	cfg := immcore.DefaultConfig()
	cfg.AnalysisWindow = 1 * time.Minute
	cfg.ProbingInterval = 1 * time.Second
	cfg.MaxHistory = 500

	engine := immcore.NewState(cfg)

	now := time.Now()
	baseHeap := uint64(1024 * 1024 * 100) // 100 MB base

	// Phase 1: Stable memory (60 seconds)
	for i := range 60 {
		input := immcore.Input{
			Time:   now.Add(time.Duration(i) * time.Second),
			Values: [immcore.NumMetrics]uint64{baseHeap, baseHeap * 3 / 2},
		}
		engine.Step(input)
	}

	// Phase 2: Memory leak starts (leak 1MB per minute = ~17KB/sec)
	leakRate := uint64(17 * 1024) // bytes per second
	for i := 60; i < 300; i++ {
		leakDuration := uint64(i) - 60 //nolint:gosec // i is bounded by loop range 60-299
		leaked := leakDuration * leakRate
		input := immcore.Input{
			Time: now.Add(time.Duration(i) * time.Second),
			Values: [immcore.NumMetrics]uint64{
				baseHeap + leaked,
				baseHeap*3/2 + leaked*3/2,
			},
		}
		probe := engine.Step(input)

		// After 2 minutes of leaking, score should start rising
		if i == 180 {
			t.Logf("Score after 2 min of leak: %f", probe.Score)
			if probe.Score < 0.5 {
				t.Logf("Warning: Expected some score increase after sustained leak, got %f", probe.Score)
			}
		}
	}

	finalProbe := engine.History()[len(engine.History())-1]
	t.Logf("Final leak scenario score: %f (recent=%f, entire=%f)",
		finalProbe.Score, finalProbe.RecentFeature, finalProbe.EntireFeature)
}

// TestGoldenFilesScoring validates that the IMM produces meaningful scores on real data
// by using the imm-experiment tool to reprocess golden CSV files
func TestGoldenFilesScoring(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name          string
		filename      string
		expectLeak    bool
		minFinalScore float64
		maxFinalScore float64
	}{
		{
			name:          "Leak Scenario",
			filename:      "testdata/memory_usage_golden_leak.csv",
			expectLeak:    true,
			minFinalScore: 3.0,  // Should show elevated score
			maxFinalScore: 10.0, // But not necessarily max
		},
		{
			name:          "No Leak Scenario",
			filename:      "testdata/memory_usage_golden_noleak.csv",
			expectLeak:    false,
			minFinalScore: 0.0,
			maxFinalScore: 2.0, // Should stay low
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Check if input file exists
			if _, err := os.Stat(tc.filename); os.IsNotExist(err) {
				t.Skipf("Golden file %s not found", tc.filename)
			}

			// Use imm-experiment tool to reprocess the CSV
			tmpDir := t.TempDir()
			outputFile := filepath.Join(tmpDir, "recalc.csv")

			// Build the imm-experiment tool if not already built
			immExpBin := buildImmExperiment(t)

			// Run imm-experiment to reprocess the golden file
			scores, err := runImmExperiment(immExpBin, tc.filename, outputFile)
			if err != nil {
				t.Fatalf("Failed to run imm-experiment: %v", err)
			}

			if len(scores) == 0 {
				t.Fatalf("No scores returned from imm-experiment for %s", tc.filename)
			}

			// Get final score
			finalScore := scores[len(scores)-1]

			t.Logf("Processed %d probes from %s", len(scores), tc.filename)
			t.Logf("Final score: %.3f", finalScore.Score)
			t.Logf("Recent feature: %.3f, Entire feature: %.3f",
				finalScore.RecentFeature, finalScore.EntireFeature)

			// Validate score range
			if finalScore.Score < tc.minFinalScore {
				t.Errorf("Expected final score >= %.1f, got %.3f", tc.minFinalScore, finalScore.Score)
			}
			if finalScore.Score > tc.maxFinalScore {
				t.Errorf("Expected final score <= %.1f, got %.3f", tc.maxFinalScore, finalScore.Score)
			}

			// Additional checks for leak detection
			if tc.expectLeak {
				// Leak should have high recent OR entire evidence
				if finalScore.RecentFeature < 0.3 && finalScore.EntireFeature < 0.3 {
					t.Errorf("Expected elevated evidence for leak, got recent=%.3f, entire=%.3f",
						finalScore.RecentFeature, finalScore.EntireFeature)
				}
			} else {
				// No leak should have low evidence
				if finalScore.RecentFeature > 0.5 || finalScore.EntireFeature > 0.5 {
					t.Logf("Warning: High evidence in no-leak scenario, recent=%.3f, entire=%.3f",
						finalScore.RecentFeature, finalScore.EntireFeature)
				}
			}
		})
	}
}

// ScoreResult holds the parsed result from imm-experiment output
type ScoreResult struct {
	Score         float64
	RecentFeature float64
	EntireFeature float64
}

// buildImmExperiment builds the imm-experiment tool and returns the path to the binary
func buildImmExperiment(t *testing.T) string {
	t.Helper()

	// Build the tool
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "imm-experiment")

	cmd := exec.Command("go", "build", "-o", binPath,
		"github.com/lf-edge/eve/pkg/pillar/cmd/watcher/cmd/imm-experiment")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build imm-experiment: %v\nOutput: %s", err, output)
	}

	return binPath
}

// runImmExperiment runs the imm-experiment tool and parses the output CSV
func runImmExperiment(binPath, inputFile, outputFile string) ([]ScoreResult, error) {
	// Run imm-experiment
	cmd := exec.Command(binPath, "-in", inputFile, "-out", outputFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("imm-experiment failed: %w\nOutput: %s", err, output)
	}

	// Parse the output CSV
	return parseScoresFromCSV(outputFile)
}

// parseScoresFromCSV reads the recalculated CSV and extracts scores
func parseScoresFromCSV(filename string) ([]ScoreResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, errors.New("no data in output CSV")
	}

	// Parse header to find column indices
	header := lines[0]
	cols := strings.Split(header, ",")

	scoreIdx := findColumnIndex(cols, "score")
	recentIdx := findColumnIndex(cols, "recent_feature")
	entireIdx := findColumnIndex(cols, "entire_feature")

	if scoreIdx < 0 || recentIdx < 0 || entireIdx < 0 {
		return nil, errors.New("missing required columns in output CSV")
	}

	var results []ScoreResult

	// Parse data rows
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) <= maxInt2(scoreIdx, maxInt2(recentIdx, entireIdx)) {
			continue
		}

		var score, recent, entire float64
		if _, err := fmt.Sscanf(fields[scoreIdx], "%f", &score); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(fields[recentIdx], "%f", &recent); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(fields[entireIdx], "%f", &entire); err != nil {
			continue
		}

		results = append(results, ScoreResult{
			Score:         score,
			RecentFeature: recent,
			EntireFeature: entire,
		})
	}

	return results, nil
}

// findColumnIndex finds the index of a column by name
func findColumnIndex(cols []string, name string) int {
	for i, col := range cols {
		if col == name {
			return i
		}
	}
	return -1
}

func maxInt2(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func countLines(s string) int {
	if len(s) == 0 {
		return 0
	}
	count := 1
	for i := range len(s) {
		if s[i] == '\n' {
			count++
		}
	}
	// Don't count trailing newline
	if s[len(s)-1] == '\n' {
		count--
	}
	return count
}
