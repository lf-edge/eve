// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package coverage_test verifies that the coverage-merge Makefile target
// correctly incorporates binary coverage files supplied via EXTRA_COVERAGE_DIR.
package coverage_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot returns the absolute path to the EVE repository root, derived from
// the location of this test file (tests/coverage/ → ../../).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	abs, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// TestExtraCoverageDir verifies that when EXTRA_COVERAGE_DIR points at a
// directory containing binary Go coverage files (covmeta.* + covcounters.*),
// the coverage-merge Makefile target converts them via "go tool covdata
// textfmt" and appends the resulting lines to the combined profile.
func TestExtraCoverageDir(t *testing.T) {
	root := repoRoot(t)
	tmpDir := t.TempDir()

	// ------------------------------------------------------------------ //
	// Step 1 — build a tiny coverage-instrumented binary from a temp dir. //
	// ------------------------------------------------------------------ //
	helperDir := filepath.Join(tmpDir, "helper")
	if err := os.MkdirAll(helperDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helperDir, "go.mod"),
		[]byte("module example.com/covertest\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// The function Greet is exercised when the binary runs, so it will appear
	// in the coverage profile with a non-zero hit count.
	if err := os.WriteFile(filepath.Join(helperDir, "main.go"), []byte(`package main

import "fmt"

func Greet(name string) string { return "hello, " + name }

func main() { fmt.Println(Greet("world")) }
`), 0644); err != nil {
		t.Fatal(err)
	}

	helperBin := filepath.Join(tmpDir, "covertest")
	cmd := exec.Command("go", "build", "-cover", "-covermode=atomic",
		"-o", helperBin, ".")
	cmd.Dir = helperDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build -cover: %v\n%s", err, out)
	}

	// ------------------------------------------------------------------ //
	// Step 2 — run the binary with GOCOVERDIR to emit binary coverage.    //
	// ------------------------------------------------------------------ //
	covBinDir := filepath.Join(tmpDir, "extra_cov")
	if err := os.MkdirAll(covBinDir, 0755); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(helperBin)
	cmd.Env = append(os.Environ(), "GOCOVERDIR="+covBinDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("covertest binary: %v\n%s", err, out)
	}

	// Sanity-check: both covmeta and covcounters files must be present.
	entries, err := os.ReadDir(covBinDir)
	if err != nil {
		t.Fatal(err)
	}
	var hasMeta, hasCounters bool
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), "covmeta."):
			hasMeta = true
		case strings.HasPrefix(e.Name(), "covcounters."):
			hasCounters = true
		}
	}
	if !hasMeta || !hasCounters {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected covmeta.* and covcounters.* in %s; got: %v", covBinDir, names)
	}

	// ------------------------------------------------------------------ //
	// Step 3 — create a fake unit coverage file (pkg/pillar/coverage.txt) //
	// ------------------------------------------------------------------ //
	unitCovFile := filepath.Join(tmpDir, "unit_coverage.txt")
	unitLine := "github.com/lf-edge/eve/pkg/pillar/types/fake.go:1.1,2.2 1 1"
	if err := os.WriteFile(unitCovFile,
		[]byte("mode: atomic\n"+unitLine+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// ------------------------------------------------------------------ //
	// Step 4 — invoke the real Makefile target with overrides.            //
	// ------------------------------------------------------------------ //
	distDir := filepath.Join(tmpDir, "dist")
	cmd = exec.Command("make", "-C", root, "coverage-merge",
		"UNIT_COV_FILE="+unitCovFile,
		"EXTRA_COVERAGE_DIR="+covBinDir,
		"DIST="+distDir,
		"ZARCH=amd64",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make coverage-merge: %v\n%s", err, out)
	}

	// ------------------------------------------------------------------ //
	// Step 5 — verify the combined output.                                //
	// ------------------------------------------------------------------ //
	combinedFile := filepath.Join(distDir, "current", "combined_coverage.txt")
	raw, err := os.ReadFile(combinedFile)
	if err != nil {
		t.Fatalf("reading combined_coverage.txt: %v", err)
	}
	combined := string(raw)

	// Must begin with the coverage mode header.
	if !strings.HasPrefix(combined, "mode: atomic\n") {
		t.Errorf("combined_coverage.txt does not start with 'mode: atomic\\n':\n%.200s", combined)
	}

	// Must contain the unit-test fake line.
	if !strings.Contains(combined, unitLine) {
		t.Errorf("combined_coverage.txt is missing the unit-test line %q", unitLine)
	}

	// Must contain coverage lines from the extra binary coverage dir.
	// go tool covdata textfmt emits lines with the module path "example.com/covertest".
	if !strings.Contains(combined, "example.com/covertest") {
		t.Errorf("combined_coverage.txt is missing lines from EXTRA_COVERAGE_DIR\ncombined:\n%s", combined)
	}
}

// buildExtraCovDir builds a tiny coverage-instrumented binary, runs it, and
// returns the directory containing the resulting binary coverage files
// (covmeta.* + covcounters.*).  The directory is inside tmpDir.
func buildExtraCovDir(t *testing.T, tmpDir string) string {
	t.Helper()

	helperDir := filepath.Join(tmpDir, "helper")
	if err := os.MkdirAll(helperDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helperDir, "go.mod"),
		[]byte("module example.com/covertest\n\ngo 1.24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(helperDir, "main.go"), []byte(`package main

import "fmt"

func Greet(name string) string { return "hello, " + name }

func main() { fmt.Println(Greet("world")) }
`), 0644); err != nil {
		t.Fatal(err)
	}

	helperBin := filepath.Join(tmpDir, "covertest")
	cmd := exec.Command("go", "build", "-cover", "-covermode=atomic", "-o", helperBin, ".")
	cmd.Dir = helperDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build -cover: %v\n%s", err, out)
	}

	covBinDir := filepath.Join(tmpDir, "extra_cov")
	if err := os.MkdirAll(covBinDir, 0755); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(helperBin)
	cmd.Env = append(os.Environ(), "GOCOVERDIR="+covBinDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("covertest binary: %v\n%s", err, out)
	}
	return covBinDir
}

// TestRealMerge exercises coverage-merge against the real unit-test and Eden
// E2E coverage profiles produced by "make test" and "make eden-cover",
// supplemented by a dummy binary coverage dir (as EXTRA_COVERAGE_DIR).
// It skips if either real coverage file is absent.
// Run it to reproduce the full three-source merge and print per-function totals.
func TestRealMerge(t *testing.T) {
	root := repoRoot(t)

	unitCov := filepath.Join(root, "pkg/pillar/coverage.txt")
	if _, err := os.Stat(unitCov); err != nil {
		t.Skipf("unit coverage not found (%s); run 'make test' first", unitCov)
	}
	edenCov := filepath.Join(root, "dist/amd64/current/eden_coverage/eden_e2e_coverage.txt")
	if _, err := os.Stat(edenCov); err != nil {
		t.Skipf("Eden E2E coverage not found (%s); run 'make eden-cover' first", edenCov)
	}

	tmpDir := t.TempDir()
	extraCovDir := buildExtraCovDir(t, tmpDir)

	// Run make coverage-merge against the real dist tree so that the Eden E2E
	// profile is picked up automatically via its standard path.
	cmd := exec.Command("make", "-C", root, "coverage-merge",
		"UNIT_COV_FILE="+unitCov,
		"EXTRA_COVERAGE_DIR="+extraCovDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make coverage-merge: %v\n%s", err, out)
	}
	t.Logf("make coverage-merge output:\n%s", out)

	combinedFile := filepath.Join(root, "dist/amd64/current/combined_coverage.txt")
	raw, err := os.ReadFile(combinedFile)
	if err != nil {
		t.Fatalf("reading combined_coverage.txt: %v", err)
	}
	combined := string(raw)

	if !strings.HasPrefix(combined, "mode: atomic\n") {
		t.Errorf("combined_coverage.txt does not start with 'mode: atomic\\n'")
	}
	if !strings.Contains(combined, "example.com/covertest") {
		t.Errorf("combined_coverage.txt missing EXTRA_COVERAGE_DIR lines")
	}

	// go tool cover -func needs to resolve source files, so filter out any
	// non-EVE lines (e.g. from the dummy example.com/covertest helper) before
	// running it.  The combined_coverage.txt is kept intact for other tooling.
	var filtered strings.Builder
	for i, line := range strings.Split(combined, "\n") {
		if i == 0 || strings.HasPrefix(line, "github.com/lf-edge/eve/") {
			filtered.WriteString(line + "\n")
		}
	}
	filteredFile := filepath.Join(tmpDir, "combined_eve_only.txt")
	if err := os.WriteFile(filteredFile, []byte(filtered.String()), 0644); err != nil {
		t.Fatal(err)
	}

	coverCmd := exec.Command("go", "tool", "cover", "-func="+filteredFile)
	coverCmd.Dir = filepath.Join(root, "pkg/pillar")
	funcOut, err := coverCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go tool cover -func: %v\n%s", err, funcOut)
	}
	// Print the total line so the caller can see the numbers.
	for _, line := range strings.Split(string(funcOut), "\n") {
		if strings.HasPrefix(line, "total:") {
			fmt.Printf("\nCoverage summary (unit + Eden E2E + extra):\n%s\n", line)
			break
		}
	}
	t.Logf("combined profile: %s", combinedFile)
}
