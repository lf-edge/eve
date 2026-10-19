// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func TestParseArtifactDirName(t *testing.T) {
	cases := []struct {
		dirName   string
		wantName  string
		wantStamp string
		wantOK    bool
	}{
		{"TestTelemetrySuite-2026-08-07_09-17-40", "TestTelemetrySuite", "2026-08-07_09-17-40", true},
		{"TestSingleNodeCluster-2026-08-07_08-16-29", "TestSingleNodeCluster", "2026-08-07_08-16-29", true},
		{"garbage", "", "", false},
		{"-2026-08-07_08-16-29", "", "", false},
		{"TestFoo-2026-13-99_08-16-29", "", "", false}, // not a valid timestamp
		{"TestFoo-2026-08-07_08-16", "", "", false},    // truncated timestamp
	}
	for _, tc := range cases {
		name, stamp, ok := parseArtifactDirName(tc.dirName)
		if ok != tc.wantOK || name != tc.wantName || stamp != tc.wantStamp {
			t.Errorf("parseArtifactDirName(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.dirName, name, stamp, ok, tc.wantName, tc.wantStamp, tc.wantOK)
		}
	}
}

func TestFindPreviousPass(t *testing.T) {
	const suite = "TestTelemetrySuite"
	const ranAt = "2026-08-07_09-17-40"

	t.Run("genuine pass", func(t *testing.T) {
		gotest := "" +
			"=== RUN   TestTelemetrySuite\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceInfo\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceMetrics\n" +
			"--- PASS: TestTelemetrySuite (343.19s)\n" +
			"    --- PASS: TestTelemetrySuite/TestDeviceInfo (168.68s)\n" +
			"    --- PASS: TestTelemetrySuite/TestDeviceMetrics (149.09s)\n" +
			"PASS\n"
		passedAt, ok := findPreviousPass(gotest, suite, "TestDeviceInfo", ranAt)
		if !ok || passedAt != ranAt {
			t.Fatalf("got (%q, %v), want (%q, true)", passedAt, ok, ranAt)
		}
	})

	t.Run("genuine failure", func(t *testing.T) {
		gotest := "" +
			"=== RUN   TestTelemetrySuite\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceInfo\n" +
			"--- FAIL: TestTelemetrySuite (1.00s)\n" +
			"    --- FAIL: TestTelemetrySuite/TestDeviceInfo (1.00s)\n" +
			"FAIL\n"
		_, ok := findPreviousPass(gotest, suite, "TestDeviceInfo", ranAt)
		if ok {
			t.Fatalf("expected ok=false for a failed subtest")
		}
	})

	t.Run("go skip is not a pass", func(t *testing.T) {
		gotest := "" +
			"=== RUN   TestTelemetrySuite\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceInfo\n" +
			"--- PASS: TestTelemetrySuite (1.00s)\n" +
			"    --- SKIP: TestTelemetrySuite/TestDeviceInfo (1.00s)\n" +
			"PASS\n"
		_, ok := findPreviousPass(gotest, suite, "TestDeviceInfo", ranAt)
		if ok {
			t.Fatalf("expected ok=false for a skipped subtest")
		}
	})

	t.Run("chained skip propagates original timestamp", func(t *testing.T) {
		const originalPassedAt = "2026-08-05_10-00-00"
		skipMsg := fmt.Sprintf(restartOnlyFailedSkipMsgTmpl, suite+"/TestDeviceInfo", originalPassedAt)
		gotest := "" +
			"=== RUN   TestTelemetrySuite\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceInfo\n" +
			"[34mHARNESS [0m time=\"2026-08-07T09:17:46Z\" level=info msg=\"" +
			skipMsg + "\"\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceMetrics\n" +
			"--- PASS: TestTelemetrySuite (0.01s)\n" +
			"    --- PASS: TestTelemetrySuite/TestDeviceInfo (0.00s)\n" +
			"    --- PASS: TestTelemetrySuite/TestDeviceMetrics (149.09s)\n" +
			"PASS\n"
		passedAt, ok := findPreviousPass(gotest, suite, "TestDeviceInfo", ranAt)
		if !ok || passedAt != originalPassedAt {
			t.Fatalf("got (%q, %v), want (%q, true)", passedAt, ok, originalPassedAt)
		}
	})

	t.Run("test not present", func(t *testing.T) {
		gotest := "" +
			"=== RUN   TestTelemetrySuite\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceInfo\n" +
			"--- PASS: TestTelemetrySuite (1.00s)\n" +
			"    --- PASS: TestTelemetrySuite/TestDeviceInfo (1.00s)\n" +
			"PASS\n"
		_, ok := findPreviousPass(gotest, suite, "TestDeviceLogs", ranAt)
		if ok {
			t.Fatalf("expected ok=false for a test absent from the log")
		}
	})

	t.Run("name prefix collision does not false-match", func(t *testing.T) {
		gotest := "" +
			"=== RUN   TestTelemetrySuite\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceInfoExtra\n" +
			"--- PASS: TestTelemetrySuite (1.00s)\n" +
			"    --- PASS: TestTelemetrySuite/TestDeviceInfoExtra (1.00s)\n" +
			"PASS\n"
		_, ok := findPreviousPass(gotest, suite, "TestDeviceInfo", ranAt)
		if ok {
			t.Fatalf("expected ok=false: TestDeviceInfo must not match TestDeviceInfoExtra")
		}
	})

	// This is accepted as "unknown, so just rerun it": determining a pass
	// relies entirely on the deferred "--- PASS" summary block, which go test
	// only flushes once the whole top-level suite test returns. If a later
	// subtest paused on failure (EVETEST_PAUSE_ON_FAILURE) and the run was
	// killed before that, the block never gets printed for any subtest of
	// the suite -- not even ones, like TestDeviceInfo here, that already
	// passed cleanly. EVETEST_RESTART_ONLY_FAILED is only an optimization,
	// so simply re-running it is an acceptable outcome.
	t.Run("run killed before the deferred summary is treated as unknown", func(t *testing.T) {
		gotest := "" +
			"=== RUN   TestTelemetrySuite\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceInfo\n" +
			"=== RUN   TestTelemetrySuite/TestDeviceMetrics\n"
			// Killed here while TestDeviceMetrics is paused; no deferred
			// summary block ever gets printed.
		_, ok := findPreviousPass(gotest, suite, "TestDeviceInfo", ranAt)
		if ok {
			t.Fatalf("expected ok=false: no deferred result line and no skip message")
		}
	})
}

// jsonOutputEvent builds a single "go test -json" Action:"output" event line
// (see TestEvent in cmd/test2json) carrying the given raw output line, used
// to assemble synthetic gotest.json fixtures below.
func jsonOutputEvent(t *testing.T, output string) string {
	t.Helper()
	data, err := json.Marshal(goTestJSONEvent{Action: "output", Output: output})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(data) + "\n"
}

// TestFindPreviousPassJSON only exercises the gotest.json -> text
// reconstruction itself; once reassembled, the actual pass/fail
// determination is delegated to findPreviousPass and is already covered
// exhaustively by TestFindPreviousPass.
func TestFindPreviousPassJSON(t *testing.T) {
	const suite = "TestTelemetrySuite"
	const ranAt = "2026-08-07_09-17-40"

	t.Run("reconstructed text is parsed the same as plain gotest.txt", func(t *testing.T) {
		gotest := jsonOutputEvent(t, "=== RUN   TestTelemetrySuite\n") +
			jsonOutputEvent(t, "=== RUN   TestTelemetrySuite/TestDeviceInfo\n") +
			jsonOutputEvent(t, "=== RUN   TestTelemetrySuite/TestDeviceMetrics\n") +
			jsonOutputEvent(t, "--- PASS: TestTelemetrySuite (2.00s)\n") +
			jsonOutputEvent(t, "    --- PASS: TestTelemetrySuite/TestDeviceInfo (1.00s)\n") +
			jsonOutputEvent(t, "    --- PASS: TestTelemetrySuite/TestDeviceMetrics (1.00s)\n") +
			jsonOutputEvent(t, "PASS\n") +
			// Non-"output" events (the semantic actions go test -json also
			// emits alongside the raw line) must be ignored, not double-counted.
			`{"Action":"run","Test":"TestTelemetrySuite/TestDeviceInfo"}` + "\n" +
			`{"Action":"pass","Test":"TestTelemetrySuite/TestDeviceInfo","Elapsed":1}` + "\n"

		passedAt, ok := findPreviousPassJSON([]byte(gotest), suite, "TestDeviceInfo", ranAt)
		if !ok || passedAt != ranAt {
			t.Fatalf("got (%q, %v), want (%q, true)", passedAt, ok, ranAt)
		}
	})

	t.Run("no PASS line and no skip message means unknown", func(t *testing.T) {
		gotest := jsonOutputEvent(t, "=== RUN   TestTelemetrySuite\n") +
			jsonOutputEvent(t, "=== RUN   TestTelemetrySuite/TestDeviceInfo\n") +
			jsonOutputEvent(t, "=== RUN   TestTelemetrySuite/TestDeviceMetrics\n")
		_, ok := findPreviousPassJSON([]byte(gotest), suite, "TestDeviceInfo", ranAt)
		if ok {
			t.Fatalf("expected ok=false: no deferred result line and no skip message")
		}
	})
}

func TestPreviousArtifactDir(t *testing.T) {
	const suite = "TestTelemetrySuite"
	const thisRanAt = "2026-08-07_12-00-00"

	// mkArtifactsRoot creates an artifacts root populated with the given
	// artifact directory names (plus a stray file, which must be ignored).
	mkArtifactsRoot := func(t *testing.T, dirNames ...string) string {
		t.Helper()
		root := t.TempDir()
		for _, name := range dirNames {
			if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, "some-file"), nil, 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		return root
	}

	t.Run("newest earlier run of the same suite wins", func(t *testing.T) {
		root := mkArtifactsRoot(t,
			suite+"-2026-08-05_10-00-00",
			suite+"-2026-08-07_09-17-40", // the newest earlier one
			suite+"-2026-08-06_23-59-59",
			"TestOtherSuite-2026-08-07_11-00-00", // different suite
			suite+"-2026-08-07_13-00-00",         // started after the current run
			suite+"-"+thisRanAt,                  // the current run itself
			"not-an-artifact-dir",
		)
		dir, ranAt, err := previousArtifactDir(root, suite, thisRanAt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantRanAt := "2026-08-07_09-17-40"
		if want := filepath.Join(root, suite+"-"+wantRanAt); dir != want || ranAt != wantRanAt {
			t.Fatalf("got (%q, %q), want (%q, %q)", dir, ranAt, want, wantRanAt)
		}
	})

	t.Run("no earlier run of this suite", func(t *testing.T) {
		root := mkArtifactsRoot(t,
			"TestOtherSuite-2026-08-07_09-17-40",
			suite+"-"+thisRanAt,
			suite+"-2026-08-07_13-00-00",
		)
		if _, _, err := previousArtifactDir(root, suite, thisRanAt); err == nil {
			t.Fatalf("expected error when there is no earlier run of the suite")
		}
	})

	t.Run("artifacts root does not exist", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "nonexistent")
		if _, _, err := previousArtifactDir(root, suite, thisRanAt); err == nil {
			t.Fatalf("expected error for a nonexistent artifacts root")
		}
	})
}

func TestPreviouslyPassedAt(t *testing.T) {
	const suite = "TestTelemetrySuite"
	const prevRanAt = "2026-08-07_09-17-40"

	// newHarness sets up an artifacts root holding a single previous run of
	// suite, whose results (in resultFile, i.e. either gotest.txt or
	// gotest.json) record TestDeviceInfo as passed, and returns a harness whose
	// own, more recent artifact dir sits under that same root.
	newHarness := func(t *testing.T, resultFile, results string) *TestHarness {
		t.Helper()
		root := t.TempDir()
		prevDir := filepath.Join(root, suite+"-"+prevRanAt)
		if err := os.MkdirAll(prevDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(
			filepath.Join(prevDir, resultFile), []byte(results), 0o644); err != nil {
			t.Fatalf("write %s: %v", resultFile, err)
		}
		return &TestHarness{
			log:         logrus.New(),
			artifactDir: filepath.Join(root, suite+"-2026-08-07_10-00-00"),
		}
	}

	gotestTxt := "" +
		"=== RUN   TestTelemetrySuite\n" +
		"=== RUN   TestTelemetrySuite/TestDeviceInfo\n" +
		"--- PASS: TestTelemetrySuite (1.00s)\n" +
		"    --- PASS: TestTelemetrySuite/TestDeviceInfo (1.00s)\n" +
		"PASS\n"

	t.Run("disabled by default", func(t *testing.T) {
		viper.Set(constants.RestartOnlyFailedEnv, false)
		defer viper.Set(constants.RestartOnlyFailedEnv, false)
		th := newHarness(t, "gotest.txt", gotestTxt)
		if _, ok := th.previouslyPassedAt(suite, "TestDeviceInfo"); ok {
			t.Fatalf("expected ok=false when EVETEST_RESTART_ONLY_FAILED is unset")
		}
	})

	t.Run("enabled, same suite, passed", func(t *testing.T) {
		viper.Set(constants.RestartOnlyFailedEnv, true)
		defer viper.Set(constants.RestartOnlyFailedEnv, false)
		th := newHarness(t, "gotest.txt", gotestTxt)
		passedAt, ok := th.previouslyPassedAt(suite, "TestDeviceInfo")
		if !ok || passedAt != prevRanAt {
			t.Fatalf("got (%q, %v), want (%q, true)", passedAt, ok, prevRanAt)
		}
	})

	t.Run("enabled, different suite", func(t *testing.T) {
		viper.Set(constants.RestartOnlyFailedEnv, true)
		defer viper.Set(constants.RestartOnlyFailedEnv, false)
		th := newHarness(t, "gotest.txt", gotestTxt)
		if _, ok := th.previouslyPassedAt("TestOtherSuite", "TestDeviceInfo"); ok {
			t.Fatalf("expected ok=false for a mismatched suite name")
		}
	})

	t.Run("enabled, EVETEST_OUTPUT_FORMAT=json", func(t *testing.T) {
		viper.Set(constants.RestartOnlyFailedEnv, true)
		defer viper.Set(constants.RestartOnlyFailedEnv, false)
		gotestJSON := jsonOutputEvent(t, "=== RUN   TestTelemetrySuite/TestDeviceInfo\n") +
			jsonOutputEvent(t, "--- PASS: TestTelemetrySuite/TestDeviceInfo (1.00s)\n")
		th := newHarness(t, "gotest.json", gotestJSON)
		passedAt, ok := th.previouslyPassedAt(suite, "TestDeviceInfo")
		if !ok || passedAt != prevRanAt {
			t.Fatalf("got (%q, %v), want (%q, true)", passedAt, ok, prevRanAt)
		}
	})
}
