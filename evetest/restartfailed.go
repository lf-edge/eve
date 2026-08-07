// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/spf13/viper"
)

// artifactDirTimestampLayout matches the timestamp suffix that entrypoint.sh
// appends to each run's artifact directory name, e.g.
// "TestFooSuite-2026-08-07_08-16-29".
const artifactDirTimestampLayout = "2006-01-02_15-04-05"

// restartOnlyFailedSkipMsgTmpl is logged, with the (sub)test's full name and
// the original pass timestamp substituted in for the two %s, whenever a subtest
// is skipped because EVETEST_RESTART_ONLY_FAILED found that it already
// passed in a previous run. findPreviousPass parses this exact message back
// out of a previous gotest.txt, using a regex built from this same template
// (regexp.QuoteMeta leaves "%s" alone, so the timestamp placeholder can just
// be swapped for a capture group), so that a chain of skipped reruns still
// reports the timestamp of the run that actually executed the test.
const restartOnlyFailedSkipMsgTmpl = "%s already passed in a previous run at %s, " +
	"skipping (EVETEST_RESTART_ONLY_FAILED is enabled)"

// previouslyPassedAt implements EVETEST_RESTART_ONLY_FAILED: it reports
// whether the given (sub)test of the given suite already passed in a
// previous run, and if so, the timestamp at which it actually executed
// (which may predate the previous run itself, if that run had in turn
// skipped it via this same mechanism).
//
// ok is false whenever the feature does not apply: it is disabled, there is
// no earlier run of the same suite to consult, or the test's pass could not be
// confirmed there. The caller should just run the test normally in that case.
func (th *TestHarness) previouslyPassedAt(
	suiteName, testName string) (passedAt string, ok bool) {
	if !viper.GetBool(constants.RestartOnlyFailedEnv) {
		return "", false
	}

	_, thisRanAt, ok := parseArtifactDirName(filepath.Base(th.artifactDir))
	if !ok {
		th.log.Debugf("Artifact dir %q is not timestamped, skipping "+
			"restart-only-failed check", th.artifactDir)
		return "", false
	}

	artifactsRoot := filepath.Dir(th.artifactDir)
	prevDir, ranAt, err := previousArtifactDir(artifactsRoot, suiteName, thisRanAt)
	if err != nil {
		th.log.Debugf("Could not determine the previous artifact directory: %v", err)
		return "", false
	}

	// entrypoint.sh writes either gotest.txt (default "go test -v" output, or
	// no per-test lines at all under EVETEST_OUTPUT_FORMAT=quiet) or
	// gotest.json (EVETEST_OUTPUT_FORMAT=json), never both -- try the text
	// form first since it is the default.
	textPath := filepath.Join(prevDir, "gotest.txt")
	if data, err := os.ReadFile(textPath); err == nil {
		return findPreviousPass(string(data), suiteName, testName, ranAt)
	}

	jsonPath := filepath.Join(prevDir, "gotest.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		th.log.Debugf("Could not read %s or %s", textPath, jsonPath)
		return "", false
	}

	return findPreviousPassJSON(data, suiteName, testName, ranAt)
}

// previousArtifactDir finds the most recent earlier run of the given suite by
// looking for the newest "<suiteName>-<timestamp>" directory under
// artifactsRoot that predates the current run (identified by its timestamp,
// thisRanAt). Nothing needs to record which run came last: the artifact
// directory names themselves say it, and CI can make the previous attempt's
// artifact discoverable simply by unpacking it under artifactsRoot with its
// original name.
func previousArtifactDir(
	artifactsRoot, suiteName, thisRanAt string) (dir, ranAt string, err error) {
	entries, err := os.ReadDir(artifactsRoot)
	if err != nil {
		return "", "", fmt.Errorf("cannot list %s: %w", artifactsRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name, timestamp, ok := parseArtifactDirName(entry.Name())
		if !ok || name != suiteName {
			continue
		}
		// artifactDirTimestampLayout is zero-padded most-significant-first, so
		// comparing timestamps as strings orders them chronologically.
		if timestamp >= thisRanAt || timestamp <= ranAt {
			continue
		}
		dir, ranAt = filepath.Join(artifactsRoot, entry.Name()), timestamp
	}

	if dir == "" {
		err = fmt.Errorf("no artifact directory of an earlier %s run found in %s",
			suiteName, artifactsRoot)
		return "", "", err
	}
	return dir, ranAt, nil
}

// parseArtifactDirName splits an artifact directory name of the form
// "<name>-YYYY-MM-DD_HH-MM-SS" (see entrypoint.sh) into the test/suite name
// and the run timestamp.
func parseArtifactDirName(dirName string) (name, timestamp string, ok bool) {
	if len(dirName) <= len(artifactDirTimestampLayout)+1 {
		return "", "", false
	}
	sep := len(dirName) - len(artifactDirTimestampLayout) - 1
	if dirName[sep] != '-' {
		return "", "", false
	}
	name, timestamp = dirName[:sep], dirName[sep+1:]
	if _, err := time.Parse(artifactDirTimestampLayout, timestamp); err != nil {
		return "", "", false
	}
	return name, timestamp, true
}

// findPreviousPass scans plain "go test -v" output (as produced by
// entrypoint.sh into gotest.txt, or reconstructed from gotest.json by
// findPreviousPassJSON) for evidence that the "<suiteName>/<testName>"
// subtest passed: either its own "--- PASS: <suiteName>/<testName> (...)"
// line, or restartOnlyFailedSkipMsgTmpl recording that it had already passed
// even earlier. This is purely an optimization to skip redundant work, so
// anything short of positive proof of a pass -- including a previous run
// that failed, or was interrupted before completing -- is treated the same
// as "unknown": ok=false, meaning the caller just runs the test again.
func findPreviousPass(
	gotest, suiteName, testName, ranAt string) (passedAt string, ok bool) {
	fullName := suiteName + "/" + testName
	pattern := fmt.Sprintf(regexp.QuoteMeta(restartOnlyFailedSkipMsgTmpl),
		regexp.QuoteMeta(fullName), `(\S+)`)
	if m := regexp.MustCompile(pattern).FindStringSubmatch(gotest); m != nil {
		return m[1], true
	}

	if strings.Contains(gotest, "--- PASS: "+fullName+" (") {
		return ranAt, true
	}

	return "", false
}

// goTestJSONEvent is one line of "go test -json" output (see TestEvent in
// cmd/test2json). Only the Output events are needed here.
type goTestJSONEvent struct {
	Action string
	Output string
}

// findPreviousPassJSON is the EVETEST_OUTPUT_FORMAT=json counterpart of
// findPreviousPass. "go test -json" is a line-oriented conversion of the same
// "-v" text protocol: every raw line -- "=== RUN"/"--- PASS" lines as well as
// any output a test logs -- is preserved verbatim, in original order, as some
// event's Output field. Reassembling those recovers exactly the text
// findPreviousPass already knows how to parse, so there is no separate
// implementation (and no separate risk of the two drifting apart) to
// maintain here.
func findPreviousPassJSON(
	gotestJSON []byte, suiteName, testName, ranAt string) (passedAt string, ok bool) {
	var text strings.Builder
	dec := json.NewDecoder(bytes.NewReader(gotestJSON))
	for {
		var ev goTestJSONEvent
		if err := dec.Decode(&ev); err != nil {
			break
		}
		if ev.Action == "output" {
			text.WriteString(ev.Output)
		}
	}
	return findPreviousPass(text.String(), suiteName, testName, ranAt)
}
