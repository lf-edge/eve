// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stageRecord(t *testing.T) {
	t.Helper()
	orig := recordPath
	recordPath = filepath.Join(t.TempDir(), "quorum-recovery.json")
	t.Cleanup(func() { recordPath = orig })
}

func TestAppliedRoundTrip(t *testing.T) {
	stageRecord(t)

	if _, recorded, err := ReadApplied(); err != nil || recorded {
		t.Fatalf("absent marker gave (%v, %v); want not recorded, no error", recorded, err)
	}
	want := gen("cluster-a", 2)
	if err := WriteApplied(want, false); err != nil {
		t.Fatalf("WriteApplied: %v", err)
	}
	got, recorded, err := ReadApplied()
	if err != nil || !recorded || got != want {
		t.Errorf("ReadApplied = (%v, %v, %v), want %v recorded", got, recorded, err, want)
	}
}

// TestAppliedRole: the seed bit rides along with the generation, and a
// marker without it (written before the role was tracked) reads as not
// having been seed.
func TestAppliedRole(t *testing.T) {
	stageRecord(t)
	g := gen("cluster-a", 2)

	for _, asSeed := range []bool{true, false} {
		if err := WriteApplied(g, asSeed); err != nil {
			t.Fatalf("WriteApplied: %v", err)
		}
		got, recorded, err := ReadApplied()
		if err != nil || !recorded || got != g {
			t.Errorf("asSeed=%v: ReadApplied = (%v, %v, %v)", asSeed, got, recorded, err)
		}
		if seed, err := ReadAppliedAsSeed(); err != nil || seed != asSeed {
			t.Errorf("ReadAppliedAsSeed = (%v, %v), want %v", seed, err, asSeed)
		}
	}

}

// TestReportRejection: the reason is recorded for StampNodeStatus and
// is not rewritten while it stays the same.
func TestReportRejection(t *testing.T) {
	stageRecord(t)

	if err := reportRejection(gen("a", 0), gen("a", 1)); err != nil {
		t.Fatalf("reportRejection: %v", err)
	}
	msg, found, err := ReadFailure()
	if err != nil || !found || !strings.Contains(msg, "join_server_ip") ||
		!strings.Contains(msg, "generation 1") {
		t.Fatalf("ReadFailure = (%q, %v, %v)", msg, found, err)
	}
	if err := os.Chmod(filepath.Dir(recordPath), 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(recordPath), 0700) })
	if err := reportRejection(gen("a", 0), gen("a", 1)); err != nil {
		t.Errorf("an unchanged rejection must not be rewritten: %v", err)
	}
}

func TestIntentRoundTrip(t *testing.T) {
	stageRecord(t)

	want := Intent{
		Generation: gen("cluster-a", 1),
		Action:     ActionPromote,
		StartedAt:  time.Now(),
	}
	if err := WriteIntent(want); err != nil {
		t.Fatalf("WriteIntent: %v", err)
	}
	got, found, err := ReadIntent()
	if err != nil || !found {
		t.Fatalf("ReadIntent = (%v, %v, %v)", got, found, err)
	}
	if got.Generation != want.Generation || got.Action != want.Action ||
		!got.StartedAt.Equal(want.StartedAt) {
		t.Errorf("ReadIntent = %+v, want %+v", got, want)
	}
}

// TestResumeReturnsRecordedAction: the action must come from the
// intent, not from re-deciding. A config push landing mid-reset would
// otherwise restart the reset against a newer generation across a
// reboot, leaving a half-reset database.
func TestResumeReturnsRecordedAction(t *testing.T) {
	stageRecord(t)

	want := Intent{Generation: gen("cluster-a", 1), Action: ActionPromote,
		StartedAt: time.Unix(1000, 0)}
	if err := WriteIntent(want); err != nil {
		t.Fatalf("WriteIntent: %v", err)
	}
	got, found, err := Resume()
	if err != nil || !found {
		t.Fatalf("Resume = (%v, %v, %v)", got, found, err)
	}
	if got.Action != ActionPromote {
		t.Errorf("Resume action = %v, want promote", got.Action)
	}
}

// TestResumeIgnoresFinishedWork: an intent for a generation already
// applied is a marker that outlived its work. Re-running it would
// repeat the reset on a node that has already recovered.
func TestResumeIgnoresFinishedWork(t *testing.T) {
	stageRecord(t)

	g := gen("cluster-a", 1)
	if err := WriteIntent(Intent{Generation: g, Action: ActionPromote,
		StartedAt: time.Unix(1000, 0)}); err != nil {
		t.Fatalf("WriteIntent: %v", err)
	}
	if err := WriteApplied(g, true); err != nil {
		t.Fatalf("WriteApplied: %v", err)
	}
	_, found, err := Resume()
	if err != nil || found {
		t.Errorf("Resume = (found %v, err %v), want no work to resume", found, err)
	}
	if in, found, err := ReadIntent(); err != nil || found {
		t.Errorf("a stale intent should have been cleared, got (%v, %v, %v)", in, found, err)
	}
}

// TestResumeAfterACrashMidAction: applied still names the previous
// generation, so the work is unfinished and has to be picked up.
func TestResumeAfterACrashMidAction(t *testing.T) {
	stageRecord(t)

	if err := WriteApplied(gen("cluster-a", 0), false); err != nil {
		t.Fatalf("WriteApplied: %v", err)
	}
	if err := WriteIntent(Intent{Generation: gen("cluster-a", 1),
		Action: ActionPromote, StartedAt: time.Unix(1000, 0)}); err != nil {
		t.Fatalf("WriteIntent: %v", err)
	}
	got, found, err := Resume()
	if err != nil || !found {
		t.Fatalf("Resume = (%v, %v, %v), want the unfinished action", got, found, err)
	}
	if got.Action != ActionPromote || got.Generation != gen("cluster-a", 1) {
		t.Errorf("Resume = %+v, want the recorded promote at generation 1", got)
	}
}

func TestClearIntentIsIdempotent(t *testing.T) {
	stageRecord(t)
	if err := ClearIntent(); err != nil {
		t.Errorf("clearing an absent intent: %v", err)
	}
	if err := WriteIntent(Intent{Generation: gen("a", 1), Action: ActionPromote,
		StartedAt: time.Unix(1, 0)}); err != nil {
		t.Fatalf("WriteIntent: %v", err)
	}
	if err := ClearIntent(); err != nil {
		t.Fatalf("ClearIntent: %v", err)
	}
	if err := ClearIntent(); err != nil {
		t.Errorf("second ClearIntent: %v", err)
	}
}

func TestReadIntentRejectsMalformed(t *testing.T) {
	stageRecord(t)
	for _, raw := range []string{
		"garbage",
		`{"Intent":{"Action":"nonsense"}}`,
	} {
		if err := os.WriteFile(recordPath, []byte(raw), 0644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, found, err := ReadIntent(); err == nil || found {
			t.Errorf("ReadIntent(%q) = (found %v, err %v), want an error", raw, found, err)
		}
	}
}

// TestRecordHoldsEverythingTogether: the facts share one file, so changing
// one never loses another, and completing an intent is a single write.
func TestRecordHoldsEverythingTogether(t *testing.T) {
	stageRecord(t)
	g0, g1 := gen("a", 0), gen("a", 1)

	if err := WriteApplied(g0, true); err != nil {
		t.Fatal(err)
	}
	if err := WriteIntent(Intent{Generation: g1, Action: ActionPromote,
		StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFailure(g1, errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	if g, recorded, _ := ReadApplied(); !recorded || g != g0 {
		t.Errorf("applied lost after writing intent and failure: (%v, %v)", g, recorded)
	}
	at, _, _ := AppliedAt()

	if err := CompleteIntent(g1, true); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := ReadIntent(); found {
		t.Error("CompleteIntent left the intent behind")
	}
	if g, _, _ := ReadApplied(); g != g1 {
		t.Errorf("applied = %v, want %v", g, g1)
	}
	if msg, found, _ := ReadFailure(); !found || !strings.Contains(msg, "boom") {
		t.Errorf("CompleteIntent must not touch the failure: (%q, %v)", msg, found)
	}
	if at2, _, _ := AppliedAt(); !at2.After(at) && !at2.Equal(at) {
		t.Errorf("AppliedAt went backwards: %v -> %v", at, at2)
	}
}

// TestAppliedAtSurvivesARoleChange: only a new generation moves the time.
func TestAppliedAtSurvivesARoleChange(t *testing.T) {
	stageRecord(t)
	g := gen("a", 2)
	if err := WriteApplied(g, true); err != nil {
		t.Fatal(err)
	}
	first, _, _ := AppliedAt()
	time.Sleep(10 * time.Millisecond)
	if err := WriteApplied(g, false); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := AppliedAt(); !again.Equal(first) {
		t.Errorf("a role change moved AppliedAt: %v -> %v", first, again)
	}
}

// TestEmptyRecordRemovesTheFile: nothing recorded is not the same as an
// empty record on disk, and clearing an absent failure writes nothing.
func TestEmptyRecordRemovesTheFile(t *testing.T) {
	stageRecord(t)
	if err := ClearFailure(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(recordPath); err == nil {
		t.Error("clearing an absent failure created the file")
	}
	if err := WriteFailure(gen("a", 1), errors.New("x")); err != nil {
		t.Fatal(err)
	}
	if err := ClearFailure(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(recordPath); err == nil {
		t.Error("an emptied record should remove the file")
	}
}
