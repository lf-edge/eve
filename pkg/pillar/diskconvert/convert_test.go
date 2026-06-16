// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskconvert

import (
	"errors"
	"testing"
)

type fakeRunner struct {
	check       CheckResult
	checkErr    error
	growErr     error
	backupErr   error
	growCalls   []string // bootDisk
	backupCalls []string // target
}

func (f *fakeRunner) Check(string) (CheckResult, error) { return f.check, f.checkErr }
func (f *fakeRunner) Grow(bootDisk string) error {
	f.growCalls = append(f.growCalls, bootDisk)
	return f.growErr
}
func (f *fakeRunner) Backup(target string) error {
	f.backupCalls = append(f.backupCalls, target)
	return f.backupErr
}

func checkWith(decision string, persistGiB int64) CheckResult {
	r := CheckResult{Decision: decision, DecisionReason: "test"}
	if persistGiB > 0 {
		r.Partitions = []struct {
			Name      string `json:"name"`
			SizeBytes int64  `json:"sizeBytes"`
		}{{Name: "P3", SizeBytes: persistGiB << 30}}
		r.Shrink = &struct {
			NeededBytes int64 `json:"neededBytes"`
		}{NeededBytes: 22 << 30}
	}
	return r
}

func TestRunDecisionMatrix(t *testing.T) {
	t.Run("proceed: no resizer action", func(t *testing.T) {
		f := &fakeRunner{check: checkWith(DecisionProceed, 0)}
		c := &Converter{Runner: f}
		r, err := c.Run("/dev/sda")
		if err != nil || r.Outcome != OutcomeProceed {
			t.Fatalf("got outcome=%v err=%v, want proceed/nil", r.Outcome, err)
		}
		if len(f.growCalls) != 0 || len(f.backupCalls) != 0 {
			t.Errorf("proceed must not call resize/backup: resize=%v backup=%v", f.growCalls, f.backupCalls)
		}
	})

	t.Run("grow: resize online, then proceed", func(t *testing.T) {
		f := &fakeRunner{check: checkWith(DecisionGrow, 0)}
		c := &Converter{Runner: f}
		r, err := c.Run("/dev/sda")
		if err != nil || r.Outcome != OutcomeProceed {
			t.Fatalf("got outcome=%v err=%v, want proceed/nil", r.Outcome, err)
		}
		if len(f.growCalls) != 1 || f.growCalls[0] != "/dev/sda" {
			t.Errorf("grow must resize online with no shrink: %v", f.growCalls)
		}
		if len(f.backupCalls) != 0 {
			t.Errorf("grow must not back up: %v", f.backupCalls)
		}
	})

	t.Run("shrink: backup + reboot, correct target", func(t *testing.T) {
		f := &fakeRunner{check: checkWith(DecisionShrink, 100)} // 100G persist, need 22G -> 78G
		c := &Converter{Runner: f}
		r, err := c.Run("/dev/sda")
		if err != nil || r.Outcome != OutcomeRebootForShrink {
			t.Fatalf("got outcome=%v err=%v, want reboot-for-shrink/nil", r.Outcome, err)
		}
		want := sizeK((100 << 30) - (22 << 30)) // 78 GiB in KiB
		if r.ShrinkTarget != want {
			t.Errorf("shrink target = %q, want %q", r.ShrinkTarget, want)
		}
		if len(f.backupCalls) != 1 || f.backupCalls[0] != want {
			t.Errorf("backup must be called once with the target: %v", f.backupCalls)
		}
		if len(f.growCalls) != 0 {
			t.Errorf("shrink path defers resize to the offline boot, must not resize online: %v", f.growCalls)
		}
	})

	t.Run("insufficient: error, no action", func(t *testing.T) {
		f := &fakeRunner{check: checkWith(DecisionInsufficient, 0)}
		c := &Converter{Runner: f}
		r, err := c.Run("/dev/sda")
		if err == nil || r.Outcome != OutcomeInsufficient {
			t.Fatalf("got outcome=%v err=%v, want insufficient/error", r.Outcome, err)
		}
		if len(f.growCalls) != 0 || len(f.backupCalls) != 0 {
			t.Errorf("insufficient must not act: resize=%v backup=%v", f.growCalls, f.backupCalls)
		}
	})
}

func TestRunCheckErrorPropagates(t *testing.T) {
	f := &fakeRunner{checkErr: errors.New("disk gone")}
	c := &Converter{Runner: f}
	if _, err := c.Run("/dev/sda"); err == nil {
		t.Fatal("expected check error to propagate")
	}
}

func TestRunShrinkBackupFailureSurfaces(t *testing.T) {
	f := &fakeRunner{check: checkWith(DecisionShrink, 100), backupErr: errors.New("config full")}
	c := &Converter{Runner: f}
	r, err := c.Run("/dev/sda")
	if err == nil {
		t.Fatal("expected backup failure to surface (must not reboot without a backup)")
	}
	if r.Outcome == OutcomeRebootForShrink {
		t.Error("must not signal reboot when the backup failed")
	}
}

func TestShrinkTargetMissingPersist(t *testing.T) {
	// shrink decided but no P3 in the partition list -> cannot compute target
	f := &fakeRunner{check: CheckResult{Decision: DecisionShrink}}
	c := &Converter{Runner: f}
	if _, err := c.Run("/dev/sda"); err == nil {
		t.Fatal("expected an error when the persist partition size is unknown")
	}
}
