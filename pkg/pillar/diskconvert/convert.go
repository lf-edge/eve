// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package diskconvert is the baseosmgr-side orchestration for the EVE-kvm <->
// EVE-k boot-disk repartition (design-doc Item 3). It runs the standalone
// storage-resizer binary's pre-flight `check`, maps the result to an action,
// and drives that action — without importing go-diskfs/partitionresizer into
// pillar (it only execs the binary).
//
// Wiring into the live baseosmgr cross-flavor update path (the
// IsHVTypeKube/IsVersionHVTypeKube seam in handlebaseos.go, relaxed by
// lf-edge/eve PR #6036) and reporting ZDEVICE_STATE_CONVERTING are done during
// the integration phase; this package provides the decision + step selection in
// an independently testable form.
package diskconvert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Decisions reported by `storage-resizer check`.
const (
	DecisionProceed      = "proceed"      // geometry already EVE-k; go to A/B install
	DecisionGrow         = "grow"         // boot disk has free tail; create partitions online
	DecisionShrink       = "shrink"       // shrink ext4 /persist (offline) to make room
	DecisionInsufficient = "insufficient" // cannot make room; stay on current flavor
)

// defaultNeededBytes is the room the new ESP2/IMGA2/IMGB2 partitions need
// (2 + 10 + 10 GB); used to derive the shrink target if the check did not
// report one.
const defaultNeededBytes = int64(22) << 30

// CheckResult is the subset of `storage-resizer check --json` this package needs.
type CheckResult struct {
	Decision       string `json:"decision"`
	DecisionReason string `json:"decisionReason"`
	Partitions     []struct {
		Name      string `json:"name"`
		SizeBytes int64  `json:"sizeBytes"`
	} `json:"partitions"`
	Shrink *struct {
		NeededBytes int64 `json:"neededBytes"`
	} `json:"spaceToShrinkExt"`
}

// Runner abstracts the storage-resizer binary so the orchestration is testable
// without a real disk or the binary present.
type Runner interface {
	// Check runs the pre-flight check on the boot disk.
	Check(bootDisk string) (CheckResult, error)
	// Backup copies the connectivity-, ssh-, and device-identity-critical files
	// (including the /persist/certs/ attestation/decryption keys) to /config and
	// writes the repartition flag file (the shrink target size), to be consumed by
	// the offline resize after the reboot.
	Backup(target string) error
	// ArmGrow writes the repartition flag file with the grow-only sentinel; no
	// backup is needed because the grow is non-destructive. storage-init performs
	// the actual grow offline after the reboot — the boot disk's partition table
	// cannot be re-read live while its own rootfs is mounted, the same constraint
	// that forces the shrink offline.
	ArmGrow() error
}

// Outcome tells the caller (baseosmgr) what to do next.
type Outcome int

const (
	// OutcomeProceed means the geometry is (now) correct; continue the A/B install.
	OutcomeProceed Outcome = iota
	// OutcomeRebootForRepartition means the flag file is written (and, on the
	// shrink path, the backup); reboot so storage-init runs the offline resize
	// (shrink+grow, or grow-only), then re-evaluate on the next boot. The
	// repartition always runs offline because the boot disk's partition table
	// cannot be re-read live while its rootfs is mounted.
	OutcomeRebootForRepartition
	// OutcomeInsufficient means room cannot be made; abort the conversion, stay put.
	OutcomeInsufficient
)

func (o Outcome) String() string {
	switch o {
	case OutcomeProceed:
		return "proceed"
	case OutcomeRebootForRepartition:
		return "reboot-for-repartition"
	case OutcomeInsufficient:
		return "insufficient"
	default:
		return fmt.Sprintf("Outcome(%d)", int(o))
	}
}

// Result describes what the conversion step decided and did.
type Result struct {
	Decision     string
	Outcome      Outcome
	Reason       string
	ShrinkTarget string // set when a shrink was planned (e.g. "81788928K")
}

// Converter orchestrates one conversion step against a boot disk.
type Converter struct {
	Runner       Runner
	PersistLabel string // GPT label of the persist partition (default "P3")
}

// Run executes one conversion step: check, then the selected action.
//
//	proceed      -> OutcomeProceed (no action)
//	grow         -> arm grow-only flag, OutcomeRebootForRepartition (caller reboots)
//	shrink       -> backup + flag file, OutcomeRebootForRepartition (caller reboots)
//	insufficient -> OutcomeInsufficient + error
func (c *Converter) Run(bootDisk string) (Result, error) {
	label := c.PersistLabel
	if label == "" {
		label = "P3"
	}
	res, err := c.Runner.Check(bootDisk)
	if err != nil {
		return Result{}, fmt.Errorf("storage-resizer check: %w", err)
	}
	r := Result{Decision: res.Decision, Reason: res.DecisionReason}

	switch res.Decision {
	case DecisionProceed:
		r.Outcome = OutcomeProceed
		return r, nil

	case DecisionGrow:
		// The grow runs OFFLINE in storage-init, not here: the boot disk's GPT
		// cannot be re-read live while its rootfs is mounted (the kernel returns
		// EBUSY on the partition-table re-read), so an online grow can never apply.
		// Arm the grow-only flag and let the caller reboot into the offline grow,
		// exactly as the shrink path does.
		if err := c.Runner.ArmGrow(); err != nil {
			return r, fmt.Errorf("arm grow-only repartition: %w", err)
		}
		r.Outcome = OutcomeRebootForRepartition
		return r, nil

	case DecisionShrink:
		target := shrinkTargetBytes(res, label)
		if target <= 0 {
			return r, fmt.Errorf("cannot determine shrink target for %q", label)
		}
		r.ShrinkTarget = sizeK(target)
		if err := c.Runner.Backup(r.ShrinkTarget); err != nil {
			return r, fmt.Errorf("backup before shrink: %w", err)
		}
		r.Outcome = OutcomeRebootForRepartition
		return r, nil

	case DecisionInsufficient:
		r.Outcome = OutcomeInsufficient
		return r, fmt.Errorf("insufficient space for conversion: %s", res.DecisionReason)

	default:
		return r, fmt.Errorf("unexpected check decision %q", res.Decision)
	}
}

// shrinkTargetBytes is the new persist size that frees the needed room at the
// disk tail: current persist partition size minus the needed bytes.
func shrinkTargetBytes(res CheckResult, persistLabel string) int64 {
	var persistSize int64
	for _, p := range res.Partitions {
		if p.Name == persistLabel {
			persistSize = p.SizeBytes
			break
		}
	}
	if persistSize == 0 {
		return 0
	}
	need := defaultNeededBytes
	if res.Shrink != nil && res.Shrink.NeededBytes > 0 {
		need = res.Shrink.NeededBytes
	}
	return persistSize - need
}

// sizeK renders bytes as a whole-KiB size string (resize2fs/storage-resizer accept it).
func sizeK(b int64) string { return fmt.Sprintf("%dK", b/1024) }

// BinaryRunner is the production Runner: it execs the storage-resizer binary.
type BinaryRunner struct {
	Binary    string // path to storage-resizer (default: look up "storage-resizer" on PATH)
	Persist   string // override --persist (default in the binary: /persist)
	BackupDir string // override --backup-dir
	FlagFile  string // override --flag-file
}

func (b BinaryRunner) bin() string {
	if b.Binary != "" {
		return b.Binary
	}
	return "storage-resizer"
}

func (b BinaryRunner) configFlags() []string {
	var a []string
	if b.Persist != "" {
		a = append(a, "--persist", b.Persist)
	}
	if b.BackupDir != "" {
		a = append(a, "--backup-dir", b.BackupDir)
	}
	if b.FlagFile != "" {
		a = append(a, "--flag-file", b.FlagFile)
	}
	return a
}

// Check runs `storage-resizer check --disk <bootDisk> --json`.
func (b BinaryRunner) Check(bootDisk string) (CheckResult, error) {
	args := []string{"check", "--disk", bootDisk, "--json"}
	cmd := exec.Command(b.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return CheckResult{}, fmt.Errorf("%s: %w\n%s", b.bin(), err, stderr.String())
	}
	var res CheckResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return CheckResult{}, fmt.Errorf("parse check output: %w", err)
	}
	return res, nil
}

// Backup runs `storage-resizer backup --target <target> [config flags]`.
func (b BinaryRunner) Backup(target string) error {
	args := append([]string{"backup", "--target", target}, b.configFlags()...)
	return runQuiet(b.bin(), args...)
}

// ArmGrow runs `storage-resizer backup --grow-only [config flags]`, which writes
// the repartition flag with the grow-only sentinel and copies no backup. The
// grow itself runs offline in storage-init after the reboot.
func (b BinaryRunner) ArmGrow() error {
	return runQuiet(b.bin(), append([]string{"backup", "--grow-only"}, b.configFlags()...)...)
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, stderr.String())
	}
	return nil
}
