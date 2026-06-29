// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Boot-reason files consumed by the EVE base-OS telemetry layer.
const (
	// BootReasonFile records why the current power cycle started.
	// Only the first writer per power cycle should set it, so the
	// original cause survives multiple chained transition reboots.
	// The on-disk value is the canonical string from
	// BootReasonKubeTransition; downstream telemetry consumers parse
	// the exact value, so changes are a coordinated rollout.
	BootReasonFile = "/persist/boot-reason"

	// RebootReasonFile is an append-only log: one line per requested
	// reboot, preserving the full sequence for post-mortem inspection.
	// Format is `[YYYY-MM-DD HH:MM:SS]: <BootReason>, <reason>` plus a
	// leading space — matches the on-disk contract that operator
	// scripts grep for.
	RebootReasonFile = "/persist/reboot-reason"

	// BootReasonKubeTransition is the canonical value written to
	// BootReasonFile when kube-init triggers a reboot. Part of the
	// telemetry on-disk contract; downstream tooling matches it
	// verbatim.
	BootReasonKubeTransition = "BootReasonKubeTransition"
)

// rebootBinary is the absolute path to /sbin/reboot. Pinned (not
// relying on $PATH lookup) because $PATH is process-environment-
// influenceable and this is a system action.
const rebootBinary = "/sbin/reboot"

// rebootSettleTime is how long RebootWithReason blocks after a
// successful /sbin/reboot invocation. /sbin/reboot returns
// immediately on Linux; the kernel takes a few seconds to actually
// halt userspace. Blocking here prevents the daemon caller from
// proceeding as if the reboot succeeded synchronously.
const rebootSettleTime = 2 * time.Minute

// Test seams. Production binds to the real syscalls; tests overwrite
// them with spies. Hooks are unexported and assumed single-threaded
// within a test (use t.Cleanup to restore).
var (
	rebootCmd = func() error {
		out, err := exec.Command(rebootBinary).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s failed: %w (output: %s)",
				rebootBinary, err, string(out))
		}
		return nil
	}
	syncFS    = syscall.Sync
	postReset = func() { time.Sleep(rebootSettleTime) }
)

// ErrInvalidRebootReason is returned by RebootWithReason when the
// reason argument contains characters that would corrupt the
// one-line-per-reboot format of RebootReasonFile (currently:
// newlines and carriage returns).
var ErrInvalidRebootReason = errors.New("invalid reboot reason")

// RebootWithReason records the reason in the persist boot-reason and
// reboot-reason files and triggers /sbin/reboot. The function blocks
// for rebootSettleTime after a successful reboot invocation, so under
// normal conditions it never returns to its caller.
//
// Sequencing matters: reason files are written FIRST (so they survive
// even if the reboot happens immediately), THEN sync'd, THEN the
// reboot is requested. Returning early would let the caller continue
// running between the reboot request and the kernel actually halting
// userspace, with unpredictable side effects.
func RebootWithReason(reason string) error {
	if strings.ContainsAny(reason, "\r\n") {
		return fmt.Errorf("%w: contains newline (%q)",
			ErrInvalidRebootReason, reason)
	}
	log.Printf("rebooting with reason: %s", reason)

	if err := prepareReboot(reason, BootReasonFile, RebootReasonFile); err != nil {
		return err
	}
	syncFS()
	if err := rebootCmd(); err != nil {
		return err
	}
	postReset()
	return nil
}

// prepareReboot records the reason in the persist files. Exposed
// only to tests so the file-writing semantics can be exercised
// without an actual reboot.
func prepareReboot(reason, bootReasonPath, rebootReasonPath string) error {
	if err := writeFirstBootReason(bootReasonPath); err != nil {
		return err
	}
	return appendRebootReason(rebootReasonPath, reason)
}

// writeFirstBootReason writes BootReasonKubeTransition to path iff
// the file does not already exist. Uses O_CREATE|O_EXCL so the
// "first writer per power cycle" invariant is enforced atomically by
// the kernel rather than by a stat/write window that another writer
// could squeeze through.
func writeFirstBootReason(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	switch {
	case err == nil:
		// We are the first writer.
		if _, werr := f.WriteString(BootReasonKubeTransition); werr != nil {
			f.Close()
			return fmt.Errorf("write boot reason to %s: %w", path, werr)
		}
		if serr := f.Sync(); serr != nil {
			f.Close()
			return fmt.Errorf("sync boot reason file %s: %w", path, serr)
		}
		if cerr := f.Close(); cerr != nil {
			return fmt.Errorf("close boot reason file %s: %w", path, cerr)
		}
		return nil
	case errors.Is(err, os.ErrExist):
		// Some earlier writer (us or the base OS) already set it.
		// Leave it alone — the original cause should survive.
		return nil
	default:
		return fmt.Errorf("open boot reason file %s: %w", path, err)
	}
}

// appendRebootReason appends a timestamped one-line record to path
// in the format the legacy on-disk contract specifies:
//
//	 [2026-05-15 14:23:45]: BootReasonKubeTransition, <reason>
//
// (Note the leading space — preserved verbatim from the shell flow's
// format string.) The file is fsync'd before close so a reboot
// triggered immediately after this call still finds the line on disk.
func appendRebootReason(path, reason string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open reboot reason file %s: %w", path, err)
	}
	line := fmt.Sprintf(" [%s]: %s, %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		BootReasonKubeTransition, reason)
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return fmt.Errorf("write reboot reason to %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync reboot reason file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close reboot reason file %s: %w", path, err)
	}
	return nil
}
