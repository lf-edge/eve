// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// newCrashedDomain returns a running domain of an activated config, wired the
// way the boot retry test does it, with no adapters and no vTPM.
func newCrashedDomain(t *testing.T) (*domainContext, *types.DomainStatus, *recordingTask) {
	t.Helper()
	appUUID, err := uuid.FromString("0b6f4c2e-7d1a-4f3b-9c5d-2e8a6b7c9d10")
	if err != nil {
		t.Fatal(err)
	}
	config := types.DomainConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: appUUID, Version: "1"},
		DisplayName:    "crashing-app",
		Activate:       true,
		AppNum:         2,
		VmConfig: types.VmConfig{
			VirtualizationMode: types.HVM,
			DisableVirtualTPM:  true,
		},
	}
	task := newRecordingHypervisor(t)
	configs := &mapSubscription{items: map[string]interface{}{config.Key(): config}}
	ctx := newRetryBootContext(t, &types.AssignableAdapters{Initialized: true}, configs)
	status := &types.DomainStatus{
		UUIDandVersion: config.UUIDandVersion,
		DisplayName:    config.DisplayName,
		DomainName:     config.GetTaskName(),
		AppNum:         config.AppNum,
		VmConfig:       config.VmConfig,
		State:          types.RUNNING,
		Activated:      true,
		DomainId:       7,
		BootTime:       time.Now(),
	}
	publishDomainStatus(ctx, status)
	return ctx, status, task
}

// A guest that crashed is torn down and booted again once timer.boot.retry
// has passed, like a domain that failed to boot, up to maxCrashRetries times
// in a row; past them it stays BROKEN for the operator to restart.
func TestCrashedGuestIsBootedAgain(t *testing.T) {
	ctx, status, _ := newCrashedDomain(t)
	const crash = "guest VM crashed, guest core saved"

	for i := 1; i <= maxCrashRetries; i++ {
		status.Activated, status.State, status.DomainId = true, types.RUNNING, 7
		brokenAndTeardown(ctx, status, crash)
		if status.State != types.BROKEN || status.Activated || status.DomainId != 0 {
			t.Fatalf("crash %d: domain not torn down: state %s activated %v id %d",
				i, status.State, status.Activated, status.DomainId)
		}
		if !status.BootFailed || status.CrashRetries != i {
			t.Fatalf("crash %d: no boot retry scheduled: bootFailed %v retries %d",
				i, status.BootFailed, status.CrashRetries)
		}
		if status.Error != crash || status.ErrorSeverity != types.ErrorSeverityWarning ||
			!strings.Contains(status.ErrorRetryCondition, fmt.Sprintf("%d of %d", i, maxCrashRetries)) {
			t.Fatalf("crash %d: error %q severity %d retry %q", i,
				status.Error, status.ErrorSeverity, status.ErrorRetryCondition)
		}

		// Not before timer.boot.retry has passed since the crash.
		tried := status.TriedCount
		maybeRetryBoot(ctx, status)
		if status.TriedCount != tried {
			t.Fatalf("crash %d: boot retried before timer.boot.retry passed", i)
		}
		status.ErrorTime = time.Now().Add(-time.Duration(ctx.domainBootRetryTime+1) * time.Second)
		maybeRetryBoot(ctx, status)
		if status.TriedCount != tried+1 {
			t.Fatalf("crash %d: boot not retried after timer.boot.retry passed", i)
		}
		// The recording hypervisor cannot create domains, so the retry failed
		// like any boot failure; the count of crash retries is untouched.
		if !status.BootFailed || status.CrashRetries != i {
			t.Fatalf("crash %d: after the retry: bootFailed %v retries %d",
				i, status.BootFailed, status.CrashRetries)
		}
	}

	status.Activated, status.State, status.DomainId = true, types.RUNNING, 7
	brokenAndTeardown(ctx, status, crash)
	if status.BootFailed || status.CrashRetries != maxCrashRetries {
		t.Fatalf("crash %d: a boot retry was scheduled past the limit: bootFailed %v retries %d",
			maxCrashRetries+1, status.BootFailed, status.CrashRetries)
	}
	if !strings.Contains(status.Error, crash) || !strings.Contains(status.Error, "please restart application instance") {
		t.Fatalf("crash %d: error %q does not ask for a restart", maxCrashRetries+1, status.Error)
	}
	if status.State != types.BROKEN || status.Activated {
		t.Fatalf("crash %d: state %s activated %v", maxCrashRetries+1, status.State, status.Activated)
	}
}

// A domain that has run for crashRetryGrace since its last boot gets its
// retries back; one that just booted keeps them, as does one not running.
func TestCrashRetriesForgottenAfterGrace(t *testing.T) {
	ctx, status, _ := newCrashedDomain(t)
	status.CrashRetries = 2

	status.BootTime = time.Now()
	forgetCrashRetries(ctx, status, types.RUNNING)
	if status.CrashRetries != 2 {
		t.Fatalf("retries forgotten right after the boot: %d", status.CrashRetries)
	}
	status.BootTime = time.Now().Add(-crashRetryGrace)
	forgetCrashRetries(ctx, status, types.BOOTING)
	if status.CrashRetries != 2 {
		t.Fatalf("retries forgotten while not running: %d", status.CrashRetries)
	}
	forgetCrashRetries(ctx, status, types.RUNNING)
	if status.CrashRetries != 0 {
		t.Fatalf("retries not forgotten after %s of running: %d", crashRetryGrace, status.CrashRetries)
	}
}
