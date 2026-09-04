// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// The budget the poweroff request gets decides how long an application stays
// reported as halting when its guest cannot service that request. A guest whose
// mode carries no meaning for the hypervisor running it must not hold the whole
// budget before the stop is escalated. No remaining hypervisor acts on the
// mode, so that applies to every mode.
func TestShutdownBudget(t *testing.T) {
	const maxDelay = 600 * time.Second

	tests := []struct {
		name           string
		mode           types.VmMode
		maxDelay       time.Duration
		wantShutdown   bool
		wantFirstDelay time.Duration
	}{
		{
			name:           "PV is the unset default and waits briefly",
			mode:           types.PV,
			maxDelay:       maxDelay,
			wantShutdown:   true,
			wantFirstDelay: gracefulShutdownWait,
		},
		{
			name:           "HVM waits briefly",
			mode:           types.HVM,
			maxDelay:       maxDelay,
			wantShutdown:   true,
			wantFirstDelay: gracefulShutdownWait,
		},
		{
			name:           "FML waits briefly",
			mode:           types.FML,
			maxDelay:       maxDelay,
			wantShutdown:   true,
			wantFirstDelay: gracefulShutdownWait,
		},
		{
			name:         "NOHYPER is never asked to power off",
			mode:         types.NOHYPER,
			maxDelay:     maxDelay,
			wantShutdown: false,
		},
		{
			name:         "LEGACY is never asked to power off",
			mode:         types.LEGACY,
			maxDelay:     maxDelay,
			wantShutdown: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doShutdown, firstDelay := shutdownBudget(tt.mode, tt.maxDelay)
			if doShutdown != tt.wantShutdown {
				t.Fatalf("doShutdown = %v, want %v", doShutdown, tt.wantShutdown)
			}
			if doShutdown && firstDelay != tt.wantFirstDelay {
				t.Errorf("firstDelay = %v, want %v", firstDelay, tt.wantFirstDelay)
			}
		})
	}
}
