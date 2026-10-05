// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestDeschedulerPending covers the decision both reasons share.
//
// The boot event reads events.OnBoot live, each tick, and fires once per
// boot within the window. The periodic event is owed while an app is
// misplaced, once the node has been ready for settle, and again only settle
// after it last acted.
func TestDeschedulerPending(t *testing.T) {
	now := time.Now()
	windowOpen := now.Add(10 * time.Minute)
	windowShut := now.Add(-1 * time.Minute)
	const settle = 3 * time.Minute
	settled := now.Add(-settle)
	settling := now.Add(-settle + time.Second)

	boot := types.VmiDescheduleConfig{OnBoot: true}
	periodic := types.VmiDescheduleConfig{OnPeriodic: true}
	both := types.VmiDescheduleConfig{OnBoot: true, OnPeriodic: true}

	cases := []struct {
		name       string
		in         deschedulerInputs
		wantReason deschedulerReason
		wantOwed   bool
	}{{
		name:       "boot owed while the window is open",
		in:         deschedulerInputs{settle: settle, events: boot, bootWindowEnd: windowOpen, now: now},
		wantReason: deschedulerReasonBoot, wantOwed: true,
	}, {
		name: "boot satisfied once triggered",
		in: deschedulerInputs{settle: settle, events: boot, triggeredSinceBoot: true,
			bootWindowEnd: windowOpen, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		name:       "boot expires with the window",
		in:         deschedulerInputs{settle: settle, events: boot, bootWindowEnd: windowShut, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		// Zero means WaitForKubernetes has not returned: there is no
		// cluster to act on yet.
		name:       "boot waits for kubernetes",
		in:         deschedulerInputs{settle: settle, events: boot, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		name:       "boot not configured",
		in:         deschedulerInputs{settle: settle, bootWindowEnd: windowOpen, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		name:       "periodic owed once settled",
		in:         deschedulerInputs{settle: settle, events: periodic, misplaced: true, readySince: settled, now: now},
		wantReason: deschedulerReasonPeriodic, wantOwed: true,
	}, {
		name:       "periodic not configured",
		in:         deschedulerInputs{settle: settle, misplaced: true, readySince: settled, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		name:       "periodic waits for the node to settle",
		in:         deschedulerInputs{settle: settle, events: periodic, misplaced: true, readySince: settling, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		name:       "periodic waits for the node to be ready",
		in:         deschedulerInputs{settle: settle, events: periodic, misplaced: true, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		name: "periodic not retried right after acting",
		in: deschedulerInputs{settle: settle, events: periodic, misplaced: true, readySince: settled,
			lastPlacementRun: settling, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		name: "periodic retried once the interval has passed",
		in: deschedulerInputs{settle: settle, events: periodic, misplaced: true, readySince: settled,
			lastPlacementRun: settled, now: now},
		wantReason: deschedulerReasonPeriodic, wantOwed: true,
	}, {
		// A shorter configured settle period lets a node act sooner.
		name: "periodic owed once a shorter settle period has passed",
		in: deschedulerInputs{settle: 30 * time.Second, events: periodic, misplaced: true,
			readySince: now.Add(-31 * time.Second), now: now},
		wantReason: deschedulerReasonPeriodic, wantOwed: true,
	}, {
		name:       "periodic not owed while nothing is misplaced",
		in:         deschedulerInputs{settle: settle, events: periodic, readySince: settled, now: now},
		wantReason: deschedulerReasonNone, wantOwed: false,
	}, {
		// Both move apps with the same descheduler Job, so boot running
		// first leaves the periodic event nothing to do in the common case.
		name: "boot ahead of a pending periodic run",
		in: deschedulerInputs{settle: settle, events: both, bootWindowEnd: windowOpen,
			misplaced: true, readySince: settled, now: now},
		wantReason: deschedulerReasonBoot, wantOwed: true,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, owed := deschedulerPending(c.in)
			if owed != c.wantOwed || reason != c.wantReason {
				t.Errorf("deschedulerPending() = (%q, %t), want (%q, %t)",
					reason, owed, c.wantReason, c.wantOwed)
			}
		})
	}
}

func TestParseVmiDescheduleEvents(t *testing.T) {
	cases := []struct {
		val  string
		want types.VmiDescheduleConfig
	}{
		{"", types.VmiDescheduleConfig{}},
		{"boot", types.VmiDescheduleConfig{OnBoot: true}},
		{"periodic", types.VmiDescheduleConfig{OnPeriodic: true}},
		{" boot , periodic ", types.VmiDescheduleConfig{OnBoot: true, OnPeriodic: true}},
		// Tokens this version does not know, from a newer or an older
		// controller, are ignored rather than rejecting the setting.
		{"boot,join,future", types.VmiDescheduleConfig{OnBoot: true}},
	}
	for _, c := range cases {
		if got := parseVmiDescheduleEvents(c.val); got != c.want {
			t.Errorf("parseVmiDescheduleEvents(%q) = %+v, want %+v", c.val, got, c.want)
		}
	}
}
