// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// haltBudget bounds how long an application may take to be reported HALTED
// after it is deactivated.
//
// What it separates are two hardcoded budgets in domainmgr's doInactivate, an
// order of magnitude apart: a stop which escalates promptly costs the 60s first
// wait plus the reap and the report, and one which does not costs the 600s
// second wait on top. Neither side is a measure of work, so a loaded host moves
// both by a little and crosses the gap by neither: the prompt path has measured
// 95-100s across ~90 runs under contention, against 636s and 701s for the two
// ways of losing the budget. 300s sits between them with room on both sides.
const haltBudget = 300 * time.Second

// haltTiming records when an application's halt transitions were reported,
// relative to the deactivation which caused them.
type haltTiming struct {
	deactivatedAt time.Time
	haltingAt     time.Time
	haltedAt      time.Time
	done          chan struct{}
}

// watchHalt takes ownership of updates from the deactivation onwards and
// timestamps the HALTING and HALTED reports as they arrive.
//
// Arrival time is the point: a caller which reads the channel later sees the
// same reports, but by then they have been sitting in it, so timing them at
// read time measures the caller rather than the device.
func watchHalt(updates <-chan *eveinfo.ZInfoApp) *haltTiming {
	ht := &haltTiming{deactivatedAt: time.Now(), done: make(chan struct{})}
	go func() {
		defer close(ht.done)
		for update := range updates {
			switch update.GetState() {
			case eveinfo.ZSwState_HALTING:
				if ht.haltingAt.IsZero() {
					ht.haltingAt = time.Now()
				}
			case eveinfo.ZSwState_HALTED:
				ht.haltedAt = time.Now()
				return
			}
		}
	}()
	return ht
}

// requireHaltedWithinBudget fails unless the application was reported HALTED
// within haltBudget of being deactivated, and logs how long it took either way.
func requireHaltedWithinBudget(t *WithT, ht *haltTiming) {
	select {
	case <-ht.done:
	case <-time.After(haltBudget):
		t.Expect(false).To(BeTrue(),
			"application was not reported HALTED within %v of being deactivated; "+
				"a stop which does not escalate costs the whole 600s budget", haltBudget)
		return
	}
	took := ht.haltedAt.Sub(ht.deactivatedAt)
	evetest.Logger().Infof("Application reported HALTED %v after being deactivated",
		took.Round(time.Second))
	t.Expect(took).To(BeNumerically("<", haltBudget),
		"application took %v to be reported HALTED", took.Round(time.Second))
}
