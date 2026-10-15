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

// haltBudget bounds how long an application may take to be reported HALTED after
// it is deactivated. It sits between two hardcoded budgets in domainmgr's
// doInactivate an order of magnitude apart: a stop which escalates promptly
// costs the 60s first wait, one which does not costs the 600s second wait on
// top. Neither is a measure of work, so this is not a stopwatch on a loaded
// host.
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
// timestamps the HALTING and HALTED reports as they arrive. Timing them at
// arrival rather than at read time measures the device, not the caller.
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
