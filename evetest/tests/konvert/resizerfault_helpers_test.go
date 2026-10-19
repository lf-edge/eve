// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"regexp"
	"strings"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// Whether the offline resize was interruptible is a property of the image, and
// the resizer announces it on the serial console: run-watchdog prints one line
// per resize attempt saying which way it opened /dev/watchdog. Reading that back
// is the only way a test can tell an interrupted resize from an uninterrupted
// one, because the resize retry loop runs in storage-init before pillar starts,
// so a watchdog reset there leaves no reboot reason and no device log behind.
//
// Without this distinction a conversion that injected nothing is indistinguishable
// from one that survived repeated resets: both converge and both verify clean.
const (
	// A stress build holds the watchdog without feeding it, so it fires.
	wdHoldingMarker = "run-watchdog: holding "
	wdNoPetMarker   = "WITHOUT petting"
	// An ordinary build feeds it, so a long resize is never cut short.
	wdFeedingMarker = "run-watchdog: feeding "
	// Either build prints this when the device could not be opened at all.
	wdMissingMarker = "run-watchdog: no "
)

// resizerFaultMode is what the console says about this image's ability to
// interrupt the offline resize.
type resizerFaultMode int

const (
	// resizerFaultUnknown: no run-watchdog line at all, so the resizer either
	// never ran or its console output was not captured.
	resizerFaultUnknown resizerFaultMode = iota
	// resizerFaultDisarmed: the resizer ran but found no usable watchdog, so
	// nothing could interrupt it however the image was built.
	resizerFaultDisarmed
	// resizerFaultOff: the watchdog is fed normally; an ordinary build.
	resizerFaultOff
	// resizerFaultOn: the watchdog is held unfed; a stress build.
	resizerFaultOn
)

func (m resizerFaultMode) String() string {
	switch m {
	case resizerFaultDisarmed:
		return "DISARMED"
	case resizerFaultOff:
		return "OFF"
	case resizerFaultOn:
		return "ON"
	default:
		return "UNKNOWN"
	}
}

// resizeFaultReport summarizes what the resize actually went through.
type resizeFaultReport struct {
	mode     resizerFaultMode
	attempts int
	// cut counts the attempts that never reached the next one, split by the step
	// they died in. Only a shrink cut can tear an app volume: it is the step that
	// relocates data, whereas a fire during the grow moves nothing.
	shrinkCuts int
	growCuts   int
}

func (r resizeFaultReport) String() string {
	return fmt.Sprintf("fault=%s attempts=%d cut-in-shrink=%d cut-in-grow=%d",
		r.mode, r.attempts, r.shrinkCuts, r.growCuts)
}

var (
	resizeAttemptRE    = regexp.MustCompile(`storage-resizer: (shrink\+grow|grow-only) requested on \S+ \(attempt \d+\)`)
	resizeShrinkDoneRE = regexp.MustCompile(`storage-resizer: shrink step done \(attempt \d+\)`)
	resizeCommittedRE  = regexp.MustCompile(`storage-resizer: (shrink|grow) committed the GPT; rebooting to apply`)
)

// resizeAttempt is one pass of the resizer's retry loop.
type resizeAttempt struct {
	growOnly bool
	// shrunk: the shrink step finished, so anything that cut this attempt short
	// landed in the grow.
	shrunk bool
	// committed: the attempt ended by committing the GPT, which reboots on
	// purpose, so it is followed by another attempt without having been cut.
	committed bool
}

// parseResizerFault derives the report from raw console output. Attempts are
// taken in the order the console prints them, because the lines that end one do
// not carry its number. An attempt followed by another ended early, and that is
// a cut unless it committed the GPT; a cut lands in the grow if that attempt
// announced its shrink step done, and in the shrink otherwise. The final attempt
// is the one that converged and is never a cut.
func parseResizerFault(console string) resizeFaultReport {
	var r resizeFaultReport

	switch {
	case strings.Contains(console, wdHoldingMarker) && strings.Contains(console, wdNoPetMarker):
		r.mode = resizerFaultOn
	case strings.Contains(console, wdFeedingMarker):
		r.mode = resizerFaultOff
	case strings.Contains(console, wdMissingMarker):
		r.mode = resizerFaultDisarmed
	default:
		r.mode = resizerFaultUnknown
	}

	var attempts []*resizeAttempt
	for _, line := range strings.Split(console, "\n") {
		if m := resizeAttemptRE.FindStringSubmatch(line); m != nil {
			attempts = append(attempts, &resizeAttempt{growOnly: m[1] == "grow-only"})
			continue
		}
		if len(attempts) == 0 {
			continue
		}
		cur := attempts[len(attempts)-1]
		switch {
		case resizeShrinkDoneRE.MatchString(line):
			cur.shrunk = true
		case resizeCommittedRE.MatchString(line):
			cur.committed = true
		}
	}

	r.attempts = len(attempts)
	for i, a := range attempts {
		if i == len(attempts)-1 || a.committed {
			continue
		}
		if a.shrunk || a.growOnly {
			r.growCuts++
		} else {
			r.shrinkCuts++
		}
	}
	return r
}

// recordResizeFault reads the console after a conversion and reports what the
// resize went through, so no result is published without saying whether anything
// interrupted the resize that produced it. It never fails: a layout claim holds
// whether or not the resize was cut, and not every provider exposes a watchdog.
func recordResizeFault(device *evetest.EdgeDevice) resizeFaultReport {
	log := evetest.Logger()
	console, err := device.ConsoleOutput()
	if err != nil {
		log.Warnf("[RESIZE-FAULT] console unavailable (%v); whether the resize was "+
			"interrupted is unknown", err)
		return resizeFaultReport{}
	}
	r := parseResizerFault(console)
	log.Infof("[RESIZE-FAULT] %s", r)
	return r
}

// assertResizeFaultAccounted is recordResizeFault for a test that claims data
// survived the conversion. Such a claim is only worth anything if something could
// have damaged the data, so here an image that could not arm the watchdog is a
// failure rather than a note: the conversion then completes untouched and the
// volume verifies perfectly, which reads exactly like evidence that an interrupted
// shrink preserves the data. assertWatchdogDriverBound catches that with the
// system up; this catches it on the resizer's own path, which runs much earlier
// and is the one that decides whether the resize gets cut.
func assertResizeFaultAccounted(t Gomega, device *evetest.EdgeDevice) resizeFaultReport {
	r := recordResizeFault(device)

	t.Expect(r.mode).NotTo(Equal(resizerFaultUnknown),
		"the resizer never announced a watchdog on the console, so it may not have "+
			"run at all; a clean result here cannot be attributed to the conversion")
	t.Expect(r.mode).NotTo(Equal(resizerFaultDisarmed),
		"the resizer found no usable watchdog and ran uninterrupted, so this run "+
			"measures nothing about an interrupted resize; check that the provider "+
			"exposes a watchdog and that the chipset may reset the guest")

	if r.mode == resizerFaultOn && r.shrinkCuts == 0 {
		// Not fatal: the timeout ladder escalates past the shrink once an attempt
		// clears it, so a run can legitimately cut only the grow. It does mean this
		// run carries no evidence about a torn relocation, which is worth saying
		// plainly rather than leaving to be inferred from a passing result.
		log := evetest.Logger()
		log.Warnf("[RESIZE-FAULT] no reset landed in the shrink; this run says " +
			"nothing about a relocation being torn")
	}
	return r
}
