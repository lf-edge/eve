// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"
	"time"
)

// sat2am is the reference time used throughout: Saturday 2026-06-27 02:00:00 UTC.
var sat2am = time.Date(2026, time.June, 27, 2, 0, 0, 0, time.UTC)

// simulateWeek drives CronShouldFire across a synthetic week one minute at a
// time, starting from start, for totalDays calendar days. Returns the times
// at which the spec fired. No real time.Sleep involved.
func simulateWeek(spec string, start time.Time, totalDays int) []time.Time {
	var lastFired time.Time
	var fired []time.Time
	end := start.Add(time.Duration(totalDays) * 24 * time.Hour)
	for tick := start; tick.Before(end); tick = tick.Add(time.Minute) {
		if CronShouldFire(spec, tick, &lastFired) {
			fired = append(fired, tick)
		}
	}
	return fired
}

// TestCronShouldFireDefaultSchedules drives the two default trim schedules
// through a full synthetic week (Monday→Sunday+1) and verifies that each
// fires exactly twice — once Saturday and once Sunday at the expected hour.
// No real sleep; time is advanced one synthetic minute per iteration.
func TestCronShouldFireDefaultSchedules(t *testing.T) {
	// Start on Monday 2026-06-22 00:00 UTC so the week contains both
	// Saturday (Jun 27) and Sunday (Jun 28).
	monday := time.Date(2026, time.June, 22, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		spec      string
		wantCount int
		wantHour  int
	}{
		{"vault trim default 0 2 * * 6,0", "0 2 * * 6,0", 2, 2},
		{"pool trim default 0 3 * * 6,0", "0 3 * * 6,0", 2, 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fired := simulateWeek(tc.spec, monday, 9) // Mon → following Mon
			if len(fired) != tc.wantCount {
				t.Fatalf("fired %d times, want %d; times: %v", len(fired), tc.wantCount, fired)
			}
			for _, ft := range fired {
				if ft.Hour() != tc.wantHour || ft.Minute() != 0 {
					t.Errorf("fired at %s, want %02d:00", ft.Format("Mon 15:04"), tc.wantHour)
				}
				wd := ft.Weekday()
				if wd != time.Saturday && wd != time.Sunday {
					t.Errorf("fired on %s, want Saturday or Sunday", wd)
				}
			}
		})
	}
}

func TestCronMatch(t *testing.T) {
	tests := []struct {
		name string
		spec string
		at   time.Time
		want bool
	}{
		// Empty / malformed specs.
		{
			name: "empty spec always false",
			spec: "",
			at:   sat2am,
			want: false,
		},
		{
			name: "four fields rejected",
			spec: "0 2 * *",
			at:   sat2am,
			want: false,
		},
		{
			name: "six fields rejected",
			spec: "0 2 * * 6 2026",
			at:   sat2am,
			want: false,
		},

		// Wildcard.
		{
			name: "all wildcards matches any time",
			spec: "* * * * *",
			at:   sat2am,
			want: true,
		},

		// Default vault trim schedule: 0 2 * * 6,0 (Sat+Sun 02:00).
		{
			name: "vault trim default: Saturday 02:00 matches",
			spec: "0 2 * * 6,0",
			at:   sat2am, // Saturday 02:00
			want: true,
		},
		{
			name: "vault trim default: Saturday 02:01 no match (minute)",
			spec: "0 2 * * 6,0",
			at:   sat2am.Add(time.Minute),
			want: false,
		},
		{
			name: "vault trim default: Saturday 03:00 no match (hour)",
			spec: "0 2 * * 6,0",
			at:   sat2am.Add(time.Hour),
			want: false,
		},
		{
			name: "vault trim default: Sunday 02:00 matches",
			spec: "0 2 * * 6,0",
			at:   sat2am.Add(24 * time.Hour), // Sunday
			want: true,
		},
		{
			name: "vault trim default: Friday 02:00 no match (weekday)",
			spec: "0 2 * * 6,0",
			at:   sat2am.Add(-24 * time.Hour), // Friday
			want: false,
		},

		// Default pool trim schedule: 0 3 * * 6,0 (Sat+Sun 03:00).
		{
			name: "pool trim default: Saturday 03:00 matches",
			spec: "0 3 * * 6,0",
			at:   sat2am.Add(time.Hour), // Saturday 03:00
			want: true,
		},
		{
			name: "pool trim default: Saturday 02:00 no match",
			spec: "0 3 * * 6,0",
			at:   sat2am,
			want: false,
		},

		// Weekday 7 treated as Sunday.
		{
			name: "weekday 7 matches Sunday",
			spec: "0 2 * * 7",
			at:   sat2am.Add(24 * time.Hour), // Sunday
			want: true,
		},
		{
			name: "weekday 7 does not match Saturday",
			spec: "0 2 * * 7",
			at:   sat2am,
			want: false,
		},

		// Step expressions.
		{
			name: "*/15 minute: matches minute 0",
			spec: "*/15 * * * *",
			at:   sat2am, // minute=0
			want: true,
		},
		{
			name: "*/15 minute: matches minute 15",
			spec: "*/15 * * * *",
			at:   sat2am.Add(15 * time.Minute),
			want: true,
		},
		{
			name: "*/15 minute: matches minute 30",
			spec: "*/15 * * * *",
			at:   sat2am.Add(30 * time.Minute),
			want: true,
		},
		{
			name: "*/15 minute: matches minute 45",
			spec: "*/15 * * * *",
			at:   sat2am.Add(45 * time.Minute),
			want: true,
		},
		{
			name: "*/15 minute: no match at minute 7",
			spec: "*/15 * * * *",
			at:   sat2am.Add(7 * time.Minute),
			want: false,
		},

		// Monthly schedule (1st of month at midnight).
		{
			name: "monthly: matches 1st of month midnight",
			spec: "0 0 1 * *",
			at:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "monthly: no match on 2nd of month",
			spec: "0 0 1 * *",
			at:   time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC),
			want: false,
		},
		{
			name: "monthly: no match on 1st at wrong hour",
			spec: "0 0 1 * *",
			at:   time.Date(2026, time.January, 1, 1, 0, 0, 0, time.UTC),
			want: false,
		},

		// Specific month constraint.
		{
			name: "month 6 matches June",
			spec: "0 0 1 6 *",
			at:   time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "month 6 does not match July",
			spec: "0 0 1 6 *",
			at:   time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
			want: false,
		},

		// Step on a base-1 field: "*/2" day-of-month must start at 1
		// (odd days), matching standard cron rather than even days.
		{
			name: "day */2 matches the 1st",
			spec: "0 0 */2 * *",
			at:   time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "day */2 matches the 3rd",
			spec: "0 0 */2 * *",
			at:   time.Date(2026, time.January, 3, 0, 0, 0, 0, time.UTC),
			want: true,
		},
		{
			name: "day */2 does not match the 2nd",
			spec: "0 0 */2 * *",
			at:   time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CronMatch(tc.spec, tc.at)
			if got != tc.want {
				t.Errorf("CronMatch(%q, %v) = %v, want %v",
					tc.spec, tc.at.Format(time.RFC3339), got, tc.want)
			}
		})
	}
}

// tickSequence drives CronShouldFire through a slice of wall-clock times and
// returns a bitmask of which ticks fired (bit 0 = tick 0, etc.).
func tickSequence(spec string, ticks []time.Time) uint64 {
	var lastFired time.Time
	var fired uint64
	for i, tick := range ticks {
		if CronShouldFire(spec, tick, &lastFired) {
			fired |= 1 << uint(i)
		}
	}
	return fired
}

func TestCronShouldFire(t *testing.T) {
	// base: Saturday 2026-06-27 02:00:00 UTC (matches "0 2 * * 6,0").
	base := sat2am

	// Helper to build a tick N minutes after base.
	m := func(n int) time.Time { return base.Add(time.Duration(n) * time.Minute) }

	tests := []struct {
		name     string
		spec     string
		ticks    []time.Time
		wantMask uint64 // bitmask: bit i set if tick i should fire
	}{
		{
			// Every 15-minute spec fires at 0, 15, 30, 45 min past the hour.
			// The bug (23h guard) would only fire tick 0 and then silence for ~23h.
			name:     "every 15 min fires four times per hour",
			spec:     "*/15 * * * *",
			ticks:    []time.Time{m(0), m(15), m(30), m(45), m(60)},
			wantMask: 0b11111, // all five ticks fire (0, 15, 30, 45, 60 are all ≡0 mod 15)
		},
		{
			// Non-matching minute between two matching minutes does not fire.
			name:     "non-matching minute skipped",
			spec:     "*/15 * * * *",
			ticks:    []time.Time{m(0), m(1), m(15)},
			wantMask: 0b101, // ticks 0 and 2 fire; tick 1 (minute 1) does not
		},
		{
			// Two ticks at the same truncated minute (e.g. ticker jitter) must
			// not fire twice.
			name: "double-tick at same minute fires once",
			spec: "*/15 * * * *",
			ticks: []time.Time{
				m(0),
				m(0).Add(30 * time.Second), // same truncated minute
				m(15),
			},
			wantMask: 0b101, // ticks 0 and 2 fire; tick 1 (same minute) does not
		},
		{
			// Daily spec fires once on matching day/time, not again until the
			// next calendar match.
			name:     "daily spec fires once per day",
			spec:     "0 2 * * 6,0", // Sat+Sun 02:00
			ticks:    []time.Time{m(0), m(1), base.Add(24 * time.Hour)},
			wantMask: 0b101, // tick 0 (Sat 02:00) and tick 2 (Sun 02:00) fire
		},
		{
			// Empty spec never fires.
			name:     "empty spec never fires",
			spec:     "",
			ticks:    []time.Time{m(0), m(15), m(30)},
			wantMask: 0,
		},
		{
			// Non-matching time never fires.
			name:     "no match never fires",
			spec:     "0 4 * * 1", // Monday 04:00
			ticks:    []time.Time{m(0), m(15), m(30)},
			wantMask: 0,
		},
		{
			// lastFired resets correctly: after one fire, a non-matching tick,
			// then another matching tick at a different minute fires again.
			name:     "fires again at next matching minute after gap",
			spec:     "*/30 * * * *",
			ticks:    []time.Time{m(0), m(7), m(30)},
			wantMask: 0b101, // m(0) and m(30) fire; m(7) does not
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tickSequence(tc.spec, tc.ticks)
			if got != tc.wantMask {
				t.Errorf("tick firing mask = %b, want %b", got, tc.wantMask)
				for i, tick := range tc.ticks {
					fired := got&(1<<uint(i)) != 0
					t.Logf("  tick[%d] %s fired=%v", i, tick.Format("Mon 15:04:05"), fired)
				}
			}
		})
	}
}

func TestCronFieldMatch(t *testing.T) {
	// lo/hi are the field's valid range (minute 0-59 unless noted).
	tests := []struct {
		name      string
		field     string
		val       int
		lo, hi    int
		isWeekday bool
		want      bool
	}{
		// Wildcard.
		{"wildcard matches any", "*", 42, 0, 59, false, true},
		{"wildcard matches zero", "*", 0, 0, 59, false, true},

		// Single numeric.
		{"single value match", "5", 5, 0, 59, false, true},
		{"single value no match", "5", 6, 0, 59, false, false},
		{"zero matches zero", "0", 0, 0, 59, false, true},

		// Comma list.
		{"list: first element matches", "1,3,5", 1, 0, 59, false, true},
		{"list: middle element matches", "1,3,5", 3, 0, 59, false, true},
		{"list: last element matches", "1,3,5", 5, 0, 59, false, true},
		{"list: no element matches", "1,3,5", 2, 0, 59, false, false},

		// Weekday Saturday+Sunday (default schedule).
		{"6,0 Saturday matches", "6,0", 6, 0, 7, true, true},
		{"6,0 Sunday matches", "6,0", 0, 0, 7, true, true},
		{"6,0 Monday no match", "6,0", 1, 0, 7, true, false},

		// Weekday 7 as Sunday in comma list.
		{"6,7 Saturday matches", "6,7", 6, 0, 7, true, true},
		{"6,7 Sunday (0) matches via 7", "6,7", 0, 0, 7, true, true},
		{"6,7 Monday no match", "6,7", 1, 0, 7, true, false},

		// Range.
		{"range 1-5 lo matches", "1-5", 1, 0, 59, false, true},
		{"range 1-5 mid matches", "1-5", 3, 0, 59, false, true},
		{"range 1-5 hi matches", "1-5", 5, 0, 59, false, true},
		{"range 1-5 below lo no match", "1-5", 0, 0, 59, false, false},
		{"range 1-5 above hi no match", "1-5", 6, 0, 59, false, false},

		// Step.
		{"*/5 matches 0", "*/5", 0, 0, 59, false, true},
		{"*/5 matches 5", "*/5", 5, 0, 59, false, true},
		{"*/5 matches 55", "*/5", 55, 0, 59, false, true},
		{"*/5 no match 3", "*/5", 3, 0, 59, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cronFieldMatch(tc.field, tc.val, tc.lo, tc.hi, tc.isWeekday)
			if got != tc.want {
				t.Errorf("cronFieldMatch(%q, %d, [%d,%d], %v) = %v, want %v",
					tc.field, tc.val, tc.lo, tc.hi, tc.isWeekday, got, tc.want)
			}
		})
	}
}

func TestCronAtomMatch(t *testing.T) {
	// lo/hi are the field's valid range: minute 0-59, weekday 0-7,
	// day-of-month 1-31, month 1-12. It only affects "*" / "*/n" atoms.
	tests := []struct {
		name      string
		atom      string
		val       int
		lo, hi    int
		isWeekday bool
		want      bool
	}{
		// Wildcard.
		{"* matches any non-weekday", "*", 30, 0, 59, false, true},
		{"* matches weekday", "*", 3, 0, 7, true, true},

		// Single value.
		{"exact match", "2", 2, 0, 59, false, true},
		{"exact no match", "2", 3, 0, 59, false, false},
		{"zero exact match", "0", 0, 0, 59, false, true},

		// Weekday Sunday duality.
		{"weekday 0 matches Sunday val 0", "0", 0, 0, 7, true, true},
		{"weekday 7 matches Sunday val 0", "7", 0, 0, 7, true, true},
		{"weekday 7 no match Saturday val 6", "7", 6, 0, 7, true, false},
		{"weekday 6 matches Saturday", "6", 6, 0, 7, true, true},
		{"non-weekday 7 matches val 7", "7", 7, 0, 59, false, true},

		// Range.
		{"range lo boundary", "1-5", 1, 0, 59, false, true},
		{"range mid", "1-5", 3, 0, 59, false, true},
		{"range hi boundary", "1-5", 5, 0, 59, false, true},
		{"range below lo", "1-5", 0, 0, 59, false, false},
		{"range above hi", "1-5", 6, 0, 59, false, false},

		// Range including weekday 7 (5-7 covers Fri, Sat, Sun).
		{"weekday range 5-7 Friday matches", "5-7", 5, 0, 7, true, true},
		{"weekday range 5-7 Saturday matches", "5-7", 6, 0, 7, true, true},
		{"weekday range 5-7 Sunday via 7 matches", "5-7", 0, 0, 7, true, true},
		{"weekday range 5-7 Monday no match", "5-7", 1, 0, 7, true, false},

		// Step: */n on the minute field (base 0).
		{"*/5 minute 0", "*/5", 0, 0, 59, false, true},
		{"*/5 minute 5", "*/5", 5, 0, 59, false, true},
		{"*/5 minute 10", "*/5", 10, 0, 59, false, true},
		{"*/5 minute 55", "*/5", 55, 0, 59, false, true},
		{"*/5 minute 3 no match", "*/5", 3, 0, 59, false, false},
		{"*/5 minute 57 no match", "*/5", 57, 0, 59, false, false},
		{"*/15 minute 0", "*/15", 0, 0, 59, false, true},
		{"*/15 minute 15", "*/15", 15, 0, 59, false, true},
		{"*/15 minute 30", "*/15", 30, 0, 59, false, true},
		{"*/15 minute 45", "*/15", 45, 0, 59, false, true},
		{"*/15 minute 1 no match", "*/15", 1, 0, 59, false, false},

		// Step: */n on a base-1 field (day-of-month 1-31) must start at 1
		// like standard cron: matches 1,3,5,... not 0,2,4,...
		{"day */2 matches 1", "*/2", 1, 1, 31, false, true},
		{"day */2 matches 3", "*/2", 3, 1, 31, false, true},
		{"day */2 matches 31", "*/2", 31, 1, 31, false, true},
		{"day */2 no match 2", "*/2", 2, 1, 31, false, false},
		{"day */2 no match 4", "*/2", 4, 1, 31, false, false},

		// Step: */n on the month field (1-12) must start at 1: 1,4,7,10.
		{"month */3 matches 1", "*/3", 1, 1, 12, false, true},
		{"month */3 matches 4", "*/3", 4, 1, 12, false, true},
		{"month */3 matches 10", "*/3", 10, 1, 12, false, true},
		{"month */3 no match 3", "*/3", 3, 1, 12, false, false},

		// Step: range/n.
		{"1-6/2 matches 1", "1-6/2", 1, 0, 59, false, true},
		{"1-6/2 matches 3", "1-6/2", 3, 0, 59, false, true},
		{"1-6/2 matches 5", "1-6/2", 5, 0, 59, false, true},
		{"1-6/2 no match 2", "1-6/2", 2, 0, 59, false, false},
		{"1-6/2 no match 4", "1-6/2", 4, 0, 59, false, false},
		{"1-6/2 no match 6 (beyond last step)", "1-6/2", 6, 0, 59, false, false},

		// Invalid inputs — should return false, not panic.
		{"non-numeric atom", "abc", 0, 0, 59, false, false},
		{"step zero invalid", "*/0", 0, 0, 59, false, false},
		{"invalid range hi", "1-abc", 1, 0, 59, false, false},
		{"invalid range lo", "abc-5", 1, 0, 59, false, false},
		{"invalid step suffix", "1-5/x", 1, 0, 59, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cronAtomMatch(tc.atom, tc.val, tc.lo, tc.hi, tc.isWeekday)
			if got != tc.want {
				t.Errorf("cronAtomMatch(%q, %d, [%d,%d], %v) = %v, want %v",
					tc.atom, tc.val, tc.lo, tc.hi, tc.isWeekday, got, tc.want)
			}
		})
	}
}
