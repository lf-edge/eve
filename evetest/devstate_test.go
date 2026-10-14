// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestCountReboots(t *testing.T) {
	t0 := time.Date(2026, 10, 14, 3, 29, 21, 0, time.UTC)
	t1 := t0.Add(2 * time.Minute)
	t2 := t1.Add(3 * time.Minute)

	// An observation is one ZInfoDevice message; powerCycle marks the harness
	// power-cycling the device instead.
	type obs struct {
		counter    uint32
		boot       time.Time
		powerCycle bool
	}
	tests := []struct {
		name string
		seq  []obs
		want int
	}{
		{
			name: "reboot advances counter and boot time",
			seq:  []obs{{counter: 1, boot: t0}, {counter: 2, boot: t1}},
			want: 1,
		},
		{
			name: "counter advance without boot times",
			seq:  []obs{{counter: 1}, {counter: 2}},
			want: 1,
		},
		{
			name: "boot time change without counter advance",
			seq:  []obs{{counter: 1, boot: t0}, {counter: 1, boot: t1}},
			want: 1,
		},
		{
			name: "power cycle, first message carries the new counter",
			seq: []obs{{counter: 0, boot: t0}, {powerCycle: true},
				{counter: 1, boot: t1}, {counter: 2, boot: t2}},
			want: 2,
		},
		{
			// zedagent published before nodeagent's status reached it.
			name: "power cycle, first message still carries counter 0",
			seq: []obs{{counter: 0, boot: t0}, {powerCycle: true},
				{counter: 0, boot: t1}, {counter: 1, boot: t1}, {counter: 2, boot: t2}},
			want: 2,
		},
		{
			name: "counter advances within one boot",
			seq:  []obs{{counter: 0, boot: t0}, {counter: 1, boot: t0.Add(time.Second)}},
			want: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev := &deviceState{}
			th := &TestHarness{
				log:     logrus.New(),
				devices: map[string]*deviceState{"edge-dev": dev},
			}
			for _, o := range tc.seq {
				if o.powerCycle {
					th.countPowerCycleReboot("edge-dev")
					continue
				}
				th.countReboots("edge-dev", dev, o.counter, o.boot)
			}
			if dev.rebootCount != tc.want {
				t.Errorf("rebootCount = %d, want %d", dev.rebootCount, tc.want)
			}
		})
	}
}
