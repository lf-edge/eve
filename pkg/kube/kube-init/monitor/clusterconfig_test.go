// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"testing"
	"time"
)

func TestClusterWithdrawn(t *testing.T) {
	const grace = 3 * time.Minute

	cases := []struct {
		name             string
		configPresent    bool
		sinceStart       time.Duration
		wantWithdrawn    bool
		wantRecheckAfter time.Duration
	}{
		{
			name:          "config present is never a withdrawal",
			configPresent: true,
			sinceStart:    time.Hour,
		},
		{
			name:             "config absent right after boot is not yet a withdrawal",
			sinceStart:       21 * time.Second,
			wantRecheckAfter: grace - 21*time.Second,
		},
		{
			name:             "config absent just inside the grace period",
			sinceStart:       grace - time.Second,
			wantRecheckAfter: time.Second,
		},
		{
			name:          "config absent at the end of the grace period",
			sinceStart:    grace,
			wantWithdrawn: true,
		},
		{
			name:          "config absent long after boot is a withdrawal",
			sinceStart:    time.Hour,
			wantWithdrawn: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withdrawn, recheckAfter := clusterWithdrawn(tc.configPresent, tc.sinceStart, grace)
			if withdrawn != tc.wantWithdrawn {
				t.Errorf("withdrawn = %v, want %v", withdrawn, tc.wantWithdrawn)
			}
			if recheckAfter != tc.wantRecheckAfter {
				t.Errorf("recheckAfter = %v, want %v", recheckAfter, tc.wantRecheckAfter)
			}
		})
	}
}
