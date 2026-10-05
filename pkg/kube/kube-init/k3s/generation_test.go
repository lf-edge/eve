// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import "testing"

func TestGenerationRoundTrip(t *testing.T) {
	cases := []Generation{
		{ClusterID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Counter: 0},
		{ClusterID: "7c9e6679-7425-40de-944b-e07fc1f90ae7", Counter: 4294967295},
	}
	for _, want := range cases {
		got, recorded, err := ParseGeneration(want.String())
		if err != nil || !recorded || got != want {
			t.Errorf("round trip of %v gave (%v, %v, %v)", want, got, recorded, err)
		}
	}
}

// TestParseGenerationEmptyIsNotAnError: an absent marker is the normal
// state on a first boot, not a failure to report.
func TestParseGenerationEmptyIsNotAnError(t *testing.T) {
	for _, in := range []string{"", "   ", "\n"} {
		got, recorded, err := ParseGeneration(in)
		if err != nil || recorded || got != (Generation{}) {
			t.Errorf("ParseGeneration(%q) = (%v, %v, %v)", in, got, recorded, err)
		}
	}
}

func TestParseGenerationRejectsMalformed(t *testing.T) {
	for _, in := range []string{"cluster-a", "cluster-a x", "cluster-a -1", "cluster-a 1 2 3"} {
		if _, _, err := ParseGeneration(in); err == nil {
			t.Errorf("ParseGeneration(%q) accepted malformed input", in)
		}
	}
}
