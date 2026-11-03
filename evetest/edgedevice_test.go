// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"strings"
	"testing"

	eveinfo "github.com/lf-edge/eve-api/go/info"
)

// TestAppDownloadProgress pins the classification of ZSwState values, which
// is not derivable from their numeric order: RESOLVING_TAG (12) and
// RESOLVED_TAG (13) are numerically greater than DOWNLOADED (3) but happen
// before the download starts, while CREATING_VOLUME (14) and LOADED (19)
// happen after it finishes.
func TestAppDownloadProgress(t *testing.T) {
	vol := func(state eveinfo.ZSwState, pct uint32) *eveinfo.ZInfoVolume {
		return &eveinfo.ZInfoVolume{
			Uuid:               "vol",
			State:              state,
			ProgressPercentage: pct,
		}
	}

	tests := []struct {
		name string
		vol  *eveinfo.ZInfoVolume
		want uint32
	}{
		// Before the download: must never report progress, however high the
		// enum value is.
		{"invalid", vol(eveinfo.ZSwState_INVALID, 0), 0},
		{"initial", vol(eveinfo.ZSwState_INITIAL, 0), 0},
		{"resolving tag", vol(eveinfo.ZSwState_RESOLVING_TAG, 0), 0},
		{"resolved tag", vol(eveinfo.ZSwState_RESOLVED_TAG, 0), 0},
		// During the download: whatever the device reports, including the 0
		// that a container-registry pull reports throughout.
		{"downloading, no bytes reported", vol(eveinfo.ZSwState_DOWNLOAD_STARTED, 0), 0},
		{"downloading, partway", vol(eveinfo.ZSwState_DOWNLOAD_STARTED, 42), 42},
		// After the download.
		{"downloaded", vol(eveinfo.ZSwState_DOWNLOADED, 0), 100},
		// A failed volume must not read as complete, or the stall timer is
		// retired and the app fails against the wrong (much longer) budget.
		{"error", vol(eveinfo.ZSwState_ERROR, 0), 0},
		{"delivered", vol(eveinfo.ZSwState_DELIVERED, 0), 100},
		{"installed", vol(eveinfo.ZSwState_INSTALLED, 0), 100},
		{"creating volume", vol(eveinfo.ZSwState_CREATING_VOLUME, 0), 100},
		{"verifying", vol(eveinfo.ZSwState_VERIFYING, 0), 100},
		{"loaded", vol(eveinfo.ZSwState_LOADED, 0), 100},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := appDownloadProgress([]string{"vol"},
				map[string]*eveinfo.ZInfoVolume{"vol": tc.vol})
			if got != tc.want {
				t.Errorf("appDownloadProgress(%v) = %d%%, want %d%%",
					tc.vol.GetState(), got, tc.want)
			}
		})
	}
}

// TestAppDownloadProgressAveraging covers the multi-volume arithmetic,
// including a volume the device has not reported on yet.
func TestAppDownloadProgressAveraging(t *testing.T) {
	volumes := map[string]*eveinfo.ZInfoVolume{
		"a": {Uuid: "a", State: eveinfo.ZSwState_LOADED},
		"b": {Uuid: "b", State: eveinfo.ZSwState_DOWNLOAD_STARTED, ProgressPercentage: 50},
	}
	if got := appDownloadProgress([]string{"a", "b"}, volumes); got != 75 {
		t.Errorf("two volumes at 100%% and 50%% = %d%%, want 75%%", got)
	}
	// "c" has no info yet: counted as 0, not skipped, or an app would look
	// complete while a volume of it had not been heard from at all.
	if got := appDownloadProgress([]string{"a", "b", "c"}, volumes); got != 50 {
		t.Errorf("unreported third volume = %d%%, want 50%%", got)
	}
	if got := appDownloadProgress(nil, volumes); got != 0 {
		t.Errorf("no volume refs = %d%%, want 0%%", got)
	}
}

// TestIsAppVolume covers the membership check that keeps an unrelated
// volume's state changes from resetting this app's stall timer.
func TestIsAppVolume(t *testing.T) {
	refs := []string{"a", "b"}
	for uuid, want := range map[string]bool{"a": true, "b": true, "c": false, "": false} {
		if got := isAppVolume(uuid, refs); got != want {
			t.Errorf("isAppVolume(%q, %v) = %v, want %v", uuid, refs, got, want)
		}
	}
	if isAppVolume("a", nil) {
		t.Error("isAppVolume with no refs must be false")
	}
}

func TestReportedClusterMatches(t *testing.T) {
	const (
		cluster      = "6b2c7d3e-0f4a-4b5c-9d8e-1a2b3c4d5e6f"
		otherCluster = "0e9a8b7c-6d5e-4f3a-8b2c-1d0e9f8a7b6c"
		nilCluster   = "00000000-0000-0000-0000-000000000000"
	)
	tests := []struct {
		name                 string
		reported, configured string
		want                 bool
	}{
		{"same cluster", cluster, cluster, true},
		{"same cluster, other case", strings.ToUpper(cluster), cluster, true},
		{"report from a previous test's cluster", otherCluster, cluster, false},
		{"report from before the cluster config", nilCluster, cluster, false},
		{"no cluster config, no cluster reported", nilCluster, "", true},
		{"no cluster config, cluster reported", cluster, "", false},
		{"EVE that reports no cluster ID", "", cluster, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reportedClusterMatches(tt.reported, tt.configured); got != tt.want {
				t.Fatalf("reportedClusterMatches(%q, %q) = %v, want %v",
					tt.reported, tt.configured, got, tt.want)
			}
		})
	}
}
