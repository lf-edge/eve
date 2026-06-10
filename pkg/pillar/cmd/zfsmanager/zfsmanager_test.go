// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import "testing"

// TestDecideZVolAction covers the reconcile truth table that decides, for a
// stored fsnotify device event, whether to publish, unpublish, retry, or drop.
//
// The "device present" rows are authoritative over the event flag. The second
// row is the regression guard for the app-purge race: a Remove event that
// coalesced over an unprocessed Create for a device that actually exists must
// still publish ZVolStatus, otherwise volumemgr never sees the recreated zvol
// and the purged app is stranded in HALTING forever.
func TestDecideZVolAction(t *testing.T) {
	const dataset = "persist/vault/volumes/18b27b2f-6a81-49d8-b3cb-6901be9aa9c6.0"

	tests := []struct {
		name            string
		event           zVolDeviceEvent
		devicePresent   bool
		statusPublished bool
		want            zvolReconcileAction
	}{
		{
			name:          "create event, device present -> publish",
			event:         zVolDeviceEvent{dataset: dataset},
			devicePresent: true,
			want:          zvolPublish,
		},
		{
			name:          "coalesced delete over create, device present -> publish",
			event:         zVolDeviceEvent{delete: true}, // dataset lost to coalescing
			devicePresent: true,
			want:          zvolPublish,
		},
		{
			name:          "create event, device absent -> retry",
			event:         zVolDeviceEvent{dataset: dataset},
			devicePresent: false,
			want:          zvolRetry,
		},
		{
			name:            "delete event, device absent, status published -> unpublish",
			event:           zVolDeviceEvent{delete: true},
			devicePresent:   false,
			statusPublished: true,
			want:            zvolUnpublish,
		},
		{
			name:            "delete event, device absent, nothing published -> drop",
			event:           zVolDeviceEvent{delete: true},
			devicePresent:   false,
			statusPublished: false,
			want:            zvolDrop,
		},
		{
			// A coalesced Remove leaves both flags unset; if the device is
			// gone and nothing was published there is nothing to do.
			name:          "coalesced delete, device absent, nothing published -> drop",
			event:         zVolDeviceEvent{delete: true},
			devicePresent: false,
			want:          zvolDrop,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideZVolAction(tt.event, tt.devicePresent, tt.statusPublished)
			if got != tt.want {
				t.Errorf("decideZVolAction(%+v, present=%v, published=%v) = %v, want %v",
					tt.event, tt.devicePresent, tt.statusPublished, got, tt.want)
			}
		})
	}
}
