// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"

	"github.com/sirupsen/logrus"
)

func testLog() *base.LogObject {
	return base.NewSourceLogObject(logrus.StandardLogger(), "test-kubeapi", 0)
}

// healthOf returns a NodeHealthLookup that answers only for the given UUID,
// with every other UUID reporting not found -- the same as a cache that has
// never heard of a node.
func healthOf(uuid string, ready bool, since time.Time) NodeHealthLookup {
	return func(nodeUUID string) (bool, time.Time, bool) {
		if nodeUUID != uuid {
			return false, time.Time{}, false
		}
		return ready, since, true
	}
}

func notFound(string) (bool, time.Time, bool) {
	return false, time.Time{}, false
}

func TestIsCurrentlyBackupDNIDFromHealth(t *testing.T) {
	const threshold = 10 * time.Minute

	for _, tc := range []struct {
		name    string
		lookup  NodeHealthLookup
		want    bool
		wantErr bool
	}{{
		// The designated node is fine; nobody stands in for it.
		name:   "ready node",
		lookup: healthOf("uuid-1", true, time.Now().Add(-time.Hour)),
		want:   false,
	}, {
		// This is the case the whole feature exists for, so it must be the
		// one that most clearly returns true.
		name:   "not ready past threshold",
		lookup: healthOf("uuid-1", false, time.Now().Add(-time.Hour)),
		want:   true,
	}, {
		name:   "not ready under threshold",
		lookup: healthOf("uuid-1", false, time.Now().Add(-time.Minute)),
		want:   false,
	}, {
		// time.Since of the zero time is centuries, which would clear any
		// threshold instantly. Unusable, not unhealthy.
		name:    "zero transition time",
		lookup:  healthOf("uuid-1", false, time.Time{}),
		want:    false,
		wantErr: true,
	}, {
		name:    "not yet known",
		lookup:  notFound,
		want:    false,
		wantErr: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := isCurrentlyBackupDNIDFromHealth(testLog(), tc.lookup,
				"uuid-1", threshold)
			if got != tc.want {
				t.Errorf("got %v, want %v (err %v)", got, tc.want, err)
			}
			if tc.wantErr && err == nil {
				t.Error("expected an error explaining why it could not confirm")
			}
		})
	}
}

// A zero LastTransitionTime must not read as an eternity of downtime.
// Asserted separately because a node that never reported carries exactly
// this value.
func TestZeroTransitionTimeIsNotAnOutage(t *testing.T) {
	got, err := isCurrentlyBackupDNIDFromHealth(testLog(),
		healthOf("uuid-z", false, time.Time{}), "uuid-z", time.Minute)
	if got {
		t.Error("a zero Ready timestamp was treated as a crossed threshold")
	}
	if err == nil {
		t.Error("expected an error naming the unusable timestamp")
	}
}

// Required affinity is excluded by IsCurrentlyBackupDNID, not by
// backupDNIDEligible underneath it: the exclusion exists to stop a peer
// creating resources on a node the app can never run on, which only applies
// to a caller that would place something.
func TestRequiredAffinityExcludedOnlyForCreate(t *testing.T) {
	lookup := healthOf("uuid-1", false, time.Now().Add(-time.Hour))
	if IsCurrentlyBackupDNID(testLog(), lookup, "uuid-1", true,
		types.RequiredDuringScheduling, time.Minute) {
		t.Error("Required affinity was allowed through the activate path")
	}
}

// backupDNIDEligible refuses before touching the lookup when this node does
// not hold the lease or the app has no designated node, so a non-leader
// costs nothing per app per tick.
func TestBackupDNIDEarlyOuts(t *testing.T) {
	calls := 0
	lookup := func(string) (bool, time.Time, bool) {
		calls++
		return false, time.Time{}, false
	}
	for _, tc := range []struct {
		name          string
		dnid          string
		isAppOpLeader bool
	}{
		{"not the lease holder", "uuid-1", false},
		{"no designated node", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if backupDNIDEligible(testLog(), lookup, tc.dnid, tc.isAppOpLeader,
				time.Minute) {
				t.Error("eligible despite the early-out condition")
			}
		})
	}
	if calls != 0 {
		t.Errorf("lookup was called %d times on an early-out path", calls)
	}
}
