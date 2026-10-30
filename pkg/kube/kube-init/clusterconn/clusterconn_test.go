// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package clusterconn

import (
	"errors"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/etcd"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	healthy  = etcd.Status{HasLeader: true}
	noLeader = etcd.Status{Errors: []string{"etcdserver: no leader"}}
)

// TestTrackerLostNeedsRepeatedFailures covers the debounce: one probe
// without a leader, as during an etcd election, is not a lost quorum,
// but failureThreshold in a row is, and the first good probe clears it.
func TestTrackerLostNeedsRepeatedFailures(t *testing.T) {
	var tr tracker
	if c, changed := tr.observe("c1", healthy, nil); !changed || c.Quorum != types.ClusterQuorumEstablished {
		t.Fatalf("first healthy probe: got %+v changed=%v, want types.ClusterQuorumEstablished", c, changed)
	}
	for i := 1; i < failureThreshold; i++ {
		if c, changed := tr.observe("c1", noLeader, nil); changed {
			t.Fatalf("failure %d reported %+v, want no change yet", i, c)
		}
	}
	c, changed := tr.observe("c1", noLeader, nil)
	if !changed || c.Quorum != types.ClusterQuorumLost {
		t.Fatalf("threshold failure: got %+v changed=%v, want types.ClusterQuorumLost", c, changed)
	}
	if c.Error.Error == "" || c.Error.ErrorTime.IsZero() {
		t.Errorf("types.ClusterQuorumLost error %+v lacks text or time, so it would not reach the controller", c.Error)
	}
	if _, changed := tr.observe("c1", noLeader, nil); changed {
		t.Error("an unchanged lost quorum was reported again")
	}
	if c, changed := tr.observe("c1", healthy, nil); !changed || c.Quorum != types.ClusterQuorumEstablished ||
		c.Error.Error != "" {
		t.Errorf("recovery: got %+v changed=%v, want types.ClusterQuorumEstablished with no error", c, changed)
	}
}

// TestTrackerFlapResets pins that failures must be consecutive: a good
// probe in between starts the count over.
func TestTrackerFlapResets(t *testing.T) {
	var tr tracker
	tr.observe("c1", healthy, nil)
	for i := 0; i < failureThreshold-1; i++ {
		tr.observe("c1", noLeader, nil)
	}
	tr.observe("c1", healthy, nil)
	for i := 0; i < failureThreshold-1; i++ {
		if c, changed := tr.observe("c1", noLeader, nil); changed {
			t.Fatalf("failure %d after a good probe reported %+v", i+1, c)
		}
	}
}

// TestTrackerUnreachableIsNotLost covers etcd not answering at all, as
// while k3s restarts: it is reported as unknown, never as a lost quorum.
func TestTrackerUnreachableIsNotLost(t *testing.T) {
	var tr tracker
	tr.observe("c1", healthy, nil)
	boom := errors.New("connection refused")
	for i := 1; i < failureThreshold; i++ {
		if _, changed := tr.observe("c1", etcd.Status{}, boom); changed {
			t.Fatalf("unreachable probe %d reported a change", i)
		}
	}
	c, changed := tr.observe("c1", etcd.Status{}, boom)
	if !changed || c.Quorum != types.ClusterQuorumUnknown {
		t.Fatalf("persistently unreachable: got %+v changed=%v, want types.ClusterQuorumUnknown", c, changed)
	}
}

// TestTrackerReset covers a node leaving the cluster: what it reported
// is cleared once, and nothing more is sent while it stays out.
func TestTrackerReset(t *testing.T) {
	var tr tracker
	if _, changed := tr.reset(); changed {
		t.Error("reset of a node that never reported claimed a change")
	}
	tr.observe("c1", healthy, nil)
	c, changed := tr.reset()
	if !changed || c.Quorum != types.ClusterQuorumUnknown || c.ClusterID != "" {
		t.Fatalf("reset: got %+v changed=%v, want an empty connection", c, changed)
	}
	if _, changed := tr.reset(); changed {
		t.Error("second reset claimed a change")
	}
}

// TestTrackerQuorumChangeTime pins that the time is stamped when the
// quorum value changes, not on every probe or when only the error or
// cluster changes, and that it is unset while the quorum is unknown.
func TestTrackerQuorumChangeTime(t *testing.T) {
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	tr := tracker{now: func() time.Time { return now }}

	established := now
	c, _ := tr.observe("c1", healthy, nil)
	if !c.QuorumChangeTime.Equal(established) {
		t.Fatalf("established at %v, want %v", c.QuorumChangeTime, established)
	}

	now = now.Add(time.Minute)
	for i := 0; i < failureThreshold; i++ {
		now = now.Add(Interval)
		c, _ = tr.observe("c1", noLeader, nil)
	}
	lost := now
	if c.Quorum != types.ClusterQuorumLost || !c.QuorumChangeTime.Equal(lost) {
		t.Fatalf("lost: got %+v, want change time %v", c, lost)
	}

	now = now.Add(time.Minute)
	if c, changed := tr.observe("c2", noLeader, nil); !changed || !c.QuorumChangeTime.Equal(lost) {
		t.Errorf("cluster change alone moved the time: got %+v changed=%v, want %v", c, changed, lost)
	}

	now = now.Add(time.Minute)
	regained := now
	if c, _ = tr.observe("c2", healthy, nil); !c.QuorumChangeTime.Equal(regained) {
		t.Errorf("regained at %v, want %v", c.QuorumChangeTime, regained)
	}

	for i := 0; i < failureThreshold; i++ {
		c, _ = tr.observe("c2", etcd.Status{}, errors.New("etcdctl failed"))
	}
	if c.Quorum != types.ClusterQuorumUnknown || !c.QuorumChangeTime.IsZero() {
		t.Errorf("unknown: got %+v, want zero change time", c)
	}

	if c, changed := tr.reset(); !c.QuorumChangeTime.IsZero() || changed {
		t.Errorf("reset: got %+v changed=%v, want zero time", c, changed)
	}
}
