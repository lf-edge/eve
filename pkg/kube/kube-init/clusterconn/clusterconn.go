// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package clusterconn publishes whether this node can reach a quorum of
// its cluster's etcd, for zedagent to report to the controller.
//
// The cluster-wide report (zedkube's KubeClusterInfo) needs a working
// Kubernetes API and an elected reporter, and so cannot say that quorum
// has been lost: once too few members are alive and in reach of each
// other, no one is able to produce it. Each node asks its own etcd
// instead, which answers without the API and without quorum.
package clusterconn

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/etcd"
	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Probing is paced so that a lost quorum is reported within about
// failureThreshold*Interval, long enough that an etcd leader election
// after a restart, which also reports no leader for a few seconds, does
// not read as one.
const (
	Interval         = 10 * time.Second
	failureThreshold = 3
)

// Probe is how the node asks its local etcd about itself.
type Probe func(ctx context.Context) (etcd.Status, error)

// Active reports the cluster this node is a member of, if it is one
// right now.
type Active func() (clusterID string, ok bool)

var (
	mu  sync.Mutex
	pub pubsub.Publication
)

// RegisterPublisher creates the publication. Call once at startup,
// before the pubsub manager runs.
func RegisterPublisher(m *pubsubclient.Manager) error {
	p, err := m.NewPublication(pubsub.PublicationOptions{
		AgentName: pubsubclient.AgentName(),
		TopicType: types.ClusterNodeConnection{},
		// Live state, re-derived on every start. A stale value
		// surviving a reboot would claim a quorum that is not there.
		Persistent: false,
	})
	if err != nil {
		return err
	}
	mu.Lock()
	pub = p
	mu.Unlock()
	return nil
}

func publish(c types.ClusterNodeConnection) {
	mu.Lock()
	p := pub
	mu.Unlock()
	if p == nil {
		return
	}
	//nolint:errcheck // pubsub logs its own publication failures
	_ = p.Publish(c.Key(), c)
}

// tracker turns single probe results into the state worth reporting. A
// failing probe has to repeat failureThreshold times before the state
// changes, so one slow answer is not a report; a good one is believed at
// once, since quorum coming back should clear the report promptly.
type tracker struct {
	reported types.ClusterNodeConnection
	failures int
	silent   int
	// now is the clock, time.Now when unset.
	now func() time.Time
}

func (t *tracker) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// observe folds in one probe result and reports the connection to
// publish, if it differs from the last one.
func (t *tracker) observe(clusterID string, st etcd.Status, err error) (types.ClusterNodeConnection, bool) {
	next := t.reported
	next.ClusterID = clusterID
	switch {
	case err == nil && st.HasLeader && len(st.Errors) == 0:
		t.failures, t.silent = 0, 0
		next.Quorum = types.ClusterQuorumEstablished
		next.Error = types.ErrorDescription{}
	case err == nil:
		t.silent = 0
		t.failures++
		if t.failures >= failureThreshold {
			next.Quorum = types.ClusterQuorumLost
			next.Error = describe(strings.Join(st.Errors, "; "), "etcd reports no leader")
		}
	default:
		// etcd could not be asked at all, such as while k3s restarts.
		// That says nothing about quorum, but it must not leave a stale
		// answer standing forever either.
		t.failures = 0
		t.silent++
		if t.silent >= failureThreshold {
			next.Quorum = types.ClusterQuorumUnknown
			next.Error = describe(err.Error(), "")
		}
	}
	if next.Quorum != t.reported.Quorum {
		next.QuorumChangeTime = time.Time{}
		if next.Quorum != types.ClusterQuorumUnknown {
			next.QuorumChangeTime = t.clock()
		}
	}
	if sameConnection(next, t.reported) {
		return next, false
	}
	t.reported = next
	return next, true
}

// reset forgets the state when the node leaves the cluster, and reports
// the change if there was something to clear.
func (t *tracker) reset() (types.ClusterNodeConnection, bool) {
	had := t.reported.Quorum != types.ClusterQuorumUnknown
	t.failures, t.silent = 0, 0
	t.reported = types.ClusterNodeConnection{}
	return t.reported, had
}

func describe(text, fallback string) types.ErrorDescription {
	if text == "" {
		text = fallback
	}
	var ed types.ErrorDescription
	if text != "" {
		// SetErrorDescription stamps the time, without which the
		// error is not carried to the controller.
		ed.SetErrorDescription(types.ErrorDescription{Error: text})
	}
	return ed
}

// sameConnection ignores the error's timestamp, which is set when it
// is created and would otherwise make every probe look like a change.
func sameConnection(a, b types.ClusterNodeConnection) bool {
	return a.ClusterID == b.ClusterID && a.Quorum == b.Quorum &&
		a.Error.Error == b.Error.Error
}

// Run probes the local etcd every Interval while the node is a cluster
// member and publishes each change in what it finds. It returns when
// ctx is cancelled.
func Run(ctx context.Context, active Active, probe Probe) {
	var t tracker
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		step(ctx, &t, active, probe)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func step(ctx context.Context, t *tracker, active Active, probe Probe) {
	clusterID, ok := active()
	if !ok {
		if c, changed := t.reset(); changed {
			publish(c)
		}
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, Interval)
	defer cancel()
	st, err := probe(probeCtx)
	if c, changed := t.observe(clusterID, st, err); changed {
		publish(c)
	}
}
