// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package witnessstatus publishes what the witness knows about its own
// etcd membership, for zedkube on the same device to forward to the
// controller.
//
// Only the witness's own process can report this. It has no Kubernetes
// Node object to annotate, having no kubelet, and etcd's membership
// alone cannot answer it: a member list shows a member that is present,
// but not one that is mid-wipe or failing to rejoin, which lives only
// here.
package witnessstatus

import (
	"sync"

	"github.com/lf-edge/eve/pkg/kube/kube-init/pubsubclient"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	mu     sync.Mutex
	pub    pubsub.Publication
	cached types.WitnessStatus
)

// RegisterPublisher creates the publication. Call once at startup,
// before the pubsub manager runs.
func RegisterPublisher(m *pubsubclient.Manager) error {
	p, err := m.NewPublication(pubsub.PublicationOptions{
		AgentName: pubsubclient.AgentName(),
		TopicType: types.WitnessStatus{},
		// Not persistent: this is live state, re-derived on every
		// start. A stale value surviving a reboot would claim a vote
		// the witness has not yet cast.
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

// SetState records the witness's membership state and publishes if
// anything changed.
func SetState(state types.WitnessEtcdState, witnessIP string) {
	mu.Lock()
	changed := cached.State != state || cached.WitnessIP != witnessIP
	cached.State = state
	cached.WitnessIP = witnessIP
	// Reaching any other state clears the error that explained an
	// earlier failure; a fresh one is set again through SetError.
	if state != types.WitnessEtcdStateError {
		cached.Error = types.ErrorDescription{}
	}
	mu.Unlock()
	if changed {
		publish()
	}
}

// SetError records why the witness is not where it should be.
func SetError(err error, witnessIP string) {
	mu.Lock()
	cached.State = types.WitnessEtcdStateError
	cached.WitnessIP = witnessIP
	cached.Error.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
	mu.Unlock()
	publish()
}

// Get returns the current status.
func Get() types.WitnessStatus {
	mu.Lock()
	defer mu.Unlock()
	return cached
}

func publish() {
	mu.Lock()
	p, snapshot := pub, cached
	mu.Unlock()
	if p == nil {
		// Before RegisterPublisher, or in the kube role, where nothing
		// publishes this topic.
		return
	}
	//nolint:errcheck // pubsub logs its own publication failures
	_ = p.Publish(snapshot.Key(), snapshot)
}
