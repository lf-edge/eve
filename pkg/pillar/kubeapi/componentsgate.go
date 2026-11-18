// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubeapi

import (
	"context"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// kubeComponentsGatePoll is how often Wait looks at the gate.
const kubeComponentsGatePoll = 5 * time.Second

// KubeComponentsGate tells whether kube-init is done changing the kube
// components (Multus, KubeVirt, CDI, Longhorn) for this boot.
//
// After an EVE upgrade kube-init may upgrade those components, which can
// take an hour and rolls their control planes along the way. A component
// that reports ready in the middle of that is not one to create volumes
// or start VMs against, so the gate is checked before any
// component-specific readiness check, whichever component is moving.
//
// The gate reads kube-init's own status topic rather than the Kubernetes
// API, so it still answers when the upgrade has left the API unusable.
//
// A nil gate is always ready, which is what builds without kubernetes
// use.
type KubeComponentsGate struct {
	sub pubsub.Subscription
}

// NewKubeComponentsGate subscribes agentName to kube-init's status. The
// gate processes the subscription on its own goroutine, so the agent
// has nothing to add to its event loop.
func NewKubeComponentsGate(ps *pubsub.PubSub, agentName string) (*KubeComponentsGate, error) {
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   types.KubeInitAgentName,
		MyAgentName: agentName,
		TopicImpl:   types.KubeInitStatus{},
		Activate:    true,
	})
	if err != nil {
		return nil, err
	}
	go func() {
		for change := range sub.MsgChan() {
			sub.ProcessChange(change)
		}
	}()
	return &KubeComponentsGate{sub: sub}, nil
}

// Status returns kube-init's last published status, and false if it has
// not published one this boot.
func (gate *KubeComponentsGate) Status() (types.KubeInitStatus, bool) {
	if gate == nil {
		return types.KubeInitStatus{}, false
	}
	item, err := gate.sub.Get("global")
	if err != nil {
		return types.KubeInitStatus{}, false
	}
	status, ok := item.(types.KubeInitStatus)
	return status, ok
}

// Ready reports whether kube-init is done changing the kube components
// for this boot. A pass that failed for good counts: nothing more will
// change, and the component-specific checks decide from there.
func (gate *KubeComponentsGate) Ready() bool {
	if gate == nil {
		return true
	}
	status, ok := gate.Status()
	return ok && status.ComponentPassOver()
}

// Wait blocks until Ready or until ctx is done.
func (gate *KubeComponentsGate) Wait(ctx context.Context) error {
	if gate.Ready() {
		return nil
	}
	ticker := time.NewTicker(kubeComponentsGatePoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if gate.Ready() {
				return nil
			}
		}
	}
}
