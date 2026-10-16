// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

// initPortMapTestRouter returns a zedrouter whose NetworkInstanceConfig
// subscription is backed by pubsub.NewMemoryDriver, so that the given NIs
// are visible to lookupNetworkInstanceConfig.
func initPortMapTestRouter(t *testing.T, nis ...types.NetworkInstanceConfig) *zedrouter {
	t.Helper()
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "zedrouter-test", 1234)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)

	pubNIConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedagent",
		TopicType: types.NetworkInstanceConfig{},
	})
	if err != nil {
		t.Fatalf("NewPublication(NetworkInstanceConfig): %v", err)
	}
	z := &zedrouter{logger: logger, log: log}
	subNIConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.NetworkInstanceConfig{},
		Ctx:         z,
	})
	if err != nil {
		t.Fatalf("NewSubscription(NetworkInstanceConfig): %v", err)
	}
	if err := subNIConfig.Activate(); err != nil {
		t.Fatalf("Activate(NetworkInstanceConfig): %v", err)
	}
	z.subNetworkInstanceConfig = subNIConfig
	for _, ni := range nis {
		if err := pubNIConfig.Publish(ni.Key(), ni); err != nil {
			t.Fatalf("Publish(NetworkInstanceConfig): %v", err)
		}
		// MemoryDriver notifies asynchronously over a channel.
		change := <-subNIConfig.MsgChan()
		subNIConfig.ProcessChange(change)
	}
	return z
}

func newTestNI(niType types.NetworkInstanceType, portLabel string) types.NetworkInstanceConfig {
	return types.NetworkInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
		Type:           niType,
		PortLabel:      portLabel,
	}
}

// newPortMapAdapter returns an app adapter with a single port-map ACL rule
// forwarding <protocol>/<lport> to the same port inside the app.
func newPortMapAdapter(network uuid.UUID, protocol, lport string) types.AppNetAdapterConfig {
	return types.AppNetAdapterConfig{
		Network: network,
		ACLs: []types.ACE{{
			Matches: []types.ACEMatch{
				{Type: "protocol", Value: protocol},
				{Type: "lport", Value: lport},
			},
			Actions: []types.ACEAction{{PortMap: true, TargetPort: 22}},
			RuleID:  1,
		}},
	}
}

// TestCheckForPortMapOverlap verifies that the same port-map rule used by two
// apps is reported as a conflict only when port maps actually take effect
// (Local NI). Switch NI does not implement port mapping, so apps on different
// Switch NIs (e.g. two air-gapped Switch NIs, which share the empty port label)
// must not be refused with "overlapping portmaps".
func TestCheckForPortMapOverlap(t *testing.T) {
	localA := newTestNI(types.NetworkInstanceTypeLocal, "")
	localB := newTestNI(types.NetworkInstanceTypeLocal, "")
	localEth1 := newTestNI(types.NetworkInstanceTypeLocal, "eth1")
	switchA := newTestNI(types.NetworkInstanceTypeSwitch, "")
	switchB := newTestNI(types.NetworkInstanceTypeSwitch, "")
	unknownNI := uuid.Must(uuid.NewV4())
	z := initPortMapTestRouter(t, localA, localB, localEth1, switchA, switchB)

	tests := []struct {
		name     string
		app1     types.AppNetAdapterConfig
		app2     types.AppNetAdapterConfig
		conflict bool
	}{
		{
			name:     "same Local NI",
			app1:     newPortMapAdapter(localA.UUID, "tcp", "2222"),
			app2:     newPortMapAdapter(localA.UUID, "tcp", "2222"),
			conflict: true,
		},
		{
			name:     "different Local NIs with the same port label",
			app1:     newPortMapAdapter(localA.UUID, "tcp", "2222"),
			app2:     newPortMapAdapter(localB.UUID, "tcp", "2222"),
			conflict: true,
		},
		{
			name:     "different Local NIs with different port labels",
			app1:     newPortMapAdapter(localA.UUID, "tcp", "2222"),
			app2:     newPortMapAdapter(localEth1.UUID, "tcp", "2222"),
			conflict: false,
		},
		{
			name:     "same Local NI, different external ports",
			app1:     newPortMapAdapter(localA.UUID, "tcp", "2222"),
			app2:     newPortMapAdapter(localA.UUID, "tcp", "2223"),
			conflict: false,
		},
		{
			name:     "different Switch NIs with the same port label",
			app1:     newPortMapAdapter(switchA.UUID, "tcp", "2222"),
			app2:     newPortMapAdapter(switchB.UUID, "tcp", "2222"),
			conflict: false,
		},
		{
			name:     "same Switch NI",
			app1:     newPortMapAdapter(switchA.UUID, "tcp", "2222"),
			app2:     newPortMapAdapter(switchA.UUID, "tcp", "2222"),
			conflict: false,
		},
		{
			name:     "Switch NI and Local NI with the same port label",
			app1:     newPortMapAdapter(switchA.UUID, "tcp", "2222"),
			app2:     newPortMapAdapter(localA.UUID, "tcp", "2222"),
			conflict: false,
		},
		{
			name:     "unknown NI is checked conservatively",
			app1:     newPortMapAdapter(unknownNI, "tcp", "2222"),
			app2:     newPortMapAdapter(unknownNI, "tcp", "2222"),
			conflict: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			list1 := []types.AppNetAdapterConfig{tc.app1}
			list2 := []types.AppNetAdapterConfig{tc.app2}
			if got := z.checkForPortMapOverlap(list1, list2); got != tc.conflict {
				t.Errorf("checkForPortMapOverlap(app1, app2) = %t, want %t",
					got, tc.conflict)
			}
			// The check must be symmetric.
			if got := z.checkForPortMapOverlap(list2, list1); got != tc.conflict {
				t.Errorf("checkForPortMapOverlap(app2, app1) = %t, want %t",
					got, tc.conflict)
			}
		})
	}
}

// TestCheckForPortMapOverlapWithinSwitchAdapter verifies that duplicate
// port-map rules within a single VIF are reported only for Local NI.
func TestCheckForPortMapOverlapWithinSwitchAdapter(t *testing.T) {
	localNI := newTestNI(types.NetworkInstanceTypeLocal, "")
	switchNI := newTestNI(types.NetworkInstanceTypeSwitch, "")
	z := initPortMapTestRouter(t, localNI, switchNI)

	withDuplicateRules := func(network uuid.UUID) []types.AppNetAdapterConfig {
		adapter := newPortMapAdapter(network, "tcp", "2222")
		dup := adapter.ACLs[0]
		dup.RuleID = 2
		adapter.ACLs = append(adapter.ACLs, dup)
		return []types.AppNetAdapterConfig{adapter}
	}
	if !z.checkForPortMapOverlap(withDuplicateRules(localNI.UUID), nil) {
		t.Error("duplicate port-map rules on Local NI were not detected")
	}
	if z.checkForPortMapOverlap(withDuplicateRules(switchNI.UUID), nil) {
		t.Error("duplicate port-map rules on Switch NI were reported as a conflict")
	}
}
