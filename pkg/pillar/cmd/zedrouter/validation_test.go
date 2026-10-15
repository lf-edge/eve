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

// newPortMapTestRouter returns a zedrouter whose NetworkInstanceConfig
// subscription holds the given network instances.
func newPortMapTestRouter(t *testing.T, nis ...types.NetworkInstanceConfig) *zedrouter {
	t.Helper()
	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, agentName, 0)
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "zedagent",
		TopicType: types.NetworkInstanceConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ni := range nis {
		if err := pub.Publish(ni.Key(), ni); err != nil {
			t.Fatal(err)
		}
	}
	// Persistent makes Activate populate the subscription synchronously.
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:  "zedagent",
		TopicImpl:  types.NetworkInstanceConfig{},
		Persistent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.Activate(); err != nil {
		t.Fatal(err)
	}
	return &zedrouter{logger: logger, log: log, subNetworkInstanceConfig: sub}
}

func portMapAdapter(network uuid.UUID, lport string, targetPort int) types.AppNetAdapterConfig {
	return types.AppNetAdapterConfig{
		Network: network,
		ACLs: []types.ACE{
			{
				Matches: []types.ACEMatch{{Type: "ip", Value: "0.0.0.0/0"}},
			},
			{
				Matches: []types.ACEMatch{
					{Type: "protocol", Value: "tcp"},
					{Type: "lport", Value: lport},
				},
				Actions: []types.ACEAction{{PortMap: true, TargetPort: targetPort}},
			},
		},
	}
}

// TestPortMapOverlapIgnoredOnSwitchNI covers EV-2926: two apps on the same
// Switch NI with the same portmap must not be reported as overlapping, since
// a Switch NI does not NAT and never applies portmap rules. The same config on
// a Local NI is a real conflict and must still be reported.
func TestPortMapOverlapIgnoredOnSwitchNI(t *testing.T) {
	switchNI := types.NetworkInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
		Type:           types.NetworkInstanceTypeSwitch,
		PortLabel:      "eth0",
	}
	localNI := types.NetworkInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
		Type:           types.NetworkInstanceTypeLocal,
		PortLabel:      "uplink",
	}
	z := newPortMapTestRouter(t, switchNI, localNI)

	tests := []struct {
		name    string
		app1    []types.AppNetAdapterConfig
		app2    []types.AppNetAdapterConfig
		overlap bool
	}{
		{
			name:    "same portmap on switch NI",
			app1:    []types.AppNetAdapterConfig{portMapAdapter(switchNI.UUID, "7022", 22)},
			app2:    []types.AppNetAdapterConfig{portMapAdapter(switchNI.UUID, "7022", 22)},
			overlap: false,
		},
		{
			name:    "same portmap on local NI",
			app1:    []types.AppNetAdapterConfig{portMapAdapter(localNI.UUID, "7022", 22)},
			app2:    []types.AppNetAdapterConfig{portMapAdapter(localNI.UUID, "7022", 22)},
			overlap: true,
		},
		{
			name:    "different portmap on local NI",
			app1:    []types.AppNetAdapterConfig{portMapAdapter(localNI.UUID, "7022", 22)},
			app2:    []types.AppNetAdapterConfig{portMapAdapter(localNI.UUID, "7080", 80)},
			overlap: false,
		},
		{
			name: "switch NI conflict next to clean local NI",
			app1: []types.AppNetAdapterConfig{
				portMapAdapter(switchNI.UUID, "7022", 22),
				portMapAdapter(localNI.UUID, "8022", 22),
			},
			app2:    []types.AppNetAdapterConfig{portMapAdapter(switchNI.UUID, "7022", 22)},
			overlap: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := z.checkForPortMapOverlap(tt.app1, tt.app2); got != tt.overlap {
				t.Errorf("checkForPortMapOverlap() = %v, want %v", got, tt.overlap)
			}
		})
	}
}
