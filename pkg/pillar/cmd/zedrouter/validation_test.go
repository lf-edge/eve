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

// TestPortMapOverlapAcrossNIs checks portmap conflicts between apps attached
// to different network instances. Apps on two Local NIs conflict when the NIs
// share an external port, because the portmap DNAT rules are installed on that
// port. The Local NI cases use port labels that each name a single port (eth0,
// eth1), so the same label means the same port and different labels mean
// different ports. Shared labels (e.g. "uplink" and "freeuplink") can differ
// and still match a common port; that is not covered here.
// Switch NIs never apply portmaps, so apps on them must not conflict, e.g. on
// two air-gapped Switch NIs, which both have an empty port label.
func TestPortMapOverlapAcrossNIs(t *testing.T) {
	newNI := func(niType types.NetworkInstanceType, portLabel string) types.NetworkInstanceConfig {
		return types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
			Type:           niType,
			PortLabel:      portLabel,
		}
	}
	localEth0A := newNI(types.NetworkInstanceTypeLocal, "eth0")
	localEth0B := newNI(types.NetworkInstanceTypeLocal, "eth0")
	localEth1 := newNI(types.NetworkInstanceTypeLocal, "eth1")
	switchA := newNI(types.NetworkInstanceTypeSwitch, "")
	switchB := newNI(types.NetworkInstanceTypeSwitch, "")
	switchEth0 := newNI(types.NetworkInstanceTypeSwitch, "eth0")
	unknownNI := uuid.Must(uuid.NewV4())
	z := newPortMapTestRouter(t, localEth0A, localEth0B, localEth1, switchA, switchB, switchEth0)

	tests := []struct {
		name    string
		app1    types.AppNetAdapterConfig
		app2    types.AppNetAdapterConfig
		overlap bool
	}{
		{
			name:    "different local NIs on the same port",
			app1:    portMapAdapter(localEth0A.UUID, "7022", 22),
			app2:    portMapAdapter(localEth0B.UUID, "7022", 22),
			overlap: true,
		},
		{
			name:    "different local NIs on different ports",
			app1:    portMapAdapter(localEth0A.UUID, "7022", 22),
			app2:    portMapAdapter(localEth1.UUID, "7022", 22),
			overlap: false,
		},
		{
			name:    "different air-gapped switch NIs",
			app1:    portMapAdapter(switchA.UUID, "7022", 22),
			app2:    portMapAdapter(switchB.UUID, "7022", 22),
			overlap: false,
		},
		{
			name:    "switch NI and local NI on the same port",
			app1:    portMapAdapter(switchEth0.UUID, "7022", 22),
			app2:    portMapAdapter(localEth0A.UUID, "7022", 22),
			overlap: false,
		},
		{
			name:    "unknown NI is checked conservatively",
			app1:    portMapAdapter(unknownNI, "7022", 22),
			app2:    portMapAdapter(unknownNI, "7022", 22),
			overlap: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app1 := []types.AppNetAdapterConfig{tt.app1}
			app2 := []types.AppNetAdapterConfig{tt.app2}
			if got := z.checkForPortMapOverlap(app1, app2); got != tt.overlap {
				t.Errorf("checkForPortMapOverlap(app1, app2) = %v, want %v", got, tt.overlap)
			}
			// The check must not depend on the order of the apps.
			if got := z.checkForPortMapOverlap(app2, app1); got != tt.overlap {
				t.Errorf("checkForPortMapOverlap(app2, app1) = %v, want %v", got, tt.overlap)
			}
		})
	}
}

// TestPortMapOverlapWithinAdapter checks that duplicate portmap rules within
// a single app interface are reported only where portmaps are applied.
func TestPortMapOverlapWithinAdapter(t *testing.T) {
	switchNI := types.NetworkInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
		Type:           types.NetworkInstanceTypeSwitch,
	}
	localNI := types.NetworkInstanceConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.Must(uuid.NewV4())},
		Type:           types.NetworkInstanceTypeLocal,
	}
	z := newPortMapTestRouter(t, switchNI, localNI)

	withDuplicateRule := func(network uuid.UUID) []types.AppNetAdapterConfig {
		adapter := portMapAdapter(network, "7022", 22)
		adapter.ACLs = append(adapter.ACLs, adapter.ACLs[1])
		return []types.AppNetAdapterConfig{adapter}
	}
	if !z.checkForPortMapOverlap(withDuplicateRule(localNI.UUID), nil) {
		t.Error("duplicate portmap rules on local NI were not reported")
	}
	if z.checkForPortMapOverlap(withDuplicateRule(switchNI.UUID), nil) {
		t.Error("duplicate portmap rules on switch NI were reported as overlapping")
	}
}
