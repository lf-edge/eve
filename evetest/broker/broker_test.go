// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/lf-edge/eve/evetest/broker/provider"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// TestBrokerCapabilitiesAdvertisesLocalLiveImage covers the decision that
// belongs to the broker, not to any device provider: a provider that does not
// build a per-device image (DiskImageOverlay/DiskImageStandalone) allows the
// broker to consume an uploaded live image directly, so the broker must
// advertise CAPABILITY_LOCAL_LIVE_IMAGE for it. A DiskImageLegacyBuild
// provider builds per device and cannot consume one, so the broker must not.
func TestBrokerCapabilitiesAdvertisesLocalLiveImage(t *testing.T) {
	providerCaps := []api.Capability{api.Capability_CAPABILITY_TPM}

	cases := []struct {
		name     string
		strategy provider.DiskImageStrategy
		want     bool
	}{
		{"overlay strategy advertises the capability", provider.DiskImageOverlay, true},
		{"standalone strategy advertises the capability", provider.DiskImageStandalone, true},
		{"legacy build strategy does not advertise the capability", provider.DiskImageLegacyBuild, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := brokerCapabilities(providerCaps, c.strategy)
			if has := generics.ContainsItem(
				got, api.Capability_CAPABILITY_LOCAL_LIVE_IMAGE); has != c.want {
				t.Errorf("brokerCapabilities(_, %v) contains CAPABILITY_LOCAL_LIVE_IMAGE = %v, want %v",
					c.strategy, has, c.want)
			}
		})
	}
}

// TestBrokerCapabilitiesPreservesProviderCapabilities covers that the
// provider's own capabilities are carried through unchanged, regardless of
// disk image strategy.
func TestBrokerCapabilitiesPreservesProviderCapabilities(t *testing.T) {
	providerCaps := []api.Capability{
		api.Capability_CAPABILITY_FORWARD_LACP, api.Capability_CAPABILITY_TPM,
	}
	got := brokerCapabilities(providerCaps, provider.DiskImageLegacyBuild)
	for _, want := range providerCaps {
		if !generics.ContainsItem(got, want) {
			t.Errorf("brokerCapabilities() = %v, missing provider capability %v", got, want)
		}
	}
}
