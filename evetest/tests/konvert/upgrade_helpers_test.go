// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"

	"github.com/lf-edge/eve/evetest"
)

// altHypervisor returns the flavor on the other side of the cross-flavor seam.
func altHypervisor(h evetest.Hypervisor) evetest.Hypervisor {
	if h == evetest.HypervisorKubevirt {
		return evetest.HypervisorKVM
	}
	return evetest.HypervisorKubevirt
}

// resolveAltVersion reads the alternate-flavor version, defaulting to the
// initial one: the cross-flavor tests hop between two flavors of the *same*
// released version, so that the flavor is the only thing that changed.
func resolveAltVersion(p deviceParams) string {
	version := evetest.GetTestParameter[string](altEVEVersionParamKey)
	if version == "" {
		version = p.initialVersion
	}
	return version
}

// altParameterDefinitions declares the alternate-flavor axes.
func altParameterDefinitions() []evetest.TestParameterDefinition {
	return []evetest.TestParameterDefinition{
		{
			Key:          altEVEVersionParamKey,
			DefaultValue: "",
			Description: evetest.TestParameterDescription{
				Summary: "Released EVE version of the alternate flavor",
				Default: "\"\" (the same version the device started on)",
			},
		},
	}
}

// shortBaseImageCooldown cuts the wait EVE imposes before it commits a new base
// image, which is dead time for a test that is not measuring it.
//
// Built from an empty map, not a defaulted one: applying a fully populated map
// sets every property the device did not ask about back to its default, which
// includes clearing the SSH authorized key the harness injected -- leaving the
// device up, addressable, and refusing every connection on port 22.
func shortBaseImageCooldown() *pillartypes.ConfigItemValueMap {
	props := pillartypes.NewConfigItemValueMap()
	props.SetGlobalValueInt(pillartypes.MintimeUpdateSuccess, 30)
	return props
}

// upgradeAcrossFlavors drives one cross-flavor base-OS update and waits for the
// device to report itself running it.
//
// Which repository the target is pulled from is EVETEST_EVE_REPO's to decide,
// the same as for any other upgrade; only the initial device can be pointed
// somewhere else, through RequireEdgeDevice.WithEVERepo.
func upgradeAcrossFlavors(device *evetest.EdgeDevice,
	version string, hypervisor evetest.Hypervisor) {
	device.UpgradeEVE(version, hypervisor, evetest.BaseOSDatastoreHTTP, true, false)
}
