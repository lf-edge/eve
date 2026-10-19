// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestUpgradeSuite runs TestEVEUpgrade across multiple hypervisor combinations.
func TestUpgradeSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	const (
		initialEVEVersionForKVM = "16.0.0-lts"

		// The OCI-datastore variant points EVE at evetest's own embedded OCI
		// registry (see PushDockerImageToLocalRegistry), which is fronted by
		// the harness's self-signed CA. Resolving an OCI tag against a
		// custom-CA registry only honors the datastore's trusted certificates
		// since pillar commit 90fb8664 ("downloader: ds custom certs when
		// resolving OCI"), which is not part of 16.0.0-lts. If this variant
		// fails on the latest 16.0.x release, backport the fix and bump this
		// to the new patch release.
		initialEVEVersionForOCIDatastore = "16.0.2-lts"
	)

	// Define configurable parameters available for the test suite.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestEVEUpgrade,
			// Target EVE version is common to all variants: set via EVETEST_EVE_VERSION.
			Variants: []evetest.TestVariant{
				{
					Name: "TestEVEUpgradeKVMtoKVM",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKVM},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKVMWithOCIDatastore",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForOCIDatastore},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKVM},
						// Have EVE pull the target rootfs directly from its OCI registry
						// instead of the default evetest-hosted HTTP datastore.
						{Key: datastoreTypeParamKey, Value: evetest.BaseOSDatastoreOCI},
					},
				},
			},
		},
	)
}
