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

		// EVE-K (k3s/kubevirt-based EVE) is officially supported starting from 17.0.0.
		// However, currently 17.0-stable does not include github.com/lf-edge/eve/pull/6209,
		// which is needed for reliable app deployment.
		// For the time being, we will use EVE version from the master, at the commit just
		// before the big rewrite of kube-init from shell scripts to Go.
		initialEVEVersionForKubevirt = "0.0.0-master-66475696"

		// The OCI-datastore variant points EVE at evetest's own embedded OCI
		// registry (see PushDockerImageToLocalRegistry), which is fronted by
		// the harness's self-signed CA. Resolving an OCI tag against a
		// custom-CA registry only started honoring the datastore's trusted
		// certificates in pillar commit 90fb8664 ("downloader: ds custom
		// certs when resolving OCI"); before that, tag resolution opened the
		// registry without them and failed TLS verification even though the
		// certs were (and still are) applied correctly for the subsequent
		// download. That fix is included in 17.0.0-lts (but not in 16.0.0-lts).
		initialEVEVersionForOCIDatastore = "17.0.0-lts"
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
				{
					Name: "TestEVEUpgradeKubevirtToKubevirt",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKubevirt},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKubevirt},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
					},
				},
			},
		},
	)
}
