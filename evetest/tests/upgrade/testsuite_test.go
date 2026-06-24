// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestUpgradeSuite runs TestEVEUpgrade across multiple hypervisor combinations
// and disk sizes.
// IMPORTANT: In this test suite, it is assumed that the tested EVE version
// (selected by the variable EVETEST_EVE_VERSION) is at least 17.0.0
// and therefore uses the 2 * 10GB partition layout.
func TestUpgradeSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	const (
		// 16.0.0-lts has small enough partitions to boot on smallDiskSizeMiB.
		// The target EVE version (>= 17.0.0) requires larger partitions, so the
		// upgrade fails and EVE reverts -- which is what the *WithSmallDisk variants
		// are designed to test.
		initialEVEVersionForKVM = "16.0.0-lts"

		// EVE-K (k3s/kubevirt-based EVE) is officially supported starting from 17.0.0.
		// TODO: strip the rc suffix once 17.0.0 is released.
		initialEVEVersionForKubevirt = "17.0.0-rc2"

		// Enough for the pre-10GB partition layout, but not enough for EVE 17.0.0+,
		// which is why *WithSmallDisk variants expect revert.
		smallDiskSizeMiB = uint32(20480) // 20 GiB
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
					Name: "TestEVEUpgradeKubevirtToKubevirt",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKubevirt},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKubevirt},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKubevirt",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKVMWithSmallDisk",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKVM},
						// Extra params
						{Key: evetest.DiskSizeMiBParameterKey, Value: smallDiskSizeMiB},
						// Expect upgrade to fail
						{Key: expectRevertParamKey, Value: true},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKubevirtWithSmallDisk",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
						// Extra params
						{Key: evetest.DiskSizeMiBParameterKey, Value: smallDiskSizeMiB},
						// Expect upgrade to fail
						{Key: expectRevertParamKey, Value: true},
					},
				},
			},
		},
	)
}
