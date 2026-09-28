// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package portscan

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestPortScanSuite scans the network-facing ports of an EVE device, once per
// hypervisor flavor: EVE-kvm and single-node EVE-k.
func TestPortScanSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestExternalPortScan,
			Variants: []evetest.TestVariant{
				{
					Name: "TestExternalPortScanKVM",
					Parameters: []evetest.TestParameterValue{
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKVM},
					},
				},
				{
					Name: "TestExternalPortScanKubevirt",
					Parameters: []evetest.TestParameterValue{
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
					},
				},
			},
		},
	)
}
