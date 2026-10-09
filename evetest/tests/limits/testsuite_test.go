// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package limits_test holds the tests that push a single configuration or
// status object past what EVE's internal messaging carries. pubsub, the bus
// between pillar's agents, delivers every object as one message of at most
// 64 KiB, and an object that outgrows it makes the publishing agent exit with
// a fatal, after which the watchdog reboots the device and every application
// restarts. When the object came from the controller it is checkpointed and
// re-read after the reboot, so the device keeps crashing until the controller
// sends something smaller. Each test here builds one such object out of an
// ordinary controller configuration or workload and expects EVE to either
// apply it or report an error for it, while staying up.
//
// Helper layout: helpers_test.go holds what every test shares -- the device
// and its base configuration, the wait that fails at once on a crash and
// then requires the device to keep reporting -- and nothing else; each test
// file holds one test and the generator of its own oversized object.
package limits_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestLimitsSuite runs every test of this package on one device
// (netmodels.SingleEthWithDHCP, configuration reset between tests). The tests
// without an application come first; the two that deploy applications, which
// take longest, come last, and the last of them needs a device with more
// memory, so the framework recreates the device once, at the end.
//
// Subtests
// --------
//   - TestManyStaticDNSEntries -- a network instance with hundreds of static
//     DNS entries (NetworkInstanceConfig from zedagent).
//   - TestManyPhysicalIOAdapters -- a device model with hundreds of I/O
//     adapters (PhysicalIOAdapterList from zedagent).
//   - TestHugeConfigItem -- a configuration property with a value of tens of
//     KB (ConfigItemValueMap from zedagent).
//   - TestLargePACFile -- a proxy auto-config script of tens of KB on the
//     management port (DevicePortConfig from zedagent, the port status and
//     the persisted port config list in nim).
//   - TestManyVolumesPerApp -- an application with a hundred volumes
//     (AppInstanceStatus from zedmanager).
//   - TestManyAppInterfaces -- hundreds of application interfaces
//     (NetworkMetrics from zedrouter).
//
// All subtests share the HYPERVISOR parameter; each sizes its object with a
// parameter of its own, defaulting to a value measured to overflow with
// margin. Run with EVETEST_SUITE_MAX_FAILURES=-1 to see every subtest fail on
// a build that does not bound them, since each failure leaves the device
// rebooting until its configuration is reset for the next subtest.
func TestLimitsSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestManyStaticDNSEntries,
		},
		evetest.TestCase{
			Test: TestManyPhysicalIOAdapters,
		},
		evetest.TestCase{
			Test: TestHugeConfigItem,
		},
		evetest.TestCase{
			Test: TestLargePACFile,
		},
		evetest.TestCase{
			Test: TestManyVolumesPerApp,
		},
		evetest.TestCase{
			Test: TestManyAppInterfaces,
		},
	)
}
