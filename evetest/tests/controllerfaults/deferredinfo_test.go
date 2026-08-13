// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// What EVE does with a state report the controller does not accept.

package controllerfaults_test

import (
	"net/http"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// How long the controller keeps failing info messages, which has to cover the
// application state transition the tests make during it.
const faultWindow = 2 * time.Minute

// How long to wait for the controller to catch up once it accepts info messages
// again. The device holds a refused message back for a delay which doubles with
// every refusal, so by the end of faultWindow the next attempt can be a few
// minutes out, and nothing prompts the device to try sooner.
const convergeTimeout = 8 * time.Minute

// TestInfoRetriedAfterServerError verifies that a state change which happens
// while the controller answers info messages with 503 still reaches the
// controller once it stops doing so.
//
// This is the end-to-end form of lf-edge/eve#6302: application state is
// reported only when it changes, and nothing re-asserts it later, so a report
// discarded because of a temporary server error leaves the controller's view of
// the application wrong for as long as the application stays in that state -
// for a steady-state application, indefinitely.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the fault is injected at the controller,
//     not in the network, so a single management port is all this needs.
//
// Device configuration
// --------------------
//   - ethernet0 (mgmt+apps, DHCP), one local network instance, one container
//     application, activated.
//
// Phases
// ------
//  1. Deploy the application and wait until the controller reports it RUNNING,
//     which establishes that info messages flow.
//  2. Arm a fault answering every info request with 503, and confirm the
//     controller stops learning anything: no info message arrives while it is
//     armed.
//  3. With the fault still armed, deactivate the application. EVE notices the
//     transition and reports it; every attempt is refused.
//  4. Clear the fault. The controller must converge on the state the
//     application actually has, without anything else prompting the device.
//
// Before the fix the message is discarded on the first 503 and phase 4 times
// out with the controller still reporting RUNNING.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestInfoRetriedAfterServerError(test *testing.T) {
	// Also needed when this test runs on its own rather than through the suite;
	// it has no effect once the controller is already up.
	evetest.EnableControllerFaults()
	evetestT := evetest.Init(test)
	defer evetest.Close()
	t := NewGomegaWithT(evetestT)

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	// Phase 1: the application runs and the controller knows it.
	devConfig, appUUID := appDeviceConfig()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	// Phase 2: the controller refuses every info message from now on.
	evetest.ArmControllerFault(evetest.ControllerFault{
		Method:     http.MethodPost,
		PathSuffix: infoPath,
		Action:     evetest.FaultAnswerStatus,
		StatusCode: http.StatusServiceUnavailable,
	})
	defer evetest.ClearControllerFaults()
	log.Info("Controller now answers 503 to every info message")

	// Drain what was already in flight, then confirm nothing new arrives.
	drainAppUpdates(appUpdates)
	t.Consistently(appUpdates, 45*time.Second, 5*time.Second).
		ShouldNot(Receive(), "controller kept receiving info despite the 503s")
	evetest.Checkpoint("info-refused")

	// Phase 3: change the application state while reports cannot get through.
	// The config request itself is not affected, so the device applies it and
	// starts tearing the application down.
	device.DeactivateApplication(appUUID, false, 0)
	log.Info("Application deactivated while info messages are refused")

	// The transition has to complete while the fault is still armed, otherwise
	// the report of it is produced after the controller is answering normally
	// again and the test would pass whether or not a refused report survives.
	// How far the device has got cannot be observed from here - that is exactly
	// what the fault is blocking - so allow generously more than an application
	// takes to stop, and keep requiring that nothing reaches the controller.
	t.Consistently(appUpdates, faultWindow, 10*time.Second).
		ShouldNot(Receive(), "a refused info message was delivered anyway")
	evetest.Checkpoint("app-deactivated-during-fault")

	// Phase 4: with the controller accepting info again, its view has to catch
	// up on its own.
	evetest.ClearControllerFaults()
	log.Info("Controller accepts info messages again")
	t.Eventually(appUpdates, convergeTimeout).Should(Receive(
		matchers.SatisfyPredicate("Application is reported HALTED",
			isAppState(eveinfo.ZSwState_HALTED)).StopIf(appHasError)))
	evetest.Checkpoint("controller-converged")
}

// TestInfoRetriedAfterLostController verifies the same convergence when the
// controller cannot be reached at all, rather than answering with an error.
//
// The two are handled differently by EVE: an answer from the controller is a
// verdict on that one message, while a failure to reach the controller says
// nothing about it and stops the queue until connectivity returns. Both must
// end with the controller knowing the current state.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the connection is dropped at the
//     controller, so no network impairment is needed.
//
// Device configuration
// --------------------
//   - As in TestInfoRetriedAfterServerError.
//
// Phases
// ------
//  1. Deploy the application and wait until it is reported RUNNING.
//  2. Arm a fault dropping the connection for every info request.
//  3. Deactivate the application while its reports cannot be delivered.
//  4. Clear the fault; the controller must converge on the actual state.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestInfoRetriedAfterLostController(test *testing.T) {
	// Also needed when this test runs on its own rather than through the suite;
	// it has no effect once the controller is already up.
	evetest.EnableControllerFaults()
	evetestT := evetest.Init(test)
	defer evetest.Close()
	t := NewGomegaWithT(evetestT)

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	devConfig, appUUID := appDeviceConfig()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	evetest.ArmControllerFault(evetest.ControllerFault{
		Method:     http.MethodPost,
		PathSuffix: infoPath,
		Action:     evetest.FaultCloseConn,
	})
	defer evetest.ClearControllerFaults()
	log.Info("Controller now drops the connection for every info message")

	drainAppUpdates(appUpdates)
	t.Consistently(appUpdates, 45*time.Second, 5*time.Second).
		ShouldNot(Receive(), "controller kept receiving info despite the drops")
	evetest.Checkpoint("info-undeliverable")

	device.DeactivateApplication(appUUID, false, 0)
	log.Info("Application deactivated while info messages cannot be delivered")

	// As in TestInfoRetriedAfterServerError, the transition has to happen while
	// the fault is still armed for the test to mean anything.
	t.Consistently(appUpdates, faultWindow, 10*time.Second).
		ShouldNot(Receive(), "an undeliverable info message arrived anyway")
	evetest.Checkpoint("app-deactivated-during-fault")

	evetest.ClearControllerFaults()
	log.Info("Controller reachable again")
	t.Eventually(appUpdates, convergeTimeout).Should(Receive(
		matchers.SatisfyPredicate("Application is reported HALTED",
			isAppState(eveinfo.ZSwState_HALTED)).StopIf(appHasError)))
	evetest.Checkpoint("controller-converged")
}

// TestInfoDroppedOnRejectionKeepsDeviceReporting verifies that a message the
// controller rejects outright is given up on - which is intended, since
// retrying bytes the controller has refused would achieve nothing - and that
// doing so leaves the device reporting normally afterwards.
//
// This is the counterpart to the two tests above: the fix must distinguish a
// controller which cannot accept a message right now from one which will never
// accept it, and a message dropped for the latter reason must not take the
// reporting of everything else down with it.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP.
//
// Device configuration
// --------------------
//   - As in TestInfoRetriedAfterServerError.
//
// Whether the application has finished stopping cannot be observed while its
// reports are being rejected, and how long it takes varies by minutes, so this
// test deliberately does not depend on it. It uses the device information
// instead: that is the one report EVE re-sends on a timer even when nothing
// changed (zedagent's configTimerTask), so its arrival after the rejections is
// a reliable signal that the queue is still delivering. The interval is lowered
// to the allowed minimum to keep the wait short.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP.
//
// Device configuration
// --------------------
//   - As in TestInfoRetriedAfterServerError, plus timer.deviceinfo.interval
//     lowered to 30s.
//
// Phases
// ------
//  1. Deploy the application and wait until it is reported RUNNING.
//  2. Arm a fault rejecting every info request with 404, the answer a controller
//     gives for an object it no longer knows about.
//  3. Deactivate the application. The reports of the transition are rejected and
//     dropped, and nothing about the application reaches the controller.
//  4. Clear the fault. Device information has to start arriving again, which is
//     what proves the drops did not leave the queue unable to deliver.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestInfoDroppedOnRejectionKeepsDeviceReporting(test *testing.T) {
	// Also needed when this test runs on its own rather than through the suite;
	// it has no effect once the controller is already up.
	evetest.EnableControllerFaults()
	evetestT := evetest.Init(test)
	defer evetest.Close()
	t := NewGomegaWithT(evetestT)

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	devConfig, appUUID := appDeviceConfig()
	// EVE re-sends the device information on this timer even when nothing about
	// the device changed, which is what phase 4 waits for.
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.DevInfoInterval, 30)
	devConfig.SetConfigProperties(cfgProps)

	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	deviceUpdates, stopDeviceWatch := device.WatchDeviceInfo()
	defer stopDeviceWatch()
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	evetest.ArmControllerFault(evetest.ControllerFault{
		Method:     http.MethodPost,
		PathSuffix: infoPath,
		Action:     evetest.FaultAnswerStatus,
		StatusCode: http.StatusNotFound,
	})
	defer evetest.ClearControllerFaults()
	log.Info("Controller now rejects every info message with 404")

	drainAppUpdates(appUpdates)
	device.DeactivateApplication(appUUID, false, 0)
	log.Info("Application deactivated while info messages are rejected")

	// Nothing about the application reaches the controller: the reports of the
	// transition are rejected, and a rejected report is not offered again.
	t.Consistently(appUpdates, faultWindow, 10*time.Second).
		ShouldNot(Receive(), "a rejected info message was delivered anyway")
	evetest.Checkpoint("info-rejected-during-fault")

	// The device information which the rejections dropped along the way has to
	// start arriving again. Nothing prompts it other than its own timer, so this
	// is the queue proving it still works after giving up on messages.
	evetest.ClearControllerFaults()
	log.Info("Controller accepts info messages again")
	drainDeviceUpdates(deviceUpdates)
	t.Eventually(deviceUpdates, convergeTimeout).Should(Receive(),
		"device stopped reporting after its messages were rejected")
	evetest.Checkpoint("reporting-recovered")
}

// drainDeviceUpdates empties the device information channel, so that a later
// wait is satisfied by a message published after that point rather than before.
func drainDeviceUpdates(updates <-chan *eveinfo.ZInfoDevice) {
	for {
		select {
		case <-updates:
		case <-time.After(2 * time.Second):
			return
		}
	}
}

// drainAppUpdates empties the watch channel of messages published before a
// fault was armed, so that a later assertion about what does or does not arrive
// is not satisfied by a stale message.
func drainAppUpdates(updates <-chan *eveinfo.ZInfoApp) {
	for {
		select {
		case <-updates:
		case <-time.After(2 * time.Second):
			return
		}
	}
}
