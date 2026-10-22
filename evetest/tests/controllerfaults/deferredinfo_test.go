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
)

// How long the controller keeps failing info messages, which has to cover the
// application state transition the tests make during it.
const faultWindow = 2 * time.Minute

// How long to wait for the controller to catch up once it accepts info messages
// again. The device holds a refused message back for a delay which doubles with
// every refusal, so by the end of faultWindow the next attempt can be a few
// minutes out, and nothing prompts the device to try sooner.
const convergeTimeout = 8 * time.Minute

// deviceInfoTimeout bounds the wait for the periodic device info, which EVE
// 14.5 publishes every 10 minutes +/- 20% and does not allow to configure.
const deviceInfoTimeout = 13 * time.Minute

// TestInfoRetriedAfterLostController verifies that a state change which happens
// while the controller cannot be reached at all still reaches the controller
// once it can be reached again.
//
// A failure to reach the controller says nothing about a message and stops
// the queue until connectivity returns. It must then end with the controller
// knowing the current state.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- the connection is dropped at the
//     controller, so no network impairment is needed.
//
// Device configuration
// --------------------
//   - ethernet0 (mgmt+apps, DHCP), one local network instance, one container
//     application, activated.
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
	evetestT := evetest.Init(test, evetest.WithControllerFaults())
	defer evetest.Close()
	if !evetest.ControllerFaultsEnabled() {
		test.Skip("controller fault injection was turned off; " +
			"unset EVETEST_CONTROLLER_FAULTS to run this test")
	}
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

	// The transition has to happen while the fault is still armed for the test
	// to mean anything.
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
//   - ethernet0 (mgmt+apps, DHCP), one local network instance, one container
//     application, activated.
//
// Whether the application has finished stopping cannot be observed while its
// reports are being rejected, and how long it takes varies by minutes, so this
// test deliberately does not depend on it. It uses the device information
// instead: that is the one report EVE re-sends on a timer even when nothing
// changed (zedagent's configTimerTask), so its arrival after the rejections is
// a reliable signal that the queue is still delivering. EVE 14.5 does not
// allow lowering that interval, which is fixed at 10 minutes +/- 20%, so the
// wait is correspondingly long.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP.
//
// Device configuration
// --------------------
//   - ethernet0 (mgmt+apps, DHCP), one local network instance, one container
//     application, activated.
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
	evetestT := evetest.Init(test, evetest.WithControllerFaults())
	defer evetest.Close()
	if !evetest.ControllerFaultsEnabled() {
		test.Skip("controller fault injection was turned off; " +
			"unset EVETEST_CONTROLLER_FAULTS to run this test")
	}
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
	t.Eventually(deviceUpdates, deviceInfoTimeout).Should(Receive(),
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
