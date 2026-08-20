// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/evetest/controller"
	"github.com/spf13/viper"
)

// ControllerFault describes which of the requests a device sends to the
// controller should fail, and how. See ArmControllerFault.
type ControllerFault = controller.FaultRule

// Ways in which the controller can be made to fail a device request.
const (
	// FaultAnswerStatus answers the request with ControllerFault.StatusCode
	// instead of passing it to the controller.
	FaultAnswerStatus = controller.FaultActionStatus
	// FaultCloseConn drops the connection without answering, which the device
	// sees as a failure to reach the controller rather than as an answer.
	FaultCloseConn = controller.FaultActionCloseConn
	// FaultDelay passes the request on after ControllerFault.Delay, to exercise
	// slow answers and timeouts.
	FaultDelay = controller.FaultActionDelay
)

// ControllerFaultsEnabled reports whether the controller runs behind the fault
// injecting proxy, which EVETEST_CONTROLLER_FAULTS asks for. It is off by
// default, so a test which arms faults has to skip when it returns false.
func ControllerFaultsEnabled() bool {
	return viper.GetBool(constants.ControllerFaultsEnv)
}

// ArmControllerFault makes the controller fail the device requests matching the
// given description, until the fault is used up (ControllerFault.Count) or
// cleared with ClearControllerFaults. Several faults can be armed at once; the
// first one matching a request applies.
//
// Requires EVETEST_CONTROLLER_FAULTS - see ControllerFaultsEnabled. Only the
// requests devices make can be failed: the harness reaches the controller
// directly, so watching info or metrics is never disturbed by an injected fault.
//
// For example, to make every info message fail with 503 while leaving the
// device config alone:
//
//	evetest.ArmControllerFault(evetest.ControllerFault{
//		Method:     "POST",
//		PathSuffix: "/info",
//		Action:     evetest.FaultAnswerStatus,
//		StatusCode: http.StatusServiceUnavailable,
//	})
func ArmControllerFault(fault ControllerFault) {
	th := getTestHarness()
	proxy := th.adamClient.FaultProxy()
	if proxy == nil {
		th.t.Fatalf("ArmControllerFault requires %s%s=true",
			constants.EnvPrefix, constants.ControllerFaultsEnv)
	}
	proxy.ArmFault(fault)
}

// ClearControllerFaults removes every armed fault, so that the controller
// answers device requests normally again.
func ClearControllerFaults() {
	th := getTestHarness()
	proxy := th.adamClient.FaultProxy()
	if proxy == nil {
		th.t.Fatalf("ClearControllerFaults requires %s%s=true",
			constants.EnvPrefix, constants.ControllerFaultsEnv)
	}
	proxy.ClearFaults()
}

// WithControllerFault arms a fault, runs the given function, and clears the
// fault afterwards even if the function fails the test.
func WithControllerFault(fault ControllerFault, run func()) {
	ArmControllerFault(fault)
	defer ClearControllerFaults()
	run()
}

// FaultForDuration is a convenience for a fault which stays armed for a window
// of time rather than for a number of requests.
func FaultForDuration(fault ControllerFault, window time.Duration, run func()) {
	ArmControllerFault(fault)
	timer := time.AfterFunc(window, ClearControllerFaults)
	defer timer.Stop()
	defer ClearControllerFaults()
	run()
}
