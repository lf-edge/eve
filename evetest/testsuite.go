// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/spf13/viper"
)

// TestCase represents a single logical test along with optional variants.
// If no variants are provided, the test is executed once with default
// parameters.
type TestCase struct {
	// Test is the test function to execute.
	Test func(t *testing.T)

	// Variants defines multiple configurations under which the test
	// should be executed. Each variant is run as a subtest.
	Variants []TestVariant
}

// TestVariant represents a named variation of a test case with a specific
// set of parameter values. Variants are typically used to run the same test
// logic under different configurations.
type TestVariant struct {
	// Name is the name of the test variant.
	Name string

	// Parameters contains the concrete parameter values applied for this variant.
	Parameters []TestParameterValue
}

// RunTestSuite executes all variants of all test cases using t.Run.
// Each variant is executed as a subtest with its own parameter values.
//
// Environment variables such as EVETEST_SUITE_MAX_FAILURES may be used
// to control suite-wide execution behavior (e.g., early termination on
// excessive failures).
func RunTestSuite(cases ...TestCase) {
	th := getTestHarness()

	// Move testState to testSuiteState.
	th.testM.Lock()
	if th.suite != nil {
		th.t.Fatalf("Nested test suites are not supported")
	}
	th.suite = &testSuiteState{
		name:      th.test.name,
		paramDefs: th.test.paramDefs,
	}
	suiteT := th.t
	suiteFailedCh := th.test.failedCh
	th.testM.Unlock()

	maxFailures := viper.GetInt(constants.SuiteMaxFailuresEnv)
	failures := 0

	// Helper to decide whether execution should stop.
	shouldStop := func() bool {
		return maxFailures >= 0 && failures >= maxFailures
	}

	// Execute all test cases.
	for _, tc := range cases {
		if shouldStop() {
			break
		}

		if len(tc.Variants) == 0 {
			th.testM.Lock()
			testName := testFuncName(tc.Test)
			th.test.name = testName
			th.test.paramDefs = nil
			th.test.paramVals = nil
			th.test.failedCh = nil
			th.test.initialized = false
			th.testM.Unlock()

			succeeded := suiteT.Run(testName, func(t *testing.T) {
				tc.Test(t)
			})
			if !succeeded {
				failures++
			}
			continue
		}

		for _, variant := range tc.Variants {
			if shouldStop() {
				break
			}

			th.testM.Lock()
			testName := variant.Name
			th.test.name = testName
			th.test.paramDefs = nil
			th.test.paramVals = variant.Parameters
			th.test.failedCh = nil
			th.test.initialized = false
			th.testM.Unlock()

			succeeded := suiteT.Run(testName, func(t *testing.T) {
				tc.Test(t)
			})
			if !succeeded {
				failures++
			}
		}
	}

	// Move testSuiteState back to testState.
	th.testM.Lock()
	th.test.name = th.suite.name
	th.test.paramDefs = th.suite.paramDefs
	th.test.paramVals = nil
	th.test.failedCh = suiteFailedCh
	th.test.executedTestSuite = true
	th.test.initialized = true
	th.suite = nil
	th.t = suiteT
	th.testM.Unlock()
}

func testFuncName(fn interface{}) string {
	pc := reflect.ValueOf(fn).Pointer()
	f := runtime.FuncForPC(pc)
	if f == nil {
		return "unknown_test"
	}
	name := f.Name()

	// Trim package path
	if idx := strings.LastIndex(name, "."); idx != -1 {
		name = name[idx+1:]
	}
	return name
}
