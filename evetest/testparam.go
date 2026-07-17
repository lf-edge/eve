// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"os"
	"strconv"

	"github.com/lf-edge/eve/evetest/constants"
)

// TestParameterDescription provides metadata for a test parameter, used when
// listing available tests (see "make list-tests").
type TestParameterDescription struct {
	// Summary is a human-readable explanation of what the parameter controls.
	Summary string
	// Default is the default value expressed as a human-readable string
	// (e.g. "kvm", "false", "42").
	// IMPORTANT: this field must be set to a string literal so that
	// list-tests can extract it via static AST analysis. Do not use
	// computed expressions such as method calls or variable references.
	Default string
	// AllowedValues describes the set of accepted values in human-readable form.
	// For enum parameters the recommended format is "<val1>|<val2>|<val3>".
	// For numeric ranges you might write "<minval>-<maxval>".
	// Leave empty if unrestricted (any value of the given type is allowed).
	// Same constraint as Default: must be a string literal.
	AllowedValues string
}

// TestParameterDefinition describes a parameter that a test or test-suite
// can accept. Parameters may have a default value, can be overridden by
// test-suites, or via environment variables.
type TestParameterDefinition struct {
	// Key is the unique identifier of the parameter.
	Key string

	// DefaultValue is the value used if the parameter is not explicitly set.
	DefaultValue interface{}

	// Description provides human-readable metadata about the parameter.
	Description TestParameterDescription
}

// TestParameterValue represents a concrete value assigned to a test parameter,
// typically by a test-suite when running parameterized tests.
type TestParameterValue struct {
	// Key is the identifier of the parameter.
	Key string

	// Value is the concrete value assigned to the parameter.
	Value interface{}
}

// FromStringer should be implemented by a test parameter if its type is not a basic
// Go type.
type FromStringer interface {
	FromString(string) error
}

// DefineTestParameters defines the set of parameters available to the
// currently executing test or test suite.
func DefineTestParameters(params ...TestParameterDefinition) {
	th := getTestHarness()
	th.testM.Lock()
	defer th.testM.Unlock()
	th.test.paramDefs = params
}

// GetTestParameter returns the value of a test parameter with the given key,
// resolved in the following order:
//
//  1. Value set explicitly by the test-suite
//  2. Value provided via environment variable EVETEST_<KEY>
//  3. Default value from the parameter definition
//
// The type parameter T must match the parameter’s declared type, otherwise
// the test will fail.
func GetTestParameter[T any](key string) T {
	th := getTestHarness()
	th.testM.Lock()
	defer th.testM.Unlock()

	// Check that the given parameter is defined for the current test.
	var definition TestParameterDefinition
	for _, param := range th.test.paramDefs {
		if param.Key == key {
			definition = param
			break
		}
	}
	if th.suite != nil {
		for _, param := range th.suite.paramDefs {
			if param.Key == key {
				definition = param
				break
			}
		}
	}
	if definition.Key == "" {
		th.t.Fatalf("Parameter %q is not defined for test %q",
			key, th.test.name)
	}

	// Check if RunTestSuite has set some value for the parameter.
	for _, param := range th.test.paramVals {
		if param.Key == key {
			val, ok := param.Value.(T)
			if !ok {
				th.t.Fatalf(
					"parameter %q has type %T, expected %T",
					key, param.Value, *new(T),
				)
			}
			return val
		}
	}

	// Check environment variables.
	val := os.Getenv(constants.EnvPrefix + key)
	if val != "" {
		var zero T
		switch any(zero).(type) {
		case string:
			return any(val).(T)
		case bool:
			parsed, err := strconv.ParseBool(val)
			if err != nil {
				th.t.Fatalf("invalid boolean for %s: %v", key, err)
			}
			return any(parsed).(T)
		case int:
			parsed, err := strconv.Atoi(val)
			if err != nil {
				th.t.Fatalf("invalid int for %s: %v", key, err)
			}
			return any(parsed).(T)
		case int8:
			parsed, err := strconv.ParseInt(val, 10, 8)
			if err != nil {
				th.t.Fatalf("invalid int8 for %s: %v", key, err)
			}
			return any(int8(parsed)).(T)
		case int16:
			parsed, err := strconv.ParseInt(val, 10, 16)
			if err != nil {
				th.t.Fatalf("invalid int16 for %s: %v", key, err)
			}
			return any(int16(parsed)).(T)
		case int32:
			parsed, err := strconv.ParseInt(val, 10, 32)
			if err != nil {
				th.t.Fatalf("invalid int32 for %s: %v", key, err)
			}
			return any(int32(parsed)).(T)
		case int64:
			parsed, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				th.t.Fatalf("invalid int64 for %s: %v", key, err)
			}
			return any(parsed).(T)
		case uint:
			parsed, err := strconv.ParseUint(val, 10, 0)
			if err != nil {
				th.t.Fatalf("invalid uint for %s: %v", key, err)
			}
			return any(uint(parsed)).(T)
		case uint8:
			parsed, err := strconv.ParseUint(val, 10, 8)
			if err != nil {
				th.t.Fatalf("invalid uint8 for %s: %v", key, err)
			}
			return any(uint8(parsed)).(T)
		case uint16:
			parsed, err := strconv.ParseUint(val, 10, 16)
			if err != nil {
				th.t.Fatalf("invalid uint16 for %s: %v", key, err)
			}
			return any(uint16(parsed)).(T)
		case uint32:
			parsed, err := strconv.ParseUint(val, 10, 32)
			if err != nil {
				th.t.Fatalf("invalid uint32 for %s: %v", key, err)
			}
			return any(uint32(parsed)).(T)
		case uint64:
			parsed, err := strconv.ParseUint(val, 10, 64)
			if err != nil {
				th.t.Fatalf("invalid uint64 for %s: %v", key, err)
			}
			return any(parsed).(T)
		}

		// Try FromStringer interface
		ptr := new(T)
		if fm, ok := any(ptr).(FromStringer); ok {
			if err := fm.FromString(val); err != nil {
				th.t.Fatalf("error parsing %s from env: %v", key, err)
			}
			return *ptr
		}

		th.t.Fatalf("unsupported parameter type for key %s", key)
	}

	// Return default value.
	defVal, ok := definition.DefaultValue.(T)
	if !ok {
		th.t.Fatalf(
			"default value for parameter %q has type %T, expected %T",
			key, definition.DefaultValue, *new(T),
		)
	}
	return defVal
}

// HypervisorParameterKey is the key used for the Hypervisor parameter.
const HypervisorParameterKey = "HYPERVISOR"

// HypervisorParameter is a predefined TestParameterDefinition for the Hypervisor parameter.
func HypervisorParameter() TestParameterDefinition {
	return TestParameterDefinition{
		Key:          HypervisorParameterKey,
		DefaultValue: HypervisorKVM,
		Description: TestParameterDescription{
			Summary:       "Hypervisor to use for the test",
			Default:       "kvm",
			AllowedValues: "kvm|xen|kubevirt",
		},
	}
}

// GetHypervisorParameterValue returns the value set for the Hypervisor parameter.
func GetHypervisorParameterValue() Hypervisor {
	return GetTestParameter[Hypervisor](HypervisorParameterKey)
}

// EVEVersionParameterKey is the key used for the EVE version parameter.
// This is the EVETEST_EVE_VERSION environment variable, which defaults to the
// HEAD of the checked-out EVE repo when not set (determined by the evetest
// Makefile).
// Most tests do not need to explicitly use this parameter and will automatically
// get EVE device(s) running the version defined by the EVETEST_EVE_VERSION variable.
// Only needed when a test must start from a different EVE version and then later
// upgrade to the version selected by EVETEST_EVE_VERSION, or when a test suite
// needs to override the EVE version for a specific sub-test variant.
const EVEVersionParameterKey = "EVE_VERSION"

// EVEVersionParameter is a predefined TestParameterDefinition for the EVE version.
func EVEVersionParameter() TestParameterDefinition {
	return TestParameterDefinition{
		Key:          EVEVersionParameterKey,
		DefaultValue: "",
		Description: TestParameterDescription{
			Summary: "EVE version to run on the device (e.g. \"16.0.0-lts\")",
			Default: "HEAD of the checked-out EVE repo (determined by the evetest Makefile)",
		},
	}
}

// GetEVEVersionParameterValue returns the value set for the EVE version parameter.
func GetEVEVersionParameterValue() string {
	return GetTestParameter[string](EVEVersionParameterKey)
}

// DiskSizeMiBParameterKey is the key used for the DiskSizeMiB parameter.
const DiskSizeMiBParameterKey = "DISK_SIZE_MB"

// DiskSizeMiBParameter is a predefined TestParameterDefinition for the device disk size.
// A value of 0 means the framework default (65536 MiB) is used.
func DiskSizeMiBParameter() TestParameterDefinition {
	return TestParameterDefinition{
		Key:          DiskSizeMiBParameterKey,
		DefaultValue: uint32(0),
		Description: TestParameterDescription{
			Summary: "Device disk size in MiB",
			Default: "0 (use framework default 65536 MiB)",
		},
	}
}

// GetDiskSizeMiBParameterValue returns the value set for the DiskSizeMiB parameter.
func GetDiskSizeMiBParameterValue() uint32 {
	return GetTestParameter[uint32](DiskSizeMiBParameterKey)
}

// SkipIfHypervisorKubevirt skips the current test if the resolved HYPERVISOR
// parameter is HypervisorKubevirt. Kubevirt is only supported by tests under
// `evetest/tests/cluster`; non-cluster tests should call this helper right
// after defining the HypervisorParameter to ensure they are not accidentally
// exercised on a Kubevirt-flavored EVE build.
func SkipIfHypervisorKubevirt() {
	th := getTestHarness()
	if GetHypervisorParameterValue() == HypervisorKubevirt {
		th.t.Skipf("Kubevirt hypervisor is only supported by cluster tests " +
			"(under evetest/tests/cluster); use kvm or xen")
	}
}

// FilesystemParameterKey is the key used for the Filesystem parameter.
const FilesystemParameterKey = "FILESYSTEM"

// FilesystemParameter is a predefined TestParameterDefinition for the Filesystem parameter.
func FilesystemParameter() TestParameterDefinition {
	return TestParameterDefinition{
		Key:          FilesystemParameterKey,
		DefaultValue: FilesystemEXT4,
		Description: TestParameterDescription{
			Summary:       "Filesystem for persistent storage on the EVE device",
			Default:       "ext4",
			AllowedValues: "ext4|zfs",
		},
	}
}

// GetFilesystemParameterValue returns the value set for the Filesystem parameter.
func GetFilesystemParameterValue() Filesystem {
	return GetTestParameter[Filesystem](FilesystemParameterKey)
}

// TPMParameterKey is the key used for the TPM parameter.
const TPMParameterKey = "TPM"

// TPMParameter is a predefined TestParameterDefinition for the TPM parameter.
func TPMParameter() TestParameterDefinition {
	return TestParameterDefinition{
		Key:          TPMParameterKey,
		DefaultValue: true,
		Description: TestParameterDescription{
			Summary: "Enable or disable TPM emulation",
			Default: "true",
		},
	}
}

// GetTPMParameterValue returns the value set for the TPM parameter.
func GetTPMParameterValue() (useTPM bool) {
	return GetTestParameter[bool](TPMParameterKey)
}
