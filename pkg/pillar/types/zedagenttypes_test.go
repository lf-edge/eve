// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// BootReasonFromString — covers all branches

func TestBootReasonFromString(t *testing.T) {
	cases := []struct {
		input string
		want  BootReason
	}{
		{"", BootReasonNone},
		{"BootReasonNone", BootReasonNone},
		{"BootReasonFirst", BootReasonFirst},
		{"BootReasonRebootCmd", BootReasonRebootCmd},
		{"BootReasonUpdate", BootReasonUpdate},
		{"BootReasonFallback", BootReasonFallback},
		{"BootReasonDisconnect", BootReasonDisconnect},
		{"BootReasonFatal", BootReasonFatal},
		{"BootReasonOOM", BootReasonOOM},
		{"BootReasonWatchdogHung", BootReasonWatchdogHung},
		{"BootReasonWatchdogPid", BootReasonWatchdogPid},
		{"BootReasonKernel", BootReasonKernel},
		{"BootReasonPowerFail", BootReasonPowerFail},
		{"BootReasonUnknown", BootReasonUnknown},
		{"BootReasonVaultFailure", BootReasonVaultFailure},
		{"BootReasonPoweroffCmd", BootReasonPoweroffCmd},
		{"BootReasonKubeTransition", BootReasonKubeTransition},
		{"BadValue", BootReasonParseFail},
		// Whitespace trimming
		{"  BootReasonFirst\n", BootReasonFirst},
	}
	for _, tc := range cases {
		got := BootReasonFromString(tc.input)
		assert.Equal(t, tc.want, got, "input=%q", tc.input)
	}
}

// MaintenanceModeReason.String

func TestMaintenanceModeReasonString(t *testing.T) {
	cases := []struct {
		mmr  MaintenanceModeReason
		want string
	}{
		{MaintenanceModeReasonNone, "MaintenanceModeReasonNone"},
		{MaintenanceModeReasonUserRequested, "MaintenanceModeReasonUserRequested"},
		{MaintenanceModeReasonVaultLockedUp, "MaintenanceModeReasonVaultLockedUp"},
		{MaintenanceModeReasonNoDiskSpace, "MaintenanceModeReasonNoDiskSpace"},
		{MaintenanceModeReasonTpmEncFailure, "MaintenanceModeReasonTpmEncFailure"},
		{MaintenanceModeReasonEdgeNodeCertsRefused, "MaintenanceModeReasonEdgeNodeCertsRefused"},
		{MaintenanceModeReason(999), "Unknown MaintenanceModeReason"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.mmr.String())
	}
}

// DeviceOperation.String

func TestDeviceOperationString(t *testing.T) {
	cases := []struct {
		do   DeviceOperation
		want string
	}{
		{DeviceOperationReboot, "reboot"},
		{DeviceOperationShutdown, "shutdown"},
		{DeviceOperationPoweroff, "poweroff"},
		{DeviceOperation(99), fmt.Sprintf("Unknown DeviceOperation %d", 99)},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.do.String())
	}
}
