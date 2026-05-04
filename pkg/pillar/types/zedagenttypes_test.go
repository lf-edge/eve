// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	uuid "github.com/satori/go.uuid"
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

// MaintenanceModeMultiReason.String and ToProto

func TestMaintenanceModeMultiReasonString(t *testing.T) {
	// Empty slice → empty string
	assert.Equal(t, "", MaintenanceModeMultiReason{}.String())

	// Single reason
	single := MaintenanceModeMultiReason{MaintenanceModeReasonNone}
	assert.Equal(t, "MaintenanceModeReasonNone", single.String())

	// Multiple reasons joined with |
	multi := MaintenanceModeMultiReason{
		MaintenanceModeReasonUserRequested,
		MaintenanceModeReasonVaultLockedUp,
	}
	assert.Equal(t, "MaintenanceModeReasonUserRequested|MaintenanceModeReasonVaultLockedUp", multi.String())
}

// BootReason.String

func TestBootReasonString(t *testing.T) {
	cases := []struct {
		br   BootReason
		want string
	}{
		{BootReasonNone, "BootReasonNone"},
		{BootReasonFirst, "BootReasonFirst"},
		{BootReasonRebootCmd, "BootReasonRebootCmd"},
		{BootReasonUpdate, "BootReasonUpdate"},
		{BootReasonFallback, "BootReasonFallback"},
		{BootReasonDisconnect, "BootReasonDisconnect"},
		{BootReasonFatal, "BootReasonFatal"},
		{BootReasonOOM, "BootReasonOOM"},
		{BootReasonWatchdogHung, "BootReasonWatchdogHung"},
		{BootReasonWatchdogPid, "BootReasonWatchdogPid"},
		{BootReasonKernel, "BootReasonKernel"},
		{BootReasonPowerFail, "BootReasonPowerFail"},
		{BootReasonUnknown, "BootReasonUnknown"},
		{BootReasonVaultFailure, "BootReasonVaultFailure"},
		{BootReasonPoweroffCmd, "BootReasonPoweroffCmd"},
		{BootReasonKubeTransition, "BootReasonKubeTransition"},
		{BootReason(99), fmt.Sprintf("Unknown BootReason %d", 99)},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.br.String(), "br=%d", tc.br)
	}
}

// BootReason.StartWithSavedConfig

func TestBootReasonStartWithSavedConfig(t *testing.T) {
	// returns true
	for _, br := range []BootReason{
		BootReasonRebootCmd, BootReasonUpdate, BootReasonDisconnect,
		BootReasonKernel, BootReasonPowerFail, BootReasonUnknown,
		BootReasonPoweroffCmd, BootReasonKubeTransition,
	} {
		assert.True(t, br.StartWithSavedConfig(), "br=%s", br)
	}
	// returns false
	for _, br := range []BootReason{
		BootReasonNone, BootReasonFirst, BootReasonFallback,
		BootReasonFatal, BootReasonOOM, BootReasonWatchdogHung,
		BootReasonWatchdogPid, BootReasonVaultFailure, BootReason(99),
	} {
		assert.False(t, br.StartWithSavedConfig(), "br=%s", br)
	}
}

// DeviceState.String

func TestDeviceStateString(t *testing.T) {
	cases := []struct {
		ds   DeviceState
		want string
	}{
		{DEVICE_STATE_UNSPECIFIED, "unspecified"},
		{DEVICE_STATE_ONLINE, "online"},
		{DEVICE_STATE_REBOOTING, "rebooting"},
		{DEVICE_STATE_MAINTENANCE_MODE, "maintenance_mode"},
		{DEVICE_STATE_BASEOS_UPDATING, "baseos_updating"},
		{DEVICE_STATE_BOOTING, "booting"},
		{DEVICE_STATE_PREPARING_POWEROFF, "preparing_poweroff"},
		{DEVICE_STATE_POWERING_OFF, "powering_off"},
		{DEVICE_STATE_PREPARED_POWEROFF, "prepared_poweroff"},
		{DeviceState(99), fmt.Sprintf("Unknown state %d", 99)},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.ds.String(), "ds=%d", tc.ds)
	}
}

// RadioSilence.String

func TestRadioSilenceString(t *testing.T) {
	assert.Equal(t, "Radio transmitters OFF", RadioSilence{Imposed: true}.String())
	assert.Equal(t, "Radio transmitters ON", RadioSilence{Imposed: false}.String())
}

// LocalCommands.Empty

func TestLocalCommandsEmpty(t *testing.T) {
	lc := &LocalCommands{}
	assert.True(t, lc.Empty())

	lc.AppCommands = map[string]*LocalAppCommand{"app1": {}}
	assert.False(t, lc.Empty())
}

// DevCommand.String

func TestDevCommandString(t *testing.T) {
	cases := []struct {
		c    DevCommand
		want string
	}{
		{DevCommandUnspecified, "Unspecified"},
		{DevCommandShutdown, "Shutdown"},
		{DevCommandShutdownPoweroff, "Shutdown + Poweroff"},
		{DevCommandGracefulReboot, "Graceful Reboot"},
		{DevCommandCollectInfo, "Collect Info"},
		{DevCommand(99), "Unknown"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.c.String())
	}
}

func TestMaintenanceModeMultiReasonToProto(t *testing.T) {
	// nil/empty → nil result
	assert.Nil(t, MaintenanceModeMultiReason{}.ToProto())

	multi := MaintenanceModeMultiReason{
		MaintenanceModeReasonNone,
		MaintenanceModeReasonUserRequested,
	}
	got := multi.ToProto()
	assert.Len(t, got, 2)
	assert.Equal(t, info.MaintenanceModeReason(MaintenanceModeReasonNone), got[0])
	assert.Equal(t, info.MaintenanceModeReason(MaintenanceModeReasonUserRequested), got[1])
}

// BaseOsConfig / BaseOsStatus / DatastoreConfig / NodeAgentStatus / ZedAgentStatus Key / LogKey

func TestBaseOsConfigKey(t *testing.T) {
	cfg := BaseOsConfig{ContentTreeUUID: "tree-uuid-1", BaseOsVersion: "1.0"}
	assert.Equal(t, "tree-uuid-1", cfg.Key())
	assert.Contains(t, cfg.LogKey(), "1.0")
}

func TestBaseOsStatusKey(t *testing.T) {
	status := BaseOsStatus{ContentTreeUUID: "tree-uuid-2", BaseOsVersion: "2.0"}
	assert.Equal(t, "tree-uuid-2", status.Key())
	assert.Contains(t, status.LogKey(), "2.0")
}

func TestDatastoreConfigLogKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	cfg := DatastoreConfig{UUID: id}
	assert.Equal(t, id.String(), cfg.Key())
	assert.Contains(t, cfg.LogKey(), id.String())
}

func TestNodeAgentStatusLogKey(t *testing.T) {
	s := NodeAgentStatus{Name: "nodeagent"}
	assert.Equal(t, "nodeagent", s.Key())
	assert.Contains(t, s.LogKey(), "nodeagent")
}

func TestZedAgentStatusLogKey(t *testing.T) {
	s := ZedAgentStatus{Name: "zedagent"}
	assert.Equal(t, "zedagent", s.Key())
	assert.Contains(t, s.LogKey(), "zedagent")
}
