// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// ZedAgentStatus reports device-level status from zedagent (controller
// connectivity, lifecycle state, attestation).
type ZedAgentStatus struct {
	ConfigStatus    ConfigGetStatus `json:"configStatus"`
	DeviceState     DeviceState     `json:"deviceState"`
	AttestState     AttestState     `json:"attestState"`
	AttestError     string          `json:"attestError"`
	BootReason      BootReason      `json:"bootReason"`
	RebootReason    string          `json:"rebootReason"`
	MaintenanceMode bool            `json:"maintenanceMode"`
}

// ConfigGetStatus is the outcome of the last controller config fetch.
type ConfigGetStatus string

// ConfigGetStatus enumerates the controller config-fetch outcomes.
const (
	ConfigGetStatusSuccess       ConfigGetStatus = "success"
	ConfigGetStatusFail          ConfigGetStatus = "fail"
	ConfigGetStatusTemporaryFail ConfigGetStatus = "temporaryFail"
	ConfigGetStatusReadSaved     ConfigGetStatus = "readSaved"
)

// DeviceState is the device lifecycle state.
type DeviceState string

// DeviceState enumerates the device lifecycle states.
const (
	DeviceStateUnspecified       DeviceState = "unspecified"
	DeviceStateOnline            DeviceState = "online"
	DeviceStateRebooting         DeviceState = "rebooting"
	DeviceStateMaintenanceMode   DeviceState = "maintenanceMode"
	DeviceStateBaseOsUpdating    DeviceState = "baseOsUpdating"
	DeviceStateBooting           DeviceState = "booting"
	DeviceStatePreparingPowerOff DeviceState = "preparingPowerOff"
	DeviceStatePoweringOff       DeviceState = "poweringOff"
	DeviceStatePreparedPowerOff  DeviceState = "preparedPowerOff"
)

// AttestState is the remote-attestation progress.
type AttestState string

// AttestState enumerates the attestation progress states.
const (
	AttestStateNone               AttestState = "none"
	AttestStateNonceWait          AttestState = "nonceWait"
	AttestStateInternalQuoteWait  AttestState = "internalQuoteWait"
	AttestStateInternalEscrowWait AttestState = "internalEscrowWait"
	AttestStateAttestWait         AttestState = "attestWait"
	AttestStateAttestEscrowWait   AttestState = "attestEscrowWait"
	AttestStateRestartWait        AttestState = "restartWait"
	AttestStateComplete           AttestState = "complete"
)

// BootReason is why the device last booted.
type BootReason string

// BootReason enumerates the reasons for the last boot.
const (
	BootReasonNone         BootReason = "none"
	BootReasonFirst        BootReason = "first"
	BootReasonRebootCmd    BootReason = "rebootCmd"
	BootReasonUpdate       BootReason = "update"
	BootReasonFallback     BootReason = "fallback"
	BootReasonDisconnect   BootReason = "disconnect"
	BootReasonFatal        BootReason = "fatal"
	BootReasonOom          BootReason = "oom"
	BootReasonWatchdogHung BootReason = "watchdogHung"
	BootReasonWatchdogPid  BootReason = "watchdogPid"
	BootReasonKernel       BootReason = "kernel"
	BootReasonPowerFail    BootReason = "powerFail"
	BootReasonUnknown      BootReason = "unknown"
	BootReasonVaultFailure BootReason = "vaultFailure"
	BootReasonPoweroffCmd  BootReason = "poweroffCmd"
	BootReasonParseFail    BootReason = "parseFail"
)
