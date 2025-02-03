// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package ppi provides a way of interacting with the TCG PC Client Physical Presence Interface
*/
package ppi

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/canonical/go-tpm2"
)

var (
	// ErrOperationUnsupported indicates that the requested physical presence
	// operation is unsupported.
	ErrOperationUnsupported = errors.New("the requested PPI operation is unsupported")

	// ErrOperationFailed indicates that the requested physical presence
	// operation request failed.
	ErrOperationFailed = errors.New("the PPI operation request failed")
)

type OperationError uint64

func (e OperationError) Error() string {
	switch {
	case e == 0xfffffff0:
		return "user abort"
	case e == 0xfffffff1:
		return "BIOS failure"
	case e > 0 && e < 0x1000:
		return fmt.Sprintf("TPM error: %#x", e)
	case e == 0:
		return "success"
	default:
		return fmt.Sprintf("%#x", e)
	}
}

// OperationId corresponds to a physical presence operation.
type OperationId uint64

const (
	// OperationEnableTPM corresponds to the Enable operation.
	OperationEnableTPM OperationId = 1

	// OperationDisableTPM corresponds to the Enable operation.
	OperationDisableTPM OperationId = 2

	// OperationClearTPM corresponds to the Clear operation.
	OperationClearTPM OperationId = 5

	// OperationEnableAndClearTPM corresponds to the Enable + Clear operation for TPM2 devices, or
	// the Clear + Enable + Activate operation for TPM1.2 devices.
	OperationEnableAndClearTPM OperationId = 14

	// OperationSetPPRequiredForClearTPM corresponds to the SetPPRequiredForClear_True operation
	// for TPM2 devices, or the SetNoPPIClear_False for TPM1.2 devices.
	OperationSetPPRequiredForClearTPM OperationId = 17

	// OperationClearPPRequiredForClearTPM corresponds to the SetPPRequiredForClear_False
	// operation for TPM2 devices, or the SetNoPPIClear_True for TPM1.2 devices.
	OperationClearPPRequiredForClearTPM OperationId = 18

	// OperationSetPCRBanks corresponds to the SetPCRBanks operation for TPM2 devices.
	OperationSetPCRBanks OperationId = 23

	// OperationChangeEPS corresponds to the ChangeEPS operation for TPM2 devices.
	OperationChangeEPS OperationId = 24

	// OperationClearPPRequiredForChangePCRs corresponds to the SetPPRequiredForChangePCRs_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForChangePCRs OperationId = 25

	// OperationSetPPRequiredForChangePCRs corresponds to the SetPPRequiredForChangePCRs_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForChangePCRs OperationId = 26

	// OperationClearPPRequiredForEnableTPM corresponds to the SetPPRequiredForTurnOn_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForEnableTPM OperationId = 27

	// OperationSetPPRequiredForEnableTPM corresponds to the SetPPRequiredForTurnOn_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForEnableTPM OperationId = 28

	// OperationClearPPRequiredForDisableTPM corresponds to the SetPPRequiredForTurnOff_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForDisableTPM OperationId = 29

	// OperationSetPPRequiredForDisableTPM corresponds to the SetPPRequiredForTurnOff_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForDisableTPM OperationId = 30

	// OperationClearPPRequiredForChangeEPS corresponds to the SetPPRequiredForChangeEPS_False
	// operation for TPM2 devices.
	OperationClearPPRequiredForChangeEPS OperationId = 31

	// OperationSetPPRequiredForChangeEPS corresponds to the SetPPRequiredForChangeEPS_True
	// operation for TPM2 devices.
	OperationSetPPRequiredForChangeEPS OperationId = 32

	//OperationLogAllDigests                                           = 33
	//OperationDisableEndorsementEnableStorageHierarchy                = 34
	//OperationEnableBlockSIDFunc                                      = 96
	//OperationDisableBlockSIDFunc                                     = 97
	//OperationSetPPRequiredForEnableBlockSIDFuncTrue                  = 98
	//OperationSetPPRequiredForEnableBlockSIDFuncFalse                 = 99
	//OperationSetPPRequiredForDisableBlockSIDFuncTrue                 = 100
	//OperationSetPPRequiredForDisableBlockSIDFuncFalse                = 101
)

type ppControl struct {
	enable  OperationId
	disable OperationId
}

var ppControlMap = map[OperationId]ppControl{
	OperationEnableTPM: ppControl{
		enable:  OperationSetPPRequiredForEnableTPM,
		disable: OperationClearPPRequiredForEnableTPM},
	OperationDisableTPM: ppControl{
		enable:  OperationSetPPRequiredForDisableTPM,
		disable: OperationClearPPRequiredForDisableTPM},
	OperationClearTPM: ppControl{
		enable:  OperationSetPPRequiredForClearTPM,
		disable: OperationClearPPRequiredForClearTPM},
	OperationSetPCRBanks: ppControl{
		enable:  OperationSetPPRequiredForChangePCRs,
		disable: OperationClearPPRequiredForChangePCRs},
	OperationChangeEPS: ppControl{
		enable:  OperationSetPPRequiredForChangeEPS,
		disable: OperationClearPPRequiredForChangeEPS}}

// OperationStatus indicates the status of a physical presence operation.
type OperationStatus uint64

func (s OperationStatus) String() string {
	switch s {
	case OperationNotImplemented:
		return "Not implemented"
	case OperationFirmwareOnly:
		return "BIOS only"
	case OperationBlockedByFirmwareConfig:
		return "Blocked for OS by BIOS"
	case OperationPPRequired:
		return "User required"
	case OperationPPNotRequired:
		return "User not required"
	default:
		return "invalid operation status: " + strconv.Itoa(int(s))
	}
}

const (
	// OperationNotImplemented indicates that an operation is not implemented.
	OperationNotImplemented OperationStatus = 0

	// OperationFirmwareOnly indicates that an operation is supported but it
	// cannot be requested from the OS.
	OperationFirmwareOnly OperationStatus = 1

	// OperationBlockedByFirmwareConfig indicates that an operation is supported
	// but it cannot be requested from the OS because the current firmware settings
	// don't permit this.
	OperationBlockedByFirmwareConfig OperationStatus = 2

	// OperationPPRequired indicates that an operation can be requested from the
	// OS but the operation requires approval from a physically present user.
	OperationPPRequired OperationStatus = 3

	// OperationPPNotRequired indicates that an operation can be requested from
	// the OS without approval from a physically present user.
	OperationPPNotRequired OperationStatus = 4
)

// StateTransitionAction describes the action required to transition to the pre-OS
// environment in order for the pending physical presence operation request to be executed.
type StateTransitionAction uint64

func (a StateTransitionAction) String() string {
	switch a {
	case StateTransitionNoAction:
		return "None"
	case StateTransitionShutdownRequired:
		return "Shutdown"
	case StateTransitionRebootRequired:
		return "Reboot"
	case StateTransitionActionOSVendorSpecific:
		return "OS Vendor-specific"
	default:
		return "invalid state transition action: " + strconv.Itoa(int(a))
	}
}

const (
	// StateTransitionNoAction indicates that no action is required.
	StateTransitionNoAction StateTransitionAction = 0

	// StateTransitionShutdownRequired indicates that the OS must shut down
	// the machine in order to execute a pending operation.
	StateTransitionShutdownRequired StateTransitionAction = 1

	// StateTransitionRebootRequired indicates that the OS must perform a warm
	// reboot of the machine in order to execute a pending operation.
	StateTransitionRebootRequired StateTransitionAction = 2

	// StateTransitionActionOSVendorSpecific indicates that an OS-specific
	// action can take place.
	StateTransitionActionOSVendorSpecific StateTransitionAction = 3
)

// Version indicates the version of the physical presence interface.
type Version int

func (v Version) String() string {
	switch v {
	case Version10:
		return "1.0"
	case Version11:
		return "1.1"
	case Version12:
		return "1.2"
	case Version13:
		return "1.3"
	default:
		return "invalid version"
	}
}

const (
	VersionInvalid Version = iota
	Version10              // 1.0
	Version11              // 1.1
	Version12              // 1.2
	Version13              // 1.3
)

// OperationResponse provides the response of the last operation executed by the pre-OS
// environment.
type OperationResponse struct {
	Operation OperationId
	Err       error // Will be set if the operation failed.
}

type hashAlgorithms uint64

const (
	hashAlgorithmSHA1 hashAlgorithms = 1 << iota
	hashAlgorithmSHA256
	hashAlgorithmSHA384
	hashAlgorithmSHA512
	hashAlgorithmSM3_256
	hashAlgorithmSHA3_256
	hashAlgorithmSHA3_384
	hashAlgorithmSHA3_512
)

type PPIBackend interface {
	Version() string
	SubmitOperation(op OperationId, arg *uint64) error
	StateTransitionAction() StateTransitionAction
	OperationStatus(op OperationId) OperationStatus
	OperationResponse() (*OperationResponse, error)
}

// PPI provides a way to interact with the physical presence interface associated with a TPM.
type PPI struct {
	functions PPIBackend
}

func NewPPI(functions PPIBackend) *PPI {
	return &PPI{functions: functions}
}

func (p *PPI) submitOperation(op OperationId) error {
	return p.functions.SubmitOperation(op, nil)
}

func (p *PPI) Version() Version {
	version := p.functions.Version()
	switch version {
	case "1.0":
		return Version10
	case "1.1":
		return Version11
	case "1.2":
		return Version12
	case "1.3":
		return Version13
	default:
		return VersionInvalid
	}
}

// StateTransitionAction returns the action required to transition the device to the pre-OS
// environment in order to complete the pending physical presence operation request.
func (p *PPI) StateTransitionAction() StateTransitionAction {
	return p.functions.StateTransitionAction()
}

// OperationStatus returns the status of the specified operation.
func (p *PPI) OperationStatus(op OperationId) OperationStatus {
	return p.functions.OperationStatus(op)
}

// EnableTPM requests that the TPM be enabled by the platform firmware.
// For TPM1.2 devices, the TPM is enabled by executing the TPM_PhysicalEnable command.
// For TPM2 devices, the TPM is enabled by not disabling the storage and endorsement hierarchies
// with TPM2_HierarchyControl after TPM2_Startup.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) EnableTPM() error {
	return p.submitOperation(OperationEnableTPM)
}

// DisableTPM requests that the TPM be disabled by the platform firmware.
// For TPM1.2 devices, the TPM is disabled by executing the TPM_PhysicalDisable command.
// For TPM2 devices, the TPM is disabled by disabling the storage and endorsement hierarchies
// with TPM2_HierarchyControl after TPM2_Startup.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) DisableTPM() error {
	return p.submitOperation(OperationDisableTPM)
}

// ClearTPM requests that the TPM is cleared by the platform firmware.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) ClearTPM() error {
	return p.submitOperation(OperationClearTPM)
}

// EnableAndClearTPM requests that the TPM is enabled and cleared by the platform firmware.
// For TPM1.2 devices, this also activates the device with the TPM_PhysicalSetDeactivated
// command.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) EnableAndClearTPM() error {
	return p.submitOperation(OperationEnableAndClearTPM)
}

// SetPCRBanks requests that the PCR banks associated with the specified algorithms are enabled
// by the platform firmware.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) SetPCRBanks(algs ...tpm2.HashAlgorithmId) error {
	var bits hashAlgorithms
	for _, alg := range algs {
		switch alg {
		case tpm2.HashAlgorithmSHA1:
			bits |= hashAlgorithmSHA1
		case tpm2.HashAlgorithmSHA256:
			bits |= hashAlgorithmSHA256
		case tpm2.HashAlgorithmSHA384:
			bits |= hashAlgorithmSHA384
		case tpm2.HashAlgorithmSHA512:
			bits |= hashAlgorithmSHA512
		case tpm2.HashAlgorithmSHA3_256:
			bits |= hashAlgorithmSHA3_256
		case tpm2.HashAlgorithmSHA3_384:
			bits |= hashAlgorithmSHA3_384
		case tpm2.HashAlgorithmSHA3_512:
			bits |= hashAlgorithmSHA3_512
		}
	}
	return p.functions.SubmitOperation(OperationSetPCRBanks, (*uint64)(&bits))
}

// ChangeEPS requests that the TPM's endorsement primary seed is changed by the platform firmware.
// This is only implemented for TPM2 devices.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) ChangeEPS() error {
	return p.submitOperation(OperationChangeEPS)
}

// SetPPRequiredForOperation requests that approval from a physically present user should be
// required for the specified operation.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) SetPPRequiredForOperation(op OperationId) error {
	control, exists := ppControlMap[op]
	if !exists {
		return errors.New("invalid operation")
	}
	return p.submitOperation(control.enable)
}

// SetPPRequiredForOperation requests that approval from a physically present user should not be
// required for the specified operation.
// The caller needs to perform the action described by [PPI.StateTransitionAction] in
// order to complete the request.
func (p *PPI) ClearPPRequiredForOperation(op OperationId) error {
	control, exists := ppControlMap[op]
	if !exists {
		return errors.New("invalid operation")
	}
	return p.submitOperation(control.disable)
}

// OperationResponse returns the response to the previously executed operation from the pre-OS
// environment.
func (p *PPI) OperationResponse() (*OperationResponse, error) {
	return p.functions.OperationResponse()
}
