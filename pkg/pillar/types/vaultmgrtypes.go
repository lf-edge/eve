// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/lf-edge/eve-api/go/info"

	"github.com/google/go-cmp/cmp"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

// VaultUnlockMethod records how a vault was unlocked this boot, so an operator
// can tell a clean local TPM unseal apart from a controller-key recovery (both
// of which end with Status enabled).
type VaultUnlockMethod uint8

const (
	// VaultUnlockNone means the vault is not (yet) unlocked.
	VaultUnlockNone VaultUnlockMethod = iota
	// VaultUnlockTPMLocalSealed means the locally TPM-sealed key unsealed
	// against the current PCRs, with no controller involvement.
	VaultUnlockTPMLocalSealed
	// VaultUnlockControllerKey means the local unseal failed (e.g. a PCR policy
	// mismatch) and the controller-provided escrowed key was used instead.
	VaultUnlockControllerKey
	// VaultUnlockNoTPM means the platform has no TPM; the key is not sealed.
	VaultUnlockNoTPM
	// VaultUnlockRecreated means the local unseal failed and the controller had
	// no escrowed key to return, so the vault was wiped and recreated empty. No
	// key unlocked the existing vault; its prior contents were lost.
	VaultUnlockRecreated
)

// String implements fmt.Stringer.
func (m VaultUnlockMethod) String() string {
	switch m {
	case VaultUnlockTPMLocalSealed:
		return "tpm-local-sealed"
	case VaultUnlockControllerKey:
		return "controller-key"
	case VaultUnlockNoTPM:
		return "no-tpm"
	case VaultUnlockRecreated:
		return "recreated"
	default:
		return "none"
	}
}

// VaultStatus represents running status of a Vault
type VaultStatus struct {
	Name               string
	Status             info.DataSecAtRestStatus
	PCRStatus          info.PCRStatus
	ConversionComplete bool
	// only valid if TPM is enabled and Sealed key is used
	MismatchingPCRs []int
	// UnlockMethod records how the vault was unlocked this boot (local TPM key,
	// controller-provided key, no TPM, or a wipe-and-recreate). VaultUnlockNone
	// until unlocked. VaultUnlockTPMLocalSealed means the locally TPM-sealed key
	// unsealed on the first attempt; VaultUnlockControllerKey means the local
	// unseal failed and the device is relying on the controller-key fallback;
	// VaultUnlockRecreated means the local unseal failed with no escrowed key, so
	// the vault was wiped and recreated (prior contents lost).
	UnlockMethod VaultUnlockMethod
	// ErrorAndTime provides SetErrorNow() and ClearError()
	ErrorAndTime
}

// VaultConfig represents vault key to be used
type VaultConfig struct {
	TpmKeyOnly bool
}

// Key :
func (config VaultConfig) Key() string {
	return "global"
}

// Key returns the key used for indexing into a list of vaults
func (status VaultStatus) Key() string {
	return status.Name
}

// LogCreate :
func (status VaultStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.VaultStatusLogType, status.Name,
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("Vault status create")
}

// LogModify :
func (status VaultStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.VaultStatusLogType, status.Name,
		nilUUID, status.LogKey())

	oldStatus, ok := old.(VaultStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of VaultStatus type")
	}
	// XXX remove?
	logObject.CloneAndAddField("diff", cmp.Diff(oldStatus, status)).
		Noticef("Vault status modify")
	if status.HasError() {
		errAndTime := status.ErrorAndTime
		logObject.CloneAndAddField("error", errAndTime.Error).
			AddField("error-time", errAndTime.ErrorTime).
			Noticef("Vault status modify")
	}
}

// LogDelete :
func (status VaultStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.VaultStatusLogType, status.Name,
		nilUUID, status.LogKey())
	logObject.Noticef("Vault status delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey :
func (status VaultStatus) LogKey() string {
	return string(base.VaultStatusLogType) + "-" + status.Key()
}

// EncryptedVaultKeyFromDevice is published by vaultmgr towards Controller (through zedagent)
type EncryptedVaultKeyFromDevice struct {
	Name              string
	EncryptedVaultKey []byte // empty if no TPM enabled
	IsTpmEnabled      bool
}

// Key returns name of the vault corresponding to this object
// for now it is only the default vault i.e. "Application Volume Store"
func (key EncryptedVaultKeyFromDevice) Key() string {
	return key.Name
}

// LogCreate :
func (key EncryptedVaultKeyFromDevice) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.EncryptedVaultKeyFromDeviceLogType, key.Name,
		nilUUID, key.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("EncryptedVaultKeyFromDevice create")
}

// LogModify :
func (key EncryptedVaultKeyFromDevice) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.EncryptedVaultKeyFromDeviceLogType, key.Name,
		nilUUID, key.LogKey())

	_, ok := old.(EncryptedVaultKeyFromDevice)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of EncryptedVaultKeyFromDevice type")
	}
	logObject.Noticef("EncryptedVaultKeyFromDevice modify")
}

// LogDelete :
func (key EncryptedVaultKeyFromDevice) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.EncryptedVaultKeyFromDeviceLogType, key.Name,
		nilUUID, key.LogKey())
	logObject.Noticef("EncryptedVaultKeyFromDevice delete")

	base.DeleteLogObject(logBase, key.LogKey())
}

// LogKey :
func (key EncryptedVaultKeyFromDevice) LogKey() string {
	return string(base.EncryptedVaultKeyFromDeviceLogType) + "-" + key.Key()
}

// EncryptedVaultKeyFromController is published from Controller to vaultmgr (through zedagent)
type EncryptedVaultKeyFromController struct {
	Name              string
	EncryptedVaultKey []byte
	PolicyPcr         VaultKeyPolicyPCR
}

// VaultKeyPolicyPCR defines the PCR policy associated with a vault key,
// it is received from the controller along with the encrypted vault key.
type VaultKeyPolicyPCR struct {
	PolicyPresent bool
	Indexes       []int
	ID            int
}

const (
	// PolicyPCRRecoveredDefault indicate that the PCR policy was recovered using default PCRs.
	PolicyPCRRecoveredDefault = 0
	// PolicyPCRRecovered indicate that the PCR policy was recovered locally by vaultmgr.
	PolicyPCRRecovered = -1
)

// Key returns name of the vault corresponding to this object
// for now it is only the default vault i.e. "Application Volume Store"
func (key EncryptedVaultKeyFromController) Key() string {
	return key.Name
}

// LogCreate :
func (key EncryptedVaultKeyFromController) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.EncryptedVaultKeyFromControllerLogType, key.Name,
		nilUUID, key.LogKey())
	if logObject == nil {
		return
	}
	logObject.Noticef("EncryptedVaultKeyFromController create")
}

// LogModify :
func (key EncryptedVaultKeyFromController) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.EncryptedVaultKeyFromControllerLogType, key.Name,
		nilUUID, key.LogKey())

	_, ok := old.(EncryptedVaultKeyFromController)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of EncryptedVaultKeyFromController type")
	}
	logObject.Noticef("EncryptedVaultKeyFromController modify")
}

// LogDelete :
func (key EncryptedVaultKeyFromController) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.EncryptedVaultKeyFromControllerLogType, key.Name,
		nilUUID, key.LogKey())
	logObject.Noticef("EncryptedVaultKeyFromController delete")

	base.DeleteLogObject(logBase, key.LogKey())
}

// LogKey :
func (key EncryptedVaultKeyFromController) LogKey() string {
	return string(base.EncryptedVaultKeyFromControllerLogType) + "-" + key.Key()
}

// IsVaultInError :
func (status VaultStatus) IsVaultInError() bool {
	return (status.Status == info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR) && len(status.MismatchingPCRs) > 0
}
