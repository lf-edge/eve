// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"fmt"

	libzfs "github.com/bicomsystems/go-libzfs"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

const (
	zfsKeyDir  = "/run/TmpVaultDir2"
	zfsKeyFile = zfsKeyDir + "/protector.key"
)

// ZFSHandler handles vault operations with ZFS
type ZFSHandler struct {
	log     *base.LogObject
	options HandlerOptions
}

// GetOperationalInfo returns status of encryption and string with information
func (h *ZFSHandler) GetOperationalInfo() (info.DataSecAtRestStatus, string) {
	if !etpm.IsTpmEnabled() {
		// No encryption on platforms without a (working) TPM
		h.log.Trace("Setting status to disabled, TPM is not in use")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
			"TPM is either absent or not in use"
	}
	// Check if default zpool (i.e. "persist" dataset) is setup
	if !zfs.DatasetExist(h.log, types.PersistDataset) {
		h.log.Errorf("default ZFS zpool is not setup")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
			"Default ZFS zpool is not setup"
	}
	return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		"ZFS Encryption is enabled for vaults"
}

// SetupDeprecatedVaults is dummy for ZFSHandler
func (h *ZFSHandler) SetupDeprecatedVaults() error {
	return nil
}

// SetHandlerOptions adjust handler options
func (h *ZFSHandler) SetHandlerOptions(options HandlerOptions) {
	h.options = options
}

// GetVaultStatuses returns statuses of vault(s)
func (h *ZFSHandler) GetVaultStatuses() []*types.VaultStatus {
	return []*types.VaultStatus{h.getVaultStatus(types.DefaultVaultName, types.SealedDataset)}
}

// UnlockDefaultVault e.g. zfs load-key persist/vault followed by
// zfs mount persist/vault
func (h *ZFSHandler) UnlockDefaultVault() error {
	return h.unlockVault(types.SealedDataset)
}

// RemoveDefaultVault removes vault from zfs
// e.g. zfs destroy -fr persist/vault
func (h *ZFSHandler) RemoveDefaultVault() error {
	if err := zfs.UnmountDataset(types.SealedDataset); err != nil {
		h.log.Errorf("Error unmounting vault %s, error=%v", types.SealedDataset, err)
		return err
	}

	if err := zfs.DestroyDataset(types.SealedDataset); err != nil {
		h.log.Errorf("Error destroying vault %s, error=%v", types.SealedDataset, err)
		return err
	}

	return nil
}

// SetupDefaultVault setups vaults on zfs, using zfs native encryption support
func (h *ZFSHandler) SetupDefaultVault() error {
	if !etpm.IsTpmEnabled() {
		if zfs.DatasetExist(h.log, types.SealedDataset) {
			return nil
		}
		if err := zfs.CreateDataset(types.SealedDataset); err != nil {
			return fmt.Errorf("error creating zfs vault %s, error=%v",
				types.SealedDataset, err)
		}
		return nil
	}

	if err := h.setupVault(types.SealedDataset); err != nil {
		return fmt.Errorf("error in setting up ZFS vault %s:%v", types.SealedDataset, err)
	}
	// Log the type of key used for unlocking default vault
	h.log.Noticef("default zfs vault unlocked using key type: %s",
		etpm.CompareLegacyandSealedKey(h.log).String())
	return nil
}

func (h *ZFSHandler) unlockVault(vaultPath string) error {
	// prepare key in the staging file
	// we never unlock a deprecated vault in ZFS (we never created those)
	// cloudKeyOnlyMode=false, useSealedKey=true
	unstage, err := stageKey(h.log, false, true, h.options.TpmKeyOnlyMode, zfsKeyDir, zfsKeyFile)
	if err != nil {
		return err
	}
	defer unstage()

	// zfs load-key
	args := []string{"load-key", vaultPath}
	if stdOut, stdErr, err := execCmd(types.ZFSBinary, args...); err != nil {
		h.log.Errorf("Error loading key for vault: %v, %s, %s",
			err, stdOut, stdErr)
		return err
	}

	// zfs mount
	if err := zfs.MountDataset(vaultPath); err != nil {
		h.log.Errorf("Error unlocking vault: %v", err)
		return err
	}

	return nil
}

// e.g. zfs create -o encryption=aes-256-gcm -o keylocation=file://tmp/raw.key -o keyformat=raw persist/vault
func (h *ZFSHandler) createVault(vaultPath string) error {
	// prepare key in the staging file
	// we never create deprecated vault on ZFS
	// cloudKeyOnlyMode=false, useSealedKey=true
	unstage, err := stageKey(h.log, false, true, h.options.TpmKeyOnlyMode, zfsKeyDir, zfsKeyFile)
	if err != nil {
		return err
	}
	defer unstage()

	if err := zfs.CreateVaultDataset(vaultPath, zfsKeyFile); err != nil {
		h.log.Errorf("Error creating zfs vault %s, error=%v", vaultPath, err)
		return err
	}

	h.log.Functionf("Created new vault %s", vaultPath)
	return nil
}

// e.g. zfs get keystatus persist/vault
func (h *ZFSHandler) checkZfsKeyStatus(vaultPath string) error {
	if _, err := zfs.GetDatasetKeyStatus(vaultPath); err != nil {
		h.log.Tracef("keystatus query for %s results in error=%v",
			vaultPath, err)
		return err
	}

	return nil
}

func (h *ZFSHandler) setupVault(vaultPath string) error {
	// zfs get keystatus returns success as long as vaultPath is a dataset,
	// (even if not mounted yet), so use it to check dataset presence
	if err := h.checkZfsKeyStatus(vaultPath); err == nil {
		//present, call unlock
		return h.unlockVault(vaultPath)
	}
	// If it does not exist then the mount presumbly does not exist either but
	// double check.
	if !isDirEmpty(h.log, vaultPath) {
		h.log.Noticef("Not disturbing non-empty vault(%s)",
			vaultPath)
	} else {
		h.log.Warnf("Clear saved keys for empty vault(%s)",
			vaultPath)
		if err := etpm.WipeOutStaleSealedKeyIfAny(); err != nil {
			h.log.Errorf("WipeOutStaleSealKeyIfAny failed: %s", err)
		}
	}
	// try creating the dataset
	return h.createVault(vaultPath)
}

func (h *ZFSHandler) getVaultStatus(vaultName, vaultPath string) *types.VaultStatus {
	status := types.VaultStatus{}
	status.Name = vaultName

	if etpm.PCRBankSHA256Enabled() {
		status.PCRStatus = info.PCRStatus_PCR_ENABLED
	} else {
		status.PCRStatus = info.PCRStatus_PCR_DISABLED
	}

	zfsEncryptStatus, zfsEncryptError := h.GetOperationalInfo()
	if zfsEncryptStatus != info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED {
		status.Status = zfsEncryptStatus
		status.SetErrorDescription(types.ErrorDescription{Error: zfsEncryptError})
	} else {
		if err := h.checkOperationalStatus(vaultPath); err != nil {
			h.log.Errorf("Status failed, %s", err)
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
			status.SetErrorDescription(types.ErrorDescription{Error: err.Error()})
		} else {
			h.log.Functionf("checkOperStatus returns ok for %s", vaultPath)
			status.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED
		}
	}
	return &status
}

// checkOperationalStatus returns nil if for vaultPath properties
// for in ZFS have the following values:
// mounted:yes keystatus:available encryption:aes-256-gcm;
// else return err
func (h *ZFSHandler) checkOperationalStatus(vaultPath string) error {
	dataset, err := libzfs.DatasetOpen(vaultPath)
	if err != nil {
		return err
	}
	defer dataset.Close()

	mounted, err := dataset.GetProperty(libzfs.DatasetPropMounted)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property PropMounted failed. %s",
			vaultPath, err.Error())
	}

	encryption, err := dataset.GetProperty(libzfs.DatasetPropEncryption)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property Encryption failed. %s",
			vaultPath, err.Error())

	}

	// This property is not available for a dataset if no options associated
	// with the key were specified during it's creation.
	keyStatus, err := dataset.GetProperty(libzfs.DatasetPropKeyStatus)
	if err != nil {
		return fmt.Errorf("DatasetExist(%s): Get property KeyStatus failed. %s",
			vaultPath, err.Error())

	}

	//Expect mounted:yes keystatus:available encryption:aes-256-gcm
	if mounted.Value != "yes" {
		return fmt.Errorf("DatasetExist(%s): Dataset is not mounted. value: %s",
			vaultPath, mounted.Value)
	}

	if keyStatus.Value != "available" {
		return fmt.Errorf("DatasetExist(%s): Key is not loaded. value: %s",
			vaultPath, keyStatus.Value)
	}

	if encryption.Value != "aes-256-gcm" {
		return fmt.Errorf("DatasetExist(%s): Encryption is not enabled. value: %s",
			vaultPath, encryption.Value)
	}

	return nil
}
