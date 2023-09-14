// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	libzfs "github.com/bicomsystems/go-libzfs"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	"golang.org/x/sys/unix"
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
		if base.IsHVTypeKube() {
			if err := CreateZvolVault(h.log, types.SealedDataset, "", false); err != nil {
				return fmt.Errorf("error creating zfs vault %s, error=%v",
					types.SealedDataset, err)
			}
			return nil
		}
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
		etpm.CompareLegacyandSealedKey().String())
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
	if base.IsHVTypeKube() {
		if err := MountVaultZvol(h.log, vaultPath); err != nil {
			h.log.Errorf("Error unlocking vault: %v", err)
			return err
		}
	} else {
		if err := zfs.MountDataset(vaultPath); err != nil {
			h.log.Errorf("Error unlocking vault: %v", err)
			return err
		}
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

	if base.IsHVTypeKube() {
		if err := CreateZvolVault(h.log, vaultPath, zfsKeyFile, true); err != nil {
			h.log.Errorf("Error creating zfs vault %s, error=%v", vaultPath, err)
			return err
		}
	} else {
		if err := zfs.CreateVaultDataset(vaultPath, zfsKeyFile); err != nil {
			h.log.Errorf("Error creating zfs vault %s, error=%v", vaultPath, err)
			return err
		}
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

	if dataset.Type == libzfs.DatasetTypeFilesystem {
		mounted, err := dataset.GetProperty(libzfs.DatasetPropMounted)
		if err != nil {
			return fmt.Errorf("DatasetExist(%s): Get property PropMounted failed. %s",
				vaultPath, err.Error())
		}

		//Expect mounted:yes keystatus:available encryption:aes-256-gcm
		if mounted.Value != "yes" {
			return fmt.Errorf("DatasetExist(%s): Dataset is not mounted. value: %s",
				vaultPath, mounted.Value)
		}
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

// waitPath - Wait up to the requested number of seconds for path to exist or return error
func waitPath(log *base.LogObject, path string, seconds int64) error {
	begin_time := time.Now().Unix()
	for {
		_, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				log.Warnf("waitPath path:%s missing", path)
				time.Sleep(1 * time.Second)
			}
		} else {
			return nil
		}
		if (time.Now().Unix() - begin_time) > seconds {
			break
		}
	}
	return fmt.Errorf("waitPath path %s not found after %d seconds", path, seconds)
}

// MountVaultZvol Wrapper with wait for device
func MountVaultZvol(log *base.LogObject, datasetPath string) error {
	devPath := zfs.GetZvolPath(datasetPath)
	err := waitPath(log, devPath, vaultZvolPathWaitSeconds)
	if err != nil {
		return fmt.Errorf("Vault zvol dev path missing: %v", err)
	}

	_, err = os.Stat("/" + types.SealedDataset)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Mkdir("/"+types.SealedDataset, os.FileMode(755))
			if err != nil {
				return fmt.Errorf("MountVaultZvol path %s creation error: %v", "/"+types.SealedDataset, err)
			}
		}
	}

	err = unix.Mount(devPath, "/"+types.SealedDataset, vaultFsType, unix.MS_DIRSYNC|unix.MS_NOATIME, "")
	if err != nil {
		return fmt.Errorf("mount of %s to %s err:%v", devPath, "/"+types.SealedDataset, err)
	}
	return nil
}

// formatZvol apply an ext4 fs to the device path given
func formatZvol(log *base.LogObject, zvolDevPath string, fsType string) error {
	// Not enabling encryption...its already set on the zvol
	ctx := context.Background()
	args := []string{zvolDevPath}
	output, err := base.Exec(log, "/sbin/mkfs."+fsType, args...).WithContext(ctx).CombinedOutputWithCustomTimeout(3600)
	if err != nil {
		return fmt.Errorf("formatZvol dev:%s, stdout:%s, err:%v", zvolDevPath, output, err)
	}
	return nil
}

const vaultZvolPathWaitSeconds int64 = 20
const vaultFsType string = "ext4"

// CreateZvolVault Create and mount an empty vault dataset zvol
func CreateZvolVault(log *base.LogObject, datasetName string, zfsKeyFile string, encrypted bool) error {
	// Remaining space in the pool
	sizeBytes := uint64(0)

	parentDatasetName := datasetName
	if strings.Contains(parentDatasetName, "/") {
		datasetParts := strings.Split(parentDatasetName, "/")
		parentDatasetName = datasetParts[0]
	}

	sizeBytes, err := zfs.GetDatasetAvailableBytes(parentDatasetName)
	if err != nil {
		return fmt.Errorf("Dataset %s available bytes read error: %v", parentDatasetName, err)
	}

	err = zfs.CreateVaultVolumeDataset(log, datasetName, zfsKeyFile, encrypted, sizeBytes)
	if err != nil {
		return fmt.Errorf("Vault zvol creation error; %v", err)
	}

	devPath := zfs.GetZvolPath(types.SealedDataset)
	// Sometimes we wait for /dev path to the zvol to appear
	// Since this only occurs on first boot, we can afford to be patient
	if err = waitPath(log, devPath, vaultZvolPathWaitSeconds); err != nil {
		return fmt.Errorf("Vault zvol dev path missing: %v", err)
	}

	if err = formatZvol(log, devPath, vaultFsType); err != nil {
		return fmt.Errorf("Vault zvol format error: %v", err)
	}

	if err = MountVaultZvol(log, types.SealedDataset); err != nil {
		return fmt.Errorf("Vault zvol mount error: %v", err)
	}
	return nil
}
