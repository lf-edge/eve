// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

const (
	defaultSecretDataset    = vault.DefaultZpool + "/vault"
	defaultCfgSecretDataset = vault.DefaultZpool + "/config"
	zfsKeyFile              = zfsKeyDir + "/protector.key"
	zfsKeyDir               = "/run/TmpVaultDir2"
)

// e.g. zfs load-key persist/vault followed by
// zfs mount persist/vault
func unlockZfsVault(vaultPath string) error {
	// prepare key in the staging file
	// we never unlock a deprecated vault in ZFS (we never created those)
	// cloudKeyOnlyMode=false, useSealedKey=true
	if err := stageKey(false, true, zfsKeyDir, zfsKeyFile); err != nil {
		return err
	}
	defer unstageKey(zfsKeyDir, zfsKeyFile)

	// zfs load-key
	args := []string{"load-key", vaultPath}
	if stdOut, stdErr, err := execCmd(types.ZFSBinary, args...); err != nil {
		log.Errorf("Error loading key for vault: %v, %s, %s",
			err, stdOut, stdErr)
		return err
	}

	// zfs mount
	if err := zfs.MountDataset(vaultPath); err != nil {
		log.Errorf("Error unlocking vault: %v", err)
		return err
	}

	return nil
}

// e.g. zfs create -o encryption=aes-256-gcm -o keylocation=file://tmp/raw.key -o keyformat=raw persist/vault
func createZfsVault(vaultPath string) error {
	// prepare key in the staging file
	// we never create deprecated vault on ZFS
	// cloudKeyOnlyMode=false, useSealedKey=true
	if err := stageKey(false, true, zfsKeyDir, zfsKeyFile); err != nil {
		return err
	}
	defer unstageKey(zfsKeyDir, zfsKeyFile)

	if err := zfs.CreateVaultDataset(vaultPath, zfsKeyFile); err != nil {
		log.Errorf("Error creating zfs vault %s, error=%v", vaultPath, err)
		return err
	}

	log.Functionf("Created new vault %s", vaultPath)
	return nil
}

// remove vault from zfs
// e.g. zfs destroy -fr persist/vault
func removeDefaultVaultOnZfs() error {
	if err := zfs.UnmountDataset(defaultSecretDataset); err != nil {
		log.Errorf("Error unmounting vault %s, error=%v", defaultSecretDataset, err)
		return err
	}

	if err := zfs.DestroyDataset(defaultSecretDataset); err != nil {
		log.Errorf("Error destroying vault %s, error=%v", defaultSecretDataset, err)
		return err
	}

	return nil
}

// e.g. zfs get keystatus persist/vault
func checkKeyStatus(vaultPath string) error {
	if _, err := zfs.GetDatasetKeyStatus(vaultPath); err != nil {
		log.Tracef("keystatus query for %s results in error=%v",
			vaultPath, err)
		return err
	}

	return nil
}

func setupZfsVault(vaultPath string) error {
	// zfs get keystatus returns success as long as vaultPath is a dataset,
	// (even if not mounted yet), so use it to check dataset presence
	if err := checkKeyStatus(vaultPath); err == nil {
		//present, call unlock
		return unlockZfsVault(vaultPath)
	}
	// If it does not exist then the mount presumbly does not exist either but
	// double check.
	if !isDirEmpty(vaultPath) {
		log.Noticef("Not disturbing non-empty vault(%s)",
			vaultPath)
	} else {
		log.Warnf("Clear saved keys for empty vault(%s)",
			vaultPath)
		if err := etpm.WipeOutStaleSealedKeyIfAny(); err != nil {
			log.Errorf("WipteOutStaleSealKeyIfAny failed: %s", err)
		}
	}
	// try creating the dataset
	return createZfsVault(vaultPath)
}
