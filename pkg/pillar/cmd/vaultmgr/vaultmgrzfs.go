// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vaultmgr

import (
	"net"
	"os"
	"path/filepath"
	"regexp"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/contrib/snapshotservice"
	zfsSnapshooter "github.com/containerd/zfs"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"google.golang.org/grpc"
)

const (
	defaultSecretDataset    = vault.DefaultZpool + "/vault"
	defaultCfgSecretDataset = vault.DefaultZpool + "/config"
	zfsKeyFile              = zfsKeyDir + "/protector.key"
	zfsKeyDir               = "/run/TmpVaultDir2"
	zfsSnapshotterSock      = "/run/" + types.ZFSSnapshotter + ".sock"
)

func getCreateParams(vaultPath string, encrypted bool) []string {
	if encrypted {
		return []string{"/hostfs", "zfs", "create", "-o", "encryption=aes-256-gcm", "-o", "keylocation=file://" + zfsKeyFile, "-o", "keyformat=raw", vaultPath}
	}
	return []string{"/hostfs", "zfs", "create", vaultPath}
}

func getLoadKeyParams(vaultPath string) []string {
	args := []string{"/hostfs", "zfs", "load-key", vaultPath}
	return args
}

func getMountParams(vaultPath string) []string {
	args := []string{"/hostfs", "zfs", "mount", vaultPath}
	return args
}

func getKeyStatusParams(vaultPath string) []string {
	args := []string{"/hostfs", "zfs", "get", "keystatus", vaultPath}
	return args
}

//e.g. zfs load-key persist/vault followed by
//zfs mount persist/vault
func unlockZfsVault(vaultPath string) error {
	//prepare key in the staging file
	//we never unlock a deprecated vault in ZFS (we never created those)
	//cloudKeyOnlyMode=false, useSealedKey=true
	if err := stageKey(false, true, zfsKeyDir, zfsKeyFile); err != nil {
		return err
	}
	defer unstageKey(zfsKeyDir, zfsKeyFile)

	//zfs load-key
	args := getLoadKeyParams(vaultPath)
	if stdOut, stdErr, err := execCmd(vault.ZfsPath, args...); err != nil {
		log.Errorf("Error loading key for vault: %v, %s, %s",
			err, stdOut, stdErr)
		return err
	}
	//zfs mount
	args = getMountParams(vaultPath)
	if stdOut, stdErr, err := execCmd(vault.ZfsPath, args...); err != nil {
		log.Errorf("Error unlocking vault: %v, %s, %s", err, stdOut, stdErr)
		return err
	}
	return nil
}

//e.g. zfs create -o encryption=aes-256-gcm -o keylocation=file://tmp/raw.key -o keyformat=raw perist/vault
func createZfsVault(vaultPath string) error {
	//prepare key in the staging file
	//we never create deprecated vault on ZFS
	//cloudKeyOnlyMode=false, useSealedKey=true
	if err := stageKey(false, true, zfsKeyDir, zfsKeyFile); err != nil {
		return err
	}
	defer unstageKey(zfsKeyDir, zfsKeyFile)
	args := getCreateParams(vaultPath, true)
	if stdOut, stdErr, err := execCmd(vault.ZfsPath, args...); err != nil {
		log.Errorf("Error creating zfs vault %s, error=%v, %s, %s",
			vaultPath, err, stdOut, stdErr)
		return err
	}
	log.Functionf("Created new vault %s", vaultPath)
	return nil
}

//e.g. zfs get keystatus persist/vault
func checkKeyStatus(vaultPath string) error {
	args := getKeyStatusParams(vaultPath)
	if stdOut, stdErr, err := execCmd(vault.ZfsPath, args...); err != nil {
		log.Tracef("keystatus query for %s results in error=%v, %s, %s",
			vaultPath, err, stdOut, stdErr)
		return err
	}
	return nil
}

func processOperStatus(status string) string {
	//Expect mounted:yes keystatus:available encryption:aes-256-gcm
	matchConditions := []struct {
		regexStr string //match this
		errStr   string //if no match, this is the error to show
	}{
		{"keystatus\\s+available\\s", "Key is not loaded"},
		{"mounted\\s+yes\\s", "Dataset is not mounted"},
		{"encryption\\s+aes-256-gcm\\s", "Encryption is not enabled"},
	}

	for _, match := range matchConditions {
		pattern := regexp.MustCompile(match.regexStr)
		if !pattern.MatchString(status) {
			return match.errStr
		}
	}
	return ""
}

func setupZfsVault(vaultPath string) error {
	//zfs get keystatus returns success as long as vaultPath is a dataset,
	//(even if not mounted yet), so use it to check dataset presence
	if err := checkKeyStatus(vaultPath); err == nil {
		//present, call unlock
		return unlockZfsVault(vaultPath)
	}
	//try creating the dataset
	return createZfsVault(vaultPath)
}

// eveZFSSnapshotterInit initializes containerd snapshotter eve.zfs.snapshotter
// we cannot use default one because of no mount of persist/vault dataset on boot if encrypted
// we use proxy plugin and start it here after defaultVault is mounted
func eveZFSSnapshotterInit() error {
	dirToSaveMetadata := filepath.Join(defaultVault, types.ZFSSnapshotter)
	err := os.MkdirAll(dirToSaveMetadata, os.ModeDir)
	if err != nil {
		return err
	}
	//it makes lookup internally for mount point of provided path
	sn, err := zfsSnapshooter.NewSnapshotter(dirToSaveMetadata)
	if err != nil {
		return err
	}
	service := snapshotservice.FromSnapshotter(sn)
	rpc := grpc.NewServer()
	snapshotsapi.RegisterSnapshotsServer(rpc, service)
	l, err := net.Listen("unix", zfsSnapshotterSock)
	if err != nil {
		return err
	}
	go func() {
		if err := rpc.Serve(l); err != nil {
			log.Fatalf("eveZFSSnapshotterInit Serve error: %v\n", err)
		}
	}()
	return nil
}
