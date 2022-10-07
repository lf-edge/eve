// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

const (
	// FscryptConfFile is where we keep config
	FscryptConfFile = "/etc/fscrypt.conf"

	// FscryptPath is the fscrypt binary
	FscryptPath = "/opt/zededa/bin/fscrypt"

	// MountPoint is the root of all vaults
	MountPoint = types.PersistDir

	// DefaultZpool is used by zfs
	DefaultZpool = "persist"

	evePersistTypeFile = "/run/eve.persist_type"

	// allowVaultCleanFile existence indicates that we want to recreate vault in case of no controller key
	// we set it in installer and storage-init
	// so path must be aligned
	allowVaultCleanFile = types.PersistStatusDir + "/allow-vault-clean"
)

var (
	// StatusParams is used by fscrypt
	StatusParams = []string{"status", MountPoint}
)

// getFscryptOperInfo returns operational status of fscrypt encryption
func getFscryptOperInfo(log *base.LogObject) (info.DataSecAtRestStatus, string) {
	_, err := os.Stat(FscryptConfFile)
	if err == nil {
		if _, _, err := execCmd(FscryptPath, StatusParams...); err != nil {
			// fscrypt is setup, but not being used
			log.Trace("Setting status to Error")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
				"Fscrypt Encryption is not setup"
		} else {
			// fscrypt is setup, and being used on /persist
			log.Trace("Setting status to Enabled")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
				"Fscrypt is enabled and active"
		}
	} else {
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
			"Fscrypt is not enabled"

	}
}

// getZfsOperInfo returns operational status of ZFS encryption
func getZfsOperInfo(log *base.LogObject) (info.DataSecAtRestStatus, string) {
	// Check if default zpool (i.e. "persist" dataset) is setup
	if !zfs.DatasetExist(log, DefaultZpool) {
		log.Errorf("default ZFS zpool is not setup")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
			"Default ZFS zpool is not setup"
	}
	return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		"ZFS Encryption is enabled for vaults"
}

// GetOperInfo gets the current operational state of encryption tool
func GetOperInfo(log *base.LogObject) (info.DataSecAtRestStatus, string) {
	if !etpm.IsTpmEnabled() {
		// No encryption on platforms without a (working) TPM
		log.Trace("Setting status to disabled, TPM is not in use")
		return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
			"TPM is either absent or not in use"
	}
	persistFsType := ReadPersistType()
	switch persistFsType {
	case types.PersistExt4:
		return getFscryptOperInfo(log)
	case types.PersistZFS:
		return getZfsOperInfo(log)
	default:
		log.Tracef("Unsupported filesystem (%s), setting status to disabled",
			persistFsType)
		return info.DataSecAtRestStatus_DATASEC_AT_REST_DISABLED,
			"Current filesystem does not support encryption"
	}
}

func execCmd(command string, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(command, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	stdoutStr, stderrStr := stdout.String(), stderr.String()
	return stdoutStr, stderrStr, err
}

// ReadPersistType returns the persist filesystem
func ReadPersistType() types.PersistType {
	persistFsType := ""
	pBytes, err := ioutil.ReadFile(evePersistTypeFile)
	if err == nil {
		persistFsType = strings.TrimSpace(string(pBytes))
	}
	return types.ParsePersistType(persistFsType)
}

// DisallowVaultCleanup do not allow vault cleanup
func DisallowVaultCleanup() error {
	if _, err := os.Stat(allowVaultCleanFile); os.IsNotExist(err) {
		return nil
	}
	// remove file to indicate that we do not allow to clean vault
	if err := os.RemoveAll(allowVaultCleanFile); err != nil {
		return fmt.Errorf("cannot remove allowVaultCleanFile: %w", err)
	}
	return utils.DirSync(filepath.Dir(allowVaultCleanFile))
}

// IsVaultCleanupAllowed returns true if vault cleanup allowed
func IsVaultCleanupAllowed() bool {
	if _, err := os.Stat(allowVaultCleanFile); os.IsNotExist(err) {
		return false
	}
	return true
}
