// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// FscryptConfFile is where we keep config
	FscryptConfFile = "/etc/fscrypt.conf"

	// FscryptPath is the fscrypt binary
	FscryptPath = "/opt/zededa/bin/fscrypt"

	// ZfsPath is the zfs binary(?)
	ZfsPath = "/usr/sbin/chroot"

	// MountPoint is the root of all vaults
	MountPoint = types.PersistDir

	// DefaultZpool is used by zfs
	DefaultZpool = "persist"

	evePersistTypeFile = "/run/eve.persist_type"
)

var (
	// StatusParams is used by fscrypt
	StatusParams = []string{"status", MountPoint}
)

//getFscryptOperInfo returns operational status of fscrypt encryption
func getFscryptOperInfo(log *base.LogObject) (info.DataSecAtRestStatus, string) {
	_, err := os.Stat(FscryptConfFile)
	if err == nil {
		if _, _, err := execCmd(FscryptPath, StatusParams...); err != nil {
			//fscrypt is setup, but not being used
			log.Trace("Setting status to Error")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
				"Fscrypt Encryption is not setup"
		} else {
			//fscrypt is setup, and being used on /persist
			log.Trace("Setting status to Enabled")
			return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
				"Fscrypt is enabled and active"
		}
	} else {
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
			"Fscrypt is not enabled"

	}
}

//getZfsOperInfo returns operational status of ZFS encryption
func getZfsOperInfo(log *base.LogObject) (info.DataSecAtRestStatus, string) {
	//Check if default zpool (i.e. "persist" dataset) is setup
	_, err := CheckOperStatus(log, DefaultZpool)
	if err != nil {
		log.Errorf("default zpool status returns error %v", err)
		return info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
			"Default ZFS zpool is not setup"
	}
	return info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		"ZFS Encryption is enabled for vaults"

}

//GetOperInfo gets the current operational state of encryption tool
func GetOperInfo(log *base.LogObject) (info.DataSecAtRestStatus, string) {
	if !etpm.IsTpmEnabled() {
		//No encryption on plaforms without a (working) TPM
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

//ReadPersistType returns the persist filesystem
func ReadPersistType() types.PersistType {
	persistFsType := ""
	pBytes, err := ioutil.ReadFile(evePersistTypeFile)
	if err == nil {
		persistFsType = strings.TrimSpace(string(pBytes))
	}
	return types.ParsePersistType(persistFsType)
}
