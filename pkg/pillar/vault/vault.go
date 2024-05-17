// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

const (
	// allowVaultCleanFile existence indicates that we want to recreate vault in case of no controller key
	// we set it in installer and storage-init
	// so path must be aligned
	allowVaultCleanFile = types.PersistStatusDir + "/allow-vault-clean"
)

// GetOperationalInfo gets the current operational state of encryption tool
func GetOperationalInfo(log *base.LogObject) (info.DataSecAtRestStatus, string) {
	h := GetHandler(log)
	return h.GetOperationalInfo()
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

func isDirEmpty(log *base.LogObject, path string) bool {
	if f, err := os.Open(path); err == nil {
		files, err := f.Readdirnames(0)
		if err != nil {
			log.Errorf("Error reading dir contents: %v", err)
			return false
		}
		if len(files) == 0 {
			log.Tracef("No files in %s", path)
			return true
		}
		log.Tracef("Dir is not empty at %s", path)
		return false
	}
	log.Tracef("Dir not exist %s - consider empty", path)
	return true
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
