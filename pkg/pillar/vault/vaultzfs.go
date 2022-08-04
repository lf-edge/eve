// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func getOperStatusParams(vaultPath string) []string {
	args := []string{"get", "mounted,encryption,keystatus", vaultPath}
	return args
}

// CheckOperStatus returns ZFS status
func CheckOperStatus(log *base.LogObject, vaultPath string) (string, error) {
	args := getOperStatusParams(vaultPath)
	if stdOut, stdErr, err := execCmd(types.ZFSBinary, args...); err != nil {
		log.Errorf("oper status query for %s results in error=%v, %s, %s",
			vaultPath, err, stdOut, stdErr)
		return stdErr, err
	} else {
		return stdOut, nil
	}
}
