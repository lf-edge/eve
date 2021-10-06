// Copyright (c) 2017-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// PkillArgs does a pkill
func PkillArgs(log *base.LogObject, match string, printOnError bool, kill bool) {
	cmd := "pkill"
	var args []string
	if kill {
		args = []string{
			"-kill",
			"-f",
			match,
		}
	} else {
		args = []string{
			"-f",
			match,
		}
	}
	var err error
	var out []byte
	for i := 0; i < 3; i++ {
		log.Functionf("Calling command %s %v\n", cmd, args)
		out, err = base.Exec(log, cmd, args...).CombinedOutput()
		if err == nil {
			break
		}
		if printOnError {
			log.Warnf("Retrying failed command %v %v: %s output %s",
				cmd, args, err, out)
		}
		time.Sleep(time.Second)
	}
	if err != nil && printOnError {
		log.Errorf("Command %v %v failed: %s output %s\n",
			cmd, args, err, out)
	}
}
