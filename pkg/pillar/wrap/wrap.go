// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Wrap calls to get some logging information

package wrap

import (
	log "github.com/sirupsen/logrus"
	"os/exec"
)

func Command(name string, arg ...string) *exec.Cmd {

	log.Infof("Calling command %s %v\n", name, arg)
	return exec.Command(name, arg...)
}
