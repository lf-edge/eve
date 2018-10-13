// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

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
