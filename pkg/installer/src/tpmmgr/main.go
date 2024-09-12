// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func main() {
	if len(os.Args) < 2 {
		logger.Panic("Insufficient arguments. Usage: tpmmgr command [args]")
	}
	command := os.Args[1]
	args := os.Args[2:]
	os.Exit(runCommand(command, args))
}
