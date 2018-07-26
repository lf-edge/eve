// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package hardwaremodel

import (
	"flag"
	"fmt"
	"github.com/zededa/go-provision/hardware"
	"os"
)

// Set from Makefile
var Version = "No version specified"

func Run() {
	versionPtr := flag.Bool("v", false, "Version")
	cPtr := flag.Bool("c", false, "No CRLF")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	model := hardware.GetHardwareModelNoOverride()
	if *cPtr {
		fmt.Printf("%s", model)
	} else {
		fmt.Printf("%s\n", model)
	}
}
