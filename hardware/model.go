// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Library to determine a hardwareModel string which can be used as a filename
// Implements HardwareModel() string
// In a disaggregated system this would probably need to run in dom0 hence
// would have an API between a domU and dom0

// XXX TBD: Should we add the other dmidecode calls from zedagent in here?

package hardware

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	compatibleFile = "/proc/device-tree/compatible"
)

func HardwareModel() string {
	model := ""
	product := ""
	pname, err := exec.Command("dmidecode", "-s", "system-product-name").Output()
	if err != nil {
		log.Println("dmidecode system-product-name:", err)
	} else {
		product = strings.TrimSpace(string(pname))
	}
	manufacturer := ""
	manu, err := exec.Command("dmidecode", "-s", "system-manufacturer").Output()
	if err != nil {
		log.Println("dmidecode system-manufacturer:", err)
	} else {
		manufacturer = strings.TrimSpace(string(manu))
	}
	compatible := ""
	if _, err := os.Stat(compatibleFile); err == nil {
		// No dmidecode on ARM. Can only report compatible string
		contents, err := ioutil.ReadFile(compatibleFile)
		if err != nil {
			log.Println(err)
		} else {
			compatible = string(contents)
		}
	}
	if manufacturer != "" {
		model = manufacturer + "."
	}
	if product != "" {
		model = model + product
	}
	if compatible != "" {
		if product != "" {
			model += "."
		}
		model = model + compatible
	}
	if model == "" {
		model = "default"
	}
	// Make sure it can be used as a filename
	safename := strings.Replace(model, "/", "_ ", -1)
	return safename
}
