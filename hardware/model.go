// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// Library to determine a hardwareModel string which can be used as a filename
// In a disaggregated system this would probably need to run in dom0 hence
// would have an API between a domU and dom0

// Implements GetHardwareModel() string
// We have no dmidecode on ARM. Can only report compatible string
// Note that we replace any nul characters with '.' since
// /proc/device-tree/compatible contains nuls.

// XXX TBD: Are there other hardware-related infos which should indirect
// through this package?

package hardware

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	compatibleFile = "/proc/device-tree/compatible"
)

func GetHardwareModel() string {
	model := ""
	product := ""
	manufacturer := ""

	cmd := exec.Command("dmidecode", "-s", "system-product-name")
	pname, err := cmd.Output()
	if err != nil {
		log.Println("dmidecode system-product-name:", err)
	} else {
		product = strings.TrimSpace(string(pname))
	}
	cmd = exec.Command("dmidecode", "-s", "system-manufacturer")
	manu, err := cmd.Output()
	if err != nil {
		log.Println("dmidecode system-manufacturer:", err)
	} else {
		manufacturer = strings.TrimSpace(string(manu))
	}
	compatible := GetCompatible()
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
	// Make sure it can be used as a filename by removing any '/'
	safename := strings.Replace(model, "/", "_ ", -1)
	return safename
}

func GetCompatible() string {
	compatible := ""
	if _, err := os.Stat(compatibleFile); err == nil {
		contents, err := ioutil.ReadFile(compatibleFile)
		if err != nil {
			log.Println(err)
		} else {
			contents = bytes.Replace(contents, []byte("\x00"),
				[]byte("."), -1)
			compatible = string(contents)
		}
	}
	return compatible
}

// Returns productManufacturer, productName, productVersion, productSerial, productUuid
func GetDeviceManufacturerInfo() (string, string, string, string, string) {
	cmd := exec.Command("dmidecode", "-s", "system-product-name")
	pname, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		pname = []byte{}
	}
	cmd = exec.Command("dmidecode", "-s", "system-manufacturer")
	manufacturer, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		manufacturer = []byte{}
	}
	cmd = exec.Command("dmidecode", "-s", "system-version")
	version, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		version = []byte{}
	}
	cmd = exec.Command("dmidecode", "-s", "system-serial-number")
	serial, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		serial = []byte{}
	}
	cmd = exec.Command("dmidecode", "-s", "system-uuid")
	uuid, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		uuid = []byte{}
	}
	productManufacturer := string(manufacturer)
	productName := string(pname)
	productVersion := string(version)
	productSerial := string(serial)
	productUuid := string(uuid)
	return productManufacturer, productName, productVersion, productSerial, productUuid
}

// Returns BIOS vendor, version, release-date
func GetDeviceBios() (string, string, string) {
	cmd := exec.Command("dmidecode", "-s", "bios-vendor")
	vendor, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		vendor = []byte{}
	}
	cmd = exec.Command("dmidecode", "-s", "bios-version")
	version, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		version = []byte{}
	}
	cmd = exec.Command("dmidecode", "-s", "bios-release-date")
	releaseDate, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		releaseDate = []byte{}
	}
	return string(vendor), string(version), string(releaseDate)
}
