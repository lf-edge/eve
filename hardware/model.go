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
	overrideFile   = "/config/hardwaremodel"
)

// XXX Note that this function (and the ones below) log if there is an
// error. That's impolite for a library to do.
func GetHardwareModel() string {
	model := getOverride(overrideFile)
	if model != "" {
		return model
	}
	product := ""
	manufacturer := ""

	cmd := exec.Command("dmidecode", "-s", "system-product-name")
	pname, err := cmd.Output()
	if err != nil {
		log.Println("dmidecode system-product-name:", err)
	} else {
		product = string(pname)
	}
	cmd = exec.Command("dmidecode", "-s", "system-manufacturer")
	manu, err := cmd.Output()
	if err != nil {
		log.Println("dmidecode system-manufacturer:", err)
	} else {
		manufacturer = string(manu)
	}
	compatible := GetCompatible()
	return FormatModel(manufacturer, product, compatible)
}

func FormatModel(manufacturer, product, compatible string) string {
	var model string

	if manufacturer != "" {
		manufacturer = strings.TrimSpace(manufacturer)
		model = manufacturer + "."
	}
	if product != "" {
		product = strings.TrimSpace(product)
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

// If the file exists return its content
func getOverride(filename string) string {
	if _, err := os.Stat(filename); err != nil {
		return ""
	}
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println(err)
		return ""
	}
	return string(contents)
}

const controlChars = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

func GetCompatible() string {
	compatible := ""
	if _, err := os.Stat(compatibleFile); err == nil {
		contents, err := ioutil.ReadFile(compatibleFile)
		if err != nil {
			log.Println(err)
		} else {
			contents = bytes.Replace(contents, []byte("\x00"),
				[]byte("."), -1)
			filter := func(r rune) rune {
				if strings.IndexRune(controlChars, r) < 0 {
					return r
				}
				return -1
			}
			contents = bytes.Map(filter, contents)
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
