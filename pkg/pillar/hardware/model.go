// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Library to determine a hardwareModel string which can be used as a filename
// In a disaggregated system this would probably need to run in dom0 hence
// would have an API between a domU and dom0

// Implements GetHardwareModel() string
// We have no dmidecode on ARM, so we use /proc/cpuinfo and look for Serial
// We also report compatible string:
// Note that we replace any intermediate nul characters with '.' since
// /proc/device-tree/compatible contains nuls to separate different strings.

// XXX TBD: Are there other hardware-related infos which should indirect
// through this package?

package hardware

import (
	"bytes"
	"os"
	"regexp"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	compatibleFile    = "/proc/device-tree/compatible"
	cpuInfoFile       = "/proc/cpuinfo"
	modelOverrideFile = types.PersistStatusDir + "/hardwaremodel"
	softSerialFile    = types.IdentityDirname + "/soft_serial"
)

// XXX Note that this function (and the ones below) log if there is an
// error. That's impolite for a library to do.

// GetHardwareModel uses the most current i.e., prefers override from the controller
func GetHardwareModel(log *base.LogObject) string {
	model := getOverride(log, modelOverrideFile)
	if model != "" {
		return model
	}
	return GetHardwareModelNoOverride(log)
}

// GetHardwareModelOverride gets any override from the controller
func GetHardwareModelOverride(log *base.LogObject) string {
	return getOverride(log, modelOverrideFile)
}

func GetHardwareModelNoOverride(log *base.LogObject) string {
	product := ""
	manufacturer := ""

	pname, err := base.Exec(log, "dmidecode", "-s", "system-product-name").Output()
	if err != nil {
		log.Errorln("dmidecode system-product-name:", err)
	} else {
		product = string(pname)
	}
	manu, err := base.Exec(log, "dmidecode", "-s", "system-manufacturer").Output()
	if err != nil {
		log.Errorln("dmidecode system-manufacturer:", err)
	} else {
		manufacturer = string(manu)
	}
	compatible := GetCompatible(log)
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
func getOverride(log *base.LogObject, filename string) string {
	if _, err := os.Stat(filename); err != nil {
		return ""
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		log.Errorf("getOverride(%s) failed: %s\n", filename, err)
		return ""
	}
	return strings.TrimSpace(string(contents))
}

const controlChars = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

func GetCompatible(log *base.LogObject) string {
	compatible := ""
	if _, err := os.Stat(compatibleFile); err == nil {
		contents, err := os.ReadFile(compatibleFile)
		if err != nil {
			log.Errorf("GetCompatible(%s) failed %s\n",
				compatibleFile, err)
		} else {
			compatible = string(massageCompatible(contents))
		}
	}
	return compatible
}

func getCPUSerial(log *base.LogObject) string {
	serial := ""
	if _, err := os.Stat(cpuInfoFile); err == nil {
		contents, err := os.ReadFile(cpuInfoFile)
		if err != nil {
			log.Errorf("getCPUSerial(%s) failed %s\n",
				cpuInfoFile, err)
		} else {
			match := regexp.MustCompile(`(?s)Serial\s*:\s*(\S+)`).FindStringSubmatch(string(contents))
			if match != nil && len(match) == 2 {
				serial = match[1]
			}
		}
	}
	return serial
}

func massageCompatible(contents []byte) []byte {
	filter := func(r rune) rune {
		if strings.IndexRune(controlChars, r) < 0 {
			return r
		}
		return -1
	}

	// Drop last control character if present to avoid a trailing .
	cl := len(contents)
	if cl > 0 && filter(rune(contents[cl-1])) == -1 {
		contents = contents[:cl-1]
	}
	contents = bytes.Replace(contents, []byte("\x00"), []byte("."), -1)
	return bytes.Map(filter, contents)
}

// GetSoftSerial returns software defined product serial number
func GetSoftSerial(log *base.LogObject) string {
	return strings.TrimSuffix(getOverride(log, softSerialFile), "\n")
}

func GetProductSerial(log *base.LogObject) string {
	serial, err := base.Exec(log, "dmidecode", "-s", "system-serial-number").Output()
	if err != nil {
		log.Errorf("GetProductSerial system-serial-number failed %s\n",
			err)
		serial = []byte{}
	}
	if string(serial) != "" {
		return strings.TrimSuffix(string(serial), "\n")
	} else {
		return getCPUSerial(log)
	}
}

// Returns productManufacturer, productName, productVersion, productSerial, productUuid
func GetDeviceManufacturerInfo(log *base.LogObject) (string, string, string, string, string) {
	pname, err := base.Exec(log, "dmidecode", "-s", "system-product-name").Output()
	if err != nil {
		log.Errorf("GetDeviceManufacturerInfo system-product-name failed %s\n",
			err)
		pname = []byte{}
	}
	manufacturer, err := base.Exec(log, "dmidecode", "-s", "system-manufacturer").Output()
	if err != nil {
		log.Errorf("GetDeviceManufacturerInfo system-manufacturer failed %s\n",
			err)
		manufacturer = []byte{}
	}
	version, err := base.Exec(log, "dmidecode", "-s", "system-version").Output()
	if err != nil {
		log.Errorf("GetDeviceManufacturerInfo system-version failed %s\n",
			err)
		version = []byte{}
	}
	uuid, err := base.Exec(log, "dmidecode", "-s", "system-uuid").Output()
	if err != nil {
		log.Errorf("GetDeviceManufacturerInfo system-uuid failed %s\n",
			err)
		uuid = []byte{}
	}
	productSerial := GetProductSerial(log)
	productManufacturer := string(manufacturer)
	productName := string(pname)
	productVersion := string(version)
	productUuid := string(uuid)
	return productManufacturer, productName, productVersion, productSerial, productUuid
}

// Returns BIOS vendor, version, release-date
func GetDeviceBios(log *base.LogObject) (string, string, string) {
	vendor, err := base.Exec(log, "dmidecode", "-s", "bios-vendor").Output()
	if err != nil {
		log.Errorf("GetDeviceBios bios-vendor failed %s\n",
			err)
		vendor = []byte{}
	}
	version, err := base.Exec(log, "dmidecode", "-s", "bios-version").Output()
	if err != nil {
		log.Errorf("GetDeviceBios bios-version failed %s\n",
			err)
		version = []byte{}
	}
	releaseDate, err := base.Exec(log, "dmidecode", "-s", "bios-release-date").Output()
	if err != nil {
		log.Errorf("GetDeviceBios bios-release-date failed %s\n",
			err)
		releaseDate = []byte{}
	}
	return string(vendor), string(version), string(releaseDate)
}
