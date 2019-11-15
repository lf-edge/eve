// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"fmt"
	"unicode/utf8"

	zconfig "github.com/lf-edge/eve/api/go/config"
)

func readValidateConfig(staleConfigTime uint32,
	validateFile string) (bool, *zconfig.EdgeDevConfig) {
	config, err := readSavedProtoMessage(staleConfigTime, validateFile, true)
	if err != nil {
		fmt.Printf("getconfig: %v\n", err)
		return false, nil
	}
	return true, config
}

// Check various strings to make sure they are valid UTF-8
// Note that byte strings like the Siginfo.Signature will fail this check.
func validateConfigUTF8(config *zconfig.EdgeDevConfig) bool {

	valid := true
	Apps := config.GetApps()
	for _, cfgApp := range Apps {
		for i, intfEnt := range cfgApp.Interfaces {
			if len(intfEnt.Lispsignature) != 0 {
				fmt.Printf("lispSignature for app %s intf %d <%v>\n",
					cfgApp.Displayname, i,
					intfEnt.Lispsignature)
				if utf8.ValidString(intfEnt.Lispsignature) {
					fmt.Printf("lispSignature valid\n")
				} else {
					fmt.Printf("lispSignature is invalid UTF-8\n")
					valid = false
				}
			}
		}
		v := validateDrives(cfgApp.Displayname, cfgApp.Drives)
		valid = valid && v
	}
	cfgOsList := config.GetBase()
	for _, cfgOs := range cfgOsList {
		if cfgOs.GetBaseOSVersion() == "" {
			// Empty slot - silently ignore
			continue
		}
		v := validateDrives(cfgOs.GetBaseOSVersion(), cfgOs.Drives)
		valid = valid && v
	}
	return valid
}

func validateDrives(name string, drives []*zconfig.Drive) bool {

	valid := true
	for i, drive := range drives {
		if drive.Image == nil {
			fmt.Printf("drive.Image missing for %s\n", name)
			continue
		}
		if len(drive.Image.Siginfo.Signature) != 0 {
			fmt.Printf("Signature for %s drive %d <%v>\n",
				name, i, drive.Image.Siginfo.Signature)
			if utf8.ValidString(string(drive.Image.Siginfo.Signature)) {
				fmt.Printf("signature valid\n")
			} else {
				fmt.Printf("signature is invalid UTF-8\n")
				valid = false
			}
		}
	}
	return valid
}
