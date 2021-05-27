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
	config, err := readSavedProtoMessageConfig(staleConfigTime, validateFile, true)
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
	}
	cfgOsList := config.GetBase()
	for _, cfgOs := range cfgOsList {
		if cfgOs.GetBaseOSVersion() == "" {
			// Empty slot - silently ignore
			continue
		}
	}
	return valid
}
