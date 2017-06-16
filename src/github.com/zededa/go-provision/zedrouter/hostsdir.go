// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// hostsdir configlet for overlay interface towards domU

package main

import (
	"fmt"       
	"log"
	"os"
	"os/exec"
	"github.com/zededa/go-provision/types"
)

// XXX would be more polite to return an error then to Fatal
func createHostsConfiglet(cfgDirname string, namesToEids []types.NameToEid) {
	err := os.Mkdir(cfgDirname, 0755)
	if err != nil {
		log.Fatal("os.Mkdir for ", cfgDirname, err)
	}

	for i, ne := range namesToEids {
		fmt.Printf("createHostsConfiglet: %d name %s\n", i, ne.HostName)
		
		cfgPathname := cfgDirname + "/" + ne.HostName
		file, err := os.Create(cfgPathname)
		if err != nil {
			log.Fatal("os.Create for ", cfgPathname, err)
		}
		defer file.Close()
		for j, eid := range ne.EIDs {
			fmt.Printf("createHostsConfiglet: %d EID %s\n", j, eid)
			file.WriteString(fmt.Sprintf("%s	%s\n",
				eid, ne.HostName))
		}
	}
}

func deleteHostsConfiglet(cfgDirname string, printOnError bool) {
	cmd := "rm"
	args := []string{
		"-r",
		cfgDirname,
	}
	_, err := exec.Command(cmd, args...).Output()
	if err != nil && printOnError {
		// XXX should this be log?
		fmt.Printf("Command %v %v failed: %s\n", cmd, args, err)
	}
}
