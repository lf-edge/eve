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
func createHostsConfiglet(cfgDirname string, nameToEidList []types.NameToEid) {
	fmt.Printf("createHostsConfiglet: dir %s nameToEidList %v\n",
		cfgDirname, nameToEidList)
		
	err := os.Mkdir(cfgDirname, 0755)
	if err != nil {
		log.Fatal("os.Mkdir for ", cfgDirname, err)
	}

	for _, ne := range nameToEidList {
		cfgPathname := cfgDirname + "/" + ne.HostName
		file, err := os.Create(cfgPathname)
		if err != nil {
			log.Fatal("os.Create for ", cfgPathname, err)
		}
		defer file.Close()
		for _, eid := range ne.EIDs {
			file.WriteString(fmt.Sprintf("%s	%s\n",
				eid, ne.HostName))
		}
	}
}

func updateHostsConfiglet(cfgDirname string, nameToEidList []types.NameToEid) {
	fmt.Printf("updateHostsConfiglet: dir %s nameToEidList %v\n",
		cfgDirname, nameToEidList)
		
	for _, ne := range nameToEidList {
		// XXX look for hosts which didn't change, and hosts which
		// should be deleted
		cfgPathname := cfgDirname + "/" + ne.HostName
		file, err := os.Create(cfgPathname)
		if err != nil {
			log.Fatal("os.Create for ", cfgPathname, err)
		}
		defer file.Close()
		for _, eid := range ne.EIDs {
			file.WriteString(fmt.Sprintf("%s	%s\n",
				eid, ne.HostName))
			// XXX look for eids which should be deleted
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
