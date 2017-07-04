// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// hostsdir configlet for overlay interface towards domU

package main

import (
	"fmt"       
	"log"
	"net"
	"os"
	"github.com/zededa/go-provision/types"
)

// Create the hosts file for the overlay DNS resolution
// Would be more polite to return an error then to Fatal
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

func containsHostName(nameToEidList []types.NameToEid, hostname string) bool {
	for _, ne := range nameToEidList {
		if hostname == ne.HostName {
			return true
		}
	}
	return false
}

func containsEID(nameToEidList []types.NameToEid, EID net.IP) bool {
	for _, ne := range nameToEidList {
		for _, eid := range ne.EIDs {
			if eid.Equal(EID) {
				return true
			}
		}
	}
	return false
}

func updateHostsConfiglet(cfgDirname string,
     oldNameToEidList []types.NameToEid, newNameToEidList []types.NameToEid) {
	fmt.Printf("updateHostsConfiglet: dir %s old %v, new %v\n",
		cfgDirname, oldNameToEidList, newNameToEidList)
		
	// Look for hosts which should be deleted
	for _, ne := range oldNameToEidList {
		if !containsHostName(newNameToEidList, ne.HostName) {
			cfgPathname := cfgDirname + "/" + ne.HostName
			if err := os.Remove(cfgPathname); err != nil {
				log.Println("os.Remove for ", cfgPathname, err)
			}
		}
	}

	for _, ne := range newNameToEidList {
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

func deleteHostsConfiglet(cfgDirname string, printOnError bool) {
	fmt.Printf("deleteHostsConfiglet: dir %s\n", cfgDirname)
	err := os.RemoveAll(cfgDirname)
	if err != nil && printOnError {
		log.Println("RemoveAll ", cfgDirname, err)
	}
}
