// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// hostsdir configlet for overlay interface towards domU

package zedrouter

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"net"
	"os"
)

// Create the hosts file for the overlay DNS resolution
// Would be more polite to return an error then to Fatal
func createHostsConfiglet(cfgDirname string, nameToIPList []types.DnsNameToIP) {
	if debug {
		log.Printf("createHostsConfiglet: dir %s nameToIPList %v\n",
			cfgDirname, nameToIPList)
	}
	ensureDir(cfgDirname)

	for _, ne := range nameToIPList {
		addIPToHostsConfiglet(cfgDirname, ne.HostName, ne.IPs)
	}
}

func ensureDir(dirname string) {
	if _, err := os.Stat(dirname); err != nil {
		err := os.Mkdir(dirname, 0755)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Create one file per hostname
func addIPToHostsConfiglet(cfgDirname string, hostname string, addrs []net.IP) {
	ensureDir(cfgDirname)
	cfgPathname := cfgDirname + "/" + hostname
	file, err := os.Create(cfgPathname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	for _, addr := range addrs {
		file.WriteString(fmt.Sprintf("%s	%s\n",
			addr.String(), hostname))
	}
}

// Create one file per hostname
func addToHostsConfiglet(cfgDirname string, hostname string, addrs []string) {
	ensureDir(cfgDirname)
	cfgPathname := cfgDirname + "/" + hostname
	file, err := os.Create(cfgPathname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	for _, addr := range addrs {
		file.WriteString(fmt.Sprintf("%s	%s\n", addr, hostname))
	}
}

func removeFromHostsConfiglet(cfgDirname string, hostname string) {
	cfgPathname := cfgDirname + "/" + hostname
	if err := os.Remove(cfgPathname); err != nil {
		log.Println("removeFromHostsConfiglet: ", err)
	}
}

func containsHostName(nameToIPList []types.DnsNameToIP, hostname string) bool {
	for _, ne := range nameToIPList {
		if hostname == ne.HostName {
			return true
		}
	}
	return false
}

func containsIP(nameToIPList []types.DnsNameToIP, ip net.IP) bool {
	for _, ne := range nameToIPList {
		for _, i := range ne.IPs {
			if i.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func updateHostsConfiglet(cfgDirname string,
	oldList []types.DnsNameToIP, newList []types.DnsNameToIP) {
	if debug {
		log.Printf("updateHostsConfiglet: dir %s old %v, new %v\n",
			cfgDirname, oldList, newList)
	}
	// Look for hosts which should be deleted
	for _, ne := range oldList {
		if !containsHostName(newList, ne.HostName) {
			cfgPathname := cfgDirname + "/" + ne.HostName
			if err := os.Remove(cfgPathname); err != nil {
				log.Println("updateHostsConfiglet: ", err)
			}
		}
	}

	for _, ne := range newList {
		cfgPathname := cfgDirname + "/" + ne.HostName
		file, err := os.Create(cfgPathname)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		for _, ip := range ne.IPs {
			file.WriteString(fmt.Sprintf("%s	%s\n",
				ip, ne.HostName))
		}
	}
}

func deleteHostsConfiglet(cfgDirname string, printOnError bool) {
	if debug {
		log.Printf("deleteHostsConfiglet: dir %s\n", cfgDirname)
	}
	err := os.RemoveAll(cfgDirname)
	if err != nil && printOnError {
		log.Println("deleteHostsConfiglet: ", err)
	}
}
