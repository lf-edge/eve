// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// default ipset configlet for interfaces towards domU

package zedrouter

import (
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"log"
)

// Create local IPv6 ipset called "local.ipv6" and "local.ipv4"
// XXX should we add 169.254.0.0/16 as well?
func createDefaultIpset() {
	if debug {
		log.Printf("createDefaultIpset()\n")
	}
	ipsetName := "local.ipv6"
	if !ipsetExists(ipsetName) {
		if err := ipsetCreate(ipsetName, "hash:net", 6); err != nil {
			log.Fatal("ipset create for ", ipsetName, err)
		}
	} else {
		if err := ipsetFlush(ipsetName); err != nil {
			log.Fatal("ipset flush for ", ipsetName, err)
		}
	}
	prefixes := []string{"fe80::/10", "ff02::/16"}
	for _, prefix := range prefixes {
		err := ipsetAdd(ipsetName, prefix)
		if err != nil {
			log.Println("ipset add ", ipsetName, prefix, err)
		}
	}
	ipsetName = "local.ipv4"
	if !ipsetExists(ipsetName) {
		if err := ipsetCreate(ipsetName, "hash:net", 4); err != nil {
			log.Fatal("ipset create for ", ipsetName, err)
		}
	} else {
		if err := ipsetFlush(ipsetName); err != nil {
			log.Fatal("ipset flush for ", ipsetName, err)
		}
	}
	prefixes = []string{"0.0.0.0/32", "255.255.255.255/32", "224.0.0.0/4"}
	for _, prefix := range prefixes {
		err := ipsetAdd(ipsetName, prefix)
		if err != nil {
			log.Println("ipset add ", ipsetName, prefix, err)
		}
	}
}

// Create an ipset called eids.<vifname> with all the addresses from
// the DnsNameToIPList.
// Would be more polite to return an error then to Fatal
func createDefaultIpsetConfiglet(vifname string, nameToIPList []types.DnsNameToIP,
	myIp string) {
	if debug {
		log.Printf("createDefaultIpsetConfiglet: olifName %s nameToIPList %v myIp %s\n",
			vifname, nameToIPList, myIp)
	}
	ipsetName := "eids." + vifname
	if !ipsetExists(ipsetName) {
		if err := ipsetCreate(ipsetName, "hash:ip", 6); err != nil {
			log.Fatal("ipset create for ", ipsetName, err)
		}
	} else {
		if err := ipsetFlush(ipsetName); err != nil {
			log.Fatal("ipset flush for ", ipsetName, err)
		}
	}
	for _, ne := range nameToIPList {
		for _, ip := range ne.IPs {
			err := ipsetAdd(ipsetName, ip.String())
			if err != nil {
				log.Println("ipset add ", ipsetName,
					ip.String(), err)
			}
		}
	}
	if myIp != "" {
		err := ipsetAdd(ipsetName, myIp)
		if err != nil {
			log.Println("ipset add ", ipsetName,
				myIp, err)
		}
	}
}

func updateDefaultIpsetConfiglet(vifname string,
	oldList []types.DnsNameToIP, newList []types.DnsNameToIP) {
	if debug {
		log.Printf("updateDefaultIpsetConfiglet: vifname %s old %v, new %v\n",
			vifname, oldList, newList)
	}
	ipsetName := "eids." + vifname

	// Look for IPs which should be deleted
	for _, ne := range oldList {
		for _, ip := range ne.IPs {
			if !containsIP(newList, ip) {
				err := ipsetDel(ipsetName, ip.String())
				if err != nil {
					log.Println("ipset del ", ipsetName,
						ip.String(), err)
				}
			}
		}
	}

	// Look for IPs which should be added
	for _, ne := range newList {
		for _, ip := range ne.IPs {
			if !containsIP(oldList, ip) {
				err := ipsetAdd(ipsetName, ip.String())
				if err != nil {
					log.Println("ipset add ", ipsetName,
						ip.String(), err)
				}
			}
		}
	}
}

func deleteDefaultIpsetConfiglet(vifname string, printOnError bool) {
	if debug {
		log.Printf("deleteDefaultIpsetConfiglet: vifname %s\n", vifname)
	}
	ipsetName := "eids." + vifname

	err := ipsetDestroy(ipsetName)
	if err != nil && printOnError {
		log.Println("ipset destroy ", ipsetName, err)
	}
}

// If doesn't exist create the ipv4/ipv6 pair of sets.
func ipsetCreatePair(ipsetName string) error {
	set4 := "ipv4." + ipsetName
	set6 := "ipv6." + ipsetName
	setType := "hash:ip"
	if !ipsetExists(set4) {
		if err := ipsetCreate(set4, setType, 4); err != nil {
			return err
		}
	}
	if !ipsetExists(set6) {
		if err := ipsetCreate(set6, setType, 6); err != nil {
			return err
		}
	}
	return nil
}

func ipsetCreate(ipsetName string, setType string, ipVer int) error {
	cmd := "ipset"
	family := ""
	if ipVer == 4 {
		family = "inet"
	} else if ipVer == 6 {
		family = "inet6"
	}
	args := []string{"create", ipsetName, setType, "family", family}
	if _, err := wrap.Command(cmd, args...).Output(); err != nil {
		return err
	}
	return nil
}

func ipsetDestroy(ipsetName string) error {
	cmd := "ipset"
	args := []string{"destroy", ipsetName}
	if _, err := wrap.Command(cmd, args...).Output(); err != nil {
		return err
	}
	return nil
}

func ipsetFlush(ipsetName string) error {
	cmd := "ipset"
	args := []string{"flush", ipsetName}
	if _, err := wrap.Command(cmd, args...).Output(); err != nil {
		return err
	}
	return nil
}

func ipsetAdd(ipsetName string, member string) error {
	cmd := "ipset"
	args := []string{"add", ipsetName, member}
	if _, err := wrap.Command(cmd, args...).Output(); err != nil {
		return err
	}
	return nil
}

func ipsetDel(ipsetName string, member string) error {
	cmd := "ipset"
	args := []string{"del", ipsetName, member}
	if _, err := wrap.Command(cmd, args...).Output(); err != nil {
		return err
	}
	return nil
}

func ipsetExists(ipsetName string) bool {
	cmd := "ipset"
	args := []string{"list", ipsetName}
	if _, err := wrap.Command(cmd, args...).Output(); err != nil {
		return false
	}
	return true
}
