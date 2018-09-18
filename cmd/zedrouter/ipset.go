// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

// default ipset configlet for interfaces towards domU

package zedrouter

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/wrap"
	"net"
)

// Create a pair of local ipsets called "ipv6.local" and "ipv4.local"
// XXX should we add 169.254.0.0/16 as well?
func createDefaultIpset() {
	if debug {
		log.Printf("createDefaultIpset()\n")
	}
	ipsetName := "local"
	err := ipsetCreatePair(ipsetName, "hash:net")
	if err != nil {
		log.Fatal("ipsetCreatePair for ", ipsetName, err)
	}
	set4 := "ipv4." + ipsetName
	set6 := "ipv6." + ipsetName

	prefixes := []string{"fe80::/10", "ff02::/16"}
	for _, prefix := range prefixes {
		err := ipsetAdd(set6, prefix)
		if err != nil {
			log.Println("ipset add ", set6, prefix, err)
		}
	}
	prefixes = []string{"0.0.0.0/32", "255.255.255.255/32", "224.0.0.0/4"}
	for _, prefix := range prefixes {
		err := ipsetAdd(set4, prefix)
		if err != nil {
			log.Println("ipset add ", set4, prefix, err)
		}
	}
}

// Create an ipset called eids.<vifname> with all the addresses from
// the DnsNameToIPList.
// Would be more polite to return an error then to Fatal
func createDefaultIpsetConfiglet(vifname string, nameToIPList []types.DnsNameToIP,
	appIPAddr string) {
	if debug {
		log.Printf("createDefaultIpsetConfiglet: olifName %s nameToIPList %v appIPAddr %s\n",
			vifname, nameToIPList, appIPAddr)
	}
	ipsetName := "eids." + vifname
	err := ipsetCreatePair(ipsetName, "hash:ip")
	if err != nil {
		log.Fatal("ipsetCreatePair for ", ipsetName, err)
	}
	set4 := "ipv4." + ipsetName
	set6 := "ipv6." + ipsetName
	var appIP net.IP
	if appIPAddr != "" {
		// XXX should we change strings to net.IP across the board
		// to avoid parsing in places like this?
		appIP = net.ParseIP(appIPAddr)
		if appIP == nil {
			log.Printf("ipset failed to parse appIPAddr %s\n",
				appIPAddr)
		}
	}
	for _, ne := range nameToIPList {
		for _, ip := range ne.IPs {
			var set string
			if ip.To4() == nil {
				set = set6
			} else {
				set = set4
			}
			err = ipsetAdd(set, ip.String())
			if err != nil {
				log.Println("ipset add ", set,
					ip.String(), err)
			}
			// Is appIP in nameToIPList?
			if appIP != nil && ip.Equal(appIP) {
				appIP = nil
			}
		}
	}
	if appIP != nil {
		var set string
		if appIP.To4() == nil {
			set = set6
		} else {
			set = set4
		}
		err = ipsetAdd(set, appIP.String())
		if err != nil {
			log.Println("ipset add ", set, appIP.String(), err)
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
	set4 := "ipv4." + ipsetName
	set6 := "ipv6." + ipsetName

	// Look for IPs which should be deleted
	for _, ne := range oldList {
		for _, ip := range ne.IPs {
			if !containsIP(newList, ip) {
				var set string
				if ip.To4() == nil {
					set = set6
				} else {
					set = set4
				}
				err := ipsetDel(set, ip.String())
				if err != nil {
					log.Println("ipset del ", set,
						ip.String(), err)
				}
			}
		}
	}

	// Look for IPs which should be added
	for _, ne := range newList {
		for _, ip := range ne.IPs {
			if !containsIP(oldList, ip) {
				var set string
				if ip.To4() == nil {
					set = set6
				} else {
					set = set4
				}
				err := ipsetAdd(set, ip.String())
				if err != nil {
					log.Println("ipset add ", set,
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
	set4 := "ipv4." + ipsetName
	set6 := "ipv6." + ipsetName

	err := ipsetDestroy(set4)
	if err != nil && printOnError {
		log.Println("ipset destroy ", set4, err)
	}
	err = ipsetDestroy(set6)
	if err != nil && printOnError {
		log.Println("ipset destroy ", set6, err)
	}
}

// If doesn't exist create the ipv4/ipv6 pair of sets.
func ipsetCreatePair(ipsetName string, setType string) error {
	set4 := "ipv4." + ipsetName
	set6 := "ipv6." + ipsetName
	if !ipsetExists(set4) {
		if err := ipsetCreate(set4, setType, 4); err != nil {
			return err
		} else {
			if err := ipsetFlush(set4); err != nil {
				return err
			}
		}
	}
	if !ipsetExists(set6) {
		if err := ipsetCreate(set6, setType, 6); err != nil {
			return err
		} else {
			if err := ipsetFlush(set6); err != nil {
				return err
			}
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
	if _, err := wrap.Command(cmd, args...).CombinedOutput(); err != nil {
		return err
	}
	return nil
}

func ipsetDestroy(ipsetName string) error {
	cmd := "ipset"
	args := []string{"destroy", ipsetName}
	if res, err := wrap.Command(cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset destroy %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
	}
	return nil
}

func ipsetFlush(ipsetName string) error {
	cmd := "ipset"
	args := []string{"flush", ipsetName}
	if res, err := wrap.Command(cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset flush %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
	}
	return nil
}

func ipsetAdd(ipsetName string, member string) error {
	cmd := "ipset"
	args := []string{"add", ipsetName, member}
	if res, err := wrap.Command(cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset add %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
	}
	return nil
}

func ipsetDel(ipsetName string, member string) error {
	cmd := "ipset"
	args := []string{"del", ipsetName, member}
	if res, err := wrap.Command(cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset del %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
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
