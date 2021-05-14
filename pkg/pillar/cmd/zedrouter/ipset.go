// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Default ipset configlet for interfaces towards domU.
// Note that for ipsets we use the following naming scheme:
//  ipsetName = ipv[46].<ipsetBasename>

package zedrouter

import (
	"errors"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"net"
)

// Netfilter limits ipset name to contain at most 31 characters.
const ipsetNameLenLimit = 31

// Create a pair of local ipsets called "ipv6.local" and "ipv4.local"
// XXX should we add 169.254.0.0/16 as well?
func createDefaultIpset() {

	log.Tracef("createDefaultIpset()\n")
	ipsetBasename := "local"
	err := ipsetCreatePair(ipsetBasename, "hash:net")
	if err != nil {
		log.Fatal("ipsetCreatePair for ", ipsetBasename, err)
	}
	set4 := "ipv4." + ipsetBasename
	set6 := "ipv6." + ipsetBasename

	prefixes := []string{"fe80::/10", "ff02::/16"}
	for _, prefix := range prefixes {
		err := ipsetAdd(set6, prefix)
		if err != nil {
			log.Errorln("ipset add ", set6, prefix, err)
		}
	}
	prefixes = []string{"0.0.0.0/32", "255.255.255.255/32", "224.0.0.0/4"}
	for _, prefix := range prefixes {
		err := ipsetAdd(set4, prefix)
		if err != nil {
			log.Errorln("ipset add ", set4, prefix, err)
		}
	}
}

// Create an ipset called eids.<vifname> with all the addresses from
// the DnsNameToIPList.
// Would be more polite to return an error then to Fatal
func createDefaultIpsetConfiglet(vifname string, nameToIPList []types.DnsNameToIP,
	appIPAddr string) {

	log.Tracef("createDefaultIpsetConfiglet: olifName %s nameToIPList %v appIPAddr %s\n",
		vifname, nameToIPList, appIPAddr)
	ipsetBasename := "eids." + vifname
	err := ipsetCreatePair(ipsetBasename, "hash:ip")
	if err != nil {
		log.Fatal("ipsetCreatePair for ", ipsetBasename, err)
	}
	set4 := "ipv4." + ipsetBasename
	set6 := "ipv6." + ipsetBasename
	var appIP net.IP
	if appIPAddr != "" {
		// XXX should we change strings to net.IP across the board
		// to avoid parsing in places like this?
		appIP = net.ParseIP(appIPAddr)
		if appIP == nil {
			log.Errorf("ipset failed to parse appIPAddr %s\n",
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
				log.Errorln("ipset add ", set,
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
			log.Errorln("ipset add ", set, appIP.String(), err)
		}
	}
}

func updateDefaultIpsetConfiglet(vifname string,
	oldList []types.DnsNameToIP, newList []types.DnsNameToIP) {

	log.Tracef("updateDefaultIpsetConfiglet: vifname %s old %v, new %v\n",
		vifname, oldList, newList)
	ipsetBasename := "eids." + vifname
	set4 := "ipv4." + ipsetBasename
	set6 := "ipv6." + ipsetBasename

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
					log.Errorln("ipset del ", set,
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
					log.Errorln("ipset add ", set,
						ip.String(), err)
				}
			}
		}
	}
}

func deleteDefaultIpsetConfiglet(vifname string, printOnError bool) {

	log.Tracef("deleteDefaultIpsetConfiglet: vifname %s\n", vifname)
	ipsetBasename := "eids." + vifname
	set4 := "ipv4." + ipsetBasename
	set6 := "ipv6." + ipsetBasename

	err := ipsetDestroy(set4)
	if err != nil && printOnError {
		log.Errorln("ipset destroy ", set4, err)
	}
	err = ipsetDestroy(set6)
	if err != nil && printOnError {
		log.Errorln("ipset destroy ", set6, err)
	}
}

// If doesn't exist create the ipv4/ipv6 pair of sets.
func ipsetCreatePair(ipsetBasename string, setType string) error {
	set4 := "ipv4." + ipsetBasename
	set6 := "ipv6." + ipsetBasename
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
	log.Functionf("Calling command %s %v\n", cmd, args)
	if _, err := base.Exec(log, cmd, args...).CombinedOutput(); err != nil {
		return err
	}
	return nil
}

func ipsetDestroy(ipsetName string) error {
	cmd := "ipset"
	args := []string{"destroy", ipsetName}
	log.Functionf("Calling command %s %v\n", cmd, args)
	if res, err := base.Exec(log, cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset destroy %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
	}
	return nil
}

func ipsetFlush(ipsetName string) error {
	cmd := "ipset"
	args := []string{"flush", ipsetName}
	log.Functionf("Calling command %s %v\n", cmd, args)
	if res, err := base.Exec(log, cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset flush %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
	}
	return nil
}

func ipsetAdd(ipsetName string, member string) error {
	cmd := "ipset"
	args := []string{"add", ipsetName, member}
	log.Functionf("Calling command %s %v\n", cmd, args)
	if res, err := base.Exec(log, cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset add %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
	}
	return nil
}

func ipsetDel(ipsetName string, member string) error {
	cmd := "ipset"
	args := []string{"del", ipsetName, member}
	log.Functionf("Calling command %s %v\n", cmd, args)
	if res, err := base.Exec(log, cmd, args...).CombinedOutput(); err != nil {
		errStr := fmt.Sprintf("ipset del %s failed %s: %s",
			ipsetName, res, err)
		return errors.New(errStr)
	}
	return nil
}

func ipsetExists(ipsetName string) bool {
	cmd := "ipset"
	args := []string{"list", ipsetName}
	log.Functionf("Calling command %s %v\n", cmd, args)
	if _, err := base.Exec(log, cmd, args...).Output(); err != nil {
		return false
	}
	return true
}
