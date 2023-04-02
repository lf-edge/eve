// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nim

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/devicenetwork"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	minTTLSec       int = 30
	maxTTLSec       int = 3600
	extraSec        int = 10
	etcHostFileName     = "/etc/hosts"
	tmpHostFileName     = "/tmp/etchosts"
	resolvFileName      = "/etc/resolv.conf"
)

// go routine for dns query to the controller
func (n *nim) queryControllerDNS() {
	var etchosts, controllerServer []byte
	var ttlSec int
	var ipaddrCached string

	if _, err := os.Stat(etcHostFileName); err == nil {
		etchosts, err = os.ReadFile(etcHostFileName)
		if err == nil {
			controllerServer, _ = os.ReadFile(types.ServerFileName)
			controllerServer = bytes.TrimSuffix(controllerServer, []byte("\n"))
			if bytes.Contains(controllerServer, []byte(":")) {
				serverport := bytes.Split(controllerServer, []byte(":"))
				if len(serverport) == 2 {
					controllerServer = serverport[0]
				}
			}
		}
	}

	if len(controllerServer) == 0 {
		n.Log.Errorf("can't read /etc/hosts or server file")
		return
	}

	dnsTimer := time.NewTimer(time.Duration(minTTLSec) * time.Second)

	wdName := agentName + "dnsQuery"
	stillRunning := time.NewTicker(stillRunTime)
	n.PubSub.StillRunning(wdName, warningTime, errorTime)
	n.PubSub.RegisterFileWatchdog(wdName)

	for {
		select {
		case <-dnsTimer.C:
			// base on ttl from server dns update frequency for controller IP resolve
			// even if the dns server implementation returns the remaining value of the TTL it caches,
			// it will still work.
			ipaddrCached, ttlSec = n.controllerDNSCache(etchosts, controllerServer, ipaddrCached)
			dnsTimer = time.NewTimer(time.Duration(ttlSec) * time.Second)

		case <-stillRunning.C:
		}
		n.PubSub.StillRunning(wdName, warningTime, errorTime)
	}
}

func (n *nim) resolveWithPorts(domain string) []devicenetwork.DNSResponse {
	dnsResponse, errs := devicenetwork.ResolveWithPortsLambda(
		domain,
		n.dpcManager.GetDNS(),
		devicenetwork.ResolveWithSrcIP,
	)
	if len(errs) > 0 {
		n.Log.Warnf("resolveWithPortsLambda failed: %+v", errs)
	}
	return dnsResponse
}

// periodical cache the controller DNS resolution into /etc/hosts file
// it returns the cached ip string, and TTL setting from the server
func (n *nim) controllerDNSCache(
	etchosts, controllerServer []byte,
	ipaddrCached string,
) (string, int) {
	// Check to see if the server domain is already in the /etc/hosts as in eden,
	// then skip this DNS queries
	isCached, ipAddrCached, ttlCached := n.checkCachedEntry(
		etchosts,
		controllerServer,
		ipaddrCached,
	)
	if isCached {
		return ipAddrCached, ttlCached
	}

	err := os.Remove(tmpHostFileName)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		n.Log.Warnf("%s exists but removing failed: %+v", tmpHostFileName, err)
	}

	var newhosts []byte
	var ttlSec int
	var lookupIPaddr string

	dnsResponses := n.resolveWithPorts(string(controllerServer))
	ttlSec = int(dnsResponses[0].TTL)
	lookupIPaddr = dnsResponses[0].IP.String()
	serverEntry := fmt.Sprintf("%s %s\n", lookupIPaddr, controllerServer)
	newhosts = append(etchosts, []byte(serverEntry)...)

	if len(dnsResponses) == 0 {
		newhosts = append(newhosts, etchosts...)
	}

	if len(dnsResponses) > 0 && n.writeHostsFile(newhosts) {
		n.Log.Tracef("append controller IP %s to /etc/hosts", lookupIPaddr)
		ipaddrCached = lookupIPaddr
	} else {
		ipaddrCached = ""
	}

	return ipaddrCached, ttlSec
}

func (n *nim) writeHostsFile(newhosts []byte) bool {
	err := os.WriteFile(tmpHostFileName, newhosts, 0644)
	if err != nil {
		n.Log.Errorf("can not write /tmp/etchosts file %v", err)
		return false
	}
	if err := os.Rename(tmpHostFileName, etcHostFileName); err != nil {
		n.Log.Errorf("can not rename /etc/hosts file %v", err)
		return false
	}
	return true
}

func (*nim) readNameservers() []string {
	var nameServers []string
	dnsServer, _ := os.ReadFile(resolvFileName)
	dnsRes := bytes.Split(dnsServer, []byte("\n"))
	for _, d := range dnsRes {
		d1 := bytes.Split(d, []byte("nameserver "))
		if len(d1) == 2 {
			nameServers = append(nameServers, string(d1[1]))
		}
	}
	if len(nameServers) == 0 {
		nameServers = append(nameServers, "8.8.8.8")
	}
	return nameServers
}

func (n *nim) checkCachedEntry(
	etchosts []byte,
	controllerServer []byte,
	ipaddrCached string,
) (bool, string, int) {
	if len(etchosts) == 0 || len(controllerServer) == 0 {
		return true, ipaddrCached, maxTTLSec
	}

	if ipaddrCached == "" {
		hostsEntries := bytes.Split(etchosts, []byte("\n"))
		for _, entry := range hostsEntries {
			fields := bytes.Fields(entry)
			if len(fields) == 2 {
				if bytes.Compare(fields[1], controllerServer) == 0 {
					n.Log.Tracef("server entry %s already in /etc/hosts, skip", controllerServer)
					return true, ipaddrCached, maxTTLSec
				}
			}
		}
	}
	return false, "", 0
}

func getTTL(ttl time.Duration) int {
	ttlSec := int(ttl.Seconds())
	if ttlSec < minTTLSec {
		// this can happen often, when the dns server returns ttl being the remaining value
		// of it's own cached ttl, we set it to minTTLSec and retry. Next time will get the
		// upper range value of it's remaining ttl.
		ttlSec = minTTLSec
	} else if ttlSec > maxTTLSec {
		ttlSec = maxTTLSec
	}

	// some dns server returns actual remaining time of TTL, to avoid next time
	// get 0 or 1 those numbers, add some extra seconds
	return ttlSec + extraSec
}
