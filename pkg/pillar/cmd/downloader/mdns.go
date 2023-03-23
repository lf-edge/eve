// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
// github.com/grandcat/zeroconf: under MIT License

package downloader

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// given a local server URL string, and returns the modified url with server IP address in it,
// and bridge name and source IP address for connecting to the server.
func findDSmDNS(dctx *downloaderContext, serverURL string) (string, string, net.IP, error) {
	dsURL, err := url.Parse(serverURL)
	if err != nil {
		log.Errorf("findDSmDNS: error %v", err)
		return "", "", nil, err
	}
	hostname := dsURL.Hostname()
	var newURL string
	var foundIP []net.IP

	urlParts := strings.SplitN(serverURL, hostname, 2)
	if len(urlParts) != 2 {
		return "", "", nil, fmt.Errorf("findDSmDNS: urls format error %v", urlParts)
	}

	// try to loop through the well-known services, workstation, http and https
	// until success, for the local data store zeroconf
	services := []string{
		"workstation", "http", "https",
	}

	sub := dctx.subNetworkInstanceStatus
	niItems := sub.GetAll()
	ifs := findLocalBridges(niItems)
	if len(ifs) == 0 {
		return "", "", nil, fmt.Errorf("findDSmDNS: has no bridge interface")
	}

	for _, service := range services {
		foundIP, err = queryService(ifs, hostname, service)
		if err != nil {
			return "", "", nil, err
		}
		if len(foundIP) > 0 {
			break
		}
	}

	if len(foundIP) == 0 {
		return "", "", nil, fmt.Errorf("findDSmDNS: mDNS host not found for %s", hostname)
	}

	// find the first src/dst pair we can use for local DS downloading
	for _, dsIP := range foundIP {
		ipStr := dsIP.String()
		ifname, ipSrc := findLocalDsSrc(niItems, net.ParseIP(ipStr))
		if ipSrc != nil {
			newURL = urlParts[0] + ipStr + urlParts[1]
			return newURL, ifname, ipSrc, nil
		}
	}

	return "", "", nil, fmt.Errorf("findDSmDNS: source IP not found for %v", foundIP)
}

// query for mDNS services over device local interfaces/bridges
func queryService(ifs []net.Interface, hostname, service string) ([]net.IP, error) {
	var foundIP []net.IP
	// restrict the mDNS local query to bridge interfaces and protocol IPv4
	ifOption := zeroconf.SelectIfaces(ifs)
	ipOption := zeroconf.SelectIPTraffic(zeroconf.IPv4)
	resolver, err := zeroconf.NewResolver(ipOption, ifOption)
	if err != nil {
		log.Errorf("queryService: Failed to initialize resolver: %v", err)
		return foundIP, err
	}

	mctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(10))
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry)
	go func(results <-chan *zeroconf.ServiceEntry) {
		for entry := range results {
			log.Functionf("findDSmDNS: %v", entry)
			if strings.Contains(entry.HostName, hostname) {
				foundIP = entry.AddrIPv4
				cancel()
				break
			}
		}
	}(entries)

	serviceStr := "_" + service + "._tcp"
	err = resolver.Browse(mctx, serviceStr, "local", entries)
	if err != nil {
		log.Errorf("queryService: resolver error %v", err)
		return foundIP, err
	}

	<-mctx.Done()
	return foundIP, nil
}

func findLocalDsSrc(niItems map[string]interface{}, hostip net.IP) (ifname string, ipSrc net.IP) {
	if hostip == nil {
		log.Errorf("findLocalDsSrc: host ip nil passed in")
		return "", nil
	}
	for _, item := range niItems {
		status := item.(types.NetworkInstanceStatus)
		if status.IsIpAssigned(hostip) {
			return status.BridgeName, status.BridgeIPAddr
		}
	}
	return "", nil
}

func findLocalBridges(niItems map[string]interface{}) []net.Interface {
	var ifs []net.Interface
	for _, item := range niItems {
		status := item.(types.NetworkInstanceStatus)
		bridge := net.Interface{
			Name:  status.BridgeName,
			Index: status.BridgeIfindex,
		}
		ifs = append(ifs, bridge)
	}
	return ifs
}
