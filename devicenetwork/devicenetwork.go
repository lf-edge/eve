// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/eriknordmark/ipinfo"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"time"
)

// Parse the file with DeviceNetworkConfig
func GetDeviceNetworkConfig(configFilename string) (types.DeviceNetworkConfig, error) {
	var globalConfig types.DeviceNetworkConfig
	cb, err := ioutil.ReadFile(configFilename)
	if err != nil {
		return types.DeviceNetworkConfig{}, err
	}
	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		return types.DeviceNetworkConfig{}, err
	}
	// Workaround for old config with FreeUplinks not set
	if len(globalConfig.FreeUplinks) == 0 {
		log.Printf("Setting FreeUplinks from Uplink: %v\n",
			globalConfig.Uplink)
		globalConfig.FreeUplinks = globalConfig.Uplink
	}
	return globalConfig, nil
}

// Calculate local IP addresses to make a types.DeviceNetworkStatus
func MakeDeviceNetworkStatus(globalConfig types.DeviceNetworkConfig) (types.DeviceNetworkStatus, error) {
	var globalStatus types.DeviceNetworkStatus
	var err error = nil

	globalStatus.UplinkStatus = make([]types.NetworkUplink,
		len(globalConfig.Uplink))
	for ix, u := range globalConfig.Uplink {
		globalStatus.UplinkStatus[ix].IfName = u
		for _, f := range globalConfig.FreeUplinks {
			if f == u {
				globalStatus.UplinkStatus[ix].Free = true
				break
			}
		}
		link, err := netlink.LinkByName(u)
		if err != nil {
			log.Printf("MakeDeviceNetworkStatus LinkByName %s: %s\n", u, err)
			err = errors.New(fmt.Sprintf("Uplink in config/global does not exist: %v", u))
			continue
		}
		addrs4, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			addrs4 = nil
		}
		addrs6, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			addrs6 = nil
		}
		globalStatus.UplinkStatus[ix].AddrInfoList = make([]types.AddrInfo,
			len(addrs4)+len(addrs6))
		for i, addr := range addrs4 {
			log.Printf("UplinkAddrs(%s) found IPv4 %v\n",
				u, addr.IP)
			globalStatus.UplinkStatus[ix].AddrInfoList[i].Addr = addr.IP
		}
		for i, addr := range addrs6 {
			// We include link-locals since they can be used for LISP behind nats
			log.Printf("UplinkAddrs(%s) found IPv6 %v\n",
				u, addr.IP)
			globalStatus.UplinkStatus[ix].AddrInfoList[i+len(addrs4)].Addr = addr.IP
		}
	}
	// Immediate check
	UpdateDeviceNetworkGeo(time.Second, &globalStatus)
	return globalStatus, err
}

// Returns true if anything might have changed
func UpdateDeviceNetworkGeo(timelimit time.Duration, globalStatus *types.DeviceNetworkStatus) bool {
	change := false
	for ui, _ := range globalStatus.UplinkStatus {
		u := &globalStatus.UplinkStatus[ui]
		for i, _ := range u.AddrInfoList {
			// Need pointer since we are going to modify
			ai := &u.AddrInfoList[i]
			timePassed := time.Since(ai.LastGeoTimestamp)
			if timePassed < timelimit {
				continue
			}
			// geoloc with short timeout
			opt := ipinfo.Options{
				Timeout:  5 * time.Second,
				// XXX for test purpose use token
				Token:    "e1277a86467b6b",
				SourceIp: ai.Addr,
			}
			info, err := ipinfo.MyIPWithOptions(opt)
			if err != nil {
				// Ignore error
				log.Printf("UpdateDeviceNetworkGeo MyIPInfo failed %s\n", err)
				continue
			}
			// Note that if the global IP is unchanged we don't
			// update anything.
			if info.IP == ai.Geo.IP {
				continue
			}
			log.Printf("UpdateDeviceNetworkGeo MyIPInfo changed from %v to %v\n",
				ai.Geo, *info)
			ai.Geo = *info
			ai.LastGeoTimestamp = time.Now()
			change = true
		}
	}
	return change
}
