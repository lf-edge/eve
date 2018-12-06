// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"errors"
	"fmt"
	"github.com/eriknordmark/ipinfo"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/types"
	"net"
	"time"
)

// Genetate NetworkUplinkConfig based on DeviceNetworkConfig
func MakeNetworkUplinkConfig(globalConfig types.DeviceNetworkConfig) types.DeviceUplinkConfig {
	var config types.DeviceUplinkConfig

	config.Uplinks = make([]types.NetworkUplinkConfig,
		len(globalConfig.Uplink))
	for ix, u := range globalConfig.Uplink {
		config.Uplinks[ix].IfName = u
		for _, f := range globalConfig.FreeUplinks {
			if f == u {
				config.Uplinks[ix].Free = true
				break
			}
		}
		config.Uplinks[ix].Dhcp = types.DT_CLIENT
	}
	return config
}

func isProxyConfigEmpty(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) == 0 &&
		proxyConfig.Exceptions == "" &&
		proxyConfig.Pacfile == "" &&
		proxyConfig.NetworkProxyEnable == false &&
		proxyConfig.NetworkProxyURL == "" {
		return true
	}
	return false
}

// Calculate local IP addresses to make a types.DeviceNetworkStatus
func MakeDeviceNetworkStatus(globalConfig types.DeviceUplinkConfig, oldStatus types.DeviceNetworkStatus) (types.DeviceNetworkStatus, error) {
	var globalStatus types.DeviceNetworkStatus
	var err error = nil

	globalStatus.UplinkStatus = make([]types.NetworkUplink,
		len(globalConfig.Uplinks))
	for ix, u := range globalConfig.Uplinks {
		globalStatus.UplinkStatus[ix].IfName = u.IfName
		globalStatus.UplinkStatus[ix].Free = u.Free
		// XXX
		// If device DeviceNetworkStatus already has non-empty proxy
		// configuration for this uplink and the new proxy configuration
		// is empty, we should retain the existing proxy configuration to
		// avoid bricking the device.
		// These kind of checks should go away when we have Network manager
		// service that tests proxy configuration before trying to apply it.
		if isProxyConfigEmpty(u.ProxyConfig) {
			for _, uplink := range oldStatus.UplinkStatus {
				if uplink.IfName == u.IfName {
					globalStatus.UplinkStatus[ix].ProxyConfig = uplink.ProxyConfig
					break
				}
			}
		} else {
			globalStatus.UplinkStatus[ix].ProxyConfig = u.ProxyConfig
		}
		// XXX should we get statics?
		link, err := netlink.LinkByName(u.IfName)
		if err != nil {
			log.Warnf("MakeDeviceNetworkStatus LinkByName %s: %s\n",
				u.IfName, err)
			err = errors.New(fmt.Sprintf("Uplink in config/global does not exist: %v",
				u))
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
			log.Infof("UplinkAddrs(%s) found IPv4 %v\n",
				u.IfName, addr.IP)
			globalStatus.UplinkStatus[ix].AddrInfoList[i].Addr = addr.IP
		}
		for i, addr := range addrs6 {
			// We include link-locals since they can be used for LISP behind nats
			log.Infof("UplinkAddrs(%s) found IPv6 %v\n",
				u.IfName, addr.IP)
			globalStatus.UplinkStatus[ix].AddrInfoList[i+len(addrs4)].Addr = addr.IP
		}
		// Get DNS info from dhcpcd. Updates DomainName and DnsServers
		err = GetDnsInfo(&globalStatus.UplinkStatus[ix])
		if err != nil {
			errStr := fmt.Sprintf("GetDnsInfo failed %s", err)
			globalStatus.UplinkStatus[ix].Error = errStr
			globalStatus.UplinkStatus[ix].ErrorTime = time.Now()
		}

		// Attempt to get a wpad.dat file if so configured
		// Result is updating the Pacfile
		err = CheckAndGetNetworkProxy(&globalStatus,
			&globalStatus.UplinkStatus[ix])
		if err != nil {
			errStr := fmt.Sprintf("GetNetworkProxy failed %s", err)
			globalStatus.UplinkStatus[ix].Error = errStr
			globalStatus.UplinkStatus[ix].ErrorTime = time.Now()
		}
	}
	// Preserve geo info for existing interface and IP address
	for ui, _ := range globalStatus.UplinkStatus {
		u := &globalStatus.UplinkStatus[ui]
		for i, _ := range u.AddrInfoList {
			// Need pointer since we are going to modify
			ai := &u.AddrInfoList[i]
			oai := lookupUplinkStatusAddr(oldStatus,
				u.IfName, ai.Addr)
			if oai == nil {
				continue
			}
			ai.Geo = oai.Geo
			ai.LastGeoTimestamp = oai.LastGeoTimestamp
		}
	}
	// Immediate check
	UpdateDeviceNetworkGeo(time.Second, &globalStatus)
	return globalStatus, err
}

func lookupUplinkStatusAddr(status types.DeviceNetworkStatus,
	ifname string, addr net.IP) *types.AddrInfo {
	for _, u := range status.UplinkStatus {
		if u.IfName != ifname {
			continue
		}
		for _, ai := range u.AddrInfoList {
			if ai.Addr.Equal(addr) {
				return &ai
			}
		}
	}
	return nil
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
				SourceIp: ai.Addr,
			}
			info, err := ipinfo.MyIPWithOptions(opt)
			if err != nil {
				// Ignore error
				log.Infof("UpdateDeviceNetworkGeo MyIPInfo failed %s\n", err)
				continue
			}
			// Note that if the global IP is unchanged we don't
			// update anything.
			if info.IP == ai.Geo.IP {
				continue
			}
			log.Infof("UpdateDeviceNetworkGeo MyIPInfo changed from %v to %v\n",
				ai.Geo, *info)
			ai.Geo = *info
			ai.LastGeoTimestamp = time.Now()
			change = true
		}
	}
	return change
}

func lookupOnIfname(config types.DeviceUplinkConfig, ifname string) *types.NetworkUplinkConfig {
	for _, c := range config.Uplinks {
		if c.IfName == ifname {
			return &c
		}
	}
	return nil
}
