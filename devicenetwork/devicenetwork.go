// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"errors"
	"fmt"
	"github.com/eriknordmark/ipinfo"
	"github.com/vishvananda/netlink"
	"github.com/zededa/go-provision/types"
	"log"
	"net"
	"os"
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

// Calculate local IP addresses to make a types.DeviceNetworkStatus
func MakeDeviceNetworkStatus(globalConfig types.DeviceUplinkConfig, oldStatus types.DeviceNetworkStatus) (types.DeviceNetworkStatus, error) {
	var globalStatus types.DeviceNetworkStatus
	var err error = nil

	// Copy proxy settings
	globalStatus.ProxyConfig = globalConfig.ProxyConfig
	// Apply proxy before we do geolocation calls
	ProxyToEnv(globalStatus.ProxyConfig)

	globalStatus.UplinkStatus = make([]types.NetworkUplink,
		len(globalConfig.Uplinks))
	for ix, u := range globalConfig.Uplinks {
		globalStatus.UplinkStatus[ix].IfName = u.IfName
		globalStatus.UplinkStatus[ix].Free = u.Free
		// XXX should we get statics?
		link, err := netlink.LinkByName(u.IfName)
		if err != nil {
			log.Printf("MakeDeviceNetworkStatus LinkByName %s: %s\n", u.IfName, err)
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
				u.IfName, addr.IP)
			globalStatus.UplinkStatus[ix].AddrInfoList[i].Addr = addr.IP
		}
		for i, addr := range addrs6 {
			// We include link-locals since they can be used for LISP behind nats
			log.Printf("UplinkAddrs(%s) found IPv6 %v\n",
				u.IfName, addr.IP)
			globalStatus.UplinkStatus[ix].AddrInfoList[i+len(addrs4)].Addr = addr.IP
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

func lookupOnIfname(config types.DeviceUplinkConfig, ifname string) *types.NetworkUplinkConfig {
	for _, c := range config.Uplinks {
		if c.IfName == ifname {
			return &c
		}
	}
	return nil
}

func IsUplink(config types.DeviceUplinkConfig, ifname string) bool {
	return lookupOnIfname(config, ifname) != nil
}

func IsFreeUplink(config types.DeviceUplinkConfig, ifname string) bool {
	c := lookupOnIfname(config, ifname)
	return c != nil && c.Free
}

func GetUplinks(config types.DeviceUplinkConfig) []string {
	var result []string
	for _, c := range config.Uplinks {
		result = append(result, c.IfName)
	}
	return result
}

func GetFreeUplinks(config types.DeviceUplinkConfig) []string {
	var result []string
	for _, c := range config.Uplinks {
		if c.Free {
			result = append(result, c.IfName)
		}
	}
	return result
}

func ProxyToEnv(config types.ProxyConfig) {
	log.Printf("ProxyToEnv: %s, %s, %s, %s\n",
		config.HttpsProxy, config.HttpProxy, config.FtpProxy,
		config.NoProxy)
	if config.HttpsProxy == "" {
		os.Unsetenv("HTTPS_PROXY")
	} else {
		os.Setenv("HTTPS_PROXY", config.HttpsProxy)
	}
	if config.HttpProxy == "" {
		os.Unsetenv("HTTP_PROXY")
	} else {
		os.Setenv("HTTP_PROXY", config.HttpProxy)
	}
	if config.FtpProxy == "" {
		os.Unsetenv("FTP_PROXY")
	} else {
		os.Setenv("FTP_PROXY", config.FtpProxy)
	}
	if config.SocksProxy == "" {
		os.Unsetenv("SOCKS_PROXY")
	} else {
		os.Setenv("SOCKS_PROXY", config.SocksProxy)
	}
	if config.NoProxy == "" {
		os.Unsetenv("NO_PROXY")
	} else {
		os.Setenv("NO_PROXY", config.NoProxy)
	}
}
