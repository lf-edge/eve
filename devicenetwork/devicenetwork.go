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
	//"github.com/zededa/go-provision/zedpac"
	"net"
	"net/url"
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

	globalStatus.UplinkStatus = make([]types.NetworkUplink,
		len(globalConfig.Uplinks))
	for ix, u := range globalConfig.Uplinks {
		globalStatus.UplinkStatus[ix].IfName = u.IfName
		globalStatus.UplinkStatus[ix].Free = u.Free
		globalStatus.UplinkStatus[ix].ProxyConfig = u.ProxyConfig
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
		// Get DNS info from dhcpcd
		// XXX put error in status? Local only error so ignore?
		GetDnsInfo(&globalStatus.UplinkStatus[ix])

		// Attempt to get a wpad.dat file if so configured
		// Result is updating the Pacfile
		// XXX put error in status?
		CheckAndGetNetworkProxy(&globalStatus,
			&globalStatus.UplinkStatus[ix])
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

func LookupProxy(
	status *types.DeviceNetworkStatus, ifname string, rawUrl string) (*url.URL, error) {
	//(types.ProxyEntry, types.NetworkProxyType, bool) {
	for _, uplink := range status.UplinkStatus {
		log.Debugf("LookupProxy: Looking for proxy config on Uplink %s", uplink.IfName)
		if uplink.IfName != ifname {
			continue
		}
		log.Debugf("LookupProxy: Uplink configuration found for %s", ifname)
		proxyConfig := uplink.ProxyConfig

		// Check if the URL is present in exception list
		// XXX Should we just get the domain name part of URL and compare?
		// XXX Doing the domain portion comparison for now.
		// Parse url and find the host domain part
		u, err := url.Parse(rawUrl)
		if err != nil {
			errStr := fmt.Sprintf("LookupProxy: malformed URL %s", rawUrl)
			log.Errorf(errStr)
			return nil, errors.New(errStr)
		}

		/*
		// Check if we have a PAC file
		if len(proxyConfig.Pacfile) > 0 {
			pacFile, err := base64.StdEncoding.DecodeString(proxyConfig.Pacfile)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: Decoding proxy file failed: %s", err)
				log.Errorf(errStr)
				return nil, errors.New(errStr)
			}
			proxyString, err := zedpac.Find_proxy_sync(
				string(pacFile), rawUrl, u.Host)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: PAC file could not find proxy for %s: %s",
					rawUrl, err)
				log.Errorf(errStr)
				return nil, errors.New(errStr)
			}
			//if proxyString == "DIRECT" {
			if strings.HasPrefix(proxyString, "DIRECT") {
				return nil, nil
			}
			proxies := strings.Split(proxyString, ";")
			if len(proxies) == 0 {
				log.Errorf("LookupProxy: Number of proxies in PAC file result is Zero")
				return nil, nil
			}

			// XXX Take the first proxy for now. Failing over to the next
			// proxy should be implemented
			proxy0 := proxies[0]
			proxy0 = strings.Split(proxy0, " ")[1]
			// Proxy address returned by PAC does not have the URL scheme.
			// We prepend the scheme (http/https) of the incoming raw URL.
			if len(u.Scheme) == 0 {
				proxy0 = "http://" + proxy0
			} else {
				proxy0 = u.Scheme + "://" + proxy0
			}
			proxy, err := url.Parse(proxy0)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: PAC file returned invalid proxy %s: %s",
					proxyString, err)
				log.Errorf(errStr)
				return nil, errors.New(errStr)
			}
			log.Debugf("LookupProxy: PAC proxy being used is %s", proxy0)
			return proxy, err
		}
		*/

		config := &Config{}
		for _, proxy := range proxyConfig.Proxies {
			switch proxy.Type {
			case types.NPT_HTTP:
				var httpProxy string
				if proxy.Port > 0 {
					httpProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpProxy = fmt.Sprintf("%s", proxy.Server)
				}
				config.HTTPProxy = httpProxy
				log.Debugf("LookupProxy: Adding HTTP proxy %s for uplink %s",
					config.HTTPProxy, ifname)
			case types.NPT_HTTPS:
				var httpsProxy string
				if proxy.Port > 0 {
					httpsProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpsProxy = fmt.Sprintf("%s", proxy.Server)
				}
				config.HTTPSProxy = httpsProxy
				log.Debugf("LookupProxy: Adding HTTPS proxy %s for uplink %s",
					config.HTTPSProxy, ifname)
			default:
				// XXX We should take care of Socks proxy, FTP proxy also in future
			}
		}
		config.NoProxy = proxyConfig.Exceptions
		proxyFunc := config.ProxyFunc()
		proxy, err := proxyFunc(u)
		if err != nil {
			errStr := fmt.Sprintf("LookupProxy: proxyFunc error: %s", err)
			log.Errorf(errStr)
			return proxy, errors.New(errStr)
		}
		return proxy, err
	}
	log.Infof("LookupProxy: No proxy configured for uplink %s", ifname)
	return nil, nil
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

