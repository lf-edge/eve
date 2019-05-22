// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/eriknordmark/ipinfo"
	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// Generate DevicePortConfig based on DeviceNetworkConfig
// XXX retire when we have retired DeviceNetworkConfig
func MakeDevicePortConfig(globalConfig types.DeviceNetworkConfig) types.DevicePortConfig {

	config := makeDevicePortConfig(globalConfig.Uplink, globalConfig.FreeUplinks)
	// Set to higher than all zero.
	config.TimePriority = time.Unix(2, 0)
	return config
}

func LastResortDevicePortConfig(ports []string) types.DevicePortConfig {

	config := makeDevicePortConfig(ports, ports)
	// Set to higher than all zero but lower than the hardware model derived one above
	config.TimePriority = time.Unix(0, 0)
	return config
}

func makeDevicePortConfig(ports []string, free []string) types.DevicePortConfig {
	var config types.DevicePortConfig

	config.Version = types.DPCIsMgmt
	config.Ports = make([]types.NetworkPortConfig, len(ports))
	for ix, u := range ports {
		config.Ports[ix].IfName = u
		for _, f := range free {
			if f == u {
				config.Ports[ix].Free = true
				break
			}
		}
		config.Ports[ix].IsMgmt = true
		config.Ports[ix].Name = config.Ports[ix].IfName
		config.Ports[ix].Dhcp = types.DT_CLIENT
	}
	return config
}

func IsProxyConfigEmpty(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) == 0 &&
		proxyConfig.Exceptions == "" &&
		proxyConfig.Pacfile == "" &&
		proxyConfig.NetworkProxyEnable == false &&
		proxyConfig.NetworkProxyURL == "" {
		return true
	}
	return false
}

// Check if device can talk to outside world via atleast one of the free uplinks
func VerifyDeviceNetworkStatus(status types.DeviceNetworkStatus,
	retryCount int) (bool, error) {

	log.Infof("VerifyDeviceNetworkStatus() %d\n", retryCount)
	// Check if it is 1970 in which case we declare success since
	// our certificates will not work until NTP has brought the time
	// forward.
	if time.Now().Year() == 1970 {
		log.Infof("VerifyDeviceNetworkStatus skip due to 1970")
		return false, nil
	}

	serverFileName := "/config/server"
	server, err := ioutil.ReadFile(serverFileName)
	if err != nil {
		log.Fatal(err)
	}
	serverNameAndPort := strings.TrimSpace(string(server))
	serverName := strings.Split(serverNameAndPort, ":")[0]
	testUrl := serverNameAndPort + "/api/v1/edgedevice/ping"

	zedcloudCtx := zedcloud.ZedCloudContext{
		DeviceNetworkStatus: &status,
	}
	tlsConfig, err := zedcloud.GetTlsConfig(serverName, nil)
	if err != nil {
		log.Infof("VerifyDeviceNetworkStatus: " +
			"Device certificate not found, looking for Onboarding certificate")

		identityDirname := "/config"
		onboardingCertName := identityDirname + "/onboard.cert.pem"
		onboardingKeyName := identityDirname + "/onboard.key.pem"
		onboardingCert, err := tls.LoadX509KeyPair(onboardingCertName,
			onboardingKeyName)
		if err != nil {
			errStr := "Onboarding certificate cannot be found"
			log.Infof("VerifyDeviceNetworkStatus: %s\n", errStr)
			return false, errors.New(errStr)
		}
		clientCert := &onboardingCert
		tlsConfig, err = zedcloud.GetTlsConfig(serverName, clientCert)
		if err != nil {
			errStr := "TLS configuration for talking to Zedcloud cannot be found"

			log.Infof("VerifyDeviceNetworkStatus: %s\n", errStr)
			return false, errors.New(errStr)
		}
	}
	zedcloudCtx.TlsConfig = tlsConfig
	for ix := range status.Ports {
		err = CheckAndGetNetworkProxy(&status, &status.Ports[ix])
		if err != nil {
			errStr := fmt.Sprintf("GetNetworkProxy failed %s", err)
			log.Errorf("VerifyDeviceNetworkStatus: %s\n", errStr)
			return false, errors.New(errStr)
		}
	}
	cloudReachable, cf, err := zedcloud.VerifyAllIntf(zedcloudCtx, testUrl, retryCount, 1)
	if err != nil {
		log.Errorf("VerifyDeviceNetworkStatus: VerifyAllIntf failed %s\n",
			err)
		if cf {
			log.Errorf("VerifyDeviceNetworkStatus: VerifyAllIntf certificate failure")
		}
		return cf, err
	}

	if cloudReachable {
		log.Infof("Uplink test SUCCESS to URL: %s", testUrl)
		return cf, nil
	}
	errStr := fmt.Sprintf("Uplink test FAIL to URL: %s", testUrl)
	log.Errorf("VerifyDeviceNetworkStatus: %s\n", errStr)
	return cf, errors.New(errStr)
}

// Calculate local IP addresses to make a types.DeviceNetworkStatus
func MakeDeviceNetworkStatus(globalConfig types.DevicePortConfig, oldStatus types.DeviceNetworkStatus) (types.DeviceNetworkStatus, error) {
	var globalStatus types.DeviceNetworkStatus
	var err error = nil

	log.Infof("MakeDeviceNetworkStatus()\n")
	globalStatus.Version = globalConfig.Version
	globalStatus.Ports = make([]types.NetworkPortStatus,
		len(globalConfig.Ports))
	for ix, u := range globalConfig.Ports {
		globalStatus.Ports[ix].IfName = u.IfName
		globalStatus.Ports[ix].Name = u.Name
		globalStatus.Ports[ix].IsMgmt = u.IsMgmt
		globalStatus.Ports[ix].Free = u.Free
		globalStatus.Ports[ix].ProxyConfig = u.ProxyConfig
		// Set fields from the config...
		globalStatus.Ports[ix].Dhcp = u.Dhcp
		_, subnet, _ := net.ParseCIDR(u.AddrSubnet)
		if subnet != nil {
			globalStatus.Ports[ix].Subnet = *subnet
		}
		globalStatus.Ports[ix].Gateway = u.Gateway
		globalStatus.Ports[ix].DomainName = u.DomainName
		globalStatus.Ports[ix].NtpServer = u.NtpServer
		globalStatus.Ports[ix].DnsServers = u.DnsServers
		ifindex, err := IfnameToIndex(u.IfName)
		if err != nil {
			errStr := fmt.Sprintf("Port %s does not exist - ignored",
				u.IfName)
			log.Errorf("MakeDeviceNetworkStatus: %s\n", errStr)
			err = errors.New(errStr)
			continue
		}
		addrs, err := getAddrs(ifindex)
		if err != nil {
			log.Warnf("MakeDeviceNetworkStatus addrs not found %s index %d: %s\n",
				u.IfName, ifindex, err)
			addrs = nil
		}
		globalStatus.Ports[ix].AddrInfoList = make([]types.AddrInfo,
			len(addrs))
		for i, addr := range addrs {
			v := "IPv4"
			if addr.IP.To4() == nil {
				v = "IPv6"
			}
			log.Infof("PortAddrs(%s) found %s %v\n",
				u.IfName, v, addr.IP)
			globalStatus.Ports[ix].AddrInfoList[i].Addr = addr.IP
		}
		// Get DNS etc info from dhcpcd. Updates DomainName and DnsServers
		err = GetDhcpInfo(&globalStatus.Ports[ix])
		if err != nil {
			errStr := fmt.Sprintf("GetDhcpInfo failed %s", err)
			globalStatus.Ports[ix].Error = errStr
			globalStatus.Ports[ix].ErrorTime = time.Now()
		}

		// Attempt to get a wpad.dat file if so configured
		// Result is updating the Pacfile
		// We always redo this since we don't know what has changed
		// from the previous DeviceNetworkStatus.
		err = CheckAndGetNetworkProxy(&globalStatus,
			&globalStatus.Ports[ix])
		if err != nil {
			errStr := fmt.Sprintf("GetNetworkProxy failed %s", err)
			globalStatus.Ports[ix].Error = errStr
			globalStatus.Ports[ix].ErrorTime = time.Now()
		}
	}
	// Preserve geo info for existing interface and IP address
	for ui := range globalStatus.Ports {
		u := &globalStatus.Ports[ui]
		for i := range u.AddrInfoList {
			// Need pointer since we are going to modify
			ai := &u.AddrInfoList[i]
			oai := lookupPortStatusAddr(oldStatus,
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
	log.Infof("MakeDeviceNetworkStatus() DONE\n")
	return globalStatus, err
}

// Return all IP addresses for an ifindex
// Leaves mask uninitialized
// Also replaces what is in the Ifindex cache since AddrChange callbacks
// are far from reliable.
// If AddrChange worked reliably this would just be:
// return IfindexToAddrs(ifindex)
func getAddrs(ifindex int) ([]net.IPNet, error) {

	var addrs []net.IPNet

	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		err = errors.New(fmt.Sprintf("Port in config/global does not exist: %d",
			ifindex))
		return addrs, err
	}
	addrs4, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.Warnf("netlink.AddrList %d V4 failed: %s", ifindex, err)
		addrs4 = nil
	}
	addrs6, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		log.Warnf("netlink.AddrList %d V4 failed: %s", ifindex, err)
		addrs6 = nil
	}
	IfindexToAddrsFlush(ifindex)
	for _, a := range addrs4 {
		if a.IP == nil {
			continue
		}
		ip := net.IPNet{IP: a.IP}
		addrs = append(addrs, ip)
		IfindexToAddrsAdd(ifindex, ip)
	}
	for _, a := range addrs6 {
		if a.IP == nil {
			continue
		}
		ip := net.IPNet{IP: a.IP}
		addrs = append(addrs, ip)
		IfindexToAddrsAdd(ifindex, ip)
	}
	return addrs, nil

}

func lookupPortStatusAddr(status types.DeviceNetworkStatus,
	ifname string, addr net.IP) *types.AddrInfo {

	for _, u := range status.Ports {
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
	for ui := range globalStatus.Ports {
		u := &globalStatus.Ports[ui]
		if globalStatus.Version >= types.DPCIsMgmt &&
			!u.IsMgmt {
			continue
		}
		for i := range u.AddrInfoList {
			// Need pointer since we are going to modify
			ai := &u.AddrInfoList[i]
			if ai.Addr.IsLinkLocalUnicast() {
				continue
			}

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

func lookupOnIfname(config types.DevicePortConfig, ifname string) *types.NetworkPortConfig {
	for _, c := range config.Ports {
		if c.IfName == ifname {
			return &c
		}
	}
	return nil
}
