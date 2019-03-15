// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/eriknordmark/ipinfo"
	"github.com/eriknordmark/netlink"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

// Generate DevicePortConfig based on DeviceNetworkConfig
// XXX retire when we have retired DeviceNetworkConfig
func MakeDevicePortConfig(globalConfig types.DeviceNetworkConfig) types.DevicePortConfig {
	var config types.DevicePortConfig

	config.Version = types.DPCIsMgmt
	config.Ports = make([]types.NetworkPortConfig,
		len(globalConfig.Uplink))
	for ix, u := range globalConfig.Uplink {
		config.Ports[ix].IfName = u
		for _, f := range globalConfig.FreeUplinks {
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
	retryCount int) error {

	log.Infof("VerifyDeviceNetworkStatus() %d\n", retryCount)

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
			return errors.New(errStr)
		}
		clientCert := &onboardingCert
		tlsConfig, err = zedcloud.GetTlsConfig(serverName, clientCert)
		if err != nil {
			errStr := "TLS configuration for talking to Zedcloud cannot be found"

			log.Infof("VerifyDeviceNetworkStatus: %s\n", errStr)
			return errors.New(errStr)
		}
	}
	zedcloudCtx.TlsConfig = tlsConfig
	for ix, _ := range status.Ports {
		err = CheckAndGetNetworkProxy(&status, &status.Ports[ix])
		if err != nil {
			errStr := fmt.Sprintf("GetNetworkProxy failed %s", err)
			log.Errorf("VerifyDeviceNetworkStatus: %s\n", errStr)
			return errors.New(errStr)
		}
	}
	cloudReachable, err := zedcloud.VerifyAllIntf(zedcloudCtx, testUrl, retryCount, 1)
	if err != nil {
		log.Errorf("VerifyDeviceNetworkStatus: VerifyAllIntf failed %s\n",
			err)
		return err
	}

	if cloudReachable {
		log.Infof("Uplink test SUCCESS to URL: %s", testUrl)
		return nil
	}
	errStr := fmt.Sprintf("Uplink test FAIL to URL: %s", testUrl)
	log.Errorf("VerifyDeviceNetworkStatus: %s\n", errStr)
	return errors.New(errStr)
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
		// XXX check against local IfindexToAddrs() - need ifindex for
		// that. XXX remove old code?
		ifindex, err := IfnameToIndex(u.IfName)
		numAddrs := 0
		var addrs []net.IPNet
		if err == nil {
			addrs, err = IfindexToAddrs(ifindex)
			if err == nil {
				numAddrs = len(addrs)
				log.Infof("MakeDeviceNetworkStatus %s found %d addrs %+v\n",
					u.IfName, len(addrs), addrs)
			} else {
				log.Warnf("MakeDeviceNetworkStatus addrs not found %s index %d: %s\n",
					u.IfName, ifindex, err)
			}
		} else {
			log.Warnf("MakeDeviceNetworkStatus ifindex not found %s: %s\n",
				u.IfName, err)
		}

		link, err := netlink.LinkByName(u.IfName)
		if err != nil {
			log.Warnf("MakeDeviceNetworkStatus LinkByName %s: %s\n",
				u.IfName, err)
			err = errors.New(fmt.Sprintf("Port in config/global does not exist: %v",
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
		if numAddrs != len(addrs4)+len(addrs6) {
			log.Warnf("MakeDeviceNetworkStatus len mismatch %d %d %d\n",
				numAddrs, len(addrs4), len(addrs6))
			log.Warnf("MakeDeviceNetworkStatus mismatch %v %v %v\n",
				addrs, addrs4, addrs6)
		} else {
			log.Infof("MakeDeviceNetworkStatus len match %d %d %d\n",
				numAddrs, len(addrs4), len(addrs6))
			log.Infof("MakeDeviceNetworkStatus match %v %v %v\n",
				addrs, addrs4, addrs6)
		}
		// XXX log only for now ... then assign
		for _, addr := range addrs {
			v := "IPv4"
			if addr.IP.To4() == nil {
				v = "IPv6"
			}
			log.Infof("PortAddrs(%s) found %s %v\n",
				v, u.IfName, addr.IP)
		}
		globalStatus.Ports[ix].AddrInfoList = make([]types.AddrInfo,
			len(addrs4)+len(addrs6))
		for i, addr := range addrs4 {
			log.Infof("PortAddrs(%s) found IPv4 %v\n",
				u.IfName, addr.IP)
			globalStatus.Ports[ix].AddrInfoList[i].Addr = addr.IP
		}
		for i, addr := range addrs6 {
			// We include link-locals since they can be used for LISP behind nats
			log.Infof("PortAddrs(%s) found IPv6 %v\n",
				u.IfName, addr.IP)
			globalStatus.Ports[ix].AddrInfoList[i+len(addrs4)].Addr = addr.IP
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
	for ui, _ := range globalStatus.Ports {
		u := &globalStatus.Ports[ui]
		for i, _ := range u.AddrInfoList {
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
	for ui, _ := range globalStatus.Ports {
		u := &globalStatus.Ports[ui]
		if globalStatus.Version >= types.DPCIsMgmt &&
			!u.IsMgmt {
			continue
		}
		for i, _ := range u.AddrInfoList {
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
