// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/vishvananda/netlink"
)

func LastResortDevicePortConfig(ctx *DeviceNetworkContext, ports []string) types.DevicePortConfig {

	config := makeDevicePortConfig(ctx, ports)
	// Set to higher than all zero but lower than the hardware model derived one above
	config.TimePriority = time.Unix(0, 0)
	return config
}

func makeDevicePortConfig(ctx *DeviceNetworkContext, ports []string) types.DevicePortConfig {
	var config types.DevicePortConfig

	config.Version = types.DPCIsMgmt
	config.Ports = make([]types.NetworkPortConfig, len(ports))
	for ix, u := range ports {
		config.Ports[ix].IfName = u
		config.Ports[ix].Phylabel = u
		config.Ports[ix].Logicallabel = u
		config.Ports[ix].IsMgmt = true
		config.Ports[ix].Dhcp = types.DT_CLIENT
		portPtr := ctx.DevicePortConfig.GetPortByIfName(u)
		if portPtr != nil {
			config.Ports[ix].WirelessCfg = portPtr.WirelessCfg
		}
	}
	return config
}

func IsProxyConfigEmpty(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) == 0 &&
		len(proxyConfig.ProxyCertPEM) == 0 &&
		proxyConfig.Exceptions == "" &&
		proxyConfig.Pacfile == "" &&
		proxyConfig.NetworkProxyEnable == false &&
		proxyConfig.NetworkProxyURL == "" {
		return true
	}
	return false
}

// VerifyDeviceNetworkStatus
//  Check if device can talk to outside world via atleast 'successCount' of the
//  uplinks
// Return Values:
//  Success / Failure
//  error - Overall Error
//  PerInterfaceErrorMap - Key: ifname
//    Includes entries for all interfaces that were tested.
//    For each interface verified
//      set Error ( If success, set to "")
//      set ErrorTime to time of testing ( Even if verify Successful )
func VerifyDeviceNetworkStatus(log *base.LogObject, ctx *DeviceNetworkContext, status types.DeviceNetworkStatus,
	successCount uint, timeout uint32) (bool, types.IntfStatusMap, error) {

	agentName := ctx.AgentName
	iteration := ctx.Iteration
	log.Tracef("VerifyDeviceNetworkStatus() successCount %d, iteration %d",
		successCount, iteration)

	// Map of per-interface errors
	intfStatusMap := *types.NewIntfStatusMap()

	server, err := ioutil.ReadFile(types.ServerFileName)
	if err != nil {
		log.Fatal(err)
	}
	serverNameAndPort := strings.TrimSpace(string(server))
	serverName := strings.Split(serverNameAndPort, ":")[0]

	zedcloudCtx := zedcloud.NewContext(log, zedcloud.ContextOptions{
		DevNetworkStatus: &status,
		Timeout:          timeout,
		AgentMetrics:     ctx.ZedcloudMetrics,
		Serial:           hardware.GetProductSerial(log),
		SoftSerial:       hardware.GetSoftSerial(log),
		AgentName:        agentName,
	})
	log.Functionf("VerifyDeviceNetworkStatus: Use V2 API %v\n", zedcloud.UseV2API())
	testURL := zedcloud.URLPathString(serverNameAndPort, zedcloudCtx.V2API, nilUUID, "ping")

	log.Tracef("NIM Get Device Serial %s, Soft Serial %s\n", zedcloudCtx.DevSerial,
		zedcloudCtx.DevSoftSerial)

	tlsConfig, err := zedcloud.GetTlsConfig(zedcloudCtx.DeviceNetworkStatus, serverName,
		nil, &zedcloudCtx)
	if err != nil {
		log.Functionf("VerifyDeviceNetworkStatus: " +
			"Device certificate not found, looking for Onboarding certificate")

		onboardingCert, err := tls.LoadX509KeyPair(types.OnboardCertName,
			types.OnboardKeyName)
		if err != nil {
			errStr := "Onboarding certificate cannot be found"
			log.Functionf("VerifyDeviceNetworkStatus: %s\n", errStr)
			return false, intfStatusMap, errors.New(errStr)
		}
		clientCert := &onboardingCert
		tlsConfig, err = zedcloud.GetTlsConfig(zedcloudCtx.DeviceNetworkStatus,
			serverName, clientCert, &zedcloudCtx)
		if err != nil {
			errStr := fmt.Sprintf("TLS configuration for talking to Zedcloud cannot be found: %s", err)
			log.Functionf("VerifyDeviceNetworkStatus: %s\n", errStr)
			return false, intfStatusMap, errors.New(errStr)
		}
	}

	if ctx.PrevTLSConfig != nil {
		tlsConfig.ClientSessionCache = ctx.PrevTLSConfig.ClientSessionCache
	}
	zedcloudCtx.TlsConfig = tlsConfig
	for ix := range status.Ports {
		err = CheckAndGetNetworkProxy(ctx, &status, &status.Ports[ix])
		if err != nil {
			ifName := status.Ports[ix].IfName
			errStr := fmt.Sprintf("ifName: %s. Failed to get NetworkProxy. Err:%s",
				ifName, err)
			log.Errorf("VerifyDeviceNetworkStatus: %s", errStr)
			intfStatusMap.RecordFailure(ifName, errStr)
			return false, intfStatusMap, errors.New(errStr)
		}
	}
	cloudReachable, rtf, tempIntfStatusMap, err := zedcloud.VerifyAllIntf(
		&zedcloudCtx, testURL, successCount, iteration)
	intfStatusMap.SetOrUpdateFromMap(tempIntfStatusMap)
	log.Tracef("VerifyDeviceNetworkStatus: intfStatusMap - %+v", intfStatusMap)
	if err != nil {
		if rtf {
			log.Errorf("VerifyDeviceNetworkStatus: VerifyAllIntf remoteTemporaryFailure %s",
				err)
		} else {
			log.Errorf("VerifyDeviceNetworkStatus: VerifyAllIntf failed %s",
				err)
		}
		return rtf, intfStatusMap, err
	}

	ctx.PrevTLSConfig = zedcloudCtx.TlsConfig

	if cloudReachable {
		log.Functionf("Uplink test SUCCESS to URL: %s", testURL)
		return false, intfStatusMap, nil
	}
	errStr := fmt.Sprintf("Uplink test FAIL to URL: %s", testURL)
	log.Errorf("VerifyDeviceNetworkStatus: %s, intfStatusMap: %+v",
		errStr, intfStatusMap)
	return rtf, intfStatusMap, err
}

// Calculate local IP addresses to make a types.DeviceNetworkStatus
func MakeDeviceNetworkStatus(ctx *DeviceNetworkContext, globalConfig types.DevicePortConfig,
	oldStatus types.DeviceNetworkStatus) types.DeviceNetworkStatus {
	var globalStatus types.DeviceNetworkStatus
	log := ctx.Log

	log.Functionf("MakeDeviceNetworkStatus()\n")
	globalStatus.Version = globalConfig.Version
	globalStatus.State = oldStatus.State
	globalStatus.Ports = make([]types.NetworkPortStatus,
		len(globalConfig.Ports))
	for ix, u := range globalConfig.Ports {
		globalStatus.Ports[ix].IfName = u.IfName
		globalStatus.Ports[ix].Phylabel = u.Phylabel
		globalStatus.Ports[ix].Logicallabel = u.Logicallabel
		globalStatus.Ports[ix].Alias = u.Alias
		globalStatus.Ports[ix].IsMgmt = u.IsMgmt
		globalStatus.Ports[ix].Cost = u.Cost
		globalStatus.Ports[ix].ProxyConfig = u.ProxyConfig
		// Set fields from the config...
		globalStatus.Ports[ix].Dhcp = u.Dhcp
		globalStatus.Ports[ix].Type = u.Type
		_, subnet, _ := net.ParseCIDR(u.AddrSubnet)
		if subnet != nil {
			globalStatus.Ports[ix].Subnet = *subnet
		}
		// Start with any statically assigned values; update below
		globalStatus.Ports[ix].DomainName = u.DomainName
		globalStatus.Ports[ix].DNSServers = u.DnsServers

		globalStatus.Ports[ix].NtpServer = u.NtpServer
		globalStatus.Ports[ix].TestResults = u.TestResults
		ifindex, err := IfnameToIndex(log, u.IfName)
		if err != nil {
			errStr := fmt.Sprintf("Port %s does not exist - ignored",
				u.IfName)
			log.Errorf("MakeDeviceNetworkStatus: %s\n", errStr)
			globalStatus.Ports[ix].RecordFailure(errStr)
			continue
		}
		addrs, up, macAddr, err := GetIPAddrs(log, ifindex)
		if err != nil {
			log.Warnf("MakeDeviceNetworkStatus addrs not found %s index %d: %s\n",
				u.IfName, ifindex, err)
			addrs = nil
		}
		globalStatus.Ports[ix].Up = up
		globalStatus.Ports[ix].MacAddr = macAddr.String()
		globalStatus.Ports[ix].AddrInfoList = make([]types.AddrInfo,
			len(addrs))
		if len(addrs) == 0 {
			log.Functionf("PortAddrs(%s) found NO addresses",
				u.IfName)
		}
		for i, addr := range addrs {
			v := "IPv4"
			if addr.To4() == nil {
				v = "IPv6"
			}
			log.Functionf("PortAddrs(%s) found %s %v\n",
				u.IfName, v, addr)
			globalStatus.Ports[ix].AddrInfoList[i].Addr = addr
		}
		// Get DNS etc info from dhcpcd. Updates DomainName and DnsServers
		GetDhcpInfo(log, &globalStatus.Ports[ix])
		GetDNSInfo(log, &globalStatus.Ports[ix])

		// Get used default routers aka gateways from kernel
		globalStatus.Ports[ix].DefaultRouters = getDefaultRouters(log, ifindex)

		// Attempt to get a wpad.dat file if so configured
		// Result is updating the Pacfile
		// We always redo this since we don't know what has changed
		// from the previous DeviceNetworkStatus.
		err = CheckAndGetNetworkProxy(ctx, &globalStatus,
			&globalStatus.Ports[ix])
		if err != nil {
			errStr := fmt.Sprintf("GetNetworkProxy failed for %s: %s",
				u.IfName, err)
			// XXX where can we return this failure?
			// Already have TestResults set from above
			log.Error(errStr)
		}

		// If this is a cellular network connectivity, add status information
		// obtained from the wwan service.
		if u.WirelessCfg.WType == types.WirelessTypeCellular {
			wwanNetStatus, found := ctx.WwanService.Status.LookupNetworkStatus(u.Logicallabel)
			if found {
				globalStatus.Ports[ix].WirelessStatus = types.WirelessStatus{
					WType:    types.WirelessTypeCellular,
					Cellular: wwanNetStatus,
				}
			}
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
	// Need to write resolv.conf for Geo
	UpdateResolvConf(log, globalStatus)
	UpdatePBR(log, globalStatus)
	globalStatus.RadioSilence = ctx.RadioSilence

	log.Functionf("MakeDeviceNetworkStatus() DONE\n")
	return globalStatus
}

// CheckDNSUpdate sees if we should update based on DNS
// XXX identical code to HandleAddressChange
func CheckDNSUpdate(ctx *DeviceNetworkContext) {

	log := ctx.Log
	// Check if we have more or less addresses
	var dnStatus types.DeviceNetworkStatus

	log.Functionf("CheckDnsUpdate Pending.Inprogress %v",
		ctx.Pending.Inprogress)
	if !ctx.Pending.Inprogress {
		dnStatus = *ctx.DeviceNetworkStatus
		status := MakeDeviceNetworkStatus(ctx, *ctx.DevicePortConfig,
			dnStatus)

		if !reflect.DeepEqual(*ctx.DeviceNetworkStatus, status) {
			log.Functionf("CheckDNSUpdate: change from %v to %v\n",
				*ctx.DeviceNetworkStatus, status)
			*ctx.DeviceNetworkStatus = status
			DoDNSUpdate(ctx)
		} else {
			log.Functionf("CheckDNSUpdate: No change\n")
		}
	} else {
		dnStatus = MakeDeviceNetworkStatus(ctx, *ctx.DevicePortConfig,
			ctx.Pending.PendDNS)

		if !reflect.DeepEqual(ctx.Pending.PendDNS, dnStatus) {
			log.Functionf("CheckDNSUpdate pending: change from %v to %v\n",
				ctx.Pending.PendDNS, dnStatus)
			pingTestDNS := checkIfMgmtPortsHaveIPandDNS(log, dnStatus)
			if pingTestDNS {
				// We have a suitable candiate for running our cloud ping test.
				log.Functionf("CheckDNSUpdate: Running cloud ping test now, " +
					"Since we have suitable addresses already.")
				VerifyDevicePortConfig(ctx)
			}
		} else {
			log.Functionf("CheckDNSUpdate pending: No change\n")
		}
	}
}

// GetIPAddrs return all IP addresses for an ifindex, and updates the cached info.
// Also returns the up flag (based on admin status), and hardware address.
// Leaves mask uninitialized
// It replaces what is in the Ifindex cache since AddrChange callbacks
// are far from reliable.
// If AddrChange worked reliably this would just be:
// return IfindexToAddrs(ifindex)
func GetIPAddrs(log *base.LogObject, ifindex int) ([]net.IP, bool, net.HardwareAddr, error) {

	var addrs []net.IP
	var up bool
	var macAddr net.HardwareAddr

	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		err = errors.New(fmt.Sprintf("Port in config/global does not exist: %d",
			ifindex))
		return addrs, up, macAddr, err
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
	attrs := link.Attrs()
	up = (attrs.Flags & net.FlagUp) != 0
	if attrs.HardwareAddr != nil {
		macAddr = attrs.HardwareAddr
	}

	log.Functionf("GetIPAddrs(%d) found %v and %v", ifindex, addrs4, addrs6)
	IfindexToAddrsFlush(log, ifindex)
	for _, a := range addrs4 {
		if a.IP == nil {
			continue
		}
		addrs = append(addrs, a.IP)
		IfindexToAddrsAdd(log, ifindex, a.IP)
	}
	for _, a := range addrs6 {
		if a.IP == nil {
			continue
		}
		addrs = append(addrs, a.IP)
		IfindexToAddrsAdd(log, ifindex, a.IP)
	}
	return addrs, up, macAddr, nil

}

// getDefaultRouters retries the default routers from the kernel i.e.,
// the ones actually in use whether from DHCP or static
func getDefaultRouters(log *base.LogObject, ifindex int) []net.IP {
	var res []net.IP
	table := types.GetDefaultRouteTable()
	// Note that a default route is represented as nil Dst
	filter := netlink.Route{Table: table, LinkIndex: ifindex, Dst: nil}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	fflags |= netlink.RT_FILTER_DST
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Errorf("getDefaultRouters: for ifindex %d RouteList failed: %v",
			ifindex, err)
		return res
	}
	// log.Tracef("getDefaultRouters(%s) - got %d", ifname, len(routes))
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		// log.Tracef("getDefaultRouters route dest %v", rt.Dst)
		res = append(res, rt.Gw)
	}
	return res
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
func UpdateDeviceNetworkGeo(log *base.LogObject, timelimit time.Duration, globalStatus *types.DeviceNetworkStatus) bool {
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

			numDNSServers := types.CountDNSServers(*globalStatus, u.IfName)
			if numDNSServers == 0 {
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
				log.Functionf("UpdateDeviceNetworkGeo MyIPInfo failed %s\n", err)
				continue
			}
			// Note that if the global IP is unchanged we don't
			// update anything.
			if info.IP == ai.Geo.IP {
				continue
			}
			log.Functionf("UpdateDeviceNetworkGeo MyIPInfo changed from %v to %v\n",
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
