// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/ssh"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	MaxBaseOsCount       = 2
	BaseOsImageCount     = 1
	rebootConfigFilename = configDir + "/rebootConfig"
)

var rebootDelay int = 30 // take a 30 second delay
var rebootTimer *time.Timer

// Returns a rebootFlag
func parseConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext,
	usingSaved bool) bool {

	// XXX can this happen when usingSaved is set?
	if parseOpCmds(config, getconfigCtx) {
		log.Infoln("Reboot flag set, skipping config processing")
		// Make sure we tell apps to shut down
		shutdownApps(getconfigCtx)
		return true
	}
	ctx := getconfigCtx.zedagentCtx

	// updating/rebooting, ignore config??
	if isBaseOsOtherPartitionStateUpdating(ctx) {
		log.Infoln("OtherPartitionStatusUpdating - setting rebootFlag")
		// Make sure we tell apps to shut down
		shutdownApps(getconfigCtx)
		getconfigCtx.rebootFlag = true
	}

	// If the other partition is inprogress it means update failed
	// We leave in inprogress state so logmanager can use it to decide
	// to upload the other logs. If a different BaseOsVersion is provided
	// we allow it to be installed into the inprogress partition.
	if isBaseOsOtherPartitionStateInProgress(ctx) {
		otherPart := getZbootOtherPartition(ctx)
		log.Errorf("Other %s partition contains failed update\n",
			otherPart)
	}

	// Look for timers and other settings in configItems
	parseConfigItems(config, getconfigCtx)
	parseDatastoreConfig(config, getconfigCtx)

	// XXX Deprecated but used for systemAdapters
	//	parseNetworkXObjectConfig
	parseNetworkXObjectConfig(config, getconfigCtx)

	parseSystemAdapterConfig(config, getconfigCtx, false)

	parseBaseOsConfig(getconfigCtx, config)

	parseNetworkInstanceConfig(config, getconfigCtx)
	parseAppInstanceConfig(config, getconfigCtx)

	return false
}

// Walk published AppInstanceConfig's and set Activate=false
// Note that we don't currently wait for the shutdown to complete.
func shutdownApps(getconfigCtx *getconfigContext) {
	pub := getconfigCtx.pubAppInstanceConfig
	items := pub.GetAll()
	for key, c := range items {
		config := cast.CastAppInstanceConfig(c)
		if config.Key() != key {
			log.Errorf("shutdownApps key/UUID mismatch %s vs %s; ignored %+v\n",
				key, config.Key(), config)
			continue
		}
		if config.Activate {
			log.Infof("shutdownApps: clearing Activate for %s uuid %s\n",
				config.DisplayName, config.Key())
			config.Activate = false
			pub.Publish(config.Key(), config)
		}
	}
}

func shutdownAppsGlobal(ctx *zedagentContext) {
	shutdownApps(ctx.getconfigCtx)
}

var baseosPrevConfigHash []byte

func parseBaseOsConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	cfgOsList := config.GetBase()
	h := sha256.New()
	for _, os := range cfgOsList {
		computeConfigElementSha(h, os)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, baseosPrevConfigHash)
	baseosPrevConfigHash = configHash
	if same {
		log.Debugf("parseBaseOsConfig: baseos sha is unchanged: % x\n",
			configHash)
		return
	}
	log.Infof("parseBaseOsConfig: Applying updated config sha % x vs. % x: %v\n",
		baseosPrevConfigHash, configHash, cfgOsList)

	baseOsCount := len(cfgOsList)
	if baseOsCount == 0 {
		return
	}
	if !zboot.IsAvailable() {
		log.Errorf("No zboot; ignoring baseOsConfig\n")
		return
	}

	// First look for deleted ones
	items := getconfigCtx.pubBaseOsConfig.GetAll()
	for uuidStr := range items {
		found := false
		for _, baseOs := range cfgOsList {
			if baseOs.Uuidandversion.Uuid == uuidStr {
				found = true
				break
			}
		}
		// baseOS instance not found, delete
		if !found {
			log.Infof("parseBaseOsConfig: deleting %s\n", uuidStr)
			getconfigCtx.pubBaseOsConfig.Unpublish(uuidStr)

			unpublishCertObjConfig(getconfigCtx, uuidStr)
		}
	}

	for _, cfgOs := range cfgOsList {
		if cfgOs.GetBaseOSVersion() == "" {
			// Empty slot - silently ignore
			log.Debugf("parseBaseOsConfig ignoring empty %s\n",
				cfgOs.Uuidandversion.Uuid)
			continue
		}
		baseOs := new(types.BaseOsConfig)

		baseOs.UUIDandVersion.UUID, _ = uuid.FromString(cfgOs.Uuidandversion.Uuid)
		baseOs.UUIDandVersion.Version = cfgOs.Uuidandversion.Version

		baseOs.Activate = cfgOs.GetActivate()
		baseOs.BaseOsVersion = cfgOs.GetBaseOSVersion()

		cfgOsDetails := cfgOs.GetBaseOSDetails()
		cfgOsParamList := cfgOsDetails.GetBaseOSParams()

		for jdx, cfgOsDetail := range cfgOsParamList {
			param := new(types.OsVerParams)
			param.OSVerKey = cfgOsDetail.GetOSVerKey()
			param.OSVerValue = cfgOsDetail.GetOSVerValue()
			baseOs.OsParams[jdx] = *param
		}

		baseOs.StorageConfigList = make([]types.StorageConfig,
			len(cfgOs.Drives))
		parseStorageConfigList(baseOsObj, baseOs.StorageConfigList,
			cfgOs.Drives)

		certInstance := getCertObjects(baseOs.UUIDandVersion,
			baseOs.ConfigSha256, baseOs.StorageConfigList)
		log.Debugf("parseBaseOsConfig publishing %v\n",
			baseOs)
		publishBaseOsConfig(getconfigCtx, baseOs)
		if certInstance != nil {
			publishCertObjConfig(getconfigCtx, certInstance,
				baseOs.Key())
		}
	}
}

func lookupBaseOsConfigPub(getconfigCtx *getconfigContext, key string) *types.BaseOsConfig {

	pub := getconfigCtx.pubBaseOsConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Infof("lookupBaseOsConfig(%s) not found\n", key)
		return nil
	}
	config := cast.CastBaseOsConfig(c)
	if config.Key() != key {
		log.Errorf("lookupBaseOsConfig(%s) got %s; ignored %+v\n",
			key, config.Key(), config)
		return nil
	}
	return &config
}

var networkConfigPrevConfigHash []byte

func parseNetworkXObjectConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) {

	h := sha256.New()
	nets := config.GetNetworks()
	for _, n := range nets {
		computeConfigElementSha(h, n)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, networkConfigPrevConfigHash)
	networkConfigPrevConfigHash = configHash
	if same {
		log.Debugf("parseNetworkXObjectConfig: network sha is unchanged: % x\n",
			configHash)
		return
	}
	log.Infof("parseNetworkXObjectConfig: Applying updated config sha % x vs. % x: %v\n",
		networkConfigPrevConfigHash, configHash, nets)
	// Export NetworkXObjectConfig for ourselves; systemAdapter
	// XXX
	// System Adapter points to network for Proxy configuration.
	// There could be a situation where networks change, but
	// systerm adapters do not change. When we see the networks
	// change, we should parse systerm adapters again.
	publishNetworkXObjectConfig(getconfigCtx, nets)
	parseSystemAdapterConfig(config, getconfigCtx, true)
}

func unpublishDeletedNetworkInstanceConfig(ctx *getconfigContext,
	networkInstances []*zconfig.NetworkInstanceConfig) {

	currentEntries := ctx.pubNetworkInstanceConfig.GetAll()
	for key, entry := range currentEntries {
		networkInstanceEntry := lookupNetworkInstanceById(key, networkInstances)
		if networkInstanceEntry != nil {
			// Entry not deleted.
			log.Infof("NetworkInstance %s (Name: %s) still exists\n",
				key, networkInstanceEntry.Displayname)
			continue
		}

		config := cast.CastNetworkInstanceConfig(entry)
		log.Infof("unpublishing NetworkInstance %s (Name: %s) \n",
			key, config.DisplayName)
		if err := ctx.pubNetworkInstanceConfig.Unpublish(key); err != nil {
			log.Fatalf("Network Instance UnPublish (key:%s, name:%s) FAILED: %s",
				key, config.DisplayName, err)
		}
	}
}

func parseDnsNameToIpList(
	apiConfigEntry *zconfig.NetworkInstanceConfig,
	config *types.NetworkInstanceConfig) {

	// Parse and store DnsNameToIPList form Network configuration
	dnsEntries := apiConfigEntry.GetDns()

	// Parse and populate the DnsNameToIP list
	// This is what we will publish to zedrouter
	nameToIPs := []types.DnsNameToIP{}
	for _, dnsEntry := range dnsEntries {
		hostName := dnsEntry.HostName

		ips := []net.IP{}
		for _, strAddr := range dnsEntry.Address {
			ip := net.ParseIP(strAddr)
			if ip != nil {
				ips = append(ips, ip)
			} else {
				log.Errorf("Bad dnsEntry %s ignored\n",
					strAddr)
			}
		}

		nameToIP := types.DnsNameToIP{
			HostName: hostName,
			IPs:      ips,
		}
		nameToIPs = append(nameToIPs, nameToIP)
	}
	config.DnsNameToIPList = nameToIPs
}

func publishNetworkInstanceConfig(ctx *getconfigContext,
	networkInstances []*zconfig.NetworkInstanceConfig) {

	log.Infof("Publish NetworkInstance Config: %+v", networkInstances)

	unpublishDeletedNetworkInstanceConfig(ctx, networkInstances)
	// check we do not have more than one VPN network instance
	vpnCount := 0
	for _, netInstApiCfg := range networkInstances {
		if oCfg := netInstApiCfg.Cfg; oCfg != nil {
			opaqueCfg := oCfg.GetOconfig()
			if opaqueCfg != "" {
				opaqueType := oCfg.GetType()
				if opaqueType == zconfig.ZNetworkOpaqueConfigType_ZNetOConfigVPN {
					vpnCount++
				}
			}
		}
	}

	if vpnCount > 1 {
		log.Errorf("publishNetworkInstanceConfig(): more than one VPN instance configuration\n")
		return
	}

	for _, apiConfigEntry := range networkInstances {
		id, err := uuid.FromString(apiConfigEntry.Uuidandversion.Uuid)
		version := apiConfigEntry.Uuidandversion.Version
		if err != nil {
			log.Errorf("NetworkInstanceConfig: Malformed UUID %s. ignored. Err: %s\n",
				apiConfigEntry.Uuidandversion.Uuid, err)
			// XXX - We should propagate this error to Cloud.
			// Why ignore only for this specific Check?
			// Shouldn't we reject the config if any of the fields have errors?
			// Or may be identify some fields as imp. fields and reject them only?
			// Either way, it is good to propagate the error to Cloud.
			continue
		}
		networkInstanceConfig := types.NetworkInstanceConfig{
			UUIDandVersion: types.UUIDandVersion{UUID: id, Version: version},
			DisplayName:    apiConfigEntry.Displayname,
			Type:           types.NetworkInstanceType(apiConfigEntry.InstType),
			Activate:       apiConfigEntry.Activate,
		}
		log.Infof("publishNetworkInstanceConfig: processing %s %s type %d activate %v\n",
			networkInstanceConfig.UUID.String(), networkInstanceConfig.DisplayName,
			networkInstanceConfig.Type, networkInstanceConfig.Activate)

		if apiConfigEntry.Port != nil {
			networkInstanceConfig.Port = apiConfigEntry.Port.Name
		}
		// XXX temporary hack:
		// For switch log+force to AddressTypeNone and do not copy
		// ipconfig but do copy opaque
		// XXX zedcloud should send First/None type for switch
		// network instances
		networkInstanceConfig.IpType = types.AddressType(apiConfigEntry.IpType)

		switch networkInstanceConfig.Type {
		case types.NetworkInstanceTypeSwitch:
			if networkInstanceConfig.IpType != types.AddressTypeNone {
				log.Warnf("Switch network instance %s %s with invalid IpType %d overridden as %d\n",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType,
					types.AddressTypeNone)
				networkInstanceConfig.IpType = types.AddressTypeNone
			}
			ctx.pubNetworkInstanceConfig.Publish(networkInstanceConfig.UUID.String(),
				&networkInstanceConfig)

		case types.NetworkInstanceTypeMesh:
			// mark HasEncap as true, for special MTU handling
			networkInstanceConfig.HasEncap = true
			// if not cryptoIPv4/IPv6 type, flag it
			if networkInstanceConfig.IpType != types.AddressTypeCryptoIPV4 && networkInstanceConfig.IpType != types.AddressTypeCryptoIPV6 {
				log.Errorf("Network instance %s %s, %v not crypto type\n",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType)
			}
			populateLispConfig(apiConfigEntry, &networkInstanceConfig)

		// FIXME:XXX set encap flag, when the dummy interface
		// is tested for the VPN
		case types.NetworkInstanceTypeCloud:
			// if opaque config not set, flag it
			if apiConfigEntry.Cfg == nil {
				log.Errorf("Network instance %s %s, %v, opaque not set\n",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType)
			} else {
				ocfg := apiConfigEntry.Cfg
				if ocfg.Type != zconfig.ZNetworkOpaqueConfigType_ZNetOConfigVPN {
					log.Errorf("Network instance %s %s, %v invalid config \n",
						networkInstanceConfig.UUID.String(),
						networkInstanceConfig.DisplayName,
						networkInstanceConfig.IpType)
				}
				networkInstanceConfig.OpaqueConfig = ocfg.Oconfig
			}
			// if not IPv4 type, flag it
			if networkInstanceConfig.IpType != types.AddressTypeIPV4 {
				log.Errorf("Network instance %s %s, %v not IPv4 type\n",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType)
			}
		}

		// other than switch-type(l2)
		// if ip type is l3, do the needful
		if networkInstanceConfig.IpType != types.AddressTypeNone {
			parseIpspec(apiConfigEntry.Ip,
				&networkInstanceConfig)

			parseDnsNameToIpList(apiConfigEntry,
				&networkInstanceConfig)
		}

		ctx.pubNetworkInstanceConfig.Publish(networkInstanceConfig.UUID.String(),
			&networkInstanceConfig)
	}
}

func populateLispConfig(apiConfigEntry *zconfig.NetworkInstanceConfig,
	networkInstanceConfig *types.NetworkInstanceConfig) {
	lispConfig := apiConfigEntry.Cfg.LispConfig
	if lispConfig != nil {
		mapServers := []types.MapServer{}
		for _, ms := range lispConfig.LispMSs {
			mapServer := types.MapServer{
				ServiceType: types.MapServerType(ms.ZsType),
				NameOrIp:    ms.NameOrIp,
				Credential:  ms.Credential,
			}
			mapServers = append(mapServers, mapServer)
		}
		eidPrefix := net.IP(lispConfig.Allocationprefix)

		// Populate service Lisp config that should be sent to zedrouter
		networkInstanceConfig.LispConfig = types.NetworkInstanceLispConfig{
			MapServers:    mapServers,
			IID:           lispConfig.LispInstanceId,
			Allocate:      lispConfig.Allocate,
			ExportPrivate: lispConfig.Exportprivate,
			EidPrefix:     eidPrefix,
			EidPrefixLen:  lispConfig.Allocationprefixlen,
			Experimental:  lispConfig.Experimental,
		}
	}
}

var networkInstancePrevConfigHash []byte

func parseNetworkInstanceConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) {

	networkInstances := config.GetNetworkInstances()

	h := sha256.New()
	for _, n := range networkInstances {
		computeConfigElementSha(h, n)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, networkInstancePrevConfigHash)
	networkConfigPrevConfigHash = configHash
	if same {
		return
	}
	log.Infof("parseNetworkInstanceConfig: Applying updated config "+
		"sha % x vs. % x: %v\n",
		networkInstancePrevConfigHash, configHash, networkInstances)
	// Export NetworkInstanceConfig to zedrouter
	publishNetworkInstanceConfig(getconfigCtx, networkInstances)
}

var appinstancePrevConfigHash []byte

func parseAppInstanceConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) {
	log.Debugf("EdgeDevConfig: %v\n", *config)

	Apps := config.GetApps()
	h := sha256.New()
	for _, a := range Apps {
		computeConfigElementSha(h, a)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, appinstancePrevConfigHash)
	appinstancePrevConfigHash = configHash
	if same {
		log.Debugf("parseAppInstanceConfig: appinstance sha is unchanged: % x\n",
			configHash)
		return
	}
	if getconfigCtx.rebootFlag {
		log.Infof("parseAppInstanceConfig: ignoring updated config due to rebootFlag: %v\n",
			Apps)
		return
	}
	log.Infof("parseAppInstanceConfig: Applying updated config sha % x vs. % x: %v\n",
		appinstancePrevConfigHash, configHash, Apps)

	// First look for deleted ones
	items := getconfigCtx.pubAppInstanceConfig.GetAll()
	for uuidStr := range items {
		found := false
		for _, app := range Apps {
			if app.Uuidandversion.Uuid == uuidStr {
				found = true
				break
			}
		}
		if !found {
			log.Infof("Remove app config %s\n", uuidStr)
			getconfigCtx.pubAppInstanceConfig.Unpublish(uuidStr)

			unpublishCertObjConfig(getconfigCtx, uuidStr)
		}
	}

	var appInstanceList []*types.AppInstanceConfig

	for _, cfgApp := range Apps {
		// Note that we repeat this even if the app config didn't
		// change but something else in the EdgeDeviceConfig did
		log.Debugf("New/updated app instance %v\n", cfgApp)
		appInstance := new(types.AppInstanceConfig)

		appInstance.UUIDandVersion.UUID, _ = uuid.FromString(cfgApp.Uuidandversion.Uuid)
		appInstance.UUIDandVersion.Version = cfgApp.Uuidandversion.Version
		appInstance.DisplayName = cfgApp.Displayname
		appInstance.Activate = cfgApp.Activate

		appInstance.FixedResources.Kernel = cfgApp.Fixedresources.Kernel
		appInstance.FixedResources.BootLoader = cfgApp.Fixedresources.Bootloader
		appInstance.FixedResources.Ramdisk = cfgApp.Fixedresources.Ramdisk
		appInstance.FixedResources.MaxMem = int(cfgApp.Fixedresources.Maxmem)
		appInstance.FixedResources.Memory = int(cfgApp.Fixedresources.Memory)
		appInstance.FixedResources.RootDev = cfgApp.Fixedresources.Rootdev
		appInstance.FixedResources.VCpus = int(cfgApp.Fixedresources.Vcpus)
		appInstance.FixedResources.VirtualizationMode = types.VmMode(cfgApp.Fixedresources.VirtualizationMode)
		appInstance.FixedResources.EnableVnc = cfgApp.Fixedresources.EnableVnc
		appInstance.FixedResources.VncDisplay = cfgApp.Fixedresources.VncDisplay
		appInstance.FixedResources.VncPasswd = cfgApp.Fixedresources.VncPasswd

		appInstance.StorageConfigList = make([]types.StorageConfig,
			len(cfgApp.Drives))
		parseStorageConfigList(appImgObj, appInstance.StorageConfigList,
			cfgApp.Drives)

		// fill the overlay/underlay config
		parseAppNetworkConfig(appInstance, cfgApp, config.Networks,
			config.NetworkInstances)

		// I/O adapters
		appInstance.IoAdapterList = nil
		for _, adapter := range cfgApp.Adapters {
			log.Debugf("Processing adapter type %d name %s\n",
				adapter.Type, adapter.Name)
			appInstance.IoAdapterList = append(appInstance.IoAdapterList,
				types.IoAdapter{Type: types.IoType(adapter.Type),
					Name: adapter.Name})
		}
		log.Infof("Got adapters %v\n", appInstance.IoAdapterList)

		cmd := cfgApp.GetRestart()
		if cmd != nil {
			appInstance.RestartCmd.Counter = cmd.Counter
			appInstance.RestartCmd.ApplyTime = cmd.OpsTime
		}
		cmd = cfgApp.GetPurge()
		if cmd != nil {
			appInstance.PurgeCmd.Counter = cmd.Counter
			appInstance.PurgeCmd.ApplyTime = cmd.OpsTime
		}
		userData := cfgApp.GetUserData()
		if userData != "" {
			log.Debugf("Received cloud-init userData %s\n",
				userData)
		}

		appInstance.CloudInitUserData = userData
		appInstance.RemoteConsole = cfgApp.GetRemoteConsole()
		appInstanceList = append(appInstanceList, appInstance)
	}

	// publish the config objects
	for _, appInstance := range appInstanceList {
		uuidStr := appInstance.UUIDandVersion.UUID.String()
		// write to zedmanager config directory
		publishAppInstanceConfig(getconfigCtx, *appInstance)
		// get the certs for image sha verification
		certInstance := getCertObjects(appInstance.UUIDandVersion,
			appInstance.ConfigSha256, appInstance.StorageConfigList)
		if certInstance != nil {
			publishCertObjConfig(getconfigCtx, certInstance,
				uuidStr)
		}
	}
}

var systemAdaptersPrevConfigHash []byte

func parseSystemAdapterConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext, forceParse bool) {
	log.Debugf("parseSystemAdapterConfig: EdgeDevConfig: %v\n", *config)

	sysAdapters := config.GetSystemAdapterList()
	h := sha256.New()
	for _, a := range sysAdapters {
		computeConfigElementSha(h, a)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, systemAdaptersPrevConfigHash)
	if same && !forceParse {
		log.Debugf("parseSystemAdapterConfig: system adapter sha is unchanged: % x\n",
			configHash)
		return
	}
	if getconfigCtx.rebootFlag {
		log.Infof("parseSystemAdapterConfig: ignoring updated config due to rebootFlag: %v\n",
			sysAdapters)
		return
	}
	log.Infof("parseSystemAdapterConfig: Applying updated config sha % x vs. % x: %v\n",
		systemAdaptersPrevConfigHash, configHash, sysAdapters)

	systemAdaptersPrevConfigHash = configHash

	// Check if we have any with Uplink/IsMgmt set, in which case we
	// infer the version
	// XXX should we have a version in the proto file? Will end up with
	// a collapsed systemAdapter with network info inlined soon.
	version := types.DPCInitial
	for _, sysAdapter := range sysAdapters {
		if sysAdapter.Uplink {
			version = types.DPCIsMgmt
		}
	}

	newPorts := []types.NetworkPortConfig{}
	for _, sysAdapter := range sysAdapters {
		var isUplink, isFreeUplink bool = false, false

		// XXX Rename Uplink in proto file to IsMgmt! Ditto for FreeUplink
		if version < types.DPCIsMgmt {
			// XXX Make Uplink and FreeUplink true
			// This should go away when cloud sends proper values
			isUplink = true
			isFreeUplink = true
			version = types.DPCIsMgmt
		} else {
			isUplink = sysAdapter.Uplink
			isFreeUplink = sysAdapter.FreeUplink
			// XXX zedcloud doesn't set FreeUplink
			isFreeUplink = isUplink
		}

		port := types.NetworkPortConfig{}
		port.IfName = sysAdapter.Name
		if sysAdapter.LogicalName != "" {
			port.Name = sysAdapter.LogicalName
		} else {
			port.Name = sysAdapter.Name
		}
		port.IsMgmt = isUplink
		port.Free = isFreeUplink

		port.Dhcp = types.DT_NONE
		// XXX temporary hack: if static IP 0.0.0.0 we log and
		// Dhcp = DT_NONE. Remove once zedcloud can send Dhcp = None
		forceDhcpNone := false
		var ip net.IP
		if sysAdapter.Addr != "" {
			ip = net.ParseIP(sysAdapter.Addr)
			if ip == nil {
				log.Errorf("parseSystemAdapterConfig: Port %s has Bad "+
					"sysAdapter.Addr %s - ignored\n",
					sysAdapter.Name, sysAdapter.Addr)
				continue
			}
			if ip.IsUnspecified() {
				forceDhcpNone = true
			}
			// XXX Note that ip is not used unless we have a network below
		}
		if sysAdapter.NetworkUUID != "" &&
			sysAdapter.NetworkUUID != nilUUID.String() {

			// Lookup the network with given UUID
			// and copy proxy and other configuration
			networkXObject, err := getconfigCtx.pubNetworkXObjectConfig.Get(sysAdapter.NetworkUUID)
			if err != nil {
				log.Errorf("parseSystemAdapterConfig: Network with UUID %s not found: %s\n",
					sysAdapter.NetworkUUID, err)
				continue
			}
			network := cast.CastNetworkXObjectConfig(networkXObject)
			addrSubnet := network.Subnet
			addrSubnet.IP = ip
			port.AddrSubnet = addrSubnet.String()

			port.Gateway = network.Gateway
			port.DomainName = network.DomainName
			port.NtpServer = network.NtpServer
			port.DnsServers = network.DnsServers
			// Need to be careful since zedcloud can feed us bad Dhcp type
			port.Dhcp = network.Dhcp
			switch network.Dhcp {
			case types.DT_STATIC:
				if forceDhcpNone {
					log.Warnf("Forcing DT_NONE for %+v\n", port)
					port.Dhcp = types.DT_NONE
					break
				}
				if port.Gateway.IsUnspecified() || port.AddrSubnet == "" ||
					port.DnsServers == nil {
					log.Errorf("parseSystemAdapterConfig: DT_STATIC but missing parameters in %+v; ignored\n",
						port)
					continue
				}
			case types.DT_CLIENT:
				// Do nothing
			case types.DT_NONE:
				// Do nothing
			default:
				log.Warnf("parseSystemAdapterConfig: ignore unsupported dhcp type %v\n",
					network.Dhcp)
				continue
			}
			// XXX use DnsNameToIpList?
			if network.Proxy != nil {
				port.ProxyConfig = *network.Proxy
			}
		}
		newPorts = append(newPorts, port)
	}
	if len(newPorts) == 0 {
		log.Infof("parseSystemAdapterConfig: No Port configuration present")
		return
	}
	portConfig := &types.DevicePortConfig{}
	portConfig.Version = version
	portConfig.Ports = newPorts

	// Any content change?
	if cmp.Equal(getconfigCtx.devicePortConfig.Ports, portConfig.Ports) &&
		getconfigCtx.devicePortConfig.Version == portConfig.Version {
		log.Infof("parseSystemAdapterConfig: Done with no change")
		return
	}
	log.Infof("parseSystemAdapterConfig: version %d/%d diff %v",
		getconfigCtx.devicePortConfig.Version, portConfig.Version,
		cmp.Diff(getconfigCtx.devicePortConfig.Ports, portConfig.Ports))

	// This is suboptimal after a reboot since the config will be the same
	// yet the timestamp be new. HandleDPCModify takes care of that.
	portConfig.TimePriority = time.Now()
	getconfigCtx.devicePortConfig = *portConfig

	getconfigCtx.pubDevicePortConfig.Publish("zedagent", *portConfig)

	log.Infof("parseSystemAdapterConfig: Done")
}

func lookupDatastore(datastores []*zconfig.DatastoreConfig,
	dsid string) *zconfig.DatastoreConfig {

	for _, ds := range datastores {
		if dsid == ds.Id {
			return ds
		}
	}
	return nil
}

var datastoreConfigPrevConfigHash []byte

func parseDatastoreConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) {

	stores := config.GetDatastores()
	h := sha256.New()
	for _, ds := range stores {
		computeConfigElementSha(h, ds)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, datastoreConfigPrevConfigHash)
	datastoreConfigPrevConfigHash = configHash
	if same {
		log.Debugf("parseDatastoreConfig: datastore sha is unchanged: % x\n",
			configHash)
		return
	}
	log.Infof("parseDatastoreConfig: Applying updated datastore config shaa % x vs. % x:  %v\n",
		datastoreConfigPrevConfigHash, configHash, stores)
	publishDatastoreConfig(getconfigCtx, stores)
}

func publishDatastoreConfig(ctx *getconfigContext,
	cfgDatastores []*zconfig.DatastoreConfig) {

	// Check for items to delete first
	items := ctx.pubDatastoreConfig.GetAll()
	for k := range items {
		ds := lookupDatastore(cfgDatastores, k)
		if ds != nil {
			continue
		}
		log.Debugf("publishDatastoresConfig: unpublishing %s\n", k)
		ctx.pubDatastoreConfig.Unpublish(k)
	}
	for _, ds := range cfgDatastores {
		datastore := new(types.DatastoreConfig)
		datastore.UUID, _ = uuid.FromString(ds.Id)
		datastore.Fqdn = ds.Fqdn
		datastore.Dpath = ds.Dpath
		datastore.DsType = ds.DType.String()
		datastore.ApiKey = ds.ApiKey
		datastore.Password = ds.Password
		datastore.Region = ds.Region
		// XXX compatibility with unmodified zedcloud datastores
		// default to "us-west-2"
		if datastore.Region == "" {
			datastore.Region = "us-west-2"
		}
		ctx.pubDatastoreConfig.Publish(datastore.Key(), &datastore)
	}
}

func parseStorageConfigList(objType string,
	storageList []types.StorageConfig, drives []*zconfig.Drive) {

	var idx int = 0

	for _, drive := range drives {
		image := new(types.StorageConfig)
		if drive.Image == nil {
			log.Errorf("No drive.Image for drive %v\n",
				drive)
			// Pass on for error reporting
			image.DatastoreId = nilUUID
		} else {
			id, _ := uuid.FromString(drive.Image.DsId)
			image.DatastoreId = id
			image.Name = drive.Image.Name

			image.Format = strings.ToLower(drive.Image.Iformat.String())
			image.Size = uint64(drive.Image.SizeBytes)
			image.ImageSignature = drive.Image.Siginfo.Signature
			image.SignatureKey = drive.Image.Siginfo.Signercerturl

			// XXX:FIXME certificates can be many
			// this list, currently contains the certUrls
			// should be the sha/uuid of cert filenames
			// as proper DataStore Entries

			if drive.Image.Siginfo.Intercertsurl != "" {
				image.CertificateChain = make([]string, 1)
				image.CertificateChain[0] = drive.Image.Siginfo.Intercertsurl
			}
		}
		image.ReadOnly = drive.Readonly
		image.Preserve = drive.Preserve
		image.Maxsizebytes = uint64(drive.Maxsizebytes)
		image.Target = strings.ToLower(drive.Target.String())
		image.Devtype = strings.ToLower(drive.Drvtype.String())
		image.ImageSha256 = drive.Image.Sha256
		storageList[idx] = *image
		idx++
	}
}

// XXX Remove when systemAdapter embeds the NetworkXObject
func lookupNetworkId(id string, cfgNetworks []*zconfig.NetworkConfig) *zconfig.NetworkConfig {
	for _, netEnt := range cfgNetworks {
		if id == netEnt.Id {
			return netEnt
		}
	}
	return nil
}

func lookupNetworkInstanceId(id string,
	cfgNetworkInstances []*zconfig.NetworkInstanceConfig) *zconfig.NetworkInstanceConfig {
	for _, netEnt := range cfgNetworkInstances {
		if id == netEnt.Uuidandversion.Uuid {
			return netEnt
		}
	}
	return nil
}

func lookupNetworkInstanceById(uuid string,
	networkInstancesConfigList []*zconfig.NetworkInstanceConfig) *zconfig.NetworkInstanceConfig {
	for _, entry := range networkInstancesConfigList {
		if uuid == entry.Uuidandversion.Uuid {
			return entry
		}
	}
	return nil
}

func publishNetworkXObjectConfig(ctx *getconfigContext,
	cfgNetworks []*zconfig.NetworkConfig) {

	// Check for items to delete first
	items := ctx.pubNetworkXObjectConfig.GetAll()
	for k := range items {
		netEnt := lookupNetworkId(k, cfgNetworks)
		if netEnt != nil {
			continue
		}
		log.Debugf("publishNetworkXObjectConfig: unpublishing %s\n", k)
		ctx.pubNetworkXObjectConfig.Unpublish(k)
	}

	// XXX note that we currently get repeats in the same loop.
	// Should we track them and not rewrite them?
	for _, netEnt := range cfgNetworks {
		id, err := uuid.FromString(netEnt.Id)
		if err != nil {
			log.Errorf("publishNetworkXObjectConfig: Malformed UUID ignored: %s\n",
				err)
			continue
		}
		config := types.NetworkXObjectConfig{
			UUID: id,
			Type: types.NetworkType(netEnt.Type),
		}
		// proxy configuration from cloud network configuration
		netProxyConfig := netEnt.GetEntProxy()
		if netProxyConfig == nil {
			log.Infof("publishNetworkXObjectConfig: EntProxy of network %s is nil",
				netEnt.Id)
		}
		if netProxyConfig != nil {
			log.Infof("publishNetworkXObjectConfig: Proxy configuration present in %s",
				netEnt.Id)

			proxyConfig := types.ProxyConfig{
				NetworkProxyEnable: netProxyConfig.NetworkProxyEnable,
				NetworkProxyURL:    netProxyConfig.NetworkProxyURL,
				Pacfile:            netProxyConfig.Pacfile,
			}
			proxyConfig.Exceptions = netProxyConfig.Exceptions

			// parse the static proxy entries
			for _, proxy := range netProxyConfig.Proxies {
				proxyEntry := types.ProxyEntry{
					Server: proxy.Server,
					Port:   proxy.Port,
				}
				switch proxy.Proto {
				case zconfig.ProxyProto_PROXY_HTTP:
					proxyEntry.Type = types.NPT_HTTP
				case zconfig.ProxyProto_PROXY_HTTPS:
					proxyEntry.Type = types.NPT_HTTPS
				case zconfig.ProxyProto_PROXY_SOCKS:
					proxyEntry.Type = types.NPT_SOCKS
				case zconfig.ProxyProto_PROXY_FTP:
					proxyEntry.Type = types.NPT_FTP
				default:
				}
				proxyConfig.Proxies = append(proxyConfig.Proxies, proxyEntry)
				log.Debugf("publishNetworkXObjectConfig: Adding proxy entry %s:%d in %s",
					proxyEntry.Server, proxyEntry.Port, netEnt.Id)
			}

			config.Proxy = &proxyConfig
		}

		log.Infof("publishNetworkXObjectConfig: processing %s type %d\n",
			config.Key(), config.Type)

		ipspec := netEnt.GetIp()
		switch config.Type {
		case types.NT_CryptoEID, types.NT_IPV4, types.NT_IPV6:
			if ipspec == nil {
				log.Errorf("publishNetworkXObjectConfig: Missing ipspec for %s in %v\n",
					id.String(), netEnt)
				continue
			}
			err := parseIpspecNetworkXObject(ipspec, &config)
			if err != nil {
				// XXX return how?
				log.Errorf("publishNetworkXObjectConfig: parseIpspec failed: %s\n", err)
				continue
			}
		case types.NT_NOOP:
			// XXX zedcloud is sending static and dynamic entries with zero.
			// XXX could also be for a switch without an IP address??
			if ipspec != nil {
				err := parseIpspecNetworkXObject(ipspec, &config)
				if err != nil {
					// XXX return how?
					log.Errorf("publishNetworkXObjectConfig: parseIpspec ignored: %s\n", err)
				}
			}

		default:
			log.Errorf("publishNetworkXObjectConfig: Unknown NetworkConfig type %d for %s in %v; ignored\n",
				config.Type, id.String(), netEnt)
			// XXX return error? Ignore for now
			continue
		}

		// Parse and store DnsNameToIPList form Network configuration
		dnsEntries := netEnt.GetDns()

		// Parse and populate the DnsNameToIP list
		// This is what we will publish to zedrouter
		nameToIPs := []types.DnsNameToIP{}
		for _, dnsEntry := range dnsEntries {
			hostName := dnsEntry.HostName

			ips := []net.IP{}
			for _, strAddr := range dnsEntry.Address {
				ip := net.ParseIP(strAddr)
				if ip != nil {
					ips = append(ips, ip)
				} else {
					log.Errorf("Bad dnsEntry %s ignored\n",
						strAddr)
				}
			}

			nameToIP := types.DnsNameToIP{
				HostName: hostName,
				IPs:      ips,
			}
			nameToIPs = append(nameToIPs, nameToIP)
		}
		config.DnsNameToIPList = nameToIPs

		ctx.pubNetworkXObjectConfig.Publish(config.Key(),
			&config)
	}
}

func parseIpspecNetworkXObject(ipspec *zconfig.Ipspec, config *types.NetworkXObjectConfig) error {
	config.Dhcp = types.DhcpType(ipspec.Dhcp)
	config.DomainName = ipspec.GetDomain()
	if s := ipspec.GetSubnet(); s != "" {
		_, subnet, err := net.ParseCIDR(s)
		if err != nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad subnet %s: %s",
				s, err))
		}
		config.Subnet = *subnet
	}
	if g := ipspec.GetGateway(); g != "" {
		config.Gateway = net.ParseIP(g)
		if config.Gateway == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad gateway IP %s",
				g))
		}
	}
	if n := ipspec.GetNtp(); n != "" {
		config.NtpServer = net.ParseIP(n)
		if config.NtpServer == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad ntp IP %s",
				n))
		}
	}
	for _, dsStr := range ipspec.GetDns() {
		ds := net.ParseIP(dsStr)
		if ds == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad dns IP %s",
				dsStr))
		}
		config.DnsServers = append(config.DnsServers, ds)
	}
	if dr := ipspec.GetDhcpRange(); dr != nil && dr.GetStart() != "" {
		start := net.ParseIP(dr.GetStart())
		if start == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad start IP %s",
				dr.GetStart()))
		}
		end := net.ParseIP(dr.GetEnd())
		if end == nil && dr.GetEnd() != "" {
			return errors.New(fmt.Sprintf("parseIpspec: bad end IP %s",
				dr.GetEnd()))
		}
		config.DhcpRange.Start = start
		config.DhcpRange.End = end
	}
	return nil
}

func parseIpspec(ipspec *zconfig.Ipspec,
	config *types.NetworkInstanceConfig) error {

	config.DomainName = ipspec.GetDomain()
	// Parse Subnet
	if s := ipspec.GetSubnet(); s != "" {
		_, subnet, err := net.ParseCIDR(s)
		if err != nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad subnet %s: %s",
				s, err))
		}
		config.Subnet = *subnet
	}
	// Parse Gateway
	if g := ipspec.GetGateway(); g != "" {
		config.Gateway = net.ParseIP(g)
		if config.Gateway == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad gateway IP %s",
				g))
		}
	}
	// Parse NTP Server
	if n := ipspec.GetNtp(); n != "" {
		config.NtpServer = net.ParseIP(n)
		if config.NtpServer == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad ntp IP %s",
				n))
		}
	}
	// Parse Dns Servers
	for _, dsStr := range ipspec.GetDns() {
		ds := net.ParseIP(dsStr)
		if ds == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad dns IP %s",
				dsStr))
		}
		config.DnsServers = append(config.DnsServers, ds)
	}
	// Parse DhcpRange
	if dr := ipspec.GetDhcpRange(); dr != nil && dr.GetStart() != "" {
		start := net.ParseIP(dr.GetStart())
		if start == nil {
			return errors.New(fmt.Sprintf("parseIpspec: bad start IP %s",
				dr.GetStart()))
		}
		end := net.ParseIP(dr.GetEnd())
		if end == nil && dr.GetEnd() != "" {
			return errors.New(fmt.Sprintf("parseIpspec: bad end IP %s",
				dr.GetEnd()))
		}
		config.DhcpRange.Start = start
		config.DhcpRange.End = end
	}
	return nil
}

func parseAppNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig,
	cfgNetworkInstances []*zconfig.NetworkInstanceConfig) {

	parseUnderlayNetworkConfig(appInstance, cfgApp, cfgNetworks,
		cfgNetworkInstances)
	parseOverlayNetworkConfig(appInstance, cfgApp, cfgNetworks,
		cfgNetworkInstances)
}

func parseUnderlayNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig,
	cfgNetworkInstances []*zconfig.NetworkInstanceConfig) {

	for _, intfEnt := range cfgApp.Interfaces {
		ulCfg := parseUnderlayNetworkConfigEntry(
			cfgApp, cfgNetworks, cfgNetworkInstances, intfEnt)
		if ulCfg == nil {
			log.Infof("Nil underlay config for Interface %s", intfEnt.Name)
			continue
		}
		appInstance.UnderlayNetworkList = append(appInstance.UnderlayNetworkList,
			*ulCfg)
		if ulCfg.Error != "" {
			appInstance.Errors = append(appInstance.Errors, ulCfg.Error)
			log.Errorf("Error in Interface(%s) config. Error: %s",
				intfEnt.Name, ulCfg.Error)
		}
	}
}

func isOverlayNetwork(netEnt *zconfig.NetworkConfig) bool {
	switch netEnt.Type {
	case zconfig.NetworkType_CryptoV4, zconfig.NetworkType_CryptoV6:
		return true
	default:
	}
	return false
}

func isOverlayNetworkInstance(netInstEntry *zconfig.NetworkInstanceConfig) bool {
	return netInstEntry.InstType == zconfig.ZNetworkInstType_ZnetInstMesh
}

func parseUnderlayNetworkConfigEntry(
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig,
	cfgNetworkInstances []*zconfig.NetworkInstanceConfig,
	intfEnt *zconfig.NetworkAdapter) *types.UnderlayNetworkConfig {

	ulCfg := new(types.UnderlayNetworkConfig)
	ulCfg.Name = intfEnt.Name

	// Lookup NetworkInstance ID
	networkInstanceEntry := lookupNetworkInstanceId(intfEnt.NetworkId,
		cfgNetworkInstances)
	if networkInstanceEntry == nil {
		ulCfg.Error = fmt.Sprintf("App %s-%s: Can't find %s in network instances.\n",
			cfgApp.Displayname, cfgApp.Uuidandversion.Uuid,
			intfEnt.NetworkId)
		log.Errorf("%s", ulCfg.Error)
		return ulCfg
	}
	if isOverlayNetworkInstance(networkInstanceEntry) {
		return nil
	}
	uuid, err := uuid.FromString(intfEnt.NetworkId)
	if err != nil {
		ulCfg.Error = fmt.Sprintf("App %s-%s: Malformed Network UUID %s. Err: %s\n",
			cfgApp.Displayname, cfgApp.Uuidandversion.Uuid,
			intfEnt.NetworkId, err)
		log.Errorf("%s", ulCfg.Error)
		return ulCfg
	}
	log.Infof("NetworkInstance(%s-%s): InstType %v\n",
		cfgApp.Displayname, cfgApp.Uuidandversion.Uuid,
		networkInstanceEntry.InstType)

	ulCfg.Network = uuid
	if intfEnt.MacAddress != "" {
		log.Infof("parseUnderlayNetworkConfig: got static MAC %s\n",
			intfEnt.MacAddress)
		ulCfg.AppMacAddr, err = net.ParseMAC(intfEnt.MacAddress)
		if err != nil {
			ulCfg.Error = fmt.Sprintf("App %s-%s: bad MAC:%s, Err: %s\n",
				cfgApp.Displayname, cfgApp.Uuidandversion.Uuid, intfEnt.MacAddress,
				err)
			log.Errorf("%s", ulCfg.Error)
			return ulCfg
		}
	}
	if intfEnt.Addr != "" {
		log.Infof("parseUnderlayNetworkConfig: got static IP %s\n",
			intfEnt.Addr)
		ulCfg.AppIPAddr = net.ParseIP(intfEnt.Addr)
		if ulCfg.AppIPAddr == nil {
			ulCfg.Error = fmt.Sprintf("App %s-%s: bad AppIPAddr:%s\n",
				cfgApp.Displayname, cfgApp.Uuidandversion.Uuid, intfEnt.Addr)
			log.Errorf("%s", ulCfg.Error)
			return ulCfg
		}

		// XXX - Should be move this check to zed manager? Only checks
		// absolutely needed to fill in the AppInstanceConfig should
		//	be in this routing. Rest of the checks should be done in zedmanager
		//	when processing the config. Clean it up..
		if ulCfg.AppIPAddr.To4() == nil {
			ulCfg.Error = fmt.Sprintf("Static IPv6 addressing (%s) not yet supported.\n",
				intfEnt.Addr)
			log.Errorf("%s", ulCfg.Error)
			return ulCfg
		}
	}

	ulCfg.ACLs = make([]types.ACE, len(intfEnt.Acls))
	for aclIdx, acl := range intfEnt.Acls {
		aclCfg := new(types.ACE)
		aclCfg.Matches = make([]types.ACEMatch,
			len(acl.Matches))
		aclCfg.Actions = make([]types.ACEAction,
			len(acl.Actions))
		for matchIdx, match := range acl.Matches {
			matchCfg := new(types.ACEMatch)
			matchCfg.Type = match.Type
			matchCfg.Value = match.Value
			aclCfg.Matches[matchIdx] = *matchCfg
		}

		for actionIdx, action := range acl.Actions {
			actionCfg := new(types.ACEAction)
			actionCfg.Limit = action.Limit
			actionCfg.LimitRate = int(action.Limitrate)
			actionCfg.LimitUnit = action.Limitunit
			actionCfg.LimitBurst = int(action.Limitburst)
			actionCfg.PortMap = action.Portmap
			actionCfg.TargetPort = int(action.AppPort)
			// XXX:FIXME actionCfg.Drop = <TBD>
			aclCfg.Actions[actionIdx] = *actionCfg
		}
		ulCfg.ACLs[aclIdx] = *aclCfg
	}
	return ulCfg
}

func parseOverlayNetworkConfigEntry(
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig,
	cfgNetworkInstances []*zconfig.NetworkInstanceConfig,
	intfEnt *zconfig.NetworkAdapter) *types.EIDOverlayConfig {

	olCfg := new(types.EIDOverlayConfig)
	olCfg.Name = intfEnt.Name

	// Lookup NetworkInstance ID
	networkInstanceEntry := lookupNetworkInstanceId(intfEnt.NetworkId,
		cfgNetworkInstances)
	if networkInstanceEntry == nil {
		olCfg.Error = fmt.Sprintf("App %s-%s: Can't find %s in network instances.\n",
			cfgApp.Displayname, cfgApp.Uuidandversion.Uuid,
			intfEnt.NetworkId)
		log.Errorf("%s", olCfg.Error)
		// XXX These errors should be propagated to zedrouter.
		// zedrouter can then relay these errors to zedcloud.
		return olCfg
	}
	if !isOverlayNetworkInstance(networkInstanceEntry) {
		return nil
	}
	uuid, err := uuid.FromString(intfEnt.NetworkId)
	if err != nil {
		olCfg.Error = fmt.Sprintf("parseOverlayNetworkConfigEntry: "+
			"Malformed UUID ignored: %s", err)
		log.Errorf("%s", olCfg.Error)
		return olCfg
	}
	log.Infof("NetworkInstance(%s-%s): InstType %v\n",
		cfgApp.Displayname, uuid.String(),
		networkInstanceEntry.InstType)

	olCfg.Network = uuid
	if intfEnt.MacAddress != "" {
		log.Infof("parseOverlayNetworkConfigEntry: (App %s, Overlay interface %s) - "+
			"Got static mac %s", cfgApp.Displayname, olCfg.Name, intfEnt.MacAddress)
		olCfg.AppMacAddr, err = net.ParseMAC(intfEnt.MacAddress)
		if err != nil {
			olCfg.Error = fmt.Sprintf("parseOverlayNetworkConfigEntry: bad MAC %s: %s\n",
				intfEnt.MacAddress, err)
			log.Errorf("%s", olCfg.Error)
			return olCfg
		}
	}
	// Handle old and new location of EIDv6
	if intfEnt.CryptoEid != "" {
		olCfg.EIDConfigDetails.EID = net.ParseIP(intfEnt.CryptoEid)
		if olCfg.EIDConfigDetails.EID == nil {
			olCfg.Error = fmt.Sprintf("parseOverlayNetworkConfigEntry: bad CryptoEid %s\n",
				intfEnt.CryptoEid)
			log.Errorf("%s", olCfg.Error)
			return olCfg
		}
		// Any IPv4 EID?
		if intfEnt.Addr != "" {
			olCfg.AppIPAddr = net.ParseIP(intfEnt.Addr)
			if olCfg.AppIPAddr == nil {
				olCfg.Error = fmt.Sprintf("parseOverlayNetworkConfigEntry: bad Addr %s\n",
					intfEnt.Addr)
				log.Errorf("%s", olCfg.Error)
				return olCfg
			}
		}
	} else if intfEnt.Addr != "" {
		olCfg.EIDConfigDetails.EID = net.ParseIP(intfEnt.Addr)
		if olCfg.EIDConfigDetails.EID == nil {
			olCfg.Error = fmt.Sprintf("parseOverlayNetworkConfigEntry: bad Addr %s\n",
				intfEnt.Addr)
			log.Errorf("%s", olCfg.Error)
			return olCfg
		}
	}
	if olCfg.AppIPAddr == nil {
		olCfg.AppIPAddr = olCfg.EIDConfigDetails.EID
	}

	olCfg.ACLs = make([]types.ACE, len(intfEnt.Acls))
	for aclIdx, acl := range intfEnt.Acls {
		aclCfg := new(types.ACE)
		aclCfg.Matches = make([]types.ACEMatch,
			len(acl.Matches))
		aclCfg.Actions = make([]types.ACEAction,
			len(acl.Actions))
		for matchIdx, match := range acl.Matches {
			matchCfg := new(types.ACEMatch)
			matchCfg.Type = match.Type
			matchCfg.Value = match.Value
			aclCfg.Matches[matchIdx] = *matchCfg
		}

		for actionIdx, action := range acl.Actions {
			actionCfg := new(types.ACEAction)
			actionCfg.Limit = action.Limit
			actionCfg.LimitRate = int(action.Limitrate)
			actionCfg.LimitUnit = action.Limitunit
			actionCfg.LimitBurst = int(action.Limitburst)
			actionCfg.PortMap = action.Portmap
			actionCfg.TargetPort = int(action.AppPort)
			aclCfg.Actions[actionIdx] = *actionCfg
		}
		olCfg.ACLs[aclIdx] = *aclCfg
	}

	olCfg.EIDConfigDetails.LispSignature = intfEnt.Lispsignature
	olCfg.EIDConfigDetails.PemCert = intfEnt.Pemcert
	olCfg.EIDConfigDetails.PemPrivateKey = intfEnt.Pemprivatekey

	return olCfg
}

// parseOverlayNetworkConfig
func parseOverlayNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig,
	cfgNetworkInstances []*zconfig.NetworkInstanceConfig) {

	for _, intfEnt := range cfgApp.Interfaces {
		olCfg := parseOverlayNetworkConfigEntry(
			cfgApp, cfgNetworks, cfgNetworkInstances, intfEnt)
		if olCfg == nil {
			log.Infof("Nil olcfg for App interface %s", intfEnt.Name)
			continue
		}
		appInstance.OverlayNetworkList = append(appInstance.OverlayNetworkList,
			*olCfg)
		if olCfg.Error != "" {
			appInstance.Errors = append(appInstance.Errors, olCfg.Error)
			log.Errorf("Error in Interface(%s) config. Error: %s",
				intfEnt.Name, olCfg.Error)
		}
	}
}

var itemsPrevConfigHash []byte

func parseConfigItems(config *zconfig.EdgeDevConfig, ctx *getconfigContext) {

	items := config.GetConfigItems()
	h := sha256.New()
	for _, i := range items {
		computeConfigElementSha(h, i)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, itemsPrevConfigHash)
	itemsPrevConfigHash = configHash
	if same {
		log.Debugf("parseConfigItems: items sha is unchanged: % x\n",
			configHash)
		return
	}
	log.Infof("parseConfigItems: Applying updated config sha % x vs. % x: %v\n",
		itemsPrevConfigHash, configHash, items)

	// Start with the defaults so that we revert to default when no data
	newGlobalConfig := types.GlobalConfigDefaults

	for _, item := range items {
		log.Infof("parseConfigItems key %s value %s\n",
			item.Key, item.Value)

		key := item.Key
		switch key {
		case "timer.config.interval":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.ConfigInterval = uint32(i64)

		case "timer.metric.interval":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.MetricInterval = uint32(i64)

		case "timer.reboot.no.network":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.ResetIfCloudGoneTime = uint32(i64)

		case "timer.update.fallback.no.network":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.FallbackIfCloudGoneTime = uint32(i64)

		case "timer.test.baseimage.update":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.MintimeUpdateSuccess = uint32(i64)

		case "timer.port.georedo":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.NetworkGeoRedoTime = uint32(i64)

		case "timer.port.georetry":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.NetworkGeoRetryTime = uint32(i64)

		case "timer.port.testduration":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.NetworkTestDuration = uint32(i64)

		case "timer.port.testinterval":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.NetworkTestInterval = uint32(i64)

		case "timer.port.testbetterinterval":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.NetworkTestBetterInterval = uint32(i64)

		case "network.fallback.any.eth":
			newTs, err := types.ParseTriState(item.Value)
			if err != nil {
				log.Errorf("parseConfigItems: bad tristate value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.NetworkFallbackAnyEth = newTs

		case "debug.enable.usb":
			newBool, err := strconv.ParseBool(item.Value)
			if err != nil {
				log.Errorf("parseConfigItems: bad bool value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.UsbAccess = newBool

		case "debug.enable.ssh":
			var newBool bool
			// This can be either a boolean (old) or an ssh
			// authorized_key which starts with "ssh"
			if strings.HasPrefix(item.Value, "ssh") {
				newGlobalConfig.SshAuthorizedKeys = item.Value
				newBool = true
			} else {
				var err error
				newBool, err = strconv.ParseBool(item.Value)
				if err != nil {
					log.Errorf("parseConfigItems: bad bool value %s for %s: %s\n",
						item.Value, key, err)
					continue
				}
			}
			newGlobalConfig.SshAccess = newBool

		case "app.allow.vnc":
			newBool, err := strconv.ParseBool(item.Value)
			if err != nil {
				log.Errorf("parseConfigItems: bad bool value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.AllowAppVnc = newBool

		case "timer.use.config.checkpoint":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.StaleConfigTime = uint32(i64)

		case "timer.gc.download":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.DownloadGCTime = uint32(i64)

		case "timer.gc.vdisk":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.VdiskGCTime = uint32(i64)

		case "timer.download.retry":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.DownloadRetryTime = uint32(i64)

		case "timer.boot.retry":
			i64, err := strconv.ParseInt(item.Value, 10, 32)
			if err != nil {
				log.Errorf("parseConfigItems: bad int value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.DomainBootRetryTime = uint32(i64)

		case "debug.default.loglevel":
			newGlobalConfig.DefaultLogLevel = item.Value

		case "debug.default.remote.loglevel":
			newGlobalConfig.DefaultRemoteLogLevel = item.Value

		default:
			// Handle agentname items for loglevels
			newString := item.Value
			components := strings.Split(key, ".")
			if len(components) == 3 && components[0] == "debug" &&
				components[2] == "loglevel" {

				agentName := components[1]
				current := agentlog.LogLevel(&globalConfig,
					agentName)
				if current != newString && newString != "" {
					log.Infof("parseConfigItems: %s change from %v to %v\n",
						key, current, newString)
					agentlog.SetLogLevel(&newGlobalConfig,
						agentName, newString)
				} else {
					agentlog.SetLogLevel(&newGlobalConfig,
						agentName, current)
				}
			} else if len(components) == 4 && components[0] == "debug" &&
				components[2] == "remote" && components[3] == "loglevel" {
				agentName := components[1]
				current := agentlog.RemoteLogLevel(&globalConfig,
					agentName)
				if current != newString && newString != "" {
					log.Infof("parseConfigItems: %s change from %v to %v\n",
						key, current, newString)
					agentlog.SetRemoteLogLevel(&newGlobalConfig,
						agentName, newString)
				} else {
					agentlog.SetRemoteLogLevel(&newGlobalConfig,
						agentName, current)
				}
			} else {
				log.Errorf("Unknown configItem %s value %s\n",
					key, item.Value)
				// XXX send back error? Need device error for that
			}
		}
	}
	newGlobalConfig = types.ApplyGlobalConfig(newGlobalConfig)
	if !cmp.Equal(globalConfig, newGlobalConfig) {
		log.Infof("parseConfigItems: change %v",
			cmp.Diff(globalConfig, newGlobalConfig))

		oldGlobalConfig := globalConfig
		globalConfig = types.EnforceGlobalConfigMinimums(newGlobalConfig)
		if globalConfig.ConfigInterval != oldGlobalConfig.ConfigInterval {
			log.Infof("parseConfigItems: %s change from %d to %d\n",
				"ConfigInterval",
				oldGlobalConfig.ConfigInterval,
				globalConfig.ConfigInterval)
			updateConfigTimer(ctx.configTickerHandle)
		}
		if globalConfig.MetricInterval != oldGlobalConfig.MetricInterval {
			log.Infof("parseConfigItems: %s change from %d to %d\n",
				"MetricInterval",
				oldGlobalConfig.MetricInterval,
				globalConfig.MetricInterval)
			updateMetricsTimer(ctx.metricsTickerHandle)
		}
		if globalConfig.SshAuthorizedKeys != oldGlobalConfig.SshAuthorizedKeys {
			log.Infof("parseConfigItems: %v change from %v to %v",
				"SshAuthorizedKeys",
				oldGlobalConfig.SshAuthorizedKeys,
				globalConfig.SshAuthorizedKeys)
			ssh.UpdateSshAuthorizedKeys(globalConfig.SshAuthorizedKeys)
		}
		err := pubsub.PublishToDir("/persist/config/", "global",
			&globalConfig)
		if err != nil {
			log.Errorf("PublishToDir for globalConfig failed %s\n",
				err)
		}
	}
}

func publishAppInstanceConfig(getconfigCtx *getconfigContext,
	config types.AppInstanceConfig) {

	key := config.Key()
	log.Debugf("publishAppInstanceConfig UUID %s\n", key)
	pub := getconfigCtx.pubAppInstanceConfig
	pub.Publish(key, config)
}

func publishBaseOsConfig(getconfigCtx *getconfigContext,
	config *types.BaseOsConfig) {

	key := config.Key()
	log.Debugf("publishBaseOsConfig UUID %s, %s, activate %v\n",
		key, config.BaseOsVersion, config.Activate)
	pub := getconfigCtx.pubBaseOsConfig
	pub.Publish(key, config)
}

func getCertObjects(uuidAndVersion types.UUIDandVersion,
	sha256 string, drives []types.StorageConfig) *types.CertObjConfig {

	var cidx int = 0

	// count the number of cerificates in this object
	for _, image := range drives {
		if image.SignatureKey != "" {
			cidx++
		}
		for _, certUrl := range image.CertificateChain {
			if certUrl != "" {
				cidx++
			}
		}
	}

	// if no cerificates, return
	if cidx == 0 {
		return nil
	}

	// using the holder object UUID for
	// cert config json, and also the config sha
	var config = &types.CertObjConfig{}

	// certs object holder
	// each storageConfigList entry is a
	// certificate object
	config.UUIDandVersion = uuidAndVersion
	config.ConfigSha256 = sha256
	config.StorageConfigList = make([]types.StorageConfig, cidx)

	cidx = 0
	for _, image := range drives {
		if image.SignatureKey != "" {
			getCertObjConfig(config, image, image.SignatureKey, cidx)
			cidx++
		}

		for _, certUrl := range image.CertificateChain {
			if certUrl != "" {
				getCertObjConfig(config, image, certUrl, cidx)
				cidx++
			}
		}
	}

	return config
}

func getCertObjConfig(config *types.CertObjConfig,
	image types.StorageConfig, certUrl string, idx int) {

	if certUrl == "" {
		return
	}

	// XXX the sha for the cert should be set
	// XXX:FIXME hardcoding Size as 100KB
	var drive = &types.StorageConfig{
		DatastoreId: image.DatastoreId,
		Name:        certUrl, // XXX FIXME use??
		NameIsURL:   true,
		Size:        100 * 1024,
		ImageSha256: "",
	}
	config.StorageConfigList[idx] = *drive
}

func publishCertObjConfig(getconfigCtx *getconfigContext,
	config *types.CertObjConfig, uuidStr string) {

	key := uuidStr // XXX vs. config.Key()?
	log.Debugf("publishCertObjConfig(%s) key %s\n", uuidStr, config.Key())
	pub := getconfigCtx.pubCertObjConfig
	pub.Publish(key, config)
}

func unpublishCertObjConfig(getconfigCtx *getconfigContext, uuidStr string) {

	key := uuidStr
	log.Debugf("unpublishCertObjConfig(%s)\n", key)
	pub := getconfigCtx.pubCertObjConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishCertObjConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

// Get sha256 for a subset of the protobuf message.
// Used to determine which pieces changed
func computeConfigSha(msg proto.Message) []byte {
	data, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalf("computeConfigSha: proto.Marshal: %s\n", err)
	}
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// Get sha256 for a subset of the protobuf message.
// Used to determine which pieces changed
func computeConfigElementSha(h hash.Hash, msg proto.Message) {
	data, err := proto.Marshal(msg)
	if err != nil {
		log.Fatalf("computeConfigItemSha: proto.Marshal: %s\n",
			err)
	}
	h.Write(data)
}

// Returns a rebootFlag
func parseOpCmds(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) bool {

	scheduleBackup(config.GetBackup())
	return scheduleReboot(config.GetReboot(), getconfigCtx)
}

var rebootPrevConfigHash []byte
var rebootPrevReturn bool

// Returns a rebootFlag
func scheduleReboot(reboot *zconfig.DeviceOpsCmd,
	getconfigCtx *getconfigContext) bool {

	if reboot == nil {
		log.Infof("scheduleReboot - removing %s\n",
			rebootConfigFilename)
		// stop the timer
		if rebootTimer != nil {
			rebootTimer.Stop()
		}
		// remove the existing file
		os.Remove(rebootConfigFilename)
		return false
	}

	configHash := computeConfigSha(reboot)
	same := bytes.Equal(configHash, rebootPrevConfigHash)
	rebootPrevConfigHash = configHash
	if same {
		log.Debugf("scheduleReboot: reboot sha is unchanged: % x\n",
			configHash)
		return rebootPrevReturn
	}
	log.Infof("scheduleReboot: Applying updated config %v\n", reboot)

	if _, err := os.Stat(rebootConfigFilename); err != nil {
		// Take received as current and store in file
		log.Infof("scheduleReboot - writing initial %s\n",
			rebootConfigFilename)
		bytes, err := json.Marshal(reboot)
		if err != nil {
			log.Fatal(err)
		}
		err = pubsub.WriteRename(rebootConfigFilename, bytes)
		if err != nil {
			log.Fatal(err)
		}
	}
	rebootConfig := &zconfig.DeviceOpsCmd{}

	log.Infof("scheduleReboot - reading %s\n",
		rebootConfigFilename)
	// read old reboot config
	bytes, err := ioutil.ReadFile(rebootConfigFilename)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(bytes, rebootConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("scheduleReboot read %v\n", rebootConfig)

	// If counter value has changed it means new reboot event
	if rebootConfig.Counter != reboot.Counter {

		log.Infof("scheduleReboot: old %d new %d\n",
			rebootConfig.Counter, reboot.Counter)

		// store current config, persistently
		bytes, err = json.Marshal(reboot)
		if err == nil {
			err := pubsub.WriteRename(rebootConfigFilename, bytes)
			if err != nil {
				log.Errorf("scheduleReboot: failed %s\n",
					err)
			}
		}

		//timer was started, stop now
		if rebootTimer != nil {
			rebootTimer.Stop()
		}

		// Defer if inprogress by returning
		ctx := getconfigCtx.zedagentCtx
		if isBaseOsCurrentPartitionStateInProgress(ctx) {
			// Wait until TestComplete
			log.Warnf("Rebooting even though testing inprogress; defer\n")
			ctx.rebootCmdDeferred = true
			return false
		}

		// start the timer again
		// XXX:FIXME, need to handle the scheduled time
		duration := time.Second * time.Duration(rebootDelay)
		rebootTimer = time.NewTimer(duration)

		log.Infof("Scheduling for reboot %d %d %d seconds\n",
			rebootConfig.Counter, reboot.Counter,
			duration/time.Second)

		go handleReboot(getconfigCtx)
		rebootPrevReturn = true
		return true
	}
	rebootPrevReturn = false
	return false
}

var backupPrevConfigHash []byte

func scheduleBackup(backup *zconfig.DeviceOpsCmd) {
	// XXX:FIXME  handle backup semantics
	if backup == nil {
		return
	}
	configHash := computeConfigSha(backup)
	same := bytes.Equal(configHash, backupPrevConfigHash)
	backupPrevConfigHash = configHash
	if same {
		log.Debugf("scheduleBackup: backup sha is unchanged: % x\n",
			configHash)
		return
	}
	log.Infof("scheduleBackup: Applying updated config %v\n", backup)
	log.Errorf("XXX handle Backup Config: %v\n", backup)
}

// the timer channel handler
func handleReboot(getconfigCtx *getconfigContext) {

	log.Infof("handleReboot timer handler\n")
	rebootConfig := &zconfig.DeviceOpsCmd{}
	var state bool = true // If no file we reboot and not power off

	<-rebootTimer.C

	// read reboot config
	if _, err := os.Stat(rebootConfigFilename); err == nil {
		bytes, err := ioutil.ReadFile(rebootConfigFilename)
		if err == nil {
			err = json.Unmarshal(bytes, rebootConfig)
		}
		state = rebootConfig.DesiredState
		log.Infof("rebootConfig.DesiredState: %v\n", state)
	}

	shutdownAppsGlobal(getconfigCtx.zedagentCtx)
	errStr := "NORMAL: handleReboot rebooting"
	log.Errorf(errStr)
	agentlog.RebootReason(errStr)
	execReboot(state)
}

// Used by doBaseOsDeviceReboot only
func startExecReboot() {

	log.Infof("startExecReboot: scheduling exec reboot\n")

	//timer was started, stop now
	if rebootTimer != nil {
		rebootTimer.Stop()
	}

	// start the timer again
	// XXX:FIXME, need to handle the scheduled time
	duration := time.Second * time.Duration(rebootDelay)
	rebootTimer = time.NewTimer(duration)
	log.Infof("startExecReboot: timer %d seconds\n",
		duration/time.Second)

	go handleExecReboot()
}

// Used by doBaseOsDeviceReboot only
func handleExecReboot() {

	<-rebootTimer.C

	errStr := "NORMAL: baseimage-update reboot"
	log.Errorf(errStr)
	agentlog.RebootReason(errStr)
	execReboot(true)
}

func execReboot(state bool) {

	// do a sync
	log.Infof("State: %t, Doing a sync..\n", state)
	syscall.Sync()

	switch state {

	case true:
		duration := time.Second * time.Duration(rebootDelay)
		log.Infof("Rebooting... Starting timer for Duration(secs): %d\n",
			duration/time.Second)

		// Start timer to allow applications some time to shudown and for
		//      disks to sync.
		// We could explicitly wait for domains to shutdown, but
		// some (which don't have a shutdown hook like the mirageOs ones) take a
		// very long time.
		timer := time.NewTimer(duration)
		log.Infof("Timer started. Wait to expire\n")
		<-timer.C
		log.Infof("Timer Expired.. Zboot.Reset()\n")
		zboot.Reset()

	case false:
		log.Infof("Powering Off..\n")
		duration := time.Second * time.Duration(rebootDelay)
		timer := time.NewTimer(duration)
		log.Infof("Timer started (duration: %d seconds). Wait to expire\n",
			duration/time.Second)
		<-timer.C
		log.Infof("Timer Expired.. do Poweroff\n")
		poweroffCmd := exec.Command("poweroff")
		_, err := poweroffCmd.Output()
		if err != nil {
			log.Errorf("poweroffCmd failed %s\n", err)
		}
	}
}
