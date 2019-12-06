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
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/ssh"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	MaxBaseOsCount       = 2
	BaseOsImageCount     = 1
	rebootConfigFilename = types.IdentityDirname + "/rebootConfig"
)

// Returns a rebootFlag
func parseConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext,
	usingSaved bool) bool {

	// XXX can this happen when usingSaved is set?
	if parseOpCmds(config, getconfigCtx) {
		log.Infoln("Reboot flag set, skipping config processing")
		return true
	}
	ctx := getconfigCtx.zedagentCtx

	// XXX - DO NOT LOG entire config till secrets are spunoff into a separate
	//  struct, referenced by a pointer. That way, the passwords won't get
	//  printed.
	//log.Debugf("parseConfig: EdgeDevConfig: %v\n", *config)

	// Look for timers and other settings in configItems
	// Process Config items even when rebootFlag is set.. Allows us to
	//  recover if the system got stuck after setting rebootFlag
	parseConfigItems(config, getconfigCtx)

	if getconfigCtx.rebootFlag || ctx.deviceReboot {
		log.Debugf("parseConfig: Ignoring config as rebootFlag set\n")
	} else {
		parseDatastoreConfig(config, getconfigCtx)
		// DeviceIoList has some defaults for Usage and UsagePolicy
		// used by systemAdapters
		physioChanged := parseDeviceIoListConfig(config, getconfigCtx)
		// Network objects are used for systemAdapters
		networksChanged := parseNetworkXObjectConfig(config, getconfigCtx)
		// system adapter configuration that we publish, depends
		// on Physio configuration and Networks configuration. If either of
		// Physio or Networks change, we should re-parse system adapters and
		// publish updated configuration.
		forceSystemAdaptersParse := physioChanged || networksChanged
		parseSystemAdapterConfig(config, getconfigCtx, forceSystemAdaptersParse)
		parseBaseOsConfig(getconfigCtx, config)
		parseNetworkInstanceConfig(config, getconfigCtx)
		parseAppInstanceConfig(config, getconfigCtx)
	}
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
	if same {
		return
	}
	log.Infof("parseBaseOsConfig: Applying updated config\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"cfgOsList: %v\n",
		baseosPrevConfigHash, configHash, cfgOsList)

	baseosPrevConfigHash = configHash

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
		parseStorageConfigList(types.BaseOsObj, baseOs.StorageConfigList,
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

var networkConfigPrevConfigHash []byte

func parseNetworkXObjectConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) bool {

	h := sha256.New()
	nets := config.GetNetworks()
	for _, n := range nets {
		computeConfigElementSha(h, n)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, networkConfigPrevConfigHash)
	if same {
		return false
	}
	log.Infof("parseNetworkXObjectConfig: Applying updated config.\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"networks: %v\n",
		networkConfigPrevConfigHash, configHash, nets)
	networkConfigPrevConfigHash = configHash
	// Export NetworkXObjectConfig for ourselves; systemAdapter
	// XXX
	// System Adapter points to network for Proxy configuration.
	// There could be a situation where networks change, but
	// systerm adapters do not change. When we see the networks
	// change, we should parse systerm adapters again.
	publishNetworkXObjectConfig(getconfigCtx, nets)
	return true
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
		networkInstanceConfig.IpType = types.AddressType(apiConfigEntry.IpType)

		switch networkInstanceConfig.Type {
		case types.NetworkInstanceTypeSwitch:
			// XXX controller should send AddressTypeNone type for switch
			// network instances
			if networkInstanceConfig.IpType != types.AddressTypeNone {
				log.Errorf("Switch network instance %s %s with invalid IpType %d should be %d\n",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType,
					types.AddressTypeNone)
				// Let's relax the requirement until cloud side update the right IpType
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
	if same {
		return
	}
	log.Infof("parseNetworkInstanceConfig: Applying updated config\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"networkInstances: %v\n",
		networkInstancePrevConfigHash, configHash, networkInstances)
	networkInstancePrevConfigHash = configHash
	// Export NetworkInstanceConfig to zedrouter
	publishNetworkInstanceConfig(getconfigCtx, networkInstances)
}

var appinstancePrevConfigHash []byte

func parseAppInstanceConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) {

	Apps := config.GetApps()
	h := sha256.New()
	for _, a := range Apps {
		computeConfigElementSha(h, a)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, appinstancePrevConfigHash)
	if same {
		return
	}
	log.Infof("parseAppInstanceConfig: Applying updated config\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"Apps: %v\n",
		appinstancePrevConfigHash, configHash, Apps)
	appinstancePrevConfigHash = configHash

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

	for _, cfgApp := range Apps {
		// Note that we repeat this even if the app config didn't
		// change but something else in the EdgeDeviceConfig did
		log.Debugf("New/updated app instance %v\n", cfgApp)
		var appInstance types.AppInstanceConfig

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
		parseStorageConfigList(types.AppImgObj, appInstance.StorageConfigList,
			cfgApp.Drives)

		// fill the overlay/underlay config
		parseAppNetworkConfig(&appInstance, cfgApp, config.Networks,
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
			appInstance.CloudInitUserData = &userData
		}
		appInstance.RemoteConsole = cfgApp.GetRemoteConsole()
		// get the certs for image sha verification
		certInstance := getCertObjects(appInstance.UUIDandVersion,
			appInstance.ConfigSha256, appInstance.StorageConfigList)

		// write to zedmanager config directory
		uuidStr := cfgApp.Uuidandversion.Uuid
		publishAppInstanceConfig(getconfigCtx, appInstance)
		if certInstance != nil {
			publishCertObjConfig(getconfigCtx, certInstance,
				uuidStr)
		}
	}
}

var systemAdaptersPrevConfigHash []byte

func parseSystemAdapterConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext, forceParse bool) {

	sysAdapters := config.GetSystemAdapterList()
	h := sha256.New()
	for _, a := range sysAdapters {
		computeConfigElementSha(h, a)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, systemAdaptersPrevConfigHash)
	if same && !forceParse {
		return
	}
	log.Infof("parseSystemAdapterConfig: Applying updated config\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"sysAdapters: %v\n"+
		"Forced parsing: %v\n",
		systemAdaptersPrevConfigHash, configHash, sysAdapters, forceParse)

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
		port := parseOneSystemAdapterConfig(getconfigCtx, sysAdapter, version)
		if port != nil {
			newPorts = append(newPorts, *port)
		}
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
		log.Infof("parseSystemAdapterConfig: DevicePortConfig - " +
			"Done with no change")
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

// Returns a port if it should be added to the list; some errors result in
// adding an port to to DevicePortConfig with ParseError set.
func parseOneSystemAdapterConfig(getconfigCtx *getconfigContext,
	sysAdapter *zconfig.SystemAdapter,
	version types.DevicePortConfigVersion) *types.NetworkPortConfig {
	var isMgmt, isFree bool = false, false

	port := new(types.NetworkPortConfig)

	// XXX - There seems to be an implicit Assumption here that
	// sysAdapter.Name is same as Port.IfName
	// CHANGE this to: port.IfName = sysAdapter.getIfname()
	port.IfName = sysAdapter.Name
	port.Name = sysAdapter.Name

	// XXX - Make the change after LowerLayerName starts to get used.
	//  Look up using LowerLayerName ( PhysicalLabel).
	// If LowerLayerName is not found, use sysAdapter.Name to do the lookup
	//  Currently, lookupDeviceIo looks up using LogicalLabel. But it should
	//  Really be physical Label.
	phyio := lookupDeviceIo(getconfigCtx, sysAdapter.Name)
	if phyio == nil {
		// We will re-check when phyio changes.
		errStr := fmt.Sprintf("Missing phyio for %s; ignored",
			sysAdapter.Name)
		log.Error(errStr)
		port.ParseError = errStr
		port.ParseErrorTime = time.Now()
		return port
	}
	isFree = phyio.UsagePolicy.FreeUplink
	log.Infof("Found phyio for %s: isFree: %t", sysAdapter.Name, isFree)

	if version < types.DPCIsMgmt {
		log.Warnf("XXX old version; assuming isMgmt and isFree")
		// This should go away when cloud sends proper values
		isMgmt = true
		isFree = true
		version = types.DPCIsMgmt
	} else {
		isMgmt = sysAdapter.Uplink
		log.Infof("System adapter %s, isMgmt: %t", sysAdapter.Name, isMgmt)
		// Either one can set isFree; both need to clear
		if sysAdapter.FreeUplink && !isFree {
			log.Warnf("Free flag forced by system adapter for %s",
				sysAdapter.Name)
			isFree = true
		}
	}

	port.IsMgmt = isMgmt
	port.Free = isFree

	port.Dhcp = types.DT_NONE
	port.AccessPoint = sysAdapter.AccessPoint
	var ip net.IP
	if sysAdapter.Addr != "" {
		ip = net.ParseIP(sysAdapter.Addr)
		if ip == nil {
			errStr := fmt.Sprintf("parseSystemAdapterConfig: Port %s has Bad "+
				"sysAdapter.Addr %s - ignored",
				sysAdapter.Name, sysAdapter.Addr)
			log.Error(errStr)
			port.ParseError = errStr
			port.ParseErrorTime = time.Now()
			return port
		}
		// Note that ip is not used unless we have a network UUID
	}
	if sysAdapter.NetworkUUID != "" &&
		sysAdapter.NetworkUUID != nilUUID.String() {

		// Lookup the network with given UUID
		// and copy proxy and other configuration
		networkXObject, err := getconfigCtx.pubNetworkXObjectConfig.Get(sysAdapter.NetworkUUID)
		if err != nil {
			errStr := fmt.Sprintf("parseSystemAdapterConfig: Port %s Network with UUID %s not found: %s",
				port.IfName, sysAdapter.NetworkUUID, err)
			log.Error(errStr)
			port.ParseError = errStr
			port.ParseErrorTime = time.Now()
			return port
		}
		network := cast.CastNetworkXObjectConfig(networkXObject)
		if network.Error != "" {
			errStr := fmt.Sprintf("parseSystemAdapterConfig: Port %s Network error: %v",
				port.IfName, network.Error)
			port.ParseError = errStr
			port.ParseErrorTime = network.ErrorTime
			return port
		}
		if ip != nil {
			addrSubnet := network.Subnet
			addrSubnet.IP = ip
			port.AddrSubnet = addrSubnet.String()
		}

		port.Gateway = network.Gateway
		port.DomainName = network.DomainName
		port.NtpServer = network.NtpServer
		port.DnsServers = network.DnsServers
		// Need to be careful since zedcloud can feed us bad Dhcp type
		port.Dhcp = network.Dhcp
		switch network.Dhcp {
		case types.DT_STATIC:
			if port.AddrSubnet == "" {
				errStr := fmt.Sprintf("parseSystemAdapterConfig: Port %s DT_STATIC but missing "+
					"subnet address in %+v; ignored", port.IfName, port)
				log.Error(errStr)
				port.ParseError = errStr
				port.ParseErrorTime = time.Now()
				return port
			}
		case types.DT_CLIENT:
			// Do nothing
		case types.DT_NONE:
			if isMgmt {
				errStr := fmt.Sprintf("parseSystemAdapterConfig: Port %s: isMgmt with DT_NONE not supported",
					port.IfName)
				log.Error(errStr)
				port.ParseError = errStr
				port.ParseErrorTime = time.Now()
				return port
			}
		default:
			errStr := fmt.Sprintf("parseSystemAdapterConfig: Port %s: ignore unsupported dhcp type %v",
				port.IfName, network.Dhcp)
			log.Error(errStr)
			port.ParseError = errStr
			port.ParseErrorTime = time.Now()
			return port
		}
		// XXX use DnsNameToIpList?
		if network.Proxy != nil {
			port.ProxyConfig = *network.Proxy
		}
	} else if isMgmt {
		errStr := fmt.Sprintf("parseSystemAdapterConfig: Port %s isMgmt without networkUUID not supported",
			port.IfName)
		log.Error(errStr)
		port.ParseError = errStr
		port.ParseErrorTime = time.Now()
		return port
	}
	return port
}

var deviceIoListPrevConfigHash []byte

func parseDeviceIoListConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) bool {

	deviceIoList := config.GetDeviceIoList()
	h := sha256.New()
	for _, a := range deviceIoList {
		computeConfigElementSha(h, a)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, deviceIoListPrevConfigHash)
	if same {
		return false
	}
	log.Infof("parseDeviceIoListConfig: Applying updated config\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"deviceIoList: %v\n",
		deviceIoListPrevConfigHash, configHash, deviceIoList)

	deviceIoListPrevConfigHash = configHash

	phyIoAdapterList := types.PhysicalIOAdapterList{}
	phyIoAdapterList.AdapterList = make([]types.PhysicalIOAdapter, 0)

	for indx, ioDevicePtr := range deviceIoList {
		if ioDevicePtr == nil {
			log.Errorf("parseDeviceIoListConfig: nil ioDevicePtr at indx %d\n",
				indx)
			continue
		}
		port := types.PhysicalIOAdapter{
			Ptype:        ioDevicePtr.Ptype,
			Phylabel:     ioDevicePtr.Phylabel,
			Logicallabel: ioDevicePtr.Logicallabel,
			Assigngrp:    ioDevicePtr.Assigngrp,
			Usage:        ioDevicePtr.Usage,
		}
		if ioDevicePtr.UsagePolicy != nil {
			port.UsagePolicy.FreeUplink = ioDevicePtr.UsagePolicy.FreeUplink
		}

		for key, value := range ioDevicePtr.Phyaddrs {
			key = strings.ToLower(key)
			switch key {
			case "pcilong":
				port.Phyaddr.PciLong = value
			case "ifname":
				port.Phyaddr.Ifname = value
			case "serial":
				port.Phyaddr.Serial = value
			case "irq":
				port.Phyaddr.Irq = value
			case "ioports":
				port.Phyaddr.Ioports = value
			default:
				port.Phyaddr.UnknownType = value
				log.Warnf("Unrecognized Physical address Ignored: "+
					"key: %s, value: %s", key, value)
			}
		}
		phyIoAdapterList.AdapterList = append(phyIoAdapterList.AdapterList,
			port)
		getconfigCtx.zedagentCtx.physicalIoAdapterMap[port.Phylabel] = port
	}
	phyIoAdapterList.Initialized = true
	getconfigCtx.pubPhysicalIOAdapters.Publish("zedagent", phyIoAdapterList)

	log.Infof("parseDeviceIoListConfig: Done")
	return true
}

func lookupDeviceIo(getconfigCtx *getconfigContext, logicalLabel string) *types.PhysicalIOAdapter {
	for _, port := range getconfigCtx.zedagentCtx.physicalIoAdapterMap {
		if port.Logicallabel == logicalLabel {
			return &port
		}
	}
	return nil
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
	if same {
		return
	}

	// XXX - Careful not to log sensitive information. For now, just log
	// individual fields. The next commit should separate the sensitive
	// information into a separate structure - linked by a reference. That
	//  way, accidental print / log statements won't expose the secrets.
	log.Infof("parseDatastoreConfig: Applying updated datastore config\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"Num Stores: %d\n",
		datastoreConfigPrevConfigHash, configHash, len(stores))
	datastoreConfigPrevConfigHash = configHash
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
			image.DatastoreID = nilUUID
		} else {
			id, _ := uuid.FromString(drive.Image.DsId)
			image.DatastoreID = id
			image.Name = drive.Image.Name
			image.ImageID, _ = uuid.FromString(drive.Image.Uuidandversion.Uuid)
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
		if image.Format == "container" && image.ImageSha256 == "" {
			// XXX HACK - The right fix is to use ImageIDs to Track
			// images instead of SHA.
			// Currently, for container images, Zedcloud doesn't have
			// The SHA for the image. Use ImageID as the Sha.
			// Download Config add verifier config / status are keyed by SHA.
			// TIll we move away from that, set ImageSha to ImageID to
			// handle this case.
			image.ImageSha256 = image.ImageID.String()

		}
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

	// XXX note that we currently get repeats in the same loop since
	// the controller can send the same network multiple times.
	// Should we track them and not rewrite them?
	for _, netEnt := range cfgNetworks {
		config := parseOneNetworkXObjectConfig(ctx, netEnt)
		if config != nil {
			ctx.pubNetworkXObjectConfig.Publish(config.Key(),
				config)
		}
	}
}

func parseOneNetworkXObjectConfig(ctx *getconfigContext, netEnt *zconfig.NetworkConfig) *types.NetworkXObjectConfig {

	config := new(types.NetworkXObjectConfig)
	config.Type = types.NetworkType(netEnt.Type)
	id, err := uuid.FromString(netEnt.Id)
	if err != nil {
		errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: Malformed UUID ignored: %s",
			err)
		config.Error = errStr
		config.ErrorTime = time.Now()
		return config
	}
	config.UUID = id

	log.Infof("parseOneNetworkXObjectConfig: processing %s type %d",
		config.Key(), config.Type)

	// proxy configuration from cloud network configuration
	netProxyConfig := netEnt.GetEntProxy()
	if netProxyConfig == nil {
		log.Infof("parseOneNetworkXObjectConfig: EntProxy of network %s is nil",
			netEnt.Id)
	} else {
		log.Infof("parseOneNetworkXObjectConfig: Proxy configuration present in %s",
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
			log.Debugf("parseOneNetworkXObjectConfig: Adding proxy entry %s:%d in %s",
				proxyEntry.Server, proxyEntry.Port, netEnt.Id)
		}

		config.Proxy = &proxyConfig
	}

	ipspec := netEnt.GetIp()
	switch config.Type {
	case types.NT_CryptoEID, types.NT_IPV4, types.NT_IPV6:
		if ipspec == nil {
			errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: Missing ipspec for %s in %v",
				config.Key(), netEnt)
			log.Error(errStr)
			config.Error = errStr
			config.ErrorTime = time.Now()
			return config
		}
		err := parseIpspecNetworkXObject(ipspec, config)
		if err != nil {
			errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: parseIpspec failed for %s: %s",
				config.Key(), err)
			log.Error(errStr)
			config.Error = errStr
			config.ErrorTime = time.Now()
			return config
		}
	case types.NT_NOOP:
		// XXX is controller still sending static and dynamic entries with NT_NOOP? Why?
		if ipspec != nil {
			log.Warnf("XXX NT_NOOP for %s with ipspec %v",
				config.Key(), ipspec)
			err := parseIpspecNetworkXObject(ipspec, config)
			if err != nil {
				errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: parseIpspec ignored for %s: %s",
					config.Key(), err)
				log.Error(errStr)
				config.Error = errStr
				config.ErrorTime = time.Now()
				return config
			}
		}

	default:
		errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: Unknown NetworkConfig type %d for %s in %v; ignored",
			config.Type, id.String(), netEnt)
		log.Error(errStr)
		config.Error = errStr
		config.ErrorTime = time.Now()
		return config
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
				errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: bad dnsEntry %s for %s",
					strAddr, config.Key())
				log.Error(errStr)
				config.Error = errStr
				config.ErrorTime = time.Now()
				return config
			}
		}

		nameToIP := types.DnsNameToIP{
			HostName: hostName,
			IPs:      ips,
		}
		nameToIPs = append(nameToIPs, nameToIP)
	}
	config.DnsNameToIPList = nameToIPs
	return config
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
		aclCfg.RuleID = acl.Id
		aclCfg.Name = acl.Name
		aclCfg.Dir = types.ACEDirection(acl.Dir)
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
		aclCfg.RuleID = acl.Id
		aclCfg.Name = acl.Name
		aclCfg.Dir = types.ACEDirection(acl.Dir)
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
		return
	}
	log.Infof("parseConfigItems: Applying updated config\n"+
		"prevSha: % x\n"+
		"NewSha : % x\n"+
		"items: %v\n",
		itemsPrevConfigHash, configHash, items)

	// Start with the defaults so that we revert to default when no data
	// If there is Error Value for an item, we use the Default value
	// instead - NOT the current value. This guarantees a known state for the
	// Config item:
	//      1) Use the specified Value if no Errors
	//      2) Use the Default value if Value cannot be parsed.
	//      3) Use the Min. Value if the specified value < Min ( For Ints )
	//      4) Use the Max. Value if the specified value > Max ( For Ints )
	gcPtr := &ctx.zedagentCtx.globalConfig
	newGlobalConfig := types.GlobalConfigDefaults

	newGlobalStatus := types.GlobalStatus{}
	newGlobalStatus.ConfigItems = make(map[string]types.ConfigItemStatus)
	newGlobalStatus.UnknownConfigItems = make(map[string]types.ConfigItemStatus)

	unknownConfigItem := false
	var err error
	for _, item := range items {
		key := item.Key
		log.Infof("parseConfigItems key %s value %s\n", key, item.Value)
		switch key {
		case "timer.config.interval":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.ConfigInterval = uint32(i64)
			}

		case "timer.metric.interval":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.MetricInterval = uint32(i64)
			}

		case "timer.send.timeout":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.NetworkSendTimeout = uint32(i64)
			}

		case "timer.reboot.no.network":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.ResetIfCloudGoneTime = uint32(i64)
			}

		case "timer.update.fallback.no.network":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.FallbackIfCloudGoneTime = uint32(i64)
			}

		case "timer.test.baseimage.update":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.MintimeUpdateSuccess = uint32(i64)
			}

		case "timer.port.georedo":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.NetworkGeoRedoTime = uint32(i64)
			}

		case "timer.port.georetry":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.NetworkGeoRetryTime = uint32(i64)
			}

		case "timer.port.testduration":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.NetworkTestDuration = uint32(i64)
			}

		case "timer.port.testinterval":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.NetworkTestInterval = uint32(i64)
			}

		case "timer.port.timeout":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.NetworkTestTimeout = uint32(i64)
			}

		case "timer.port.testbetterinterval":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.NetworkTestBetterInterval = uint32(i64)
			}

		case "network.fallback.any.eth":
			newTs, err := types.ParseTriState(item.Value)
			if err == nil {
				newGlobalConfig.NetworkFallbackAnyEth = newTs
			}

		case "debug.enable.usb":
			newBool, err := strconv.ParseBool(item.Value)
			if err == nil {
				newGlobalConfig.UsbAccess = newBool
			}

		case "debug.enable.ssh":
			if strings.HasPrefix(item.Value, "ssh") {
				newGlobalConfig.SshAuthorizedKeys = item.Value
				newGlobalConfig.SshAccess = true
			} else {
				err = fmt.Errorf("Invalid value for debug.enable.ssh. "+
					"Not starting with prefix ssh. Value: %s", item.Value)
			}

		case "app.allow.vnc":
			newBool, err := strconv.ParseBool(item.Value)
			if err == nil {
				newGlobalConfig.AllowAppVnc = newBool
			}

		case "timer.use.config.checkpoint":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.StaleConfigTime = uint32(i64)
			}

		case "timer.gc.download":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.DownloadGCTime = uint32(i64)
			}

		case "timer.gc.vdisk":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.VdiskGCTime = uint32(i64)
			}

		case "timer.gc.rkt.graceperiod":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.RktGCGracePeriod = uint32(i64)
			}

		case "timer.download.retry":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.DownloadRetryTime = uint32(i64)
			}

		case "timer.boot.retry":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.DomainBootRetryTime = uint32(i64)
			}

		case "network.allow.wwan.app.download":
			newTs, err := types.ParseTriState(item.Value)
			if err == nil {
				newGlobalConfig.AllowNonFreeAppImages = newTs
			}

		case "network.allow.wwan.baseos.download":
			newTs, err := types.ParseTriState(item.Value)
			if err == nil {
				newGlobalConfig.AllowNonFreeBaseImages = newTs
			}

		case "debug.default.loglevel":
			newGlobalConfig.DefaultLogLevel = item.Value

		case "debug.default.remote.loglevel":
			newGlobalConfig.DefaultRemoteLogLevel = item.Value

		case "storage.dom0.disk.minusage.percent":
			i64, err := strconv.ParseUint(item.Value, 10, 32)
			if err == nil {
				newGlobalConfig.Dom0MinDiskUsagePercent = uint32(i64)
			}
			// Max diskspace for dom0 is 80%.
			if newGlobalConfig.Dom0MinDiskUsagePercent > 80 {
				err = fmt.Errorf("dom0MinDiskUsagePercent (%d) "+
					"> maxAllowed (80). Setting it to 80.",
					newGlobalConfig.Dom0MinDiskUsagePercent)
				log.Errorf("parseConfigItems: %s", err)
				newGlobalConfig.Dom0MinDiskUsagePercent = 80
			}
			log.Infof("Set storage.dom0MinDiskUsagePercent to %d",
				newGlobalConfig.Dom0MinDiskUsagePercent)

		case "storage.apps.ignore.disk.check":
			newBool, err := strconv.ParseBool(item.Value)
			if err != nil {
				log.Errorf("parseConfigItems: bad bool value %s for %s: %s\n",
					item.Value, key, err)
				continue
			}
			newGlobalConfig.IgnoreDiskCheckForApps = newBool

		default:
			// Handle agentname items for loglevels
			newString := item.Value
			components := strings.Split(key, ".")
			if len(components) == 3 && components[0] == "debug" &&
				components[2] == "loglevel" {

				agentName := components[1]
				current := agentlog.LogLevel(gcPtr, agentName)
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
				current := agentlog.RemoteLogLevel(gcPtr, agentName)
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
				unknownConfigItem = true
				err = fmt.Errorf("Unknown configItem %s value %s\n",
					key, item.Value)
				log.Errorf("parseConfigItems: %s", err)
			}
		}
		if err != nil {
			if unknownConfigItem {
				newGlobalStatus.UnknownConfigItems[key] =
					types.ConfigItemStatus{Value: item.Value, Err: err}
			} else {
				err = fmt.Errorf("bad value %s for %s. Error: %s\n",
					item.Value, key, err)
				newGlobalStatus.ConfigItems[key] =
					types.ConfigItemStatus{Err: err}
				log.Errorf("parseConfigItems: %s", err)
			}
			unknownConfigItem = false
			err = nil
		}
	}
	ctx.zedagentCtx.globalStatus = newGlobalStatus
	newGlobalConfig = types.ApplyGlobalConfig(newGlobalConfig)
	// XXX - Should we also not call EnforceGlobalConfigMinimums on
	// newGlobalConfig here before checking if anything changed??
	// Also - if we changed the Config Value based on Min / Max, we should
	// report it to the user.
	if !cmp.Equal(*gcPtr, newGlobalConfig) {
		log.Infof("parseConfigItems: change %v",
			cmp.Diff(*gcPtr, newGlobalConfig))

		oldGlobalConfig := *gcPtr
		*gcPtr = types.EnforceGlobalConfigMinimums(newGlobalConfig)

		// Set GlobalStatus Values from GlobalConfig.
		newGlobalStatus.UpdateItemValuesFromGlobalConfig(*gcPtr)

		if gcPtr.ConfigInterval != oldGlobalConfig.ConfigInterval {
			log.Infof("parseConfigItems: %s change from %d to %d\n",
				"ConfigInterval",
				oldGlobalConfig.ConfigInterval, gcPtr.ConfigInterval)
			updateConfigTimer(gcPtr.ConfigInterval, ctx.configTickerHandle)
		}
		if gcPtr.MetricInterval != oldGlobalConfig.MetricInterval {
			log.Infof("parseConfigItems: %s change from %d to %d\n",
				"MetricInterval",
				oldGlobalConfig.MetricInterval, gcPtr.MetricInterval)
			updateMetricsTimer(gcPtr.MetricInterval, ctx.metricsTickerHandle)
		}
		if gcPtr.SshAuthorizedKeys != oldGlobalConfig.SshAuthorizedKeys {
			log.Infof("parseConfigItems: %v change from %v to %v",
				"SshAuthorizedKeys",
				oldGlobalConfig.SshAuthorizedKeys, gcPtr.SshAuthorizedKeys)
			ssh.UpdateSshAuthorizedKeys(gcPtr.SshAuthorizedKeys)
		}
		err := pubsub.PublishToDir(types.PersistConfigDir, "global", gcPtr)
		if err != nil {
			// XXX - IS there a valid reason for this to Fail? If not, we should
			//  fo log.Fatalf here..
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
		DatastoreID: image.DatastoreID,
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
func computeConfigSha(msg interface{}) []byte {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Fatalf("computeConfigSha: proto.Marshal: %s\n", err)
	}
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// Get sha256 for a subset of the protobuf message.
// Used to determine which pieces changed
func computeConfigElementSha(h hash.Hash, msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Fatalf("computeConfigItemSha: json.Marshal: %s\n", err)
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
		// remove the existing file
		os.Remove(rebootConfigFilename)
		return false
	}

	configHash := computeConfigSha(reboot)
	same := bytes.Equal(configHash, rebootPrevConfigHash)
	rebootPrevConfigHash = configHash
	if same {
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

		// if device reboot is set, ignore op-command
		if getconfigCtx.zedagentCtx.deviceReboot {
			log.Warnf("device reboot is set\n")
			return false
		}

		// Defer if inprogress by returning
		ctx := getconfigCtx.zedagentCtx
		if getconfigCtx.updateInprogress {
			// Wait until TestComplete
			log.Warnf("Rebooting even though testing inprogress; defer\n")
			ctx.rebootCmdDeferred = true
			return false
		}

		infoStr := "NORMAL: handleReboot rebooting"
		handleRebootCmd(ctx, infoStr)
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
		return
	}
	log.Infof("scheduleBackup: Applying updated config %v\n", backup)
	log.Errorf("XXX handle Backup Config: %v\n", backup)
}

// user driven reboot command,
// shutdown the application instances and
// trigger nodeagent, to perform node reboot
func handleRebootCmd(ctxPtr *zedagentContext, infoStr string) {
	if ctxPtr.rebootCmd || ctxPtr.deviceReboot {
		return
	}
	ctxPtr.rebootCmd = true
	// shutdown the application instances
	shutdownAppsGlobal(ctxPtr)
	getconfigCtx := ctxPtr.getconfigCtx
	ctxPtr.rebootReason = infoStr
	publishZedAgentStatus(getconfigCtx)
	log.Infof(infoStr)
}

// nodeagent has initiated a node reboot,
// shutdown application instances
func handleDeviceReboot(ctxPtr *zedagentContext) {
	if ctxPtr.rebootCmd || ctxPtr.deviceReboot {
		return
	}
	ctxPtr.deviceReboot = true
	// shutdown the application instances
	shutdownAppsGlobal(ctxPtr)
	// nothing else to be done
}
