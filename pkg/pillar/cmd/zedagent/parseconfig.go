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
	"sort"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

const (
	MaxBaseOsCount       = 2
	BaseOsImageCount     = 1
	rebootConfigFilename = types.PersistStatusDir + "/rebootConfig"
)

// Returns a rebootFlag
func parseConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext,
	usingSaved bool) bool {

	getconfigCtx.lastReceivedConfig = time.Now()
	ctx := getconfigCtx.zedagentCtx

	// XXX - DO NOT LOG entire config till secrets are in encrypted blobs
	//log.Tracef("parseConfig: EdgeDevConfig: %v", *config)

	// Look for timers and other settings in configItems
	// Process Config items even when rebootFlag is set.. Allows us to
	//  recover if the system got stuck after setting rebootFlag
	parseConfigItems(config, getconfigCtx)

	// Did MaintenanceMode change?
	if ctx.apiMaintenanceMode != config.MaintenanceMode {
		ctx.apiMaintenanceMode = config.MaintenanceMode
		mergeMaintenanceMode(ctx)
	}

	// Did the ForceFallbackCounter change? If so we publish for
	// baseosmgr to take a look
	newForceFallbackCounter := int(ctx.globalConfig.GlobalValueInt(types.ForceFallbackCounter))
	if newForceFallbackCounter != ctx.forceFallbackCounter {
		log.Noticef("ForceFallbackCounter update from %d to %d",
			ctx.forceFallbackCounter, newForceFallbackCounter)
		ctx.forceFallbackCounter = newForceFallbackCounter
		publishZedAgentStatus(ctx.getconfigCtx)
	}

	// Any new reboot command?
	if !usingSaved && parseOpCmds(config, getconfigCtx) {
		log.Noticeln("Reboot flag set, skipping config processing")
		return true
	}

	if getconfigCtx.rebootFlag || ctx.deviceReboot {
		log.Noticef("parseConfig: Ignoring config as rebootFlag set")
	} else if ctx.maintenanceMode {
		log.Noticef("parseConfig: Ignoring config due to maintenanceMode")
	} else {
		handleControllerCertsSha(ctx, config)
		parseCipherContext(getconfigCtx, config)
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
		parseBaseOS(getconfigCtx, config)
		parseBaseOsConfig(getconfigCtx, config)
		parseNetworkInstanceConfig(config, getconfigCtx)
		parseContentInfoConfig(getconfigCtx, config)
		parseVolumeConfig(getconfigCtx, config)

		// parseProfile must be called before processing of app instances from config
		parseProfile(getconfigCtx, config)
		parseAppInstanceConfig(config, getconfigCtx)
		getconfigCtx.lastProcessedConfig = time.Now()
	}
	return false
}

// Walk published AppInstanceConfig's and set Activate=false
// Note that we don't currently wait for the shutdown to complete.
func shutdownApps(getconfigCtx *getconfigContext) {
	pub := getconfigCtx.pubAppInstanceConfig
	items := pub.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		if config.Activate {
			log.Functionf("shutdownApps: clearing Activate for %s uuid %s",
				config.DisplayName, config.Key())
			config.Activate = false
			pub.Publish(config.Key(), config)
		}
	}
}

func shutdownAppsGlobal(ctx *zedagentContext) {
	shutdownApps(ctx.getconfigCtx)
}

var baseOSPrevConfigHash []byte

func parseBaseOS(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	baseOS := config.GetBaseos()
	if baseOS == nil {
		log.Function("parseBaseOS: nil config received")
		return
	}
	h := sha256.New()
	computeConfigElementSha(h, baseOS)
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, baseOSPrevConfigHash)
	if same {
		return
	}
	log.Functionf("parseBaseOS: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"baseOS: %v",
		baseOSPrevConfigHash, configHash, baseOS)
	baseOSPrevConfigHash = configHash
	if baseOS.GetRetryUpdate() != nil {
		if getconfigCtx.configRetryUpdateCounter != baseOS.GetRetryUpdate().GetCounter() {
			log.Noticef("configRetryUpdateCounter update from %d to %d",
				getconfigCtx.configRetryUpdateCounter, baseOS.GetRetryUpdate().GetCounter())
			getconfigCtx.configRetryUpdateCounter = baseOS.GetRetryUpdate().GetCounter()
		}
	}
	cfg := &types.BaseOs{
		ContentTreeUUID:          baseOS.ContentTreeUuid,
		ConfigRetryUpdateCounter: getconfigCtx.configRetryUpdateCounter,
	}
	publishBaseOs(getconfigCtx, cfg)
}

var baseOSConfigPrevConfigHash []byte

func parseBaseOsConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

	cfgOsList := config.GetBase()
	h := sha256.New()
	for _, os := range cfgOsList {
		computeConfigElementSha(h, os)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, baseOSConfigPrevConfigHash)
	if same {
		return
	}
	log.Functionf("parseBaseOsConfig: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"cfgOsList: %v",
		baseOSConfigPrevConfigHash, configHash, cfgOsList)

	baseOSConfigPrevConfigHash = configHash

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
			log.Functionf("parseBaseOsConfig: deleting %s", uuidStr)
			getconfigCtx.pubBaseOsConfig.Unpublish(uuidStr)
		}
	}

	for _, cfgOs := range cfgOsList {
		if cfgOs.GetBaseOSVersion() == "" {
			// Empty slot - silently ignore
			log.Tracef("parseBaseOsConfig ignoring empty %s",
				cfgOs.Uuidandversion.Uuid)
			continue
		}
		baseOs := new(types.BaseOsConfig)

		baseOs.UUIDandVersion.UUID, _ = uuid.FromString(cfgOs.Uuidandversion.Uuid)
		baseOs.UUIDandVersion.Version = cfgOs.Uuidandversion.Version
		baseOs.Activate = cfgOs.GetActivate()
		baseOs.BaseOsVersion = cfgOs.GetBaseOSVersion()
		baseOs.ContentTreeConfigList = make([]types.ContentTreeConfig,
			len(cfgOs.Drives))
		parseContentTreeConfigList(baseOs.ContentTreeConfigList, cfgOs.Drives)

		log.Tracef("parseBaseOsConfig publishing %v",
			baseOs)
		publishBaseOsConfig(getconfigCtx, baseOs)
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
	log.Functionf("parseNetworkXObjectConfig: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"networks: %v",
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
			log.Functionf("NetworkInstance %s (Name: %s) still exists",
				key, networkInstanceEntry.Displayname)
			continue
		}

		config := entry.(types.NetworkInstanceConfig)
		log.Functionf("unpublishing NetworkInstance %s (Name: %s)",
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
				log.Errorf("Bad dnsEntry %s ignored",
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

	log.Functionf("Publish NetworkInstance Config: %+v", networkInstances)

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
		log.Errorf("publishNetworkInstanceConfig(): more than one VPN instance configuration")
		return
	}

	for _, apiConfigEntry := range networkInstances {
		id, err := uuid.FromString(apiConfigEntry.Uuidandversion.Uuid)
		version := apiConfigEntry.Uuidandversion.Version
		if err != nil {
			log.Errorf("NetworkInstanceConfig: Malformed UUID %s. ignored. Err: %s",
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
		log.Functionf("publishNetworkInstanceConfig: processing %s %s type %d activate %v",
			networkInstanceConfig.UUID.String(), networkInstanceConfig.DisplayName,
			networkInstanceConfig.Type, networkInstanceConfig.Activate)

		if apiConfigEntry.Port != nil {
			networkInstanceConfig.Logicallabel = apiConfigEntry.Port.Name
		}
		networkInstanceConfig.IpType = types.AddressType(apiConfigEntry.IpType)

		switch networkInstanceConfig.Type {
		case types.NetworkInstanceTypeSwitch:
			// XXX controller should send AddressTypeNone type for switch
			// network instances
			if networkInstanceConfig.IpType != types.AddressTypeNone {
				log.Errorf("Switch network instance %s %s with invalid IpType %d should be %d",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType,
					types.AddressTypeNone)
				// Let's relax the requirement until cloud side update the right IpType
				networkInstanceConfig.IpType = types.AddressTypeNone
			}
			ctx.pubNetworkInstanceConfig.Publish(networkInstanceConfig.UUID.String(),
				networkInstanceConfig)

		// FIXME:XXX set encap flag, when the dummy interface
		// is tested for the VPN
		case types.NetworkInstanceTypeCloud:
			// if opaque config not set, flag it
			if apiConfigEntry.Cfg == nil {
				log.Errorf("Network instance %s %s, %v, opaque not set",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType)
			} else {
				ocfg := apiConfigEntry.Cfg
				if ocfg.Type != zconfig.ZNetworkOpaqueConfigType_ZNetOConfigVPN {
					log.Errorf("Network instance %s %s, %v invalid config",
						networkInstanceConfig.UUID.String(),
						networkInstanceConfig.DisplayName,
						networkInstanceConfig.IpType)
				}
				networkInstanceConfig.OpaqueConfig = ocfg.Oconfig
			}
			// if not IPv4 type, flag it
			if networkInstanceConfig.IpType != types.AddressTypeIPV4 {
				log.Errorf("Network instance %s %s, %v not IPv4 type",
					networkInstanceConfig.UUID.String(),
					networkInstanceConfig.DisplayName,
					networkInstanceConfig.IpType)
			}
		}

		// other than switch-type(l2)
		// if ip type is l3, do the needful
		if networkInstanceConfig.IpType != types.AddressTypeNone {
			err := parseIpspec(apiConfigEntry.Ip, &networkInstanceConfig)
			if err != nil {
				errStr := fmt.Sprintf("Network Instance %s parameter parse failed: %s",
					networkInstanceConfig.Key(), err)
				log.Error(errStr)
				networkInstanceConfig.SetErrorNow(errStr)
				// Proceed to send error back to controller
			}

			parseDnsNameToIpList(apiConfigEntry,
				&networkInstanceConfig)
		}

		ctx.pubNetworkInstanceConfig.Publish(networkInstanceConfig.UUID.String(),
			networkInstanceConfig)
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
	log.Functionf("parseNetworkInstanceConfig: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"networkInstances: %v",
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
	log.Functionf("parseAppInstanceConfig: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"Apps: %v",
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
			log.Functionf("Remove app config %s", uuidStr)
			getconfigCtx.pubAppInstanceConfig.Unpublish(uuidStr)
		}
	}

	for _, cfgApp := range Apps {
		// Note that we repeat this even if the app config didn't
		// change but something else in the EdgeDeviceConfig did
		log.Tracef("New/updated app instance %v", cfgApp)
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
		appInstance.FixedResources.DisableLogs = cfgApp.Fixedresources.DisableLogs
		appInstance.MetaDataType = types.MetaDataType(cfgApp.MetaDataType)

		appInstance.VolumeRefConfigList = make([]types.VolumeRefConfig,
			len(cfgApp.VolumeRefList))
		parseVolumeRefList(appInstance.VolumeRefConfigList, cfgApp.GetVolumeRefList())

		// fill in the collect stats IP address of the App
		appInstance.CollectStatsIPAddr = net.ParseIP(cfgApp.GetCollectStatsIPAddr())

		// fill the app adapter config
		parseAppNetworkConfig(&appInstance, cfgApp, config.Networks,
			config.NetworkInstances)

		// I/O adapters
		appInstance.IoAdapterList = nil
		for _, adapter := range cfgApp.Adapters {
			log.Tracef("Processing adapter type %d name %s",
				adapter.Type, adapter.Name)
			appInstance.IoAdapterList = append(appInstance.IoAdapterList,
				types.IoAdapter{Type: types.IoType(adapter.Type),
					Name: adapter.Name})
		}
		log.Functionf("Got adapters %v", appInstance.IoAdapterList)

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
		appInstance.CipherBlockStatus = parseCipherBlock(getconfigCtx, appInstance.Key(),
			cfgApp.GetCipherData())
		appInstance.ProfileList = cfgApp.ProfileList

		// Verify that it fits and if not publish with error
		checkAndPublishAppInstanceConfig(getconfigCtx, appInstance)
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
	// XXX secrets like wifi credentials in here
	if false {
		log.Functionf("parseSystemAdapterConfig: Applying updated config "+
			"prevSha: % x, "+
			"NewSha : % x, "+
			"sysAdapters: %v, "+
			"Forced parsing: %v",
			systemAdaptersPrevConfigHash, configHash, sysAdapters, forceParse)
	}
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
		log.Functionf("parseSystemAdapterConfig: No Port configuration present")
		return
	}
	portConfig := &types.DevicePortConfig{}
	portConfig.Version = version
	portConfig.Ports = newPorts

	// Check if all management ports have errors
	// Propagate any parse errors for all ports to the DPC
	// since controller expects LastError and LastFailed for the DPC
	ok := false
	mgmtCount := 0
	errStr := ""
	for _, p := range portConfig.Ports {
		if !p.IsMgmt {
			continue
		}
		mgmtCount++
		if !p.HasError() {
			ok = true
			break
		}
		errStr += p.LastError + "\n"
	}
	if !ok {
		if errStr != "" {
			errStr = "All management ports failed to parse: " + errStr
		} else if mgmtCount == 0 {
			errStr = "No management interfaces"
		} else {
			errStr = "All management ports failed parser"
		}
		portConfig.RecordFailure(errStr)
	}

	// Any content change?
	// Even if only ErrorAndTime changed we publish so
	// the change can be sent back to the controller using ctx.devicePortConfigList
	if cmp.Equal(getconfigCtx.devicePortConfig.Ports, portConfig.Ports) &&
		getconfigCtx.devicePortConfig.Version == portConfig.Version {
		log.Functionf("parseSystemAdapterConfig: DevicePortConfig - " +
			"Done with no change")
		return
	}
	log.Functionf("parseSystemAdapterConfig: version %d/%d differs",
		getconfigCtx.devicePortConfig.Version, portConfig.Version)

	// This is suboptimal after a reboot since the config will be the same
	// yet the timestamp be new. HandleDPCModify takes care of that.
	portConfig.TimePriority = time.Now()
	getconfigCtx.devicePortConfig = *portConfig

	getconfigCtx.pubDevicePortConfig.Publish("zedagent", *portConfig)

	log.Functionf("parseSystemAdapterConfig: Done")
}

// Returns a port if it should be added to the list; some errors result in
// adding a port to to DevicePortConfig with ErrorAndTime set.
func parseOneSystemAdapterConfig(getconfigCtx *getconfigContext,
	sysAdapter *zconfig.SystemAdapter,
	version types.DevicePortConfigVersion) *types.NetworkPortConfig {

	log.Functionf("XXX parseOneSystemAdapterConfig name %s lowerLayerName %s",
		sysAdapter.Name, sysAdapter.LowerLayerName)
	port := new(types.NetworkPortConfig)

	port.Logicallabel = sysAdapter.Name // XXX Rename field in protobuf?
	port.Alias = sysAdapter.Alias
	// Look up using LowerLayerName which should match a phyio PhysicalLabel.
	// If LowerLayerName was not set we use Name i.e., assume
	// Phylabel and Logicallabel are the same
	if sysAdapter.LowerLayerName == "" {
		port.Phylabel = sysAdapter.Name
	} else {
		port.Phylabel = sysAdapter.LowerLayerName
	}
	phyio := lookupDeviceIoLogicallabel(getconfigCtx, port.Logicallabel)
	if phyio == nil {
		phyio = lookupDeviceIoPhylabel(getconfigCtx, port.Phylabel)
	}
	if phyio == nil {
		// We will re-check when phyio changes.
		errStr := fmt.Sprintf("Missing phyio for %s lower %s; ignored",
			sysAdapter.Name, sysAdapter.LowerLayerName)
		log.Error(errStr)
		return nil
	}
	if !types.IoType(phyio.Ptype).IsNet() {
		errStr := fmt.Sprintf("phyio for %s lower %s not IsNet; ignored",
			sysAdapter.Name, sysAdapter.LowerLayerName)
		log.Error(errStr)
		return nil
	}
	if port.Logicallabel != phyio.Logicallabel {
		errStr := fmt.Sprintf("phyio for %s lower %s mismatched logicallabel %s vs %s",
			sysAdapter.Name, sysAdapter.LowerLayerName,
			port.Logicallabel, phyio.Logicallabel)
		log.Warn(errStr)
	}
	port.Phylabel = phyio.Phylabel
	port.IfName = phyio.Phyaddr.Ifname
	if port.IfName == "" {
		// Might not be set for all models
		log.Warnf("Phyio for phylabel %s logicallabel %s has no ifname",
			phyio.Phylabel, phyio.Logicallabel)
		if phyio.Logicallabel != "" {
			port.IfName = phyio.Logicallabel
		} else {
			port.IfName = phyio.Phylabel
		}
	}
	// We check if any phyio has FreeUplink set. If so we operate
	// in old mode which means that cost is 1 if FreeUplink == false
	// XXX Remove this when all controllers send cost.
	oldController := anyDeviceIoWithFreeUplink(getconfigCtx)
	log.Functionf("Found phyio for %s: free %t, oldController: %t",
		sysAdapter.Name, phyio.UsagePolicy.FreeUplink, oldController)

	var portCost uint8
	if sysAdapter.Cost > 255 {
		log.Warnf("SysAdpter cost %d for %s clamped to 255",
			sysAdapter.Cost, sysAdapter.Name)
		portCost = 255
	} else {
		portCost = uint8(sysAdapter.Cost)
	}
	if portCost == 0 {
		if phyio.UsagePolicy.FreeUplink || sysAdapter.FreeUplink {
			portCost = 0
		} else if oldController {
			log.Warnf("XXX oldController and !FreeUplink; assume %s cost=1",
				sysAdapter.Name)
			portCost = 1
		}
	}

	var isMgmt bool
	if version < types.DPCIsMgmt {
		log.Warnf("XXX old version; assuming %s isMgmt and cost=0",
			sysAdapter.Name)
		// This should go away when cloud sends proper values
		isMgmt = true
		portCost = 0
	} else {
		isMgmt = sysAdapter.Uplink
	}

	log.Functionf("System adapter %s, isMgmt: %t cost: %d free %t",
		sysAdapter.Name, isMgmt, portCost, sysAdapter.FreeUplink)

	port.IsMgmt = isMgmt
	port.Cost = portCost
	port.Dhcp = types.DT_NONE
	var ip net.IP
	var network *types.NetworkXObjectConfig
	if sysAdapter.Addr != "" {
		ip = net.ParseIP(sysAdapter.Addr)
		if ip == nil {
			errStr := fmt.Sprintf("Device Config Error. Port %s has Bad "+
				"SysAdapter.Addr %s. The IP address is ignored. Please fix the "+
				"device configuration.", sysAdapter.Name, sysAdapter.Addr)
			log.Errorf("parseSystemAdapterConfig: %s", errStr)
			port.RecordFailure(errStr)
			// IP will not be set below
		}
		// Note that ip is not used unless we have a network UUID
	}
	if sysAdapter.NetworkUUID != "" &&
		sysAdapter.NetworkUUID != nilUUID.String() {

		// Lookup the network with given UUID
		// and copy proxy and other configuration
		networkXObject, err := getconfigCtx.pubNetworkXObjectConfig.Get(sysAdapter.NetworkUUID)
		if err != nil {
			// XXX when do we retry looking for the networkXObject?
			errStr := fmt.Sprintf("Device Config Error. Port %s configured with "+
				"UNKNOWN Network UUID (%s). Err: %s. Please fix the "+
				"device configuration.",
				port.IfName, sysAdapter.NetworkUUID, err)
			log.Errorf("parseSystemAdapterConfig: %s", errStr)
			port.RecordFailure(errStr)
		} else {
			net := networkXObject.(types.NetworkXObjectConfig)
			port.NetworkUUID = net.UUID
			port.Type = net.Type
			network = &net
			if network.HasError() {
				errStr := fmt.Sprintf("Port %s configured with a network "+
					"(UUID: %s) which has an error (%s).",
					port.IfName, port.NetworkUUID, network.Error)
				log.Errorf("parseSystemAdapterConfig: %s", errStr)
				port.RecordFailure(errStr)
			}
		}

		if network != nil {
			if ip != nil {
				addrSubnet := network.Subnet
				addrSubnet.IP = ip
				port.AddrSubnet = addrSubnet.String()
			}
			port.WirelessCfg = network.WirelessCfg
			port.Gateway = network.Gateway
			port.DomainName = network.DomainName
			port.NtpServer = network.NtpServer
			port.DnsServers = network.DnsServers
			// Need to be careful since zedcloud can feed us bad Dhcp type
			port.Dhcp = network.Dhcp
		}
		switch port.Dhcp {
		case types.DT_STATIC:
			if port.AddrSubnet == "" {
				errStr := fmt.Sprintf("Port %s Configured as DT_STATIC but "+
					"missing subnet address. SysAdapter - Name: %s, Addr:%s",
					port.IfName, sysAdapter.Name, sysAdapter.Addr)
				log.Errorf("parseSystemAdapterConfig: %s", errStr)
				port.RecordFailure(errStr)
			}
		case types.DT_CLIENT:
			// Do nothing
		case types.DT_NONE:
			if isMgmt {
				errStr := fmt.Sprintf("Port %s configured as Management port "+
					"with an unsupported DHCP type %d. Client and static are "+
					"the only allowed DHCP modes for management ports.",
					port.IfName, types.DT_NONE)

				log.Errorf("parseSystemAdapterConfig: %s", errStr)
				port.RecordFailure(errStr)
			}
		default:
			errStr := fmt.Sprintf("Port %s configured with unknown DHCP type %v",
				port.IfName, network.Dhcp)
			log.Errorf("parseSystemAdapterConfig: %s", errStr)
			port.RecordFailure(errStr)
		}
		// XXX use DnsNameToIpList?
		if network != nil && network.Proxy != nil {
			port.ProxyConfig = *network.Proxy
		}
	} else if isMgmt {
		errStr := fmt.Sprintf("Port %s Configured as Management port without "+
			"configuring a Network. Network is required for Management ports",
			port.IfName)
		log.Errorf("parseSystemAdapterConfig: %s", errStr)
		port.RecordFailure(errStr)
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
	// XXX secrets like wifi credentials in here
	if false {
		log.Functionf("parseDeviceIoListConfig: Applying updated config "+
			"prevSha: % x, "+
			"NewSha : % x, "+
			"deviceIoList: %v",
			deviceIoListPrevConfigHash, configHash, deviceIoList)
	}

	deviceIoListPrevConfigHash = configHash

	phyIoAdapterList := types.PhysicalIOAdapterList{}
	phyIoAdapterList.AdapterList = make([]types.PhysicalIOAdapter, 0)

	for indx, ioDevicePtr := range deviceIoList {
		if ioDevicePtr == nil {
			log.Errorf("parseDeviceIoListConfig: nil ioDevicePtr at indx %d",
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
			// Need to keep this to make proper determination
			// for SystemAdapter
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
			case "usbaddr":
				port.Phyaddr.UsbAddr = value
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

	log.Functionf("parseDeviceIoListConfig: Done")
	return true
}

func lookupDeviceIoPhylabel(getconfigCtx *getconfigContext, label string) *types.PhysicalIOAdapter {
	for _, port := range getconfigCtx.zedagentCtx.physicalIoAdapterMap {
		if port.Phylabel == label {
			return &port
		}
	}
	return nil
}

func lookupDeviceIoLogicallabel(getconfigCtx *getconfigContext, label string) *types.PhysicalIOAdapter {
	for _, port := range getconfigCtx.zedagentCtx.physicalIoAdapterMap {
		if port.Logicallabel == label {
			return &port
		}
	}
	return nil
}

func anyDeviceIoWithFreeUplink(getconfigCtx *getconfigContext) bool {
	for _, port := range getconfigCtx.zedagentCtx.physicalIoAdapterMap {
		if port.UsagePolicy.FreeUplink {
			return true
		}
	}
	return false
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
	log.Functionf("parseDatastoreConfig: Applying updated datastore config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"Num Stores: %d",
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
		log.Tracef("publishDatastoresConfig: unpublishing %s", k)
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

		datastore.DsCertPEM = ds.GetDsCertPEM()

		datastore.CipherBlockStatus = parseCipherBlock(ctx, datastore.Key(),
			ds.GetCipherData())
		ctx.pubDatastoreConfig.Publish(datastore.Key(), *datastore)
	}
}

func parseContentTreeConfigList(contentTreeList []types.ContentTreeConfig, drives []*zconfig.Drive) {

	var idx int = 0

	for _, drive := range drives {
		contentTree := new(types.ContentTreeConfig)
		if drive.Image == nil {
			log.Errorf("No drive.Image for drive %v",
				drive)
			// Pass on for error reporting
			contentTree.ContentID = nilUUID
		} else {
			contentTree.ContentID, _ = uuid.FromString(drive.Image.Uuidandversion.Uuid)
			contentTree.DatastoreID, _ = uuid.FromString(drive.Image.DsId)
			contentTree.RelativeURL = drive.Image.Name
			contentTree.Format = drive.Image.Iformat
			contentTree.ContentSha256 = strings.ToLower(drive.Image.Sha256)
			contentTree.MaxDownloadSize = uint64(drive.Image.SizeBytes)
			contentTree.DisplayName = drive.Image.Name
		}
		contentTreeList[idx] = *contentTree
		idx++
	}
}

func parseVolumeRefList(volumeRefConfigList []types.VolumeRefConfig,
	volumeRefs []*zconfig.VolumeRef) {

	var idx int
	for _, volumeRef := range volumeRefs {
		volume := new(types.VolumeRefConfig)
		volume.VolumeID, _ = uuid.FromString(volumeRef.Uuid)
		volume.GenerationCounter = volumeRef.GenerationCount
		volume.RefCount = 1
		volume.MountDir = volumeRef.GetMountDir()
		volumeRefConfigList[idx] = *volume
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
		log.Tracef("publishNetworkXObjectConfig: unpublishing %s", k)
		ctx.pubNetworkXObjectConfig.Unpublish(k)
	}

	// XXX note that we currently get repeats in the same loop since
	// the controller can send the same network multiple times.
	// Should we track them and not rewrite them?
	for _, netEnt := range cfgNetworks {
		config := parseOneNetworkXObjectConfig(ctx, netEnt)
		if config != nil {
			ctx.pubNetworkXObjectConfig.Publish(config.Key(),
				*config)
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
		log.Error(errStr)
		config.SetErrorNow(errStr)
		return config
	}
	config.UUID = id

	log.Functionf("parseOneNetworkXObjectConfig: processing %s type %d",
		config.Key(), config.Type)

	// proxy configuration from cloud network configuration
	netProxyConfig := netEnt.GetEntProxy()
	if netProxyConfig == nil {
		log.Functionf("parseOneNetworkXObjectConfig: EntProxy of network %s is nil",
			netEnt.Id)
	} else {
		log.Functionf("parseOneNetworkXObjectConfig: Proxy configuration present in %s",
			netEnt.Id)

		proxyConfig := types.ProxyConfig{
			NetworkProxyEnable: netProxyConfig.NetworkProxyEnable,
			NetworkProxyURL:    netProxyConfig.NetworkProxyURL,
			Pacfile:            netProxyConfig.Pacfile,
			ProxyCertPEM:       netProxyConfig.ProxyCertPEM,
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
			log.Tracef("parseOneNetworkXObjectConfig: Adding proxy entry %s:%d in %s",
				proxyEntry.Server, proxyEntry.Port, netEnt.Id)
		}

		config.Proxy = &proxyConfig
	}

	// wireless property configuration
	config.WirelessCfg = parseNetworkWirelessConfig(ctx, config.Key(), netEnt)

	ipspec := netEnt.GetIp()
	switch config.Type {
	case types.NT_IPV4, types.NT_IPV6:
		if ipspec == nil {
			errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: Missing ipspec for %s in %v",
				config.Key(), netEnt)
			log.Error(errStr)
			config.SetErrorNow(errStr)
			return config
		}
		err := parseIpspecNetworkXObject(ipspec, config)
		if err != nil {
			errStr := fmt.Sprintf("Network parameter parse for %s failed: %s",
				config.Key(), err)
			log.Error(errStr)
			config.SetErrorNow(errStr)
			return config
		}
	case types.NT_NOOP:
		// XXX is controller still sending static and dynamic entries with NT_NOOP? Why?
		if ipspec != nil {
			log.Warnf("XXX NT_NOOP for %s with ipspec %v",
				config.Key(), ipspec)
			err := parseIpspecNetworkXObject(ipspec, config)
			if err != nil {
				errStr := fmt.Sprintf("Network parameter parse for %s failed: %s",
					config.Key(), err)
				log.Error(errStr)
				config.SetErrorNow(errStr)
				return config
			}
		}

	default:
		errStr := fmt.Sprintf("parseOneNetworkXObjectConfig: Unknown NetworkConfig type %d for %s in %v; ignored",
			config.Type, id.String(), netEnt)
		log.Error(errStr)
		config.SetErrorNow(errStr)
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
				config.SetErrorNow(errStr)
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

func parseNetworkWirelessConfig(ctx *getconfigContext, key string, netEnt *zconfig.NetworkConfig) types.WirelessConfig {
	var wconfig types.WirelessConfig

	netWireless := netEnt.GetWireless()
	if netWireless == nil {
		return wconfig
	}
	log.Functionf("parseNetworkWirelessConfig: Wireless of network present in %s, config %v", netEnt.Id, netWireless)

	wType := netWireless.GetType()
	switch wType {
	case zconfig.WirelessType_Cellular:
		//
		wconfig.WType = types.WirelessTypeCellular
		cellulars := netWireless.GetCellularCfg()
		for _, cellular := range cellulars {
			var wcell types.CellConfig
			wcell.APN = cellular.GetAPN()
			wcell.ProbeAddr = cellular.GetProbe().GetProbeAddress()
			wcell.DisableProbe = cellular.GetProbe().GetDisable()
			wconfig.Cellular = append(wconfig.Cellular, wcell)
		}
		log.Functionf("parseNetworkWirelessConfig: Wireless of network Cellular, %v", wconfig.Cellular)
	case zconfig.WirelessType_WiFi:
		//
		wconfig.WType = types.WirelessTypeWifi
		wificfgs := netWireless.GetWifiCfg()

		for _, wificfg := range wificfgs {
			var wifi types.WifiConfig
			wifi.SSID = wificfg.GetWifiSSID()
			if wificfg.GetKeyScheme() == zconfig.WiFiKeyScheme_WPAPSK {
				wifi.KeyScheme = types.KeySchemeWpaPsk
			} else if wificfg.GetKeyScheme() == zconfig.WiFiKeyScheme_WPAEAP {
				wifi.KeyScheme = types.KeySchemeWpaEap
			}
			wifi.Identity = wificfg.GetIdentity()
			wifi.Password = wificfg.GetPassword()
			wifi.Priority = wificfg.GetPriority()
			key = fmt.Sprintf("%s-%s", key, wifi.SSID)
			wifi.CipherBlockStatus = parseCipherBlock(ctx, key,
				wificfg.GetCipherData())

			wconfig.Wifi = append(wconfig.Wifi, wifi)
		}
		log.Functionf("parseNetworkWirelessConfig: Wireless of network Wifi, %v", wconfig.Wifi)
	default:
		log.Errorf("parseNetworkWirelessConfig: unsupported wireless configure type %d", wType)
	}
	return wconfig
}

func parseIpspecNetworkXObject(ipspec *zconfig.Ipspec, config *types.NetworkXObjectConfig) error {
	config.Dhcp = types.DhcpType(ipspec.Dhcp)
	config.DomainName = ipspec.GetDomain()
	if s := ipspec.GetSubnet(); s != "" {
		_, subnet, err := net.ParseCIDR(s)
		if err != nil {
			return errors.New(fmt.Sprintf("bad subnet %s: %s",
				s, err))
		}
		config.Subnet = *subnet
	}
	if g := ipspec.GetGateway(); g != "" {
		config.Gateway = net.ParseIP(g)
		if config.Gateway == nil {
			return errors.New(fmt.Sprintf("bad gateway IP %s",
				g))
		}
	}
	if n := ipspec.GetNtp(); n != "" {
		config.NtpServer = net.ParseIP(n)
		if config.NtpServer == nil {
			return errors.New(fmt.Sprintf("bad ntp IP %s",
				n))
		}
	}
	for _, dsStr := range ipspec.GetDns() {
		ds := net.ParseIP(dsStr)
		if ds == nil {
			return errors.New(fmt.Sprintf("bad dns IP %s",
				dsStr))
		}
		config.DnsServers = append(config.DnsServers, ds)
	}
	if dr := ipspec.GetDhcpRange(); dr != nil && dr.GetStart() != "" {
		start := net.ParseIP(dr.GetStart())
		if start == nil {
			return errors.New(fmt.Sprintf("bad start IP %s",
				dr.GetStart()))
		}
		end := net.ParseIP(dr.GetEnd())
		if end == nil && dr.GetEnd() != "" {
			return errors.New(fmt.Sprintf("bad end IP %s",
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
	// Parse NTP Server
	if n := ipspec.GetNtp(); n != "" {
		config.NtpServer = net.ParseIP(n)
		if config.NtpServer == nil {
			return errors.New(fmt.Sprintf("bad ntp IP %s",
				n))
		}
	}
	// Parse Dns Servers
	for _, dsStr := range ipspec.GetDns() {
		ds := net.ParseIP(dsStr)
		if ds == nil {
			return errors.New(fmt.Sprintf("bad dns IP %s",
				dsStr))
		}
		config.DnsServers = append(config.DnsServers, ds)
	}
	// Parse Subnet
	if s := ipspec.GetSubnet(); s != "" {
		_, subnet, err := net.ParseCIDR(s)
		if err != nil {
			return errors.New(fmt.Sprintf("bad subnet %s: %s",
				s, err))
		}
		config.Subnet = *subnet
	}
	// Parse Gateway
	if g := ipspec.GetGateway(); g != "" {
		config.Gateway = net.ParseIP(g)
		if config.Gateway == nil {
			return errors.New(fmt.Sprintf("bad gateway IP %s",
				g))
		}
	}
	// Parse DhcpRange
	if dr := ipspec.GetDhcpRange(); dr != nil && dr.GetStart() != "" {
		start := net.ParseIP(dr.GetStart())
		if start == nil {
			return errors.New(fmt.Sprintf("bad start IP %s",
				dr.GetStart()))
		}
		end := net.ParseIP(dr.GetEnd())
		if end == nil && dr.GetEnd() != "" {
			return errors.New(fmt.Sprintf("bad end IP %s",
				dr.GetEnd()))
		}
		config.DhcpRange.Start = start
		config.DhcpRange.End = end
	}

	addrCount := types.GetIPAddrCountOnSubnet(config.Subnet)
	if addrCount <= types.MinSubnetSize {
		return fmt.Errorf("network(%s), Subnet too small(%d)",
			config.Key(), addrCount)
	}

	// if not set, take some default
	if config.Gateway == nil {
		config.Gateway = types.AddToIP(config.Subnet.IP, 1)
		log.Warnf("network(%s), No Gateway, setting default(%s)",
			config.Key(), config.Gateway.String())
	}
	dhcpRangeStart := 2
	if addrCount >= types.LargeSubnetSize {
		// the dhcpRange starts at the half point,
		// provided the DhcpRange.End is not set
		if config.DhcpRange.End == nil {
			dhcpRangeStart = addrCount / 2
		}
	}
	// last addressable endpoint, with 0 base, and subnet.IP as start,
	// it accounts for (2^(iplen - subnetMask) - 2) addresses
	dhcpRangeEnd := addrCount - 2

	// if not set, take some default
	if config.DhcpRange.Start == nil {
		config.DhcpRange.Start = types.AddToIP(config.Subnet.IP,
			dhcpRangeStart)
		log.Warnf("network(%s), No Dhcp Start, setting default(%s)",
			config.Key(), config.DhcpRange.Start.String())
	}
	if config.DhcpRange.End == nil {
		config.DhcpRange.End = types.AddToIP(config.Subnet.IP,
			dhcpRangeEnd)
		log.Warnf("network(%s), No Dhcp End, setting default(%s)",
			config.Key(), config.DhcpRange.End.String())
	}
	// check whether the dhcp range(start, end)
	// equal (network, gateway, broadcast) addresses
	if network := types.GetIPNetwork(config.Subnet); network != nil {
		if network.Equal(config.DhcpRange.Start) {
			log.Warnf("network(%s), Dhcp Start is Network(%s), correcting",
				config.Key(), config.Subnet.IP.String())
			config.DhcpRange.Start =
				types.AddToIP(config.DhcpRange.Start, 1)
		}
		if config.Gateway.Equal(config.DhcpRange.Start) {
			log.Warnf("network(%s), Dhcp Start is Gateway(%s), correcting",
				config.Key(), config.Gateway.String())
			config.DhcpRange.Start =
				types.AddToIP(config.Gateway, 1)
		}
	}
	if bcast := types.GetIPBroadcast(config.Subnet); bcast != nil {
		if bcast.Equal(config.DhcpRange.End) {
			log.Warnf("network(%s), Dhcp End is Broadcast(%s), correcting",
				config.Key(), bcast.String())
			config.DhcpRange.End =
				types.AddToIP(config.DhcpRange.End, -1)
		}
	}
	// Gateway should not be inside the DhcpRange
	if config.DhcpRange.Contains(config.Gateway) {
		return fmt.Errorf("gateway(%s) inside Dhcp Range",
			config.Gateway.String())
	}
	return nil
}

func parseAppNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig,
	cfgNetworkInstances []*zconfig.NetworkInstanceConfig) {

	parseUnderlayNetworkConfig(appInstance, cfgApp, cfgNetworks,
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
			log.Functionf("Nil underlay config for Interface %s", intfEnt.Name)
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
	// sort based on intfOrder
	// XXX remove? Debug?
	if len(appInstance.UnderlayNetworkList) > 1 {
		log.Functionf("XXX pre sort %+v", appInstance.UnderlayNetworkList)
	}
	sort.Slice(appInstance.UnderlayNetworkList[:],
		func(i, j int) bool {
			return appInstance.UnderlayNetworkList[i].IntfOrder <
				appInstance.UnderlayNetworkList[j].IntfOrder
		})
	// XXX remove? Debug?
	if len(appInstance.UnderlayNetworkList) > 1 {
		log.Functionf("XXX post sort %+v", appInstance.UnderlayNetworkList)
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
	// XXX set ulCfg.IntfOrder from API once available
	var intfOrder int32
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
	log.Functionf("NetworkInstance(%s-%s): InstType %v",
		cfgApp.Displayname, cfgApp.Uuidandversion.Uuid,
		networkInstanceEntry.InstType)

	ulCfg.Network = uuid
	if intfEnt.MacAddress != "" {
		log.Functionf("parseUnderlayNetworkConfig: got static MAC %s",
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
		log.Functionf("parseUnderlayNetworkConfig: got static IP %s",
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
		// XXX temporary until we get an intfOrder in the API
		if intfOrder == 0 {
			intfOrder = acl.Id
		}
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
			actionCfg.Drop = action.Drop
			aclCfg.Actions[actionIdx] = *actionCfg
		}
		ulCfg.ACLs[aclIdx] = *aclCfg
	}
	// XXX set ulCfg.IntfOrder from API once available
	ulCfg.IntfOrder = intfOrder
	ulCfg.AccessVlanID = intfEnt.AccessVlanId
	return ulCfg
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
	log.Functionf("parseConfigItems: Applying updated config "+
		"prevSha: % x, "+
		"NewSha : % x, "+
		"items: %v",
		itemsPrevConfigHash, configHash, items)

	// Start with the defaults so that we revert to default when no data
	// 1) Use the specified Value if no Errors
	// 2) Is there are Errors ( Parse Errors or > Max or  < Min errors),
	//  retain the previous value with Error set. In case of val > Max
	//  or val < Min, Do not try to correct it. Either take the specified
	//  value or retain the previous value.
	gcPtr := &ctx.zedagentCtx.globalConfig
	newGlobalConfig := types.DefaultConfigItemValueMap()
	// Note: UsbAccess is special in that it has two defaults.
	// When the device first boots the default is "true" as specified
	// in the DefaultConfigItemValueMap. But when connecting to the
	// controller, if the controller does not include the item, it
	// should default to "false".
	// That way bringup of new hardware models can be done using an
	// attached keyboard.
	newGlobalConfig.SetGlobalValueBool(types.UsbAccess, false)
	newGlobalStatus := types.NewGlobalStatus()

	for _, item := range items {
		itemValue, err := ctx.zedagentCtx.specMap.ParseItem(newGlobalConfig,
			gcPtr, item.Key, item.Value)
		newGlobalStatus.ConfigItems[item.Key] = types.ConfigItemStatus{
			Err:   err,
			Value: itemValue.StringValue(),
		}
		log.Tracef("Processed ConfigItem: key: %s, Value: %s, itemValue: %+v",
			item.Key, item.Value, itemValue)
	}
	log.Tracef("Done with Parsing ConfigItems. globalStatus: %+v",
		*newGlobalStatus)
	ctx.zedagentCtx.globalStatus = *newGlobalStatus
	// XXX - Should we also not call EnforceGlobalConfigMinimums on
	// newGlobalConfig here before checking if anything changed??
	// Also - if we changed the Config Value based on Min / Max, we should
	// report it to the user.
	if !cmp.Equal(*gcPtr, newGlobalConfig) {
		log.Functionf("parseConfigItems: change %v",
			cmp.Diff(*gcPtr, newGlobalConfig))
		oldGlobalConfig := *gcPtr
		*gcPtr = *newGlobalConfig

		// Set GlobalStatus Values from GlobalConfig.
		oldConfigInterval := oldGlobalConfig.GlobalValueInt(types.ConfigInterval)
		newConfigInterval := newGlobalConfig.GlobalValueInt(types.ConfigInterval)

		oldMetricInterval := oldGlobalConfig.GlobalValueInt(types.MetricInterval)
		newMetricInterval := newGlobalConfig.GlobalValueInt(types.MetricInterval)

		if newConfigInterval != oldConfigInterval {
			log.Functionf("parseConfigItems: %s change from %d to %d",
				"ConfigInterval", oldConfigInterval, newConfigInterval)
			updateConfigTimer(newConfigInterval, ctx.configTickerHandle)
			updateConfigTimer(newConfigInterval, ctx.localProfileTickerHandle)
		}
		if newMetricInterval != oldMetricInterval {
			log.Functionf("parseConfigItems: %s change from %d to %d",
				"MetricInterval", oldMetricInterval, newMetricInterval)
			updateMetricsTimer(newMetricInterval, ctx.metricsTickerHandle)
		}
		oldMaintenanceMode := oldGlobalConfig.GlobalValueTriState(types.MaintenanceMode)
		newMaintenanceMode := newGlobalConfig.GlobalValueTriState(types.MaintenanceMode)
		if oldMaintenanceMode != newMaintenanceMode {
			ctx.zedagentCtx.gcpMaintenanceMode = newMaintenanceMode
			mergeMaintenanceMode(ctx.zedagentCtx)
		}

		pub := ctx.zedagentCtx.pubGlobalConfig
		err := pub.Publish("global", *gcPtr)
		if err != nil {
			// Could fail if no space in filesystem
			log.Errorf("PublishToDir for globalConfig failed %s", err)
		}
		triggerPublishDevInfo(ctx.zedagentCtx)
	}
}

// mergeMaintenanceMode handles the configItem override (unless NONE)
// and the API setting
func mergeMaintenanceMode(ctx *zedagentContext) {
	switch ctx.gcpMaintenanceMode {
	case types.TS_ENABLED:
		// Overrides everything, and sets maintenance mode
		ctx.maintenanceMode = true
		ctx.maintModeReason = types.MaintenanceModeReasonUserRequested
	case types.TS_DISABLED:
		// Overrides everything, and resets maintenance mode
		ctx.maintenanceMode = false
		ctx.maintModeReason = types.MaintenanceModeReasonNone
	case types.TS_NONE:
		// Now, look at user config and local triggers
		ctx.maintenanceMode = ctx.apiMaintenanceMode || ctx.localMaintenanceMode
		if ctx.apiMaintenanceMode {
			// set reason as user requested
			ctx.maintModeReason = types.MaintenanceModeReasonUserRequested
		} else if ctx.localMaintenanceMode {
			// set reason to reflect exact local reason
			ctx.maintModeReason = ctx.localMaintModeReason
		}
	}
	log.Noticef("Changed maintenanceMode to %t, with reason as %s, considering {%v, %v, %v}",
		ctx.maintenanceMode, ctx.maintModeReason.String(), ctx.gcpMaintenanceMode,
		ctx.apiMaintenanceMode, ctx.localMaintenanceMode)
}

func checkAndPublishAppInstanceConfig(getconfigCtx *getconfigContext,
	config types.AppInstanceConfig) {

	key := config.Key()
	log.Tracef("checkAndPublishAppInstanceConfig UUID %s", key)
	pub := getconfigCtx.pubAppInstanceConfig
	if err := pub.CheckMaxSize(key, config); err != nil {
		log.Error(err)
		var clearNumBytes int
		if config.CloudInitUserData != nil {
			clearNumBytes = len(*config.CloudInitUserData)
		}
		cryptoNumBytes := len(config.CipherData)
		numACLs := 0
		for i := range config.UnderlayNetworkList {
			numACLs += len(config.UnderlayNetworkList[i].ACLs)
		}
		if clearNumBytes == 0 && cryptoNumBytes == 0 {
			// Issue must be due to ACLs
			err = fmt.Errorf("App instance has too many ACLs: %d",
				numACLs)
			// Approximate number; 20 can never be a problem
		} else if numACLs < 20 {
			if clearNumBytes == 0 {
				err = fmt.Errorf("App instance encrypted cloud-init user data too large: %d bytes",
					cryptoNumBytes)
			} else {
				err = fmt.Errorf("App instance cloud-init user data too large: %d + %d bytes",
					clearNumBytes, cryptoNumBytes)
			}
		} else {
			if clearNumBytes == 0 {
				err = fmt.Errorf("App instance encrypted cloud-init user data %d bytes plus %d ACLs too large",
					cryptoNumBytes, numACLs)
			} else {
				err = fmt.Errorf("App instance cloud-init user data %d + %d bytes plus %d ACLs too large",
					clearNumBytes, cryptoNumBytes, numACLs)
			}
		}
		log.Error(err)
		config.Errors = append(config.Errors, err.Error())
		// Clear out all the fields which can be large
		config.CloudInitUserData = nil
		config.CipherData = nil
		for i := range config.UnderlayNetworkList {
			config.UnderlayNetworkList[i].ACLs = nil
		}
	}

	pub.Publish(key, config)
}

func publishBaseOsConfig(getconfigCtx *getconfigContext,
	config *types.BaseOsConfig) {

	key := config.Key()
	log.Tracef("publishBaseOsConfig UUID %s, %s, activate %v",
		key, config.BaseOsVersion, config.Activate)
	pub := getconfigCtx.pubBaseOsConfig
	pub.Publish(key, *config)
}

func publishBaseOs(getconfigCtx *getconfigContext,
	config *types.BaseOs) {

	log.Tracef("publishBaseOs ConfigRetryUpdateCounter: %d, ContentTreeUUID: %v",
		config.ConfigRetryUpdateCounter, config.ContentTreeUUID)
	pub := getconfigCtx.pubBaseOs
	pub.Publish("global", *config)
}

// Get sha256 for a subset of the protobuf message.
// Used to determine which pieces changed
func computeConfigSha(msg interface{}) []byte {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Fatalf("computeConfigSha: proto.Marshal: %s", err)
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
		log.Fatalf("computeConfigItemSha: json.Marshal: %s", err)
	}
	h.Write(data)
}

// Returns a rebootFlag
func parseOpCmds(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) bool {

	scheduleBackup(config.GetBackup())
	return scheduleReboot(config.GetReboot(), getconfigCtx)
}

// Returns the cmd if the file exists
func readRebootConfig() *types.DeviceOpsCmd {
	log.Tracef("readRebootConfigCounter - reading %s", rebootConfigFilename)

	bytes, err := ioutil.ReadFile(rebootConfigFilename)
	if err == nil {
		rebootConfig := types.DeviceOpsCmd{}
		err = json.Unmarshal(bytes, &rebootConfig)
		if err != nil {
			// Treat the same way as a missing file
			log.Error(err)
			return nil
		}
		return &rebootConfig
	}
	log.Functionf("readRebootConfigCounter - %s doesn't exist",
		rebootConfigFilename)
	return nil
}

func saveRebootConfig(reboot types.DeviceOpsCmd) {
	log.Functionf("saveRebootConfig - reboot.Counter: %d", reboot.Counter)
	bytes, err := json.Marshal(reboot)
	if err != nil {
		log.Fatal(err)
	}
	err = fileutils.WriteRename(rebootConfigFilename, bytes)
	if err != nil {
		// Can fail if low on disk space
		log.Error(err)
	}
}

var rebootPrevConfigHash []byte
var rebootPrevReturn bool

// Returns a rebootFlag
func scheduleReboot(reboot *zconfig.DeviceOpsCmd,
	getconfigCtx *getconfigContext) bool {
	if reboot == nil {
		log.Functionf("scheduleReboot - removing %s",
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

	log.Functionf("scheduleReboot: Applying updated config %v", reboot)
	rebootConfig := readRebootConfig()
	if rebootConfig != nil && rebootConfig.Counter == reboot.Counter {
		rebootPrevReturn = false
		return false
	}
	if rebootConfig == nil || rebootConfig.Counter != reboot.Counter {
		// store current config, persistently
		rebootCmd := types.DeviceOpsCmd{
			Counter:      reboot.Counter,
			DesiredState: reboot.DesiredState,
			OpsTime:      reboot.OpsTime,
		}
		saveRebootConfig(rebootCmd)
		// We read this into zedagentCtx.rebootConfigCounter and report that
		// value to the controller once we have rebooted
	}
	if rebootConfig == nil {
		// First boot - skip the reboot but report to cloud
		getconfigCtx.zedagentCtx.rebootConfigCounter = reboot.Counter
		triggerPublishDevInfo(getconfigCtx.zedagentCtx)
		rebootPrevReturn = false
		return false
	}

	// if device reboot is set, ignore op-command
	if getconfigCtx.zedagentCtx.deviceReboot {
		log.Warnf("device reboot is set")
		return false
	}

	// Defer if inprogress by returning
	ctx := getconfigCtx.zedagentCtx
	if getconfigCtx.updateInprogress {
		// Wait until TestComplete
		log.Warnf("Rebooting even though testing inprogress; defer")
		ctx.rebootCmdDeferred = true
		return false
	}

	infoStr := "NORMAL: handleReboot rebooting"
	handleRebootCmd(ctx, infoStr)
	rebootPrevReturn = true
	return true
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
	log.Functionf("scheduleBackup: Applying updated config %v", backup)
	log.Errorf("XXX handle Backup Config: %v", backup)
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
	ctxPtr.currentRebootReason = infoStr
	ctxPtr.currentBootReason = types.BootReasonRebootCmd

	publishZedAgentStatus(getconfigCtx)
	log.Functionf(infoStr)
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
