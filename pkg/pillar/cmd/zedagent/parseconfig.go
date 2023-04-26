// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/objtonum"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
)

const (
	MaxBaseOsCount         = 2
	BaseOsImageCount       = 1
	rebootConfigFilename   = types.PersistStatusDir + "/rebootConfig"
	shutdownConfigFilename = types.PersistStatusDir + "/shutdownConfig"

	// interface name length limit as imposed by Linux kernel.
	ifNameMaxLength = 15

	// range of valid VLAN IDs
	minVlanID = 1
	maxVlanID = 4094
)

func parseConfig(getconfigCtx *getconfigContext, config *zconfig.EdgeDevConfig,
	source configSource) configProcessingRetval {

	// Do not accept new commands from Local profile server while new config
	// from the controller is being applied.
	if getconfigCtx.localCommands != nil {
		getconfigCtx.localCommands.Lock()
		defer getconfigCtx.localCommands.Unlock()
	}

	// Make sure we do not accidentally revert to an older configuration.
	// This depends on the controller attaching config timestamp.
	// If not provided, the check is skipped.
	if config.ConfigTimestamp.IsValid() {
		configTimestamp := config.ConfigTimestamp.AsTime()
		if getconfigCtx.lastConfigTimestamp.After(configTimestamp) {
			log.Warnf("Skipping obsolete device configuration "+
				"(source: %v, timestamp: %v, currently applied: %v)",
				source, configTimestamp, getconfigCtx.lastConfigTimestamp)
			return obsoleteConfig
		}
		getconfigCtx.lastConfigTimestamp = configTimestamp
	}

	// Update lastReceivedConfig even if the config processing is skipped below.
	if config.ConfigTimestamp.IsValid() {
		getconfigCtx.lastReceivedConfig = config.ConfigTimestamp.AsTime()
	} else {
		getconfigCtx.lastReceivedConfig = time.Now()
	}

	ctx := getconfigCtx.zedagentCtx

	// XXX - DO NOT LOG entire config till secrets are in encrypted blobs
	//log.Tracef("parseConfig: EdgeDevConfig: %v", *config)

	// Prepare LOC structure before everything to be ready to
	// publish info
	parseLocConfig(getconfigCtx, config)

	// Look for timers and other settings in configItems
	// Process Config items even when configProcessingSkipFlag is set.
	// Allows us to recover if the system got stuck after setting
	// configProcessingSkipFlag
	parseConfigItems(getconfigCtx, config, source)

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

	if source == fromController {
		rebootFlag, shutdownFlag := parseOpCmds(getconfigCtx, config)

		// Any new reboot command?
		if rebootFlag {
			log.Noticeln("Reboot flag set, skipping config processing")
			return skipConfig
		}

		// Any new shutdown command?
		if shutdownFlag {
			log.Noticeln("Shutdown flag set, skipping config processing")
			return skipConfig
		}
	}

	if getconfigCtx.configProcessingSkipFlag || ctx.deviceReboot || ctx.deviceShutdown {
		log.Noticef("parseConfig: Ignoring config as reboot/shutdown flag set")
	} else if ctx.maintenanceMode {
		log.Noticef("parseConfig: Ignoring config due to maintenanceMode")
	} else {
		if source != fromBootstrap {
			handleControllerCertsSha(ctx, config)
			parseCipherContext(getconfigCtx, config)
			parseDatastoreConfig(getconfigCtx, config)
		}

		// DeviceIoList has some defaults for Usage and UsagePolicy
		// used by systemAdapters
		physioChanged := parseDeviceIoListConfig(getconfigCtx, config)
		// It is important to parse Bonds before VLANs.
		bondsChanged := parseBonds(getconfigCtx, config)
		vlansChanged := parseVlans(getconfigCtx, config)
		// Network objects are used for systemAdapters
		networksChanged := parseNetworkXObjectConfig(getconfigCtx, config)
		sourceChanged := getconfigCtx.lastConfigSource != source
		// system adapter configuration that we publish, depends
		// on Physio, VLAN, Bond and Networks configuration.
		// If any of these change, we should re-parse system adapters and
		// publish updated configuration.
		forceSystemAdaptersParse := physioChanged || networksChanged || vlansChanged ||
			bondsChanged || sourceChanged
		parseSystemAdapterConfig(getconfigCtx, config, source, forceSystemAdaptersParse)

		if source != fromBootstrap {
			parseBaseOS(getconfigCtx, config)
			parseNetworkInstanceConfig(getconfigCtx, config)
			parseContentInfoConfig(getconfigCtx, config)
			parseVolumeConfig(getconfigCtx, config)

			// parseProfile must be called before processing of app instances from config
			parseProfile(getconfigCtx, config)
			parseAppInstanceConfig(getconfigCtx, config)

			parseEvConfig(getconfigCtx, config)

			parseDisksConfig(getconfigCtx, config)

			parseEdgeNodeInfo(getconfigCtx, config)
		}

		getconfigCtx.lastProcessedConfig = getconfigCtx.lastReceivedConfig
		getconfigCtx.lastConfigSource = source
	}
	return configOK
}

// Walk published AppInstanceConfig's and set Activate=false
// Note that we don't currently wait for the shutdown to complete.
// If withLocalServer is set we skip the app instances which are running
// a Local Profile Server, and return the number of Local Profile Server apps
func shutdownApps(getconfigCtx *getconfigContext, withLocalServer bool) (lpsCount uint) {
	pub := getconfigCtx.pubAppInstanceConfig
	items := pub.GetAll()
	for _, c := range items {
		config := c.(types.AppInstanceConfig)
		if config.Activate {
			if config.HasLocalServer && !withLocalServer {
				log.Noticef("shutdownApps: defer for %s uuid %s",
					config.DisplayName, config.Key())
				lpsCount++
				continue
			}
			log.Functionf("shutdownApps: clearing Activate for %s uuid %s",
				config.DisplayName, config.Key())
			config.Activate = false
			pub.Publish(config.Key(), config)
		}
	}
	return lpsCount
}

// countRunningApps returns the number of app instances which are booting,
// running, or halting.
func countRunningApps(getconfigCtx *getconfigContext) (runningCount uint) {
	sub := getconfigCtx.subAppInstanceStatus
	items := sub.GetAll()
	for _, s := range items {
		status := s.(types.AppInstanceStatus)
		switch status.State {
		case types.BOOTING, types.RUNNING, types.HALTING:
			runningCount++
		case types.PURGING, types.RESTARTING:
			log.Noticef("countRunningApps: %s for %s in %s",
				status.Key(), status.DisplayName, status.State)
			runningCount++
		}
	}
	return runningCount
}

// Defer shutting down app instances with HasLocalServer until all other app
// instances has halted
func shutdownAppsGlobal(ctx *zedagentContext) {
	lpsCount := shutdownApps(ctx.getconfigCtx, false)
	if lpsCount == 0 {
		log.Noticef("shutDownAppsGlobal: no Local Profile Server apps")
		return
	}
	startTime := time.Now()
	go func() {
		for {
			runningCount := countRunningApps(ctx.getconfigCtx)
			log.Noticef("shutdownAppsGlobal: %d LPS apps, %d running, waited %v",
				lpsCount, runningCount, time.Since(startTime))
			if runningCount > lpsCount {
				waitTimer := time.NewTimer(10 * time.Second)
				<-waitTimer.C
				continue
			}
			log.Noticef("shutdownAppsGlobal: defer done after %v",
				time.Since(startTime))
			shutdownApps(ctx.getconfigCtx, true)
			break
		}
	}()
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
	cfg := &types.BaseOsConfig{
		ContentTreeUUID:    baseOS.ContentTreeUuid,
		BaseOsVersion:      baseOS.BaseOsVersion,
		RetryUpdateCounter: getconfigCtx.configRetryUpdateCounter,
		Activate:           baseOS.Activate,
	}
	// First look for deleted ones
	items := getconfigCtx.pubBaseOsConfig.GetAll()
	for idStr := range items {
		if idStr != cfg.Key() {
			log.Functionf("parseBaseOS: deleting %s\n", idStr)
			unpublishBaseOsConfig(getconfigCtx, idStr)
		}
	}
	// publish new one
	publishBaseOsConfig(getconfigCtx, cfg)
}

var networkConfigPrevConfigHash []byte

func parseNetworkXObjectConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) bool {

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

		if networkInstanceConfig.Type == types.NetworkInstanceTypeSwitch {
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

func parseNetworkInstanceConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

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

func parseAppInstanceConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) {

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
			delLocalAppConfig(getconfigCtx, uuidStr)
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
		appInstance.FixedResources.MaxCpus = int(cfgApp.Fixedresources.Maxcpus)
		appInstance.FixedResources.VirtualizationMode = types.VmMode(cfgApp.Fixedresources.VirtualizationMode)
		appInstance.FixedResources.EnableVnc = cfgApp.Fixedresources.EnableVnc
		appInstance.FixedResources.VncDisplay = cfgApp.Fixedresources.VncDisplay
		appInstance.FixedResources.VncPasswd = cfgApp.Fixedresources.VncPasswd
		appInstance.DisableLogs = cfgApp.Fixedresources.DisableLogs
		appInstance.MetaDataType = types.MetaDataType(cfgApp.MetaDataType)
		appInstance.Delay = time.Duration(cfgApp.StartDelayInSeconds) * time.Second
		appInstance.Service = cfgApp.Service
		appInstance.CloudInitVersion = cfgApp.CloudInitVersion
		appInstance.FixedResources.CPUsPinned = cfgApp.Fixedresources.PinCpu

		// Parse the snapshot related fields
		if cfgApp.Snapshot != nil {
			parseSnapshotConfig(&appInstance.Snapshot, cfgApp.Snapshot)
		}

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
			ioa := types.IoAdapter{Type: types.IoType(adapter.Type), Name: adapter.Name}
			if ioa.Type == types.IoNetEthVF && adapter.EthVf != nil {
				// not checking lower bound, since it's zero if VlanId is not specified
				if adapter.EthVf.VlanId > maxVlanID {
					log.Errorf("Incorrect VlanID %d for adapter %s", adapter.EthVf.VlanId, adapter)
					continue
				}
				hwaddr, err := net.ParseMAC(adapter.EthVf.Mac)
				if err != nil {
					log.Errorf("Failed to parse hardware address for adapter %s: %s", adapter.Name, err)
				}
				ioa.EthVf = sriov.EthVF{
					Mac:    hwaddr.String(),
					VlanID: uint16(adapter.EthVf.VlanId)}
			}
			appInstance.IoAdapterList = append(appInstance.IoAdapterList, ioa)
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
		appInstance.CipherBlockStatus = parseCipherBlock(getconfigCtx, appInstance.Key(), cfgApp.GetCipherData())
		appInstance.ProfileList = cfgApp.ProfileList

		// Add config submitted via local profile server.
		addLocalAppConfig(getconfigCtx, &appInstance)

		// Verify that it fits and if not publish with error
		checkAndPublishAppInstanceConfig(getconfigCtx, appInstance)
	}
}

func parseSnapshotConfig(appInstanceSnapshot *types.SnapshotConfig, cfgAppSnapshot *zconfig.SnapshotConfig) {
	appInstanceSnapshot.ActiveSnapshot = cfgAppSnapshot.ActiveSnapshot
	appInstanceSnapshot.MaxSnapshots = cfgAppSnapshot.MaxSnapshots
	if cfgAppSnapshot.RollbackCmd != nil {
		appInstanceSnapshot.RollbackCmd.ApplyTime = cfgAppSnapshot.RollbackCmd.OpsTime
		appInstanceSnapshot.RollbackCmd.Counter = cfgAppSnapshot.RollbackCmd.Counter
	}
	appInstanceSnapshot.Snapshots = make([]types.SnapshotDesc, len(cfgAppSnapshot.Snapshots))
	parseSnapshots(appInstanceSnapshot.Snapshots, cfgAppSnapshot.Snapshots)
}

func parseSnapshots(snapshots []types.SnapshotDesc, cfgSnapshots []*zconfig.SnapshotDesc) {
	for i, cfgSnapshot := range cfgSnapshots {
		snapshots[i].SnapshotID = cfgSnapshot.Id
		snapshots[i].SnapshotType = types.SnapshotType(cfgSnapshot.Type)
	}
}

var systemAdaptersPrevConfigHash []byte

func parseSystemAdapterConfig(getconfigCtx *getconfigContext, config *zconfig.EdgeDevConfig,
	source configSource, forceParse bool) {

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

	portConfig := &types.DevicePortConfig{}
	portConfig.Version = version
	if source == fromBootstrap {
		portConfig.Key = "bootstrap" // Instead of "zedagent".
	}
	var newPorts []*types.NetworkPortConfig
	for _, sysAdapter := range sysAdapters {
		ports, err := parseOneSystemAdapterConfig(getconfigCtx, sysAdapter, version)
		if err != nil {
			portConfig.RecordFailure(err.Error())
		}
		newPorts = append(newPorts, ports...)
	}
	validateAndAssignNetPorts(portConfig, newPorts)

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
		if errStr == "" && portConfig.HasError() {
			errStr = portConfig.LastError
		}
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
		cmp.Equal(getconfigCtx.devicePortConfig.TestResults, portConfig.TestResults) &&
		getconfigCtx.devicePortConfig.Version == portConfig.Version &&
		getconfigCtx.devicePortConfig.Key == portConfig.Key {
		log.Functionf("parseSystemAdapterConfig: DevicePortConfig - " +
			"Done with no change")
		return
	}
	log.Functionf("parseSystemAdapterConfig: version %d/%d differs",
		getconfigCtx.devicePortConfig.Version, portConfig.Version)

	if config.ConfigTimestamp.IsValid() {
		portConfig.TimePriority = config.ConfigTimestamp.AsTime()
	} else {
		// This is suboptimal after a reboot since the config will be the same
		// yet the timestamp be new. HandleDPCModify takes care of that.
		portConfig.TimePriority = time.Now()
	}
	getconfigCtx.devicePortConfig = *portConfig

	getconfigCtx.pubDevicePortConfig.Publish("zedagent", *portConfig)

	log.Functionf("parseSystemAdapterConfig: Done")
}

// Validate parsed network ports and assign non-duplicates to DevicePortConfig.
func validateAndAssignNetPorts(dpc *types.DevicePortConfig, newPorts []*types.NetworkPortConfig) {
	var validatedPorts []*types.NetworkPortConfig

	// 1. check for collisions
	for _, port := range newPorts {
		var skip bool
		for _, port2 := range validatedPorts {
			// With VLANs the same physicalIO or bond may be used by multiple system adapters.
			// So it is OK to get duplicates but they should be completely equal.
			if cmp.Equal(port, port2) {
				skip = true
				break
			}
			if port.Logicallabel == port2.Logicallabel {
				errStr := fmt.Sprintf(
					"Port collides with another port with the same logical label (%s)",
					port.Logicallabel)
				log.Error(errStr)
				port.RecordFailure(errStr)
				port2.RecordFailure(errStr)
				break
			}
			if port.IfName == port2.IfName {
				errStr := fmt.Sprintf(
					"Port collides with another port with the same interface name (%s)",
					port.IfName)
				log.Error(errStr)
				port.RecordFailure(errStr)
				port2.RecordFailure(errStr)
				break
			}
		}
		if skip {
			continue
		}
		validatedPorts = append(validatedPorts, port)
	}

	// 2. validate L2 references
	type l2References struct {
		vlanSubIntfs []*types.NetworkPortConfig
		bondMasters  []*types.NetworkPortConfig
	}
	// key = logical name, value = inverted references from higher layers
	invertedRefs := make(map[string]*l2References)
	// build map of inverted L2 references, used for validation purposes below
	for _, port := range validatedPorts {
		switch port.L2LinkConfig.L2Type {
		case types.L2LinkTypeVLAN:
			parent := port.L2LinkConfig.VLAN.ParentPort
			if _, exist := invertedRefs[parent]; !exist {
				invertedRefs[parent] = &l2References{}
			}
			l2Refs := invertedRefs[parent]
			l2Refs.vlanSubIntfs = append(l2Refs.vlanSubIntfs, port)
		case types.L2LinkTypeBond:
			aggrPorts := port.L2LinkConfig.Bond.AggregatedPorts
			for _, aggrPort := range aggrPorts {
				if _, exist := invertedRefs[aggrPort]; !exist {
					invertedRefs[aggrPort] = &l2References{}
				}
				l2Refs := invertedRefs[aggrPort]
				l2Refs.bondMasters = append(l2Refs.bondMasters, port)
			}
		}
	}
	for _, port := range validatedPorts {
		l2Refs := invertedRefs[port.Logicallabel]
		if l2Refs == nil {
			continue
		}
		if len(l2Refs.bondMasters) > 1 {
			errStr := fmt.Sprintf(
				"Port %s is aggregated by multiple bond interfaces (%s, %s, ...)",
				port.Logicallabel,
				l2Refs.bondMasters[0].Logicallabel,
				l2Refs.bondMasters[1].Logicallabel)
			log.Error(errStr)
			port.RecordFailure(errStr)
			continue
		}
		if len(l2Refs.bondMasters) > 0 && len(l2Refs.vlanSubIntfs) > 0 {
			errStr := fmt.Sprintf(
				"Port %s is referenced by both bond (%s) and VLAN (%s)",
				port.Logicallabel, l2Refs.bondMasters[0].Logicallabel,
				l2Refs.vlanSubIntfs[0].Logicallabel)
			log.Error(errStr)
			port.RecordFailure(errStr)
			continue
		}
		for i, vlanSubIntf := range l2Refs.vlanSubIntfs {
			for j := 0; j < i; j++ {
				if vlanSubIntf.VLAN.ID == l2Refs.vlanSubIntfs[j].VLAN.ID {
					errStr := fmt.Sprintf(
						"Port %s has duplicate VLAN sub-interfaces (VLAN ID = %d)",
						port.Logicallabel, vlanSubIntf.VLAN.ID)
					log.Error(errStr)
					port.RecordFailure(errStr)
					continue
				}
			}
		}
	}

	// 3. Propagate errors up to system adapters
	propagateFrom := validatedPorts
	for len(propagateFrom) > 0 {
		var propagateFromNext []*types.NetworkPortConfig
		for _, port := range propagateFrom {
			if port.IsL3Port || !port.HasError() {
				continue
			}
			l2Refs := invertedRefs[port.Logicallabel]
			if l2Refs == nil {
				continue
			}
			for _, vlanSubIntf := range l2Refs.vlanSubIntfs {
				if !vlanSubIntf.HasError() {
					propagateError(vlanSubIntf, port)
					propagateFromNext = append(propagateFromNext, vlanSubIntf)
				}
			}
			for _, bondMaster := range l2Refs.bondMasters {
				if !bondMaster.HasError() {
					propagateError(bondMaster, port)
					propagateFromNext = append(propagateFromNext, bondMaster)
				}
			}
		}
		propagateFrom = propagateFromNext
	}

	// 4. Assign all non-duplicate, validated ports.
	for _, port := range validatedPorts {
		dpc.Ports = append(dpc.Ports, *port)
	}
}

// Propagate error from a lower-layer adapter to a higher-layer adapter.
func propagateError(higherLayerPort, lowerLayerPort *types.NetworkPortConfig) {
	if lowerLayerPort.HasError() {
		// Inherit error from the lower-layer adapter if there is any
		errStr := fmt.Sprintf("Lower-layer adapter %s has an error (%s)",
			lowerLayerPort.Logicallabel, lowerLayerPort.LastError)
		higherLayerPort.RecordFailure(errStr)
	}
}

func propagatePhyioAttrsToPort(port *types.NetworkPortConfig, phyio *types.PhysicalIOAdapter) {
	port.Phylabel = phyio.Phylabel
	port.IfName = phyio.Phyaddr.Ifname
	if port.IfName == "" {
		// Might not be set for all models
		log.Warnf("Physical IO %s (Phylabel %s) has no ifname",
			phyio.Logicallabel, phyio.Phylabel)
		if phyio.Logicallabel != "" {
			port.IfName = phyio.Logicallabel
		} else {
			port.IfName = phyio.Phylabel
		}
	}
}

// Make NetworkPortConfig entry for PhysicalIO which is below an L2 port.
// The port configuration will contain only labels and the interface name.
func makeL2PhyioPort(phyio *types.PhysicalIOAdapter) *types.NetworkPortConfig {
	phyioPort := &types.NetworkPortConfig{Logicallabel: phyio.Logicallabel}
	propagatePhyioAttrsToPort(phyioPort, phyio)
	return phyioPort
}

// Make NetworkPortConfig entry for L2Adapter (VLAN, bond, ...)
// which is below a higher-level adapter (i.e. it is not L3 port).
// Recursively adds port entries for all adapter below this one.
// The port configuration will contain only labels, the interface name
// and L2 configuration.
func makeL2Port(l2Adapter *L2Adapter) (ports []*types.NetworkPortConfig) {
	ports = append(ports, &types.NetworkPortConfig{
		IfName:       l2Adapter.config.IfName,
		Phylabel:     l2Adapter.config.Phylabel,
		Logicallabel: l2Adapter.config.Logicallabel,
		L2LinkConfig: l2Adapter.config.L2LinkConfig,
		// copy parsing error if any
		TestResults: l2Adapter.config.TestResults,
	})
	for _, phyio := range l2Adapter.lowerPhysPorts {
		ports = append(ports, makeL2PhyioPort(phyio))
	}
	for _, lowerL2 := range l2Adapter.lowerL2Ports {
		ports = append(ports, makeL2Port(lowerL2)...)
	}
	return ports
}

// Returns a list of ports that should be added to DevicePortConfig.
// Even for a single system adapter there can be multiple ports returned.
// This is because we may have a hierarchy of adapters with multiple layers (vlans, bonds, etc.).
// One of the returned ports is L3 port (IsL3Port=true), others are from lower
// layers with only some of the NetworkPortConfig attributes set.
// Some parsing errors are recorded into ErrorAndTime which is embedded into NetworkPortConfig.
func parseOneSystemAdapterConfig(getconfigCtx *getconfigContext,
	sysAdapter *zconfig.SystemAdapter, version types.DevicePortConfigVersion,
) (ports []*types.NetworkPortConfig, err error) {

	log.Functionf("XXX parseOneSystemAdapterConfig name %s lowerLayerName %s",
		sysAdapter.Name, sysAdapter.LowerLayerName)

	// We check if any phyio has FreeUplink set. If so we operate
	// in old mode which means that cost is 1 if FreeUplink == false
	// XXX Remove this when all controllers send cost.
	oldController := anyDeviceIoWithFreeUplink(getconfigCtx)

	port := &types.NetworkPortConfig{}
	port.Logicallabel = sysAdapter.Name // XXX Rename field in protobuf?
	port.Alias = sysAdapter.Alias
	port.IsL3Port = true // this one has SystemAdapter directly attached to it
	lowerLayerName := sysAdapter.LowerLayerName
	if lowerLayerName == "" {
		// If LowerLayerName was not set we use Name i.e., assume that the system adapter
		// and the underlying port share the same logical label.
		log.Warnf("System adapter without a logical label: %v", sysAdapter)
		lowerLayerName = sysAdapter.Name
	}

	// Lower layer of a system adapter is either an L2 object or a physical network adapter.
	var matchCount int
	phyio := lookupDeviceIoLogicallabel(getconfigCtx, lowerLayerName)
	if phyio != nil {
		matchCount++
	}
	var l2Adapter *L2Adapter
	bond := lookupBondLogicallabel(getconfigCtx, lowerLayerName)
	if bond != nil {
		matchCount++
		l2Adapter = bond
	}
	vlan := lookupVlanLogicallabel(getconfigCtx, lowerLayerName)
	if vlan != nil {
		matchCount++
		l2Adapter = vlan
	}
	if matchCount == 0 {
		err = fmt.Errorf("missing lower-layer adapter %s", lowerLayerName)
		log.Errorf("parseSystemAdapterConfig: %v", err)
		return nil, err
	}
	if matchCount > 1 {
		err = fmt.Errorf("multiple lower-layer adapters match label %s",
			lowerLayerName)
		log.Errorf("parseSystemAdapterConfig: %v", err)
		return nil, err
	}

	var phyioFreeUplink bool // XXX Remove this when all controllers send cost.
	if phyio != nil {
		// System adapter is referencing a physical IO adapter
		if !types.IoType(phyio.Ptype).IsNet() {
			err = fmt.Errorf(
				"physicalIO %s (phyLabel %s) is not a network adapter",
				phyio.Logicallabel, phyio.Phylabel)
			log.Errorf("parseSystemAdapterConfig: %v", err)
			return nil, err
		}
		phyioFreeUplink = phyio.UsagePolicy.FreeUplink
		log.Functionf("Found phyio for %s: free %t, oldController: %t",
			sysAdapter.Name, phyioFreeUplink, oldController)
		propagatePhyioAttrsToPort(port, phyio)
	} else {
		// Note that if controller sends VLAN or bond config,
		// it means that it is new enough to not use FreeUplink anymore.
		port.IfName = l2Adapter.config.IfName
		port.L2LinkConfig = l2Adapter.config.L2LinkConfig
		propagateError(port, l2Adapter.config)
		// Add NetworkPortConfig entries for lower-layer adapters.
		for _, phyio := range l2Adapter.lowerPhysPorts {
			ports = append(ports, makeL2PhyioPort(phyio))
		}
		for _, lowerL2 := range l2Adapter.lowerL2Ports {
			ports = append(ports, makeL2Port(lowerL2)...)
		}
	}

	var portCost uint8
	if sysAdapter.Cost > 255 {
		log.Warnf("SysAdpter cost %d for %s clamped to 255",
			sysAdapter.Cost, sysAdapter.Name)
		portCost = 255
	} else {
		portCost = uint8(sysAdapter.Cost)
	}
	if portCost == 0 {
		if phyioFreeUplink || sysAdapter.FreeUplink {
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
			if network.Proxy != nil {
				port.ProxyConfig = *network.Proxy
			}
		}
	} else if isMgmt {
		errStr := fmt.Sprintf("Port %s Configured as Management port without "+
			"configuring a Network. Network is required for Management ports",
			port.IfName)
		log.Errorf("parseSystemAdapterConfig: %s", errStr)
		port.RecordFailure(errStr)
	}
	ports = append(ports, port)
	return ports, nil // there can still be error recorded inside individual ports
}

var deviceIoListPrevConfigHash []byte

func parseDeviceIoListConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) bool {

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
		if port.Logicallabel == "" {
			log.Warnf("PhysicalIO without logical label: %+v", port)
			// XXX Originally, the physical label was used as the IO adapter identifier
			// and for references from upper layers.
			// Now that we have migrated to logical labels, make sure that any old
			// device model without logical labeling will still be supported.
			port.Logicallabel = port.Phylabel
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

		if ioDevicePtr.Vflist != nil && ioDevicePtr.Vflist.VfCount > 0 {
			port.Vfs.Count = uint8(ioDevicePtr.Vflist.VfCount)
			port.Vfs.Data = make([]sriov.EthVF, ioDevicePtr.Vflist.VfCount)

			valid := true
			for i, vf := range ioDevicePtr.Vflist.Data {
				// not checking lower bound, since it's zero if VlanId is not specified
				if vf.VlanId > maxVlanID {
					log.Errorf("Incorrect VlanID %d for PhysicalIO %s", vf.VlanId, ioDevicePtr)
					valid = false
					break
				}

				port.Vfs.Data[i] = sriov.EthVF{
					Index:  uint8(vf.Index),
					Mac:    vf.Mac,
					VlanID: uint16(vf.VlanId),
				}
			}
			if !valid {
				continue
			}
			// Generate unspecified VFs
			if len(port.Vfs.Data) != int(ioDevicePtr.Vflist.VfCount) {
				set := map[int]struct{}{}
				for _, d := range port.Vfs.Data {
					set[int(d.Index)] = struct{}{}
				}
				for i := 0; i < int(ioDevicePtr.Vflist.VfCount); i++ {
					if _, ok := set[i]; ok {
						continue
					}
					port.Vfs.Data = append(port.Vfs.Data, sriov.EthVF{
						Index: uint8(i),
					})
				}
			}
		}

		phyIoAdapterList.AdapterList = append(phyIoAdapterList.AdapterList,
			port)
		getconfigCtx.zedagentCtx.physicalIoAdapterMap[port.Logicallabel] = port
	}
	phyIoAdapterList.Initialized = true
	getconfigCtx.pubPhysicalIOAdapters.Publish("zedagent", phyIoAdapterList)

	log.Functionf("parseDeviceIoListConfig: Done")
	return true
}

var bondsPrevConfigHash []byte

func parseBonds(getconfigCtx *getconfigContext, config *zconfig.EdgeDevConfig) bool {
	bonds := config.GetBonds()
	h := sha256.New()
	for _, bond := range bonds {
		computeConfigElementSha(h, bond)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, bondsPrevConfigHash)
	if same {
		return false
	}
	bondsPrevConfigHash = configHash

	getconfigCtx.bonds = []L2Adapter{}
	for _, bondConfig := range config.GetBonds() {
		portConfig := new(types.NetworkPortConfig)
		portConfig.L2Type = types.L2LinkTypeBond
		bond := L2Adapter{config: portConfig}

		// logical label
		portConfig.Logicallabel = bondConfig.GetLogicallabel()
		if portConfig.Logicallabel == "" {
			errStr := fmt.Sprintf("Bond without logicallabel: %+v; ignored", bondConfig)
			log.Errorf("parseBonds: %s", errStr)
			continue
		}

		// interface name
		portConfig.IfName = bondConfig.GetInterfaceName()
		if portConfig.IfName == "" {
			portConfig.IfName = bondConfig.GetLogicallabel()
		}
		if len(portConfig.IfName) > ifNameMaxLength {
			errStr := fmt.Sprintf("Bond interface name too long: %s", portConfig.IfName)
			log.Errorf("parseBonds: %s", errStr)
			portConfig.RecordFailure(errStr)
		}

		// bond parameters
		portConfig.Bond.Mode = types.BondMode(bondConfig.GetBondMode())
		portConfig.Bond.LacpRate = types.LacpRate(bondConfig.GetLacpRate())

		// link monitoring
		switch monitoring := bondConfig.Monitoring.(type) {
		case *zconfig.BondAdapter_Arp:
			arpMonitor := types.BondArpMonitor{
				Enabled:  true,
				Interval: monitoring.Arp.Interval,
			}
			for _, arpTarget := range monitoring.Arp.IpTargets {
				ip := net.ParseIP(arpTarget)
				if ip != nil {
					arpMonitor.IPTargets = append(arpMonitor.IPTargets, ip)
				} else {
					errStr := fmt.Sprintf("Bond ARP monitoring configured with invalid target: %s",
						arpTarget)
					log.Errorf("parseBonds: %s", errStr)
					portConfig.RecordFailure(errStr)
				}
			}
			portConfig.Bond.ARPMonitor = arpMonitor
		case *zconfig.BondAdapter_Mii:
			portConfig.Bond.MIIMonitor = types.BondMIIMonitor{
				Enabled:   true,
				Interval:  monitoring.Mii.Interval,
				UpDelay:   monitoring.Mii.Updelay,
				DownDelay: monitoring.Mii.Downdelay,
			}
		}

		// find physical IOs aggregated by the bond
		for _, lowerLayerName := range bondConfig.LowerLayerNames {
			physIO := lookupDeviceIoLogicallabel(getconfigCtx, lowerLayerName)
			if physIO != nil {
				if types.IoType(physIO.Ptype).IsNet() {
					portConfig.Bond.AggregatedPorts =
						append(portConfig.Bond.AggregatedPorts, physIO.Logicallabel)
					bond.lowerPhysPorts = append(bond.lowerPhysPorts, physIO)
				} else {
					errStr := fmt.Sprintf("Bond %s is attached to a non-network adapter %s",
						portConfig.Logicallabel, physIO.Logicallabel)
					log.Errorf("parseBonds: %s", errStr)
					portConfig.RecordFailure(errStr)
				}
			} else {
				errStr := fmt.Sprintf("Bond interface %s referencing non-existing physical adapter %s",
					portConfig.Logicallabel, lowerLayerName)
				log.Errorf("parseBonds: %s", errStr)
				portConfig.RecordFailure(errStr)
			}
		}
		if !portConfig.HasError() && len(portConfig.Bond.AggregatedPorts) == 0 {
			errStr := fmt.Sprintf("Missing all lower-layer adapters for bond %s",
				portConfig.Logicallabel)
			log.Errorf("parseBonds: %s", errStr)
			portConfig.RecordFailure(errStr)
		}

		// add parsed Bond adapter
		getconfigCtx.bonds = append(getconfigCtx.bonds, bond)
	}
	return true
}

var vlansPrevConfigHash []byte

func parseVlans(getconfigCtx *getconfigContext, config *zconfig.EdgeDevConfig) bool {
	vlans := config.GetVlans()
	h := sha256.New()
	for _, vlan := range vlans {
		computeConfigElementSha(h, vlan)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, vlansPrevConfigHash)
	if same {
		return false
	}
	vlansPrevConfigHash = configHash

	getconfigCtx.vlans = []L2Adapter{}
	for _, vlanConfig := range config.GetVlans() {
		portConfig := new(types.NetworkPortConfig)
		portConfig.L2Type = types.L2LinkTypeVLAN
		vlan := L2Adapter{config: portConfig}

		// logical label
		portConfig.Logicallabel = vlanConfig.GetLogicallabel()
		if portConfig.Logicallabel == "" {
			errStr := fmt.Sprintf("VLAN without logicallabel: %+v; ignored",
				vlanConfig)
			log.Errorf("parseVlans: %s", errStr)
			continue
		}

		// interface name
		portConfig.IfName = vlanConfig.GetInterfaceName()
		if portConfig.IfName == "" {
			portConfig.IfName = vlanConfig.GetLogicallabel()
		}
		if len(portConfig.IfName) > ifNameMaxLength {
			errStr := fmt.Sprintf("VLAN interface name too long: %s",
				portConfig.IfName)
			log.Errorf("parseVlans: %s", errStr)
			portConfig.RecordFailure(errStr)
		}

		// VLAN ID
		vlanID := vlanConfig.GetVlanId()
		if vlanID < minVlanID || vlanID > maxVlanID {
			errStr := fmt.Sprintf("VLAN ID out of range: %d", vlanID)
			log.Errorf("parseVlans: %s", errStr)
			portConfig.RecordFailure(errStr)
			// do not try to create this VLAN sub-interface
			// (conversion to uint16 could turn it into a valid ID)
			const maxUint16 = 0xFFFF
			if vlanID > maxUint16 {
				vlanID = maxUint16
			}
		}
		portConfig.VLAN.ID = uint16(vlanID)

		// find parent (physical IO or bond)
		physIO := lookupDeviceIoLogicallabel(getconfigCtx, vlanConfig.GetLowerLayerName())
		if physIO != nil {
			if types.IoType(physIO.Ptype).IsNet() {
				portConfig.VLAN.ParentPort = physIO.Logicallabel
				vlan.lowerPhysPorts = []*types.PhysicalIOAdapter{physIO}
			} else {
				errStr := fmt.Sprintf("VLAN %s is attached to a non-network adapter %s",
					portConfig.Logicallabel, physIO.Logicallabel)
				log.Errorf("parseVlans: %s", errStr)
				portConfig.RecordFailure(errStr)
			}
		} else {
			bond := lookupBondLogicallabel(getconfigCtx, vlanConfig.GetLowerLayerName())
			if bond != nil {
				portConfig.VLAN.ParentPort = bond.config.Logicallabel
				vlan.lowerL2Ports = []*L2Adapter{bond}
				if bond.config.HasError() {
					// Inherit error from bond if there is any
					errStr := fmt.Sprintf("VLAN %s is attached to bond %s which has an error (%s)",
						portConfig.Logicallabel, bond.config.Logicallabel, bond.config.LastError)
					log.Errorf("parseVlans: %s", errStr)
					portConfig.RecordFailure(errStr)
				}
			}
		}
		if !portConfig.HasError() && portConfig.VLAN.ParentPort == "" {
			errStr := fmt.Sprintf("Missing lower-layer adapter for VLAN %s",
				portConfig.Logicallabel)
			log.Errorf("parseVlans: %s", errStr)
			portConfig.RecordFailure(errStr)
		}

		// add parsed VLAN adapter
		getconfigCtx.vlans = append(getconfigCtx.vlans, vlan)
	}
	return true
}

func lookupDeviceIoLogicallabel(getconfigCtx *getconfigContext, label string) *types.PhysicalIOAdapter {
	port, exists := getconfigCtx.zedagentCtx.physicalIoAdapterMap[label]
	if !exists {
		return nil
	}
	return &port
}

func lookupBondLogicallabel(getconfigCtx *getconfigContext, label string) *L2Adapter {
	for _, port := range getconfigCtx.bonds {
		if port.config.Logicallabel == label {
			return &port
		}
	}
	return nil
}

func lookupVlanLogicallabel(getconfigCtx *getconfigContext, label string) *L2Adapter {
	for _, port := range getconfigCtx.vlans {
		if port.config.Logicallabel == label {
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

func parseDatastoreConfig(getconfigCtx *getconfigContext, config *zconfig.EdgeDevConfig) {

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

		datastore.CipherBlockStatus = parseCipherBlock(ctx, datastore.Key(), ds.GetCipherData())
		ctx.pubDatastoreConfig.Publish(datastore.Key(), *datastore)
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
		volume.VerifyOnly = true
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
			wcell.LocationTracking = cellular.GetLocationTracking()
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
			wifi.CipherBlockStatus = parseCipherBlock(ctx, key, wificfg.GetCipherData())

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
	if addrCount < types.MinSubnetSize {
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
	addressesInRange := config.DhcpRange.Size()
	// Currently, we cannot use more than ByteAllocatorMaxNum IPs for dynamic allocation
	// (i.e. 256 at maximum) and should keep some place in the end for static IPs
	// assignment.
	// XXX Later we could implement NumberAllocator with larger capacity (larger than
	// what ByteAllocator can provide) and use it for network instances
	// that require bigger subnets.
	if addressesInRange > objtonum.ByteAllocatorMaxNum {
		config.DhcpRange.End = types.AddToIP(config.DhcpRange.Start, objtonum.ByteAllocatorMaxNum)
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

	// calculate IfIdx field for interfaces connected to the same network
	nextIfIndexForNetwork := make(map[uuid.UUID]uint32)
	for i := range appInstance.UnderlayNetworkList {
		ulCfg := &appInstance.UnderlayNetworkList[i]
		if ind, ok := nextIfIndexForNetwork[ulCfg.Network]; ok {
			ulCfg.IfIdx = ind
			nextIfIndexForNetwork[ulCfg.Network] = ind + 1
			continue
		}
		nextIfIndexForNetwork[ulCfg.Network] = 1
		ulCfg.IfIdx = 0
	}

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

func parseConfigItems(ctx *getconfigContext, config *zconfig.EdgeDevConfig,
	source configSource) {

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
	// Note: UsbAccess, VgaAccess and ConsoleAccess are special in that they has two defaults.
	// When the device first boots the default is "true" as specified
	// in the DefaultConfigItemValueMap. But when connecting to the
	// controller, if the controller does not include the item, it
	// should default to "false".
	// That way bringup of new hardware models can be done using an
	// attached keyboard and monitor.
	if source == fromBootstrap {
		newGlobalConfig.SetGlobalValueBool(types.UsbAccess, true)
		newGlobalConfig.SetGlobalValueBool(types.VgaAccess, true)
		newGlobalConfig.SetGlobalValueBool(types.ConsoleAccess, true)
	} else {
		// from controller (live or saved)
		newGlobalConfig.SetGlobalValueBool(types.UsbAccess, false)
		newGlobalConfig.SetGlobalValueBool(types.VgaAccess, false)
		newGlobalConfig.SetGlobalValueBool(types.ConsoleAccess, false)
	}
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
	if !ctx.zedagentCtx.globalConfigPublished || !cmp.Equal(gcPtr, newGlobalConfig) {
		log.Functionf("parseConfigItems: change %v",
			cmp.Diff(gcPtr, newGlobalConfig))
		oldGlobalConfig := *gcPtr
		*gcPtr = *newGlobalConfig

		// Set GlobalStatus Values from GlobalConfig.
		oldConfigInterval := oldGlobalConfig.GlobalValueInt(types.ConfigInterval)
		newConfigInterval := newGlobalConfig.GlobalValueInt(types.ConfigInterval)
		oldCertInterval := oldGlobalConfig.GlobalValueInt(types.CertInterval)
		newCertInterval := newGlobalConfig.GlobalValueInt(types.CertInterval)

		oldMetricInterval := oldGlobalConfig.GlobalValueInt(types.MetricInterval)
		newMetricInterval := newGlobalConfig.GlobalValueInt(types.MetricInterval)

		oldLocationCloudInterval := oldGlobalConfig.GlobalValueInt(
			types.LocationCloudInterval)
		newLocationCloudInterval := newGlobalConfig.GlobalValueInt(
			types.LocationCloudInterval)
		oldLocationAppInterval := oldGlobalConfig.GlobalValueInt(
			types.LocationAppInterval)
		newLocationAppInterval := newGlobalConfig.GlobalValueInt(
			types.LocationAppInterval)

		if newConfigInterval != oldConfigInterval {
			log.Functionf("parseConfigItems: %s change from %d to %d",
				"ConfigInterval", oldConfigInterval, newConfigInterval)
			updateConfigTimer(newConfigInterval, ctx.configTickerHandle)
			updateConfigTimer(newConfigInterval, ctx.localProfileTickerHandle)
		}
		if newCertInterval != oldCertInterval {
			log.Functionf("parseConfigItems: %s change from %d to %d",
				"CertInterval", oldCertInterval, newCertInterval)
			updateCertTimer(newCertInterval, ctx.certTickerHandle)
		}
		if newMetricInterval != oldMetricInterval {
			log.Functionf("parseConfigItems: %s change from %d to %d",
				"MetricInterval", oldMetricInterval, newMetricInterval)
			maybeUpdateMetricsTimer(ctx, false)
		}
		if oldLocationCloudInterval != newLocationCloudInterval {
			log.Functionf("parseConfigItems: %s change from %d to %d",
				"LocationCloudInterval", oldLocationCloudInterval, newLocationCloudInterval)
			updateLocationCloudTimer(ctx, newLocationCloudInterval)
		}
		if oldLocationAppInterval != newLocationAppInterval {
			log.Functionf("parseConfigItems: %s change from %d to %d",
				"LocationAppInterval", oldLocationAppInterval, newLocationAppInterval)
			updateLocationAppTimer(ctx, newLocationAppInterval)
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
		ctx.zedagentCtx.globalConfigPublished = err == nil
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
	if config.Service && config.FixedResources.VirtualizationMode != types.NOHYPER {
		err := fmt.Errorf("service app instance %s must have NOHYPER VirtualizationMode", config.UUIDandVersion.UUID)
		log.Error(err)
		config.Errors = append(config.Errors, err.Error())
	}

	pub.Publish(key, config)
}

func publishBaseOsConfig(getconfigCtx *getconfigContext,
	config *types.BaseOsConfig) {

	key := config.Key()
	log.Tracef("publishBaseOsConfig UUID %s, %s, activate %v",
		key, config.ContentTreeUUID, config.Activate)
	pub := getconfigCtx.pubBaseOsConfig
	pub.Publish(key, *config)
}

func unpublishBaseOsConfig(ctx *getconfigContext, key string) {
	log.Tracef("unpublishBaseOsConfig(%s)", key)
	pub := ctx.pubBaseOsConfig
	config, _ := pub.Get(key)
	if config == nil {
		log.Errorf("unpublishBaseOsConfig(%s) not found", key)
		return
	}
	if err := pub.Unpublish(key); err != nil {
		log.Errorf("unpublishBaseOsConfig(%s) failed to unpublish: %s", key, err)
		return
	}
	log.Tracef("unpublishBaseOsConfig(%s) done", key)
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

// Returns reboot and shutdown flags
func parseOpCmds(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) (bool, bool) {

	scheduleBackup(config.GetBackup())
	reboot := scheduleDeviceOperation(getconfigCtx, config.GetReboot(), types.DeviceOperationReboot)
	shutdown := scheduleDeviceOperation(getconfigCtx, config.GetShutdown(), types.DeviceOperationShutdown)
	return reboot, shutdown
}

func isLocConfigValid(locConfig *zconfig.LOCConfig) bool {
	if locConfig == nil || len(locConfig.LocUrl) == 0 {
		return false
	}
	_, err := url.Parse(locConfig.LocUrl)
	return err == nil
}

// parseLocConfig() - assign LOC config only if URL is valid
func parseLocConfig(getconfigCtx *getconfigContext,
	config *zconfig.EdgeDevConfig) {
	locConfig := config.GetLocConfig()
	if isLocConfigValid(locConfig) {
		getconfigCtx.locConfig = &types.LOCConfig{
			LocURL: locConfig.LocUrl,
		}
	} else {
		getconfigCtx.locConfig = nil
	}
}

func removeDeviceOpsCmdConfig(op types.DeviceOperation) {
	fileName := ""
	switch op {
	case types.DeviceOperationReboot:
		fileName = rebootConfigFilename
	case types.DeviceOperationShutdown:
		fileName = shutdownConfigFilename
	default:
		log.Errorf("removeDeviceOpsCmdConfig unknown operation: %v", op)
		return
	}
	log.Functionf("removeDeviceOpsCmdConfig - removing %s", fileName)
	// remove the existing file if it exists
	if _, err := os.Stat(fileName); err != nil && os.IsNotExist(err) {
		return
	}
	if err := os.Remove(fileName); err != nil {
		log.Errorf("removeDeviceOpsCmdConfig error in removing of %s: %s", fileName, err)
	}
}

// Returns the cmd if the file exists
func readDeviceOpsCmdConfig(op types.DeviceOperation) *types.DeviceOpsCmd {
	fileName := ""
	switch op {
	case types.DeviceOperationReboot:
		fileName = rebootConfigFilename
	case types.DeviceOperationShutdown:
		fileName = shutdownConfigFilename
	default:
		log.Errorf("readDeviceOpsCmdConfig unknown operation: %v", op)
		return nil
	}
	log.Tracef("readDeviceOpsCmdConfig - reading %s", fileName)

	b, err := os.ReadFile(fileName)
	if err == nil {
		cfg := types.DeviceOpsCmd{}
		err = json.Unmarshal(b, &cfg)
		if err != nil {
			// Treat the same way as a missing file
			log.Error(err)
			return nil
		}
		return &cfg
	}
	log.Functionf("readDeviceOpsCmdConfig - %s doesn't exist",
		fileName)
	return nil
}

func saveDeviceOpsCmdConfig(cfg types.DeviceOpsCmd, op types.DeviceOperation) {
	fileName := ""
	switch op {
	case types.DeviceOperationReboot:
		fileName = rebootConfigFilename
	case types.DeviceOperationShutdown:
		fileName = shutdownConfigFilename
	default:
		log.Errorf("saveDeviceOpsCmdConfig unknown operation: %v", op)
		return
	}
	log.Functionf("saveDeviceOpsCmdConfig - %s.Counter: %d", op.String(), cfg.Counter)
	b, err := json.Marshal(cfg)
	if err != nil {
		log.Fatal(err)
	}
	err = fileutils.WriteRename(fileName, b)
	if err != nil {
		// Can fail if low on disk space
		log.Error(err)
	}
}

var rebootPrevConfigHash []byte
var rebootPrevReturn bool
var shutdownPrevConfigHash []byte
var shutdownPrevReturn bool

// Returns operation flag
func scheduleDeviceOperation(getconfigCtx *getconfigContext, opsCmd *zconfig.DeviceOpsCmd,
	op types.DeviceOperation) bool {

	if opsCmd == nil {
		removeDeviceOpsCmdConfig(op)
		return false
	}

	var prevHash *[]byte
	var prevReturn *bool
	var configCounter *uint32
	var operationFlag bool

	switch op {
	case types.DeviceOperationReboot:
		prevHash = &rebootPrevConfigHash
		prevReturn = &rebootPrevReturn
		operationFlag = getconfigCtx.zedagentCtx.deviceReboot
		configCounter = &getconfigCtx.zedagentCtx.rebootConfigCounter
	case types.DeviceOperationShutdown:
		prevHash = &shutdownPrevConfigHash
		prevReturn = &shutdownPrevReturn
		operationFlag = getconfigCtx.zedagentCtx.deviceShutdown
		configCounter = &getconfigCtx.zedagentCtx.shutdownConfigCounter
	default:
		log.Errorf("scheduleDeviceOperation wrong operation: %v", op)
		return false
	}

	configHash := computeConfigSha(opsCmd)
	same := bytes.Equal(configHash, *prevHash)
	*prevHash = configHash
	if same {
		return *prevReturn
	}

	log.Functionf("scheduleDeviceOperation: Applying updated config %v",
		opsCmd)
	opCfg := readDeviceOpsCmdConfig(op)
	if opCfg != nil && opCfg.Counter == opsCmd.Counter {
		*prevReturn = false
		return *prevReturn
	}
	if opCfg == nil || opCfg.Counter != opsCmd.Counter {
		// store current config, persistently
		cmdToSave := types.DeviceOpsCmd{
			Counter:      opsCmd.Counter,
			DesiredState: opsCmd.DesiredState,
			OpsTime:      opsCmd.OpsTime,
		}
		saveDeviceOpsCmdConfig(cmdToSave, op)
		// We read this into zedagentCtx reboot or shutdown ConfigCounter and report that
		// value to the controller once we have started again after reboot/shutdown
	}
	if opCfg == nil {
		// First boot - skip the reboot/shutdown but report to cloud
		*configCounter = opsCmd.Counter
		triggerPublishDevInfo(getconfigCtx.zedagentCtx)
		*prevReturn = false
		return *prevReturn
	}

	// if device operation flag is set, ignore op-command
	if operationFlag {
		log.Warnf("device %s is set", op.String())
		return *prevReturn
	}

	// Defer if inprogress by returning
	ctx := getconfigCtx.zedagentCtx
	if getconfigCtx.updateInprogress {
		// Wait until TestComplete
		log.Warnf("%s even though testing inprogress; defer", op.String())
		switch op {
		case types.DeviceOperationReboot:
			ctx.rebootCmdDeferred = true
		case types.DeviceOperationShutdown:
			ctx.shutdownCmdDeferred = true
		}
		return false
	}

	infoStr := fmt.Sprintf("NORMAL: controller %s", op.String())
	handleDeviceOperationCmd(ctx, infoStr, op)
	*prevReturn = true
	return *prevReturn
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

// user driven reboot/shutdown/poweroff command originating from controller or
// local profile server.
// Shut dpwn the application instances and trigger nodeagent to perform node
// reboot or poweroff.
func handleDeviceOperationCmd(ctxPtr *zedagentContext, infoStr string, op types.DeviceOperation) {
	switch op {
	case types.DeviceOperationReboot:
		if ctxPtr.rebootCmd || ctxPtr.deviceReboot {
			return
		}
		ctxPtr.rebootCmd = true
		ctxPtr.requestedRebootReason = infoStr
		ctxPtr.requestedBootReason = types.BootReasonRebootCmd
	case types.DeviceOperationShutdown:
		if ctxPtr.shutdownCmd || ctxPtr.deviceShutdown {
			return
		}
		ctxPtr.shutdownCmd = true
	case types.DeviceOperationPoweroff:
		if ctxPtr.poweroffCmd || ctxPtr.devicePoweroff {
			return
		}
		ctxPtr.poweroffCmd = true
		ctxPtr.requestedRebootReason = infoStr
		ctxPtr.requestedBootReason = types.BootReasonPoweroffCmd
	default:
		log.Errorf("handleDeviceOperationCmd wrong operation: %v", op)
		return
	}
	// shutdown the application instances
	shutdownAppsGlobal(ctxPtr)
	getconfigCtx := ctxPtr.getconfigCtx

	publishZedAgentStatus(getconfigCtx)
}

// nodeagent has initiated a node reboot/shutdown,
// shutdown application instances, or poweroff.
func handleDeviceOperation(ctxPtr *zedagentContext, op types.DeviceOperation) {
	switch op {
	case types.DeviceOperationReboot:
		if ctxPtr.rebootCmd || ctxPtr.deviceReboot {
			return
		}
		ctxPtr.deviceReboot = true
	case types.DeviceOperationShutdown:
		if ctxPtr.shutdownCmd || ctxPtr.deviceShutdown {
			return
		}
		ctxPtr.deviceShutdown = true
	case types.DeviceOperationPoweroff:
		if ctxPtr.poweroffCmd || ctxPtr.devicePoweroff {
			return
		}
		ctxPtr.devicePoweroff = true
	default:
		log.Errorf("handleDeviceOperation wrong operation: %v", op)
		return
	}
	// shutdown the application instances
	shutdownAppsGlobal(ctxPtr)
	// nothing else to be done
}
