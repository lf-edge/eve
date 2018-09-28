// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/pubsub"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zboot"
	"hash"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	MaxBaseOsCount       = 2
	BaseOsImageCount     = 1
	rebootConfigFilename = configDir + "/rebootConfig"
)

var immediate int = 30 // take a 30 second delay
var rebootTimer *time.Timer

// Returns a rebootFlag
func parseConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext,
	usingSaved bool) bool {

	// XXX can this happen when usingSaved is set?
	if parseOpCmds(config) {
		log.Infoln("Reboot flag set, skipping config processing")
		// Make sure we tell apps to shut down
		shutdownApps(getconfigCtx)
		return true
	}

	// updating/rebooting, ignore config??
	// XXX can we get stuck here? When do we set updating? As part of activate?
	// XXX can this happen when usingSaved is set?
	if zboot.IsOtherPartitionStateUpdating() {
		log.Infoln("OtherPartitionStatusUpdating - returning rebootFlag")
		// Make sure we tell apps to shut down
		shutdownApps(getconfigCtx)
		return true
	}

	// If the other partition is inprogress it means update failed
	// We leave in inprogress state so logmanager can use it to decide
	// to upload the other logs. If a different BaseOsVersion is provided
	// we allow it to be installed into the inprogress partition.
	if zboot.IsOtherPartitionStateInProgress() {
		otherPart := zboot.GetOtherPartition()
		log.Errorf("Other %s partition contains failed update\n",
			otherPart)
	}

	// Look for timers and other settings in configItems
	parseConfigItems(config, getconfigCtx)
	parseDatastoreConfig(config, getconfigCtx)

	parseBaseOsConfig(getconfigCtx, config)
	parseNetworkObjectConfig(config, getconfigCtx)
	parseNetworkServiceConfig(config, getconfigCtx)
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
	if ctx.getconfigCtx != nil {
		shutdownApps(ctx.getconfigCtx)
	}
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
	for uuidStr, _ := range items {
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

	// We need to publish the Activate=false first then those with
	// true to avoid the subscriber seeing two activated
	// XXX Unfortunately that makes no difference since the subscriber
	// is likely to see the items in key order
	expectActivate := false
	for {
		published := parseAndPublish(getconfigCtx, cfgOsList,
			expectActivate)
		if expectActivate {
			break
		} else {
			expectActivate = true
			if published {
				// XXX hack - wait for a bit for XXX ourselves
				// to receive update!
			}
		}
	}
}

// Returns true if something was updated
func parseAndPublish(getconfigCtx *getconfigContext,
	cfgOsList []*zconfig.BaseOSConfig, expectActivate bool) bool {

	published := false
	for _, cfgOs := range cfgOsList {
		if cfgOs.GetBaseOSVersion() == "" {
			// Empty slot - silently ignore
			continue
		}
		if cfgOs.GetActivate() != expectActivate {
			// Skip until next round
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
		publishBaseOsConfig(getconfigCtx, baseOs)
		if certInstance != nil {
			publishCertObjConfig(getconfigCtx, certInstance,
				baseOs.Key())
		}
		published = true
	}
	return published
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

func parseNetworkObjectConfig(config *zconfig.EdgeDevConfig,
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
		log.Debugf("parseNetworkObjectConfig: network sha is unchanged: % x\n",
			configHash)
		return
	}
	log.Infof("parseNetworkObjectConfig: Applying updated config sha % x vs. % x: %v\n",
		networkConfigPrevConfigHash, configHash, nets)
	// Export NetworkObjectConfig to zedrouter
	publishNetworkObjectConfig(getconfigCtx, nets)

	// XXX hack - wait for a while so zedrouter can pick up this
	// before it sees AppNetworkConfig using this network/service
	time.Sleep(10 * time.Second)
}

var networkServicePrevConfigHash []byte

func parseNetworkServiceConfig(config *zconfig.EdgeDevConfig,
	getconfigCtx *getconfigContext) {

	h := sha256.New()
	svcs := config.GetServices()
	for _, s := range svcs {
		computeConfigElementSha(h, s)
	}
	configHash := h.Sum(nil)
	same := bytes.Equal(configHash, networkServicePrevConfigHash)
	networkServicePrevConfigHash = configHash
	if same {
		log.Debugf("parseNetworkServiceConfig: service sha is unchanged: % x\n",
			configHash)
		return
	}
	log.Infof("parseNetworkServiceConfig: Applying updated config sha % x vs. % x: %v\n",
		networkServicePrevConfigHash, configHash, svcs)

	// Export NetworkServiceConfig to zedrouter
	publishNetworkServiceConfig(getconfigCtx, svcs)

	// XXX hack - wait for a while so zedrouter can pick up this
	// before it sees AppNetworkConfig using this network/service
	time.Sleep(10 * time.Second)
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
	log.Infof("parseAppInstanceConfig: Applying updated config sha % x vs. % x: %v\n",
		appinstancePrevConfigHash, configHash, Apps)

	// First look for deleted ones
	items := getconfigCtx.pubAppInstanceConfig.GetAll()
	for uuidStr, _ := range items {
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

		appInstance.StorageConfigList = make([]types.StorageConfig,
			len(cfgApp.Drives))
		parseStorageConfigList(appImgObj, appInstance.StorageConfigList,
			cfgApp.Drives)

		// fill the overlay/underlay config
		parseAppNetworkConfig(&appInstance, cfgApp, config.Networks)

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

	// XXX hack - wait for a while so we and zedmananger can pick up this
	// before a BaseOsConfig or AppNetworkConfig using this is visible
	// to them
	time.Sleep(10 * time.Second)
}

func publishDatastoreConfig(ctx *getconfigContext,
	cfgDatastores []*zconfig.DatastoreConfig) {

	// Check for items to delete first
	items := ctx.pubDatastoreConfig.GetAll()
	for k, _ := range items {
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
		image.Target = strings.ToLower(drive.Target.String())
		image.Devtype = strings.ToLower(drive.Drvtype.String())
		image.ImageSha256 = drive.Image.Sha256
		storageList[idx] = *image
		idx++
	}
}

func lookupNetworkId(id string, cfgNetworks []*zconfig.NetworkConfig) *zconfig.NetworkConfig {
	for _, netEnt := range cfgNetworks {
		if id == netEnt.Id {
			return netEnt
		}
	}
	return nil
}

func lookupServiceId(id string, cfgServices []*zconfig.ServiceInstanceConfig) *zconfig.ServiceInstanceConfig {
	for _, svcEnt := range cfgServices {
		if id == svcEnt.Id {
			return svcEnt
		}
	}
	return nil
}

func publishNetworkObjectConfig(ctx *getconfigContext,
	cfgNetworks []*zconfig.NetworkConfig) {

	// Check for items to delete first
	items := ctx.pubNetworkObjectConfig.GetAll()
	for k, _ := range items {
		netEnt := lookupNetworkId(k, cfgNetworks)
		if netEnt != nil {
			continue
		}
		log.Debugf("publishNetworkObjectConfig: unpublishing %s\n", k)
		ctx.pubNetworkObjectConfig.Unpublish(k)
	}
	// XXX note that we currently get repeats in the same loop.
	// Should we track them and not rewrite them?
	for _, netEnt := range cfgNetworks {
		id, err := uuid.FromString(netEnt.Id)
		if err != nil {
			log.Errorf("publishNetworkObjectConfig: Malformed UUID ignored: %s\n",
				err)
			continue
		}
		config := types.NetworkObjectConfig{
			UUID: id,
			Type: types.NetworkType(netEnt.Type),
		}

		log.Infof("publishNetworkObjectConfig: processing %s type %d\n",
			config.Key(), config.Type)

		ipspec := netEnt.GetIp()
		switch config.Type {
		case types.NT_CryptoEID:
			// XXX hack waiting for cloud
			if ipspec == nil {
				log.Errorf("XXX CryptoEID publishNetworkObjectConfig: Missing ipspec for %s in %v\n",
					id.String(), netEnt)
				break
			}
			fallthrough
		case types.NT_IPV4, types.NT_IPV6:
			if ipspec == nil {
				log.Errorf("publishNetworkObjectConfig: Missing ipspec for %s in %v\n",
					id.String(), netEnt)
				continue
			}
			err := parseIpspec(ipspec, &config)
			if err != nil {
				// XXX return how?
				log.Errorf("publishNetworkObjectConfig: parseIpspec failed: %s\n", err)
				continue
			}
		default:
			log.Errorf("publishNetworkObjectConfig: Unknown NetworkConfig type %d for %s in %v; ignored\n",
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

		ctx.pubNetworkObjectConfig.Publish(config.Key(),
			&config)
	}
}

func parseIpspec(ipspec *zconfig.Ipspec, config *types.NetworkObjectConfig) error {
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

func publishNetworkServiceConfig(ctx *getconfigContext,
	cfgServices []*zconfig.ServiceInstanceConfig) {

	// Check for items to delete first
	items := ctx.pubNetworkServiceConfig.GetAll()
	for k, c := range items {
		svcEnt := lookupServiceId(k, cfgServices)
		if svcEnt != nil {
			continue
		}
		config := cast.CastNetworkServiceConfig(c)
		if config.Key() != k {
			log.Errorf("publishNetworkServiceConfig key/UUID mismatch %s vs %s; ignored %+v\n",
				k, config.Key(), config)
			continue
		}
		if config.Internal {
			log.Infof("publishNetworkServiceConfig: not deleting internal %s: %v\n", k, config)
			continue
		}
		log.Debugf("publishNetworkServiceConfig: unpublishing %s\n", k)
		ctx.pubNetworkServiceConfig.Unpublish(k)
	}
	for _, svcEnt := range cfgServices {
		id, err := uuid.FromString(svcEnt.Id)
		if err != nil {
			log.Errorf("NetworkServiceConfig: Malformed UUID %s ignored: %s\n",
				svcEnt.Id, err)
			continue
		}
		service := types.NetworkServiceConfig{
			UUID:        id,
			DisplayName: svcEnt.Displayname,
			Type:        types.NetworkServiceType(svcEnt.Srvtype),
			Activate:    svcEnt.Activate,
		}
		log.Infof("publishNetworkServiceConfig: processing %s %s type %d activate %v\n",
			service.UUID.String(), service.DisplayName, service.Type,
			service.Activate)

		if svcEnt.Applink != "" {
			applink, err := uuid.FromString(svcEnt.Applink)
			if err != nil {
				log.Errorf("publishNetworkServiceConfig: Malformed UUID %s ignored: %s\n",
					svcEnt.Applink, err)
				continue
			}
			service.AppLink = applink
		}
		if svcEnt.Devlink != nil {
			if svcEnt.Devlink.Type != zconfig.ZCioType_ZCioEth {
				log.Errorf("publishNetworkServiceConfig: Unsupported IoType %v ignored\n",
					svcEnt.Devlink.Type)
				continue
			}
			service.Adapter = svcEnt.Devlink.Name
		}
		if svcEnt.Cfg != nil {
			service.OpaqueConfig = svcEnt.Cfg.Oconfig
		}
		if svcEnt.LispCfg != nil {
			mapServers := []types.MapServer{}
			for _, ms := range svcEnt.LispCfg.LispMSs {
				mapServer := types.MapServer{
					ServiceType: types.MapServerType(ms.ZsType),
					NameOrIp:    ms.NameOrIp,
					Credential:  ms.Credential,
				}
				mapServers = append(mapServers, mapServer)
			}
			eidPrefix := net.IP(svcEnt.LispCfg.Allocationprefix)

			// Populate service Lisp config that should be sent to zedrouter
			service.LispConfig = types.ServiceLispConfig{
				MapServers:    mapServers,
				IID:           svcEnt.LispCfg.LispInstanceId,
				Allocate:      svcEnt.LispCfg.Allocate,
				ExportPrivate: svcEnt.LispCfg.Exportprivate,
				EidPrefix:     eidPrefix,
				EidPrefixLen:  svcEnt.LispCfg.Allocationprefixlen,
				Experimental:  svcEnt.LispCfg.Experimental,
			}
		}
		ctx.pubNetworkServiceConfig.Publish(service.UUID.String(),
			&service)
	}
}

func parseAppNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig) {

	parseUnderlayNetworkConfig(appInstance, cfgApp, cfgNetworks)
	parseOverlayNetworkConfig(appInstance, cfgApp, cfgNetworks)
}

func parseUnderlayNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig) {

	for _, intfEnt := range cfgApp.Interfaces {
		netEnt := lookupNetworkId(intfEnt.NetworkId, cfgNetworks)
		if netEnt == nil {
			log.Errorf("parseUnderlayNetworkConfig: Can't find network id %s; ignored\n",
				intfEnt.NetworkId)
			continue
		}
		uuid, err := uuid.FromString(netEnt.Id)
		if err != nil {
			log.Errorf("parseUnderlayNetworkConfig: Malformed UUID %s ignored: %s\n",
				netEnt.Id, err)
			continue
		}
		switch netEnt.Type {
		case zconfig.NetworkType_V4, zconfig.NetworkType_V6:
			// Do nothing
		default:
			continue
		}
		log.Infof("parseUnderlayNetworkConfig: app %v net %v type %v\n",
			cfgApp.Displayname, uuid.String(), netEnt.Type)

		ulCfg := new(types.UnderlayNetworkConfig)
		ulCfg.Network = uuid
		if intfEnt.MacAddress != "" {
			log.Infof("parseUnderlayNetworkConfig: got static MAC %s\n",
				intfEnt.MacAddress)
			ulCfg.AppMacAddr, err = net.ParseMAC(intfEnt.MacAddress)
			if err != nil {
				log.Errorf("parseUnderlayNetworkConfig: bad MAC %s: %s\n",
					intfEnt.MacAddress, err)
				// XXX report error?
			}
		}
		if intfEnt.Addr != "" {
			log.Infof("parseUnderlayNetworkConfig: got static IP %s\n",
				intfEnt.Addr)
			ulCfg.AppIPAddr = net.ParseIP(intfEnt.Addr)
			if ulCfg.AppIPAddr == nil {
				log.Errorf("parseUnderlayNetworkConfig: bad AppIPAddr %s\n",
					intfEnt.Addr)
				// XXX report error?
			}
			// XXX workaround for bad config from zedcloud
			if ulCfg.AppIPAddr.To4() == nil {
				log.Errorf("XXX parseUnderlayNetworkConfig: ignoring static IPv6 %s\n",
					intfEnt.Addr)
				ulCfg.AppIPAddr = nil
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
		appInstance.UnderlayNetworkList = append(appInstance.UnderlayNetworkList,
			*ulCfg)
	}
}

func parseOverlayNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig) {

	for _, intfEnt := range cfgApp.Interfaces {
		netEnt := lookupNetworkId(intfEnt.NetworkId, cfgNetworks)
		if netEnt == nil {
			log.Errorf("parseOverlayNetworkConfig: Can't find network id %s; ignored\n",
				intfEnt.NetworkId)
			continue
		}
		uuid, err := uuid.FromString(netEnt.Id)
		if err != nil {
			log.Errorf("parseOverlayNetworkConfig: Malformed UUID ignored: %s\n",
				err)
			continue
		}
		if netEnt.Type != zconfig.NetworkType_CryptoEID {
			continue
		}
		log.Infof("parseOverlayNetworkConfig: app %v net %v type %v\n",
			cfgApp.Displayname, uuid.String(), netEnt.Type)

		olCfg := new(types.EIDOverlayConfig)
		olCfg.Network = uuid
		if intfEnt.MacAddress != "" {
			olCfg.AppMacAddr, err = net.ParseMAC(intfEnt.MacAddress)
			if err != nil {
				log.Errorf("parseOverlayNetworkConfig: bad MAC %s: %s\n",
					intfEnt.MacAddress, err)
				// XXX report error?
			}
		}
		// Handle old and new location of EIDv6
		if intfEnt.CryptoEid != "" {
			olCfg.EIDConfigDetails.EID = net.ParseIP(intfEnt.CryptoEid)
			if olCfg.EIDConfigDetails.EID == nil {
				log.Errorf("parseOverrlayNetworkConfig: bad CryptoEid %s\n",
					intfEnt.CryptoEid)
				// XXX report error?
			}
			// Any IPv4 EID?
			if intfEnt.Addr != "" {
				olCfg.AppIPAddr = net.ParseIP(intfEnt.Addr)
				if olCfg.AppIPAddr == nil {
					log.Errorf("parseOverlayNetworkConfig: bad Addr %s\n",
						intfEnt.Addr)
					// XXX report error?
				}
			}
		} else if intfEnt.Addr != "" {
			olCfg.EIDConfigDetails.EID = net.ParseIP(intfEnt.Addr)
			if olCfg.EIDConfigDetails.EID == nil {
				log.Errorf("parseOverrlayNetworkConfig: bad Addr %s\n",
					intfEnt.Addr)
				// XXX report error?
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

		appInstance.OverlayNetworkList = append(appInstance.OverlayNetworkList,
			*olCfg)
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

	globalConfigChange := false
	for _, item := range items {
		log.Infof("parseConfigItems key %s\n", item.Key)

		var newU32 uint32
		var newBool bool
		var newString string
		switch u := item.ConfigItemValue.(type) {
		case *zconfig.ConfigItem_Uint32Value:
			newU32 = u.Uint32Value
		case *zconfig.ConfigItem_BoolValue:
			newBool = u.BoolValue
		case *zconfig.ConfigItem_StringValue:
			newString = u.StringValue
		default:
			log.Errorf("parseConfigItems: not supporting %T type\n",
				u)
			continue
		}
		switch item.Key {
		case "configInterval":
			if newU32 == 0 {
				// Revert to default
				newU32 = globalConfigDefaults.ConfigInterval
			}
			if newU32 != globalConfig.ConfigInterval {
				log.Infof("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					globalConfig.ConfigInterval,
					newU32)
				globalConfig.ConfigInterval = newU32
				globalConfigChange = true
				updateConfigTimer(ctx.configTickerHandle)
			}
		case "metricInterval":
			if newU32 == 0 {
				// Revert to default
				newU32 = globalConfigDefaults.MetricInterval
			}
			if newU32 != globalConfig.MetricInterval {
				log.Infof("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					globalConfig.MetricInterval,
					newU32)
				globalConfig.MetricInterval = newU32
				globalConfigChange = true
				updateMetricsTimer(ctx.metricsTickerHandle)
			}
		case "resetIfCloudGoneTime":
			if newU32 == 0 {
				// Revert to default
				newU32 = globalConfigDefaults.ResetIfCloudGoneTime
			}
			if newU32 != globalConfig.ResetIfCloudGoneTime {
				log.Infof("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					globalConfig.ResetIfCloudGoneTime,
					newU32)
				globalConfig.ResetIfCloudGoneTime = newU32
				globalConfigChange = true
			}
		case "fallbackIfCloudGoneTime":
			if newU32 == 0 {
				// Revert to default
				newU32 = globalConfigDefaults.FallbackIfCloudGoneTime
			}
			if newU32 != globalConfig.FallbackIfCloudGoneTime {
				log.Infof("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					globalConfig.FallbackIfCloudGoneTime,
					newU32)
				globalConfig.FallbackIfCloudGoneTime = newU32
				globalConfigChange = true
			}
		case "mintimeUpdateSuccess":
			if newU32 == 0 {
				// Revert to default
				newU32 = globalConfigDefaults.MintimeUpdateSuccess
			}
			if newU32 != globalConfig.MintimeUpdateSuccess {
				log.Errorf("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					globalConfig.MintimeUpdateSuccess,
					newU32)
				globalConfig.MintimeUpdateSuccess = newU32
				globalConfigChange = true
			}
		case "noUsbAccess": // XXX swap name
			if newBool != globalConfig.NoUsbAccess {
				log.Infof("parseConfigItems: %s change from %v to %v\n",
					item.Key,
					globalConfig.NoUsbAccess,
					newBool)
				globalConfig.NoUsbAccess = newBool
				globalConfigChange = true
				// Need to enable/disable login in domainMgr
				// for PCI assignment
				// XXX updateUsbAccess(!globalConfig.NoUsbAccess)
			}
		case "noSshAccess": // XXX swap name
			if newBool != globalConfig.NoSshAccess {
				log.Infof("parseConfigItems: %s change from %v to %v\n",
					item.Key,
					globalConfig.NoSshAccess,
					newBool)
				globalConfig.NoSshAccess = newBool
				globalConfigChange = true
				updateSshAccess(!globalConfig.NoSshAccess)
			}
		case "staleConfigTime":
			if newU32 == 0 {
				// Revert to default
				newU32 = globalConfigDefaults.StaleConfigTime
			}
			if newU32 != globalConfig.StaleConfigTime {
				log.Infof("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					globalConfig.StaleConfigTime,
					newU32)
				globalConfig.StaleConfigTime = newU32
				globalConfigChange = true
			}
		case "defaultLogLevel":
			if newString == "" {
				// Revert to default
				newString = globalConfigDefaults.DefaultLogLevel
			}
			if newString != globalConfig.DefaultLogLevel {
				log.Infof("parseConfigItems: %s change from %v to %v\n",
					item.Key,
					globalConfig.DefaultLogLevel,
					newString)
				globalConfig.DefaultLogLevel = newString
				globalConfigChange = true
			}
		case "defaultRemoteLogLevel":
			if newString == "" {
				// Revert to default
				newString = globalConfigDefaults.DefaultRemoteLogLevel
			}
			if newString != globalConfig.DefaultRemoteLogLevel {
				log.Infof("parseConfigItems: %s change from %v to %v\n",
					item.Key,
					globalConfig.DefaultRemoteLogLevel,
					newString)
				globalConfig.DefaultRemoteLogLevel = newString
				globalConfigChange = true
			}
		default:
			log.Errorf("Unknown configItem %s\n", item.Key)
			// XXX send back error? Need device error for that
		}
	}
	if globalConfigChange {
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
		log.Fatal("computeConfigSha: proto.Marshal: %s\n", err)
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
		log.Fatal("computeConfigItemSha: proto.Marshal: %s\n",
			err)
	}
	h.Write(data)
}

// Returns a rebootFlag
func parseOpCmds(config *zconfig.EdgeDevConfig) bool {

	scheduleBackup(config.GetBackup())
	return scheduleReboot(config.GetReboot())
}

var rebootPrevConfigHash []byte
var rebootPrevReturn bool

// Returns a rebootFlag
func scheduleReboot(reboot *zconfig.DeviceOpsCmd) bool {

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

		// start the timer again
		// XXX:FIXME, need to handle the scheduled time
		duration := time.Duration(immediate)
		rebootTimer = time.NewTimer(time.Second * duration)

		log.Infof("Scheduling for reboot %d %d\n",
			rebootConfig.Counter, reboot.Counter)

		go handleReboot()
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
func handleReboot() {

	rebootConfig := &zconfig.DeviceOpsCmd{}
	var state bool

	<-rebootTimer.C

	// read reboot config
	if _, err := os.Stat(rebootConfigFilename); err == nil {
		bytes, err := ioutil.ReadFile(rebootConfigFilename)
		if err == nil {
			err = json.Unmarshal(bytes, rebootConfig)
		}
		state = rebootConfig.DesiredState
	}

	execReboot(state)
}

func startExecReboot() {

	log.Infof("startExecReboot: scheduling exec reboot\n")

	//timer was started, stop now
	if rebootTimer != nil {
		rebootTimer.Stop()
	}

	// start the timer again
	// XXX:FIXME, need to handle the scheduled time
	duration := time.Duration(immediate)
	rebootTimer = time.NewTimer(time.Second * duration)

	go handleExecReboot()
}

func handleExecReboot() {

	<-rebootTimer.C

	execReboot(true)
}

func execReboot(state bool) {

	// do a sync
	log.Infof("Doing a sync..\n")
	syscall.Sync()

	switch state {

	case true:
		log.Infof("Rebooting...\n")
		duration := time.Duration(immediate)
		timer := time.NewTimer(time.Second * duration)
		<-timer.C
		zboot.Reset()

	case false:
		log.Infof("Powering Off..\n")
		duration := time.Duration(immediate)
		timer := time.NewTimer(time.Second * duration)
		<-timer.C
		poweroffCmd := exec.Command("poweroff")
		_, err := poweroffCmd.Output()
		if err != nil {
			log.Errorln(err)
		}
	}
}
