// Copyright (c) 2017 Zededa, Inc.
// All rights reserved.

package main

import (
	"encoding/json"
	"github.com/satori/go.uuid"
	"github.com/zededa/api/zconfig"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zboot"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"reflect"
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
func parseConfig(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext) bool {

	log.Println("Applying new config")

	if parseOpCmds(config) == true {
		log.Println("Reboot flag set, skipping config processing")
		return true
	}

	// updating/rebooting, ignore config??
	// XXX can we get stuck here?
	if zboot.IsOtherPartitionStateUpdating() {
		log.Println("OtherPartitionStatusUpdating - returning rebootFlag")
		return true
	}

	// If the other partition is inprogress it means update failed
	// We leave in inprogress state so logmanager can use it to decide
	// to upload the other logs. If a different BaseOsVersion is provided
	// we allow it to be installed into the inprogress partition.
	if zboot.IsOtherPartitionStateInProgress() {
		otherPart := zboot.GetOtherPartition()
		log.Printf("Other %s partition contains failed upgrade\n",
			otherPart)
	}

	if validateConfig(config) {
		// Look for timers and other settings in configItems
		parseConfigItems(config, getconfigCtx)

		// if no baseOs config write, consider
		// picking up application image config

		if parseBaseOsConfig(config) == false {
			parseAppInstanceConfig(config)
		}

		// XXX:FIXME, otherwise, dont process
		// app image config, until the current
		// baseos config processing is complete
	}
	return false
}

func validateConfig(config *zconfig.EdgeDevConfig) bool {

	//XXX:FIXME, check if any validation required

	// Check the drives entries  MaxSize
	// for baseOs/App has non-zero value

	return true
}

// Returns true if there is some baseOs work to do
func parseBaseOsConfig(config *zconfig.EdgeDevConfig) bool {
	cfgOsList := config.GetBase()
	baseOsCount := len(cfgOsList)
	log.Printf("parseBaseOsConfig() Applying Base Os config len %d\n",
		baseOsCount)

	if baseOsCount == 0 {
		return false
	}
	if !zboot.IsAvailable() {
		log.Printf("No zboot; ignoring baseOsConfig\n")
		return false
	}

	baseOsList := make([]*types.BaseOsConfig, len(cfgOsList))
	certList := make([]*types.CertObjConfig, len(cfgOsList))

	idx := 0
	for _, cfgOs := range cfgOsList {

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

		imageCount := 0
		for _, drive := range cfgOs.Drives {
			if drive.Image != nil {
				imageId := drive.Image.DsId

				for _, dsEntry := range config.Datastores {
					if dsEntry.Id == imageId {
						imageCount++
						break
					}
				}
			}
		}

		if imageCount != BaseOsImageCount {
			log.Printf("%s, invalid storage config %d\n", baseOs.BaseOsVersion, imageCount)
			continue
		}

		baseOs.StorageConfigList = make([]types.StorageConfig, imageCount)
		parseStorageConfigList(config, baseOsObj,
			baseOs.StorageConfigList, cfgOs.Drives)

		baseOsList[idx] = baseOs
		certInstance := getCertObjects(baseOs.UUIDandVersion,
			baseOs.ConfigSha256, baseOs.StorageConfigList)
		if certInstance != nil {
			certList[idx] = certInstance
		}
		idx++

		// Dump the config content
		bytes, err := json.Marshal(baseOs)
		if err == nil {
			log.Printf("New/updated BaseOs %d: %s\n", idx, bytes)
		}
		// XXX shouldn't the code write what it just marshalled?
	}

	// XXX defer until we have validated; call with BaseOsStatus
	assignBaseOsPartition(baseOsList)

	// XXX configCount needs to take "failed update" into account
	configCount := 0
	if validateBaseOsConfig(baseOsList) == true {
		configCount = createBaseOsConfig(baseOsList, certList)
	}

	// baseOs config write, is true
	if configCount > 0 {
		return true
	}
	return false
}

// XXX should work on BaseOsStatus
func assignBaseOsPartition(baseOsList []*types.BaseOsConfig) {
	curPartName := zboot.GetCurrentPartition()
	otherPartName := zboot.GetOtherPartition()
	curPartVersion := zboot.GetShortVersion(curPartName)
	otherPartVersion := zboot.GetShortVersion(otherPartName)

	assignedPart := true
	// older assignments/installations
	for _, baseOs := range baseOsList {
		if baseOs == nil {
			continue
		}
		uuidStr := baseOs.UUIDandVersion.UUID.String()
		curBaseOsConfig := baseOsConfigGet(uuidStr)

		if curBaseOsConfig != nil &&
			curBaseOsConfig.PartitionLabel != "" {
			baseOs.PartitionLabel = curBaseOsConfig.PartitionLabel
			setStoragePartitionLabel(baseOs)
			log.Printf("%s, assigned with partition %s, %s\n",
				uuidStr, baseOs.BaseOsVersion, baseOs.PartitionLabel)
			continue
		}

		if curPartVersion == baseOs.BaseOsVersion {
			baseOs.PartitionLabel = curPartName
			setStoragePartitionLabel(baseOs)
			log.Printf("%s, installed in partition %s\n",
				baseOs.BaseOsVersion, baseOs.PartitionLabel)
			continue
		}

		if otherPartVersion == baseOs.BaseOsVersion {
			baseOs.PartitionLabel = otherPartName
			setStoragePartitionLabel(baseOs)
			log.Printf("%s, installed in partition %s\n",
				baseOs.BaseOsVersion, baseOs.PartitionLabel)
			continue
		}
		assignedPart = false
	}

	if assignedPart == true {
		return
	}

	// if activate set, assign partition
	for _, baseOs := range baseOsList {
		if baseOs == nil || baseOs.PartitionLabel != "" {
			continue
		}

		if baseOs.Activate == true {
			baseOs.PartitionLabel = otherPartName
			setStoragePartitionLabel(baseOs)
			log.Printf("%s, assigning with partition %s\n",
				baseOs.BaseOsVersion, baseOs.PartitionLabel)
			assignedPart = true
			break
		}
	}

	if assignedPart == true {
		return
	}

	// still not assigned, assign partition
	for _, baseOs := range baseOsList {
		if baseOs == nil || baseOs.PartitionLabel != "" {
			continue
		}
		baseOs.PartitionLabel = otherPartName
		setStoragePartitionLabel(baseOs)
		log.Printf("%s, assigning with partition %s\n",
			baseOs.BaseOsVersion, baseOs.PartitionLabel)
	}
}

func setStoragePartitionLabel(baseOs *types.BaseOsConfig) {

	for idx, _ := range baseOs.StorageConfigList {
		sc := &baseOs.StorageConfigList[idx]
		sc.FinalObjDir = baseOs.PartitionLabel
	}
}

func parseAppInstanceConfig(config *zconfig.EdgeDevConfig) {

	var appInstance = types.AppInstanceConfig{}

	log.Println("Applying App Instance config")

	Apps := config.GetApps()

	for _, cfgApp := range Apps {

		log.Printf("New/updated app instance %v\n", cfgApp)

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

		var imageCount int
		for _, drive := range cfgApp.Drives {
			if drive.Image != nil {
				imageId := drive.Image.DsId

				for _, dsEntry := range config.Datastores {
					if dsEntry.Id == imageId {
						imageCount++
						break
					}
				}
			}
		}

		if imageCount != 0 {
			appInstance.StorageConfigList = make([]types.StorageConfig, imageCount)
			parseStorageConfigList(config, appImgObj,
				appInstance.StorageConfigList, cfgApp.Drives)
		}

		// fill the overlay/underlay config
		parseNetworkConfig(&appInstance, cfgApp, config.Networks)

		// I/O adapters
		appInstance.IoAdapterList = nil
		for _, adapter := range cfgApp.Adapters {
			log.Printf("Processing adapter type %d name %s\n",
				adapter.Type, adapter.Name)
			appInstance.IoAdapterList = append(appInstance.IoAdapterList,
				types.IoAdapter{Type: types.IoType(adapter.Type),
					Name: adapter.Name})
		}
		log.Printf("Got adapters %v\n", appInstance.IoAdapterList)

		// get the certs for image sha verification
		certInstance := getCertObjects(appInstance.UUIDandVersion,
			appInstance.ConfigSha256, appInstance.StorageConfigList)

		if validateAppInstanceConfig(appInstance) == true {

			// write to zedmanager config directory
			uuidStr := cfgApp.Uuidandversion.Uuid
			writeAppInstanceConfig(appInstance, uuidStr)
			if certInstance != nil {
				writeCertObjConfig(certInstance, uuidStr)
			}
		}
	}
}

func parseStorageConfigList(config *zconfig.EdgeDevConfig, objType string,
	storageList []types.StorageConfig, drives []*zconfig.Drive) {

	var idx int = 0

	for _, drive := range drives {

		found := false

		image := new(types.StorageConfig)
		for _, ds := range config.Datastores {

			if drive.Image != nil &&
				drive.Image.DsId == ds.Id {

				found = true
				image.DownloadURL = ds.Fqdn + "/" + ds.Dpath + "/" + drive.Image.Name
				image.TransportMethod = ds.DType.String()
				image.ApiKey = ds.ApiKey
				image.Password = ds.Password
				image.Dpath = ds.Dpath
				break
			}
		}

		if found == false {
			continue
		}

		image.Format = strings.ToLower(drive.Image.Iformat.String())
		image.Size = uint64(drive.Image.SizeBytes)
		image.ReadOnly = drive.Readonly
		image.Preserve = drive.Preserve
		image.Target = strings.ToLower(drive.Target.String())
		image.Devtype = strings.ToLower(drive.Drvtype.String())
		image.ImageSignature = drive.Image.Siginfo.Signature
		image.ImageSha256 = drive.Image.Sha256
		image.ImageSha256 = drive.Image.Sha256

		// copy the certificates
		if drive.Image.Siginfo.Signercerturl != "" {
			image.SignatureKey = drive.Image.Siginfo.Signercerturl
		}

		// XXX:FIXME certificates can be many
		// this list, currently contains the certUrls
		// should be the sha/uuid of cert filenames
		// as proper DataStore Entries

		if drive.Image.Siginfo.Intercertsurl != "" {
			image.CertificateChain = make([]string, 1)
			image.CertificateChain[0] = drive.Image.Siginfo.Intercertsurl
		}

		storageList[idx] = *image
		idx++
	}
}

func parseNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig) {

	var ulMaxIdx int = 0
	var olMaxIdx int = 0

	// count the interfaces and allocate
	for _, intfEnt := range cfgApp.Interfaces {
		for _, netEnt := range cfgNetworks {

			if intfEnt.NetworkId == netEnt.Id {

				switch strings.ToLower(netEnt.Type.String()) {
				// underlay interface
				case "v4", "v6":
					{
						ulMaxIdx++
						break
					}
				// overlay interface
				case "lisp":
					{
						olMaxIdx++
						break
					}
				}
			}
		}
	}

	if ulMaxIdx != 0 {
		appInstance.UnderlayNetworkList = make([]types.UnderlayNetworkConfig, ulMaxIdx)
		parseUnderlayNetworkConfig(appInstance, cfgApp, cfgNetworks)
	}

	if olMaxIdx != 0 {
		appInstance.OverlayNetworkList = make([]types.EIDOverlayConfig, olMaxIdx)
		parseOverlayNetworkConfig(appInstance, cfgApp, cfgNetworks)
	}
}

func parseUnderlayNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig) {

	var ulIdx int = 0

	for _, intfEnt := range cfgApp.Interfaces {
		for _, netEnt := range cfgNetworks {

			if intfEnt.NetworkId == netEnt.Id &&
				(strings.ToLower(netEnt.Type.String()) == "v4" ||
					strings.ToLower(netEnt.Type.String()) == "v6") {

				nv4 := netEnt.GetNv4() //XXX not required now...
				if nv4 != nil {
					booValNv4 := nv4.Dhcp
					log.Println("booValNv4: ", booValNv4)
				}
				nv6 := netEnt.GetNv6() //XXX not required now...
				if nv6 != nil {
					booValNv6 := nv6.Dhcp
					log.Println("booValNv6: ", booValNv6)
				}

				ulCfg := new(types.UnderlayNetworkConfig)
				ulCfg.ACLs = make([]types.ACE, len(intfEnt.Acls))

				for aclIdx, acl := range intfEnt.Acls {

					aclCfg := new(types.ACE)
					aclCfg.Matches = make([]types.ACEMatch, len(acl.Matches))
					aclCfg.Actions = make([]types.ACEAction, len(acl.Actions))

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
						// XXX:FIXME actionCfg.Drop = <TBD>
						aclCfg.Actions[actionIdx] = *actionCfg
					}
					ulCfg.ACLs[aclIdx] = *aclCfg
				}
				appInstance.UnderlayNetworkList[ulIdx] = *ulCfg
				ulIdx++
			}
		}
	}
}

func parseOverlayNetworkConfig(appInstance *types.AppInstanceConfig,
	cfgApp *zconfig.AppInstanceConfig,
	cfgNetworks []*zconfig.NetworkConfig) {
	var olIdx int = 0

	for _, intfEnt := range cfgApp.Interfaces {
		for _, netEnt := range cfgNetworks {

			if intfEnt.NetworkId == netEnt.Id &&
				strings.ToLower(netEnt.Type.String()) == "lisp" {

				olCfg := new(types.EIDOverlayConfig)
				olCfg.ACLs = make([]types.ACE, len(intfEnt.Acls))

				for aclIdx, acl := range intfEnt.Acls {

					aclCfg := new(types.ACE)
					aclCfg.Matches = make([]types.ACEMatch, len(acl.Matches))
					aclCfg.Actions = make([]types.ACEAction, len(acl.Actions))

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
						aclCfg.Actions[actionIdx] = *actionCfg
					}
					olCfg.ACLs[aclIdx] = *aclCfg
				}

				olCfg.EIDConfigDetails.EID = net.ParseIP(intfEnt.Addr)
				olCfg.EIDConfigDetails.LispSignature = intfEnt.Lispsignature
				olCfg.EIDConfigDetails.PemCert = intfEnt.Pemcert
				olCfg.EIDConfigDetails.PemPrivateKey = intfEnt.Pemprivatekey

				nlisp := netEnt.GetNlisp()

				if nlisp != nil {

					if nlisp.Eidalloc != nil {

						olCfg.EIDConfigDetails.IID = nlisp.Iid
						olCfg.EIDConfigDetails.EIDAllocation.Allocate = nlisp.Eidalloc.Allocate
						olCfg.EIDConfigDetails.EIDAllocation.ExportPrivate = nlisp.Eidalloc.Exportprivate
						olCfg.EIDConfigDetails.EIDAllocation.AllocationPrefix = nlisp.Eidalloc.Allocationprefix
						olCfg.EIDConfigDetails.EIDAllocation.AllocationPrefixLen = int(nlisp.Eidalloc.Allocationprefixlen)
					}

					if len(nlisp.Nmtoeid) != 0 {

						olCfg.NameToEidList = make([]types.NameToEid, len(nlisp.Nmtoeid))

						for nameIdx, nametoeid := range nlisp.Nmtoeid {

							nameCfg := new(types.NameToEid)
							nameCfg.HostName = nametoeid.Hostname
							nameCfg.EIDs = make([]net.IP, len(nametoeid.Eids))

							for eIdx, eid := range nametoeid.Eids {
								nameCfg.EIDs[eIdx] = net.ParseIP(eid)
							}

							olCfg.NameToEidList[nameIdx] = *nameCfg
						}
					}
				} else {
					log.Printf("No Nlisp in for %v\n", netEnt.Id)
				}

				appInstance.OverlayNetworkList[olIdx] = *olCfg
				olIdx++
			}
		}
	}
}

func parseConfigItems(config *zconfig.EdgeDevConfig, getconfigCtx *getconfigContext) {
	log.Printf("parseConfigItems\n")

	items := config.GetConfigItems()
	for _, item := range items {
		log.Printf("parseConfigItems key %s\n", item.Key)

		var newU32 uint32
		switch u := item.ConfigItemValue.(type) {
		case *zconfig.ConfigItem_Uint32Value:
			newU32 = u.Uint32Value
		// XXX handle more types
		// Currently we only have configItems with a uint32Value
		default:
			log.Printf("parseConfigItems: currently only supporting uint32\n")
			continue
		}
		switch item.Key {
		case "configInterval":
			if newU32 == 0 {
				// Revert to default
				newU32 = configItemDefaults.configInterval
			}
			if newU32 != configItemCurrent.configInterval {
				log.Printf("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					configItemCurrent.configInterval,
					newU32)
				configItemCurrent.configInterval = newU32
				updateConfigTimer(getconfigCtx.configTickerHandle)
			}
		case "metricInterval":
			if newU32 == 0 {
				// Revert to default
				newU32 = configItemDefaults.metricInterval
			}
			if newU32 != configItemCurrent.metricInterval {
				log.Printf("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					configItemCurrent.metricInterval,
					newU32)
				configItemCurrent.metricInterval = newU32
				updateMetricsTimer(getconfigCtx.metricsTickerHandle)
			}
		case "resetIfCloudGoneTime":
			if newU32 == 0 {
				// Revert to default
				newU32 = configItemDefaults.resetIfCloudGoneTime
			}
			if newU32 != configItemCurrent.resetIfCloudGoneTime {
				log.Printf("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					configItemCurrent.resetIfCloudGoneTime,
					newU32)
				configItemCurrent.resetIfCloudGoneTime = newU32
			}
		case "fallbackIfCloudGoneTime":
			if newU32 == 0 {
				// Revert to default
				newU32 = configItemDefaults.fallbackIfCloudGoneTime
			}
			if newU32 != configItemCurrent.fallbackIfCloudGoneTime {
				log.Printf("parseConfigItems: %s change from %d to %d\n",
					item.Key,
					configItemCurrent.fallbackIfCloudGoneTime,
					newU32)
				configItemCurrent.fallbackIfCloudGoneTime = newU32
			}
		// XXX what other configItems should we add?
		default:
			log.Printf("Unknown configItem %s\n", item.Key)
			// XXX send back error? Need device error for that
		}
	}
}

func writeAppInstanceConfig(appInstance types.AppInstanceConfig,
	uuidStr string) {

	log.Printf("Writing app instance UUID %s\n", uuidStr)
	bytes, err := json.Marshal(appInstance)
	if err != nil {
		log.Fatal(err, "json Marshal AppInstanceConfig")
	}
	configFilename := zedmanagerConfigDirname + "/" + uuidStr + ".json"
	err = ioutil.WriteFile(configFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func writeBaseOsConfig(baseOsConfig *types.BaseOsConfig, uuidStr string) {

	configFilename := zedagentBaseOsConfigDirname + "/" + uuidStr + ".json"
	bytes, err := json.Marshal(baseOsConfig)

	if err != nil {
		log.Fatal(err, "json Marshal BaseOsConfig")
	}

	log.Printf("Writing baseOs config UUID %s, %s\n", configFilename, bytes)

	err = ioutil.WriteFile(configFilename, bytes, 0644)

	if err != nil {
		log.Fatal(err)
	}
}

func writeBaseOsStatus(baseOsStatus *types.BaseOsStatus, uuidStr string) {

	statusFilename := zedagentBaseOsStatusDirname + "/" + uuidStr + ".json"
	bytes, err := json.Marshal(baseOsStatus)
	if err != nil {
		log.Fatal(err, "json Marshal BaseOsStatus")
	}

	err = ioutil.WriteFile(statusFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
	// XXX For now we might trigger more often than needed
	// XXX should check whether the status changed
	PublishDeviceInfoToZedCloud(baseOsStatusMap, devCtx.assignableAdapters)
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

	// XXX:FIXME dpath/key/pwd from image storage
	// should be coming from Drive
	// also the sha for the cert should be set
	// XXX:FIXME hardcoding Size as 100KB
	var drive = &types.StorageConfig{
		DownloadURL:     certUrl,
		Size:            100 * 1024,
		TransportMethod: image.TransportMethod,
		Dpath:           "zededa-cert-repo",
		ApiKey:          image.ApiKey,
		Password:        image.Password,
		ImageSha256:     "",
		FinalObjDir:     certificateDirname,
	}
	config.StorageConfigList[idx] = *drive
}

func validateBaseOsConfig(baseOsList []*types.BaseOsConfig) bool {

	var osCount, activateCount int

	//count base os instance activate count
	for _, baseOs := range baseOsList {
		if baseOs != nil {
			osCount++
			if baseOs.Activate == true {
				activateCount++
			}
		}
	}

	// not more than max base os count(2)
	if osCount > MaxBaseOsCount {
		log.Printf("baseOs: Unsupported Instance Count %d\n", osCount)
		return false
	}

	// can not be more than one activate as true
	if osCount != 0 {
		if activateCount != 1 {
			log.Printf("baseOs: Unsupported Activate Count %v\n", activateCount)
			return false
		}
	}
	return true
}

// Returns the number of BaseOsConfig that are new or modified
// XXX not useful for caller if we want to catch failed upgrades up front.
// XXX should we initially populate BaseOsStyatus with what we find in
// the partitions? Makes the checks simpler.
func createBaseOsConfig(baseOsList []*types.BaseOsConfig, certList []*types.CertObjConfig) int {

	writeCount := 0
	for idx, baseOs := range baseOsList {

		if baseOs == nil {
			continue
		}
		uuidStr := baseOs.UUIDandVersion.UUID.String()
		configFilename := zedagentBaseOsConfigDirname + "/" + uuidStr + ".json"
		// file not present
		if _, err := os.Stat(configFilename); err != nil {
			writeBaseOsConfig(baseOs, uuidStr)
			if certList[idx] != nil {
				writeCertObjConfig(certList[idx], uuidStr)
			}
			writeCount++
		} else {
			curBaseOs := &types.BaseOsConfig{}
			bytes, err := ioutil.ReadFile(configFilename)
			if err != nil {
				log.Fatal(err)
			}
			err = json.Unmarshal(bytes, curBaseOs)
			if err != nil {
				log.Fatal(err)
			}
			// changed file
			if !reflect.DeepEqual(curBaseOs, baseOs) {
				writeBaseOsConfig(baseOs, uuidStr)
				if certList[idx] != nil {
					writeCertObjConfig(certList[idx], uuidStr)
				}
				writeCount++
			}
		}
	}
	return writeCount
}

func validateAppInstanceConfig(appInstance types.AppInstanceConfig) bool {
	return true
}

func writeCertObjConfig(config *types.CertObjConfig, uuidStr string) {

	configFilename := zedagentCertObjConfigDirname + "/" + uuidStr + ".json"

	bytes, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err, "json Marshal certObjConfig")
	}

	log.Printf("Writing CA config %s, %s\n", configFilename, bytes)

	err = ioutil.WriteFile(configFilename, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

// Returns a rebootFlag
func parseOpCmds(config *zconfig.EdgeDevConfig) bool {

	scheduleBackup(config.GetBackup())
	return scheduleReboot(config.GetReboot())
}

// Returns a rebootFlag
func scheduleReboot(reboot *zconfig.DeviceOpsCmd) bool {

	if reboot == nil {
		log.Printf("scheduleReboot - removing %s\n",
			rebootConfigFilename)
		// stop the timer
		if rebootTimer != nil {
			rebootTimer.Stop()
		}
		// remove the existing file
		os.Remove(rebootConfigFilename)
		return false
	}

	if _, err := os.Stat(rebootConfigFilename); err != nil {
		// Take received as current and store in file
		log.Printf("scheduleReboot - writing initial %s\n",
			rebootConfigFilename)
		bytes, err := json.Marshal(reboot)
		if err != nil {
			log.Fatal(err)
		}
		err = ioutil.WriteFile(rebootConfigFilename, bytes, 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
	rebootConfig := &zconfig.DeviceOpsCmd{}

	log.Printf("scheduleReboot - reading %s\n",
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
	log.Printf("scheduleReboot read %v\n", rebootConfig)

	// If counter value has changed it means new reboot event
	if rebootConfig.Counter != reboot.Counter {

		log.Printf("scheduleReboot: old %d new %d\n",
			rebootConfig.Counter, reboot.Counter)

		// store current config, persistently
		bytes, err = json.Marshal(reboot)
		if err == nil {
			ioutil.WriteFile(rebootConfigFilename, bytes, 0644)
		}

		//timer was started, stop now
		if rebootTimer != nil {
			rebootTimer.Stop()
		}

		// start the timer again
		// XXX:FIXME, need to handle the scheduled time
		duration := time.Duration(immediate)
		rebootTimer = time.NewTimer(time.Second * duration)

		log.Printf("Scheduling for reboot %d %d\n", rebootConfig.Counter, reboot.Counter)

		go handleReboot()
		return true
	}
	return false
}

func scheduleBackup(backup *zconfig.DeviceOpsCmd) {
	log.Printf("scheduleBackup(%v)\n", backup)
	// XXX:FIXME  handle baackup semantics
	log.Printf("Backup Config: %v\n", backup)
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

	log.Printf("startExecReboot: scheduling exec reboot\n")

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

	// XXX:FIXME perform graceful service stop/ state backup

	// do a sync
	log.Printf("Doing a sync..\n")
	syscall.Sync()

	switch state {

	case true:
		log.Printf("Rebooting...\n")
		duration := time.Duration(immediate)
		timer := time.NewTimer(time.Second * duration)
		<-timer.C
		zboot.Reset()

	case false:
		log.Printf("Powering Off..\n")
		duration := time.Duration(immediate)
		timer := time.NewTimer(time.Second * duration)
		<-timer.C
		poweroffCmd := exec.Command("poweroff")
		_, err := poweroffCmd.Output()
		if err != nil {
			log.Println(err)
		}
	}
}
