// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Pushes info to zedcloud

package zedagent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/containerd/containerd/mount"
	"github.com/eriknordmark/ipinfo"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/info"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netclone"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/host"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// Topic for zedagent netdumps of successful info msg publications.
	netDumpInfoOKTopic = agentName + "-info-ok"
	// Topic for zedagent netdumps of failed info msg publications.
	netDumpInfoFailTopic = agentName + "-info-fail"
)

var (
	nilIPInfo       = ipinfo.IPInfo{}
	smartData       = types.NewSmartDataWithDefaults()
	maxSmartCtlSize = 65536 // Limit size of smartctl output files
)

func deviceInfoTask(ctxPtr *zedagentContext, triggerDeviceInfo <-chan destinationBitset) {
	wdName := agentName + "devinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	ctxPtr.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case dest := <-triggerDeviceInfo:
			start := time.Now()
			log.Function("deviceInfoTask got message")

			PublishDeviceInfoToZedCloud(ctxPtr, dest)
			ctxPtr.iteration++
			log.Function("deviceInfoTask done with message")
			ctxPtr.ps.CheckMaxTimeTopic(wdName, "PublishDeviceInfo", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

// objectInfoTask publishes info for objects, identified by key and type coming from the channel
func objectInfoTask(ctxPtr *zedagentContext, triggerInfo <-chan infoForObjectKey) {
	wdName := agentName + "objectinfo"

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	ctxPtr.ps.RegisterFileWatchdog(wdName)

	for {
		select {
		case infoForKeyMessage := <-triggerInfo:
			infoType := infoForKeyMessage.infoType
			infoDest := infoForKeyMessage.infoDest
			log.Functionf("objectInfoTask got message for %s", infoType.String())
			start := time.Now()
			var err error
			var c interface{}
			switch infoType {
			case info.ZInfoTypes_ZiDevice:
				// publish device info
				PublishDeviceInfoToZedCloud(ctxPtr, infoDest)
				ctxPtr.iteration++
			case info.ZInfoTypes_ZiApp:
				// publish application info
				sub := ctxPtr.getconfigCtx.subAppInstanceStatus
				if c, err = sub.Get(infoForKeyMessage.objectKey); err == nil {
					appStatus := c.(types.AppInstanceStatus)
					uuidStr := appStatus.Key()
					PublishAppInfoToZedCloud(ctxPtr, uuidStr, &appStatus, ctxPtr.assignableAdapters,
						ctxPtr.iteration, infoDest)
					ctxPtr.iteration++
				}
			case info.ZInfoTypes_ZiNetworkInstance:
				// publish network instance info
				sub := ctxPtr.subNetworkInstanceStatus
				if c, err = sub.Get(infoForKeyMessage.objectKey); err == nil {
					niStatus := c.(types.NetworkInstanceStatus)
					prepareAndPublishNetworkInstanceInfoMsg(ctxPtr, niStatus,
						false, infoDest)
					ctxPtr.iteration++
				}
			case info.ZInfoTypes_ZiVolume:
				// publish volume info
				sub := ctxPtr.getconfigCtx.subVolumeStatus
				if c, err = sub.Get(infoForKeyMessage.objectKey); err == nil {
					volumeStatus := c.(types.VolumeStatus)
					uuidStr := volumeStatus.VolumeID.String()
					PublishVolumeToZedCloud(ctxPtr, uuidStr, &volumeStatus,
						ctxPtr.iteration, infoDest)
					ctxPtr.iteration++
				}
			case info.ZInfoTypes_ZiContentTree:
				// publish content tree info
				sub := ctxPtr.getconfigCtx.subContentTreeStatus
				if c, err = sub.Get(infoForKeyMessage.objectKey); err == nil {
					ctStatus := c.(types.ContentTreeStatus)
					// We publish the info to zedcloud only if it is a local contenttree
					if ctStatus.IsLocal {
						uuidStr := ctStatus.Key()
						PublishContentInfoToZedCloud(ctxPtr, uuidStr, &ctStatus,
							ctxPtr.iteration, infoDest)
						ctxPtr.iteration++
					}
				}
			case info.ZInfoTypes_ZiBlobList:
				// publish blob info
				sub := ctxPtr.subBlobStatus
				if c, err = sub.Get(infoForKeyMessage.objectKey); err == nil {
					blobStatus := c.(types.BlobStatus)
					uuidStr := blobStatus.Key()
					PublishBlobInfoToZedCloud(ctxPtr, uuidStr, &blobStatus,
						ctxPtr.iteration, infoDest)
					ctxPtr.iteration++
				}
			case info.ZInfoTypes_ZiAppInstMetaData:
				// publish appInst metadata info
				sub := ctxPtr.subAppInstMetaData
				if c, err = sub.Get(infoForKeyMessage.objectKey); err == nil {
					appInstMetaData := c.(types.AppInstMetaData)
					PublishAppInstMetaDataToZedCloud(ctxPtr, &appInstMetaData,
						false, infoDest)
					ctxPtr.iteration++
				}
			case info.ZInfoTypes_ZiHardware:
				PublishHardwareInfoToZedCloud(ctxPtr, infoDest)
				ctxPtr.iteration++
			case info.ZInfoTypes_ZiEdgeview:
				// publish Edgeview info
				sub := ctxPtr.subEdgeviewStatus
				if c, err = sub.Get(infoForKeyMessage.objectKey); err == nil {
					evStatus := c.(types.EdgeviewStatus)
					PublishEdgeviewToZedCloud(ctxPtr, &evStatus, infoDest)
				}
			case info.ZInfoTypes_ZiLocation:
				locInfo := getLocationInfo(ctxPtr)
				if locInfo != nil {
					// Note that we use a zero iteration
					// counter here.
					publishLocationToDest(ctxPtr, locInfo, 0, infoDest)
				}
			}
			if err != nil {
				log.Functionf("objectInfoTask not found %s for key %s: %s",
					infoType.String(), infoForKeyMessage.objectKey, err)
			}
			log.Function("objectInfoTask done with message")
			ctxPtr.ps.CheckMaxTimeTopic(wdName, "PublishInfo", start,
				warningTime, errorTime)
		case <-stillRunning.C:
		}
		ctxPtr.ps.StillRunning(wdName, warningTime, errorTime)
	}
}

func fillStorageChildren(children []*types.StorageChildren) []*info.StorageChildren {
	var infoChildren []*info.StorageChildren
	for _, child := range children {
		childInfo := new(info.StorageChildren)
		childInfo.CurrentRaid = info.StorageRaidType(child.CurrentRaid)
		childInfo.GUID = child.GUID
		childInfo.DisplayName = child.DisplayName
		for _, disk := range child.Disks {
			diskInfo := new(info.StorageDiskState)
			diskInfo.Status = info.StorageStatus(disk.Status)
			if disk.DiskName != nil {
				diskInfo.DiskName = new(evecommon.DiskDescription)
				diskInfo.DiskName.Name = disk.DiskName.Name
				diskInfo.DiskName.LogicalName = disk.DiskName.LogicalName
				diskInfo.DiskName.Serial = disk.DiskName.Serial
			}
			childInfo.Disks = append(childInfo.Disks, diskInfo)
		}
		childInfo.Children = fillStorageChildren(child.Children)
		infoChildren = append(infoChildren, childInfo)
	}
	return infoChildren
}

// PublishDeviceInfoToZedCloud This function is called per change, hence needs to try over all management ports
func PublishDeviceInfoToZedCloud(ctx *zedagentContext, dest destinationBitset) {
	aa := ctx.assignableAdapters
	subBaseOsStatus := ctx.subBaseOsStatus

	var ReportInfo = &info.ZInfoMsg{}

	deviceType := new(info.ZInfoTypes)
	*deviceType = info.ZInfoTypes_ZiDevice
	ReportInfo.Ztype = *deviceType
	deviceUUID := devUUID.String()
	ReportInfo.DevId = *proto.String(deviceUUID)
	ReportInfo.AtTimeStamp = timestamppb.Now()
	log.Functionf("PublishDeviceInfoToZedCloud uuid %s", deviceUUID)

	ReportDeviceInfo := new(info.ZInfoDevice)

	// Get the remote access status
	ReportDeviceInfo.RemoteAccessDisabled = utils.RemoteAccessDisabled()

	var uname unix.Utsname
	err := unix.Uname(&uname)
	if err != nil {
		log.Errorf("get info from uname failed %s", err)
	} else {
		ReportDeviceInfo.MachineArch = *proto.String(unix.ByteSliceToString(uname.Machine[:]))
		ReportDeviceInfo.CpuArch = *proto.String(unix.ByteSliceToString(uname.Machine[:]))
		ReportDeviceInfo.Platform = *proto.String(unix.ByteSliceToString(uname.Machine[:]))
	}

	sub := ctx.getconfigCtx.subHostMemory
	m, _ := sub.Get("global")
	if m != nil {
		metric := m.(types.HostMemory)
		ReportDeviceInfo.Ncpu = *proto.Uint32(metric.Ncpus)
		ReportDeviceInfo.Memory = *proto.Uint64(metric.TotalMemoryMB)
	}

	ReportDeviceInfo.PowerCycleCounter = smartData.PowerCycleCount
	// Find all disks and partitions
	for _, diskMetric := range getAllDiskMetrics(ctx) {
		var diskPath, mountPath string
		if diskMetric.IsDir {
			mountPath = diskMetric.DiskPath
		} else {
			diskPath = diskMetric.DiskPath
		}
		is := info.ZInfoStorage{
			Device:    diskPath,
			MountPath: mountPath,
			Total:     utils.RoundToMbytes(diskMetric.TotalBytes),
		}
		if diskMetric.DiskPath == types.PersistDir {
			is.StorageLocation = true
			ReportDeviceInfo.Storage += *proto.Uint64(utils.RoundToMbytes(diskMetric.TotalBytes))
		}

		ReportDeviceInfo.StorageList = append(ReportDeviceInfo.StorageList, &is)
	}

	ReportDeviceManufacturerInfo := new(info.ZInfoManufacturer)
	productManufacturer, productName, productVersion, productSerial, productUUID := hardware.GetDeviceManufacturerInfo(log)
	ReportDeviceManufacturerInfo.Manufacturer = *proto.String(strings.TrimSpace(productManufacturer))
	ReportDeviceManufacturerInfo.ProductName = *proto.String(strings.TrimSpace(productName))
	ReportDeviceManufacturerInfo.Version = *proto.String(strings.TrimSpace(productVersion))
	ReportDeviceManufacturerInfo.SerialNumber = *proto.String(strings.TrimSpace(productSerial))
	ReportDeviceManufacturerInfo.UUID = *proto.String(strings.TrimSpace(productUUID))

	biosVendor, biosVersion, biosReleaseDate := hardware.GetDeviceBios(log)
	ReportDeviceManufacturerInfo.BiosVendor = *proto.String(strings.TrimSpace(biosVendor))
	ReportDeviceManufacturerInfo.BiosVersion = *proto.String(strings.TrimSpace(biosVersion))
	ReportDeviceManufacturerInfo.BiosReleaseDate = *proto.String(strings.TrimSpace(biosReleaseDate))

	compatible := hardware.GetCompatible(log)
	ReportDeviceManufacturerInfo.Compatible = *proto.String(compatible)
	ReportDeviceInfo.Minfo = ReportDeviceManufacturerInfo

	ReportDeviceInfo.BaseosUpdateCounter = getBaseosUpdateCounter(ctx)

	// Report BaseOs Status for the two partitions
	getBaseOsStatus := func(partLabel string) *types.BaseOsStatus {
		// Look for a matching IMGA/IMGB in baseOsStatus
		items := subBaseOsStatus.GetAll()
		for _, st := range items {
			bos := st.(types.BaseOsStatus)
			if bos.PartitionLabel == partLabel {
				return &bos
			}
		}
		return nil
	}
	getSwInfo := func(partLabel string) *info.ZInfoDevSW {
		swInfo := new(info.ZInfoDevSW)
		tooEarly := false
		if bos := getBaseOsStatus(partLabel); bos != nil {
			// Get current state/version which is different than
			// what is on disk
			swInfo.Activated = bos.Activated
			swInfo.PartitionLabel = bos.PartitionLabel
			swInfo.PartitionDevice = bos.PartitionDevice
			swInfo.PartitionState = bos.PartitionState
			swInfo.Status = bos.State.ZSwState()
			swInfo.ShortVersion = bos.BaseOsVersion
			swInfo.LongVersion = "" // XXX
			ctInterface, _ := ctx.getconfigCtx.subContentTreeStatus.Get(bos.ContentTreeUUID)
			if ctInterface != nil {
				ct, ok := ctInterface.(types.ContentTreeStatus)
				if ok {
					swInfo.DownloadProgress = uint32(ct.Progress)
				}
			}
			if !bos.ErrorTime.IsZero() {
				log.Tracef("reportMetrics sending error time %v error %v for %s",
					bos.ErrorTime, bos.Error,
					bos.BaseOsVersion)
				swInfo.SwErr = encodeErrorInfo(bos.ErrorAndTime.ErrorDescription)
			}
			if swInfo.ShortVersion == "" {
				swInfo.Status = info.ZSwState_INITIAL
				swInfo.DownloadProgress = 0
			}
			tooEarly = bos.TooEarly
		} else {
			partStatus := getZbootPartitionStatus(ctx, partLabel)
			swInfo.PartitionLabel = partLabel
			if partStatus != nil {
				swInfo.Activated = partStatus.CurrentPartition
				swInfo.PartitionDevice = partStatus.PartitionDevname
				swInfo.PartitionState = partStatus.PartitionState
				swInfo.ShortVersion = partStatus.ShortVersion
				swInfo.LongVersion = partStatus.LongVersion
			}
			if swInfo.ShortVersion != "" {
				swInfo.Status = info.ZSwState_INSTALLED
				swInfo.DownloadProgress = 100
			} else {
				swInfo.Status = info.ZSwState_INITIAL
				swInfo.DownloadProgress = 0
			}
		}
		addUserSwInfo(ctx, swInfo, tooEarly)
		return swInfo
	}

	ReportDeviceInfo.SwList = make([]*info.ZInfoDevSW, 2)
	ReportDeviceInfo.SwList[0] = getSwInfo(getZbootCurrentPartition(ctx))
	ReportDeviceInfo.SwList[1] = getSwInfo(getZbootOtherPartition(ctx))
	// Report any other BaseOsStatus which might have errors
	items := subBaseOsStatus.GetAll()
	for _, st := range items {
		bos := st.(types.BaseOsStatus)
		if bos.PartitionLabel != "" {
			// Already reported above
			continue
		}
		log.Tracef("reportMetrics sending unattached bos for %s",
			bos.BaseOsVersion)
		swInfo := new(info.ZInfoDevSW)
		swInfo.Status = bos.State.ZSwState()
		swInfo.ShortVersion = bos.BaseOsVersion
		swInfo.LongVersion = "" // XXX
		ctInterface, _ := ctx.getconfigCtx.subContentTreeStatus.Get(bos.ContentTreeUUID)
		if ctInterface == nil {
			continue
		}
		ct, ok := ctInterface.(types.ContentTreeStatus)
		if !ok {
			continue
		}
		// Assume one - pick first ContentTreeStatus
		swInfo.DownloadProgress = uint32(ct.Progress)
		if !bos.ErrorTime.IsZero() {
			log.Tracef("reportMetrics sending error time %v error %v for %s",
				bos.ErrorTime, bos.Error, bos.BaseOsVersion)
			swInfo.SwErr = encodeErrorInfo(bos.ErrorAndTime.ErrorDescription)
		}
		addUserSwInfo(ctx, swInfo, bos.TooEarly)
		ReportDeviceInfo.SwList = append(ReportDeviceInfo.SwList,
			swInfo)
	}

	// Reporting all zpools in Storage Info
	if persist.ReadPersistType() == types.PersistZFS {
		zfsPoolStatusMap := ctx.subZFSPoolStatus.GetAll()
		for _, el := range zfsPoolStatusMap {
			zfsPoolStatus := el.(types.ZFSPoolStatus)
			storageInfo := new(info.StorageInfo)
			storageInfo.StorageType = info.StorageTypeInfo_STORAGE_TYPE_INFO_ZFS
			storageInfo.PoolName = zfsPoolStatus.PoolName
			storageInfo.StorageState = info.StorageStatus(zfsPoolStatus.StorageState)
			storageInfo.ZfsVersion = zfsPoolStatus.ZfsVersion
			storageInfo.CurrentRaid = info.StorageRaidType(zfsPoolStatus.CurrentRaid)
			storageInfo.CompressionRatio = zfsPoolStatus.CompressionRatio
			storageInfo.ZpoolSize = zfsPoolStatus.ZpoolSize
			storageInfo.CountZvols = zfsPoolStatus.CountZvols
			storageInfo.PoolStatusMsg = zfsPoolStatus.PoolStatusMsgStr
			storageInfo.CollectorErrors = zfsPoolStatus.CollectorErrors
			for _, disk := range zfsPoolStatus.Disks {
				diskInfo := new(info.StorageDiskState)
				diskInfo.Status = info.StorageStatus(disk.Status)
				diskInfo.SmartStatus = hardware.CheckSMARTinfoForDisk(disk.DiskName.Name)
				diskInfo.State = disk.AuxStateStr
				if disk.DiskName != nil {
					diskInfo.DiskName = new(evecommon.DiskDescription)
					diskInfo.DiskName.Name = disk.DiskName.Name
					diskInfo.DiskName.LogicalName = disk.DiskName.LogicalName
					diskInfo.DiskName.Serial = disk.DiskName.Serial
				}
				storageInfo.Disks = append(storageInfo.Disks, diskInfo)
			}
			storageInfo.Children = fillStorageChildren(zfsPoolStatus.Children)
			ReportDeviceInfo.StorageInfo = append(ReportDeviceInfo.StorageInfo, storageInfo)
			log.Tracef("sending info for ZFS zpool %s", zfsPoolStatus.PoolName)
		}
	} else {
		xStorageInfo := new(info.StorageInfo)
		xStorageInfo.StorageType = info.StorageTypeInfo_STORAGE_TYPE_INFO_EXT4
		xStorageInfo.PoolName = *proto.String(types.PersistDir)
		mi, err := mount.Lookup(types.PersistDir)
		if err != nil {
			log.Errorf("cannot find device with %s mount", types.PersistDir)
			xStorageInfo.StorageState = info.StorageStatus_STORAGE_STATUS_OFFLINE
		} else {
			// If ext4 is mounted its state is considered online
			xStorageInfo.StorageState = info.StorageStatus_STORAGE_STATUS_ONLINE
			serialNumber, err := hardware.GetSerialNumberForDisk(mi.Source)
			if err != nil {
				serialNumber = "unknown"
			}
			rDiskStatus := new(info.StorageDiskState)
			rDiskStatus.DiskName = new(evecommon.DiskDescription)
			rDiskStatus.DiskName.Name = *proto.String(mi.Source)
			rDiskStatus.DiskName.Serial = *proto.String(serialNumber)
			rDiskStatus.Status = info.StorageStatus_STORAGE_STATUS_ONLINE
			rDiskStatus.SmartStatus = hardware.CheckSMARTinfoForDisk(rDiskStatus.DiskName.Name)
			xStorageInfo.Disks = append(xStorageInfo.Disks, rDiskStatus)
		}
		ReportDeviceInfo.StorageInfo = append(ReportDeviceInfo.StorageInfo, xStorageInfo)
		log.Tracef("report metrics sending info for EXT4 storage type")
	}

	// We report all the ports in DeviceNetworkStatus
	// Note that this is deprecated in favour of SystemAdapterInfo.
	for _, p := range deviceNetworkStatus.Ports {
		ReportDeviceNetworkInfo := encodeNetInfo(p)
		// XXX rename DevName to Logicallabel in proto file
		ReportDeviceNetworkInfo.DevName = p.Logicallabel
		ReportDeviceInfo.Network = append(ReportDeviceInfo.Network,
			ReportDeviceNetworkInfo)
	}
	// Report all SIM cards and cellular modules, including those not in use.
	if statusObj, _ := ctx.subWwanStatus.Get("global"); statusObj != nil {
		if status, ok := statusObj.(types.WwanStatus); ok {
			for _, cellNet := range status.Networks {
				ReportDeviceInfo.CellRadios = append(
					ReportDeviceInfo.CellRadios,
					encodeCellModuleInfo(cellNet.Module))
				ReportDeviceInfo.Sims = append(
					ReportDeviceInfo.Sims,
					encodeSimCards(cellNet.Module.Name, cellNet.SimCards)...)
			}
		}
	}
	// Fill in global ZInfoDNS dns from /etc/resolv.conf
	// Note that "domain" is returned in search, hence DNSdomain is
	// not filled in.
	dc := netclone.DnsReadConfig("/etc/resolv.conf")
	log.Tracef("resolv.conf servers %v", dc.Servers)
	log.Tracef("resolv.conf search %v", dc.Search)

	ReportDeviceInfo.Dns = new(info.ZInfoDNS)
	ReportDeviceInfo.Dns.DNSservers = dc.Servers
	ReportDeviceInfo.Dns.DNSsearch = dc.Search

	// Report AssignableAdapters.
	// Domainmgr excludes adapters which do not currently exist in
	// what it publishes.
	// We also mark current management ports as such.
	var seenBundles []string
	for _, ib := range aa.IoBundleList {
		// Report each group once
		seen := false
		for _, s := range seenBundles {
			if s == ib.AssignmentGroup {
				seen = true
				break
			}
		}
		if seen && ib.AssignmentGroup != "" {
			continue
		}
		seenBundles = append(seenBundles, ib.AssignmentGroup)
		reportAA := new(info.ZioBundle)
		reportAA.Type = evecommon.PhyIoType(ib.Type)
		reportAA.Name = ib.AssignmentGroup
		// XXX - Cast is needed because PhyIoMemberUsage was replicated in info
		//  When this is fixed, we can remove this case.
		reportAA.Usage = evecommon.PhyIoMemberUsage(ib.Usage)
		list := aa.LookupIoBundleGroup(ib.AssignmentGroup)
		if len(list) == 0 {
			if ib.AssignmentGroup != "" {
				log.Functionf("Nothing to report for %d %s",
					ib.Type, ib.AssignmentGroup)
				continue
			}
			// Singleton
			list = append(list, &ib)
		}
		for _, b := range list {
			if b == nil {
				continue
			}
			reportAA.Members = append(reportAA.Members,
				b.Logicallabel)
			if b.MacAddr != "" {
				reportMac := new(info.IoAddresses)
				reportMac.MacAddress = b.MacAddr
				reportAA.IoAddressList = append(reportAA.IoAddressList,
					reportMac)
			}
		}
		if ib.UsedByUUID != nilUUID {
			reportAA.UsedByAppUUID = ib.UsedByUUID.String()
		} else if ib.KeepInHost {
			reportAA.UsedByBaseOS = true
		}
		if !ib.Error.Empty() {
			errInfo := new(info.ErrorInfo)
			errInfo.Description = ib.Error.String()
			errInfo.Severity = info.Severity_SEVERITY_ERROR
			if !ib.Error.ErrorTime().IsZero() {
				errInfo.Timestamp = timestamppb.New(ib.Error.ErrorTime())
			}
			reportAA.Err = errInfo
		}
		log.Tracef("AssignableAdapters for %s macs %v",
			reportAA.Name, reportAA.IoAddressList)
		ReportDeviceInfo.AssignableAdapters = append(ReportDeviceInfo.AssignableAdapters,
			reportAA)
	}

	hinfo, err := host.Info()
	if err != nil {
		log.Fatalf("host.Info(): %s", err)
	}
	log.Tracef("uptime %d = %d days",
		hinfo.Uptime, hinfo.Uptime/(3600*24))
	log.Tracef("Booted at %v", time.Unix(int64(hinfo.BootTime), 0).UTC())

	ReportDeviceInfo.BootTime = timestamppb.New(
		time.Unix(int64(hinfo.BootTime), 0).UTC())
	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("HostName failed: %s", err)
	} else {
		ReportDeviceInfo.HostName = hostname
	}

	ReportDeviceInfo.LastRebootReason = ctx.rebootReason
	ReportDeviceInfo.LastBootReason = info.BootReason(ctx.bootReason)
	if ctx.bootReason != types.BootReasonNone {
		// XXX Remove?
		log.Tracef("Reporting BootReason %s", ctx.bootReason.String())
		log.Tracef("Reporting RebootReason %s", ctx.rebootReason)
	}

	ReportDeviceInfo.LastRebootStack = ctx.rebootStack
	if !ctx.rebootTime.IsZero() {
		ReportDeviceInfo.LastRebootTime = timestamppb.New(ctx.rebootTime)
	}

	ReportDeviceInfo.SystemAdapter = encodeSystemAdapterInfo(ctx)

	ReportDeviceInfo.RestartCounter = ctx.restartCounter
	ReportDeviceInfo.RebootConfigCounter = ctx.rebootConfigCounter
	ReportDeviceInfo.ShutdownConfigCounter = ctx.shutdownConfigCounter

	//Operational information about TPM presence/absence/usage.
	ReportDeviceInfo.HSMStatus = etpm.FetchTpmSwStatus()
	ReportDeviceInfo.HSMInfo, _ = etpm.FetchTpmHwInfo()

	//Operational information about Data Security At Rest
	ReportDataSecAtRestInfo := getDataSecAtRestInfo(ctx)

	//This will be removed after new fields propagate to Controller.
	ReportDataSecAtRestInfo.Status, ReportDataSecAtRestInfo.Info =
		vault.GetOperationalInfo(log)
	ReportDeviceInfo.DataSecAtRestInfo = ReportDataSecAtRestInfo
	if len(ReportDataSecAtRestInfo.VaultList) > 0 {
		// We look at the first one since current implementation only
		// has the default vault
		first := ReportDataSecAtRestInfo.VaultList[0]
		var firstErr string
		if first.VaultErr != nil {
			firstErr = first.VaultErr.Description
		}
		if ctx.vaultStatus != first.Status ||
			ctx.pcrStatus != first.PcrStatus ||
			ctx.vaultErr != firstErr {
			ctx.vaultStatus = first.Status
			ctx.pcrStatus = first.PcrStatus
			ctx.vaultErr = firstErr
			publishZedAgentStatus(ctx.getconfigCtx)
		}
	}

	// Add SecurityInfo
	ReportDeviceInfo.SecInfo = getSecurityInfo(ctx)

	// EVE needs to fill deprecated MaintenanceMode until it is removed
	ReportDeviceInfo.MaintenanceMode = ctx.maintenanceMode
	// if we are in maintenance mode, this must have at least one reason, but
	// better safe than sorry.
	if len(ctx.maintModeReasons) > 0 {
		ReportDeviceInfo.MaintenanceModeReason = info.MaintenanceModeReason(ctx.maintModeReasons[0])
	}
	// For backward compatibility added new field
	ReportDeviceInfo.MaintenanceModeReasons = append(ReportDeviceInfo.MaintenanceModeReasons,
		infoMaintModeReason(ctx.maintModeReasons)...)

	// Watchdog
	ReportDeviceInfo.HardwareWatchdogPresent = getHardwareWatchdogPresent(ctx)

	// This is also reported in State
	ReportDeviceInfo.RebootInprogress = ctx.rebootCmd || ctx.deviceReboot

	ReportDeviceInfo.Capabilities = getCapabilities(ctx)
	ReportDeviceInfo.OptionalCapabilities = getOptionalCapabilities(ctx)

	devState := getDeviceState(ctx)
	if ctx.devState != devState {
		ctx.devState = devState
		publishZedAgentStatus(ctx.getconfigCtx)
	}
	ReportDeviceInfo.State = info.ZDeviceState(devState)

	// TODO: Enhance capability reporting with a bitmap-like approach for increased granularity.
	// We report the snapshot capability despite the fact that we support snapshots only
	// for file-based volumes. If a controller tries to make a snapshot of ZFS-based volume
	// device returns a runtime error. Similarly, we only support enforced application network
	// interface order for the KVM hypervisor. If enabled for application deployed under Xen
	// or Kubevirt hypervisor, EVE returns error and the application will not be started.
	ReportDeviceInfo.ApiCapability = info.APICapability_API_CAPABILITY_DISABLE_VTPM

	// Report if there is a local override of profile
	if ctx.getconfigCtx.sideController.currentProfile !=
		ctx.getconfigCtx.sideController.globalProfile {
		ReportDeviceInfo.LocalProfile = ctx.getconfigCtx.sideController.currentProfile
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Dinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Dinfo); ok {
		x.Dinfo = ReportDeviceInfo
	}

	// Add ConfigItems to the DeviceInfo
	ReportDeviceInfo.ConfigItemStatus = createConfigItemStatus(ctx.globalStatus)

	// Add AppInstances to the DeviceInfo. We send a list of all AppInstances
	// currently on the device - even if the corresponding AppInstanceConfig
	// is deleted.
	createAppInstances(ctx, ReportDeviceInfo)

	if ctx.attestCtx != nil && ctx.attestCtx.attestFsmCtx != nil {
		ReportDeviceInfo.AttestationInfo = &info.AttestationInfo{
			State: info.AttestationState(ctx.attestCtx.attestFsmCtx.GetState()),
		}
		if ctx.attestCtx.attestFsmCtx.HasError() {
			ReportDeviceInfo.AttestationInfo.Error = encodeErrorInfo(ctx.attestCtx.attestFsmCtx.ErrorDescription)
		}
		if ctx.attestCtx.Started {
			attestFsmCtx := ctx.attestCtx.attestFsmCtx
			if ctx.attestState != attestFsmCtx.GetState() ||
				ctx.attestError != attestFsmCtx.ErrorDescription.Error {
				ctx.attestState = attestFsmCtx.GetState()
				ctx.attestError = attestFsmCtx.ErrorDescription.Error
				publishZedAgentStatus(ctx.getconfigCtx)
			}
		}
	}

	log.Tracef("PublishDeviceInfoToZedCloud sending %v", ReportInfo)
	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishDeviceInfoToZedCloud proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	withNetTracing := traceNextInfoReq(ctx)
	queueInfoToDest(ctx, dest, deviceUUID, buf, true, withNetTracing, false,
		info.ZInfoTypes_ZiDevice)
}

// PublishAppInstMetaDataToZedCloud is called when an appInst reports its Metadata to EVE.
// AppInst metadata is relayed to the controller to be processed further.
func PublishAppInstMetaDataToZedCloud(ctx *zedagentContext,
	appInstMetadata *types.AppInstMetaData, isDelete bool,
	dest destinationBitset) {

	metadataType := appInstMetadata.Type
	appInstId := appInstMetadata.AppInstUUID.String()
	log.Functionf("PublishAppInstMetaDataToZedCloud: appInstID: %v", appInstId)
	var ReportInfo = &info.ZInfoMsg{}

	contentType := new(info.ZInfoTypes)
	*contentType = info.ZInfoTypes_ZiAppInstMetaData
	ReportInfo.Ztype = *contentType
	ReportInfo.DevId = *proto.String(devUUID.String())
	ReportInfo.AtTimeStamp = timestamppb.Now()

	ReportAppInstMetaData := new(info.ZInfoAppInstMetaData)
	ReportAppInstMetaData.Uuid = appInstId
	ReportAppInstMetaData.Type = info.AppInstMetaDataType(metadataType)

	if !isDelete {
		// The Data size is expected to be <= 32KB. We have a check for that in zedrouter.
		ReportAppInstMetaData.Data = appInstMetadata.Data
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Amdinfo)
	if reportAppInstMetadata, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Amdinfo); ok {
		reportAppInstMetadata.Amdinfo = ReportAppInstMetaData
	}

	log.Functionf("PublishAppInstMetaDataToZedCloud sending %v", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishAppInstMetaDataToZedCloud proto marshaling error: ", err)
	}
	deferKey := "appInstMetadataInfo:" + appInstMetadata.Key()

	buf := bytes.NewBuffer(data)
	if buf == nil {
		log.Fatal("malloc error")
	}

	//We queue the message and then get the highest priority message to send.
	//If there are no failures and defers we'll send this message,
	//but if there is a queue we'll retry sending the highest priority message.
	queueInfoToDest(ctx, dest, deferKey, buf, true, false, false,
		info.ZInfoTypes_ZiAppInstMetaData)
}

// Convert the implementation details to the user-friendly userStatus and subStatus*
func addUserSwInfo(ctx *zedagentContext, swInfo *info.ZInfoDevSW, tooEarly bool) {
	log.Functionf("Device swInfo: %s", swInfo.String())
	switch swInfo.Status {
	case info.ZSwState_INITIAL:
		// If Unused and partitionLabel is set them it
		// is the uninitialized IMGB partition which we don't report
		if swInfo.PartitionState == "unused" &&
			swInfo.PartitionLabel != "" {

			swInfo.UserStatus = info.BaseOsStatus_NONE
		} else if swInfo.ShortVersion == "" {
			swInfo.UserStatus = info.BaseOsStatus_NONE
		} else {
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = info.BaseOsSubStatus_UPDATE_INITIALIZING
			swInfo.SubStatusStr = "Initializing update"
		}
	case info.ZSwState_DOWNLOAD_STARTED:
		swInfo.UserStatus = info.BaseOsStatus_DOWNLOADING
		swInfo.SubStatus = info.BaseOsSubStatus_DOWNLOAD_INPROGRESS
		swInfo.SubStatusProgress = swInfo.DownloadProgress
		swInfo.SubStatusStr = fmt.Sprintf("Download %d%% done",
			swInfo.SubStatusProgress)
	case info.ZSwState_DOWNLOADED:
		if swInfo.Activated {
			swInfo.UserStatus = info.BaseOsStatus_DOWNLOADING
			swInfo.SubStatus = info.BaseOsSubStatus_DOWNLOAD_INPROGRESS
			swInfo.SubStatusProgress = 100
			swInfo.SubStatusStr = "Download 100% done"
		} else {
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	case info.ZSwState_DELIVERED:
		if swInfo.Activated {
			swInfo.UserStatus = info.BaseOsStatus_DOWNLOAD_DONE
			swInfo.SubStatusStr = "Downloaded and verified"
		} else if tooEarly {
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = info.BaseOsSubStatus_UPDATE_DEFERRED
			swInfo.SubStatusStr = "Waiting for current image to finish testing before updating again"
		} else {
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	case info.ZSwState_INSTALLED:
		switch swInfo.PartitionState {
		case "active":
			if swInfo.Activated {
				swInfo.UserStatus = info.BaseOsStatus_UPDATED
			} else {
				swInfo.UserStatus = info.BaseOsStatus_FALLBACK
			}
		case "updating":
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = info.BaseOsSubStatus_UPDATE_REBOOTING
			// XXX progress based on time left??
			swInfo.SubStatusStr = "About to reboot"
		case "inprogress":
			if swInfo.Activated {
				swInfo.UserStatus = info.BaseOsStatus_UPDATING
				swInfo.SubStatus = info.BaseOsSubStatus_UPDATE_TESTING
				swInfo.SubStatusProgress = uint32(ctx.remainingTestTime / time.Second)
				swInfo.SubStatusStr = fmt.Sprintf("Testing for %d more seconds",
					swInfo.SubStatusProgress)
			} else {
				swInfo.UserStatus = info.BaseOsStatus_FAILED
			}

		case "unused":
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	default:
		// The other states are use for app instances not for baseos
		swInfo.UserStatus = info.BaseOsStatus_NONE
	}
	if swInfo.SwErr != nil && swInfo.SwErr.Description != "" {
		swInfo.UserStatus = info.BaseOsStatus_FAILED
	}
}

// encodeNetInfo encodes info from the port
func encodeNetInfo(port types.NetworkPortStatus) *info.ZInfoNetwork {

	networkInfo := new(info.ZInfoNetwork)
	networkInfo.LocalName = port.IfName
	networkInfo.IPAddrs = make([]string, len(port.AddrInfoList))
	for index, ai := range port.AddrInfoList {
		networkInfo.IPAddrs[index] = ai.Addr.String()
	}
	networkInfo.Ipv4Up = port.Up
	networkInfo.MacAddr = port.MacAddr.String()
	networkInfo.DevName = port.Logicallabel

	networkInfo.Alias = port.Alias
	// Default routers from kernel whether or not we are using DHCP
	networkInfo.DefaultRouters = make([]string, len(port.DefaultRouters))
	for index, dr := range port.DefaultRouters {
		networkInfo.DefaultRouters[index] = *proto.String(dr.String())
	}

	networkInfo.Uplink = port.IsMgmt
	// fill in ZInfoDNS from what is currently used
	networkInfo.Dns = new(info.ZInfoDNS)
	networkInfo.Dns.DNSdomain = port.DomainName
	for _, server := range port.DNSServers {
		networkInfo.Dns.DNSservers = append(networkInfo.Dns.DNSservers,
			server.String())
	}

	// XXX we potentially have geoloc information for each IP
	// address.
	// For now fill in using the first IP address which has location
	// info.
	for _, ai := range port.AddrInfoList {
		if ai.Geo == nilIPInfo {
			continue
		}
		geo := new(info.GeoLoc)
		geo.UnderlayIP = ai.Geo.IP
		geo.Hostname = ai.Geo.Hostname
		geo.City = ai.Geo.City
		geo.Country = ai.Geo.Country
		geo.Loc = ai.Geo.Loc
		geo.Org = ai.Geo.Org
		geo.Postal = ai.Geo.Postal
		networkInfo.Location = geo
		break
	}
	// Any error or test result?
	networkInfo.NetworkErr = encodeTestResults(port.TestResults)

	networkInfo.Proxy = encodeProxyStatus(&port.ProxyConfig)
	networkInfo.NtpServers = []string{}
	if !port.IgnoreDhcpNtpServers {
		for _, server := range port.DhcpNtpServers {
			networkInfo.NtpServers = append(networkInfo.NtpServers, server.String())
		}
	}
	return networkInfo
}

func encodeCellModuleInfo(wwanModule types.WwanCellModule) *info.ZCellularModuleInfo {
	var opState info.ZCellularOperatingState
	switch wwanModule.OpMode {
	case types.WwanOpModeUnspecified:
		opState = info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_UNSPECIFIED
	case types.WwanOpModeOnline:
		opState = info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_ONLINE
	case types.WwanOpModeConnected:
		opState = info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_ONLINE_AND_CONNECTED
	case types.WwanOpModeRadioOff:
		opState = info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_RADIO_OFF
	case types.WwanOpModeOffline:
		opState = info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_OFFLINE
	case types.WwanOpModeUnrecognized:
		opState = info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_UNRECOGNIZED
	default:
		log.Errorf("Invalid wwan module operating state: %v", wwanModule.OpMode)
	}

	var ctrlProto info.ZCellularControlProtocol
	switch wwanModule.ControlProtocol {
	case types.WwanCtrlProtUnspecified:
		ctrlProto = info.ZCellularControlProtocol_Z_CELLULAR_CONTROL_PROTOCOL_UNSPECIFIED
	case types.WwanCtrlProtQMI:
		ctrlProto = info.ZCellularControlProtocol_Z_CELLULAR_CONTROL_PROTOCOL_QMI
	case types.WwanCtrlProtMBIM:
		ctrlProto = info.ZCellularControlProtocol_Z_CELLULAR_CONTROL_PROTOCOL_MBIM
	default:
		log.Errorf("Invalid wwan module control protocol: %v", wwanModule.ControlProtocol)
	}
	return &info.ZCellularModuleInfo{
		Name:            wwanModule.Name,
		Imei:            wwanModule.IMEI,
		FirmwareVersion: wwanModule.Revision,
		Model:           wwanModule.Model,
		Manufacturer:    wwanModule.Manufacturer,
		OperatingState:  opState,
		ControlProtocol: ctrlProto,
	}
}

func encodeSimCards(cellModule string, wwanSimCards []types.WwanSimCard) (simCards []*info.ZSimcardInfo) {
	for _, simCard := range wwanSimCards {
		simCards = append(simCards, &info.ZSimcardInfo{
			Name:           simCard.Name,
			CellModuleName: cellModule,
			Imsi:           simCard.IMSI,
			Iccid:          simCard.ICCID,
			Type:           info.SimType(simCard.Type),
			State:          simCard.State,
			SlotNumber:     uint32(simCard.SlotNumber),
			SlotActivated:  simCard.SlotActivated,
		})
	}
	return simCards
}

func encodeCellProvider(wwanProvider types.WwanProvider) (provider *info.ZCellularProvider) {
	return &info.ZCellularProvider{
		Plmn:           wwanProvider.PLMN,
		Description:    wwanProvider.Description,
		CurrentServing: wwanProvider.CurrentServing,
		Roaming:        wwanProvider.Roaming,
		Forbidden:      wwanProvider.Forbidden,
	}
}

func encodeCellProviders(wwanStatus types.WwanNetworkStatus) (providers []*info.ZCellularProvider) {
	var includedCurrentProvider bool
	for _, provider := range wwanStatus.VisibleProviders {
		if provider == wwanStatus.CurrentProvider {
			includedCurrentProvider = true
		}
		providers = append(providers, encodeCellProvider(provider))
	}
	if !includedCurrentProvider && wwanStatus.CurrentProvider.PLMN != "" {
		providers = append(providers, encodeCellProvider(wwanStatus.CurrentProvider))
	}
	return providers
}

func encodeCellIPType(ipType types.WwanIPType) evecommon.CellularIPType {
	switch ipType {
	case types.WwanIPTypeUnspecified:
		return evecommon.CellularIPType_CELLULAR_IP_TYPE_UNSPECIFIED
	case types.WwanIPTypeIPv4:
		return evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV4
	case types.WwanIPTypeIPv4AndIPv6:
		return evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV4_AND_IPV6
	case types.WwanIPTypeIPv6:
		return evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV6
	default:
		log.Errorf("Invalid wwan IP type: %v", ipType)
	}
	return evecommon.CellularIPType_CELLULAR_IP_TYPE_UNSPECIFIED
}

func encodeCellBearerType(bearerType types.BearerType) evecommon.BearerType {
	switch bearerType {
	case types.BearerTypeUnspecified:
		return evecommon.BearerType_BEARER_TYPE_UNSPECIFIED
	case types.BearerTypeAttach:
		return evecommon.BearerType_BEARER_TYPE_ATTACH
	case types.BearerTypeDefault:
		return evecommon.BearerType_BEARER_TYPE_DEFAULT
	case types.BearerTypeDedicated:
		return evecommon.BearerType_BEARER_TYPE_DEDICATED
	default:
		log.Errorf("Invalid wwan bearer type: %v", bearerType)
	}
	return evecommon.BearerType_BEARER_TYPE_UNSPECIFIED
}

func encodeCellBearers(wwanStatus types.WwanNetworkStatus) (bearers []*info.CellularBearer) {
	for _, bearer := range wwanStatus.Bearers {
		var connectedAt *timestamppb.Timestamp
		if bearer.ConnectedAt != 0 {
			connectedAt = timestamppb.New(time.Unix(int64(bearer.ConnectedAt), 0))
		}
		bearers = append(bearers, &info.CellularBearer{
			Apn:             bearer.APN,
			BearerType:      encodeCellBearerType(bearer.Type),
			IpType:          encodeCellIPType(bearer.IPType),
			Connected:       bearer.Connected,
			ConnectionError: bearer.ConnectionError,
			ConnectedAt:     connectedAt,
		})
	}
	return bearers
}

func encodeCellProfiles(wwanStatus types.WwanNetworkStatus) (profiles []*info.CellularProfile) {
	for _, profile := range wwanStatus.Profiles {
		profiles = append(profiles, &info.CellularProfile{
			ProfileName:   profile.Name,
			Apn:           profile.APN,
			BearerType:    encodeCellBearerType(profile.BearerType),
			IpType:        encodeCellIPType(profile.IPType),
			ForbidRoaming: profile.ForbidRoaming,
		})
	}
	return profiles
}

func encodeSystemAdapterInfo(ctx *zedagentContext) *info.SystemAdapterInfo {
	dpcl := *ctx.DevicePortConfigList
	sainfo := new(info.SystemAdapterInfo)
	sainfo.CurrentIndex = uint32(dpcl.CurrentIndex)
	sainfo.Status = make([]*info.DevicePortStatus, len(dpcl.PortConfigList))
	for i, dpc := range dpcl.PortConfigList {
		dps := new(info.DevicePortStatus)
		dps.Version = uint32(dpc.Version)
		dps.Key = dpc.Key
		dps.TimePriority = timestamppb.New(dpc.TimePriority)
		if !dpc.LastFailed.IsZero() {
			dps.LastFailed = timestamppb.New(dpc.LastFailed)
		}
		if !dpc.LastSucceeded.IsZero() {
			dps.LastSucceeded = timestamppb.New(dpc.LastSucceeded)
		}
		dps.LastError = dpc.LastError

		dps.Ports = make([]*info.DevicePort, len(dpc.Ports))
		for j, p := range dpc.Ports {
			if i == dpcl.CurrentIndex {
				// For the currently used DPC we publish the status (DeviceNetworkStatus).
				portStatus := deviceNetworkStatus.LookupPortByLogicallabel(p.Logicallabel)
				if portStatus != nil {
					dps.Ports[j] = encodeNetworkPortStatus(ctx, portStatus, p.NetworkUUID)
					continue
				}
			}
			// For inactive DPCs (or if DNS is not available) we publish the config
			// (DevicePortConfig).
			dps.Ports[j] = encodeNetworkPortConfig(ctx, &p)
		}
		sainfo.Status[i] = dps
	}
	log.Tracef("encodeSystemAdapterInfo: %+v", sainfo)
	return sainfo
}

func encodeNetworkPortStatus(ctx *zedagentContext,
	port *types.NetworkPortStatus, network uuid.UUID) *info.DevicePort {
	aa := ctx.assignableAdapters
	ioBundle := aa.LookupIoBundleLogicallabel(port.Logicallabel)

	devicePort := new(info.DevicePort)
	devicePort.Ifname = port.IfName
	devicePort.Name = port.Logicallabel
	devicePort.Err = encodeTestResults(port.TestResults)
	if ioBundle != nil {
		devicePort.Usage = ioBundle.Usage
	}
	devicePort.Cost = uint32(port.Cost)
	devicePort.IsMgmt = port.IsMgmt
	devicePort.Free = port.Cost == 0 // To be deprecated
	devicePort.NetworkUUID = network.String()
	devicePort.DhcpType = uint32(port.Dhcp)
	devicePort.Subnet = port.Subnet.String()
	devicePort.Up = port.Up
	devicePort.Mtu = uint32(port.MTU)
	devicePort.Domainname = port.DomainName
	ntpServers := make([]string, 0)
	if port.ConfiguredNtpServers != nil {
		ntpServers = append(ntpServers, port.ConfiguredNtpServers...)
	}
	if len(port.DhcpNtpServers) > 0 && !port.IgnoreDhcpNtpServers {
		ntpServers = append(ntpServers, port.DhcpNtpServers[0].String())
		if len(port.DhcpNtpServers) > 1 {
			for _, ntpServer := range port.DhcpNtpServers[1:] {
				ntpServers = append(ntpServers, ntpServer.String())
			}
		}
	}
	if len(ntpServers) > 0 {
		devicePort.NtpServer = ntpServers[0]
	}
	if len(ntpServers) > 1 {
		devicePort.MoreNtpServers = ntpServers[1:]
	}

	devicePort.Proxy = encodeProxyStatus(&port.ProxyConfig)
	devicePort.MacAddr = port.MacAddr.String()
	for _, ipAddr := range port.AddrInfoList {
		devicePort.IPAddrs = append(devicePort.IPAddrs, ipAddr.Addr.String())
	}
	// devicePort.Gateway is deprecated - replaced by DefaultRouters
	for _, router := range port.DefaultRouters {
		devicePort.DefaultRouters = append(devicePort.DefaultRouters, router.String())
	}
	// devicePort.DNSServers is deprecated - replaced by Dns
	devicePort.Dns = new(info.ZInfoDNS)
	devicePort.Dns.DNSdomain = port.DomainName
	for _, dnsServer := range port.DNSServers {
		devicePort.Dns.DNSservers = append(devicePort.Dns.DNSservers, dnsServer.String())
	}
	// TODO We may have geoloc information for each IP address.
	// For now fill in using the first IP address which has location info available.
	for _, ai := range port.AddrInfoList {
		if ai.Geo == nilIPInfo {
			continue
		}
		geo := new(info.GeoLoc)
		geo.UnderlayIP = ai.Geo.IP
		geo.Hostname = ai.Geo.Hostname
		geo.City = ai.Geo.City
		geo.Country = ai.Geo.Country
		geo.Loc = ai.Geo.Loc
		geo.Org = ai.Geo.Org
		geo.Postal = ai.Geo.Postal
		devicePort.Location = geo
		break
	}
	switch port.WirelessStatus.WType {
	case types.WirelessTypeCellular:
		wwanStatus := port.WirelessStatus.Cellular
		var simCards []string
		for _, simCard := range wwanStatus.SimCards {
			simCards = append(simCards, simCard.Name)
		}
		var rats []evecommon.RadioAccessTechnology
		for _, rat := range wwanStatus.CurrentRATs {
			switch rat {
			case types.WwanRATGSM:
				rats = append(rats, evecommon.RadioAccessTechnology_RADIO_ACCESS_TECHNOLOGY_GSM)
			case types.WwanRATUMTS:
				rats = append(rats, evecommon.RadioAccessTechnology_RADIO_ACCESS_TECHNOLOGY_UMTS)
			case types.WwanRATLTE:
				rats = append(rats, evecommon.RadioAccessTechnology_RADIO_ACCESS_TECHNOLOGY_LTE)
			case types.WwanRAT5GNR:
				rats = append(rats, evecommon.RadioAccessTechnology_RADIO_ACCESS_TECHNOLOGY_5GNR)
			}
		}
		var connectedAt *timestamppb.Timestamp
		if wwanStatus.ConnectedAt != 0 {
			connectedAt = timestamppb.New(time.Unix(int64(wwanStatus.ConnectedAt), 0))
		}
		devicePort.WirelessStatus = &info.WirelessStatus{
			Type: info.WirelessType_WIRELESS_TYPE_CELLULAR,
			Cellular: &info.ZCellularStatus{
				CellularModule: wwanStatus.Module.Name,
				SimCards:       simCards,
				Providers:      encodeCellProviders(wwanStatus),
				CurrentRats:    rats,
				ConnectedAt:    connectedAt,
				ConfigError:    wwanStatus.ConfigError,
				ProbeError:     wwanStatus.ProbeError,
				Bearers:        encodeCellBearers(wwanStatus),
				Profiles:       encodeCellProfiles(wwanStatus),
			},
		}
	case types.WirelessTypeWifi:
		devicePort.WirelessStatus = &info.WirelessStatus{
			Type: info.WirelessType_WIRELESS_TYPE_WIFI,
		}
	}
	return devicePort
}

func encodeNetworkPortConfig(ctx *zedagentContext,
	npc *types.NetworkPortConfig) *info.DevicePort {
	aa := ctx.assignableAdapters

	dp := new(info.DevicePort)
	dp.Ifname = npc.IfName
	// XXX rename the protobuf field Name to Logicallabel and add Phylabel?
	dp.Name = npc.Logicallabel
	// XXX Add Alias to DevicePort?
	// dp.Alias = npc.Alias

	ibPtr := aa.LookupIoBundleLogicallabel(npc.Logicallabel)
	if ibPtr != nil {
		dp.Usage = ibPtr.Usage
	}

	dp.IsMgmt = npc.IsMgmt
	dp.Cost = uint32(npc.Cost)
	dp.Free = npc.Cost == 0 // To be deprecated
	// DhcpConfig
	dp.DhcpType = uint32(npc.Dhcp)
	dp.Subnet = npc.AddrSubnet

	dp.DefaultRouters = make([]string, 0)
	dp.DefaultRouters = append(dp.DefaultRouters, npc.Gateway.String())

	if npc.NTPServers != nil && len(npc.NTPServers) > 0 {
		dp.NtpServer = npc.NTPServers[0]

		if len(npc.NTPServers) > 1 {
			dp.MoreNtpServers = append(dp.MoreNtpServers, npc.NTPServers[1:]...)
		}
	}

	dp.Dns = new(info.ZInfoDNS)
	dp.Dns.DNSdomain = npc.DomainName
	dp.Dns.DNSservers = make([]string, 0)
	for _, d := range npc.DNSServers {
		dp.Dns.DNSservers = append(dp.Dns.DNSservers, d.String())
	}
	// XXX Not in definition. Remove?
	// XXX  string dhcpRangeLow = 17;
	// XXX  string dhcpRangeHigh = 18;

	dp.Proxy = encodeProxyStatus(&npc.ProxyConfig)

	dp.Err = encodeTestResults(npc.TestResults)

	var nilUUID uuid.UUID
	if npc.NetworkUUID != nilUUID {
		dp.NetworkUUID = npc.NetworkUUID.String()
	}
	return dp
}

// getDataSecAtRestInfo prepares status related to Data security at Rest
func getDataSecAtRestInfo(ctx *zedagentContext) *info.DataSecAtRest {
	subVaultStatus := ctx.subVaultStatus
	ReportDataSecAtRestInfo := new(info.DataSecAtRest)
	ReportDataSecAtRestInfo.VaultList = make([]*info.VaultInfo, 0)
	vaultList := subVaultStatus.GetAll()
	for _, vaultItem := range vaultList {
		v := vaultItem.(types.VaultStatus)
		vaultInfo := new(info.VaultInfo)
		vaultInfo.Name = v.Name
		vaultInfo.Status = v.Status
		vaultInfo.PcrStatus = v.PCRStatus
		if !v.ErrorTime.IsZero() {
			vaultInfo.VaultErr = encodeErrorInfo(v.ErrorAndTime.ErrorDescription)
		}
		ReportDataSecAtRestInfo.VaultList = append(ReportDataSecAtRestInfo.VaultList, vaultInfo)
	}
	return ReportDataSecAtRestInfo
}

func createConfigItemStatus(
	status types.GlobalStatus) *info.ZInfoConfigItemStatus {

	cfgItemsPtr := new(info.ZInfoConfigItemStatus)

	// Copy ConfigItems
	cfgItemsPtr.ConfigItems = make(map[string]*info.ZInfoConfigItem)
	for key, statusCfgItem := range status.ConfigItems {
		if statusCfgItem.Err != nil {
			cfgItemsPtr.ConfigItems[key] = &info.ZInfoConfigItem{
				Value: statusCfgItem.Value,
				Error: statusCfgItem.Err.Error()}
		} else {
			cfgItemsPtr.ConfigItems[key] = &info.ZInfoConfigItem{
				Value: statusCfgItem.Value}
		}
	}

	// Copy Unknown Config Items
	cfgItemsPtr.UnknownConfigItems = make(map[string]*info.ZInfoConfigItem)
	for key, statusUnknownCfgItem := range status.UnknownConfigItems {
		cfgItemsPtr.UnknownConfigItems[key] = &info.ZInfoConfigItem{
			Value: statusUnknownCfgItem.Value,
			Error: statusUnknownCfgItem.Err.Error()}
	}
	return cfgItemsPtr
}

func createAppInstances(ctxPtr *zedagentContext,
	zinfoDevice *info.ZInfoDevice) {

	addAppInstanceFunc := func(key string, value interface{}) bool {
		ais := value.(types.AppInstanceStatus)
		zinfoAppInst := new(info.ZInfoAppInstance)
		zinfoAppInst.Uuid = ais.UUIDandVersion.UUID.String()
		zinfoAppInst.Name = ais.DisplayName
		zinfoAppInst.DomainName = ais.DomainName
		zinfoDevice.AppInstances = append(zinfoDevice.AppInstances,
			zinfoAppInst)
		return true
	}
	ctxPtr.getconfigCtx.subAppInstanceStatus.Iterate(
		addAppInstanceFunc)
}

func parseSMARTData() {
	filename := "/persist/SMART_details.json"
	data, err := fileutils.ReadWithMaxSize(log, filename,
		maxSmartCtlSize)
	if err != nil {
		log.Errorf("parseSMARTData: exception while opening %s. %s", filename, err.Error())
		return
	}

	if err := json.Unmarshal(data, &smartData); err != nil {
		log.Errorf("parseSMARTData: exception while parsing SMART data. %s", err.Error())
		return
	}
}

func getCapabilities(ctx *zedagentContext) *info.Capabilities {
	m, err := ctx.subCapabilities.Get("global")
	if err != nil {
		log.Warnf("ctx.subCapabilities.Get failed: %s", err)
		return nil
	}
	capabilities := m.(types.Capabilities)
	return &info.Capabilities{
		HWAssistedVirtualization: capabilities.HWAssistedVirtualization,
		IOVirtualization:         capabilities.IOVirtualization,
	}
}

func getOptionalCapabilities(ctx *zedagentContext) *info.OptionalCapabilities {
	return &info.OptionalCapabilities{
		HvTypeKubevirt: ctx.hvTypeKube,
	}
}

func getBaseosUpdateCounter(ctx *zedagentContext) uint32 {
	m, err := ctx.subBaseOsMgrStatus.Get("global")
	if err != nil {
		log.Warnf("ctx.subBaseOsMgrStatus.Get failed: %s", err)
		return 0
	}
	status := m.(types.BaseOSMgrStatus)
	return status.CurrentRetryUpdateCounter
}

func getDeviceState(ctx *zedagentContext) types.DeviceState {
	if ctx.maintenanceMode {
		return types.DEVICE_STATE_MAINTENANCE_MODE
	}
	if isUpdating(ctx) || isKubeClusterUpdating(ctx) {
		return types.DEVICE_STATE_BASEOS_UPDATING
	}
	if ctx.rebootCmd || ctx.deviceReboot {
		return types.DEVICE_STATE_REBOOTING
	}
	if ctx.shutdownCmd || ctx.deviceShutdown {
		if ctx.allDomainsHalted {
			return types.DEVICE_STATE_PREPARED_POWEROFF
		}
		return types.DEVICE_STATE_PREPARING_POWEROFF
	}
	if ctx.poweroffCmd || ctx.devicePoweroff {
		return types.DEVICE_STATE_POWERING_OFF
	}
	if ctx.getconfigCtx != nil && (ctx.getconfigCtx.configReceived ||
		ctx.getconfigCtx.readSavedConfig) {
		return types.DEVICE_STATE_ONLINE
	}
	return types.DEVICE_STATE_BOOTING
}

func lookupZbootStatus(ctx *zedagentContext, key string) *types.ZbootStatus {
	sub := ctx.subZbootStatus
	if sub == nil {
		return nil
	}
	st, _ := sub.Get(key)
	if st == nil {
		log.Errorf("lookupZbootStatus(%s) not found", key)
		return nil
	}
	status := st.(types.ZbootStatus)
	return &status
}

// did we start baseos image update
func isUpdating(ctx *zedagentContext) bool {
	// check if inprogress state of current partition
	if ctx.getconfigCtx != nil && ctx.getconfigCtx.updateInprogress {
		return true
	}
	// check if updating state of other partition
	partName := getZbootOtherPartition(ctx)
	if status := lookupZbootStatus(ctx, partName); status != nil {
		if status.PartitionState == "updating" {
			return true
		}
		return false
	}
	return false
}

// Function decides if the next call to SendOnAllIntf for /info request should be traced
// and netdump published at the end (see libs/nettrace and pkg/pillar/netdump).
func traceNextInfoReq(ctx *zedagentContext) bool {
	return traceNextReq(ctx, ctx.lastInfoNetdumpPub)
}

// Publish netdump containing traces of executed /info requests.
func publishInfoNetdump(ctx *zedagentContext,
	result types.SenderStatus, tracedInfoReqs []netdump.TracedNetRequest) {
	netDumper := ctx.netDumper
	if netDumper == nil {
		return
	}
	var topic string
	switch result {
	case types.SenderStatusNone:
		topic = netDumpInfoOKTopic
	case types.SenderStatusDebug:
		// There was no actual /info request so there is nothing interesting to publish.
		return
	default:
		topic = netDumpInfoFailTopic
	}
	filename, err := netDumper.Publish(topic, tracedInfoReqs...)
	if err != nil {
		log.Warnf("Failed to publish netdump for topic %s: %v", topic, err)
	} else {
		log.Noticef("Published netdump for topic %s: %s", topic, filename)
	}
	ctx.lastInfoNetdumpPub = time.Now()
}
