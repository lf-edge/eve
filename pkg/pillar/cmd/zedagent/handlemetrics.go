// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Push info and metrics to zedcloud

package zedagent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/eriknordmark/ipinfo"
	"github.com/eriknordmark/netlink"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/api/go/metrics"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cast"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netclone"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	psutilnet "github.com/shirou/gopsutil/net"
	log "github.com/sirupsen/logrus"
)

// Also report usage for these paths
const persistPath = "/persist"

var reportPaths = []string{"/", "/config", persistPath}

// Application-related files live here; includes downloads and verifications in progress
var appPersistPaths = []string{"/persist/img", "/persist/downloads/appImg.obj"}

func publishMetrics(ctx *zedagentContext, iteration int) {
	cpuMemoryStat := ExecuteXentopCmd()
	if cpuMemoryStat == nil {
		return
	}
	PublishMetricsToZedCloud(ctx, cpuMemoryStat, iteration)
}

// Run a periodic post of the metrics

func metricsTimerTask(ctx *zedagentContext, handleChannel chan interface{}) {
	iteration := 0
	log.Infoln("starting report metrics timer task")
	publishMetrics(ctx, iteration)

	interval := time.Duration(globalConfig.MetricInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)

	for {
		select {
		case <-ticker.C:
			iteration += 1
			publishMetrics(ctx, iteration)
		case <-stillRunning.C:
			agentlog.StillRunning(agentName + "metrics")
		}
	}
}

// Called when globalConfig changes
// Assumes the caller has verifier that the interval has changed
func updateMetricsTimer(tickerHandle interface{}) {
	interval := time.Duration(globalConfig.MetricInterval) * time.Second
	log.Infof("updateMetricsTimer() change to %v\n", interval)
	max := float64(interval)
	min := max * 0.3
	flextimer.UpdateRangeTicker(tickerHandle,
		time.Duration(min), time.Duration(max))
	// Force an immediate timout since timer could have decreased
	flextimer.TickNow(tickerHandle)
}

func ExecuteXlInfoCmd() map[string]string {
	xlCmd := exec.Command("xl", "info")
	stdout, err := xlCmd.Output()
	if err != nil {
		log.Errorf("xl info failed %s\n", err)
		return nil
	}
	xlInfo := string(stdout)
	splitXlInfo := strings.Split(xlInfo, "\n")

	dict := make(map[string]string, len(splitXlInfo)-1)
	for _, str := range splitXlInfo {
		res := strings.SplitN(str, ":", 2)
		if len(res) == 2 {
			dict[strings.TrimSpace(res[0])] = strings.TrimSpace(res[1])
		}
	}
	return dict
}

// Shadow copy of suscription to determine info for deletes. Key is UUID
var domainStatus map[string]types.DomainStatus

// Key is DomainName; value is array of interface names
var appInterfaceAndNameList map[string][]string

// Key is DomainName; value is array of disk images
var appDiskAndNameList map[string][]string

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Debugf("handleDomainStatusModify for %s\n", key)
	status := cast.CastDomainStatus(statusArg)
	ctx := ctxArg.(*zedagentContext)
	if status.Key() != key {
		log.Errorf("handleDomainStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	// Update Progress counter even if Pending

	if domainStatus == nil {
		log.Debugf("create Domain map\n")
		domainStatus = make(map[string]types.DomainStatus)
	}
	// Detect if any changes relevant to the device status report
	old := lookupDomainStatus(ctx, key)
	if old != nil {
		log.Infof("handleDomainStatusModify change for %s domainname %s\n",
			key, status.DomainName)
		if ioAdapterListChanged(*old, status) {
			ctx.TriggerDeviceInfo = true
		}
	} else {
		log.Infof("handleDomainStatusModify add for %s domainname %s\n",
			key, status.DomainName)
		if ioAdapterListChanged(types.DomainStatus{}, status) {
			ctx.TriggerDeviceInfo = true
		}
	}
	domainStatus[key] = status
	if appInterfaceAndNameList == nil {
		appInterfaceAndNameList = make(map[string][]string)
	}
	if appDiskAndNameList == nil {
		appDiskAndNameList = make(map[string][]string)
	}
	var interfaceList []string
	for _, vif := range status.VifList {
		interfaceList = append(interfaceList, vif.Vif)
	}
	appInterfaceAndNameList[status.DomainName] = interfaceList
	var diskList []string
	for _, ds := range status.DiskStatusList {
		diskList = append(diskList, ds.ActiveFileLocation)
	}
	appDiskAndNameList[status.DomainName] = diskList
	log.Debugf("handleDomainStatusModify appIntf %s %v\n",
		status.DomainName, interfaceList)
	log.Debugf("handleDomainStatusModify done for %s\n", key)
}

func handleDomainStatusDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*zedagentContext)
	log.Infof("handleDomainStatusDelete for %s\n", key)
	status := cast.CastDomainStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleDomainStatusDelete key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}

	// Detect if any changes relevant to the device status report
	if ioAdapterListChanged(status, types.DomainStatus{}) {
		ctx.TriggerDeviceInfo = true
	}

	if _, ok := appInterfaceAndNameList[status.DomainName]; ok {
		log.Infof("appInterfaceAndnameList for %v\n",
			status.DomainName)
		delete(appInterfaceAndNameList, status.DomainName)
	}

	// XXX remove domainStatus once we can count it below? But
	// assigning away devices to /dev/null aka pciback means not visible
	// at boot.
	delete(domainStatus, key)
	log.Infof("handleDomainStatusDelete done for %s\n", key)
}

// Note that this function returns the entry even if Pending* is set.
func lookupDomainStatus(ctx *zedagentContext, key string) *types.DomainStatus {
	sub := ctx.subDomainStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Infof("lookupDomainStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDomainStatus(st)
	if status.Key() != key {
		log.Errorf("lookupDomainStatus key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func ioAdapterListChanged(old types.DomainStatus, new types.DomainStatus) bool {
	log.Infof("ioAdapterListChanged(%v, %v)\n",
		old.IoAdapterList, new.IoAdapterList)
	if len(old.IoAdapterList) != len(new.IoAdapterList) {
		log.Infof("ioAdapterListChanged length from %d to %d\n",
			len(old.IoAdapterList), len(new.IoAdapterList))
		return true
	}
	adapterSet := make(map[types.IoAdapter]bool)
	for _, ad := range old.IoAdapterList {
		adapterSet[ad] = true
	}
	for _, ad := range new.IoAdapterList {
		if _, ok := adapterSet[ad]; !ok {
			log.Infof("ioAdapterListChanged %v not in old set\n",
				ad)
			return true
		}
	}
	log.Infof("ioAdapterListChanged: no change\n")
	return false
}

func ReadAppInterfaceList(domainName string) []string {
	return appInterfaceAndNameList[domainName]
}

func ReadAppDiskList(domainName string) []string {
	return appDiskAndNameList[domainName]
}

func LookupDomainStatus(domainName string) *types.DomainStatus {
	for _, ds := range domainStatus {
		if strings.Compare(ds.DomainName, domainName) == 0 {
			return &ds
		}
	}
	return nil
}

func LookupDomainStatusUUID(uuid string) *types.DomainStatus {
	for _, ds := range domainStatus {
		if strings.Compare(ds.Key(), uuid) == 0 {
			return &ds
		}
	}
	return nil
}

// XXX can we use libxenstat? /usr/local/lib/libxenstat.so on hikey
// /usr/lib/libxenstat.so in container
func ExecuteXentopCmd() [][]string {
	var cpuMemoryStat [][]string

	count := 0
	counter := 0
	arg1 := "xentop"
	arg2 := "-b"
	arg3 := "-d"
	arg4 := "1"
	arg5 := "-i"
	arg6 := "2"
	arg7 := "-f"

	stdout, ok, err := execWithTimeout(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
	if err != nil {
		log.Errorf("xentop failed: %s", err)
		return [][]string{}
	}
	if !ok {
		log.Warnf("xentop timed out")
		return nil
	}

	xentopInfo := string(stdout)

	splitXentopInfo := strings.Split(xentopInfo, "\n")

	splitXentopInfoLength := len(splitXentopInfo)
	var i int
	var start int

	for i = 0; i < splitXentopInfoLength; i++ {

		str := splitXentopInfo[i]
		re := regexp.MustCompile(" ")

		spaceRemovedsplitXentopInfo := re.ReplaceAllLiteralString(str, "")
		matched, err := regexp.MatchString("NAMESTATECPU.*", spaceRemovedsplitXentopInfo)

		if err != nil {
			log.Debugf("MatchString failed: %s", err)
		} else if matched {

			count++
			log.Debugf("string matched: %s", str)
			if count == 2 {
				start = i + 1
				log.Debugf("value of i: %d", start)
			}
		}
	}

	length := splitXentopInfoLength - 1 - start
	finalOutput := make([][]string, length)

	for j := start; j < splitXentopInfoLength-1; j++ {

		finalOutput[j-start] = strings.Fields(strings.TrimSpace(splitXentopInfo[j]))
	}

	cpuMemoryStat = make([][]string, length)

	for i := range cpuMemoryStat {
		cpuMemoryStat[i] = make([]string, 20)
	}

	// Need to treat "no limit" as one token
	for f := 0; f < length; f++ {

		// First name and state
		out := 0
		counter++
		cpuMemoryStat[f][counter] = finalOutput[f][out]
		out++
		counter++
		cpuMemoryStat[f][counter] = finalOutput[f][out]
		out++
		for ; out < len(finalOutput[f]); out++ {

			if finalOutput[f][out] == "no" {

			} else if finalOutput[f][out] == "limit" {
				counter++
				cpuMemoryStat[f][counter] = "no limit"
			} else {
				counter++
				cpuMemoryStat[f][counter] = finalOutput[f][out]
			}
		}
		counter = 0
	}
	log.Debugf("ExecuteXentopCmd return %+v", cpuMemoryStat)
	return cpuMemoryStat
}

func execWithTimeout(command string, args ...string) ([]byte, bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, false, nil
	}
	return out, true, err
}

// Returns cpuTotal, usedMemory, availableMemory, usedPercentage
func lookupCpuMemoryStat(cpuMemoryStat [][]string, domainname string) (uint64, uint32, uint32, float64) {

	for _, stat := range cpuMemoryStat {
		if len(stat) <= 2 {
			continue
		}
		dn := strings.TrimSpace(stat[1])
		if dn == domainname {
			if len(stat) <= 6 {
				return 0, 0, 0, 0.0
			}
			log.Debugf("lookupCpuMemoryStat for %s %d elem: %+v",
				domainname, len(stat), stat)
			cpuTotal, err := strconv.ParseUint(stat[3], 10, 0)
			if err != nil {
				log.Errorf("ParseUint(%s) failed: %s",
					stat[3], err)
				cpuTotal = 0
			}
			// This is in kbytes
			totalMemory, err := strconv.ParseUint(stat[5], 10, 0)
			if err != nil {
				log.Errorf("ParseUint(%s) failed: %s",
					stat[5], err)
				totalMemory = 0
			}
			totalMemory = RoundFromKbytesToMbytes(totalMemory)
			usedMemoryPercent, err := strconv.ParseFloat(stat[6], 10)
			if err != nil {
				log.Errorf("ParseFloat(%s) failed: %s",
					stat[6], err)
				usedMemoryPercent = 0
			}
			usedMemory := (float64(totalMemory) * (usedMemoryPercent)) / 100
			availableMemory := float64(totalMemory) - usedMemory

			return cpuTotal, uint32(usedMemory), uint32(availableMemory),
				float64(usedMemoryPercent)
		}
	}
	return 0, 0, 0, 0.0
}

func PublishMetricsToZedCloud(ctx *zedagentContext, cpuMemoryStat [][]string,
	iteration int) {

	var ReportMetrics = &metrics.ZMetricMsg{}

	ReportDeviceMetric := new(metrics.DeviceMetric)
	ReportDeviceMetric.Memory = new(metrics.MemoryMetric)
	ReportDeviceMetric.CpuMetric = new(metrics.AppCpuMetric)

	ReportMetrics.DevID = *proto.String(zcdevUUID.String())
	ReportZmetric := new(metrics.ZmetricTypes)
	*ReportZmetric = metrics.ZmetricTypes_ZmDevice

	ReportMetrics.AtTimeStamp = ptypes.TimestampNow()

	info, err := host.Info()
	if err != nil {
		log.Fatalf("host.Info(): %s\n", err)
	}
	log.Debugf("uptime %d = %d days\n",
		info.Uptime, info.Uptime/(3600*24))
	log.Debugf("Booted at %v\n", time.Unix(int64(info.BootTime), 0).UTC())

	// Note that uptime is seconds we've been up. We're converting
	// to a timestamp. That better not be interpreted as a time since
	// the epoch
	uptime, _ := ptypes.TimestampProto(
		time.Unix(int64(info.Uptime), 0).UTC())
	ReportDeviceMetric.CpuMetric.UpTime = uptime

	// Memory related info for the device
	dict := ExecuteXlInfoCmd()
	var totalMemory, freeMemory uint64
	if dict != nil {
		var err error
		totalMemory, err = strconv.ParseUint(dict["total_memory"], 10, 64)
		if err != nil {
			log.Errorf("Failed parsing total_memory: %s", err)
			totalMemory = 0
		}
		freeMemory, err = strconv.ParseUint(dict["free_memory"], 10, 64)
		if err != nil {
			log.Errorf("Failed parsing free_memory: %s", err)
			freeMemory = 0
		}
	}
	// total_memory and free_memory is in MBytes
	used := totalMemory - freeMemory
	ReportDeviceMetric.Memory.UsedMem = uint32(used)
	ReportDeviceMetric.Memory.AvailMem = uint32(freeMemory)
	var usedPercent float64
	if totalMemory != 0 {
		usedPercent = float64(100) * float64(used) / float64(totalMemory)
	}
	ReportDeviceMetric.Memory.UsedPercentage = usedPercent
	ReportDeviceMetric.Memory.AvailPercentage = (100.0 - (usedPercent))
	log.Debugf("Device Memory from xl info: %v %v %v %v",
		ReportDeviceMetric.Memory.UsedMem,
		ReportDeviceMetric.Memory.AvailMem,
		ReportDeviceMetric.Memory.UsedPercentage,
		ReportDeviceMetric.Memory.AvailPercentage)

	// Use the network metrics from zedrouter subscription
	// Only report stats for the ports in DeviceNetworkStatus
	portNames := types.ReportPorts(*deviceNetworkStatus)
	for _, port := range portNames {
		var metric *types.NetworkMetric
		ifname := types.AdapterToIfName(deviceNetworkStatus, port)
		for _, m := range networkMetrics.MetricList {
			if ifname == m.IfName {
				metric = &m
				break
			}
		}
		if metric == nil {
			continue
		}
		networkDetails := new(metrics.NetworkMetric)
		networkDetails.LocalName = metric.IfName
		networkDetails.IName = port

		networkDetails.TxPkts = metric.TxPkts
		networkDetails.RxPkts = metric.RxPkts
		networkDetails.TxBytes = metric.TxBytes
		networkDetails.RxBytes = metric.RxBytes
		networkDetails.TxDrops = metric.TxDrops
		networkDetails.RxDrops = metric.RxDrops
		networkDetails.TxErrors = metric.TxErrors
		networkDetails.RxErrors = metric.RxErrors
		networkDetails.TxAclDrops = metric.TxAclDrops
		networkDetails.RxAclDrops = metric.RxAclDrops
		networkDetails.TxAclRateLimitDrops = metric.TxAclRateLimitDrops
		networkDetails.RxAclRateLimitDrops = metric.RxAclRateLimitDrops
		ReportDeviceMetric.Network = append(ReportDeviceMetric.Network,
			networkDetails)
	}
	log.Debugln("network metrics: ", ReportDeviceMetric.Network)

	// Collect zedcloud metrics from ourselves and other agents
	cms := zedcloud.GetCloudMetrics()
	// Have to make a copy
	cms = zedcloud.CastCloudMetrics(cms)
	cms1 := zedcloud.CastCloudMetrics(clientMetrics)
	if cms1 != nil {
		cms = zedcloud.Append(cms, cms1)
	}
	cms1 = zedcloud.CastCloudMetrics(logmanagerMetrics)
	if cms1 != nil {
		cms = zedcloud.Append(cms, cms1)
	}
	cms1 = zedcloud.CastCloudMetrics(downloaderMetrics)
	if cms1 != nil {
		cms = zedcloud.Append(cms, cms1)
	}
	for ifname, cm := range cms {
		metric := metrics.ZedcloudMetric{IfName: ifname,
			Failures: cm.FailureCount,
			Success:  cm.SuccessCount,
		}
		if !cm.LastFailure.IsZero() {
			lf, _ := ptypes.TimestampProto(cm.LastFailure)
			metric.LastFailure = lf
		}
		if !cm.LastSuccess.IsZero() {
			ls, _ := ptypes.TimestampProto(cm.LastSuccess)
			metric.LastSuccess = ls
		}
		for url, um := range cm.UrlCounters {
			log.Debugf("CloudMetrics[%s] url %s %v\n",
				ifname, url, um)
			urlMet := new(metrics.UrlcloudMetric)
			urlMet.Url = url
			urlMet.TryMsgCount = um.TryMsgCount
			urlMet.TryByteCount = um.TryByteCount
			urlMet.SentMsgCount = um.SentMsgCount
			urlMet.SentByteCount = um.SentByteCount
			urlMet.RecvMsgCount = um.RecvMsgCount
			urlMet.RecvByteCount = um.RecvByteCount
			metric.UrlMetrics = append(metric.UrlMetrics, urlMet)
		}
		ReportDeviceMetric.Zedcloud = append(ReportDeviceMetric.Zedcloud,
			&metric)
	}

	disks := findDisksPartitions()
	for _, d := range disks {
		size, _ := partitionSize(d)
		log.Debugf("Disk/partition %s size %d\n", d, size)
		size = RoundToMbytes(size)
		metric := metrics.DiskMetric{Disk: d, Total: size}
		stat, err := disk.IOCounters(d)
		if err == nil {
			metric.ReadBytes = RoundToMbytes(stat[d].ReadBytes)
			metric.WriteBytes = RoundToMbytes(stat[d].WriteBytes)
			metric.ReadCount = stat[d].ReadCount
			metric.WriteCount = stat[d].WriteCount
		}
		// XXX do we have a mountpath? Combine with paths below if same?
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	for _, path := range reportPaths {
		u, err := disk.Usage(path)
		if err != nil {
			// Happens e.g., if we don't have a /persist
			log.Errorf("disk.Usage: %s\n", err)
			continue
		}
		log.Debugf("Path %s total %d used %d free %d\n",
			path, u.Total, u.Used, u.Free)
		metric := metrics.DiskMetric{MountPath: path,
			Total: RoundToMbytes(u.Total),
			Used:  RoundToMbytes(u.Used),
			Free:  RoundToMbytes(u.Free),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	// Determine how much we use in /persist and how much of it is
	// for the benefits of applications
	persistUsage := diskmetrics.SizeFromDir(persistPath)
	var persistAppUsage uint64
	for _, path := range appPersistPaths {
		persistAppUsage += diskmetrics.SizeFromDir(path)
	}
	persistOverhead := persistUsage - persistAppUsage
	// Convert to MB
	runtimeStorageOverhead := types.RoundupToKB(types.RoundupToKB(persistOverhead))
	appRunTimeStorage := types.RoundupToKB(types.RoundupToKB(persistAppUsage))
	log.Debugf("runtimeStorageOverhead %d MB, appRunTimeStorage %d MB",
		runtimeStorageOverhead, appRunTimeStorage)
	ReportDeviceMetric.RuntimeStorageOverheadMB = runtimeStorageOverhead
	ReportDeviceMetric.AppRunTimeStorageMB = appRunTimeStorage

	// Walk all verified downloads and report their size (faked
	// as disks)
	verifierStatusMap := verifierGetAll(ctx)
	for _, st := range verifierStatusMap {
		vs := cast.CastVerifyImageStatus(st)
		log.Debugf("verifierStatusMap %s size %d\n",
			vs.Safename, vs.Size)
		metric := metrics.DiskMetric{
			Disk:  vs.Safename,
			Total: RoundToMbytes(uint64(vs.Size)),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	downloaderStatusMap := downloaderGetAll(ctx)
	for _, st := range downloaderStatusMap {
		ds := cast.CastDownloaderStatus(st)
		log.Debugf("downloaderStatusMap %s size %d\n",
			ds.Safename, ds.Size)
		if _, found := verifierStatusMap[ds.Key()]; found {
			log.Debugf("Found verifierStatusMap for %s\n", ds.Key())
			continue
		}
		metric := metrics.DiskMetric{
			Disk:  ds.Safename,
			Total: RoundToMbytes(uint64(ds.Size)),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}

	// Note that these are associated with the device and not with a
	// device name like ppp0 or wwan0
	lte := readLTEMetrics()
	for _, i := range lte {
		item := new(metrics.MetricItem)
		item.Key = i.Key
		item.Type = metrics.MetricItemType(i.Type)
		setMetricAnyValue(item, i.Value)
		ReportDeviceMetric.MetricItems = append(ReportDeviceMetric.MetricItems, item)
	}

	cpuTotal, usedMemory, availableMemory, usedMemoryPercent := lookupCpuMemoryStat(cpuMemoryStat, "Domain-0")
	log.Debugf("Domain-0 CPU from xentop: %d, percent used %d\n",
		cpuTotal, (100*cpuTotal)/uint64(info.Uptime))
	ReportDeviceMetric.CpuMetric.Total = *proto.Uint64(cpuTotal)

	ReportDeviceMetric.SystemServicesMemoryMB = new(metrics.MemoryMetric)
	ReportDeviceMetric.SystemServicesMemoryMB.UsedMem = usedMemory
	ReportDeviceMetric.SystemServicesMemoryMB.AvailMem = availableMemory
	ReportDeviceMetric.SystemServicesMemoryMB.UsedPercentage = usedMemoryPercent
	ReportDeviceMetric.SystemServicesMemoryMB.AvailPercentage = (100.0 - (usedMemoryPercent))
	log.Debugf("dom-0 Memory from xentop: %v %v %v %v",
		ReportDeviceMetric.SystemServicesMemoryMB.UsedMem,
		ReportDeviceMetric.SystemServicesMemoryMB.AvailMem,
		ReportDeviceMetric.SystemServicesMemoryMB.UsedPercentage,
		ReportDeviceMetric.SystemServicesMemoryMB.AvailPercentage)

	ReportMetrics.MetricContent = new(metrics.ZMetricMsg_Dm)
	if x, ok := ReportMetrics.GetMetricContent().(*metrics.ZMetricMsg_Dm); ok {
		x.Dm = ReportDeviceMetric
	}

	// Loop over AppInstanceStatus so we report before the instance has booted
	sub := ctx.getconfigCtx.subAppInstanceStatus
	items := sub.GetAll()
	for _, st := range items {
		aiStatus := cast.CastAppInstanceStatus(st)

		ReportAppMetric := new(metrics.AppMetric)
		ReportAppMetric.Cpu = new(metrics.AppCpuMetric)
		ReportAppMetric.Memory = new(metrics.MemoryMetric)
		ReportAppMetric.AppName = aiStatus.DisplayName
		ReportAppMetric.AppID = aiStatus.Key()
		if !aiStatus.BootTime.IsZero() {
			elapsed := time.Since(aiStatus.BootTime)
			uptime, _ := ptypes.TimestampProto(
				time.Unix(0, elapsed.Nanoseconds()).UTC())
			ReportAppMetric.Cpu.UpTime = uptime
		}

		appCpuTotal, usedMemory, availableMemory, usedMemoryPercent := lookupCpuMemoryStat(cpuMemoryStat, aiStatus.DomainName)
		log.Debugf("xentop for %s CPU %d, usedMem %v, availMem %v, availMemPercent %v",
			aiStatus.DomainName, appCpuTotal, usedMemory,
			availableMemory, usedMemoryPercent)
		ReportAppMetric.Cpu.Total = *proto.Uint64(appCpuTotal)
		ReportAppMetric.Memory.UsedMem = usedMemory
		ReportAppMetric.Memory.AvailMem = availableMemory
		ReportAppMetric.Memory.UsedPercentage = usedMemoryPercent
		availableMemoryPercent := 100.0 - usedMemoryPercent
		ReportAppMetric.Memory.AvailPercentage = availableMemoryPercent

		appInterfaceList := ReadAppInterfaceList(aiStatus.DomainName)
		log.Debugf("ReportMetrics: domainName %s ifs %v\n",
			aiStatus.DomainName, appInterfaceList)
		// Use the network metrics from zedrouter subscription
		for _, ifName := range appInterfaceList {
			var metric *types.NetworkMetric
			for _, m := range networkMetrics.MetricList {
				if ifName == m.IfName {
					metric = &m
					break
				}
			}
			if metric == nil {
				continue
			}
			networkDetails := new(metrics.NetworkMetric)
			name := appIfnameToName(&aiStatus, metric.IfName)
			log.Debugf("app %s/%s localname %s name %s\n",
				aiStatus.Key(), aiStatus.DisplayName,
				metric.IfName, name)
			networkDetails.IName = name
			networkDetails.LocalName = metric.IfName
			// Counters not swapped on vif
			if strings.HasPrefix(ifName, "nbn") ||
				strings.HasPrefix(ifName, "nbu") ||
				strings.HasPrefix(ifName, "nbo") {
				networkDetails.TxPkts = metric.TxPkts
				networkDetails.RxPkts = metric.RxPkts
				networkDetails.TxBytes = metric.TxBytes
				networkDetails.RxBytes = metric.RxBytes
				networkDetails.TxDrops = metric.TxDrops
				networkDetails.RxDrops = metric.RxDrops
				networkDetails.TxErrors = metric.TxErrors
				networkDetails.RxErrors = metric.RxErrors
				networkDetails.TxAclDrops = metric.TxAclDrops
				networkDetails.RxAclDrops = metric.RxAclDrops
				networkDetails.TxAclRateLimitDrops = metric.TxAclRateLimitDrops
				networkDetails.RxAclRateLimitDrops = metric.RxAclRateLimitDrops
			} else {
				// Note that the packets received on bu* and bo* where sent
				// by the domU and vice versa, hence we swap here
				networkDetails.TxPkts = metric.RxPkts
				networkDetails.RxPkts = metric.TxPkts
				networkDetails.TxBytes = metric.RxBytes
				networkDetails.RxBytes = metric.TxBytes
				networkDetails.TxDrops = metric.RxDrops
				networkDetails.RxDrops = metric.TxDrops
				networkDetails.TxErrors = metric.RxErrors
				networkDetails.RxErrors = metric.TxErrors
				networkDetails.TxAclDrops = metric.RxAclDrops
				networkDetails.RxAclDrops = metric.TxAclDrops
				networkDetails.TxAclRateLimitDrops = metric.RxAclRateLimitDrops
				networkDetails.RxAclRateLimitDrops = metric.TxAclRateLimitDrops
			}
			ReportAppMetric.Network = append(ReportAppMetric.Network,
				networkDetails)
		}

		appDiskList := ReadAppDiskList(aiStatus.DomainName)
		// Use the network metrics from zedrouter subscription
		for _, diskfile := range appDiskList {
			appDiskDetails := new(metrics.AppDiskMetric)
			err := getDiskInfo(diskfile, appDiskDetails)
			if err != nil {
				log.Errorf("getDiskInfo(%s) failed %v\n",
					diskfile, err)
				continue
			}
			ReportAppMetric.Disk = append(ReportAppMetric.Disk,
				appDiskDetails)
		}
		ReportMetrics.Am = append(ReportMetrics.Am, ReportAppMetric)
	}

	createNetworkInstanceMetrics(ctx, ReportMetrics)

	log.Debugf("PublishMetricsToZedCloud sending %s\n", ReportMetrics)
	SendMetricsProtobuf(ReportMetrics, iteration)
}

func getDiskInfo(diskfile string, appDiskDetails *metrics.AppDiskMetric) error {
	imgInfo, err := diskmetrics.GetImgInfo(diskfile)
	if err != nil {
		return err
	}
	appDiskDetails.Disk = diskfile
	appDiskDetails.Provisioned = RoundToMbytes(imgInfo.VirtualSize)
	appDiskDetails.Used = RoundToMbytes(imgInfo.ActualSize)
	appDiskDetails.DiskType = imgInfo.Format
	appDiskDetails.Dirty = imgInfo.DirtyFlag
	return nil
}

func RoundToMbytes(byteCount uint64) uint64 {
	const mbyte = 1024 * 1024

	return (byteCount + mbyte/2) / mbyte
}

func RoundFromKbytesToMbytes(byteCount uint64) uint64 {
	const kbyte = 1024

	return (byteCount + kbyte/2) / kbyte
}

// This function is called per change, hence needs to try over all management ports
func PublishDeviceInfoToZedCloud(ctx *zedagentContext) {
	aa := ctx.assignableAdapters
	iteration := ctx.iteration
	subBaseOsStatus := ctx.subBaseOsStatus

	var ReportInfo = &info.ZInfoMsg{}

	deviceType := new(info.ZInfoTypes)
	*deviceType = info.ZInfoTypes_ZiDevice
	ReportInfo.Ztype = *deviceType
	deviceUUID := zcdevUUID.String()
	ReportInfo.DevId = *proto.String(deviceUUID)
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportDeviceInfo := new(info.ZInfoDevice)

	var machineArch string
	machineCmd := exec.Command("uname", "-m")
	stdout, err := machineCmd.Output()
	if err != nil {
		log.Errorf("uname -m failed %s\n", err)
	} else {
		machineArch = string(stdout)
		ReportDeviceInfo.MachineArch = *proto.String(strings.TrimSpace(machineArch))
	}

	cpuCmd := exec.Command("uname", "-p")
	stdout, err = cpuCmd.Output()
	if err != nil {
		log.Errorf("uname -p failed %s\n", err)
	} else {
		cpuArch := string(stdout)
		ReportDeviceInfo.CpuArch = *proto.String(strings.TrimSpace(cpuArch))
	}

	platformCmd := exec.Command("uname", "-i")
	stdout, err = platformCmd.Output()
	if err != nil {
		log.Errorf("uname -i failed %s\n", err)
	} else {
		platform := string(stdout)
		ReportDeviceInfo.Platform = *proto.String(strings.TrimSpace(platform))
	}

	dict := ExecuteXlInfoCmd()
	if dict != nil {
		// Note that this is the set of physical CPUs which is different
		// than the set of CPUs assigned to dom0
		ncpus, err := strconv.ParseUint(dict["nr_cpus"], 10, 32)
		if err != nil {
			log.Errorln("error while converting ncpus to int: ", err)
		} else {
			ReportDeviceInfo.Ncpu = *proto.Uint32(uint32(ncpus))
		}
		totalMemory, err := strconv.ParseUint(dict["total_memory"], 10, 64)
		if err == nil {
			// totalMemory is in MBytes
			ReportDeviceInfo.Memory = *proto.Uint64(uint64(totalMemory))
		}
	}

	// Find all disks and partitions
	disks := findDisksPartitions()
	ReportDeviceInfo.Storage = *proto.Uint64(0)
	for _, disk := range disks {
		size, isPart := partitionSize(disk)
		log.Debugf("Disk/partition %s size %d\n", disk, size)
		size = RoundToMbytes(size)
		is := info.ZInfoStorage{Device: disk, Total: size}
		ReportDeviceInfo.StorageList = append(ReportDeviceInfo.StorageList,
			&is)
		if isPart {
			ReportDeviceInfo.Storage += *proto.Uint64(size)
		}
	}
	for _, path := range reportPaths {
		u, err := disk.Usage(path)
		if err != nil {
			// Happens e.g., if we don't have a /persist
			log.Errorf("disk.Usage: %s\n", err)
			continue
		}
		log.Debugf("Path %s total %d used %d free %d\n",
			path, u.Total, u.Used, u.Free)
		is := info.ZInfoStorage{
			MountPath: path, Total: RoundToMbytes(u.Total)}
		// We know this is where we store images and keep
		// domU virtual disks.
		if path == persistPath {
			is.StorageLocation = true
		}
		ReportDeviceInfo.StorageList = append(ReportDeviceInfo.StorageList,
			&is)
	}

	ReportDeviceManufacturerInfo := new(info.ZInfoManufacturer)
	if strings.Contains(machineArch, "x86") {
		productManufacturer, productName, productVersion, productSerial, productUuid := hardware.GetDeviceManufacturerInfo()
		ReportDeviceManufacturerInfo.Manufacturer = *proto.String(strings.TrimSpace(productManufacturer))
		ReportDeviceManufacturerInfo.ProductName = *proto.String(strings.TrimSpace(productName))
		ReportDeviceManufacturerInfo.Version = *proto.String(strings.TrimSpace(productVersion))
		ReportDeviceManufacturerInfo.SerialNumber = *proto.String(strings.TrimSpace(productSerial))
		ReportDeviceManufacturerInfo.UUID = *proto.String(strings.TrimSpace(productUuid))

		biosVendor, biosVersion, biosReleaseDate := hardware.GetDeviceBios()
		ReportDeviceManufacturerInfo.BiosVendor = *proto.String(strings.TrimSpace(biosVendor))
		ReportDeviceManufacturerInfo.BiosVersion = *proto.String(strings.TrimSpace(biosVersion))
		ReportDeviceManufacturerInfo.BiosReleaseDate = *proto.String(strings.TrimSpace(biosReleaseDate))
	}
	compatible := hardware.GetCompatible()
	ReportDeviceManufacturerInfo.Compatible = *proto.String(compatible)
	ReportDeviceInfo.Minfo = ReportDeviceManufacturerInfo

	// Report BaseOs Status for the two partitions
	getBaseOsStatus := func(partLabel string) *types.BaseOsStatus {
		// Look for a matching IMGA/IMGB in baseOsStatus
		items := subBaseOsStatus.GetAll()
		for _, st := range items {
			bos := cast.CastBaseOsStatus(st)
			if bos.PartitionLabel == partLabel {
				return &bos
			}
		}
		return nil
	}
	getSwInfo := func(partLabel string) *info.ZInfoDevSW {
		swInfo := new(info.ZInfoDevSW)
		if bos := getBaseOsStatus(partLabel); bos != nil {
			// Get current state/version which is different than
			// what is on disk
			swInfo.Activated = bos.Activated
			swInfo.PartitionLabel = bos.PartitionLabel
			swInfo.PartitionDevice = bos.PartitionDevice
			swInfo.PartitionState = bos.PartitionState
			swInfo.Status = info.ZSwState(bos.State)
			swInfo.ShortVersion = bos.BaseOsVersion
			swInfo.LongVersion = "" // XXX
			if len(bos.StorageStatusList) > 0 {
				// Assume one - pick first StorageStatus
				swInfo.DownloadProgress = uint32(bos.StorageStatusList[0].Progress)
			}
			if !bos.ErrorTime.IsZero() {
				log.Debugf("reportMetrics sending error time %v error %v for %s\n",
					bos.ErrorTime, bos.Error,
					bos.BaseOsVersion)
				errInfo := new(info.ErrorInfo)
				errInfo.Description = bos.Error
				errTime, _ := ptypes.TimestampProto(bos.ErrorTime)
				errInfo.Timestamp = errTime
				swInfo.SwErr = errInfo
			}
		} else {
			partStatus := getBaseOsPartitionStatus(ctx, partLabel)
			swInfo.PartitionLabel = partLabel
			if partStatus != nil {
				swInfo.Activated = partStatus.CurrentPartition
				swInfo.PartitionDevice = partStatus.PartitionDevname
				swInfo.PartitionState = partStatus.PartitionState
				swInfo.ShortVersion = partStatus.ShortVersion
				swInfo.LongVersion = partStatus.LongVersion
			}
			if swInfo.ShortVersion != "" {
				// Must be factory install i.e. INSTALLED
				swInfo.Status = info.ZSwState(types.INSTALLED)
				swInfo.DownloadProgress = 100
			} else {
				swInfo.Status = info.ZSwState(types.INITIAL)
				swInfo.DownloadProgress = 0
			}
		}
		addUserSwInfo(ctx, swInfo)
		return swInfo
	}

	ReportDeviceInfo.SwList = make([]*info.ZInfoDevSW, 2)
	ReportDeviceInfo.SwList[0] = getSwInfo(getBaseOsCurrentPartition(ctx))
	ReportDeviceInfo.SwList[1] = getSwInfo(getBaseOsOtherPartition(ctx))
	// Report any other BaseOsStatus which might have errors
	items := subBaseOsStatus.GetAll()
	for _, st := range items {
		bos := cast.CastBaseOsStatus(st)
		if bos.PartitionLabel != "" {
			// Already reported above
			continue
		}
		log.Debugf("reportMetrics sending unattached bos for %s\n",
			bos.BaseOsVersion)
		swInfo := new(info.ZInfoDevSW)
		swInfo.Status = info.ZSwState(bos.State)
		swInfo.ShortVersion = bos.BaseOsVersion
		swInfo.LongVersion = "" // XXX
		if len(bos.StorageStatusList) > 0 {
			// Assume one - pick first StorageStatus
			swInfo.DownloadProgress = uint32(bos.StorageStatusList[0].Progress)
		}
		if !bos.ErrorTime.IsZero() {
			log.Debugf("reportMetrics sending error time %v error %v for %s\n",
				bos.ErrorTime, bos.Error, bos.BaseOsVersion)
			errInfo := new(info.ErrorInfo)
			errInfo.Description = bos.Error
			errTime, _ := ptypes.TimestampProto(bos.ErrorTime)
			errInfo.Timestamp = errTime
			swInfo.SwErr = errInfo
		}
		addUserSwInfo(ctx, swInfo)
		ReportDeviceInfo.SwList = append(ReportDeviceInfo.SwList,
			swInfo)
	}

	// Read interface name from library and match it with port name from
	// global status. Only report the ports in DeviceNetworkStatus
	interfaces, _ := psutilnet.Interfaces()
	portNames := types.ReportPorts(*deviceNetworkStatus)
	for _, port := range portNames {
		ifname := types.AdapterToIfName(deviceNetworkStatus, port)
		for _, interfaceDetail := range interfaces {
			if ifname != interfaceDetail.Name {
				continue
			}
			ReportDeviceNetworkInfo := getNetInfo(interfaceDetail, true)
			ReportDeviceNetworkInfo.DevName = *proto.String(port)
			ReportDeviceInfo.Network = append(ReportDeviceInfo.Network,
				ReportDeviceNetworkInfo)
		}
	}
	// Fill in global ZInfoDNS dns from /etc/resolv.conf
	// Note that "domain" is returned in search, hence DNSdomain is
	// not filled in.
	dc := netclone.DnsReadConfig("/etc/resolv.conf")
	log.Debugf("resolv.conf servers %v\n", dc.Servers)
	log.Debugf("resolv.conf search %v\n", dc.Search)

	ReportDeviceInfo.Dns = new(info.ZInfoDNS)
	ReportDeviceInfo.Dns.DNSservers = dc.Servers
	ReportDeviceInfo.Dns.DNSsearch = dc.Search

	// Report AssignableAdapters.
	// Domainmgr excludes adapters which do not currently exist in
	// what it publishes.
	// We also mark current management ports as such.
	for i := range aa.IoBundleList {
		ib := &aa.IoBundleList[i]
		reportAA := new(info.ZioBundle)
		reportAA.Type = info.ZioType(ib.Type)
		reportAA.Name = ib.Name
		reportAA.Members = ib.Members
		if ib.IsPort {
			reportAA.UsedByBaseOS = true
		} else if ib.UsedByUUID != nilUUID {
			reportAA.UsedByAppUUID = ib.UsedByUUID.String()
		}

		ReportDeviceInfo.AssignableAdapters = append(ReportDeviceInfo.AssignableAdapters,
			reportAA)
	}

	hinfo, err := host.Info()
	if err != nil {
		log.Fatalf("host.Info(): %s\n", err)
	}
	log.Debugf("uptime %d = %d days\n",
		hinfo.Uptime, hinfo.Uptime/(3600*24))
	log.Debugf("Booted at %v\n", time.Unix(int64(hinfo.BootTime), 0).UTC())

	bootTime, _ := ptypes.TimestampProto(
		time.Unix(int64(hinfo.BootTime), 0).UTC())
	ReportDeviceInfo.BootTime = bootTime
	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("HostName failed: %s\n", err)
	} else {
		ReportDeviceInfo.HostName = hostname
	}

	// Note that these are associated with the device and not with a
	// device name like ppp0 or wwan0
	lte := readLTEInfo()
	lteNets := readLTENetworks()
	if lteNets != nil {
		lte = append(lte, lteNets...)
	}
	for _, i := range lte {
		item := new(info.DeprecatedMetricItem)
		item.Key = i.Key
		item.Type = info.DepMetricItemType(i.Type)
		// setDeprecatedMetricAnyValue(item, i.Value)
		ReportDeviceInfo.MetricItems = append(ReportDeviceInfo.MetricItems, item)
	}

	ReportDeviceInfo.LastRebootReason = ctx.rebootReason
	if !ctx.rebootTime.IsZero() {
		rebootTime, _ := ptypes.TimestampProto(ctx.rebootTime)
		ReportDeviceInfo.LastRebootTime = rebootTime
	}

	ReportDeviceInfo.SystemAdapter = encodeSystemAdapterInfo(ctx.devicePortConfigList)

	ReportDeviceInfo.RestartCounter = ctx.restartCounter

	//Operational information about TPM presence/absence/usage.
	//"Unknown" for now, till we enable TPM functionality.
	ReportDeviceInfo.HSMStatus = info.HwSecurityModuleStatus_UNKNOWN
	ReportDeviceInfo.HSMInfo = "Not Available"

	ReportInfo.InfoContent = new(info.ZInfoMsg_Dinfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Dinfo); ok {
		x.Dinfo = ReportDeviceInfo
	}

	log.Debugf("PublishDeviceInfoToZedCloud sending %v\n", ReportInfo)
	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishDeviceInfoToZedCloud proto marshaling error: ", err)
	}

	statusUrl := serverName + "/" + statusApi
	zedcloud.RemoveDeferred(deviceUUID)
	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(ReportInfo))
	err = SendProtobuf(statusUrl, buf, size, iteration)
	if err != nil {
		log.Errorf("PublishDeviceInfoToZedCloud failed: %s\n", err)
		// Try sending later
		zedcloud.SetDeferred(deviceUUID, buf, size, statusUrl,
			zedcloudCtx, true)
	} else {
		writeSentDeviceInfoProtoMessage(data)
	}
}

// Convert the implementation details to the user-friendly userStatus and subStatus
func addUserSwInfo(ctx *zedagentContext, swInfo *info.ZInfoDevSW) {
	switch swInfo.Status {
	case info.ZSwState_INITIAL:
		// If Unused and partitionLabel is set them it
		// is the uninitialized IMGB partition which we don't report
		if swInfo.PartitionState == "unused" &&
			swInfo.PartitionLabel != "" {

			swInfo.UserStatus = info.BaseOsStatus_NONE
		} else {
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = "Initializing update"
		}
	case info.ZSwState_DOWNLOAD_STARTED:
		swInfo.UserStatus = info.BaseOsStatus_UPDATING
		swInfo.SubStatus = fmt.Sprintf("Downloading %d%% done", swInfo.DownloadProgress)
	case info.ZSwState_DOWNLOADED:
		if swInfo.Activated {
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = "Downloaded 100%"
		} else {
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	case info.ZSwState_DELIVERED:
		if swInfo.Activated {
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = "Downloaded and verified"
		} else {
			// XXX Remove once we have one slot
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	case info.ZSwState_INSTALLED:
		switch swInfo.PartitionState {
		case "active":
			if swInfo.Activated {
				swInfo.UserStatus = info.BaseOsStatus_ACTIVE
			} else {
				swInfo.UserStatus = info.BaseOsStatus_FALLBACK
			}
		case "updating":
			swInfo.UserStatus = info.BaseOsStatus_UPDATING
			swInfo.SubStatus = "About to reboot"
		case "inprogress":
			swInfo.UserStatus = info.BaseOsStatus_TESTING
			swInfo.SubStatus = fmt.Sprintf("Testing for %d more seconds",
				ctx.remainingTestTime/time.Second)

		case "unused":
			swInfo.UserStatus = info.BaseOsStatus_NONE
		}
	// XXX anything else?
	default:
		// The other states are use for app instances not for baseos
		swInfo.UserStatus = info.BaseOsStatus_NONE
	}
}

func setMetricAnyValue(item *metrics.MetricItem, val interface{}) {
	switch t := val.(type) {
	case uint32:
		u := val.(uint32)
		item.MetricItemValue = new(metrics.MetricItem_Uint32Value)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_Uint32Value); ok {
			x.Uint32Value = u
		}
	case uint64:
		u := val.(uint64)
		item.MetricItemValue = new(metrics.MetricItem_Uint64Value)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_Uint64Value); ok {
			x.Uint64Value = u
		}
	case bool:
		b := val.(bool)
		item.MetricItemValue = new(metrics.MetricItem_BoolValue)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_BoolValue); ok {
			x.BoolValue = b
		}
	case float32:
		f := val.(float32)
		item.MetricItemValue = new(metrics.MetricItem_FloatValue)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_FloatValue); ok {
			x.FloatValue = f
		}

	case string:
		s := val.(string)
		item.MetricItemValue = new(metrics.MetricItem_StringValue)
		if x, ok := item.GetMetricItemValue().(*metrics.MetricItem_StringValue); ok {
			x.StringValue = s
		}

	default:
		log.Errorf("setMetricAnyValue unknown %T\n", t)
	}
}

var nilIPInfo = ipinfo.IPInfo{}

func getNetInfo(interfaceDetail psutilnet.InterfaceStat,
	getAddrs bool) *info.ZInfoNetwork {

	networkInfo := new(info.ZInfoNetwork)
	networkInfo.LocalName = *proto.String(interfaceDetail.Name)
	if getAddrs {
		networkInfo.IPAddrs = make([]string, len(interfaceDetail.Addrs))
		for index, ip := range interfaceDetail.Addrs {
			networkInfo.IPAddrs[index] = *proto.String(ip.Addr)
		}
		networkInfo.MacAddr = *proto.String(interfaceDetail.HardwareAddr)
		// In case caller doesn't override
		networkInfo.DevName = *proto.String(networkInfo.LocalName)

		// Default routers from kernel whether or not we are using DHCP
		drs := getDefaultRouters(interfaceDetail.Name)
		networkInfo.DefaultRouters = make([]string, len(drs))
		for index, dr := range drs {
			log.Debugf("got dr: %v\n", dr)
			networkInfo.DefaultRouters[index] = *proto.String(dr)
		}
	}
	for _, fl := range interfaceDetail.Flags {
		if fl == "up" {
			networkInfo.Up = true
			break
		}
	}

	port := types.GetPort(*deviceNetworkStatus, interfaceDetail.Name)
	if port != nil {
		networkInfo.Uplink = port.IsMgmt
		// fill in ZInfoDNS
		networkInfo.Dns = new(info.ZInfoDNS)
		networkInfo.Dns.DNSdomain = port.DomainName
		for _, server := range port.DnsServers {
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
			geo.UnderlayIP = *proto.String(ai.Geo.IP)
			geo.Hostname = *proto.String(ai.Geo.Hostname)
			geo.City = *proto.String(ai.Geo.City)
			geo.Country = *proto.String(ai.Geo.Country)
			geo.Loc = *proto.String(ai.Geo.Loc)
			geo.Org = *proto.String(ai.Geo.Org)
			geo.Postal = *proto.String(ai.Geo.Postal)
			networkInfo.Location = geo
			break
		}
		// Any error?
		if !port.ErrorTime.IsZero() {
			errInfo := new(info.ErrorInfo)
			errInfo.Description = port.Error
			errTime, _ := ptypes.TimestampProto(port.ErrorTime)
			errInfo.Timestamp = errTime
			networkInfo.NetworkErr = errInfo
		}
		if port.Proxy != nil {
			networkInfo.Proxy = encodeProxyStatus(port.Proxy)
		}
	}
	return networkInfo
}

func encodeProxyStatus(proxyConfig *types.ProxyConfig) *info.ProxyStatus {
	status := new(info.ProxyStatus)
	status.Proxies = make([]*info.ProxyEntry, len(proxyConfig.Proxies))
	for i, pe := range proxyConfig.Proxies {
		pep := new(info.ProxyEntry)
		pep.Type = uint32(pe.Type)
		pep.Server = pe.Server
		pep.Port = pe.Port
		status.Proxies[i] = pep
	}
	status.Exceptions = proxyConfig.Exceptions
	status.Pacfile = proxyConfig.Pacfile
	status.NetworkProxyEnable = proxyConfig.NetworkProxyEnable
	status.NetworkProxyURL = proxyConfig.NetworkProxyURL
	status.WpadURL = proxyConfig.WpadURL
	log.Debugf("encodeProxyStatus: %+v\n", status)
	return status
}

func encodeSystemAdapterInfo(dpcl types.DevicePortConfigList) *info.SystemAdapterInfo {
	sainfo := new(info.SystemAdapterInfo)
	sainfo.CurrentIndex = uint32(dpcl.CurrentIndex)
	sainfo.Status = make([]*info.DevicePortStatus, len(dpcl.PortConfigList))
	for i, dpc := range dpcl.PortConfigList {
		dps := new(info.DevicePortStatus)
		dps.Version = uint32(dpc.Version)
		dps.Key = dpc.Key
		ts, _ := ptypes.TimestampProto(dpc.TimePriority)
		dps.TimePriority = ts
		if !dpc.LastFailed.IsZero() {
			ts, _ := ptypes.TimestampProto(dpc.LastFailed)
			dps.LastFailed = ts
		}
		if !dpc.LastSucceeded.IsZero() {
			ts, _ := ptypes.TimestampProto(dpc.LastSucceeded)
			dps.LastSucceeded = ts
		}
		dps.LastError = dpc.LastError

		dps.Ports = make([]*info.DevicePort, len(dpc.Ports))
		for j, p := range dpc.Ports {
			dps.Ports[j] = encodeNetworkPortConfig(&p)
		}
		sainfo.Status[i] = dps
	}
	log.Debugf("encodeSystemAdapterInfo: %+v\n", sainfo)
	return sainfo
}

func encodeNetworkPortConfig(npc *types.NetworkPortConfig) *info.DevicePort {
	dp := new(info.DevicePort)
	dp.Ifname = npc.IfName
	dp.Name = npc.Name
	dp.IsMgmt = npc.IsMgmt
	dp.Free = npc.Free
	// DhcpConfig
	dp.DhcpType = uint32(npc.Dhcp)
	dp.Subnet = npc.AddrSubnet
	dp.Gateway = npc.Gateway.String()
	dp.Domainname = npc.DomainName
	dp.NtpServer = npc.NtpServer.String()
	for _, d := range npc.DnsServers {
		dp.DnsServers = append(dp.DnsServers, d.String())
	}
	// XXX Not in definition. Remove?
	// XXX  string dhcpRangeLow = 17;
	// XXX  string dhcpRangeHigh = 18;

	dp.Proxy = encodeProxyStatus(&npc.ProxyConfig)
	return dp
}

// This function is called per change, hence needs to try over all management ports
// When aiStatus is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishAppInfoToZedCloud(ctx *zedagentContext, uuid string,
	aiStatus *types.AppInstanceStatus,
	aa *types.AssignableAdapters, iteration int) {
	log.Debugf("PublishAppInfoToZedCloud uuid %s\n", uuid)
	var ReportInfo = &info.ZInfoMsg{}

	appType := new(info.ZInfoTypes)
	*appType = info.ZInfoTypes_ZiApp
	ReportInfo.Ztype = *appType
	ReportInfo.DevId = *proto.String(zcdevUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportAppInfo := new(info.ZInfoApp)

	ReportAppInfo.AppID = uuid
	ReportAppInfo.SystemApp = false
	ReportAppInfo.State = info.ZSwState(types.HALTED)
	if aiStatus != nil {
		ReportAppInfo.AppName = aiStatus.DisplayName
		ReportAppInfo.State = info.ZSwState(aiStatus.State)
		ds := LookupDomainStatusUUID(uuid)
		if ds == nil {
			log.Infof("ReportAppInfo: Did not find DomainStatus for UUID %s\n",
				uuid)
			// Expect zedmanager to send us update when DomainStatus
			// appears. We avoid nil checks below by:
			ds = &types.DomainStatus{}
		} else {
			// XXX better compare? Pick REFRESHING and PURGING from
			// aiStatus but HALTED from DomainStatus
			if ds.State > aiStatus.State {
				ReportAppInfo.State = info.ZSwState(ds.State)
			}
		}

		if !aiStatus.ErrorTime.IsZero() {
			errInfo := new(info.ErrorInfo)
			errInfo.Description = aiStatus.Error
			errTime, _ := ptypes.TimestampProto(aiStatus.ErrorTime)
			errInfo.Timestamp = errTime
			ReportAppInfo.AppErr = append(ReportAppInfo.AppErr,
				errInfo)
		}

		if len(aiStatus.StorageStatusList) == 0 {
			log.Infof("storage status detail is empty so ignoring")
		} else {
			ReportAppInfo.SoftwareList = make([]*info.ZInfoSW, len(aiStatus.StorageStatusList))
			for idx, ss := range aiStatus.StorageStatusList {
				ReportSoftwareInfo := new(info.ZInfoSW)
				ReportSoftwareInfo.SwVersion = aiStatus.UUIDandVersion.Version
				ReportSoftwareInfo.ImageName = ss.Name
				ReportSoftwareInfo.SwHash = ss.ImageSha256
				ReportSoftwareInfo.State = info.ZSwState(ss.State)
				ReportSoftwareInfo.DownloadProgress = uint32(ss.Progress)

				ReportSoftwareInfo.Target = ss.Target
				for _, disk := range ds.DiskStatusList {
					if disk.ImageSha256 == ss.ImageSha256 {
						ReportSoftwareInfo.Vdev = disk.Vdev
						break
					}
				}

				ReportAppInfo.SoftwareList[idx] = ReportSoftwareInfo
			}
		}
		if aiStatus.BootTime.IsZero() {
			// If never booted
			log.Infoln("BootTime is empty")
		} else {
			bootTime, _ := ptypes.TimestampProto(aiStatus.BootTime)
			ReportAppInfo.BootTime = bootTime
		}

		for _, ib := range ds.IoAdapterList {
			reportAA := new(info.ZioBundle)
			reportAA.Type = info.ZioType(ib.Type)
			reportAA.Name = ib.Name
			reportAA.UsedByAppUUID = ds.Key()
			b := types.LookupIoBundle(aa, ib.Type, ib.Name)
			if b != nil {
				reportAA.Members = b.Members
			}
			ReportAppInfo.AssignedAdapters = append(ReportAppInfo.AssignedAdapters,
				reportAA)
		}
		// Get vifs assigned to the application
		// Mostly reporting the UP status
		// We extract the appIP from the dnsmasq assignment
		interfaces, _ := psutilnet.Interfaces()
		ifNames := ReadAppInterfaceList(aiStatus.DomainName)
		log.Debugf("ReportAppInfo: domainName %s ifs %v\n",
			aiStatus.DomainName, ifNames)
		for _, ifname := range ifNames {
			for _, interfaceDetail := range interfaces {
				if ifname != interfaceDetail.Name {
					continue
				}
				networkInfo := getNetInfo(interfaceDetail, false)
				ip, macAddr := getAppIP(ctx, aiStatus,
					ifname)
				networkInfo.IPAddrs = make([]string, 1)
				networkInfo.IPAddrs[0] = *proto.String(ip)
				networkInfo.MacAddr = *proto.String(macAddr)
				name := appIfnameToName(aiStatus, ifname)
				log.Debugf("app %s/%s localName %s devName %s\n",
					aiStatus.Key(), aiStatus.DisplayName,
					ifname, name)
				networkInfo.DevName = *proto.String(name)
				ReportAppInfo.Network = append(ReportAppInfo.Network,
					networkInfo)
			}
		}
	}

	ReportInfo.InfoContent = new(info.ZInfoMsg_Ainfo)
	if x, ok := ReportInfo.GetInfoContent().(*info.ZInfoMsg_Ainfo); ok {
		x.Ainfo = ReportAppInfo
	}

	log.Debugf("PublishAppInfoToZedCloud sending %v\n", ReportInfo)

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishAppInfoToZedCloud proto marshaling error: ", err)
	}
	statusUrl := serverName + "/" + statusApi

	zedcloud.RemoveDeferred(uuid)
	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(ReportInfo))
	err = SendProtobuf(statusUrl, buf, size, iteration)
	if err != nil {
		log.Errorf("PublishAppInfoToZedCloud failed: %s\n", err)
		// Try sending later
		zedcloud.SetDeferred(uuid, buf, size, statusUrl, zedcloudCtx,
			true)
	} else {
		writeSentAppInfoProtoMessage(data)
	}
}

func appIfnameToName(aiStatus *types.AppInstanceStatus, vifname string) string {
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.Vif == vifname {
			return ulStatus.Name
		}
	}
	for _, olStatus := range aiStatus.OverlayNetworks {
		if olStatus.Vif == vifname {
			return olStatus.Name
		}
	}
	return ""
}

// This function is called per change, hence needs to try over all management ports
// For each port we try different source IPs until we find a working one.
// For any 400 error we give up (don't retry) by not returning an error
func SendProtobuf(url string, buf *bytes.Buffer, size int64,
	iteration int) error {

	const return400 = true
	resp, _, err := zedcloud.SendOnAllIntf(zedcloudCtx, url,
		size, buf, iteration, return400)
	if resp != nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
		log.Infof("SendProtoBuf: %s silently ignore code %d\n",
			url, resp.StatusCode)
		return nil
	}
	return err
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different port for load spreading.
// For each port we try all its local IP addresses until we get a success.
func SendMetricsProtobuf(ReportMetrics *metrics.ZMetricMsg,
	iteration int) {
	data, err := proto.Marshal(ReportMetrics)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	buf := bytes.NewBuffer(data)
	size := int64(proto.Size(ReportMetrics))
	metricsUrl := serverName + "/" + metricsApi
	const return400 = false
	_, _, err = zedcloud.SendOnAllIntf(zedcloudCtx, metricsUrl,
		size, buf, iteration, return400)
	if err != nil {
		// Hopefully next timeout will be more successful
		log.Errorf("SendMetricsProtobuf failed: %s\n", err)
		return
	} else {
		writeSentMetricsProtoMessage(data)
	}
}

// Return an array of names like "sda", "sdb1"
func findDisksPartitions() []string {
	out, err := exec.Command("lsblk", "-nlo", "NAME").Output()
	if err != nil {
		log.Errorf("lsblk -nlo NAME failed %s\n", err)
		return nil
	}
	res := strings.Split(string(out), "\n")
	// Remove blank/empty string after last CR
	res = res[:len(res)-1]
	return res
}

// Given "sdb1" return the size of the partition; "sdb" to size of disk
// Returns size and a bool to indicate that it is a partition.
func partitionSize(part string) (uint64, bool) {
	out, err := exec.Command("lsblk", "-nbdo", "SIZE", "/dev/"+part).Output()
	if err != nil {
		log.Errorf("lsblk -nbdo SIZE %s failed %s\n", "/dev/"+part, err)
		return 0, false
	}
	res := strings.Split(string(out), "\n")
	val, err := strconv.ParseUint(res[0], 10, 64)
	if err != nil {
		log.Errorf("parseUint(%s) failed %s\n", res[0], err)
		return 0, false
	}
	out, err = exec.Command("lsblk", "-nbdo", "TYPE", "/dev/"+part).Output()
	if err != nil {
		log.Errorf("lsblk -nbdo TYPE %s failed %s\n", "/dev/"+part, err)
		return 0, false
	}
	isPart := strings.EqualFold(strings.TrimSpace(string(out)), "part")
	return val, isPart
}

func getDefaultRouters(ifname string) []string {
	var res []string
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		log.Errorf("getDefaultRouters failed to find %s: %s\n",
			ifname, err)
		return res
	}
	ifindex := link.Attrs().Index
	table := types.GetDefaultRouteTable()
	// Note that a default route is represented as nil Dst
	filter := netlink.Route{Table: table, LinkIndex: ifindex, Dst: nil}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	fflags |= netlink.RT_FILTER_DST
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Fatalf("getDefaultRouters RouteList failed: %v\n", err)
	}
	// log.Debugf("getDefaultRouters(%s) - got %d\n", ifname, len(routes))
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		// log.Debugf("getDefaultRouters route dest %v\n", rt.Dst)
		res = append(res, rt.Gw.String())
	}
	return res
}

// Use the ifname/vifname to find the overlay or underlay status
// and from there the (ip, mac) addresses for the app
func getAppIP(ctx *zedagentContext, aiStatus *types.AppInstanceStatus,
	vifname string) (string, string) {

	log.Debugf("getAppIP(%s, %s)\n", aiStatus.Key(), vifname)
	for _, ulStatus := range aiStatus.UnderlayNetworks {
		if ulStatus.Vif != vifname {
			continue
		}
		log.Debugf("getAppIP(%s, %s) found underlay %s mac %s\n",
			aiStatus.Key(), vifname,
			ulStatus.AssignedIPAddr, ulStatus.Mac)
		return ulStatus.AssignedIPAddr, ulStatus.Mac
	}
	for _, olStatus := range aiStatus.OverlayNetworks {
		if olStatus.Vif != vifname {
			continue
		}
		log.Debugf("getAppIP(%s, %s) found overlay %s mac %s\n",
			aiStatus.Key(), vifname,
			olStatus.EID.String(), olStatus.Mac)
		return olStatus.EID.String(), olStatus.Mac
	}
	return "", ""
}
