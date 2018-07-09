// Copyright (c) 2017-2018 Zededa, Inc.
// All rights reserved.

// Push info and metrics to zedcloud

package zedagent

import (
	"bytes"
	"fmt"
	"github.com/eriknordmark/ipinfo"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	psutilnet "github.com/shirou/gopsutil/net"
	"github.com/vishvananda/netlink"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/diskmetrics"
	"github.com/zededa/go-provision/flextimer"
	"github.com/zededa/go-provision/hardware"
	"github.com/zededa/go-provision/netclone"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zboot"
	"github.com/zededa/go-provision/zedcloud"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Remember the set of names of the disks and partitions
var savedDisks []string

// Also report usage for these paths
const persistPath = "/persist"

var reportPaths = []string{"/", "/config", persistPath}

func publishMetrics(iteration int) {
	cpuStorageStat := ExecuteXentopCmd()
	PublishMetricsToZedCloud(cpuStorageStat, iteration)
}

// Run a periodic post of the metrics

func metricsTimerTask(handleChannel chan interface{}) {
	iteration := 0
	log.Println("starting report metrics timer task")
	publishMetrics(iteration)

	interval := time.Duration(configItemCurrent.metricInterval) * time.Second
	max := float64(interval)
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))
	// Return handle to caller
	handleChannel <- ticker
	for range ticker.C {
		iteration += 1
		publishMetrics(iteration)
	}
}

// Called when configItemCurrent changes
// Assumes the caller has verifier that the interval has changed
func updateMetricsTimer(tickerHandle interface{}) {
	interval := time.Duration(configItemCurrent.metricInterval) * time.Second
	log.Printf("updateMetricsTimer() change to %v\n", interval)
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
		log.Println(err.Error())
	}
	xlInfo := fmt.Sprintf("%s", stdout)
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

//Returns boolean depending upon the existence of domain
func verifyDomainExists(domainId int) bool {
	cmd := exec.Command("xl", "list", strconv.Itoa(domainId))
	_, err := cmd.Output()
	if err != nil {
		log.Println(err.Error())
		return false
	} else {
		return true
	}
}

// Shadow copy of suscription to determine info for deletes. Key is UUID
var domainStatus map[string]types.DomainStatus

// Key is DomainName; value is array of interface names
var appInterfaceAndNameList map[string][]string

// Key is DomainName; value is array of disk images
var appDiskAndNameList map[string][]string

func handleDomainStatusModify(ctxArg interface{}, key string,
	statusArg interface{}) {

	status := cast.CastDomainStatus(statusArg)
	ctx := ctxArg.(*zedagentContext)
	if status.Key() != key {
		log.Printf("handleDomainStatusModify key/UUID mismatch %s vs %s; ignored %+v\n",
			key, status.Key(), status)
		return
	}
	if debug {
		log.Printf("handleDomainStatusModify for %s\n", key)
	}
	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		if debug {
			log.Printf("handleDomainstatusModify skipped due to Pending* for %s\n",
				key)
		}
		return
	}
	if domainStatus == nil {
		if debug {
			log.Printf("create Domain map\n")
		}
		domainStatus = make(map[string]types.DomainStatus)
	}
	// Detect if any changes relevant to the device status report
	old := lookupDomainStatus(ctx, key)
	if old != nil {
		if ioAdapterListChanged(*old, status) {
			ctx.TriggerDeviceInfo = true
		}
	} else {
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
	// We report the vif and bridge since the ACL drops are on the Bridge
	// XXX move ACLs to vif??
	for _, vif := range status.VifList {
		interfaceList = append(interfaceList, vif.Vif)
		interfaceList = append(interfaceList, vif.Bridge)
	}
	appInterfaceAndNameList[status.DomainName] = interfaceList
	var diskList []string
	for _, ds := range status.DiskStatusList {
		diskList = append(diskList, ds.ActiveFileLocation)
	}
	appDiskAndNameList[status.DomainName] = diskList
	log.Printf("handleDomainStatusModify appIntf %s %v\n",
		status.DomainName, interfaceList)
	if debug {
		log.Printf("handleDomainStatusModify done for %s\n", key)
	}
}

func handleDomainStatusDelete(ctxArg interface{}, key string) {

	ctx := ctxArg.(*zedagentContext)
	log.Printf("handleDomainStatusDelete for %s\n", key)
	// Use shadow copy to determine what changed
	if m, ok := domainStatus[key]; !ok {
		log.Printf("handleDomainStatusDelete for %s - not found\n",
			key)
	} else {
		// Detect if any changes relevant to the device status report
		if ioAdapterListChanged(m, types.DomainStatus{}) {
			ctx.TriggerDeviceInfo = true
		}

		if _, ok := appInterfaceAndNameList[m.DomainName]; ok {
			log.Printf("appInterfaceAndnameList for %v\n", m.DomainName)
			delete(appInterfaceAndNameList, m.DomainName)
		}
		log.Printf("Domain map delete for %v\n", key)
		delete(domainStatus, key)
	}
	log.Printf("handleDomainStatusDelete done for %s\n", key)
}

func lookupDomainStatus(ctx *zedagentContext, key string) *types.DomainStatus {
	sub := ctx.subDomainStatus
	st, _ := sub.Get(key)
	if st == nil {
		log.Printf("lookupDomainStatus(%s) not found\n", key)
		return nil
	}
	status := cast.CastDomainStatus(st)
	if status.Key() != key {
		log.Printf("lookupDomainStatus(%s) got %s; ignored %+v\n",
			key, status.Key(), status)
		return nil
	}
	return &status
}

func ioAdapterListChanged(old types.DomainStatus, new types.DomainStatus) bool {
	log.Printf("ioAdapterListChanged(%v, %v)\n",
		old.IoAdapterList, new.IoAdapterList)
	if len(old.IoAdapterList) != len(new.IoAdapterList) {
		log.Printf("ioAdapterListChanged length from %d to %d\n",
			len(old.IoAdapterList), len(new.IoAdapterList))
		return true
	}
	adapterSet := make(map[types.IoAdapter]bool)
	for _, ad := range old.IoAdapterList {
		adapterSet[ad] = true
	}
	for _, ad := range new.IoAdapterList {
		if _, ok := adapterSet[ad]; !ok {
			log.Printf("ioAdapterListChanged %v not in old set\n",
				ad)
			return true
		}
	}
	log.Printf("ioAdapterListChanged: no change\n")
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

// Look for a DomainStatus which is using the IoBundle
func LookupDomainStatusIoBundle(ioType types.IoType, name string) *types.DomainStatus {
	for _, ds := range domainStatus {
		for _, b := range ds.IoAdapterList {
			if b.Type == ioType && strings.EqualFold(b.Name, name) {
				return &ds
			}
		}
	}
	return nil
}

// XXX can we use libxenstat? /usr/local/lib/libxenstat.so on hikey
// /usr/lib/libxenstat.so in container
func ExecuteXentopCmd() [][]string {
	var cpuStorageStat [][]string

	count := 0
	counter := 0
	arg1 := "xentop"
	arg2 := "-b"
	arg3 := "-d"
	arg4 := "1"
	arg5 := "-i"
	arg6 := "2"
	arg7 := "-f"

	cmd := exec.Command(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
	stdout, err := cmd.Output()
	if err != nil {
		println(err.Error())
		return [][]string{}
	}

	xentopInfo := fmt.Sprintf("%s", stdout)

	splitXentopInfo := strings.Split(xentopInfo, "\n")

	splitXentopInfoLength := len(splitXentopInfo)
	var i int
	var start int

	for i = 0; i < splitXentopInfoLength; i++ {

		str := fmt.Sprintf(splitXentopInfo[i])
		re := regexp.MustCompile(" ")

		spaceRemovedsplitXentopInfo := re.ReplaceAllLiteralString(splitXentopInfo[i], "")
		matched, err := regexp.MatchString("NAMESTATECPU.*", spaceRemovedsplitXentopInfo)

		if matched {

			count++
			fmt.Sprintf("string matched: ", str)
			if count == 2 {

				start = i
				fmt.Sprintf("value of i: ", start)
			}

		} else {
			fmt.Sprintf("string not matched", err)
		}
	}

	length := splitXentopInfoLength - 1 - start
	finalOutput := make([][]string, length)

	for j := start; j < splitXentopInfoLength-1; j++ {

		str := fmt.Sprintf(splitXentopInfo[j])
		splitOutput := regexp.MustCompile(" ")
		finalOutput[j-start] = splitOutput.Split(str, -1)
	}

	cpuStorageStat = make([][]string, length)

	for i := range cpuStorageStat {
		cpuStorageStat[i] = make([]string, 20)
	}

	for f := 0; f < length; f++ {

		for out := 0; out < len(finalOutput[f]); out++ {

			matched, err := regexp.MatchString("[A-Za-z0-9]+", finalOutput[f][out])
			if err != nil {
				log.Println(err)
			} else if matched {

				if finalOutput[f][out] == "no" {

				} else if finalOutput[f][out] == "limit" {
					counter++
					cpuStorageStat[f][counter] = "no limit"
				} else {
					counter++
					cpuStorageStat[f][counter] = finalOutput[f][out]
				}
			} else {

				fmt.Sprintf("space: ", finalOutput[f][counter])
			}
		}
		counter = 0
	}
	return cpuStorageStat
}

func PublishMetricsToZedCloud(cpuStorageStat [][]string, iteration int) {

	var ReportMetrics = &zmet.ZMetricMsg{}

	ReportDeviceMetric := new(zmet.DeviceMetric)
	ReportDeviceMetric.Memory = new(zmet.MemoryMetric)
	ReportDeviceMetric.CpuMetric = new(zmet.AppCpuMetric)

	ReportMetrics.DevID = *proto.String(zcdevUUID.String())
	ReportZmetric := new(zmet.ZmetricTypes)
	*ReportZmetric = zmet.ZmetricTypes_ZmDevice

	ReportMetrics.AtTimeStamp = ptypes.TimestampNow()

	info, err := host.Info()
	if err != nil {
		log.Fatal("host.Info(): %s\n", err)
	}
	if debug {
		log.Printf("uptime %d = %d days\n",
			info.Uptime, info.Uptime/(3600*24))
		log.Printf("Booted at %v\n", time.Unix(int64(info.BootTime), 0).UTC())
	}
	cpuSecs := getCpuSecs()
	if debug && info.Uptime != 0 {
		log.Printf("uptime %d cpuSecs %d, percent used %d\n",
			info.Uptime, cpuSecs, (100*cpuSecs)/info.Uptime)
	}

	ReportDeviceMetric.CpuMetric.Total = *proto.Uint64(cpuSecs)
	// Note that uptime is seconds we've been up. We're converting
	// to a timestamp. That better not be interpreted as a time since
	// the epoch
	uptime, _ := ptypes.TimestampProto(
		time.Unix(int64(info.Uptime), 0).UTC())
	ReportDeviceMetric.CpuMetric.UpTime = uptime

	// Memory related info for dom0
	ram, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("mem.VirtualMemory: %s\n", err)
	} else {
		ReportDeviceMetric.Memory.UsedMem = uint32(RoundToMbytes(ram.Used))
		ReportDeviceMetric.Memory.AvailMem = uint32(RoundToMbytes(ram.Available))
		ReportDeviceMetric.Memory.UsedPercentage = ram.UsedPercent
		ReportDeviceMetric.Memory.AvailPercentage =
			(100.0 - (ram.UsedPercent))
	}
	// Use the network metrics from zedrouter subscription
	// Only report stats for the uplinks plus dbo1x0
	ifNames := types.ReportInterfaces(deviceNetworkStatus)
	for _, ifName := range ifNames {
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
		networkDetails := new(zmet.NetworkMetric)
		networkDetails.IName = metric.IfName
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
	if debug {
		log.Println("network metrics: ",
			ReportDeviceMetric.Network)
	}
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
		metric := zmet.ZedcloudMetric{IfName: ifname,
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
			if debug {
				log.Printf("CloudMetrics[%s] url %s %v\n",
					ifname, url, um)
			}
			urlMet := new(zmet.UrlcloudMetric)
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

	// Add DiskMetric
	// XXX should we get a new list of disks each time?
	// XXX can we use part, err = disk.Partitions(false)
	// and then p.MountPoint for the usage?
	for _, d := range savedDisks {
		size := partitionSize(d)
		if debug {
			log.Printf("Disk/partition %s size %d\n",
				d, size)
		}
		size = RoundToMbytes(size)
		metric := zmet.DiskMetric{Disk: d, Total: size}
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
			log.Printf("disk.Usage: %s\n", err)
			continue
		}
		if debug {
			log.Printf("Path %s total %d used %d free %d\n",
				path, u.Total, u.Used, u.Free)
		}
		metric := zmet.DiskMetric{MountPath: path,
			Total: RoundToMbytes(u.Total),
			Used:  RoundToMbytes(u.Used),
			Free:  RoundToMbytes(u.Free),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	// Walk all verified downloads and report their size (faked
	// as disks)
	for _, vs := range verifierStatusMap {
		if debug {
			log.Printf("verifierStatusMap %s size %d\n",
				vs.Safename, vs.Size)
		}
		metric := zmet.DiskMetric{
			Disk:  vs.Safename,
			Total: RoundToMbytes(uint64(vs.Size)),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}
	// XXX TBD: Avoid dups with verifierStatusMap above
	for _, ds := range downloaderStatusMap {
		if debug {
			log.Printf("downloaderStatusMap %s size %d\n",
				ds.Safename, ds.Size)
		}
		metric := zmet.DiskMetric{
			Disk:  ds.Safename,
			Total: RoundToMbytes(uint64(ds.Size)),
		}
		ReportDeviceMetric.Disk = append(ReportDeviceMetric.Disk, &metric)
	}

	// Note that these are associated with the device and not with a
	// device name like ppp0 or wwan0
	lte := readLTEMetrics()
	for _, i := range lte {
		item := new(zmet.MetricItem)
		item.Key = i.Key
		item.Type = zmet.MetricItemType(i.Type)
		setMetricAnyValue(item, i.Value)
		ReportDeviceMetric.MetricItems = append(ReportDeviceMetric.MetricItems, item)
	}

	ReportMetrics.MetricContent = new(zmet.ZMetricMsg_Dm)
	if x, ok := ReportMetrics.GetMetricContent().(*zmet.ZMetricMsg_Dm); ok {
		x.Dm = ReportDeviceMetric
	}

	// Handle xentop failing above
	if len(cpuStorageStat) == 0 {
		log.Printf("No xentop? metrics: %s\n", ReportMetrics)
		SendMetricsProtobuf(ReportMetrics, iteration)
		return
	}

	countApp := 0
	ReportMetrics.Am = make([]*zmet.AppMetric, len(cpuStorageStat)-2)
	for arr := 1; arr < len(cpuStorageStat); arr++ {
		if strings.Contains(cpuStorageStat[arr][1], "Domain-0") {
			if debug {
				log.Printf("Nothing to report for Domain-0\n")
			}
			continue
		}
		if len(cpuStorageStat) <= 2 {
			continue
		}
		ReportAppMetric := new(zmet.AppMetric)
		ReportAppMetric.Cpu = new(zmet.AppCpuMetric)
		ReportAppMetric.Memory = new(zmet.MemoryMetric)

		domainName := cpuStorageStat[arr][1]
		ds := LookupDomainStatus(domainName)
		if ds == nil {
			log.Printf("Did not find status for domainName %s\n",
				domainName)
			// Note that it is included in the
			// metrics without a name and uuid.
			// XXX ignore and report next time?
			// Avoid nil checks
			ds = &types.DomainStatus{}
		} else {
			ReportAppMetric.AppName = ds.DisplayName
			ReportAppMetric.AppID = ds.Key()
		}

		appCpuTotal, _ := strconv.ParseUint(cpuStorageStat[arr][3], 10, 0)
		ReportAppMetric.Cpu.Total = *proto.Uint64(appCpuTotal)
		// We don't report ReportAppMetric.Cpu.Uptime
		// since we already report BootTime for the app

		// This is in kbytes
		totalAppMemory, _ := strconv.ParseUint(cpuStorageStat[arr][5], 10, 0)
		totalAppMemory = RoundFromKbytesToMbytes(totalAppMemory)
		usedAppMemoryPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][6], 10)
		usedMemory := (float64(totalAppMemory) * (usedAppMemoryPercent)) / 100
		availableMemory := float64(totalAppMemory) - usedMemory
		availableAppMemoryPercent := 100 - usedAppMemoryPercent

		ReportAppMetric.Memory.UsedMem = uint32(usedMemory)
		ReportAppMetric.Memory.AvailMem = uint32(availableMemory)
		ReportAppMetric.Memory.UsedPercentage = float64(usedAppMemoryPercent)
		ReportAppMetric.Memory.AvailPercentage = float64(availableAppMemoryPercent)

		appInterfaceList := ReadAppInterfaceList(strings.TrimSpace(cpuStorageStat[arr][1]))
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
			networkDetails := new(zmet.NetworkMetric)
			networkDetails.IName = metric.IfName
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

		appDiskList := ReadAppDiskList(strings.TrimSpace(cpuStorageStat[arr][1]))
		// Use the network metrics from zedrouter subscription
		for _, diskfile := range appDiskList {
			appDiskDetails := new(zmet.AppDiskMetric)
			err := getDiskInfo(diskfile, appDiskDetails)
			if err != nil {
				log.Printf("getDiskInfo(%s) failed %v\n",
					diskfile, err)
				continue
			}
			ReportAppMetric.Disk = append(ReportAppMetric.Disk,
				appDiskDetails)
		}
		ReportMetrics.Am[countApp] = ReportAppMetric
		if debug {
			log.Println("metrics per app is: ",
				ReportMetrics.Am[countApp])
		}
		countApp++
	}

	if debug {
		log.Printf("PublishMetricsToZedCloud sending %s\n",
			ReportMetrics)
	}
	SendMetricsProtobuf(ReportMetrics, iteration)
}

func getDiskInfo(diskfile string, appDiskDetails *zmet.AppDiskMetric) error {
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

// This function is called per change, hence needs to try over all uplinks
// send report on each uplink.
func PublishDeviceInfoToZedCloud(baseOsStatus map[string]types.BaseOsStatus,
	aa *types.AssignableAdapters, iteration int) {

	var ReportInfo = &zmet.ZInfoMsg{}

	deviceType := new(zmet.ZInfoTypes)
	*deviceType = zmet.ZInfoTypes_ZiDevice
	ReportInfo.Ztype = *deviceType
	deviceUUID := zcdevUUID.String()
	ReportInfo.DevId = *proto.String(deviceUUID)
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportDeviceInfo := new(zmet.ZInfoDevice)

	var machineArch string
	machineCmd := exec.Command("uname", "-m")
	stdout, err := machineCmd.Output()
	if err != nil {
		log.Println(err.Error())
	} else {
		machineArch = fmt.Sprintf("%s", stdout)
		ReportDeviceInfo.MachineArch = *proto.String(strings.TrimSpace(machineArch))
	}

	cpuCmd := exec.Command("uname", "-p")
	stdout, err = cpuCmd.Output()
	if err != nil {
		log.Println(err.Error())
	} else {
		cpuArch := fmt.Sprintf("%s", stdout)
		ReportDeviceInfo.CpuArch = *proto.String(strings.TrimSpace(cpuArch))
	}

	platformCmd := exec.Command("uname", "-p")
	stdout, err = platformCmd.Output()
	if err != nil {
		log.Println(err.Error())
	} else {
		platform := fmt.Sprintf("%s", stdout)
		ReportDeviceInfo.Platform = *proto.String(strings.TrimSpace(platform))
	}

	dict := ExecuteXlInfoCmd()
	if dict != nil {
		// Note that this is the set of physical CPUs which is different
		// than the set of CPUs assigned to dom0
		ncpus, err := strconv.ParseUint(dict["nr_cpus"], 10, 32)
		if err != nil {
			log.Println("error while converting ncpus to int: ", err)
		} else {
			ReportDeviceInfo.Ncpu = *proto.Uint32(uint32(ncpus))
		}
		totalMemory, err := strconv.ParseUint(dict["total_memory"], 10, 64)
		if err == nil {
			// totalMemory is in MBytes
			ReportDeviceInfo.Memory = *proto.Uint64(uint64(totalMemory))
		}
	}

	d, err := disk.Usage("/")
	if err != nil {
		log.Printf("disk.Usage: %s\n", err)
	} else {
		mbytes := RoundToMbytes(d.Total)
		ReportDeviceInfo.Storage = *proto.Uint64(mbytes)
	}
	// Find all disks and partitions
	disks := findDisksPartitions()
	savedDisks = disks // Save for stats

	for _, disk := range disks {
		size := partitionSize(disk)
		if debug {
			log.Printf("Disk/partition %s size %d\n", disk, size)
		}
		size = RoundToMbytes(size)
		is := zmet.ZInfoStorage{Device: disk, Total: size}
		ReportDeviceInfo.StorageList = append(ReportDeviceInfo.StorageList,
			&is)
	}
	for _, path := range reportPaths {
		u, err := disk.Usage(path)
		if err != nil {
			// Happens e.g., if we don't have a /persist
			log.Printf("disk.Usage: %s\n", err)
			continue
		}

		if debug {
			log.Printf("Path %s total %d used %d free %d\n",
				path, u.Total, u.Used, u.Free)
		}
		is := zmet.ZInfoStorage{
			MountPath: path, Total: RoundToMbytes(u.Total)}
		// We know this is where we store images and keep
		// domU virtual disks.
		if path == persistPath {
			is.StorageLocation = true
		}
		ReportDeviceInfo.StorageList = append(ReportDeviceInfo.StorageList,
			&is)
	}

	ReportDeviceManufacturerInfo := new(zmet.ZInfoManufacturer)
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
		// XXX sanity check on activated vs. curPart
		// XXX are there cases where we've started download without
		// having assigned a partLabel?
		for _, bos := range baseOsStatus {
			if bos.PartitionLabel == partLabel {
				return &bos
			}
		}
		return nil
	}
	getSwInfo := func(partLabel string) *zmet.ZInfoDevSW {
		swInfo := new(zmet.ZInfoDevSW)
		swInfo.Activated = (partLabel == zboot.GetCurrentPartition())
		swInfo.PartitionLabel = partLabel
		swInfo.PartitionDevice = zboot.GetPartitionDevname(partLabel)
		swInfo.PartitionState = zboot.GetPartitionState(partLabel)
		swInfo.ShortVersion = zboot.GetShortVersion(partLabel)
		swInfo.LongVersion = zboot.GetLongVersion(partLabel)
		if bos := getBaseOsStatus(partLabel); bos != nil {
			// Get current state/version which is different than
			// what is on disk
			swInfo.Status = zmet.ZSwState(bos.State)
			swInfo.ShortVersion = bos.BaseOsVersion
			swInfo.LongVersion = "" // XXX
			if !bos.ErrorTime.IsZero() {
				log.Printf("reportMetrics sending error time %v error %v for %s\n",
					bos.ErrorTime, bos.Error,
					bos.BaseOsVersion)
				errInfo := new(zmet.ErrorInfo)
				errInfo.Description = bos.Error
				errTime, _ := ptypes.TimestampProto(bos.ErrorTime)
				errInfo.Timestamp = errTime
				swInfo.SwErr = errInfo
			}
		} else if swInfo.ShortVersion != "" {
			// Must be factory install i.e. INSTALLED
			swInfo.Status = zmet.ZSwState(types.INSTALLED)
		} else {
			swInfo.Status = zmet.ZSwState(types.INITIAL)
		}
		return swInfo
	}

	ReportDeviceInfo.SwList = make([]*zmet.ZInfoDevSW, 2)
	ReportDeviceInfo.SwList[0] = getSwInfo(zboot.GetCurrentPartition())
	ReportDeviceInfo.SwList[1] = getSwInfo(zboot.GetOtherPartition())

	// Read interface name from library and match it with uplink name from
	// global status. Only report the uplinks plus dbo1x0
	// XXX should get this info from zedrouter subscription
	// Should we put it all in DeviceNetworkStatus?
	interfaces, _ := psutilnet.Interfaces()
	ifNames := types.ReportInterfaces(deviceNetworkStatus)
	for _, ifname := range ifNames {
		for _, interfaceDetail := range interfaces {
			if ifname == interfaceDetail.Name {
				ReportDeviceNetworkInfo := getNetInfo(interfaceDetail)
				ReportDeviceInfo.Network = append(ReportDeviceInfo.Network,
					ReportDeviceNetworkInfo)
			}
		}
	}
	// Fill in global ZInfoDNS dns from /etc/resolv.conf
	// Note that "domain" is returned in search, hence DNSdomain is
	// not filled in.
	dc := netclone.DnsReadConfig("/etc/resolv.conf")
	if debug {
		log.Printf("resolv.conf servers %v\n", dc.Servers)
		log.Printf("resolv.conf search %v\n", dc.Search)
	}
	ReportDeviceInfo.Dns = new(zmet.ZInfoDNS)
	ReportDeviceInfo.Dns.DNSservers = dc.Servers
	ReportDeviceInfo.Dns.DNSsearch = dc.Search

	// Report AssignableAdapters
	// We exclude adapters which do not currently exist.
	// We also exclude current uplinks. Note that this routine
	// is called when the uplinks change (to also report any change in
	// the uplink IP addresses etc.))
	for i, _ := range aa.IoBundleList {
		ib := &aa.IoBundleList[i]
		// For a PCI device we check if it exists in hardware/kernel
		// XXX could have been assigned away; hack to check for domains
		_, _, err := types.IoBundleToPci(ib)
		if err != nil {
			if len(domainStatus) == 0 {
				if debug {
					log.Printf("Not reporting non-existent PCI device %d %s: %v\n",
						ib.Type, ib.Name, err)
				}
				continue
			}
			if debug {
				log.Printf("Reporting non-existent PCI device %d %s: %v\n",
					ib.Type, ib.Name, err)
			}
		}
		reportAA := new(zmet.ZioBundle)
		reportAA.Type = zmet.ZioType(ib.Type)
		reportAA.Name = ib.Name
		reportAA.Members = ib.Members
		// lookup domains to see what is in use
		ds := LookupDomainStatusIoBundle(ib.Type, ib.Name)
		if ds != nil {
			reportAA.UsedByAppUUID = ds.Key()
		} else {
			for _, m := range ib.Members {
				if types.IsUplink(deviceNetworkStatus, m) {
					reportAA.UsedByBaseOS = true
					break
				}
			}
		}
		ReportDeviceInfo.AssignableAdapters = append(ReportDeviceInfo.AssignableAdapters,
			reportAA)
	}

	info, err := host.Info()
	if err != nil {
		log.Fatal("host.Info(): %s\n", err)
	}
	if debug {
		log.Printf("uptime %d = %d days\n",
			info.Uptime, info.Uptime/(3600*24))
		log.Printf("Booted at %v\n", time.Unix(int64(info.BootTime), 0).UTC())
	}
	bootTime, _ := ptypes.TimestampProto(
		time.Unix(int64(info.BootTime), 0).UTC())
	ReportDeviceInfo.BootTime = bootTime
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("HostName failed: %s\n", err)
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
		item := new(zmet.MetricItem)
		item.Key = i.Key
		item.Type = zmet.MetricItemType(i.Type)
		setMetricAnyValue(item, i.Value)
		ReportDeviceInfo.MetricItems = append(ReportDeviceInfo.MetricItems, item)
	}

	ReportInfo.InfoContent = new(zmet.ZInfoMsg_Dinfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Dinfo); ok {
		x.Dinfo = ReportDeviceInfo
	}

	if debug {
		log.Printf("PublishDeviceInfoToZedCloud sending %v\n",
			ReportInfo)
	}
	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishDeviceInfoToZedCloud proto marshaling error: ", err)
	}

	statusUrl := serverName + "/" + statusApi
	zedcloud.RemoveDeferred(deviceUUID)
	err = SendProtobuf(statusUrl, data, iteration)
	if err != nil {
		log.Printf("PublishDeviceInfoToZedCloud failed: %s\n", err)
		// Try sending later
		zedcloud.SetDeferred(deviceUUID, data, statusUrl, zedcloudCtx,
			true)
	}
}

func setMetricAnyValue(item *zmet.MetricItem, val interface{}) {
	switch t := val.(type) {
	case uint32:
		u := val.(uint32)
		item.MetricItemValue = new(zmet.MetricItem_Uint32Value)
		if x, ok := item.GetMetricItemValue().(*zmet.MetricItem_Uint32Value); ok {
			x.Uint32Value = u
		}
	case uint64:
		u := val.(uint64)
		item.MetricItemValue = new(zmet.MetricItem_Uint64Value)
		if x, ok := item.GetMetricItemValue().(*zmet.MetricItem_Uint64Value); ok {
			x.Uint64Value = u
		}
	case bool:
		b := val.(bool)
		item.MetricItemValue = new(zmet.MetricItem_BoolValue)
		if x, ok := item.GetMetricItemValue().(*zmet.MetricItem_BoolValue); ok {
			x.BoolValue = b
		}
	case float32:
		f := val.(float32)
		item.MetricItemValue = new(zmet.MetricItem_FloatValue)
		if x, ok := item.GetMetricItemValue().(*zmet.MetricItem_FloatValue); ok {
			x.FloatValue = f
		}

	case string:
		s := val.(string)
		item.MetricItemValue = new(zmet.MetricItem_StringValue)
		if x, ok := item.GetMetricItemValue().(*zmet.MetricItem_StringValue); ok {
			x.StringValue = s
		}

	default:
		log.Printf("setMetricAnyValue unknown %T\n", t)
	}
}

var nilIPInfo = ipinfo.IPInfo{}

func getNetInfo(interfaceDetail psutilnet.InterfaceStat) *zmet.ZInfoNetwork {
	networkInfo := new(zmet.ZInfoNetwork)
	networkInfo.IPAddrs = make([]string, len(interfaceDetail.Addrs))
	for index, ip := range interfaceDetail.Addrs {
		// For compatibility we put he first in the deprecated singleton
		// Note CIDR notation with /N
		if index == 0 {
			networkInfo.IPAddr = *proto.String(ip.Addr)
		}
		networkInfo.IPAddrs[index] = *proto.String(ip.Addr)
	}
	networkInfo.MacAddr = *proto.String(interfaceDetail.HardwareAddr)
	networkInfo.DevName = *proto.String(interfaceDetail.Name)
	// Default routers from kernel whether or not we are using DHCP
	drs := getDefaultRouters(interfaceDetail.Name)
	networkInfo.DefaultRouters = make([]string, len(drs))
	for index, dr := range drs {
		if debug {
			log.Printf("got dr: %v\n", dr)
		}
		networkInfo.DefaultRouters[index] = *proto.String(dr)
	}

	// XXX fill in ZInfoDNS dns
	// XXX from correct resolv conf file - static map from intf to file?
	// XXX in /hostfs/containers/services/dhcpcd/tmp/upper/run/dhcpcd/resolv.conf/eth0.dhcp; place in
	for _, fl := range interfaceDetail.Flags {
		if fl == "up" {
			networkInfo.Up = true
			break
		}
	}

	uplink := types.GetUplink(deviceNetworkStatus, interfaceDetail.Name)
	if uplink != nil {
		networkInfo.Uplink = true
		// XXX we potentially have geoloc information for each IP
		// address.
		// For now fill in using the first IP address which has location
		// info.
		for _, ai := range uplink.AddrInfoList {
			if ai.Geo == nilIPInfo {
				continue
			}
			geo := new(zmet.GeoLoc)
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
	}

	// XXX once we have static config add any
	// config errors. Note that this might imply
	// reporting for devices which do not exist.

	return networkInfo
}

// This function is called per change, hence needs to try over all uplinks
// send report on each uplink.
// When aiStatus is nil it means a delete and we send a message
// containing only the UUID to inform zedcloud about the delete.
func PublishAppInfoToZedCloud(uuid string, aiStatus *types.AppInstanceStatus,
	aa *types.AssignableAdapters, iteration int) {
	if debug {
		log.Printf("PublishAppInfoToZedCloud uuid %s\n", uuid)
	}
	var ReportInfo = &zmet.ZInfoMsg{}

	appType := new(zmet.ZInfoTypes)
	*appType = zmet.ZInfoTypes_ZiApp
	ReportInfo.Ztype = *appType
	ReportInfo.DevId = *proto.String(zcdevUUID.String())
	ReportInfo.AtTimeStamp = ptypes.TimestampNow()

	ReportAppInfo := new(zmet.ZInfoApp)

	ReportAppInfo.AppID = uuid
	ReportAppInfo.SystemApp = false
	if aiStatus != nil {
		ReportAppInfo.AppName = aiStatus.DisplayName
		ReportAppInfo.State = zmet.ZSwState(aiStatus.State)
		ds := LookupDomainStatusUUID(uuid)
		if ds == nil {
			log.Printf("Did not find DomainStatus for UUID %s\n",
				uuid)
			// XXX should we reschedule when we have a domainStatus?
			// Avoid nil checks
			ds = &types.DomainStatus{}
		} else {
			ReportAppInfo.Activated = aiStatus.Activated && verifyDomainExists(ds.DomainId)
		}

		if !aiStatus.ErrorTime.IsZero() {
			errInfo := new(zmet.ErrorInfo)
			errInfo.Description = aiStatus.Error
			errTime, _ := ptypes.TimestampProto(aiStatus.ErrorTime)
			errInfo.Timestamp = errTime
			ReportAppInfo.AppErr = append(ReportAppInfo.AppErr,
				errInfo)
		}

		if len(aiStatus.StorageStatusList) == 0 {
			log.Printf("storage status detail is empty so ignoring")
		} else {
			ReportAppInfo.SoftwareList = make([]*zmet.ZInfoSW, len(aiStatus.StorageStatusList))
			for idx, sc := range aiStatus.StorageStatusList {
				ReportSoftwareInfo := new(zmet.ZInfoSW)
				ReportSoftwareInfo.SwVersion = aiStatus.UUIDandVersion.Version
				ReportSoftwareInfo.SwHash = sc.ImageSha256
				ReportSoftwareInfo.State = zmet.ZSwState(sc.State)
				ReportSoftwareInfo.Target = sc.Target
				for _, disk := range ds.DiskStatusList {
					if disk.ImageSha256 == sc.ImageSha256 {
						ReportSoftwareInfo.Vdev = disk.Vdev
						break
					}
				}

				ReportAppInfo.SoftwareList[idx] = ReportSoftwareInfo
			}
		}
		if ds.BootTime.IsZero() {
			// If never booted or we didn't find a DomainStatus
			log.Println("BootTime is empty")
		} else {
			bootTime, _ := ptypes.TimestampProto(ds.BootTime)
			ReportAppInfo.BootTime = bootTime
		}

		for _, ib := range ds.IoAdapterList {
			reportAA := new(zmet.ZioBundle)
			reportAA.Type = zmet.ZioType(ib.Type)
			reportAA.Name = ib.Name
			reportAA.UsedByAppUUID = ds.Key()
			// Can we call
			b := types.LookupIoBundle(aa, ib.Type, ib.Name)
			if b != nil {
				reportAA.Members = b.Members
			}
			ReportAppInfo.AssignedAdapters = append(ReportAppInfo.AssignedAdapters,
				reportAA)
		}
	}

	ReportInfo.InfoContent = new(zmet.ZInfoMsg_Ainfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Ainfo); ok {
		x.Ainfo = ReportAppInfo
	}

	if debug {
		log.Printf("PublishAppInfoToZedCloud sending %v\n", ReportInfo)
	}

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		log.Fatal("PublishAppInfoToZedCloud proto marshaling error: ", err)
	}
	statusUrl := serverName + "/" + statusApi

	zedcloud.RemoveDeferred(uuid)
	err = SendProtobuf(statusUrl, data, iteration)
	if err != nil {
		log.Printf("PublishAppInfoToZedCloud failed: %s\n", err)
		// Try sending later
		zedcloud.SetDeferred(uuid, data, statusUrl, zedcloudCtx, true)
	}
}

// This function is called per change, hence needs to try over all uplinks
// send report on each uplink.
// For each uplink we try different source IPs until we find a working one.
// For any 400 error we give up (don't retry) by not returning an error
func SendProtobuf(url string, data []byte, iteration int) error {
	resp, _, err := zedcloud.SendOnAllIntf(zedcloudCtx, url,
		int64(len(data)), bytes.NewBuffer(data), iteration, true)
	if resp != nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
		log.Printf("SendProtoBuf: %s silently ignore code %d\n",
			url, resp.StatusCode)
		return nil
	}
	return err
}

// Try all (first free, then rest) until it gets through.
// Each iteration we try a different uplink for load spreading.
// For each uplink we try all its local IP addresses until we get a success.
func SendMetricsProtobuf(ReportMetrics *zmet.ZMetricMsg,
	iteration int) {
	data, err := proto.Marshal(ReportMetrics)
	if err != nil {
		log.Fatal("SendInfoProtobufStr proto marshaling error: ", err)
	}

	metricsUrl := serverName + "/" + metricsApi
	_, _, err = zedcloud.SendOnAllIntf(zedcloudCtx, metricsUrl,
		int64(len(data)), bytes.NewBuffer(data), iteration, false)
	if err != nil {
		// Hopefully next timeout will be more successful
		log.Printf("SendMetricsProtobuf failed: %s\n", err)
		return
	}
}

// Return an array of names like "sda", "sdb1"
func findDisksPartitions() []string {
	out, err := exec.Command("lsblk", "-nlo", "NAME").Output()
	if err != nil {
		log.Println(err)
		return nil
	}
	res := strings.Split(string(out), "\n")
	// Remove blank/empty string after last CR
	res = res[:len(res)-1]
	return res
}

// Given "sdb1" return the size of the partition; "sdb" to size of disk
func partitionSize(part string) uint64 {
	out, err := exec.Command("lsblk", "-nbdo", "SIZE", "/dev/"+part).Output()
	if err != nil {
		log.Println(err)
		return 0
	}
	res := strings.Split(string(out), "\n")
	val, err := strconv.ParseUint(res[0], 10, 64)
	if err != nil {
		log.Println(err)
		return 0
	}
	return val
}

// Returns the number of CPU seconds since boot
func getCpuSecs() uint64 {
	contents, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		log.Fatal("/proc/uptime: %s\n", err)
	}
	lines := strings.Split(string(contents), "\n")

	var idle uint64
	var uptime uint64
	for _, line := range lines {
		fields := strings.Fields(line)
		for i, f := range fields {
			val, err := strconv.ParseFloat(f, 64)
			if err != nil {
				log.Println("Error: ", f, err)
			} else {
				switch i {
				case 0:
					uptime = uint64(val)
				case 1:
					idle = uint64(val)
				}
			}
		}
	}
	cpus, err := cpu.Info()
	if err != nil {
		log.Printf("cpu.Info: %s\n", err)
		// Assume 1 CPU
		return uptime - idle
	}
	ncpus := uint64(len(cpus))
	// Idle time is measured for each CPU hence need to scale
	// to figure out how much CPU was used
	return uptime - (idle / ncpus)
}

func getDefaultRouters(ifname string) []string {
	var res []string
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		log.Printf("getDefaultRouters failed to find %s: %s\n",
			ifname, err)
		return res
	}
	ifindex := link.Attrs().Index
	table := syscall.RT_TABLE_MAIN
	// Note that a default route is represented as nil Dst
	filter := netlink.Route{Table: table, LinkIndex: ifindex, Dst: nil}
	fflags := netlink.RT_FILTER_TABLE
	fflags |= netlink.RT_FILTER_OIF
	fflags |= netlink.RT_FILTER_DST
	routes, err := netlink.RouteListFiltered(syscall.AF_UNSPEC,
		&filter, fflags)
	if err != nil {
		log.Fatal("getDefaultRouters RouteList failed: %v\n", err)
	}
	// log.Printf("getDefaultRouters(%s) - got %d\n", ifname, len(routes))
	for _, rt := range routes {
		if rt.Table != table {
			continue
		}
		if ifindex != 0 && rt.LinkIndex != ifindex {
			continue
		}
		// log.Printf("getDefaultRouters route dest %v\n", rt.Dst)
		res = append(res, rt.Gw.String())
	}
	return res
}
