package main

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	psutilnet "github.com/shirou/gopsutil/net"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/types"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	compatibleFile = "/proc/device-tree/compatible"
)

func publishMetrics(iteration int) {
	cpuStorageStat := ExecuteXentopCmd()
	PublishMetricsToZedCloud(cpuStorageStat, iteration)
}

// XXX should the timers be randomized to avoid self-synchronization across
// potentially lots of devices?
func metricsTimerTask() {
	iteration := 0
	log.Println("starting report metrics timer task")
	publishMetrics(iteration)
	ticker := time.NewTicker(time.Second * 60)
	for range ticker.C {
		iteration += 1
		publishMetrics(iteration)
	}
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

func GetDeviceManufacturerInfo() (string, string, string, string, string) {

	dmidecodeNameCmd := exec.Command("dmidecode", "-s", "system-product-name")
	pname, err := dmidecodeNameCmd.Output()
	if err != nil {
		log.Println(err.Error())
	}
	dmidecodeManuCmd := exec.Command("dmidecode", "-s", "system-manufacturer")
	manufacturer, err := dmidecodeManuCmd.Output()
	if err != nil {
		log.Println(err.Error())
	}
	dmidecodeVersionCmd := exec.Command("dmidecode", "-s", "system-version")
	version, err := dmidecodeVersionCmd.Output()
	if err != nil {
		log.Println(err.Error())
	}
	dmidecodeSerialCmd := exec.Command("dmidecode", "-s", "system-serial-number")
	serial, err := dmidecodeSerialCmd.Output()
	if err != nil {
		log.Println(err.Error())
	}
	dmidecodeUuidCmd := exec.Command("dmidecode", "-s", "system-uuid")
	uuid, err := dmidecodeUuidCmd.Output()
	if err != nil {
		log.Println(err.Error())
	}
	productManufacturer := string(manufacturer)
	productName := string(pname)
	productVersion := string(version)
	productSerial := string(serial)
	productUuid := string(uuid)
	return productManufacturer, productName, productVersion, productSerial, productUuid
}

// Returns BIOS vendor, version, release-date
func GetDeviceBios() (string, string, string) {

	vendor, err := exec.Command("dmidecode", "-s", "bios-vendor").Output()
	if err != nil {
		log.Println(err.Error())
	}
	version, err := exec.Command("dmidecode", "-s", "bios-version").Output()
	if err != nil {
		log.Println(err.Error())
	}
	releaseDate, err := exec.Command("dmidecode", "-s", "bios-release-date").Output()
	if err != nil {
		log.Println(err.Error())
	}
	return string(vendor), string(version), string(releaseDate)
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

// Key is UUID
var domainStatus map[string]types.DomainStatus

// Key is DomainName; value is arrive of interfacenames
var appInterfaceAndNameList map[string][]string

func handleDomainStatusModify(ctxArg interface{}, statusFilename string,
	statusArg interface{}) {
	status := statusArg.(*types.DomainStatus)
	key := status.UUIDandVersion.UUID.String()
	log.Printf("handleDomainStatusModify for %s\n", key)
	// Ignore if any Pending* flag is set
	if status.PendingAdd || status.PendingModify || status.PendingDelete {
		log.Printf("handleDomainstatusModify skipped due to Pending* for %s\n",
			key)
		return
	}
	if domainStatus == nil {
		fmt.Printf("create Domain map\n")
		domainStatus = make(map[string]types.DomainStatus)
	}
	domainStatus[key] = *status
	if appInterfaceAndNameList == nil {
		appInterfaceAndNameList = make(map[string][]string)
	}
	var interfaceList []string
	for _, vif := range status.VifList {
		interfaceList = append(interfaceList, vif.Bridge)
	}
	appInterfaceAndNameList[status.DomainName] = interfaceList
	log.Printf("handleDomainStatusModidy appIntf %s %v\n", status.DomainName, interfaceList)
	log.Printf("handleDomainStatusModify done for %s\n", key)
}

func handleDomainStatusDelete(ctxArg interface{}, statusFilename string) {
	log.Printf("handleDomainStatusDelete for %s\n", statusFilename)
	key := statusFilename
	if m, ok := domainStatus[key]; !ok {
		log.Printf("handleDomainStatusDelete for %s - not found\n",
			key)
	} else {
		if _, ok := appInterfaceAndNameList[m.DomainName]; ok {
			fmt.Printf("appInterfaceAndnameList for %v\n", m.DomainName)
			delete(appInterfaceAndNameList, m.DomainName)
		}
		fmt.Printf("Domain map delete for %v\n", key)
		delete(domainStatus, key)
	}
	log.Printf("handleDomainStatusDelete done for %s\n",
		statusFilename)
}

func ReadAppInterfaceName(appName string) []string {
	return appInterfaceAndNameList[appName]
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
		if strings.Compare(ds.UUIDandVersion.UUID.String(), uuid) == 0 {
			return &ds
		}
	}
	return nil
}

// XXX can we use libxenstat? /usr/local/lib/libxenstat.so on hikey
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
			fmt.Sprint(err)
			if matched {

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
	ReportDeviceMetric.Cpu = new(zmet.CpuMetric)
	ReportDeviceMetric.Memory = new(zmet.MemoryMetric)

	ReportMetrics.DevID = *proto.String(deviceId)
	ReportZmetric := new(zmet.ZmetricTypes)
	*ReportZmetric = zmet.ZmetricTypes_ZmDevice

	ReportMetrics.Ztype = *ReportZmetric
	ReportMetrics.AtTimeStamp = ptypes.TimestampNow()

	// Handle xentop failing above
	if len(cpuStorageStat) == 0 {
		log.Printf("No xentop? metrics: %s\n", ReportMetrics)
		SendMetricsProtobufStrThroughHttp(ReportMetrics, iteration)
		return
	}

	countApp := 0
	ReportMetrics.Am = make([]*zmet.AppMetric, len(cpuStorageStat)-2)
	for arr := 1; arr < len(cpuStorageStat); arr++ {
		if strings.Contains(cpuStorageStat[arr][1], "Domain-0") {
			cpuTime, _ := strconv.ParseUint(cpuStorageStat[arr][3], 10, 0)
			ReportDeviceMetric.Cpu.UpTime = *proto.Uint32(uint32(cpuTime))
			cpuUsedInPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][4], 10)
			ReportDeviceMetric.Cpu.CpuUtilization = *proto.Float64(float64(cpuUsedInPercent))
			cpuDetail, err := cpu.Times(true)
			if err != nil {
				log.Println("error while fetching cpu related time: ", err)
			} else {
				for _, cpuStat := range cpuDetail {
					ReportDeviceMetric.Cpu.Usr = cpuStat.User
					ReportDeviceMetric.Cpu.Nice = cpuStat.Nice
					ReportDeviceMetric.Cpu.System = cpuStat.System
					ReportDeviceMetric.Cpu.Io = cpuStat.Irq
					ReportDeviceMetric.Cpu.Irq = cpuStat.Irq
					ReportDeviceMetric.Cpu.Soft = cpuStat.Softirq
					ReportDeviceMetric.Cpu.Steal = cpuStat.Steal
					ReportDeviceMetric.Cpu.Guest = cpuStat.Guest
					ReportDeviceMetric.Cpu.Idle = cpuStat.Idle
				}
			}
			// Memory related info for dom0
			ram, err := mem.VirtualMemory()
			if err != nil {
				log.Println(err)
			} else {
				ReportDeviceMetric.Memory.UsedMem = uint32(ram.Used)
				ReportDeviceMetric.Memory.AvailMem = uint32(ram.Available)
				ReportDeviceMetric.Memory.UsedPercentage = ram.UsedPercent
				ReportDeviceMetric.Memory.AvailPercentage = (100.0 - (ram.UsedPercent))
			}
			//find network related info...
			network, err := psutilnet.IOCounters(true)
			if err != nil {
				log.Println(err)
			} else {
				// Only report stats for the uplinks plus dbo1x0
				// Latter will move to a system app when we disaggregate
				// Build list of uplinks + dbo1x0
				countDeviceInterfaces := 0
				reportNames := func() []string {
					var names []string
					names = append(names, "dbo1x0")
					for _, uplink := range deviceNetworkStatus.UplinkStatus {
						names = append(names, uplink.IfName)
					}
					return names
				}
				ifNames := reportNames()

				countNoOfInterfaceToReport := 0
				for _, ifName := range ifNames {
					for _, networkInfo := range network {
						if ifName == networkInfo.Name {
							countNoOfInterfaceToReport++
						}
					}
				}
				ReportDeviceMetric.Network = make([]*zmet.NetworkMetric, countNoOfInterfaceToReport)

				for _, ifName := range ifNames {
					var ni *psutilnet.IOCountersStat
					for _, networkInfo := range network {
						if (ifName == networkInfo.Name) && (countDeviceInterfaces < countNoOfInterfaceToReport) {
							ni = &networkInfo
							break
						}
					}
					if ni == nil {
						continue
					}
					networkDetails := new(zmet.NetworkMetric)
					networkDetails.IName = ni.Name
					networkDetails.TxPkts = ni.PacketsSent
					networkDetails.RxPkts = ni.PacketsRecv
					networkDetails.TxBytes = ni.BytesSent
					networkDetails.RxBytes = ni.BytesRecv
					networkDetails.TxDrops = ni.Dropout
					networkDetails.RxDrops = ni.Dropin
					networkDetails.TxErrors = ni.Errout
					networkDetails.RxErrors = ni.Errin
					if networkDetails != nil {
						ReportDeviceMetric.Network[countDeviceInterfaces] = networkDetails
						countDeviceInterfaces++
					}
				}
				if debug {
					log.Println("network metrics: ",
						ReportDeviceMetric.Network)
				}
			}
			ReportMetrics.MetricContent = new(zmet.ZMetricMsg_Dm)
			if x, ok := ReportMetrics.GetMetricContent().(*zmet.ZMetricMsg_Dm); ok {
				x.Dm = ReportDeviceMetric
			}
		} else {

			if len(cpuStorageStat) > 2 {
				ReportAppMetric := new(zmet.AppMetric)
				ReportAppMetric.Cpu = new(zmet.AppCpuMetric)
				ReportAppMetric.Memory = new(zmet.MemoryMetric)

				domainName := cpuStorageStat[arr][1]
				ds := LookupDomainStatus(domainName)
				if ds == nil {
					log.Printf("Did not find status for domainName %s\n",
						domainName)
				} else {
					ReportAppMetric.AppName = ds.DisplayName
					ReportAppMetric.AppID = ds.UUIDandVersion.UUID.String()
				}

				appCpuTotal, _ := strconv.ParseUint(cpuStorageStat[arr][3], 10, 0)
				ReportAppMetric.Cpu.CpuTotal = *proto.Uint32(uint32(appCpuTotal))
				// XXX add ReportAppMetric.Cpu.UpTime - does zedmanager need to track boot time?
				appCpuUsedInPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][4], 10)
				ReportAppMetric.Cpu.CpuPercentage = *proto.Float64(float64(appCpuUsedInPercent))

				totalAppMemory, _ := strconv.ParseUint(cpuStorageStat[arr][5], 10, 0)
				usedAppMemoryPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][6], 10)
				usedMemory := (float64(totalAppMemory) * (usedAppMemoryPercent)) / 100
				availableMemory := float64(totalAppMemory) - usedMemory
				availableAppMemoryPercent := 100 - usedAppMemoryPercent

				ReportAppMetric.Memory.UsedMem = uint32(usedMemory)
				ReportAppMetric.Memory.AvailMem = uint32(availableMemory)
				ReportAppMetric.Memory.UsedPercentage = float64(usedAppMemoryPercent)
				ReportAppMetric.Memory.AvailPercentage = float64(availableAppMemoryPercent)

				appInterfaceList := ReadAppInterfaceName(strings.TrimSpace(cpuStorageStat[arr][1]))
				network, err := psutilnet.IOCounters(true)
				if err != nil {
					log.Println(err)
				} else if len(appInterfaceList) != 0 {
					ReportAppMetric.Network = make([]*zmet.NetworkMetric, len(appInterfaceList))
					for index, ifName := range appInterfaceList {
						var ni *psutilnet.IOCountersStat
						for _, networkInfo := range network {
							if ifName == networkInfo.Name {
								ni = &networkInfo
								break
							}
						}
						if ni == nil {
							continue
						}
						networkDetails := new(zmet.NetworkMetric)
						networkDetails.IName = ni.Name
						// Note that the packets received on bu* and bo* where sent
						// by the domU and vice versa, hence we swap here
						networkDetails.TxPkts = ni.PacketsRecv
						networkDetails.RxPkts = ni.PacketsSent
						networkDetails.TxBytes = ni.BytesRecv
						networkDetails.RxBytes = ni.BytesSent
						networkDetails.TxDrops = ni.Dropin
						networkDetails.RxDrops = ni.Dropout
						networkDetails.TxErrors = ni.Errin
						networkDetails.RxErrors = ni.Errout

						ReportAppMetric.Network[index] = networkDetails

					}
				}
				ReportMetrics.Am[countApp] = ReportAppMetric
				if debug {
					log.Println("metrics per app is: ",
						ReportMetrics.Am[countApp])
				}
				countApp++
			}

		}
	}
	if debug {
		log.Printf("Metrics: %s\n", ReportMetrics)
	}
	SendMetricsProtobufStrThroughHttp(ReportMetrics, iteration)
}

func PublishDeviceInfoToZedCloud(baseOsStatus map[string]types.BaseOsStatus, iteration int) {

	var ReportInfo = &zmet.ZInfoMsg{}

	deviceType := new(zmet.ZInfoTypes)
	*deviceType = zmet.ZInfoTypes_ZiDevice
	ReportInfo.Ztype = *deviceType
	ReportInfo.DevId = *proto.String(deviceId)

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
	ncpus, err := strconv.ParseUint(dict["nr_cpus"], 10, 32)
	if err != nil {
		log.Println("error while converting ncpus to int: ", err)
	} else {
		ReportDeviceInfo.Ncpu = *proto.Uint32(uint32(ncpus))
	}
	totalMemory, _ := strconv.ParseUint(dict["total_memory"], 10, 64)
	ReportDeviceInfo.Memory = *proto.Uint64(uint64(totalMemory))

	d, err := disk.Usage("/")
	if err != nil {
		log.Println(err)
	} else {
		ReportDeviceInfo.Storage = *proto.Uint64(uint64(d.Total))
	}

	ReportDeviceManufacturerInfo := new(zmet.ZInfoManufacturer)
	if strings.Contains(machineArch, "x86") {
		// XXX should we save manufacturer and product name and use it
		// to check for capabilities elsewhere? Have e.g. "Supermicro/SYS-E100-9APP"
		productManufacturer, productName, productVersion, productSerial, productUuid := GetDeviceManufacturerInfo()
		ReportDeviceManufacturerInfo.Manufacturer = *proto.String(strings.TrimSpace(productManufacturer))
		ReportDeviceManufacturerInfo.ProductName = *proto.String(strings.TrimSpace(productName))
		ReportDeviceManufacturerInfo.Version = *proto.String(strings.TrimSpace(productVersion))
		ReportDeviceManufacturerInfo.SerialNumber = *proto.String(strings.TrimSpace(productSerial))
		ReportDeviceManufacturerInfo.UUID = *proto.String(strings.TrimSpace(productUuid))

		biosVendor, biosVersion, biosReleaseDate := GetDeviceBios()
		ReportDeviceManufacturerInfo.BiosVendor = *proto.String(strings.TrimSpace(biosVendor))
		ReportDeviceManufacturerInfo.BiosVersion = *proto.String(strings.TrimSpace(biosVersion))
		ReportDeviceManufacturerInfo.BiosReleaseDate = *proto.String(strings.TrimSpace(biosReleaseDate))
		ReportDeviceInfo.Minfo = ReportDeviceManufacturerInfo
	}
	if _, err := os.Stat(compatibleFile); err == nil {
		// No dmidecode on ARM. Can only report compatible string
		contents, err := ioutil.ReadFile(compatibleFile)
		if err != nil {
			log.Println(err)
		} else {
			compatible := strings.TrimSpace(string(contents))
			ReportDeviceManufacturerInfo.Compatible = *proto.String(compatible)
		}
		ReportDeviceInfo.Minfo = ReportDeviceManufacturerInfo
	}
	ReportDeviceSoftwareInfo := new(zmet.ZInfoSW)
	systemHost, err := host.Info()
	if err != nil {
		log.Println(err)
	}
	ReportDeviceSoftwareInfo.SwVersion = systemHost.KernelVersion //XXX for now we are filling kernel version...
	ReportDeviceSoftwareInfo.SwHash = *proto.String(" ")
	ReportDeviceInfo.Software = ReportDeviceSoftwareInfo

	// Report BaseOs Status
	ReportDeviceInfo.SoftwareList = make([]*zmet.ZInfoSW, len(baseOsStatus))
	var idx int = 0
	for _, value := range baseOsStatus {
		ReportDeviceSoftwareInfo := new(zmet.ZInfoSW)
		ReportDeviceSoftwareInfo.SwVersion = value.BaseOsVersion
		ReportDeviceSoftwareInfo.SwHash = value.ConfigSha256
		ReportDeviceSoftwareInfo.State = zmet.ZSwState(value.State)
		ReportDeviceSoftwareInfo.Activated = value.Activated
		ReportDeviceInfo.SoftwareList[idx] = ReportDeviceSoftwareInfo
		idx++
	}

	// Read interface name from library and match it with uplink name from
	// global status. Only report the uplinks.
	interfaces, _ := psutilnet.Interfaces()
	ReportDeviceInfo.Network = make([]*zmet.ZInfoNetwork,
		len(deviceNetworkStatus.UplinkStatus))
	for index, uplink := range deviceNetworkStatus.UplinkStatus {
		for _, interfaceDetail := range interfaces {
			if uplink.IfName == interfaceDetail.Name {
				ReportDeviceNetworkInfo := new(zmet.ZInfoNetwork)
				ReportDeviceNetworkInfo.IPAddrs = make([]string, len(interfaceDetail.Addrs))
				for index, ip := range interfaceDetail.Addrs {
					// For compatibility we putt he first in the deprecated singleton
					if index == 0 {
						ReportDeviceNetworkInfo.IPAddr = *proto.String(ip.Addr)
					}
					ReportDeviceNetworkInfo.IPAddrs[index] = *proto.String(ip.Addr)
				}

				ReportDeviceNetworkInfo.MacAddr = *proto.String(interfaceDetail.HardwareAddr)
				ReportDeviceNetworkInfo.DevName = *proto.String(interfaceDetail.Name)
				ReportDeviceInfo.Network[index] = ReportDeviceNetworkInfo
			}
		}
	}
	ReportInfo.InfoContent = new(zmet.ZInfoMsg_Dinfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Dinfo); ok {
		x.Dinfo = ReportDeviceInfo
	}

	fmt.Println(ReportInfo)
	fmt.Println(" ")

	SendInfoProtobufStrThroughHttp(ReportInfo, iteration)
}

// XXX change caller filename to key which is uuid; not used for now
func PublishAppInfoToZedCloud(uuid string, aiStatus *types.AppInstanceStatus,
	iteration int) {
	fmt.Printf("PublishAppInfoToZedCloud uuid %s\n", uuid)
	// XXX if it was deleted we publish nothing; do we need to delete from
	// zedcloud?
	if aiStatus == nil {
		fmt.Printf("PublishAppInfoToZedCloud uuid %s deleted\n", uuid)
		return
	}
	var ReportInfo = &zmet.ZInfoMsg{}

	appType := new(zmet.ZInfoTypes)
	*appType = zmet.ZInfoTypes_ZiApp
	ReportInfo.Ztype = *appType
	ReportInfo.DevId = *proto.String(deviceId)

	ReportAppInfo := new(zmet.ZInfoApp)

	ReportAppInfo.AppID = aiStatus.UUIDandVersion.UUID.String()
	ReportAppInfo.SystemApp = false
	ReportAppInfo.AppName = aiStatus.DisplayName

	ds := LookupDomainStatusUUID(aiStatus.UUIDandVersion.UUID.String())
	if ds == nil {
		log.Printf("Did not find status(DomainId) for domainUUID %s\n",
			aiStatus.UUIDandVersion.UUID.String())
	} else {
		ReportAppInfo.Activated = aiStatus.Activated && verifyDomainExists(ds.DomainId)
	}

	ReportAppInfo.Error = aiStatus.Error

	if (aiStatus.ErrorTime).IsZero() {
		log.Println("ErrorTime is empty...so do not fill it")
	} else {
		errTime, _ := ptypes.TimestampProto(aiStatus.ErrorTime)
		ReportAppInfo.ErrorTime = errTime
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

			ReportAppInfo.SoftwareList[idx] = ReportSoftwareInfo
		}
	}
	ReportInfo.InfoContent = new(zmet.ZInfoMsg_Ainfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Ainfo); ok {
		x.Ainfo = ReportAppInfo
	}

	fmt.Println(ReportInfo)
	fmt.Println(" ")

	SendInfoProtobufStrThroughHttp(ReportInfo, iteration)
}

// This function is called per change, hence needs to try over all uplinks
// send report on each uplink (This means the iteration arg is not useful)
// For each uplink we try different source IPs until we find a working one.
func SendInfoProtobufStrThroughHttp(ReportInfo *zmet.ZInfoMsg, iteration int) {

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		fmt.Println("marshaling error: ", err)
		return
	}

	for i, uplink := range deviceNetworkStatus.UplinkStatus {
		intf := uplink.IfName
		addrCount := types.CountLocalAddrAny(deviceNetworkStatus, intf)
		if debug {
			log.Printf("Connecting to %s using intf %s i %d #sources %d\n",
				statusUrl, intf, i, addrCount)
		}

		for retryCount := 0; retryCount < addrCount; retryCount += 1 {
			localAddr, err := types.GetLocalAddrAny(deviceNetworkStatus,
				retryCount, intf)
			if err != nil {
				log.Fatal(err)
			}
			localTCPAddr := net.TCPAddr{IP: localAddr}
			if debug {
				fmt.Printf("Connecting to %s using intf %s source %v\n",
					statusUrl, intf, localTCPAddr)
			}
			d := net.Dialer{LocalAddr: &localTCPAddr}
			transport := &http.Transport{
				TLSClientConfig: tlsConfig,
				Dial:            d.Dial,
			}
			client := &http.Client{Transport: transport}

			resp, err := client.Post("https://"+statusUrl,
				"application/x-proto-binary",
				bytes.NewBuffer(data))
			if err != nil {
				fmt.Println(err)
				continue
			}
			defer resp.Body.Close()
			connState := resp.TLS
			if connState == nil {
				log.Println("no TLS connection state")
				continue
			}

			if connState.OCSPResponse == nil ||
				!stapledCheck(connState) {
				if connState.OCSPResponse == nil {
					log.Printf("no OCSP response for %s\n",
						configUrl)
				} else {
					log.Printf("OCSP stapled check failed for %s\n",
						configUrl)
				}
				//XXX OSCP is not implemented in cloud side so
				// commenting out it for now. Should be:
				// continue
			}

			switch resp.StatusCode {
			case http.StatusOK:
				if debug {
					fmt.Printf("SendInfoProtobufStrThroughHttp to %s using intf %s source %v StatusOK\n",
						statusUrl, intf, localTCPAddr)
				}
				return
			default:
				fmt.Printf("SendInfoProtobufStrThroughHttp to %s using intf %s source %v statuscode %d %s\n",
					statusUrl, intf, localTCPAddr,
					resp.StatusCode, http.StatusText(resp.StatusCode))
				if debug {
					fmt.Printf("received response %v\n",
						resp)
				}
			}
		}
		log.Printf("All attempts to connect to %s using intf %s failed\n",
			statusUrl, intf)
	}
	log.Printf("All attempts to connect to %s failed\n", statusUrl)
}

// Each iteration we try a different uplink. For each uplink we try all
// its local IP addresses until we get a success.
func SendMetricsProtobufStrThroughHttp(ReportMetrics *zmet.ZMetricMsg,
	iteration int) {
	data, err := proto.Marshal(ReportMetrics)
	if err != nil {
		fmt.Println("marshaling error: ", err)
	}

	intf, err := types.GetUplinkAny(deviceNetworkStatus, iteration)
	if err != nil {
		log.Printf("SendMetricsProtobufStrThroughHttp: %s\n", err)
		return
	}
	addrCount := types.CountLocalAddrAny(deviceNetworkStatus, intf)
	if debug {
		log.Printf("Connecting to %s using intf %s interation %d #sources %d\n",
			metricsUrl, intf, iteration, addrCount)
	}
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAny(deviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Fatal(err)
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		if debug {
			fmt.Printf("Connecting to %s using intf %s source %v\n",
				metricsUrl, intf, localTCPAddr)
		}
		d := net.Dialer{LocalAddr: &localTCPAddr}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			Dial:            d.Dial,
		}
		client := &http.Client{Transport: transport}

		resp, err := client.Post("https://"+metricsUrl,
			"application/x-proto-binary", bytes.NewBuffer(data))
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer resp.Body.Close()
		connState := resp.TLS
		if connState == nil {
			log.Println("no TLS connection state")
			continue
		}

		if connState.OCSPResponse == nil ||
			!stapledCheck(connState) {
			if connState.OCSPResponse == nil {
				log.Printf("no OCSP response for %s\n",
					metricsUrl)
			} else {
				log.Printf("OCSP stapled check failed for %s\n",
					metricsUrl)
			}
			//XXX OSCP is not implemented in cloud side so
			// commenting out it for now. Should be:
			// continue
		}
		switch resp.StatusCode {
		case http.StatusOK:
			if debug {
				fmt.Printf("SendMetricsProtobufStrThroughHttp to %s using intf %s source %v StatusOK\n",
					metricsUrl, intf, localTCPAddr)
			}
			return
		default:
			fmt.Printf("SendMetricsProtobufStrThroughHttp to %s using intf %s source %v  statuscode %d %s\n",
				metricsUrl, intf, localTCPAddr,
				resp.StatusCode,
				http.StatusText(resp.StatusCode))
			if debug {
				fmt.Printf("received response %v\n", resp)
			}
		}
	}
	log.Printf("All attempts to connect to %s using intf %s failed\n",
		metricsUrl, intf)
}
