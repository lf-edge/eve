package main

import (
	"bytes"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	psutilnet "github.com/shirou/gopsutil/net"
	"github.com/zededa/api/zmet"
	"github.com/zededa/go-provision/types"
	"net"
	"net/http"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	baseDirname   = "/var/tmp/zedrouter"
	configDirname = baseDirname + "/config"
)

func publishMetrics(iteration int) {
	cpuStorageStat := ExecuteXentopCmd()
	PublishMetricsToZedCloud(cpuStorageStat, iteration)
}

func metricsTimerTask() {
	iteration := 0
	ticker := time.NewTicker(time.Second * 60)
	for t := range ticker.C {
		log.Println("Tick at", t)
		publishMetrics(iteration)
		iteration += 1
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

func ExecuteXentopCmd() [][]string{
	var cpuStorageStat [][]string

	count := 0
	counter := 0
	arg1 := "xentop"
	arg2 := "-b"
	arg3 := "-d"
	arg4 := "1"
	arg5 := "-i"
	arg6 := "2"

	cmd1 := exec.Command(arg1, arg2, arg3, arg4, arg5, arg6)
	stdout, err := cmd1.Output()
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

	// Handle xentop failing above
	if len(cpuStorageStat) == 0 {
		log.Printf("No xentop? metrics: %s\n", ReportMetrics)
		SendMetricsProtobufStrThroughHttp(ReportMetrics, iteration)
		return
	}
	
	for arr := 1; arr < 2; arr++ {

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
		//memory related info for dom0...XXX later we will add for domU also..
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
			ReportDeviceMetric.Network = make([]*zmet.NetworkMetric, len(network))
			for netx, networkInfo := range network {
				networkDetails := new(zmet.NetworkMetric)
				networkDetails.IName = networkInfo.Name
				networkDetails.TxBytes = networkInfo.PacketsSent
				networkDetails.RxBytes = networkInfo.PacketsRecv
				networkDetails.TxDrops = networkInfo.Dropout
				networkDetails.RxDrops = networkInfo.Dropin
				//networkDetails.TxRate = //XXX TBD
				//networkDetails.RxRate = //XXX TBD
				ReportDeviceMetric.Network[netx] = networkDetails
			}
		}
		ReportMetrics.MetricContent = new(zmet.ZMetricMsg_Dm)
		if x, ok := ReportMetrics.GetMetricContent().(*zmet.ZMetricMsg_Dm); ok {
			x.Dm = ReportDeviceMetric
		}
	}

	log.Printf("Metrics: %s\n", ReportMetrics)
	SendMetricsProtobufStrThroughHttp(ReportMetrics, iteration)
}

func PublishDeviceInfoToZedCloud(iteration int) {

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

		productManufacturer, productName, productVersion, productSerial, productUuid := GetDeviceManufacturerInfo()
		ReportDeviceManufacturerInfo.Manufacturer = *proto.String(strings.TrimSpace(productManufacturer))
		ReportDeviceManufacturerInfo.ProductName = *proto.String(strings.TrimSpace(productName))
		ReportDeviceManufacturerInfo.Version = *proto.String(strings.TrimSpace(productVersion))
		ReportDeviceManufacturerInfo.SerialNumber = *proto.String(strings.TrimSpace(productSerial))
		ReportDeviceManufacturerInfo.UUID = *proto.String(strings.TrimSpace(productUuid))
		ReportDeviceInfo.Minfo = ReportDeviceManufacturerInfo
	} else {
		log.Println("fill manufacturer info for arm...") //XXX FIXME
	}
	ReportDeviceSoftwareInfo := new(zmet.ZInfoSW)
	systemHost, err := host.Info()
	if err != nil {
		log.Println(err)
	}
	ReportDeviceSoftwareInfo.SwVersion = systemHost.KernelVersion //XXX for now we are filling kernel version...
	ReportDeviceSoftwareInfo.SwHash = *proto.String(" ")
	ReportDeviceInfo.Software = ReportDeviceSoftwareInfo

	//read interface name from library
	//and match it with uplink name from
	//global status...
	interfaces, _ := psutilnet.Interfaces()
	ReportDeviceInfo.Network = make([]*zmet.ZInfoNetwork,
		len(deviceNetworkStatus.UplinkStatus))
	for index, uplink := range deviceNetworkStatus.UplinkStatus {
		for _, interfaceDetail := range interfaces {
			if uplink.IfName == interfaceDetail.Name {
				ReportDeviceNetworkInfo := new(zmet.ZInfoNetwork)
				for ip := 0; ip < len(interfaceDetail.Addrs)-1; ip++ {
					ReportDeviceNetworkInfo.IPAddr = *proto.String(interfaceDetail.Addrs[ip].Addr)
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

func PublishHypervisorInfoToZedCloud(iteration int) {

	var ReportInfo = &zmet.ZInfoMsg{}

	hypervisorType := new(zmet.ZInfoTypes)
	*hypervisorType = zmet.ZInfoTypes_ZiHypervisor
	ReportInfo.Ztype = *hypervisorType
	ReportInfo.DevId = *proto.String(deviceId)

	ReportHypervisorInfo := new(zmet.ZInfoHypervisor)
	cpuInfo, err := cpu.Info()
	if err != nil {
		log.Println(err)
	} else {
		ReportHypervisorInfo.Ncpu = *proto.Uint32(uint32(len(cpuInfo)))
	}
	ram, err := mem.VirtualMemory()
	if err != nil {
		log.Println(err)
	} else {
		ReportHypervisorInfo.Memory = *proto.Uint64(uint64(ram.Total))
	}
	d, err := disk.Usage("/")
	if err != nil {
		log.Println(err)
	} else {
		ReportHypervisorInfo.Storage = *proto.Uint64(uint64(d.Total))
	}
	ReportDeviceSoftwareInfo := new(zmet.ZInfoSW)

	dict := ExecuteXlInfoCmd()
	ReportDeviceSoftwareInfo.SwVersion = *proto.String(dict["xen_version"])

	ReportDeviceSoftwareInfo.SwHash = *proto.String(" ")
	ReportHypervisorInfo.Software = ReportDeviceSoftwareInfo

	ReportInfo.InfoContent = new(zmet.ZInfoMsg_Hinfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Hinfo); ok {
		x.Hinfo = ReportHypervisorInfo
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
	uuidStr := aiStatus.UUIDandVersion.Version
	var ReportInfo = &zmet.ZInfoMsg{}

	appType := new(zmet.ZInfoTypes)
	*appType = zmet.ZInfoTypes_ZiApp
	ReportInfo.Ztype = *appType
	ReportInfo.DevId = *proto.String(deviceId)

	ReportAppInfo := new(zmet.ZInfoApp)
	ReportAppInfo.AppID = *proto.String(uuidStr)

	// XXX:TBD should come from xen usage
	ReportAppInfo.Ncpu = *proto.Uint32(uint32(0))
	ReportAppInfo.Memory = *proto.Uint32(uint32(0))
	//ReportAppInfo.Storage	=	*proto.Uint32(uint32(0)) //XXX FIXME TBD

	// XXX: should be multiple entries, one per storage item
	ReportVerInfo := new(zmet.ZInfoSW)
	if len(aiStatus.StorageStatusList) == 0 {
		log.Printf("storage status detail is empty so ignoring")
	} else {
		sc := aiStatus.StorageStatusList[0]
		ReportVerInfo.SwHash = *proto.String(sc.ImageSha256)
	}
	ReportVerInfo.SwVersion = *proto.String(aiStatus.UUIDandVersion.Version)

	// XXX: this should be a list
	ReportAppInfo.Software = ReportVerInfo

	ReportInfo.InfoContent = new(zmet.ZInfoMsg_Ainfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Ainfo); ok {
		x.Ainfo = ReportAppInfo
	}

	fmt.Println(ReportInfo)
	fmt.Println(" ")

	SendInfoProtobufStrThroughHttp(ReportInfo, iteration)
}

// This function is called per change, hence needs to try over all uplinks
// send report on each uplink (XXX means iteration arg is not useful)
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
		// XXX makes logfile too long; debug flag?
		log.Printf("Connecting to %s using intf %s i %d #sources %d\n",
			statusUrl, intf, i, addrCount)

		for retryCount := 0; retryCount < addrCount; retryCount += 1 {
			localAddr, err := types.GetLocalAddrAny(deviceNetworkStatus,
				retryCount, intf)
			if err != nil {
				log.Fatal(err)
			}
			localTCPAddr := net.TCPAddr{IP: localAddr}
			// XXX makes logfile too long; debug flag?
			fmt.Printf("Connecting to %s using intf %s source %v\n",
				statusUrl, intf, localTCPAddr)
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
			switch resp.StatusCode {
			case http.StatusOK:
				fmt.Printf("SendInfoProtobufStrThroughHttp StatusOK\n")
			default:
				fmt.Printf("SendInfoProtobufStrThroughHttp statuscode %d %s\n",
					resp.StatusCode, http.StatusText(resp.StatusCode))
				fmt.Printf("received response %v\n", resp)
			}
			break
		}
		log.Printf("All attempts to connect to %s using intf %s failed\n",
			statusUrl, intf)
	}
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
	// XXX makes logfile too long; debug flag?
	log.Printf("Connecting to %s using intf %s interation %d #sources %d\n",
		metricsUrl, intf, iteration, addrCount)
	
	for retryCount := 0; retryCount < addrCount; retryCount += 1 {
		localAddr, err := types.GetLocalAddrAny(deviceNetworkStatus,
			retryCount, intf)
		if err != nil {
			log.Fatal(err)
		}
		localTCPAddr := net.TCPAddr{IP: localAddr}
		// XXX makes logfile too long; debug flag?
		fmt.Printf("Connecting to %s using intf %s source %v\n",
			metricsUrl, intf, localTCPAddr)
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
		switch resp.StatusCode {
		case http.StatusOK:
			fmt.Printf("SendMetricsProtobufStrThroughHttp StatusOK\n")
		default:
			fmt.Printf("SendMetricsProtobufStrThroughHttp statuscode %d %s\n",
				resp.StatusCode, http.StatusText(resp.StatusCode))
			fmt.Printf("received response %v\n", resp)
		}
		return
	}
	log.Printf("All attempts to connect to %s using intf %s failed\n",
		metricsUrl, intf)
}
