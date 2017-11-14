package main

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"io/ioutil"
	"github.com/zededa/go-provision/types"
	"github.com/golang/protobuf/proto"
	"github.com/zededa/api/zmet"
	"time"
	"bytes"
	"github.com/matishsiao/goInfo"
	"github.com/shirou/gopsutil/mem"
	// "github.com/shirou/gopsutil/cpu" //XXX will use it later
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/net"
)

var networkStat [][]string
var cpuStorageStat [][]string


func publishMetrics() {
	DeviceCpuStorageStat()
	DeviceNetworkStat()
	MakeMetricsProtobufStructure()
}


func metricsTimerTask() {
	ticker := time.NewTicker(time.Second  * 60)
	for t := range ticker.C {
		fmt.Println("Tick at", t)
		publishMetrics();
	}
}

func DeviceCpuStorageStat() {
	count := 0
	counter := 0
	app0 := "sudo"
	app := "xentop"
	arg0 := "-b"
	arg4 := "-d"
	arg5 := "1"
	arg2 := "-i"
	arg3 := "2"

	cmd1 := exec.Command(app0, app, arg0, arg4, arg5, arg2, arg3)
	stdout, err := cmd1.Output()
	if err != nil {
		println(err.Error())
		return
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
}

func DeviceNetworkStat() {

	counter := 0
	netDetails,err := ioutil.ReadFile("/proc/net/dev")
	if err != nil {
		fmt.Println(err)
	}

	networkInfo := fmt.Sprintf("%s", netDetails)
	splitNetworkInfo := strings.Split(networkInfo, "\n")
	splitNetworkInfoLength := len(splitNetworkInfo)
	length := splitNetworkInfoLength - 1

	finalNetworStatOutput := make([][]string, length)

	for j := 0; j < splitNetworkInfoLength-1; j++ {

		str := fmt.Sprintf(splitNetworkInfo[j])
		splitOutput := regexp.MustCompile(" ")
		finalNetworStatOutput[j] = splitOutput.Split(str, -1)
	}

	networkStat = make([][]string, length)

	for i := range networkStat {
		networkStat[i] = make([]string, 20)
	}

	for f := 0; f < length; f++ {

		for out := 0; out < len(finalNetworStatOutput[f]); out++ {

			matched, err := regexp.MatchString("[A-Za-z0-9]+", finalNetworStatOutput[f][out])
			fmt.Sprint(err)
			if matched {
				counter++
				networkStat[f][counter] = finalNetworStatOutput[f][out]
			}
		}
		counter = 0
	}
}

func MakeMetricsProtobufStructure() {

	var ReportMetrics = &zmet.ZMetricMsg{}

	ReportDeviceMetric := new(zmet.DeviceMetric)
	ReportDeviceMetric.Cpu		 = new(zmet.CpuMetric)
	ReportDeviceMetric.Memory	 = new(zmet.MemoryMetric)
	ReportDeviceMetric.Network	 = make([]*zmet.NetworkMetric, len(networkStat)-2)

	ReportMetrics.DevID = *proto.String(deviceId)
	ReportZmetric := new(zmet.ZmetricTypes)
	*ReportZmetric = zmet.ZmetricTypes_ZmDevice

	ReportMetrics.Ztype = *ReportZmetric

	for arr := 1; arr < 2; arr++ {

		cpuTime, _ := strconv.ParseUint(cpuStorageStat[arr][3], 10, 0)
		ReportDeviceMetric.Cpu.UpTime = *proto.Uint32(uint32(cpuTime))
		cpuUsedInPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][4], 10)
		ReportDeviceMetric.Cpu.CpuUtilization = *proto.Float64(float64(cpuUsedInPercent))

		memory, _ := strconv.ParseUint(cpuStorageStat[arr][5], 10, 0)
		ReportDeviceMetric.Memory.UsedMem = *proto.Uint32(uint32(memory))
		memoryUsedInPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][6], 10)
		ReportDeviceMetric.Memory.UsedPercentage = *proto.Float64(float64(memoryUsedInPercent))

		for net := 2; net < len(networkStat); net++ {

			networkDetails := new(zmet.NetworkMetric)
			networkDetails.IName = *proto.String(networkStat[net][1])

			txBytes, _ := strconv.ParseUint(networkStat[net][10], 10, 0)
			networkDetails.TxBytes = *proto.Uint64(txBytes)
			rxBytes, _ := strconv.ParseUint(networkStat[net][2], 10, 0)
			networkDetails.RxBytes = *proto.Uint64(rxBytes)

			txDrops, _ := strconv.ParseUint(networkStat[net][13], 10, 0)
			networkDetails.TxDrops = *proto.Uint64(txDrops)
			rxDrops, _ := strconv.ParseUint(networkStat[net][5], 10, 0)
			networkDetails.RxDrops = *proto.Uint64(rxDrops)
			// assume rx and tx rates 0 for now...
			txRate, _ := strconv.ParseUint("0", 10, 0)
			networkDetails.TxRate = *proto.Uint64(txRate)
			rxRate, _ := strconv.ParseUint("0", 10, 0)
			networkDetails.RxRate = *proto.Uint64(rxRate)

			ReportDeviceMetric.Network[net-2] = networkDetails
			ReportMetrics.MetricContent = new(zmet.ZMetricMsg_Dm)
			if x, ok := ReportMetrics.GetMetricContent().(*zmet.ZMetricMsg_Dm); ok {
				x.Dm = ReportDeviceMetric
			}
		}
	}

	log.Printf("%s\n", ReportMetrics)
	SendMetricsProtobufStrThroughHttp(ReportMetrics)
}

func MakeDeviceInfoProtobufStructure () {

	var ReportInfo = &zmet.ZInfoMsg{}

	deviceType		:= new(zmet.ZInfoTypes)
	*deviceType		=	zmet.ZInfoTypes_ZiDevice
	ReportInfo.Ztype	=	*deviceType
	ReportInfo.DevId	=	*proto.String(deviceId)

	ReportDeviceInfo	:=	new(zmet.ZInfoDevice)

	ReportDeviceInfo.MachineArch	=	*proto.String(goInfo.GetInfo().Platform)
	ReportDeviceInfo.CpuArch	=	*proto.String(goInfo.GetInfo().Platform)
	ReportDeviceInfo.Platform	=	*proto.String(goInfo.GetInfo().Platform)
	ReportDeviceInfo.Ncpu		=	*proto.Uint32(uint32(goInfo.GetInfo().CPUs))
	ram, err := mem.VirtualMemory()
	if err != nil {
		log.Println(err)
	}
	ReportDeviceInfo.Memory     =   *proto.Uint64(uint64(ram.Total))
	d,err := disk.Usage("/")
	if err != nil {
		log.Println(err)
	}
	ReportDeviceInfo.Storage    =   *proto.Uint64(uint64(d.Total))

	ReportDeviceInfo.Devices	=	make([]*zmet.ZinfoPeripheral,	1)
	ReportDevicePeripheralInfo	:=	new(zmet.ZinfoPeripheral)

	// XXX report real data from /proc and dmiinfo akin to device-steps
	for	index,_	:=	range ReportDeviceInfo.Devices	{

		PeripheralType					:=		new(zmet.ZPeripheralTypes)
		ReportDevicePeripheralManufacturerInfo		:=		new(zmet.ZInfoManufacturer)
		*PeripheralType						=		zmet.ZPeripheralTypes_ZpNone
		ReportDevicePeripheralInfo.Ztype			=		*PeripheralType
		ReportDevicePeripheralInfo.Pluggable			=		*proto.Bool(false)
		// XXX report real data from /proc and dmiinfo akin to device-steps
		ReportDevicePeripheralManufacturerInfo.Manufacturer	=		*proto.String(" ")
		ReportDevicePeripheralManufacturerInfo.ProductName	=		*proto.String(" ")
		ReportDevicePeripheralManufacturerInfo.Version		=		*proto.String(" ")
		ReportDevicePeripheralManufacturerInfo.SerialNumber	=		*proto.String(" ")
		ReportDevicePeripheralManufacturerInfo.UUID		=		*proto.String(" ")
		ReportDevicePeripheralInfo.Minfo			=		ReportDevicePeripheralManufacturerInfo
		ReportDeviceInfo.Devices[index]				=		ReportDevicePeripheralInfo
	}

	// XXX report real data from /proc and dmiinfo akin to device-steps
	ReportDeviceManufacturerInfo	:=	new(zmet.ZInfoManufacturer)
	ReportDeviceManufacturerInfo.Manufacturer		=		*proto.String(" ")
	ReportDeviceManufacturerInfo.ProductName		=		*proto.String(" ")
	ReportDeviceManufacturerInfo.Version			=		*proto.String(" ")
	ReportDeviceManufacturerInfo.SerialNumber		=		*proto.String(" ")
	ReportDeviceManufacturerInfo.UUID			=		*proto.String(" ")
	ReportDeviceInfo.Minfo					=		ReportDeviceManufacturerInfo

	ReportDeviceSoftwareInfo	:=	new(zmet.ZInfoSW)
	ReportDeviceSoftwareInfo.SwVersion	=		*proto.String(" ")
	ReportDeviceSoftwareInfo.SwHash		=		*proto.String(" ")
	ReportDeviceInfo.Software		=		ReportDeviceSoftwareInfo

	//find	all	network	related	info...
	interfaces,_	:=	net.Interfaces()
	ReportDeviceInfo.Network	=	make([]*zmet.ZInfoNetwork,	len(interfaces))
	for	index,val	:=	range	interfaces	{

		ReportDeviceNetworkInfo	:=	new(zmet.ZInfoNetwork)
		for	ip := 0;ip < len(val.Addrs) - 1;ip++ {
			ReportDeviceNetworkInfo.IPAddr	=	*proto.String(val.Addrs[0].Addr)
		}

		ReportDeviceNetworkInfo.MacAddr		=	*proto.String(val.HardwareAddr)
		ReportDeviceNetworkInfo.DevName		=	*proto.String(val.Name)
		ReportDeviceInfo.Network[index]		=	ReportDeviceNetworkInfo

	}
	ReportInfo.InfoContent = new(zmet.ZInfoMsg_Dinfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Dinfo); ok {
		x.Dinfo = ReportDeviceInfo
	}

	fmt.Println(ReportInfo)
	fmt.Println(" ")

	SendInfoProtobufStrThroughHttp(ReportInfo)
}

func MakeHypervisorInfoProtobufStructure (){

	var ReportInfo		=	&zmet.ZInfoMsg{}

	hypervisorType := new(zmet.ZInfoTypes)
	*hypervisorType		=	zmet.ZInfoTypes_ZiHypervisor
	ReportInfo.Ztype	=	*hypervisorType
	ReportInfo.DevId	=	*proto.String(deviceId)

	// XXX report real data from /proc and dmiinfo akin to device-steps
	ReportHypervisorInfo := new(zmet.ZInfoHypervisor)
	ReportHypervisorInfo.Ncpu		=	*proto.Uint32(uint32(goInfo.GetInfo().CPUs))
	memory, _ := strconv.ParseUint(cpuStorageStat[1][5], 10, 0)
	ReportHypervisorInfo.Memory		=	*proto.Uint64(uint64(memory))
	d,err := disk.Usage("/")
	if err != nil {
		log.Println(err)
	}
	ReportHypervisorInfo.Storage		=	*proto.Uint64(uint64(d.Total))

	ReportDeviceSoftwareInfo := new(zmet.ZInfoSW)
	ReportDeviceSoftwareInfo.SwVersion	=	*proto.String(" ")
	ReportDeviceSoftwareInfo.SwHash		=	*proto.String(" ")
	ReportHypervisorInfo.Software		=	ReportDeviceSoftwareInfo

	ReportInfo.InfoContent	=	new(zmet.ZInfoMsg_Hinfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Hinfo); ok {
		x.Hinfo = ReportHypervisorInfo
	}

	fmt.Println(ReportInfo)
	fmt.Println(" ")

	SendInfoProtobufStrThroughHttp(ReportInfo)
}

func publishAiInfoToCloud(aiStatus *types.AppInstanceStatus) {

	var ReportInfo		=	&zmet.ZInfoMsg{}
	var uuidStr string	=	aiStatus.UUIDandVersion.UUID.String()

	appType := new(zmet.ZInfoTypes)
	*appType		=	zmet.ZInfoTypes_ZiApp
	ReportInfo.Ztype	=	*appType
	ReportInfo.DevId	=	*proto.String(deviceId)

	ReportAppInfo		:=	new(zmet.ZInfoApp)
	ReportAppInfo.AppID	=	*proto.String(uuidStr)

	// XXX:TBD should come from xen usage
	ReportAppInfo.Ncpu		=	*proto.Uint32(uint32(0))
	ReportAppInfo.Memory	=	*proto.Uint32(uint32(0))
	ReportAppInfo.Storage	=	*proto.Uint32(uint32(0))

	// XXX: should be multiple entries, one per storage item
	ReportVerInfo			:=	new(zmet.ZInfoSW)
	if len(aiStatus.StorageStatusList) == 0 {
		log.Printf("storage status detail is empty so ignoring")
	}else{
		sc			:=	aiStatus.StorageStatusList[0]
		ReportVerInfo.SwHash	=	*proto.String(sc.ImageSha256)
	}
	ReportVerInfo.SwVersion		=	*proto.String(aiStatus.UUIDandVersion.Version)

	// XXX: this should be a list
	ReportAppInfo.Software		=	ReportVerInfo

	ReportInfo.InfoContent		=	new(zmet.ZInfoMsg_Ainfo)
	if x, ok := ReportInfo.GetInfoContent().(*zmet.ZInfoMsg_Ainfo); ok {
		x.Ainfo = ReportAppInfo
	}

	fmt.Println(ReportInfo)
	fmt.Println(" ")

	SendInfoProtobufStrThroughHttp(ReportInfo)
}

func SendInfoProtobufStrThroughHttp (ReportInfo *zmet.ZInfoMsg) {

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		fmt.Println("marshaling error: ", err)
	}

	_, err = cloudClient.Post("https://"+statusUrl, "application/x-proto-binary", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println(err)
	}
}

func SendMetricsProtobufStrThroughHttp (ReportMetrics *zmet.ZMetricMsg) {

	data, err := proto.Marshal(ReportMetrics)
	if err != nil {
		fmt.Println("marshaling error: ", err)
	}

	_, err = cloudClient.Post("https://"+metricsUrl, "application/x-proto-binary", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println(err)
	}
}
