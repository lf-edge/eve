package main

import (
	"fmt"
	"log"
	"os/exec"
	"protometrics"
	"regexp"
	"strconv"
	"strings"
	"io/ioutil"
	"github.com/golang/protobuf/proto"
	"time"
	"net/http"
	"bytes"
)

var networkStat [][]string
var cpuStorageStat [][]string

const (
	statusURL string = "http://192.168.1.8:8088/api/v1/edgedevice/info"
)

func main() {

	DeviceCpuStorageStat()
	DeviceNetworkStat()
	MakeProtobufStructure()

	ticker := time.NewTicker(time.Second  * 15)
        for t := range ticker.C {

		fmt.Println("Tick at", t)
		DeviceCpuStorageStat()
		DeviceNetworkStat()
		MakeProtobufStructure()
	}
}

func DeviceCpuStorageStat() {
	count := 0
	counter := 0
	app0 := "sudo"
	app := "xentop"
	arg0 := "-b"
	//arg1 := "-n"
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
	//fmt.Println(string(stdout))

	xentopInfo := fmt.Sprintf("%s", stdout)

	splitXentopInfo := strings.Split(xentopInfo, "\n")

	splitXentopInfoLength := len(splitXentopInfo)
	//fmt.Println("splitXentopInfoLength: ",splitXentopInfoLength)
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
	//var finalOutput [length] string
	finalOutput := make([][]string, length)
	//fmt.Println(len(finalOutput))

	for j := start; j < splitXentopInfoLength-1; j++ {

		str := fmt.Sprintf(splitXentopInfo[j])
		splitOutput := regexp.MustCompile(" ")
		finalOutput[j-start] = splitOutput.Split(str, -1)
	}

	//var cpuStorageStat [][]string
	cpuStorageStat = make([][]string, length)

	for i := range cpuStorageStat {
		cpuStorageStat[i] = make([]string, 20)
	}

	for f := 0; f < length; f++ {

		for out := 0; out < len(finalOutput[f]); out++ {

			//fmt.Println(finalOutput[f][out])
			matched, err := regexp.MatchString("[A-Za-z0-9]+", finalOutput[f][out])
			fmt.Sprint(err)
			if matched {

				if finalOutput[f][out] == "no" {

				} else if finalOutput[f][out] == "limit" {
					counter++
					cpuStorageStat[f][counter] = "no limit"
					//fmt.Println("f : out: ",f,counter,cpuStorageStat[f][counter])
				} else {
					counter++
					cpuStorageStat[f][counter] = finalOutput[f][out]
					//fmt.Println("f : out: ",f,counter,cpuStorageStat[f][counter])
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

	//var networkStat [][]string
	networkStat = make([][]string, length)

	for i := range networkStat {
		networkStat[i] = make([]string, 20)
	}

	for f := 0; f < length; f++ {

		for out := 0; out < len(finalNetworStatOutput[f]); out++ {

			//fmt.Println(finalNetworStatOutput[f][out])
			matched, err := regexp.MatchString("[A-Za-z0-9]+", finalNetworStatOutput[f][out])
			fmt.Sprint(err)
			if matched {
				counter++
				networkStat[f][counter] = finalNetworStatOutput[f][out]
				//fmt.Println("f : out: ",f,counter,networkStat[f][counter])
			}
		}
		counter = 0
	}
}

func MakeProtobufStructure() {

	var ReportMetricsToZedCloud = &protometrics.ZMetricMsg{}

	ReportDeviceMetric := new(protometrics.DeviceMetric)
	ReportDeviceMetric.Cpu = new(protometrics.CpuMetric)
	ReportDeviceMetric.Memory = new(protometrics.MemoryMetric)

	ReportDeviceMetric.Network = make([]*protometrics.NetworkMetric, len(networkStat)-2)

	ReportMetricsToZedCloud.DevID = proto.String("38455FA5-4132-4095-9AEF-F0A3CA242FA3")
	ReportZmetric := new(protometrics.ZmetricTypes)
	*ReportZmetric = protometrics.ZmetricTypes_ZmDevice
	ReportMetricsToZedCloud.Ztype = ReportZmetric

	for arr := 1; arr < 2; arr++ {

		cpuTime, _ := strconv.ParseUint(cpuStorageStat[arr][3], 10, 0)
		ReportDeviceMetric.Cpu.UpTime = proto.Uint32(uint32(cpuTime))

		cpuUsedInPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][4], 10)
		ReportDeviceMetric.Cpu.CpuUtilization = proto.Float32(float32(cpuUsedInPercent))

		memory, _ := strconv.ParseUint(cpuStorageStat[arr][5], 10, 0)
		ReportDeviceMetric.Memory.UsedMem = proto.Uint32(uint32(memory))

		memoryUsedInPercent, _ := strconv.ParseFloat(cpuStorageStat[arr][6], 10)
		ReportDeviceMetric.Memory.UsedPercentage = proto.Float32(float32(memoryUsedInPercent))

		maxMemory, _ := strconv.ParseUint(cpuStorageStat[arr][7], 10, 0)
		ReportDeviceMetric.Memory.MaxMem = proto.Uint32(uint32(maxMemory))

		for net := 2; net < len(networkStat); net++ {

			//fmt.Println(networkStat[2][1])
			networkDetails := new(protometrics.NetworkMetric)

			networkDetails.DevName = proto.String(networkStat[net][1])

			txBytes, _ := strconv.ParseUint(networkStat[net][10], 10, 0)
			networkDetails.TxBytes = proto.Uint64(txBytes)
			rxBytes, _ := strconv.ParseUint(networkStat[net][2], 10, 0)
			networkDetails.RxBytes = proto.Uint64(rxBytes)

			txDrops, _ := strconv.ParseUint(networkStat[net][13], 10, 0)
			networkDetails.TxDrops = proto.Uint64(txDrops)
			rxDrops, _ := strconv.ParseUint(networkStat[net][5], 10, 0)
			networkDetails.RxDrops = proto.Uint64(rxDrops)
			// assume rx and tx rates 0 for now...
			txRate, _ := strconv.ParseUint("0", 10, 0)
			networkDetails.TxRate = proto.Uint64(txRate)
			rxRate, _ := strconv.ParseUint("0", 10, 0)
			networkDetails.RxRate = proto.Uint64(rxRate)

			ReportDeviceMetric.Network[net-2] = networkDetails
			//fmt.Println(ReportDeviceMetric.Network[net-2])
			ReportMetricsToZedCloud.Dm = ReportDeviceMetric

		}

	}

	fmt.Println(ReportMetricsToZedCloud)
	fmt.Println(" ")

	data, err := proto.Marshal(ReportMetricsToZedCloud)
	if err != nil {
		fmt.Println("marshaling error: ", err)
	}
	_, err = http.Post(statusURL, "application/x-proto-binary",
		bytes.NewBuffer(data))
	if err != nil {
		fmt.Println(err)
	}

	newTest := &protometrics.ZMetricMsg{}
	err = proto.Unmarshal(data, newTest)
	if err != nil {
		log.Fatal("unmarshaling error: ", err)
	}

	log.Println(newTest)

}
