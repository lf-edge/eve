package main

import (
	"fmt"
	"log"
	"time"
	"os"
	"os/signal"
	"syscall"
	"runtime"
	"bytes"
	"net/http"
	"./zmet"

	"github.com/golang/protobuf/proto"
)

// Device ID that we are going to use
const (
	myDeviceId string = "38455FA5-4132-4095-9AEF-F0A3CA242FA3"
	// Assume for time being that the status is being posted
	// to an REST API
	statusURL string = "http://192.168.1.8:8088/api/v1/devices/status"
)

// populate CPU metrics into given variable
func populateCpuMetrics(cpu *zmet.CpuMetric) {
	cpu.UpTime = 0		// FIXME
	cpu.CpuUtilization = 0	// FIXME
}

// populate Memory metrics into given variable
func populateMemoryMetrics(mem *zmet.MemoryMetric) {
	mem.UsedMem = 0		// FIXME
	mem.UsedPercentage = 0	// FIXME
	mem.MaxMem = 0		// FIXME
}

// populate Network metrics into given variable
func populateNetworkMetrics(net *zmet.NetworkMetric) {
	net.DevName = "eth0"	// FIXME
	net.TxBytes = 0		// FIXME
	net.RxBytes = 0		// FIXME
	net.TxRate = 0		// FIXME
	net.RxRate = 0		// FIXME
}

// count the number of network interfaces
func countNetDevs() int {
	fp, err := os.Open("/proc/net/dev")
	if err != nil {
		log.Fatal(err)
		return 0
	}
	defer os.Close(fp)
	data := make([]byte, 32*1024)
	lineSep := []byte{'\n'}
	lines := 0
	for {
		count, err := fp.Read(data)
		lines += bytes.Count(data[:count], lineSep)
		if err != nil {
			break
		}
	}
	return lines
}

// poll the system status, compose a metric message and return it
func pollSystemStatus() zmet.ZMetricMsg {
	// allocate container msg
	zmsg := new(zmet.ZMetricMsg)
	zmsg.DevID = myDeviceId
	zmsg.Ztype = zmet.ZmetricTypes_ZmDevice // Hard code Device metrics for now

	// allocate device metric message
	dmm := new(zmet.ZMetricMsg_Dm)
	dmm.CpuMetric = new(zmet.CpuMetric)
	populateCpuMetrics(&dmm.CpuMetric)

	// allocate network metric message
	dmm.MemoryMetric = new(zmet.MemoryMetric)
	populateMemoryMetrics(&dmm.MemoryMetric)

	netdevs := countNetDevs()
	fmt.Printf("We have %d interfaces\n", netdevs - 2)
	dmm.NetworkMetric = make([]*zmet.NetworkMetric, netdevs)
	populateNetworkMetrics(&dmm.network)

	return *zmsg
}

// take the given metric message, encode it, and send it
func sendSystemStatus(msg zmet.ZMetricMsg) {
	fmt.Println("Posting status for ", msg.DevID)
	data, err := proto.Marshal(&msg)
	if err != nil {
		panic(err)
	}
	_, err = http.Post(statusURL, "application/x-proto-binary",
		bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
}

func signalHandler(ch chan os.Signal) {
	sig := <-ch
	fmt.Println("\nCaught signal: ", sig)
	os.Exit(1)
}

func main() {
	signals := make(chan os.Signal)

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go signalHandler(signals)

	ticker := time.NewTicker(time.Second * 5)
	go func() {
		for range ticker.C {
			sendSystemStatus(pollSystemStatus())
		}
	}()

	for {
		runtime.Gosched()
	}
}
