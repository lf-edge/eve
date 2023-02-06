package gostats

import (
	"fmt"
	"net"
	"runtime"
	"time"
)

// Statsd host:port pair
var Endpoint = "localhost:8125"

// collector
var c *collector = nil

// Collector implements the periodic grabbing of informational data from the
// runtime package and outputting it to statsd.
type collector struct {
	// PauseDur represents the interval between each set of stats output.
	// Defaults to 5 seconds.
	pauseDur time.Duration

	// EnableCPU determines whether CPU statistics will be output. Defaults to true.
	enableCPU bool

	// EnableMem determines whether memory statistics will be output. Defaults to true.
	enableMem bool

	// EnableGC determines whether garbage collection statistics will be output. EnableMem
	// must also be set to true for this to take affect. Defaults to true.
	enableGC bool

	// Bucket prefix
	prefix string

	// Connection handler
	conn net.Conn
}

// New creates a new Collector that will periodically output statistics to send.
func newCollector(prefix string, conn net.Conn) *collector {
	return &collector{
		pauseDur:  5 * time.Second,
		enableCPU: true,
		enableMem: true,
		enableGC:  true,
		prefix:    prefix,
		conn:      conn,
	}
}

// Run gathers statistics from package runtime and outputs them statsd,
// this will never return.
func (c *collector) run() {
	c.outputStats()

	// Gauges are a 'snapshot' rather than a histogram. Pausing for some interval
	// aims to get a 'recent' snapshot out before statsd flushes metrics.
	tick := time.NewTicker(c.pauseDur)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			c.outputStats()
		}
	}
}

type cpuStats struct {
	NumGoroutine uint64
	NumCgoCall   uint64
}

func (c *collector) outputStats() {
	if c.enableCPU {
		cStats := cpuStats{
			NumGoroutine: uint64(runtime.NumGoroutine()),
			NumCgoCall:   uint64(runtime.NumCgoCall()),
		}
		c.outputCPUStats(&cStats)
	}
	if c.enableMem {
		m := &runtime.MemStats{}
		runtime.ReadMemStats(m)
		c.outputMemStats(m)
		if c.enableGC {
			c.outputGCStats(m)
		}
	}
}

func (c *collector) outputCPUStats(s *cpuStats) {
	c.send("cpu.NumGoroutine", s.NumGoroutine)
	c.send("cpu.NumCgoCall", s.NumCgoCall)
}

func (c *collector) outputMemStats(m *runtime.MemStats) {
	// sys
	c.send("mem.sys.Sys", m.Sys)
	c.send("mem.sys.Lookups", m.Lookups)
	c.send("mem.sys.OtherSys", m.OtherSys)

	// common
	c.send("mem.com.Total_VM_Bytes_Reserved", m.Sys)
	c.send("mem.com.Live_Heap_Bytes_Allocated", m.Alloc)
	c.send("mem.com.Cumulative_Heap_Bytes_Allocated", m.TotalAlloc)
	c.send("mem.com.Total_Stack_Allocation", m.StackSys)
	c.send("mem.com.Other_Bytes_Allocation", m.OtherSys)

	// Heap
	c.send("mem.heap.Alloc", m.Alloc)
	c.send("mem.heap.TotalAlloc", m.TotalAlloc)
	c.send("mem.heap.Mallocs", m.Mallocs)
	c.send("mem.heap.Frees", m.Frees)
	c.send("mem.heap.HeapAlloc", m.HeapAlloc)
	c.send("mem.heap.HeapSys", m.HeapSys)
	c.send("mem.heap.HeapIdle", m.HeapIdle)
	c.send("mem.heap.HeapInuse", m.HeapInuse)
	c.send("mem.heap.HeapReleased", m.HeapReleased)
	c.send("mem.heap.HeapObjects", m.HeapObjects)

	// Stack
	c.send("mem.stack.StackSys", m.StackSys)
	c.send("mem.stack.StackInuse", m.StackInuse)
	c.send("mem.stack.MSpanInuse", m.MSpanInuse)
	c.send("mem.stack.MSpanSys", m.MSpanSys)
	c.send("mem.stack.MCacheInuse", m.MCacheInuse)
	c.send("mem.stack.MCacheSys", m.MCacheSys)

}

func (c *collector) outputGCStats(m *runtime.MemStats) {
	c.send("mem.gc.GCSys", m.GCSys)
	c.send("mem.gc.NextGC", m.NextGC)
	c.send("mem.gc.LastGC", m.LastGC)
	c.send("mem.gc.PauseTotalNs", m.PauseTotalNs)
	c.send("mem.gc.Pause", m.PauseNs[(m.NumGC+255)%256])
	c.send("mem.gc.NumGC", uint64(m.NumGC))
}

func (c *collector) send(bucket string, value uint64) {
	buf := []byte(fmt.Sprintf("%v.%v:%v|g", c.prefix, bucket, value))
	n, err := c.conn.Write(buf)
	if err != nil {
		fmt.Printf("error sending data:  %s", err)
	} else if n != len(buf) {
		fmt.Printf("error short send: %d < %d", n, len(buf))
	}
}

func Collect(endpoint string, prefix string, pauseDuration int, cpu bool, mem bool, gc bool) error {
	conn, err := net.DialTimeout("udp", endpoint, 2*time.Second)
	if err != nil {
		return err
	}

	c = newCollector(prefix, conn)
	c.pauseDur = time.Duration(pauseDuration) * time.Second
	c.enableCPU = cpu
	c.enableMem = mem
	c.enableGC = gc

	go c.run()
	return nil
}
