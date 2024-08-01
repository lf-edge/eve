// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

var (
	listenDebugRunning  atomic.Bool
	psiCollectorRunning atomic.Bool
	psiCollectorCancel  context.CancelFunc
)

func roundToMb(b uint64) uint64 {
	kb := (b + 512) / 1024
	mb := (kb + 512) / 1024
	return mb
}

func logMemUsage(log *base.LogObject, file *os.File) {
	var m runtime.MemStats

	runtime.ReadMemStats(&m)
	log.Functionf("Alloc %d Mb, TotalAlloc %d Mb, Sys %d Mb, NumGC %d",
		roundToMb(m.Alloc), roundToMb(m.TotalAlloc), roundToMb(m.Sys), m.NumGC)

	if file != nil {
		// This goes to /persist/agentdebug/<agentname>/sigusr2 file
		// And there in not much difference from the above log except the CRNL at the end.
		statString := fmt.Sprintf("Alloc %d Mb, TotalAlloc %d Mb, Sys %d Mb, NumGC %d\n",
			roundToMb(m.Alloc), roundToMb(m.TotalAlloc), roundToMb(m.Sys), m.NumGC)
		file.WriteString(statString)
	}
}

// Print in sorted order based on top bytes
func logMemAllocationSites(log *base.LogObject, file *os.File) {
	reportZeroInUse := false
	numSites, sites := GetMemAllocationSites(reportZeroInUse)
	log.Warnf("alloc %d sites len %d", numSites, len(sites))
	sort.Slice(sites,
		func(i, j int) bool {
			return sites[i].InUseBytes > sites[j].InUseBytes ||
				(sites[i].InUseBytes == sites[j].InUseBytes &&
					sites[i].AllocBytes > sites[j].AllocBytes)
		})
	for _, site := range sites {
		log.Warnf("alloc %d bytes %d objects total %d/%d at:\n%s",
			site.InUseBytes, site.InUseObjects, site.AllocBytes,
			site.AllocObjects, site.PrintedStack)

		if file != nil {
			// This goes to /persist/agentdebug/<agentname>/sigusr2 file
			// And there in not much difference from the above log except the CRNL at the end.
			statString := fmt.Sprintf("alloc %d bytes %d objects total %d/%d at:\n%s\n",
				site.InUseBytes, site.InUseObjects, site.AllocBytes,
				site.AllocObjects, site.PrintedStack)
			file.WriteString(statString)
		}
	}
}

func dumpMemoryInfo(log *base.LogObject, fileName string) {
	log.Warnf("SIGUSR2 triggered memory info:\n")
	sigUsr2File, err := os.OpenFile(fileName,
		os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0755)
	if err != nil {
		log.Errorf("handleSignals: Error opening file %s with: %s", fileName, err)
	} else {
		// This goes to /persist/agentdebug/<agentname>/sigusr2 file
		_, err := sigUsr2File.WriteString("SIGUSR2 triggered memory info:\n")
		if err != nil {
			log.Errorf("could not write to %s: %+v", fileName, err)
		}
	}

	logMemUsage(log, sigUsr2File)
	logMemAllocationSites(log, sigUsr2File)
	if sigUsr2File != nil {
		sigUsr2File.Close()
	}
}

func writeOrLog(log *base.LogObject, w io.Writer, msg string) {
	if _, err := w.Write([]byte(msg)); err != nil {
		log.Errorf("Could not write to %+v: %+v", w, err)
	}
}

// ListenDebug starts an HTTP server on localhost:6543 that provides various debugging capabilities.
// It sets up several endpoints for profiling, memory monitoring, and stack dumping.
// The server can only be started once and will run until a POST request is made to the /stop endpoint.
// This function ensures that only one instance of the server is running at any given time.
// For the API documentation, see the info string in the function.
func ListenDebug(log *base.LogObject, stacksDumpFileName, memDumpFileName string) {
	if listenDebugRunning.Swap(true) {
		return
	}

	mux := http.NewServeMux()

	server := &http.Server{
		Addr:              "localhost:6543",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	info := `
	This server provides various debugging capabilities, including the <code>net/http/pprof</code> API and additional monitoring endpoints.</br></br>

	<strong>Available Endpoints:</strong></br>
	<ul>
		<li><strong>pprof API</strong>:</br>
			Endpoint: <code>GET /debug/pprof/</code></br>
			Description: Exposes the <code>net/http/pprof</code> API for performance profiling.</br>
			More Info: See the <a href="https://pkg.go.dev/net/http/pprof">official documentation</a>.</br>
			Explore the available <a href="debug/pprof/">pprof methods</a>.</br></br>
			<ul>
				<li><strong>Flamegraph Creation</strong>:</br>
					Command: <code>go tool pprof -raw -output=cpu.txt 'http://localhost:6543/debug/pprof/profile?seconds=5'</code></br>
					Description: Generates raw profiling data for CPU usage. Use additional tools to create a flamegraph.</br>
					More Info: Required scripts can be found <a href="https://github.com/brendangregg/FlameGraph">here</a>.</li>
			</ul>
		</li>

		<li><strong>Memory PSI Collector - Start</strong>:</br>
			Endpoint: <code>POST /memory-monitor/psi-collector/start</code></br>
			Description: Starts the memory PSI (Pressure Stall Information) collector to monitor memory pressure.</br>
			Output: The collected data is saved to <code>/persist/memory-monitor/output/psi.txt</code>.</br>
			More Info: For more details on PSI, see the <a href="https://www.kernel.org/doc/Documentation/accounting/psi.txt">Linux documentation</a>.</li>

		<li><strong>Memory PSI Collector - Stop</strong>:</br>
			Endpoint: <code>POST /memory-monitor/psi-collector/stop</code></br>
			Description: Stops the memory PSI collector.</li>

		<li><strong>Stop Server</strong>:</br>
			Endpoint: <code>POST /stop</code></br>
			Description: Stops the server. The server can only be started once and will run until this endpoint is triggered.</li>

		<li><strong>Dump Stacks</strong>:</br>
			Endpoint: <code>POST /dump/stacks</code></br>
			Description: Dumps the current stack traces.</li>

		<li><strong>Dump Memory Info</strong>:</br>
			Endpoint: <code>POST /dump/memory</code></br>
			Description: Dumps current memory usage information.</li>
	</ul></br>

	<em>Note</em>: The server starts on <code>localhost:6543</code> and can only be initiated once. It will continue to run until a <code>POST /stop</code> request is received.
	`

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		writeOrLog(log, w, info)
	}))
	mux.Handle("/index.html", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		writeOrLog(log, w, info)
	}))

	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	mux.Handle("/stop", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			server.Close()
			listenDebugRunning.Swap(false)
		} else {
			http.Error(w, "Did you want to use POST method?", http.StatusMethodNotAllowed)
			return
		}
	}))
	mux.Handle("/dump/stacks", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			dumpStacks(log, stacksDumpFileName)
			response := fmt.Sprintf("Stacks can be found in logread or %s\n", stacksDumpFileName)
			writeOrLog(log, w, response)
		} else {
			http.Error(w, "Did you want to use POST method?", http.StatusMethodNotAllowed)
			return
		}
	}))
	mux.Handle("/dump/memory", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			dumpMemoryInfo(log, memDumpFileName)
			response := fmt.Sprintf("Stacks can be found in logread or %s\n", memDumpFileName)
			writeOrLog(log, w, response)
		} else {
			http.Error(w, "Did you want to use POST method?", http.StatusMethodNotAllowed)
			return
		}
	}))
	mux.Handle("/memory-monitor/psi-collector/start", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if psiCollectorRunning.Swap(true) {
				http.Error(w, "Memory PSI collector is already running", http.StatusConflict)
				return
			}
			// Start the memoryPSICollector
			psiCollectorCtx, cancel := context.WithCancel(context.Background())
			psiCollectorCancel = cancel
			go func() {
				err := MemoryPSICollector(psiCollectorCtx, log)
				defer psiCollectorRunning.Swap(false)
				if err != nil {
					log.Errorf("MemoryPSICollector failed: %+v", err)
				}
			}()
			// Send a response to the client
			response := "Memory PSI collector started.\n"
			writeOrLog(log, w, response)
		} else {
			http.Error(w, "Did you want to use POST method?", http.StatusMethodNotAllowed)
			return
		}
	}))
	mux.Handle("/memory-monitor/psi-collector/stop", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if !psiCollectorRunning.Swap(false) {
				http.Error(w, "Memory PSI collector is not running", http.StatusNotFound)
				return
			}
			// Stop the memoryPSICollector
			psiCollectorCancel()
			// Send a response to the client
			response := "Memory PSI collector stopped.\n"
			writeOrLog(log, w, response)
		} else {
			http.Error(w, "Did you want to use POST method?", http.StatusMethodNotAllowed)
			return
		}
	}))

	if err := server.ListenAndServe(); err != nil {
		log.Errorf("Listening failed: %+v", err)
	}
}
