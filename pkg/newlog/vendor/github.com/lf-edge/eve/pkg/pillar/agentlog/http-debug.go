// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	ctrdd "github.com/containerd/containerd"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var (
	listenDebugRunning  atomic.Bool
	psiCollectorRunning atomic.Bool
	psiCollectorCancel  context.CancelFunc
)

var listenAddress = "localhost:6543"

func roundToMb(b uint64) uint64 {
	kb := (b + 512) / 1024
	mb := (kb + 512) / 1024
	return mb
}

func writeOrLog(log *base.LogObject, w io.Writer, msg string) {
	if _, err := w.Write([]byte(msg)); err != nil {
		log.Errorf("Could not write to %+v: %+v", w, err)
	}
}

func writeAndLog(log *base.LogObject, w io.Writer, msg string) {
	_, err := w.Write([]byte(msg))
	if err != nil {
		log.Errorf("Could not write to %+v: %+v", w, err)
	}

	log.Warn(msg)
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

type mutexWriter struct {
	w     io.Writer
	mutex *sync.Mutex
}

func (m mutexWriter) Write(p []byte) (n int, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// seems containerd sometimes wants to write something into it,
	// but it is already too late
	if m.w == nil {
		return 0, syscall.ENOENT
	}
	n, err = m.w.Write(p)

	return n, err
}

type bpftraceHandler struct {
	log *base.LogObject
}

func (b bpftraceHandler) runInDebugContainer(clientCtx context.Context, w io.Writer, args []string, timeout time.Duration) error {
	ctrd, err := containerd.NewContainerdClient(false)
	if err != nil {
		return fmt.Errorf("could not initialize containerd client: %+v\n", err)
	}

	ctx, done := ctrd.CtrNewSystemServicesCtx()
	defer done()

	container, err := ctrd.CtrLoadContainer(ctx, "debug")
	if err != nil {
		return fmt.Errorf("loading container failed: %+v", err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return fmt.Errorf("getting debug container task failed: %+v", err)
	}

	pspec := specs.Process{
		Args: args,
		Cwd:  "/",
		Scheduler: &specs.Scheduler{
			Deadline: uint64(time.Now().Add(timeout).Unix()),
		},
	}
	taskID := fmt.Sprintf("bpftrace-%d", rand.Int()) // TODO: avoid collision
	stderrBuf := bytes.Buffer{}

	writingDone := make(chan struct{})
	defer close(writingDone)
	mutexWriter := mutexWriter{
		w:     w,
		mutex: &sync.Mutex{},
	}
	stdcio := ctrd.CtrWriterCreator(mutexWriter, &stderrBuf)

	process, err := task.Exec(ctx, taskID, &pspec, stdcio)
	if err != nil {
		return fmt.Errorf("executing in task failed: %+v", err)
	}
	waiter, err := process.Wait(ctx)
	if err != nil {
		return fmt.Errorf("process wait failed: %+v", err)
	}
	err = process.Start(ctx)
	if err != nil {
		return fmt.Errorf("process start failed: %+v", err)
	}

	exitStatus := struct {
		exitCode        uint32
		killedByTimeout bool
	}{
		exitCode:        0,
		killedByTimeout: false,
	}

	timeoutTimer := time.NewTimer(timeout)
	select {
	case <-clientCtx.Done():
		exitStatus.killedByTimeout = true
		err := b.killProcess(ctx, process)
		if err != nil {
			b.log.Warnf("writer closed - killing process %+v failed: %v", args, err)
		}
	case <-timeoutTimer.C:
		exitStatus.killedByTimeout = true
		err := b.killProcess(ctx, process)
		if err != nil {
			b.log.Warnf("timeout - killing process %+v failed: %v", args, err)
		}
	case containerExitStatus := <-waiter:
		exitStatus.exitCode = containerExitStatus.ExitCode()
	}
	timeoutTimer.Stop()

	if !exitStatus.killedByTimeout {
		st, err := process.Status(ctx)
		if err != nil {
			return fmt.Errorf("process status failed: %+v", err)
		}
		b.log.Noticef("process status is: %+v", st)

		status, err := process.Delete(ctx)
		if err != nil {
			return fmt.Errorf("process delete (%+v) failed: %+v", status, err)
		}
	}

	stderrBytes, err := io.ReadAll(&stderrBuf)
	if len(stderrBytes) > 0 {
		return fmt.Errorf("Stderr output was: %s", string(stderrBytes))
	}

	mutexWriter.w = nil

	return nil
}

func (b bpftraceHandler) killProcess(ctx context.Context, process ctrdd.Process) error {
	err := process.Kill(ctx, syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("timeout reached, killing of process failed: %w", err)
	}
	time.Sleep(time.Second)
	st, err := process.Status(ctx)
	if err != nil {
		return fmt.Errorf("timeout reached, retrieving status of process failed: %w", err)
	}
	if st.Status == ctrdd.Stopped {
		return nil
	}
	err = process.Kill(ctx, syscall.SIGKILL)
	if err != nil {
		return fmt.Errorf("timeout reached, killing of process (SIGKILL) failed: %w", err)
	}

	return nil
}

func (b bpftraceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	file, err := os.CreateTemp("/persist/tmp", "bpftrace-aot")
	if err != nil {
		b.log.Warnf("could not create temp dir: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	filename := file.Name()
	defer os.Remove(filename)

	timeoutString := r.FormValue("timeout")
	if timeoutString == "" {
		timeoutString = "5"
	}
	timeoutSeconds, err := strconv.ParseUint(timeoutString, 10, 16)
	if err != nil {
		writeAndLog(b.log, w, fmt.Sprintf("Error happened, could not parse timeout: %s\n", err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	aotForm, _, err := r.FormFile("aot")
	if err != nil {
		writeAndLog(b.log, w, fmt.Sprintf("could not retrieve form file: %s", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err = io.Copy(file, aotForm)
	if err != nil {
		writeAndLog(b.log, w, fmt.Sprintf("could not copy form file: %s", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = aotForm.Close()
	if err != nil {
		writeAndLog(b.log, w, fmt.Sprintf("could not close form file: %s", err))
	}
	err = file.Close()
	if err != nil {
		writeAndLog(b.log, w, fmt.Sprintf("could not close file: %s", err))
	}

	args := []string{"/usr/bin/bpftrace-aotrt", "-f", "json", filename}
	err = b.runInDebugContainer(r.Context(), w, args, time.Duration(timeoutSeconds)*time.Second)
	if err != nil {
		fmt.Fprintf(w, "Error happened:\n%s\n", err.Error())
		return
	}
}

func bpftraceForm(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
				<html>
				<form method="post" enctype="multipart/form-data">
                <label>Please choose the aot bpftrace file:
                <input name="aot" type="file" accept="binary/*">
                and the timeout:
                <input name="timeout" min="0" max="3600" value="5" step="5" accept="binary/*">
                </label>
                <br/>
                <button>Start</button>
                </form>
				</html>
			`)
}

func archHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, runtime.GOARCH)
}

func linuxkitYmlHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "/hostfs/etc/linuxkit-eve-config.yml")
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
		Addr:              listenAddress,
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

		<li><strong>Run bpftrace compiled script</strong>:</br>
			<a href="debug/bpftrace">bpftrace interface</a> </li>
	</ul></br>

	<em>Note</em>: The server starts on <code>localhost:6543</code> and can only be initiated once. It will continue to run until a <code>POST /stop</code> request is received.
	`

	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		writeOrLog(log, w, info)
	}))
	mux.Handle("GET /index.html", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		writeOrLog(log, w, info)
	}))

	bpfHandler := bpftraceHandler{
		log: log.Clone(),
	}

	mux.Handle("GET /debug/info/arch", http.HandlerFunc(archHandler))
	mux.Handle("GET /debug/info/linuxkit.yml", http.HandlerFunc(linuxkitYmlHandler))
	mux.Handle("POST /debug/bpftrace", bpfHandler)
	mux.Handle("GET /debug/bpftrace", http.HandlerFunc(bpftraceForm))
	mux.Handle("GET /debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("GET /debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	mux.Handle("GET /debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	mux.Handle("GET /debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	mux.Handle("GET /debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	mux.Handle("POST /stop", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.Close()
		listenDebugRunning.Swap(false)
	}))
	mux.Handle("POST /dump/stacks", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dumpStacks(log, stacksDumpFileName)
		response := fmt.Sprintf("Stacks can be found in logread or %s\n", stacksDumpFileName)
		writeOrLog(log, w, response)
	}))
	mux.Handle("POST /dump/memory", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dumpMemoryInfo(log, memDumpFileName)
		response := fmt.Sprintf("Stacks can be found in logread or %s\n", memDumpFileName)
		writeOrLog(log, w, response)
	}))
	mux.Handle("POST /memory-monitor/psi-collector/start", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	mux.Handle("POST /memory-monitor/psi-collector/stop", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !psiCollectorRunning.Swap(false) {
			http.Error(w, "Memory PSI collector is not running", http.StatusNotFound)
			return
		}
		// Stop the memoryPSICollector
		psiCollectorCancel()
		// Send a response to the client
		response := "Memory PSI collector stopped.\n"
		writeOrLog(log, w, response)
	}))

	if err := server.ListenAndServe(); err != nil {
		log.Errorf("Listening failed: %+v", err)
	}
}
