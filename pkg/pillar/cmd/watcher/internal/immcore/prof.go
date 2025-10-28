// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package immcore

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Lightweight, opt-in profiling utility for IMM engine.
// Configure at runtime via SetProfiling/SetProfilingConfig from the watcher.
// Usage:
//   defer Profile("imm.step")()
//   end := Profile("imm.entire"); ...; end()

var profilePath = filepath.Join(types.MemoryMonitorOutputDir, "imm-profile.dat")

var (
	profEnabled int32  // 0/1
	profMinNS   int64  // minimum duration in ns to emit
	profEvery   uint64 = 1
	profCount   uint64

	profFile *os.File
	profMu   sync.Mutex
)

// SetProfiling enables or disables profiling at runtime.
func SetProfiling(enabled bool) {
	if enabled {
		// Open file for append and ensure directory exists.
		dir := filepath.Dir(profilePath)
		_ = os.MkdirAll(dir, 0o755)
		f, err := os.OpenFile(profilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		profMu.Lock()
		if profFile != nil {
			_ = profFile.Close()
		}
		if err == nil {
			profFile = f
		} else {
			profFile = nil // keep enabled; just drop writes
		}
		profMu.Unlock()
		atomic.StoreInt32(&profEnabled, 1)
	} else {
		atomic.StoreInt32(&profEnabled, 0)
		profMu.Lock()
		if profFile != nil {
			_ = profFile.Close()
			profFile = nil
		}
		profMu.Unlock()
	}
}

// SetProfilingConfig sets optional runtime tuning for profiling output.
// Pass minDuration as 0 for no threshold; every of 0 will be treated as 1.
func SetProfilingConfig(minDuration time.Duration, every uint64) {
	atomic.StoreInt64(&profMinNS, minDuration.Nanoseconds())
	if every == 0 {
		every = 1
	}
	atomic.StoreUint64(&profEvery, every)
}

// Profile starts a labeled timing region and returns a closure to end it.
// Use as: defer Profile("label")()
func Profile(label string) func() {
	if atomic.LoadInt32(&profEnabled) == 0 {
		return func() {}
	}
	start := time.Now()
	pc, file, line, _ := runtime.Caller(1)
	fn := runtime.FuncForPC(pc)
	fname := ""
	if fn != nil {
		fname = fn.Name()
	}
	gid := curGID()
	return func() {
		end := time.Now()
		dur := end.Sub(start)
		minDur := time.Duration(atomic.LoadInt64(&profMinNS))
		if minDur > 0 && dur < minDur {
			return
		}
		c := atomic.AddUint64(&profCount, 1)
		every := atomic.LoadUint64(&profEvery)
		if every > 1 && (c%every) != 0 {
			return
		}
		profMu.Lock()
		f := profFile
		if f == nil {
			profMu.Unlock()
			return
		}
		startTS := start.UTC().Format(time.RFC3339Nano)
		endTS := end.UTC().Format(time.RFC3339Nano)
		_, _ = fmt.Fprintf(f,
			"immprof ts=%s start_ts=%s end_ts=%s gid=%d label=%s dur_ms=%.3f file=%s line=%d func=%s\n",
			endTS, startTS, endTS, gid, label, float64(dur.Microseconds())/1000.0, shortFile(file), line, fname,
		)
		profMu.Unlock()
	}
}

// Profiling reports whether lightweight profiling is currently enabled.
func Profiling() bool { return atomic.LoadInt32(&profEnabled) != 0 }

func shortFile(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func curGID() uint64 {
	// Parse from runtime.Stack for debug-only use; acceptable when profiling.
	var b [64]byte
	n := runtime.Stack(b[:], false)
	// line looks like: "goroutine 12345 [running]:\n"
	line := string(b[:n])
	line = strings.TrimPrefix(line, "goroutine ")
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return 0
	}
	idStr := line[:sp]
	id, _ := strconv.ParseUint(idStr, 10, 64)
	return id
}
