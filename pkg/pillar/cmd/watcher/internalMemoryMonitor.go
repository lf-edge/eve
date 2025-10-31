// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	immcore "github.com/lf-edge/eve/pkg/pillar/cmd/watcher/internal/immcore"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// ---------- File sizing / gates ----------

// ---------- IMM params ----------

type InternalMemoryMonitorParams struct {
	mutex          sync.Mutex
	storeEnabled   bool
	analyzeEnabled bool
}

func (immp *InternalMemoryMonitorParams) Set(storeEnabled, analyzeEnabled bool) {
	immp.mutex.Lock()
	immp.storeEnabled = storeEnabled
	// enforce: analyze requires store
	if !storeEnabled {
		analyzeEnabled = false
	}
	immp.analyzeEnabled = analyzeEnabled
	immp.mutex.Unlock()
}

func (immp *InternalMemoryMonitorParams) Get() (bool, bool) {
	immp.mutex.Lock()
	defer immp.mutex.Unlock()
	return immp.storeEnabled, immp.analyzeEnabled
}

// ---------- CSV housekeeping ----------

func cleanupOldCsvFiles() {
	dir := types.MemoryMonitorOutputDir
	if immcore.Profiling() {
		defer immcore.Profile("io.cleanup")()
	}
	if immcore.Profiling() {
		end := immcore.Profile("io.readdir")
		_ = end
		end()
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		log.Warnf("failed to read directory: %v", err)
		return
	}

	var totalSize int64
	var fileInfos []os.FileInfo

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if filepath.Ext(file.Name()) != ".csv" && filepath.Ext(file.Name()) != ".old" {
			continue
		}
		if immcore.Profiling() {
			end := immcore.Profile("io.fileinfo")
			_ = end
			defer end()
		}
		info, err := file.Info()
		if err != nil {
			log.Warnf("failed to get file info: %v", err)
			continue
		}
		fileInfos = append(fileInfos, info)
		totalSize += info.Size()
	}

	if totalSize <= 10*1024*1024 { // 10MB
		return
	}

	sort.Slice(fileInfos, func(i, j int) bool {
		return fileInfos[i].ModTime().Before(fileInfos[j].ModTime())
	})

	for _, fileInfo := range fileInfos {
		if totalSize <= 10*1024*1024 {
			break
		}
		if immcore.Profiling() {
			end := immcore.Profile("io.remove")
			_ = end
			defer end()
		}
		err := os.Remove(filepath.Join(dir, fileInfo.Name()))
		if err != nil {
			log.Warnf("failed to remove file: %v", err)
			continue
		}
		totalSize -= fileInfo.Size()
		log.Noticef("removed old CSV file: %s\n", fileInfo.Name())
	}
}

func backupOldCsvFile() {
	fileName := filepath.Join(types.MemoryMonitorOutputDir, "memory_usage.csv")
	if immcore.Profiling() {
		defer immcore.Profile("io.backup")()
	}
	if immcore.Profiling() {
		end := immcore.Profile("io.stat")
		_ = end
		defer end()
	}
	info, err := os.Stat(fileName)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("stat failed: %v", err)
		}
		return // nothing to back up
	}
	if info.Size() == 0 {
		return
	}

	dir := filepath.Dir(fileName)
	ts := time.Now().UTC().Format("20060102T150405")
	backupFileName := filepath.Join(dir, fmt.Sprintf("memory_usage.csv.%s.old", ts))

	if immcore.Profiling() {
		end := immcore.Profile("io.rename")
		_ = end
		defer end()
	}
	if err := os.Rename(fileName, backupFileName); err != nil {
		log.Warnf("failed to rename to backup: %v", err)
		return
	}
	if d, err := os.Open(dir); err == nil {
		if immcore.Profiling() {
			end := immcore.Profile("io.syncdir")
			_ = end
			defer end()
		}
		_ = d.Sync()
		_ = d.Close()
	}
	log.Noticef("Backup of old CSV created: %s\n", backupFileName)
}

// ---------- CSV writer (preallocated) ----------

func writeProbesCSV(probes []immcore.Probe, fileName string) {
	if immcore.Profiling() {
		defer immcore.Profile("io.write.csv")()
	}
	// we know file is capped to ~1MB, pre-grow a bit
	var buf bytes.Buffer
	buf.Grow(1<<20 + 4096)

	w := csv.NewWriter(&buf)

	// header
	header := []string{"time"}
	for _, spec := range immcore.MetricRegistry {
		header = append(header, spec.Name)
	}
	header = append(header, "score", "recent_feature", "entire_feature")
	for _, spec := range immcore.MetricRegistry {
		header = append(header, "s_recent:"+spec.Name)
	}
	for _, spec := range immcore.MetricRegistry {
		header = append(header, "s_entire:"+spec.Name)
	}
	if err := w.Write(header); err != nil {
		log.Warnf("header: %v", err)
		return
	}

	rec := make([]string, len(header))
	for _, p := range probes {
		idx := 0
		rec[idx] = p.Time.Format(time.RFC3339)
		idx++

		// values for all metrics in registry order
		for i := 0; i < len(immcore.MetricRegistry); i++ {
			rec[idx] = fmt.Sprintf("%d", p.Values[i])
			idx++
		}

		rec[idx] = fmt.Sprintf("%.3f", p.Score)
		idx++
		rec[idx] = fmt.Sprintf("%.4f", p.RecentFeature)
		idx++
		rec[idx] = fmt.Sprintf("%.4f", p.EntireFeature)
		idx++

		for i := 0; i < len(immcore.MetricRegistry); i++ {
			rec[idx] = fmt.Sprintf("%.4f", p.SRecent[i])
			idx++
		}
		for i := 0; i < len(immcore.MetricRegistry); i++ {
			rec[idx] = fmt.Sprintf("%.4f", p.SEntire[i])
			idx++
		}
		_ = w.Write(rec[:idx])
	}
	if immcore.Profiling() {
		end := immcore.Profile("io.csv.flush")
		_ = end
		defer end()
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Warnf("flush: %v", err)
		return
	}
	if immcore.Profiling() {
		end := immcore.Profile("io.write.rename")
		_ = end
		defer end()
	}
	if err := fileutils.WriteRename(fileName, buf.Bytes()); err != nil {
		log.Warnf("WriteRename failed: %v", err)
		return
	}
}

// ---------- Main goroutine ----------

func InternalMemoryMonitor(ctx *watcherContext) {
	log.Functionf("#ohm: Starting internal memory monitor")
	log.Warnf("#ohm: Internal memory monitor started")

	// Build config from engine defaults.
	cfg := immcore.DefaultConfig()
	cfg.MaxHistory = immcore.MaxHistory

	// Read initial flags
	storeEnabled, analyzeEnabled := ctx.IMMParams.Get()

	var engine *immcore.IMMState
	if storeEnabled {
		engine = immcore.NewState(cfg)
	}

	fileName := filepath.Join(types.MemoryMonitorOutputDir, "memory_usage.csv")
	backupOldCsvFile()
	cleanupOldCsvFiles()

	statsWrittenLastTime := time.Now()

	for {

		// read latest flags; enforce dependency
		storeEnabled, analyzeEnabled = ctx.IMMParams.Get()
		if !storeEnabled && analyzeEnabled {
			analyzeEnabled = false
		}

		if !storeEnabled {
			// not collecting
			time.Sleep(cfg.ProbingInterval)
			continue
		}

		// collect metrics via engine
		valsArr, errs := immcore.CollectNow()
		for _, err := range errs {
			log.Warnf("IMM collect: %v", err)
		}

		// ensure engine exists (handle dynamic enable)
		if engine == nil {
			engine = immcore.NewState(cfg)
		}

		if analyzeEnabled {
			probe := engine.Step(immcore.Input{
				Time:   time.Now(),
				Values: valsArr,
			})

			log.Noticef("%s (samples=%d)", immcore.Summary(probe), len(engine.History()))
		} else {
			// store-only: append values without analysis into the same history
			p := engine.AppendOnly(immcore.Input{
				Time:   time.Now(),
				Values: valsArr,
			})
			log.Noticef("%s (samples=%d)", immcore.Summary(p), len(engine.History()))
		}

		// trim by file budget using single history
		if len(engine.History())+1 > immcore.MaxHistory {
			linesToDrop := len(engine.History()) + 1 - immcore.MaxHistory
			if linesToDrop > 0 && linesToDrop < len(engine.History()) {
				engine.DropHead(linesToDrop)
				log.Noticef("trimming memory probes by %d", linesToDrop)
			}
		}

		if time.Since(statsWrittenLastTime) >= time.Minute {
			writeProbesCSV(engine.History(), fileName)
			statsWrittenLastTime = time.Now()
		}

		// sleep
		time.Sleep(cfg.ProbingInterval)
	}
}

// ---------- Config wiring ----------

func updateInternalMemoryMonitorConfig(ctx *watcherContext) {
	gcp := agentlog.GetGlobalConfig(log, ctx.subGlobalConfig)
	if gcp == nil {
		return
	}

	// Legacy flag kept for compatibility; prefer store/analyze flags
	store := gcp.GlobalValueBool(types.InternalMemoryMonitorStoreEnabled)
	analyze := gcp.GlobalValueBool(types.InternalMemoryMonitorAnalyzeEnabled)
	if analyze && !store {
		log.Warnf("IMM: analyze enabled but store disabled; forcing analyze=false")
		analyze = false
	}
	ctx.IMMParams.Set(store, analyze)
}

// ---------- tiny utils ----------

// (no helpers needed)
