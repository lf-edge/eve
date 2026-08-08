// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/prereqs"
)

const (
	k3sLogFile       = "k3s.log"
	maxCrashLogFiles = 10
	// maxRaftLogFiles caps how many of k3s' own rotated raft log
	// files (k3s-YYYY-MM-DDTHH-MM-SS.mmm.log.gz) we retain.
	maxRaftLogFiles = 10
)

// SaveCrashLog gzip-compresses the tail of the previous k3s.log
// (from the last "Starting k3s <version>" banner to EOF) and
// prunes old crash logs to maxCrashLogFiles. No-op on the first
// start (restartCount <= 1).
func SaveCrashLog(restartCount int) {
	if restartCount <= 1 {
		return
	}
	timestamp := time.Now().Format("20060102-150405")
	crashLogName := fmt.Sprintf("%s.restart.%s.%d.gz",
		k3sLogFile, timestamp, restartCount)
	srcFile := filepath.Join(prereqs.KubeLogDir, k3sLogFile)
	dstFile := filepath.Join(prereqs.KubeLogDir, crashLogName)

	if err := gzipLastRestartPart(srcFile, dstFile); err != nil {
		log.Printf("warning: save crash log: %v", err)
		return
	}
	log.Printf("saved crash log %s", crashLogName)
	pruneOldCrashLogs()
}

// pruneOldCrashLogs deletes the oldest crash logs when more than
// maxCrashLogFiles are present.
func pruneOldCrashLogs() {
	entries, err := os.ReadDir(prereqs.KubeLogDir)
	if err != nil {
		log.Printf("warning: read log dir for crash log cleanup: %v", err)
		return
	}
	var crashLogs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, k3sLogFile+".restart.") &&
			strings.HasSuffix(name, ".gz") {
			crashLogs = append(crashLogs, name)
		}
	}
	if len(crashLogs) <= maxCrashLogFiles {
		return
	}
	// Sort by name — the embedded timestamp ensures chronological
	// order.
	sort.Strings(crashLogs)
	for _, name := range crashLogs[:len(crashLogs)-maxCrashLogFiles] {
		path := filepath.Join(prereqs.KubeLogDir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: remove old crash log %s: %v", name, err)
		}
	}
	log.Printf("pruned %d old crash log(s)",
		len(crashLogs)-maxCrashLogFiles)
}

// gzipLastRestartPart extracts the tail of srcFile starting at the
// last occurrence of the k3s startup banner ("Starting k3s
// <version>") and writes a gzip-compressed copy to dstFile. When
// the banner is not found, the entire file is compressed.
//
// Two passes: one to find the last banner line number, one to
// stream from that line through gzip. Streaming (vs reading into
// memory) keeps memory bounded even when k3s.log has accumulated
// to the 5MB rotation threshold over many restarts.
func gzipLastRestartPart(srcFile, dstFile string) (retErr error) {
	sf, err := os.Open(srcFile)
	if err != nil {
		return fmt.Errorf("open source %s: %w", srcFile, err)
	}
	defer func() { _ = sf.Close() }()

	searchString := "Starting k3s " + k3s.K3sVersion

	lastLine, err := findLastBannerLine(sf, searchString)
	if err != nil {
		return fmt.Errorf("scan source %s: %w", srcFile, err)
	}
	if _, err := sf.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek source %s: %w", srcFile, err)
	}

	df, err := os.Create(dstFile)
	if err != nil {
		return fmt.Errorf("create dest %s: %w", dstFile, err)
	}
	defer func() {
		if cerr := df.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
		// Clean up partial gzip on any earlier failure.
		if retErr != nil {
			if rmErr := os.Remove(dstFile); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				log.Printf("warning: remove partial crash log %s: %v",
					dstFile, rmErr)
			}
		}
	}()

	gw, err := gzip.NewWriterLevel(df, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("create gzip writer: %w", err)
	}
	if err := streamLinesFrom(sf, gw, lastLine); err != nil {
		return fmt.Errorf("stream gzip from %s: %w", srcFile, err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}
	return nil
}

// findLastBannerLine returns the 1-indexed line number of the last
// line containing search; 1 if no match (so the full file gets
// compressed).
func findLastBannerLine(r io.Reader, search string) (int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	last := 1
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if strings.Contains(scanner.Text(), search) {
			last = lineNum
		}
	}
	return last, scanner.Err()
}

// streamLinesFrom writes lines from startLine (1-indexed) through
// EOF of r into w, appending a newline after each line.
func streamLinesFrom(r io.Reader, w io.Writer, startLine int) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum < startLine {
			continue
		}
		if _, err := w.Write(scanner.Bytes()); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// CleanExcessiveK3sLogs prunes k3s' own rotated raft log files
// (k3s-YYYY-MM-DDTHH-MM-SS.mmm.log.gz) to maxRaftLogFiles. k3s
// itself doesn't cap these and they otherwise grow without bound.
func CleanExcessiveK3sLogs() {
	entries, err := os.ReadDir(prereqs.KubeLogDir)
	if err != nil {
		return
	}
	var raftLogs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// k3s-YYYY-MM-DDTHH-MM-SS.mmm.log.gz
		if strings.HasPrefix(name, "k3s-") &&
			strings.HasSuffix(name, ".log.gz") &&
			name != "k3s.log.gz" {
			raftLogs = append(raftLogs, name)
		}
	}
	if len(raftLogs) <= maxRaftLogFiles {
		return
	}
	sort.Strings(raftLogs)
	for _, name := range raftLogs[:len(raftLogs)-maxRaftLogFiles] {
		path := filepath.Join(prereqs.KubeLogDir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: remove old raft log %s: %v", name, err)
		}
	}
	log.Printf("cleaned %d excessive k3s raft log file(s)",
		len(raftLogs)-maxRaftLogFiles)
}
