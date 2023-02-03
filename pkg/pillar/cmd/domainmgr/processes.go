// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

// Periodically extract and publish information about the running processes
// and their memory, thread, FD, etc usage

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/shirou/gopsutil/process"
)

const (
	maxStackStringLen = 1024 // Single stack
	totalMaxStackLen  = 8192 // All reported stacks
)

// Return a slice of all the ProcessMetric plus a map of the pids
// Excludes kernel-only processes
func gatherProcessMetricList(ctx *domainContext) ([]types.ProcessMetric, map[int32]bool) {
	var ret []types.ProcessMetric
	reportedPids := make(map[int32]bool)

	watchedPids, err := getWatchedPids()
	if err != nil {
		log.Errorf("process.Processes failed: %s", err)
		return ret, reportedPids
	}
	log.Tracef("watchedPids: %+v", watchedPids)
	processes, err := process.Processes()
	if err != nil {
		log.Errorf("process.Processes failed: %s", err)
		return ret, reportedPids
	}
	totalStacks := 0
	for _, p := range processes {
		pi, err := getProcessMetric(p)
		if err != nil {
			// Process might have just exited
			log.Functionf("getProcessMetric failed: %s", err)
			continue
		}
		if pi.UserProcess {
			if _, ok := watchedPids[pi.Pid]; ok {
				pi.Watched = true
			} else if time.Since(pi.CreateTime) > time.Minute {
				// Report stack for not watched processed which
				// have been running for a while. This is
				// a bit of belt and suspenders approach to
				// catch hung processes which are not watched by
				// the watchdog process to be able to see them
				// even when we have no debug ssh access.
				// We limit the total memory used for stacks for
				// all the processes.
				filename := fmt.Sprintf("/proc/%d/stack", pi.Pid)
				b, err := fileutils.ReadWithMaxSize(log, filename, maxStackStringLen)
				if err != nil {
					log.Error(err)
					continue
				}
				pi.Stack = string(b)
				// Apply size limit
				if pi.Stack != "" {
					if totalStacks+len(pi.Stack) > totalMaxStackLen {
						pi.Stack = "Omitted"
					} else {
						totalStacks += len(pi.Stack)
					}
				}
			}

			reportedPids[int32(pi.Pid)] = true
			ret = append(ret, *pi)
		}

	}
	return ret, reportedPids
}

const (
	watchdogDirName = "/run/watchdog/pid/"
	pidDirName      = "/run"
)

// getWatchedPids returns a map will all the pids watched by watchdog
// based on /run/watchdog/pid/<foo> by reading the content of /run/<foo>
func getWatchedPids() (map[int32]bool, error) {
	return getWatchedPidsFromDir(watchdogDirName, pidDirName)
}

func getWatchedPidsFromDir(wDirname string, pDirname string) (map[int32]bool, error) {
	pids := make(map[int32]bool)
	locations, err := os.ReadDir(wDirname)
	if err != nil {
		return pids, err
	}
	for _, location := range locations {
		if location.IsDir() {
			wsubdir := path.Join(wDirname, location.Name())
			psubdir := path.Join(pDirname, location.Name())
			p, err := getWatchedPidsFromDir(wsubdir, psubdir)
			if err != nil {
				continue
			}
			// copy map (entries)
			for k, v := range p {
				pids[k] = v
			}
			continue
		}
		pidFile := path.Join(pDirname, location.Name())

		pidBytes, err := os.ReadFile(pidFile)
		if err != nil {
			log.Errorf("pidFile %s read error %v", pidFile, err)
			continue
		}
		pidStr := string(pidBytes)
		pidStr = strings.TrimSuffix(pidStr, "\n")
		pidStr = strings.TrimSpace(pidStr)
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			log.Errorf("pidFile %s with <%s> convert error %v",
				pidFile, pidStr, err)
			continue
		}
		pids[int32(pid)] = true
	}
	return pids, nil
}

// getProcessMetric gets the metrics for one process
func getProcessMetric(p *process.Process) (*types.ProcessMetric, error) {
	n, err := p.Name()
	if err != nil {
		return nil, err
	}
	// Ensure we have a copy and not reference into slice
	n = string([]byte(n))
	_, err = p.Exe()
	userProcess := (err == nil) // kernel or user-space?

	c, err := p.CPUPercent()
	if err != nil {
		return nil, err
	}
	mp, err := p.MemoryPercent()
	if err != nil {
		return nil, err
	}
	ts, err := p.Times()
	if err != nil {
		return nil, err
	}
	// Requires permissions
	nfd, err := p.NumFDs()
	if err != nil {
		return nil, err
	}
	nt, err := p.NumThreads()
	if err != nil {
		return nil, err
	}

	ct, err := p.CreateTime()
	if err != nil {
		return nil, err
	}
	ctSec := ct / 1000
	ctNsec := (ct - ctSec*1000) * 1000000
	createTime := time.Unix(ctSec, ctNsec)
	m, err := p.MemoryInfo()
	if err != nil {
		return nil, err
	}
	return &types.ProcessMetric{
		Pid:           p.Pid,
		Name:          n,
		UserProcess:   userProcess,
		CPUPercent:    c,
		MemoryPercent: mp,
		NumFDs:        nfd,
		NumThreads:    nt,
		UserTime:      ts.User,
		SystemTime:    ts.System,
		CreateTime:    createTime,
		VMBytes:       m.VMS,
		RssBytes:      m.RSS,
	}, nil
}

// unpublishRemovedPids removes the old ones which are not in new
func unpublishRemovedPids(ctx *domainContext, oldPids, newPids map[int32]bool) {
	for pid := range oldPids {
		if _, ok := newPids[pid]; !ok {
			unpublishProcessMetric(ctx, uint32(pid))
		}
	}
}

func publishProcessMetric(ctx *domainContext, status *types.ProcessMetric) {
	key := status.Key()
	log.Tracef("publishProcessMetric(%s)", key)
	pub := ctx.pubProcessMetric
	pub.Publish(key, *status)
}

func unpublishProcessMetric(ctx *domainContext, pid uint32) {
	key := strconv.Itoa(int(pid))
	log.Tracef("unpublishProcessMetric(%s)", key)
	pub := ctx.pubProcessMetric
	pub.Unpublish(key)
}
