// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"context"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/flextimer"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	log "github.com/sirupsen/logrus"
)

const (
	dom0Name = "Domain-0"
)

// Run a periodic post of the metrics
func metricsTimerTask(ctx *domainContext, hyper hypervisor.Hypervisor) {
	log.Infoln("starting metrics timer task")
	getAndPublishMetrics(ctx, hyper)

	// Publish 4X more often than zedagent publishes to controller
	interval := time.Duration(ctx.metricInterval) * time.Second
	max := float64(interval) / 4
	min := max * 0.3
	ticker := flextimer.NewRangeTicker(time.Duration(min), time.Duration(max))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)

	for {
		select {
		case <-ticker.C:
			start := time.Now()
			getAndPublishMetrics(ctx, hyper)
			pubsub.CheckMaxTimeTopic(agentName+"metrics", "publishMetrics", start,
				warningTime, errorTime)

		case <-stillRunning.C:
		}
		agentlog.StillRunning(agentName+"metrics", warningTime, errorTime)
	}
}

func getAndPublishMetrics(ctx *domainContext, hyper hypervisor.Hypervisor) {
	getAndPublishCPUMemory(ctx)
	hm, _ := hyper.GetHostCPUMem()
	ctx.pubHostMemory.Publish("global", hm)
}

func getAndPublishCPUMemory(ctx *domainContext) {
	var dmList map[string]types.DomainMetric
	cpuMemoryStat := executeXentopCmd()
	if len(cpuMemoryStat) == 0 {
		dmList = fallbackDomainMetric()
	} else {
		dmList = parseCPUMemoryStat(cpuMemoryStat)
	}
	for domainName, dm := range dmList {
		uuid, err := domainnameToUUID(ctx, domainName)
		if err != nil {
			log.Errorf("domainname %s: %s", domainName, err)
			continue
		}
		dm.UUIDandVersion.UUID = uuid
		ctx.pubDomainMetric.Publish(dm.Key(), dm)
	}
	if false {
		// debug code to compare Xen and fallback
		log.Infof("XXX reported DomainMetric %+v", dmList)
		dmList = fallbackDomainMetric()
		log.Infof("XXX fallback DomainMetric %+v", dmList)
	}
}

// Returns zero for the host/overhead
func domainnameToUUID(ctx *domainContext, domainName string) (uuid.UUID, error) {
	if domainName == dom0Name {
		return uuid.UUID{}, nil
	}
	pub := ctx.pubDomainStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.DomainStatus)
		if status.DomainName == domainName {
			return status.UUIDandVersion.UUID, nil
		}
	}
	return uuid.UUID{}, fmt.Errorf("Unknown domainname %s", domainName)
}

// First approximation for a host without Xen
// XXX Assumes that all of the used memory in the host is overhead the same way dom0 is
// overhead, which is completely incorrect when running containers
func fallbackDomainMetric() map[string]types.DomainMetric {
	dmList := make(map[string]types.DomainMetric)
	vm, err := mem.VirtualMemory()
	if err != nil {
		log.Errorf("mem.VirtualMemory failed: %s", err)
		return dmList
	}
	var usedMemoryPercent float64
	if vm.Total != 0 {
		usedMemoryPercent = float64(100 * (vm.Total - vm.Available) / vm.Total)
	}
	total := roundFromBytesToMbytes(vm.Total)
	available := roundFromBytesToMbytes(vm.Available)
	dm := types.DomainMetric{
		UsedMemory:        uint32(total - available),
		AvailableMemory:   uint32(available),
		UsedMemoryPercent: usedMemoryPercent,
	}
	// Ask for one total entry
	cpuStat, err := cpu.Times(false)
	if err != nil {
		log.Errorf("cpu.TimesStat failed: %s", err)
		return dmList
	}
	for _, cpu := range cpuStat {
		log.Infof("cpuStat %s: %v", cpu.CPU, cpu)
		dm.CPUTotal = uint64(cpu.Total())
		break
	}
	dmList[dom0Name] = dm
	return dmList
}

// XXX can we use libxenstat? /usr/local/lib/libxenstat.so on hikey
// /usr/lib/libxenstat.so in container
func executeXentopCmd() [][]string {
	var cpuMemoryStat [][]string

	count := 0
	counter := 0
	arg1 := "xentop"
	arg2 := "-b"
	arg3 := "-d"
	arg4 := "1"
	arg5 := "-i"
	arg6 := "2"
	arg7 := "-f"

	stdout, ok, err := execWithTimeout(arg1, arg2, arg3, arg4, arg5, arg6, arg7)
	if err != nil {
		log.Errorf("xentop failed: %s", err)
		return [][]string{}
	}
	if !ok {
		log.Warnf("xentop timed out")
		return nil
	}

	xentopInfo := string(stdout)

	splitXentopInfo := strings.Split(xentopInfo, "\n")

	splitXentopInfoLength := len(splitXentopInfo)
	var i int
	var start int

	for i = 0; i < splitXentopInfoLength; i++ {

		str := splitXentopInfo[i]
		re := regexp.MustCompile(" ")

		spaceRemovedsplitXentopInfo := re.ReplaceAllLiteralString(str, "")
		matched, err := regexp.MatchString("NAMESTATECPU.*", spaceRemovedsplitXentopInfo)

		if err != nil {
			log.Debugf("MatchString failed: %s", err)
		} else if matched {

			count++
			log.Debugf("string matched: %s", str)
			if count == 2 {
				start = i + 1
				log.Debugf("value of i: %d", start)
			}
		}
	}

	length := splitXentopInfoLength - 1 - start
	finalOutput := make([][]string, length)

	for j := start; j < splitXentopInfoLength-1; j++ {

		finalOutput[j-start] = strings.Fields(strings.TrimSpace(splitXentopInfo[j]))
	}

	cpuMemoryStat = make([][]string, length)

	for i := range cpuMemoryStat {
		cpuMemoryStat[i] = make([]string, 20)
	}

	// Need to treat "no limit" as one token
	for f := 0; f < length; f++ {

		// First name and state
		out := 0
		counter++
		cpuMemoryStat[f][counter] = finalOutput[f][out]
		out++
		counter++
		cpuMemoryStat[f][counter] = finalOutput[f][out]
		out++
		for ; out < len(finalOutput[f]); out++ {

			if finalOutput[f][out] == "no" {

			} else if finalOutput[f][out] == "limit" {
				counter++
				cpuMemoryStat[f][counter] = "no limit"
			} else {
				counter++
				cpuMemoryStat[f][counter] = finalOutput[f][out]
			}
		}
		counter = 0
	}
	log.Debugf("ExecuteXentopCmd return %+v", cpuMemoryStat)
	return cpuMemoryStat
}

func execWithTimeout(command string, args ...string) ([]byte, bool, error) {

	ctx, cancel := context.WithTimeout(context.Background(),
		10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, false, nil
	}
	return out, true, err
}

// Returns cpuTotal, usedMemory, availableMemory, usedPercentage
func parseCPUMemoryStat(cpuMemoryStat [][]string) map[string]types.DomainMetric {

	result := make(map[string]types.DomainMetric)
	for _, stat := range cpuMemoryStat {
		if len(stat) <= 2 {
			continue
		}
		domainname := strings.TrimSpace(stat[1])
		if len(stat) <= 6 {
			continue
		}
		log.Debugf("lookupCPUMemoryStat for %s %d elem: %+v",
			domainname, len(stat), stat)
		cpuTotal, err := strconv.ParseUint(stat[3], 10, 0)
		if err != nil {
			log.Errorf("ParseUint(%s) failed: %s",
				stat[3], err)
			cpuTotal = 0
		}
		// This is in kbytes
		totalMemory, err := strconv.ParseUint(stat[5], 10, 0)
		if err != nil {
			log.Errorf("ParseUint(%s) failed: %s",
				stat[5], err)
			totalMemory = 0
		}
		totalMemory = RoundFromKbytesToMbytes(totalMemory)
		usedMemoryPercent, err := strconv.ParseFloat(stat[6], 10)
		if err != nil {
			log.Errorf("ParseFloat(%s) failed: %s",
				stat[6], err)
			usedMemoryPercent = 0
		}
		usedMemory := (float64(totalMemory) * (usedMemoryPercent)) / 100
		availableMemory := float64(totalMemory) - usedMemory

		dm := types.DomainMetric{
			CPUTotal:          cpuTotal,
			UsedMemory:        uint32(usedMemory),
			AvailableMemory:   uint32(availableMemory),
			UsedMemoryPercent: float64(usedMemoryPercent),
		}
		result[domainname] = dm
	}
	return result
}

// RoundFromKbytesToMbytes rounds
func RoundFromKbytesToMbytes(byteCount uint64) uint64 {
	const kbyte = 1024

	return (byteCount + kbyte/2) / kbyte
}

func roundFromBytesToMbytes(byteCount uint64) uint64 {
	const kbyte = 1024

	kbytes := (byteCount + kbyte/2) / kbyte
	return (kbytes + kbyte/2) / kbyte
}
