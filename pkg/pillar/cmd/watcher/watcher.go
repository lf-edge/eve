// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"flag"
	"fmt"
	ctrdd "github.com/containerd/containerd"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"math"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/containerd/cgroups"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	"github.com/sirupsen/logrus"
)

const (
	agentName      = "watcher"
	errorTime      = 3 * time.Minute
	warningTime    = 40 * time.Second
	usageThreshold = 2
)

// GoroutineLeakDetectionParams holds the global goroutine leak detection parameters
type GoroutineLeakDetectionParams struct {
	mutex          sync.Mutex
	threshold      int
	checkInterval  time.Duration
	checkStatsFor  time.Duration
	keepStatsFor   time.Duration
	cooldownPeriod time.Duration
	// Context to make the monitoring goroutine cancellable
	context context.Context
	stop    context.CancelFunc
}

func validateGoroutineLeakDetectionParams(threshold int, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod time.Duration) bool {
	if threshold < 1 {
		log.Warnf("Invalid threshold: %d", threshold)
		return false
	}
	if checkInterval < 0 {
		log.Warnf("Invalid check interval: %v", checkInterval)
		return false
	}
	if checkStatsFor < checkInterval*10 {
		log.Warnf("Invalid check window: %v", checkStatsFor)
		log.Warnf("Check window must be at least 10 times the check interval (%v)", checkInterval)
		return false
	}
	if keepStatsFor < checkStatsFor {
		log.Warnf("Invalid keep stats duration: %v", keepStatsFor)
		log.Warnf("Keep stats duration must be greater than a check window (%v)", checkStatsFor)
		return false
	}
	if cooldownPeriod < checkInterval {
		log.Warnf("Invalid cooldown period: %v", cooldownPeriod)
		log.Warnf("Cooldown period must be greater than a check interval (%v)", checkInterval)
		return false
	}
	return true
}

// Set atomically sets the global goroutine leak detection parameters
func (gldp *GoroutineLeakDetectionParams) Set(threshold int, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod time.Duration) {
	if !validateGoroutineLeakDetectionParams(threshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod) {
		return
	}
	gldp.mutex.Lock()
	gldp.threshold = threshold
	gldp.checkInterval = checkInterval
	gldp.checkStatsFor = checkStatsFor
	gldp.keepStatsFor = keepStatsFor
	gldp.cooldownPeriod = cooldownPeriod
	gldp.mutex.Unlock()
}

// MakeStoppable creates a cancellable context and a stop function
func (gldp *GoroutineLeakDetectionParams) MakeStoppable() {
	gldp.context, gldp.stop = context.WithCancel(context.Background())
}

func (gldp *GoroutineLeakDetectionParams) isStoppable() bool {
	return gldp.context != nil
}

func (gldp *GoroutineLeakDetectionParams) checkStopCondition() bool {
	if gldp.context != nil {
		select {
		case <-gldp.context.Done():
			return true
		default:
			return false
		}
	}
	return false
}

// Stop cancels the context to stop the monitoring goroutine
func (gldp *GoroutineLeakDetectionParams) Stop() {
	if gldp.stop != nil {
		gldp.stop()
	}
}

// Get atomically gets the global goroutine leak detection parameters
func (gldp *GoroutineLeakDetectionParams) Get() (int, time.Duration, time.Duration, time.Duration, time.Duration) {
	var threshold int
	var checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod time.Duration

	gldp.mutex.Lock()
	threshold = gldp.threshold
	checkInterval = gldp.checkInterval
	checkStatsFor = gldp.checkStatsFor
	keepStatsFor = gldp.keepStatsFor
	cooldownPeriod = gldp.cooldownPeriod
	gldp.mutex.Unlock()

	return threshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod
}

type watcherContext struct {
	agentbase.AgentBase
	ps              *pubsub.PubSub
	subGlobalConfig pubsub.Subscription
	subHostMemory   pubsub.Subscription
	subDiskMetric   pubsub.Subscription

	pubMemoryNotification pubsub.Publication
	pubDiskNotification   pubsub.Publication

	GCInitialized bool
	// cli options

	// Global goroutine leak detection parameters
	GRLDParams GoroutineLeakDetectionParams
}

// AddAgentSpecificCLIFlags adds CLI options
func (ctx *watcherContext) AddAgentSpecificCLIFlags(flagSet *flag.FlagSet) {
}

var prevDiskNotification types.DiskNotification
var prevMemNotification types.MemoryNotification
var logger *logrus.Logger
var log *base.LogObject

var gogcForcedLock sync.Mutex
var gogcForcedIntervalInSec uint32
var gogcForcedGrowthMemInMiB uint32
var gogcForcedGrowthMemPerc uint32

func getForcedGOGCParams() (time.Duration, uint64, uint64) {
	var minGrowthMemAbs, minGrowthMemPerc uint64
	var interval time.Duration

	gogcForcedLock.Lock()
	interval = time.Second * time.Duration(gogcForcedIntervalInSec)
	minGrowthMemAbs = uint64(gogcForcedGrowthMemInMiB << 20)
	minGrowthMemPerc = uint64(gogcForcedGrowthMemPerc)
	gogcForcedLock.Unlock()

	return interval, minGrowthMemAbs, minGrowthMemPerc
}

func setForcedGOGCParams(ctx *watcherContext) {
	gcp := agentlog.GetGlobalConfig(log, ctx.subGlobalConfig)
	if gcp == nil {
		return
	}
	gogcForcedLock.Lock()
	gogcForcedIntervalInSec =
		gcp.GlobalValueInt(types.GOGCForcedIntervalInSec)
	gogcForcedGrowthMemInMiB =
		gcp.GlobalValueInt(types.GOGCForcedGrowthMemInMiB)
	gogcForcedGrowthMemPerc =
		gcp.GlobalValueInt(types.GOGCForcedGrowthMemPerc)
	gogcForcedLock.Unlock()
}

// Read the global goroutine leak detection parameters to the context
func updateGoroutineLeakDetectionConfig(ctx *watcherContext) {
	gcp := agentlog.GetGlobalConfig(log, ctx.subGlobalConfig)
	if gcp == nil {
		return
	}

	threshold := int(gcp.GlobalValueInt(types.GoroutineLeakDetectionThreshold))
	checkInterval := time.Duration(gcp.GlobalValueInt(types.GoroutineLeakDetectionCheckIntervalMinutes)) * time.Minute
	checkStatsFor := time.Duration(gcp.GlobalValueInt(types.GoroutineLeakDetectionCheckWindowMinutes)) * time.Minute
	keepStatsFor := time.Duration(gcp.GlobalValueInt(types.GoroutineLeakDetectionKeepStatsHours)) * time.Hour
	cooldownPeriod := time.Duration(gcp.GlobalValueInt(types.GoroutineLeakDetectionCooldownMinutes)) * time.Minute

	ctx.GRLDParams.Set(threshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)
}

// setContainerRunning pauses the container with the given ID
func setContainerRunning(containerID string, running bool) error {
	ctrd, err := containerd.NewContainerdClient(false)
	if err != nil {
		return fmt.Errorf("creating containerd client failed: %+v", err)
	}

	ctx, done := ctrd.CtrNewSystemServicesCtx()
	defer done()

	container, err := ctrd.CtrLoadContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("loading container failed: %+v", err)
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		return fmt.Errorf("getting container task failed: %+v", err)
	}

	status, err := task.Status(ctx)
	if err != nil {
		return fmt.Errorf("getting task info failed: %+v", err)
	}

	if running && status.Status == ctrdd.Paused {
		if err := task.Resume(ctx); err != nil {
			return fmt.Errorf("resuming container failed: %+v", err)
		}
		return nil
	}

	if !running && status.Status == ctrdd.Running {
		if err := task.Pause(ctx); err != nil {
			return fmt.Errorf("pausing container failed: %+v", err)
		}
		return nil
	}

	return nil
}

// read the global config and update the memory monitor status
func updateMemoryMonitorConfig(ctx *watcherContext) {
	log.Functionf("Updating memory monitor config")
	gcp := agentlog.GetGlobalConfig(log, ctx.subGlobalConfig)
	if gcp == nil {
		return
	}
	enabled := gcp.GlobalValueBool(types.MemoryMonitorEnabled)
	if enabled {
		log.Functionf("Enabling memory monitor")
		if err := setContainerRunning("memory-monitor", true); err != nil {
			log.Warnf("Resuming memory monitor failed: %v", err)
		}
	} else { // memory monitor is disabled
		log.Functionf("Disabling memory monitor")
		if err := setContainerRunning("memory-monitor", false); err != nil {
			log.Warnf("Pausing memory monitor failed: %v", err)
		}
	}
	return
}

// Listens to root cgroup in hierarchy mode (events always propagate
// up to the root) and call Go garbage collector with reasonable
// interval when certain amount of memory has been allocated (presumably
// there is something to reclaim) by an application.
func handleMemoryPressureEvents() {
	controller, err := cgroups.Load(cgroups.V1, cgroups.StaticPath(""))
	if err != nil {
		log.Warnf("handleMemoryPressureEvents(): failed to find root cgroups directory")
		return
	}
	defer controller.Delete()
	event := cgroups.MemoryPressureEvent(cgroups.MediumPressure,
		cgroups.HierarchyMode)
	efd, err := controller.RegisterMemoryEvent(event)

	fd := os.NewFile(efd, "efd")
	defer fd.Close()

	buf := make([]byte, 8)

	var before, after runtime.MemStats
	var expected uint64
	var ts time.Time

	// Infinite loop until error or death
	for {
		if _, err := fd.Read(buf); err != nil {
			log.Warnf("handleMemoryPressureEvents(): can't read eventfd, exiting loop")
			return
		}
		// GC is called explicitly no more than once every @interval,
		// and only if the application has already growth at least
		// @minGrowthMemAbs and certain fraction from the last
		// reclaim, so shortly:
		//     limit = MAX(minGrowthMemAbs, reclaimed * minGrowthMemPerc / 100)
		interval, minGrowthMemAbs, minGrowthMemPerc := getForcedGOGCParams()

		if interval == 0 || time.Now().Sub(ts) < interval {
			// Don't call GC frequently in case of many sequential events
			continue
		}
		runtime.ReadMemStats(&before)
		if before.Alloc < expected {
			// Not enough allocated since last GC call, skip this event
			continue
		}
		runtime.GC()
		runtime.ReadMemStats(&after)

		var reclaimed uint64
		// Careful, unlikely but can be negative if nothing was
		// reclaimed but allocation has happened just in between the
		// GC call and stats collection
		reclaimed = 0
		if before.Alloc > after.Alloc {
			reclaimed = before.Alloc - after.Alloc
		}
		// Limit on both criteria: absolute and relative to @reclaimed
		limit := reclaimed * minGrowthMemPerc / 100
		if limit < minGrowthMemAbs {
			limit = minGrowthMemAbs
		}
		expected = after.Alloc + limit
		ts = time.Now()

		log.Warnf("Received memory pressure event, before GC MemStats.Alloc=%vKB, after GC MemStats.Alloc=%vKB, reclaimed %vKB, next GC when MemStats.Alloc=%vKB is reached",
			before.Alloc>>10,
			after.Alloc>>10,
			reclaimed>>10,
			expected>>10)
	}
}

func movingAverage(data []int, windowSize int) []float64 {
	// Validates the window size
	if windowSize <= 0 {
		windowSize = 1 // Do not smooth the data
	}

	if windowSize > len(data) {
		windowSize = len(data)
	}

	if len(data) == 0 {
		return nil
	}

	smoothed := make([]float64, len(data)-windowSize+1)
	var windowSum int

	// Calculates the sum of the first window
	for i := 0; i < windowSize; i++ {
		windowSum += data[i]
	}
	smoothed[0] = float64(windowSum) / float64(windowSize)

	// Slides the window through the data
	for i := 1; i < len(smoothed); i++ {
		windowSum = windowSum - data[i-1] + data[i+windowSize-1]
		smoothed[i] = float64(windowSum) / float64(windowSize)
	}

	return smoothed
}

// calculateMeanStdDev calculates the mean and standard deviation of a slice of float64 numbers.
func calculateMeanStdDev(data []float64) (mean, stdDev float64) {
	n := float64(len(data))
	var sum, sumSq float64
	for _, value := range data {
		sum += value
		sumSq += value * value
	}
	mean = sum / n
	variance := (sumSq / n) - (mean * mean)
	stdDev = math.Sqrt(variance)
	return
}

// detectGoroutineLeaks detects if there's a potential goroutine leak over time.
// Returns true if a leak is detected, false otherwise.
func detectGoroutineLeaks(stats []int) (bool, []float64) {

	if len(stats) < 10 {
		// Not enough data to determine trend
		return false, nil
	}

	// The window size for the moving average
	windowSize := len(stats) / 10

	// Step 1: Smooth the data
	smoothedData := movingAverage(stats, windowSize)

	if len(smoothedData) < 2 {
		// Not enough data to determine trend
		return false, smoothedData
	}

	// Step 2: Calculate the rate of change
	rateOfChange := make([]float64, len(smoothedData)-1)
	for i := 1; i < len(smoothedData); i++ {
		rateOfChange[i-1] = smoothedData[i] - smoothedData[i-1]
	}

	// Step 3: Calculate mean and standard deviation of the rate of change
	mean, stdDev := calculateMeanStdDev(rateOfChange)

	// Step 4: Determine the dynamic threshold
	threshold := 0.0 + stdDev

	// Step 5: Check if the latest rate of change exceeds the threshold
	latestChange := rateOfChange[len(rateOfChange)-1]
	if mean > threshold && latestChange > threshold {
		log.Warnf("Potential goroutine leak detected: latest increase of %.2f exceeds dynamic threshold of %.2f.", latestChange, threshold)
		return true, smoothedData
	}
	return false, smoothedData
}

func handlePotentialGoroutineLeak() {
	// Dump the stack traces of all goroutines
	agentlog.DumpAllStacks(log, agentName)
}

// goroutinesMonitor monitors the number of goroutines and detects potential goroutine leaks.
func goroutinesMonitor(ctx *watcherContext) {
	log.Functionf("Starting goroutines monitor (stoppable: %v)", ctx.GRLDParams.isStoppable())
	// Get the initial goroutine leak detection parameters to create the stats slice
	goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod := ctx.GRLDParams.Get()
	entriesToKeep := int(keepStatsFor / checkInterval)
	stats := make([]int, 0, entriesToKeep+1)
	var lastLeakHandled time.Time
	for {
		// Check if we have to stop
		if ctx.GRLDParams.checkStopCondition() {
			log.Functionf("Stopping goroutines monitor")
			return
		}
		// Check if we have to resize the stats slice
		goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod = ctx.GRLDParams.Get()
		newEntriesToKeep := int(keepStatsFor / checkInterval)
		if newEntriesToKeep != entriesToKeep {
			entriesToKeep = newEntriesToKeep
			log.Functionf("Resizing stats slice to %d", entriesToKeep)
			if len(stats) > entriesToKeep {
				log.Functionf("Removing %d oldest entries", len(stats)-entriesToKeep)
				stats = stats[len(stats)-entriesToKeep:]
			}
		}
		entriesToCheck := int(checkStatsFor / checkInterval)
		// Wait for the next check interval
		time.Sleep(checkInterval)
		numGoroutines := runtime.NumGoroutine()
		// First check for the threshold
		if numGoroutines > goroutinesThreshold {
			log.Warnf("Number of goroutines exceeds threshold: %d", numGoroutines)
			if time.Since(lastLeakHandled) < cooldownPeriod {
				// Skip if we've handled a leak recently
				log.Warnf("Skipping stacks dumping due to cooldown period")
				continue
			}
			handlePotentialGoroutineLeak()
			lastLeakHandled = time.Now()
			continue
		}
		stats = append(stats, numGoroutines)
		// Keep the stats for the last keepStatsFor duration
		if len(stats) > entriesToKeep {
			stats = stats[1:]
		}

		// If we have enough data, detect goroutine leaks
		if len(stats) > entriesToCheck {
			// Analyze the data for the last check window
			entriesInLastCheckWindow := stats[len(stats)-entriesToCheck:]
			leakDetected, _ := detectGoroutineLeaks(entriesInLastCheckWindow)
			if leakDetected {
				// Count the number of goroutines that were created in the last check window
				numGoroutinesCheckWindowAgo := stats[len(stats)-entriesToCheck]
				leakCount := numGoroutines - numGoroutinesCheckWindowAgo
				minutesInCheckWindow := int(checkStatsFor.Minutes())
				log.Warnf("Potential goroutine leak! Created in the last %d minutes: %d, total: %d",
					minutesInCheckWindow, leakCount, numGoroutines)
				if time.Since(lastLeakHandled) < cooldownPeriod {
					// Skip detailed handling if we've handled a leak recently
					log.Warnf("Skipping stacks dumping due to cooldown period")
					continue
				}
				handlePotentialGoroutineLeak()
				lastLeakHandled = time.Now()
			}
		}
	}
}

// Run :
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject, arguments []string, baseDir string) int {
	logger = loggerArg
	log = logArg

	ctx := watcherContext{
		ps: ps,
	}
	agentbase.Init(&ctx, logger, log, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Look for global config such as log levels
	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    true,
		Activate:      false,
		Ctx:           &ctx,
		CreateHandler: handleGlobalConfigCreate,
		ModifyHandler: handleGlobalConfigModify,
		DeleteHandler: handleGlobalConfigDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	pubMemNotif, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.MemoryNotification{},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubMemoryNotification = pubMemNotif

	pubDiskNotif, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.DiskNotification{},
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	ctx.pubDiskNotification = pubDiskNotif

	subHostMemory, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "domainmgr",
		MyAgentName:   agentName,
		TopicImpl:     types.HostMemory{},
		Activate:      true,
		Ctx:           &ctx,
		CreateHandler: handleHostMemoryCreate,
		ModifyHandler: handleHostMemoryModify,
		DeleteHandler: handleHostMemoryDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subHostMemory = subHostMemory

	subDiskMetric, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "volumemgr",
		MyAgentName:   agentName,
		TopicImpl:     types.DiskMetric{},
		Activate:      true,
		Ctx:           &ctx,
		CreateHandler: handleDiskMetricCreate,
		ModifyHandler: handleDiskMetricModify,
		DeleteHandler: handleDiskMetricDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx.subDiskMetric = subDiskMetric

	for !ctx.GCInitialized {
		log.Functionf("waiting for GCInitialized")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	log.Functionf("processed GlobalConfig")

	if err := wait.WaitForVault(ps, log, agentName, warningTime, errorTime); err != nil {
		log.Fatal(err)
	}
	log.Functionf("processed Vault Status")

	// Handle memory pressure events by calling GC explicitly
	go handleMemoryPressureEvents()

	go goroutinesMonitor(&ctx)

	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
			setForcedGOGCParams(&ctx)
		case change := <-subHostMemory.MsgChan():
			subHostMemory.ProcessChange(change)
		case change := <-subDiskMetric.MsgChan():
			subDiskMetric.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func isPersistMetric(status types.DiskMetric) bool {
	return status.DiskPath == "/persist"
}

func computeUsageZoneAndSlab(total uint64, used uint64) (types.UsageZone, uint64, uint64) {
	usagePercentage := uint64((float64(used) / float64(total)) * 100)
	usageSlab := (usagePercentage / 10)
	slabExcess := usagePercentage % 10

	var zone types.UsageZone
	switch {
	case usagePercentage >= 90:
		zone = types.RedZone
	case usagePercentage >= 80:
		zone = types.OrangeZone
	case usagePercentage >= 50:
		zone = types.YellowZone
	default:
		zone = types.GreenZone
	}
	return zone, usageSlab, slabExcess
}

func makeDiskMetricNotification(status types.DiskMetric) types.DiskNotification {
	diskNotif := types.DiskNotification{
		Total:     status.TotalBytes,
		Used:      status.UsedBytes,
		PrevUsage: 0,
		PrevSlab:  0,
	}
	var excess uint64
	diskNotif.Zone, diskNotif.UsageSlab, excess = computeUsageZoneAndSlab(diskNotif.Total, diskNotif.Used)
	diskNotif.LastFive = []uint64{diskNotif.UsageSlab*10 + excess}

	return diskNotif
}

func makeHostMemoryNotification(status types.HostMemory) types.MemoryNotification {
	total := status.TotalMemoryMB * 1024 * 1024
	used := total - status.FreeMemoryMB*1024*1024
	memNotif := types.MemoryNotification{
		Total:     total,
		Used:      used,
		PrevUsage: 0,
		PrevSlab:  0,
	}
	var excess uint64
	memNotif.Zone, memNotif.UsageSlab, excess = computeUsageZoneAndSlab(memNotif.Total, memNotif.Used)
	memNotif.LastFive = []uint64{memNotif.UsageSlab*10 + excess}

	return memNotif
}

// getUsageSlab :
// To avoid flapping between slabs when there are transient changes back and forth,
// we only change slab when there is at least X percentage usage different between
// previous usage and current usage.
func getUsageSlab(used uint64, prevUsage uint64, total uint64) uint64 {
	currPercent := uint64((float64(used) / float64(total)) * 100)
	prevPercent := uint64((float64(prevUsage) / float64(total)) * 100)

	currSlab := (currPercent / 10)
	prevSlab := (prevPercent / 10)
	if currSlab == prevSlab {
		return currSlab
	}

	var usageDiff uint64
	if currPercent > prevPercent {
		usageDiff = currPercent - prevPercent
	} else {
		usageDiff = prevPercent - currPercent
	}
	if usageDiff < usageThreshold {
		return prevSlab
	}
	return currSlab
}

func handleHostMemoryCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.HostMemory)
	ctx := ctxArg.(*watcherContext)

	memNotif := makeHostMemoryNotification(status)

	ctx.pubMemoryNotification.Publish("global", memNotif)
	prevMemNotification = memNotif
	log.Functionf("handleHostMemoryCreate:")
}

func handleHostMemoryModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	status := statusArg.(types.HostMemory)
	ctx := ctxArg.(*watcherContext)

	memNotif := makeHostMemoryNotification(status)
	memNotif.PrevSlab = prevMemNotification.UsageSlab
	memNotif.PrevUsage = prevMemNotification.Used
	memNotif.UsageSlab = getUsageSlab(memNotif.Used, memNotif.PrevUsage, memNotif.Total)
	lastFive := prevMemNotification.LastFive

	currUsage := uint64((float64(memNotif.Used) / float64(memNotif.Total)) * 100)
	if len(lastFive) >= 5 {
		lastFive = append([]uint64{currUsage}, lastFive[:4]...)
	} else {
		lastFive = append([]uint64{currUsage}, lastFive[:]...)
	}
	memNotif.LastFive = lastFive

	ctx.pubMemoryNotification.Publish("global", memNotif)
	prevMemNotification = memNotif
	log.Functionf("handleHostMemoryModify:")
}

func handleHostMemoryDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	ctx := ctxArg.(*watcherContext)
	ctx.pubMemoryNotification.Publish("global", types.MemoryNotification{})
	log.Functionf("handleHostMemoryDelete:")
}

func handleDiskMetricCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.DiskMetric)
	ctx := ctxArg.(*watcherContext)

	if !isPersistMetric(status) {
		// We are only interested in the Global /persist metric
		return
	}

	diskNotif := makeDiskMetricNotification(status)
	prevDiskNotification = diskNotif

	ctx.pubDiskNotification.Publish("persist", diskNotif)
	log.Functionf("handleDiskMetricCreate:")
}

func handleDiskMetricModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	status := statusArg.(types.DiskMetric)
	ctx := ctxArg.(*watcherContext)

	if !isPersistMetric(status) {
		// We are only interested in the Global /persist metric
		return
	}
	diskNotif := makeDiskMetricNotification(status)
	diskNotif.PrevSlab = prevDiskNotification.UsageSlab
	diskNotif.PrevUsage = prevDiskNotification.Used
	diskNotif.UsageSlab = getUsageSlab(diskNotif.Used, diskNotif.PrevUsage, diskNotif.Total)
	lastFive := prevDiskNotification.LastFive

	currUsage := uint64((float64(diskNotif.Used) / float64(diskNotif.Total)) * 100)
	if len(lastFive) >= 5 {
		lastFive = append([]uint64{currUsage}, lastFive[:4]...)
	} else {
		lastFive = append([]uint64{currUsage}, lastFive[:]...)
	}
	diskNotif.LastFive = lastFive

	prevDiskNotification = diskNotif
	ctx.pubDiskNotification.Publish("persist", diskNotif)
	log.Functionf("handleDiskMetricModify:")
}

func handleDiskMetricDelete(ctxArg interface{}, key string,
	statusArg interface{}) {
	status := statusArg.(types.DiskMetric)
	ctx := ctxArg.(*watcherContext)

	if !isPersistMetric(status) {
		// We are only interested in the Global /persist metric
		return
	}
	ctx.pubDiskNotification.Publish("persist", types.DiskNotification{})
	log.Functionf("handleDiskMetricDelete:")
}

func handleGlobalConfigCreate(ctxArg interface{}, key string,
	statusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigModify(ctxArg interface{}, key string,
	statusArg interface{}, oldStatusArg interface{}) {
	handleGlobalConfigImpl(ctxArg, key, statusArg)
}

func handleGlobalConfigImpl(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*watcherContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigImpl: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigImpl for %s", key)
	gcp := agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	if gcp != nil {
		ctx.GCInitialized = true
	}
	updateGoroutineLeakDetectionConfig(ctx)
	updateMemoryMonitorConfig(ctx)
	log.Functionf("handleGlobalConfigImpl done for %s", key)
}

func handleGlobalConfigDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	ctx := ctxArg.(*watcherContext)
	if key != "global" {
		log.Functionf("handleGlobalConfigDelete: ignoring %s", key)
		return
	}
	log.Functionf("handleGlobalConfigDelete for %s", key)
	agentlog.HandleGlobalConfig(log, ctx.subGlobalConfig, agentName,
		ctx.CLIParams().DebugOverride, logger)
	log.Functionf("handleGlobalConfigDelete done for %s", key)
}
