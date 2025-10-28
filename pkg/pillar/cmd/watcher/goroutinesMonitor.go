// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"math"
	"runtime"
	"sync"
	"time"
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

// GoroutinesMonitor monitors the number of goroutines and detects potential goroutine leaks.
func GoroutinesMonitor(ctx *watcherContext) {
	log.Functionf("Starting goroutines monitor (stoppable: %v)", ctx.GRLDParams.isStoppable())
	log.Warnf("#ohm: GoroutinesMonitor started")
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
