// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/sirupsen/logrus"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Scenario 1: Initial growth that slows down and then stabilizes
func emulateSystemStart(startDuration, stabilizationDuration int) []int {
	totalDuration := startDuration + stabilizationDuration
	data := make([]int, startDuration)
	baseGoroutines := 0
	for i := 0; i < startDuration; i++ {
		// Simulate fast growth that slows down
		growth := int(500 * (1 - math.Exp(-float64(i)/10))) // Exponential decay
		data[i] = baseGoroutines + growth
	}
	// Stabilize after growth
	stableGoroutines := data[len(data)-1]
	for i := startDuration; i < totalDuration; i++ {
		data = append(data, stableGoroutines)
	}
	return data
}

// Scenario 2: Stabilization, then a process creates a lot of goroutines quickly, which then stabilizes
func emulateSpikeAfterSystemStart(startDuration, stabilizationDuration, spikeDuration int) []int {
	data := emulateSystemStart(startDuration, stabilizationDuration)
	totalStartDuration := len(data)
	baseGoroutines := data[len(data)-1]
	for i := totalStartDuration; i < totalStartDuration+spikeDuration; i++ {
		growth := int(100 * (1 - math.Exp(-float64(i-startDuration)/5))) // Quick spike
		data = append(data, baseGoroutines+growth)
	}
	// Stabilize after spike
	stableGoroutines := data[len(data)-1]
	for i := totalStartDuration + spikeDuration; i < totalStartDuration+spikeDuration+stabilizationDuration; i++ {
		data = append(data, stableGoroutines)
	}
	return data
}

// Scenario 3: After the spike, goroutine count decreases
func emulateDecreaseAfterSpike(decreaseDuration, spikeDuration, stabilizationDuration, startDuration int) []int {
	data := emulateSpikeAfterSystemStart(startDuration, stabilizationDuration, spikeDuration)
	decreaseStart := len(data)
	baseGoroutines := data[decreaseStart-1]
	for i := 0; i < decreaseDuration; i++ {
		decrease := int(float64(baseGoroutines) * (1 - float64(i)/float64(decreaseDuration)))
		data = append(data, decrease)
	}
	return data
}

// Scenario 4: After the spike, goroutine count starts to slowly increase over time
func emulateLeakAfterSpike(leakDuration, stabilizationDuration, spikeDuration, startDuration int) []int {
	data := emulateSpikeAfterSystemStart(startDuration, stabilizationDuration, spikeDuration)
	increaseStart := len(data)
	baseGoroutines := data[increaseStart-1]
	for i := increaseStart; i < increaseStart+leakDuration; i++ {
		// Slow linear increase
		growth := baseGoroutines + (i-increaseStart)*5
		data = append(data, growth)
	}
	return data
}

func TestMain(m *testing.M) {
	logger, log = agentlog.Init("watcher")
	os.Exit(m.Run())
}

// Computes moving average correctly for valid data and window size
func TestMovingAverageValidData(t *testing.T) {
	data := []int{1, 2, 3, 4, 5}
	windowSize := 3
	expected := []float64{2.0, 3.0, 4.0}

	result := movingAverage(data, windowSize)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

// Handles window size equal to data length by returning a single average
func TestMovingAverageWindowSizeEqualDataLength(t *testing.T) {
	data := []int{1, 2, 3, 4, 5}
	windowSize := 5
	expected := []float64{3.0}

	result := movingAverage(data, windowSize)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

// Handles empty data array gracefully
func TestMovingAverageEmptyData(t *testing.T) {
	data := []int{}
	windowSize := 3
	var expected []float64
	expected = nil

	result := movingAverage(data, windowSize)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v (type %T), got %v (type %T)", expected, expected, result, result)
	}
}

// Manages window size of zero by defaulting to 1
func TestMovingAverageWindowSizeZero(t *testing.T) {
	data := []int{1, 2, 3, 4, 5}
	windowSize := 0
	expected := []float64{1.0, 2.0, 3.0, 4.0, 5.0}

	result := movingAverage(data, windowSize)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

// Deals with window size larger than data length by defaulting to data length
func TestMovingAverageWindowSizeLargerThanDataLength(t *testing.T) {
	data := []int{1, 2, 3}
	windowSize := 5
	expected := []float64{2.0}

	result := movingAverage(data, windowSize)

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, got %v", expected, result)
	}
}

func TestGoroutineLeakDetectorWithSystemStart(t *testing.T) {
	backupOut := logger.Out
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(backupOut)
	stats := emulateSystemStart(5, 5)
	detected, _ := detectGoroutineLeaks(stats)
	if detected {
		t.Errorf("Expected no goroutine leak, but detected one")
	}
}

func TestGoroutineLeakDetectorWithLegitSpike(t *testing.T) {
	backupOut := logger.Out
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(backupOut)
	stats := emulateSpikeAfterSystemStart(5, 5, 20)
	detected, _ := detectGoroutineLeaks(stats)
	if detected {
		t.Errorf("Expected no goroutine leak, but detected one")
	}
}

func TestGoroutineLeakDetectorWithDecreaseAfterSpike(t *testing.T) {
	backupOut := logger.Out
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(backupOut)
	stats := emulateDecreaseAfterSpike(10, 20, 5, 5)
	detected, _ := detectGoroutineLeaks(stats)
	if detected {
		t.Errorf("Expected no goroutine leak, but detected one")
	}
}

func TestGoroutineLeakDetectorWithLeakAfterSpike(t *testing.T) {
	backupOut := logger.Out
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(backupOut)
	stats := emulateLeakAfterSpike(100, 5, 20, 5)
	detected, _ := detectGoroutineLeaks(stats)
	if !detected {
		t.Errorf("Expected goroutine leak to be detected, but it was not")
	}
}

func TestGoroutineLeakDetectorWithLeakEachStep(t *testing.T) {
	backupOut := logger.Out
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(backupOut)
	startDuration := 5
	stabilizationDuration := 5
	spikeDuration := 20
	leakDuration := 100
	leakMayBeDetectedAfter := startDuration + stabilizationDuration + spikeDuration + stabilizationDuration
	possibleFalsePositives := 60
	leakMustBeDetectedAfter := leakMayBeDetectedAfter + possibleFalsePositives
	stats := emulateLeakAfterSpike(leakDuration, stabilizationDuration, spikeDuration, startDuration)
	// Now check the behavior of detector on each new data point
	for i := 0; i < len(stats); i++ {
		detected, _ := detectGoroutineLeaks(stats[:i])
		// Leak should be detected after the slow increase starts
		if detected && i < startDuration+stabilizationDuration+spikeDuration+stabilizationDuration {
			t.Errorf("Expected no goroutine leak, but detected one at step %d", i)
		}
		if !detected && i >= leakMayBeDetectedAfter && i < leakMustBeDetectedAfter {
			t.Logf("Expected goroutine leak to be detected, but it was not at step %d", i)
		}
		if !detected && i >= leakMustBeDetectedAfter {
			t.Errorf("Expected goroutine leak to be detected, but it was not at step %d", i)
		}
	}
}

// Handles empty input data gracefully
func TestEmptyInputData(t *testing.T) {
	backupOut := logger.Out
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(backupOut)
	stats := []int{}
	detected, smoothedData := detectGoroutineLeaks(stats)
	if detected || smoothedData != nil {
		t.Errorf("Expected no detection and nil smoothed data for empty input")
	}
}

// Handles input data with fewer than two elements
func TestInputDataWithFewerThanTwoElements(t *testing.T) {
	backupOut := logger.Out
	logger.SetOutput(io.Discard)
	defer logger.SetOutput(backupOut)
	stats := []int{5}
	detected, smoothedData := detectGoroutineLeaks(stats)
	if detected || len(smoothedData) != 0 {
		t.Errorf("Expected no detection and empty smoothed data for input with fewer than two elements")
	}
}

// Handles window size larger than data length
func TestWindowSizeLargerThanDataLength(t *testing.T) {
	stats := []int{1, 2}
	windowSize := len(stats) + 1
	smoothedData := movingAverage(stats, windowSize)
	if len(smoothedData) != 1 {
		t.Errorf("Expected smoothed data length of 1 when window size is larger than data length")
	}
}

// Monitors goroutine count at regular intervals
func TestGoroutinesMonitorNoLeak(t *testing.T) {
	keepStatsFor := 24 * 60 * time.Millisecond
	goroutinesThreshold := 100
	checkInterval := 1 * time.Millisecond
	checkStatsFor := 10 * time.Millisecond
	cooldownPeriod := 5 * time.Millisecond

	backupOut := logger.Out
	// Create a pipe to capture log output
	r, w, _ := os.Pipe()
	logger.SetOutput(w)
	defer logger.SetOutput(backupOut)

	// Create context with default parameters
	ctx := &watcherContext{}
	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)
	ctx.GRLDParams.MakeStoppable()

	go goroutinesMonitor(ctx)
	defer ctx.GRLDParams.Stop()

	timeStart := time.Now()
	for {
		if time.Since(timeStart) > 2*keepStatsFor {
			break
		}
		// Create a goroutine
		go func() {
			time.Sleep(checkInterval / 2)
		}()
		time.Sleep(2 * checkInterval)
	}

	// Close the pipe
	w.Close()

	// Read the log output
	output, _ := io.ReadAll(r)

	// Check if the log output does not contain the detection message
	// If it does, it means that the goroutine leak was detected
	if strings.Contains(string(output), "leak detected") {
		t.Errorf("Expected no goroutine leak to be detected")
	}

}

func TestGoroutinesMonitorLeak(t *testing.T) {
	keepStatsFor := 24 * 60 * time.Millisecond
	goroutinesThreshold := 100
	checkInterval := 1 * time.Millisecond
	checkStatsFor := 10 * time.Millisecond
	cooldownPeriod := 5 * time.Millisecond

	backupOut := logger.Out
	// Create a pipe to capture log output
	r, w, _ := os.Pipe()
	logger.SetOutput(w)
	defer logger.SetOutput(backupOut)

	// Create context with default parameters
	ctx := &watcherContext{}
	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)
	ctx.GRLDParams.MakeStoppable()

	go goroutinesMonitor(ctx)
	defer ctx.GRLDParams.Stop()

	timeStart := time.Now()
	for {
		if time.Since(timeStart) > 2*keepStatsFor {
			break
		}
		// Create a goroutine
		go func() {
			time.Sleep(checkInterval * 100)
		}()
		time.Sleep(checkInterval / 2)
	}

	// Close the pipe
	_ = w.Close()

	// Read the log output
	output, _ := io.ReadAll(r)

	// Check if the log output contains the expected message
	if !strings.Contains(string(output), "leak detected") {
		t.Errorf("Expected log output to contain 'leak detected'")
	}
}

// Adjust stats slice size dynamically based on updated parameters
func TestGoroutinesMonitorUpdateParamsKeepStatsDecrease(t *testing.T) {
	backupOut := logger.Out
	backupLevel := logger.Level
	// Create a pipe to capture log output
	r, w, _ := os.Pipe()
	logger.SetOutput(w)
	logger.SetLevel(logrus.TraceLevel)
	defer func() {
		logger.SetOutput(backupOut)
		logger.SetLevel(backupLevel)
	}()

	// Define a context with default parameters
	ctx := &watcherContext{}

	// Define parameters
	goroutinesThreshold := 100
	checkInterval := 1 * time.Millisecond
	checkStatsFor := 10 * time.Millisecond
	keepStatsFor := 24 * 60 * time.Millisecond
	cooldownPeriod := 5 * time.Millisecond

	// Set the parameters
	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)
	ctx.GRLDParams.MakeStoppable()

	go goroutinesMonitor(ctx)
	defer ctx.GRLDParams.Stop()

	// Wait until we fill the stats slice
	time.Sleep(2 * keepStatsFor)

	// Count the expected size of the stats slice
	oldSize := int(keepStatsFor / checkInterval)

	// Change the keepStatsFor parameter to force resizing of the stats slice
	keepStatsFor /= 2

	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)

	// Wait for several check intervals to allow the new context to be updated
	time.Sleep(checkInterval * 100)

	// Close the pipe
	_ = w.Close()
	output, _ := io.ReadAll(r)

	expectedNewSize := int(keepStatsFor / checkInterval)
	expectedRemovedEntries := oldSize - expectedNewSize

	// Define the expected log output with the new size
	msgResize := fmt.Sprintf("Resizing stats slice to %d", expectedNewSize)
	msgRemove := fmt.Sprintf("Removing %d oldest entries", expectedRemovedEntries)

	expectedMsgs := []string{msgResize, msgRemove}

	// Check if the log output contains the expected messages
	for _, expectedMsg := range expectedMsgs {
		if !strings.Contains(string(output), expectedMsg) {
			t.Errorf("Expected log output to contain '%s', but got '%s'", expectedMsg, output)
		}
	}
}

// Adjust stats slice size dynamically based on updated parameters
func TestGoroutinesMonitorUpdateParamsKeepStatsIncrease(t *testing.T) {
	backupOut := logger.Out
	backupLevel := logger.Level
	// Create a pipe to capture log output
	r, w, _ := os.Pipe()
	logger.SetOutput(w)
	logger.SetLevel(logrus.TraceLevel)
	defer func() {
		logger.SetOutput(backupOut)
		logger.SetLevel(backupLevel)
	}()

	// Define a context with default parameters
	ctx := &watcherContext{}

	// Define parameters
	goroutinesThreshold := 100
	checkInterval := 1 * time.Millisecond
	checkStatsFor := 10 * time.Millisecond
	keepStatsFor := 24 * 60 * time.Millisecond
	cooldownPeriod := 5 * time.Millisecond

	// Set the parameters
	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)
	ctx.GRLDParams.MakeStoppable()

	go goroutinesMonitor(ctx)
	defer ctx.GRLDParams.Stop()

	// Wait until we fill the stats slice
	time.Sleep(2 * keepStatsFor)

	// Change the keepStatsFor parameter to force resizing of the stats slice
	keepStatsFor *= 2

	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)

	// Wait for several check intervals to allow the new context to be updated
	time.Sleep(checkInterval * 100)

	// Close the pipe
	_ = w.Close()
	output, _ := io.ReadAll(r)

	expectedNewSize := int(keepStatsFor / checkInterval)

	// Define the expected log output with the new size
	msgResize := fmt.Sprintf("Resizing stats slice to %d", expectedNewSize)

	expectedMsgs := []string{msgResize}

	// Check if the log output contains the expected messages
	for _, expectedMsg := range expectedMsgs {
		if !strings.Contains(string(output), expectedMsg) {
			t.Errorf("Expected log output to contain '%s'", expectedMsg)
		}
	}
}

func TestGoroutineMonitorStops(t *testing.T) {
	keepStatsFor := 24 * 60 * time.Millisecond
	goroutinesThreshold := 100
	checkInterval := 1 * time.Millisecond
	checkStatsFor := 10 * time.Millisecond
	cooldownPeriod := 5 * time.Millisecond

	backupOut := logger.Out
	backupLevel := logger.Level
	// Create a pipe to capture log output
	r, w, _ := os.Pipe()
	logger.SetOutput(w)
	logger.SetLevel(logrus.TraceLevel)

	// Create context with default parameters
	ctx := &watcherContext{}
	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)
	ctx.GRLDParams.MakeStoppable()

	go goroutinesMonitor(ctx)

	// Let the monitor run for a while
	time.Sleep(keepStatsFor * 2)

	ctx.GRLDParams.Stop()

	// Wait for several check intervals to allow the monitor to stop
	time.Sleep(checkInterval * 100)

	// Close the pipe
	_ = w.Close()
	logger.SetOutput(backupOut)
	logger.SetLevel(backupLevel)

	// Read the log output
	output, _ := io.ReadAll(r)

	msgStart := "Starting goroutines monitor (stoppable: true)"
	msgStop := "Stopping goroutines monitor"
	expectedMsgs := []string{msgStart, msgStop}
	for _, expectedMsg := range expectedMsgs {
		if !strings.Contains(string(output), expectedMsg) {
			t.Errorf("Expected log output to contain '%s'", expectedMsg)
		}
	}
}

func TestGoroutineMonitorRunsFineUnstoppable(t *testing.T) {
	keepStatsFor := 24 * 60 * time.Millisecond
	goroutinesThreshold := 100
	checkInterval := 1 * time.Millisecond
	checkStatsFor := 10 * time.Millisecond
	cooldownPeriod := 5 * time.Millisecond

	backupOut := logger.Out
	backupLevel := logger.Level
	// Create a pipe to capture log output
	r, w, _ := os.Pipe()
	logger.SetOutput(w)
	logger.SetLevel(logrus.TraceLevel)
	defer func() {
		logger.SetOutput(backupOut)
		logger.SetLevel(backupLevel)
	}()

	// Create context with default parameters
	ctx := &watcherContext{}
	ctx.GRLDParams.Set(goroutinesThreshold, checkInterval, checkStatsFor, keepStatsFor, cooldownPeriod)

	go goroutinesMonitor(ctx)

	time.Sleep(keepStatsFor * 2)

	// Close the pipe
	_ = w.Close()

	// Read the log output
	output, _ := io.ReadAll(r)

	msgStart := "Starting goroutines monitor (stoppable: false)"
	expectedMsgs := []string{msgStart}
	for _, expectedMsg := range expectedMsgs {
		if !strings.Contains(string(output), expectedMsg) {
			t.Errorf("Expected log output to contain '%s'", expectedMsg)
		}
	}

}
