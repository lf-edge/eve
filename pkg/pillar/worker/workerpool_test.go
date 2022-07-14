// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// worker provides a dynamic set of workers so that work can be
// spawned without head-of-line blocking

package worker_test

import (
	"errors"
	"log"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	"github.com/sirupsen/logrus"
)

var sleep1 = dummyDescription{
	sleepTime:      1,
	generateOutput: "sleep1",
}
var sleep2 = dummyDescription{
	sleepTime:      2,
	generateOutput: "sleep2",
}

var sleep3 = dummyDescription{
	sleepTime:      3,
	generateOutput: "sleep3",
}

var sleep4 = dummyDescription{
	sleepTime:      4,
	generateOutput: "sleep4",
}

var sleep8 = dummyDescription{
	sleepTime:      8,
	generateOutput: "sleep8",
}

var sleep20 = dummyDescription{
	sleepTime:      20,
	generateOutput: "sleep20",
}

var logObject *base.LogObject

func setupPool(maxPool int) (*dummyContext, *worker.Pool, *worker.WorkResult) {
	ctx := dummyContext{contextName: "testContext"}
	var res worker.WorkResult
	dummyResponse := func(ctx interface{}, r worker.WorkResult) error {
		res = r
		return nil
	}
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.TraceLevel)
	logObject = base.NewSourceLogObject(logger, "test", 1234)
	wp := worker.NewPoolWithGC(
		logObject,
		&ctx, maxPool, map[string]worker.Handler{
			"test": {Request: dummyWorker, Response: dummyResponse},
		},
		1, 2)
	return &ctx, wp.(*worker.Pool), &res
}

// TestInOrder verifies that workers are spawned and return in order
func TestInOrder(t *testing.T) {
	time.Sleep(time.Second)
	origStacks := getStacks(true)
	numGoroutines := runtime.NumGoroutine()
	ctx, wp, res := setupPool(3)
	testname := "testinorder"

	t.Logf("Running test case %s", testname)
	start := time.Now()
	w1 := worker.Work{Kind: "test", Key: testname + "1", Description: sleep1}
	done, err := wp.TrySubmit(w1)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 1, wp.NumWorkers())
	assert.Equal(t, 1, wp.NumPending())

	w2 := worker.Work{Kind: "test", Key: testname + "2", Description: sleep2}
	done, err = wp.TrySubmit(w2)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 2, wp.NumWorkers())
	assert.Equal(t, 2, wp.NumPending())

	w3 := worker.Work{Kind: "test", Key: testname + "3", Description: sleep3}
	done, err = wp.TrySubmit(w3)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 3, wp.NumWorkers())
	assert.Equal(t, 3, wp.NumPending())

	// This one will fail
	w4 := worker.Work{Kind: "test", Key: testname + "4", Description: sleep4}
	done, err = wp.TrySubmit(w4)
	assert.False(t, done)
	assert.NotNil(t, err)
	logrus.Error(err)
	assert.Equal(t, 3, wp.NumWorkers())
	assert.Equal(t, 3, wp.NumPending())

	proc1 := <-wp.MsgChan()
	proc1.Process(ctx, true)
	res1 := wp.Pop(testname + "1")
	assert.Equal(t, testname+"1", res1.Key)
	assert.Equal(t, 2, wp.NumPending())
	assert.Equal(t, testname+"1", res.Key)
	assert.Equal(t, sleep1.generateOutput, res.Output)

	proc2 := <-wp.MsgChan()
	proc2.Process(ctx, true)
	res2 := wp.Pop(testname + "2")
	assert.Equal(t, testname+"2", res2.Key)
	assert.Equal(t, 1, wp.NumPending())
	assert.Equal(t, testname+"2", res.Key)
	assert.Equal(t, sleep2.generateOutput, res.Output)

	proc3 := <-wp.MsgChan()
	proc3.Process(ctx, true)
	res3 := wp.Pop(testname + "3")
	assert.Equal(t, testname+"3", res3.Key)
	assert.Equal(t, sleep3.generateOutput, res3.Output)
	assert.Equal(t, 0, wp.NumPending())

	// Should have completed in parallel i.e., more than max (3) and less
	// than sum (1+2+3) of sleeptime
	took := time.Since(start)
	assert.GreaterOrEqual(t, int64(took), int64(3*time.Second))
	assert.LessOrEqual(t, int64(took), int64(6*time.Second))

	wp.Done()
	_, ok := <-wp.MsgChan()
	done = !ok
	assert.True(t, done)
	// Check that goroutines are gone
	time.Sleep(time.Second)
	newCount := runtime.NumGoroutine()
	assert.Equal(t, numGoroutines, newCount)
	if numGoroutines != newCount {
		t.Logf("All goroutine stacks on entry: %v",
			origStacks)
		t.Logf("All goroutine stacks on exit: %v",
			getStacks(true))
	}
}

// TestNoLimit verifies that zero means no limit
func TestNoLimit(t *testing.T) {
	time.Sleep(time.Second)
	origStacks := getStacks(true)
	numGoroutines := runtime.NumGoroutine()
	ctx, wp, res := setupPool(0)
	testname := "testnolimit"

	t.Logf("Running test case %s", testname)
	start := time.Now()
	w1 := worker.Work{Kind: "test", Key: testname + "1", Description: sleep1}
	done, err := wp.TrySubmit(w1)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 1, wp.NumWorkers())
	assert.Equal(t, 1, wp.NumPending())

	w2 := worker.Work{Kind: "test", Key: testname + "2", Description: sleep2}
	done, err = wp.TrySubmit(w2)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 2, wp.NumWorkers())
	assert.Equal(t, 2, wp.NumPending())

	w3 := worker.Work{Kind: "test", Key: testname + "3", Description: sleep3}
	done, err = wp.TrySubmit(w3)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 3, wp.NumWorkers())
	assert.Equal(t, 3, wp.NumPending())

	w4 := worker.Work{Kind: "test", Key: testname + "4", Description: sleep4}
	done, err = wp.TrySubmit(w4)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 4, wp.NumWorkers())
	assert.Equal(t, 4, wp.NumPending())

	proc1 := <-wp.MsgChan()
	proc1.Process(ctx, true)
	assert.Equal(t, 3, wp.NumPending())
	assert.Equal(t, testname+"1", res.Key)
	assert.Equal(t, sleep1.generateOutput, res.Output)

	proc2 := <-wp.MsgChan()
	proc2.Process(ctx, true)
	assert.Equal(t, 2, wp.NumPending())
	assert.Equal(t, testname+"2", res.Key)
	assert.Equal(t, sleep2.generateOutput, res.Output)

	proc3 := <-wp.MsgChan()
	proc3.Process(ctx, true)
	// this one uses the Pop, so we exercise it
	res3 := wp.Pop(testname + "3")
	assert.Equal(t, testname+"3", res3.Key)
	assert.Equal(t, sleep3.generateOutput, res3.Output)
	assert.Equal(t, 1, wp.NumPending())

	proc4 := <-wp.MsgChan()
	proc4.Process(ctx, true)
	res4 := wp.Pop(testname + "4")
	assert.Equal(t, testname+"4", res4.Key)
	assert.Equal(t, sleep4.generateOutput, res4.Output)
	assert.Equal(t, 0, wp.NumPending())

	// Should have completed in parallel i.e., more than max (4) and less
	// than sum (1+2+3+4) of sleeptime
	took := time.Since(start)
	assert.GreaterOrEqual(t, int64(took), int64(4*time.Second))
	assert.LessOrEqual(t, int64(took), int64(10*time.Second))

	wp.Done()
	_, ok := <-wp.MsgChan()
	done = !ok
	assert.True(t, done)
	// Check that goroutines are gone
	time.Sleep(time.Second)
	newCount := runtime.NumGoroutine()
	assert.Equal(t, numGoroutines, newCount)
	if numGoroutines != newCount {
		t.Logf("All goroutine stacks on entry: %v",
			origStacks)
		t.Logf("All goroutine stacks on exit: %v",
			getStacks(true))
	}
}

// TestNoblocking verifies that a short after a long completes first
func TestNoblocking(t *testing.T) {
	time.Sleep(time.Second)
	origStacks := getStacks(true)
	numGoroutines := runtime.NumGoroutine()
	ctx, wp, res := setupPool(3)
	testname := "testnoblocking"

	t.Logf("Running test case %s", testname)
	start := time.Now()
	w1 := worker.Work{Kind: "test", Key: testname + "1", Description: sleep4}
	done, err := wp.TrySubmit(w1)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 1, wp.NumWorkers())
	assert.Equal(t, 1, wp.NumPending())

	w2 := worker.Work{Kind: "test", Key: testname + "2", Description: sleep1}
	done, err = wp.TrySubmit(w2)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 2, wp.NumWorkers())
	assert.Equal(t, 2, wp.NumPending())

	proc1 := <-wp.MsgChan()
	proc1.Process(ctx, true)
	assert.Equal(t, 1, wp.NumPending())
	assert.Equal(t, testname+"2", res.Key)
	assert.Equal(t, sleep1.generateOutput, res.Output)

	proc2 := <-wp.MsgChan()
	proc2.Process(ctx, true)
	assert.Equal(t, 0, wp.NumPending())
	assert.Equal(t, testname+"1", res.Key)
	assert.Equal(t, sleep4.generateOutput, res.Output)

	// Should have completed in parallel i.e., more than max (4) and less
	// than sum (1+4) of sleeptime
	took := time.Since(start)
	assert.GreaterOrEqual(t, int64(took), int64(4*time.Second))
	assert.LessOrEqual(t, int64(took), int64(5*time.Second))

	wp.Done()
	_, ok := <-wp.MsgChan()
	done = !ok
	assert.True(t, done)
	// Check that goroutines are gone
	time.Sleep(time.Second)
	newCount := runtime.NumGoroutine()
	assert.Equal(t, numGoroutines, newCount)
	if numGoroutines != newCount {
		t.Logf("All goroutine stacks on entry: %v",
			origStacks)
		t.Logf("All goroutine stacks on exit: %v",
			getStacks(true))
	}
}

// TestGC verifies that unused workers are deleted
func TestGC(t *testing.T) {
	time.Sleep(time.Second)
	origStacks := getStacks(true)
	numGoroutines := runtime.NumGoroutine()
	ctx, wp, res := setupPool(0)
	testname := "testgc"

	t.Logf("Running test case %s", testname)
	w1 := worker.Work{Kind: "test", Key: testname + "1", Description: sleep20}
	done, err := wp.TrySubmit(w1)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 1, wp.NumWorkers())
	assert.Equal(t, 1, wp.NumPending())

	w2 := worker.Work{Kind: "test", Key: testname + "2", Description: sleep1}
	done, err = wp.TrySubmit(w2)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 2, wp.NumWorkers())
	assert.Equal(t, 2, wp.NumPending())

	w3 := worker.Work{Kind: "test", Key: testname + "3", Description: sleep4}
	done, err = wp.TrySubmit(w3)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 3, wp.NumWorkers())
	assert.Equal(t, 3, wp.NumPending())

	w4 := worker.Work{Kind: "test", Key: testname + "4", Description: sleep8}
	done, err = wp.TrySubmit(w4)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 4, wp.NumWorkers())
	assert.Equal(t, 4, wp.NumPending())

	// Pick up 1 second one
	proc2 := <-wp.MsgChan()
	err = proc2.Process(ctx, true)
	assert.Nil(t, err)
	res2 := wp.Pop(testname + "2")
	assert.Equal(t, testname+"2", res2.Key)
	assert.Equal(t, 3, wp.NumPending())
	assert.Equal(t, testname+"2", res.Key)
	assert.Equal(t, sleep1.generateOutput, res.Output)

	// Wait for GC timer after 1 second test
	time.Sleep(2 * time.Second)
	assert.Equal(t, 3, wp.NumWorkers())

	// Pick up four seconds test
	proc3 := <-wp.MsgChan()
	err = proc3.Process(ctx, true)
	assert.Nil(t, err)
	res3 := wp.Pop(testname + "3")
	assert.Equal(t, testname+"3", res3.Key)
	assert.Equal(t, 2, wp.NumPending())
	assert.Equal(t, testname+"3", res.Key)
	assert.Equal(t, sleep4.generateOutput, res.Output)

	// Wait for GC timer after four second test
	time.Sleep(2 * time.Second)
	assert.Equal(t, 2, wp.NumWorkers())

	// sleep to keep eight seconds test work in the background
	time.Sleep(8 * time.Second)

	w5 := worker.Work{Kind: "test", Key: testname + "5", Description: sleep1}
	done, err = wp.TrySubmit(w5)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 2, wp.NumWorkers())
	assert.Equal(t, 3, wp.NumPending())

	// Pick up eight seconds test
	// it is expected to end before one second test
	// as we wait enough for result
	proc4 := <-wp.MsgChan()
	err = proc4.Process(ctx, true)
	assert.Nil(t, err)
	res4 := wp.Pop(testname + "4")
	assert.Equal(t, testname+"4", res4.Key)
	assert.Equal(t, 2, wp.NumPending())
	assert.Equal(t, testname+"4", res.Key)
	assert.Equal(t, sleep8.generateOutput, res.Output)

	// Pick up one second test
	proc5 := <-wp.MsgChan()
	err = proc5.Process(ctx, true)
	assert.Nil(t, err)
	res5 := wp.Pop(testname + "5")
	assert.Equal(t, testname+"5", res5.Key)
	assert.Equal(t, 1, wp.NumPending())
	assert.Equal(t, testname+"5", res.Key)
	assert.Equal(t, sleep1.generateOutput, res.Output)

	proc1 := <-wp.MsgChan()
	err = proc1.Process(ctx, true)
	assert.Nil(t, err)
	res1 := wp.Pop(testname + "1")
	assert.Equal(t, testname+"1", res1.Key)
	assert.Equal(t, 0, wp.NumPending())
	assert.Equal(t, testname+"1", res.Key)
	assert.Equal(t, sleep20.generateOutput, res.Output)
	assert.Equal(t, 1, wp.NumWorkers())

	wp.Done()
	_, ok := <-wp.MsgChan()
	done = !ok
	assert.True(t, done)
	assert.Equal(t, 0, wp.NumWorkers())

	// Check that goroutines are gone
	time.Sleep(time.Second)
	newCount := runtime.NumGoroutine()
	assert.Equal(t, numGoroutines, newCount)
	if numGoroutines != newCount {
		t.Logf("All goroutine stacks on entry: %v",
			origStacks)
		t.Logf("All goroutine stacks on exit: %v",
			getStacks(true))
	}
}

// TestNoGC verifies that workers with pending work are not delete
func TestNoGC(t *testing.T) {
	time.Sleep(time.Second)
	origStacks := getStacks(true)
	numGoroutines := runtime.NumGoroutine()
	ctx, wp, res := setupPool(0)
	testname := "testnogc"

	t.Logf("Running test case %s", testname)
	w1 := worker.Work{Kind: "test", Key: testname + "1", Description: sleep20}
	done, err := wp.TrySubmit(w1)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 1, wp.NumWorkers())
	assert.Equal(t, 1, wp.NumPending())

	w2 := worker.Work{Kind: "test", Key: testname + "2", Description: sleep1}
	done, err = wp.TrySubmit(w2)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 2, wp.NumWorkers())
	assert.Equal(t, 2, wp.NumPending())

	w3 := worker.Work{Kind: "test", Key: testname + "3", Description: sleep3}
	done, err = wp.TrySubmit(w3)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 3, wp.NumWorkers())
	assert.Equal(t, 3, wp.NumPending())

	w4 := worker.Work{Kind: "test", Key: testname + "4", Description: sleep4}
	done, err = wp.TrySubmit(w4)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 4, wp.NumWorkers())
	assert.Equal(t, 4, wp.NumPending())

	// Pick up 1 second one and two second one
	proc2 := <-wp.MsgChan()
	proc2.Process(ctx, true)
	time.Sleep(10 * time.Second)
	res2 := wp.Pop(testname + "2")
	assert.Equal(t, testname+"2", res2.Key)
	assert.Equal(t, 3, wp.NumPending())
	assert.Equal(t, testname+"2", res.Key)
	assert.Equal(t, sleep1.generateOutput, res.Output)

	proc3 := <-wp.MsgChan()
	proc3.Process(ctx, true)
	time.Sleep(10 * time.Second)
	res3 := wp.Pop(testname + "3")
	assert.Equal(t, testname+"3", res3.Key)
	assert.Equal(t, 2, wp.NumPending())
	assert.Equal(t, testname+"3", res.Key)
	assert.Equal(t, sleep3.generateOutput, res.Output)

	assert.Equal(t, 3, wp.NumWorkers())
	// Wait for GC timer
	time.Sleep(10 * time.Second)

	w5 := worker.Work{Kind: "test", Key: testname + "5", Description: sleep1}
	done, err = wp.TrySubmit(w5)
	assert.True(t, done)
	assert.Nil(t, err)
	assert.Equal(t, 2, wp.NumWorkers())
	assert.Equal(t, 3, wp.NumPending())

	proc4 := <-wp.MsgChan()
	proc4.Process(ctx, true)
	time.Sleep(10 * time.Second)
	res4 := wp.Pop(testname + "4")
	assert.Equal(t, testname+"4", res4.Key)
	assert.Equal(t, 2, wp.NumPending())
	assert.Equal(t, testname+"4", res.Key)
	assert.Equal(t, sleep4.generateOutput, res.Output)

	proc1 := <-wp.MsgChan()
	proc1.Process(ctx, true)
	time.Sleep(10 * time.Second)
	res1 := wp.Pop(testname + "1")
	assert.Equal(t, testname+"1", res1.Key)
	assert.Equal(t, 1, wp.NumPending())
	assert.Equal(t, testname+"1", res.Key)
	assert.Equal(t, sleep20.generateOutput, res.Output)

	proc5 := <-wp.MsgChan()
	proc5.Process(ctx, true)
	res5 := wp.Pop(testname + "5")
	assert.Equal(t, testname+"5", res5.Key)
	assert.Equal(t, 0, wp.NumPending())
	assert.Equal(t, testname+"5", res.Key)
	assert.Equal(t, sleep1.generateOutput, res.Output)
	assert.Equal(t, 1, wp.NumWorkers())

	wp.Done()
	_, ok := <-wp.MsgChan()
	done = !ok
	assert.True(t, done)
	assert.Equal(t, 0, wp.NumWorkers())

	// Check that goroutines are gone
	time.Sleep(time.Second)
	newCount := runtime.NumGoroutine()
	assert.Equal(t, numGoroutines, newCount)
	if numGoroutines != newCount {
		t.Logf("All goroutine stacks on entry: %v",
			origStacks)
		t.Logf("All goroutine stacks on exit: %v",
			getStacks(true))
	}
}

type dummyContext struct {
	contextName string
}

type dummyDescription struct {
	sleepTime      int
	generateOutput string
	generateError  bool
	done           bool
}

func dummyWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*dummyContext)
	if ctx.contextName != "testContext" {
		panic("contextName mismatch")
	}
	d := w.Description.(dummyDescription)
	if d.sleepTime != 0 {
		log.Printf("dummyWorker sleeping for %d seconds", d.sleepTime)
		time.Sleep(time.Duration(d.sleepTime) * time.Second)
	}
	result := worker.WorkResult{
		Key:    w.Key,
		Output: d.generateOutput,
	}
	if d.generateError {
		result.Error = errors.New("generated error")
		result.ErrorTime = time.Now()
	}
	d.done = true
	result.Description = d
	log.Printf("dummyWorker returning (sleep time %d)", d.sleepTime)
	return result
}

func getStacks(all bool) string {
	var (
		buf       []byte
		stackSize int
	)
	bufferLen := 16384
	for stackSize == len(buf) {
		buf = make([]byte, bufferLen)
		stackSize = runtime.Stack(buf, all)
		bufferLen *= 2
	}
	buf = buf[:stackSize]
	return string(buf)
}
