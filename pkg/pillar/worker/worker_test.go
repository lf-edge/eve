// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// worker is used to kick off some work to a goroutine and get a notification
// when the work is complete

package worker

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
	"time"
)

var timestamp time.Time

func TestWork(t *testing.T) {
	testMatrix := map[string]struct {
		description dummyDescription
	}{
		"output": {
			description: dummyDescription{
				generateOutput: "test1",
			},
		},
		"output + sleep": {
			description: dummyDescription{
				sleepTime:      1,
				generateOutput: "test2",
			},
		},
		"output + error": {
			description: dummyDescription{
				generateOutput: "test3",
				generateError:  true,
			},
		},
		"output + sleep + error": {
			description: dummyDescription{
				sleepTime:      1,
				generateOutput: "test4",
				generateError:  true,
			},
		},
	}
	ctx := dummyContext{contextName: "testContext"}
	worker := NewWorker(dummyWorker, &ctx, 1)
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		t.Run(testname, func(t *testing.T) {
			d := test.description
			w := Work{Key: testname, Description: d}
			timestamp = time.Now() // In case we ask for sleep
			worker.Submit(w)
			assert.Equal(t, 1, worker.NumPending())
			res := worker.Process(<-worker.MsgChan())
			assert.Equal(t, 0, worker.NumPending())
			assert.Equal(t, testname, res.Key)
			assert.Equal(t, d.generateOutput, res.Output)
			if d.sleepTime != 0 {
				minDuration := time.Duration(d.sleepTime) * time.Second
				maxDuration := minDuration + 100*time.Millisecond
				took := time.Since(timestamp)
				assert.GreaterOrEqual(t, int64(took), int64(minDuration))
				assert.Less(t, int64(took), int64(maxDuration))
			}
			if d.generateError {
				assert.NotEqual(t, nil, res.Error)
				assert.Equal(t, timestamp, res.ErrorTime)
			}
			dout := res.Description.(dummyDescription)
			assert.Equal(t, d.generateOutput, dout.generateOutput)
			assert.Equal(t, true, dout.done)
		})
	}
	assert.Equal(t, 0, worker.NumPending())
	worker.Done()
	_, ok := <-worker.MsgChan()
	done := !ok
	assert.Equal(t, true, done)
}

var sleep1 = dummyDescription{
	sleepTime:      1,
	generateOutput: "sleep1",
}
var sleep2 = dummyDescription{
	sleepTime:      2,
	generateOutput: "sleep2",
}
var sleep3 = dummyDescription{
	sleepTime:      0,
	generateOutput: "sleep2",
}

// TestLength verifies that the channel length causes delay
func TestLength(t *testing.T) {
	ctx := dummyContext{contextName: "testContext"}
	worker := NewWorker(dummyWorker, &ctx, 1)
	testname := "testlength"

	t.Logf("Running test case %s", testname)
	w1 := Work{Key: testname, Description: sleep1}
	timestamp = time.Now() // In case we ask for sleep
	submit1start := timestamp
	worker.Submit(w1)
	assert.Equal(t, 1, worker.NumPending())
	submit1time := time.Since(submit1start)
	log.Printf("Submit1 took %v", submit1time)
	minDuration := time.Duration(0)
	maxDuration := minDuration + 100*time.Millisecond
	assert.GreaterOrEqual(t, int64(submit1time), int64(minDuration))
	assert.Less(t, int64(submit1time), int64(maxDuration))

	w2 := Work{Key: testname, Description: sleep2}
	submit2start := time.Now()
	worker.Submit(w2)
	assert.Equal(t, 2, worker.NumPending())
	submit2time := time.Since(submit2start)
	log.Printf("Submit2 took %v", submit2time)
	assert.GreaterOrEqual(t, int64(submit2time), int64(minDuration))
	assert.Less(t, int64(submit2time), int64(maxDuration))

	w3 := Work{Key: testname, Description: sleep3}
	submit3start := time.Now()
	worker.Submit(w3)
	assert.Equal(t, 3, worker.NumPending())
	submit3time := time.Since(submit3start)
	log.Printf("Submit3 took %v", submit3time)
	// With channel length 1 have to wait for w1 to complete
	minDuration = time.Duration(sleep1.sleepTime) * time.Second
	maxDuration = minDuration + 100*time.Millisecond
	minDuration -= 100 * time.Millisecond
	assert.GreaterOrEqual(t, int64(submit3time), int64(minDuration))
	assert.Less(t, int64(submit3time), int64(maxDuration))

	res1 := worker.Process(<-worker.MsgChan())
	assert.Equal(t, 2, worker.NumPending())
	assert.Equal(t, testname, res1.Key)
	assert.Equal(t, sleep1.generateOutput, res1.Output)
	if sleep1.sleepTime != 0 {
		minDuration := time.Duration(sleep1.sleepTime)*time.Second + submit1time
		maxDuration := minDuration + 100*time.Millisecond
		took := time.Since(timestamp)
		assert.GreaterOrEqual(t, int64(took), int64(minDuration))
		assert.Less(t, int64(took), int64(maxDuration))
	}
	res2 := worker.Process(<-worker.MsgChan())
	assert.Equal(t, 1, worker.NumPending())
	assert.Equal(t, testname, res2.Key)
	assert.Equal(t, sleep2.generateOutput, res2.Output)
	if sleep2.sleepTime != 0 {
		// Single worker processing serially
		secs := sleep1.sleepTime + sleep2.sleepTime
		minDuration := time.Duration(secs)*time.Second + submit1time + submit2time
		maxDuration := minDuration + 100*time.Millisecond
		took := time.Since(timestamp)
		assert.GreaterOrEqual(t, int64(took), int64(minDuration))
		assert.Less(t, int64(took), int64(maxDuration))
	}

	res3 := worker.Process(<-worker.MsgChan())
	assert.Equal(t, 0, worker.NumPending())
	assert.Equal(t, testname, res3.Key)
	assert.Equal(t, sleep3.generateOutput, res3.Output)
	if sleep3.sleepTime != 0 {
		minDuration := time.Duration(sleep3.sleepTime)*time.Second + submit1time + submit2time + submit3time
		maxDuration := minDuration + 100*time.Millisecond
		took := time.Since(timestamp)
		assert.GreaterOrEqual(t, int64(took), int64(minDuration))
		assert.Less(t, int64(took), int64(maxDuration))
	}

	assert.Equal(t, 0, worker.NumPending())
	worker.Done()
	_, ok := <-worker.MsgChan()
	done := !ok
	assert.Equal(t, true, done)
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

func dummyWorker(ctxPtr interface{}, w Work) WorkResult {
	ctx := ctxPtr.(*dummyContext)
	if ctx.contextName != "testContext" {
		panic("contextName mismatch")
	}
	d := w.Description.(dummyDescription)
	if d.sleepTime != 0 {
		log.Printf("dummyWorker sleeping for %d seconds", d.sleepTime)
		time.Sleep(time.Duration(d.sleepTime) * time.Second)
	}
	result := WorkResult{
		Key:    w.Key,
		Output: d.generateOutput,
	}
	if d.generateError {
		result.Error = errors.New("generated error")
		result.ErrorTime = timestamp
	}
	d.done = true
	result.Description = d
	return result
}
