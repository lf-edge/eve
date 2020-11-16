// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package worker_test

import (
	"context"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/worker"
	"github.com/sirupsen/logrus"
)

func Example_workerprocess() {
	key := "123456"
	kind := "install"
	input := "25"
	ctx := context.Background()
	var output string

	// a worker that just adds some test
	installWorker := func(ctxPtr interface{}, w worker.Work) worker.WorkResult {
		d := w.Description.(string)
		result := worker.WorkResult{
			Key:         w.Key,
			Description: fmt.Sprintf("processed-%s", d),
		}
		return result
	}
	// a processor that just sets the var in the closure to show that it worked
	processInstallWorkResult := func(ctxPtr interface{}, res worker.WorkResult) error {
		d := res.Description.(string)
		output = d
		return nil
	}

	// create a new worker that can handle jobs of Kind "install"
	logObject := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	work := worker.NewWorker(logObject, ctx, 5, map[string]worker.Handler{
		kind: {Request: installWorker, Response: processInstallWorkResult},
	})

	err := work.Submit(worker.Work{Key: key, Kind: kind, Description: input})
	// what happened when we submitted?
	if err != nil {
		if _, ok := err.(*worker.JobInProgressError); ok {
			logrus.Fatal("job already in progress")
		}
		logrus.Fatalf("unknown error: %v\n", err)
	}
	logrus.Info("job submitted")
	// nothing to do now, wait for the result
forloop:
	for {
		select {
		case res := <-work.C():
			res.Process(ctx, true)
			// break out of the loop once we have a result
			// normally, you would keep going
			break forloop
		}
	}
	// print the output, which is set to what the worker did
	fmt.Println(output)

	// see that we can retrieve it via Pop
	wr := work.Pop(key)
	d := wr.Description.(string)
	fmt.Println(d)

	// Output:
	// processed-25
	// processed-25
}
