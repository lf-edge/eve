// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/worker"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

const (
	workInstall = "install"
)

// installWorkDescription install work we feed into the worker go routine
type installWorkDescription struct {
	key    string
	ref    string
	target string
}

// AddWorkInstall create a Work job to install the provided image to the target path
func AddWorkInstall(ctx *baseOsMgrContext, key, ref, target string) {
	d := installWorkDescription{
		key:    key,
		ref:    ref,
		target: target,
	}
	// Don't fail on errors to make idempotent (Submit returns an error if
	// the work was already submitted)
	done, err := ctx.worker.TrySubmit(worker.Work{Key: key, Kind: workInstall,
		Description: d})
	if err != nil {
		log.Errorf("TrySubmit %s failed: %s", key, err)
	} else if !done {
		log.Fatalf("Failed to submit work due to queue length for %s", key)
	}
	log.Functionf("AddWorkInstall(%s) done", key)
}

// installWorker implementation of work.WorkFunction that installs an image to a particular location
func installWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	d := w.Description.(installWorkDescription)

	result := worker.WorkResult{
		Key:         w.Key,
		Description: d,
	}

	if d.target == "" {
		result.Error = fmt.Errorf("installWorker: unassigned destination partition for %s", d.ref)
		result.ErrorTime = time.Now()
		return result
	}

	log.Functionf("installWorker to install %s to %s", d.ref, d.target)
	err := zboot.WriteToPartition(log, d.ref, d.target)
	log.Functionf("installWorker DONE install %s to %s: err %v",
		d.ref, d.target, err)

	if err != nil {
		result.Error = err
		result.ErrorTime = time.Now()
	}
	return result
}

// processInstallWorkResult handle the work result that was an installation
func processInstallWorkResult(ctxPtr interface{}, res worker.WorkResult) error {
	ctx := ctxPtr.(*baseOsMgrContext)
	d := res.Description.(installWorkDescription)
	baseOsHandleStatusUpdateUUID(ctx, d.key)
	return nil
}
