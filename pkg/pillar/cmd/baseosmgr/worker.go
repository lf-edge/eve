// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"errors"
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/worker"
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

// AddWorkInstall create a Work job to install the provided image to the target path.
// Returns an error if the job could not be handed to the worker pool, in
// which case no worker owns the install and the caller must arrange for a
// retry. A job already in progress for this key counts as success, so the
// caller stays idempotent.
func AddWorkInstall(ctx *baseOsMgrContext, key, ref, target string) error {
	d := installWorkDescription{
		key:    key,
		ref:    ref,
		target: target,
	}
	done, err := ctx.worker.TrySubmit(worker.Work{Key: key, Kind: workInstall,
		Description: d})
	if err != nil {
		var inProgress *worker.JobInProgressError
		if errors.As(err, &inProgress) {
			log.Functionf("AddWorkInstall(%s): job already in progress", key)
			return nil
		}
		log.Errorf("AddWorkInstall(%s): TrySubmit failed: %s", key, err)
		return err
	}
	if !done {
		// A pool never returns (false, nil); only a bare worker with a full
		// queue does, and baseosmgr uses a pool.
		err := fmt.Errorf("worker did not accept install job %s", key)
		log.Error(err)
		return err
	}
	log.Functionf("AddWorkInstall(%s) done", key)
	return nil
}

// installWorker implementation of work.WorkFunction that installs an image to a particular location
func installWorker(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	ctx := ctxPtr.(*baseOsMgrContext)
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
	err := ctx.zboot.WriteToPartition(d.ref, d.target)
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
