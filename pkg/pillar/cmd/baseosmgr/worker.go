// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"fmt"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/worker"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// installWorkDescription install work we feed into the worker go routine
type installWorkDescription struct {
	contentID string
	ref       string
	target    string
}

// installWorkResult result of sending to a partition
type installWorkResult struct {
	worker.WorkResult // Error etc
}

var pendingInstallMap = make(map[string]bool)
var installWorkResultMap = make(map[string]installWorkResult)

func lookupPendingInstall(key string) bool {
	res, ok := pendingInstallMap[key]
	return ok && res
}

func addPendingInstall(key string) {
	pendingInstallMap[key] = true
}

func deletePendingInstall(key string) {
	delete(pendingInstallMap, key)
}

// AddWorkInstall checks if the Key is in the map of pending work
// and if not kicks of a worker and adds it
func AddWorkInstall(ctx *baseOsMgrContext, key, ref, target string) {
	log.Infof("AddWorkInstall(%s)", key)
	if lookupPendingInstall(key) {
		log.Infof("AddWorkInstall(%s) found", key)
		return
	}
	d := installWorkDescription{
		contentID: key,
		ref:       ref,
		target:    target,
	}
	w := worker.Work{Key: key, Description: d}
	ctx.worker.Submit(w)
	addPendingInstall(key)
	log.Infof("AddWorkInstall(%s) done", key)
}

// DeleteWorkInstall is called by user when work is done
func DeleteWorkInstall(key string) {
	log.Infof("DeleteWorkInstall(%s)", key)
	if !lookupPendingInstall(key) {
		log.Infof("DeleteWorkInstall(%s) NOT found", key)
		return
	}
	deletePendingInstall(key)
	log.Infof("DeleteWorkInstall(%s) done", key)
}

func lookupInstallWorkResult(key string) *installWorkResult {
	if res, ok := installWorkResultMap[key]; ok {
		return &res
	}
	return nil
}

func addInstallWorkResult(key string, res installWorkResult) {
	installWorkResultMap[key] = res
}

func deleteInstallWorkResult(key string) {
	delete(installWorkResultMap, key)
}

// HandleWorkResult processes what comes out of the select loop
func HandleWorkResult(ctx *baseOsMgrContext, res worker.WorkResult) {
	// we do not really need a switch here, but we might have more types in the future
	switch res.Description.(type) {
	case installWorkDescription:
		processInstallWorkResult(ctx, res)
	default:
		log.Fatalf("received unknown work description type %T", res.Description)
	}
}

// WorkerHandler worker switchboard for different types of workers
func WorkerHandler(ctxPtr interface{}, w worker.Work) worker.WorkResult {
	// we do not really need a switch here, but we might have more types in the future
	switch t := w.Description.(type) {
	case installWorkDescription:
		return installWorker(ctxPtr, w)
	default:
		return worker.WorkResult{
			Key:         w.Key,
			Description: w.Description,
			Error:       fmt.Errorf("unknown work description type %v", t),
			ErrorTime:   time.Now(),
		}
	}
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

	log.Infof("installWorker to install %s to %s", d.ref, d.target)
	err := zboot.WriteToPartition(log, d.ref, d.target)

	if err != nil {
		result.Error = err
		result.ErrorTime = time.Now()
	}
	return result
}

// processInstallWorkResult handle the work result that was an installation
func processInstallWorkResult(ctx *baseOsMgrContext, res worker.WorkResult) {
	d := res.Description.(installWorkDescription)
	wres := installWorkResult{
		WorkResult: res,
	}
	addInstallWorkResult(res.Key, wres)
	baseOsHandleStatusUpdateImageSha(ctx, d.contentID)
}
