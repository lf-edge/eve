// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
)

// Cache for the EVE-k cluster-storage readiness probe (single-threaded volumemgr
// main loop, so no lock needed). Once ready it stays ready (longhorn/CDI don't
// un-deploy); while not ready we re-probe at most every clusterStorageProbeTTL.
var (
	clusterStorageReadyCache   bool
	clusterStorageReadyCheckAt time.Time
)

const clusterStorageProbeTTL = 15 * time.Second

// clusterStorageReady reports whether EVE-k longhorn+CDI are ready to create app
// volumes, caching the kube-API probe. The volume-create path calls this so
// volumemgr DEFERS (quietly, no error) until the cluster storage stack is up,
// instead of attempting and failing (storageclass-not-found / no-upload-pod-
// annotation) then relying on the error-retry. Always true off EVE-k.
func clusterStorageReady(ctx *volumemgrContext) bool {
	if !ctx.hvTypeKube {
		return true
	}
	if clusterStorageReadyCache {
		return true
	}
	if time.Since(clusterStorageReadyCheckAt) < clusterStorageProbeTTL {
		return false
	}
	clusterStorageReadyCheckAt = time.Now()
	clusterStorageReadyCache = kubeapi.ClusterStorageReadyForVolumes(log, ctx.nodeName)
	return clusterStorageReadyCache
}
