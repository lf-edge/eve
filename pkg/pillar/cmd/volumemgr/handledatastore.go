// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Handles both create and modify events
func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.DatastoreConfig)
	log.Infof("handleDatastoreConfigModify for %s", key)
	updateStatusByDatastore(ctx, config)
	log.Infof("handleDatastoreConfigModify for %s, done", key)
}
