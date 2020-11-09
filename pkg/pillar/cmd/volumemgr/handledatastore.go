// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func handleDatastoreConfigCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleDatastoreConfigImpl(ctxArg, key, configArg)
}

func handleDatastoreConfigModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleDatastoreConfigImpl(ctxArg, key, configArg)
}

func handleDatastoreConfigImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	ctx := ctxArg.(*volumemgrContext)
	config := configArg.(types.DatastoreConfig)
	log.Functionf("handleDatastoreConfigImpl for %s", key)
	updateStatusByDatastore(ctx, config)
	log.Functionf("handleDatastoreConfigImpl for %s, done", key)
}
