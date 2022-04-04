// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfsmanager

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

func handleNodeAgentStatusCreate(ctxArg interface{}, key string,
	configArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, configArg)
}

func handleNodeAgentStatusModify(ctxArg interface{}, key string,
	configArg interface{}, oldConfigArg interface{}) {
	handleNodeAgentStatusImpl(ctxArg, key, configArg)
}

func handleNodeAgentStatusImpl(ctxArg interface{}, key string,
	configArg interface{}) {

	if vault.ReadPersistType() != types.PersistZFS {
		return
	}

	ctx := ctxArg.(*zfsContext)
	status := configArg.(types.NodeAgentStatus)
	if !ctx.zbootWaitTestComplete {
		return
	}
	if !status.UpdateInprogress {
		ctx.zbootWaitTestComplete = false
		// run it in goroutine as possible long-time process
		go func() {
			log.Noticeln("ZpoolUpgrade start")
			if message, err := zfs.ZpoolUpgrade(log, vault.DefaultZpool); err != nil {
				log.Errorf("ZpoolUpgrade done with error: %s %s", message, err)
				return
			}
			log.Noticeln("ZpoolUpgrade done")
		}()
	}

	log.Functionf("handleNodeAgentStatusImpl(%s) done", key)
}
