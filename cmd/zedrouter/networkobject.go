// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkObject

package zedrouter

import (
	//	"errors"
	"fmt"
	"github.com/zededa/go-provision/cast"
	"github.com/zededa/go-provision/types"
	"log"
	"time"
)

func handleNetworkConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkObjectStatus
	config := cast.CastNetworkObjectConfig(configArg)
	log.Printf("handleNetworkConfigModify(%s)\n", config.UUID.String())
	st, err := pub.Get(key)
	if err != nil {
		log.Printf("handleNetworkConfigModify(%s) failed %s\n",
			key, err)
		return
	}
	if st != nil {
		log.Printf("handleNetworkConfigModify(%s)\n", key)
		status := cast.CastNetworkObjectStatus(st)
		status.PendingModify = true
		pub.Publish(key, status)
		doNetworkModify(ctx, config, &status)
		status.PendingModify = false
		pub.Publish(key, status)
	} else {
		handleNetworkConfigCreate(ctx, key, config)
	}
}

func handleNetworkConfigCreate(ctx *zedrouterContext, key string, config types.NetworkObjectConfig) {
	log.Printf("handleNetworkConfigCreate(%s)\n", key)

	pub := ctx.pubNetworkObjectStatus
	status := types.NetworkObjectStatus{
		NetworkObjectConfig: config,
	}
	status.PendingAdd = true
	pub.Publish(key, status)
	err := doNetworkCreate(config, &status)
	if err != nil {
		log.Printf("doNetworkCreate(%s) failed: %s\n", key, err)
		status.Error = err.Error()
		status.ErrorTime = time.Now()
		status.PendingAdd = false
		pub.Publish(key, status)
		return
	}
	status.PendingAdd = false
	pub.Publish(key, status)
}

func handleNetworkConfigDelete(ctxArg interface{}, key string) {
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkObjectStatus
	log.Printf("handleNetworkConfigDelete()\n")
	st, err := pub.Get(key)
	if err != nil {
		log.Printf("handleNetworkConfigDelete(%s) failed %s\n",
			key, err)
		return
	}
	if st == nil {
		log.Printf("handleNetworkConfigDelete: unknown %s\n", key)
		return
	}
	status := cast.CastNetworkObjectStatus(st)
	status.PendingDelete = true
	pub.Publish(key, status)
	doNetworkDelete(&status)
	status.PendingDelete = false
	pub.Unpublish(key)
}

func doNetworkCreate(config types.NetworkObjectConfig, status *types.NetworkObjectStatus) error {
	log.Printf("doNetworkCreate NetworkObjectStatus key %s type %d\n",
		config.UUID, config.Type)

	// Check for valid types
	var err error
	// Validate that the objects exists
	switch config.Type {
	}
	return err

	// XXX Allocate bridgeNum ...

	// XXX Create bridge
}

func doNetworkModify(ctx *zedrouterContext, config types.NetworkObjectConfig,
	status *types.NetworkObjectStatus) {

	log.Printf("doNetworkModify NetworkObjectStatus key %s\n", config.UUID)
	if config.Type != status.Type {
		errStr := fmt.Sprintf("doNetworkModify NetworkObjectStatus can't change key %s",
			config.UUID)
		log.Println(errStr)
		status.Error = errStr
		status.ErrorTime = time.Now()
		return
	}

}

func doNetworkDelete(status *types.NetworkObjectStatus) {
	log.Printf("doNetworkDelete NetworkObjectStatus key %s type %d\n",
		status.UUID, status.Type)
	// XXX delete bridge
}
