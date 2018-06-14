// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkService setup

package zedrouter

import (
	"github.com/zededa/go-provision/types"
	"log"
)

func handleNetworkServiceModify(ctxArg interface{}, key string, configArg interface{}) {
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	config := CastNetworkService(configArg)
	st, err := pub.Get(key)
	if err != nil {
		log.Printf("handleNetworkServiceModify(%s) failed %s\n",
			key, err)
		return
	}
	if st != nil {
		log.Printf("handleNetworkServiceModify(%s)\n", key)
		status := CastNetworkServiceStatus(st)
		status.PendingModify = true
		pub.Publish(key, status)
		// XXX what do we do?
		status.PendingModify = false
		pub.Publish(key, status)
	} else {
		handleNetworkServiceCreate(ctx, key, config)
	}
}

func handleNetworkServiceCreate(ctx *zedrouterContext, key string, config types.NetworkService) {
	log.Printf("handleNetworkServiceCreate(%s)\n", key)

	pub := ctx.pubNetworkServiceStatus
	status := types.NetworkServiceStatus{
		UUID:        config.UUID,
		DisplayName: config.DisplayName,
		Type:        config.Type,
		AppLink:     config.AppLink,
		Adapter:     config.Adapter,
	}
	status.PendingAdd = true
	pub.Publish(key, status)
	// XXX do work
	if config.Activate {
		// XXX doActivate
		status.Activated = true
	}
	status.PendingAdd = false
	pub.Publish(key, status)
}

func handleNetworkServiceDelete(ctxArg interface{}, key string) {
	ctx := ctxArg.(*zedrouterContext)
	pub := ctx.pubNetworkServiceStatus
	log.Printf("handleNetworkServiceDelete(%s)\n", key)
	st, err := pub.Get(key)
	if err != nil {
		log.Printf("handleNetworkServiceDelete(%s) failed %s\n",
			key, err)
		return
	}
	if st == nil {
		log.Printf("handleNetworkServiceDelete: unknown %s\n", key)
		return
	}
	status := CastNetworkServiceStatus(st)
	status.PendingDelete = true
	pub.Publish(key, status)
	// XXX what do we do?

	status.PendingDelete = false
	pub.Unpublish(key)
}
