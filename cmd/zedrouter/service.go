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
		doModify(config, &status)
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
	doCreate(config, &status)
	pub.Publish(key, status)
	if config.Activate {
		doActivate(config, &status)
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
	if status.Activated {
		doInactivate(&status)
		pub.Publish(key, status)
	}
	doDelete(&status)
	status.PendingDelete = false
	pub.Unpublish(key)
}

func doCreate(config types.NetworkService, status *types.NetworkServiceStatus) {
	log.Printf("XXX doCreate NetworkService key %s\n", config.UUID)
	// Validate that the objects exists
	switch config.Type {
	case 1:
	}
}

func doModify(config types.NetworkService, status *types.NetworkServiceStatus) {
	log.Printf("doModify NetworkService key %s\n", config.UUID)
	if config.Type != status.Type ||
		config.AppLink != status.AppLink ||
		config.Adapter != status.Adapter {
		log.Printf("XXX doModify NetworkService can't change key %s\n",
			config.UUID)
		// XXX report error somehow?
		return
	}

	if config.Activate && !status.Activated {
		doActivate(config, status)
		status.Activated = true
	} else if status.Activated && !config.Activate {
		doInactivate(status)
		status.Activated = false
	}
}

func doActivate(config types.NetworkService, status *types.NetworkServiceStatus) {
	log.Printf("XXX doActivate NetworkService key %s\n", config.UUID)
}

func doInactivate(status *types.NetworkServiceStatus) {
	log.Printf("XXX doInactivate NetworkService key %s\n", status.UUID)
}

func doDelete(status *types.NetworkServiceStatus) {
	log.Printf("XXX doDelete NetworkService key %s\n", status.UUID)
	// Anything to do except the inactivate already done?
}
