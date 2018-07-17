// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkService responses from zedrouter

package zedagent

import (
	"github.com/zededa/go-provision/cast"
	"log"
)

func handleNetworkServiceModify(ctxArg interface{}, key string, statusArg interface{}) {
	log.Printf("handleNetworkServiceCreate(%s)\n", key)
	// XXX ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkServiceStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleNetworkServiceModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	// XXX look for error; copy to device error; need device error in proto
	// XXX have handlemetrics read sub.GetAll() and look for errors?
	if !status.ErrorTime.IsZero() {
		log.Printf("Received NetworkService error %s\n", status.Error)
	}
	log.Printf("handleNetworkServiceCreate(%s) done\n", key)
}

func handleNetworkServiceDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleNetworkServiceDelete(%s)\n", key)
	// XXX how do we find and delete any error
	// ctx := ctxArg.(*zedagentContext)
	log.Printf("handleNetworkServiceDelete(%s) done\n", key)
}
