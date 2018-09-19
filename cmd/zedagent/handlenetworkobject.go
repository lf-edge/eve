// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkObject

package zedagent

import (
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/cast"
)

// XXX rename to NetworkObjectStatus?
func handleNetworkObjectModify(ctxArg interface{}, key string, statusArg interface{}) {
	log.Printf("handleNetworkObjectCreate(%s)\n", key)
	// XXX ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkObjectStatus(statusArg)
	if status.Key() != key {
		log.Printf("handleNetworkObjectModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	// XXX look for error; copy to device error; need device error in proto
	// XXX have handlemetrics read sub.GetAll() and look for errors?
	if !status.ErrorTime.IsZero() {
		log.Printf("Received NetworkObject error %s\n", status.Error)
	}

	log.Printf("handleNetworkObjectCreate(%s) done\n", key)
}

// XXX rename to NetworkObjectStatus?
func handleNetworkObjectDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Printf("handleNetworkObjectDelete(%s)\n", key)
	// XXX how do we find and delete any error
	// ctx := ctxArg.(*zedagentContext)
	log.Printf("handleNetworkObjectDelete(%s) done\n", key)
}
