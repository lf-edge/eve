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
	log.Infof("handleNetworkObjectCreate(%s)\n", key)
	// XXX ctx := ctxArg.(*zedagentContext)
	status := cast.CastNetworkObjectStatus(statusArg)
	if status.Key() != key {
		log.Errorf("handleNetworkObjectModify key/UUID mismatch %s vs %s; ignored %+v\n", key, status.Key(), status)
		return
	}
	// XXX look for error; copy to device error; need device error in proto
	// XXX have handlemetrics read sub.GetAll() and look for errors?
	if !status.ErrorTime.IsZero() {
		log.Errorf("Received NetworkObject error %s\n", status.Error)
	}

	log.Infof("handleNetworkObjectCreate(%s) done\n", key)
}

// XXX rename to NetworkObjectStatus?
func handleNetworkObjectDelete(ctxArg interface{}, key string,
	statusArg interface{}) {

	log.Infof("handleNetworkObjectDelete(%s)\n", key)
	// XXX how do we find and delete any error
	// ctx := ctxArg.(*zedagentContext)
	log.Infof("handleNetworkObjectDelete(%s) done\n", key)
}
