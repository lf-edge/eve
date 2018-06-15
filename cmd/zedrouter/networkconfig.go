// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

// Handle NetworkConfig (the network objects sent by zedcloud)

package zedrouter

import (
	//	"errors"
	//	"fmt"
	//	"github.com/vishvananda/netlink"
	//	"github.com/zededa/go-provision/types"
	"log"
	//	"strings"
	//	"time"
)

func handleNetworkConfigModify(ctxArg interface{}, key string, configArg interface{}) {
	// XXX ctx := ctxArg.(*zedrouterContext)
	config := CastNetworkConfig(configArg)
	log.Printf("handleNetworkConfigModify(%s)\n", config.UUID.String())
}

func handleNetworkConfigDelete(ctxArg interface{}, key string) {
	// XXX ctx := ctxArg.(*zedrouterContext)
	log.Printf("handleNetworkConfigDelete()\n")
}
