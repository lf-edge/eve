// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Publish the IsZedmanager AppNetworkConfig and /etc/hosts
// XXX Should also look at the corresponding AppNetworkStatus and report
// any errors back as device errors to zedcloud.

package zedagent

import (
	"bytes"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	infraFileName           = types.IdentityDirname + "/infra"
	zedserverConfigFileName = types.TmpDirname + "/zedserverconfig"
)

func publishAppNetworkConfig(getconfigCtx *getconfigContext,
	config types.AppNetworkConfig) {

	key := config.Key()
	log.Debugf("publishAppNetworkConfig %s", key)
	pub := getconfigCtx.pubAppNetworkConfig
	pub.Publish(key, config)
}

func unpublishAppNetworkConfig(getconfigCtx *getconfigContext, key string) {

	log.Debugf("unpublishAppNetworkConfig %s", key)
	pub := getconfigCtx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishAppNetworkConfig(%s) not found", key)
		return
	}
	pub.Unpublish(key)
}

func addrStringToIP(addrString string) (net.IP, error) {
	clientTCP, err := net.ResolveTCPAddr("tcp", addrString)
	if err != nil {
		return net.IP{}, err
	}
	return clientTCP.IP, nil
}

// IsMyAddress checks the IP address against the local IPs. Returns True if
// there is a match.
func IsMyAddress(clientIP net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok &&
			!ipnet.IP.IsLoopback() {
			if bytes.Compare(ipnet.IP, clientIP) == 0 {
				return true
			}
		}
	}
	return false
}
