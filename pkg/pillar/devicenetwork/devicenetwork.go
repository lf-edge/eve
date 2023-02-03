// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

func IsProxyConfigEmpty(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) == 0 &&
		len(proxyConfig.ProxyCertPEM) == 0 &&
		proxyConfig.Exceptions == "" &&
		proxyConfig.Pacfile == "" &&
		proxyConfig.NetworkProxyEnable == false &&
		proxyConfig.NetworkProxyURL == "" {
		return true
	}
	return false
}

// IsExplicitProxyConfigured returns true if EVE is explicitly configured
// to route traffic via a proxy for a given uplink interface.
func IsExplicitProxyConfigured(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) > 0 ||
		proxyConfig.Pacfile != "" ||
		proxyConfig.NetworkProxyEnable {
		return true
	}
	return false
}

// UplinkToPhysdev checks if the ifname is a bridge and if so it
// prepends a "k" to the name (assuming that ifname exists)
// If any issues it returns the argument ifname.
func UplinkToPhysdev(log *base.LogObject, ifname string) string {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		err = fmt.Errorf("UplinkToPhysdev LinkByName(%s) failed: %v",
			ifname, err)
		log.Error(err)
		return ifname
	}
	linkType := link.Type()
	if linkType != "bridge" {
		log.Functionf("UplinkToPhysdev(%s) not a bridge", ifname)
		return ifname
	}

	kernIfname := "k" + ifname
	_, err = netlink.LinkByName(kernIfname)
	if err != nil {
		err = fmt.Errorf("UplinkToPhysdev(%s) %s does not exist: %v",
			ifname, kernIfname, err)
		log.Error(err)
		return ifname
	}
	log.Functionf("UplinkToPhysdev found %s", kernIfname)
	return kernIfname
}
