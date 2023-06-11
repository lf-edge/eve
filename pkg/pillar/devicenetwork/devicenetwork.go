// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package devicenetwork

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
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
