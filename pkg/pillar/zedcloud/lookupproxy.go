// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedcloud

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedpac"
	log "github.com/sirupsen/logrus"
	"net/url"
	"strings"
)

func LookupProxy(status *types.DeviceNetworkStatus, ifname string,
	rawUrl string) (*url.URL, error) {

	for _, port := range status.Ports {
		log.Debugf("LookupProxy: Looking for proxy config on port %s",
			port.IfName)
		if port.IfName != ifname {
			continue
		}
		log.Debugf("LookupProxy: Port configuration found for %s", ifname)
		proxyConfig := port.ProxyConfig

		// Check if the URL is present in exception list
		// XXX Should we just get the domain name part of URL and compare?
		// XXX Doing the domain portion comparison for now.
		// Parse url and find the host domain part
		u, err := url.Parse(rawUrl)
		if err != nil {
			errStr := fmt.Sprintf("LookupProxy: malformed URL %s", rawUrl)
			log.Errorf(errStr)
			return nil, errors.New(errStr)
		}

		// Check if we have a PAC file
		if len(proxyConfig.Pacfile) > 0 {
			pacFile, err := base64.StdEncoding.DecodeString(proxyConfig.Pacfile)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: Decoding proxy file failed: %s", err)
				log.Errorf(errStr)
				return nil, errors.New(errStr)
			}
			proxyString, err := zedpac.Find_proxy_sync(
				string(pacFile), rawUrl, u.Host)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: PAC file could not find proxy for %s: %s",
					rawUrl, err)
				log.Errorf(errStr)
				return nil, errors.New(errStr)
			}
			//if proxyString == "DIRECT" {
			if strings.HasPrefix(proxyString, "DIRECT") {
				return nil, nil
			}
			proxies := strings.Split(proxyString, ";")
			if len(proxies) == 0 {
				log.Errorf("LookupProxy: Number of proxies in PAC file result is Zero")
				return nil, nil
			}

			// XXX Take the first proxy for now. Failing over to the next
			// proxy should be implemented
			proxy0 := proxies[0]
			proxy0 = strings.Split(proxy0, " ")[1]
			// Proxy address returned by PAC does not have the URL scheme.
			// We prepend the scheme (http/https) of the incoming raw URL.
			proxy0 = "http://" + proxy0
			proxy, err := url.Parse(proxy0)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: PAC file returned invalid proxy %s: %s",
					proxyString, err)
				log.Errorf(errStr)
				return nil, errors.New(errStr)
			}
			log.Debugf("LookupProxy: PAC proxy being used is %s", proxy0)
			return proxy, err
		}

		config := &Config{}
		for _, proxy := range proxyConfig.Proxies {
			switch proxy.Type {
			case types.NPT_HTTP:
				var httpProxy string
				if proxy.Port > 0 {
					httpProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpProxy = fmt.Sprintf("%s", proxy.Server)
				}
				config.HTTPProxy = httpProxy
				log.Debugf("LookupProxy: Adding HTTP proxy %s for port %s",
					config.HTTPProxy, ifname)
			case types.NPT_HTTPS:
				var httpsProxy string
				if proxy.Port > 0 {
					httpsProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpsProxy = fmt.Sprintf("%s", proxy.Server)
				}
				config.HTTPSProxy = httpsProxy
				log.Debugf("LookupProxy: Adding HTTPS proxy %s for port %s",
					config.HTTPSProxy, ifname)
			default:
				// XXX We should take care of Socks proxy, FTP proxy also in future
			}
		}
		config.NoProxy = proxyConfig.Exceptions
		proxyFunc := config.ProxyFunc()
		proxy, err := proxyFunc(u)
		if err != nil {
			errStr := fmt.Sprintf("LookupProxy: proxyFunc error: %s", err)
			log.Errorf(errStr)
			return proxy, errors.New(errStr)
		}
		return proxy, err
	}
	log.Infof("LookupProxy: No proxy configured for port %s", ifname)
	return nil, nil
}
