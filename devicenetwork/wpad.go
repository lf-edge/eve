// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
)

// Caller should loop over interfaces
// Download a wpad file if so configured
func CheckAndGetNetworkProxy(status *types.DeviceNetworkStatus,
	proxyConfig *types.ProxyConfig) error {

	log.Infof("CheckAndGetNetworkProxy: enable %v, url %s, %s, %s\n",
		proxyConfig.NetworkProxyEnable, proxyConfig.NetworkProxyURL)

	// XXX make per interface
	ifname := "eth0"
	if proxyConfig.Pacfile != "" {
		log.Infof("CheckAndGetNetworkProxy: already have Pacfile\n")
		return nil
	}
	if !proxyConfig.NetworkProxyEnable {
		log.Infof("CheckAndGetNetworkProxy: not enabled\n")
		return nil
	}
	if proxyConfig.NetworkProxyURL != "" {
		pac, err := getFile(status, proxyConfig.NetworkProxyURL, ifname)
		if err != nil {
			errStr := fmt.Sprintf("Failed to fetch %s: %s",
				proxyConfig.NetworkProxyURL, err)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
		log.Infof("CheckAndGetNetworkProxy: fetched from URL %s: %s\n",
			proxyConfig.NetworkProxyURL, pac)
		proxyConfig.Pacfile = pac
		return nil
	}
	// XXX try http://wpad.%s/wpad.dat", dn
	// starting with DomainName and truncating it
	return nil
}

var ctx = zedcloud.ZedCloudContext{
	FailureFunc: zedcloud.ZedCloudFailure,
	SuccessFunc: zedcloud.ZedCloudSuccess,
}

func getFile(status *types.DeviceNetworkStatus, url string,
	ifname string) (string, error) {

	ctx.DeviceNetworkStatus = status
	_, contents, err := zedcloud.SendOnIntf(ctx, url, ifname, 0, nil)
	return string(contents), err
}
