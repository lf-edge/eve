// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/zedcloud"
	"strings"
)

// Download a wpad file if so configured
func CheckAndGetNetworkProxy(deviceNetworkStatus *types.DeviceNetworkStatus,
	status *types.NetworkUplink) error {

	ifname := status.IfName
	proxyConfig := &status.ProxyConfig

	log.Infof("CheckAndGetNetworkProxy(%s): enable %v, url %s\n",
		ifname, proxyConfig.NetworkProxyEnable,
		proxyConfig.NetworkProxyURL)

	if proxyConfig.Pacfile != "" {
		log.Infof("CheckAndGetNetworkProxy(%s): already have Pacfile\n",
			ifname)
		return nil
	}
	if !proxyConfig.NetworkProxyEnable {
		log.Infof("CheckAndGetNetworkProxy(%s): not enabled\n",
			ifname)
		return nil
	}
	if proxyConfig.NetworkProxyURL != "" {
		pac, err := getFile(deviceNetworkStatus,
			proxyConfig.NetworkProxyURL, ifname)
		if err != nil {
			errStr := fmt.Sprintf("Failed to fetch %s for %s: %s",
				proxyConfig.NetworkProxyURL, ifname, err)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
		log.Infof("CheckAndGetNetworkProxy(%s): fetched from URL %s: %s\n",
			ifname, proxyConfig.NetworkProxyURL, pac)
		proxyConfig.Pacfile = pac
		return nil
	}
	dn := status.DomainName
	if dn == "" {
		errStr := fmt.Sprintf("NetworkProxyEnable for %s but neither a NetworkProxyURL nor a DomainName",
			ifname)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Infof("CheckAndGetNetworkProxy(%s): DomainName %s\n",
		ifname, dn)
	// Try http://wpad.%s/wpad.dat", dn where we the leading labels
	// in DomainName until we succeed
	for {
		url := fmt.Sprintf("http://wpad.%s/wpad.dat", dn)
		pac, err := getFile(deviceNetworkStatus, url, ifname)
		if err == nil {
			log.Infof("CheckAndGetNetworkProxy(%s): fetched from URL %s: %s\n",
				ifname, url, pac)
			proxyConfig.Pacfile = pac
			return nil
		}
		errStr := fmt.Sprintf("Failed to fetch %s for %s: %s",
			url, ifname, err)
		log.Warnln(errStr)
		i := strings.Index(dn, ".")
		if i == -1 {
			log.Infof("CheckAndGetNetworkProxy(%s): no dots in DomainName %s\n",
				ifname, dn)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
		b := []byte(dn)
		dn = string(b[i+1:])
		// How many dots left? End when we have a TLD i.e., no dots
		// since wpad.com isn't a useful place to look
		count := strings.Count(dn, ".")
		if count == 0 {
			log.Infof("CheckAndGetNetworkProxy(%s): reached TLD in DomainName %s\n",
				ifname, dn)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
	}
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
