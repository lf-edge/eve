// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

package devicenetwork

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zededa/go-provision/types"
)

// Caller should loop over interfaces
// Download a wpad file if so configured
func CheckAndGetNetworkProxy(config *types.ProxyConfig) error {

	log.Infof("CheckAndGetNetworkProxy: enable %v, url %s, %s, %s\n",
		config.NetworkProxyEnable, config.NetworkProxyURL)

	if config.Pacfile != "" {
		log.Infof("CheckAndGetNetworkProxy: already have Pacfile\n")
		return nil
	}
	if !config.NetworkProxyEnable {
		log.Infof("CheckAndGetNetworkProxy: not enabled\n")
		return nil
	}
	if config.NetworkProxyURL != "" {
		pac, err := getFile(config.NetworkProxyURL)
		if err != nil {
			errStr := fmt.Sprintf("Failed to fetch %s: %s",
				config.NetworkProxyURL, err)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
		log.Infof("CheckAndGetNetworkProxy: fetched from URL %s: %s\n",
			config.NetworkProxyURL, pac)
		// XXX write to status
		config.Pacfile = pac
		return nil
	}
	// XXX try http://wpad.%s/wpad.dat", dn
	// starting with DomainName and truncating it
	// XXX need DomainName set
	// XXX need per interface
	return nil
}

func getFile(url string) (string, error) {
	// XXX
	return "", nil
}
