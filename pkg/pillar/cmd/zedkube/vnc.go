// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
)

// runAppVNC - run vnc for EVE 'k' VMI remote console
func (z *zedkube) runAppVNC(config *types.AppInstanceConfig) {
	log.Noticef("runAppVNC: starting for app %s, RemoteConsole=%v",
		config.DisplayName, config.RemoteConsole)

	vmconfig := config.FixedResources

	var vmiName string
	for i := 5; i >= 0; i-- {
		var err error
		vmiName, err = z.getVMIdomainName(config)
		if err != nil {
			log.Noticef("runAppVNC: get vmi domainname error %v, retries left %d", err, i)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	if vmiName == "" {
		log.Errorf("runAppVNC: can not find vmiName for app %s", config.DisplayName)
		return
	}
	log.Noticef("runAppVNC: found vmiName %s for app %s", vmiName, config.DisplayName)

	vncPort := vmconfig.VncDisplay + 5900

	if config.RemoteConsole {
		// Check if file already exists (another VNC session is active)
		if _, err := os.Stat(types.VmiVNCFileName); err == nil {
			log.Errorf("runAppVNC: VNC file already exists, another session may be active")
			return
		}

		// Ensure the VNC directory exists
		if err := os.MkdirAll(types.VmiVNCDir, 0755); err != nil {
			log.Errorf("runAppVNC: Error creating VNC directory %s: %v", types.VmiVNCDir, err)
			return
		}

		// Write JSON format config file
		vncConfig := types.VmiVNCConfig{
			VMIName: vmiName,
			VNCPort: uint32(vncPort),
			// CallerPID is not set for remote-console VNC (only edgeview sets it)
		}

		content, err := json.Marshal(vncConfig)
		if err != nil {
			log.Errorf("runAppVNC: Error marshaling VNC config: %v", err)
			return
		}

		err = os.WriteFile(types.VmiVNCFileName, content, 0644)
		if err != nil {
			log.Errorf("runAppVNC: Error creating file %s: %v", types.VmiVNCFileName, err)
			return
		}
		log.Noticef("runAppVNC: vmiName %s, port %d, vmiVNC file %s created",
			vmiName, vncPort, types.VmiVNCFileName)
	} else {
		if _, err := os.Stat(types.VmiVNCFileName); err == nil {
			log.Noticef("runAppVNC: RemoteConsole disabled, removing VNC file %s", types.VmiVNCFileName)
			err = os.Remove(types.VmiVNCFileName)
			if err != nil {
				log.Errorf("runAppVNC: Error remove file %v", err)
				return
			}
		}
	}
	log.Noticef("runAppVNC: %s done", vmiName)
}

func (z *zedkube) getVMIdomainName(config *types.AppInstanceConfig) (string, error) {
	if z.config == nil {
		config, err := kubeapi.GetKubeConfig()
		if err != nil {
			log.Errorf("getVMIs: config is nil")
			return "", fmt.Errorf("getVMIs: config get failed error %v", err)
		}
		z.config = config
	}
	virtClient, err := kubecli.GetKubevirtClientFromRESTConfig(z.config)
	if err != nil {
		log.Errorf("getVMIs: get virtclient error %v", err)
		return "", err
	}

	vmiName := base.GetAppKubeName(config.DisplayName, config.UUIDandVersion.UUID)
	var domainName string
	vmis, err := virtClient.VirtualMachineInstance(kubeapi.EVEKubeNameSpace).List(context.Background(), &metav1.ListOptions{})
	if err != nil {
		log.Errorf("getVMIs: get VMI list error %v", err)
		return "", err
	}

	for _, vmi := range vmis.Items {
		if !strings.Contains(vmi.ObjectMeta.Name, vmiName) {
			continue
		}
		domainName = vmi.ObjectMeta.Name
		break
	}

	return domainName, nil
}
